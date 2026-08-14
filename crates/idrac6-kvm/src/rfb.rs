//! Minimal RFB 3.8 (VNC) server exposing the shared framebuffer. Security = None, one Raw
//! encoding. Serves any duplex stream: a TCP socket for native VNC clients, or an
//! RFB-over-WebSocket pipe for the browser (noVNC). Input events are forwarded to the KVM session.

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::kvm::{Input, SharedFb};

pub async fn serve(listener: TcpListener, shared: SharedFb, input: mpsc::Sender<Input>) -> Result<()> {
    loop {
        let (sock, peer) = listener.accept().await.context("accept")?;
        info!(%peer, "RFB client connected");
        let fb = shared.clone();
        let tx = input.clone();
        tokio::spawn(async move {
            sock.set_nodelay(true).ok();
            if let Err(e) = serve_conn(sock, fb, tx).await {
                warn!(%peer, "RFB client ended: {e:#}");
            }
        });
    }
}

/// Run the RFB protocol over one duplex stream until it closes.
pub async fn serve_conn<S: AsyncRead + AsyncWrite + Unpin>(
    mut sock: S,
    shared: SharedFb,
    input: mpsc::Sender<Input>,
) -> Result<()> {
    // ProtocolVersion
    sock.write_all(b"RFB 003.008\n").await?;
    let mut ver = [0u8; 12];
    sock.read_exact(&mut ver).await?;

    // Security: offer only None (type 1).
    sock.write_all(&[1u8, 1u8]).await?;
    let mut chosen = [0u8; 1];
    sock.read_exact(&mut chosen).await?;
    sock.write_all(&0u32.to_be_bytes()).await?; // SecurityResult = OK

    // ClientInit (shared-flag) -> ServerInit
    let mut client_init = [0u8; 1];
    sock.read_exact(&mut client_init).await?;
    let (w, h) = {
        let g = shared.lock().unwrap();
        (g.fb.width as u16, g.fb.height as u16)
    };
    sock.write_all(&server_init(w, h)).await?;

    let mut last_gen = u64::MAX;
    let mut last_dims = (w, h); // size the client currently knows; DesktopSize keeps it in sync
    let mut desktopsize = false;
    let mut ty = [0u8; 1];
    loop {
        sock.read_exact(&mut ty).await?;
        match ty[0] {
            0 => {
                let mut b = [0u8; 19]; // SetPixelFormat
                sock.read_exact(&mut b).await?;
            }
            2 => {
                let mut b = [0u8; 3]; // SetEncodings: pad + count
                sock.read_exact(&mut b).await?;
                let n = u16::from_be_bytes([b[1], b[2]]) as usize;
                let mut enc = vec![0u8; n * 4];
                sock.read_exact(&mut enc).await?;
                // DesktopSize pseudo-encoding (-223) = the client can be told about resizes.
                if enc.chunks_exact(4).any(|c| c == [0xFF, 0xFF, 0xFF, 0x21]) {
                    desktopsize = true;
                }
            }
            3 => {
                let mut b = [0u8; 9]; // FramebufferUpdateRequest
                sock.read_exact(&mut b).await?;
                send_update(&mut sock, &shared, &mut last_gen, &mut last_dims, desktopsize).await?;
            }
            4 => {
                let mut b = [0u8; 7]; // KeyEvent: down(1)+pad(2)+keysym(4)
                sock.read_exact(&mut b).await?;
                let down = b[0] != 0;
                let keysym = u32::from_be_bytes([b[3], b[4], b[5], b[6]]);
                // send (not try_send): never drop a key event — a lost key-up sticks a key.
                let _ = input.send(Input::Key { down, keysym }).await;
            }
            5 => {
                let mut b = [0u8; 5]; // PointerEvent: buttons(1)+x(2)+y(2)
                sock.read_exact(&mut b).await?;
                let _ = input
                    .send(Input::Pointer {
                        buttons: b[0],
                        x: u16::from_be_bytes([b[1], b[2]]),
                        y: u16::from_be_bytes([b[3], b[4]]),
                    })
                    .await;
            }
            6 => {
                let mut hdr = [0u8; 7]; // ClientCutText: pad(3) + length(4)
                sock.read_exact(&mut hdr).await?;
                let raw_len = i32::from_be_bytes([hdr[3], hdr[4], hdr[5], hdr[6]]);
                let n = raw_len.unsigned_abs() as usize;
                if n > 1 << 20 {
                    anyhow::bail!("implausible ClientCutText length {n}");
                }
                let mut text = vec![0u8; n];
                sock.read_exact(&mut text).await?;
                // Basic ClientCutText (positive length) is Latin-1 text the user pasted; type it
                // into the guest. The extended-clipboard format uses a negative length and a
                // different layout, which we don't advertise, so it is consumed and ignored.
                if raw_len > 0 {
                    paste_text(&text, &input).await;
                }
            }
            other => anyhow::bail!("unknown RFB client message {other}"),
        }
    }
}

/// Type pasted clipboard text into the guest as keystrokes (the iDRAC carries only keyboard and
/// mouse, so paste is synthesized typing). Latin-1 printables map to their keysym; the existing
/// input path adds Shift where needed. Paced so the guest registers each key rather than
/// coalescing a burst into dropped characters.
async fn paste_text(text: &[u8], input: &mpsc::Sender<Input>) {
    for &c in text {
        let Some(keysym) = paste_keysym(c) else { continue };
        if input.send(Input::Key { down: true, keysym }).await.is_err() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(8)).await;
        if input.send(Input::Key { down: false, keysym }).await.is_err() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(8)).await;
    }
}

/// A Latin-1 clipboard byte mapped to its X11 keysym, or `None` for control bytes we skip.
/// Downstream `send_input` turns the keysym into a HID usage and synthesizes Shift as needed.
fn paste_keysym(c: u8) -> Option<u32> {
    match c {
        b'\n' | b'\r' => Some(0xFF0D),               // Return
        b'\t' => Some(0xFF09),                       // Tab
        0x20..=0x7E | 0xA0..=0xFF => Some(c as u32), // printable Latin-1: keysym == codepoint
        _ => None,
    }
}

fn server_init(w: u16, h: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(24 + 10);
    v.extend_from_slice(&w.to_be_bytes());
    v.extend_from_slice(&h.to_be_bytes());
    // PixelFormat: 32bpp, depth 24, little-endian, true-colour, RGB in shifts 16/8/0.
    v.extend_from_slice(&[32, 24, 0, 1]);
    v.extend_from_slice(&255u16.to_be_bytes()); // red-max
    v.extend_from_slice(&255u16.to_be_bytes()); // green-max
    v.extend_from_slice(&255u16.to_be_bytes()); // blue-max
    v.extend_from_slice(&[16, 8, 0, 0, 0, 0]); // shifts + padding
    let name = b"idrac6-kvm";
    v.extend_from_slice(&(name.len() as u32).to_be_bytes());
    v.extend_from_slice(name);
    v
}

/// A framebuffer update: nothing changed, a resolution change (DesktopSize + full frame), or one
/// changed rectangle.
enum Update {
    Empty,
    Resize { w: u16, h: u16, pixels: Vec<u32> },
    Rect { x: u16, y: u16, w: u16, h: u16, pixels: Vec<u32> },
}

/// Append a rectangle header (x, y, w, h, encoding), all big-endian.
fn push_rect(msg: &mut Vec<u8>, x: u16, y: u16, w: u16, h: u16, encoding: i32) {
    msg.extend_from_slice(&x.to_be_bytes());
    msg.extend_from_slice(&y.to_be_bytes());
    msg.extend_from_slice(&w.to_be_bytes());
    msg.extend_from_slice(&h.to_be_bytes());
    msg.extend_from_slice(&encoding.to_be_bytes());
}

/// Send a FramebufferUpdate. Waits briefly for a new frame, then sends only the changed row-band
/// (the whole framebuffer on the first update). When the framebuffer resized and the client
/// advertised DesktopSize (-223), prefix a DesktopSize pseudo-rect so it re-sizes; an empty update
/// if nothing changed.
async fn send_update<S: AsyncWrite + Unpin>(
    sock: &mut S,
    shared: &SharedFb,
    last_gen: &mut u64,
    last_dims: &mut (u16, u16),
    desktopsize: bool,
) -> Result<()> {
    // Wait up to ~1s for a new frame so idle clients don't busy-loop.
    let mut waited = 0;
    loop {
        if shared.lock().unwrap().generation != *last_gen {
            break;
        }
        if waited >= 1000 {
            sock.write_all(&[0u8, 0, 0, 0]).await?;
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(15)).await;
        waited += 15;
    }

    let update = {
        // First update after connect must paint the whole screen; afterwards only the damage.
        let first = *last_gen == u64::MAX;
        let mut g = shared.lock().unwrap();
        *last_gen = g.generation;
        let (fw, fh) = (g.fb.width as u16, g.fb.height as u16);
        let width = g.fb.width as usize;
        let len = g.fb.pixels.len();
        if width == 0 || len == 0 {
            Update::Empty
        } else if desktopsize && (fw, fh) != *last_dims {
            // Resolution changed: announce the new size and repaint the whole (new) frame.
            *last_dims = (fw, fh);
            g.take_dirty();
            Update::Resize { w: fw, h: fh, pixels: g.fb.pixels.clone() }
        } else {
            let range = if first { None } else { g.take_dirty() };
            match range {
                Some((lo, hi)) if hi > lo && hi <= len => {
                    let (y0, y1) = (lo / width, (hi - 1) / width);
                    let pixels = g.fb.pixels[y0 * width..(y1 + 1) * width].to_vec();
                    Update::Rect { x: 0, y: y0 as u16, w: fw, h: (y1 - y0 + 1) as u16, pixels }
                }
                // First update, or damage already consumed by another viewer: send full frame.
                _ => Update::Rect { x: 0, y: 0, w: fw, h: fh, pixels: g.fb.pixels.clone() },
            }
        }
    };

    let mut msg = Vec::new();
    match update {
        Update::Empty => {
            sock.write_all(&[0u8, 0, 0, 0]).await?;
            return Ok(());
        }
        Update::Resize { w, h, pixels } => {
            msg.reserve(28 + pixels.len() * 4);
            msg.extend_from_slice(&[0u8, 0]); // FramebufferUpdate + padding
            msg.extend_from_slice(&2u16.to_be_bytes()); // 2 rectangles
            push_rect(&mut msg, 0, 0, w, h, -223); // DesktopSize pseudo-rect
            push_rect(&mut msg, 0, 0, w, h, 0); // full Raw frame at the new size
            for px in &pixels {
                msg.extend_from_slice(&px.to_le_bytes());
            }
        }
        Update::Rect { x, y, w, h, pixels } => {
            msg.reserve(16 + pixels.len() * 4);
            msg.extend_from_slice(&[0u8, 0]);
            msg.extend_from_slice(&1u16.to_be_bytes());
            push_rect(&mut msg, x, y, w, h, 0); // Raw
            for px in &pixels {
                msg.extend_from_slice(&px.to_le_bytes()); // 0xFFRRGGBB -> [B,G,R,FF]
            }
        }
    }
    sock.write_all(&msg).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{paste_keysym, serve_conn};
    use crate::video::Framebuffer;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    #[test]
    fn paste_keysym_maps_printables_and_specials() {
        assert_eq!(paste_keysym(b'P'), Some(0x50)); // upper -> keysym (Shift added downstream)
        assert_eq!(paste_keysym(b'a'), Some(0x61));
        assert_eq!(paste_keysym(b'9'), Some(0x39));
        assert_eq!(paste_keysym(b'!'), Some(0x21));
        assert_eq!(paste_keysym(b'\n'), Some(0xFF0D));
        assert_eq!(paste_keysym(b'\r'), Some(0xFF0D));
        assert_eq!(paste_keysym(b'\t'), Some(0xFF09));
        assert_eq!(paste_keysym(0x00), None);
        assert_eq!(paste_keysym(0x7F), None);
    }

    async fn fbu_rects(c: &mut DuplexStream) -> u16 {
        let mut h = [0u8; 4];
        c.read_exact(&mut h).await.unwrap();
        assert_eq!(h[0], 0); // FramebufferUpdate
        u16::from_be_bytes([h[2], h[3]])
    }

    /// Read a rectangle header, returning (w, h, encoding), and skip any Raw pixel data.
    async fn rect(c: &mut DuplexStream) -> (u16, u16, i32) {
        let mut r = [0u8; 12];
        c.read_exact(&mut r).await.unwrap();
        let (w, h) = (u16::from_be_bytes([r[4], r[5]]), u16::from_be_bytes([r[6], r[7]]));
        let enc = i32::from_be_bytes([r[8], r[9], r[10], r[11]]);
        if enc == 0 {
            let mut px = vec![0u8; w as usize * h as usize * 4];
            c.read_exact(&mut px).await.unwrap();
        }
        (w, h, enc)
    }

    #[tokio::test]
    async fn desktopsize_announced_on_resolution_change() {
        let shared = crate::kvm::shared(4, 2);
        let (tx, _rx) = tokio::sync::mpsc::channel::<crate::kvm::Input>(4);
        let (mut c, server_end) = tokio::io::duplex(1 << 16);
        let srv = tokio::spawn(serve_conn(server_end, shared.clone(), tx));

        // RFB 3.8 handshake.
        let mut buf = [0u8; 12];
        c.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"RFB 003.008\n");
        c.write_all(b"RFB 003.008\n").await.unwrap();
        c.read_exact(&mut [0u8; 2]).await.unwrap(); // security types
        c.write_all(&[1]).await.unwrap(); // choose None
        c.read_exact(&mut [0u8; 4]).await.unwrap(); // SecurityResult
        c.write_all(&[1]).await.unwrap(); // ClientInit
        let mut init = [0u8; 24];
        c.read_exact(&mut init).await.unwrap();
        assert_eq!((init[0], init[1], init[2], init[3]), (0, 4, 0, 2)); // 4x2
        let namelen = u32::from_be_bytes([init[20], init[21], init[22], init[23]]) as usize;
        c.read_exact(&mut vec![0u8; namelen]).await.unwrap();

        // Advertise DesktopSize (-223).
        c.write_all(&[2, 0, 0, 1]).await.unwrap();
        c.write_all(&(-223i32).to_be_bytes()).await.unwrap();

        // First update is the full 4x2 frame.
        c.write_all(&[3, 0, 0, 0, 0, 0, 0, 4, 0, 2]).await.unwrap();
        assert_eq!(fbu_rects(&mut c).await, 1);
        assert_eq!(rect(&mut c).await, (4, 2, 0));

        // The guest changes resolution to 6x3.
        {
            let mut g = shared.lock().unwrap();
            g.fb = Framebuffer::new(6, 3);
            g.generation += 1;
        }

        // The next update announces the resize and repaints at the new size.
        c.write_all(&[3, 0, 0, 0, 0, 0, 0, 4, 0, 2]).await.unwrap();
        assert_eq!(fbu_rects(&mut c).await, 2, "resize update carries DesktopSize + frame");
        assert_eq!(rect(&mut c).await, (6, 3, -223), "first rect is DesktopSize at the new size");
        assert_eq!(rect(&mut c).await, (6, 3, 0), "second rect is the full frame at the new size");

        srv.abort();
    }
}
