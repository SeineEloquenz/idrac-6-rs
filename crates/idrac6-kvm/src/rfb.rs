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
            }
            3 => {
                let mut b = [0u8; 9]; // FramebufferUpdateRequest
                sock.read_exact(&mut b).await?;
                send_update(&mut sock, &shared, &mut last_gen).await?;
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

/// One Raw rectangle to send, or an empty update.
enum Update {
    Empty,
    Rect { x: u16, y: u16, w: u16, h: u16, pixels: Vec<u32> },
}

/// Send a FramebufferUpdate. Waits briefly for a new frame, then sends only the changed
/// row-band (the whole framebuffer on the first update); an empty update if nothing changed.
async fn send_update<S: AsyncWrite + Unpin>(sock: &mut S, shared: &SharedFb, last_gen: &mut u64) -> Result<()> {
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
        let width = g.fb.width as usize;
        let len = g.fb.pixels.len();
        let range = if first || width == 0 { None } else { g.take_dirty() };
        match range {
            Some((lo, hi)) if hi > lo && hi <= len => {
                let (y0, y1) = (lo / width, (hi - 1) / width);
                let pixels = g.fb.pixels[y0 * width..(y1 + 1) * width].to_vec();
                Update::Rect { x: 0, y: y0 as u16, w: width as u16, h: (y1 - y0 + 1) as u16, pixels }
            }
            _ if width == 0 => Update::Empty,
            _ => {
                // First update, or damage already consumed by another viewer: send full frame.
                let (w, h) = (g.fb.width as u16, g.fb.height as u16);
                Update::Rect { x: 0, y: 0, w, h, pixels: g.fb.pixels.clone() }
            }
        }
    };

    let Update::Rect { x, y, w, h, pixels } = update else {
        sock.write_all(&[0u8, 0, 0, 0]).await?;
        return Ok(());
    };
    let mut msg = Vec::with_capacity(16 + pixels.len() * 4);
    msg.extend_from_slice(&[0u8, 0]); // message-type 0 + padding
    msg.extend_from_slice(&1u16.to_be_bytes()); // number-of-rectangles
    msg.extend_from_slice(&x.to_be_bytes());
    msg.extend_from_slice(&y.to_be_bytes());
    msg.extend_from_slice(&w.to_be_bytes());
    msg.extend_from_slice(&h.to_be_bytes());
    msg.extend_from_slice(&0i32.to_be_bytes()); // encoding: Raw
    for px in &pixels {
        msg.extend_from_slice(&px.to_le_bytes()); // 0xFFRRGGBB -> [B,G,R,FF]
    }
    sock.write_all(&msg).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::paste_keysym;

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
}
