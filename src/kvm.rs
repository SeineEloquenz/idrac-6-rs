//! Live KVM session: connect + authenticate, then decode the ch2 video stream into a shared
//! framebuffer while pumping frame requests and forwarding input.

use std::sync::{Arc, Mutex};

use anyhow::{bail, Result};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::apcp::{self, ConnKind};
use crate::auth;
use crate::video::{decoder::Decoder, Framebuffer};

/// Shared framebuffer with a generation counter bumped on every decoded frame and the union of
/// changed pixel ranges (half-open linear indices) since a client last consumed them.
pub struct FbState {
    pub fb: Framebuffer,
    pub generation: u64,
    dirty: Option<(usize, usize)>,
}

impl FbState {
    /// Union a decoded frame's changed span into the pending damage.
    pub fn mark_dirty(&mut self, (lo, hi): (usize, usize)) {
        self.dirty = Some(match self.dirty {
            Some((a, b)) => (a.min(lo), b.max(hi)),
            None => (lo, hi),
        });
    }

    /// Take and clear the pending damage span.
    pub fn take_dirty(&mut self) -> Option<(usize, usize)> {
        self.dirty.take()
    }
}

pub type SharedFb = Arc<Mutex<FbState>>;

pub fn shared(width: u32, height: u32) -> SharedFb {
    Arc::new(Mutex::new(FbState { fb: Framebuffer::new(width, height), generation: 0, dirty: None }))
}

/// Input events from the RFB layer, translated to APCP on the KVM channel.
#[derive(Debug, Clone, Copy)]
pub enum Input {
    /// Character-level key (RFB `KeyEvent`): mapped to a HID usage assuming a US guest layout,
    /// synthesizing Shift for characters a virtual keyboard sends without it.
    Key { down: bool, keysym: u32 },
    Pointer { buttons: u8, x: u16, y: u16 },
}

/// Run the KVM session until the connection drops. Decodes video into `shared`.
pub async fn run(s: auth::Session, shared: SharedFb, mut input_rx: mpsc::Receiver<Input>) -> Result<()> {
    info!(host = %s.host, "connecting KVM session");
    let (mut ch1, _) = apcp::open_channel(&s.host, s.video_port, ConnKind::Primary, false).await?;
    let c = auth::send_login(&mut ch1, &s.user, &s.password, true).await?;
    let (rd1, wr1) = tokio::io::split(ch1);
    let mut rd1 = rd1;

    // Wait for login success.
    loop {
        let pkt = tokio::time::timeout(std::time::Duration::from_secs(10), apcp::read_packet(&mut rd1))
            .await
            .map_err(|_| anyhow::anyhow!("timeout waiting for login response"))??;
        if pkt.kind == 0x8305 || pkt.kind == 0x8300 {
            match pkt.body.first() {
                Some(0) => break,
                other => bail!("KVM login rejected (status {other:?})"),
            }
        }
    }
    info!("login ok; opening media channel");
    let (mut ch2, _) = apcp::open_channel(&s.host, s.kvm_port, ConnKind::Secondary, false).await?;
    apcp::send_link(&mut ch2, c, 0).await?;
    let (rd2, mut wr2) = tokio::io::split(ch2);
    let mut rd2 = rd2;

    let (tx, mut rx) = mpsc::channel::<(&'static str, apcp::Packet)>(256);
    let tx1 = tx.clone();
    tokio::spawn(async move {
        while let Ok(p) = apcp::read_packet(&mut rd1).await {
            if tx1.send(("ch1", p)).await.is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        while let Ok(p) = apcp::read_packet(&mut rd2).await {
            if tx.send(("ch2", p)).await.is_err() {
                break;
            }
        }
    });

    // Input + keep-alive run on their own task so key make/break are never delayed by video
    // decode (delayed breaks stick keys -> autorepeat, and interleaving corrupts modifiers).
    let wr1 = std::sync::Arc::new(tokio::sync::Mutex::new(wr1));
    let wr1_io = wr1.clone();
    tokio::spawn(async move {
        let mut keepalive = tokio::time::interval(std::time::Duration::from_secs(2));
        let mut mods = Mods::default();
        loop {
            tokio::select! {
                _ = keepalive.tick() => {
                    let mut w = wr1_io.lock().await;
                    let _ = apcp::write_packet(&mut *w, 1024, &[0u8; 8]).await; // `p` keep-alive
                }
                ev = input_rx.recv() => match ev {
                    None => break,
                    Some(input) => {
                        let mut w = wr1_io.lock().await;
                        let _ = send_input(&mut *w, input, &mut mods).await;
                    }
                }
            }
        }
    });

    // Video loop: decode ch2 frames into the shared framebuffer, ack flow control on ch2, and
    // drive the ch1 config reactions.
    let mut dec: Option<Decoder> = None;
    let mut frame: Vec<u8> = Vec::new();
    let mut dims = (0u16, 0u16);
    let mut frames_decoded = 0u64;
    let mut hb_count = 0u32; // media packets since last flow-control ack (W = 20)

    while let Some((_chan, pkt)) = rx.recv().await {
        match pkt.kind {
            0x0084 => {
                let mut w = wr1.lock().await;
                apcp::send_video_start(&mut *w, 1024, 768).await.ok();
            }
            0x8201 => {
                let mut w = wr1.lock().await;
                apcp::send_resolution_ack(&mut *w).await.ok();
            }
            0x0081 => {
                hb_count += 1;
                if hb_count >= 20 {
                    apcp::send_frame_ack(&mut wr2, hb_count as u8).await.ok();
                    hb_count = 0;
                }
                let b = &pkt.body;
                if b.len() >= 12 && &b[0..4] == b"\xde\xad\xbe\xef" {
                    let flags = b[8];
                    if flags & 1 != 0 {
                        frame.clear();
                        dims = (u16::from_be_bytes([b[6], b[7]]), u16::from_be_bytes([b[4], b[5]]));
                    }
                    frame.extend_from_slice(&b[12..]);
                    if flags & 2 != 0 && dims.0 > 0 && dims.1 > 0 {
                        let (w, h) = (dims.0 as u32, dims.1 as u32);
                        {
                            let mut g = shared.lock().unwrap();
                            if g.fb.width != w || g.fb.height != h {
                                g.fb = Framebuffer::new(w, h);
                                dec = Some(Decoder::new(w, h));
                            }
                            let d = dec.get_or_insert_with(|| Decoder::new(w, h));
                            let (_, dirty) = d.decode_frame(&frame, &mut g.fb);
                            // Only advance the generation on real damage, so a no-op frame never
                            // wakes a client into the empty-dirty full-frame fallback.
                            if let Some(r) = dirty {
                                g.mark_dirty(r);
                                g.generation = g.generation.wrapping_add(1);
                            }
                        }
                        frames_decoded += 1;
                        if frames_decoded.is_multiple_of(300) {
                            info!(frames_decoded, "video frames decoded");
                        }
                        frame.clear();
                    }
                }
            }
            _ => {}
        }
    }
    warn!("KVM channels closed");
    Ok(())
}

/// Keyboard modifier state carried across input events, so Shift synthesized for a shifted
/// character is not doubled when the client already holds Shift itself.
#[derive(Default)]
struct Mods {
    client_shift: bool,
}

/// Translate an RFB input event to its APCP packet (sent on the control channel).
/// Keyboard = packet type 512 (`f`): [0, down?0:1, hidHi, hidLo, 0,0,0,0].
/// Mouse    = packet type 513 (`gc`): [0, buttons, xHi, xLo, yHi, yLo, 0, 0], absolute coords.
async fn send_input<S: tokio::io::AsyncWrite + Unpin>(s: &mut S, ev: Input, mods: &mut Mods) -> Result<()> {
    match ev {
        Input::Key { down, keysym } => {
            if keysym == 0xFFE1 || keysym == 0xFFE2 {
                mods.client_shift = down;
            }
            match keysym_to_hid(keysym) {
                Some((hid, needs_shift)) => {
                    let synth = needs_shift && !mods.client_shift;
                    debug!(down, keysym = format!("{keysym:#x}"), hid = format!("{hid:#x}"), synth, "key -> APCP 512");
                    if down {
                        if synth {
                            send_key_hid(s, true, 0xE1).await?; // Shift_L down
                        }
                        send_key_hid(s, true, hid).await?;
                    } else {
                        send_key_hid(s, false, hid).await?;
                        if synth {
                            send_key_hid(s, false, 0xE1).await?; // Shift_L up
                        }
                    }
                }
                None => debug!(keysym = format!("{keysym:#x}"), "key unmapped"),
            }
        }
        Input::Pointer { buttons, x, y } => {
            debug!(buttons, x, y, "pointer -> APCP 513");
            let mut b = 0u8;
            if buttons & 0x01 != 0 {
                b |= 0x01; // left
            }
            if buttons & 0x02 != 0 {
                b |= 0x04; // middle
            }
            if buttons & 0x04 != 0 {
                b |= 0x02; // right
            }
            let body = [0, b, (x >> 8) as u8, x as u8, (y >> 8) as u8, y as u8, 0, 0];
            apcp::write_packet(s, 513, &body).await?;
        }
    }
    Ok(())
}

/// Map an X11 keysym to (USB HID usage, needs_shift) for a US guest layout. `needs_shift` is
/// true for characters that require Shift on US (uppercase, `!@#`, `_+{}|:"<>?~`); the caller
/// synthesizes Shift so virtual (mobile) keyboards, which send the character without a Shift
/// event, still produce the right symbol.
fn keysym_to_hid(ks: u32) -> Option<(u16, bool)> {
    let out: (u16, bool) = match ks {
        0x61..=0x7A => (0x04 + (ks - 0x61) as u16, false), // a-z
        0x41..=0x5A => (0x04 + (ks - 0x41) as u16, true),  // A-Z
        0x31..=0x39 => (0x1E + (ks - 0x31) as u16, false), // 1-9
        0x30 => (0x27, false),                             // 0
        0xFF0D => (0x28, false),                           // Return
        0xFF1B => (0x29, false),                           // Escape
        0xFF08 => (0x2A, false),                           // Backspace
        0xFF09 => (0x2B, false),                           // Tab
        0x20 => (0x2C, false),                             // Space
        0x2D => (0x2D, false),                             // -
        0x5F => (0x2D, true),                              // _
        0x3D => (0x2E, false),                             // =
        0x2B => (0x2E, true),                              // +
        0x5B => (0x2F, false),                             // [
        0x7B => (0x2F, true),                              // {
        0x5D => (0x30, false),                             // ]
        0x7D => (0x30, true),                              // }
        0x5C => (0x31, false),                             // \
        0x7C => (0x31, true),                              // |
        0x3B => (0x33, false),                             // ;
        0x3A => (0x33, true),                              // :
        0x27 => (0x34, false),                             // '
        0x22 => (0x34, true),                              // "
        0x60 => (0x35, false),                             // `
        0x7E => (0x35, true),                              // ~
        0x2C => (0x36, false),                             // ,
        0x3C => (0x36, true),                              // <
        0x2E => (0x37, false),                             // .
        0x3E => (0x37, true),                              // >
        0x2F => (0x38, false),                             // /
        0x3F => (0x38, true),                              // ?
        0x21 => (0x1E, true),                              // !
        0x40 => (0x1F, true),                              // @
        0x23 => (0x20, true),                              // #
        0x24 => (0x21, true),                              // $
        0x25 => (0x22, true),                              // %
        0x5E => (0x23, true),                              // ^
        0x26 => (0x24, true),                              // &
        0x2A => (0x25, true),                              // *
        0x28 => (0x26, true),                              // (
        0x29 => (0x27, true),                              // )
        0xFFBE..=0xFFC9 => (0x3A + (ks - 0xFFBE) as u16, false), // F1-F12
        0xFF50 => (0x4A, false),                           // Home
        0xFF57 => (0x4D, false),                           // End
        0xFF55 => (0x4B, false),                           // PageUp
        0xFF56 => (0x4E, false),                           // PageDown
        0xFF63 => (0x49, false),                           // Insert
        0xFFFF => (0x4C, false),                           // Delete
        0xFF51 => (0x50, false),                           // Left
        0xFF53 => (0x4F, false),                           // Right
        0xFF52 => (0x52, false),                           // Up
        0xFF54 => (0x51, false),                           // Down
        0xFFE1 => (0xE1, false),                           // Shift_L
        0xFFE2 => (0xE5, false),                           // Shift_R
        0xFFE3 => (0xE0, false),                           // Control_L
        0xFFE4 => (0xE4, false),                           // Control_R
        0xFFE9 => (0xE2, false),                           // Alt_L
        0xFFEA => (0xE6, false),                           // Alt_R
        0xFFEB | 0xFFEC => (0xE3, false),                  // Super
        0xFFE5 => (0x39, false),                           // CapsLock
        _ => return None,
    };
    Some(out)
}

async fn send_key_hid<S: tokio::io::AsyncWrite + Unpin>(s: &mut S, down: bool, hid: u16) -> Result<()> {
    let body = [0, if down { 0 } else { 1 }, (hid >> 8) as u8, hid as u8, 0, 0, 0, 0];
    apcp::write_packet(s, 512, &body).await
}

/// Convenience wrapper used by `serve`/`web`: build the shared fb, spawn the session, hand back
/// the shared fb, an input sender, and the task handle (abort it to drop the KVM connection).
pub fn spawn(session: auth::Session) -> (SharedFb, mpsc::Sender<Input>, tokio::task::JoinHandle<()>) {
    let shared = shared(1024, 768);
    let (tx, rx) = mpsc::channel(256);
    let fb = shared.clone();
    let handle = tokio::spawn(async move {
        if let Err(e) = run(session, fb, rx).await {
            warn!("KVM session ended: {e:#}");
        }
    });
    (shared, tx, handle)
}

#[cfg(test)]
mod tests {
    use super::{keysym_to_hid, send_input, Input, Mods};
    use tokio::io::AsyncReadExt;

    /// Parse consecutive 16-byte APCP key packets into (down, hid) pairs.
    fn key_events(buf: &[u8]) -> Vec<(bool, u16)> {
        buf.chunks_exact(16)
            .map(|p| (p[9] == 0, u16::from_be_bytes([p[10], p[11]])))
            .collect()
    }

    #[tokio::test]
    async fn shifted_char_synthesizes_shift() {
        let (mut w, mut r) = tokio::io::duplex(1024);
        let mut mods = Mods::default();
        // '!' press then release. Shift (0xE1) must wrap the '1' key (0x1E).
        send_input(&mut w, Input::Key { down: true, keysym: 0x21 }, &mut mods).await.unwrap();
        send_input(&mut w, Input::Key { down: false, keysym: 0x21 }, &mut mods).await.unwrap();
        let mut buf = [0u8; 64];
        r.read_exact(&mut buf).await.unwrap();
        assert_eq!(
            key_events(&buf),
            vec![(true, 0xE1), (true, 0x1E), (false, 0x1E), (false, 0xE1)],
        );
    }

    #[tokio::test]
    async fn client_held_shift_is_not_doubled() {
        let (mut w, mut r) = tokio::io::duplex(1024);
        let mut mods = Mods::default();
        // Client presses Shift itself, then 'A' (0x41). No synthesized Shift should be added.
        send_input(&mut w, Input::Key { down: true, keysym: 0xFFE1 }, &mut mods).await.unwrap();
        send_input(&mut w, Input::Key { down: true, keysym: 0x41 }, &mut mods).await.unwrap();
        send_input(&mut w, Input::Key { down: false, keysym: 0x41 }, &mut mods).await.unwrap();
        let mut buf = [0u8; 48];
        r.read_exact(&mut buf).await.unwrap();
        assert_eq!(key_events(&buf), vec![(true, 0xE1), (true, 0x04), (false, 0x04)]);
    }

    #[test]
    fn keysym_maps_characters_with_shift() {
        assert_eq!(keysym_to_hid(0x61), Some((0x04, false))); // 'a'
        assert_eq!(keysym_to_hid(0x41), Some((0x04, true))); // 'A' needs shift
        assert_eq!(keysym_to_hid(0xFF0D), Some((0x28, false))); // Return
        assert_eq!(keysym_to_hid(0x21), Some((0x1E, true))); // '!' = Shift+1
        assert_eq!(keysym_to_hid(0x5F), Some((0x2D, true))); // '_' = Shift+-
        assert_eq!(keysym_to_hid(0x2D), Some((0x2D, false))); // '-' unshifted
    }
}
