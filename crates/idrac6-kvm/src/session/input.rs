//! Input translation: RFB key/pointer events -> APCP keyboard (type 512) and mouse (type 513)
//! packets, via a US-layout keysym->HID map with Shift synthesis for virtual keyboards.

use anyhow::Result;
use tracing::debug;

use crate::appliance::apcp;

/// Input events from the RFB layer, translated to APCP on the KVM channel.
#[derive(Debug, Clone, Copy)]
pub enum Input {
    /// Character-level key (RFB `KeyEvent`): mapped to a HID usage assuming a US guest layout,
    /// synthesizing Shift for characters a virtual keyboard sends without it.
    Key { down: bool, keysym: u32 },
    Pointer { buttons: u8, x: u16, y: u16 },
}

/// Keyboard modifier state carried across input events, so Shift synthesized for a shifted
/// character is not doubled when the client already holds Shift itself.
#[derive(Default)]
pub(crate) struct Mods {
    client_shift: bool,
}

/// Translate an RFB input event to its APCP packet (sent on the control channel).
/// Keyboard = packet type 512 (`f`): [0, down?0:1, hidHi, hidLo, 0,0,0,0].
/// Mouse    = packet type 513 (`gc`): [0, buttons, xHi, xLo, yHi, yLo, 0, 0], absolute coords.
pub(crate) async fn send_input<S: tokio::io::AsyncWrite + Unpin>(s: &mut S, ev: Input, mods: &mut Mods) -> Result<()> {
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
            apcp::write_packet(s, apcp::PacketType::Pointer, &body).await?;
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
    apcp::write_packet(s, apcp::PacketType::Keyboard, &body).await
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
