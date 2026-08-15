//! Reassembly of `hb` (0x0081) video fragments into whole frames. Each fragment body is
//! `deadbeef` + height(2 BE) + width(2 BE) + flags(first/last) + reserved + optional trailer,
//! then the compressed payload from offset 12. Fragments from a first-flagged one up to the next
//! last-flagged one make one frame.

const MAGIC: &[u8; 4] = b"\xde\xad\xbe\xef";
const HEADER_LEN: usize = 12;
const FLAG_FIRST: u8 = 1;
const FLAG_LAST: u8 = 2;

/// A frame's pixel dimensions, named so width and height can't be transposed.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Resolution {
    pub width: u16,
    pub height: u16,
}

/// One parsed `hb` fragment: its frame resolution, first/last flags, and payload slice.
struct Fragment<'a> {
    resolution: Resolution,
    first: bool,
    last: bool,
    payload: &'a [u8],
}

impl<'a> Fragment<'a> {
    /// Parse a fragment body from the `deadbeef` magic. `None` if too short or mis-magicked.
    fn parse(body: &'a [u8]) -> Option<Self> {
        if body.len() < HEADER_LEN || &body[0..4] != MAGIC {
            return None;
        }
        let height = u16::from_be_bytes([body[4], body[5]]);
        let width = u16::from_be_bytes([body[6], body[7]]);
        let flags = body[8];
        Some(Fragment {
            resolution: Resolution { width, height },
            first: flags & FLAG_FIRST != 0,
            last: flags & FLAG_LAST != 0,
            payload: &body[HEADER_LEN..],
        })
    }
}

/// Accumulates `hb` fragment bodies into complete frames.
#[derive(Default)]
pub struct HbReassembler {
    frame: Vec<u8>,
    resolution: Resolution,
}

impl HbReassembler {
    /// Feed one fragment body. Returns the frame resolution and reassembled payload once a
    /// fragment carries the last-fragment flag, else `None`. Malformed fragments are ignored.
    pub fn push(&mut self, body: &[u8]) -> Option<(Resolution, &[u8])> {
        let frag = Fragment::parse(body)?;
        if frag.first {
            self.frame.clear();
            self.resolution = frag.resolution;
        }
        self.frame.extend_from_slice(frag.payload);
        if frag.last {
            Some((self.resolution, &self.frame))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_fragment_frame_carries_resolution() {
        let mut r = HbReassembler::default();
        // height=0x0300 (768), width=0x0400 (1024), flags=first|last, payload [0xAA, 0xBB].
        let body = [0xde, 0xad, 0xbe, 0xef, 0x03, 0x00, 0x04, 0x00, 0x03, 0, 0, 0, 0xAA, 0xBB];
        let (res, payload) = r.push(&body).expect("first|last fragment completes a frame");
        assert_eq!(res, Resolution { width: 1024, height: 768 });
        assert_eq!(payload, &[0xAA, 0xBB]);
    }

    #[test]
    fn fragments_reassemble_in_order() {
        let mut r = HbReassembler::default();
        let first = [0xde, 0xad, 0xbe, 0xef, 0, 4, 0, 8, FLAG_FIRST, 0, 0, 0, 1, 2];
        assert!(r.push(&first).is_none());
        let last = [0xde, 0xad, 0xbe, 0xef, 0, 4, 0, 8, FLAG_LAST, 0, 0, 0, 3, 4];
        let (res, payload) = r.push(&last).expect("last fragment completes the frame");
        assert_eq!(res, Resolution { width: 8, height: 4 });
        assert_eq!(payload, &[1, 2, 3, 4]);
    }

    #[test]
    fn malformed_fragment_is_ignored() {
        let mut r = HbReassembler::default();
        assert!(r.push(&[0, 1, 2]).is_none()); // too short
        assert!(r.push(&[0xaa; 14]).is_none()); // bad magic
    }
}
