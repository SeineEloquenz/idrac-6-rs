//! iDRAC 6 `hb` (0x0081) video codec, ported from `com/avocent/kvm/d/b.java` (RLE driver)
//! and `com/avocent/kvm/d/c.java` (RGB555 literals). It is byte-oriented over a linear
//! framebuffer cursor, not the block-JPEG path (the separate `gb` codec).
//!
//! Each op is the top 3 bits of a byte. The low 5 bits start a run length that extends across
//! following bytes sharing the same op (`run`). The ops are:
//!   000 skip (leave prev-frame pixels)      010 copy `run` pixels from one row above
//!   001 repeat the left pixel `run` times    011 two-colour pattern
//!   1xx literal pixel (RGB555, 2 bytes)
//! The framebuffer persists across frames. The cursor resets to 0 each frame, and `skip`
//! advances it to the changed region.

use super::Framebuffer;
use std::ops::Range;

/// RGB555 (0bRRRRRGGGGGBBBBB) -> 0xFFRRGGBB, matching d/c.java's LUT.
#[inline]
fn rgb555(c15: u16) -> u32 {
    let r = ((c15 & 0x7C00) >> 7) as u32;
    let g = ((c15 & 0x03E0) >> 2) as u32;
    let b = ((c15 & 0x001F) << 3) as u32;
    0xFF00_0000 | (r << 16) | (g << 8) | b
}

pub struct Decoder {
    width: usize,
    cursor: usize,
}

impl Decoder {
    pub fn new(width: u32, _height: u32) -> Self {
        Self {
            width: width as usize,
            cursor: 0,
        }
    }

    /// Decode one frame payload into `fb` (persistent across frames). Returns the op count and
    /// the changed pixel span as a half-open linear index range (`None` if nothing was written).
    /// `skip` advances the cursor without writing, so the span bounds the actual damage.
    pub fn decode_frame(
        &mut self,
        p: &[u8],
        fb: &mut Framebuffer,
    ) -> (usize, Option<Range<usize>>) {
        self.cursor = 0;
        let len = fb.pixels.len();
        let mut o = 0usize;
        let mut ops = 0usize;
        let (mut dmin, mut dmax) = (usize::MAX, 0usize);

        // Variable-length run: low 5 bits of the op byte, extended by up to 4 following
        // bytes that share the same top-3-bit op tag.
        let run = |p: &[u8], o: &mut usize, by: u8| -> usize {
            let tag = by & 0xE0;
            let mut n = (by & 0x1F) as usize;
            let mut k = 1;
            while k < 5 && *o < p.len() && (p[*o] & 0xE0) == tag {
                n |= ((p[*o] & 0x1F) as usize) << (5 * k);
                *o += 1;
                k += 1;
            }
            n
        };

        while o < p.len() {
            let by = p[o];
            o += 1;
            ops += 1;
            let cur_before = self.cursor;
            match by & 0xE0 {
                0x00 => {
                    // skip: advance cursor, keep previous-frame pixels
                    self.cursor = (self.cursor + run(p, &mut o, by)).min(len);
                }
                0x20 => {
                    // repeat the pixel to the left
                    let n = run(p, &mut o, by);
                    let color = if self.cursor > 0 {
                        fb.pixels[self.cursor - 1]
                    } else {
                        0xFF00_0000
                    };
                    let end = (self.cursor + n).min(len);
                    fb.pixels[self.cursor..end].fill(color);
                    self.cursor = end;
                }
                0x40 => {
                    // copy from one row up
                    let n = run(p, &mut o, by);
                    if self.cursor >= self.width {
                        let src = self.cursor - self.width;
                        for k in 0..n {
                            if self.cursor + k >= len {
                                break;
                            }
                            fb.pixels[self.cursor + k] = fb.pixels[src + k];
                        }
                    }
                    self.cursor = (self.cursor + n).min(len);
                }
                0x60 => self.pattern(p, &mut o, by, fb),
                _ => {
                    // literal RGB555: 7 low bits + next byte
                    if by & 0x80 != 0 && o < p.len() {
                        let c15 = (((by & 0x7F) as u16) << 8) | p[o] as u16;
                        o += 1;
                        if self.cursor < len {
                            fb.pixels[self.cursor] = rgb555(c15);
                        }
                        self.cursor += 1;
                    }
                }
            }
            // Literal and pattern ops advance the cursor without a length check; clamp it so a
            // crafted frame can't run it past the end and panic the next op's indexing.
            self.cursor = self.cursor.min(len);
            // Anything but `skip` (0x00) wrote pixels in [cur_before, cursor).
            if by & 0xE0 != 0x00 {
                dmin = dmin.min(cur_before);
                dmax = dmax.max(self.cursor);
            }
        }
        let dirty = (dmax > dmin).then_some(dmin..dmax);
        (ops, dirty)
    }

    /// Two-colour pattern fill (f() in d/b.java). Emits 4 pixels from the op byte's low nibble,
    /// then, if bit4 is set, 7 pixels per following byte while bit7 stays set. Colour `a` is the
    /// left pixel, `b` the most recent different pixel.
    fn pattern(&mut self, p: &[u8], o: &mut usize, first: u8, fb: &mut Framebuffer) {
        let len = fb.pixels.len();
        let a = if self.cursor > 0 {
            fb.pixels[self.cursor - 1]
        } else {
            0xFF00_0000
        };
        let mut b = a;
        let start = self.cursor.min(len).saturating_sub(1);
        for i in (0..=start).rev() {
            if fb.pixels[i] != a {
                b = fb.pixels[i];
                break;
            }
        }
        let put = |fb: &mut Framebuffer, cur: &mut usize, color: u32| {
            if *cur < len {
                fb.pixels[*cur] = color;
            }
            *cur += 1;
        };
        for bit in [0x08u8, 0x04, 0x02, 0x01] {
            put(fb, &mut self.cursor, if first & bit != 0 { b } else { a });
        }
        if first & 0x10 != 0 {
            loop {
                if *o >= p.len() {
                    break;
                }
                let by = p[*o];
                *o += 1;
                for bit in [0x40u8, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01] {
                    put(fb, &mut self.cursor, if by & bit != 0 { b } else { a });
                }
                if by & 0x80 == 0 {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dirty_span_covers_only_written_pixels() {
        let mut fb = Framebuffer::new(8, 4); // 32 pixels
        let mut dec = Decoder::new(8, 4);
        // skip 5, then 3 white RGB555 literals -> damage is exactly [5, 8).
        let payload = [0x05u8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let (_, dirty) = dec.decode_frame(&payload, &mut fb);
        assert_eq!(dirty, Some(5..8));
    }

    #[test]
    fn skip_only_frame_is_not_dirty() {
        let mut fb = Framebuffer::new(8, 4);
        let mut dec = Decoder::new(8, 4);
        let (_, dirty) = dec.decode_frame(&[0x1F], &mut fb); // skip 31, no writes
        assert_eq!(dirty, None);
    }

    #[test]
    fn cursor_overrun_frame_does_not_panic() {
        let mut fb = Framebuffer::new(8, 4); // 32 pixels
        let mut dec = Decoder::new(8, 4);
        // Literals past the end (each 0x80,0x00) followed by a repeat op previously ran the cursor
        // beyond len and panicked on the next op's indexing.
        let mut payload = [0x80u8, 0x00].repeat(40);
        payload.push(0x21);
        let _ = dec.decode_frame(&payload, &mut fb);
    }
}
