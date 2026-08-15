//! Framebuffer-update wire encoding for the RFB server. Pixel-format conversion and Raw/Zlib
//! rectangle serialization. The protocol dispatch lives in the parent `rfb` module.

use anyhow::Result;
use flate2::{Compress, Compression, FlushCompress};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::session::kvm::SharedFb;

const ENC_RAW: i32 = 0;
const ENC_ZLIB: i32 = 6;

/// A client's persistent per-connection deflate stream (context kept across rectangles).
pub(super) type ZlibStream = Compress;

/// A fresh zlib stream for a client that advertised the Zlib (6) encoding.
pub(super) fn new_zlib() -> ZlibStream {
    Compress::new(Compression::default(), true)
}

/// The pixel layout the client wants for framebuffer data (from SetPixelFormat, else the
/// ServerInit default of 32bpp little-endian with RGB in shifts 16/8/0).
#[derive(Clone, Copy)]
pub(super) struct PixelFormat {
    bpp: u8,
    big_endian: bool,
    true_colour: bool,
    r_max: u16,
    g_max: u16,
    b_max: u16,
    r_shift: u8,
    g_shift: u8,
    b_shift: u8,
}

impl Default for PixelFormat {
    fn default() -> Self {
        PixelFormat {
            bpp: 32,
            big_endian: false,
            true_colour: true,
            r_max: 255,
            g_max: 255,
            b_max: 255,
            r_shift: 16,
            g_shift: 8,
            b_shift: 0,
        }
    }
}

impl PixelFormat {
    /// Parse the 16-byte PixelFormat structure (bpp, depth, big-endian, true-colour, maxes, shifts).
    pub(super) fn parse(b: &[u8]) -> Self {
        PixelFormat {
            bpp: b[0],
            big_endian: b[2] != 0,
            true_colour: b[3] != 0,
            r_max: u16::from_be_bytes([b[4], b[5]]),
            g_max: u16::from_be_bytes([b[6], b[7]]),
            b_max: u16::from_be_bytes([b[8], b[9]]),
            r_shift: b[10],
            g_shift: b[11],
            b_shift: b[12],
        }
    }

    /// Whether we can encode to this client format (true-colour 8/16/32bpp). Others keep the default.
    pub(super) fn acceptable(&self) -> bool {
        self.true_colour && matches!(self.bpp, 8 | 16 | 32)
    }

    /// Encode one `0xFFRRGGBB` pixel into this format and append its `bpp/8` bytes to `out`.
    fn push(&self, out: &mut Vec<u8>, px: u32) {
        let scale = |c: u32, max: u16| (c * max as u32 + 127) / 255;
        let value = (scale((px >> 16) & 0xff, self.r_max) << self.r_shift)
            | (scale((px >> 8) & 0xff, self.g_max) << self.g_shift)
            | (scale(px & 0xff, self.b_max) << self.b_shift);
        let n = (self.bpp as usize / 8).clamp(1, 4);
        if self.big_endian {
            for i in (0..n).rev() {
                out.push((value >> (8 * i)) as u8);
            }
        } else {
            for i in 0..n {
                out.push((value >> (8 * i)) as u8);
            }
        }
    }
}

/// A framebuffer update, either nothing changed, a resolution change (DesktopSize + full frame),
/// or one changed rectangle.
enum Update {
    Empty,
    Resize {
        w: u16,
        h: u16,
        pixels: Vec<u32>,
    },
    Rect {
        x: u16,
        y: u16,
        w: u16,
        h: u16,
        pixels: Vec<u32>,
    },
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
/// advertised DesktopSize (-223), a DesktopSize pseudo-rect is prefixed so it re-sizes. An empty
/// update is sent if nothing changed.
pub(super) async fn send_update<S: AsyncWrite + Unpin>(
    sock: &mut S,
    shared: &SharedFb,
    last_gen: &mut u64,
    last_dims: &mut (u16, u16),
    desktopsize: bool,
    fmt: &PixelFormat,
    zlib: Option<&mut ZlibStream>,
) -> Result<()> {
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
        let first = *last_gen == u64::MAX;
        let mut g = shared.lock().unwrap();
        *last_gen = g.generation;
        let (fw, fh) = (g.fb.width as u16, g.fb.height as u16);
        let width = g.fb.width as usize;
        let len = g.fb.pixels.len();
        if width == 0 || len == 0 {
            Update::Empty
        } else if desktopsize && (fw, fh) != *last_dims {
            *last_dims = (fw, fh);
            g.take_dirty();
            Update::Resize {
                w: fw,
                h: fh,
                pixels: g.fb.pixels.clone(),
            }
        } else {
            let range = if first { None } else { g.take_dirty() };
            match range {
                Some(r) if r.end > r.start && r.end <= len => {
                    let (y0, y1) = (r.start / width, (r.end - 1) / width);
                    let pixels = g.fb.pixels[y0 * width..(y1 + 1) * width].to_vec();
                    Update::Rect {
                        x: 0,
                        y: y0 as u16,
                        w: fw,
                        h: (y1 - y0 + 1) as u16,
                        pixels,
                    }
                }
                // Full frame on the first update, or when another viewer already drained the damage.
                _ => Update::Rect {
                    x: 0,
                    y: 0,
                    w: fw,
                    h: fh,
                    pixels: g.fb.pixels.clone(),
                },
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
            msg.extend_from_slice(&[0u8, 0]); // FramebufferUpdate + padding
            msg.extend_from_slice(&2u16.to_be_bytes()); // 2 rectangles
            push_rect(&mut msg, 0, 0, w, h, -223); // DesktopSize pseudo-rect
            push_pixel_rect(&mut msg, (0, 0, w, h), &pixels, fmt, zlib);
        }
        Update::Rect { x, y, w, h, pixels } => {
            msg.extend_from_slice(&[0u8, 0]);
            msg.extend_from_slice(&1u16.to_be_bytes());
            push_pixel_rect(&mut msg, (x, y, w, h), &pixels, fmt, zlib);
        }
    }
    sock.write_all(&msg).await?;
    Ok(())
}

/// Append a pixel rectangle: Raw, or Zlib (encoding 6) when the client's persistent zlib stream is
/// present. Zlib is just the Raw pixel bytes deflated on a per-connection stream, which crushes the
/// redundant console content.
fn push_pixel_rect(
    msg: &mut Vec<u8>,
    (x, y, w, h): (u16, u16, u16, u16),
    pixels: &[u32],
    fmt: &PixelFormat,
    zlib: Option<&mut ZlibStream>,
) {
    let mut raw = Vec::with_capacity(pixels.len() * (fmt.bpp as usize / 8).max(1));
    for &px in pixels {
        fmt.push(&mut raw, px);
    }
    match zlib {
        Some(z) => {
            let mut zdata = Vec::with_capacity(raw.len() / 2 + 64);
            deflate_sync(z, &raw, &mut zdata);
            push_rect(msg, x, y, w, h, ENC_ZLIB);
            msg.extend_from_slice(&(zdata.len() as u32).to_be_bytes());
            msg.extend_from_slice(&zdata);
        }
        None => {
            push_rect(msg, x, y, w, h, ENC_RAW);
            msg.extend_from_slice(&raw);
        }
    }
}

/// Deflate `input` into `out` on the persistent `z` stream, sync-flushed so the client can inflate
/// this rectangle now while keeping the stream context (dictionary) for the next one. A sync flush
/// always emits a marker, so completion is detected by the flush leaving output room to spare
/// (not by "no new output"). Reserve generously so that happens in one pass.
fn deflate_sync(z: &mut ZlibStream, input: &[u8], out: &mut Vec<u8>) {
    let start = z.total_in();
    loop {
        out.reserve(input.len() + 128); // enough spare that a completed flush doesn't fill it
        let consumed = (z.total_in() - start) as usize;
        let spare = out.capacity() - out.len();
        let before_out = z.total_out();
        z.compress_vec(&input[consumed..], out, FlushCompress::Sync)
            .expect("zlib deflate");
        let all_in = (z.total_in() - start) as usize >= input.len();
        let produced = (z.total_out() - before_out) as usize;
        if all_in && produced < spare {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PixelFormat;

    #[test]
    fn zlib_rects_roundtrip_on_persistent_stream() {
        use flate2::{Compress, Compression, Decompress, FlushDecompress};
        let mut enc = Compress::new(Compression::default(), true);
        let mut dec = Decompress::new(true);

        // Each "rectangle" must decode against the shared, persistent inflate stream, in order.
        for chunk in [
            &b"\x00\x00\x00\x00\xff\xff\xff\xff"[..],
            b"\x00\x00\x00\x00\xff\xff\xff\xfe",
            b"hello zlib hello zlib hello",
        ] {
            let mut z = Vec::new();
            super::deflate_sync(&mut enc, chunk, &mut z);
            assert!(z.len() < chunk.len() + 16); // sanity: not wildly expanding

            let mut out = Vec::with_capacity(chunk.len());
            let start = dec.total_in();
            while out.len() < chunk.len() {
                if out.len() == out.capacity() {
                    out.reserve(chunk.len() - out.len() + 8);
                }
                let consumed = (dec.total_in() - start) as usize;
                dec.decompress_vec(&z[consumed..], &mut out, FlushDecompress::Sync)
                    .unwrap();
                if (dec.total_in() - start) as usize >= z.len() && out.len() < chunk.len() {
                    break;
                }
            }
            assert_eq!(
                out, chunk,
                "each zlib rect must round-trip on the persistent stream"
            );
        }
    }

    #[test]
    fn pixel_format_encodes_to_client_layout() {
        // Default: 32bpp little-endian, RGB in shifts 16/8/0 -> [B, G, R, unused].
        let mut v = Vec::new();
        PixelFormat::default().push(&mut v, 0xFF3366CC);
        assert_eq!(v, [0xCC, 0x66, 0x33, 0x00]);

        // RGB565 little-endian: 0x3366CC -> 0x3339.
        let f565 = PixelFormat {
            bpp: 16,
            big_endian: false,
            true_colour: true,
            r_max: 31,
            g_max: 63,
            b_max: 31,
            r_shift: 11,
            g_shift: 5,
            b_shift: 0,
        };
        let mut v = Vec::new();
        f565.push(&mut v, 0xFF3366CC);
        assert_eq!(v, [0x39, 0x33]);

        // Same format, big-endian byte order.
        let mut v = Vec::new();
        PixelFormat {
            big_endian: true,
            ..f565
        }
        .push(&mut v, 0xFF3366CC);
        assert_eq!(v, [0x33, 0x39]);
    }
}
