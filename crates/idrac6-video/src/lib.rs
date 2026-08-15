//! Video decode: the iDRAC 6 `hb` (0x0081) RLE/RGB555 codec into an RGBA framebuffer.

pub mod decoder;
pub mod hb;

/// RGBA framebuffer (row-major, `0xAARRGGBB`).
pub struct Framebuffer {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u32>,
}

impl Framebuffer {
    pub fn new(width: u32, height: u32) -> Self {
        Self {
            width,
            height,
            pixels: vec![0xFF000000; (width * height) as usize],
        }
    }

    /// Write a PPM (P6) image for offline inspection.
    pub fn write_ppm(&self, path: &std::path::Path) -> std::io::Result<()> {
        use std::io::Write;
        let mut f = std::io::BufWriter::new(std::fs::File::create(path)?);
        write!(f, "P6\n{} {}\n255\n", self.width, self.height)?;
        for px in &self.pixels {
            f.write_all(&[(px >> 16) as u8, (px >> 8) as u8, *px as u8])?;
        }
        f.flush()
    }
}
