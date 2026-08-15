//! Video decode for the iDRAC 6 `hb` (0x0081) RLE/RGB555 codec into an RGBA framebuffer.

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
}
