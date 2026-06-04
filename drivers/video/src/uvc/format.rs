//! Pixel-format decoders.
//!
//! MJPEG and H.264 are passed through as opaque byte streams; the
//! caller is responsible for decoding. YUYV and NV12 are raw planar
//! formats that this module can convert to RGBA8888 for software
//! rendering if needed.
//!
//! Linux reference: `drivers/media/usb/uvc/uvc_driver.c`
//! `uvc_format_by_guid()` (around line 190) — maps GUIDs to internal
//! format structures. The passthrough strategy for MJPEG matches
//! `uvc_video_decode_data()` in `uvc_video.c` line ~590 which simply
//! copies compressed data without decompression.

use super::streaming::PixelFmt;
use alloc::vec::Vec;

/// A decoded or passthrough video frame.
#[derive(Clone, Debug)]
pub struct DecodedFrame {
    pub pixel_fmt: PixelFmt,
    pub width: u16,
    pub height: u16,
    /// Raw frame bytes.
    ///
    /// - MJPEG: complete JPEG bitstream.
    /// - YUYV: width × height × 2 bytes packed.
    /// - NV12: width × height × 3/2 bytes (Y plane then UV plane).
    /// - FrameBased (H.264 etc.): compressed bitstream, passthrough.
    pub data: Vec<u8>,
}

/// Pass a raw UVC frame buffer through as-is.
///
/// For MJPEG, YUYV, NV12, and frame-based formats, the driver does not
/// decompress. The application layer or a separate codec daemon handles
/// decompression.
pub fn passthrough(pixel_fmt: PixelFmt, width: u16, height: u16, raw: Vec<u8>) -> DecodedFrame {
    DecodedFrame {
        pixel_fmt,
        width,
        height,
        data: raw,
    }
}

/// Convert a YUYV (YUY2) frame to RGBA8888.
///
/// YUYV layout: Y0 U0 Y1 V0, Y2 U2 Y3 V2, …
/// Each pair of pixels shares one chroma pair (U, V).
///
/// `raw` must be exactly `width × height × 2` bytes.
/// Returns an empty `Vec` if the length check fails.
///
/// BT.601 full-range coefficients.
pub fn yuyv_to_rgba(width: u16, height: u16, raw: &[u8]) -> Vec<u8> {
    let w = width as usize;
    let h = height as usize;
    let expected = w * h * 2;
    if raw.len() < expected {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(w * h * 4);
    let mut i = 0usize;
    while i + 3 < raw.len() {
        let y0 = raw[i] as i32;
        let u = raw[i + 1] as i32 - 128;
        let y1 = raw[i + 2] as i32;
        let v = raw[i + 3] as i32 - 128;

        for y in [y0, y1] {
            let r = clamp8(y + (1_403 * v) / 1000);
            let g = clamp8(y - (344 * u) / 1000 - (714 * v) / 1000);
            let b = clamp8(y + (1_773 * u) / 1000);
            out.push(r);
            out.push(g);
            out.push(b);
            out.push(0xFF);
        }
        i += 4;
    }
    out
}

/// Convert an NV12 frame to RGBA8888.
///
/// NV12 layout: Y plane (width × height bytes), then interleaved UV
/// plane (width × height/2 bytes). The UV plane has one sample per
/// 2×2 luma block.
///
/// `raw` must be at least `width × height × 3 / 2` bytes.
pub fn nv12_to_rgba(width: u16, height: u16, raw: &[u8]) -> Vec<u8> {
    let w = width as usize;
    let h = height as usize;
    let y_size = w * h;
    let uv_size = w * (h / 2);
    if raw.len() < y_size + uv_size {
        return Vec::new();
    }
    let y_plane = &raw[..y_size];
    let uv_plane = &raw[y_size..y_size + uv_size];
    let mut out = Vec::with_capacity(w * h * 4);

    for row in 0..h {
        for col in 0..w {
            let y = y_plane[row * w + col] as i32;
            let uv_row = row / 2;
            let uv_col = (col / 2) * 2;
            let u = uv_plane[uv_row * w + uv_col] as i32 - 128;
            let v = uv_plane[uv_row * w + uv_col + 1] as i32 - 128;

            let r = clamp8(y + (1_403 * v) / 1000);
            let g = clamp8(y - (344 * u) / 1000 - (714 * v) / 1000);
            let b = clamp8(y + (1_773 * u) / 1000);
            out.push(r);
            out.push(g);
            out.push(b);
            out.push(0xFF);
        }
    }
    out
}

fn clamp8(v: i32) -> u8 {
    v.clamp(0, 255) as u8
}

/// Validate that a MJPEG frame starts with the JFIF/EXIF SOI marker `0xFF 0xD8`.
pub fn is_valid_mjpeg(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == 0xFF && data[1] == 0xD8
}

/// Expected byte length of a YUYV frame for the given resolution.
pub fn yuyv_frame_size(width: u16, height: u16) -> usize {
    width as usize * height as usize * 2
}

/// Expected byte length of an NV12 frame for the given resolution.
pub fn nv12_frame_size(width: u16, height: u16) -> usize {
    let w = width as usize;
    let h = height as usize;
    w * h + w * (h / 2)
}
