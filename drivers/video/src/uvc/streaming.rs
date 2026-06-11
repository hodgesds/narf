//! VS interface format/frame enumeration.
//!
//! Walks a flattened VS class-specific descriptor blob and extracts
//! all FORMAT + FRAME descriptors into a structured list of
//! [`StreamFormat`] entries.
//!
//! Linux reference: `drivers/media/usb/uvc/uvc_driver.c`
//! `uvc_parse_streaming()` (around line 900) — iterates the VS class-
//! specific descriptors with the same bLength-based walking strategy,
//! building `uvc_streaming::formats[]`.

use super::descriptor::{
    DescError, FormatFrameBased, FormatMjpeg, FormatUncompressed, FrameFrameBased, FrameMjpeg,
    FrameUncompressed, CS_INTERFACE, GUID_FORMAT_NV12, GUID_FORMAT_YUY2, VS_FORMAT_FRAME_BASED,
    VS_FORMAT_MJPEG, VS_FORMAT_UNCOMPRESSED, VS_FRAME_FRAME_BASED, VS_FRAME_MJPEG,
    VS_FRAME_UNCOMPRESSED,
};
use alloc::vec::Vec;

/// Pixel format classification.
///
/// Mirrors V4L2's `V4L2_PIX_FMT_*` taxonomy for the subset the UVC
/// driver handles.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PixelFmt {
    /// Motion-JPEG compressed. MJPEG passthrough — deliver JPEG bytes.
    Mjpeg,
    /// Packed YUYV 4:2:2. Raw delivery.
    Yuyv,
    /// Semi-planar NV12 4:2:0. Raw delivery.
    Nv12,
    /// Frame-based compressed (H.264, H.265). Passthrough.
    FrameBased,
    /// Unrecognised GUID.
    Unknown,
}

/// A single supported resolution + interval combination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameMode {
    /// 1-based frame index within the parent FORMAT descriptor.
    pub frame_index: u8,
    pub width: u16,
    pub height: u16,
    /// Discrete frame intervals in 100 ns units.
    pub frame_intervals: Vec<u32>,
    /// Continuous interval range (min/max/step in 100 ns units).
    pub continuous_min: Option<u32>,
    pub continuous_max: Option<u32>,
    pub continuous_step: Option<u32>,
    pub default_frame_interval: u32,
}

impl FrameMode {
    /// True iff the given interval (100 ns) is supported by this frame mode.
    pub fn supports_interval(&self, interval_100ns: u32) -> bool {
        if !self.frame_intervals.is_empty() {
            return self.frame_intervals.contains(&interval_100ns);
        }
        // Continuous range.
        if let (Some(mn), Some(mx), Some(st)) = (
            self.continuous_min,
            self.continuous_max,
            self.continuous_step,
        ) {
            if interval_100ns < mn || interval_100ns > mx {
                return false;
            }
            if st == 0 {
                return true;
            }
            return (interval_100ns - mn) % st == 0;
        }
        false
    }

    /// Best-effort "nearest supported interval" for the requested fps.
    ///
    /// Returns the first interval whose fps is ≥ requested fps, or
    /// the lowest fps available if all are slower than requested.
    pub fn nearest_interval_for_fps(&self, fps: u32) -> u32 {
        let want_interval = if fps == 0 { u32::MAX } else { 10_000_000 / fps };

        if !self.frame_intervals.is_empty() {
            // intervals are smallest-to-largest = fastest-to-slowest fps
            let best = self
                .frame_intervals
                .iter()
                .copied()
                .min_by_key(|&iv| iv.abs_diff(want_interval))
                .unwrap_or(self.default_frame_interval);
            return best;
        }
        if let Some(mn) = self.continuous_min {
            if want_interval >= mn {
                return want_interval;
            }
            return mn;
        }
        self.default_frame_interval
    }
}

/// One complete format group: pixel format + all its frame modes.
#[derive(Clone, Debug)]
pub struct StreamFormat {
    /// 1-based format index within the VS interface.
    pub format_index: u8,
    pub pixel_fmt: PixelFmt,
    pub default_frame_index: u8,
    pub frames: Vec<FrameMode>,
}

impl StreamFormat {
    /// Find the frame mode best matching `(width, height, fps)`.
    ///
    /// Matches exact dimensions first; then picks the best interval.
    pub fn find_frame(&self, width: u16, height: u16, fps: u32) -> Option<(u8, u32)> {
        let modes: Vec<&FrameMode> = self
            .frames
            .iter()
            .filter(|f| f.width == width && f.height == height)
            .collect();

        if modes.is_empty() {
            return None;
        }

        // Pick the one whose nearest interval is closest to requested fps.
        let best = modes
            .iter()
            .min_by_key(|f| {
                let iv = f.nearest_interval_for_fps(fps);
                let want_iv = if fps == 0 { u32::MAX } else { 10_000_000 / fps };
                iv.abs_diff(want_iv)
            })
            .unwrap();

        let interval = best.nearest_interval_for_fps(fps);
        Some((best.frame_index, interval))
    }
}

/// Errors from descriptor-blob walking.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StreamingError {
    Desc(DescError),
    /// No FORMAT descriptors found in the blob.
    NoFormats,
}

impl From<DescError> for StreamingError {
    fn from(e: DescError) -> Self {
        StreamingError::Desc(e)
    }
}

/// Walk a raw VS class-specific descriptor blob and extract all format
/// groups.
///
/// `blob` is the contiguous bytes of the VS interface's class-specific
/// descriptors (everything between the VS_INPUT_HEADER and the first
/// standard endpoint descriptor).
///
/// This mirrors the descriptor-walk in Linux `uvc_parse_streaming()`
/// around line 930 of `uvc_driver.c`:
/// ```text
///   for each descriptor (by bLength):
///     if bDescriptorType != CS_INTERFACE → skip
///     dispatch on bDescriptorSubtype
/// ```
pub fn parse_streaming_descriptors(blob: &[u8]) -> Result<Vec<StreamFormat>, StreamingError> {
    let mut formats: Vec<StreamFormat> = Vec::new();
    let mut i = 0usize;

    while i + 2 <= blob.len() {
        let blen = blob[i] as usize;
        if blen < 3 || i + blen > blob.len() {
            break;
        }
        let slice = &blob[i..i + blen];
        i += blen;

        if slice[1] != CS_INTERFACE {
            continue;
        }

        let subtype = slice[2];
        match subtype {
            VS_FORMAT_MJPEG => {
                if let Ok(f) = FormatMjpeg::parse(slice) {
                    formats.push(StreamFormat {
                        format_index: f.format_index,
                        pixel_fmt: PixelFmt::Mjpeg,
                        default_frame_index: f.default_frame_index,
                        frames: Vec::new(),
                    });
                }
            }
            VS_FRAME_MJPEG => {
                if let Ok(fr) = FrameMjpeg::parse(slice) {
                    let mode = FrameMode {
                        frame_index: fr.frame_index,
                        width: fr.width,
                        height: fr.height,
                        frame_intervals: fr.frame_intervals,
                        continuous_min: fr.continuous_min,
                        continuous_max: fr.continuous_max,
                        continuous_step: fr.continuous_step,
                        default_frame_interval: fr.default_frame_interval,
                    };
                    if let Some(fmt) = formats.last_mut() {
                        fmt.frames.push(mode);
                    }
                }
            }
            VS_FORMAT_UNCOMPRESSED => {
                if let Ok(f) = FormatUncompressed::parse(slice) {
                    let pixel_fmt = if f.guid == GUID_FORMAT_YUY2 {
                        PixelFmt::Yuyv
                    } else if f.guid == GUID_FORMAT_NV12 {
                        PixelFmt::Nv12
                    } else {
                        PixelFmt::Unknown
                    };
                    formats.push(StreamFormat {
                        format_index: f.format_index,
                        pixel_fmt,
                        default_frame_index: f.default_frame_index,
                        frames: Vec::new(),
                    });
                }
            }
            VS_FRAME_UNCOMPRESSED => {
                if let Ok(fr) = FrameUncompressed::parse(slice) {
                    let mode = FrameMode {
                        frame_index: fr.frame_index,
                        width: fr.width,
                        height: fr.height,
                        frame_intervals: fr.frame_intervals,
                        continuous_min: fr.continuous_min,
                        continuous_max: fr.continuous_max,
                        continuous_step: fr.continuous_step,
                        default_frame_interval: fr.default_frame_interval,
                    };
                    if let Some(fmt) = formats.last_mut() {
                        fmt.frames.push(mode);
                    }
                }
            }
            VS_FORMAT_FRAME_BASED => {
                if let Ok(f) = FormatFrameBased::parse(slice) {
                    let _ = f;
                    formats.push(StreamFormat {
                        format_index: slice[3],
                        pixel_fmt: PixelFmt::FrameBased,
                        default_frame_index: slice[22],
                        frames: Vec::new(),
                    });
                }
            }
            VS_FRAME_FRAME_BASED => {
                if let Ok(fr) = FrameFrameBased::parse(slice) {
                    let mode = FrameMode {
                        frame_index: fr.frame_index,
                        width: fr.width,
                        height: fr.height,
                        frame_intervals: fr.frame_intervals,
                        continuous_min: fr.continuous_min,
                        continuous_max: fr.continuous_max,
                        continuous_step: fr.continuous_step,
                        default_frame_interval: fr.default_frame_interval,
                    };
                    if let Some(fmt) = formats.last_mut() {
                        fmt.frames.push(mode);
                    }
                }
            }
            _ => { /* VS_INPUT_HEADER, VS_OUTPUT_HEADER, colorimetry — skip */ }
        }
    }

    if formats.is_empty() {
        return Err(StreamingError::NoFormats);
    }
    Ok(formats)
}

/// Summarised format descriptor exposed to `Camera::list_formats()`.
#[derive(Clone, Debug)]
pub struct FormatDescriptor {
    pub format_index: u8,
    pub pixel_fmt: PixelFmt,
    pub width: u16,
    pub height: u16,
    pub fps_list: Vec<u32>,
}

/// Flatten `formats` into a list of `FormatDescriptor` entries (one
/// per frame mode per format).
pub fn flatten_formats(formats: &[StreamFormat]) -> Vec<FormatDescriptor> {
    let mut out = Vec::new();
    for sf in formats {
        for fm in &sf.frames {
            let fps_list: Vec<u32> = if !fm.frame_intervals.is_empty() {
                fm.frame_intervals
                    .iter()
                    .map(|&iv| if iv == 0 { 0 } else { 10_000_000 / iv })
                    .collect()
            } else {
                // Continuous range — emit min/max.
                let mut v = Vec::new();
                if let (Some(mn), Some(mx)) = (fm.continuous_min, fm.continuous_max) {
                    if mn > 0 {
                        v.push(10_000_000 / mn);
                    }
                    if mx > 0 && mx != mn {
                        v.push(10_000_000 / mx);
                    }
                }
                v
            };
            out.push(FormatDescriptor {
                format_index: sf.format_index,
                pixel_fmt: sf.pixel_fmt,
                width: fm.width,
                height: fm.height,
                fps_list,
            });
        }
    }
    out
}
