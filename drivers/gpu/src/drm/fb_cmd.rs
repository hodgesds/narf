//! The DRM_IOCTL_MODE_ADDFB2 wire request (`struct drm_mode_fb_cmd2`)
//! and its decoder. This is a kernel UAPI layout, identical for every
//! DRM driver, so it lives in the DRM core rather than with any one
//! vendor's modifier checks. Linux reference:
//! `include/uapi/drm/drm_mode.h`.

/// A DRM_IOCTL_MODE_ADDFB2 request (`struct drm_mode_fb_cmd2`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FbCmd {
    pub width: u32,
    pub height: u32,
    pub pixel_format: u32,
    pub flags: u32,
    pub handles: [u32; 4],
    pub pitches: [u32; 4],
    pub offsets: [u32; 4],
    pub modifier: [u64; 4],
}
/// DRM_MODE_FB_INTERLACED and DRM_MODE_FB_MODIFIERS.
pub const FB_INTERLACED: u32 = 1;
pub const FB_MODIFIERS: u32 = 2;
impl FbCmd {
    /// Decode `struct drm_mode_fb_cmd2` (104 bytes; a shorter legacy
    /// struct leaves the modifiers zero).
    pub fn parse(arg: &[u8]) -> Option<Self> {
        let w = |at: usize| u32::from_le_bytes(arg[at..at + 4].try_into().unwrap());
        if arg.len() < 68 {
            return None;
        }
        let mut cmd = Self {
            width: w(4),
            height: w(8),
            pixel_format: w(12),
            flags: w(16),
            ..Self::default()
        };
        for i in 0..4 {
            cmd.handles[i] = w(20 + 4 * i);
            cmd.pitches[i] = w(36 + 4 * i);
            cmd.offsets[i] = w(52 + 4 * i);
            if let Some(m) = arg.get(72 + 8 * i..80 + 8 * i) {
                cmd.modifier[i] = u64::from_le_bytes(m.try_into().unwrap());
            }
        }
        Some(cmd)
    }
}

/// DRM_MODE_FB_DIRTY_ANNOTATE_COPY, every DRM_MODE_FB_DIRTY_FLAGS bit, and
/// DRM_MODE_FB_DIRTY_MAX_CLIPS.
pub const DIRTY_ANNOTATE_COPY: u32 = 1;
pub const DIRTY_FLAGS: u32 = 3;
pub const DIRTY_MAX_CLIPS: u32 = 256;
/// `struct drm_clip_rect` is four u16s.
pub const CLIP_RECT_BYTES: usize = 8;

/// A DRM_IOCTL_MODE_DIRTYFB request (`struct drm_mode_fb_dirty_cmd`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DirtyCmd {
    pub fb_id: u32,
    pub flags: u32,
    pub num_clips: u32,
    pub clips_ptr: u64,
}
impl DirtyCmd {
    /// Decode the 24-byte request, refusing what `drm_mode_dirtyfb_ioctl`
    /// refuses with -EINVAL: a clip count without clips (or the reverse),
    /// unknown flags, unpaired copy annotations and too many clips.
    pub fn parse(arg: &[u8]) -> Option<Self> {
        if arg.len() < 24 {
            return None;
        }
        let w = |at: usize| u32::from_le_bytes(arg[at..at + 4].try_into().unwrap());
        let cmd = Self {
            fb_id: w(0),
            flags: w(4),
            num_clips: w(12),
            clips_ptr: u64::from_le_bytes(arg[16..24].try_into().unwrap()),
        };
        if (cmd.num_clips == 0) != (cmd.clips_ptr == 0)
            || cmd.flags & !DIRTY_FLAGS != 0
            || (cmd.flags & DIRTY_ANNOTATE_COPY != 0 && cmd.num_clips % 2 != 0)
            || cmd.num_clips > DIRTY_MAX_CLIPS
        {
            return None;
        }
        Some(cmd)
    }
    /// The rows of a `height`-row framebuffer that `clips` (this request's
    /// `drm_clip_rect` array) damage, as one covering span: every row when
    /// there are no clips, empty when no clip covers a row. A copy
    /// annotation pairs each destination with its source; as in
    /// `drm_atomic_helper_dirtyfb`, only the destinations count.
    pub fn rows(&self, clips: &[u8], height: u32) -> core::ops::Range<u32> {
        if self.num_clips == 0 {
            return 0..height;
        }
        let step = if self.flags & DIRTY_ANNOTATE_COPY != 0 {
            2
        } else {
            1
        };
        let h = |c: &[u8], at: usize| u32::from(u16::from_le_bytes([c[at], c[at + 1]]));
        let mut span: Option<core::ops::Range<u32>> = None;
        for clip in clips
            .chunks_exact(CLIP_RECT_BYTES)
            .take(self.num_clips as usize)
            .step_by(step)
        {
            let (x1, y1, x2, y2) = (h(clip, 0), h(clip, 2), h(clip, 4), h(clip, 6));
            let (y1, y2) = (y1.min(height), y2.min(height));
            if x2 <= x1 || y2 <= y1 {
                continue;
            }
            span = Some(match span {
                Some(s) => s.start.min(y1)..s.end.max(y2),
                None => y1..y2,
            });
        }
        span.unwrap_or(0..0)
    }
}
