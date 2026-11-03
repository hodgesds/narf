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
    /// `DRM_MODE_FB_DIRTY_FLAGS & r->flags`: unknown bits are dropped,
    /// never refused.
    pub flags: u32,
    pub num_clips: u32,
    pub clips_ptr: u64,
}
impl DirtyCmd {
    /// Decode the 24-byte request without validating it. The caller looks
    /// the framebuffer up (`-ENOENT`) before [`DirtyCmd::validate`], as
    /// `drm_mode_dirtyfb_ioctl` does.
    pub fn decode(arg: &[u8]) -> Option<Self> {
        if arg.len() < 24 {
            return None;
        }
        let w = |at: usize| u32::from_le_bytes(arg[at..at + 4].try_into().unwrap());
        Some(Self {
            fb_id: w(0),
            flags: w(4) & DIRTY_FLAGS,
            num_clips: w(12),
            clips_ptr: u64::from_le_bytes(arg[16..24].try_into().unwrap()),
        })
    }
    /// `drm_mode_dirtyfb_ioctl`'s `-EINVAL` checks after the framebuffer
    /// lookup, in its order: a clip count without clips (or the reverse),
    /// an odd count under `DRM_MODE_FB_DIRTY_ANNOTATE_COPY`, then a count
    /// that is negative as `int` or above `DRM_MODE_FB_DIRTY_MAX_CLIPS`.
    pub fn validate(&self) -> Result<(), ()> {
        if (self.num_clips == 0) != (self.clips_ptr == 0)
            || (self.flags & DIRTY_ANNOTATE_COPY != 0 && self.num_clips % 2 != 0)
            || self.num_clips > DIRTY_MAX_CLIPS
        {
            return Err(());
        }
        Ok(())
    }
    /// [`DirtyCmd::decode`] then [`DirtyCmd::validate`].
    pub fn parse(arg: &[u8]) -> Option<Self> {
        let cmd = Self::decode(arg)?;
        cmd.validate().ok()?;
        Some(cmd)
    }
    /// The byte length of the `drm_clip_rect` array the request names.
    pub fn clips_len(&self) -> usize {
        self.num_clips as usize * CLIP_RECT_BYTES
    }
    /// `drm_atomic_helper_dirtyfb`'s damage: no clips leave the plane's
    /// FB_DAMAGE_CLIPS unset (a full-plane update); otherwise every clip
    /// becomes a `drm_mode_rect`, taking every second one under
    /// `DRM_MODE_FB_DIRTY_ANNOTATE_COPY` (`num_clips /= 2`, `inc = 2`).
    pub fn damage(&self, clips: &[u8]) -> Damage {
        if self.num_clips == 0 {
            return Damage::Full;
        }
        let (count, step) = if self.flags & DIRTY_ANNOTATE_COPY != 0 {
            (self.num_clips as usize / 2, 2)
        } else {
            (self.num_clips as usize, 1)
        };
        let h = |c: &[u8], at: usize| i32::from(u16::from_le_bytes([c[at], c[at + 1]]));
        Damage::Clips(
            clips
                .chunks_exact(CLIP_RECT_BYTES)
                .step_by(step)
                .take(count)
                .map(|c| Rect {
                    x1: h(c, 0),
                    y1: h(c, 2),
                    x2: h(c, 4),
                    y2: h(c, 6),
                })
                .collect(),
        )
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

/// `struct drm_mode_rect` / `struct drm_rect`: integer corners, `x2`/`y2`
/// exclusive.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rect {
    pub x1: i32,
    pub y1: i32,
    pub x2: i32,
    pub y2: i32,
}
impl Rect {
    pub const fn new(x1: i32, y1: i32, x2: i32, y2: i32) -> Self {
        Self { x1, y1, x2, y2 }
    }
    pub fn width(&self) -> i32 {
        self.x2.wrapping_sub(self.x1)
    }
    pub fn height(&self) -> i32 {
        self.y2.wrapping_sub(self.y1)
    }
    /// `drm_rect_visible`.
    pub fn visible(&self) -> bool {
        self.width() > 0 && self.height() > 0
    }
    /// `drm_rect_intersect`: `self` becomes the intersection; whether it is
    /// still visible.
    pub fn intersect(&mut self, other: &Rect) -> bool {
        self.x1 = self.x1.max(other.x1);
        self.y1 = self.y1.max(other.y1);
        self.x2 = self.x2.min(other.x2);
        self.y2 = self.y2.min(other.y2);
        self.visible()
    }
    /// `drm_rect_translate`.
    pub fn translate(&mut self, dx: i32, dy: i32) {
        self.x1 = self.x1.wrapping_add(dx);
        self.y1 = self.y1.wrapping_add(dy);
        self.x2 = self.x2.wrapping_add(dx);
        self.y2 = self.y2.wrapping_add(dy);
    }
}

/// `sizeof(struct drm_mode_rect)`, the FB_DAMAGE_CLIPS element.
pub const DAMAGE_RECT_BYTES: usize = 16;

/// A plane's frame damage for one commit (`drm_plane_state.fb_damage_clips`),
/// in framebuffer coordinates.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Damage {
    /// No FB_DAMAGE_CLIPS blob: `drm_atomic_helper_damage_iter_init`'s full
    /// update (the whole plane source is damaged).
    #[default]
    Full,
    /// The blob's clips, unclamped. An empty list damages nothing.
    Clips(alloc::vec::Vec<Rect>),
}
impl Damage {
    /// An FB_DAMAGE_CLIPS blob: `drm_property_replace_blob_from_id` with
    /// `expected_elem_size = sizeof(struct drm_mode_rect)` refuses (`-EINVAL`)
    /// a length that is not a whole number of rectangles.
    pub fn from_blob(bytes: &[u8]) -> Result<Self, ()> {
        if bytes.len() % DAMAGE_RECT_BYTES != 0 {
            return Err(());
        }
        let w = |c: &[u8], at: usize| i32::from_le_bytes(c[at..at + 4].try_into().unwrap());
        Ok(Self::Clips(
            bytes
                .chunks_exact(DAMAGE_RECT_BYTES)
                .map(|c| Rect::new(w(c, 0), w(c, 4), w(c, 8), w(c, 12)))
                .collect(),
        ))
    }
    /// `drm_atomic_helper_damage_merged` for a visible plane with framebuffer
    /// source `src` (integer; the 16.16 rounding is the identity) whose old
    /// source was `old_src`: the bounding box of every clip that intersects
    /// the source, clamped to it, or the whole source when there is no blob
    /// or the source moved. `None` when nothing is damaged.
    pub fn merged(&self, old_src: &Rect, src: &Rect) -> Option<Rect> {
        let clips = match self {
            Self::Clips(clips) if old_src == src => clips,
            _ => return Some(*src),
        };
        let mut rect = Rect::new(i32::MAX, i32::MAX, 0, 0);
        let mut valid = false;
        for clip in clips {
            let mut clip = *clip;
            if !clip.intersect(src) {
                continue;
            }
            rect.x1 = rect.x1.min(clip.x1);
            rect.y1 = rect.y1.min(clip.y1);
            rect.x2 = rect.x2.max(clip.x2);
            rect.y2 = rect.y2.max(clip.y2);
            valid = true;
        }
        valid.then_some(rect)
    }
}
