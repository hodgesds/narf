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
