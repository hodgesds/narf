//! Linux's legacy framebuffer ABI, exercised without GPU hardware on both arches.

use super::card::Card;
use super::ioctl::{dispatch, legacy_fb_cmd, DrmIoctlError, DrmIoctlResult};
use super::render_node::DrmFileCtx;
use narf_kernel_test::{kernel_test_in, TestResult};

// Literal Linux UAPI values keep a mistaken local enum/constant from making
// the test pass with the same mistaken request number as the implementation.
const ADDFB: u32 = 0xc01c_64ae;
const RMFB: u32 = 0xc004_64af;
/// `DRM_IOWR('d', 0xB1, struct drm_mode_fb_dirty_cmd)` (24 bytes).
const DIRTYFB: u32 = 0xc018_64b1;

fn request(handle: u32, bpp: u32, depth: u32, pitch: u32) -> [u8; 28] {
    let mut arg = [0u8; 28];
    for (dst, value) in arg
        .chunks_exact_mut(4)
        .zip([0, 64, 32, pitch, bpp, depth, handle])
    {
        dst.copy_from_slice(&value.to_le_bytes());
    }
    arg
}

fn legacy_addfb_rmfb_linux_wire_roundtrip() -> TestResult {
    let mut card = Card::new("amdgpu", "legacy framebuffer fixture", (1, 0, 0));
    // Synthetic backing is never dereferenced/freed; the GEM handle keeps
    // its initial reference throughout this test.
    let handle = card
        .register_dumb_backing(0x8000_0000, 64 * 32 * 4, 1)
        .unwrap();
    let ctx = DrmFileCtx::primary_master();
    let id = match dispatch(&mut card, ADDFB, &request(handle, 32, 24, 256), &ctx) {
        Ok(DrmIoctlResult::AddFb2(id)) => id,
        _ => return TestResult::Fail("Linux ADDFB request did not create a framebuffer"),
    };
    let fb = card.framebuffer(id).unwrap();
    if fb.width != 64
        || fb.height != 32
        || fb.pitch != 256
        || fb.gem_handle != handle
        || fb.format as u32 != 0x3432_5258
        || fb.modifier != 0
        || fb.offsets != [0, 0]
    {
        return TestResult::Fail("legacy depth/handle/pitch did not map to linear XRGB8888");
    }
    if card.dumb_backing(handle).unwrap().refcount != 2 {
        return TestResult::Fail("legacy framebuffer did not retain its backing");
    }
    if !matches!(
        dispatch(&mut card, RMFB, &id.to_le_bytes(), &ctx),
        Ok(DrmIoctlResult::RmFb)
    ) || !card.framebuffers.is_empty()
    {
        return TestResult::Fail("Linux RMFB request did not remove the framebuffer");
    }
    if card.dumb_backing(handle).unwrap().refcount != 1 {
        return TestResult::Fail("RMFB did not release the framebuffer's backing reference");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm/fb_legacy",
    legacy_addfb_rmfb_linux_wire_roundtrip
);

fn legacy_addfb_formats_and_zeroed_extension() -> TestResult {
    for (bpp, depth, fourcc) in [
        (1, 1, *b"C1  "),
        (2, 2, *b"C2  "),
        (4, 4, *b"C4  "),
        (8, 8, *b"C8  "),
        (16, 15, *b"XR15"),
        (16, 16, *b"RG16"),
        (24, 24, *b"RG24"),
        (32, 24, *b"XR24"),
        (32, 30, *b"XR30"),
        (32, 32, *b"AR24"),
    ] {
        let mut arg = request(19, bpp, depth, 256);
        arg[..4].copy_from_slice(&u32::MAX.to_le_bytes()); // output id is not input
        let cmd = legacy_fb_cmd(&arg).unwrap();
        if cmd.pixel_format != u32::from_le_bytes(fourcc)
            || cmd.width != 64
            || cmd.height != 32
            || cmd.handles != [19, 0, 0, 0]
            || cmd.pitches != [256, 0, 0, 0]
            || cmd.flags != 0
            || cmd.offsets != [0; 4]
            || cmd.modifier != [0; 4]
        {
            return TestResult::Fail("legacy framebuffer conversion disagrees with Linux");
        }
    }
    // A card still decides which converted formats its planes can scan out.
    for (bpp, depth, fourcc) in [
        (16, 16, 0x3631_4752),
        (32, 24, 0x3432_5258),
        (32, 30, 0x3033_5258),
        (32, 32, 0x3432_5241),
    ] {
        let mut card = Card::new("amdgpu", "legacy format fixture", (1, 0, 0));
        card.plane_formats = Some(&[0x3631_4752, 0x3432_5258, 0x3033_5258, 0x3432_5241]);
        let h = card.gem.alloc(0x8000_0000, 8192).unwrap();
        let Ok(DrmIoctlResult::AddFb2(id)) = dispatch(
            &mut card,
            ADDFB,
            &request(h, bpp, depth, 256),
            &DrmFileCtx::primary_master(),
        ) else {
            return TestResult::Fail("supported legacy format refused");
        };
        if card.framebuffer(id).unwrap().format as u32 != fourcc {
            return TestResult::Fail("legacy framebuffer format changed after conversion");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm/fb_legacy",
    legacy_addfb_formats_and_zeroed_extension
);

fn legacy_addfb_rejects_bad_requests_without_retaining_backing() -> TestResult {
    let mut card = Card::new("amdgpu", "legacy bounds fixture", (1, 0, 0));
    let h = card.register_dumb_backing(0x8000_0000, 8192, 1).unwrap();
    let ctx = DrmFileCtx::primary_master();
    let good = request(h, 32, 24, 256);
    for len in 0..28 {
        if !matches!(
            dispatch(&mut card, ADDFB, &good[..len], &ctx),
            Err(DrmIoctlError::BadSize)
        ) {
            return TestResult::Fail("short legacy framebuffer request was not rejected");
        }
    }
    for (bpp, depth) in [
        (0, 0),
        (32, 16),
        (16, 24),
        (24, 32),
        (64, 32),
        (32, u32::MAX),
    ] {
        if !matches!(
            dispatch(&mut card, ADDFB, &request(h, bpp, depth, 256), &ctx),
            Err(DrmIoctlError::Card(super::card::CardError::UnknownFormat))
        ) {
            return TestResult::Fail("invalid legacy depth/bpp accepted");
        }
    }
    // Zero dimensions, a short pitch, an oversized extent, a missing GEM
    // handle, and a converted format unsupported by the card all fail.
    for (at, value) in [
        (4, 0),
        (8, 0),
        (12, 255),
        (8, 33),
        (4, u32::MAX),
        (8, u32::MAX),
        (24, h + 100),
        (16, 24),
    ] {
        let mut bad = good;
        bad[at..at + 4].copy_from_slice(&value.to_le_bytes());
        if dispatch(&mut card, ADDFB, &bad, &ctx).is_ok() {
            return TestResult::Fail("invalid legacy framebuffer created");
        }
    }
    if !card.framebuffers.is_empty() || card.dumb_backing(h).unwrap().refcount != 1 {
        return TestResult::Fail("refused legacy framebuffer retained a backing or id");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm/fb_legacy",
    legacy_addfb_rejects_bad_requests_without_retaining_backing
);

fn legacy_framebuffer_permissions_and_linux_request_numbers() -> TestResult {
    use super::ioctl::IoctlCmd;
    if crate::drm_uapi::DRM_IOCTL_MODE_ADDFB != ADDFB
        || crate::drm_uapi::DRM_IOCTL_MODE_RMFB != RMFB
        || IoctlCmd::from_raw(ADDFB) != IoctlCmd::ModeAddFb
        || IoctlCmd::from_raw(RMFB) != IoctlCmd::ModeRmFb
        // Xorg's modesetting probes DIRTYFB once and, if it is unknown,
        // never reports shadow updates to a CRTC that copies its buffer.
        || IoctlCmd::from_raw(DIRTYFB) != IoctlCmd::ModeDirtyFb
    {
        return TestResult::Fail("framebuffer ioctl numbers differ from Linux UAPI");
    }
    let mut card = Card::new("amdgpu", "legacy permissions fixture", (1, 0, 0));
    let h = card.gem.alloc(0x8000_0000, 8192).unwrap();
    let arg = request(h, 32, 24, 256);
    for ctx in [DrmFileCtx::render_client(), DrmFileCtx::primary(false)] {
        for cmd in [ADDFB, RMFB] {
            if !matches!(
                dispatch(&mut card, cmd, &arg, &ctx),
                Err(DrmIoctlError::PermissionDenied(_))
            ) {
                return TestResult::Fail(
                    "legacy framebuffer operation bypassed display-authority gate",
                );
            }
        }
    }
    // 0xa8 is Linux ATTACHMODE, never RMFB. An invalid old request must
    // not accidentally destroy a framebuffer.
    if !matches!(
        dispatch(
            &mut card,
            0xc004_64a8,
            &1u32.to_le_bytes(),
            &DrmFileCtx::primary_master()
        ),
        Err(DrmIoctlError::UnknownCmd)
    ) {
        return TestResult::Fail("ATTACHMODE incorrectly dispatched as RMFB");
    }
    if !card.framebuffers.is_empty() {
        return TestResult::Fail("permission failure allocated a framebuffer");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm/fb_legacy",
    legacy_framebuffer_permissions_and_linux_request_numbers
);
