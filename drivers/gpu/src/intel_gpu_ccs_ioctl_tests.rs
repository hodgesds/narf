// A compressed primary committed through the KMS presenter
// (`narf.intel.ccs=1`): display 14 `I915_FORMAT_MOD_4_TILED_MTL_RC_CCS_CC`
// on the i915 personality. Independent literals from Linux 7.4-rc4
// intel_fb.c (gen12_ccs_aux_stride, the 64-byte x 64-line CCS tile),
// skl_universal_plane.c (skl_plane_ctl_tiling, skl_plane_aux_dist,
// skl_program_plane_noarm's PLANE_CC_VAL) and intel_display.c
// (intel_atomic_prepare_plane_clear_colors: the native value at CC + 16).
use super::panning::{request, submit, worker};
use super::*;
use crate::intel_gpu_scanout::ccs::I915_FORMAT_MOD_4_TILED_MTL_RC_CCS_CC;
use crate::intel_gpu_scanout::TILE4_MODIFIER;

/// `PLANE_AUX_DIST(A, 1)`, `PLANE_AUX_OFFSET(A, 1)`, `PLANE_CC_VAL(A, 1, 0/1)`.
const AUX_DIST: u64 = 0x701c0;
const AUX_OFFSET: u64 = 0x701c4;
const CC_VAL: [u64; 2] = [0x701b4, 0x701b8];
/// 256x96 XR24 at pitch 1024 in Tile4: the main surface is 1024 * 96 =
/// 0x18000 bytes; the AUX plane (pitch DIV_ROUND_UP(1024, 512) * 64 = 128)
/// starts there and spans one 64-line AUX tile row, 128 * 64 = 0x2000
/// bytes; the clear-colour plane follows at 0x1a000.
const AUX_AT: u32 = 0x18000;
const CC_AT: u32 = 0x1a000;
const NATIVE: u64 = 0x0123_4567_89ab_cdef;

fn ccs_mode() -> ModeState {
    let mode = tiled_mode();
    {
        let mut card = mode.lock();
        card.intel_tile4 = true;
        card.intel_ccs = Some(14);
    }
    mode
}

/// ADDFB2 of a framebuffer of `modifier` (compressed planes when it is the
/// CC one), or `None` where the WC placement is unimplemented (aarch64).
fn frame(mode: &ModeState, modifier: u64) -> Option<Result<u32, ()>> {
    use crate::intel_gpu_gem::{GemState, Placement};
    let gem = GemState::new();
    let h = match gem.create_placed(0x1b000, None, Placement::SystemWc, |_, _| Ok(())) {
        Ok(h) => h,
        Err(FsError::NotImplemented) => {
            assert!(cfg!(target_arch = "aarch64"));
            return None;
        }
        Err(error) => panic!("CCS framebuffer object: {error:?}"),
    };
    let object = gem.object(h).unwrap();
    // The i915 path's scanout object (the KMS commit requires it).
    object.mark_scanout();
    object
        .write(u64::from(CC_AT) + 16, &NATIVE.to_le_bytes())
        .unwrap();
    let compressed = modifier == I915_FORMAT_MOD_4_TILED_MTL_RC_CCS_CC;
    let cmd = crate::drm::fb_cmd::FbCmd {
        width: 256,
        height: 96,
        pixel_format: DRM_FORMAT_XRGB8888,
        handles: if compressed { [h, h, h, 0] } else { [h, 0, 0, 0] },
        pitches: if compressed {
            [1024, 128, 0, 0]
        } else {
            [1024, 0, 0, 0]
        },
        offsets: if compressed {
            [0, AUX_AT, CC_AT, 0]
        } else {
            [0; 4]
        },
        flags: 2,
        modifier: if compressed {
            [modifier, modifier, modifier, 0]
        } else {
            [modifier, 0, 0, 0]
        },
    };
    Some(
        mode.lock()
            .addfb2_intel(&cmd, object, 7, false)
            .map_err(|_| ()),
    )
}

fn smoke_intel_ccs_primary_commits_through_the_presenter() -> TestResult {
    let mode = ccs_mode();
    let Some(ccs) = frame(&mode, I915_FORMAT_MOD_4_TILED_MTL_RC_CCS_CC) else {
        return TestResult::Pass;
    };
    let (Ok(ccs), Some(Ok(plain))) = (ccs, frame(&mode, TILE4_MODIFIER)) else {
        return TestResult::Fail("ADDFB2 must take the CCS and the plain Tile4 framebuffers");
    };
    // Without the option's card flag ADDFB2 refuses the modifier.
    {
        let off = tiled_mode();
        off.lock().intel_tile4 = true;
        if frame(&off, I915_FORMAT_MOD_4_TILED_MTL_RC_CCS_CC) != Some(Err(())) {
            return TestResult::Fail("a card without narf.intel.ccs must not take CCS");
        }
    }
    let queue = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    request(&cpu, ccs, 0, 0, NONBLOCK, None);
    let first = submit(&queue, &cpu, &events);
    let p = MockPlatform::new();
    let mut worker = worker(&p);
    // The queue's run future completes once its submissions are drained:
    // run it to completion for each commit.
    run(queue.run(&mut worker));
    if first.status() != 1 {
        return TestResult::Fail("the compressed commit must latch");
    }
    // PLANE_CTL: enable | XRGB8888 (8 << 23) | TILED_4 (5 << 10) |
    // RENDER_DECOMPRESSION (bit 15), no CLEAR_COLOR_DISABLE for _RC_CCS_CC;
    // PLANE_STRIDE in 128-byte Tile4 units; the AUX plane 0x18000 past the
    // main surface; the clear colour's native value split low/high.
    if p.read32(CTL) != 0x8400_9400
        || p.read32(STRIDE) != 1024 / 128
        || p.read32(AUX_DIST) != AUX_AT
        || p.read32(AUX_OFFSET) != 0
        || [p.read32(CC_VAL[0]), p.read32(CC_VAL[1])] != [0x89ab_cdef, 0x0123_4567]
    {
        return TestResult::Fail("the armed compressed primary must carry Linux's registers");
    }
    // Back to plain Tile4: decompression off and the AUX distance cleared.
    request(&cpu, plain, 0, 0, NONBLOCK, None);
    let second = submit(&queue, &cpu, &events);
    run(queue.run(&mut worker));
    if second.status() != 1 || p.read32(CTL) != 0x8400_1400 || p.read32(AUX_DIST) != 0 {
        return TestResult::Fail("a plain Tile4 flip must leave no decompression or AUX");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_intel_ccs_primary_commits_through_the_presenter
);

/// `PLANE_OFFSET(A, 1)`.
const PLANE_OFFSET: u64 = 0x701a4;

/// A panned compressed primary (`skl_check_plane_surface`): the AUX plane
/// first (`skl_check_ccs_aux_surface`), then the main surface stepped back
/// in 16 KiB units until its x/y match the AUX plane's
/// (`skl_check_main_surface`), values worked from Linux 7.4's arithmetic
/// for the 256x96 `_RC_CCS_CC` framebuffer above: main pitch 1024 (8 Tile4
/// tiles), AUX plane 24 pages in at pitch 128 (2 AUX tiles of 64 bytes x 64
/// lines; `intel_fb_offset_to_xy` gives it x/y (0, 768) in AUX units), AUX
/// subsampling 2 x 32 (`intel_fb_plane_get_subsampling`).
///
/// - At (160, 0) the AUX tile is (768 / 64) * 2 + 80 / 64 = 25, 0x19000,
///   with x/y (16 * 2, 0) = (32, 0); the main tile 5 rounds down to the
///   16 KiB offset 0x4000 with x 32 (`tgl_plane_min_alignment`): they
///   match, so `PLANE_SURF` is 0x4000 into the framebuffer's 16 KiB-aligned
///   GGTT base (0x0a000000, the arena's first), `PLANE_OFFSET` 0x20 and
///   `PLANE_AUX_DIST` 0x19000 - 0x4000 = 0x15000.
/// - At (33, 33) the AUX tile stays 0x18000 with x/y (33, 33); the main
///   offset 0x8000 (x/y 33, 1) never matches until offset 0 (x/y 33, 33):
///   `PLANE_OFFSET` 0x210021, `PLANE_AUX_DIST` 0x18000, in a second
///   mapping 16 KiB aligned past the first one's 26 pages (0x0a01c000).
fn smoke_intel_ccs_panned_primary_takes_linux_offsets() -> TestResult {
    let mode = ccs_mode();
    let Some(ccs) = frame(&mode, I915_FORMAT_MOD_4_TILED_MTL_RC_CCS_CC) else {
        return TestResult::Pass;
    };
    let Ok(ccs) = ccs else {
        return TestResult::Fail("ADDFB2 must take the CCS framebuffer");
    };
    let queue = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    request(&cpu, ccs, 160, 0, NONBLOCK, None);
    let first = submit(&queue, &cpu, &events);
    let p = MockPlatform::new();
    let mut worker = worker(&p);
    run(queue.run(&mut worker));
    if first.status() != 1
        || p.read32(CTL) != 0x8400_9400
        || p.read32(SURF) != 0x0a00_4000
        || p.read32(PLANE_OFFSET) != 0x20
        || p.read32(AUX_DIST) != 0x1_5000
        || p.read32(AUX_OFFSET) != 0
        || [p.read32(CC_VAL[0]), p.read32(CC_VAL[1])] != [0x89ab_cdef, 0x0123_4567]
    {
        return TestResult::Fail("the (160, 0) pan must take Linux's SURF, OFFSET and AUX_DIST");
    }
    request(&cpu, ccs, 33, 33, NONBLOCK, None);
    let second = submit(&queue, &cpu, &events);
    run(queue.run(&mut worker));
    if second.status() != 1
        || p.read32(SURF) != 0x0a01_c000
        || p.read32(PLANE_OFFSET) != 0x0021_0021
        || p.read32(AUX_DIST) != 0x1_8000
        || p.read32(CTL) != 0x8400_9400
    {
        return TestResult::Fail("the (33, 33) pan must keep the main surface at offset 0");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_intel_ccs_panned_primary_takes_linux_offsets
);
