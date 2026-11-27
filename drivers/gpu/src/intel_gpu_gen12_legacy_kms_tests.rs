//! Rocket Lake panel (`narf.intel.rkl_edp=1`) presenter fixtures through the
//! production Device/Guard/Presenter/PollIo path and the Gen12 primary
//! owner. Values are worked from Linux 7.4: `intel_display_device.c`
//! (`rkl_desc`: `XE_D_DISPLAY` with `pipe_mask` A-C; four sprites under
//! `HAS_D12_PLANE_MINIMIZATION`), `gen8_ggtt_pte_encode` (a present-only
//! Gen12 GGTT PTE, no PAT bits) and `skl_plane_ctl` (the linear XRGB8888
//! primary, `PLANE_CTL` 0x84000000 on display 12). The shared native KMS
//! model supplies only the hardware latch.
use super::*;

/// Two 4 KiB present-only Gen12 PTEs (bit 0, no PAT field and no high
/// bits above the 39-bit address) for the 64x32 XR24 frame.
fn gen12_system_ptes(mappings: &[(u64, u32)], platform: &MockPlatform) -> bool {
    let low: Vec<_> = mappings.iter().filter(|(r, _)| r % 8 == 0).collect();
    low.len() == 2
        && low.iter().all(|&&(register, pte)| {
            pte & 0xfff == 1 && platform.read32(register + 4) & !0x7f == 0
        })
}

/// With `narf.intel.rkl_edp=1` the Rocket Lake panel's Pipe A primary flips
/// a GEM framebuffer in hardware as Tiger Lake's does: the Gen12 primary
/// owner captures the panel route, two Gen12 PTEs map the frame, `PLANE_SURF`
/// latches inside the GEM arena, and the console comes back with every
/// mapping cleared. Rocket Lake's missing pipe D and planes 6/7 are never
/// read.
fn smoke_intel_rkl_panel_presenter_latches_gem_flips() -> TestResult {
    crate::intel_gpu_modeset::set_rkl_edp(true);
    let result = rkl_presenter_run();
    crate::intel_gpu_modeset::set_rkl_edp(false);
    result
}
fn rkl_presenter_run() -> TestResult {
    let platform = MockPlatform::new();
    let device = platform.rocket();
    let Ok(object) = object(true) else {
        // aarch64 has no WC system placement.
        return TestResult::Pass;
    };
    let mut guard = complete(device.session()).unwrap();
    if complete(guard.present(object, geometry())).is_err() {
        return TestResult::Fail("the Rocket Lake panel presents a GEM frame");
    }
    let live = platform.read32(LIVE);
    if live == CONSOLE
        || platform.read32(SURF) != live
        || !(GEM_SCANOUT_GTT_START..GEM_SCANOUT_GTT_END).contains(&u64::from(live))
    {
        return TestResult::Fail("PLANE_SURF latches inside the GEM arena");
    }
    if !gen12_system_ptes(&platform.primary_mappings(), &platform) {
        return TestResult::Fail("two present-only Gen12 PTEs map the frame");
    }
    if complete(guard.restore_console()).is_err()
        || platform.read32(LIVE) != CONSOLE
        || !platform.primary_mappings().is_empty()
    {
        return TestResult::Fail("the console is restored and the mappings cleared");
    }
    if platform.forbidden_display_reads() != 0 {
        return TestResult::Fail("Rocket Lake has no pipe D and five planes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_rkl_panel_presenter_latches_gem_flips
);

/// Without `narf.intel.rkl_edp=1` no Rocket Lake panel is owned, and the
/// presenter is refused (`Unsupported`, so the KMS falls back to the CPU
/// copy) before any GEM page is mapped or `PLANE_SURF` armed. The Gen12
/// identity tables hold for Rocket Lake either way: display 12 with the
/// Tiger Lake PTE and no PAT index, and a generation/family pair that
/// agrees.
fn smoke_intel_rkl_presenter_refused_without_rkl_edp() -> TestResult {
    use crate::intel_gpu_gt::Gen12Platform;
    use crate::intel_gpu_gtt::PteFormat;
    use crate::intel_gpu_scanout_io::{display_pat_programmed, display_pte, gen12_generation};
    if display_pte(Generation::RocketLake) != Some((PteFormat::Gen12, 0))
        || !display_pat_programmed(&MockPlatform::new(), Generation::RocketLake)
        || gen12_generation(Gen12Platform::RocketLake) != Generation::RocketLake
        || gen12_generation(Gen12Platform::TigerLake) != Generation::TigerLake
        || gen12_generation(Gen12Platform::AlderLakeS) != Generation::AlderLake
    {
        return TestResult::Fail("Rocket Lake's Gen12 display tables");
    }
    crate::intel_gpu_modeset::set_rkl_edp(false);
    let platform = MockPlatform::new();
    let device = platform.rocket();
    let Ok(object) = object(true) else {
        return TestResult::Pass;
    };
    let mut guard = complete(device.session()).unwrap();
    if complete(guard.present(object, geometry())) != Err(FsError::Unsupported) {
        return TestResult::Fail("no presenter without narf.intel.rkl_edp=1");
    }
    if !platform.primary_mappings().is_empty()
        || platform.read32(SURF) != CONSOLE
        || platform.read32(LIVE) != CONSOLE
    {
        return TestResult::Fail("refused before any page is mapped or armed");
    }
    let _ = complete(guard.restore_console());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_rkl_presenter_refused_without_rkl_edp
);
