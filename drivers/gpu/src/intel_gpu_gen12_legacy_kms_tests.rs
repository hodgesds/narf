//! Rocket Lake panel (`narf.intel.rkl_edp=1`) and DG1 (`narf.intel.dg1_kms=1`)
//! presenter fixtures through the production Device/Guard/Presenter/PollIo
//! path. Values are worked from Linux 7.4: `intel_display_device.c`
//! (`rkl_desc`: `XE_D_DISPLAY` with `pipe_mask` A-C; four sprites under
//! `HAS_D12_PLANE_MINIMIZATION`; `dg1_desc`: `XE_D_DISPLAY`),
//! `gen8_ggtt_pte_encode` (a present-only Gen12 GGTT PTE, no PAT bits;
//! `GEN12_GGTT_PTE_LM`, bit 1, for local memory), `i915_fb_pin.c`
//! `intel_fb_pin_to_ggtt` (with `HAS_LMEM` a framebuffer migrates to
//! `LMEM_0`) and `skl_plane_ctl` (the linear XRGB8888 primary, `PLANE_CTL`
//! 0x84000000 on display 12). The shared native KMS model supplies only the
//! hardware latch.
use super::*;

/// Two 4 KiB present-only Gen12 PTEs (bit 0, no PAT field and no high
/// bits above the 39-bit address) for the 64x32 XR24 frame.
fn gen12_system_ptes(mappings: &[(u64, u32)], platform: &MockPlatform) -> bool {
    let low: Vec<_> = mappings.iter().filter(|(r, _)| r % 8 == 0).collect();
    low.len() == 2
        && low
            .iter()
            .all(|&&(register, pte)| pte & 0xfff == 1 && platform.read32(register + 4) & !0x7f == 0)
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

/// DG1 (`narf.intel.dg1_kms=1`): Tiger Lake's display 12 on a discrete
/// card, its firmware-lit Pipe A on an external port (here DDI B HDMI, no
/// panel power). The integrated panel's Gen12 owner does not apply; the
/// presenter flips a VRAM framebuffer with a Gen12 local-memory PTE
/// (present | `GEN12_GGTT_PTE_LM`) and refuses a system-memory one before
/// mapping it (`intel_fb_pin_to_ggtt` puts every DG1 framebuffer in
/// `LMEM_0`), which the KMS then presents by CPU copy. The console comes
/// back with every mapping cleared.
fn smoke_intel_dg1_presenter_flips_vram_on_firmware_pipe_a() -> TestResult {
    use crate::intel_gpu_gem::GemState;
    use crate::intel_gpu_gtt::{PTE_DM, PTE_PRESENT};
    use crate::intel_gpu_vram::{Vram, VramLayout};
    let platform = MockPlatform::new();
    // No panel: PP_STATUS/PP_CONTROL off, DDI A's buffer off, and
    // TRANS_DDI_FUNC_CTL A on DDI B (TGL_TRANS_DDI_SELECT_PORT = 2) in HDMI
    // mode (TRANS_DDI_MODE_SELECT_HDMI = 0).
    for (register, value) in [
        (0xc7200, 0),
        (0xc7204, 0),
        (0x64000, 0),
        (0x60400, (1 << 31) | (2 << 27)),
        (0x64100, 1 << 31),
    ] {
        platform.set(register, value);
    }
    let device = platform.dg1();
    let order = 6u8;
    let Ok(frame) = narf_memory::frame::alloc_pages_on(0, order) else {
        return TestResult::Fail("VRAM fixture frames");
    };
    let len = 256 * 1024;
    let bar = narf_bus::MmioRegion {
        phys: frame.start_address(),
        virt: frame.start_address().kernel_ptr::<u8>() as u64,
        len,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    let layout = VramLayout {
        tile_size: len,
        tile_offset: 0,
        usable: len,
    };
    // SAFETY: exclusively owned contiguous frames back this fixture's LMEM
    // pool, freed only after every object and the pool are dropped.
    let pool = unsafe { Vram::new(bar, layout) }.unwrap();
    let gem = GemState::new();
    let pending = gem
        .prepare_vram_class(8192, None, &pool, true)
        .expect("prepare vram bo");
    let vram = pending.object();
    vram.mark_scanout();
    let result = (|| {
        let mut guard = complete(device.session()).unwrap();
        if let Ok(system) = object(true) {
            if complete(guard.present(system, geometry())) != Err(FsError::Unsupported)
                || !platform.primary_mappings().is_empty()
                || platform.read32(LIVE) != CONSOLE
            {
                return TestResult::Fail("DG1 refuses a system-memory frame before mapping it");
            }
        }
        if complete(guard.present(vram.clone(), geometry())).is_err() {
            return TestResult::Fail("DG1 presents its VRAM frame");
        }
        let live = platform.read32(LIVE);
        if live == CONSOLE
            || platform.read32(SURF) != live
            || !(GEM_SCANOUT_GTT_START..GEM_SCANOUT_GTT_END).contains(&u64::from(live))
        {
            return TestResult::Fail("PLANE_SURF latches inside the GEM arena");
        }
        let pte = GGTT_ARRAY_BASE + u64::from(live) / 4096 * 8;
        if u64::from(platform.read32(pte)) & (PTE_PRESENT | PTE_DM) != PTE_PRESENT | PTE_DM {
            return TestResult::Fail("a Gen12 local-memory PTE maps the frame");
        }
        if complete(guard.restore_console()).is_err()
            || platform.read32(LIVE) != CONSOLE
            || !platform.primary_mappings().is_empty()
        {
            return TestResult::Fail("the console is restored and the mappings cleared");
        }
        TestResult::Pass
    })();
    drop(pending);
    drop(vram);
    drop(pool);
    narf_memory::frame::free_pages(frame, order);
    result
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_dg1_presenter_flips_vram_on_firmware_pipe_a
);

/// The integrated Gen12 owner still refuses every other discrete display:
/// DG2 (display 13, no Gen12 family) gets no presenter (`Unsupported`, the
/// CPU copy), and a DG1 identity whose generation is not Tiger Lake's
/// display 12 fails closed (`NoDevice`), both before any page is mapped.
fn smoke_intel_discrete_presenter_refusals_besides_dg1() -> TestResult {
    let Ok(object) = object(true) else {
        return TestResult::Pass;
    };
    object.mark_scanout();
    let dg2 = MockPlatform::new();
    dg2.0.lock().discrete = Some(crate::intel_gpu_xe2lpd::DiscreteDisplayIp::Dg2);
    let device = Device::new(dg2.clone(), Generation::AlderLake, 0x1000000, console());
    let mut guard = complete(device.session()).unwrap();
    if complete(guard.present(object.clone(), geometry())) != Err(FsError::Unsupported)
        || !dg2.primary_mappings().is_empty()
        || dg2.read32(LIVE) != CONSOLE
    {
        return TestResult::Fail("DG2 stays without a presenter");
    }
    let _ = complete(guard.restore_console());
    drop(guard);
    let crossed = MockPlatform::new();
    let mut platform = crossed.clone();
    platform.3 = Some(crate::intel_gpu_gt::Gen12Platform::Dg1);
    crossed.0.lock().discrete = Some(crate::intel_gpu_xe2lpd::DiscreteDisplayIp::Dg1);
    let device = Device::new(platform, Generation::AlderLake, 0x1000000, console());
    let mut guard = complete(device.session()).unwrap();
    if complete(guard.present(object, geometry())) != Err(FsError::NoDevice)
        || !crossed.primary_mappings().is_empty()
    {
        return TestResult::Fail("a crossed DG1 identity fails closed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_discrete_presenter_refusals_besides_dg1
);
