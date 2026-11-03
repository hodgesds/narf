//! Display-20 (Xe2_LPD) KMS fixtures through the production Device/Guard/
//! Presenter/PollIo path (§17 10.5). Expected values are worked by hand from
//! Linux b90c984d: xe_pat.c (Xe2 `idx[XE_CACHE_NONE]` = 3), xe_ggtt.c
//! (`xelpg_ggtt_pte_flags`), xe_fb_pin.c, intel_display_irq.c
//! (`gen8_de_pipe_fault_mask`), intel_display_device.c (`xe2_lpd_display`,
//! `num_sprites`) and intel_psr.c (the display >= 20 PSR1 branches). Register
//! literals are repeated independently of the production constants; the
//! shared native KMS model supplies only the hardware latch.
use super::*;

/// FLIP_DONE | PLANE1_FAULT | PIPEDMC_FAULT | FIFO_UNDERRUN | plane ATS |
/// PIPEDMC ATS: every DE pipe status bit any profile may own.
const ALL_OWNED: u32 = 0x8304_0088;

fn lunar(platform: &MockPlatform) -> Device<MockPlatform> {
    Device::new(
        platform.clone(),
        Generation::LunarLake,
        0x100_0000,
        console(),
    )
}

fn smoke_xe2lpd_kms_pte_profile_and_owned_status() -> TestResult {
    use crate::intel_gpu_gtt::PteFormat;
    use crate::intel_gpu_scanout_io::{display_pte, owned_status};
    // GEM scanout PTE profiles: Gen12 has no PAT field; MTL keeps PAT1;
    // display 20 maps with xe2 idx[XE_CACHE_NONE] = 3; PTL has no owner.
    assert_eq!(
        display_pte(Generation::TigerLake),
        Some((PteFormat::Gen12, 0))
    );
    assert_eq!(
        display_pte(Generation::AlderLake),
        Some((PteFormat::Gen12, 0))
    );
    assert_eq!(
        display_pte(Generation::MeteorLake),
        Some((PteFormat::XeLpg, 1))
    );
    assert_eq!(
        display_pte(Generation::LunarLake),
        Some((PteFormat::Xe2, 3))
    );
    assert_eq!(display_pte(Generation::PantherLake), None);
    // XELPG_GGTT_PTE_PAT0 (bit 52) | XELPG_GGTT_PTE_PAT1 (bit 53).
    assert_eq!(
        PteFormat::Xe2.encode_ggtt(0x1234_5000, 3),
        Ok(0x0030_0000_1234_5001)
    );
    assert_eq!(
        PteFormat::XeLpg.encode_ggtt(0x1234_5000, 1),
        Ok(0x0010_0000_1234_5001)
    );
    // Display 20 is not limited to the Gen12 39-bit display DMA mask.
    assert_eq!(
        crate::intel_gpu_gtt::encode_display_pte(PteFormat::Xe2, 0x2000_0000_0000, 3),
        Ok(0x0030_2000_0000_0001)
    );
    // Owned DE pipe status: display 20 drops GEN12_PIPEDMC_FAULT (25) and
    // MTL_PIPEDMC_ATS_FAULT (24) and keeps MTL_PLANE_ATS_FAULT (18).
    assert_eq!(owned_status(Generation::MeteorLake), 0x8304_0088);
    assert_eq!(owned_status(Generation::LunarLake), 0x8004_0088);
    assert_eq!(owned_status(Generation::TigerLake), 0x8200_0088);
    assert_eq!(owned_status(Generation::AlderLake), 0x8200_0088);

    // The console takes the firmware surface's own PAT index, only if 0.
    use crate::intel_gpu_xe2lpd::{console_pat, firmware_pte_pat};
    assert_eq!(firmware_pte_pat(0x0010_0001, 0), Some(0));
    assert_eq!(firmware_pte_pat(0x0010_0001, 1 << 20), Some(1));
    assert_eq!(firmware_pte_pat(0x0010_0001, 3 << 20), Some(3));
    assert_eq!(firmware_pte_pat(0x0010_0000, 0), None); // not present
    assert_eq!(firmware_pte_pat(u32::MAX, 0), None);
    assert_eq!(firmware_pte_pat(1, u32::MAX), None);
    assert_eq!(console_pat(Some(0)), Some(0));
    for refused in [Some(1), Some(2), Some(3), None] {
        assert_eq!(console_pat(refused), None);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe2lpd_kms",
    smoke_xe2lpd_kms_pte_profile_and_owned_status
);

/// A fixed linear XRGB8888 flip on Pipe A, then console restoration: the
/// GEM pages map with PAT3 and the owned status is the display-20 set; the
/// display-14 profile, run through the same conversation, is unchanged.
#[cfg(target_arch = "x86_64")]
fn smoke_xe2lpd_kms_linear_flip_maps_pat3_and_restores_console() -> TestResult {
    for (generation, pat, status) in [
        (Generation::LunarLake, 3, 0x8004_0088),
        (Generation::MeteorLake, 1, 0x8304_0088),
    ] {
        let platform = MockPlatform::new();
        let device = Device::new(platform.clone(), generation, 0x100_0000, console());
        let object = object(true).unwrap();
        let weak = Arc::downgrade(&object);
        let mut guard = complete(device.session()).unwrap();
        complete(guard.present(object.clone(), geometry())).unwrap();
        let surface = platform.read32(LIVE);
        assert!((GEM_SCANOUT_GTT_START..GEM_SCANOUT_GTT_END).contains(&u64::from(surface)));
        assert_eq!(platform.read32(SURF), surface);
        let pte = GGTT_ARRAY_BASE + u64::from(surface) / 4096 * 8;
        assert_eq!(platform.read32(pte) & 0xfff, 1, "{generation:?}");
        assert_eq!((platform.read32(pte + 4) >> 20) & 3, pat, "{generation:?}");
        assert_eq!(platform.read32(IER) & ALL_OWNED, status, "{generation:?}");
        assert_eq!(platform.read32(IMR) & status, status);
        drop(object);
        complete(guard.restore_console()).unwrap();
        assert_eq!(platform.read32(LIVE), CONSOLE);
        assert_eq!(platform.read32(pte), 0);
        assert_eq!(platform.read32(pte + 4), 0);
        assert!(weak.upgrade().is_none());
        assert_eq!(platform.read32(IER), 0);
        assert_eq!(platform.read32(IMR), u32::MAX);
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe2lpd_kms",
    smoke_xe2lpd_kms_linear_flip_maps_pat3_and_restores_console
);

fn smoke_xe2lpd_kms_fetcher_inventory_and_refused_services() -> TestResult {
    // FBC A–D and five universal planes per pipe on display 20.
    for (register, lunar_ok, meteor_ok, tiger_ok) in [
        (0x43288u64, false, true, true), // FBC C: only display 20 has it
        (0x432c8, false, true, true),    // FBC D
        (0x43248, false, false, true),   // FBC B: display 14 and 20
        (0x71580, false, false, false),  // PLANE_CTL_5_B
        (0x70680, true, true, false),    // PLANE_CTL_6_A: TGL only
        (0x72c08, false, false, false),  // DSB_CTRL(C, 1)
        (0x73080, false, false, false),  // CUR_CTL_D
    ] {
        for (generation, admitted) in [
            (Generation::LunarLake, lunar_ok),
            (Generation::MeteorLake, meteor_ok),
            (Generation::TigerLake, tiger_ok),
        ] {
            let platform = MockPlatform::new();
            platform.set(register, 0x8000_0001);
            assert_eq!(
                fetchers_with_cursor(&platform, generation, false, false).is_ok(),
                admitted,
                "{register:#x} {generation:?}"
            );
        }
    }

    // Cursor and CTM are not offered on display 20 in this slice: refused
    // before any hardware write.
    let platform = MockPlatform::new();
    let timing = platform.dsb_timing();
    let device = lunar(&platform);
    let mut guard = complete(device.session()).unwrap();
    assert_eq!(
        complete(guard.cursor(None, false, Some((0, 0)), timing)),
        Err(FsError::Unsupported)
    );
    assert_eq!(
        complete(guard.set_ctm(Some([0; 9]))),
        Err(FsError::Unsupported)
    );
    assert_eq!(platform.read32(SURF), CONSOLE);
    assert_eq!(platform.read32(IER), 0);
    assert!(platform.writes().is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe2lpd_kms",
    smoke_xe2lpd_kms_fetcher_inventory_and_refused_services
);

/// PSR1 stays refused on display 20: with a PSR-capable sink, a
/// PSR-enabling VBT and qualifying watermarks (the display-14 enable
/// fixture's inputs), a latched display-20 flip neither writes the sink's
/// PSR configuration nor arms `PSR_CTL`. intel_psr.c's display >= 20 PSR1
/// differs in hsw_activate_psr1 (no MAX_SLEEP_TIME, ENTRY_SETUP_FRAMES),
/// the SRD_STATUS set-context latency and Wa_16025596647, none of which is
/// implemented.
#[cfg(target_arch = "x86_64")]
fn smoke_xe2lpd_kms_psr1_refused_on_display20() -> TestResult {
    let platform = MockPlatform::new();
    let timing = platform.dsb_timing();
    super::psr::attach(&platform, timing, Some(false));
    let device = lunar(&platform);
    let mut guard = complete(device.session()).unwrap();
    complete(guard.present(object(true).unwrap(), geometry())).unwrap();
    drop(guard);
    assert!(super::psr::psr(&device).is_none());
    assert_eq!(platform.read32(super::psr::PSR_CTL) & (1 << 31), 0);
    assert!(super::psr::sink_writes(&platform.all_writes()).is_empty());
    // The display-14 owner, given the same inputs, does enable it.
    let platform = MockPlatform::new();
    let timing = platform.dsb_timing();
    super::psr::attach(&platform, timing, Some(false));
    let device = platform.meteor();
    super::psr::present_once(&device, object(true).unwrap());
    assert!(super::psr::psr(&device).is_some());
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe2lpd_kms",
    smoke_xe2lpd_kms_psr1_refused_on_display20
);
