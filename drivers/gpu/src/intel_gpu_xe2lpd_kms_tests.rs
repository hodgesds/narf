//! Display-20 (Xe2_LPD) KMS fixtures through the production Device/Guard/
//! Presenter/PollIo path (§17 10.5). Expected values are worked by hand from
//! Linux b90c984d: xe_pat.c (Xe2 `idx[XE_CACHE_NONE]` = 3, `PAT_INDEX(3)` at
//! 0x480c holding `XE2_PAT(0, 0, 0, 3, 3, 0)` = 0x3c), xe_ggtt.c
//! (`xelpg_ggtt_pte_flags`), xe_fb_pin.c, intel_display_irq.c
//! (`gen8_de_pipe_fault_mask`), intel_display_device.c (`xe2_lpd_display`,
//! `num_sprites`), intel_cursor.c (`i9xx_cursor_ctl`,
//! `intel_cursor_position`), intel_color.c and intel_psr.c (the display >=
//! 20 PSR1 branches). Register
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

    // The display-20 cursor is offered only over a proved display-20
    // resource layout: with GMD_ID_DISPLAY not reading 20.00, the cursor
    // profile capture refuses before any hardware write, even with the GT
    // owner's PAT3 programmed.
    let platform = MockPlatform::new();
    let timing = platform.dsb_timing();
    platform.set(0x480c, 0x3c);
    let device = lunar(&platform);
    let mut guard = complete(device.session()).unwrap();
    assert_eq!(
        complete(guard.cursor(None, false, Some((0, 0)), timing)),
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

const IDENTITY: [u64; 9] = [1 << 32, 0, 0, 0, 1 << 32, 0, 0, 0, 1 << 32];

fn gamma_ramp() -> Arc<crate::intel_gpu_color::Lut> {
    let bytes: Vec<u8> = (0..1024u32)
        .flat_map(|i| {
            let v = (i * 65535 / 1023) as u16;
            [v.to_le_bytes(), v.to_le_bytes(), v.to_le_bytes(), [0, 0]].concat()
        })
        .collect();
    crate::intel_gpu_color::Lut::decode(&bytes).unwrap()
}

/// The cursor and DSB owners map their GGTT pages with the IP's display
/// profile: Xe2 PTEs at PAT3 on display 20, admitted only while
/// `PAT_INDEX(3)` reads 0x3c; display 14 keeps PAT1 behind `PAT_INDEX(1)`.
#[cfg(target_arch = "x86_64")]
fn smoke_xe2lpd_kms_cursor_and_dsb_pages_map_xe2_pat3() -> TestResult {
    use crate::intel_gpu_scanout_io::display_pat_programmed;
    // The admission read, per generation.
    let platform = MockPlatform::new();
    assert!(!display_pat_programmed(&platform, Generation::LunarLake));
    assert!(display_pat_programmed(&platform, Generation::MeteorLake));
    platform.set(0x480c, 0x3c);
    assert!(display_pat_programmed(&platform, Generation::LunarLake));
    platform.set(0x4804, 0);
    assert!(!display_pat_programmed(&platform, Generation::MeteorLake));
    assert!(display_pat_programmed(&platform, Generation::TigerLake));
    assert!(!display_pat_programmed(&platform, Generation::PantherLake));

    for (generation, pat) in [(Generation::LunarLake, 3), (Generation::MeteorLake, 1)] {
        let platform = MockPlatform::new();
        let timing = platform.dsb_timing();
        platform.set(0x480c, 0x3c);
        // DSB command pages: 16 KiB, four PTEs.
        let mut dsb =
            crate::intel_gpu_dsb::Owner::reserve_for(platform.clone(), 0x100_0000, generation)
                .unwrap();
        dsb.arm(timing, &[(0x49028, 0)], None, platform.now())
            .unwrap();
        let pages = platform.dsb_mappings();
        assert_eq!(pages.len(), 8, "{generation:?}");
        for (r, v) in pages {
            if r % 8 == 0 {
                assert_eq!(v & 1, 1, "{generation:?} {r:#x}");
            } else {
                assert_eq!((v >> 20) & 3, pat, "{generation:?} {r:#x}");
            }
        }
        // Cursor image pages: two 64x64 ARGB slots, eight PTEs.
        let gem = crate::intel_gpu_gem::GemState::new();
        let handle = gem.create(16384, |_, _| Ok(())).unwrap();
        let image = gem.object(handle).unwrap();
        let mut cursor = crate::intel_gpu_cursor::Owner::new_for(
            platform.clone(),
            0x100_0000,
            timing,
            generation,
        )
        .unwrap();
        let regs = cursor
            .stage_with(|_| Vec::new(), Some(&image), true, Some((0, 0)))
            .unwrap();
        let base = regs.iter().find(|(r, _)| *r == 0x70084).unwrap().1;
        assert_ne!(base, 0);
        for page in 0..8u64 {
            let r = GGTT_ARRAY_BASE + (u64::from(base) / 4096 + page) * 8;
            assert_eq!(platform.read32(r) & 1, 1, "{generation:?} page {page}");
            assert_eq!((platform.read32(r + 4) >> 20) & 3, pat, "{generation:?}");
        }
        cursor.cancel_unarmed();
    }

    // Without the GT owner's PAT3, display 20 refuses both owners before
    // any write; a generation without a display-14/20 profile is refused.
    let platform = MockPlatform::new();
    let timing = platform.dsb_timing();
    assert!(matches!(
        crate::intel_gpu_dsb::Owner::reserve_for(
            platform.clone(),
            0x100_0000,
            Generation::LunarLake
        ),
        Err(FsError::NoDevice)
    ));
    assert!(matches!(
        crate::intel_gpu_cursor::Owner::new_for(
            platform.clone(),
            0x100_0000,
            timing,
            Generation::LunarLake
        ),
        Err(FsError::NoDevice)
    ));
    for refused in [Generation::PantherLake, Generation::TigerLake] {
        assert!(matches!(
            crate::intel_gpu_dsb::Owner::reserve_for(platform.clone(), 0x100_0000, refused),
            Err(FsError::Unsupported)
        ));
        assert!(matches!(
            crate::intel_gpu_cursor::Owner::new_for(platform.clone(), 0x100_0000, timing, refused),
            Err(FsError::Unsupported)
        ));
    }
    assert!(platform.writes().is_empty());
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe2lpd_kms",
    smoke_xe2lpd_kms_cursor_and_dsb_pages_map_xe2_pat3
);

/// The display-20 cursor owner's DE pipe faults are
/// `gen8_de_pipe_fault_mask`'s display >= 20 set: neither PIPEDMC fault
/// (25, 24) refuses a display-20 update, while the plane ATS (18), cursor
/// (11) and primary (7) faults and the FIFO underrun (31) do; display 14
/// refuses all six. `GEN12_PIPEDMC_INTERRUPT` (26) is no fault on either.
#[cfg(target_arch = "x86_64")]
fn smoke_xe2lpd_kms_cursor_fault_mask_drops_pipedmc() -> TestResult {
    for (bit, lunar_ok, meteor_ok) in [
        (25, true, false),
        (24, true, false),
        (18, false, false),
        (11, false, false),
        (7, false, false),
        (31, false, false),
        (26, true, true),
    ] {
        for (generation, admitted) in [
            (Generation::LunarLake, lunar_ok),
            (Generation::MeteorLake, meteor_ok),
        ] {
            let platform = MockPlatform::new();
            let timing = platform.dsb_timing();
            platform.set(0x480c, 0x3c);
            let mut cursor = crate::intel_gpu_cursor::Owner::new_for(
                platform.clone(),
                0x100_0000,
                timing,
                generation,
            )
            .unwrap();
            platform.set(IIR, 1 << bit);
            let staged = cursor.stage_with(|_| Vec::new(), None, false, Some((1, 2)));
            assert_eq!(staged.is_ok(), admitted, "bit {bit} {generation:?}");
            if !admitted {
                assert_eq!(staged, Err(FsError::NoDevice));
            }
            cursor.cancel_unarmed();
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe2lpd_kms",
    smoke_xe2lpd_kms_cursor_fault_mask_drops_pipedmc
);

/// `MockPlatform::cursor_resources` presenting display 20: GMD_ID_DISPLAY
/// 20.00, the GT owner's Xe2 PAT3 and a known display-20 307.2 MHz clock
/// (`xe2lpd_cdclk_table`: PLL ratio 16 locked, squash waveform 0xffff,
/// `CDCLK_CTL` with the MDCLK source select), then the owned single-pipe
/// display-20 resource initialization (MDCLK ratio 2 into the MBUS throttle
/// and DBUF minimum trackers).
#[cfg(target_arch = "x86_64")]
pub(super) fn display20_resources(platform: &MockPlatform) -> crate::intel_gpu_dsb::Timing {
    use crate::intel_gpu_xe2lpd::{DisplayIp, CDCLK_TABLE};
    let timing = platform.dsb_timing();
    let rung = CDCLK_TABLE[8];
    assert_eq!(
        (rung.cdclk_khz, rung.ratio, rung.waveform),
        (307_200, 16, 0xffff)
    );
    for (r, v) in [
        (0x510a0, 20 << 22),
        (0x480c, 0x3c),
        (0x70008, 0),
        (0x70180, 0),
        (0x46070, 0xc000_0010),
        (0x46008, 0x8f00_ffff),
        (
            0x46000,
            crate::intel_gpu_xelpg_cdclk::ctl_value_ip(DisplayIp::Xe2Lpd, rung),
        ),
    ] {
        platform.set(r, v);
    }
    let mode = crate::intel_gpu_modeset::Mode {
        pixel_clock_khz: timing.clock,
        h_active: timing.width,
        h_total: timing.htotal,
        v_active: timing.height,
        v_total: timing.vtotal,
        ..crate::intel_gpu_modeset::Mode::VESA_1024X768_60
    };
    crate::intel_gpu_display_resources::initialize(platform, &mode, 307_200)
        .unwrap()
        .unwrap();
    platform.set(0x70008, 3 << 30);
    platform.set(0x70180, 0x8400_0000);
    timing
}

#[cfg(target_arch = "x86_64")]
pub(super) fn drive<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    for _ in 0..1024 {
        if let Poll::Ready(result) = once(future.as_mut()) {
            return result;
        }
    }
    panic!("display-20 KMS conversation did not finish");
}

/// The display-20 cursor through the production Guard: the display-14
/// conversation (cursor WM/DDB, CTL, POS, BASE in the DSB's evaded window)
/// over the proved display-20 resource layout, with every cursor image and
/// DSB command PTE at Xe2 PAT3. Hiding it keeps the same mappings.
#[cfg(target_arch = "x86_64")]
fn smoke_xe2lpd_kms_cursor_arms_through_dsb_on_display20() -> TestResult {
    let platform = MockPlatform::new();
    let timing = display20_resources(&platform);
    let profile =
        crate::intel_gpu_display_resources::Profile::capture_timing(&platform, timing).unwrap();
    let device = lunar(&platform);
    let gem = crate::intel_gpu_gem::GemState::new();
    let handle = gem.create(16384, |_, _| Ok(())).unwrap();
    {
        let mut session = complete(device.session()).unwrap();
        drive(session.cursor(
            Some(gem.object(handle).unwrap()),
            true,
            Some((3, 4)),
            timing,
        ))
        .unwrap();
    }
    // i9xx_cursor_ctl: MCURSOR_MODE_64_ARGB_AX alone (ARB_SLOTS is display
    // 13 only); intel_cursor_position: x | y << 16.
    assert_eq!(platform.read32(0x70080), 0x27);
    assert_eq!(platform.read32(0x70088), 0x0004_0003);
    let base = platform.read32(0x700ac);
    assert_ne!(base, 0);
    assert_eq!(platform.read32(0x70084), base);
    for (r, v) in profile.cursor_registers(true) {
        assert_eq!(platform.read32(r), v, "cursor WM/DDB {r:#x}");
    }
    let pte = GGTT_ARRAY_BASE + u64::from(base) / 4096 * 8;
    assert_eq!(platform.read32(pte) & 1, 1);
    assert_eq!((platform.read32(pte + 4) >> 20) & 3, 3);
    // Eight cursor and four DSB pages, low and high words each.
    let mappings = platform.dsb_mappings();
    assert_eq!(mappings.len(), 24);
    for &(r, v) in &mappings {
        if r % 8 == 4 {
            assert_eq!((v >> 20) & 3, 3, "PTE {r:#x}");
        } else {
            assert_eq!(v & 1, 1, "PTE {r:#x}");
        }
    }
    // Hiding the cursor retires the plane and keeps the same pages.
    {
        let mut session = complete(device.session()).unwrap();
        drive(session.cursor(None, true, None, timing)).unwrap();
    }
    assert_eq!(platform.read32(0x70080), 0);
    assert_eq!(platform.read32(0x700ac), 0);
    assert_eq!(platform.dsb_mappings(), mappings);
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe2lpd_kms",
    smoke_xe2lpd_kms_cursor_arms_through_dsb_on_display20
);

/// CTM and the 1024-entry gamma LUT on display 20 through the production
/// Guard: the display-14 color owner (`tgl_color_funcs`; intel_color.c has
/// no branch between displays 14 and 20), restored to the original on
/// console return.
fn smoke_xe2lpd_kms_ctm_and_gamma_owned_on_display20() -> TestResult {
    use crate::intel_gpu_color::{GAMMA, MODE};
    let platform = MockPlatform::new();
    platform.set(0x49010, 0x1234_5678);
    let device = lunar(&platform);
    {
        let mut session = complete(device.session()).unwrap();
        complete(session.set_ctm(Some(IDENTITY))).unwrap();
        session.confirm_ctm();
        assert_eq!(platform.read32(MODE), 1 << 31);
        complete(session.restore_console()).unwrap();
        assert_eq!(platform.read32(MODE), 0);
        assert_eq!(platform.read32(0x49010), 0x1234_5678);
    }
    {
        let mut session = complete(device.session()).unwrap();
        complete(session.set_color(None, Some(gamma_ramp()))).unwrap();
        session.confirm_ctm();
        assert_eq!(platform.read32(GAMMA), (1 << 30) | 1);
        assert_eq!(platform.palette_writes(), 1024);
        complete(session.restore_console()).unwrap();
        assert_eq!(platform.read32(GAMMA), 0);
        assert_eq!(platform.palette_writes(), 2048);
    }
    assert!(device.legacy().is_ok());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe2lpd_kms",
    smoke_xe2lpd_kms_ctm_and_gamma_owned_on_display20
);
