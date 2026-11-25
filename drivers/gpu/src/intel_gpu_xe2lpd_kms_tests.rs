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
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
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
                fetchers_with_cursor(&platform, generation, None, false, false).is_ok(),
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
/// Display-20 PSR1 qualification and programming through the KMS latch
/// (`Xe2Lpd`, `intel_psr.c` display >= 20 branches):
/// - SRD_STATUS requires `TRANS_SET_CONTEXT_LATENCY_A >= 1` (`0x6007c`):
///   with SCL == 0 PSR1 refuses without touching PSR registers/sink.
/// - With SCL >= 1, PSR1 enables with no `EDP_PSR_MAX_SLEEP_TIME` in
///   `PSR_CTL` (`0x1f << 20`), no `EDP_PSR_DEBUG_MASK_MAX_SLEEP` (`1 << 28`)
///   in `PSR_DEBUG`, and `LNL_EDP_PSR_ENTRY_SETUP_FRAMES` (`bits 17:16`).
/// - Long setup times compute `entry_setup_frames == 1` instead of
///   `SetupTimeTooLong`, `Wa_18037818876` refuses PSR1 without SU, and
///   `Wa_16025596647` blocks PKGC via `PIPEDMC_BLOCK_PKGC_SW_A` when
///   non-PSR pipes are active.
#[cfg(target_arch = "x86_64")]
fn smoke_xe2lpd_kms_psr1_enabled_on_display20() -> TestResult {
    // 1. With TRANS_SET_CONTEXT_LATENCY_A == 0, SRD_STATUS precondition refuses PSR1.
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

    // 2. With TRANS_SET_CONTEXT_LATENCY_A >= 1, display-20 PSR1 enables without
    // MAX_SLEEP_TIME in PSR_CTL or MAX_SLEEP in PSR_DEBUG.
    let platform = MockPlatform::new();
    platform.set(0x6007c, 1);
    let timing = platform.dsb_timing();
    super::psr::attach(&platform, timing, Some(false));
    let device = lunar(&platform);
    super::psr::present_once(&device, object(true).unwrap());
    let psr = super::psr::psr(&device).unwrap();
    assert!(psr.config().display20);
    assert_eq!(psr.config().entry_setup_frames, 0);
    let ctl = platform.read32(super::psr::PSR_CTL);
    assert_ne!(ctl & (1 << 31), 0);
    assert_eq!(ctl & (0x1f << 20), 0);
    assert_eq!(ctl & (3 << 16), 0);
    assert_eq!(platform.read32(0x60860), (1 << 27) | (1 << 26) | (1 << 25));

    // 3. Long setup time on display 20 computes entry_setup_frames = 1 (encoded
    // in bits 17:16 of PSR_CTL) instead of refusing SetupTimeTooLong; without
    // SU, Wa_18037818876 refuses with SetupFramesNoSu.
    let short_vblank = crate::intel_gpu_dsb::Timing {
        clock: 1034,
        width: 64,
        height: 32,
        htotal: 224,
        vtotal: 34, // blank = 2, cap = 1 line, 330 us = 2 lines > 1
        flags: 0,
    };
    let sink = crate::intel_gpu_psr::Sink::read(&mut PsrAux(&platform)).unwrap();
    let vbt = platform.psr_vbt();
    assert_eq!(
        crate::intel_gpu_psr::compute_psr1(&sink, &short_vblank, &vbt, Some(false)),
        Err(crate::intel_gpu_psr::Refusal::SetupTimeTooLong)
    );
    assert_eq!(
        crate::intel_gpu_psr::compute_psr1_for(
            &sink,
            &short_vblank,
            &vbt,
            Some(false),
            true,
            Some(1),
            false,
        ),
        Err(crate::intel_gpu_psr::Refusal::SetupFramesNoSu)
    );
    let su_cfg = crate::intel_gpu_psr::compute_psr1_for(
        &sink,
        &short_vblank,
        &vbt,
        Some(false),
        true,
        Some(1),
        true,
    )
    .unwrap();
    assert_eq!(su_cfg.entry_setup_frames, 1);
    assert_eq!(crate::intel_gpu_psr::psr1_ctl(&su_cfg) & (3 << 16), 1 << 16);
    assert_eq!(crate::intel_gpu_psr::psr1_ctl(&su_cfg) & (0x1f << 20), 0);

    // 4. Wa_16025596647: non-PSR pipes engage PIPEDMC_BLOCK_PKGC_SW_A while active
    // and clear it on disable.
    crate::intel_gpu_psr::set_non_psr_pipes(0b10);
    let wa_platform = MockPlatform::new();
    wa_platform.set(0x6007c, 1);
    let wa_timing = wa_platform.dsb_timing();
    super::psr::attach(&wa_platform, wa_timing, Some(false));
    let wa_device = lunar(&wa_platform);
    super::psr::present_once(&wa_device, object(true).unwrap());
    assert_ne!(
        wa_platform.read32(crate::intel_gpu_psr::pipedmc_block_pkgc_sw(0))
            & crate::intel_gpu_psr::PIPEDMC_BLOCK_PKGC_SW_BLOCK_PKGC_ALWAYS,
        0
    );
    {
        let mut guard = complete(wa_device.session()).unwrap();
        complete(guard.restore_console()).unwrap();
    }
    assert_eq!(
        wa_platform.read32(crate::intel_gpu_psr::pipedmc_block_pkgc_sw(0))
            & crate::intel_gpu_psr::PIPEDMC_BLOCK_PKGC_SW_BLOCK_PKGC_ALWAYS,
        0
    );
    crate::intel_gpu_psr::set_non_psr_pipes(0);

    // 5. The display-14 owner continues to enable with MAX_SLEEP_TIME.
    let platform = MockPlatform::new();
    let timing = platform.dsb_timing();
    super::psr::attach(&platform, timing, Some(false));
    let device = platform.meteor();
    super::psr::present_once(&device, object(true).unwrap());
    let mtl_psr = super::psr::psr(&device).unwrap();
    assert!(!mtl_psr.config().display20);
    assert_ne!(platform.read32(super::psr::PSR_CTL) & (0x1f << 20), 0);
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe2lpd_kms",
    smoke_xe2lpd_kms_psr1_enabled_on_display20
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

/// The display-20 DPT layout (intel_fb.c, display >= 14 with DPT): the
/// remapped stride `roundup_pow_of_two(max(width tiles, 8))`, entries for
/// the visible tiles of each row at `row * dst`, padding unmapped, and a
/// source stride wider than the DPT stride refused (it would make
/// `PLANE_STRIDE` the DPT stride).
fn smoke_xe2lpd_kms_dpt_layout_pot_remap() -> TestResult {
    use crate::intel_gpu_scanout::{DptLayout, Layout};
    let g = |width, height, pitch| Geometry {
        width,
        height,
        pitch,
    };
    // 1080p Tile4 (128-byte, 32-row tiles) at the packed pitch: 60 source
    // tiles, DPT stride 64, 34 tile rows.
    let tile4 = DptLayout::new(g(1920, 1080, 7680), Layout::Tile4).unwrap();
    assert_eq!(
        tile4,
        DptLayout {
            src: 60,
            width: 60,
            dst: 64,
            rows: 34
        }
    );
    assert_eq!(tile4.bytes(), 20480);
    assert_eq!(tile4.source(0), Some(0));
    assert_eq!(tile4.source(59), Some(59));
    assert_eq!(tile4.source(60), None);
    assert_eq!(tile4.source(63), None);
    assert_eq!(tile4.source(64), Some(60));
    assert_eq!(tile4.source(64 * 33 + 59), Some(33 * 60 + 59));
    assert_eq!(tile4.source(64 * 34), None);
    // A power-of-two pitch is its own DPT stride.
    let pot = DptLayout::new(g(1920, 1080, 8192), Layout::Tile4).unwrap();
    assert_eq!((pot.src, pot.dst), (64, 64));
    assert_eq!(pot.source(64), Some(64));
    // A source stride beyond the DPT stride is refused.
    assert_eq!(DptLayout::new(g(1920, 1080, 9216), Layout::Tile4), None);
    // X (512-byte, 8-row tiles): 15 tiles, DPT stride 16, 135 rows.
    let x = DptLayout::new(g(1920, 1080, 7680), Layout::X).unwrap();
    assert_eq!((x.src, x.width, x.dst, x.rows), (15, 15, 16, 135));
    assert_eq!(x.bytes(), 20480);
    // The minimum DPT stride is 8: the 64x32 fixture has two tiles in one
    // row.
    let small = DptLayout::new(geometry(), Layout::Tile4).unwrap();
    assert_eq!(
        (small.src, small.width, small.dst, small.rows),
        (2, 2, 8, 1)
    );
    assert_eq!(small.bytes(), 4096);
    assert_eq!(small.source(1), Some(1));
    assert_eq!(small.source(2), None);
    assert_eq!(small.source(8), None);
    // No DPT for a linear surface or an invalid tiled geometry.
    assert_eq!(DptLayout::new(geometry(), Layout::Linear), None);
    assert_eq!(DptLayout::new(g(1920, 1080, 7744), Layout::Tile4), None);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe2lpd_kms",
    smoke_xe2lpd_kms_dpt_layout_pot_remap
);

/// A display-20 Tile4 flip through the production Guard and the joint DSB:
/// Tile4 is admitted over the display-20 resources without the display-14
/// no-DPT chicken, and the presenter builds the remapped DPT (64x32 at pitch
/// 256: source stride 2, DPT stride 8, one row), maps its page at a 2 MiB
/// aligned GGTT address with Xe2 PAT3 and arms `PLANE_SURF` there with
/// `PLANE_CTL_TILED_4` and the source stride. The entries are the
/// framebuffer pages' GGTT PTEs at PAT3; the padding stays zero.
#[cfg(target_arch = "x86_64")]
fn smoke_xe2lpd_kms_tile4_flips_through_owned_dpt() -> TestResult {
    use crate::intel_gpu_scanout::{Layout, View};
    let platform = MockPlatform::new();
    let timing = display20_resources(&platform);
    crate::intel_gpu_kms::tile4_profile(&platform, geometry(), timing).unwrap();
    let device = lunar(&platform);
    let fb = object(true).unwrap();
    let frames: Vec<u64> = fb.pages().collect();
    assert_eq!(frames.len(), 2);
    let view = View {
        layout: Layout::Tile4,
        ..View::default()
    };
    {
        let mut session = complete(device.session()).unwrap();
        drive(session.present_color(
            fb.clone(),
            geometry(),
            view,
            None,
            Default::default(),
            timing,
        ))
        .unwrap();
    }
    assert_eq!(platform.read32(0x70180), 0x8400_1400);
    assert_eq!(platform.read32(0x70188), 2);
    let surface = platform.read32(LIVE);
    assert_eq!(platform.read32(SURF), surface);
    assert_eq!(surface % (2 << 20), 0);
    assert!((GEM_SCANOUT_GTT_START..GEM_SCANOUT_GTT_END).contains(&u64::from(surface)));
    let pte = GGTT_ARRAY_BASE + u64::from(surface) / 4096 * 8;
    let (low, high) = (platform.read32(pte), platform.read32(pte + 4));
    assert_eq!(low & 1, 1);
    assert_eq!((high >> 20) & 3, 3);
    // The one-page table is all that is mapped behind PLANE_SURF.
    assert_eq!(platform.read32(pte + 8), 0);
    let table = (u64::from(low) | (u64::from(high) << 32)) & crate::intel_gpu_gtt::PTE_PHYS_MASK;
    let entry = |index: u64| -> u64 {
        // SAFETY: the presenter retains this DPT page, mapped by the PTE
        // just read, for the surface's lifetime.
        unsafe {
            narf_memory::PhysAddr::new(table + index * 8)
                .kernel_ptr::<u64>()
                .read_volatile()
        }
    };
    for (index, phys) in frames.iter().enumerate() {
        assert_eq!(entry(index as u64), phys | 1 | (3 << 52), "entry {index}");
    }
    for index in 2..512 {
        assert_eq!(entry(index), 0, "padding {index}");
    }
    // Display 20 has no no-DPT chicken to own.
    assert!(platform.all_writes().iter().all(|&(r, _)| r != 0x7026c));
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe2lpd_kms",
    smoke_xe2lpd_kms_tile4_flips_through_owned_dpt
);

/// Display-20 Tile4 panning through the remapped DPT: `Viewport { x: 35, y: 33 }`
/// spans source tile `(col=1, row=1)` with residual `PLANE_OFFSET = (1 << 16) | 3`,
/// keeping the 2 MiB-aligned DPT base in `PLANE_SURF` while remapping entry 0
/// to source page `1 * 4 + 1 = 5`.
#[cfg(target_arch = "x86_64")]
fn smoke_xe2lpd_kms_tile4_panning_through_owned_dpt() -> TestResult {
    use crate::intel_gpu_scanout::{DptLayout, Layout, View, Viewport};
    let pan_geo = Geometry {
        width: 64,
        height: 32,
        pitch: 512, // 4 Tile4 columns
    };
    let origin = Viewport { x: 35, y: 33 };
    let (layout, start_col, start_row, plane_offset) =
        DptLayout::with_origin(pan_geo, Layout::Tile4, origin).unwrap();
    assert_eq!(start_col, 1);
    assert_eq!(start_row, 1);
    assert_eq!(plane_offset, (1 << 16) | 3);
    assert_eq!(layout.source_at(0, start_col, start_row), Some(5));
    assert_eq!(layout.source_at(2, start_col, start_row), Some(7));

    let platform = MockPlatform::new();
    let timing = display20_resources(&platform);
    platform.set(0x70188, pan_geo.pitch / 64);
    crate::intel_gpu_kms::tile4_profile(&platform, pan_geo, timing).unwrap();
    let device = Device::new(
        platform.clone(),
        Generation::LunarLake,
        0x100_0000,
        ActiveScanout {
            stride_bytes: pan_geo.pitch,
            ..console()
        },
    );
    // The panned window covers tile rows 1 and 2 of a four-column surface.
    let fb = object_sized(true, 12 * 4096).unwrap();
    let frames: Vec<u64> = fb.pages().collect();
    assert_eq!(frames.len(), 12);
    let view = View {
        origin,
        layout: Layout::Tile4,
        ..View::default()
    };
    {
        let mut session = complete(device.session()).unwrap();
        drive(session.present_color(fb.clone(), pan_geo, view, None, Default::default(), timing))
            .unwrap();
    }
    assert_eq!(platform.read32(0x701a4), (1 << 16) | 3);
    let surface = platform.read32(LIVE);
    assert_eq!(surface % (2 << 20), 0);
    let pte = GGTT_ARRAY_BASE + u64::from(surface) / 4096 * 8;
    let table = (u64::from(platform.read32(pte)) | (u64::from(platform.read32(pte + 4)) << 32))
        & crate::intel_gpu_gtt::PTE_PHYS_MASK;
    let entry = |index: u64| -> u64 {
        // SAFETY: DPT page mapped by the live PTE just read for the retained surface.
        unsafe {
            narf_memory::PhysAddr::new(table + index * 8)
                .kernel_ptr::<u64>()
                .read_volatile()
        }
    };
    for (row, first_page) in [(0, 5), (8, 9)] {
        for col in 0..3 {
            assert_eq!(
                entry(row + col as u64),
                frames[first_page + col] | 1 | (3 << 52)
            );
        }
        for padding in 3..8 {
            assert_eq!(entry(row + padding), 0);
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe2lpd_kms",
    smoke_xe2lpd_kms_tile4_panning_through_owned_dpt
);

/// Display-20 FBC skips `Wa_22014263786` (`DPFC_CHICKEN_FORCE_SLB_INVALIDATION`),
/// keeps `Wa_18038517565` (`PIPE_CLKGATE_DIS2`) + `DPFC_CONTROL`, and coexists
/// with Display-20 PSR1 (without Display 14's `Wa_14016291713` conflict).
#[cfg(target_arch = "x86_64")]
fn smoke_xe2lpd_kms_fbc_display20_deltas_and_psr1_coexistence() -> TestResult {
    let platform = MockPlatform::new();
    platform.set(0x6007c, 1);
    platform.0.lock().fbc_offset = Some(0x100_0000);
    let timing = platform.dsb_timing();
    super::psr::attach(&platform, timing, Some(false));
    let device = lunar(&platform);
    super::psr::present_once(&device, object(true).unwrap());

    assert!(super::psr::psr(&device).is_some());
    assert_ne!(platform.read32(super::psr::PSR_CTL) & (1 << 31), 0);
    // DPFC_CB_BASE and DPFC_CONTROL show FBC enabled alongside PSR1.
    assert_eq!(platform.read32(0x43200), 0x100_0000);
    assert_ne!(platform.read32(0x43208) & (1 << 31), 0);
    // Wa_18038517565 sets MTL_DPFC_GATING_DIS in MTL_PIPE_CLKGATE_DIS2(A).
    assert_ne!(platform.read32(0x60114) & (1 << 6), 0);
    // Wa_22014263786 (DPFC_CHICKEN bit 13) is skipped on display >= 20.
    assert_eq!(platform.read32(0x43224) & (1 << 13), 0);
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe2lpd_kms",
    smoke_xe2lpd_kms_fbc_display20_deltas_and_psr1_coexistence
);

/// Display 20 (Lunar Lake) and Display 30 (Panther Lake, when display30 is
/// proven) admit KMS `panel_off`/`panel_on` relight and S3 system suspend.
#[cfg(target_arch = "x86_64")]
fn smoke_xe2lpd_kms_s3_panel_relight_admitted() -> TestResult {
    use crate::intel_gpu::Generation;
    use crate::intel_gpu_gt_runtime::system_suspend_admitted;
    use crate::intel_gpu_kms::panel_generation_supported;
    assert!(panel_generation_supported(Generation::MeteorLake, false));
    assert!(panel_generation_supported(Generation::LunarLake, false));
    assert!(panel_generation_supported(Generation::PantherLake, true));
    assert!(!panel_generation_supported(Generation::PantherLake, false));
    assert!(!panel_generation_supported(Generation::TigerLake, false));
    assert!(system_suspend_admitted(false, true));
    assert!(!system_suspend_admitted(true, false));
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe2lpd_kms",
    smoke_xe2lpd_kms_s3_panel_relight_admitted
);

/// Discrete Arc display bring-up (DG2 Display 13 & BMG `Xe2_HPD` 14.01):
/// identification, non-dGPU / fused-Pipe-A refusals, live Pipe-A scanout
/// observation, discrete PTE/status profiles, and `PTE_DM` encoding.
fn smoke_discrete_arc_display_identify_and_vram_pte() -> TestResult {
    use crate::intel_gpu::Generation;
    use crate::intel_gpu_gt::GtPlatform;
    use crate::intel_gpu_gtt::{encode_display_vram_pte, PteFormat, PTE_DM, PTE_PRESENT};
    use crate::intel_gpu_scanout_io::{display_pte_for, owned_status_for};
    use crate::intel_gpu_xe2lpd::{discrete_pipe_a_scanout, DiscreteDisplayIp, IpError};

    let dg2 = MockPlatform::new();
    assert_eq!(
        DiscreteDisplayIp::identify(&dg2, GtPlatform::Alchemist),
        Ok(DiscreteDisplayIp::Dg2)
    );
    assert_eq!(DiscreteDisplayIp::Dg2.ver(), 13);
    assert_eq!(DiscreteDisplayIp::Dg2.pte_format(), PteFormat::Gen12);
    assert_eq!(
        display_pte_for(Generation::AlderLake, None, Some(DiscreteDisplayIp::Dg2)),
        Some((PteFormat::Gen12, 0))
    );
    assert_eq!(
        owned_status_for(Generation::AlderLake, None, Some(DiscreteDisplayIp::Dg2)),
        0x8200_0088
    );

    let bmg = MockPlatform::new();
    bmg.set(0x510a0, (14 << 22) | (1 << 14));
    assert_eq!(
        DiscreteDisplayIp::identify(&bmg, GtPlatform::Battlemage),
        Ok(DiscreteDisplayIp::Xe2Hpd)
    );
    assert_eq!(
        (
            DiscreteDisplayIp::Xe2Hpd.ver(),
            DiscreteDisplayIp::Xe2Hpd.rel()
        ),
        (14, 1)
    );
    assert_eq!(DiscreteDisplayIp::Xe2Hpd.pte_format(), PteFormat::XeLpg);
    assert_eq!(
        display_pte_for(
            Generation::MeteorLake,
            None,
            Some(DiscreteDisplayIp::Xe2Hpd)
        ),
        Some((PteFormat::XeLpg, 0))
    );
    assert_eq!(
        owned_status_for(
            Generation::MeteorLake,
            None,
            Some(DiscreteDisplayIp::Xe2Hpd)
        ),
        0x8304_0088
    );

    // Non-dGPU, unqualified GMD ID, and fused Pipe A refuse cleanly.
    assert!(matches!(
        DiscreteDisplayIp::identify(&bmg, GtPlatform::Integrated(Generation::LunarLake)),
        Err(IpError::Unqualified { .. })
    ));
    let dark_gmd = MockPlatform::new();
    dark_gmd.set(0x510a0, 14 << 22); // 14.00 != 14.01
    assert_eq!(
        DiscreteDisplayIp::identify(&dark_gmd, GtPlatform::Battlemage),
        Err(IpError::Unqualified { ver: 14, rel: 0 })
    );
    let fused = MockPlatform::new();
    fused.set(0x510a0, (14 << 22) | (1 << 14));
    fused.set(0x51000, 1 << 30); // DFSM_PIPE_A_DISABLE
    assert_eq!(
        DiscreteDisplayIp::identify(&fused, GtPlatform::Battlemage),
        Err(IpError::Unqualified { ver: 14, rel: 1 })
    );

    // DG1 (display 12, `dg1_display`): identified from its PCI identity
    // with Pipe A unfused, Gen12 PTEs with `GEN12_GGTT_PTE_LM` and the
    // Tiger Lake status profile; a fused Pipe A and an integrated Gen12
    // part refuse. The probe admits it only with `narf.intel.dg1_kms=1`.
    {
        use crate::intel_gpu_gt::Gen12Platform;
        use narf_boot::args::KernelCmdline;
        let dg1 = MockPlatform::new();
        assert_eq!(
            DiscreteDisplayIp::identify(&dg1, GtPlatform::Gen12(Gen12Platform::Dg1)),
            Ok(DiscreteDisplayIp::Dg1)
        );
        assert_eq!(
            (DiscreteDisplayIp::Dg1.ver(), DiscreteDisplayIp::Dg1.rel()),
            (12, 0)
        );
        assert_eq!(
            display_pte_for(Generation::TigerLake, None, Some(DiscreteDisplayIp::Dg1)),
            Some((PteFormat::Gen12, 0))
        );
        assert_eq!(
            owned_status_for(Generation::TigerLake, None, Some(DiscreteDisplayIp::Dg1)),
            0x8200_0088
        );
        let fused = MockPlatform::new();
        fused.set(0x51000, 1 << 30);
        assert_eq!(
            DiscreteDisplayIp::identify(&fused, GtPlatform::Gen12(Gen12Platform::Dg1)),
            Err(IpError::Unqualified { ver: 12, rel: 0 })
        );
        assert!(matches!(
            DiscreteDisplayIp::identify(&dg1, GtPlatform::Gen12(Gen12Platform::TigerLake)),
            Err(IpError::Unqualified { .. })
        ));
        assert_eq!(crate::intel_gpu_gt_runtime::DG1_KMS_OPT_IN, "narf.intel.dg1_kms");
        assert!(crate::intel_gpu_gt_runtime::dg1_kms_requested(KernelCmdline::new(
            "narf.intel.dg1_kms=1"
        )));
        assert!(!crate::intel_gpu_gt_runtime::dg1_kms_requested(
            KernelCmdline::new("")
        ));
    }

    // VRAM GGTT PTE sets PTE_DM | PTE_PRESENT.
    assert_eq!(
        encode_display_vram_pte(PteFormat::Gen12, 0x1234_5000, 0),
        Ok(0x1234_5000 | PTE_PRESENT | PTE_DM)
    );
    assert_eq!(
        encode_display_vram_pte(PteFormat::XeLpg, 0x1234_5000, 0),
        Ok(0x1234_5000 | PTE_PRESENT | PTE_DM)
    );

    // Dark Pipe A returns None; lit Pipe A returns ActiveScanout.
    let panel = MockPlatform::new();
    panel.set(0x70008, 0);
    assert!(discrete_pipe_a_scanout(&panel).is_none());
    panel.set(0x70008, 0xc000_0000);
    panel.set(0x70180, 0x8400_0000);
    panel.set(0x6001c, ((64 - 1) << 16) | (32 - 1));
    panel.set(0x70188, 4);
    panel.set(0x7019c, CONSOLE);
    let obs = discrete_pipe_a_scanout(&panel).unwrap();
    assert_eq!(
        (obs.width, obs.height, obs.stride_bytes, obs.gtt_offset),
        (64, 32, 256, CONSOLE)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe2lpd_kms",
    smoke_discrete_arc_display_identify_and_vram_pte
);

/// Discrete VRAM scanout admission across DRM `addfb2`, `GemObject::mark_scanout`
/// eviction pinning, and `Presenter::with_vram_scanout` GGTT `PTE_DM` mapping.
fn smoke_discrete_vram_scanout_presenter_addfb2_and_eviction_pin() -> TestResult {
    use crate::drm::card::{Card, CardError};
    use crate::drm::fb_cmd::FbCmd;
    use crate::intel_gpu_gem::GemState;
    use crate::intel_gpu_gtt::{PteFormat, PTE_DM, PTE_PRESENT};
    use crate::intel_gpu_scanout::{Presenter, ScanoutError};
    use crate::intel_gpu_scanout_io::{display_pte_for, PollIo};
    use crate::intel_gpu_vram::{Vram, VramLayout};
    use crate::intel_gpu_xe2lpd::DiscreteDisplayIp;

    let order = 6u8; // 256 KiB mock LMEM region (fits 64 KiB alignments).
    let frame = narf_memory::frame::alloc_pages_on(0, order).expect("vram test frame");
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
    // SAFETY: exclusively owned contiguous frames back this fixture's LMEM pool.
    let pool = unsafe { Vram::new(bar, layout) }.unwrap();
    let gem = GemState::new();
    let pending = gem
        .prepare_vram_class(8192, None, &pool, true)
        .expect("prepare vram bo");
    let vram_obj = pending.object();
    assert!(vram_obj.is_vram());
    assert!(!vram_obj.is_wc());
    assert!(!vram_obj.scanout());

    let cmd = FbCmd {
        width: 64,
        height: 32,
        pixel_format: 0x3432_5258,
        handles: [1, 0, 0, 0],
        pitches: [256, 0, 0, 0],
        offsets: [0, 0, 0, 0],
        modifier: [0; 4],
        flags: 0,
    };
    // Integrated card refuses VRAM scanout BOs in addfb2_intel.
    let mut igpu_card = Card::new("igpu", "test", (1, 0, 0));
    assert_eq!(
        igpu_card.addfb2_intel(&cmd, vram_obj.clone(), 1, true),
        Err(CardError::InvalidDimensions)
    );
    assert!(!vram_obj.scanout());

    // Discrete card admits VRAM scanout BOs and marks scanout (pinned against
    // normal eviction while still drainable on S3 suspend).
    let mut dgpu_card = Card::new("dgpu", "test", (1, 0, 0));
    dgpu_card.intel_vram_scanout = true;
    assert!(dgpu_card
        .addfb2_intel(&cmd, vram_obj.clone(), 1, true)
        .is_ok());
    assert!(vram_obj.scanout());
    assert!(!vram_obj.is_evictable(false));
    assert!(vram_obj.is_evictable(true));

    // Presenter without vram_scanout refuses; with vram_scanout maps PTE_DM.
    let platform = MockPlatform::new();
    let (fmt, pat) = display_pte_for(
        Generation::MeteorLake,
        None,
        Some(DiscreteDisplayIp::Xe2Hpd),
    )
    .unwrap();
    assert_eq!((fmt, pat), (PteFormat::XeLpg, 0));
    // SAFETY: MockPlatform models the Pipe-A primary plane exclusively for this test.
    let io_refuse = unsafe {
        PollIo::new(
            platform.clone(),
            Generation::MeteorLake,
            Pipe::A,
            0x100_0000,
        )
    }
    .unwrap();
    // SAFETY: exclusive MockPlatform scanout arena ownership.
    let mut presenter_refuse =
        unsafe { Presenter::new(io_refuse, 0x100_0000, Pipe::A, fmt, pat, CONSOLE) }.unwrap();
    assert_eq!(
        presenter_refuse.prepare(vram_obj.clone(), geometry()),
        Err(ScanoutError::Unsupported)
    );
    // SAFETY: no scanout surface was armed in this fixture.
    let _ = unsafe { presenter_refuse.shutdown_stopped() };

    let platform2 = MockPlatform::new();
    // SAFETY: MockPlatform models the Pipe-A primary plane exclusively for this test.
    let io_allow = unsafe {
        PollIo::new(
            platform2.clone(),
            Generation::MeteorLake,
            Pipe::A,
            0x100_0000,
        )
    }
    .unwrap();
    // SAFETY: exclusive MockPlatform scanout arena ownership.
    let mut presenter_allow =
        unsafe { Presenter::new(io_allow, 0x100_0000, Pipe::A, fmt, pat, CONSOLE) }
            .unwrap()
            .with_vram_scanout(true);
    let sid = presenter_allow
        .prepare(vram_obj.clone(), geometry())
        .unwrap();
    let _ = presenter_allow.arm(sid, 1, platform2.now());
    let gtt = platform2.read32(SURF);
    assert!((GEM_SCANOUT_GTT_START..GEM_SCANOUT_GTT_END).contains(&u64::from(gtt)));
    let pte = GGTT_ARRAY_BASE + u64::from(gtt) / 4096 * 8;
    let low = platform2.read32(pte);
    assert_eq!(
        u64::from(low) & (PTE_PRESENT | PTE_DM),
        PTE_PRESENT | PTE_DM
    );
    // SAFETY: fixture owns the mock scanout plane exclusively and drops all surfaces.
    let _ = unsafe { presenter_allow.shutdown_stopped() };
    drop(pending);
    drop(vram_obj);
    drop(pool);
    narf_memory::frame::free_pages(frame, order);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe2lpd_kms",
    smoke_discrete_vram_scanout_presenter_addfb2_and_eviction_pin
);
