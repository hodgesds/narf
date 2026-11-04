//! Display-14 PSR1 through the production Device/Guard path: enabled after
//! a latched KMS framebuffer, exited at every session start before any
//! frame change, re-armed once the session's changes latched, disabled
//! before console restore, legacy guards and reset recovery, and the
//! FBC/PSR policy in both directions. Expected values are written out from
//! intel_psr_regs.h, i915_reg.h and drm_dp.h. x86_64 only: the KMS
//! present path needs WC GEM objects.
use super::*;

pub(super) const PSR_CTL: u64 = 0x60800;
const PSR_IIR: u64 = 0x60818;
const DPFC_CONTROL: u64 = 0x43208;
const PIPE_CLKGATE_DIS2: u64 = 0x60114;
pub(super) const EN_CFG: u64 = AUX_LOG | 0x170;
const SET_POWER: u64 = AUX_LOG | 0x600;
/// hsw_activate_psr1 for the fixture sink: EDP_PSR_ENABLE,
/// MAX_SLEEP_TIME(0x1f), TP_TP1_TP3, CRC_ENABLE, TP2_TP3_TIME_2500us,
/// TP4_TIME_0us, TP1_TIME_2500us, idle frames max(6, 2 + 1).
pub(super) const ARMED: u32 =
    (1 << 31) | (0x1f << 20) | (1 << 11) | (1 << 10) | (2 << 8) | (3 << 6) | (2 << 4) | 6;
pub(super) const EXITED: u32 = ARMED & !(1 << 31);

/// eDP 1.4 PSR1 sink: DPCD 1.4, TPS3 + 4 lanes, PSR version 1, 330 µs
/// setup, SET_POWER_CAP, max resync 2 frames.
pub(super) fn sink() -> BTreeMap<u32, u8> {
    [
        (0x000, 0x14),
        (0x001, 0x1e),
        (0x002, 0xc4),
        (0x070, 0x01),
        (0x071, 0x00),
        (0x400, 0x00),
        (0x401, 0x22),
        (0x402, 0xb9),
        (0x700, 0x03),
        (0x701, 0x80),
        (0x2009, 0x02),
    ]
    .into_iter()
    .collect()
}

/// A VBT panel with PSR enabled (`psr.enable`), 2500 µs TP1 and TP2/TP3
/// wake times and no idle-frame floor.
pub(super) fn vbt(idle_frames: u8, tp1: u32, tp23: u32) -> crate::intel_gpu_psr::VbtPsr {
    crate::intel_gpu_psr::VbtPsr::Panel(crate::intel_gpu_vbt::PsrPanel {
        enable: true,
        table: Some(crate::intel_gpu_vbt::PsrTable {
            full_link: false,
            require_aux_wakeup: false,
            idle_frames,
            tp1_wakeup_time_us: tp1,
            tp2_tp3_wakeup_time_us: tp23,
            psr2_tp2_tp3_wakeup_time_us: tp23,
        }),
    })
}

/// The fixture's fixed timing (64x32, htotal 224, vtotal 77 at 1034 kHz:
/// the 330 µs setup is 2 lines, well inside 44) with a PSR sink and a
/// PSR-enabling VBT attached.
pub(super) fn attach(
    platform: &MockPlatform,
    timing: crate::intel_gpu_dsb::Timing,
    wm: Option<bool>,
) {
    let mut hw = platform.0.lock();
    hw.psr_dpcd = Some(sink());
    hw.psr_timing = Some(timing);
    hw.psr_wm = wm;
    hw.psr_vbt = vbt(0, 2500, 2500);
}

fn psr_platform() -> MockPlatform {
    let platform = MockPlatform::new();
    let timing = platform.dsb_timing();
    attach(&platform, timing, Some(false));
    platform
}

pub(super) fn psr(device: &Device<MockPlatform>) -> Option<crate::intel_gpu_psr::Psr> {
    device.state.try_lock().unwrap().psr
}

pub(super) fn sink_writes(writes: &[(u64, u32)]) -> Vec<(u64, u32)> {
    writes
        .iter()
        .filter(|(r, _)| r & AUX_LOG != 0)
        .copied()
        .collect()
}

pub(super) fn present_once(device: &Device<MockPlatform>, object: Arc<GemObject>) {
    let mut session = complete(device.session()).unwrap();
    complete(session.present(object, geometry())).unwrap();
}

fn drive<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    for _ in 0..1024 {
        if let Poll::Ready(result) = once(future.as_mut()) {
            return result;
        }
    }
    panic!("PSR fixture conversation did not finish");
}

fn smoke_psr_kms_enables_after_latch_and_activates_at_session_end() -> TestResult {
    {
        let platform = psr_platform();
        let device = platform.meteor();
        let mut session = complete(device.session()).unwrap();
        complete(session.present(object(true).unwrap(), geometry())).unwrap();
        let writes = platform.all_writes();
        // _psr_enable_sink then DP_SET_POWER D0, after the KMS latch.
        assert_eq!(
            sink_writes(&writes),
            [(EN_CFG, 0x04), (EN_CFG, 0x05), (SET_POWER, 0x01)]
        );
        let arm = writes
            .iter()
            .position(|&(r, v)| r == SURF && v != CONSOLE)
            .unwrap();
        let first_sink = writes.iter().position(|&(r, _)| r == EN_CFG).unwrap();
        assert!(arm < first_sink);
        assert_eq!(
            platform.read32(0x60860),
            (1 << 28) | (1 << 27) | (1 << 26) | (1 << 25)
        );
        assert_eq!(platform.read32(0x60814), !(1u32 << 2));
        assert_eq!(platform.read32(0x46430) & (1 << 23), 0);
        // Enabled but not active until every change of this session latched.
        assert_eq!(platform.read32(PSR_CTL) & (1 << 31), 0);
        drop(session);
        assert_eq!(platform.read32(PSR_CTL), ARMED);
        assert!(psr(&device).unwrap().active());
        // No further sink traffic for re-arming.
        assert_eq!(sink_writes(&platform.all_writes()).len(), 3);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr_kms_enables_after_latch_and_activates_at_session_end
);

fn smoke_psr_kms_flip_and_dirtyfb_exit_before_arm_and_rearm_after_latch() -> TestResult {
    {
        let platform = psr_platform();
        let device = platform.meteor();
        let front = object(true).unwrap();
        present_once(&device, front.clone());
        assert_eq!(platform.read32(PSR_CTL), ARMED);
        let flip = object(true).unwrap();
        // A flip to a new framebuffer, then a DIRTYFB re-present of it.
        for next in [flip.clone(), flip] {
            let start = platform.all_writes().len();
            let mut session = complete(device.session()).unwrap();
            assert_eq!(platform.read32(PSR_CTL), EXITED);
            complete(session.present(next, geometry())).unwrap();
            assert_eq!(platform.read32(PSR_CTL), EXITED);
            drop(session);
            assert_eq!(platform.read32(PSR_CTL), ARMED);
            let writes = &platform.all_writes()[start..];
            let exit = writes.iter().position(|&w| w == (PSR_CTL, EXITED)).unwrap();
            let arm = writes.iter().position(|&(r, _)| r == SURF).unwrap();
            let rearm = writes.iter().rposition(|&w| w == (PSR_CTL, ARMED)).unwrap();
            assert!(exit < arm && arm < rearm);
            assert!(sink_writes(writes).is_empty());
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr_kms_flip_and_dirtyfb_exit_before_arm_and_rearm_after_latch
);

fn smoke_psr_kms_color_and_cursor_rearm_only_after_their_latch() -> TestResult {
    {
        // Color (CSC arm): a cancelled update keeps PSR exited.
        let platform = psr_platform();
        let device = platform.meteor();
        present_once(&device, object(true).unwrap());
        {
            let mut session = complete(device.session()).unwrap();
            let identity = [1u64 << 32, 0, 0, 0, 1 << 32, 0, 0, 0, 1 << 32];
            let mut update = Box::pin(session.set_ctm(Some(identity)));
            assert!(once(update.as_mut()).is_pending());
            assert_eq!(platform.read32(PSR_CTL), EXITED);
            drop(update);
        }
        assert_eq!(
            platform.read32(PSR_CTL),
            EXITED,
            "re-armed over a pending CSC"
        );
        assert!(!psr(&device).unwrap().active());

        // Cursor (DSB arm): exited before the stream, re-armed after its
        // SURFLIVE latch and DSB retirement.
        let platform = MockPlatform::new();
        let timing = platform.cursor_resources();
        attach(&platform, timing, Some(false));
        let device = platform.meteor();
        present_once(&device, object(true).unwrap());
        assert_eq!(platform.read32(PSR_CTL), ARMED);
        let gem = crate::intel_gpu_gem::GemState::new();
        let handle = gem.create(16384, |_, _| Ok(())).unwrap();
        let start = platform.all_writes().len();
        let mut session = complete(device.session()).unwrap();
        drive(session.cursor(
            Some(gem.object(handle).unwrap()),
            true,
            Some((3, 4)),
            timing,
        ))
        .unwrap();
        assert_ne!(platform.read32(0x700ac), 0);
        assert_eq!(platform.read32(PSR_CTL), EXITED);
        drop(session);
        assert_eq!(platform.read32(PSR_CTL), ARMED);
        let writes = &platform.all_writes()[start..];
        let exit = writes.iter().position(|&w| w == (PSR_CTL, EXITED)).unwrap();
        let dsb = writes
            .iter()
            .position(|&(r, _)| (0x70b00..0x70c00).contains(&r))
            .unwrap();
        let rearm = writes.iter().rposition(|&w| w == (PSR_CTL, ARMED)).unwrap();
        assert!(exit < dsb && dsb < rearm);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr_kms_color_and_cursor_rearm_only_after_their_latch
);

fn smoke_psr_kms_disabled_before_console_legacy_suspend_and_reset() -> TestResult {
    {
        // Console restore: sink and source off before the console arm.
        let platform = psr_platform();
        let device = platform.meteor();
        present_once(&device, object(true).unwrap());
        let start = platform.all_writes().len();
        let mut session = complete(device.session()).unwrap();
        complete(session.restore_console()).unwrap();
        drop(session);
        assert_eq!(platform.read32(PSR_CTL) & (1 << 31), 0);
        assert!(psr(&device).is_none());
        let writes = &platform.all_writes()[start..];
        let off = writes.iter().position(|&w| w == (EN_CFG, 0)).unwrap();
        let console = writes.iter().position(|&w| w == (SURF, CONSOLE)).unwrap();
        assert!(off < console);
        assert_eq!(platform.read32(0x46430) & (1 << 23), 0);

        // Suspend (Device::quiesce → restore_console) and legacy drain.
        for drain in [false, true] {
            let platform = psr_platform();
            let device = platform.meteor();
            present_once(&device, object(true).unwrap());
            assert_eq!(platform.read32(PSR_CTL), ARMED);
            if drain {
                let guard = device.legacy_drain().unwrap();
                drop(guard);
            } else {
                complete(device.quiesce()).unwrap();
            }
            assert_eq!(platform.read32(PSR_CTL) & (1 << 31), 0);
            assert!(psr(&device).is_none());
            assert_eq!(
                sink_writes(&platform.all_writes()).last(),
                Some(&(EN_CFG, 0))
            );
        }

        // GT reset: disabled through the loss-tolerant view before
        // recovery's fetcher inventory.
        let platform = psr_platform();
        let device = platform.meteor();
        present_once(&device, object(true).unwrap());
        quarantine_reset_state(&device.state, &platform.1);
        assert!(device.reset_lost());
        let _ = complete(device.recover());
        assert_eq!(platform.read32(PSR_CTL) & (1 << 31), 0);
        assert!(psr(&device).is_none());
        assert!(sink_writes(&platform.all_writes()).contains(&(EN_CFG, 0)));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr_kms_disabled_before_console_legacy_suspend_and_reset
);

fn smoke_psr_kms_wins_over_fbc_in_both_directions() -> TestResult {
    {
        // FBC → PSR: FBC runs while PSR is not qualified (no WM input);
        // once PSR qualifies, FBC is disabled before the sink is enabled.
        let platform = MockPlatform::new();
        let timing = platform.dsb_timing();
        attach(&platform, timing, None);
        platform.0.lock().fbc_offset = Some(0x10_0000);
        let device = platform.meteor();
        let front = object(true).unwrap();
        present_once(&device, front.clone());
        assert_ne!(platform.read32(DPFC_CONTROL) & (1 << 31), 0);
        assert!(psr(&device).is_none());
        assert!(sink_writes(&platform.all_writes()).is_empty());
        platform.0.lock().psr_wm = Some(false);
        present_once(&device, front.clone());
        assert_eq!(platform.read32(DPFC_CONTROL) & (1 << 31), 0);
        assert_eq!(platform.read32(PSR_CTL), ARMED);
        let writes = platform.all_writes();
        let fbc_off = writes
            .iter()
            .rposition(|&(r, v)| r == PIPE_CLKGATE_DIS2 && v & (1 << 6) == 0)
            .unwrap();
        let sink_on = writes.iter().position(|&w| w == (EN_CFG, 0x05)).unwrap();
        assert!(fbc_off < sink_on);
        // FBC stays off while PSR is enabled, across flips.
        present_once(&device, front.clone());
        assert_eq!(platform.read32(DPFC_CONTROL) & (1 << 31), 0);

        // PSR → FBC: a PSR error disables PSR for good (sink woken), and
        // the next latch activates FBC.
        platform.set(PSR_IIR, 1 << 2);
        present_once(&device, front);
        assert!(psr(&device).is_none());
        assert_eq!(
            device.state.try_lock().unwrap().psr_refused,
            Some(crate::intel_gpu_psr::Refusal::SinkNotReliable)
        );
        assert_eq!(platform.read32(PSR_CTL) & (1 << 31), 0);
        assert_eq!(
            sink_writes(&platform.all_writes())[3..],
            [(EN_CFG, 0x00), (SET_POWER, 0x01)]
        );
        assert_ne!(platform.read32(DPFC_CONTROL) & (1 << 31), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr_kms_wins_over_fbc_in_both_directions
);

fn smoke_psr_kms_refusals_leave_zero_psr_traffic() -> TestResult {
    {
        // No timing (not display 14 / no mode), no sink PSR, a setup time
        // the blank cannot hold, and an inherited enable.
        for case in 0..4 {
            let platform = psr_platform();
            match case {
                0 => platform.0.lock().psr_timing = None,
                1 => {
                    platform
                        .0
                        .lock()
                        .psr_dpcd
                        .as_mut()
                        .unwrap()
                        .insert(0x070, 0);
                }
                2 => {
                    let mut hw = platform.0.lock();
                    hw.psr_timing.as_mut().unwrap().clock = 1_000_000;
                }
                _ => platform.set(0x60900, 1 << 31),
            }
            let device = platform.meteor();
            present_once(&device, object(true).unwrap());
            present_once(&device, object(true).unwrap());
            assert!(psr(&device).is_none());
            assert!(sink_writes(&platform.all_writes()).is_empty());
            assert!(platform
                .all_writes()
                .iter()
                .all(|&(r, _)| !(0x60800..0x60a00).contains(&r)));
        }
        // Gen12 never takes this path.
        let platform = MockPlatform::new();
        attach(
            &platform,
            crate::intel_gpu_dsb::Timing {
                clock: 1034,
                width: 64,
                height: 32,
                htotal: 224,
                vtotal: 77,
                flags: 0,
            },
            Some(false),
        );
        let device = platform.tiger();
        present_once(&device, object(true).unwrap());
        assert!(psr(&device).is_none());
        assert!(sink_writes(&platform.all_writes()).is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr_kms_refusals_leave_zero_psr_traffic
);

/// `cursor_resources` with LP4/LP5 latency word `lp4_lp5`: the owned
/// display-14 modeset programs the watermarks for that table, so a later
/// profile capture proves them programmed.
fn owned_resources(platform: &MockPlatform, lp4_lp5: u32) -> crate::intel_gpu_dsb::Timing {
    let timing = platform.dsb_timing();
    platform.set(0x45788, lp4_lp5);
    platform.set(0x70008, 0);
    platform.set(0x70180, 0);
    platform.set(0x510a0, (14 << 22) | 8);
    platform.set(0x46070, 0xc0000010);
    platform.set(0x46000, 612);
    platform.set(0x46008, 0);
    let mode = crate::intel_gpu_modeset::Mode {
        pixel_clock_khz: timing.clock,
        h_active: timing.width,
        h_total: timing.htotal,
        v_active: timing.height,
        v_total: timing.vtotal,
        ..crate::intel_gpu_modeset::Mode::VESA_1024X768_60
    };
    crate::intel_gpu_display_resources::initialize(platform, &mode, 307200)
        .unwrap()
        .unwrap();
    platform.set(0x70008, 3 << 30);
    platform.set(0x70180, 0x84000000);
    timing
}

/// A platform whose Wa_14015648006 input takes the production route (the
/// registered provider), over watermarks the owned modeset programmed.
fn provider_platform(lp4_lp5: u32) -> MockPlatform {
    let platform = MockPlatform::new();
    let timing = owned_resources(&platform, lp4_lp5);
    attach(&platform, timing, None);
    platform.0.lock().psr_wm_provider = true;
    platform
}

fn smoke_psr_kms_production_wm_provider_qualifies_and_enables() -> TestResult {
    {
        let previous = crate::intel_gpu_psr::register_wm_level_disabled(None);
        crate::intel_gpu_xelpg_wm::publish_pipe_a(None);
        // LP4 14 µs, LP5 16 µs: every level fits the fixture's 45-line
        // vblank (216 µs lines), so wm_level_disabled is false.
        let platform = provider_platform(14 | (16 << 16));
        let device = platform.meteor();
        // No provider registered: the input is unknown and PSR is retried.
        present_once(&device, object(true).unwrap());
        assert!(psr(&device).is_none());
        assert_eq!(device.state.try_lock().unwrap().psr_refused, None);
        assert!(sink_writes(&platform.all_writes()).is_empty());
        // The display-14 watermark provider: qualification proves the
        // programmed Pipe-A watermarks and reads their value.
        crate::intel_gpu_xelpg_wm::register_psr_provider();
        present_once(&device, object(true).unwrap());
        assert_eq!(
            crate::intel_gpu_xelpg_wm::pipe_a_wm_level_disabled(),
            Some(false)
        );
        assert!(!psr(&device).unwrap().config().wm_level_disabled);
        assert_eq!(platform.read32(0x46430) & (1 << 23), 0);
        assert_eq!(platform.read32(PSR_CTL), ARMED);
        assert_eq!(
            sink_writes(&platform.all_writes()),
            [(EN_CFG, 0x04), (EN_CFG, 0x05), (SET_POWER, 0x01)]
        );
        crate::intel_gpu_psr::register_wm_level_disabled(previous);
        crate::intel_gpu_xelpg_wm::publish_pipe_a(None);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr_kms_production_wm_provider_qualifies_and_enables
);

fn smoke_psr_kms_wm_level_disabled_takes_wa_14015648006() -> TestResult {
    {
        let previous = crate::intel_gpu_psr::register_wm_level_disabled(None);
        crate::intel_gpu_xelpg_wm::register_psr_provider();
        // LP5 latency 0: skl_max_wm_level_for_vblank skips the zero level,
        // so the highest fitting level is 4 and wm_level_disabled is true.
        let platform = provider_platform(14);
        let device = platform.meteor();
        present_once(&device, object(true).unwrap());
        assert_eq!(
            crate::intel_gpu_xelpg_wm::pipe_a_wm_level_disabled(),
            Some(true)
        );
        assert!(psr(&device).unwrap().config().wm_level_disabled);
        // intel_psr_enable_source → wm_optimization_wa sets
        // LATENCY_REPORTING_REMOVED(PIPE_A) before PSR is activated.
        let writes = platform.all_writes();
        let wa = writes
            .iter()
            .position(|&(r, v)| r == 0x46430 && v & (1 << 23) != 0)
            .unwrap();
        let activate = writes.iter().position(|&w| w == (PSR_CTL, ARMED)).unwrap();
        assert!(wa < activate);
        assert_eq!(platform.read32(PSR_CTL), ARMED);
        // intel_psr_disable_locked undoes it.
        complete(device.quiesce()).unwrap();
        assert!(psr(&device).is_none());
        assert_eq!(platform.read32(0x46430) & (1 << 23), 0);
        crate::intel_gpu_psr::register_wm_level_disabled(previous);
        crate::intel_gpu_xelpg_wm::publish_pipe_a(None);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr_kms_wm_level_disabled_takes_wa_14015648006
);

fn smoke_psr_kms_vbt_refusal_precedes_sink_and_source() -> TestResult {
    {
        use crate::intel_gpu_psr::VbtPsr;
        for refused in [
            VbtPsr::Missing,
            VbtPsr::Panel(crate::intel_gpu_vbt::PsrPanel {
                enable: false,
                table: None,
            }),
            VbtPsr::PanelByPnpId,
        ] {
            let platform = psr_platform();
            platform.0.lock().psr_vbt = refused;
            let device = platform.meteor();
            present_once(&device, object(true).unwrap());
            present_once(&device, object(true).unwrap());
            assert!(psr(&device).is_none());
            {
                let state = device.state.try_lock().unwrap();
                // Not latched, and no sink conversation was started.
                assert_eq!(state.psr_refused, None);
                assert!(state.psr_sink.is_none());
            }
            assert!(sink_writes(&platform.all_writes()).is_empty());
            assert!(platform
                .all_writes()
                .iter()
                .all(|&(r, _)| !(0x60800..0x60a00).contains(&r) && r != 0x46430));
            // The gate is re-evaluated at every latch.
            platform.0.lock().psr_vbt = vbt(0, 2500, 2500);
            present_once(&device, object(true).unwrap());
            assert_eq!(platform.read32(PSR_CTL), ARMED);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr_kms_vbt_refusal_precedes_sink_and_source
);

fn smoke_psr_kms_vbt_wakeup_times_reach_psr_ctl() -> TestResult {
    {
        // VBT TP1 100 µs (code 1), TP2/TP3 500 µs (code 0), idle frames 9.
        let platform = psr_platform();
        platform.0.lock().psr_vbt = vbt(9, 100, 500);
        let device = platform.meteor();
        present_once(&device, object(true).unwrap());
        assert_eq!(
            platform.read32(PSR_CTL),
            (1 << 31) | (0x1f << 20) | (1 << 11) | (1 << 10) | (3 << 6) | (1 << 4) | 9
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr_kms_vbt_wakeup_times_reach_psr_ctl
);

fn smoke_fbc_kms_present_only_polls_carve_and_activates_after_it() -> TestResult {
    {
        // No PSR timing: PSR is not offered, so FBC is eligible.
        let platform = MockPlatform::new();
        let _ = platform.dsb_timing();
        {
            let mut hw = platform.0.lock();
            hw.fbc_offset = Some(0x10_0000);
            hw.fbc_carve_pending = true;
        }
        let device = platform.meteor();
        let front = object(true).unwrap();
        let fbc_writes = |platform: &MockPlatform| {
            platform
                .all_writes()
                .iter()
                .filter(|&&(r, _)| (0x43200..0x43230).contains(&r) || r == PIPE_CLKGATE_DIS2)
                .count()
        };
        // Two latches while the off-path carve runs: each only polls it,
        // FBC stays off, nothing is programmed and nothing is refused.
        for polls in 1..=2 {
            present_once(&device, front.clone());
            assert_eq!(platform.0.lock().fbc_carve_polls, polls);
            assert_eq!(platform.read32(DPFC_CONTROL) & (1 << 31), 0);
            assert_eq!(fbc_writes(&platform), 0);
            let state = device.state.try_lock().unwrap();
            assert!(state.fbc.is_none() && !state.fbc_refused);
        }
        // The carve finished off-path: the next eligible latch places the
        // CFB and activates FBC on it.
        platform.0.lock().fbc_carve_pending = false;
        present_once(&device, front.clone());
        assert_eq!(platform.0.lock().fbc_carve_polls, 3);
        assert_eq!(platform.read32(0x43200), 0x10_0000);
        assert_ne!(platform.read32(DPFC_CONTROL) & (1 << 31), 0);
        // Placed once: later latches never poll again.
        present_once(&device, front);
        assert_eq!(platform.0.lock().fbc_carve_polls, 3);
        assert_ne!(platform.read32(DPFC_CONTROL) & (1 << 31), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_fbc",
    smoke_fbc_kms_present_only_polls_carve_and_activates_after_it
);

#[path = "intel_gpu_psr2_kms_tests.rs"]
mod psr2;

/// The panel's crtc off from a KMS owner (`intel_atomic_commit_tail` with the
/// crtc inactive) on a PSR panel: PSR is disabled (source, then sink) before
/// the platform's crtc disable; the dark panel keeps the owner valid without
/// a console scanout; panel-on lights it again once; a primary flip still
/// unlatched refuses the off with `Busy` before PSR, FBC or the crtc is
/// touched.
fn smoke_kms_mtl_panel_off_disables_psr_first_and_refuses_unlatched_flip() -> TestResult {
    {
        let platform = psr_platform();
        let device = platform.meteor();
        present_once(&device, object(true).unwrap());
        assert_eq!(platform.read32(PSR_CTL), ARMED);
        let mut session = complete(device.session()).unwrap();
        complete(session.restore_console()).unwrap();
        let start = platform.all_writes().len();
        complete(session.panel_off()).unwrap();
        assert!(session.panel_dark());
        assert!(session.psr().is_none());
        let writes = platform.all_writes()[start..].to_vec();
        let off = writes.iter().position(|&w| w == (PANEL_LOG, 0)).unwrap();
        assert_eq!(writes.iter().filter(|&&(r, _)| r == PANEL_LOG).count(), 1);
        assert_eq!(platform.read32(PSR_CTL) & (1 << 31), 0);
        if let Some(disable) = writes.iter().position(|&(r, _)| r == PSR_CTL) {
            assert!(disable < off, "PSR must be disabled before the crtc");
        }
        // A dark panel has no console scanout to prove; the owner stays valid.
        assert!(session.ownership_valid().is_ok());
        // A second off is a no-op; panel-on lights it once.
        complete(session.panel_off()).unwrap();
        complete(session.panel_on()).unwrap();
        complete(session.panel_on()).unwrap();
        assert!(!session.panel_dark());
        let panel: Vec<_> = platform.all_writes()[start..]
            .iter()
            .filter(|&&(r, _)| r == PANEL_LOG)
            .map(|&(_, v)| v)
            .collect();
        assert_eq!(panel, [0, 1]);
    }
    {
        // A flip armed but not latched (its future dropped) refuses.
        let platform = psr_platform();
        let device = platform.meteor();
        present_once(&device, object(true).unwrap());
        let mut session = complete(device.session()).unwrap();
        {
            let mut flip = Box::pin(session.present(object(true).unwrap(), geometry()));
            assert!(once(flip.as_mut()).is_pending());
        }
        let start = platform.all_writes().len();
        assert_eq!(complete(session.panel_off()), Err(FsError::Busy));
        assert!(!session.panel_dark());
        assert!(platform.all_writes()[start..].is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_kms_mtl_panel_off_disables_psr_first_and_refuses_unlatched_flip
);

/// FBIOBLANK's console DPMS (`drm_client_modeset_dpms`): without a KMS
/// master the console's crtc goes off (after the console restore) and back
/// on; with a master nothing happens and the call is `Busy`
/// (`drm_master_internal_acquire`).
fn smoke_kms_mtl_console_dpms_follows_master_and_toggles_the_panel() -> TestResult {
    let platform = psr_platform();
    let device = platform.meteor();
    let start = platform.all_writes().len();
    assert_eq!(
        complete(device.console_dpms(false, || true)),
        Err(FsError::Busy)
    );
    assert!(platform.all_writes()[start..]
        .iter()
        .all(|&(r, _)| r != PANEL_LOG));
    complete(device.console_dpms(false, || false)).unwrap();
    complete(device.console_dpms(false, || false)).unwrap();
    complete(device.console_dpms(true, || false)).unwrap();
    let panel: Vec<_> = platform.all_writes()[start..]
        .iter()
        .filter(|&&(r, _)| r == PANEL_LOG)
        .map(|&(_, v)| v)
        .collect();
    assert_eq!(panel, [0, 1]);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_kms_mtl_console_dpms_follows_master_and_toggles_the_panel
);
