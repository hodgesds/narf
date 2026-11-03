//! Display-14 PSR1 through the production Device/Guard path: enabled after
//! a latched KMS framebuffer, exited at every session start before any
//! frame change, re-armed once the session's changes latched, disabled
//! before console restore, legacy guards and reset recovery, and the
//! FBC/PSR policy in both directions. Expected values are written out from
//! intel_psr_regs.h, i915_reg.h and drm_dp.h. x86_64 only: the KMS
//! present path needs WC GEM objects.
use super::*;

const PSR_CTL: u64 = 0x60800;
const PSR_IIR: u64 = 0x60818;
const DPFC_CONTROL: u64 = 0x43208;
const PIPE_CLKGATE_DIS2: u64 = 0x60114;
const EN_CFG: u64 = AUX_LOG | 0x170;
const SET_POWER: u64 = AUX_LOG | 0x600;
/// hsw_activate_psr1 for the fixture sink: EDP_PSR_ENABLE,
/// MAX_SLEEP_TIME(0x1f), TP_TP1_TP3, CRC_ENABLE, TP2_TP3_TIME_2500us,
/// TP4_TIME_0us, TP1_TIME_2500us, idle frames max(6, 2 + 1).
const ARMED: u32 =
    (1 << 31) | (0x1f << 20) | (1 << 11) | (1 << 10) | (2 << 8) | (3 << 6) | (2 << 4) | 6;
const EXITED: u32 = ARMED & !(1 << 31);

/// eDP 1.4 PSR1 sink: DPCD 1.4, TPS3 + 4 lanes, PSR version 1, 330 µs
/// setup, SET_POWER_CAP, max resync 2 frames.
fn sink() -> BTreeMap<u32, u8> {
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

/// The fixture's fixed timing (64x32, htotal 224, vtotal 77 at 1034 kHz:
/// the 330 µs setup is 2 lines, well inside 44) with a PSR sink attached.
fn attach(platform: &MockPlatform, timing: crate::intel_gpu_dsb::Timing, wm: Option<bool>) {
    let mut hw = platform.0.lock();
    hw.psr_dpcd = Some(sink());
    hw.psr_timing = Some(timing);
    hw.psr_wm = wm;
}

fn psr_platform() -> MockPlatform {
    let platform = MockPlatform::new();
    let timing = platform.dsb_timing();
    attach(&platform, timing, Some(false));
    platform
}

fn psr(device: &Device<MockPlatform>) -> Option<crate::intel_gpu_psr::Psr> {
    device.state.try_lock().unwrap().psr
}

fn sink_writes(writes: &[(u64, u32)]) -> Vec<(u64, u32)> {
    writes
        .iter()
        .filter(|(r, _)| r & AUX_LOG != 0)
        .copied()
        .collect()
}

fn present_once(device: &Device<MockPlatform>, object: Arc<GemObject>) {
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
