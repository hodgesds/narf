//! Display-14 PSR2 with selective fetch through the production Device/Guard
//! path: qualification at the first latch (or the typed PSR1 fallback),
//! a damaged present that keeps PSR2 running and programs the commit's
//! selective fetch, the deep-sleep wake and its bounded fallback, the
//! cursor in the SU area, the external-pass bracket, FBC, and the disable
//! before the console. Expected values are written out from
//! intel_psr_regs.h, skl_universal_plane_regs.h, intel_cursor_regs.h and
//! drm_dp.h. x86_64 only, as the PSR1 fixtures.
use super::*;
use crate::drm::fb_cmd::{Damage, Rect};

const PSR2_CTL: u64 = 0x60900;
const PSR2_STATUS: u64 = 0x60940;
const MAN_TRK: u64 = 0x60910;
const SF_CTL: u64 = 0x70890;
const SF_POS: u64 = 0x70894;
const SF_SIZE: u64 = 0x70898;
const SF_CUR: u64 = 0x70880;
const CURSURFLIVE: u64 = 0x700ac;
const ALPM: u64 = AUX_LOG | 0x116;
/// hsw_activate_psr2 for the 64x32 fixture (216 µs lines: 7-line wakes,
/// an 8-line block count in the 45-line vblank): EDP_PSR2_ENABLE,
/// IDLE_FRAMES(6), FRAME_BEFORE_SU(3), TP2_TIME_2500us (VBT),
/// BLOCK_COUNT_NUM_2, IO_BUFFER_WAKE(7), FAST_WAKE(7).
const ARMED2: u32 = (1 << 31) | 6 | (3 << 4) | (2 << 8) | ((7 - 5) << 13) | ((7 - 5) << 10);
const EXITED2: u32 = ARMED2 & !(1 << 31);
/// PSR2_MAN_TRK_CTL: SF_PARTIAL_FRAME_UPDATE, SU_REGION_START_ADDR(y1),
/// SU_REGION_END_ADDR(y2 - 1).
fn su_region(y1: u32, y2: u32) -> u32 {
    (1 << 31) | (y1 << 16) | (y2 - 1)
}
/// SF_PARTIAL_FRAME_UPDATE | SF_CONTINUOS_FULL_FRAME.
const CFF: u32 = (1 << 31) | (1 << 13);

/// The PSR1 fixture sink with PSR version 3, the Y-coordinate and
/// granularity requirements, AUX-wake ALPM, 4x4 SU granularity and an
/// HBR2 link.
fn psr2_sink() -> BTreeMap<u32, u8> {
    let mut dpcd = sink();
    for (a, v) in [
        (0x070, 3),
        (0x071, 0x30),
        (0x02e, 1),
        (0x072, 4),
        (0x073, 0),
        (0x074, 4),
        (0x100, 0x14),
    ] {
        dpcd.insert(a, v);
    }
    dpcd
}

/// A PSR2 sink, a known PCI identity and display 14.00 C0 on a platform
/// [`attach`] prepared.
fn psr2_attach(platform: &MockPlatform) {
    {
        let mut hw = platform.0.lock();
        hw.psr_dpcd = Some(psr2_sink());
        hw.psr_pci = Some((0x7d55, 0x8086, 0));
    }
    platform.set(0x510a0, (14 << 22) | 8);
}

fn psr2_platform() -> MockPlatform {
    let platform = MockPlatform::new();
    let timing = platform.dsb_timing();
    attach(&platform, timing, Some(false));
    psr2_attach(&platform);
    platform
}

fn rows(y1: i32, y2: i32) -> Damage {
    Damage::Clips(alloc::vec![Rect::new(3, y1, 20, y2)])
}

fn present_damage(device: &Device<MockPlatform>, damage: &Damage) {
    let mut session = complete(device.selective_session()).unwrap();
    complete(session.present_damaged(object(true).unwrap(), geometry(), damage)).unwrap();
}

fn smoke_psr2_kms_enables_selective_fetch_after_latch() -> TestResult {
    {
        let platform = psr2_platform();
        let device = platform.meteor();
        let mut session = complete(device.session()).unwrap();
        complete(session.present(object(true).unwrap(), geometry())).unwrap();
        // intel_alpm_enable_sink, _psr_enable_sink (PSR2 with HPD on CRC
        // errors), then DP_SET_POWER D0, after the KMS latch.
        assert_eq!(
            sink_writes(&platform.all_writes()),
            [
                (ALPM, 0x03),
                (EN_CFG, 0x60),
                (EN_CFG, 0x61),
                (SET_POWER, 0x01)
            ]
        );
        // The qualifying commit's selective fetch: the whole plane.
        assert_eq!(platform.read32(MAN_TRK), su_region(0, 32));
        assert_eq!(platform.read32(SF_POS), 0);
        assert_eq!(platform.read32(SF_SIZE), (31 << 16) | 63);
        assert_eq!(platform.read32(SF_CTL), 1 << 31);
        // Enabled, not active until the session's changes latched.
        assert_eq!(platform.read32(PSR2_CTL) & (1 << 31), 0);
        drop(session);
        assert_eq!(platform.read32(PSR2_CTL), ARMED2);
        assert_eq!(platform.read32(PSR_CTL), 0);
        let psr = psr(&device).unwrap();
        assert!(psr.selective() && psr.active());
        assert_eq!(device.state.try_lock().unwrap().psr2_refused, None);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr2_kms_enables_selective_fetch_after_latch
);

fn smoke_psr2_kms_damaged_present_runs_a_selective_update() -> TestResult {
    {
        let platform = psr2_platform();
        let device = platform.meteor();
        present_once(&device, object(true).unwrap());
        assert_eq!(platform.read32(PSR2_CTL), ARMED2);
        // PSR2 in deep sleep: the frame-change event wakes it.
        platform.set(PSR2_STATUS, 8 << 28);
        let start = platform.all_writes().len();
        {
            let mut session = complete(device.selective_session()).unwrap();
            assert_eq!(
                platform.read32(PSR2_CTL),
                ARMED2,
                "selective session exited PSR2"
            );
            complete(session.present_damaged(object(true).unwrap(), geometry(), &rows(9, 10)))
                .unwrap();
        }
        assert_eq!(platform.read32(PSR2_CTL), ARMED2);
        assert_eq!(platform.read32(PSR2_STATUS), 0);
        let writes = &platform.all_writes()[start..];
        // PSR stayed enabled throughout: no PSR or PSR2 control write.
        assert!(writes.iter().all(|&(r, _)| r != PSR2_CTL && r != PSR_CTL));
        // Rows 9..10 widened to the 4-line granularity: SU 8..12. The
        // no-arm half, the frame-change event, the transcoder's manual
        // tracking, the plane's selective-fetch enable, then the arm.
        let at = |w: (u64, u32)| writes.iter().position(|&x| x == w).unwrap();
        let size = at((SF_SIZE, (3 << 16) | 63));
        let wake = at((CURSURFLIVE, 0));
        let track = at((MAN_TRK, su_region(8, 12)));
        let enable = at((SF_CTL, 1 << 31));
        let arm = writes.iter().position(|&(r, _)| r == SURF).unwrap();
        assert!(size < wake && wake < track && track < enable && enable < arm);
        assert_eq!(platform.read32(SF_POS), 8 << 16);
        assert_eq!(psr(&device).unwrap().areas().0, Some((8, 12)));
        // A whole-plane present (no FB_DAMAGE_CLIPS) is a partial frame
        // over every row; damage outside the plane is a full frame.
        present_damage(&device, &Damage::Full);
        assert_eq!(platform.read32(MAN_TRK), su_region(0, 32));
        present_damage(&device, &rows(40, 50));
        assert_eq!(platform.read32(MAN_TRK), CFF);
        assert_eq!(platform.read32(PSR2_CTL), ARMED2);
        // Any other session (here a plain present) exits PSR2 first and
        // re-arms it once its changes latched, as for PSR1.
        let start = platform.all_writes().len();
        let mut session = complete(device.session()).unwrap();
        assert_eq!(platform.read32(PSR2_CTL), EXITED2);
        complete(session.present(object(true).unwrap(), geometry())).unwrap();
        drop(session);
        assert_eq!(platform.read32(PSR2_CTL), ARMED2);
        let writes = &platform.all_writes()[start..];
        let exit = writes
            .iter()
            .position(|&w| w == (PSR2_CTL, EXITED2))
            .unwrap();
        let arm = writes.iter().position(|&(r, _)| r == SURF).unwrap();
        let rearm = writes
            .iter()
            .rposition(|&w| w == (PSR2_CTL, ARMED2))
            .unwrap();
        assert!(exit < arm && arm < rearm);
        assert!(sink_writes(writes).is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr2_kms_damaged_present_runs_a_selective_update
);

fn smoke_psr2_kms_deep_sleep_timeout_exits_before_the_arm() -> TestResult {
    {
        let platform = psr2_platform();
        let device = platform.meteor();
        present_once(&device, object(true).unwrap());
        // No wake: PSR_IDLE_TIMEOUT_MS (50 ms) passes in 10 ms ticks.
        platform.0.lock().psr2_stuck = true;
        platform.0.lock().tick_ns = 10_000_000;
        platform.set(PSR2_STATUS, 8 << 28);
        let start = platform.all_writes().len();
        let mut session = complete(device.selective_session()).unwrap();
        drive(session.present_damaged(object(true).unwrap(), geometry(), &rows(9, 10))).unwrap();
        // Linux proceeds after the timed-out wait; here PSR2 also exits so
        // the latch cannot wait on deep sleep. The commit's selective
        // fetch is still programmed.
        assert_eq!(platform.read32(PSR2_CTL), EXITED2);
        assert_eq!(platform.read32(MAN_TRK), su_region(8, 12));
        drop(session);
        assert_eq!(platform.read32(PSR2_CTL), ARMED2);
        let writes = &platform.all_writes()[start..];
        let wake = writes.iter().position(|&w| w == (CURSURFLIVE, 0)).unwrap();
        let exit = writes
            .iter()
            .position(|&w| w == (PSR2_CTL, EXITED2))
            .unwrap();
        let arm = writes.iter().position(|&(r, _)| r == SURF).unwrap();
        let rearm = writes
            .iter()
            .rposition(|&w| w == (PSR2_CTL, ARMED2))
            .unwrap();
        assert!(wake < exit && exit < arm && arm < rearm);
        assert!(psr(&device).unwrap().selective());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr2_kms_deep_sleep_timeout_exits_before_the_arm
);

fn smoke_psr2_kms_cursor_joins_the_selective_fetch() -> TestResult {
    {
        let platform = psr2_platform();
        // A visible 64x64 ARGB cursor at (3, 4): rows 4..68.
        platform.set(0x70080, 0x27);
        platform.set(0x70088, (4 << 16) | 3);
        platform.set(0x70084, 0x2000);
        let device = platform.meteor();
        present_once(&device, object(true).unwrap());
        // The qualifying commit covers rows 0..32: the cursor fetches its
        // rows 0..28, with the CURBASE write that arms it.
        assert_eq!(platform.read32(SF_CUR), 0x27);
        assert_eq!(psr(&device).unwrap().areas().1, Some((0, 28)));
        // SU 0..4 misses the cursor: its fetch is disabled.
        let start = platform.all_writes().len();
        present_damage(&device, &rows(1, 2));
        let writes = &platform.all_writes()[start..];
        let off = writes.iter().position(|&w| w == (SF_CUR, 0)).unwrap();
        let base = writes.iter().position(|&w| w == (0x70084, 0x2000)).unwrap();
        let surf = writes.iter().position(|&(r, _)| r == SURF).unwrap();
        assert!(surf < off && off < base);
        assert_eq!(platform.read32(MAN_TRK), su_region(0, 4));
        // SU 20..24 crosses it: the cursor fetches its rows 16..20.
        present_damage(&device, &rows(21, 22));
        assert_eq!(platform.read32(SF_CUR), 0x27);
        assert_eq!(psr(&device).unwrap().areas().1, Some((16, 20)));
        // A cursor at a negative x is unsupported: a full frame.
        platform.set(0x70088, (4 << 16) | (1 << 15) | 3);
        present_damage(&device, &rows(21, 22));
        assert_eq!(platform.read32(MAN_TRK), CFF);
        assert_eq!(platform.read32(PSR2_CTL), ARMED2);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr2_kms_cursor_joins_the_selective_fetch
);

fn smoke_psr2_kms_unqualified_falls_back_to_psr1_with_typed_reason() -> TestResult {
    {
        use crate::intel_gpu_psr::Psr2Refusal;
        for case in 0..5 {
            let platform = psr2_platform();
            let expected = match case {
                0 => {
                    let mut hw = platform.0.lock();
                    hw.psr_dpcd.as_mut().unwrap().insert(0x02e, 0);
                    Psr2Refusal::NoSinkSu
                }
                1 => {
                    platform.set(0x70030, 4 << 5); // PIPE_MISC_BPC_12_ADLP
                    Psr2Refusal::PipeBpp
                }
                2 => {
                    platform.set(0x78004, 1 << 31); // VDSC0_ENABLE
                    Psr2Refusal::StreamSplit
                }
                3 => {
                    platform.0.lock().psr_pci = None;
                    Psr2Refusal::Unknown
                }
                _ => {
                    // Seven blank lines: PSR1's 2 setup lines fit, PSR2's
                    // 8 block-count lines do not.
                    platform.set(0x6000c, (38 << 16) | 31);
                    platform.0.lock().psr_timing.as_mut().unwrap().vtotal = 39;
                    Psr2Refusal::Vblank
                }
            };
            let device = platform.meteor();
            present_once(&device, object(true).unwrap());
            let state = device.state.try_lock().unwrap();
            let psr = state.psr.unwrap();
            assert!(!psr.selective(), "case {case}");
            assert_eq!(state.psr2_refused, Some(expected));
            drop(state);
            assert_eq!(platform.read32(PSR_CTL), ARMED, "case {case}");
            assert_eq!(
                sink_writes(&platform.all_writes()),
                [(EN_CFG, 0x04), (EN_CFG, 0x05), (SET_POWER, 0x01)]
            );
            assert!(platform
                .all_writes()
                .iter()
                .all(|&(r, _)| r != PSR2_CTL && r != MAN_TRK && !(0x70880..0x708a0).contains(&r)));
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr2_kms_unqualified_falls_back_to_psr1_with_typed_reason
);

fn smoke_psr2_kms_external_pass_brackets_psr2() -> TestResult {
    {
        let platform = MockPlatform::new();
        let timing = owned_resources(&platform, 14 | (16 << 16));
        attach(&platform, timing, Some(false));
        psr2_attach(&platform);
        let device = platform.meteor();
        present_once(&device, object(true).unwrap());
        assert!(psr(&device).unwrap().selective());
        assert_eq!(platform.read32(PSR2_CTL), ARMED2);
        // The pass exits PSR2 and waits for its idle before any
        // repartition write, and re-arms it from idle when it ends.
        platform.step_on_read(Some(FRAME));
        {
            let mut pass = device.external_pass().unwrap();
            pass.pre_update();
            assert_eq!(platform.read32(PSR2_CTL), EXITED2);
            pass.post_update();
            assert_eq!(
                platform.read32(PSR2_CTL),
                EXITED2,
                "re-armed inside the pass"
            );
        }
        platform.step_on_read(None);
        assert_eq!(platform.read32(PSR2_CTL), ARMED2);
        assert!(psr(&device).unwrap().selective());
        // A damaged present afterwards runs a selective update again.
        present_damage(&device, &rows(9, 10));
        assert_eq!(platform.read32(MAN_TRK), su_region(8, 12));
        assert_eq!(platform.read32(PSR2_CTL), ARMED2);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr2_kms_external_pass_brackets_psr2
);

fn smoke_psr2_kms_fbc_stays_off_and_disable_precedes_console() -> TestResult {
    {
        // has_sel_update refuses FBC ("Selective update enabled"): the
        // carve is never even polled, across a selective update.
        let platform = psr2_platform();
        platform.0.lock().fbc_offset = Some(0x10_0000);
        let device = platform.meteor();
        present_once(&device, object(true).unwrap());
        present_damage(&device, &rows(9, 10));
        assert_eq!(platform.read32(0x43208) & (1 << 31), 0);
        assert_eq!(platform.0.lock().fbc_carve_polls, 0);
        // intel_psr_disable_locked before the console: PSR2 off, then the
        // sink's PSR and ALPM configuration cleared.
        let start = platform.all_writes().len();
        let mut session = complete(device.session()).unwrap();
        complete(session.restore_console()).unwrap();
        drop(session);
        assert_eq!(platform.read32(PSR2_CTL) & (1 << 31), 0);
        assert!(psr(&device).is_none());
        let writes = &platform.all_writes()[start..];
        assert_eq!(sink_writes(writes), [(EN_CFG, 0x00), (ALPM, 0x00)]);
        let off = writes.iter().position(|&w| w == (EN_CFG, 0)).unwrap();
        let console = writes.iter().position(|&w| w == (SURF, CONSOLE)).unwrap();
        assert!(off < console);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr2_kms_fbc_stays_off_and_disable_precedes_console
);
