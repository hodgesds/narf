//! Display-14 PSR1 fixtures. Every expected byte and register value is
//! written out from the pinned definitions (drm_dp.h, intel_psr_regs.h,
//! i915_reg.h) and the cited intel_psr.c functions, not from this module's
//! constants.

extern crate alloc;

use super::*;
use crate::dp_aux::AuxResponse;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cell::RefCell;
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Default)]
struct Regs {
    map: RefCell<BTreeMap<u64, u32>>,
    writes: RefCell<Vec<(u64, u32)>>,
}
impl Regs {
    fn set(&self, off: u64, v: u32) {
        self.map.borrow_mut().insert(off, v);
    }
    fn get(&self, off: u64) -> u32 {
        *self.map.borrow().get(&off).unwrap_or(&0)
    }
    fn log(&self) -> Vec<(u64, u32)> {
        self.writes.borrow().clone()
    }
}
impl MmioWindow for Regs {
    fn read32(&self, off: u64) -> u32 {
        self.get(off)
    }
    fn write32(&self, off: u64, v: u32) {
        self.writes.borrow_mut().push((off, v));
        self.set(off, v);
    }
}

#[derive(Default)]
struct Sinkd {
    dpcd: BTreeMap<u32, u8>,
    nack: Vec<u32>,
    writes: Vec<(u32, u8)>,
}
impl AuxChannel for Sinkd {
    fn transact<'a>(
        &mut self,
        req: &AuxRequest<'_>,
        reply: &'a mut [u8],
    ) -> Result<AuxResponse<'a>, AuxError> {
        if self.nack.contains(&req.address) {
            reply[0] = 1;
            return Ok(AuxResponse {
                status: AuxStatus::Nack,
                data: &reply[..0],
            });
        }
        reply[0] = 0;
        match req.cmd {
            AuxCommand::NativeWrite => {
                for (i, b) in req.data.iter().enumerate() {
                    self.dpcd.insert(req.address + i as u32, *b);
                    self.writes.push((req.address + i as u32, *b));
                }
                Ok(AuxResponse {
                    status: AuxStatus::Ack,
                    data: &reply[..0],
                })
            }
            AuxCommand::NativeRead => {
                let n = req.data.len();
                for i in 0..n {
                    reply[1 + i] = *self.dpcd.get(&(req.address + i as u32)).unwrap_or(&0);
                }
                Ok(AuxResponse {
                    status: AuxStatus::Ack,
                    data: &reply[1..1 + n],
                })
            }
            _ => Err(AuxError::UnknownStatus),
        }
    }
}

/// eDP 1.4 PSR1 panel: DPCD 1.4, TPS3 with four lanes, PSR version 1,
/// setup code 0 (330 µs), eDP general cap 1 with SET_POWER_CAP, max
/// resync 2 frames.
fn psr1_sink() -> Sinkd {
    let mut sink = Sinkd::default();
    for (a, v) in [
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
        (0x2009, 0x52),
    ] {
        sink.dpcd.insert(a, v);
    }
    sink
}

/// 2880x1800: 333_000 kHz, htotal 3040, vtotal 1866 (66 blank lines).
/// The 330 µs setup time is ceil(330 * 333_000 / (1000 * 3040)) =
/// ceil(36.15) = 37 lines.
fn timing() -> crate::intel_gpu_dsb::Timing {
    crate::intel_gpu_dsb::Timing {
        clock: 333_000,
        width: 2880,
        height: 1800,
        htotal: 3040,
        vtotal: 1866,
        flags: 0,
    }
}

/// A VBT panel with PSR enabled, 2500 µs TP1 and TP2/TP3 wake times (BDB
/// 205+ code 2) and no idle-frame floor.
fn vbt() -> VbtPsr {
    VbtPsr::Panel(crate::intel_gpu_vbt::PsrPanel {
        enable: true,
        table: Some(crate::intel_gpu_vbt::PsrTable {
            full_link: false,
            require_aux_wakeup: false,
            idle_frames: 0,
            tp1_wakeup_time_us: 2500,
            tp2_tp3_wakeup_time_us: 2500,
            psr2_tp2_tp3_wakeup_time_us: 2500,
        }),
    })
}

/// hsw_activate_psr1: EDP_PSR_ENABLE, MAX_SLEEP_TIME(0x1f), TP_TP1_TP3,
/// CRC_ENABLE, TP2_TP3_TIME_2500us, TP4_TIME_0us, TP1_TIME_2500us, idle.
fn armed(idle: u32, tps3: bool) -> u32 {
    (1 << 31)
        | (0x1f << 20)
        | if tps3 { 1 << 11 } else { 0 }
        | (1 << 10)
        | (2 << 8)
        | (3 << 6)
        | (2 << 4)
        | idle
}

fn smoke_psr_sink_caps_decode_and_refusals() -> TestResult {
    let mut aux = psr1_sink();
    let sink = Sink::read(&mut aux).unwrap();
    // DP_MAX_RESYNC_FRAME_COUNT_MASK is bits 3:0, not the last-actual field.
    assert_eq!(sink.sync_latency, 2);
    assert!(sink.tps3() && sink.set_power_cap() && !sink.su_support());
    assert_eq!(sink.setup_time_us(), Some(330));
    assert_eq!(sink.psr_support(), Ok(()));
    assert!(aux.writes.is_empty(), "capability reads wrote the sink");

    // Unreadable sync latency: Linux assumes the worst, 8 frames.
    let mut aux = psr1_sink();
    aux.nack.push(0x2009);
    assert_eq!(Sink::read(&mut aux).unwrap().sync_latency, 8);

    let refuse = |address: u32, value: u8| {
        let mut aux = psr1_sink();
        aux.dpcd.insert(address, value);
        Sink::read(&mut aux).unwrap().psr_support()
    };
    assert_eq!(refuse(0x070, 0), Err(Refusal::NoSinkPsr));
    assert_eq!(refuse(0x701, 0x7f), Err(Refusal::NoSetPowerCap));
    let mut aux = psr1_sink();
    aux.dpcd.insert(0x401, 0x10);
    aux.dpcd.insert(0x402, 0xfa);
    assert_eq!(
        Sink::read(&mut aux).unwrap().psr_support(),
        Err(Refusal::SinkQuirk)
    );
    // A failed eDP DPCD read leaves edp_dpcd zero: no power-state control.
    let mut aux = psr1_sink();
    aux.nack.push(0x700);
    assert_eq!(
        Sink::read(&mut aux).unwrap().psr_support(),
        Err(Refusal::NoSetPowerCap)
    );
    let mut aux = psr1_sink();
    aux.nack.push(0x070);
    assert_eq!(Sink::read(&mut aux), Err(Refusal::Aux(AuxError::Nacked)));

    // PSR2 capability (_psr_init_dpcd): version 3, Y-coordinate required,
    // AUX-wake ALPM; granularity required with X = 0 (default 4) and Y = 0
    // (read as 1).
    let mut aux = psr1_sink();
    for (a, v) in [
        (0x070, 3),
        (0x071, 0x30),
        (0x02e, 1),
        (0x072, 0),
        (0x073, 0),
        (0x074, 0),
    ] {
        aux.dpcd.insert(a, v);
    }
    let sink = Sink::read(&mut aux).unwrap();
    assert!(sink.su_support());
    assert_eq!((sink.su_w_granularity, sink.su_y_granularity), (4, 1));
    aux.dpcd.insert(0x02e, 0);
    assert!(!Sink::read(&mut aux).unwrap().su_support());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr_sink_caps_decode_and_refusals
);

fn smoke_psr_qualify_follows_compute_config() -> TestResult {
    let sink = Sink::read(&mut psr1_sink()).unwrap();
    assert_eq!(
        compute_psr1(&sink, &timing(), &vbt(), Some(true)),
        Ok(Psr1 {
            idle_frames: 6,
            tps3: true,
            wm_level_disabled: true,
            tp1_wakeup_us: 2500,
            tp2_tp3_wakeup_us: 2500,
        })
    );
    // idle = max(6, sync_latency + 1), at most 0xf.
    let mut latency = sink;
    latency.sync_latency = 9;
    assert_eq!(
        compute_psr1(&latency, &timing(), &vbt(), Some(false))
            .unwrap()
            .idle_frames,
        10
    );
    latency.sync_latency = 15;
    assert_eq!(
        compute_psr1(&latency, &timing(), &vbt(), Some(false))
            .unwrap()
            .idle_frames,
        15
    );
    let mut interlaced = timing();
    interlaced.flags |= 1 << 4;
    assert_eq!(
        compute_psr1(&sink, &interlaced, &vbt(), Some(false)),
        Err(Refusal::Interlaced)
    );
    // Setup code 7 is reserved: drm_dp_psr_setup_time returns -EINVAL.
    let mut reserved = sink;
    reserved.psr[1] = 7 << 1;
    assert_eq!(
        compute_psr1(&reserved, &timing(), &vbt(), Some(false)),
        Err(Refusal::InvalidSetupTime)
    );
    // 37 setup lines must fit vtotal - vdisplay - 1.
    assert_eq!(usecs_to_scanlines(&timing(), 330), 37);
    let mut tight = timing();
    tight.vtotal = 1800 + 37;
    assert_eq!(
        compute_psr1(&sink, &tight, &vbt(), Some(false)),
        Err(Refusal::SetupTimeTooLong)
    );
    tight.vtotal = 1800 + 38;
    assert!(compute_psr1(&sink, &tight, &vbt(), Some(false)).is_ok());
    // The 0 µs setup code always fits.
    let mut zero = sink;
    zero.psr[1] = 6 << 1;
    assert!(compute_psr1(&zero, &timing(), &vbt(), Some(false)).is_ok());
    assert_eq!(
        compute_psr1(&sink, &timing(), &vbt(), None),
        Err(Refusal::WmLevelUnknown)
    );
    // Latched refusals are sink/mode facts; the rest are retried.
    for r in [
        Refusal::NoSinkPsr,
        Refusal::SinkQuirk,
        Refusal::NoSetPowerCap,
        Refusal::Interlaced,
        Refusal::InvalidSetupTime,
        Refusal::SetupTimeTooLong,
        Refusal::SinkNotReliable,
        Refusal::ExitTimeout,
    ] {
        assert!(r.latched());
    }
    for r in [
        Refusal::NoTiming,
        Refusal::VbtDisabled,
        Refusal::VbtPanelByPnpId,
        Refusal::Aux(AuxError::Deferred),
        Refusal::WmLevelUnknown,
        Refusal::InterruptDelivery,
        Refusal::Inherited,
        Refusal::Unavailable,
        // VRR can toggle off, so a VRR refusal is re-evaluated at
        // the next latch rather than latched for the card's life.
        Refusal::VrrEnabled,
    ] {
        assert!(!r.latched());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr_qualify_follows_compute_config
);

fn smoke_psr_enable_conversation_is_linux_ordered() -> TestResult {
    for wm_level_disabled in [false, true] {
        let regs = Regs::default();
        regs.set(0x60800, 1 << 29); // context-restore flag is preserved
        regs.set(0x46430, (if wm_level_disabled { 0 } else { 1 << 23 }) | 1);
        regs.set(0x60814, !0x10);
        let mut aux = psr1_sink();
        let sink = Sink::read(&mut aux).unwrap();
        let config = compute_psr1(&sink, &timing(), &vbt(), Some(wm_level_disabled)).unwrap();
        let mut psr = Psr::enable(&regs, &mut aux, config).unwrap();
        // _psr_enable_sink: CRC verification without and then with
        // DP_PSR_ENABLE (no link standby on display >= 12), then D0.
        assert_eq!(aux.writes, [(0x170, 0x04), (0x170, 0x05), (0x600, 0x01)]);
        // intel_psr_enable_source: PSR_MASK HPD|MEMUP|LPSP|MAX_SLEEP,
        // psr_irq_control(TGL_PSR_MASK cleared, ~TGL_PSR_ERROR set),
        // Wa_14015648006 on GEN8_CHICKEN_DCPR_1 bit 23.
        assert_eq!(
            regs.log(),
            [
                (0x60860, (1 << 28) | (1 << 27) | (1 << 26) | (1 << 25)),
                (0x60814, !(1u32 << 2)),
                (0x46430, (if wm_level_disabled { 1 << 23 } else { 0 }) | 1),
            ]
        );
        // Activation is the caller's, after its frame change latched.
        assert!(!psr.active());
        assert_eq!(psr.resume(&regs), Ok(true));
        assert_eq!(regs.get(0x60800), (1 << 29) | armed(6, true));
        assert!(psr.active());
        // An already active PSR is not rewritten.
        let before = regs.log().len();
        assert_eq!(psr.resume(&regs), Ok(true));
        assert_eq!(regs.log().len(), before);
    }
    // Without TPS3 the TP1/TP2 select is used.
    let regs = Regs::default();
    let mut aux = psr1_sink();
    aux.dpcd.insert(0x002, 0x84);
    let sink = Sink::read(&mut aux).unwrap();
    let config = compute_psr1(&sink, &timing(), &vbt(), Some(false)).unwrap();
    let mut psr = Psr::enable(&regs, &mut aux, config).unwrap();
    psr.resume(&regs).unwrap();
    assert_eq!(regs.get(0x60800), armed(6, false));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr_enable_conversation_is_linux_ordered
);

type RefusalCase<'a> = (&'a dyn Fn(&Regs), Refusal);

fn smoke_psr_enable_refuses_before_any_write() -> TestResult {
    let config = compute_psr1(
        &Sink::read(&mut psr1_sink()).unwrap(),
        &timing(),
        &vbt(),
        Some(false),
    )
    .unwrap();
    let cases: [RefusalCase<'_>; 7] = [
        (&|r| r.set(0x60800, 1 << 31), Refusal::Inherited),
        (&|r| r.set(0x60900, 1 << 31), Refusal::Inherited),
        (&|r| r.set(0x60800, u32::MAX), Refusal::Unavailable),
        // GEN8_DE_EDP_PSR enabled and unmasked: no handler exists.
        (&|r| r.set(0x4446c, 1 << 19), Refusal::InterruptDelivery),
        // psr_interrupt_error_check: a latched TGL_PSR_ERROR.
        (&|r| r.set(0x60818, 1 << 2), Refusal::SinkNotReliable),
        (&|r| r.set(0x4446c, u32::MAX), Refusal::Unavailable),
        // GEN8_CHICKEN_DCPR_1 is read before the sink is touched.
        (&|r| r.set(0x46430, u32::MAX), Refusal::Unavailable),
    ];
    for (setup, refusal) in cases {
        let regs = Regs::default();
        setup(&regs);
        let mut aux = psr1_sink();
        assert_eq!(Psr::enable(&regs, &mut aux, config), Err(refusal));
        assert!(regs.log().is_empty() && aux.writes.is_empty());
    }
    // Masked delivery is not a refusal.
    let regs = Regs::default();
    regs.set(0x4446c, 1 << 19);
    regs.set(0x44464, 1 << 19);
    assert!(Psr::enable(&regs, &mut psr1_sink(), config).is_ok());
    // A sink that refuses its configuration leaves the source untouched
    // and is told to disable.
    let regs = Regs::default();
    let mut aux = psr1_sink();
    aux.nack.push(0x600);
    assert_eq!(
        Psr::enable(&regs, &mut aux, config),
        Err(Refusal::Aux(AuxError::Nacked))
    );
    assert!(regs.log().is_empty());
    assert_eq!(aux.writes, [(0x170, 0x04), (0x170, 0x05), (0x170, 0x00)]);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr_enable_refuses_before_any_write
);

fn smoke_psr_pause_resume_and_disable_sequences() -> TestResult {
    let config = compute_psr1(
        &Sink::read(&mut psr1_sink()).unwrap(),
        &timing(),
        &vbt(),
        Some(true),
    )
    .unwrap();
    let regs = Regs::default();
    let mut aux = psr1_sink();
    let mut psr = Psr::enable(&regs, &mut aux, config).unwrap();
    psr.resume(&regs).unwrap();
    // intel_psr_exit: only EDP_PSR_ENABLE is cleared; idle is awaited.
    let before = regs.log().len();
    assert_eq!(psr.pause(&regs), Ok(()));
    assert_eq!(wait_idle(&regs, 0), Ok(()));
    assert_eq!(
        regs.log()[before..],
        [(0x60800, armed(6, true) & !(1 << 31))]
    );
    assert!(!psr.active());
    // Re-arm only from idle (intel_psr_work's idle gate).
    regs.set(0x60840, 6 << 29); // SRDOFFACK
    assert_eq!(psr.resume(&regs), Ok(false));
    assert_eq!(regs.get(0x60800) & (1 << 31), 0);
    regs.set(0x60840, 0);
    assert_eq!(psr.resume(&regs), Ok(true));
    assert_eq!(regs.get(0x60800), armed(6, true));
    // A status that never idles is a bounded failure.
    regs.set(0x60840, 2 << 29); // SRDENT
    assert_eq!(psr.pause(&regs), Ok(()));
    assert_eq!(wait_idle(&regs, 0), Err(Refusal::ExitTimeout));
    regs.set(0x60840, u32::MAX);
    assert_eq!(wait_idle(&regs, 0), Err(Refusal::Unavailable));
    regs.set(0x60840, 0);
    // A latched TGL_PSR_ERROR fails pause and resume before any write.
    psr.resume(&regs).unwrap();
    regs.set(0x60818, 1 << 2);
    let before = regs.log().len();
    assert_eq!(psr.pause(&regs), Err(Refusal::SinkNotReliable));
    assert_eq!(regs.log().len(), before);
    // intel_psr_disable_locked + intel_psr_handle_irq: exit, idle, undo
    // Wa_14015648006, DP_PSR_EN_CFG 0, then DP_SET_POWER D0.
    aux.writes.clear();
    assert_eq!(psr.disable(&regs, &mut aux, 0, true), Ok(()));
    assert_eq!(
        regs.log()[before..],
        [(0x60800, armed(6, true) & !(1 << 31)), (0x46430, 0),]
    );
    assert_eq!(aux.writes, [(0x170, 0x00), (0x600, 0x01)]);
    assert!(!psr.active());
    // Disable of a paused PSR writes no exit; a failed sink write is
    // reported after every step ran.
    regs.set(0x60818, 0);
    let mut psr = Psr::enable(&regs, &mut aux, config).unwrap();
    aux.nack.push(0x170);
    let before = regs.log().len();
    assert_eq!(
        psr.disable(&regs, &mut aux, 0, false),
        Err(Refusal::Aux(AuxError::Nacked))
    );
    assert_eq!(regs.log()[before..], [(0x46430, 0)]);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr_pause_resume_and_disable_sequences
);

fn smoke_psr_wm_level_provider_registry() -> TestResult {
    let previous = register_wm_level_disabled(None);
    assert_eq!(wm_level_disabled(), None);
    register_wm_level_disabled(Some(|| Some(true)));
    assert_eq!(wm_level_disabled(), Some(true));
    register_wm_level_disabled(previous);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr_wm_level_provider_registry
);

fn vbt_panel(enable: bool, idle_frames: u8, tp1: u32, tp23: u32) -> VbtPsr {
    VbtPsr::Panel(crate::intel_gpu_vbt::PsrPanel {
        enable,
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

fn smoke_psr_vbt_gate_precedes_every_other_check() -> TestResult {
    let sink = Sink::read(&mut psr1_sink()).unwrap();
    let mut interlaced = timing();
    interlaced.flags |= 1 << 4;
    // psr_global_enabled is intel_psr_compute_config's first test: no
    // VBT (psr.enable never set), a VBT that clears psr.enable for the
    // panel, and an unmatched PnP-ID panel all refuse before interlace,
    // sink or watermark facts are consulted.
    for (vbt, refusal) in [
        (VbtPsr::Missing, Refusal::VbtDisabled),
        (vbt_panel(false, 0, 2500, 2500), Refusal::VbtDisabled),
        (
            VbtPsr::Panel(crate::intel_gpu_vbt::PsrPanel {
                enable: false,
                table: None,
            }),
            Refusal::VbtDisabled,
        ),
        (VbtPsr::PanelByPnpId, Refusal::VbtPanelByPnpId),
    ] {
        assert_eq!(vbt.enabled().map(|_| ()), Err(refusal));
        assert_eq!(compute_psr1(&sink, &interlaced, &vbt, None), Err(refusal));
        assert!(!refusal.latched());
    }
    // An enabled panel without a PSR block qualifies; its wake times are
    // Linux's zeroed defaults.
    let bare = VbtPsr::Panel(crate::intel_gpu_vbt::PsrPanel {
        enable: true,
        table: None,
    });
    let config = compute_psr1(&sink, &timing(), &bare, Some(false)).unwrap();
    assert_eq!((config.tp1_wakeup_us, config.tp2_tp3_wakeup_us), (0, 0));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr_vbt_gate_precedes_every_other_check
);

fn smoke_psr_vbt_wakeup_times_and_idle_frames_reach_psr_ctl() -> TestResult {
    let sink = Sink::read(&mut psr1_sink()).unwrap();
    // intel_psr1_get_tp_time: 0 µs → code 3, <= 100 → 1, <= 500 → 0,
    // otherwise 2500 µs → 2; TP1 at bits 5:4, TP2/TP3 at bits 9:8.
    for (us, code) in [
        (0u32, 3u32),
        (1, 1),
        (100, 1),
        (101, 0),
        (500, 0),
        (501, 2),
        (2500, 2),
    ] {
        let vbt = vbt_panel(true, 0, us, us);
        let config = compute_psr1(&sink, &timing(), &vbt, Some(false)).unwrap();
        assert_eq!(
            psr1_tp_time(&config),
            (3 << 6) | (code << 4) | (code << 8) | (1 << 11)
        );
    }
    // Independent TP1 and TP2/TP3 fields: TP1 100 µs, TP2/TP3 500 µs,
    // VBT idle frames 9 above the floor of 6 and sync latency 2 + 1.
    let vbt = vbt_panel(true, 9, 100, 500);
    let config = compute_psr1(&sink, &timing(), &vbt, Some(false)).unwrap();
    assert_eq!(config.idle_frames, 9);
    assert_eq!(
        psr1_ctl(&config),
        (1 << 31) | (0x1f << 20) | (1 << 11) | (1 << 10) | (3 << 6) | (1 << 4) | 9
    );
    // The VBT term never exceeds EDP_PSR_IDLE_FRAMES_MASK; 0 µs codes.
    let zero = vbt_panel(true, 15, 0, 0);
    let config = compute_psr1(&sink, &timing(), &zero, Some(false)).unwrap();
    assert_eq!(config.idle_frames, 15);
    assert_eq!(
        psr1_ctl(&config),
        (1 << 31) | (0x1f << 20) | (1 << 11) | (1 << 10) | (3 << 8) | (3 << 6) | (3 << 4) | 15
    );
    // Activation programs exactly that value.
    let regs = Regs::default();
    let mut aux = psr1_sink();
    let config = compute_psr1(&sink, &timing(), &vbt, Some(false)).unwrap();
    let mut psr = Psr::enable(&regs, &mut aux, config).unwrap();
    psr.resume(&regs).unwrap();
    assert_eq!(regs.get(0x60800), psr1_ctl(&config));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr_vbt_wakeup_times_and_idle_frames_reach_psr_ctl
);

/// A BDB 228 VBT: the eDP child on DDI A with `handle`, LFP options
/// selecting `panel` (LFP1) and `panel ^ 1` (LFP2), the LFP power block
/// enabling PSR for `enabled` panels, and a PSR table giving every panel
/// TP1 code 1 (100 µs), TP2/TP3 code 0 (500 µs) and idle frames = panel.
fn psr_vbt_image(handle: u16, panel: u8, enabled: u16) -> crate::intel_gpu_vbt::Vbt {
    use crate::intel_gpu_vbt::tests::{general_definitions, Child, VbtImage};
    use crate::intel_gpu_vbt::{block, device_type, dp_aux, dvo_port};
    let [lo, hi] = handle.to_le_bytes();
    let edp = Child::new(device_type::EDP, dvo_port::DPA)
        .aux(dp_aux::A)
        .byte(0, lo)
        .byte(1, hi);
    let mut options = alloc::vec![0u8; 34];
    options[0] = panel;
    options[1] = panel ^ 1;
    let mut power = alloc::vec![0u8; 136];
    power[24..26].copy_from_slice(&enabled.to_le_bytes());
    let mut psr = alloc::vec![0u8; 100];
    for p in 0..16usize {
        psr[6 * p + 1] = p as u8;
        psr[6 * p + 2..6 * p + 4].copy_from_slice(&1u16.to_le_bytes());
        psr[6 * p + 4..6 * p + 6].copy_from_slice(&0u16.to_le_bytes());
    }
    crate::intel_gpu_vbt::Vbt::parse(
        &VbtImage::new(228)
            .block(block::GENERAL_DEFINITIONS, general_definitions(44, &[edp]))
            .block(block::LFP_OPTIONS, options)
            .block(block::LFP_POWER, power)
            .block(block::PSR, psr)
            .build(),
    )
    .unwrap()
}

fn smoke_psr_vbt_facts_follow_intel_bios_init_panel() -> TestResult {
    // LFP1 handle: panel_type 2, enabled by the LFP power bit for panel 2.
    let facts = VbtPsr::from_vbt(&psr_vbt_image(0x0008, 2, 1 << 2));
    let panel = facts.enabled().unwrap();
    let table = panel.table.unwrap();
    assert_eq!(
        (
            table.idle_frames,
            table.tp1_wakeup_time_us,
            table.tp2_tp3_wakeup_time_us
        ),
        (2, 100, 500)
    );
    // Panel 2's bit clear: disabled even though another panel's is set.
    assert_eq!(
        VbtPsr::from_vbt(&psr_vbt_image(0x0008, 2, 1 << 3))
            .enabled()
            .map(|_| ()),
        Err(Refusal::VbtDisabled)
    );
    // An LFP2 child reads panel_type2 (2 ^ 1 = 3).
    let lfp2 = VbtPsr::from_vbt(&psr_vbt_image(0x0080, 2, 1 << 3));
    assert_eq!(lfp2.enabled().unwrap().table.unwrap().idle_frames, 3);
    // 0xFF selects by PnP ID, which this driver does not match.
    assert_eq!(
        VbtPsr::from_vbt(&psr_vbt_image(0x0008, 0xff, 0xffff)),
        VbtPsr::PanelByPnpId
    );
    // install / installed round trip; probe installs Missing without a
    // VBT.
    let previous = installed_vbt();
    install_vbt(facts);
    assert_eq!(installed_vbt(), facts);
    install_vbt(VbtPsr::Missing);
    assert_eq!(
        installed_vbt().enabled().map(|_| ()),
        Err(Refusal::VbtDisabled)
    );
    install_vbt(previous);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr_vbt_facts_follow_intel_bios_init_panel
);

fn smoke_psr_wm_optimization_wa_follows_pre_and_post_plane_update() -> TestResult {
    let sink = Sink::read(&mut psr1_sink()).unwrap();
    let config = compute_psr1(&sink, &timing(), &vbt(), Some(false)).unwrap();
    let regs = Regs::default();
    regs.set(0x46430, 1 | (1 << 22));
    let mut aux = psr1_sink();
    let mut psr = Psr::enable(&regs, &mut aux, config).unwrap();
    assert_eq!(regs.get(0x46430), 1 | (1 << 22));
    // intel_psr_pre_plane_update: set before a disabling state latches.
    let before = regs.log().len();
    assert_eq!(psr.wm_optimization_wa(&regs, true), Ok(()));
    assert_eq!(regs.log()[before..], [(0x46430, 1 | (1 << 22) | (1 << 23))]);
    assert!(psr.config().wm_level_disabled);
    // intel_psr_post_plane_update: cleared after a full-level state.
    assert_eq!(psr.wm_optimization_wa(&regs, false), Ok(()));
    assert_eq!(regs.get(0x46430), 1 | (1 << 22));
    assert!(!psr.config().wm_level_disabled);
    // An unreadable chicken register is refused before any write.
    regs.set(0x46430, u32::MAX);
    let before = regs.log().len();
    assert_eq!(
        psr.wm_optimization_wa(&regs, true),
        Err(Refusal::Unavailable)
    );
    assert_eq!(regs.log().len(), before);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr_wm_optimization_wa_follows_pre_and_post_plane_update
);

#[path = "intel_gpu_psr2_tests.rs"]
mod psr2;
