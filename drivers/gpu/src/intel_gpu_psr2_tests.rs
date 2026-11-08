//! Display-14 PSR2 with selective fetch, against register and sink models.
//! Every expected value is written out from intel_psr_regs.h,
//! skl_universal_plane_regs.h, intel_cursor_regs.h, intel_display_regs.h and
//! drm_dp.h, and from the cited intel_psr.c / intel_alpm.c functions, not
//! from this module's constants.

use super::*;
use crate::drm::fb_cmd::{Damage, Rect};

/// PSR version 3 with the Y-coordinate and granularity requirements, the
/// 330 µs setup code, AUX-wake ALPM, X granularity 4, Y granularity 4, and
/// an HBR2 link (`DP_LINK_BW_SET` 0x14).
fn psr2_sink() -> Sinkd {
    let mut sink = psr1_sink();
    for (a, v) in [
        (0x070, 3),
        (0x071, 0x30),
        (0x02e, 1),
        (0x072, 4),
        (0x073, 0),
        (0x074, 4),
        (0x100, 0x14),
    ] {
        sink.dpcd.insert(a, v);
    }
    sink
}

/// Display 14.00 C0, 8 bpc, four lanes at HBR2, no SCL, no DSC or joiner,
/// no VRR exclusion.
fn source() -> Psr2Source {
    Psr2Source {
        step: 8,
        pipe_bpp: 24,
        lane_count: 4,
        port_clock: 540_000,
        set_context_latency: 0,
        stream_split: false,
        fw_sync_quirk: false,
        vrr_excludes_psr: false,
    }
}

fn panel(tp2: u32) -> crate::intel_gpu_vbt::PsrPanel {
    let VbtPsr::Panel(mut panel) = vbt() else {
        unreachable!()
    };
    panel.table.as_mut().unwrap().psr2_tp2_tp3_wakeup_time_us = tp2;
    panel
}

fn sink() -> Sink {
    Sink::read(&mut psr2_sink()).unwrap()
}

fn smoke_psr2_qualifies_like_intel_sel_update_config_valid() -> TestResult {
    let sink = sink();
    assert!(sink.su_support());
    assert_eq!((sink.su_w_granularity, sink.su_y_granularity), (4, 4));
    // 2880x1800 at 333 MHz, htotal 3040: a 42 µs IO/fast wake is
    // ceil(42 * 333000 / 3040000) = 5 lines, raised to the BSpec 7; the
    // block count is then 8 lines, within the 66-line vblank. hblank 160
    // pixels is 480 ns against ((60 / 4) + 11) * 1000 / 540 = 48 ns.
    let expected = Psr2 {
        io_wake_lines: 7,
        fast_wake_lines: 7,
        req_sdp_prior_scanline: false,
        su_y_granularity: 4,
        frames_before_su: 3,
        tp2_wakeup_us: 2500,
        a0_to_b0: false,
        width: 2880,
        height: 1800,
    };
    assert_eq!(
        compute_psr2(&sink, &timing(), &panel(2500), &source()),
        Ok(expected)
    );
    // frames_before_su_entry = max(sync_latency + 1, 2).
    let mut slow = sink;
    slow.sync_latency = 0;
    assert_eq!(
        compute_psr2(&slow, &timing(), &panel(2500), &source())
            .unwrap()
            .frames_before_su,
        2
    );
    // Display 14.00 A0..A3 (STEP_A0 + gmd step < STEP_B0).
    for (step, a0_to_b0) in [(0, true), (3, true), (4, false), (8, false)] {
        let source = Psr2Source { step, ..source() };
        assert_eq!(
            compute_psr2(&sink, &timing(), &panel(2500), &source)
                .unwrap()
                .a0_to_b0,
            a0_to_b0
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr2_qualifies_like_intel_sel_update_config_valid
);

fn smoke_psr2_refusals_fall_back_with_typed_reasons() -> TestResult {
    let sink = sink();
    let qualify = |sink: &Sink, timing: &crate::intel_gpu_dsb::Timing, source: &Psr2Source| {
        compute_psr2(sink, timing, &panel(2500), source)
    };
    let t = timing();
    // _psr_init_dpcd: no AUX-wake ALPM, no SU.
    let mut aux = psr2_sink();
    aux.dpcd.insert(0x02e, 0);
    let no_alpm = Sink::read(&mut aux).unwrap();
    assert_eq!(qualify(&no_alpm, &t, &source()), Err(Psr2Refusal::NoSinkSu));
    // VRR exclusion (Linux `intel_psr_compute_config`, fixed-RR TG
    // relaxation): refused before any sink fact is consulted — even
    // a sink that would otherwise qualify, and it wins over a
    // sink-side refusal too.
    let vrr = Psr2Source {
        vrr_excludes_psr: true,
        ..source()
    };
    assert_eq!(qualify(&sink, &t, &vrr), Err(Psr2Refusal::VrrEnabled));
    assert_eq!(qualify(&no_alpm, &t, &vrr), Err(Psr2Refusal::VrrEnabled));
    // DSC, a joiner or the splitter on Pipe A.
    let split = Psr2Source {
        stream_split: true,
        ..source()
    };
    assert_eq!(qualify(&sink, &t, &split), Err(Psr2Refusal::StreamSplit));
    // pipe_bpp above display 12-14's 30.
    for (bpp, ok) in [(30, true), (36, false)] {
        let source = Psr2Source {
            pipe_bpp: bpp,
            ..source()
        };
        assert_eq!(qualify(&sink, &t, &source).is_ok(), ok);
        if !ok {
            assert_eq!(qualify(&sink, &t, &source), Err(Psr2Refusal::PipeBpp));
        }
    }
    // intel_alpm_compute_params: 42 µs at 1 GHz / 3040 is 14 lines > 12.
    let fast = crate::intel_gpu_dsb::Timing {
        clock: 1_000_000,
        ..t
    };
    assert_eq!(qualify(&sink, &fast, &source()), Err(Psr2Refusal::WakeTime));
    // QUIRK_FW_SYNC_LEN adds 2 µs of precharge: 42 µs is 12 lines at
    // 285 MHz / 1000 (ceil 11.97), 44 µs is 13 (ceil 12.54).
    let edge = crate::intel_gpu_dsb::Timing {
        clock: 285_000,
        width: 800,
        height: 600,
        htotal: 1000,
        vtotal: 640,
        flags: 0,
    };
    let at_edge = qualify(&sink, &edge, &source()).unwrap();
    assert_eq!((at_edge.io_wake_lines, at_edge.fast_wake_lines), (12, 12));
    let quirk = Psr2Source {
        fw_sync_quirk: true,
        ..source()
    };
    assert_eq!(qualify(&sink, &edge, &quirk), Err(Psr2Refusal::WakeTime));
    // The 8 block-count lines need 8 vblank lines.
    let short = crate::intel_gpu_dsb::Timing {
        vtotal: 1800 + 7,
        ..t
    };
    assert_eq!(qualify(&sink, &short, &source()), Err(Psr2Refusal::Vblank));
    let exact = crate::intel_gpu_dsb::Timing {
        vtotal: 1800 + 8,
        ..t
    };
    assert!(qualify(&sink, &exact, &source()).is_ok());
    // intel_psr_compute_config_late: the set context latency moves the
    // vblank start.
    let scl = Psr2Source {
        set_context_latency: 1,
        ..source()
    };
    assert_eq!(qualify(&sink, &exact, &scl), Err(Psr2Refusal::Vblank));
    // _compute_psr2_sdp_prior_scanline_indication: a 16-pixel hblank is
    // 48 ns, no more than 100 ns above the 48 ns request.
    let tight = crate::intel_gpu_dsb::Timing {
        htotal: 2880 + 16,
        ..t
    };
    assert_eq!(
        qualify(&sink, &tight, &source()),
        Err(Psr2Refusal::SdpPriorScanline)
    );
    let mut edp14b = sink;
    edp14b.edp[0] = 0x05;
    let indicated = qualify(&edp14b, &tight, &source()).unwrap();
    assert!(indicated.req_sdp_prior_scanline);
    // The indication takes one vblank line (_wake_lines_fit_into_vblank).
    let tight_exact = crate::intel_gpu_dsb::Timing {
        vtotal: 1800 + 8,
        ..tight
    };
    assert_eq!(
        qualify(&edp14b, &tight_exact, &source()),
        Err(Psr2Refusal::Vblank)
    );
    // Linux's u32 arithmetic: one RBR lane requests 438 ns, so 48 - 438
    // wraps above 100 and no indication is needed.
    let rbr = Psr2Source {
        lane_count: 1,
        port_clock: 162_000,
        ..source()
    };
    assert!(!qualify(&sink, &tight, &rbr).unwrap().req_sdp_prior_scanline);
    // psr2_granularity_check: full-line X, the sink's Y on display 14.
    let narrow = crate::intel_gpu_dsb::Timing {
        width: 2878,
        htotal: 3038,
        ..t
    };
    assert_eq!(
        qualify(&sink, &narrow, &source()),
        Err(Psr2Refusal::Granularity)
    );
    let mut by3 = sink;
    by3.su_y_granularity = 3;
    assert_eq!(qualify(&by3, &t, &source()).unwrap().su_y_granularity, 3);
    let mut by7 = sink;
    by7.su_y_granularity = 7;
    assert_eq!(qualify(&by7, &t, &source()), Err(Psr2Refusal::Granularity));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr2_refusals_fall_back_with_typed_reasons
);

fn smoke_psr2_source_reads_the_live_pipe_and_link() -> TestResult {
    let sink = sink();
    let regs = Regs::default();
    regs.set(0x510a0, (14 << 22) | 2);
    regs.set(0x70030, 1 << 5); // PIPE_MISC_BPC_10
    regs.set(0x60400, 0x8a00_0006); // DDI_PORT_WIDTH x4
    regs.set(0x6007c, 0);
    let dell = Some((0x7d55, 0x1028, 0x0cc7));
    assert_eq!(
        psr2_source(
            &regs,
            &mut psr2_sink(),
            &sink,
            Some((0x7d55, 0x8086, 1)),
            false
        ),
        Ok(Psr2Source {
            step: 2,
            pipe_bpp: 30,
            lane_count: 4,
            port_clock: 540_000,
            set_context_latency: 0,
            stream_split: false,
            fw_sync_quirk: false,
            vrr_excludes_psr: false,
        })
    );
    // The caller's VRR fact is carried into the source verbatim:
    // `psr2_source` itself reads no VRR state.
    assert!(
        psr2_source(
            &regs,
            &mut psr2_sink(),
            &sink,
            Some((0x7d55, 0x8086, 1)),
            true
        )
        .unwrap()
        .vrr_excludes_psr
    );
    assert!(
        !psr2_source(
            &regs,
            &mut psr2_sink(),
            &sink,
            Some((0x7d55, 0x8086, 1)),
            false
        )
        .unwrap()
        .vrr_excludes_psr
    );
    // QUIRK_FW_SYNC_LEN needs the Dell Precision 5490 and the 38:ec:11 OUI.
    let mut aux = psr2_sink();
    for (a, v) in [(0x400, 0x38), (0x401, 0xec), (0x402, 0x11)] {
        aux.dpcd.insert(a, v);
    }
    let dell_sink = Sink::read(&mut aux).unwrap();
    assert!(
        psr2_source(&regs, &mut aux, &dell_sink, dell, false)
            .unwrap()
            .fw_sync_quirk
    );
    assert!(
        !psr2_source(&regs, &mut psr2_sink(), &sink, dell, false)
            .unwrap()
            .fw_sync_quirk
    );
    // eDP 1.4 rate select: DP_LINK_BW_SET 0, DP_LINK_RATE_SET 2, and the
    // third DP_SUPPORTED_LINK_RATES entry 27000 (200 kHz) is HBR2.
    let mut select = psr2_sink();
    for (a, v) in [(0x100, 0), (0x115, 2), (0x014, 0x78), (0x015, 0x69)] {
        select.dpcd.insert(a, v);
    }
    assert_eq!(sink_link_rate(&mut select), Some(540_000));
    // DSC, the joiner and the splitter.
    for (register, bit) in [(0x78000, 31), (0x78000, 30), (0x78000, 29), (0x78004, 31)] {
        regs.set(register, 1 << bit);
        assert!(
            psr2_source(&regs, &mut psr2_sink(), &sink, dell, false)
                .unwrap()
                .stream_split
        );
        regs.set(register, 0);
    }
    // Unknown: display 14.01, a BPC encoding with no pipe_bpp, no PCI
    // identity, an unset link, an unreadable register.
    let unknown = |regs: &Regs, aux: &mut Sinkd, pci| psr2_source(regs, aux, &sink, pci, false);
    regs.set(0x510a0, (14 << 22) | (1 << 14));
    assert_eq!(
        unknown(&regs, &mut psr2_sink(), dell),
        Err(Psr2Refusal::Unknown)
    );
    regs.set(0x510a0, 14 << 22);
    regs.set(0x70030, 3 << 5);
    assert_eq!(
        unknown(&regs, &mut psr2_sink(), dell),
        Err(Psr2Refusal::Unknown)
    );
    regs.set(0x70030, 0);
    assert_eq!(
        unknown(&regs, &mut psr2_sink(), None),
        Err(Psr2Refusal::Unknown)
    );
    let mut unset = psr2_sink();
    unset.dpcd.insert(0x100, 0);
    assert_eq!(unknown(&regs, &mut unset, dell), Err(Psr2Refusal::Unknown));
    regs.set(0x6007c, u32::MAX);
    assert_eq!(
        unknown(&regs, &mut psr2_sink(), dell),
        Err(Psr2Refusal::Unknown)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr2_source_reads_the_live_pipe_and_link
);

/// hsw_activate_psr2 for [`source`] on the 2500 µs VBT: EDP_PSR2_ENABLE,
/// IDLE_FRAMES(6), FRAME_BEFORE_SU(3), TP2_TIME_2500us, BLOCK_COUNT_NUM_2,
/// TGL_EDP_PSR2_IO_BUFFER_WAKE(7) and TGL_EDP_PSR2_FAST_WAKE(7).
const PSR2_ARMED: u32 = (1 << 31) | 6 | (3 << 4) | (2 << 8) | ((7 - 5) << 13) | ((7 - 5) << 10);

fn smoke_psr2_ctl_and_sink_bytes_follow_hsw_activate_psr2() -> TestResult {
    let sink = sink();
    let config = compute_psr1(&sink, &timing(), &vbt(), Some(false)).unwrap();
    let su = compute_psr2(&sink, &timing(), &panel(2500), &source()).unwrap();
    assert_eq!(psr2_ctl(&config, &su), PSR2_ARMED);
    // Twelve-line wakes: block count 12 / 4 > 2, wake fields 7.
    let long = Psr2 {
        io_wake_lines: 12,
        fast_wake_lines: 12,
        req_sdp_prior_scanline: true,
        ..su
    };
    assert_eq!(
        psr2_ctl(&config, &long),
        (1 << 31) | 6 | (3 << 4) | (2 << 8) | (1 << 28) | (7 << 13) | (7 << 10) | (1 << 25)
    );
    // intel_psr2_get_tp_time: <= 50, <= 100, <= 500, else 2500 µs.
    for (us, code) in [
        (0, 3),
        (50, 3),
        (51, 1),
        (100, 1),
        (101, 0),
        (500, 0),
        (501, 2),
    ] {
        assert_eq!(psr2_tp_time(us), code << 8, "{us} µs");
    }
    assert_eq!(psr2_block_count_lines(8, 8), 8);
    assert_eq!(psr2_block_count_lines(9, 8), 12);
    // _psr_enable_sink: DP_PSR_ENABLE_PSR2 | DP_PSR_IRQ_HPD_WITH_CRC_ERRORS,
    // plus DP_PSR_SU_REGION_SCANLINE_CAPTURE with the SDP indication.
    assert_eq!(sink_cfg_psr2(&su), 0x60);
    assert_eq!(sink_cfg_psr2(&long), 0x70);
    // intel_alpm_enable_sink: DP_ALPM_ENABLE | DP_ALPM_LOCK_ERROR_IRQ_HPD_ENABLE.
    assert_eq!(SINK_ALPM_PSR2, 0x03);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr2_ctl_and_sink_bytes_follow_hsw_activate_psr2
);

/// The whole 2880x1800 plane.
fn full_plane() -> Rect {
    Rect::new(0, 0, 2880, 1800)
}

fn enable_regs() -> Regs {
    let regs = Regs::default();
    regs.set(0x60814, !0x10);
    regs.set(0x46430, 1);
    regs.set(0x604e0, 1);
    regs.set(0x604e8, 2);
    regs.set(0x70084, 0x0004_0000);
    regs
}

fn enable_su(regs: &Regs, aux: &mut Sinkd, step: u8) -> Result<Psr, Refusal> {
    let sink = Sink::read(aux).unwrap();
    let config = compute_psr1(&sink, &timing(), &vbt(), Some(false)).unwrap();
    let su = compute_psr2(
        &sink,
        &timing(),
        &panel(2500),
        &Psr2Source { step, ..source() },
    )
    .unwrap();
    Psr::enable_su(
        regs,
        aux,
        config,
        su,
        &SuCommit {
            damage: &Damage::Full,
            old_src: full_plane(),
            src: full_plane(),
            pipe_supported: true,
            cursor: None,
        },
    )
}

fn smoke_psr2_enable_programs_alpm_sink_then_sel_fetch_then_source() -> TestResult {
    for (step, workarounds) in [(8, false), (2, true)] {
        let regs = enable_regs();
        let mut aux = psr2_sink();
        let mut psr = enable_su(&regs, &mut aux, step).unwrap();
        assert!(psr.selective() && !psr.active());
        // intel_alpm_enable_sink, _psr_enable_sink, then DP_SET_POWER D0.
        assert_eq!(
            aux.writes,
            [(0x116, 0x03), (0x170, 0x60), (0x170, 0x61), (0x600, 0x01)]
        );
        // The qualifying commit damaged the whole plane: SU 0..1800.
        let mut expected: Vec<(u64, u32)> = alloc::vec![
            (0x70894, 0),
            (0x7089c, 0),
            (0x70898, (1799 << 16) | 2879),
            (0x60910, (1 << 31) | 1799),
            (0x70890, 1 << 31),
            (0x60860, (1 << 28) | (1 << 27) | (1 << 26) | (1 << 25)),
            (0x60814, !(1u32 << 2)),
            (0x46430, 1),
        ];
        if workarounds {
            // Wa_16014451276 and Wa_16012604467 on display 14.00 A0..A3.
            expected.push((0x604e0, 1 | (1 << 18)));
            expected.push((0x604e8, 2 | (1 << 7)));
        }
        assert_eq!(regs.log(), expected);
        assert_eq!(psr.areas(), (Some((0, 1800)), None));
        // hsw_activate_psr2: EDP_PSR_CTL written 0, then EDP_PSR2_CTL.
        regs.set(0x60800, 1 << 29);
        let start = regs.log().len();
        assert_eq!(psr.resume(&regs), Ok(true));
        assert_eq!(regs.log()[start..], [(0x60800, 0), (0x60900, PSR2_ARMED)]);
    }
    // Every refusal precedes the first write: an unreadable chicken on an
    // A-step part, then a sink that refuses ALPM (both sink bytes undone).
    let regs = enable_regs();
    regs.set(0x604e8, u32::MAX);
    let mut aux = psr2_sink();
    assert_eq!(enable_su(&regs, &mut aux, 2), Err(Refusal::Unavailable));
    assert!(regs.log().is_empty() && aux.writes.is_empty());
    let regs = enable_regs();
    let mut aux = psr2_sink();
    aux.nack.push(0x116);
    assert_eq!(
        enable_su(&regs, &mut aux, 8),
        Err(Refusal::Aux(AuxError::Nacked))
    );
    assert!(regs.log().is_empty());
    assert_eq!(aux.writes, [(0x170, 0)]);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr2_enable_programs_alpm_sink_then_sel_fetch_then_source
);

fn smoke_psr2_exit_resume_and_disable_use_the_psr2_registers() -> TestResult {
    let regs = enable_regs();
    let mut aux = psr2_sink();
    let mut psr = enable_su(&regs, &mut aux, 2).unwrap();
    psr.resume(&regs).unwrap();
    // intel_psr_exit: only EDP_PSR2_ENABLE is cleared; PSR1 is untouched.
    let start = regs.log().len();
    assert_eq!(psr.pause(&regs), Ok(()));
    assert_eq!(regs.log()[start..], [(0x60900, PSR2_ARMED & !(1 << 31))]);
    // Idle and re-arm follow EDP_PSR2_STATUS, not EDP_PSR_STATUS.
    regs.set(0x60840, 7 << 29);
    regs.set(0x60940, 1 << 28);
    assert_eq!(psr.idle(&regs), Ok(false));
    assert_eq!(psr.wait_idle(&regs, 0), Err(Refusal::ExitTimeout));
    assert_eq!(psr.resume(&regs), Ok(false));
    regs.set(0x60940, 0);
    assert_eq!(psr.resume(&regs), Ok(true));
    assert_eq!(regs.get(0x60900), PSR2_ARMED);
    // _psr2_ready_for_pipe_update_locked: any state below DEEP_SLEEP.
    for (state, ready) in [(0x8, false), (0xa, false), (0x1, true), (0x7, true)] {
        regs.set(0x60940, state << 28);
        assert_eq!(psr.ready_for_update(&regs), Ok(ready), "state {state:#x}");
    }
    regs.set(0x60940, 0);
    // intel_psr_disable_locked + intel_psr_handle_irq: exit, idle, undo
    // Wa_14015648006 and Wa_16012604467, clear the sink's PSR then ALPM.
    regs.set(0x46430, (1 << 23) | 1);
    let start = regs.log().len();
    let sink_start = aux.writes.len();
    assert_eq!(psr.disable(&regs, &mut aux, 0, true), Ok(()));
    assert_eq!(
        regs.log()[start..],
        [
            (0x60900, PSR2_ARMED & !(1 << 31)),
            (0x46430, 1),
            (0x604e8, 2),
        ]
    );
    assert_eq!(
        aux.writes[sink_start..],
        [(0x170, 0x00), (0x116, 0x00), (0x600, 0x01)]
    );
    assert!(!psr.active());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr2_exit_resume_and_disable_use_the_psr2_registers
);

/// A 64x32 PSR2 with SU Y granularity `g`.
fn small(g: u16) -> Psr2 {
    Psr2 {
        io_wake_lines: 7,
        fast_wake_lines: 7,
        req_sdp_prior_scanline: false,
        su_y_granularity: g,
        frames_before_su: 3,
        tp2_wakeup_us: 0,
        a0_to_b0: false,
        width: 64,
        height: 32,
    }
}

fn commit<'a>(damage: &'a Damage, cursor: Option<CursorPlane>) -> SuCommit<'a> {
    let src = Rect::new(0, 0, 64, 32);
    SuCommit {
        damage,
        old_src: src,
        src,
        pipe_supported: true,
        cursor,
    }
}

fn cursor_at(x: i32, y: i32) -> CursorPlane {
    CursorPlane {
        dst: Rect::new(x, y, x + 64, y + 64),
        ctl: 0x27,
    }
}

/// PSR2_MAN_TRK_CTL for SU rows `y1..y2`: SF_PARTIAL_FRAME_UPDATE,
/// SU_REGION_START_ADDR(y1), SU_REGION_END_ADDR(y2 - 1).
fn su_region(y1: u32, y2: u32) -> u32 {
    (1 << 31) | (y1 << 16) | (y2 - 1)
}
/// SF_PARTIAL_FRAME_UPDATE | SF_CONTINUOS_FULL_FRAME.
const CFF: u32 = (1 << 31) | (1 << 13);

fn smoke_psr2_su_area_follows_intel_psr2_sel_fetch_update() -> TestResult {
    let clips = |rects: &[[i32; 4]]| {
        Damage::Clips(
            rects
                .iter()
                .map(|r| Rect::new(r[0], r[1], r[2], r[3]))
                .collect(),
        )
    };
    let none = (None, None);
    // No FB_DAMAGE_CLIPS: the whole plane, as a partial frame (not CFF).
    let sf = sel_fetch_update(&small(4), &commit(&Damage::Full, None), none);
    assert_eq!(
        (sf.full_update, sf.su, sf.man_trk_ctl, sf.primary, sf.cursor),
        (false, (0, 32), su_region(0, 32), Some((0, 32)), None)
    );
    // One damaged row, widened to the 4-line SU granularity.
    let row = clips(&[[10, 13, 20, 14]]);
    let sf = sel_fetch_update(&small(4), &commit(&row, None), none);
    assert_eq!((sf.su, sf.man_trk_ctl), ((12, 16), su_region(12, 16)));
    assert_eq!(sf.primary, Some((12, 16)));
    // Display 14 selective fetch has 1-line granularity of its own.
    let sf = sel_fetch_update(&small(1), &commit(&row, None), none);
    assert_eq!(sf.man_trk_ctl, su_region(13, 14));
    // Several clips merge to their bounding rows; damage past the plane is
    // clamped to it.
    let sf = sel_fetch_update(
        &small(4),
        &commit(&clips(&[[0, 2, 1, 3], [0, 21, 1, 26]]), None),
        none,
    );
    assert_eq!(sf.su, (0, 28));
    let sf = sel_fetch_update(&small(4), &commit(&clips(&[[0, 30, 64, 40]]), None), none);
    assert_eq!(sf.su, (28, 32));
    // Nothing damaged on the plane (a clip outside it, or no clip): the
    // area calculation fails into a continuous full frame, and the
    // primary keeps its previous area.
    let previous = (Some((12, 16)), None);
    for damage in [clips(&[[0, 40, 8, 50]]), clips(&[])] {
        let sf = sel_fetch_update(&small(4), &commit(&damage, None), previous);
        assert_eq!(
            (sf.full_update, sf.man_trk_ctl, sf.primary),
            (true, CFF, Some((12, 16)))
        );
    }
    // A pipe or plane scaler (psr2_sel_fetch_pipe_state_supported).
    let scaled = SuCommit {
        pipe_supported: false,
        ..commit(&row, None)
    };
    let sf = sel_fetch_update(&small(4), &scaled, previous);
    assert_eq!((sf.full_update, sf.man_trk_ctl), (true, CFF));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr2_su_area_follows_intel_psr2_sel_fetch_update
);

fn smoke_psr2_cursor_joins_the_su_area_commit() -> TestResult {
    let row = Damage::Clips(alloc::vec![Rect::new(10, 13, 20, 14)]);
    // A visible cursor at (5, 14) covers rows 14..78: it fetches its rows
    // 0..2 of the 12..16 SU area. Without early transport (display < 20)
    // the SU area is not grown to the whole cursor.
    let sf = sel_fetch_update(
        &small(4),
        &commit(&row, Some(cursor_at(5, 14))),
        (None, None),
    );
    assert_eq!((sf.su, sf.man_trk_ctl), ((12, 16), su_region(12, 16)));
    assert_eq!(sf.cursor, Some((Some((0, 2)), 0x27)));
    // Below the SU area: a cursor that fetched before is disabled; one
    // that did not stays out of the commit.
    let below = Some(cursor_at(5, 20));
    let sf = sel_fetch_update(&small(4), &commit(&row, below), (None, Some((0, 2))));
    assert_eq!(sf.cursor, Some((None, 0x27)));
    let sf = sel_fetch_update(&small(4), &commit(&row, below), (None, None));
    assert_eq!(sf.cursor, None);
    // A negative position is unsupported once it intersects: full frame,
    // the primary already in the commit.
    let sf = sel_fetch_update(
        &small(4),
        &commit(&row, Some(cursor_at(-3, 14))),
        (None, None),
    );
    assert_eq!((sf.full_update, sf.man_trk_ctl), (true, CFF));
    assert_eq!((sf.primary, sf.cursor), (Some((12, 16)), None));
    let sf = sel_fetch_update(
        &small(4),
        &commit(&row, Some(cursor_at(-3, 20))),
        (None, None),
    );
    assert!(!sf.full_update);
    // CURCNTR / CURPOS: sign-magnitude, 64x64 ARGB.
    let regs = Regs::default();
    assert_eq!(CursorPlane::read(&regs), Ok(None));
    regs.set(0x70080, 0x27);
    regs.set(0x70088, (1 << 31) | (5 << 16) | (1 << 15) | 3);
    assert_eq!(
        CursorPlane::read(&regs),
        Ok(Some(CursorPlane {
            dst: Rect::new(-3, -5, 61, 59),
            ctl: 0x27,
        }))
    );
    regs.set(0x70088, (14 << 16) | 5);
    assert_eq!(CursorPlane::read(&regs), Ok(Some(cursor_at(5, 14))));
    // Another cursor mode has no size here: no exact fetch area, so the
    // commit is a full frame.
    regs.set(0x70080, 0x07);
    let odd = CursorPlane::read(&regs).unwrap();
    assert_eq!(odd.map(|c| c.dst.visible()), Some(false));
    let sf = sel_fetch_update(&small(4), &commit(&Damage::Full, odd), (None, None));
    assert_eq!(
        (sf.full_update, sf.man_trk_ctl, sf.cursor),
        (true, CFF, None)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr2_cursor_joins_the_su_area_commit
);

fn smoke_psr2_sel_fetch_registers_follow_the_plane_and_cursor_arms() -> TestResult {
    let regs = enable_regs();
    let mut aux = psr2_sink();
    let mut psr = enable_su(&regs, &mut aux, 8).unwrap();
    let start = regs.log().len();
    // Rows 40..48 of the 2880-wide plane with the cursor at (5, 44).
    let damage = Damage::Clips(alloc::vec![Rect::new(0, 41, 8, 47)]);
    let cursor = Some(cursor_at(5, 44));
    let su = SuCommit {
        old_src: full_plane(),
        src: full_plane(),
        ..commit(&damage, cursor)
    };
    let sf = psr.sel_fetch(&su).unwrap();
    assert_eq!(sf.su, (40, 48));
    psr.program_sel_fetch_noarm(&regs, &sf);
    psr.program_sel_fetch_arm(&regs, &sf);
    psr.program_sel_fetch_cursor(&regs, &sf);
    // icl_plane_update_sel_fetch_noarm (POS y | x, OFFSET y | x, SIZE
    // height - 1 | width - 1), PSR2_MAN_TRK_CTL, SEL_FETCH_PLANE_CTL, then
    // SEL_FETCH_CUR_CTL and the CURBASE write that arms the cursor.
    assert_eq!(
        regs.log()[start..],
        [
            (0x70894, 40 << 16),
            (0x7089c, 40 << 16),
            (0x70898, (7 << 16) | 2879),
            (0x60910, su_region(40, 48)),
            (0x70890, 1 << 31),
            (0x70880, 0x27),
            (0x70084, 0x0004_0000),
        ]
    );
    assert_eq!(psr.areas(), (Some((40, 48)), Some((0, 4))));
    // The cursor leaves the SU area: its fetch is disabled.
    let start = regs.log().len();
    let away = Some(cursor_at(5, 400));
    let su = SuCommit {
        old_src: full_plane(),
        src: full_plane(),
        ..commit(&damage, away)
    };
    let sf = psr.sel_fetch(&su).unwrap();
    psr.program_sel_fetch_cursor(&regs, &sf);
    assert_eq!(regs.log()[start..], [(0x70880, 0), (0x70084, 0x0004_0000)]);
    assert_eq!(psr.areas().1, None);
    // A full update rewrites the primary from its previous area and the
    // continuous full frame.
    let start = regs.log().len();
    let outside = Damage::Clips(alloc::vec![Rect::new(0, 4000, 8, 4001)]);
    let su = SuCommit {
        old_src: full_plane(),
        src: full_plane(),
        ..commit(&outside, None)
    };
    let sf = psr.sel_fetch(&su).unwrap();
    psr.program_sel_fetch_noarm(&regs, &sf);
    psr.program_sel_fetch_arm(&regs, &sf);
    assert_eq!(
        regs.log()[start..],
        [
            (0x70894, 40 << 16),
            (0x7089c, 40 << 16),
            (0x70898, (7 << 16) | 2879),
            (0x60910, CFF),
            (0x70890, 1 << 31),
        ]
    );
    // intel_psr_configure_full_frame_update's value, and the
    // frame-change event (a CURSURFLIVE write).
    assert_eq!(
        man_trk_ctl_full_frame_update(),
        (1 << 31) | (1 << 14) | (1 << 13)
    );
    let start = regs.log().len();
    frame_change_event(&regs);
    assert_eq!(regs.log()[start..], [(0x700ac, 0)]);
    // A PSR1 owner has no selective fetch.
    let mut psr1 = Psr::enable(
        &Regs::default(),
        &mut psr1_sink(),
        compute_psr1(
            &Sink::read(&mut psr1_sink()).unwrap(),
            &timing(),
            &vbt(),
            Some(false),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(psr1.sel_fetch(&su).is_none() && !psr1.selective());
    let quiet = Regs::default();
    psr1.program_sel_fetch_arm(&quiet, &sf);
    psr1.program_sel_fetch_noarm(&quiet, &sf);
    assert!(quiet.log().is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_psr",
    smoke_psr2_sel_fetch_registers_follow_the_plane_and_cursor_arms
);
