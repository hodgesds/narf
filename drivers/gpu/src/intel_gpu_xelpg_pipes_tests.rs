//! Pipe B-D owner tests over the live-repartition register model; the
//! port owner's steps between timings and enable are outside this owner.
use super::*;
use crate::intel_gpu_dc_states::NoPipeDmc;
use crate::intel_gpu_xelpg_dbuf::MBUS_CTL_MASK;
use crate::intel_gpu_xelpg_live::tests::{latency, programmed, Live};
use crate::intel_gpu_xelpg_pipes::published_layout;
use alloc::vec::Vec;
use core::cell::RefCell;
use narf_kernel_test::{kernel_test_in, TestResult};

extern crate alloc;

fn panel_state() -> State {
    res::compute(
        &crate::intel_gpu_display_resources::request(&Mode::VESA_1024X768_60, Tiling::Linear, 0),
        &latency(),
    )
    .unwrap()
}

fn lit_panel() -> Live {
    let hw = programmed(&panel_state(), &[0]);
    hw.set(0x45780, 6 | (8 << 16));
    hw.set(0x45784, 10 | (12 << 16));
    hw.set(0x45788, 14 | (16 << 16));
    // The owned Pipe-A modeset also owns GMD/IPC; Profile capture checks them.
    hw.set(0x510a0, 14 << 22);
    hw.set(0x45004, 1 << 3);
    hw
}

fn external(pipe: Pipe) -> ExternalPipe {
    ExternalPipe {
        pipe,
        mode: Mode {
            pixel_clock_khz: 74_250,
            h_active: 1280,
            h_total: 1650,
            h_sync_start: 1390,
            h_sync_end: 1430,
            v_active: 720,
            v_total: 750,
            v_sync_start: 725,
            v_sync_end: 730,
            ..Mode::VESA_1024X768_60
        },
        surface: 0x0200_0000,
        stride_bytes: 5120,
        port_clock_khz: 270_000,
        combo_phy: Some(1),
    }
}

/// Records each pipe-DMC report with the number of register writes the
/// fixture had seen when it arrived.
struct DmcAt<'a> {
    hw: &'a Live,
    events: RefCell<Vec<(u32, bool, usize)>>,
}

impl PipeDmc for DmcAt<'_> {
    fn enable_pipe(&self, pipe: u32) {
        let at = self.hw.writes.borrow().len();
        self.events.borrow_mut().push((pipe, true, at));
    }
    fn disable_pipe(&self, pipe: u32) {
        let at = self.hw.writes.borrow().len();
        self.events.borrow_mut().push((pipe, false, at));
    }
}

fn smoke_xelpg_pipes_external_enable_and_release_with_panel_lit() -> TestResult {
    let hw = lit_panel();
    // Adoption proves the owned Pipe-A image and observes it lit.
    let mut pipes = Pipes::adopt_panel(&hw, &Mode::VESA_1024X768_60).unwrap();
    assert_eq!(pipes.state(), Some(&panel_state()));
    assert!(hw.writes.borrow().is_empty());
    let ext = external(Pipe::B);
    pipes.reserve(&hw, &ext, &NoPipeDmc).unwrap();
    let reserved = hw.writes.borrow().len();
    assert_eq!(pipes.state().unwrap().dbuf.active_pipes, 0x3);
    assert_eq!(hw.get(0x4438c) & MBUS_CTL_MASK, 0, "unjoined for two pipes");
    // (The port owner programs its clock, DDI function and link here.)
    pipes.program_timings(&hw, Pipe::B).unwrap();
    assert_eq!(hw.get(0x61000), (1649 << 16) | 1279);
    assert_eq!(hw.get(0x6100c), (749 << 16) | 719);
    assert_eq!(hw.get(0x6101c), (1279 << 16) | 719);
    // The owned RGB bypass and the no-DPT chicken on Pipe B's planes.
    assert_eq!(hw.get(0x711cc), 1 << 13);
    assert!(hw.wrote(0x4ac80) && hw.get(0x4ac80) == 0, "GAMMA_MODE(B)");
    assert!(
        hw.wrote(0x49128) && hw.get(0x49128) == 0,
        "PIPE_CSC_MODE(B)"
    );
    for plane in 0..PLANES as u64 {
        assert_eq!(hw.get(0x7126c + plane * 0x100), PLANE_CHICKEN_DISABLE_DPT);
    }
    pipes.enable(&hw, Pipe::B).unwrap();
    pipes.arm_primary(&hw, Pipe::B).unwrap();
    assert!(reserved <= hw.first(0x6101c));
    assert!(
        hw.last(0x61014) < hw.first(0x71008),
        "timings before TRANSCONF"
    );
    assert!(
        hw.first(0x71008) < hw.first(0x71180),
        "pipe on before plane"
    );
    assert!(hw.first(0x71180) < hw.first(0x7119c), "SURF arms last");
    assert_eq!(hw.get(0x71008) & 0xc000_0000, 0xc000_0000);
    assert_eq!(hw.get(0x71180) & (1 << 31), 1 << 31);
    assert_eq!(hw.get(0x71188), 5120 / 64);
    assert_eq!(hw.get(0x71190), (719 << 16) | 1279);
    assert_eq!(hw.get(0x711ac), 0x0200_0000);
    let ab = *pipes.state().unwrap();
    for (r, v) in ab.pipe_registers(1, false).unwrap() {
        assert_eq!(hw.get(r), v, "external resources {r:#x}");
    }
    // Disable, then release once the port owner stopped the port.
    pipes.disable_primary(&hw, Pipe::B).unwrap();
    pipes.disable(&hw, Pipe::B).unwrap();
    assert_eq!(hw.get(0x71008) & 0xc000_0000, 0);
    assert_eq!(hw.get(0x71180) & (1 << 31), 0);
    pipes.release(&hw, Pipe::B, &NoPipeDmc).unwrap();
    assert_eq!(pipes.state().unwrap().dbuf.active_pipes, 0x1);
    assert_eq!(hw.get(0x4438c) & MBUS_CTL_MASK, 0xc000_0000, "rejoined");
    assert_eq!(hw.get(0x7127c), 0);
    for (r, v) in panel_state().pipe_registers(0, false).unwrap() {
        assert_eq!(hw.get(r), v, "panel restored {r:#x}");
    }
    // The Pipe-A panel was never stopped or replaned; its SURF is only
    // re-armed with the identical address.
    assert!(!hw.wrote(0x70008) && !hw.wrote(0x70180));
    assert_eq!(hw.get(0x7019c), 0x0100_0000);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_pipes",
    smoke_xelpg_pipes_external_enable_and_release_with_panel_lit
);

fn smoke_xelpg_pipes_refusals_are_typed_and_write_free() -> TestResult {
    let hw = lit_panel();
    let mut pipes = Pipes::adopt(Some(panel_state()), 0x1);
    assert_eq!(
        pipes.reserve(&hw, &external(Pipe::A), &NoPipeDmc),
        Err(PipeEnableError::Unsupported)
    );
    assert_eq!(
        pipes.program_timings(&hw, Pipe::B),
        Err(PipeEnableError::NotReserved)
    );
    assert_eq!(
        pipes.enable(&hw, Pipe::C),
        Err(PipeEnableError::NotReserved)
    );
    let mut narrow = external(Pipe::B);
    narrow.stride_bytes = 4096;
    assert_eq!(
        pipes.reserve(&hw, &narrow, &NoPipeDmc),
        Err(PipeEnableError::Unsupported)
    );
    let mut fast = external(Pipe::B);
    fast.mode.pixel_clock_khz = 1_400_000;
    assert_eq!(
        pipes.admit(&hw, &fast),
        Err(PipeEnableError::Resource(ResourceError::Unsupported))
    );
    assert_eq!(
        pipes.reserve(&hw, &fast, &NoPipeDmc),
        Err(PipeEnableError::Resource(ResourceError::Unsupported))
    );
    hw.set(0x72008, 0xc000_0000);
    assert_eq!(
        pipes.reserve(&hw, &external(Pipe::C), &NoPipeDmc),
        Err(PipeEnableError::Busy)
    );
    // A foreign lit pipe blocks any other reservation in admission: the
    // live transaction would refuse it, before any write either way.
    assert_eq!(
        pipes.admit(&hw, &external(Pipe::B)),
        Err(PipeEnableError::Resource(ResourceError::Busy))
    );
    hw.set(0x72008, 0);
    assert!(hw.writes.borrow().is_empty(), "refusals precede writes");
    // A second reservation of the same pipe, arming a pipe that is not
    // enabled, and releasing a lit pipe.
    pipes.reserve(&hw, &external(Pipe::B), &NoPipeDmc).unwrap();
    assert_eq!(
        pipes.reserve(&hw, &external(Pipe::B), &NoPipeDmc),
        Err(PipeEnableError::NotReserved)
    );
    pipes.program_timings(&hw, Pipe::B).unwrap();
    assert_eq!(
        pipes.arm_primary(&hw, Pipe::B),
        Err(PipeEnableError::NotLit)
    );
    pipes.enable(&hw, Pipe::B).unwrap();
    assert_eq!(pipes.enable(&hw, Pipe::B), Err(PipeEnableError::Busy));
    assert_eq!(
        pipes.release(&hw, Pipe::B, &NoPipeDmc),
        Err(PipeEnableError::Busy)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_pipes",
    smoke_xelpg_pipes_refusals_are_typed_and_write_free
);

fn smoke_xelpg_pipes_dmc_brackets_the_external_crtc() -> TestResult {
    // Linux hsw_crtc_enable starts with intel_dmc_enable_pipe (after the
    // pre-plane update, before the port PLL) and hsw_crtc_disable ends
    // with intel_dmc_disable_pipe (after the port, before the post-plane
    // repartition): the owner reports exactly there, once each.
    let hw = lit_panel();
    let dmc = DmcAt {
        hw: &hw,
        events: RefCell::new(Vec::new()),
    };
    let Ok(mut pipes) = Pipes::adopt_panel(&hw, &Mode::VESA_1024X768_60) else {
        return TestResult::Fail("the owned panel must be adopted");
    };
    // A refused reservation reports nothing.
    let mut narrow = external(Pipe::B);
    narrow.stride_bytes = 4096;
    if pipes.reserve(&hw, &narrow, &dmc).is_ok() || !dmc.events.borrow().is_empty() {
        return TestResult::Fail("a refused reservation must not report the pipe DMC");
    }
    if pipes.reserve(&hw, &external(Pipe::B), &dmc).is_err() {
        return TestResult::Fail("the reservation must commit");
    }
    let reserved = hw.writes.borrow().len();
    if *dmc.events.borrow() != [(1, true, reserved)] || reserved == 0 {
        return TestResult::Fail("the pipe DMC must be enabled right after the reservation");
    }
    let steps = [
        pipes.program_timings(&hw, Pipe::B),
        pipes.enable(&hw, Pipe::B),
        pipes.arm_primary(&hw, Pipe::B),
        pipes.disable_primary(&hw, Pipe::B),
        pipes.disable(&hw, Pipe::B),
    ];
    if steps.iter().any(Result::is_err) || dmc.events.borrow().len() != 1 {
        return TestResult::Fail("enable/disable steps must not touch the pipe DMC");
    }
    let off = hw.writes.borrow().len();
    if pipes.release(&hw, Pipe::B, &dmc).is_err() {
        return TestResult::Fail("the release must repartition");
    }
    if *dmc.events.borrow() != [(1, true, reserved), (1, false, off)]
        || hw.writes.borrow().len() <= off
    {
        return TestResult::Fail("the pipe DMC must be disabled before the repartition");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_pipes",
    smoke_xelpg_pipes_dmc_brackets_the_external_crtc
);

fn smoke_xelpg_pipes_arm_runs_inside_irq_masked_evasion() -> TestResult {
    // intel_pipe_update_start .. _end: local interrupts masked from the
    // scanline sample that leaves the evasion window through the arm
    // writes, and restored afterwards.
    let irqs = narf_arch::interrupts_enabled();
    let hw = lit_panel();
    let Ok(mut pipes) = Pipes::adopt_panel(&hw, &Mode::VESA_1024X768_60) else {
        return TestResult::Fail("the owned panel must be adopted");
    };
    let ok = pipes.reserve(&hw, &external(Pipe::B), &NoPipeDmc).is_ok()
        && pipes.program_timings(&hw, Pipe::B).is_ok()
        && pipes.enable(&hw, Pipe::B).is_ok();
    if !ok {
        return TestResult::Fail("Pipe B must be reserved and enabled");
    }
    hw.irq_log.borrow_mut().clear();
    if pipes.arm_primary(&hw, Pipe::B).is_err() {
        return TestResult::Fail("the primary must arm");
    }
    let log = hw.irq_log.borrow();
    let regs: Vec<u64> = log.iter().map(|(r, _)| *r).collect();
    // One PIPEDSL(B) sample, then PLANE_CTL and PLANE_SURF in one window.
    if regs != [0x71000, 0x71180, 0x7119c] {
        return TestResult::Fail("the arm must be one evasion sample then CTL and SURF");
    }
    if irqs && log.iter().any(|(_, enabled)| *enabled) {
        return TestResult::Fail("the evasion sample and arm writes must run IRQ-masked");
    }
    if narf_arch::interrupts_enabled() != irqs {
        return TestResult::Fail("the local interrupt state must be restored");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_pipes",
    smoke_xelpg_pipes_arm_runs_inside_irq_masked_evasion
);

fn smoke_xelpg_pipes_release_of_last_pipe_forgets_state() -> TestResult {
    // No panel: the reservation is the all-off commit; releasing the only
    // pipe leaves every pipe off and forgets the state, so the next
    // reservation is the all-off commit again (no empty computation).
    let hw = Live::new();
    hw.set(0x45780, 6 | (8 << 16));
    hw.set(0x45784, 10 | (12 << 16));
    hw.set(0x45788, 14 | (16 << 16));
    let mut pipes = Pipes::adopt(None, 0);
    let ext = external(Pipe::B);
    let ok = pipes.reserve(&hw, &ext, &NoPipeDmc).is_ok()
        && pipes.program_timings(&hw, Pipe::B).is_ok()
        && pipes.enable(&hw, Pipe::B).is_ok()
        && pipes.arm_primary(&hw, Pipe::B).is_ok()
        && pipes.disable_primary(&hw, Pipe::B).is_ok()
        && pipes.disable(&hw, Pipe::B).is_ok();
    if !ok || pipes.state().map(|s| s.dbuf.active_pipes) != Some(0x2) {
        return TestResult::Fail("a lone Pipe B must run on the all-off commit");
    }
    let before = hw.writes.borrow().len();
    if pipes.release(&hw, Pipe::B, &NoPipeDmc).is_err()
        || pipes.state().is_some()
        || hw.writes.borrow().len() != before
    {
        return TestResult::Fail("releasing the last pipe must forget the state, no writes");
    }
    if pipes.reserve(&hw, &ext, &NoPipeDmc).is_err()
        || pipes.state().map(|s| s.dbuf.active_pipes) != Some(0x2)
    {
        return TestResult::Fail("the next reservation must commit from all-off again");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_pipes",
    smoke_xelpg_pipes_release_of_last_pipe_forgets_state
);

fn smoke_xelpg_pipes_publish_layout_and_follow_a_tile4_panel_flip() -> TestResult {
    // The owner publishes what it programmed while Pipe B is part of it.
    // The panel's KMS owner then flips Pipe A to Tile4 (its primary
    // watermarks only, as Primary::stage does in this layout); the release
    // retiles the programmed state first, so the live commit does not see
    // a divergence, and Pipe A keeps its Tile4 primary image.
    crate::intel_gpu_xelpg_pipes::reset_published_layout();
    let hw = lit_panel();
    let Ok(mut pipes) = Pipes::adopt_panel(&hw, &Mode::VESA_1024X768_60) else {
        return TestResult::Fail("the owned panel must be adopted");
    };
    if published_layout().is_some() {
        return TestResult::Fail("the panel alone publishes no multi-pipe layout");
    }
    let ok = pipes.reserve(&hw, &external(Pipe::B), &NoPipeDmc).is_ok()
        && pipes.program_timings(&hw, Pipe::B).is_ok()
        && pipes.enable(&hw, Pipe::B).is_ok()
        && pipes.arm_primary(&hw, Pipe::B).is_ok();
    if !ok {
        return TestResult::Fail("Pipe B must light beside the panel");
    }
    let Some(layout) = published_layout() else {
        return TestResult::Fail("the reservation must publish the layout");
    };
    if Some(&layout.state) != pipes.state()
        || layout.surfaces != [None, Some(0x0200_0000), None, None]
    {
        return TestResult::Fail("the published layout must be the programmed one");
    }
    let Ok(tile4) = layout.state.retile(0, Tiling::Tile4, &latency()) else {
        return TestResult::Fail("Tile4 must retile within Pipe A's allocation");
    };
    if tile4.dbuf.pipes[0].planes != layout.state.dbuf.pipes[0].planes
        || tile4.dbuf.pipes[0].cursor_wm != layout.state.dbuf.pipes[0].cursor_wm
        || tile4.pmdemand != layout.state.pmdemand
        || tile4.dbuf.pipes[1] != layout.state.dbuf.pipes[1]
    {
        return TestResult::Fail("a retile must change only Pipe A's primary watermarks");
    }
    for (r, v) in res::plane_wm_image(0, 0, &tile4.dbuf.pipes[0].wm[0]).unwrap() {
        hw.set(r, v);
    }
    hw.set(0x70180, hw.get(0x70180) | (5 << 10));
    let ok = pipes.disable_primary(&hw, Pipe::B).is_ok() && pipes.disable(&hw, Pipe::B).is_ok();
    if !ok || pipes.release(&hw, Pipe::B, &NoPipeDmc).is_err() {
        return TestResult::Fail("the release must follow the panel's Tile4 flip");
    }
    let Ok(single) = panel_state().retile(0, Tiling::Tile4, &latency()) else {
        return TestResult::Fail("the single-pipe Tile4 image must compute");
    };
    for (r, v) in single.pipe_registers(0, false).unwrap() {
        if hw.get(r) != v {
            return TestResult::Fail("Pipe A must hold its single-pipe Tile4 image");
        }
    }
    if published_layout().is_some() || pipes.state() != Some(&single) {
        return TestResult::Fail("the release must withdraw the multi-pipe layout");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_pipes",
    smoke_xelpg_pipes_publish_layout_and_follow_a_tile4_panel_flip
);

fn smoke_xelpg_pipes_crtc_enable_programs_linetime_chicken_and_frame_start() -> TestResult {
    // hsw_crtc_enable for display 14 on each of Pipes B–D, pipe off:
    // PIPE_MISC after the source size; TRANS_SET_CONTEXT_LATENCY and
    // TRANS_VSYNCSHIFT before the timings; TRANS_VRR_CTL, TRANS_MULT, the
    // CHICKEN_TRANS frame-start delay and TRANSCONF (configured, disabled)
    // after them; then the RGB bypass, WM_LINETIME and PIPE_CHICKEN; the
    // transcoder enable takes the CHICKEN_TRANS workaround bits.
    // skl_linetime_wm: DIV_ROUND_UP(1650 * 1000 * 8, 74250) = 178.
    for pipe in [Pipe::B, Pipe::C, Pipe::D] {
        let p = pipe as u64;
        let (trans, pbase) = (0x60000 + p * 0x1000, 0x70000 + p * 0x1000);
        let hw = lit_panel();
        // Firmware leftovers each register write must replace; unrelated
        // chicken bits survive the read-modify-writes.
        for (r, v) in [
            (trans + 0x7c, 3),
            (trans + 0x28, 7),
            (trans + 0x2c, 1),
            (trans + 0x420, 1 << 31),
            (trans + 0x4e0, (3 << 27) | (1 << 4)),
            (pbase + 0x08, 1 << 21),
            (pbase + 0x30, 0x10),
            (pbase + 0x38, 1 << 12),
            (0x45270 + p * 4, 0x1ff),
        ] {
            hw.set(r, v);
        }
        let Ok(mut pipes) = Pipes::adopt_panel(&hw, &Mode::VESA_1024X768_60) else {
            return TestResult::Fail("the owned panel must be adopted");
        };
        if pipes.reserve(&hw, &external(pipe), &NoPipeDmc).is_err()
            || pipes.program_timings(&hw, pipe).is_err()
        {
            return TestResult::Fail("the external pipe must be reserved and programmed");
        }
        let values = [
            (pbase + 0x30, 1 << 8),
            (trans + 0x7c, 0),
            (trans + 0x28, 0),
            (trans + 0x420, 0),
            (trans + 0x2c, 0),
            (trans + 0x4e0, 1 << 4),
            (pbase + 0x08, 0),
            (0x45270 + p * 4, 178),
            (pbase + 0x38, (1 << 30) | (1 << 15) | (1 << 12) | (1 << 7)),
        ];
        if values.iter().any(|&(r, v)| hw.get(r) != v) {
            return TestResult::Fail("the crtc registers must take Linux's display-14 values");
        }
        let order = [
            trans + 0x1c,
            pbase + 0x30,
            trans + 0x7c,
            trans + 0x28,
            trans,
            trans + 0x14,
            trans + 0x420,
            trans + 0x2c,
            trans + 0x4e0,
            pbase + 0x08,
            pbase + 0x1cc,
            0x45270 + p * 4,
            pbase + 0x38,
            pbase + 0x26c,
        ];
        if order.windows(2).any(|w| hw.last(w[0]) >= hw.first(w[1])) {
            return TestResult::Fail("the crtc registers must follow hsw_crtc_enable's order");
        }
        // intel_enable_transcoder on display 14: DP_FEC_BS_JITTER_WA set
        // and DP_DSC_INSERT_SF_AT_EOL_WA cleared before TRANSCONF enables.
        let configured = hw.writes.borrow().len();
        if pipes.enable(&hw, pipe).is_err() || hw.get(trans + 0x4e0) != 1 << 15 {
            return TestResult::Fail("the transcoder enable must take its chicken bits");
        }
        let chicken = hw.last(trans + 0x4e0);
        let enable = hw.last(pbase + 0x08);
        if chicken < configured || chicken >= enable || hw.get(pbase + 0x08) & (1 << 31) == 0 {
            return TestResult::Fail("the chicken bits must precede TRANSCONF enable");
        }
        // Panel Pipe A's line time and chicken are never touched.
        if hw.wrote(0x45270) || hw.wrote(0x70038) || hw.wrote(0x604e0) {
            return TestResult::Fail("Pipe A's crtc registers belong to the panel");
        }
    }
    // The 0x1ff cap.
    let long = crate::intel_gpu_xelpg_wm::Timing {
        pixel_rate_khz: 25_000,
        htotal: 4000,
        vtotal: 600,
        vblank_start: 480,
    };
    if crate::intel_gpu_xelpg_wm::linetime(long) != Ok(0x1ff) {
        return TestResult::Fail("WM_LINETIME is capped at 0x1ff");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_pipes",
    smoke_xelpg_pipes_crtc_enable_programs_linetime_chicken_and_frame_start
);
