//! Pipe B-D owner tests over the live-repartition register model; the
//! port owner's steps between timings and enable are outside this owner.
use super::*;
use crate::intel_gpu_xelpg_dbuf::MBUS_CTL_MASK;
use crate::intel_gpu_xelpg_live::tests::{latency, programmed, Live};
use narf_kernel_test::{kernel_test_in, TestResult};

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

fn smoke_xelpg_pipes_external_enable_and_release_with_panel_lit() -> TestResult {
    let hw = lit_panel();
    // Adoption proves the owned Pipe-A image and observes it lit.
    let mut pipes = Pipes::adopt_panel(&hw, &Mode::VESA_1024X768_60).unwrap();
    assert_eq!(pipes.state(), Some(&panel_state()));
    assert!(hw.writes.borrow().is_empty());
    let ext = external(Pipe::B);
    pipes.reserve(&hw, &ext).unwrap();
    let reserved = hw.writes.borrow().len();
    assert_eq!(pipes.state().unwrap().dbuf.active_pipes, 0x3);
    assert_eq!(hw.get(0x4438c) & MBUS_CTL_MASK, 0, "unjoined for two pipes");
    pipes.program_timings(&hw, Pipe::B).unwrap();
    assert_eq!(hw.get(0x61000), (1649 << 16) | 1279);
    assert_eq!(hw.get(0x6100c), (749 << 16) | 719);
    assert_eq!(hw.get(0x6101c), (1279 << 16) | 719);
    // (The port owner programs its clock, DDI function and link here.)
    pipes.enable(&hw, Pipe::B).unwrap();
    assert!(reserved <= hw.first(0x61000));
    assert!(
        hw.last(0x6101c) < hw.first(0x71008),
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
    pipes.disable(&hw, Pipe::B).unwrap();
    assert_eq!(hw.get(0x71008) & 0xc000_0000, 0);
    assert_eq!(hw.get(0x71180) & (1 << 31), 0);
    pipes.release(&hw, Pipe::B).unwrap();
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
        pipes.reserve(&hw, &external(Pipe::A)),
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
        pipes.reserve(&hw, &narrow),
        Err(PipeEnableError::Unsupported)
    );
    let mut fast = external(Pipe::B);
    fast.mode.pixel_clock_khz = 1_400_000;
    assert_eq!(
        pipes.reserve(&hw, &fast),
        Err(PipeEnableError::Resource(ResourceError::Unsupported))
    );
    hw.set(0x72008, 0xc000_0000);
    assert_eq!(
        pipes.reserve(&hw, &external(Pipe::C)),
        Err(PipeEnableError::Busy)
    );
    hw.set(0x72008, 0);
    assert!(hw.writes.borrow().is_empty(), "refusals precede writes");
    // A second reservation of the same pipe and releasing a lit pipe.
    pipes.reserve(&hw, &external(Pipe::B)).unwrap();
    assert_eq!(
        pipes.reserve(&hw, &external(Pipe::B)),
        Err(PipeEnableError::NotReserved)
    );
    pipes.program_timings(&hw, Pipe::B).unwrap();
    pipes.enable(&hw, Pipe::B).unwrap();
    assert_eq!(pipes.enable(&hw, Pipe::B), Err(PipeEnableError::Busy));
    assert_eq!(pipes.release(&hw, Pipe::B), Err(PipeEnableError::Busy));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_pipes",
    smoke_xelpg_pipes_refusals_are_typed_and_write_free
);
