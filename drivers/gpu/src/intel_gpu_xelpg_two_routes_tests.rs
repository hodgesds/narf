//! Native fixtures for two concurrent external routes
//! (`narf.intel.ext_routes=2`): DP on TC1 and HDMI on DDI B beside the lit
//! panel, lit, retrained, torn down and relit independently, with the
//! joint display-14 resource plan Linux's atomic check computes for every
//! active pipe (`skl_compute_ddb` with `adlp_allowed_dbufs`,
//! `intel_pmdemand_atomic_check`).
extern crate alloc;

use super::tests::{
    edid_1024, hdmi_on_ddi_b, DmcEvents, ExtFake, Sink, PANEL_SURFACE, PIPECONF_A, PIPECONF_B,
    PLANE_CTL_1_A, PLANE_SURF_1_B, PMDEMAND_REQUEST1,
};
use super::*;
use crate::intel_gpu_modeset::PixelFormat;
use core::cell::Cell;
use narf_kernel_test::{kernel_test_in, TestResult};

const PIPECONF_C: u64 = 0x7_2008;
const PLANE_SURF_1_C: u64 = 0x7_219C;
const TRANS_DDI_FUNC_CTL_C: u64 = 0x6_2400;
/// `XELPDP_INITIATE_PMDEMAND_REQUEST(0)`.
const PMDEMAND_REQUEST0: u64 = 0x4_5230;
/// The surfaces the fixture's allocator hands out, in call order.
const SURFACES: [u32; 4] = [0x100_0000, 0x300_0000, 0x500_0000, 0x700_0000];

/// Two ports in one display: DDI B's register block (`DDI_BUF_CTL(B)`
/// 0x64100 through `XELPDP_PORT_CLOCK_CTL(B)` 0x641E0) and GMBUS go to the
/// HDMI side, everything else (pipes, transcoders, global resources, TC1's
/// PHY, AUX and TCSS) to the TC1 side.
struct Dual {
    tc: ExtFake,
    b: ExtFake,
}

fn port_b_side(off: u64) -> bool {
    (0x6_4100..0x6_4200).contains(&off)
        || (crate::intel_gpu_gmbus::GMBUS0..=crate::intel_gpu_gmbus::GMBUS5).contains(&off)
}

impl MmioWindow for Dual {
    fn display_access_ok(&self) -> bool {
        self.tc.display_access_ok()
    }
    fn cx0_xe3(&self) -> bool {
        self.tc.cx0_xe3()
    }
    fn cx0_c20_port_b(&self) -> bool {
        self.tc.cx0_c20_port_b()
    }
    fn read32(&self, off: u64) -> u32 {
        if port_b_side(off) {
            self.b.read32(off)
        } else {
            self.tc.read32(off)
        }
    }
    fn write32(&self, off: u64, value: u32) {
        if port_b_side(off) {
            self.b.write32(off, value)
        } else {
            self.tc.write32(off, value)
        }
    }
}

/// A DP-alt monitor on TC1 and an HDMI monitor on DDI B (both 1024x768),
/// with the owned panel lit on Pipe A.
fn dual() -> Option<(Dual, Mode)> {
    let io = Dual {
        tc: ExtFake::new(XeLpgPort::Tc1, Sink::new(0x14, edid_1024())),
        b: hdmi_on_ddi_b(edid_1024()),
    };
    // DDI B's south hotplug level (SDE_ISR lives on the shared side).
    io.tc.sde_isr.set(io.tc.sde_isr.get() | 1 << 17);
    let panel = io.tc.light_panel()?;
    Some((io, panel))
}

fn event(port: XeLpgPort, kind: MtlHpdKind) -> MtlHpdEvent {
    MtlHpdEvent {
        pin: MtlHpdPin::from_port(port).expect("external port"),
        kind,
    }
}

fn service(panel: Mode, dmc: &'static DmcEvents) -> MtlExternalService {
    let mut service = MtlExternalService::new();
    service.set_two_routes(true);
    service.set_display(MtlDisplay {
        panel: Some(panel),
        pipe_dmc: dmc,
    });
    service
}

/// An allocator that hands out a distinct surface per call.
fn allocator(next: &Cell<usize>) -> impl FnMut(&Mode) -> Option<Framebuffer> + '_ {
    move |mode: &Mode| {
        let index = next.get();
        next.set(index + 1);
        Some(Framebuffer {
            phys_addr: u64::from(*SURFACES.get(index)?),
            stride_bytes: (u32::from(mode.h_active) * 4).next_multiple_of(64),
            format: PixelFormat::Xrgb8888,
        })
    }
}

fn lit(io: &Dual, conf: u64) -> bool {
    io.read32(conf) & (ENABLE | STATE) == ENABLE | STATE
}

/// The primary's DDB start and the cursor's DDB end (inclusive) of `pipe`
/// (`skl_ddb_entry_write`: `PLANE_BUF_END(end - 1) | PLANE_BUF_START`).
fn ddb_span(io: &Dual, pipe: usize) -> (u32, u32) {
    let primary = io.read32(crate::intel_gpu_xelpg_resources::plane_buf_cfg(pipe, 0));
    let cursor = io.read32(crate::intel_gpu_xelpg_resources::cursor_buf_cfg(pipe));
    (primary & 0xfff, (cursor >> 16) & 0xfff)
}

/// The programmed PM demand (`intel_pmdemand_program_params`).
fn pmdemand(io: &Dual) -> crate::intel_gpu_pmdemand::Params {
    crate::intel_gpu_pmdemand::Params::decode(
        io.read32(PMDEMAND_REQUEST0),
        io.read32(PMDEMAND_REQUEST1),
    )
}

/// `intel_pmdemand_atomic_check` on display 14 for `pipes` active pipes and
/// `phys` active non-Type-C PHYs: `active_pipes = min(pipes, 3)`,
/// `plls = min(phys + 1, 7)`; the owned panel keeps its HBR3 reservation,
/// so `ddiclk_max = DIV_ROUND_UP(810000, 1000)`.
fn demand_matches(io: &Dual, pipes: u8, phys: u8) -> bool {
    let p = pmdemand(io);
    p.active_pipes == pipes.min(3)
        && p.active_phys == phys
        && p.plls == (phys + 1).min(7)
        && p.ddiclk_max == 810
}

/// No write ever turned `conf`'s transcoder or its primary off, and any
/// re-latch of its surface kept `surface` (the joint transaction may
/// repartition a lit pipe, never blank it).
fn never_blanked(io: &Dual, conf: u64, from: usize, surface: u32) -> bool {
    let plane_ctl = conf + 0x178;
    let plane_surf = conf + 0x194;
    io.tc.writes.borrow()[from..].iter().all(|&(off, value)| {
        off != conf && off != plane_ctl && (off != plane_surf || value == surface)
    }) && lit(io, conf)
}

fn smoke_mtl_two_routes_light_and_tear_down_independently() -> TestResult {
    let Some((io, panel)) = dual() else {
        return TestResult::Fail("the fixture must light the owned panel");
    };
    let dmc = DmcEvents::leak();
    let mut service = service(panel, dmc);
    let next = Cell::new(0);
    let mut alloc = allocator(&next);
    // Route 1: DP-alt on TC1 takes Pipe B.
    match service.handle(
        &io,
        event(XeLpgPort::Tc1, MtlHpdKind::Connected(LiveMode::DpAlt)),
        &mut alloc,
    ) {
        ServiceOutcome::Activated {
            port: XeLpgPort::Tc1,
            protocol: MtlProtocol::Dp,
            pipe: Pipe::B,
            ..
        } => {}
        _ => return TestResult::Fail("TC1 DP must light Pipe B beside the panel"),
    }
    if service.event_slot(XeLpgPort::B) != 1 || service.event_slot(XeLpgPort::Tc1) != 0 {
        return TestResult::Fail("a new port must take slot 1 beside the live slot-0 route");
    }
    let route2_from = io.tc.writes.borrow().len();
    // Route 2: HDMI on DDI B (no DPCD answers) takes Pipe C, beside both.
    match service.handle(
        &io,
        event(XeLpgPort::B, MtlHpdKind::Connected(LiveMode::Native)),
        &mut alloc,
    ) {
        ServiceOutcome::Activated {
            port: XeLpgPort::B,
            protocol: MtlProtocol::Hdmi,
            pipe: Pipe::C,
            ..
        } => {}
        _ => return TestResult::Fail("DDI B HDMI must light Pipe C beside the DP route"),
    }
    if service.routes().count() != 2
        || !lit(&io, PIPECONF_C)
        || io.read32(PLANE_SURF_1_B) != SURFACES[0]
        || io.read32(PLANE_SURF_1_C) != SURFACES[1]
        || io.read32(TRANS_DDI_FUNC_CTL_C) & (1 << 31) == 0
    {
        return TestResult::Fail("each route must scan out its own surface on its own pipe");
    }
    if !io.tc.writes_to(PIPECONF_A).is_empty()
        || !io.tc.writes_to(PLANE_CTL_1_A).is_empty()
        || io.read32(0x7_019C) != PANEL_SURFACE
        || !never_blanked(&io, PIPECONF_B, route2_from, SURFACES[0])
    {
        return TestResult::Fail("the second route must keep the panel and route 1 lit");
    }
    // The joint plan for Pipes A, B and C: adlp_allowed_dbufs gives A
    // S1|S2 and B, C S3|S4 (1024 blocks each), split by hdisplay
    // (`intel_crtc_ddb_weight`, both 1024); MBUS unjoined; PM demand for
    // three pipes and the two combo PHYs (A, B). `PLANE_BUF_CFG` holds the
    // entry relative to its slice group (`skl_crtc_allocate_ddb`:
    // `ddb_slices.start - mbus_ddb_offset(S3) + start`, read back by
    // `skl_ddb_get_hw_plane_state`), so B and C count from S3's start.
    if ddb_span(&io, 0) != (0, 2047)
        || ddb_span(&io, 1) != (0, 1023)
        || ddb_span(&io, 2) != (1024, 2047)
        || io.read32(crate::intel_gpu_xelpg_dbuf::MBUS_CTL)
            & crate::intel_gpu_xelpg_dbuf::MBUS_CTL_MASK
            != 0
        || !demand_matches(&io, 3, 2)
    {
        return TestResult::Fail("the three-pipe DDB and PM demand must be Linux's joint plan");
    }
    if dmc.events() != [(1, true), (2, true)] {
        return TestResult::Fail("each pipe's DMC must be enabled once for its crtc");
    }
    // Independent hotplug: a healthy IRQ_HPD on TC1 changes nothing.
    let quiet = io.tc.writes.borrow().len();
    if !matches!(
        service.handle(
            &io,
            event(XeLpgPort::Tc1, MtlHpdKind::ShortPulse),
            &mut alloc
        ),
        ServiceOutcome::Unchanged
    ) || !never_blanked(&io, PIPECONF_C, quiet, SURFACES[1])
    {
        return TestResult::Fail("a healthy short pulse must leave both routes alone");
    }
    // A lost link retrains TC1 on Pipe B beside the HDMI route.
    io.tc.sink.borrow_mut().drop_lock();
    let retrain_from = io.tc.writes.borrow().len();
    match service.handle(
        &io,
        event(XeLpgPort::Tc1, MtlHpdKind::ShortPulse),
        &mut alloc,
    ) {
        ServiceOutcome::Activated { pipe: Pipe::B, .. } => {}
        _ => return TestResult::Fail("a lost TC1 link must retrain on Pipe B"),
    }
    if !never_blanked(&io, PIPECONF_C, retrain_from, SURFACES[1])
        || !lit(&io, PIPECONF_B)
        || ddb_span(&io, 1) != (0, 1023)
        || !demand_matches(&io, 3, 2)
    {
        return TestResult::Fail("the retrain must keep the HDMI route and the joint plan");
    }
    // Unplug TC1: Pipe B goes, Pipe C stays lit and takes S3|S4 alone.
    let unplug_from = io.tc.writes.borrow().len();
    if !matches!(
        service.handle(
            &io,
            event(XeLpgPort::Tc1, MtlHpdKind::Disconnected),
            &mut alloc
        ),
        ServiceOutcome::Withdrawn {
            port: XeLpgPort::Tc1
        }
    ) {
        return TestResult::Fail("TC1's unplug must withdraw its route alone");
    }
    if io.read32(PIPECONF_B) & (ENABLE | STATE) != 0
        || !never_blanked(&io, PIPECONF_C, unplug_from, SURFACES[1])
        || service.routes().count() != 1
        || service.route_on(XeLpgPort::B).map(MtlRoute::live) != Some(true)
        || ddb_span(&io, 0) != (0, 2047)
        || ddb_span(&io, 2) != (0, 2047)
        || !demand_matches(&io, 2, 2)
    {
        return TestResult::Fail("Pipes A and C must keep scanning out with the A|C plan");
    }
    // Unplug DDI B: the panel gets its whole single-pipe profile back.
    if !matches!(
        service.handle(
            &io,
            event(XeLpgPort::B, MtlHpdKind::Disconnected),
            &mut alloc
        ),
        ServiceOutcome::Withdrawn { port: XeLpgPort::B }
    ) {
        return TestResult::Fail("DDI B's unplug must withdraw the HDMI route");
    }
    if io.read32(PIPECONF_C) & (ENABLE | STATE) != 0
        || service.route().is_some()
        || !io.tc.writes_to(PIPECONF_A).is_empty()
        || crate::intel_gpu_display_resources::Profile::capture(&io, &panel).is_err()
        || !demand_matches(&io, 1, 1)
    {
        return TestResult::Fail("the panel must hold its fixed profile again, never blanked");
    }
    if dmc.events()
        != [
            (1, true),
            (2, true),
            (1, false),
            (1, true),
            (1, false),
            (2, false),
        ]
    {
        return TestResult::Fail("each crtc's DMC must follow its own route's lifetime");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_two_routes_light_and_tear_down_independently
);

/// Suspend withdraws both routes; resume's re-detection relights both,
/// in either plug order, through the same joint plan.
fn smoke_mtl_two_routes_suspend_teardown_and_relight() -> TestResult {
    let Some((io, panel)) = dual() else {
        return TestResult::Fail("the fixture must light the owned panel");
    };
    let dmc = DmcEvents::leak();
    let mut service = service(panel, dmc);
    let next = Cell::new(0);
    let mut alloc = allocator(&next);
    let connect = |service: &mut MtlExternalService,
                   alloc: &mut dyn FnMut(&Mode) -> Option<Framebuffer>,
                   port: XeLpgPort,
                   live: LiveMode| {
        matches!(
            service.handle(&io, event(port, MtlHpdKind::Connected(live)), alloc),
            ServiceOutcome::Activated { .. }
        )
    };
    if !connect(&mut service, &mut alloc, XeLpgPort::B, LiveMode::Native)
        || !connect(&mut service, &mut alloc, XeLpgPort::Tc1, LiveMode::DpAlt)
    {
        return TestResult::Fail("both routes must light");
    }
    // HDMI went first this time: it holds Pipe B, DP takes Pipe C.
    if service.route_on(XeLpgPort::B).map(MtlRoute::pipe) != Some(Pipe::B)
        || service.route_on(XeLpgPort::Tc1).map(MtlRoute::pipe) != Some(Pipe::C)
        || !demand_matches(&io, 3, 2)
    {
        return TestResult::Fail("plug order must assign the lowest free pipe each time");
    }
    if !service.teardown(&io)
        || service.route().is_some()
        || io.read32(PIPECONF_B) & (ENABLE | STATE) != 0
        || io.read32(PIPECONF_C) & (ENABLE | STATE) != 0
        || !io.tc.writes_to(PIPECONF_A).is_empty()
        || !demand_matches(&io, 1, 1)
    {
        return TestResult::Fail("suspend teardown must stop and release both routes");
    }
    // Resume: the hotplug owner re-reports both sinks.
    if !connect(&mut service, &mut alloc, XeLpgPort::Tc1, LiveMode::DpAlt)
        || !connect(&mut service, &mut alloc, XeLpgPort::B, LiveMode::Native)
        || !lit(&io, PIPECONF_B)
        || !lit(&io, PIPECONF_C)
        || ddb_span(&io, 1) != (0, 1023)
        || ddb_span(&io, 2) != (1024, 2047)
        || !demand_matches(&io, 3, 2)
    {
        return TestResult::Fail("resume must relight both routes with the joint plan");
    }
    if !service.teardown(&io) {
        return TestResult::Fail("the relit routes must tear down again");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_two_routes_suspend_teardown_and_relight
);

/// Without `narf.intel.ext_routes=2` a second sink changes nothing and
/// touches neither its port nor a pipe; the option's grammar is strict.
fn smoke_mtl_second_route_refusals_precede_mmio() -> TestResult {
    let Some((io, panel)) = dual() else {
        return TestResult::Fail("the fixture must light the owned panel");
    };
    let dmc = DmcEvents::leak();
    let mut service = service(panel, dmc);
    service.set_two_routes(false);
    let next = Cell::new(0);
    let mut alloc = allocator(&next);
    if !matches!(
        service.handle(
            &io,
            event(XeLpgPort::Tc1, MtlHpdKind::Connected(LiveMode::DpAlt)),
            &mut alloc,
        ),
        ServiceOutcome::Activated { .. }
    ) {
        return TestResult::Fail("the first route must light");
    }
    let (tc_writes, b_writes) = (io.tc.writes.borrow().len(), io.b.writes.borrow().len());
    if !matches!(
        service.handle(
            &io,
            event(XeLpgPort::B, MtlHpdKind::Connected(LiveMode::Native)),
            &mut alloc,
        ),
        ServiceOutcome::Unchanged
    ) || io.tc.writes.borrow().len() != tc_writes
        || io.b.writes.borrow().len() != b_writes
        || service.event_slot(XeLpgPort::B) != 0
    {
        return TestResult::Fail("a single-route service must ignore a second sink untouched");
    }
    if !service.teardown(&io) {
        return TestResult::Fail("the route must tear down");
    }
    use narf_boot::args::KernelCmdline;
    let opt = |line: &str| {
        crate::intel_gpu_gt::boot_opt_is(KernelCmdline::new(line), EXT_ROUTES_OPTION, "2")
    };
    if !opt("quiet narf.intel.ext_routes=2")
        || opt("narf.intel.ext_routes=1")
        || opt("narf.intel.ext_routes")
        || opt("narf.intel.ext_routes=2 narf.intel.ext_routes=2")
        || opt("-- narf.intel.ext_routes=2")
        || opt("")
    {
        return TestResult::Fail("only one exact narf.intel.ext_routes=2 enables two routes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_second_route_refusals_precede_mmio
);
