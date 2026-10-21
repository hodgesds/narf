use super::*;
use crate::amdgpu_dcn401_otg::tests::{engine, harvest, run};
use alloc::collections::BTreeMap;
use narf_kernel_test::{kernel_test_in, TestResult};

const ADDR: u64 = 0x8_0010_2000;
const BLACK: u32 = 0x41 | 1 << 12;

/// Register file with the handshakes activation depends on: the lock status
/// follows the request, and releasing the lock latches the double-buffered
/// state at the next VUPDATE.
struct Hw {
    regs: BTreeMap<u64, u32>,
    layout: Layout,
    pipe: u8,
    /// An ODM pipe latching with `pipe`'s timing.
    odm: Option<u8>,
    /// Overlay pipes latching with it too.
    overlays: alloc::vec::Vec<u8>,
    /// Every write, in order.
    log: alloc::vec::Vec<(u64, u32)>,
    grant: bool,
    latch: bool,
    underflow_after: Option<usize>,
    writes: usize,
    frame: u32,
    /// OTG_TRIGA_MANUAL_TRIG writes: (value, OTG lock, HUBP address) then.
    triggers: alloc::vec::Vec<(u32, u32, u32)>,
}
impl Hw {
    fn optc_input(&self) -> u64 {
        self.layout.base + (OPTC_INPUT + u64::from(self.pipe) * 0x10) * 4
    }
    fn get(&self, at: u64) -> u32 {
        self.regs.get(&at).copied().unwrap_or(0)
    }
    fn pipes(&self) -> impl Iterator<Item = u8> + '_ {
        core::iter::once(self.pipe)
            .chain(self.odm)
            .chain(self.overlays.iter().copied())
    }
    fn latch(&mut self) {
        let pipes: alloc::vec::Vec<u8> = self.pipes().collect();
        for p in pipes {
            self.latch_pipe(p);
        }
    }
    fn latch_pipe(&mut self, p: u8) {
        let l = self.layout;
        let low = self.get(l.hubp(p, ADDRESS));
        let high = self.get(l.hubp(p, ADDRESS_HIGH));
        self.regs.insert(l.hubp(p, EARLIEST_INUSE), low);
        self.regs.insert(l.hubp(p, EARLIEST_INUSE_HIGH), high);
        *self.regs.entry(l.hubp(p, FLIP)).or_default() &= !FLIP_PENDING;
        self.regs.insert(l.opp(p, DPG_PENDING), 0);
        let connected = self.get(l.mpcc(p, TOP)) & 0xf != 0xf;
        self.regs
            .insert(l.mpcc(p, MPC_STATUS), if connected { 2 } else { 5 });
        let control = self.regs.entry(l.hubp(p, HUBP_CONTROL)).or_default();
        if connected {
            *control &= !NO_OUTSTANDING;
        } else {
            *control |= NO_OUTSTANDING;
        }
    }
}
impl Io for Hw {
    fn wait_poll_limit(&self) -> Option<u32> {
        // Latches are synchronous and the frame counter advances on reads.
        Some(16)
    }
    fn read(&mut self, at: u64) -> u32 {
        harvest::guard(self.layout, at, None);
        if at == self.layout.otg(self.pipe, FRAME_COUNT) {
            self.frame = self.frame.wrapping_add(1);
            return self.frame & FRAME_MASK;
        }
        self.get(at)
    }
    fn write(&mut self, at: u64, value: u32) {
        harvest::guard(self.layout, at, Some(value));
        self.writes += 1;
        self.log.push((at, value));
        let (l, p) = (self.layout, self.pipe);
        if at == l.otg(p, 0x1b3c) {
            let state = (
                value,
                self.get(l.otg(p, LOCK)),
                self.get(l.hubp(p, ADDRESS)),
            );
            self.triggers.push(state);
            return;
        }
        let mut value = value;
        if at == l.otg(p, LOCK) {
            if value & LOCK_REQUEST != 0 {
                if self.grant {
                    value |= LOCK_STATUS;
                }
            } else {
                value &= !LOCK_STATUS;
                if self.latch {
                    self.regs.insert(at, value);
                    self.latch();
                    return;
                }
            }
        }
        let pipes: alloc::vec::Vec<u8> = self.pipes().collect();
        for q in pipes {
            if at == l.opp(q, DPG) {
                self.regs.insert(l.opp(q, DPG_PENDING), 1);
            }
            if at == l.hubp(q, ADDRESS) {
                *self.regs.entry(l.hubp(q, FLIP)).or_default() |= FLIP_PENDING;
            }
            if at == l.hubp(q, HUBP_CONTROL) && value & BLANK_EN != 0 {
                value |= NO_OUTSTANDING;
            }
            if at == l.hubp(q, HUBP_CONTROL) && value & HUBP_UNDERFLOW_CLEAR != 0 {
                value &= !(HUBP_UNDERFLOW | HUBP_UNDERFLOW_CLEAR);
            }
        }
        if at == self.optc_input() && value & OPTC_UNDERFLOW_CLEAR != 0 {
            value &= !(OPTC_UNDERFLOW | OPTC_UNDERFLOW_CLEAR);
        }
        self.regs.insert(at, value);
        if self.underflow_after == Some(self.writes) {
            *self.regs.entry(l.hubp(p, HUBP_CONTROL)).or_default() |= 0x1000_0000;
        }
    }
}
fn staged(pipe: u8) -> Engine<Hw> {
    staged_odm(pipe, None)
}
fn staged_odm(pipe: u8, odm: Option<u8>) -> Engine<Hw> {
    staged_planes(pipe, odm, &[])
}
/// `staged_odm` with overlay planes staged on `overlays` too.
fn staged_planes(pipe: u8, odm: Option<u8>, overlays: &[u8]) -> Engine<Hw> {
    let e = engine();
    let l = e.layout;
    let mut hw = Hw {
        regs: BTreeMap::new(),
        layout: l,
        pipe,
        odm,
        overlays: overlays.to_vec(),
        log: alloc::vec::Vec::new(),
        grant: true,
        latch: true,
        underflow_after: None,
        writes: 0,
        frame: 7,
        triggers: alloc::vec::Vec::new(),
    };
    hw.regs.insert(l.otg(pipe, CONTROL), OTG_MASTER_EN);
    for q in core::iter::once(pipe)
        .chain(odm)
        .chain(overlays.iter().copied())
    {
        for (at, value) in [
            (l.hubp(q, HUBP_CONTROL), 3 | l.inst_field(pipe) << 4),
            (l.hubp(q, CURSOR), CURSOR_REQ_MODE),
            (l.hubp(q, ADDRESS), ADDR as u32),
            (l.hubp(q, ADDRESS_HIGH), (ADDR >> 32) as u32),
            (l.opp(q, DPG), BLACK),
            (l.mpcc(q, MPCC_CONTROL), 0xffff_0422),
            (l.mpcc(q, MPC_STATUS), 5),
        ] {
            hw.regs.insert(at, value);
        }
        for (at, _) in e.routes(q, false) {
            hw.regs.insert(at, 0xf);
        }
    }
    Engine {
        io: hw,
        authority: e.authority,
        layout: l,
        status: e.status,
        displays: e.displays,
    }
}
/// ODM 2:1: one master lock covers both halves. Start connects each
/// segment's MPCC to its own OPP, releases both DPGs and unblanks both
/// HUBPs at one VUPDATE, and completes only once both report the surface
/// in use; a flip re-addresses both; an underflow on the right half is the
/// scanout's; stop returns both to staged black.
fn dcn401_scanout_odm_drives_both_halves_under_one_lock() -> TestResult {
    odm_on(1, 3)
}
/// The test above on pipes (pipe, q).
fn odm_on(pipe: u8, q: u8) -> TestResult {
    let mut e = staged_odm(pipe, Some(q));
    let surface = SurfaceApplied {
        request: SurfaceRequest {
            surface: Default::default(),
            pipe,
            width: 7680,
            height: 4320,
            format: SurfaceFormat::Xrgb8888,
            odm: SplitPipes::one(q),
            mpc: SplitPipes::NONE,
            plane: None,
        },
        address: ADDR,
        pitch_bytes: 7680 * 4,
        bytes: 7680 * 4 * 4320,
        chroma: None,
    };
    e.status.surfaces[usize::from(pipe)] = Some(surface);
    let p = Pipe {
        odm: SplitPipes::one(q),
        ..target(pipe)
    };
    if run(e.start_fetch(p)).is_err() {
        return TestResult::Fail("ODM start");
    }
    let l = e.layout;
    for s in [pipe, q] {
        if e.io.get(l.mpcc(s, TOP)) & 0xf != l.inst_field(s)
            || e.io.get(l.mpcc(s, OPP_ID)) & 0xf != l.inst_field(s)
            || e.io.get(l.out_mux(s)) & 0xf != l.inst_field(s)
            || e.io.get(l.opp(s, DPG)) & DPG_FIELDS != 0
            || e.io.get(l.hubp(s, HUBP_CONTROL)) & BLANK_EN != 0
        {
            return TestResult::Fail("segment routes and unblank");
        }
    }
    if e.live_fetch(pipe, ADDR).is_err() {
        return TestResult::Fail("both halves live");
    }
    // A flip re-addresses both halves under the one lock.
    let back = ADDR + 0x0200_0000;
    if run(e.flip_to(Pipe { address: back, ..p })).is_err()
        || e.io.get(l.hubp(q, EARLIEST_INUSE)) != back as u32
        || e.io.get(l.hubp(pipe, EARLIEST_INUSE)) != back as u32
    {
        return TestResult::Fail("ODM flip");
    }
    // The right half's underflow belongs to this scanout.
    *e.io.regs.entry(l.hubp(q, HUBP_CONTROL)).or_default() |= 0x1000_0000;
    if e.underflow(pipe) != Err(Error::Underflow(l.hubp(q, HUBP_CONTROL))) {
        return TestResult::Fail("right half underflow");
    }
    *e.io.regs.entry(l.hubp(q, HUBP_CONTROL)).or_default() &= !0x1000_0000;
    if run(e.stop_fetch(Pipe { address: back, ..p })).is_err() {
        return TestResult::Fail("ODM stop");
    }
    for s in [pipe, q] {
        if e.io.get(l.mpcc(s, TOP)) & 0xf != 0xf
            || e.io.get(l.opp(s, DPG)) & DPG_FIELDS != BLACK
            || e.io.get(l.hubp(s, HUBP_CONTROL)) & 3 != 3
        {
            return TestResult::Fail("segment back to staged black");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_scanout_odm_drives_both_halves_under_one_lock
);

fn target(pipe: u8) -> Pipe {
    Pipe {
        pipe,
        odm: SplitPipes::NONE,
        mpc: SplitPipes::NONE,
        address: ADDR,
        overlays: [None; MAX_OVERLAYS],
        black: BLACK,
        timeout_us: 2000,
        watch: true,
    }
}

fn dcn401_scanout_starts_and_stops_under_one_lock_with_hardware_evidence() -> TestResult {
    for pipe in crate::amdgpu_rdna4::pipe_pool().pipes() {
        let mut e = staged(pipe);
        let p = target(pipe);
        if e.quiet(pipe).is_err() || e.staged(p).is_err() {
            return TestResult::Fail("staged fixture");
        }
        let Ok((before, after)) = run(e.start_fetch(p)) else {
            return TestResult::Fail("start");
        };
        let l = e.layout;
        let r = |e: &Engine<Hw>, at| e.io.get(at);
        if before == after
            || r(&e, l.opp(pipe, DPG)) & DPG_FIELDS != 0
            || r(&e, l.hubp(pipe, HUBP_CONTROL)) & (BLANK_EN | TTU_DISABLE) != 0
            || r(&e, l.hubp(pipe, HUBP_CLOCK)) & 1 != 1
            || r(&e, e.dpp_control(pipe)) & DPP_CLOCK_ENABLE == 0
            || r(&e, l.hubp(pipe, EARLIEST_INUSE)) != ADDR as u32
            || r(&e, l.base + DRAM_STATE * 4) & PSTATE_FORCE != 0
            || r(&e, l.otg(pipe, LOCK)) & (LOCK_REQUEST | LOCK_STATUS) != 0
        {
            return TestResult::Fail("live scanout state");
        }
        for (at, value) in e.routes(pipe, true) {
            if r(&e, at) & 0xf != value {
                return TestResult::Fail("route not connected");
            }
        }
        if run(e.stop_fetch(p)).is_err() || e.staged(p).is_err() || e.quiet(pipe).is_err() {
            return TestResult::Fail("stop did not restore the staged pipe");
        }
        // Stop/start/stop again from the restored state.
        if run(e.start_fetch(p)).is_err() || run(e.stop_fetch(p)).is_err() {
            return TestResult::Fail("restart");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_scanout_starts_and_stops_under_one_lock_with_hardware_evidence
);

fn dcn401_scanout_requires_lock_latch_and_no_underflow() -> TestResult {
    let p = target(1);
    // A lock that is never granted stops before any route is touched.
    let mut e = staged(1);
    e.io.grant = false;
    if run(e.start_fetch(p)) != Err(Error::Timeout(e.layout.otg(1, LOCK)))
        || e.io.get(e.layout.mpcc(1, TOP)) != 0xf
        || e.io.get(e.layout.opp(1, DPG)) != BLACK
    {
        return TestResult::Fail("unlocked writes");
    }
    // A requested address is not presentation: without a latch it times out.
    let mut e = staged(1);
    e.io.latch = false;
    if run(e.start_fetch(p)) != Err(Error::Timeout(e.layout.hubp(1, EARLIEST_INUSE))) {
        return TestResult::Fail("unlatched address accepted");
    }
    // Underflow during or after the latch fails the start.
    for after in [8, 14] {
        let mut e = staged(1);
        e.io.underflow_after = Some(after);
        if run(e.start_fetch(p)) != Err(Error::Underflow(e.layout.hubp(1, HUBP_CONTROL))) {
            return TestResult::Fail("underflow not reported");
        }
    }
    // Inherited pending updates or a held lock are not quiet.
    for (reg, value) in [(LOCK, LOCK_STATUS), (DOUBLE_BUFFER, 1), (PIPE_UPDATE, 0x10)] {
        let mut e = staged(1);
        let at = e.layout.otg(1, reg);
        e.io.regs.insert(at, value);
        if e.quiet(1) != Err(Error::Busy) {
            return TestResult::Fail("pending update accepted");
        }
    }
    let mut e = staged(1);
    let at = e.layout.opp(1, DPG);
    e.io.regs.insert(at, 0);
    if e.staged(p) != Err(Error::Readback(at)) {
        return TestResult::Fail("start without black");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_scanout_requires_lock_latch_and_no_underflow
);

fn dcn401_scanout_entry_requires_running_black_video_and_deadlines() -> TestResult {
    let mut e = staged(0);
    let mut surfaces = Surfaces::new();
    let mut called = false;
    if run(surfaces.start_scanout(&mut e, 0, 100_000, || {
        called = true;
        Err(Error::Busy)
    })) != Err(Error::Invalid)
        || called
    {
        return TestResult::Fail("scanout without black video");
    }
    if run(surfaces.stop_scanout(&mut e, 0, 100_000, || Err(Error::Busy))) != Err(Error::Invalid)
        || e.io.writes != 0
        || e.status.state != State::Ready
    {
        return TestResult::Fail("stop without scanout");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_scanout_entry_requires_running_black_video_and_deadlines
);

fn dcn401_scanout_live_fetch_is_recognised_exactly() -> TestResult {
    let mut e = staged(2);
    let p = target(2);
    let l = e.layout;
    if e.live_fetch(2, ADDR).is_ok() {
        return TestResult::Fail("staged pipe reported live");
    }
    if run(e.start_fetch(p)).is_err() || e.live_fetch(2, ADDR).is_err() {
        return TestResult::Fail("live pipe not recognised");
    }
    if e.live_fetch(2, ADDR + 0x1000) != Err(Error::Readback(l.hubp(2, ADDRESS))) {
        return TestResult::Fail("other surface accepted");
    }
    // Each witness of the live path matters on its own.
    for (at, value) in [
        (l.hubp(2, EARLIEST_INUSE), 0),
        (l.opp(2, DPG), BLACK),
        (l.hubp(2, CURSOR), CURSOR_REQ_MODE | 1),
        (l.mpcc(2, MPC_STATUS), 5),
        (l.out_mux(2), 0xf),
        (l.hubp(2, HUBP_CONTROL), BLANK_EN),
    ] {
        let mut e = staged(2);
        if run(e.start_fetch(p)).is_err() {
            return TestResult::Fail("restart");
        }
        e.io.regs.insert(at, value);
        if e.live_fetch(2, ADDR) != Err(Error::Readback(at)) {
            return TestResult::Fail("changed live witness accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_scanout_live_fetch_is_recognised_exactly
);

fn dcn401_scanout_underflow_returns_to_black_with_diagnostics() -> TestResult {
    for optc in [false, true] {
        let mut e = staged(3);
        let p = target(3);
        if run(e.start_fetch(p)).is_err() {
            return TestResult::Fail("start");
        }
        let l = e.layout;
        let (at, bit) = if optc {
            (e.optc_input(3), OPTC_UNDERFLOW)
        } else {
            (l.hubp(3, HUBP_CONTROL), 0x2000_0000)
        };
        *e.io.regs.entry(at).or_default() |= bit;
        if e.underflow(3) != Err(Error::Underflow(at)) {
            return TestResult::Fail("underflow not seen");
        }
        // A watched stop fails on the sticky status; recovery does not.
        let Ok(report) = run(e.recover_fetch(p)) else {
            return TestResult::Fail("recovery failed");
        };
        if report.pipe != 3
            || report.address != ADDR
            || report.optc != optc
            || report.hubp_status != if optc { 0 } else { 2 }
        {
            return TestResult::Fail("diagnostics");
        }
        if e.staged(p).is_err() || e.quiet(3).is_err() || e.io.get(l.opp(3, DPG)) != BLACK {
            return TestResult::Fail("not returned to black and clean");
        }
        if run(e.start_fetch(p)).is_err() {
            return TestResult::Fail("restart after recovery");
        }
    }
    // Without the latch the drain cannot be proven: recovery fails.
    let mut e = staged(3);
    let p = target(3);
    if run(e.start_fetch(p)).is_err() {
        return TestResult::Fail("start");
    }
    e.io.latch = false;
    *e.io.regs.entry(e.optc_input(3)).or_default() |= OPTC_UNDERFLOW;
    if run(e.recover_fetch(p)).is_ok() {
        return TestResult::Fail("unproven recovery accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_scanout_underflow_returns_to_black_with_diagnostics
);

fn dcn401_scanout_framebuffer_requires_live_owned_scanout() -> TestResult {
    let e = staged(0);
    let surfaces = Surfaces::new();
    if !matches!(
        surfaces.scanout_framebuffer(&e.status, 0),
        Err(Error::Invalid)
    ) {
        return TestResult::Fail("framebuffer without scanout");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_scanout_framebuffer_requires_live_owned_scanout
);

fn dcn401_scanout_flip_latches_new_address_under_the_lock() -> TestResult {
    const BACK: u64 = 0x8_0090_0000;
    for pipe in crate::amdgpu_rdna4::pipe_pool().pipes() {
        let mut e = staged(pipe);
        let p = target(pipe);
        if run(e.start_fetch(p)).is_err() || e.flip_quiet(pipe).is_err() {
            return TestResult::Fail("start");
        }
        let next = Pipe { address: BACK, ..p };
        if run(e.flip_to(next)).is_err()
            || e.live_fetch(pipe, BACK).is_err()
            || e.live_fetch(pipe, ADDR).is_ok()
            || e.io.get(e.layout.otg(pipe, LOCK)) & (LOCK_REQUEST | LOCK_STATUS) != 0
        {
            return TestResult::Fail("flip to back buffer");
        }
        // And back again; the retained staged state still stops cleanly.
        if run(e.flip_to(p)).is_err() || run(e.stop_fetch(p)).is_err() || e.staged(p).is_err() {
            return TestResult::Fail("flip back and stop");
        }
    }
    let p = target(2);
    let next = Pipe { address: BACK, ..p };
    // Requested is not presented: an unlatched flip times out.
    let mut e = staged(2);
    if run(e.start_fetch(p)).is_err() {
        return TestResult::Fail("start");
    }
    e.io.latch = false;
    if run(e.flip_to(next)) != Err(Error::Timeout(e.layout.hubp(2, EARLIEST_INUSE))) {
        return TestResult::Fail("unlatched flip accepted");
    }
    // Pending transactions, a held lock or underflow refuse the flip.
    for (at, value) in [
        (e.layout.hubp(2, FLIP), FLIP_PENDING),
        (e.layout.otg(2, LOCK), LOCK_STATUS),
        (e.layout.otg(2, PIPE_UPDATE), 1),
        (e.layout.hubp(2, HUBP_CONTROL), 0x1000_0000),
    ] {
        let mut e = staged(2);
        if run(e.start_fetch(p)).is_err() {
            return TestResult::Fail("start");
        }
        *e.io.regs.entry(at).or_default() |= value;
        if e.flip_quiet(2).is_ok() {
            return TestResult::Fail("busy pipe flipped");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_scanout_flip_latches_new_address_under_the_lock
);

/// Under DRR a flip fires OTG_TRIGA_MANUAL_TRIG once, after the address
/// update is unlocked (commit_planes_for_stream's manual trigger); at fixed
/// refresh, or for another pipe's DRR, it never does. Completion evidence is
/// unchanged: the new address in use.
fn dcn401_scanout_flip_fires_drr_manual_trigger_only_when_active() -> TestResult {
    const BACK: u64 = 0x8_0090_0000;
    let drr = crate::amdgpu_freesync::Drr {
        v_total_min: 1125,
        v_total_max: 1688,
    };
    for (active, other) in [(false, false), (true, false), (false, true)] {
        let pipe = 1;
        let mut e = staged(pipe);
        let p = target(pipe);
        if run(e.start_fetch(p)).is_err() || e.flip_quiet(pipe).is_err() {
            return TestResult::Fail("start");
        }
        if active || other {
            let on = if other { 3 } else { pipe };
            e.status.drr = Some(crate::amdgpu_dcn401_otg::DrrApplied::for_test(on, drr));
        }
        let next = Pipe { address: BACK, ..p };
        if run(e.flip_to(next)).is_err() || e.live_fetch(pipe, BACK).is_err() {
            return TestResult::Fail("flip");
        }
        let expected: alloc::vec::Vec<(u32, u32, u32)> = if active {
            alloc::vec![(1, 0, BACK as u32)]
        } else {
            alloc::vec::Vec::new()
        };
        if e.io.triggers != expected {
            return TestResult::Fail("manual trigger");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_scanout_flip_fires_drr_manual_trigger_only_when_active
);

fn dcn401_scanout_cursor_programs_under_its_lock_and_stops_with_fetch() -> TestResult {
    for pipe in crate::amdgpu_rdna4::pipe_pool().pipes() {
        let mut e = staged(pipe);
        let p = target(pipe);
        if run(e.start_fetch(p)).is_err() {
            return TestResult::Fail("start");
        }
        let a = super::cursor::CursorApplied {
            pipe,
            address: 0x8_00f0_0000,
            width: 64,
            height: 48,
            x: 11, // odd: X starts at bit 15, right after Y
            y: 20,
            visible: true,
            shown: 1 << pipe,
            degamma: false,
        };
        let at = [(
            pipe,
            super::cursor::placement(11, 20, (64, 48), (1920, 1080), (100_000, 148_500)),
        )];
        if e.program_cursor(a, &at).is_err() || e.verify_cursor(a, &at).is_err() {
            return TestResult::Fail("program cursor");
        }
        let l = e.layout;
        let lock = l.mpc_base + (0x2c5 + u64::from(l.inst(pipe)) * 5) * 4;
        if e.io.get(lock) != 0
            || e.io.get(l.hubp(pipe, 0x679)) != 3 << 24 | 2 << 8 | 4 | 1
            || e.io.get(l.hubp(pipe, 0x67c)) != 64 << 16 | 48
            || e.io.get(l.hubp(pipe, 0x67d)) != 11 << 15 | 20
        {
            return TestResult::Fail("cursor registers");
        }
        // The live witness now expects the owned, visible cursor.
        if e.live_fetch(pipe, ADDR).is_ok() {
            return TestResult::Fail("unreported cursor accepted");
        }
        e.status.cursor = Some(a);
        if e.live_fetch(pipe, ADDR).is_err() {
            return TestResult::Fail("owned cursor rejected");
        }
        // Stopping hides it with the fetch; the staged pipe is clean again.
        if run(e.stop_fetch(p)).is_err() || e.staged(p).is_err() {
            return TestResult::Fail("stop with cursor");
        }
        if e.io.get(l.hubp(pipe, 0x679)) & 1 != 0 || e.io.get(lock) != 0 {
            return TestResult::Fail("cursor left enabled or locked");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_scanout_cursor_programs_under_its_lock_and_stops_with_fetch
);

const OVERLAY_A: u64 = ADDR + 0x0400_0000;
const OVERLAY_B: u64 = ADDR + 0x0800_0000;

fn overlay(pipe: u8, odm: Option<u8>, address: u64) -> Option<OverlayScanout> {
    Some(OverlayScanout {
        pipe,
        odm: odm.into(),
        mpc: SplitPipes::NONE,
        address,
        underlay: false,
    })
}
/// The writes of `log` to MPCC tree selectors (low nibble) and MPCC_MODE
/// (MPCC_CONTROL's low two bits) of `pipes`, in order.
fn tree_writes(l: Layout, log: &[(u64, u32)], pipes: &[u8]) -> alloc::vec::Vec<(u64, u32)> {
    let mut regs = alloc::vec::Vec::new();
    for &q in pipes {
        for r in [TOP, BOTTOM, OPP_ID, UPDATE_LOCK] {
            regs.push((l.mpcc(q, r), 0xf));
        }
        regs.push((l.out_mux(q), 0xf));
        regs.push((l.mpcc(q, MPCC_CONTROL), 3));
    }
    log.iter()
        .filter_map(|&(at, v)| {
            regs.iter()
                .find(|&&(r, _)| r == at)
                .map(|&(_, mask)| (at, v & mask))
        })
        .collect()
}
/// The primary's surface and the display's requestor naming the overlays
/// (what `plane_pipes` and the underflow checks follow).
fn stage_records(e: &mut Engine<Hw>, pipe: u8, odm: Option<u8>, overlays: &[(u8, Option<u8>)]) {
    let surface = |pipe, odm, address| SurfaceApplied {
        request: SurfaceRequest {
            surface: Default::default(),
            pipe,
            width: 1920,
            height: 1080,
            format: SurfaceFormat::Argb8888,
            odm: SplitPipes::from(odm),
            mpc: SplitPipes::NONE,
            plane: None,
        },
        address,
        pitch_bytes: 7680,
        bytes: 7680 * 1080,
        chroma: None,
    };
    let primary = surface(pipe, odm, ADDR);
    e.status.surfaces[usize::from(pipe)] = Some(primary);
    let mut stack = [None; MAX_OVERLAYS];
    for (k, &(o, o_odm)) in overlays.iter().enumerate() {
        stack[k] = Some(surface(o, o_odm, [OVERLAY_A, OVERLAY_B][k]));
    }
    e.status.requestor = Some(RequestorApplied {
        pipe,
        surface: primary,
        overlays: stack,
        det_bytes: 327_680,
        overlay_det_bytes: [327_680; crate::amdgpu_dcn401_otg::MAX_OVERLAYS],
        compbuf_bytes: 65_536,
        pixel_chunk_bytes: 8192,
        minimum_chunk_bytes: 1024,
    });
}

/// Two overlays above the primary: dcn20_program_pipe takes the planes
/// from the top down and mpc1_insert_plane puts each at the bottom of the
/// OPP's tree, so the top overlay's MPCC goes on the OUT_MUX first, alone
/// (TOP_LAYER_ONLY), and each lower plane's MPCC then becomes the bottom of
/// the one above it, which switches to TOP_BOT_BLENDING. Every HUBP
/// unblanks and every plane's address latches under the one OTG lock;
/// only the primary's OPP leaves the DPG. The CRTC color (gamut remap)
/// goes on the top MPCC only, the input transfer function on every DPP.
fn dcn401_scanout_overlays_blend_in_linux_mpcc_order() -> TestResult {
    overlays_on(0, 2, 3)
}
/// The test above with the primary on pipe and the overlays on a and b.
fn overlays_on(pipe: u8, a: u8, b: u8) -> TestResult {
    let mut e = staged_planes(pipe, None, &[a, b]);
    let l = e.layout;
    stage_records(&mut e, pipe, None, &[(a, None), (b, None)]);
    e.displays.color[usize::from(pipe)] = Some(alloc::sync::Arc::new(ColorProgram {
        pre_degam_srgb: true,
        gamut: Some(GamutProgram {
            coef: [1, 2, 3, 4, 5, 6],
            s3_12: false,
        }),
        ogam: None,
    }));
    let p = Pipe {
        overlays: [
            overlay(a, None, OVERLAY_A),
            overlay(b, None, OVERLAY_B),
            None,
        ],
        ..target(pipe)
    };
    e.io.log.clear();
    if run(e.start_fetch(p)).is_err() {
        return TestResult::Fail("start with overlays");
    }
    let w = |q: u8, r: u64, v: u32| (l.mpcc(q, r), v);
    let c = |q: u8, v: u32| (l.mpcc(q, MPCC_CONTROL), v);
    let want = [
        // The top overlay alone on the OPP's output.
        w(b, BOTTOM, 0xf),
        c(b, 2),
        w(b, TOP, l.inst_field(b)),
        w(b, OPP_ID, l.inst_field(pipe)),
        w(b, UPDATE_LOCK, l.inst_field(pipe)),
        (l.out_mux(pipe), l.inst_field(b)),
        // The lower overlay inserted at the bottom.
        w(a, BOTTOM, 0xf),
        c(a, 2),
        w(a, TOP, l.inst_field(a)),
        w(a, OPP_ID, l.inst_field(pipe)),
        w(a, UPDATE_LOCK, l.inst_field(pipe)),
        w(b, BOTTOM, l.inst_field(a)),
        c(b, 3),
        // The primary at the very bottom.
        w(pipe, BOTTOM, 0xf),
        c(pipe, 2),
        w(pipe, TOP, l.inst_field(pipe)),
        w(pipe, OPP_ID, l.inst_field(pipe)),
        w(pipe, UPDATE_LOCK, l.inst_field(pipe)),
        w(a, BOTTOM, l.inst_field(pipe)),
        c(a, 3),
    ];
    if tree_writes(l, &e.io.log, &[pipe, a, b]) != want {
        return TestResult::Fail("mpc1_insert_plane order");
    }
    for (q, address, dpg) in [
        (pipe, ADDR, Some(0)),
        (a, OVERLAY_A, None),
        (b, OVERLAY_B, None),
    ] {
        if e.io.get(l.hubp(q, HUBP_CONTROL)) & BLANK_EN != 0
            || e.io.get(l.hubp(q, EARLIEST_INUSE)) != address as u32
            || dpg.is_some_and(|v| e.io.get(l.opp(q, DPG)) & DPG_FIELDS != v)
        {
            return TestResult::Fail("planes live at their addresses");
        }
    }
    // The overlays' OPPs never leave black: they are not this stream's.
    if e.io.get(l.opp(a, DPG)) != BLACK || e.io.get(l.opp(b, DPG)) != BLACK {
        return TestResult::Fail("overlay OPP released");
    }
    // Stream gamut remap on the top MPCC only; sRGB input on every DPP.
    if e.io.get(l.ogam(b, 0xc9)) & 3 != 1
        || e.io.get(l.ogam(a, 0xc9)) & 3 != 0
        || e.io.get(l.ogam(pipe, 0xc9)) & 3 != 0
        || [pipe, a, b]
            .iter()
            .any(|&q| e.io.get(l.dpp(q, 0xced)) & 0x73 != 1)
        || e.status.colors[usize::from(b)].gamut.is_none()
        || e.status.colors[usize::from(a)].gamut.is_some()
        || e.status.colors[usize::from(pipe)].gamut.is_some()
    {
        return TestResult::Fail("CRTC color on the top MPCC");
    }
    for live in p.live(None) {
        if e.live_pipe(live).is_err() {
            return TestResult::Fail("live witness of every plane");
        }
    }
    // A plane whose tree position is wrong is not this scanout.
    let mut bad = p.live(None)[1];
    bad.routes[2] = 0xf;
    if e.live_pipe(bad).is_ok() {
        return TestResult::Fail("wrong BOT_SEL accepted");
    }
    // Flipping the top overlay alone re-addresses only its HUBP.
    let mut next = p;
    next.overlays[1] = overlay(b, None, OVERLAY_B + 0x1000);
    e.io.log.clear();
    if run(e.flip_from(next, Some(p))).is_err() {
        return TestResult::Fail("overlay flip");
    }
    let addressed: alloc::vec::Vec<u8> = [pipe, a, b]
        .into_iter()
        .filter(|&q| e.io.log.iter().any(|&(at, _)| at == l.hubp(q, ADDRESS)))
        .collect();
    if addressed != [b]
        || e.io.get(l.hubp(b, EARLIEST_INUSE)) != (OVERLAY_B + 0x1000) as u32
        || e.io.get(l.hubp(a, EARLIEST_INUSE)) != OVERLAY_A as u32
    {
        return TestResult::Fail("only the flipped plane re-addresses");
    }
    // Stop detaches the overlays first (top down), every MPCC back to its
    // staged TOP_LAYER_ONLY, every HUBP blank, the OPP black.
    e.io.log.clear();
    if run(e.stop_fetch(next)).is_err() || e.staged(next).is_err() {
        return TestResult::Fail("stop with overlays");
    }
    let detached: alloc::vec::Vec<u64> = e
        .io
        .log
        .iter()
        .filter(|&&(at, v)| [pipe, a, b].iter().any(|&q| at == l.mpcc(q, TOP)) && v & 0xf == 0xf)
        .map(|&(at, _)| at)
        .collect();
    if detached != [l.mpcc(b, TOP), l.mpcc(a, TOP), l.mpcc(pipe, TOP)] {
        return TestResult::Fail("overlays leave the tree first");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_scanout_overlays_blend_in_linux_mpcc_order
);

/// An overlay on an ODM 2:1 stream takes a pipe in each half: each OPP has
/// its own tree, the overlay's left pipe above the primary's left pipe,
/// its right pipe above the primary's right one, both trees latching
/// under the one master lock; an underflow on the overlay's right half is
/// the scanout's.
fn dcn401_scanout_odm_overlay_builds_a_tree_per_segment() -> TestResult {
    let (pipe, q, o, o2) = (0u8, 1u8, 2u8, 3u8);
    let mut e = staged_planes(pipe, Some(q), &[o, o2]);
    let l = e.layout;
    stage_records(&mut e, pipe, Some(q), &[(o, Some(o2))]);
    let p = Pipe {
        odm: SplitPipes::one(q),
        overlays: [overlay(o, Some(o2), OVERLAY_A), None, None],
        ..target(pipe)
    };
    if p.trees() != [[pipe, o], [q, o2]] {
        return TestResult::Fail("segment trees");
    }
    if run(e.start_fetch(p)).is_err() {
        return TestResult::Fail("ODM start with overlay");
    }
    for (opp, top) in [(pipe, o), (q, o2)] {
        if e.io.get(l.out_mux(opp)) & 0xf != l.inst_field(top)
            || e.io.get(l.mpcc(top, BOTTOM)) & 0xf != l.inst_field(opp)
            || e.io.get(l.mpcc(top, OPP_ID)) & 0xf != l.inst_field(opp)
            || e.io.get(l.mpcc(top, MPCC_CONTROL)) & 3 != 3
            || e.io.get(l.mpcc(opp, MPCC_CONTROL)) & 3 != 2
            || e.io.get(l.mpcc(opp, BOTTOM)) & 0xf != 0xf
            || e.io.get(l.opp(opp, DPG)) & DPG_FIELDS != 0
        {
            return TestResult::Fail("one tree per OPP");
        }
    }
    *e.io.regs.entry(l.hubp(o2, HUBP_CONTROL)).or_default() |= 0x1000_0000;
    if e.underflow(pipe) != Err(Error::Underflow(l.hubp(o2, HUBP_CONTROL))) {
        return TestResult::Fail("overlay right half underflow");
    }
    *e.io.regs.entry(l.hubp(o2, HUBP_CONTROL)).or_default() &= !0x1000_0000;
    if run(e.stop_fetch(p)).is_err() {
        return TestResult::Fail("ODM overlay stop");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_scanout_odm_overlay_builds_a_tree_per_segment
);

/// An underlay (an overlay whose zpos is below the primary's) is the
/// bottom of the tree: the primary blends over it and still feeds its own
/// OPP, the overlay above both; the stream's color goes on the top.
fn dcn401_scanout_underlay_goes_below_the_primary() -> TestResult {
    underlay_on(1, 3, 0)
}
/// The test above on pipes (pipe, under, over).
fn underlay_on(pipe: u8, under: u8, over: u8) -> TestResult {
    let mut e = staged_planes(pipe, None, &[under, over]);
    let l = e.layout;
    stage_records(&mut e, pipe, None, &[(under, None), (over, None)]);
    let p = Pipe {
        overlays: [
            Some(OverlayScanout {
                underlay: true,
                ..overlay(under, None, OVERLAY_A).unwrap()
            }),
            overlay(over, None, OVERLAY_B),
            None,
        ],
        ..target(pipe)
    };
    if p.trees() != [[under, pipe, over]] {
        return TestResult::Fail("underlay at the bottom of the tree");
    }
    if run(e.start_fetch(p)).is_err() {
        return TestResult::Fail("start with an underlay");
    }
    let sel = |q: u8, r| e.io.get(l.mpcc(q, r)) & 0xf;
    let mode = |q: u8| e.io.get(l.mpcc(q, MPCC_CONTROL)) & 3;
    if e.io.get(l.out_mux(pipe)) & 0xf != l.inst_field(over)
        || sel(over, BOTTOM) != l.inst_field(pipe)
        || sel(pipe, BOTTOM) != l.inst_field(under)
        || sel(under, BOTTOM) != 0xf
        || [under, pipe, over]
            .iter()
            .any(|&q| sel(q, OPP_ID) != l.inst_field(pipe))
        || (mode(under), mode(pipe), mode(over)) != (2, 3, 3)
        || e.io.get(l.opp(pipe, DPG)) & DPG_FIELDS != 0
    {
        return TestResult::Fail("primary blends over the underlay");
    }
    for live in p.live(None) {
        if e.live_pipe(live).is_err() {
            return TestResult::Fail("live underlay witness");
        }
    }
    if run(e.stop_fetch(p)).is_err() || e.staged(p).is_err() {
        return TestResult::Fail("stop with an underlay");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_scanout_underlay_goes_below_the_primary
);

/// ODM 4:1: one master lock covers every segment. Start connects each
/// segment's MPCC to its own OPP, releases every DPG and unblanks every
/// HUBP at one VUPDATE; a flip re-addresses all four; stop returns each to
/// staged black.
fn dcn401_scanout_odm_four_segments_under_one_lock() -> TestResult {
    let pipe = 0u8;
    let odm = SplitPipes::new(&[3, 2, 1]).unwrap();
    let mut e = staged_planes(pipe, None, &[3, 2, 1]);
    e.status.surfaces[usize::from(pipe)] = Some(SurfaceApplied {
        request: SurfaceRequest {
            pipe,
            width: 7680,
            height: 4320,
            format: SurfaceFormat::Xrgb8888,
            odm,
            mpc: SplitPipes::NONE,
            plane: None,
            surface: PlaneSurface::LINEAR,
        },
        address: ADDR,
        pitch_bytes: 7680 * 4,
        bytes: 7680 * 4 * 4320,
        chroma: None,
    });
    let p = Pipe {
        odm,
        ..target(pipe)
    };
    if p.trees() != [[0], [3], [2], [1]] {
        return TestResult::Fail("one tree per segment");
    }
    if run(e.start_fetch(p)).is_err() {
        return TestResult::Fail("ODM 4:1 start");
    }
    let l = e.layout;
    for s in [0u8, 3, 2, 1] {
        if e.io.get(l.mpcc(s, TOP)) & 0xf != l.inst_field(s)
            || e.io.get(l.mpcc(s, OPP_ID)) & 0xf != l.inst_field(s)
            || e.io.get(l.out_mux(s)) & 0xf != l.inst_field(s)
            || e.io.get(l.opp(s, DPG)) & DPG_FIELDS != 0
            || e.io.get(l.hubp(s, HUBP_CONTROL)) & BLANK_EN != 0
        {
            return TestResult::Fail("segment routes and unblank");
        }
    }
    if e.live_fetch(pipe, ADDR).is_err() {
        return TestResult::Fail("every segment live");
    }
    let back = ADDR + 0x0200_0000;
    if run(e.flip_to(Pipe { address: back, ..p })).is_err()
        || [0u8, 3, 2, 1]
            .iter()
            .any(|&s| e.io.get(l.hubp(s, EARLIEST_INUSE)) != back as u32)
    {
        return TestResult::Fail("ODM 4:1 flip");
    }
    if run(e.stop_fetch(Pipe { address: back, ..p })).is_err() {
        return TestResult::Fail("ODM 4:1 stop");
    }
    for s in [0u8, 3, 2, 1] {
        if e.io.get(l.mpcc(s, TOP)) & 0xf != 0xf
            || e.io.get(l.opp(s, DPG)) & DPG_FIELDS != BLACK
            || e.io.get(l.hubp(s, HUBP_CONTROL)) & 3 != 3
        {
            return TestResult::Fail("segment back to staged black");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_scanout_odm_four_segments_under_one_lock
);

/// MPC combine: an MPC-combined primary's two DPPs and an MPC-combined
/// overlay's two all blend in the stream's one MPCC tree, each plane's
/// second slice directly below its first (acquire_dpp_pipe_and_add_mpc_
/// slice links it as the bottom pipe), built from the top down as
/// mpc1_insert_plane does; only the stream's OPP leaves the DPG; every
/// slice fetches its plane's address; stop detaches every MPCC.
fn dcn401_scanout_mpc_slices_blend_in_one_tree() -> TestResult {
    let (pipe, slice, o, o_slice) = (0u8, 3u8, 2u8, 1u8);
    let mut e = staged_planes(pipe, None, &[slice, o, o_slice]);
    let l = e.layout;
    let p = Pipe {
        mpc: SplitPipes::one(slice),
        overlays: [
            Some(OverlayScanout {
                pipe: o,
                odm: SplitPipes::NONE,
                mpc: SplitPipes::one(o_slice),
                address: OVERLAY_A,
                underlay: false,
            }),
            None,
            None,
        ],
        ..target(pipe)
    };
    if p.trees() != [[slice, pipe, o_slice, o]] || p.pipes().collect::<alloc::vec::Vec<_>>() != [0]
    {
        return TestResult::Fail("MPC slice tree");
    }
    e.io.log.clear();
    if run(e.start_fetch(p)).is_err() {
        return TestResult::Fail("MPC combine start");
    }
    let w = |q: u8, r: u64, v: u32| (l.mpcc(q, r), v);
    let c = |q: u8, v: u32| (l.mpcc(q, MPCC_CONTROL), v);
    let insert = |q: u8| {
        [
            w(q, BOTTOM, 0xf),
            c(q, 2),
            w(q, TOP, l.inst_field(q)),
            w(q, OPP_ID, l.inst_field(pipe)),
            w(q, UPDATE_LOCK, l.inst_field(pipe)),
        ]
    };
    let mut want = alloc::vec::Vec::new();
    want.extend(insert(o));
    want.push((l.out_mux(pipe), l.inst_field(o)));
    for (q, above) in [(o_slice, o), (pipe, o_slice), (slice, pipe)] {
        want.extend(insert(q));
        want.extend([w(above, BOTTOM, l.inst_field(q)), c(above, 3)]);
    }
    if tree_writes(l, &e.io.log, &[pipe, slice, o, o_slice]) != want {
        return TestResult::Fail("mpc1_insert_plane order with MPC slices");
    }
    for (q, address) in [
        (pipe, ADDR),
        (slice, ADDR),
        (o, OVERLAY_A),
        (o_slice, OVERLAY_A),
    ] {
        if e.io.get(l.hubp(q, HUBP_CONTROL)) & BLANK_EN != 0
            || e.io.get(l.hubp(q, EARLIEST_INUSE)) != address as u32
        {
            return TestResult::Fail("slices live at their planes' addresses");
        }
    }
    if e.io.get(l.opp(pipe, DPG)) & DPG_FIELDS != 0
        || [slice, o, o_slice]
            .iter()
            .any(|&q| e.io.get(l.opp(q, DPG)) != BLACK)
    {
        return TestResult::Fail("only the stream's OPP leaves black");
    }
    let live = p.live(None);
    if live.len() != 4 || live.iter().any(|&lp| e.live_pipe(lp).is_err()) {
        return TestResult::Fail("live witness of every slice");
    }
    if live
        .iter()
        .find(|lp| lp.pipe == slice)
        .is_none_or(|lp| lp.routes != [0xf, slice, 0xf, pipe, pipe] || lp.address != ADDR)
    {
        return TestResult::Fail("second slice at the bottom of the tree");
    }
    if run(e.stop_fetch(p)).is_err() || e.staged(p).is_err() {
        return TestResult::Fail("MPC combine stop");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_scanout_mpc_slices_blend_in_one_tree
);

/// ODM, overlays, underlays, flips, cursors and the start/stop evidence on
/// harvested boards (pipe 0, pipe 1, pipes 1 and 2 fused): the model
/// addresses the pool's instances through the owner's layout and refuses
/// any fused one (harvest::guard), and every tree selector, OPP source and
/// VTG is checked as the pipe's instance.
fn dcn401_scanout_runs_on_harvested_boards() -> TestResult {
    harvest::harvested(2, || {
        let count = crate::amdgpu_rdna4::pipe_pool().count();
        let top = count - 1;
        let mut cases: alloc::vec::Vec<TestResult> = alloc::vec![
            dcn401_scanout_starts_and_stops_under_one_lock_with_hardware_evidence(),
            dcn401_scanout_requires_lock_latch_and_no_underflow(),
            dcn401_scanout_entry_requires_running_black_video_and_deadlines(),
            dcn401_scanout_framebuffer_requires_live_owned_scanout(),
            dcn401_scanout_cursor_programs_under_its_lock_and_stops_with_fetch(),
            odm_on(0, top),
            odm_on(top, 0),
        ];
        if count > 2 {
            cases.extend([
                dcn401_scanout_live_fetch_is_recognised_exactly(),
                dcn401_scanout_flip_latches_new_address_under_the_lock(),
                overlays_on(0, 1, 2),
                overlays_on(2, 0, 1),
                underlay_on(1, 2, 0),
            ]);
        }
        cases
            .into_iter()
            .find(|r| *r != TestResult::Pass)
            .unwrap_or(TestResult::Pass)
    })
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_scanout_runs_on_harvested_boards
);
