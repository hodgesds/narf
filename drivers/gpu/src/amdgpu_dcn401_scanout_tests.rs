use super::*;
use crate::amdgpu_dcn401_otg::tests::{engine, run};
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
    fn pipes(&self) -> impl Iterator<Item = u8> {
        core::iter::once(self.pipe).chain(self.odm)
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
        if at == self.layout.otg(self.pipe, FRAME_COUNT) {
            self.frame = self.frame.wrapping_add(1);
            return self.frame & FRAME_MASK;
        }
        self.get(at)
    }
    fn write(&mut self, at: u64, value: u32) {
        self.writes += 1;
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
    let e = engine();
    let l = e.layout;
    let mut hw = Hw {
        regs: BTreeMap::new(),
        layout: l,
        pipe,
        odm,
        grant: true,
        latch: true,
        underflow_after: None,
        writes: 0,
        frame: 7,
        triggers: alloc::vec::Vec::new(),
    };
    hw.regs.insert(l.otg(pipe, CONTROL), OTG_MASTER_EN);
    for q in core::iter::once(pipe).chain(odm) {
        for (at, value) in [
            (l.hubp(q, HUBP_CONTROL), 3 | u32::from(pipe) << 4),
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
    let (pipe, q) = (1u8, 3u8);
    let mut e = staged_odm(pipe, Some(q));
    let surface = SurfaceApplied {
        request: SurfaceRequest {
            pipe,
            width: 7680,
            height: 4320,
            format: SurfaceFormat::Xrgb8888,
            odm: Some(q),
            plane: None,
        },
        address: ADDR,
        pitch_bytes: 7680 * 4,
        bytes: 7680 * 4 * 4320,
    };
    e.status.surfaces[usize::from(pipe)] = Some(surface);
    let p = Pipe {
        odm: Some(q),
        ..target(pipe)
    };
    if run(e.start_fetch(p)).is_err() {
        return TestResult::Fail("ODM start");
    }
    let l = e.layout;
    for s in [pipe, q] {
        if e.io.get(l.mpcc(s, TOP)) & 0xf != u32::from(s)
            || e.io.get(l.mpcc(s, OPP_ID)) & 0xf != u32::from(s)
            || e.io.get(l.out_mux(s)) & 0xf != u32::from(s)
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
        odm: None,
        address: ADDR,
        black: BLACK,
        timeout_us: 2000,
        watch: true,
    }
}

fn dcn401_scanout_starts_and_stops_under_one_lock_with_hardware_evidence() -> TestResult {
    for pipe in 0..4 {
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
    for pipe in 0..4 {
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
    for pipe in 0..4 {
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
        };
        let at = [(
            pipe,
            super::cursor::placement(11, 20, (64, 48), (1920, 1080), (100_000, 148_500)),
        )];
        if e.program_cursor(a, &at).is_err() || e.verify_cursor(a, &at).is_err() {
            return TestResult::Fail("program cursor");
        }
        let l = e.layout;
        let lock = l.mpc_base + (0x2c5 + u64::from(pipe) * 5) * 4;
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
