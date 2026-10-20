//! Owner-level scanout over the whole staged chain: a DML plan drives the
//! surface, VMID context, timing, black DPG, DPP, MPC, requestor and
//! deadlines through their real `prepare_*` steps, a TMDS HDMI link and its
//! black video run on that pipe, and only then does `Surfaces::start_scanout`
//! re-bind every owner and connect fetch. The OTG lock/VUPDATE latch model
//! below wraps the HDMI transmitter model, so route, latch, write-loss,
//! cancellation, link-loss and owner-change cases run against the same
//! retained state the modeset builds, on every pipe with independent
//! PHY/stream/pipe routing.
use super::*;
use crate::amdgpu_dcn401_dml as dml;
use crate::amdgpu_dcn401_otg::tests::hdmi_link::{dio, path, phy, resync, Firmware, TmdsIo};
use alloc::sync::Arc;
use core::future::Future;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

// Native register offsets (dword index, per-pipe stride), written out here
// rather than borrowed from the driver so the model checks the driver.
fn otg(p: u8, r: u64) -> u64 {
    BASE + (r + u64::from(p) * 0x80) * 4
}
fn opp(p: u8, r: u64) -> u64 {
    BASE + (r + u64::from(p) * 0x5a) * 4
}
fn mpcc(p: u8, r: u64) -> u64 {
    MPC_BASE + (r + u64::from(p) * 0x15) * 4
}
fn optc_input(p: u8) -> u64 {
    BASE + (0x1aca + u64::from(p) * 0x10) * 4
}
fn og(p: u8, r: u64) -> u64 {
    MPC_BASE + (r + u64::from(p) * 0x5e) * 4
}
fn dpp_reg(p: u8, r: u64) -> u64 {
    BASE + (r + u64::from(p) * 0x16b) * 4
}
const LOCK: u64 = 0x1b89;
const LOCK_REQUEST: u32 = 1;
const LOCK_STATUS: u32 = 0x100;
const FRAME_COUNT: u64 = 0x1b4d;
const HUBP_CONTROL: u64 = 0x5f4;
const BLANK_EN: u32 = 1;
const NO_OUTSTANDING: u32 = 2;
const HUBP_UNDERFLOW: u32 = 0x1000_0000;
const HUBP_UNDERFLOW_CLEAR: u32 = 0x8000_0000;
const OPTC_UNDERFLOW: u32 = 0x400;
const OPTC_UNDERFLOW_CLEAR: u32 = 0x1000;
const ADDRESS: u64 = 0x60a;
const ADDRESS_HIGH: u64 = 0x60b;
const FLIP: u64 = 0x613;
const FLIP_PENDING: u32 = 0x100;
const EARLIEST_INUSE: u64 = 0x61c;
const EARLIEST_INUSE_HIGH: u64 = 0x61d;
const DPG: u64 = 0x1854;
const DPG_PENDING: u64 = 0x185b;
const MPC_STATUS: u64 = 0xe;
const TOP: u64 = 0;
const GLOBAL_TIMER: u64 = 0x527;
const TX_CLOCKS: u64 = 0x2931;
const CRYSTAL_KHZ: u32 = 100_000;
const OGAM_CONTROL: u64 = 0x7e;
const GAMUT_MODE: u64 = 0xc9;
const PRE_DEGAM: u64 = 0xced;

/// The OTG master-update lock and the VUPDATE that follows its release:
/// the lock is granted on request (unless withheld), and `latch_delay`
/// register reads after the release the double-buffered state latches. The frame counter advances on every read unless frozen.
struct ScanIo {
    inner: TmdsIo,
    pipe: u8,
    armed: bool,
    grant: bool,
    latch_delay: u32,
    pending_latch: Option<u32>,
    frozen: bool,
    frame: u32,
    /// A write to this address is lost (the register keeps its value).
    drop: Option<u64>,
    /// Raise HUBP underflow after this many armed writes.
    underflow_after: Option<usize>,
    writes: usize,
    /// Set once the lock has been requested (a cancellation point).
    lock_requested: Arc<AtomicBool>,
    pause_wait: bool,
}
impl ScanIo {
    fn get(&mut self, at: u64) -> u32 {
        self.inner.inner.regs.get(&at).copied().unwrap_or(0)
    }
    fn put(&mut self, at: u64, value: u32) {
        self.inner.inner.regs.insert(at, value);
    }
    fn latch(&mut self) {
        let p = self.pipe;
        let low = self.get(h(p, ADDRESS));
        let high = self.get(h(p, ADDRESS_HIGH));
        self.put(h(p, EARLIEST_INUSE), low);
        self.put(h(p, EARLIEST_INUSE_HIGH), high);
        let flip = self.get(h(p, FLIP)) & !FLIP_PENDING;
        self.put(h(p, FLIP), flip);
        // The OGAM mode/RAM select and gamut remap set latch into their
        // CURRENT fields.
        let ogam = self.get(og(p, OGAM_CONTROL));
        self.put(
            og(p, OGAM_CONTROL),
            (ogam & 0x7f) | (ogam & 3) << 7 | (ogam >> 2 & 1) << 9,
        );
        let gamut = self.get(og(p, GAMUT_MODE));
        self.put(og(p, GAMUT_MODE), (gamut & 0x7f) | (gamut & 3) << 7);
        self.put(opp(p, DPG_PENDING), 0);
        let connected = self.get(mpcc(p, TOP)) & 0xf != 0xf;
        self.put(mpcc(p, MPC_STATUS), if connected { 2 } else { 5 });
        let control = self.get(h(p, HUBP_CONTROL));
        self.put(
            h(p, HUBP_CONTROL),
            if connected {
                control & !NO_OUTSTANDING
            } else {
                control | NO_OUTSTANDING
            },
        );
    }
}
impl Io for ScanIo {
    fn wait_poll_limit(&self) -> Option<u32> {
        // After arming, the longest successful latch needs 200 reads. Keep
        // frozen frames/latches bounded without racing the host clock.
        self.armed.then_some(256)
    }
    fn pause_wait(&self) -> bool {
        self.pause_wait
    }
    fn read(&mut self, at: u64) -> u32 {
        if !self.armed {
            return self.inner.read(at);
        }
        let p = self.pipe;
        if at == otg(p, FRAME_COUNT) {
            if !self.frozen {
                self.frame = self.frame.wrapping_add(1);
            }
            return self.frame & 0xff_ffff;
        }
        // VUPDATE arrives `latch_delay` register reads after the release.
        match self.pending_latch {
            Some(0) => {
                self.pending_latch = None;
                self.latch();
            }
            Some(n) => self.pending_latch = Some(n - 1),
            None => {}
        }
        self.inner.read(at)
    }
    fn write(&mut self, at: u64, value: u32) {
        if !self.armed {
            return self.inner.write(at, value);
        }
        self.writes += 1;
        if self.drop == Some(at) {
            self.drop = None;
            return;
        }
        let p = self.pipe;
        let mut value = value;
        if at == otg(p, LOCK) {
            if value & LOCK_REQUEST != 0 {
                self.lock_requested.store(true, Ordering::SeqCst);
                if self.grant {
                    value |= LOCK_STATUS;
                }
            } else {
                value &= !LOCK_STATUS;
                self.pending_latch = Some(self.latch_delay);
            }
        }
        if at == opp(p, DPG) {
            self.put(opp(p, DPG_PENDING), 1);
        }
        if at == h(p, ADDRESS) {
            let flip = self.get(h(p, FLIP)) | FLIP_PENDING;
            self.put(h(p, FLIP), flip);
        }
        if at == h(p, HUBP_CONTROL) {
            if value & BLANK_EN != 0 {
                value |= NO_OUTSTANDING;
            }
            if value & HUBP_UNDERFLOW_CLEAR != 0 {
                value &= !(0x7000_0000 | HUBP_UNDERFLOW_CLEAR);
            }
        }
        if at == optc_input(p) && value & OPTC_UNDERFLOW_CLEAR != 0 {
            value &= !(OPTC_UNDERFLOW | OPTC_UNDERFLOW_CLEAR);
        }
        self.inner.write(at, value);
        if self.underflow_after == Some(self.writes) {
            let control = self.get(h(p, HUBP_CONTROL)) | HUBP_UNDERFLOW;
            self.put(h(p, HUBP_CONTROL), control);
        }
    }
}

fn soc() -> dml::Soc {
    dml::Soc {
        umc_channels: 16,
        uclk_khz: 1_250_000,
        fclk_khz: [300_000, 2_500_000],
        dcfclk_khz: [200_000, 1_564_000],
        socclk_khz: 300_000,
        dispclk_max_khz: 2_000_000,
        dppclk_max_khz: 2_000_000,
        dentist_vco_khz: 4_500_000,
        dchub_refclk_khz: 50_000,
    }
}
/// CEA 640x480p60, the plan every owner below is derived from.
fn plan() -> dml::Plan {
    let timing = Timing {
        pixel_clock_khz: 25_175,
        h_active: 640,
        h_total: 800,
        h_front_porch: 16,
        h_sync_width: 96,
        v_active: 480,
        v_total: 525,
        v_front_porch: 10,
        v_sync_width: 2,
        h_sync_positive: false,
        v_sync_positive: false,
    };
    dml::admit(
        &soc(),
        &dml::Mode {
            timing,
            pitch: 640,
            bytes_per_pixel: 4,
            ycbcr420: false,
            dsc: None,
        },
    )
    .unwrap()
}
/// The plane mode and pixel clock the modeset derives from `plan` for TMDS.
fn hdmi_mode(pipe: u8, plan: &dml::Plan) -> Mode {
    let t = Request {
        pipe,
        signal: Signal::Tmds,
        ycbcr420: false,
        dsc: None,
        odm: None,
        timing: plan.mode.timing,
        sync: plan.sync,
    };
    let mut c = clock(t);
    c.request.dpp_khz = plan.clocks.dppclk_khz;
    c.request.pixel = dccg::PixelClock::Tmds {
        divider: dccg::TmdsDivider::By4,
    };
    c.global.request.display_khz = plan.clocks.dispclk_khz;
    c.global.request.dpp_khz = plan.clocks.dpprefclk_khz;
    c.global.display_khz = plan.clocks.dispclk_khz;
    c.global.dpp_khz = plan.clocks.dpprefclk_khz;
    c.global.dcf_floor_khz = plan.soc.dcfclk_khz[1];
    c.global.memory_floor_khz = plan.soc.uclk_khz;
    Mode {
        surface: SurfaceRequest {
            pipe,
            width: 640,
            height: 480,
            format: SurfaceFormat::Xrgb8888,
            odm: None,
            plane: None,
        },
        // Room for a back buffer of the same geometry.
        bytes: 2 * 640 * 4 * 480,
        timing: t,
        clock: c,
    }
}

/// Everything a live scanout retains, staged and with HDMI black video
/// running: (transmitter, stream, pipe) are independent.
struct Chain {
    backing: Vec<u32>,
    pool: Pool,
    e: Engine<ScanIo>,
    surfaces: Surfaces,
    clock: dccg::Applied,
    address: u64,
    pipe: u8,
}
fn chain(phy_index: u8, stream: u8, pipe: u8) -> Chain {
    let plan = plan();
    let mode = hdmi_mode(pipe, &plan);
    let (backing, pool, mut e, mut surfaces, clock) =
        ready_requests_with(pipe, [21, 0, 0, 0, 0], mode);
    e.io.delay = [0; 5];
    run(surfaces.prepare_requestor(&mut e, pipe, || Ok((clock, config())))).unwrap();
    e.io.fake().regs.insert(BASE + GLOBAL_TIMER * 4, 0x1002);
    let deadlines =
        run(surfaces.prepare_deadlines(&mut e, pipe, &plan, CRYSTAL_KHZ, || Ok((clock, config()))));
    assert_eq!(deadlines.map(|d| d.plan), Ok(plan), "deadlines");
    let address = e.status.surfaces[usize::from(pipe)].unwrap().address;
    // The plane wrappers' staging handshakes are done; keep their register
    // file under the HDMI transmitter model, as fixture_with arranges it.
    let mut fake = e.io.inner.surface.inner;
    for i in 0..4 {
        fake.regs.insert(phy(i, 0x2943), 0x03030303);
    }
    fake.regs.insert(dio(phy_index, 0x20bc), 3 << 28);
    fake.regs.insert(resync(phy_index), 0x30);
    fake.encoder_stall = 1 << stream;
    // Plane retirement is over: MPCC status is the lock/latch model's now.
    fake.disconnecting = false;
    fake.writes.clear();
    let event = Arc::new(AtomicU8::new(0));
    let writes = Arc::new(AtomicUsize::new(0));
    let mut fw = Firmware {
        ready: true,
        commands: Vec::new(),
        event: event.clone(),
        writes: writes.clone(),
        fail: None,
    };
    let mut e = Engine {
        io: ScanIo {
            inner: TmdsIo {
                inner: fake,
                phy: phy_index,
                stream,
                event,
                writes,
                on: false,
                dead: false,
                az: alloc::collections::BTreeMap::new(),
                az_index: [0; 4],
            },
            pipe,
            armed: false,
            pause_wait: false,
            grant: true,
            latch_delay: 0,
            pending_latch: None,
            frozen: false,
            frame: 7,
            drop: None,
            underflow_after: None,
            writes: 0,
            lock_requested: Arc::new(AtomicBool::new(false)),
        },
        authority: e.authority,
        layout: e.layout,
        status: e.status,
        displays: e.displays,
    };
    let request = crate::amdgpu_dcn401_otg::HdmiLinkRequest {
        stream,
        pipe,
        avi: Default::default(),
        hdr: None,
    };
    run(e.prepare_hdmi_link(&mut fw, path(phy_index), request, clock)).unwrap();
    run(e.start_hdmi_video(path(phy_index), clock)).unwrap();
    assert_eq!(e.status.state, State::HdmiVideoRunning(stream));
    e.io.armed = true;
    Chain {
        backing,
        pool,
        e,
        surfaces,
        clock,
        address,
        pipe,
    }
}
impl Chain {
    async fn start(&mut self) -> Result<ScanoutRunning, Error> {
        let c = self.clock;
        self.surfaces
            .start_scanout(&mut self.e, self.pipe, CRYSTAL_KHZ, || Ok((c, config())))
            .await
    }
    async fn check(&mut self) -> Result<u32, Error> {
        let c = self.clock;
        self.surfaces
            .check_scanout(&mut self.e, self.pipe, CRYSTAL_KHZ, || Ok((c, config())))
            .await
    }
    async fn stop(&mut self) -> Result<(), Error> {
        let c = self.clock;
        self.surfaces
            .stop_scanout(&mut self.e, self.pipe, CRYSTAL_KHZ, || Ok((c, config())))
            .await
    }
}
/// Poll `f` until `reached`, then drop it: cancellation at that point.
fn cancel_at(f: impl Future, mut reached: impl FnMut() -> bool) {
    let mut f = core::pin::pin!(f);
    let deadline = narf_time::Deadline::after_us(1_000_000);
    run(core::future::poll_fn(|cx| {
        if f.as_mut().poll(cx).is_ready() {
            panic!("finished before the cancellation point");
        }
        if reached() {
            core::task::Poll::Ready(())
        } else {
            assert!(!deadline.expired(), "cancellation point not reached");
            cx.waker().wake_by_ref();
            core::task::Poll::Pending
        }
    }));
}

const ROUTES: [(u8, u8, u8); 4] = [(0, 0, 0), (1, 3, 2), (2, 1, 3), (3, 2, 1)];

fn dcn401_scanout_chain_runs_on_every_pipe_over_hdmi_video() -> TestResult {
    for (t, s, p) in ROUTES {
        let mut c = chain(t, s, p);
        let Ok(live) = run(c.start()) else {
            return TestResult::Fail("start over the staged chain");
        };
        if live.pipe != p
            || live.stream != s
            || live.address != c.address
            || c.e.status.state != State::ScanoutRunning(p)
            || c.e.status.scanout != Some(live)
        {
            return TestResult::Fail("running record");
        }
        // Routes are this pipe's own; no other pipe's MPCC was touched.
        for other in (0..4).filter(|o| *o != p) {
            if c.e.io.get(mpcc(other, TOP)) & 0xf != 0xf {
                return TestResult::Fail("another pipe's MPCC");
            }
        }
        if run(c.check()).is_err() {
            return TestResult::Fail("health check of a live scanout");
        }
        if run(c.stop()).is_err() || c.e.status.state != State::HdmiVideoRunning(s) {
            return TestResult::Fail("stop back to black video");
        }
        // Black video stays running and the pipe restarts from it.
        if run(c.start()).is_err() || run(c.stop()).is_err() {
            return TestResult::Fail("restart");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_scanout_chain_runs_on_every_pipe_over_hdmi_video
);

fn dcn401_scanout_chain_waits_for_delayed_latches_and_fails_lost_writes() -> TestResult {
    // The release latches several VUPDATE polls later; start still waits.
    let mut c = chain(1, 3, 2);
    c.e.io.latch_delay = 200;
    if run(c.start()).is_err() {
        return TestResult::Fail("delayed latch");
    }
    c.e.io.latch_delay = 200;
    if run(c.stop()).is_err() {
        return TestResult::Fail("delayed latch on stop");
    }
    // A lost write is caught by its readback at once; the pipe is
    // quarantined rather than reported running, and is not restartable.
    for (t, st, p, lost) in [(2, 1, 3, mpcc(3, TOP)), (0, 0, 0, opp(0, DPG))] {
        let mut c = chain(t, st, p);
        c.e.io.drop = Some(lost);
        if run(c.start()) != Err(Error::Readback(lost))
            || c.e.status.state != State::Failed(Error::Readback(lost))
            || run(c.start()) != Err(Error::Busy)
        {
            return TestResult::Fail("lost write");
        }
    }
    // A requested address is not presentation: with no VUPDATE latch the
    // start times out on EARLIEST_INUSE.
    let mut c = chain(1, 3, 2);
    c.e.io.latch_delay = u32::MAX;
    if run(c.start()) != Err(Error::Timeout(h(2, EARLIEST_INUSE))) {
        return TestResult::Fail("unlatched address accepted");
    }
    // A lock that is never granted fails before any route moves.
    let mut c = chain(3, 2, 1);
    c.e.io.grant = false;
    if run(c.start()).is_ok() || c.e.io.get(mpcc(1, TOP)) & 0xf != 0xf {
        return TestResult::Fail("ungranted lock");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_scanout_chain_waits_for_delayed_latches_and_fails_lost_writes
);

fn dcn401_scanout_chain_owner_changes_and_cancellation_quarantine() -> TestResult {
    // The clock owner changes while start waits for the latch.
    let mut c = chain(1, 3, 2);
    let first = c.clock;
    let mut changed = first;
    changed.request.dpp_khz += 1;
    let mut calls = 0;
    let result = run(c.surfaces.start_scanout(&mut c.e, 2, CRYSTAL_KHZ, || {
        calls += 1;
        Ok((if calls == 1 { first } else { changed }, config()))
    }));
    if result != Err(Error::Busy) || c.e.status.state != State::Failed(Error::Busy) {
        return TestResult::Fail("owner change during start");
    }
    // ... and while stop drains.
    let mut c = chain(0, 0, 0);
    let mine = c.clock;
    let mut other = mine;
    other.request.dpp_khz += 1;
    if run(c.start()).is_err() {
        return TestResult::Fail("start");
    }
    let mut calls = 0;
    let result = run(c.surfaces.stop_scanout(&mut c.e, 0, CRYSTAL_KHZ, || {
        calls += 1;
        Ok((if calls == 1 { mine } else { other }, config()))
    }));
    if result != Err(Error::Busy) || c.e.status.state != State::Failed(Error::Busy) {
        return TestResult::Fail("owner change during stop");
    }
    // Cancelled while waiting for the lock: retained, quarantined, and not
    // replayable.
    let mut c = chain(3, 2, 1);
    c.e.io.grant = false;
    c.e.io.pause_wait = true;
    let requested = c.e.io.lock_requested.clone();
    let clock = c.clock;
    cancel_at(
        c.surfaces
            .start_scanout(&mut c.e, 1, CRYSTAL_KHZ, || Ok((clock, config()))),
        || requested.load(Ordering::SeqCst),
    );
    if c.e.status.state != State::StartingScanout(1)
        || run(c.start()) != Err(Error::Busy)
        || run(c.check()) != Err(Error::Invalid)
    {
        return TestResult::Fail("cancelled start");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_scanout_chain_owner_changes_and_cancellation_quarantine
);

fn dcn401_scanout_chain_link_loss_and_underflow_while_running() -> TestResult {
    // The transmitter loses its clocks under a live scanout: the check
    // reports it without writing, and the pipe can still go back to black.
    let mut c = chain(2, 1, 3);
    if run(c.start()).is_err() {
        return TestResult::Fail("start");
    }
    let tx = phy(2, TX_CLOCKS);
    let lost = c.e.io.get(tx) & !0x6f0;
    c.e.io.put(tx, lost);
    let before = c.e.io.writes;
    if run(c.check()).is_ok() || c.e.io.writes != before {
        return TestResult::Fail("link loss not reported, or written");
    }
    if c.e.status.state != State::ScanoutRunning(3) || run(c.stop()).is_err() {
        return TestResult::Fail("stop after link loss");
    }
    // Frames stop advancing: start never reports fresh frames.
    let mut c = chain(0, 0, 0);
    c.e.io.frozen = true;
    if !matches!(run(c.start()), Err(Error::Timeout(at)) if at == otg(0, FRAME_COUNT)) {
        return TestResult::Fail("frozen timing");
    }
    // Underflow under a live scanout returns to black video and retains the
    // diagnostics; the pipe starts again afterwards.
    let mut c = chain(1, 3, 2);
    if run(c.start()).is_err() {
        return TestResult::Fail("start");
    }
    let control = c.e.io.get(h(2, HUBP_CONTROL)) | HUBP_UNDERFLOW;
    c.e.io.put(h(2, HUBP_CONTROL), control);
    if !matches!(run(c.check()), Err(Error::Underflow(_)))
        || c.e.status.state != State::HdmiVideoRunning(3)
        || c.e.status.scanout.is_some()
        || c.e.status.underflow.map(|u| (u.pipe, u.address)) != Some((2, c.address))
    {
        return TestResult::Fail("underflow recovery");
    }
    if run(c.start()).is_err() || run(c.stop()).is_err() {
        return TestResult::Fail("restart after underflow");
    }
    // Underflow during start itself is recovered the same way.
    let mut c = chain(3, 2, 1);
    c.e.io.underflow_after = Some(12);
    if !matches!(run(c.start()), Err(Error::Underflow(_)))
        || c.e.status.state != State::HdmiVideoRunning(2)
    {
        return TestResult::Fail("underflow during start");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_scanout_chain_link_loss_and_underflow_while_running
);

impl Chain {
    /// The CPU word of the surface at GPU address `address` in the
    /// fixture's VRAM backing (the pool maps 0x8_0010_2000 at offset 0).
    fn vram(&self, address: u64, offset: u64) -> u32 {
        let base = (self.backing.as_ptr() as u64 + 4095) & !4095;
        let at = base + (address - 0x8_0010_2000) + offset;
        // SAFETY: inside the fixture-owned backing the pool maps.
        unsafe { (at as *const u32).read_volatile() }
    }
    async fn flip(&mut self) -> Result<FlipDone, Error> {
        let c = self.clock;
        self.surfaces
            .flip(&mut self.e, self.pipe, CRYSTAL_KHZ, || Ok((c, config())))
            .await
    }
}

fn dcn401_scanout_chain_live_updates_go_through_the_back_buffer() -> TestResult {
    for (t, s, p) in ROUTES {
        let mut c = chain(t, s, p);
        if run(c.start()).is_err() {
            return TestResult::Fail("start");
        }
        let row = [0x00ff_8040u32; 640];
        // No back buffer yet: nothing to write.
        if c.surfaces.upload_back(&mut c.e, p, 0, 0, &row) != Err(Error::Invalid) {
            return TestResult::Fail("upload without a back buffer");
        }
        let Ok(back) = run(c.surfaces.prepare_back(&mut c.e, &c.pool, p, config())) else {
            return TestResult::Fail("back buffer under live scanout");
        };
        let front = c.address;
        if back == front || c.e.status.state != State::ScanoutRunning(p) {
            return TestResult::Fail("back buffer allocation");
        }
        for (x, y, n) in [(0, 480, 1), (639, 0, 2), (0, 0, 0)] {
            if c.surfaces.upload_back(&mut c.e, p, x, y, &row[..n]) != Err(Error::Invalid) {
                return TestResult::Fail("out-of-bounds upload");
            }
        }
        // The live front is never written: the frame goes to the back.
        let front_before = c.vram(front, 0);
        for y in 0..480 {
            if c.surfaces.upload_back(&mut c.e, p, 0, y, &row).is_err() {
                return TestResult::Fail("live back-buffer upload");
            }
        }
        if c.vram(front, 0) != front_before || c.vram(back, 2560 * 479 + 4 * 639) != 0x00ff_8040 {
            return TestResult::Fail("frame landed in the wrong buffer");
        }
        let Ok(done) = run(c.flip()) else {
            return TestResult::Fail("flip to the uploaded frame");
        };
        if done.front != back || done.back != front {
            return TestResult::Fail("flip swapped the wrong buffers");
        }
        // The previous front is now the back buffer and takes the next frame.
        if c.surfaces.upload_back(&mut c.e, p, 0, 0, &[1]).is_err() || c.vram(front, 0) != 1 {
            return TestResult::Fail("next frame into the old front");
        }
        // Not while a flip is in transition, nor after the pipe stopped.
        c.e.io.grant = false;
        c.e.io.pause_wait = true;
        let requested = c.e.io.lock_requested.clone();
        requested.store(false, Ordering::SeqCst);
        let clock = c.clock;
        cancel_at(
            c.surfaces
                .flip(&mut c.e, p, CRYSTAL_KHZ, || Ok((clock, config()))),
            || requested.load(Ordering::SeqCst),
        );
        if c.e.status.state != State::Flipping(p)
            || c.surfaces.upload_back(&mut c.e, p, 0, 0, &row) != Err(Error::Busy)
        {
            return TestResult::Fail("upload during a flip");
        }
    }
    let mut c = chain(0, 0, 0);
    if run(c.start()).is_err()
        || run(c.surfaces.prepare_back(&mut c.e, &c.pool, 0, config())).is_err()
        || run(c.stop()).is_err()
        || c.surfaces.upload_back(&mut c.e, 0, 0, 0, &[1]) != Err(Error::Busy)
    {
        return TestResult::Fail("upload after stop");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_scanout_chain_live_updates_go_through_the_back_buffer
);

/// A second display selected next to a live one sees exactly the first
/// one's resources as siblings, may retire planes and stage timing on its
/// own pipes without disturbing the live scanout, and may not take the
/// live display's pipe; the first display then checks and stops as before.
fn dcn401_second_display_leaves_the_live_one_alone() -> TestResult {
    let (t, s, p) = (1, 3, 2);
    let mut c = chain(t, s, p);
    let Ok(live) = run(c.start()) else {
        return TestResult::Fail("first display start");
    };
    // Records of display 0 stay put; display 1 starts empty.
    if c.e.select_display(1).is_err() || c.e.status.state != State::Ready {
        return TestResult::Fail("select an idle second display");
    }
    let held = c.e.displays.siblings;
    let mut want = Siblings {
        pipes: 1 << p,
        det: 1 << p,
        transmitters: 1 << t,
        streams: 1 << s,
        hpo: 0,
        hpo_links: 0,
        frl: false,
        mst: 0,
        live: [None; 4],
    };
    want.live[usize::from(p)] = Some((live.address, false));
    if held != want {
        return TestResult::Fail("siblings derived from the live display");
    }
    // The other pipes' MPCCs and HUBPs drain at once in this model.
    for q in (0..4).filter(|&q| q != p) {
        c.e.io.put(mpcc(q, MPC_STATUS), 5);
        c.e.io.put(h(q, HUBP_CONTROL), BLANK_EN | NO_OUTSTANDING);
    }
    let Ok(retired) = run(c.e.retire_planes()) else {
        return TestResult::Fail("plane retirement next to a live display");
    };
    if retired.blanked & 1 << p != 0
        || retired.powered_off & 1 << p != 0
        || c.e.io.get(mpcc(p, TOP)) & 0xf != u32::from(p)
        || c.e.live_segment(p, live.address, false).is_err()
    {
        return TestResult::Fail("live display's planes touched");
    }
    let plan = plan();
    // The live display's pipe belongs to it.
    // SAFETY: the model has no external CPU or GPU references.
    let sibling_release = unsafe { c.surfaces.release(&mut c.e, p) };
    // SAFETY: as above; the idle pipe has no buffers or outstanding accesses.
    let idle_release = unsafe { c.surfaces.release(&mut c.e, 0) };
    if sibling_release != Err(Error::Busy)
        || idle_release != Ok(0)
        || c.e.live_segment(p, live.address, false).is_err()
    {
        return TestResult::Fail("surface retirement stole a live sibling");
    }
    let own = hdmi_mode(p, &plan);
    if run(c.e.prepare(own.timing, own.clock)) != Err(Error::Busy) {
        return TestResult::Fail("timing staged on another display's pipe");
    }
    let q = 0;
    let other = hdmi_mode(q, &plan);
    if run(c.e.prepare(other.timing, other.clock)).is_err() {
        return TestResult::Fail("timing staged next to a live display");
    }
    if c.e.select_display(0).is_err() || c.e.status.scanout != Some(live) {
        return TestResult::Fail("first display's records restored");
    }
    if c.e.displays.siblings.pipes != 1 << q || c.e.displays.siblings.live != [None; 4] {
        return TestResult::Fail("second display's staged pipe as sibling");
    }
    if run(c.check()).is_err() || run(c.stop()).is_err() {
        return TestResult::Fail("live display checked and stopped afterwards");
    }
    // A failed display keeps the selection: nothing else may run.
    c.e.status.state = State::Failed(Error::Busy);
    if c.e.select_display(1) != Err(Error::Busy) {
        return TestResult::Fail("selection away from a failed display");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_second_display_leaves_the_live_one_alone
);

fn dcn401_partial_activation_unwinds_native_link_video_and_scanout() -> TestResult {
    for stage in 0..4 {
        let mut c = chain(0, 0, 0);
        // The fixture leaves staging's flip pending for the scanout lock model.
        // Deliver its first VUPDATE while black video runs: retirement before
        // that event must correctly refuse the outstanding surface update.
        c.e.io.latch();
        let before = c.pool.available();
        let bytes = c.e.status.surfaces[0].unwrap().bytes.next_multiple_of(4096);
        match stage {
            0 => {
                // A link completed but video rejects its clock before writes.
                run(c.e.stop_hdmi_video(path(0))).unwrap();
                let mut wrong = c.clock;
                wrong.request.pipe = 1;
                assert!(run(c.e.start_hdmi_video(path(0), wrong)).is_err());
                assert_eq!(c.e.status.state, State::HdmiLinkReady(0));
            }
            1 => {
                // Black video completed; scanout's owner preflight rejects.
                assert_eq!(
                    run(c
                        .surfaces
                        .start_scanout(&mut c.e, 0, CRYSTAL_KHZ, || Err(Error::Busy))),
                    Err(Error::Busy)
                );
                assert_eq!(c.e.status.state, State::HdmiVideoRunning(0));
            }
            2 => {
                // Fetch completed; unsupported sink audio must not strand it.
                run(c.start()).unwrap();
                let mut info = crate::amdgpu_dcn401_otg::tests::hdmi_link::audio_info();
                info.modes[0].format = 2; // AC3 only, no supported LPCM
                info.mode_count = 1;
                assert_eq!(
                    run(c.e.start_hdmi_audio(path(0), info)),
                    Err(Error::Unsupported)
                );
                assert_eq!(c.e.status.state, State::ScanoutRunning(0));
                assert!(c.e.status.hdmi_audio.is_none());
                run(c.stop()).unwrap();
            }
            _ => {
                // Scanout wrote, then its native underflow recovery returned
                // to the last completed checkpoint (black video).
                c.e.io.underflow_after = Some(12);
                assert!(matches!(run(c.start()), Err(Error::Underflow(_))));
                assert_eq!(c.e.status.state, State::HdmiVideoRunning(0));
            }
        }
        if stage != 0 {
            run(c.e.stop_hdmi_video(path(0))).unwrap();
        }
        let mut firmware = Firmware {
            ready: true,
            commands: Vec::new(),
            event: c.e.io.inner.event.clone(),
            writes: c.e.io.inner.writes.clone(),
            fail: None,
        };
        run(c.e.stop_hdmi_link(&mut firmware, path(0))).unwrap();
        run(c.e.retire(0)).unwrap();
        assert!(
            run(c.e.retire_planes()).is_ok(),
            "planes after stage {stage}"
        );
        // SAFETY: fixture-owned VRAM with no published CPU/other-engine views;
        // actual native stop/retire phases above, fresh release proof below.
        assert_eq!(unsafe { c.surfaces.release(&mut c.e, 0) }, Ok(bytes));
        assert_eq!(c.pool.available(), before + bytes);
        assert!(c.e.status.surfaces[0].is_none());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_partial_activation_unwinds_native_link_video_and_scanout
);

fn dcn401_partial_activation_failure_keeps_native_quarantine() -> TestResult {
    let mut c = chain(0, 0, 0);
    let before = c.pool.available();
    c.e.io.drop = Some(opp(0, DPG));
    assert!(run(c.start()).is_err());
    assert!(matches!(c.e.status.state, State::Failed(_)));
    let writes = c.e.io.writes;
    // An earlier video checkpoint cannot override the failed fetch.
    assert_eq!(run(c.e.stop_hdmi_video(path(0))), Err(Error::Busy));
    assert_eq!(run(c.e.retire(0)), Err(Error::Busy));
    assert_eq!(run(c.e.retire_planes()), Err(Error::Busy));
    // SAFETY: fixture memory is never dereferenced by this refusal path.
    assert_eq!(unsafe { c.surfaces.release(&mut c.e, 0) }, Err(Error::Busy));
    assert_eq!(c.e.io.writes, writes);
    assert_eq!(c.pool.available(), before);
    assert!(c.e.status.surfaces[0].is_some());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_partial_activation_failure_keeps_native_quarantine
);

/// A CRTC color with every block in use, whose PWL has `points` entries.
fn color(points: u32, s3_12: bool) -> Arc<ColorProgram> {
    let lut: alloc::vec::Vec<u32> = (0..points).map(|i| i * 0x100).collect();
    Arc::new(ColorProgram {
        pre_degam_srgb: true,
        gamut: Some(GamutProgram {
            coef: [0x2000, 0, 0x2000, 0, 0x2000, 0],
            s3_12,
        }),
        ogam: Some(OgamProgram {
            start: [1, 2, 3],
            start_slope: [4, 5, 6],
            end_base: [7, 8, 9],
            end: [10, 11, 12],
            regions: [0x4004; 17],
            lut: [lut.clone(), lut.clone(), lut],
        }),
    })
}

/// dcn401_program_pipe's color at scanout start (under the start's lock,
/// latching with the plane) and amdgpu_dm's non-modeset updates of a live
/// scanout: alternate OGAM banks and gamut sets, bypass, the record across
/// stop and restart, health checks against it, and cancellation.
fn dcn401_scanout_chain_programs_crtc_color() -> TestResult {
    for (t, s, p) in ROUTES {
        let mut c = chain(t, s, p);
        // Not scanning out: recorded only.
        let first = color(195, false);
        let writes = c.e.io.writes;
        if run(c.e.set_color(p, Some(first.clone()))).is_err() || c.e.io.writes != writes {
            return TestResult::Fail("dark display color");
        }
        if run(c.start()).is_err() {
            return TestResult::Fail("start with color");
        }
        let latched = |c: &mut Chain, ogam: u32, gamut: u32, pre: u32| {
            c.e.io.get(og(p, OGAM_CONTROL)) & 0x387 == ogam
                && c.e.io.get(og(p, GAMUT_MODE)) & 0x183 == gamut
                && c.e.io.get(dpp_reg(p, PRE_DEGAM)) & 0x73 == pre
        };
        // RAM A and gamut set A, latched with the plane.
        if !latched(&mut c, 2 | 2 << 7, 1 | 1 << 7, 1)
            || c.e.status.colors[usize::from(p)]
                != (PipeColor {
                    pre_degam_srgb: true,
                    gamut: Some((1, false)),
                    ogam: Some(0),
                })
            || run(c.check()).is_err()
        {
            return TestResult::Fail("color at start");
        }
        // A live update: the other bank and set, latched before return.
        let second = color(195, true);
        if run(c.e.set_color(p, Some(second))).is_err()
            || c.e.status.state != State::ScanoutRunning(p)
            || !latched(&mut c, 2 | 4 | 2 << 7 | 1 << 9, 2 | 2 << 7, 1)
            || run(c.check()).is_err()
        {
            return TestResult::Fail("live color update");
        }
        // Back to bypass, live.
        if run(c.e.set_color(p, None)).is_err()
            || !latched(&mut c, 0, 0, 0)
            || c.e.status.colors[usize::from(p)] != PipeColor::default()
            || run(c.check()).is_err()
        {
            return TestResult::Fail("live bypass");
        }
        // The request survives stop and restart.
        if run(c.stop()).is_err()
            || run(c.e.set_color(p, Some(first.clone()))).is_err()
            || run(c.start()).is_err()
            || !latched(&mut c, 2 | 2 << 7, 1 | 1 << 7, 1)
            || run(c.check()).is_err()
        {
            return TestResult::Fail("color across restart");
        }
        // Cancelled inside the update's lock: the pipe is quarantined.
        c.e.io.grant = false;
        c.e.io.pause_wait = true;
        let requested = c.e.io.lock_requested.clone();
        requested.store(false, Ordering::SeqCst);
        cancel_at(c.e.set_color(p, Some(color(195, true))), || {
            requested.load(Ordering::SeqCst)
        });
        if c.e.status.state != State::UpdatingStream(p) {
            return TestResult::Fail("cancelled update not quarantined");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_scanout_chain_programs_crtc_color
);
