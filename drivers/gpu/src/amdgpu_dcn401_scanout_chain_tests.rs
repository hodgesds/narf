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
use crate::amdgpu_dcn401_otg::tests::harvest::{self, Renamed};
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
    /// Further pipes (by bit) whose planes latch with `pipe`'s timing: a
    /// live display's overlays.
    extra: u8,
    /// DET retirements can outlive a VUPDATE. Active DET changes may be
    /// modeled as double buffered, so a pre-unlock wait cannot succeed.
    det_stall: u8,
    det_on_latch: bool,
    vupdate_owned: bool,
    vupdate_pause: bool,
    vupdate_error: Option<Error>,
    vupdate_started: Arc<AtomicBool>,
}
impl ScanIo {
    fn get(&mut self, at: u64) -> u32 {
        self.inner.inner.regs.get(&at).copied().unwrap_or(0)
    }
    fn put(&mut self, at: u64, value: u32) {
        self.inner.inner.regs.insert(at, value);
    }
    /// The pipes latching at the timing's VUPDATE.
    fn latching(&self) -> alloc::vec::Vec<u8> {
        let extra = self.extra;
        core::iter::once(self.pipe)
            .chain((0..4u8).filter(move |&q| extra & 1 << q != 0))
            .collect()
    }
    fn latch(&mut self) {
        for p in self.latching() {
            self.latch_pipe(p);
        }
    }
    fn latch_pipe(&mut self, p: u8) {
        if self.det_on_latch && self.det_stall & (1 << p) == 0 {
            let at = BASE + (0x4bb + u64::from(p)) * 4;
            let value = self.get(at);
            self.put(at, (value & !0x1f00) | (value & 0x1f) << 8);
        }
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
    async fn vupdate(&mut self, _pipe: u8, enable: bool) -> Result<(), Error> {
        self.vupdate_started.store(true, Ordering::SeqCst);
        if self.vupdate_pause {
            core::future::pending::<()>().await;
        }
        if let Some(e) = self.vupdate_error {
            return Err(e);
        }
        self.vupdate_owned = enable;
        Ok(())
    }
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
        for q in self.latching() {
            if at == h(q, ADDRESS) {
                let flip = self.get(h(q, FLIP)) | FLIP_PENDING;
                self.put(h(q, FLIP), flip);
            }
            if at == h(q, HUBP_CONTROL) {
                if value & BLANK_EN != 0 {
                    value |= NO_OUTSTANDING;
                }
                if value & HUBP_UNDERFLOW_CLEAR != 0 {
                    value &= !(0x7000_0000 | HUBP_UNDERFLOW_CLEAR);
                }
            }
        }
        if at == optc_input(p) && value & OPTC_UNDERFLOW_CLEAR != 0 {
            value &= !(OPTC_UNDERFLOW | OPTC_UNDERFLOW_CLEAR);
        }
        // The CRB's DET and COMPBUF requests are acknowledged at once
        // (their CURRENT fields follow).
        if (BASE + 0x4ba * 4..=BASE + 0x4be * 4).contains(&at) {
            let index = ((at - (BASE + 0x4ba * 4)) / 4) as u8;
            let pending = index != 0
                && (self.det_stall & (1 << (index - 1)) != 0
                    || self.det_on_latch && self.latching().contains(&(index - 1)));
            let current = if pending {
                self.get(at) & 0x1f00
            } else {
                (value & 0x1f) << 8
            };
            value = (value & !0x1f00) | current;
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
            hdmi: true,
            timing,
            pitch: 640,
            bytes_per_pixel: 4,
            encoding: crate::amdgpu_hdr::PixelEncoding::from_420(false),
            dsc: None,
            planes: [None; dml::MAX_PLANES],
        },
    )
    .unwrap()
}
/// The plane mode and pixel clock the modeset derives from `plan` for TMDS.
fn hdmi_mode(pipe: u8, plan: &dml::Plan) -> Mode {
    let t = Request {
        pipe,
        signal: Signal::Tmds,
        encoding: crate::amdgpu_hdr::PixelEncoding::from_420(false),
        dsc: None,
        odm: SplitPipes::NONE,
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
            surface: Default::default(),
            pipe,
            width: plan.mode.timing.h_active,
            height: plan.mode.timing.v_active,
            format: match plan.mode.bytes_per_pixel {
                8 => SurfaceFormat::Xrgb16161616f,
                2 => SurfaceFormat::Rgb565,
                _ => SurfaceFormat::Xrgb8888,
            },
            odm: SplitPipes::NONE,
            mpc: SplitPipes::NONE,
            plane: None,
        },
        // Room for a back buffer of the same geometry.
        bytes: (if plan.pstate.is_some_and(|p| p.subvp.is_some()) {
            1
        } else {
            2
        }) * plan.mode.pitch as usize
            * plan.mode.bytes_per_pixel as usize
            * plan.mode.timing.v_active as usize,
        timing: t,
        clock: c,
    }
}

/// Everything a live scanout retains, staged and with HDMI black video
/// running: (transmitter, stream, pipe) are independent.
struct Chain {
    backing: Vec<u32>,
    pool: Pool,
    e: Engine<Renamed<ScanIo>>,
    surfaces: Surfaces,
    clock: dccg::Applied,
    address: u64,
    pipe: u8,
}
/// The staged pipe `chain` starts from: the requestor and deadlines
/// fixtures' records, before the HDMI transmitter model wraps them.
struct Staged {
    backing: Vec<u32>,
    pool: Pool,
    e: Engine<RequestIo>,
    surfaces: Surfaces,
    clock: dccg::Applied,
}
/// Boxed: tests hold several chains, each with a whole engine and its
/// register model (the aarch64 kernel-test stack is 64 KiB). Never inlined,
/// and nor is any step below: the fixtures under `staged` nest deeply, so
/// neither this frame nor a test's may also hold a step's records or
/// futures while they run.
#[inline(never)]
fn chain(phy_index: u8, stream: u8, pipe: u8) -> alloc::boxed::Box<Chain> {
    let plan = boxed_plan();
    // The staging fixtures model the full board (see hdmi_engine).
    let (s, address) = harvest::on_full_pool(|| {
        let mut s = staged(pipe, &plan);
        let address = stage_deadlines(&mut s, pipe, &plan);
        (s, address)
    });
    let mut c = hdmi_chain(s, phy_index, stream, pipe, address);
    let clock = c.clock;
    start_hdmi(&mut c.e, phy_index, stream, pipe, clock);
    c
}
/// `chain` over a (transmitter, stream, pipe) route.
fn chain_on((t, s, p): (u8, u8, u8)) -> alloc::boxed::Box<Chain> {
    chain(t, s, p)
}
#[inline(never)]
fn boxed_plan() -> alloc::boxed::Box<dml::Plan> {
    alloc::boxed::Box::new(plan())
}
/// `s` under the HDMI transmitter and lock/latch models.
#[inline(never)]
fn hdmi_chain(
    s: alloc::boxed::Box<Staged>,
    phy_index: u8,
    stream: u8,
    pipe: u8,
    address: u64,
) -> alloc::boxed::Box<Chain> {
    let Staged {
        backing,
        pool,
        e,
        surfaces,
        clock,
    } = *s;
    alloc::boxed::Box::new(Chain {
        backing,
        pool,
        e: hdmi_engine(e, phy_index, stream, pipe),
        surfaces,
        clock,
        address,
        pipe,
    })
}
#[inline(never)]
fn staged(pipe: u8, plan: &dml::Plan) -> alloc::boxed::Box<Staged> {
    let (backing, pool, e, surfaces, clock) =
        ready_requests_with(pipe, [21, 0, 0, 0, 0], hdmi_mode(pipe, plan));
    alloc::boxed::Box::new(Staged {
        backing,
        pool,
        e,
        surfaces,
        clock,
    })
}
/// The requestor and the plan's deadlines on the staged pipe; returns the
/// surface address they fetch.
#[inline(never)]
fn stage_deadlines(s: &mut Staged, pipe: u8, plan: &dml::Plan) -> u64 {
    let clock = s.clock;
    s.e.io.delay = [0; 5];
    run(s
        .surfaces
        .prepare_requestor_planes(&mut s.e, pipe, &[], Some(plan), || Ok((clock, config()))))
    .unwrap();
    s.e.io.fake().regs.insert(BASE + GLOBAL_TIMER * 4, 0x1002);
    let deadlines = run(s
        .surfaces
        .prepare_deadlines(&mut s.e, pipe, plan, CRYSTAL_KHZ, || Ok((clock, config()))));
    assert_eq!(deadlines.map(|d| d.plan), Ok(*plan), "deadlines");
    s.e.status.surfaces[usize::from(pipe)].unwrap().address
}
/// The staged engine under the HDMI transmitter and lock/latch models.
#[inline(never)]
fn hdmi_engine(
    e: Engine<RequestIo>,
    phy_index: u8,
    stream: u8,
    pipe: u8,
) -> Engine<Renamed<ScanIo>> {
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
    // Behind Renamed from here: its addresses are the full board's.
    fake.guarded = false;
    // Staged for the full board; from here the owner runs on the published
    // pool, the model behind it renamed to that board.
    let layout = harvest::harvested_layout(e.layout);
    let io = ScanIo {
        inner: TmdsIo {
            inner: fake,
            phy: phy_index,
            stream,
            event: Arc::new(AtomicU8::new(0)),
            writes: Arc::new(AtomicUsize::new(0)),
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
        extra: 0,
        det_stall: 0,
        det_on_latch: false,
        vupdate_owned: false,
        vupdate_pause: false,
        vupdate_error: None,
        vupdate_started: Arc::new(AtomicBool::new(false)),
    };
    Engine {
        io: Renamed::new(io, layout),
        authority: e.authority,
        layout,
        status: e.status,
        displays: e.displays,
    }
}
/// The TMDS link and its black video on the staged pipe, then arm the
/// lock/latch model.
#[inline(never)]
fn start_hdmi(
    e: &mut Engine<Renamed<ScanIo>>,
    phy_index: u8,
    stream: u8,
    pipe: u8,
    clock: dccg::Applied,
) {
    let mut fw = Firmware {
        ready: true,
        commands: Vec::new(),
        event: e.io.inner.event.clone(),
        writes: e.io.inner.writes.clone(),
        fail: None,
        power_downs: Vec::new(),
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
}
/// Each step runs to completion in its own frame and hands back a ready
/// future, so a test's frame never holds the step's (large) future while
/// the chain fixtures below it run on the 64 KiB aarch64 stack.
impl Chain {
    #[inline(never)]
    fn start(&mut self) -> core::future::Ready<Result<ScanoutRunning, Error>> {
        let c = self.clock;
        core::future::ready(run_boxed(|| {
            self.surfaces
                .start_scanout(&mut self.e, self.pipe, CRYSTAL_KHZ, move || {
                    Ok((c, config()))
                })
        }))
    }
    #[inline(never)]
    fn check(&mut self) -> core::future::Ready<Result<u32, Error>> {
        let c = self.clock;
        core::future::ready(run_boxed(|| {
            self.surfaces
                .check_scanout(&mut self.e, self.pipe, CRYSTAL_KHZ, move || {
                    Ok((c, config()))
                })
        }))
    }
    #[inline(never)]
    fn stop(&mut self) -> core::future::Ready<Result<(), Error>> {
        let c = self.clock;
        core::future::ready(run_boxed(|| {
            self.surfaces
                .stop_scanout(&mut self.e, self.pipe, CRYSTAL_KHZ, move || {
                    Ok((c, config()))
                })
        }))
    }
}
/// Poll the future `make` returns until `reached`, then drop it:
/// cancellation at that point. Built and polled on the heap, as by
/// `run_boxed`.
fn cancel_at<F: Future>(make: impl FnOnce() -> F, mut reached: impl FnMut() -> bool) {
    let mut f = boxed(make);
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
    for route in ROUTES {
        if let Err(why) = every_pipe(&mut chain_on(route), route) {
            return TestResult::Fail(why);
        }
    }
    TestResult::Pass
}
/// One route of the test above, in a frame beside the chain fixture's.
#[inline(never)]
fn every_pipe(c: &mut Chain, (_, s, p): (u8, u8, u8)) -> Result<(), &'static str> {
    let Ok(live) = run(c.start()) else {
        return Err("start over the staged chain");
    };
    if live.pipe != p
        || live.stream != s
        || live.address != c.address
        || c.e.status.state != State::ScanoutRunning(p)
        || c.e.status.scanout != Some(live)
    {
        return Err("running record");
    }
    // Routes are this pipe's own; no other pipe's MPCC was touched.
    for other in (0..4).filter(|o| *o != p) {
        if c.e.io.get(mpcc(other, TOP)) & 0xf != 0xf {
            return Err("another pipe's MPCC");
        }
    }
    if run(c.check()).is_err() {
        return Err("health check of a live scanout");
    }
    if run(c.stop()).is_err() || c.e.status.state != State::HdmiVideoRunning(s) {
        return Err("stop back to black video");
    }
    // Black video stays running and the pipe restarts from it.
    if run(c.start()).is_err() || run(c.stop()).is_err() {
        return Err("restart");
    }
    Ok(())
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
    // Each case's futures run in a frame of their own, beside the chain
    // fixture's rather than above it.
    let result = owner_change_during_start(&mut chain(1, 3, 2))
        .and_then(|()| owner_change_during_stop(&mut chain(0, 0, 0)))
        .and_then(|()| cancelled_start(&mut chain(3, 2, 1)));
    match result {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}
/// The clock owner changes while start waits for the latch.
#[inline(never)]
fn owner_change_during_start(c: &mut Chain) -> Result<(), &'static str> {
    let first = c.clock;
    let mut changed = first;
    changed.request.dpp_khz += 1;
    let mut calls = 0;
    let result = run_boxed(|| {
        c.surfaces.start_scanout(&mut c.e, 2, CRYSTAL_KHZ, move || {
            calls += 1;
            Ok((if calls == 1 { first } else { changed }, config()))
        })
    });
    if result != Err(Error::Busy) || c.e.status.state != State::Failed(Error::Busy) {
        return Err("owner change during start");
    }
    Ok(())
}
/// ... and while stop drains.
#[inline(never)]
fn owner_change_during_stop(c: &mut Chain) -> Result<(), &'static str> {
    let mine = c.clock;
    let mut other = mine;
    other.request.dpp_khz += 1;
    if run(c.start()).is_err() {
        return Err("start");
    }
    let mut calls = 0;
    let result = run_boxed(|| {
        c.surfaces.stop_scanout(&mut c.e, 0, CRYSTAL_KHZ, move || {
            calls += 1;
            Ok((if calls == 1 { mine } else { other }, config()))
        })
    });
    if result != Err(Error::Busy) || c.e.status.state != State::Failed(Error::Busy) {
        return Err("owner change during stop");
    }
    Ok(())
}
/// Cancelled while waiting for the lock: retained, quarantined, and not
/// replayable.
#[inline(never)]
fn cancelled_start(c: &mut Chain) -> Result<(), &'static str> {
    c.e.io.grant = false;
    c.e.io.pause_wait = true;
    let requested = c.e.io.lock_requested.clone();
    let clock = c.clock;
    cancel_at(
        || {
            c.surfaces
                .start_scanout(&mut c.e, 1, CRYSTAL_KHZ, move || Ok((clock, config())))
        },
        || requested.load(Ordering::SeqCst),
    );
    if c.e.status.state != State::StartingScanout(1)
        || run(c.start()) != Err(Error::Busy)
        || run(c.check()) != Err(Error::Invalid)
    {
        return Err("cancelled start");
    }
    Ok(())
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
    #[inline(never)]
    fn flip(&mut self) -> core::future::Ready<Result<FlipDone, Error>> {
        let c = self.clock;
        core::future::ready(run_boxed(|| {
            self.surfaces
                .flip(&mut self.e, self.pipe, CRYSTAL_KHZ, move || {
                    Ok((c, config()))
                })
        }))
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
            || {
                c.surfaces
                    .flip(&mut c.e, p, CRYSTAL_KHZ, move || Ok((clock, config())))
            },
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

impl Chain {
    #[inline(never)]
    fn flip_to(
        &mut self,
        source: FlipSource,
    ) -> core::future::Ready<Result<[Option<FlipDone>; 1 + MAX_OVERLAYS], Error>> {
        let c = self.clock;
        let mut sources = [None; 1 + MAX_OVERLAYS];
        sources[0] = Some(source);
        core::future::ready(run_boxed(|| {
            self.surfaces
                .flip_sources(&mut self.e, self.pipe, sources, CRYSTAL_KHZ, move || {
                    Ok((c, config()))
                })
        }))
    }
    fn hubp(&mut self, r: u64) -> u32 {
        let at = h(self.pipe, r);
        self.e.io.get(at)
    }
}

/// amdgpu_dm hands DC the client framebuffer's own address
/// (amdgpu_dm_plane_fill_plane_buffer_attributes): a flip to a pinned
/// buffer re-addresses the HUBP (and, for another pitch, its
/// DCSURF_SURFACE_PITCH under the same lock) without copying a byte into
/// either staged buffer; the buffer it replaces is reported no longer
/// fetched only after the new address latched; a flip back to the back
/// buffer restores the staged pitch. A buffer the plane cannot fetch
/// (misaligned, outside the frame-buffer aperture, a pitch below the
/// staged one, rows past its end, one of the plane's own staged buffers)
/// is refused with the scanout untouched.
fn dcn401_scanout_chain_scans_client_framebuffers_in_place() -> TestResult {
    scans_client_framebuffers_in_place(chain(0, 0, 0))
}
/// The test above on chain `c`.
fn scans_client_framebuffers_in_place(mut c: alloc::boxed::Box<Chain>) -> TestResult {
    let p = c.pipe;
    if run(c.start()).is_err() {
        return TestResult::Fail("start");
    }
    let Ok(back) = run(c.surfaces.prepare_back(&mut c.e, &c.pool, p, config())) else {
        return TestResult::Fail("back buffer");
    };
    let front = c.address;
    // Mark both staged buffers: nothing may write either.
    if c.surfaces
        .upload_back(&mut c.e, p, 0, 0, &[0x1234_5678])
        .is_err()
    {
        return TestResult::Fail("back-buffer marker");
    }
    let (front_word, back_word) = (c.vram(front, 0), c.vram(back, 0));
    let client = 0x8_4000_0000u64;
    let x = ExternalSurface {
        address: client,
        pitch_bytes: 4096,
        chroma: None,
        last: client + 4096 * 480 - 1,
        dcc_aligned: true,
    };
    for bad in [
        ExternalSurface {
            address: client + 64,
            last: x.last + 64,
            ..x
        },
        ExternalSurface {
            address: 0xc_0000_0000,
            last: 0xc_0000_0000 + (x.last - client),
            ..x
        },
        ExternalSurface {
            pitch_bytes: 2048,
            ..x
        },
        ExternalSurface {
            pitch_bytes: 4098,
            ..x
        },
        ExternalSurface {
            last: x.last - 1,
            ..x
        },
        ExternalSurface {
            chroma: Some((4096 * 480, 4096)),
            ..x
        },
        ExternalSurface {
            address: back,
            last: back + 4096 * 480,
            ..x
        },
    ] {
        if run(c.flip_to(FlipSource::External(bad))) != Err(Error::Invalid)
            || c.e.status.state != State::ScanoutRunning(p)
            || c.hubp(0x60a) != front as u32
        {
            return TestResult::Fail("unfetchable client framebuffer accepted");
        }
    }
    let writes = c.e.io.writes;
    let Ok(done) = run(c.flip_to(FlipSource::External(x))) else {
        return TestResult::Fail("flip to a client framebuffer");
    };
    let done = done[0].unwrap();
    if done.front != client || done.back != front {
        return TestResult::Fail("client flip report");
    }
    if c.hubp(0x60a) != client as u32 || c.hubp(0x60b) & 0xffff != (client >> 32) as u32 {
        return TestResult::Fail("HUBP not addressing the client framebuffer");
    }
    if c.hubp(0x61c) != client as u32 {
        return TestResult::Fail("client framebuffer not reported in use");
    }
    if c.hubp(0x607) & 0xffff != 4096 / 4 - 1 {
        return TestResult::Fail("client framebuffer's pitch not programmed");
    }
    // No copy: neither staged buffer changed, and a flip is a handful of
    // register writes, not a frame's worth.
    if c.vram(front, 0) != front_word || c.vram(back, 0) != back_word || c.e.io.writes - writes > 64
    {
        return TestResult::Fail("client flip copied pixels");
    }
    let mut status = c.e.status.scanout.unwrap();
    if status.address != client || c.e.status.surfaces[usize::from(p)].unwrap().pitch_bytes != 4096
    {
        return TestResult::Fail("records do not name the client framebuffer");
    }
    // Another client buffer of the same pitch: only the address moves.
    let next = ExternalSurface {
        address: client + 0x20_0000,
        last: x.last + 0x20_0000,
        ..x
    };
    let Ok(done) = run(c.flip_to(FlipSource::External(next))) else {
        return TestResult::Fail("client to client flip");
    };
    if done[0].unwrap().back != client || c.hubp(0x60a) != next.address as u32 {
        return TestResult::Fail("client to client report");
    }
    // Back to the staged back buffer (the presenter's copy path): its
    // staged pitch returns, the client buffer is released by the report.
    let Ok(done) = run(c.flip_to(FlipSource::Back)) else {
        return TestResult::Fail("flip back to the staged buffer");
    };
    let done = done[0].unwrap();
    if done.front != back || done.back != next.address || c.hubp(0x607) & 0xffff != 640 - 1 {
        return TestResult::Fail("back-buffer flip after a client one");
    }
    status = c.e.status.scanout.unwrap();
    if status.address != back
        || c.vram(back, 0) != back_word
        || c.surfaces.upload_back(&mut c.e, p, 0, 0, &[7]).is_err()
        || c.vram(front, 0) != 7
    {
        return TestResult::Fail("staged buffers after the client flips");
    }
    if run(c.stop()).is_err() {
        return TestResult::Fail("stop");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_scanout_chain_scans_client_framebuffers_in_place
);

/// A second display selected next to a live one sees exactly the first
/// one's resources as siblings, may retire planes and stage timing on its
/// own pipes without disturbing the live scanout, and may not take the
/// live display's pipe; the first display then checks and stops as before.
fn dcn401_second_display_leaves_the_live_one_alone() -> TestResult {
    let route = (1, 3, 2);
    match second_display(&mut chain_on(route), route) {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}
/// The test above over its chain, in a frame beside the chain fixture's.
#[inline(never)]
fn second_display(c: &mut Chain, (t, s, p): (u8, u8, u8)) -> Result<(), &'static str> {
    let Ok(live) = run(c.start()) else {
        return Err("first display start");
    };
    // Records of display 0 stay put; display 1 starts empty.
    if c.e.select_display(1).is_err() || c.e.status.state != State::Ready {
        return Err("select an idle second display");
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
    want.live[usize::from(p)] = Some(LivePipe {
        pipe: p,
        address: live.address,
        cursor: false,
        routes: [p, p, 0xf, p, p],
        mode: 2,
    });
    if held != want {
        return Err("siblings derived from the live display");
    }
    // The other pipes' MPCCs and HUBPs drain at once in this model.
    for q in (0..4).filter(|&q| q != p) {
        c.e.io.put(mpcc(q, MPC_STATUS), 5);
        c.e.io.put(h(q, HUBP_CONTROL), BLANK_EN | NO_OUTSTANDING);
    }
    let Ok(retired) = run(c.e.retire_planes()) else {
        return Err("plane retirement next to a live display");
    };
    if retired.blanked & 1 << p != 0
        || retired.powered_off & 1 << p != 0
        || c.e.io.get(mpcc(p, TOP)) & 0xf != u32::from(p)
        || c.e.live_segment(p, live.address, false).is_err()
    {
        return Err("live display's planes touched");
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
        return Err("surface retirement stole a live sibling");
    }
    let own = hdmi_mode(p, &plan);
    if run(c.e.prepare(own.timing, own.clock)) != Err(Error::Busy) {
        return Err("timing staged on another display's pipe");
    }
    let q = 0;
    let other = hdmi_mode(q, &plan);
    if run(c.e.prepare(other.timing, other.clock)).is_err() {
        return Err("timing staged next to a live display");
    }
    if c.e.select_display(0).is_err() || c.e.status.scanout != Some(live) {
        return Err("first display's records restored");
    }
    if c.e.displays.siblings.pipes != 1 << q || c.e.displays.siblings.live != [None; 4] {
        return Err("second display's staged pipe as sibling");
    }
    if run(c.check()).is_err() || run(c.stop()).is_err() {
        return Err("live display checked and stopped afterwards");
    }
    // A failed display keeps the selection: nothing else may run.
    c.e.status.state = State::Failed(Error::Busy);
    if c.e.select_display(1) != Err(Error::Busy) {
        return Err("selection away from a failed display");
    }
    Ok(())
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_second_display_leaves_the_live_one_alone
);

fn dcn401_partial_activation_unwinds_native_link_video_and_scanout() -> TestResult {
    for stage in 0..4 {
        unwind_stage(&mut chain(0, 0, 0), stage);
    }
    TestResult::Pass
}
/// Stop `c` at `stage` of its activation and unwind it to released memory.
/// Its futures run in this frame, beside the chain fixture's.
#[inline(never)]
fn unwind_stage(c: &mut Chain, stage: u32) {
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
                run_boxed(|| c
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
                run(c
                    .e
                    .start_hdmi_audio(path(0), info, c.e.test_audio_endpoint())),
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
        power_downs: Vec::new(),
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
    for route in ROUTES {
        if let Err(why) = crtc_color(&mut chain_on(route), route.2) {
            return TestResult::Fail(why);
        }
    }
    TestResult::Pass
}
/// One route of the test above, in a frame beside the chain fixture's.
#[inline(never)]
fn crtc_color(c: &mut Chain, p: u8) -> Result<(), &'static str> {
    // Not scanning out: recorded only.
    let first = color(195, false);
    let writes = c.e.io.writes;
    if run(c.e.set_color(p, Some(first.clone()))).is_err() || c.e.io.writes != writes {
        return Err("dark display color");
    }
    if run(c.start()).is_err() {
        return Err("start with color");
    }
    let latched = |c: &mut Chain, ogam: u32, gamut: u32, pre: u32| {
        c.e.io.get(og(p, OGAM_CONTROL)) & 0x387 == ogam
            && c.e.io.get(og(p, GAMUT_MODE)) & 0x183 == gamut
            && c.e.io.get(dpp_reg(p, PRE_DEGAM)) & 0x73 == pre
    };
    // RAM A and gamut set A, latched with the plane.
    if !latched(c, 2 | 2 << 7, 1 | 1 << 7, 1)
        || c.e.status.colors[usize::from(p)]
            != (PipeColor {
                pre_degam: PreDegam::Srgb,
                gamcor: None,
                gamut: Some((1, false)),
                ogam: Some(0),
            })
        || run(c.check()).is_err()
    {
        return Err("color at start");
    }
    // A live update: the other bank and set, latched before return.
    let second = color(195, true);
    if run(c.e.set_color(p, Some(second))).is_err()
        || c.e.status.state != State::ScanoutRunning(p)
        || !latched(c, 2 | 4 | 2 << 7 | 1 << 9, 2 | 2 << 7, 1)
        || run(c.check()).is_err()
    {
        return Err("live color update");
    }
    // Back to bypass, live.
    if run(c.e.set_color(p, None)).is_err()
        || !latched(c, 0, 0, 0)
        || c.e.status.colors[usize::from(p)] != PipeColor::default()
        || run(c.check()).is_err()
    {
        return Err("live bypass");
    }
    // The request survives stop and restart.
    if run(c.stop()).is_err()
        || run(c.e.set_color(p, Some(first.clone()))).is_err()
        || run(c.start()).is_err()
        || !latched(c, 2 | 2 << 7, 1 | 1 << 7, 1)
        || run(c.check()).is_err()
    {
        return Err("color across restart");
    }
    // Cancelled inside the update's lock: the pipe is quarantined.
    c.e.io.grant = false;
    c.e.io.pause_wait = true;
    let requested = c.e.io.lock_requested.clone();
    requested.store(false, Ordering::SeqCst);
    cancel_at(
        || c.e.set_color(p, Some(color(195, true))),
        || requested.load(Ordering::SeqCst),
    );
    if c.e.status.state != State::UpdatingStream(p) {
        return Err("cancelled update not quarantined");
    }
    Ok(())
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_scanout_chain_programs_crtc_color
);

/// A configuration change keeps a live display lit (dcn401_program_pipe for
/// a stream the commit keeps): its stream admitted beside a 1080p60 one
/// takes the new plan's global sync, DLG/TTU and watermarks under one OTG
/// lock without leaving scanout, once its timing records carry the raised
/// clocks. prepare_bandwidth's raise-only watermarks keep a higher value
/// another display needs; optimize_bandwidth's are exact. A plan for
/// another stream, or one the current clocks do not cover, is refused
/// without a write.
fn dcn401_scanout_chain_moves_a_live_display_to_a_new_plan() -> TestResult {
    let (t, s, p) = ROUTES[1];
    move_to_new_plan(chain(t, s, p), p)
}
/// The test's plans and updates, in a frame beside the chain fixture's.
#[inline(never)]
fn move_to_new_plan(mut c: alloc::boxed::Box<Chain>, p: u8) -> TestResult {
    use crate::amdgpu_dcn401_otg::WatermarkUpdate;
    if run(c.start()).is_err() {
        return TestResult::Fail("start");
    }
    let old = plan();
    let hd = dml::Mode::new(
        Timing {
            pixel_clock_khz: 148_500,
            h_active: 1920,
            h_total: 2200,
            h_front_porch: 88,
            h_sync_width: 44,
            v_active: 1080,
            v_total: 1125,
            v_front_porch: 4,
            v_sync_width: 5,
            h_sync_positive: true,
            v_sync_positive: true,
        },
        1920,
        4,
    );
    let joint = dml::admit_all(&soc(), &[old.mode, hd]).unwrap()[0];
    if joint == old || joint.mode != old.mode {
        return TestResult::Fail("joint plan");
    }
    let update = |c: &mut Chain, plan: &dml::Plan, wm| {
        let clock = c.clock;
        run(c
            .surfaces
            .update_live_plan(&mut c.e, p, plan, wm, CRYSTAL_KHZ, || Ok((clock, config()))))
    };
    // Not covered by the clocks the timing runs on yet.
    let writes = c.e.io.writes;
    if joint.clocks.dispclk_khz > c.clock.global.display_khz
        && (update(&mut c, &joint, WatermarkUpdate::Raise) != Err(Error::Invalid)
            || c.e.io.writes != writes)
    {
        return TestResult::Fail("plan beyond the running clocks");
    }
    // Another stream's plan is not this display's.
    let other = dml::admit_all(&soc(), &[hd]).unwrap()[0];
    if update(&mut c, &other, WatermarkUpdate::Raise) != Err(Error::Invalid)
        || c.e.io.writes != writes
    {
        return TestResult::Fail("another stream's plan");
    }
    // prepare_bandwidth raised the shared clocks: every timing record
    // carries them.
    let mut raised = c.clock;
    raised.global.display_khz = raised.global.display_khz.max(joint.clocks.dispclk_khz);
    raised.global.dpp_khz = raised.global.dpp_khz.max(joint.clocks.dpprefclk_khz);
    raised.global.request.display_khz = raised.global.display_khz;
    raised.global.request.dpp_khz = raised.global.dpp_khz;
    raised.request.dpp_khz = raised.request.dpp_khz.max(joint.clocks.dppclk_khz);
    c.e.status.rebind_timing(p, |a| a.clock = raised);
    c.clock = raised;
    if run(c.check()).is_err() {
        return TestResult::Fail("rebound records");
    }
    // Another display's higher urgent watermark in both sets.
    let wm_a = BASE + 0x4fe * 4;
    let wm_b = BASE + 0x511 * 4;
    for at in [wm_a, wm_b] {
        c.e.io.put(at, 0x3fff);
    }
    if update(&mut c, &joint, WatermarkUpdate::Raise).is_err() {
        return TestResult::Fail("raise update");
    }
    let sync = joint.sync;
    if c.e.status.state != State::ScanoutRunning(p)
        || c.e.status.deadlines.map(|d| d.plan) != Some(joint)
        || c.e.status.scanout.map(|s| s.plan) != Some(joint)
        || c.e.status.pipes[usize::from(p)].map(|a| a.request.sync) != Some(sync)
        || c.e.status.blanks[usize::from(p)].map(|b| b.timing.request.sync) != Some(sync)
        || c.e.io.get(otg(p, STARTUP)) & 0x3ff != sync.vstartup
        || c.e.io.get(otg(p, UPDATE)) & 0x3ffffff != sync.vupdate_offset | sync.vupdate_width << 16
        || c.e.io.get(otg(p, READY)) & 0xffff != sync.vready_offset
        || c.e.io.get(otg(p, PSTATE)) & 0x7fff != sync.pstate_keepout
        || c.e.io.get(wm_a) & 0x3fff != 0x3fff
        || c.e.io.get(wm_b) & 0x3fff != 0x3fff
        || c.e.deadline_writes(p, &joint, true).is_ok()
        || c.e
            .deadline_writes_with(p, &joint, true, WatermarkUpdate::Raise)
            .is_err()
    {
        return TestResult::Fail("new plan live with raised watermarks");
    }
    // optimize_bandwidth: exactly the plan's, and the scanout checks.
    if update(&mut c, &joint, WatermarkUpdate::Exact).is_err()
        || c.e.io.get(wm_a) & 0x3fff != joint.watermarks.urgent
        || run(c.check()).is_err()
    {
        return TestResult::Fail("exact watermarks");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_scanout_chain_moves_a_live_display_to_a_new_plan
);

/// A live stream's own DET must latch before its new plan is published, but
/// a different, idle DET can keep the optional compbuf grow pending across
/// another update. The idle zero request is issued by the real owner.
fn dcn401_live_det_settles_active_storage_and_retains_idle_retirements() -> TestResult {
    use crate::amdgpu_dcn401_otg::WatermarkUpdate;
    let mode = plan().mode;
    let partner = dml::Mode {
        hdmi: false,
        ..mode
    };
    let old = dml::admit_all(&soc(), &[mode, partner]).unwrap()[0];
    let mut faster = partner;
    faster.timing.pixel_clock_khz *= 4;
    let next = dml::admit_all(&soc(), &[mode, faster]).unwrap()[0];
    assert!(next.det_bytes < old.det_bytes);
    for active_stalls in [false, true] {
        let p = 0;
        let mut c = harvest::on_full_pool(|| {
            let mut s = staged(p, &old);
            let address = stage_deadlines(&mut s, p, &old);
            let mut c = hdmi_chain(s, 0, 0, p, address);
            let clock = c.clock;
            start_hdmi(&mut c.e, 0, 0, p, clock);
            c
        });
        run(c.start()).unwrap();
        let mut raised = c.clock;
        raised.global.display_khz = raised.global.display_khz.max(next.clocks.dispclk_khz);
        raised.global.dpp_khz = raised.global.dpp_khz.max(next.clocks.dpprefclk_khz);
        raised.global.request.display_khz = raised.global.display_khz;
        raised.global.request.dpp_khz = raised.global.dpp_khz;
        raised.request.dpp_khz = raised.request.dpp_khz.max(next.clocks.dppclk_khz);
        c.e.status.rebind_timing(p, |a| a.clock = raised);
        c.clock = raised;
        let crb = |i: u64| BASE + (0x4ba + i) * 4;
        let compbuf = 21 - old.det_bytes / 65536 - 5;
        c.e.io.put(crb(0), compbuf * 0x101);
        c.e.io.put(crb(2), 5 * 0x101);
        c.e.status.requestor.as_mut().unwrap().compbuf_bytes = compbuf * 65536;
        let previous = c.e.status.requestor;
        c.e.io.det_on_latch = true;
        c.e.io.det_stall = if active_stalls { 0b11 } else { 0b10 };
        let update = |c: &mut Chain| {
            let clock = c.clock;
            run(c.surfaces.update_live_plan(
                &mut c.e,
                p,
                &next,
                WatermarkUpdate::Raise,
                CRYSTAL_KHZ,
                || Ok((clock, config())),
            ))
        };
        let changed = update(&mut c);
        if active_stalls {
            assert!(matches!(changed, Err(Error::Timeout(_))));
            assert!(matches!(c.e.status.state, State::Failed(_)));
            assert_eq!(c.e.status.requestor, previous);
            assert_eq!(c.e.status.deadlines.unwrap().plan, old);
            assert_eq!(c.e.io.get(crb(0)) & 0x1f, compbuf);
            continue;
        }
        assert_eq!(changed.map(|d| d.plan), Ok(next));
        assert_eq!(c.e.io.get(crb(1)) & 0x1f1f, next.det_bytes / 65536 * 0x101);
        assert_eq!(c.e.io.get(crb(2)) & 0x1f1f, 5 << 8);
        assert_eq!(c.e.io.get(crb(0)) & 0x1f, compbuf);
        assert!(c.e.displays.compbuf_pending);
        assert_eq!(c.e.displays.retiring_dets & 0b10, 0b10);
        assert!(run(c.check()).is_ok());
        assert!(
            update(&mut c).is_ok(),
            "an unchanged optimize must retain the idle retirement"
        );
        assert!(c.e.displays.compbuf_pending);
        c.e.io.put(crb(2), 0);
        c.e.io.det_stall = 0;
        assert!(run(c.e.retry_compbuf()).unwrap().is_some());
        assert_eq!(c.e.io.get(crb(0)) & 0x1f, 21 - next.det_bytes / 65536);
        assert!(!c.e.displays.compbuf_pending);
        assert!(run(c.check()).is_ok());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_live_det_settles_active_storage_and_retains_idle_retirements
);

#[path = "amdgpu_dcn401_plane_update_chain_tests.rs"]
mod plane_update;

/// The chain on harvested boards (pipe 0, pipe 1, and pipes 1 and 2 fused):
/// the same owners on the pool's pipes, the staged full-board model behind
/// `harvest::Renamed`, so every access and instance field the owners make
/// must name the pool's instance of the pipe the model expects, and none a
/// fused one. Each case runs on the pipes the pool has.
fn dcn401_scanout_chain_runs_on_harvested_boards() -> TestResult {
    harvest::harvested(2, || {
        let count = crate::amdgpu_rdna4::pipe_pool().count();
        let top = count - 1;
        if let Err(why) = harvested_chain(count) {
            return TestResult::Fail(why);
        }
        for stage in 0..4 {
            unwind_stage(&mut chain(0, 0, 0), stage);
        }
        let route = (2, 1, top);
        let moved = move_to_new_plan(chain_on(route), top);
        if moved != TestResult::Pass {
            return moved;
        }
        use plane_update::*;
        for result in [
            dcn401_live_plane_update_scales_the_primary_in_place_on(route),
            dcn401_live_plane_update_adds_moves_and_removes_an_overlay_on(route, 0),
            dcn401_live_plane_update_moves_the_cursor_with_the_planes_on(route, 0),
            dcn401_live_plane_update_shows_the_first_frame_at_the_latch_on(route, 0),
            dcn401_live_plane_update_scans_a_client_framebuffer_from_the_latch_on(route, 0),
            scans_client_framebuffers_in_place(chain_on(route)),
        ] {
            if result != TestResult::Pass {
                return result;
            }
        }
        if count > 2 {
            // Its refused plan names a third pipe (1).
            return dcn401_live_plane_update_refuses_before_any_write_on((1, 3, 2), 0);
        }
        TestResult::Pass
    })
}
/// The routed cases of the test above on a pool of `count` pipes.
#[inline(never)]
fn harvested_chain(count: u8) -> Result<(), &'static str> {
    let top = count - 1;
    for route in ROUTES.into_iter().filter(|r| r.2 < count) {
        every_pipe(&mut chain_on(route), route)?;
        crtc_color(&mut chain_on(route), route.2)?;
    }
    owner_change_during_stop(&mut chain(0, 0, 0))?;
    cancelled_start(&mut chain(3, 2, 1))?;
    if count > 2 {
        owner_change_during_start(&mut chain(1, 3, 2))?;
        second_display(&mut chain_on((1, 3, 2)), (1, 3, 2))?;
    }
    // A lost write on the top pipe's MPCC (the model's) is caught by its
    // readback, at the pipe's MPCC instance (the owner's).
    let mut c = chain(2, 1, top);
    c.e.io.drop = Some(mpcc(top, TOP));
    if run(c.start()) != Err(Error::Readback(c.e.io.owner_addr(mpcc(top, TOP)))) {
        return Err("lost MPCC write on the top pipe");
    }
    Ok(())
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_scanout_chain_runs_on_harvested_boards
);

/// UCLK P-state switching on a live display (dcn401_prepare/optimize
/// bandwidth around DML21's answer): the running 640x480 display moves to
/// its vactive P-state plan with raise-only and then exact watermarks
/// while UCLK is still pinned, and keeps scanning out once PMFW may switch
/// UCLK down to the plan's level. While switching, a pinned plan is refused
/// without a write, and so is a UCLK floor below the plan's; re-pinned,
/// both the P-state plan and the pinned plan run again.
fn dcn401_scanout_chain_runs_a_uclk_pstate_plan() -> TestResult {
    let (t, s, p) = ROUTES[2];
    pstate_plan(chain(t, s, p), p, false)
}
#[inline(never)]
fn pstate_plan(mut c: alloc::boxed::Box<Chain>, p: u8, variable: bool) -> TestResult {
    use crate::amdgpu_dcn401_otg::WatermarkUpdate;
    use dml::pstate::{admit_with_drr, Method, Pstate, UclkLevels};
    if run(c.start()).is_err() {
        return TestResult::Fail("start");
    }
    let pinned = plan();
    let lfc = variable.then(|| {
        crate::amdgpu_freesync::LfcConfig::new(
            &pinned.mode.timing,
            crate::amdgpu_freesync::VrrRange {
                min_hz: 20,
                max_hz: 61,
            },
        )
        .unwrap()
    });
    if let Some(lfc) = lfc {
        run(c.e.configure_drr(p, Some(lfc.base()))).unwrap();
        run(c.e.configure_lfc(p, Some(lfc))).unwrap();
    }
    let drr = [lfc.map(|c| c.base()), None, None, None];
    let uclk = UclkLevels::new(&[96_000, 456_000, 772_000, 1_250_000]).unwrap();
    let Ok(Pstate::Supported(s)) =
        run_boxed(|| async { admit_with_drr(&soc(), &uclk, &[pinned.mode], false, drr) })
    else {
        return TestResult::Fail("640x480 P-state support");
    };
    let pstate = s.plans[0];
    if s.methods[0] != Method::Vactive
        || pstate.clocks.uclk_khz != 96_000
        || pstate.pstate.is_none()
        || pstate.mode != pinned.mode
    {
        return TestResult::Fail("vactive plan");
    }
    if let Some(lfc) = lfc {
        assert!(pstate.native_refresh_pstate(lfc.base()));
        let mut forged = pstate;
        forged.pstate.as_mut().unwrap().method = Method::FwVactiveDrr;
        assert!(!forged.native_refresh_pstate(lfc.base()));
        forged = pstate;
        forged.streams[0] = Some(pinned.mode);
        assert!(!forged.native_refresh_pstate(lfc.base()));
        let mut foreign = lfc.base();
        foreign.v_total_max -= 1;
        assert!(!pstate.native_refresh_pstate(foreign));
    }
    let update = |c: &mut Chain, plan: &dml::Plan, wm| {
        let clock = c.clock;
        run(c
            .surfaces
            .update_live_plan(&mut c.e, p, plan, wm, CRYSTAL_KHZ, || Ok((clock, config()))))
    };
    let rebind = |c: &mut Chain, f: &dyn Fn(&mut dccg::Applied)| {
        let mut clock = c.clock;
        f(&mut clock);
        c.e.status.rebind_timing(p, |a| a.clock = clock);
        c.clock = clock;
    };
    // prepare_bandwidth: whatever the P-state plan needs is raised first.
    rebind(&mut c, &|k| {
        k.global.display_khz = k.global.display_khz.max(pstate.clocks.dispclk_khz);
        k.global.dpp_khz = k.global.dpp_khz.max(pstate.clocks.dpprefclk_khz);
        k.global.request.display_khz = k.global.display_khz;
        k.global.request.dpp_khz = k.global.dpp_khz;
        k.request.dpp_khz = k.request.dpp_khz.max(pstate.clocks.dppclk_khz);
    });
    if update(&mut c, &pstate, WatermarkUpdate::Raise).is_err()
        || update(&mut c, &pstate, WatermarkUpdate::Exact).is_err()
        || c.e.status.deadlines.map(|d| d.plan) != Some(pstate)
        || run(c.check()).is_err()
    {
        return TestResult::Fail("P-state plan while pinned");
    }
    // optimize_bandwidth: UCLK switching allowed, floor at the plan's level.
    rebind(&mut c, &|k| {
        k.global.uclk_pstate = true;
        k.global.memory_floor_khz = 96_000;
    });
    if run(c.check()).is_err() {
        return TestResult::Fail("P-state plan while switching");
    }
    if let Some(lfc) = lfc {
        run(c.surfaces.prepare_back(&mut c.e, &c.pool, p, config())).unwrap();
        // The real flip samples frame transitions and updates BTR under the
        // same owner while the retained clock contract allows UCLK switching.
        run(c.flip()).unwrap();
        c.e.lfc_idle(p).unwrap();
        assert!(c.e.status.drr.unwrap().lfc_enabled());
        run(c.check()).unwrap();
        run(c.e.configure_lfc(p, None)).unwrap();
        let mid = crate::amdgpu_dcn401_otg::DrrMid {
            v_total: lfc.base().v_total_min + 1,
            frames: 3,
        };
        c.e.set_drr_mid(p, Some(mid)).unwrap();
        run(c.check()).unwrap();
        let writes = c.e.io.writes;
        assert_eq!(
            c.e.set_drr_mid(
                p,
                Some(crate::amdgpu_dcn401_otg::DrrMid {
                    v_total: lfc.base().v_total_min - 1,
                    ..mid
                })
            ),
            Err(Error::Invalid)
        );
        assert_eq!(writes, c.e.io.writes);
        c.e.set_drr_mid(p, None).unwrap();
        run(c.e.configure_lfc(p, Some(lfc))).unwrap();
        run(c.check()).unwrap();
    }
    let writes = c.e.io.writes;
    if update(&mut c, &pinned, WatermarkUpdate::Raise) != Err(Error::Invalid)
        || c.e.io.writes != writes
    {
        return TestResult::Fail("pinned plan while switching");
    }
    rebind(&mut c, &|k| k.global.memory_floor_khz = 48_000);
    if run(c.check()) != Err(Error::Invalid) {
        return TestResult::Fail("UCLK floor below the plan");
    }
    // Re-pinned (prepare_bandwidth before an unsupported configuration).
    rebind(&mut c, &|k| {
        k.global.uclk_pstate = false;
        k.global.memory_floor_khz = 1_250_000;
    });
    if run(c.check()).is_err()
        || update(&mut c, &pinned, WatermarkUpdate::Raise).is_err()
        || update(&mut c, &pinned, WatermarkUpdate::Exact).is_err()
        || c.e.status.deadlines.map(|d| d.plan) != Some(pinned)
        || run(c.check()).is_err()
    {
        return TestResult::Fail("pinned again");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_scanout_chain_runs_a_uclk_pstate_plan
);

fn dcn401_scanout_chain_native_drr_pstate_preserves_lfc_and_mid() -> TestResult {
    pstate_plan(chain(1, 3, 2), 2, true)
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_scanout_chain_native_drr_pstate_preserves_lfc_and_mid
);

fn dcn401_scanout_chain_vrr_lfc_uses_actual_flip_and_cancellation_owner() -> TestResult {
    let mut c = chain(1, 3, 2);
    run(c.start()).unwrap();
    let p = c.pipe;
    let timing = c.e.status.pipes[usize::from(p)].unwrap().request.timing;
    let lfc_config = crate::amdgpu_freesync::LfcConfig::new(
        &timing,
        crate::amdgpu_freesync::VrrRange {
            min_hz: 20,
            max_hz: 61,
        },
    )
    .unwrap();
    c.e.set_drr(p, Some(lfc_config.base())).unwrap();
    c.e.set_lfc(p, Some(lfc_config)).unwrap();
    let admitted = c.e.status.scanout.unwrap().plan;
    run(c.surfaces.prepare_back(&mut c.e, &c.pool, p, config())).unwrap();
    // Full retained-owner/source verification accepts active DRR totals.
    // The actual address transaction invokes preflip and real frame polling.
    run(c.flip()).unwrap();
    assert_eq!(c.e.status.scanout.unwrap().plan, admitted);
    assert!(c.e.status.drr.unwrap().lfc_enabled());
    run(c.check()).unwrap();
    c.e.io.grant = false;
    c.e.io.pause_wait = true;
    let requested = c.e.io.lock_requested.clone();
    requested.store(false, Ordering::SeqCst);
    let clock = c.clock;
    cancel_at(
        || {
            c.surfaces
                .flip(&mut c.e, p, CRYSTAL_KHZ, move || Ok((clock, config())))
        },
        || requested.load(Ordering::SeqCst),
    );
    assert_eq!(c.e.status.state, State::Flipping(p));
    let timing_owner = c.e.status.drr;
    assert_eq!(c.e.lfc_idle(p), Err(Error::Busy));
    assert_eq!(c.e.status.drr, timing_owner);
    assert!(c.e.status.scanout.is_some());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_scanout_chain_vrr_lfc_uses_actual_flip_and_cancellation_owner
);

fn dcn401_scanout_vupdate_mask_is_awaited_before_stop_and_cancel_quarantines() -> TestResult {
    let mut c = chain(1, 3, 2);
    run(c.start()).unwrap();
    let p = c.pipe;
    let t = c.e.status.pipes[usize::from(p)].unwrap().request.timing;
    let lfc_config = crate::amdgpu_freesync::LfcConfig::new(
        &t,
        crate::amdgpu_freesync::VrrRange {
            min_hz: 20,
            max_hz: 61,
        },
    )
    .unwrap();
    run(c.e.configure_drr(p, Some(lfc_config.base()))).unwrap();
    run(c.e.configure_lfc(p, Some(lfc_config))).unwrap();
    assert!(c.e.io.vupdate_owned);
    let held = c.e.status.drr;
    let source = c.e.io.vupdate_started.clone();
    source.store(false, Ordering::SeqCst);
    c.e.io.vupdate_pause = true;
    let clock = c.clock;
    let writes = c.e.io.writes;
    cancel_at(
        || {
            c.surfaces
                .stop_scanout(&mut c.e, p, CRYSTAL_KHZ, move || Ok((clock, config())))
        },
        || source.load(Ordering::SeqCst),
    );
    assert_eq!(c.e.status.state, State::StoppingScanout(p));
    assert!(c.e.io.vupdate_owned);
    assert_eq!(c.e.status.drr, held);
    assert!(c.e.status.scanout.is_some());
    assert_eq!(
        c.e.io.writes, writes,
        "clock/fetch write preceded source retirement"
    );
    assert_eq!(c.e.lfc_idle(p), Err(Error::Busy));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_scanout_vupdate_mask_is_awaited_before_stop_and_cancel_quarantines
);
fn dcn401_scanout_vupdate_mask_failure_blocks_writes_and_success_retires() -> TestResult {
    let mut c = chain(0, 0, 0);
    run(c.start()).unwrap();
    let p = c.pipe;
    let t = c.e.status.pipes[usize::from(p)].unwrap().request.timing;
    let lfc = crate::amdgpu_freesync::LfcConfig::new(
        &t,
        crate::amdgpu_freesync::VrrRange {
            min_hz: 20,
            max_hz: 61,
        },
    )
    .unwrap();
    run(c.e.configure_drr(p, Some(lfc.base()))).unwrap();
    run(c.e.configure_lfc(p, Some(lfc))).unwrap();
    let held = c.e.status.drr;
    let writes = c.e.io.writes;
    let error = Error::Interrupts(crate::amdgpu_ih7::Error::Readback);
    c.e.io.vupdate_error = Some(error);
    assert_eq!(run(c.stop()), Err(error));
    assert_eq!(c.e.status.state, State::Failed(error));
    assert_eq!(c.e.status.drr, held);
    assert!(c.e.io.vupdate_owned);
    assert!(c.e.status.scanout.is_some());
    assert_eq!(c.e.io.writes, writes);
    // A separate successful full chain masks first and then restores fixed
    // timing and retires fetch; it does not merely clear a waiter.
    let mut c = chain(0, 0, 0);
    run(c.start()).unwrap();
    run(c.e.configure_drr(0, Some(lfc.base()))).unwrap();
    run(c.e.configure_lfc(0, Some(lfc))).unwrap();
    assert!(c.e.io.vupdate_owned);
    run(c.stop()).unwrap();
    assert!(!c.e.io.vupdate_owned);
    assert!(c.e.status.drr.is_none());
    assert!(c.e.status.scanout.is_none());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_scanout_vupdate_mask_failure_blocks_writes_and_success_retires
);
fn dcn401_lfc_source_configuration_cancel_and_lost_events_keep_owner() -> TestResult {
    let mut c = chain(0, 0, 0);
    run(c.start()).unwrap();
    let p = c.pipe;
    let t = c.e.status.pipes[usize::from(p)].unwrap().request.timing;
    let lfc_config = crate::amdgpu_freesync::LfcConfig::new(
        &t,
        crate::amdgpu_freesync::VrrRange {
            min_hz: 20,
            max_hz: 61,
        },
    )
    .unwrap();
    run(c.e.configure_drr(p, Some(lfc_config.base()))).unwrap();
    run(c.e.configure_lfc(p, Some(lfc_config))).unwrap();
    // Lost IH history resets BTR even if only one frame appears to have
    // advanced. Nominal DML and source ownership remain retained.
    let plan = c.e.status.scanout.unwrap().plan;
    c.e.io.frozen = true;
    c.e.lfc_preflip(p, 0).unwrap();
    c.e.lfc_preflip(p, 100_000).unwrap();
    assert!(c.e.status.drr.unwrap().lfc().unwrap().active);
    c.e.lfc_resync(p).unwrap();
    assert!(!c.e.status.drr.unwrap().lfc().unwrap().active);
    assert_eq!(c.e.status.scanout.unwrap().plan, plan);
    assert!(c.e.io.vupdate_owned);
    c.e.io.vupdate_pause = true;
    let started = c.e.io.vupdate_started.clone();
    started.store(false, Ordering::SeqCst);
    cancel_at(
        || c.e.configure_lfc(p, None),
        || started.load(Ordering::SeqCst),
    );
    assert_eq!(c.e.status.state, State::UpdatingStream(p));
    assert!(c.e.io.vupdate_owned);
    assert!(c.e.status.drr.unwrap().lfc_enabled());
    assert_eq!(c.e.lfc_idle(p), Err(Error::Busy));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_lfc_source_configuration_cancel_and_lost_events_keep_owner
);

struct TimingWriter {
    requests: Vec<(u8, super::super::drr::DrrTiming)>,
    fail: bool,
    pause: bool,
    started: Arc<AtomicBool>,
}
impl super::super::firmware_timing::TimingTransport for TimingWriter {
    async fn drr(&mut self, otg: u8, timing: super::super::drr::DrrTiming) -> Result<(), Error> {
        self.requests.push((otg, timing));
        self.started.store(true, Ordering::SeqCst);
        if self.pause {
            core::future::pending::<()>().await;
        }
        if self.fail {
            return Err(Error::Firmware(crate::amdgpu_dmub_navi48::Error::Busy));
        }
        Ok(())
    }
}
fn timing_writer() -> TimingWriter {
    TimingWriter {
        requests: Vec::new(),
        fail: false,
        pause: false,
        started: Arc::new(AtomicBool::new(false)),
    }
}
fn firmware_lfc(c: &mut Chain) -> crate::amdgpu_freesync::LfcConfig {
    let p = c.pipe;
    let timing = c.e.status.pipes[usize::from(p)].unwrap().request.timing;
    let config = crate::amdgpu_freesync::LfcConfig::new(
        &timing,
        crate::amdgpu_freesync::VrrRange {
            min_hz: 20,
            max_hz: 61,
        },
    )
    .unwrap();
    run(c.e.configure_drr(p, Some(config.base()))).unwrap();
    run(c.e.configure_lfc(p, Some(config))).unwrap();
    // The caller supplied the same acknowledged request to FAMS2 before
    // handing over ownership. Firmware subsequently clamps these registers.
    c.e.handoff_drr(p, true).unwrap();
    for (r, v) in [
        (0x1b30, 1000),
        (0x1b31, 1001),
        (0x1b32, 17),
        (0x1b33, 0x40003),
    ] {
        c.e.io.put(otg(p, r), v);
    }
    config
}
fn dcn401_firmware_lfc_and_mid_use_requests_through_the_real_flip_owner() -> TestResult {
    use super::super::firmware_timing::{Loan, Spare};
    let mut c = chain(1, 3, 2);
    run(c.start()).unwrap();
    let lfc_config = firmware_lfc(&mut c);
    let p = c.pipe;
    let clock = c.clock;
    run(c.surfaces.prepare_back(&mut c.e, &c.pool, p, config())).unwrap();
    assert_eq!(c.e.lfc_idle(p), Err(Error::Busy));
    let identity = (&*c.e.status as *const _, &*c.e.displays as *const _);
    let mut spare = Some(Spare::new());
    let mut writer = timing_writer();
    {
        let mut loan = Loan::new(&mut c.e, &mut spare, &mut writer).unwrap();
        loan.lfc_preflip(p, 0).unwrap();
        loan.lfc_preflip(p, 100_000).unwrap();
        loan.lfc_idle(p).unwrap();
        run(loan.flush_drr(p)).unwrap();
        run(c
            .surfaces
            .flip(&mut *loan, p, CRYSTAL_KHZ, || Ok((clock, config()))))
        .unwrap();
        run(c.surfaces.set_color(&mut *loan, p, None)).unwrap();
        run(loan.configure_lfc(p, None)).unwrap();
        run(loan.flush_drr(p)).unwrap();
        loan.set_drr_mid(
            p,
            Some(crate::amdgpu_dcn401_otg::DrrMid {
                v_total: lfc_config.base().v_total_min + 1,
                frames: 3,
            }),
        )
        .unwrap();
        run(loan.flush_drr(p)).unwrap();
    }
    assert_eq!(
        identity,
        (&*c.e.status as *const _, &*c.e.displays as *const _)
    );
    assert!(spare.is_some());
    assert!(writer.requests.len() >= 3);
    assert!(writer.requests.iter().all(|(otg, _)| *otg == 2));
    assert_eq!(writer.requests.last().unwrap().1.mid.unwrap().frames, 3);
    for (r, v) in [
        (0x1b30, 1000),
        (0x1b31, 1001),
        (0x1b32, 17),
        (0x1b33, 0x40003),
    ] {
        assert_eq!(
            c.e.io.get(otg(p, r)),
            v,
            "native write replaced firmware timing"
        );
    }
    let writes = c.e.io.writes;
    assert_eq!(run(c.stop()), Err(Error::Busy));
    assert_eq!(c.e.io.writes, writes);
    assert_eq!(c.e.handoff_drr(p, false), Err(Error::Busy));
    // An acknowledged firmware clear cancels the finite sequence before
    // ownership changes; replaying its original count would start it again.
    {
        let mut loan = Loan::new(&mut c.e, &mut spare, &mut writer).unwrap();
        loan.set_drr_mid(p, None).unwrap();
        run(loan.flush_drr(p)).unwrap();
    }
    c.e.handoff_drr(p, false).unwrap();
    assert!(!c.e.status.drr.unwrap().firmware_owned());
    assert_eq!(c.e.io.get(otg(p, 0x1b32)), 0);
    run(c.check()).unwrap();
    c.e.handoff_drr(p, true).unwrap();
    let writes = c.e.io.writes;
    let held = c.e.status.scanout;
    let control = c.e.io.get(h(p, HUBP_CONTROL));
    c.e.io.put(h(p, HUBP_CONTROL), control | HUBP_UNDERFLOW);
    assert!(matches!(run(c.check()), Err(Error::Underflow(_))));
    assert_eq!(c.e.io.writes, writes);
    assert_eq!(c.e.status.scanout, held);
    assert!(matches!(c.e.status.state, State::Failed(_)));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_firmware_lfc_and_mid_use_requests_through_the_real_flip_owner
);

fn dcn401_firmware_timing_cancel_restores_the_quarantined_owner() -> TestResult {
    use super::super::firmware_timing::{Loan, Spare};
    let mut c = chain(1, 3, 2);
    run(c.start()).unwrap();
    let lfc_config = firmware_lfc(&mut c);
    let p = c.pipe;
    let mut spare = Some(Spare::new());
    let mut writer = timing_writer();
    writer.pause = true;
    let started = writer.started.clone();
    let held = c.e.status.scanout;
    let writes = c.e.io.writes;
    cancel_at(
        || async {
            let mut loan = Loan::new(&mut c.e, &mut spare, &mut writer).unwrap();
            loan.configure_lfc(p, None).await.unwrap();
            loan.set_drr_mid(
                p,
                Some(crate::amdgpu_dcn401_otg::DrrMid {
                    v_total: lfc_config.base().v_total_min + 1,
                    frames: 3,
                }),
            )
            .unwrap();
            loan.flush_drr(p).await
        },
        || started.load(Ordering::SeqCst),
    );
    assert!(spare.is_some());
    assert_eq!(c.e.status.state, State::UpdatingStream(p));
    assert_eq!(c.e.status.scanout, held);
    assert_eq!(c.e.lfc_idle(p), Err(Error::Busy));
    assert_eq!(c.e.io.writes, writes);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_firmware_timing_cancel_restores_the_quarantined_owner
);

fn dcn401_firmware_flip_cannot_publish_before_timing_ack() -> TestResult {
    use super::super::firmware_timing::{Loan, Spare};
    for pause in [false, true] {
        let mut c = chain(1, 3, 2);
        run(c.start()).unwrap();
        firmware_lfc(&mut c);
        let p = c.pipe;
        let clock = c.clock;
        run(c.surfaces.prepare_back(&mut c.e, &c.pool, p, config())).unwrap();
        let mut spare = Some(Spare::new());
        let mut writer = timing_writer();
        writer.pause = pause;
        writer.fail = !pause;
        let started = writer.started.clone();
        let writes = c.e.io.inner.inner.writes.len();
        let held = c.e.status.scanout.map(|a| (a.pipe, a.plan));
        let buffers = c.surfaces.retained_buffers(p);
        let flip = {
            let c = &mut *c;
            let spare = &mut spare;
            let writer = &mut writer;
            move || async move {
                let mut loan = Loan::new(&mut c.e, spare, writer).unwrap();
                loan.io.io.frozen = true;
                loan.lfc_resync(p).unwrap();
                loan.lfc_preflip(p, 0).unwrap();
                loan.lfc_preflip(p, 100_000).unwrap();
                loan.io.io.frame += 1;
                c.surfaces
                    .flip(&mut *loan, p, CRYSTAL_KHZ, || Ok((clock, config())))
                    .await
            }
        };
        if pause {
            cancel_at(flip, || started.load(Ordering::SeqCst));
        } else {
            assert!(run(flip()).is_err());
        }
        assert!(started.load(Ordering::SeqCst));
        assert_eq!(
            &c.e.io.inner.inner.writes[writes..],
            &[(0x7f000, 0)],
            "only an HDP flush may precede the timing ACK"
        );
        assert_eq!(c.e.status.scanout.map(|a| (a.pipe, a.plan)), held);
        assert_eq!(c.surfaces.retained_buffers(p), buffers);
        assert!(spare.is_some());
        if pause {
            assert_eq!(c.e.status.state, State::Flipping(p));
        } else {
            assert!(matches!(c.e.status.state, State::Failed(_)));
        }
        assert_eq!(c.e.lfc_idle(p), Err(Error::Busy));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_firmware_flip_cannot_publish_before_timing_ack
);

#[inline(never)]
fn subvp_chain() -> (
    alloc::boxed::Box<Chain>,
    alloc::boxed::Box<dml::pstate::Phantom>,
) {
    let mut mode = plan().mode;
    mode.timing = Timing {
        pixel_clock_khz: 533_250,
        h_active: 3840,
        h_total: 4000,
        h_front_porch: 48,
        h_sync_width: 32,
        v_active: 800,
        v_total: 840,
        v_front_porch: 3,
        v_sync_width: 5,
        h_sync_positive: false,
        v_sync_positive: false,
    };
    mode.pitch = 3840;
    mode.bytes_per_pixel = 8;
    let uclk = dml::pstate::UclkLevels::new(&[96_000, 456_000, 772_000, 1_250_000]).unwrap();
    let s = dml::pstate::admit_subvp(&soc(), &uclk, &mode, 64 * 1024 * 1024)
        .unwrap()
        .expect("3840x800 FP16 SubVP");
    let p = 2;
    let (stage, address) = harvest::on_full_pool(|| {
        let mut stage = staged(p, &s.plans[0]);
        let address = stage_deadlines(&mut stage, p, &s.plans[0]);
        (stage, address)
    });
    let mut c = hdmi_chain(stage, 1, 3, p, address);
    let clock = c.clock;
    start_hdmi(&mut c.e, 1, 3, p, clock);
    // The single-display staging fixtures keep their selected record in
    // slot zero even when the hardware pipe is different. Native Otg uses
    // the stream's head pipe as its slot; model that identity here before
    // testing selection and parked-owner lookup.
    c.e.displays.selected = p;
    run(c.start()).unwrap();
    // A powered spare after an earlier plane retired. DOMAIN power-up itself
    // is exercised by the existing gate_hubp/PGFSM suite.
    let q = c.e.layout.pool.pipes().find(|&q| q != p).unwrap();
    let inst = c.e.layout.inst(q);
    c.e.io.inner.inner.forbidden_hubps &= !bit(inst);
    for (at, value) in [
        (BASE + (0x80 + 2 * u64::from(inst)) * 4, 0),
        (BASE + (0x81 + 2 * u64::from(inst)) * 4, 0),
        (h(inst, 0x5f4), 3),
        (h(inst, 0x5f5), 0),
        (h(inst, 0x679), 0),
        (h(inst, 0x613), 0),
        (h(inst, 0x614), 0),
        (h(inst, 0x5f7), 8),
    ] {
        c.e.io.put(at, value);
    }
    (c, s.phantom.unwrap())
}

fn dcn401_subvp_retains_alias_until_firmware_off_and_phantom_drained() -> TestResult {
    let (mut c, phantom) = subvp_chain();
    let p = c.pipe;
    let q = c.e.reserve_subvp(p).unwrap();
    let before = c.surfaces.retained_buffers(p).unwrap();
    let mut clock = c.clock;
    clock.request.pipe = q;
    clock.request.pixel = dccg::PixelClock::DisplayPort {
        pixel_hz: u64::from(phantom.plan.mode.timing.pixel_clock_khz) * 1000,
    };
    clock.request.dpp_khz = phantom.plan.clocks.dppclk_khz;
    let l = c.e.layout;
    // Blank/unblank and disconnected MPCC acknowledgement for the spare;
    // the original model covers only the main's latch group.
    c.e.io.extra |= bit(l.inst(q));
    run_boxed(|| c.e.program_subvp(&phantom.plan, clock)).unwrap();
    assert_eq!(c.e.status.state, State::ScanoutRunning(p));
    assert_eq!(c.e.io.get(h(l.inst(q), 0x60a)), c.address as u32);
    assert_eq!(c.e.io.get(h(l.inst(q), 0x60b)), (c.address >> 32) as u32);
    assert_eq!(c.e.io.get(h(l.inst(q), 0x5f7)) & 7, 1);
    assert_eq!(c.e.io.get(h(l.inst(p), 0x5f7)) & 7, 2);
    assert_eq!(c.e.io.get(otg(l.inst(q), 0x1b43)) & 0x10001, 0);
    assert_eq!(
        c.e.io.get(BASE + (0x4bb + u64::from(l.inst(q))) * 4) & 0x1f,
        0
    );
    c.e.handoff_subvp(true).unwrap();
    let owner = c.e.subvp().unwrap();
    c.e.select_display(q).unwrap();
    assert_eq!(c.e.subvp(), Some(owner));
    c.e.select_display(p).unwrap();
    c.e.io.put(otg(l.inst(p), 0x1b30), 17);
    c.e.io.put(otg(l.inst(p), 0x1b31), 1800);
    c.e.io.put(otg(l.inst(p), 0x1b33), 3);
    assert_eq!(run_boxed(|| c.e.retire_subvp()), Err(Error::Busy));
    assert_eq!(c.surfaces.retained_buffers(p), Some(before));
    assert!(run(c.check()).is_ok());
    c.e.handoff_subvp(false).unwrap();
    assert_eq!(c.e.io.get(otg(l.inst(p), 0x1b30)), 839);
    assert_eq!(c.e.io.get(otg(l.inst(p), 0x1b31)), 839);
    // The spare's MPCC disconnect follows a normal OTG update in hardware.
    c.e.io.inner.inner.disconnecting = true;
    c.e.select_display(q).unwrap();
    assert_eq!(run_boxed(|| c.e.retire_subvp()), Ok(Some(q)));
    assert!(c.e.subvp().is_none());
    assert!(c.e.status.surfaces[usize::from(q)].is_none());
    assert_eq!(c.surfaces.retained_buffers(p), Some(before));
    assert_eq!(c.e.io.get(h(l.inst(p), 0x5f7)) & 0x1f, 8);
    assert!(run(c.check()).is_ok());
    let surface = c.e.status.surfaces[usize::from(p)].unwrap();
    let address = 0x9_0040_0000; // different high word from the retired alias
    let external = ExternalSurface {
        address,
        pitch_bytes: surface.pitch_bytes,
        chroma: None,
        last: address + u64::from(surface.pitch_bytes) * u64::from(surface.request.height) - 1,
        dcc_aligned: false,
    };
    assert!(run(c.flip_to(FlipSource::External(external))).is_ok());
    assert_eq!(c.e.status.scanout.unwrap().address, address);
    assert!(run(c.stop()).is_ok());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_subvp_retains_alias_until_firmware_off_and_phantom_drained
);

fn dcn401_subvp_partial_setup_keeps_main_buffer_and_spare_owned() -> TestResult {
    for cancel in [false, true] {
        let (mut c, phantom) = subvp_chain();
        let p = c.pipe;
        let q = c.e.reserve_subvp(p).unwrap();
        let before = c.surfaces.retained_buffers(p).unwrap();
        let mut clock = c.clock;
        clock.request.pipe = q;
        clock.request.pixel = dccg::PixelClock::DisplayPort {
            pixel_hz: u64::from(phantom.plan.mode.timing.pixel_clock_khz) * 1000,
        };
        clock.request.dpp_khz = phantom.plan.clocks.dppclk_khz;
        let l = c.e.layout;
        c.e.io.extra |= bit(l.inst(q));
        if cancel {
            c.e.io.inner.inner.stall |= 256; // phantom counter cannot advance
            c.e.io.pause_wait = true;
            cancel_at(|| c.e.program_subvp(&phantom.plan, clock), || true);
        } else {
            let at = h(l.inst(q), 0x60b);
            c.e.io.drop = Some(at); // lose the high address before fetch
            assert_eq!(
                run_boxed(|| c.e.program_subvp(&phantom.plan, clock)),
                Err(Error::Readback(h(l.inst(q), 0x60b)))
            );
        }
        assert_eq!(c.e.status.state, State::UpdatingStream(p));
        assert_eq!(c.surfaces.retained_buffers(p), Some(before));
        assert!(c.e.status.surfaces[usize::from(q)].is_some());
        assert_eq!(Siblings::of(&c.e.status).pipes & bit(q), bit(q));
        assert_eq!(c.e.reserve_subvp(p), Err(Error::Busy));
        assert_eq!(run_boxed(|| c.e.retire_subvp()), Err(Error::Busy));
        assert_eq!(run(c.stop()), Err(Error::Busy));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-scanout",
    dcn401_subvp_partial_setup_keeps_main_buffer_and_spare_owned
);
