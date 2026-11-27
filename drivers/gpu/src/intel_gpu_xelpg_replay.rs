//! Panel Replay on the owned external DP routes behind
//! `narf.intel.ext_panel_replay=1`, with the frontbuffer tracking that takes
//! the sink out of replay when the console scanout changes.
//!
//! Pinned source: Linux 7.4-rc4 `i915/display/intel_psr.c`
//! (`intel_psr_panel_replay_enable_sink`, `_panel_replay_compute_config`,
//! `_intel_psr_min_set_context_latency`, `intel_psr_enable_locked`,
//! `intel_psr_activate`, `intel_psr_exit`, `intel_psr_force_update`,
//! `intel_psr_invalidate`, `_psr_invalidate_handle`, `intel_psr_flush`,
//! `_psr_flush_handle`, `intel_psr_work`, `__psr_wait_for_idle_locked`,
//! `intel_psr_pause`, `intel_psr_resume`, `intel_psr_disable`),
//! `intel_frontbuffer.c` / `.h` (`frontbuffer_flush`,
//! `__intel_frontbuffer_invalidate`, `__intel_frontbuffer_flush`,
//! `INTEL_FRONTBUFFER`, `INTEL_FRONTBUFFER_ALL_MASK`, `enum fb_op_origin`),
//! `intel_fbdev.c` (`intelfb_dirty`: console damage reaches
//! `intel_user_framebuffer_dirty` and an `ORIGIN_DIRTYFB` flush),
//! `intel_ddi.c` (`intel_ddi_pre_enable_dp`, `intel_ddi_disable_dp`),
//! `intel_cx0_phy.c` (`intel_cx0_phy_transaction_begin`/`_end` pause
//! replay around PHY message-bus traffic) and `intel_cdclk.c`
//! (`intel_set_cdclk` pauses every replay around a CDCLK change).
//!
//! ## What runs
//!
//! - **Sink enable before training.** With the option on, the route's
//!   `mtl_ddi_pre_enable_dp` equivalent writes `PANEL_REPLAY_CONFIG` =
//!   `DP_PANEL_REPLAY_ENABLE` before link training, on 8b/10b and 128b/132b
//!   SST links ([`pretrain`]); MST never takes replay (`_panel_replay_init_dpcd`).
//! - **Enable.** After the service lit an SST DP route ([`Replays::after_event`]
//!   on `ServiceOutcome::Activated`), `_panel_replay_compute_config` runs
//!   against the route's link, timing and DSC, the sink's capability and the
//!   live set context latency, then [`PanelReplay::enable`] and
//!   `intel_psr_activate`, as `intel_psr_post_plane_update` does once the
//!   modeset committed. Selective update is not offered: the route's
//!   primary is armed once and never programs selective fetch, so
//!   `intel_sel_update_config_valid` fails as it does on display 14+
//!   without selective fetch, and replay runs full frame. The enable
//!   sends the replay VSC SDP and, for an AS SDP v2 sink that is no branch
//!   (`intel_dp_needs_as_sdp`), the fixed-vtotal Adaptive-Sync SDP
//!   ([`crate::intel_gpu_psr::panel_replay::as_sdp_needed`]) on the AS SDP
//!   timing the display-30 route programs (`TRANS_VRR_VSYNC`).
//! - **Frontbuffer flush.** The route scans out the console surface, which
//!   the kernel's fb console writes with the CPU. Each fb console flush of
//!   the published image ([`frontbuffer_flush`]) queues the route's slot,
//!   as `drm_fb_helper`'s damage worker queues `intelfb_dirty`; the next
//!   runtime pass ([`Replays::pass`]) runs `intel_psr_flush` with
//!   `ORIGIN_DIRTYFB` for the slot's primary frontbuffer bit: on display
//!   20+ `intel_psr_exit`, below it `intel_psr_force_update`, then the
//!   re-arm. `intel_psr_work`'s idle wait is not a blocking wait here: each
//!   pass polls the replay status once, until idle or the 50 ms bound
//!   (after which replay stays inactive until the next flush, as Linux
//!   leaves it until the next cycle).
//! - **Pause.** Every hotplug event the service handles may drive PHY
//!   message-bus traffic, a CDCLK change or a sibling modeset, so the
//!   service pauses every replay for the whole event (`intel_psr_pause`:
//!   exit, then the 2 s idle wait) and resumes the survivors after it
//!   (`intel_psr_resume`).
//! - **Disable.** Before a route stops (unplug, redetect, retrain,
//!   suspend or reset teardown) `intel_psr_disable` runs, as
//!   `intel_ddi_disable_dp` does before the pipe goes off.
//!
//! Refused, typed ([`Refusal`]): the option off, MST, a sink without
//! replay, DSC a sink cannot decode in replay, display 35 (not qualified),
//! display 14 (Wa_14015648006 needs the route pipe's `wm_level_disabled`,
//! which the Pipe B-D owner does not publish), and a lit transcoder whose
//! set context latency is below `_intel_psr_min_set_context_latency`
//! (display 20 DP needs one line; the route is lit without it). That
//! leaves display 30 (Panther and Wildcat Lake). DC3CO is never allowed
//! here (`HAS_DC3CO` is display 35+), so `psr2_dc3co_flush_locked` is inert.

extern crate alloc;

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use alloc::boxed::Box;

use super::{MtlExternalRoute, MtlProtocol, MtlRoute, RouteState, ServiceOutcome, MAX_ROUTES};
use crate::intel_gpu_aux::{IntelAux, MmioWindow};
use crate::intel_gpu_psr::panel_replay::{self as pr, PanelReplay, Refusal};

/// The strict default-off option.
pub const BOOT_OPTION: &str = "narf.intel.ext_panel_replay";

/// Whether the boot command line carries exactly `narf.intel.ext_panel_replay=1`.
pub fn opted_in() -> bool {
    crate::intel_gpu_gt::boot_opt_in(narf_boot::args(), BOOT_OPTION)
}

// ── Frontbuffer tracking (intel_frontbuffer.h) ───────────────────

/// `enum fb_op_origin`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    Cpu,
    Cs,
    Flip,
    Dirtyfb,
    CursorUpdate,
}

/// `INTEL_FRONTBUFFER_BITS_PER_PIPE`.
pub const FRONTBUFFER_BITS_PER_PIPE: u32 = 8;
/// `PLANE_PRIMARY` (`PLANE_1`).
pub const PLANE_PRIMARY: u8 = 0;

/// `INTEL_FRONTBUFFER(pipe, plane_id)`.
pub const fn frontbuffer(pipe: u8, plane: u8) -> u32 {
    1 << (plane as u32 + FRONTBUFFER_BITS_PER_PIPE * pipe as u32)
}

/// `INTEL_FRONTBUFFER_ALL_MASK(pipe)`.
pub const fn frontbuffer_all_mask(pipe: u8) -> u32 {
    0xff << (FRONTBUFFER_BITS_PER_PIPE * pipe as u32)
}

/// `CURSURFLIVE(pipe)` (`TGL_CURSOR_OFFSETS`: pipes 0x1000 apart).
pub const fn cursurflive(pipe: u8) -> u64 {
    crate::intel_gpu_psr::CURSURFLIVE + 0x1000 * pipe as u64
}

/// `__psr_wait_for_idle_locked`'s 50 ms bound, in ns.
pub const WORK_IDLE_TIMEOUT_NS: u64 = crate::intel_gpu_psr::PSR_IDLE_TIMEOUT_MS * 1_000_000;

/// What one step of the re-arm work did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkStep {
    /// No work was queued.
    Idle,
    /// Still waiting for the replay state machine to go idle.
    Waiting,
    /// `intel_psr_activate` ran.
    Activated,
    /// The work finished without activating: paused, busy or already
    /// active (`goto unlock`).
    Skipped,
    /// The idle wait exceeded its bound; replay stays inactive until the
    /// next flush queues the work again.
    TimedOut,
}

/// One route's Panel Replay with `intel_dp->psr`'s frontbuffer state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtReplay {
    replay: PanelReplay,
    /// The route it runs on.
    port: crate::intel_gpu_xelpg::XeLpgPort,
    pipe: u8,
    /// `psr.busy_frontbuffer_bits`.
    busy: u32,
    /// `psr.pause_counter`.
    pause: u32,
    /// `psr.work` is queued.
    work: bool,
    /// The end of the queued work's idle wait, once it started.
    work_deadline: Option<u64>,
}

impl ExtReplay {
    /// A replay [`PanelReplay::enable`] returned for the route on `port`
    /// and `pipe` (`busy_frontbuffer_bits` = 0, `pause_counter` = 0).
    pub fn new(replay: PanelReplay, port: crate::intel_gpu_xelpg::XeLpgPort, pipe: u8) -> Self {
        Self {
            replay,
            port,
            pipe,
            busy: 0,
            pause: 0,
            work: false,
            work_deadline: None,
        }
    }

    pub fn replay(&self) -> PanelReplay {
        self.replay
    }
    pub fn pipe(&self) -> u8 {
        self.pipe
    }
    pub fn port(&self) -> crate::intel_gpu_xelpg::XeLpgPort {
        self.port
    }
    /// `psr.busy_frontbuffer_bits`.
    pub fn busy(&self) -> u32 {
        self.busy
    }
    /// `psr.pause_counter`.
    pub fn pause_count(&self) -> u32 {
        self.pause
    }
    /// `psr.work` is queued.
    pub fn work_queued(&self) -> bool {
        self.work
    }

    /// Whether this replay belongs to `route` (same port and pipe).
    pub fn serves(&self, route: &MtlExternalRoute) -> bool {
        route.probe.port == self.port && route.pipe() as u8 == self.pipe
    }

    /// `intel_psr_activate` (the last step of `intel_psr_enable_locked`).
    pub fn activate<M: MmioWindow + ?Sized>(&mut self, regs: &M) -> Result<(), Refusal> {
        self.replay.activate(regs)
    }

    /// `intel_psr_invalidate` for this encoder: a flip never invalidates;
    /// otherwise the pipe's bits turn busy and `_psr_invalidate_handle`
    /// exits replay (no selective fetch runs on these routes, so the
    /// display-13 continuous-full-frame branch never applies).
    pub fn invalidate<M: MmioWindow + ?Sized>(
        &mut self,
        regs: &M,
        bits: u32,
        origin: Origin,
    ) -> Result<(), Refusal> {
        if origin == Origin::Flip {
            return Ok(());
        }
        let bits = bits & frontbuffer_all_mask(self.pipe);
        self.busy |= bits;
        if bits != 0 {
            self.replay.exit(regs)?;
        }
        Ok(())
    }

    /// `intel_psr_flush` for this encoder: the pipe's bits leave busy; unless
    /// paused or a flip, `_psr_flush_handle` (display 20+ exit, below it
    /// `intel_psr_force_update`'s `CURSURFLIVE` write); then the re-arm
    /// queues `intel_psr_work` once nothing is busy and replay is neither
    /// active nor paused.
    pub fn flush<M: MmioWindow + ?Sized>(
        &mut self,
        regs: &M,
        bits: u32,
        origin: Origin,
    ) -> Result<(), Refusal> {
        let bits = bits & frontbuffer_all_mask(self.pipe);
        if bits == 0 {
            return Ok(());
        }
        self.busy &= !bits;
        // psr2_dc3co_flush_locked: DC3CO is never allowed (HAS_DC3CO).
        if self.pause == 0 && origin != Origin::Flip {
            if self.replay.config().display_ver >= 20 {
                self.replay.exit(regs)?;
            } else {
                regs.write32(cursurflive(self.pipe), 0);
            }
        }
        if self.busy == 0 && !self.replay.active() && self.pause == 0 && !self.work {
            self.work = true;
            self.work_deadline = None;
        }
        Ok(())
    }

    /// One non-blocking step of `intel_psr_work`: paused work ends; the idle
    /// wait (`__psr_wait_for_idle_locked`, 50 ms from its first step) polls
    /// once; once idle, a busy or active replay ends the work, anything else
    /// activates.
    pub fn run_work<M: MmioWindow + ?Sized>(
        &mut self,
        regs: &M,
        now_ns: u64,
    ) -> Result<WorkStep, Refusal> {
        if !self.work {
            return Ok(WorkStep::Idle);
        }
        if self.pause != 0 {
            self.finish_work();
            return Ok(WorkStep::Skipped);
        }
        let deadline = *self
            .work_deadline
            .get_or_insert(now_ns.saturating_add(WORK_IDLE_TIMEOUT_NS));
        let idle = match self.replay.idle(regs) {
            Ok(idle) => idle,
            Err(refusal) => {
                self.finish_work();
                return Err(refusal);
            }
        };
        if !idle {
            if now_ns >= deadline {
                self.finish_work();
                return Ok(WorkStep::TimedOut);
            }
            return Ok(WorkStep::Waiting);
        }
        self.finish_work();
        if self.busy != 0 || self.replay.active() {
            return Ok(WorkStep::Skipped);
        }
        self.replay.activate(regs)?;
        Ok(WorkStep::Activated)
    }

    fn finish_work(&mut self) {
        self.work = false;
        self.work_deadline = None;
    }

    /// `intel_psr_pause`: the first pause exits replay; every pause cancels
    /// the queued work. Returns whether the caller must now wait for idle
    /// (`intel_psr_wait_exit_locked`, [`PanelReplay::wait_idle`]).
    pub fn pause<M: MmioWindow + ?Sized>(&mut self, regs: &M) -> Result<bool, Refusal> {
        let first = self.pause == 0;
        self.pause += 1;
        self.finish_work();
        if first {
            self.replay.exit(regs)?;
        }
        Ok(first)
    }

    /// `intel_psr_resume`: an unbalanced resume changes nothing; the last
    /// one activates.
    pub fn resume<M: MmioWindow + ?Sized>(&mut self, regs: &M) -> Result<(), Refusal> {
        if self.pause == 0 {
            return Ok(());
        }
        self.pause -= 1;
        if self.pause == 0 {
            self.replay.activate(regs)?;
        }
        Ok(())
    }

    /// `intel_psr_disable`: `intel_psr_disable_locked`, then the queued
    /// work is cancelled.
    pub fn disable<M: MmioWindow + ?Sized>(
        &mut self,
        regs: &M,
        timeout_ms: u64,
    ) -> Result<(), Refusal> {
        let result = self.replay.disable(regs, timeout_ms);
        self.finish_work();
        self.pause = 0;
        result
    }
}

// ── Qualification ─────────────────────────────────────────────────

/// `TRANS_SET_CONTEXT_LATENCY(trans)`.
pub const fn trans_set_context_latency(trans: u8) -> u64 {
    0x6007c + 0x1000 * trans as u64
}

/// The replay stream of a lit SST DP route (`crtc_state`): the trained
/// link, the route's timing and compression, and no selective fetch.
pub(crate) fn stream_for(route: &MtlExternalRoute) -> Result<pr::Stream, Refusal> {
    let mode = &route.probe.mode;
    let timing = crate::intel_gpu_dsb::Timing {
        clock: mode.pixel_clock_khz,
        width: mode.h_active,
        height: mode.v_active,
        htotal: mode.h_total,
        vtotal: mode.v_total,
        flags: 0,
    };
    if !timing.valid() {
        return Err(Refusal::NoTiming);
    }
    let uhbr = route.probe.uhbr.is_some();
    Ok(pr::Stream {
        display_ver: route.probe.display_version(),
        pipe: route.pipe() as u8,
        // PORT_ALPM_* are eDP only.
        port: 0,
        port_clock: if uhbr {
            route.probe.port_clock_khz()
        } else {
            super::link_clock_khz(route.trained.rate)
        },
        lanes: u32::from(route.trained.lanes),
        timing,
        dsc: route.probe.dsc.is_some(),
        uhbr,
        // _panel_replay_compute_config refuses HDCP on eDP only.
        hdcp: false,
        as_sdp_v2: false,
        edp_rev: 0,
        fw_sync_quirk: false,
        sel_fetch: false,
    })
}

/// `intel_psr_compute_config`'s Panel Replay half and
/// `intel_psr_enable_locked` for the lit SST DP `route`, then
/// `intel_psr_activate`. Every refusal precedes the first write; a failed
/// activation disables what the enable programmed.
#[inline(never)]
pub(crate) fn enable_route<M: MmioWindow + ?Sized>(
    io: &M,
    route: &MtlExternalRoute,
    opted_in: bool,
) -> Result<ExtReplay, Refusal> {
    if !opted_in {
        return Err(Refusal::Disabled);
    }
    if route.probe.mst.is_some() {
        return Err(Refusal::Mst);
    }
    if route.state() != RouteState::Live {
        return Err(Refusal::Unavailable);
    }
    let stream = stream_for(route)?;
    pr::source_supported(stream.display_ver, false)?;
    let mut aux = IntelAux::xelpdp(io, route.probe.port.aux_base(), route.probe.tbt());
    let caps = pr::Caps::read(&mut aux, false, false)?;
    let stream = pr::Stream {
        as_sdp_v2: pr::as_sdp_needed(&mut aux, route.probe.caps.dpcd_rev, &caps),
        ..stream
    };
    // Wa_14015648006 (display 14): the route pipe's wm_level_disabled is
    // not published, so compute refuses WmLevelUnknown there.
    let config = pr::compute(&caps, &stream, None)?;
    // The set context latency the modeset would have programmed for a
    // replay stream (`intel_crtc_set_context_latency`), against the live one.
    let scl = io.read32(trans_set_context_latency(stream.pipe));
    if scl == u32::MAX || !io.display_access_ok() {
        return Err(Refusal::Unavailable);
    }
    if scl < pr::min_set_context_latency(stream.display_ver, false, true, config.su, true) {
        return Err(Refusal::SetContextLatency);
    }
    let replay = PanelReplay::enable(io, &mut aux, config)?;
    let mut ext = ExtReplay::new(replay, route.probe.port, stream.pipe);
    if let Err(refusal) = ext.activate(io) {
        let _ = ext.disable(io, crate::intel_gpu_psr::PSR_EXIT_TIMEOUT_MS);
        return Err(refusal);
    }
    Ok(ext)
}

// ── The service's replays ─────────────────────────────────────────

#[derive(Debug, Default)]
struct Slots {
    replays: [Option<ExtReplay>; MAX_ROUTES],
    refused: [Option<Refusal>; MAX_ROUTES],
}

/// The Panel Replays of one external service's route slots. The state is
/// allocated on the first enable, so a service that never runs replay
/// carries only a pointer.
#[derive(Debug, Default)]
pub(crate) struct Replays {
    slots: Option<Box<Slots>>,
    /// The `narf.intel.ext_panel_replay` decision; `None` reads the boot
    /// option.
    opt: Option<bool>,
}

impl Replays {
    pub(crate) const fn new() -> Self {
        Self {
            slots: None,
            opt: None,
        }
    }

    /// Decide the option instead of reading the boot command line (fixtures).
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn set_opted_in(&mut self, on: bool) {
        self.opt = Some(on);
    }

    pub(crate) fn opted_in(&self) -> bool {
        self.opt.unwrap_or_else(opted_in)
    }

    /// The replay running on `slot`'s route.
    pub(crate) fn get(&self, slot: usize) -> Option<&ExtReplay> {
        self.slots.as_ref()?.replays.get(slot)?.as_ref()
    }

    /// Why `slot`'s last activation runs no replay.
    pub(crate) fn refusal(&self, slot: usize) -> Option<Refusal> {
        *self.slots.as_ref()?.refused.get(slot)?
    }

    /// One bit per slot that runs replay.
    pub(crate) fn live_mask(&self) -> u8 {
        (0..MAX_ROUTES).fold(0, |mask, slot| {
            mask | u8::from(self.get(slot).is_some()) << slot
        })
    }

    fn slots_mut(&mut self) -> &mut Slots {
        self.slots.get_or_insert_with(Box::default)
    }

    /// `intel_psr_pause` on every running replay before an event's
    /// hardware conversation, each followed by its idle wait. A replay
    /// whose registers are gone is dropped (its route's stop follows).
    #[inline(never)]
    pub(crate) fn pause_all<M: MmioWindow + ?Sized>(&mut self, io: &M) {
        let Some(slots) = self.slots.as_mut() else {
            return;
        };
        for slot in 0..MAX_ROUTES {
            let Some(replay) = slots.replays[slot].as_mut() else {
                continue;
            };
            match replay.pause(io) {
                // intel_psr_wait_exit_locked only logs its timeout.
                Ok(true) => {
                    let _ = replay
                        .replay()
                        .wait_idle(io, crate::intel_gpu_psr::PSR_EXIT_TIMEOUT_MS);
                }
                Ok(false) => {}
                Err(refusal) => {
                    slots.replays[slot] = None;
                    slots.refused[slot] = Some(refusal);
                }
            }
        }
    }

    /// `intel_psr_disable` on `slot` before its route's pipe goes off.
    pub(crate) fn disable<M: MmioWindow + ?Sized>(&mut self, io: &M, slot: usize) {
        let Some(slots) = self.slots.as_mut() else {
            return;
        };
        if let Some(mut replay) = slots.replays.get_mut(slot).and_then(Option::take) {
            let _ = replay.disable(io, crate::intel_gpu_psr::PSR_EXIT_TIMEOUT_MS);
        }
    }

    /// After an event: the replays paused for it resume on the routes they
    /// were enabled on (any other was disabled before its route stopped),
    /// and a DP SST route the event lit gets its replay.
    #[inline(never)]
    pub(crate) fn after_event<M: MmioWindow + ?Sized>(
        &mut self,
        io: &M,
        routes: &[Option<MtlRoute>; MAX_ROUTES],
        outcome: &ServiceOutcome,
    ) {
        let activated = match outcome {
            ServiceOutcome::Activated {
                port,
                protocol: MtlProtocol::Dp,
                ..
            } => Some(*port),
            _ => None,
        };
        for (slot, route) in routes.iter().enumerate() {
            let live = match route {
                Some(MtlRoute::Dp(route)) if route.state() == RouteState::Live => Some(route),
                _ => None,
            };
            let running = self.get(slot).copied();
            match (running, live) {
                (Some(mut replay), Some(route)) if replay.serves(route) => {
                    let slots = self.slots_mut();
                    match replay.resume(io) {
                        Ok(()) => slots.replays[slot] = Some(replay),
                        Err(refusal) => {
                            let _ = replay.disable(io, crate::intel_gpu_psr::PSR_EXIT_TIMEOUT_MS);
                            slots.replays[slot] = None;
                            slots.refused[slot] = Some(refusal);
                        }
                    }
                }
                (Some(_), _) => self.disable(io, slot),
                (None, Some(route)) if activated == Some(route.probe.port) => {
                    let result = enable_route(io, route, self.opted_in());
                    let slots = self.slots_mut();
                    match result {
                        Ok(replay) => {
                            slots.replays[slot] = Some(replay);
                            slots.refused[slot] = None;
                        }
                        Err(refusal) => slots.refused[slot] = Some(refusal),
                    }
                }
                (None, _) => {}
            }
        }
    }

    /// One runtime pass: `intel_psr_flush(ORIGIN_DIRTYFB)` for each slot in
    /// `dirty` (the console flushes queued since the last pass), then a step
    /// of each queued re-arm work. A replay whose registers are gone is
    /// disabled and dropped.
    #[inline(never)]
    pub(crate) fn pass<M: MmioWindow + ?Sized>(&mut self, io: &M, dirty: u8, now_ns: u64) {
        let Some(slots) = self.slots.as_mut() else {
            return;
        };
        for slot in 0..MAX_ROUTES {
            let Some(replay) = slots.replays[slot].as_mut() else {
                continue;
            };
            let mut result = Ok(WorkStep::Idle);
            if dirty & (1 << slot) != 0 {
                let bits = frontbuffer(replay.pipe(), PLANE_PRIMARY);
                result = replay
                    .flush(io, bits, Origin::Dirtyfb)
                    .map(|()| WorkStep::Idle);
            }
            if result.is_ok() {
                result = replay.run_work(io, now_ns);
            }
            if let Err(refusal) = result {
                let _ = replay.disable(io, crate::intel_gpu_psr::PSR_EXIT_TIMEOUT_MS);
                slots.replays[slot] = None;
                slots.refused[slot] = Some(refusal);
            }
        }
    }
}

// ── The pre-training enable ───────────────────────────────────────

/// Whether the activation in progress takes the pre-training sink enable
/// (the service's option decision, for the call chain it activates).
static PRETRAIN: AtomicBool = AtomicBool::new(false);

/// The service's option decision for one activation: the route's port
/// enable writes `PANEL_REPLAY_CONFIG` before training while it lives.
pub(crate) struct Pretrain(());

impl Pretrain {
    pub(crate) fn set(on: bool) -> Self {
        PRETRAIN.store(on, Ordering::Release);
        Self(())
    }
}

impl Drop for Pretrain {
    fn drop(&mut self) {
        PRETRAIN.store(false, Ordering::Release);
    }
}

/// `intel_psr_panel_replay_enable_sink` from `intel_ddi_pre_enable_dp` on
/// an SST DP route: with the option decided on for this activation and a
/// source and sink that can replay, `PANEL_REPLAY_CONFIG` =
/// `DP_PANEL_REPLAY_ENABLE` before training. Nothing is written otherwise.
pub(crate) fn pretrain<A: crate::dp_aux::AuxChannel + ?Sized>(
    aux: &mut A,
    display_ver: u16,
    mst: bool,
) -> bool {
    pr::enable_before_training(
        aux,
        display_ver,
        false,
        mst,
        PRETRAIN.load(Ordering::Acquire),
    )
}

// ── The console's frontbuffer queue ───────────────────────────────

/// Slots whose route runs replay, as the process-wide service published
/// them.
static LIVE: AtomicU8 = AtomicU8::new(0);
/// Slots whose console surface was flushed since the last pass.
static DIRTY: AtomicU8 = AtomicU8::new(0);

/// Publish which slots run replay (the process-wide service, at the end of
/// every pass). A slot that stops replay drops its queued flush.
pub(crate) fn publish_live(mask: u8) {
    LIVE.store(mask, Ordering::Release);
    DIRTY.fetch_and(mask, Ordering::AcqRel);
}

/// Whether any published route runs replay.
pub fn any_live() -> bool {
    LIVE.load(Ordering::Acquire) != 0
}

/// The fb console flushed the surface `slot` scans out (`intelfb_dirty`).
/// Lock-free and register-free: the flush runs at the next runtime pass.
pub fn frontbuffer_flush(slot: usize) {
    let bit = 1u8 << slot.min(7);
    if LIVE.load(Ordering::Acquire) & bit != 0 {
        DIRTY.fetch_or(bit, Ordering::AcqRel);
    }
}

/// Take the queued flushes.
pub(crate) fn take_dirty() -> u8 {
    DIRTY.swap(0, Ordering::AcqRel)
}

#[cfg(feature = "kernel-test")]
#[path = "intel_gpu_xelpg_replay_tests.rs"]
mod tests;
