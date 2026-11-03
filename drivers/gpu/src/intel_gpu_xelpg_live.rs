//! Display-14.00 live repartitioning: add or remove pipes while other
//! pipes stay lit.
//!
//! MIT Linux b90c984d `intel_display.c::intel_atomic_commit_tail` and
//! `skl_commit_modeset_enables`: PM demand pre-plane, CDCLK pre-plane only
//! when increasing, DBUF pre-plane slices (old | new), MBUS pre-DDB join
//! (`intel_dbuf_mbus_pre_ddb_update`: join, DBOX, min tracker), lit pipes
//! updated in an order where no pipe's new DDB overlaps another pipe's
//! current entry (`skl_ddb_allocation_overlaps`, reverse pipe order), with
//! a vblank wait after a changed allocation while other pipes remain,
//! MBUS post-DDB (`intel_dbuf_mbus_post_ddb_update`: tracker, DBOX,
//! unjoin plus a vblank on the formerly joined pipe, or tracker/DBOX when
//! only the active set changed), DBUF post-plane, CDCLK post-plane when
//! decreasing (`intel_cdclk_is_decreasing_later`) and PM demand post-plane.
//! A lit pipe's plane registers are double buffered and armed by
//! `PLANE_SURF` / `CURBASE` (`icl_plane_update_arm`,
//! `i9xx_cursor_update_arm`); writes happen after
//! `intel_vblank.c::intel_vblank_evade` (100 us before vblank start).
//!
//! Refused with typed errors, before any write: a lit pipe whose
//! configuration changes (Linux needs a modeset of that pipe), an unknown
//! firmware CDCLK (Linux's sanitize path forces every pipe off for the
//! full PLL relock), live FBC/DSB activity, and a DDB order with no
//! non-overlapping step. Pipes that are not lit are programmed directly;
//! the caller turns a removed pipe off before, and enables an added pipe
//! after, this transaction. Its production caller is
//! [`crate::intel_gpu_xelpg_pipes`], itself awaiting the port owner.
#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

use alloc::vec::Vec;

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_pmdemand as pmdemand;
use crate::intel_gpu_xelpg_cdclk as cdclk;
use crate::intel_gpu_xelpg_dbuf::{self as dbuf, Entry};
use crate::intel_gpu_xelpg_resources::{
    checked, read, wait, PipeRequest, ResourceError, Snapshot, State, PIPES, PLANES,
};

/// One ordered step of a live repartition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    PmDemandPre,
    CdclkPre,
    DbufPre,
    /// MBUS join before any DDB growth; `select` is the lit joined pipe.
    MbusJoin {
        select: Option<usize>,
    },
    /// Arm one lit pipe's new WM/DDB image.
    UpdatePipe {
        pipe: usize,
        wait_vblank: bool,
    },
    /// MBUS unjoin after the joined pipe shrank.
    MbusUnjoin {
        select: Option<usize>,
    },
    /// Same join state, different active pipes: tracker and DBOX.
    MbusRebalance,
    /// Pipes that are not lit take their final image directly.
    OffPipes,
    DbufPost,
    CdclkPost,
    PmDemandPost,
}

fn absolute(state: &State, pipe: usize) -> Entry {
    if state.dbuf.active_pipes & (1 << pipe) != 0 {
        state.dbuf.pipes[pipe].absolute
    } else {
        Entry::default()
    }
}

fn overlaps(a: Entry, b: Entry) -> bool {
    a.size() != 0 && b.size() != 0 && a.start < b.end && b.start < a.end
}

/// The `skl_commit_modeset_enables` update loop: lit pipes in reverse
/// order, each only once its target no longer overlaps any other pipe's
/// current allocation. `pending` pipes are enabled afterwards.
pub(crate) fn order(
    current: [Entry; PIPES],
    target: [Entry; PIPES],
    mut update: u8,
    pending: u8,
) -> Result<Vec<(usize, bool)>, ResourceError> {
    let mut entries = current;
    let mut out = Vec::new();
    while update != 0 {
        let mut progress = false;
        for pipe in (0..PIPES).rev() {
            if update & (1 << pipe) == 0 {
                continue;
            }
            let blocked = entries
                .iter()
                .enumerate()
                .any(|(other, e)| other != pipe && overlaps(target[pipe], *e));
            if blocked {
                continue;
            }
            entries[pipe] = target[pipe];
            update &= !(1 << pipe);
            let wait = current[pipe] != target[pipe] && (update | pending) != 0;
            out.push((pipe, wait));
            progress = true;
        }
        if !progress {
            return Err(ResourceError::DdbOrdering);
        }
    }
    Ok(out)
}

/// Plan the live transition from `old` (programmed) to `new` with the
/// `live` pipes lit throughout. Pure.
pub(crate) fn plan(old: &State, new: &State, live: u8) -> Result<Vec<Step>, ResourceError> {
    let old_active = old.dbuf.active_pipes;
    let new_active = new.dbuf.active_pipes;
    if live == 0 || live & !(old_active & new_active) != 0 {
        return Err(ResourceError::Unsupported);
    }
    for pipe in 0..PIPES {
        if live & (1 << pipe) != 0 && old.requests[pipe] != new.requests[pipe] {
            return Err(ResourceError::LivePipeChanged);
        }
    }
    let mut steps = Vec::new();
    if old.pmdemand != new.pmdemand {
        steps.push(Step::PmDemandPre);
    }
    if new.cdclk.cdclk_khz > old.cdclk.cdclk_khz {
        steps.push(Step::CdclkPre);
    }
    let (old_slices, new_slices) = (old.dbuf.enabled_slices, new.dbuf.enabled_slices);
    if old_slices | new_slices != old_slices {
        steps.push(Step::DbufPre);
    }
    // intel_mbus_joined_pipe: the single joined pipe if it is not modeset.
    let joined_pipe = |state: &State| {
        let pipe = state.dbuf.active_pipes.trailing_zeros() as usize;
        (live & (1 << pipe) != 0).then_some(pipe)
    };
    if !old.dbuf.joined && new.dbuf.joined {
        steps.push(Step::MbusJoin {
            select: joined_pipe(new),
        });
    }
    // Only lit pipes occupy DDB during the loop; removed pipes are already
    // off and added ones are enabled afterwards.
    let current = core::array::from_fn(|p| {
        if live & (1 << p) != 0 {
            absolute(old, p)
        } else {
            Entry::default()
        }
    });
    let target = core::array::from_fn(|p| absolute(new, p));
    for (pipe, wait_vblank) in order(current, target, live, new_active & !live)? {
        steps.push(Step::UpdatePipe { pipe, wait_vblank });
    }
    if old.dbuf.joined && !new.dbuf.joined {
        steps.push(Step::MbusUnjoin {
            select: joined_pipe(old),
        });
    } else if old.dbuf.joined == new.dbuf.joined && old_active != new_active {
        steps.push(Step::MbusRebalance);
    }
    if (old_active | new_active) & !live != 0 {
        steps.push(Step::OffPipes);
    }
    if old_slices | new_slices != new_slices {
        steps.push(Step::DbufPost);
    }
    if new.cdclk.cdclk_khz < old.cdclk.cdclk_khz {
        steps.push(Step::CdclkPost);
    }
    if old.pmdemand != new.pmdemand {
        steps.push(Step::PmDemandPost);
    }
    Ok(steps)
}

const fn pipe_reg(base: u64, pipe: usize) -> u64 {
    base + pipe as u64 * 0x1000
}
/// `PIPEDSL`, `PIPE_FRMCOUNT_G4X`, `TRANSCONF`/`PIPECONF`, `CURCNTR`,
/// `CURBASE`, `PLANE_CTL`, `PLANE_SURF`, `DSB_CTRL`.
const PIPEDSL: u64 = 0x70000;
const FRMCOUNT: u64 = 0x70040;
const CONF: u64 = 0x70008;
const CURCNTR: u64 = 0x70080;
const CURBASE: u64 = 0x70084;
const PLANE_CTL: u64 = 0x70180;
const PLANE_SURF: u64 = 0x7019c;
const DSB_CTRL: u64 = 0x70b08;
const PIPEDSL_LINE_MASK: u32 = 0xfffff;
/// `VBLANK_EVASION_TIME_US` (non-debug builds).
const EVASION_US: u64 = 100;

fn lit(io: &(impl MmioWindow + ?Sized), pipe: usize) -> Result<bool, ResourceError> {
    Ok(read(io, pipe_reg(CONF, pipe))? & 0xc000_0000 == 0xc000_0000)
}

fn cursor_on(io: &(impl MmioWindow + ?Sized), pipe: usize) -> Result<bool, ResourceError> {
    Ok(read(io, pipe_reg(CURCNTR, pipe))? & 0x27 != 0)
}

/// Lit pipes stay lit, every other pipe is completely off, and no DSB or
/// FBC can race the update.
fn check_pipes(io: &(impl MmioWindow + ?Sized), live: u8) -> Result<(), ResourceError> {
    for pipe in 0..PIPES {
        let conf = read(io, pipe_reg(CONF, pipe))? & 0xc000_0000;
        if live & (1 << pipe) != 0 {
            if conf != 0xc000_0000 {
                return Err(ResourceError::Busy);
            }
        } else {
            if conf != 0 || cursor_on(io, pipe)? {
                return Err(ResourceError::Busy);
            }
            for plane in 0..PLANES as u64 {
                if read(io, pipe_reg(PLANE_CTL, pipe) + plane * 0x100)? & (1 << 31) != 0 {
                    return Err(ResourceError::Busy);
                }
            }
        }
        for dsb in 0..3 {
            if read(io, pipe_reg(DSB_CTRL, pipe) + dsb * 0x100)? & ((1 << 31) | 1) != 0 {
                return Err(ResourceError::Busy);
            }
        }
    }
    for r in [0x43208, 0x43248] {
        if read(io, r)? & (1 << 31) != 0 {
            return Err(ResourceError::Busy);
        }
    }
    Ok(())
}

/// `intel_vblank_evade`: leave the window [vblank_start - 100 us,
/// vblank_start - 1]. The scanline is `PIPEDSL + 1` (DP); the window is
/// widened by one line to cover HDMI's extra offset. Like Linux, a 1 ms
/// timeout proceeds rather than failing.
fn evade(
    io: &(impl MmioWindow + ?Sized),
    pipe: usize,
    req: &PipeRequest,
) -> Result<(), ResourceError> {
    let vtotal = u32::from(req.vtotal);
    let vblank_start = u32::from(req.vdisplay);
    let lines =
        (EVASION_US * u64::from(req.pixel_rate_khz)).div_ceil(1000 * u64::from(req.htotal)) as u32;
    let min = vblank_start.saturating_sub(lines + 1);
    let max = vblank_start - 1;
    let mut lost = false;
    narf_scheduler::responsive_spin_until(
        || {
            let dsl = io.read32(pipe_reg(PIPEDSL, pipe));
            lost = dsl == u32::MAX || !io.display_access_ok();
            let line = ((dsl & PIPEDSL_LINE_MASK) + 1) % vtotal;
            lost || line < min || line > max
        },
        narf_time::Deadline::after_ms(1),
    );
    if lost {
        Err(ResourceError::NoDevice)
    } else {
        Ok(())
    }
}

/// Write one lit pipe's image, arm it, prove readback and, when ordered,
/// wait for the latching vblank.
fn update_pipe(
    io: &(impl MmioWindow + ?Sized),
    state: &State,
    pipe: usize,
    wait_vblank: bool,
) -> Result<(), ResourceError> {
    let req = state.requests[pipe]
        .as_ref()
        .ok_or(ResourceError::Unsupported)?;
    let image = state
        .pipe_registers(pipe, cursor_on(io, pipe)?)
        .ok_or(ResourceError::Unsupported)?;
    let mut arms = Vec::new();
    for plane in 0..PLANES as u64 {
        if read(io, pipe_reg(PLANE_CTL, pipe) + plane * 0x100)? & (1 << 31) != 0 {
            let surf = pipe_reg(PLANE_SURF, pipe) + plane * 0x100;
            arms.push((surf, read(io, surf)?));
        }
    }
    let base = pipe_reg(CURBASE, pipe);
    arms.push((base, read(io, base)?));
    evade(io, pipe, req)?;
    let frame = read(io, pipe_reg(FRMCOUNT, pipe))?;
    for &(r, v) in &image {
        io.write32(r, v);
    }
    for &(r, v) in &arms {
        io.write32(r, v);
    }
    for &(r, v) in &image {
        if read(io, r)? != v {
            return Err(ResourceError::Readback);
        }
    }
    if wait_vblank {
        let mut lost = false;
        let done = narf_scheduler::responsive_spin_until(
            || {
                let now = io.read32(pipe_reg(FRMCOUNT, pipe));
                lost = now == u32::MAX || !io.display_access_ok();
                lost || now != frame
            },
            narf_time::Deadline::after_ms(100),
        );
        if lost {
            return Err(ResourceError::NoDevice);
        }
        if !done {
            return Err(ResourceError::Timeout);
        }
    }
    Ok(())
}

fn wait_frame(io: &(impl MmioWindow + ?Sized), pipe: usize) -> Result<(), ResourceError> {
    let frame = read(io, pipe_reg(FRMCOUNT, pipe))?;
    let mut lost = false;
    let done = narf_scheduler::responsive_spin_until(
        || {
            let now = io.read32(pipe_reg(FRMCOUNT, pipe));
            lost = now == u32::MAX || !io.display_access_ok();
            lost || now != frame
        },
        narf_time::Deadline::after_ms(100),
    );
    if lost {
        Err(ResourceError::NoDevice)
    } else if done {
        Ok(())
    } else {
        Err(ResourceError::Timeout)
    }
}

fn trackers(io: &(impl MmioWindow + ?Sized), joined: bool) -> Result<(), ResourceError> {
    for (slice, r) in dbuf::DBUF_CTL.into_iter().enumerate() {
        let old = read(io, r)?;
        let enabled = if old & dbuf::DBUF_POWER_REQUEST != 0 {
            1 << slice
        } else {
            0
        };
        checked_masked(io, r, dbuf::dbuf_ctl_value(slice, old, enabled, joined))?;
    }
    Ok(())
}

fn checked_masked(io: &(impl MmioWindow + ?Sized), r: u64, v: u32) -> Result<(), ResourceError> {
    io.write32(r, v);
    let mask = dbuf::DBUF_POWER_REQUEST | dbuf::DBUF_TRACKER_MASK;
    if read(io, r)? & mask == v & mask {
        Ok(())
    } else {
        Err(ResourceError::Readback)
    }
}

fn slices(io: &(impl MmioWindow + ?Sized), enabled: u8, joined: bool) -> Result<(), ResourceError> {
    for (slice, r) in dbuf::DBUF_CTL.into_iter().enumerate() {
        let old = read(io, r)?;
        checked_masked(io, r, dbuf::dbuf_ctl_value(slice, old, enabled, joined))?;
        let want = if enabled & (1 << slice) != 0 {
            dbuf::DBUF_POWER_STATE
        } else {
            0
        };
        wait(io, r, dbuf::DBUF_POWER_STATE, want)?;
    }
    Ok(())
}

fn dboxes(io: &(impl MmioWindow + ?Sized), state: &State) -> Result<(), ResourceError> {
    for pipe in 0..PIPES {
        if state.dbuf.active_pipes & (1 << pipe) != 0 {
            checked(io, dbuf::dbox_ctl(pipe), state.dbuf.dbox(pipe))?;
        }
    }
    Ok(())
}

fn mbus(
    io: &(impl MmioWindow + ?Sized),
    state: &State,
    select: Option<usize>,
) -> Result<(), ResourceError> {
    let old = read(io, dbuf::MBUS_CTL)?;
    checked(
        io,
        dbuf::MBUS_CTL,
        (old & !dbuf::MBUS_CTL_MASK) | state.dbuf.mbus_ctl_select(select),
    )
}

fn execute(
    io: &(impl MmioWindow + ?Sized),
    old: &State,
    new: &State,
    live: u8,
    snap: &Snapshot,
    step: Step,
) -> Result<(), ResourceError> {
    match step {
        Step::PmDemandPre => {
            pmdemand::program(io, &new.pmdemand, Some(&snap.pmdemand))?;
        }
        Step::CdclkPre | Step::CdclkPost => {
            let now = cdclk::Current::read(io)?;
            cdclk::program(io, &now, new.cdclk)?;
        }
        Step::DbufPre => slices(
            io,
            old.dbuf.enabled_slices | new.dbuf.enabled_slices,
            old.dbuf.joined,
        )?,
        Step::MbusJoin { select } => {
            mbus(io, new, select)?;
            dboxes(io, new)?;
            trackers(io, true)?;
        }
        Step::UpdatePipe { pipe, wait_vblank } => update_pipe(io, new, pipe, wait_vblank)?,
        Step::MbusUnjoin { select } => {
            trackers(io, false)?;
            dboxes(io, new)?;
            mbus(io, new, select)?;
            if let Some(pipe) = select {
                wait_frame(io, pipe)?;
            }
        }
        Step::MbusRebalance => {
            trackers(io, new.dbuf.joined)?;
            dboxes(io, new)?;
        }
        Step::OffPipes => {
            for pipe in 0..PIPES {
                if live & (1 << pipe) == 0 {
                    let image = new
                        .pipe_registers(pipe, new.cursor_visible[pipe])
                        .ok_or(ResourceError::Unsupported)?;
                    for (r, v) in image {
                        checked(io, r, v)?;
                    }
                }
            }
        }
        Step::DbufPost => slices(io, new.dbuf.enabled_slices, new.dbuf.joined)?,
        Step::PmDemandPost => {
            pmdemand::program(io, &new.pmdemand, None)?;
        }
    }
    Ok(())
}

/// Undo `done` (executed steps, in order) back to `old`, in reverse. Lit
/// pipes go back through the same overlap ordering; MBUS rejoins before
/// a formerly joined pipe regrows. PM demand is restored only once the
/// original clock is back.
fn undo(
    io: &(impl MmioWindow + ?Sized),
    old: &State,
    new: &State,
    live: u8,
    snap: &Snapshot,
    done: &[Step],
) -> Result<(), ResourceError> {
    let mut i = done.len();
    while i > 0 {
        i -= 1;
        match done[i] {
            Step::UpdatePipe { .. } => {
                // Undo the whole contiguous group of pipe updates at once.
                let end = i;
                while i > 0 && matches!(done[i - 1], Step::UpdatePipe { .. }) {
                    i -= 1;
                }
                let updated = done[i..=end].iter().fold(0u8, |m, s| match s {
                    Step::UpdatePipe { pipe, .. } => m | (1 << pipe),
                    _ => m,
                });
                let current = core::array::from_fn(|p| {
                    if updated & (1 << p) != 0 {
                        absolute(new, p)
                    } else if live & (1 << p) != 0 {
                        absolute(old, p)
                    } else {
                        Entry::default()
                    }
                });
                let target = core::array::from_fn(|p| {
                    if live & (1 << p) != 0 {
                        absolute(old, p)
                    } else {
                        Entry::default()
                    }
                });
                for (pipe, wait_vblank) in order(current, target, updated, 0)? {
                    update_pipe(io, old, pipe, wait_vblank)?;
                }
            }
            Step::PmDemandPre | Step::PmDemandPost => {}
            Step::CdclkPre | Step::CdclkPost => {
                let now = cdclk::Current::read(io)?;
                cdclk::program(io, &now, old.cdclk)?;
                if cdclk::Current::read(io)?.ctl != snap.cdclk.ctl {
                    checked(io, cdclk::CDCLK_CTL, snap.cdclk.ctl)?;
                }
            }
            Step::DbufPre => slices(io, old.dbuf.enabled_slices, old.dbuf.joined)?,
            Step::DbufPost => slices(
                io,
                old.dbuf.enabled_slices | new.dbuf.enabled_slices,
                new.dbuf.joined,
            )?,
            Step::MbusJoin { select } => {
                // Reverse of a join: the unjoin protocol back to `old`.
                trackers(io, false)?;
                for (pipe, v) in snap.dbox.iter().enumerate() {
                    checked(io, dbuf::dbox_ctl(pipe), *v)?;
                }
                checked(io, dbuf::MBUS_CTL, snap.mbus_ctl)?;
                if let Some(pipe) = select {
                    wait_frame(io, pipe)?;
                }
            }
            Step::MbusUnjoin { select } => {
                mbus(io, old, select)?;
                for (pipe, v) in snap.dbox.iter().enumerate() {
                    checked(io, dbuf::dbox_ctl(pipe), *v)?;
                }
                trackers(io, true)?;
            }
            Step::MbusRebalance => {
                trackers(io, old.dbuf.joined)?;
                for (pipe, v) in snap.dbox.iter().enumerate() {
                    checked(io, dbuf::dbox_ctl(pipe), *v)?;
                }
            }
            Step::OffPipes => {
                for pipe in 0..PIPES {
                    if live & (1 << pipe) != 0 {
                        continue;
                    }
                    let image = new
                        .pipe_registers(pipe, new.cursor_visible[pipe])
                        .ok_or(ResourceError::Unsupported)?;
                    for (r, _) in image {
                        let original = snap
                            .planes
                            .iter()
                            .find(|(o, _)| *o == r)
                            .map_or(0, |(_, v)| *v);
                        checked(io, r, original)?;
                    }
                }
            }
        }
    }
    if done.contains(&Step::PmDemandPre) {
        pmdemand::program(io, &snap.pmdemand, None)?;
    }
    Ok(())
}

/// Repartition from the programmed `old` state to `new` while the `live`
/// pipes stay lit. Every refusal precedes the first write; on a later
/// failure the executed steps are undone in reverse source order.
pub(crate) fn commit_live(
    io: &(impl MmioWindow + ?Sized),
    old: &State,
    new: &State,
    live: u8,
) -> Result<(), ResourceError> {
    let steps = plan(old, new, live)?;
    check_pipes(io, live)?;
    // The programmed state must be what the hardware holds now.
    let clock = cdclk::Current::read(io)?;
    match clock.known {
        None => return Err(ResourceError::RequiresPipesOff),
        Some(rung) if rung != old.cdclk => return Err(ResourceError::Diverged),
        Some(_) => {}
    }
    if read(io, dbuf::MBUS_CTL)? & ((1 << 31) | (1 << 30)) != old.dbuf.mbus_ctl() & (3 << 30) {
        return Err(ResourceError::Diverged);
    }
    for pipe in 0..PIPES {
        if live & (1 << pipe) == 0 {
            continue;
        }
        let image = old
            .pipe_registers(pipe, cursor_on(io, pipe)?)
            .ok_or(ResourceError::Unsupported)?;
        for (r, v) in image {
            if read(io, r)? != v {
                return Err(ResourceError::Diverged);
            }
        }
        if !lit(io, pipe)? {
            return Err(ResourceError::Busy);
        }
    }
    let snap = Snapshot::capture(io, new)?;
    let mut done = Vec::with_capacity(steps.len());
    for step in steps {
        if let Err(error) = execute(io, old, new, live, &snap, step) {
            // A partially executed step is undone with the others.
            done.push(step);
            if io.display_access_ok() {
                let _ = undo(io, old, new, live, &snap, &done);
            }
            return Err(error);
        }
        done.push(step);
    }
    Ok(())
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_xelpg_live_tests.rs"]
pub(crate) mod tests;
