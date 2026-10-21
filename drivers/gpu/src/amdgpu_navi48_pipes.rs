//! The pipes of a Navi48 configuration as Linux DC acquires them: amdgpu_dm's
//! atomic check over `amdgpu_dcn401_resource::DcState` (a copy of the
//! current state, its changed planes and streams removed, the new streams
//! added in CRTC order with their OTG masters, their planes added, then
//! DML21's pipe counts mapped with map_dc_pipes_with_callbacks), each search
//! preferring the pipes the current state used the same way. The current
//! state is the running displays' (`dc_state`).
//!
//! One deviation in plane order: NARF scans a stream's primary out on its
//! OTG master pipe (and its ODM OPP heads), so each stream's DC plane list
//! is its primary first, then the other planes in amdgpu_dm's descending
//! zpos order (the overlays top first, underlays last), where amdgpu_dm adds
//! every plane in descending zpos and its top plane takes the OPP heads.
//! Planes of different streams are added stream by stream, in CRTC order,
//! not interleaved by DRM's zpos across CRTCs.
use super::*;
use crate::amdgpu_dcn401_resource::{
    DcState, ScalesAnywhere, Scaling, StreamOutput, Target, MAX_SURFACES,
};

/// One stream of a configuration as its pipes are acquired: its CRTC (the
/// stream's id), which overlay slots of its planes are present (bottom
/// first, as `PlaneSetup::overlays`), DML's plan for it and, for a stream
/// that lights, its output, on which it acquires its encoders after its
/// OTG master (resource_map_pool_resources).
#[derive(Clone, Copy, Debug)]
pub struct StreamPipes<'a> {
    pub crtc: u8,
    pub overlays: [bool; otg::MAX_OVERLAYS],
    pub plan: &'a dml::Plan,
    /// The stream's planes and timing, for their scaling on each pipe;
    /// `None` for admission's stand-in planes, which always scale.
    pub selection: Option<&'a Selection>,
    pub output: Option<StreamOutput>,
}
impl<'a> StreamPipes<'a> {
    /// The stream of `selection`'s planes on CRTC `crtc` under `plan`.
    pub fn of(crtc: u8, selection: &'a Selection, plan: &'a dml::Plan) -> Self {
        Self {
            crtc,
            overlays: selection.planes.overlays.map(|o| o.is_some()),
            plan,
            selection: Some(selection),
            output: None,
        }
    }
    /// The stream lit on `output`.
    pub fn on(self, output: StreamOutput) -> Self {
        Self {
            output: Some(output),
            ..self
        }
    }
    /// The stream of the planes `plan` was admitted with (its overlays the
    /// planes after the primary, packed from the bottom).
    pub fn of_plan(crtc: u8, plan: &'a dml::Plan) -> Self {
        let n = plan.mode.plane_list().count().saturating_sub(1);
        Self {
            crtc,
            overlays: core::array::from_fn(|k| k < n),
            plan,
            selection: None,
            output: None,
        }
    }
    /// DML's pipe counts in DC plane order: the stream's ODM slices, each
    /// plane's MPC slices (one on an ODM stream).
    fn target(&self) -> Target {
        let plan = self.plan;
        let slices = |i: usize| plan.plane(i).map_or(1, |p| p.mpc_slices(plan.pipes)).max(1);
        let (slots, n) = dc_slots(self.overlays);
        let mut mpc = [1; MAX_SURFACES];
        for (m, &slot) in mpc.iter_mut().zip(&slots[..n]) {
            // DML's planes: the primary, then the overlays packed bottom
            // first (`with_planes`).
            let i = match slot {
                0 => 0,
                s => 1 + self.overlays[..s - 1].iter().filter(|&&o| o).count(),
            };
            *m = slices(i);
        }
        Target {
            odm: plan.pipes.max(1),
            mpc,
        }
    }
}

/// Plane slots per stream: the primary (0) and overlay k (k + 1).
const SLOTS: usize = 1 + otg::MAX_OVERLAYS;
/// The DC plane id of CRTC `crtc`'s plane slot `slot`.
fn plane_id(crtc: u8, slot: usize) -> u8 {
    crtc * SLOTS as u8 + slot as u8
}
/// A stream's planes in DC plane order (slots): its primary, then the
/// present overlays top first.
fn dc_slots(overlays: [bool; otg::MAX_OVERLAYS]) -> ([usize; SLOTS], usize) {
    let mut out = [0; SLOTS];
    let mut n = 1;
    for k in (0..otg::MAX_OVERLAYS).rev().filter(|&k| overlays[k]) {
        out[n] = k + 1;
        n += 1;
    }
    (out, n)
}

/// resource_build_scaling_params on the pipes DC acquires for a
/// configuration: SPL on the pipe's ODM and MPC slice of its plane, as the
/// scanout programs it (`stream_planes`, `SurfaceRequest::scalers`). A plane
/// of a stream whose selection this does not know (admission's stand-ins)
/// scales.
struct PlaneScaling<'a> {
    /// The streams' selections by CRTC, the configured ones first.
    displays: Vec<(u8, &'a Selection)>,
}
impl<'a> PlaneScaling<'a> {
    fn new(streams: &[StreamPipes<'a>], running: &'a [Modeset]) -> Self {
        let mut displays: Vec<(u8, &'a Selection)> = streams
            .iter()
            .filter_map(|s| s.selection.map(|sel| (s.crtc, sel)))
            .collect();
        displays.extend(running.iter().map(|m| (m.crtc, &m.selection)));
        Self { displays }
    }
}
impl Scaling for PlaneScaling<'_> {
    fn build(&self, s: &DcState, pipe: u8) -> bool {
        let p = s.pipes[usize::from(pipe)];
        let (Some(crtc), Some(plane)) = (p.stream, p.plane) else {
            return true;
        };
        let Some(&(_, sel)) = self.displays.iter().find(|(c, _)| *c == crtc) else {
            return true;
        };
        let slot = usize::from(plane.wrapping_sub(plane_id(crtc, 0)));
        let (dpp, n) = s.dpp_pipes_for_plane(plane);
        let Some(rest) = otg::SplitPipes::new(&dpp[1..n.max(1)]) else {
            return true;
        };
        if n == 0 || slot >= SLOTS {
            return true;
        }
        let (odm, mpc) = if s.odm_slice_count(dpp[0]) > 1 {
            (rest, otg::SplitPipes::NONE)
        } else {
            (otg::SplitPipes::NONE, rest)
        };
        let mut overlays: OverlayPipes = [None; otg::MAX_OVERLAYS];
        if slot > 0 {
            overlays[slot - 1] = Some(PlanePipes {
                pipe: dpp[0],
                odm,
                mpc,
            });
        }
        let (primary, others) = stream_planes(
            &sel.timing,
            sel.ycbcr420,
            sel.format,
            &sel.planes,
            (dpp[0], odm, mpc),
            &overlays,
        );
        let request = if slot == 0 {
            Some(primary)
        } else {
            others[slot - 1]
        };
        request.is_none_or(|r| r.scales_on(pipe))
    }
}

fn refused() -> ModesetError {
    ModesetError::Display(otg::Error::Admission(dml::Error::Pipes))
}

/// The DC state of the running displays `running`, as their pipes record
/// it: each stream (its CRTC) on its OTG master with the encoders it holds
/// on its output, every ODM slice's OPP head after it, and in each slice
/// the blending tree of its planes in DC plane order with each plane's MPC
/// slices together (acquire_dpp_pipe_and_add_mpc_slice puts a slice right
/// after its plane's last), the slices of every plane linked across the
/// ODM segments.
pub fn dc_state(running: &[Modeset]) -> DcState {
    let mut state = DcState::new(crate::amdgpu_rdna4::pipe_pool().count());
    let mut streams: Vec<&Modeset> = running.iter().collect();
    streams.sort_by_key(|m| m.crtc);
    for m in streams {
        if usize::from(state.stream_count) == state.streams.len() {
            break;
        }
        let s = &m.scanout;
        let present = s.overlays.map(|o| o.is_some());
        let (slots, n) = dc_slots(present);
        let status = &mut state.streams[usize::from(state.stream_count)];
        status.stream = m.crtc;
        for (p, &slot) in status.planes.iter_mut().zip(&slots[..n]) {
            *p = plane_id(m.crtc, slot);
        }
        status.plane_count = n as u8;
        state.stream_count += 1;
        state.adopt_stream_encoders(m.crtc, m.output, m.encoders);
        let segments = 1 + s.odm.len();
        // Each plane's pipe in each ODM slice (the first of its MPC slices).
        let column = |slot: usize, segment: usize| -> Option<u8> {
            match (slot, segment) {
                (0, 0) => Some(m.pipe),
                (0, j) => s.odm.get(j - 1),
                (k, 0) => s.overlays[k - 1].map(|o| o.pipe),
                (k, j) => s.overlays[k - 1].and_then(|o| o.odm.get(j - 1)),
            }
        };
        let pool = state.pipe_count;
        let mut set = |q: u8, f: &dyn Fn(&mut crate::amdgpu_dcn401_resource::PipeCtx)| {
            if q < pool {
                f(&mut state.pipes[usize::from(q)]);
            }
        };
        for segment in 0..segments {
            let mut tree: Vec<(u8, usize)> = Vec::with_capacity(SLOTS + 3);
            for &slot in &slots[..n] {
                let Some(first) = column(slot, segment) else {
                    continue;
                };
                tree.push((first, slot));
                if segment == 0 {
                    let mpc = match slot {
                        0 => s.mpc,
                        k => s.overlays[k - 1].map_or(otg::SplitPipes::NONE, |o| o.mpc),
                    };
                    tree.extend(mpc.iter().map(|q| (q, slot)));
                }
            }
            for (i, &(q, slot)) in tree.iter().enumerate() {
                let top = i.checked_sub(1).map(|j| tree[j].0);
                let bottom = tree.get(i + 1).map(|t| t.0);
                set(q, &|p| {
                    p.stream = Some(m.crtc);
                    p.plane = Some(plane_id(m.crtc, slot));
                    p.top = top;
                    p.bottom = bottom;
                });
            }
        }
        for &slot in &slots[..n] {
            for segment in 0..segments {
                let Some(q) = column(slot, segment) else {
                    continue;
                };
                let prev = segment.checked_sub(1).and_then(|j| column(slot, j));
                let next = column(slot, segment + 1).filter(|_| segment + 1 < segments);
                set(q, &|p| {
                    p.prev_odm = prev;
                    p.next_odm = next;
                });
            }
        }
    }
    state
}

/// A running stream's pipe counts in `state` (what DML keeps it at).
fn current_target(state: &DcState, stream: u8) -> Target {
    let mut t = Target {
        odm: 1,
        mpc: [1; MAX_SURFACES],
    };
    if let Some(otg) = state.otg_master_for_stream(stream) {
        t.odm = state.odm_slice_count(otg) as u8;
    }
    if let Some(s) = state.streams().iter().find(|s| s.stream == stream) {
        for (m, &p) in t.mpc.iter_mut().zip(s.planes()) {
            let (dpp, n) = state.dpp_pipes_for_plane(p);
            if n > 0 {
                *m = state.mpc_slice_count(dpp[0]) as u8;
            }
        }
    }
    t
}

/// Add `s`'s planes to its stream in DC plane order (dc_state_add_plane).
fn add_planes(
    new: &mut DcState,
    cur: &DcState,
    s: &StreamPipes,
    sc: &dyn Scaling,
) -> Result<(), ModesetError> {
    let (slots, n) = dc_slots(s.overlays);
    for &slot in &slots[..n] {
        if !new.add_plane(cur, s.crtc, plane_id(s.crtc, slot), sc) {
            return Err(refused());
        }
    }
    Ok(())
}

/// DML's counts mapped onto `new` (map_dc_pipes_with_callbacks): the
/// streams `streams` at their plans, every other stream as it runs in
/// `cur`.
fn map(
    new: &mut DcState,
    cur: &DcState,
    streams: &[StreamPipes],
    sc: &dyn Scaling,
) -> Result<(), ModesetError> {
    let ok = new.map_pipes(
        cur,
        |stream| {
            streams
                .iter()
                .find(|s| s.crtc == stream)
                .map_or_else(|| current_target(cur, stream), StreamPipes::target)
        },
        sc,
    );
    if ok {
        Ok(())
    } else {
        Err(refused())
    }
}

/// Stream `crtc`'s pipes in `state`: its OTG master and the further pipes
/// of its planes (slots `overlays`).
fn stream_pipes(
    state: &DcState,
    crtc: u8,
    overlays: [bool; otg::MAX_OVERLAYS],
) -> Result<(u8, DisplayPipes), ModesetError> {
    let head = state.otg_master_for_stream(crtc).ok_or_else(refused)?;
    let (heads, segments) = state.opp_heads(head);
    let split = |p: &[u8]| otg::SplitPipes::new(p).ok_or_else(refused);
    let mut out = DisplayPipes {
        odm: split(&heads[1..segments])?,
        encoders: state
            .streams()
            .iter()
            .find(|s| s.stream == crtc)
            .and_then(|s| s.encoders)
            .unwrap_or_default(),
        ..DisplayPipes::default()
    };
    let planes = |slot: usize| state.dpp_pipes_for_plane(plane_id(crtc, slot));
    let (primary, n) = planes(0);
    if n == 0 || primary[0] != head {
        return Err(refused());
    }
    if segments == 1 {
        out.mpc = split(&primary[1..n])?;
    }
    for k in (0..otg::MAX_OVERLAYS).filter(|&k| overlays[k]) {
        let (pipes, n) = planes(k + 1);
        if n == 0 {
            return Err(refused());
        }
        let rest = split(&pipes[1..n])?;
        out.overlays[k] = Some(if segments > 1 {
            PlanePipes {
                pipe: pipes[0],
                odm: rest,
                mpc: otg::SplitPipes::NONE,
            }
        } else {
            PlanePipes {
                pipe: pipes[0],
                odm: otg::SplitPipes::NONE,
                mpc: rest,
            }
        });
    }
    Ok((head, out))
}

/// The OTG master each stream of `crtcs` (in CRTC order) acquires when
/// they are all lit anew over `current` (acquire_otg_master_pipe_for_
/// stream); a stream with none ends the list.
pub fn head_pipes(current: &DcState, crtcs: &[u8]) -> Vec<u8> {
    let mut new = DcState::new(current.pipe_count);
    let mut heads = Vec::with_capacity(crtcs.len());
    for &crtc in crtcs {
        if !new.add_stream(current, crtc, &ScalesAnywhere) {
            break;
        }
        heads.extend(new.otg_master_for_stream(crtc));
    }
    heads
}

/// The encoders `s` acquires on its output in `new` right after its OTG
/// master (none for a stream only admitted).
fn map_encoders(new: &mut DcState, s: &StreamPipes) -> bool {
    s.output
        .is_none_or(|output| new.map_stream_encoders(s.crtc, output).is_some())
}

/// A configuration lit anew over `current` (every running stream and plane
/// removed, as a full modeset of all of them): each stream of `streams` (in
/// CRTC order) with its OTG master and encoders, its planes, then DML's
/// counts. Each stream's head pipe and further pipes (with its encoders).
pub fn light_pipes(
    current: &DcState,
    streams: &[StreamPipes],
) -> Result<Vec<(u8, DisplayPipes)>, ModesetError> {
    let mut new = DcState::new(current.pipe_count);
    // Every running stream was removed: only these streams' planes scale.
    let sc = PlaneScaling::new(streams, &[]);
    for s in streams {
        if !new.add_stream(current, s.crtc, &sc) || !map_encoders(&mut new, s) {
            return Err(refused());
        }
    }
    for s in streams {
        add_planes(&mut new, current, s, &sc)?;
    }
    map(&mut new, current, streams, &sc)?;
    streams
        .iter()
        .map(|s| stream_pipes(&new, s.crtc, s.overlays))
        .collect()
}

/// `light_pipes` over no running display: stand-in pipes for admission
/// checks, which do not depend on the pipe.
pub fn plan_pipes(
    plans: &[dml::Plan],
    crtcs: &[u8],
) -> Result<Vec<(u8, DisplayPipes)>, ModesetError> {
    let streams: Vec<StreamPipes> = plans
        .iter()
        .zip(crtcs)
        .map(|(plan, &crtc)| StreamPipes::of_plan(crtc, plan))
        .collect();
    light_pipes(
        &DcState::new(crate::amdgpu_rdna4::pipe_pool().count()),
        &streams,
    )
}

/// `light_pipes` for `selections`' planes on CRTCs `crtcs` under `plans`,
/// over no running display.
pub fn display_pipes(
    selections: &[Selection],
    plans: &[dml::Plan],
    crtcs: &[u8],
) -> Result<Vec<(u8, DisplayPipes)>, ModesetError> {
    let streams: Vec<StreamPipes> = selections
        .iter()
        .zip(plans)
        .zip(crtcs)
        .map(|((s, plan), &crtc)| StreamPipes::of(crtc, s, plan))
        .collect();
    light_pipes(
        &DcState::new(crate::amdgpu_rdna4::pipe_pool().count()),
        &streams,
    )
}

/// New streams lit beside the running ones (`current`, which keep their
/// streams, planes and encoders, `running`'s): each of `streams` added
/// with its OTG master and the encoders the running ones leave, its
/// planes, then DML's counts for all (the running streams at theirs).
/// Each new stream's head pipe and further pipes, or None when they do
/// not fit or would move a running stream's pipes (acquire_first_split_
/// pipe, or dc_state_add_plane dropping another stream's MPC combine for a
/// plane short of pipes): a modeset of them.
pub fn beside_pipes(
    current: &DcState,
    streams: &[StreamPipes],
    running: &[Modeset],
) -> Option<Vec<(u8, DisplayPipes)>> {
    let mut new = *current;
    let sc = PlaneScaling::new(streams, running);
    for s in streams {
        if !new.add_stream(current, s.crtc, &sc) || !map_encoders(&mut new, s) {
            return None;
        }
    }
    for s in streams {
        add_planes(&mut new, current, s, &sc).ok()?;
    }
    map(&mut new, current, streams, &sc).ok()?;
    if !keeps_running(current, &new, streams) {
        return None;
    }
    streams
        .iter()
        .map(|s| stream_pipes(&new, s.crtc, s.overlays).ok())
        .collect()
}

/// Whether every stream of `current` not in `streams` runs on the same
/// pipes in `new`: each of its pipes as it was, and none taken.
fn keeps_running(current: &DcState, new: &DcState, streams: &[StreamPipes]) -> bool {
    let other = |stream: Option<u8>| stream.is_some_and(|t| !streams.iter().any(|n| n.crtc == t));
    current
        .pipes
        .iter()
        .zip(&new.pipes)
        .all(|(a, b)| !(other(a.stream) || other(b.stream)) || a == b)
}

/// Running stream `s`'s planes changed in place (amdgpu_dm's plane commit
/// without a modeset; `running` the running displays `current` records):
/// with `reset` (should_reset_plane) every plane of
/// the stream removed and added again in DC plane order, then DML's counts
/// for all (the other streams at theirs). The stream's further pipes, or
/// None when they do not fit, another stream's pipes would move or the
/// stream itself would (another OTG master or ODM split): a modeset.
pub fn live_pipes(
    current: &DcState,
    s: &StreamPipes,
    reset: bool,
    running: &[Modeset],
) -> Option<DisplayPipes> {
    let mut new = *current;
    let sc = PlaneScaling::new(core::slice::from_ref(s), running);
    let status = current
        .streams()
        .iter()
        .find(|t| t.stream == s.crtc)
        .copied()?;
    if reset {
        // Removed in descending zpos, the primary among them.
        for &p in status.planes().iter().rev() {
            new.remove_plane(s.crtc, p);
        }
        add_planes(&mut new, current, s, &sc).ok()?;
    } else {
        let (slots, n) = dc_slots(s.overlays);
        let same = status.planes().len() == n
            && status
                .planes()
                .iter()
                .zip(&slots[..n])
                .all(|(&p, &slot)| p == plane_id(s.crtc, slot));
        if !same {
            return None;
        }
    }
    map(&mut new, current, core::slice::from_ref(s), &sc).ok()?;
    let old = current.otg_master_for_stream(s.crtc)?;
    let head = new.otg_master_for_stream(s.crtc)?;
    if old != head
        || current.opp_heads(old) != new.opp_heads(head)
        || !keeps_running(current, &new, core::slice::from_ref(s))
    {
        return None;
    }
    stream_pipes(&new, s.crtc, s.overlays).ok().map(|(_, d)| d)
}
