//! Seamless plane changes of a running Navi48 display: amdgpu_dm's
//! non-modeset plane commit (amdgpu_dm_commit_planes) through
//! dc_update_planes_and_stream. DML admits the configuration again with
//! the display's new planes (dc_validate_global_state on a full update),
//! the planes take their pipes as DC acquires them (`live_pipes`: planes
//! amdgpu_dm recreates take their blending tree's pipes back first, new
//! ones pipes the running state leaves free), and the change runs
//! in dc_commit_updates_for_stream's order: prepare_bandwidth (shared clocks
//! and the kept pipes' DPP DTOs raised, the new pipes' DPP-only clocks,
//! the stream/plane updates with raise-only watermarks, releasing DET
//! budget before a sibling grows), the plane update under its OTG lock
//! (`Otg::update_live_planes`),
//! then optimize_bandwidth (every display's exact watermarks, the clocks
//! lowered). Only a change of the stream itself (its ODM split, or another
//! display's pipes) is a modeset, which the caller relights.
use super::*;

/// A running display moved to new planes without relighting, with every
/// running display's record (another display's plan may have moved too),
/// in CRTC order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanesChange {
    pub pipe: u8,
    pub displays: Vec<Modeset>,
    pub updated: alloc::boxed::Box<otg::PlanesUpdated>,
}

/// The first framebuffer contents of the planes a seamless update shows on
/// fresh surfaces (`otg::PlaneContent`), by plane slot: 0 the primary, k + 1
/// the setup's overlay k.
pub trait FirstFrames: Send {
    fn chunk(
        &mut self,
        slot: usize,
        a: &otg::SurfaceApplied,
        index: u32,
        words: &mut Vec<u32>,
    ) -> Option<u64>;
    /// A client framebuffer slot `slot` scans out in place instead
    /// (`otg::PlaneContent::external`).
    fn external(&mut self, _slot: usize, _a: &otg::SurfaceApplied) -> Option<otg::ExternalSurface> {
        None
    }
}
/// No first contents: fresh surfaces show cleared until the next flip.
impl FirstFrames for otg::Cleared {
    fn chunk(
        &mut self,
        _: usize,
        _: &otg::SurfaceApplied,
        _: u32,
        _: &mut Vec<u32>,
    ) -> Option<u64> {
        None
    }
}
/// `FirstFrames` addressed by the pipe each plane is staged on; `moved`
/// the pipes (by bit) another plane than before lands on.
struct BySlot<'a> {
    pipes: [Option<u8>; 1 + otg::MAX_OVERLAYS],
    moved: u8,
    frames: &'a mut dyn FirstFrames,
}
impl otg::PlaneContent for BySlot<'_> {
    fn moved_to(&mut self, pipe: u8) -> bool {
        self.moved & 1u8.checked_shl(u32::from(pipe)).unwrap_or(0) != 0
    }
    fn chunk(&mut self, a: &otg::SurfaceApplied, index: u32, words: &mut Vec<u32>) -> Option<u64> {
        let slot = self.pipes.iter().position(|&p| p == Some(a.request.pipe))?;
        self.frames.chunk(slot, a, index, words)
    }
    fn external(&mut self, a: &otg::SurfaceApplied) -> Option<otg::ExternalSurface> {
        let slot = self.pipes.iter().position(|&p| p == Some(a.request.pipe))?;
        self.frames.external(slot, a)
    }
}

/// should_reset_plane over a running display's planes going from `old`
/// (primary in `old_format`) to `new`: amdgpu_dm removes and adds again
/// every plane of the CRTC when any (cursor aside) is added or removed, or
/// changes its source or destination size (not position), rotation,
/// "pixel blend mode", "alpha", COLOR_RANGE or COLOR_ENCODING, or its
/// framebuffer's format or modifier; a plane whose normalized zpos changes
/// is recreated too. Planes only moved keep their pipes as they are.
///
/// Both setups from DRM commits (`PlaneSetup::drm`) are compared exactly
/// as Linux compares the DRM plane states. A setup not from DRM (the
/// console's, a legacy SETCRTC's) has no plane states; it is compared by
/// what DC is given instead.
pub fn planes_reset(
    old_format: otg::SurfaceFormat,
    old: &PlaneSetup,
    new_format: otg::SurfaceFormat,
    new: &PlaneSetup,
) -> bool {
    let states = |s: &PlaneSetup| {
        let n = 1 + s.overlay_count();
        let states: Vec<DrmPlaneState> = s.drm.iter().flatten().copied().collect();
        (states.len() == n).then_some(states)
    };
    if let (Some(old), Some(new)) = (states(old), states(new)) {
        return drm_planes_reset(&old, &new);
    }
    let size = |g: &PlaneGeometry| {
        (
            g.width,
            g.height,
            g.dst.width,
            g.dst.height,
            g.rotation,
            g.blend,
            g.surface,
            g.fb_size,
        )
    };
    if old_format != new_format || old.primary.as_ref().map(size) != new.primary.as_ref().map(size)
    {
        return true;
    }
    old.overlays
        .iter()
        .zip(&new.overlays)
        .any(|(a, b)| match (a, b) {
            (None, None) => false,
            (Some(a), Some(b)) => {
                a.plane != b.plane
                    || a.format != b.format
                    || a.underlay != b.underlay
                    || size(&a.geometry) != size(&b.geometry)
            }
            _ => true,
        })
}

/// The pipes (by bit) on which a plane of `new` (overlays on `new_pipes`)
/// lands where another plane of `old` (overlays on `old_pipes`) was: the
/// primary stays on the head pipe, an overlay is its DRM plane (by id, by
/// slot when one is unknown).
pub(super) fn moved_planes(
    old: &PlaneSetup,
    old_pipes: &[Option<u8>; otg::MAX_OVERLAYS],
    new: &PlaneSetup,
    new_pipes: &[Option<u8>; otg::MAX_OVERLAYS],
) -> u8 {
    let identity = |s: &PlaneSetup, k: usize| {
        s.overlays[k].map(|o| {
            if o.plane != 0 {
                (o.plane, 0)
            } else {
                (0, k + 1)
            }
        })
    };
    let mut moved = 0u8;
    for (k, &pipe) in new_pipes.iter().enumerate() {
        let (Some(pipe), Some(id)) = (pipe, identity(new, k)) else {
            continue;
        };
        let before = old_pipes
            .iter()
            .position(|&p| p == Some(pipe))
            .and_then(|j| identity(old, j));
        if before.is_some_and(|b| b != id) {
            moved |= 1u8.checked_shl(u32::from(pipe)).unwrap_or(0);
        }
    }
    moved
}

/// should_reset_plane's checks over one CRTC's non-cursor DRM planes.
fn drm_planes_reset(old: &[DrmPlaneState], new: &[DrmPlaneState]) -> bool {
    let find = |set: &[DrmPlaneState], id: u32| set.iter().find(|p| p.plane == id).copied();
    // `old_other_state->crtc != new_other_state->crtc`: added or removed.
    if old.iter().any(|o| find(new, o.plane).is_none())
        || new.iter().any(|n| find(old, n.plane).is_none())
    {
        return true;
    }
    old.iter().any(|o| {
        let n = find(new, o.plane).unwrap_or(*o);
        o.normalized_zpos != n.normalized_zpos
            || (o.src_w, o.src_h, o.crtc_w, o.crtc_h) != (n.src_w, n.src_h, n.crtc_w, n.crtc_h)
            || o.rotation != n.rotation
            || o.blend != n.blend
            || o.alpha != n.alpha
            || (o.color_range, o.color_encoding) != (n.color_range, n.color_encoding)
            || o.fourcc != n.fourcc
            || o.modifier != n.modifier
    })
}

/// Every pipe of display `m`'s planes with its plane's DPPCLK under `plan`.
fn plane_targets(m: &Modeset, plan: &dml::Plan) -> Vec<(u8, u32)> {
    running_dpp_targets(m, plan)
}

impl ColdBoot {
    /// Show `format` and `setup` on running display `display` without
    /// relighting it (amdgpu_dm's plane commit without a modeset; DC's
    /// medium or full update). `reset` when amdgpu_dm would recreate a
    /// plane (should_reset_plane: a zpos change). A plane on a fresh
    /// surface shows `frames`' content from the update's own latch.
    /// `None` when that needs a
    /// modeset, or is refused before any change, so the caller relights:
    /// an MST configuration, the display not running, DML not admitting
    /// the configuration, another ODM split, another display's pipes, or
    /// the plane update itself refused. Returns every running display.
    /// # Safety
    /// As for `modeset_displays`, except that every display stays lit.
    /// Every CPU view of the display's primary surface must be withdrawn
    /// (a format or size change replaces it).
    pub async unsafe fn update_display_planes(
        &mut self,
        display: u8,
        format: otg::SurfaceFormat,
        setup: PlaneSetup,
        reset: bool,
        frames: &mut dyn FirstFrames,
    ) -> Result<Option<PlanesChange>, ModesetError> {
        // A teardown in flight is the relight's to finish.
        if self.teardowns.check_idle().is_err() {
            return Ok(None);
        }
        let mut running: Vec<Modeset> = self.display_modesets().into_iter().flatten().collect();
        running.sort_by_key(|m| m.crtc);
        if running.iter().any(|m| m.selection.mst.is_some()) {
            return Ok(None);
        }
        let Some(i) = running.iter().position(|m| m.pipe == display) else {
            return Ok(None);
        };
        let m = running[i];
        let mut selection = m.selection;
        selection.format = format;
        selection.planes = setup;
        let soc = self.display_soc()?;
        let modes: Vec<dml::Mode> = running
            .iter()
            .map(|r| {
                if r.pipe == display {
                    selection_mode(&selection)
                } else {
                    r.plan.mode
                }
            })
            .collect();
        let Ok(plans) = dml::admit_native(&soc, &modes) else {
            return Ok(None);
        };
        let plan = plans[i];
        // Another ODM split changes the stream itself: a modeset.
        if plan.pipes != m.plan.pipes
            || running
                .iter()
                .zip(&plans)
                .enumerate()
                .any(|(j, (r, p))| j != i && !keeps_pipes(r, p))
        {
            return Ok(None);
        }
        // DC's validation on the running state: the planes recreated when
        // amdgpu_dm resets them, DML's counts mapped; a change that would
        // move the stream or another display's pipes is a modeset.
        let reset_pipes = planes_reset(m.selection.format, &m.selection.planes, format, &setup);
        let stream = StreamPipes::of(m.crtc, &selection, &plan);
        let Some(pipes) = live_pipes(&dc_state(&running), &stream, reset_pipes, &running) else {
            return Ok(None);
        };
        let (mpc, overlays) = (pipes.mpc, pipes.overlays);
        let (primary, overlay_requests) = plane_requests(&selection, display, &pipes);
        if primary.check().is_err()
            || overlay_requests
                .iter()
                .flatten()
                .any(|o| o.check().is_err())
        {
            return Ok(None);
        }
        let mut next = m;
        next.selection = selection;
        next.plan = plan;
        // The display's pipes after the change, for the clock targets.
        next.scanout.mpc = mpc;
        next.scanout.overlays = [None; otg::MAX_OVERLAYS];
        for (slot, p) in next.scanout.overlays.iter_mut().zip(&overlays) {
            *slot = p.map(|p| otg::OverlayScanout {
                pipe: p.pipe,
                odm: p.odm,
                mpc: p.mpc,
                address: 0,
                underlay: false,
            });
        }
        let old_mask = plane_targets(&m, &m.plan)
            .iter()
            .fold(0u8, |acc, &(q, _)| acc | 1 << q);
        let new_targets = plane_targets(&next, &plan);
        let frl = running.iter().any(|r| r.selection.frl.is_some());
        let frl_dtb = if frl { Some(self.top_dtb_khz()?) } else { None };
        let request = configuration_clocks(&plans, frl_dtb);
        // dcn401_prepare_bandwidth for this full update: pinned (Linux forces
        // p_state_change_support false) before update_clocks and before any
        // display's watermarks move, i.e. before the first change below.
        self.pin_display_uclk().await?;
        // prepare_bandwidth: the shared clocks only raised, the DTOs of the
        // pipes that keep fetching raised where their plane needs more.
        let mut raise: Vec<(u8, u32)> = running
            .iter()
            .zip(&plans)
            .enumerate()
            .filter(|&(j, _)| j != i)
            .flat_map(|(_, (r, p))| running_dpp_targets(r, p))
            .collect();
        raise.extend(new_targets.iter().filter(|&&(q, _)| old_mask & 1 << q != 0));
        self.update_live_display_clocks(request, &raise, false)
            .await?;
        // The new pipes' DPP-only clocks, at their planes' DPPCLK.
        for &(q, khz) in new_targets.iter().filter(|&&(q, _)| old_mask & 1 << q == 0) {
            self.prepare_display_plane_clock_live(dccg::Request {
                pipe: q,
                dpp_khz: khz,
                pixel: dccg::PixelClock::OdmSegment,
            })
            .await
            .map_err(ModesetError::PipeClocks)?;
        }
        // Plane removal can release DET which a sibling's new plan
        // needs. Include the changed display in the same shrink-first
        // transaction order as the other streams' deadline updates.
        let old_plans: Vec<_> = running.iter().map(|m| m.plan).collect();
        let order = det_update_order(&old_plans, &plans);
        let live = otg::LivePlanes {
            primary,
            overlays: overlay_requests,
            reset,
        };
        let new_pipes = overlays.map(|p| p.map(|p| p.pipe));
        let mut content = BySlot {
            pipes: core::array::from_fn(|k| match k {
                0 => Some(display),
                k => new_pipes[k - 1],
            }),
            moved: moved_planes(
                &m.selection.planes,
                &m.scanout.overlays.map(|o| o.map(|o| o.pipe)),
                &setup,
                &new_pipes,
            ),
            frames,
        };
        let mut updated = None;
        for j in order {
            if j != i {
                if plans[j] == running[j].plan {
                    continue;
                }
                // SAFETY: the caller's obligations; the scanout stays live.
                let d = unsafe { self.update_live_display_plan(running[j].pipe, &plans[j], true) }
                    .await?;
                running[j].plan = d.plan;
                running[j].scanout.plan = d.plan;
                self.modesets.retain(running[j]);
                continue;
            }
            // SAFETY: the caller's obligations, CPU views of replaced surfaces
            // withdrawn. This stream's DET/plane reductions latch before
            // siblings which need the newly available budget are visited.
            let update =
                unsafe { self.update_live_display_planes(display, &live, &plan, &mut content) };
            let change = match update.await {
                Ok(u) => u,
                // Refused before any register write: the scanout runs as it
                // was, under raised clocks; the caller relights.
                Err(_)
                    if self
                        .display_status(display)
                        .ok()
                        .flatten()
                        .is_some_and(|s| s.state == otg::State::ScanoutRunning(display)) =>
                {
                    return Ok(None);
                }
                Err(e) => return Err(e.into()),
            };
            next.scanout = change.scanout;
            running[i] = next;
            self.modesets.retain(next);
            updated = Some(change);
        }
        let updated = updated.ok_or(otg::Error::Invalid)?;
        // optimize_bandwidth over the new configuration.
        let targets: Vec<(u8, u32)> = running
            .iter()
            .flat_map(|r| running_dpp_targets(r, &r.plan))
            .collect();
        // SAFETY: as above.
        unsafe { self.optimize_running(&mut running, request, &targets) }.await?;
        for r in &running {
            self.modesets.retain(*r);
        }
        Ok(Some(PlanesChange {
            pipe: display,
            displays: running,
            updated,
        }))
    }
}
