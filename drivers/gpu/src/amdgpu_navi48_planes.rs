//! Seamless plane changes of a running Navi48 display: amdgpu_dm's
//! non-modeset plane commit (amdgpu_dm_commit_planes) through
//! dc_update_planes_and_stream. DML admits the configuration again with
//! the display's new planes (dc_validate_global_state on a full update),
//! every plane DC keeps stays on its pipes, a new plane takes free pipes
//! (resource_update_pipes_for_plane_with_slice_count), and the change runs
//! in dc_commit_updates_for_stream's order: prepare_bandwidth (shared clocks
//! and the kept pipes' DPP DTOs raised, the new pipes' DPP-only clocks,
//! the other displays to their new plans with raise-only watermarks), the
//! plane update under the display's OTG lock (`Otg::update_live_planes`),
//! then optimize_bandwidth (every display's exact watermarks, the clocks
//! lowered). Only a change of the stream itself (its ODM split, or another
//! display's pipes) is a modeset, which the caller relights.
use super::*;

/// A running display moved to new planes without relighting, with every
/// running display's record (another display's plan may have moved too),
/// in pipe order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanesChange {
    pub pipe: u8,
    pub displays: Vec<Modeset>,
    pub updated: alloc::boxed::Box<otg::PlanesUpdated>,
}

/// The first `want` pipes of `current`, then free ones for the rest.
fn keep_split(
    current: otg::SplitPipes,
    want: usize,
    free: &mut FreePipes,
) -> Result<otg::SplitPipes, ModesetError> {
    let mut pipes: Vec<u8> = current.iter().take(want).collect();
    while pipes.len() < want {
        pipes.push(free.take()?);
    }
    otg::SplitPipes::new(&pipes).ok_or(ModesetError::Display(otg::Error::Invalid))
}

/// The pipes running display `m`'s planes `setup` take under `plan`, the
/// pipes `others` being other displays': the primary keeps its pipe and
/// ODM pipes and as many of its MPC slices as `plan` keeps; an overlay DC
/// keeps (the same DRM plane, or at the same position without one) keeps
/// its pipes likewise; every further pipe comes from the free ones, from
/// the top. `None` when the stream itself would change (another ODM
/// split): a modeset.
pub fn live_plane_pipes(
    m: &Modeset,
    plan: &dml::Plan,
    setup: &PlaneSetup,
    others: u8,
) -> Result<Option<(otg::SplitPipes, OverlayPipes)>, ModesetError> {
    if plan.pipes != m.plan.pipes {
        return Ok(None);
    }
    let odm = usize::from(plan.pipes.max(1)) - 1;
    let s = &m.scanout;
    let slices = |k: usize| plan.plane(k).map_or(1, |p| p.mpc_slices(plan.pipes)) as usize;
    let primary_mpc = slices(0).max(1) - 1;
    // Each new overlay's predecessor among the running ones.
    let old = &m.selection.planes.overlays;
    let mut matched = [None; otg::MAX_OVERLAYS];
    let mut taken_old = [false; otg::MAX_OVERLAYS];
    for (k, o) in setup.overlays.iter().enumerate() {
        let Some(o) = o else { continue };
        let found = (0..otg::MAX_OVERLAYS).find(|&j| {
            !taken_old[j]
                && s.overlays[j].is_some()
                && old[j].is_some_and(|p| {
                    if o.plane != 0 {
                        p.plane == o.plane
                    } else {
                        p.plane == 0 && j == k
                    }
                })
        });
        if let Some(j) = found {
            let pipes = s.overlays[j].ok_or(ModesetError::Display(otg::Error::Invalid))?;
            if pipes.odm.len() == odm {
                taken_old[j] = true;
                matched[k] = Some(pipes);
            }
        }
    }
    // What stays: the stream's pipes, the primary's kept slices, every kept
    // overlay's pipes and kept slices.
    let mut stays = others | 1 << m.pipe | s.odm.mask();
    stays |= s.mpc.iter().take(primary_mpc).fold(0, |a, q| a | 1 << q);
    let mut position = 0;
    for (k, o) in setup.overlays.iter().enumerate() {
        if o.is_none() {
            continue;
        }
        position += 1;
        if let Some(p) = matched[k] {
            let want = slices(position).max(1) - 1;
            stays |= 1 << p.pipe | p.odm.mask();
            stays |= p.mpc.iter().take(want).fold(0, |a, q| a | 1 << q);
        }
    }
    let mut free = FreePipes(stays);
    let mpc = keep_split(s.mpc, primary_mpc, &mut free)?;
    let mut out: OverlayPipes = [None; otg::MAX_OVERLAYS];
    let mut position = 0;
    for (k, o) in setup.overlays.iter().enumerate() {
        if o.is_none() {
            continue;
        }
        position += 1;
        let want = slices(position).max(1) - 1;
        out[k] = Some(match matched[k] {
            Some(p) => PlanePipes {
                pipe: p.pipe,
                odm: p.odm,
                mpc: keep_split(p.mpc, want, &mut free)?,
            },
            None => {
                let pipe = free.take()?;
                PlanePipes {
                    pipe,
                    odm: free.split(odm)?,
                    mpc: free.split(want)?,
                }
            }
        });
    }
    Ok(Some((mpc, out)))
}

/// Every pipe of display `m`'s planes with its plane's DPPCLK under `plan`.
fn plane_targets(m: &Modeset, plan: &dml::Plan) -> Vec<(u8, u32)> {
    running_dpp_targets(m, plan)
}

impl ColdBoot {
    /// Show `format` and `setup` on running display `display` without
    /// relighting it (amdgpu_dm's plane commit without a modeset; DC's
    /// medium or full update). `reset` when amdgpu_dm would recreate a
    /// plane (should_reset_plane: a zpos change). `None` when that needs a
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
    ) -> Result<Option<PlanesChange>, ModesetError> {
        // A teardown in flight is the relight's to finish.
        if self.teardowns.check_idle().is_err() {
            return Ok(None);
        }
        let mut running: Vec<Modeset> = self.display_modesets().into_iter().flatten().collect();
        running.sort_by_key(|m| m.pipe);
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
        if running
            .iter()
            .zip(&plans)
            .enumerate()
            .any(|(j, (r, p))| j != i && !keeps_pipes(r, p))
        {
            return Ok(None);
        }
        let others = running
            .iter()
            .filter(|r| r.pipe != display)
            .flat_map(|r| running_dpp_targets(r, &r.plan))
            .fold(0u8, |acc, (q, _)| acc | 1 << q);
        let Some((mpc, overlays)) = live_plane_pipes(&m, &plan, &setup, others)? else {
            return Ok(None);
        };
        let pipes = DisplayPipes {
            odm: m.scanout.odm,
            mpc,
            overlays,
        };
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
        for (j, r) in running.iter_mut().enumerate() {
            if j == i || plans[j] == r.plan {
                continue;
            }
            // SAFETY: the caller's obligations; the scanout stays live.
            let d = unsafe { self.update_live_display_plan(r.pipe, &plans[j], true) }.await?;
            r.plan = d.plan;
            r.scanout.plan = d.plan;
            self.modesets.retain(*r);
        }
        let live = otg::LivePlanes {
            primary,
            overlays: overlay_requests,
            reset,
        };
        // SAFETY: the caller's obligations, CPU views of replaced surfaces
        // withdrawn.
        let updated = match unsafe { self.update_live_display_planes(display, &live, &plan) }.await
        {
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
        next.scanout = updated.scanout;
        running[i] = next;
        self.modesets.retain(next);
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
