//! Live plane updates of a running DCN401 scanout: planes moved, scaled,
//! reblended, given another format or surface, added (an overlay taking
//! free pipes) or removed (its pipes freed), with the timing running
//! throughout. Linux: dc_check_update_surfaces_for_stream's update types
//! (det_surface_update: get_plane_info_update_type and
//! get_scaling_info_update_type; full_update_required_weak for a plane
//! count change), then commit_planes_for_stream's sequence for a medium or
//! full update: dcn401_interdependent_update_lock (the OTG master lock),
//! dcn401_program_front_end_for_ctx (each freed pipe's DET released by
//! program_det_segments(0), then its plane_atomic_disconnect, then every
//! MPCC tree from its top pipe down: dcn20_enable_plane
//! for a new pipe, dcn20_update_dchubp_dpp with dcn20_update_mpcc's
//! remove-and-insert at the bottom on a full update, the HUBP surface,
//! viewport and DLG/TTU, the cursor), the unlock, and
//! dcn401_post_unlock_program_front_end (the new surfaces in use, then
//! dcn20_disable_plane on the freed pipes). The caller brackets it with
//! prepare_bandwidth (clocks raised, watermarks raise-only) and
//! optimize_bandwidth (exact watermarks, clocks lowered); the compressed
//! buffer, this display's to size, grows into freed DETs at the end of the
//! update as optimize_bandwidth's program_compbuf_segments does.
use super::scanout::Pipe;
use super::*;
use crate::amdgpu_dcn401_dml as dml;
use crate::amdgpu_gmc_navi48::{DisplayContext, Gmc};
use alloc::vec::Vec;

const BLANK_EN: u32 = 1;
const NO_OUTSTANDING: u32 = 2;
const TTU_DISABLE: u32 = 0x1000;
const MPCC_CONTROL: u64 = 3;
const MODE_PASSTHROUGH: u32 = 1;
const MODE_TOP_ONLY: u32 = 2;
const MODE_TOP_BOT: u32 = 3;
const DPP_CLOCK_ENABLE: u32 = 0x10;
const DOUBLE_BUFFER: u64 = 0x1b5c;
const PIPE_UPDATE: u64 = 0x1b9e;
const CM_CURSOR: u64 = 0xcf1;
const LOCK_REQUEST: u32 = 1;

/// dc's enum surface_update_type: what a plane change needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum UpdateType {
    /// Addresses only (a flip).
    Fast,
    /// Placement, blending, pitch or color space on the planes' pipes.
    Med,
    /// Bandwidth: a new format, size, rotation, tiling or DCC, or planes
    /// added or removed; DML's admission again.
    Full,
}

/// The DC surface format of a plane (X and A variants share one).
fn dc_format(f: SurfaceFormat) -> (u32, u32) {
    (f.hubp_pixel_format(), f.crossbar())
}
/// det_surface_update for a plane DC keeps (get_plane_info_update_type and
/// get_scaling_info_update_type on what amdgpu_dm's
/// fill_dc_plane_info_and_addr and fill_dc_scaling_info hand DC): the color
/// space, per-pixel or global alpha and the pitch are medium changes, the
/// rotation, format, bytes per pixel, tiling or DCC full ones; a source or
/// destination of another size is full, one moved is medium. A plane whose
/// MPC split changes (DML combining it on other DPPs, or no longer) is a
/// full update: dc only re-splits pipes in a full update's validation.
pub fn plane_update_type(old: SurfaceRequest, new: SurfaceRequest) -> UpdateType {
    let mut t = UpdateType::Fast;
    let mut elevate = |u: UpdateType| t = t.max(u);
    if old.mpc != new.mpc {
        elevate(UpdateType::Full);
    }
    let (lo, ln) = (old.layout(), new.layout());
    let color = |r: &SurfaceRequest| r.format.is_video().then_some(r.surface.color);
    if color(&old) != color(&new) {
        elevate(UpdateType::Med);
    }
    if lo.rotation != ln.rotation {
        elevate(UpdateType::Full);
    }
    if dc_format(old.format) != dc_format(new.format) {
        elevate(UpdateType::Full);
    }
    if lo.blend.per_pixel_alpha != ln.blend.per_pixel_alpha {
        elevate(UpdateType::Med);
    }
    if lo.blend.global_alpha.unwrap_or(0xff) != ln.blend.global_alpha.unwrap_or(0xff) {
        elevate(UpdateType::Med);
    }
    if old.surface.tiling.dcc != new.surface.tiling.dcc {
        elevate(UpdateType::Full);
    }
    if old.format.bytes_per_pixel() != new.format.bytes_per_pixel() {
        elevate(UpdateType::Full);
    }
    let pitch = |r: &SurfaceRequest| {
        let b = r.bytes();
        (
            b.pitch_bytes / r.format.bytes_per_pixel(),
            b.chroma.map(|(_, p)| p / r.format.chroma_bytes_per_pixel()),
        )
    };
    if pitch(&old) != pitch(&new) {
        elevate(UpdateType::Med);
    }
    if old.surface.tiling != new.surface.tiling {
        elevate(UpdateType::Full);
    }
    // The clip is the destination.
    let (s0, s1, d0, d1) = (lo.src, ln.src, lo.dst, ln.dst);
    if (s0.width, s0.height, d0.width, d0.height) != (s1.width, s1.height, d1.width, d1.height) {
        elevate(UpdateType::Full);
    }
    if (s0.x, s0.y, d0.x, d0.y) != (s1.x, s1.y, d1.x, d1.y) {
        elevate(UpdateType::Med);
    }
    t
}
/// check_update_surfaces_for_stream over a stream's planes (the primary,
/// then the overlays bottom first): a plane added or removed is a full
/// update (full_update_required_weak's plane count), as is a plane
/// amdgpu_dm recreates (`reset`: should_reset_plane on a zpos change);
/// otherwise the most any plane needs.
pub fn planes_update_type(
    old: &[SurfaceRequest],
    new: &[SurfaceRequest],
    reset: bool,
) -> UpdateType {
    if reset || old.len() != new.len() {
        return UpdateType::Full;
    }
    old.iter().zip(new).fold(UpdateType::Fast, |t, (o, n)| {
        let order = if o.layout().underlay == n.layout().underlay {
            UpdateType::Fast
        } else {
            UpdateType::Full
        };
        t.max(plane_update_type(*o, *n)).max(order)
    })
}

/// The planes a live display is to show: its primary on its own pipes, the
/// overlays (bottom first) on theirs, and whether amdgpu_dm would recreate
/// a plane (zpos change).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LivePlanes {
    pub primary: SurfaceRequest,
    pub overlays: [Option<SurfaceRequest>; MAX_OVERLAYS],
    pub reset: bool,
}

/// What a live plane update did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlanesUpdated {
    pub update: UpdateType,
    /// Pipes a plane newly took, pipes freed, and pipes kept, by bit.
    pub enabled: u8,
    pub disabled: u8,
    pub kept: u8,
    /// The live scanout now (its plan the deadlines' too).
    pub scanout: ScanoutRunning,
    /// Bytes of the superseded surfaces released once the update latched.
    pub released: u64,
}

/// The first content of a plane surface a live update allocates afresh (a
/// new plane, or one of another allocation), written into it once cleared
/// and before the update programs it, so the frame the update latches
/// already shows the plane's framebuffer, as DC scans a new plane's address
/// from the update that adds it. `chunk(a, index, words)` fills `words`
/// with chunk `index` (from 0) of surface `a`'s bytes as packed 32-bit
/// words and returns the byte offset they go to, or None when there is no
/// more (none at all leaves the surface cleared). A chunk outside the
/// surface refuses the update before any register write.
pub trait PlaneContent: Send {
    fn chunk(&mut self, a: &SurfaceApplied, index: u32, words: &mut Vec<u32>) -> Option<u64>;
    /// A client framebuffer the plane on fresh surface `a` scans out in
    /// place instead of a copy (DC programs a new plane's framebuffer
    /// address in the update that adds it): the update programs its
    /// address and pitches, its staged buffers left cleared and unfetched,
    /// and no `chunk` is asked for. One the plane cannot fetch refuses the
    /// update before any register write. The caller keeps it pinned until
    /// a later flip or stop shows it no longer fetched.
    fn external(&mut self, _a: &SurfaceApplied) -> Option<ExternalSurface> {
        None
    }
    /// Whether the plane the update puts on pipe `pipe` is another plane
    /// than the one there before (a recreated plane moved onto it): it then
    /// takes a fresh surface with this content even where the old surface
    /// has its allocation, so the update never latches with the other
    /// plane's image on it (DC programs a recreated plane's framebuffer
    /// address in the update that adds it).
    fn moved_to(&mut self, _pipe: u8) -> bool {
        false
    }
}
/// No first content: fresh surfaces stay cleared until the next flip.
#[derive(Clone, Copy, Debug, Default)]
pub struct Cleared;
impl PlaneContent for Cleared {
    fn chunk(&mut self, _: &SurfaceApplied, _: u32, _: &mut Vec<u32>) -> Option<u64> {
        None
    }
}

/// One MPCC tree as mpc1's software list keeps it: its OPP and its MPCCs,
/// top first.
struct MpcTree {
    opp: u8,
    list: Vec<u8>,
}

/// One new plane of an update: its records and whether its pipes are
/// reprogrammed (a new plane, or one whose request or surface changed).
struct LivePlane {
    applied: SurfaceApplied,
    dpp: DppApplied,
    mpc: MpcApplied,
    changed: bool,
}

/// Everything the locked part of an update programs.
struct Change {
    old: Pipe,
    new: Pipe,
    planes: Vec<LivePlane>,
    enabled: u8,
    disabled: u8,
    full: bool,
    /// The new global sync, when the plan's differs from the running one.
    sync: Option<Plan>,
    cursor: Option<(CursorApplied, Vec<(u8, super::cursor::Placement)>)>,
}

impl<I: Io> Engine<I> {
    /// mpc1_remove_mpcc: `m` leaves its tree (the MPCC above it or the
    /// OPP's OUT_MUX takes the one below; a new bottom passes its top layer
    /// through) and its muxes and update lock are released. `t` names
    /// pipes; the muxes take their MPCC instances (mpcc_id = dpp->inst).
    fn mpc_remove(&mut self, t: &mut MpcTree, m: u8) -> Result<(), Error> {
        let l = self.layout;
        let Some(i) = t.list.iter().position(|&x| x == m) else {
            return Ok(());
        };
        let below = t.list.get(i + 1).copied();
        if i == 0 {
            self.update(
                l.out_mux(t.opp),
                0xf,
                below.map_or(0xf, |b| l.inst_field(b)),
            )?;
        } else {
            let above = t.list[i - 1];
            match below {
                Some(b) => self.update(l.mpcc(above, BOTTOM), 0xf, l.inst_field(b))?,
                None => {
                    self.update(l.mpcc(above, BOTTOM), 0xf, 0xf)?;
                    self.update(l.mpcc(above, MPCC_CONTROL), 3, MODE_PASSTHROUGH)?;
                }
            }
        }
        for r in [TOP, BOTTOM, OPP_ID, UPDATE_LOCK] {
            self.update(l.mpcc(m, r), 0xf, 0xf)?;
        }
        t.list.remove(i);
        Ok(())
    }
    /// mpc1_insert_plane at the bottom of `t` (no insert_above_mpcc), as
    /// dcn20_update_mpcc inserts each pipe of a tree programmed top down:
    /// MPCC_TOP_SEL = dpp_id, MPCC_OPP_ID = opp_id, MPC_OUT_MUX and
    /// MPCC_BOT_SEL = mpcc_id, all instances of the pipes `t` and `m` name.
    fn mpc_insert_bottom(&mut self, t: &mut MpcTree, m: u8) -> Result<(), Error> {
        let l = self.layout;
        self.update(l.mpcc(m, BOTTOM), 0xf, 0xf)?;
        self.update(l.mpcc(m, MPCC_CONTROL), 3, MODE_TOP_ONLY)?;
        self.update(l.mpcc(m, TOP), 0xf, l.inst_field(m))?;
        self.update(l.mpcc(m, OPP_ID), 0xf, l.inst_field(t.opp))?;
        self.update(l.mpcc(m, UPDATE_LOCK), 0xf, l.inst_field(t.opp))?;
        match t.list.last().copied() {
            None => self.update(l.out_mux(t.opp), 0xf, l.inst_field(m))?,
            Some(a) => {
                self.update(l.mpcc(a, BOTTOM), 0xf, l.inst_field(m))?;
                self.update(l.mpcc(a, MPCC_CONTROL), 3, MODE_TOP_BOT)?;
            }
        }
        t.list.push(m);
        Ok(())
    }
    /// A pipe the selected display may take for a plane while it scans out:
    /// no display's, its OTG idle and unlocked, its MPCC in no tree and idle,
    /// and, powered, its HUBP blank, drained and clock-gated without any
    /// transaction and its DPP stopped. Returns whether it is powered.
    fn free_pipe(&mut self, q: u8) -> Result<bool, Error> {
        let l = self.layout;
        if q >= l.pool.count() || self.displays.siblings.pipes & bit(q) != 0 {
            return Err(Error::Busy);
        }
        if self.read(l.otg(q, LOCK))? & 0x101 != 0
            || self.read(l.otg(q, CLOCK))? & 0x10 != 0
            || self.read(l.otg(q, GSL))? & 0x8000_000f != 0
            || self.read(l.mpcc(q, UPDATE_LOCK))? & 0x70 != 0
        {
            return Err(Error::Busy);
        }
        for at in [
            l.out_mux(q),
            l.mpcc(q, TOP),
            l.mpcc(q, BOTTOM),
            l.mpcc(q, OPP_ID),
            l.mpcc(q, UPDATE_LOCK),
        ] {
            if self.read(at)? & 0xf != 0xf {
                return Err(Error::Busy);
            }
        }
        let status = self.read(l.mpcc(q, MPC_STATUS))?;
        if status & 2 != 0 || status & 5 == 0 {
            return Err(Error::Busy);
        }
        if !self.hubp_powered(q)? {
            return Ok(false);
        }
        if self.read(l.hubp(q, HUBP_CONTROL))? & 7 != 3 {
            return Err(Error::Busy);
        }
        self.hubp_transactions_stopped(q, false)?;
        self.dpp_stopped(q, false)?;
        Ok(true)
    }
    /// dcn20_enable_plane for a free pipe joining the display (blank and
    /// out of every tree): its fetch clock, the VMID0 aperture
    /// (hubp401_set_vm_system_aperture_settings), the requestor following
    /// the stream's VTG and its DPP clock.
    async fn enable_free_pipe(
        &mut self,
        q: u8,
        vtg: u8,
        config: DisplayContext,
    ) -> Result<(), Error> {
        let l = self.layout;
        self.update(l.hubp(q, HUBP_CLOCK), 1, 1)?;
        self.wait(l.hubp(q, HUBP_CONTROL), 0x1007, 3, 100_000)
            .await?;
        for (r, mask, value) in super::vm::pipe_registers(config) {
            let at = l.hubp(q, r);
            self.access(|io| {
                io.write(at, value);
                Ok(())
            })?;
            if self.read(at)? & mask != value {
                return Err(Error::Readback(at));
            }
        }
        // hubp_vtg_sel(tg->inst): the stream's OTG instance.
        for (r, mask, value) in super::requestor::requestor(l.inst(vtg)) {
            self.update(l.hubp(q, r), mask, value)?;
        }
        self.update(self.dpp_control(q), DPP_CLOCK_ENABLE, DPP_CLOCK_ENABLE)
    }
    /// Pipe `m`'s share of plane `a`'s composition as prepare_mpc stages it
    /// (mpc_full: the MPCC's blending, gains and background, stereo off, its
    /// color blocks in bypass, the output stage of its OPP index), its
    /// MPCC_MODE left to the tree and the CRTC color (OGAM, gamut remap) to
    /// program_color: dcn20_update_mpcc's update_blending.
    fn mpc_blend_writes(&self, a: &MpcApplied, m: u8) -> Vec<(u64, u32, u32)> {
        let l = self.layout;
        let skip = [l.ogam(m, 0x7e), l.ogam(m, 0xc9)];
        l.mpc_pipe(a, m)
            .into_iter()
            .filter(|&(at, _, _)| !skip.contains(&at))
            .map(|(at, mask, value)| {
                if at == l.mpcc(m, MPCC_CONTROL) {
                    (at, mask & !3, value)
                } else {
                    (at, mask, value)
                }
            })
            .collect()
    }
    /// The locked part of a live plane update (dcn401_interdependent_update_
    /// lock, dcn401_program_front_end_for_ctx, the unlock and
    /// dcn401_post_unlock_program_front_end), the timing running throughout:
    /// under the OTG master lock the global sync if it changed, the freed
    /// pipes' DETs released, their MPCCs out of their trees and their
    /// cursors off, each changed or new plane's DPP, on a full update every
    /// tree rebuilt from its top
    /// pipe down (each MPCC removed and inserted at the bottom, then its
    /// blending), on a medium one the changed planes' blending, each changed
    /// or new plane's HUBP surface, viewport and address, every plane's
    /// DLG/TTU with raise-only watermarks, the CRTC color on the new top
    /// MPCCs, the cursor on every pipe it now overlaps, the new pipes
    /// unblanked; then, unlocked, every plane's surface in use and the
    /// freed MPCCs idle, and the freed HUBPs drained, blanked and gated.
    async fn apply_planes(&mut self, c: &mut Change, plan: &dml::Plan) -> Result<(), Error> {
        let l = self.layout;
        let pipe = c.new.pipe;
        self.lock(pipe).await?;
        let target = self.requestor_allocation(self.status.requestor.ok_or(Error::Invalid)?)?;
        if let Some(sync) = c.sync {
            self.global_sync_writes(sync, false)?;
        }
        let mut trees: Vec<MpcTree> = c
            .old
            .trees()
            .into_iter()
            .zip(c.old.pipes())
            .map(|(t, opp)| MpcTree {
                opp,
                list: t.into_iter().rev().collect(),
            })
            .collect();
        // dcn401_program_front_end_for_ctx for every freed pipe, by pipe
        // index: its DET released (program_det_segments(hubp->inst, 0)),
        // then plane_atomic_disconnect; its cursor goes with it.
        for q in l.pool.pipes().filter(|&q| c.disabled & bit(q) != 0) {
            self.program_det_segments(q, 0)?;
            for t in trees.iter_mut() {
                self.mpc_remove(t, q)?;
            }
            self.update(l.hubp(q, CURSOR), 1, 0)?;
            self.update(self.cm(q, CM_CURSOR), 1, 0)?;
        }
        self.program_dets(target)?;
        for k in 0..c.planes.len() {
            let p = &c.planes[k];
            if p.changed {
                let mut dpp = p.dpp;
                let coef_ram = self.program_dpp_live(&mut dpp).await?;
                c.planes[k].dpp = DppApplied { coef_ram, ..dpp };
                c.planes[k].mpc.dpp = c.planes[k].dpp;
            }
        }
        let plane_of = |planes: &[LivePlane], m: u8| {
            planes
                .iter()
                .position(|p| p.applied.request.pipe_mask() & bit(m) != 0)
                .ok_or(Error::Invalid)
        };
        let new_trees = c.new.trees();
        let opps: Vec<u8> = c.new.pipes().collect();
        if c.full {
            // dcn20_update_mpcc on a full update: every tree, its top pipe
            // first, each MPCC removed and inserted at the bottom.
            for (tree, &opp) in new_trees.iter().zip(&opps) {
                let at = trees.iter().position(|t| t.opp == opp);
                let mut t = match at {
                    Some(i) => trees.swap_remove(i),
                    None => MpcTree {
                        opp,
                        list: Vec::new(),
                    },
                };
                for &m in tree.iter().rev() {
                    let k = plane_of(&c.planes, m)?;
                    self.mpc_remove(&mut t, m)?;
                    self.mpc_insert_bottom(&mut t, m)?;
                    for (at, mask, value) in self.mpc_blend_writes(&c.planes[k].mpc, m) {
                        self.update(at, mask, value)?;
                    }
                }
            }
        } else {
            for p in c.planes.iter().filter(|p| p.changed) {
                for (m, _, _) in p.applied.request.segments() {
                    for (at, mask, value) in self.mpc_blend_writes(&p.mpc, m) {
                        self.update(at, mask, value)?;
                    }
                }
            }
        }
        for p in c.planes.iter().filter(|p| p.changed) {
            for (q, scaler) in p.applied.request.scalers() {
                for (r, mask, value) in p.applied.registers(&scaler) {
                    self.update(l.hubp(q, r), mask, value)?;
                }
            }
        }
        self.deadline_writes_with(pipe, plan, false, WatermarkUpdate::Raise)?;
        self.program_color(c.new).await?;
        if let Some((a, segments)) = &c.cursor {
            for (at, mask, value) in self.cursor_writes(*a, segments) {
                self.update(at, mask, value)?;
            }
        }
        for q in l.pool.pipes().filter(|&q| c.enabled & bit(q) != 0) {
            self.update(l.hubp(q, HUBP_CONTROL), BLANK_EN | TTU_DISABLE, 0)?;
        }
        self.update(l.otg(pipe, LOCK), LOCK_REQUEST, 0)?;
        // Unlocked: under DRR the manual trigger ends the stretched blank.
        self.drr_trigger(pipe)?;
        let (new, disabled) = (c.new, c.disabled);
        self.latched(new, |e| {
            if let Some(at) = e.all_in_use(new)? {
                return Ok(Some(at));
            }
            for (at, mask) in [
                (l.otg(pipe, DOUBLE_BUFFER), 1),
                (l.otg(pipe, PIPE_UPDATE), 0x11),
            ] {
                if e.read(at)? & mask != 0 {
                    return Ok(Some(at));
                }
            }
            for q in new.all_pipes() {
                let at = l.mpcc(q, MPC_STATUS); // no longer DISABLED
                if e.read(at)? & 4 != 0 {
                    return Ok(Some(at));
                }
            }
            for q in l.pool.pipes().filter(|&q| disabled & bit(q) != 0) {
                // mpc2_assert_idle_mpcc: DISABLED, or IDLE and not BUSY.
                let at = l.mpcc(q, MPC_STATUS);
                let status = e.read(at)?;
                if status & 2 != 0 || status & 5 == 0 {
                    return Ok(Some(at));
                }
            }
            Ok(None)
        })
        .await?;
        // dcn20_disable_plane: hubp2_set_blank once nothing is outstanding,
        // then the fetch and DPP clocks off.
        for q in l.pool.pipes().filter(|&q| disabled & bit(q) != 0) {
            self.wait(
                l.hubp(q, HUBP_CONTROL),
                NO_OUTSTANDING,
                NO_OUTSTANDING,
                100_000,
            )
            .await?;
            self.update(l.hubp(q, HUBP_CONTROL), BLANK_EN | TTU_DISABLE, BLANK_EN)?;
            self.wait(l.hubp(q, HUBP_CONTROL), 0x1007, 3, 100_000)
                .await?;
            self.update(l.hubp(q, HUBP_CLOCK), 1, 0)?;
            self.update(self.dpp_control(q), DPP_CLOCK_ENABLE, 0)?;
        }
        Ok(())
    }
    /// A freed pipe as dcn20_disable_plane leaves it: blank, drained, both
    /// clocks and the cursor off, out of every tree.
    fn verify_freed(&mut self, q: u8) -> Result<(), Error> {
        let l = self.layout;
        for (at, mask, value) in [
            (l.hubp(q, HUBP_CONTROL), 0x1007, 3),
            (l.hubp(q, HUBP_CLOCK), 1, 0),
            (l.hubp(q, CURSOR), 1, 0),
            (self.dpp_control(q), DPP_CLOCK_ENABLE, 0),
        ] {
            if self.read(at)? & mask != value {
                return Err(Error::Readback(at));
            }
        }
        for at in [l.mpcc(q, TOP), l.mpcc(q, BOTTOM), l.mpcc(q, OPP_ID)] {
            if self.read(at)? & 0xf != 0xf {
                return Err(Error::Readback(at));
            }
        }
        Ok(())
    }
}

impl Surfaces {
    /// Move display `pipe`'s live scanout to the planes `request` under
    /// `plan` (its stream's own timing, admitted with them in the current
    /// configuration) without leaving scanout: DC's medium or full update
    /// on the pipes the planes keep, take (free pipes, enabled off-tree
    /// first) or free (retired after the update latched). A plane of the
    /// same allocation keeps its buffers and content; any other gets a
    /// cleared one holding `content`'s first frame, and the buffers it
    /// supersedes are released once nothing fetches them. Refusals before the first register write leave the
    /// scanout as it was; later failure or cancellation quarantines it.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::amdgpu_dcn401_otg) async fn update_live_planes<I: Io>(
        &mut self,
        e: &mut Engine<I>,
        pool: &Pool,
        pipe: u8,
        request: &LivePlanes,
        plan: &dml::Plan,
        crystal_khz: u32,
        content: &mut dyn PlaneContent,
        mut owners: impl FnMut() -> Result<(dccg::Applied, DisplayContext), Error>,
    ) -> Result<alloc::boxed::Box<PlanesUpdated>, Error> {
        let slot = usize::from(pipe);
        if e.status.state != State::ScanoutRunning(pipe) {
            return Err(Error::Busy);
        }
        let running = e.status.scanout.ok_or(Error::Invalid)?;
        let d = e.status.deadlines.ok_or(Error::Invalid)?;
        let a = e.status.requestor.ok_or(Error::Invalid)?;
        let timing = e.status.pipes[slot].ok_or(Error::Invalid)?;
        let blank = e.status.blanks[slot].ok_or(Error::Invalid)?;
        if running.pipe != pipe || d.pipe != pipe || a.pipe != pipe {
            return Err(Error::Invalid);
        }
        // The planes: each on the stream, split like it, on pipes of its
        // own; underlays below the others.
        let t = blank.timing.request;
        let planes: Vec<SurfaceRequest> = core::iter::once(request.primary)
            .chain(request.overlays.iter().flatten().copied())
            .collect();
        let on_stream = |s: &SurfaceRequest| {
            let l = s.layout();
            l.stream_width == t.timing.h_active
                && l.stream_height == t.timing.v_active
                && l.ycbcr420 == blank.request.encoding.is_420()
                && s.odm.count() == t.odm.count()
        };
        let primary = request.primary;
        if primary.pipe != pipe || primary.odm != t.odm || !on_stream(&primary) {
            return Err(Error::Invalid);
        }
        if planes.len() > MAX_OVERLAYS + 1 {
            return Err(Error::Unsupported);
        }
        let mut used = 0u8;
        let mut above = false;
        for (k, s) in planes.iter().enumerate() {
            s.check()?;
            let mask = s.pipe_mask();
            if mask & used != 0 {
                return Err(Error::Invalid);
            }
            if mask & e.displays.siblings.pipes != 0 {
                return Err(Error::Busy);
            }
            used |= mask;
            if k > 0 {
                let underlay = s.layout().underlay;
                if s.plane.is_none() || !on_stream(s) || (underlay && above) {
                    return Err(Error::Invalid);
                }
                above |= !underlay;
            }
        }
        let geometry: Vec<(u32, u64)> = planes
            .iter()
            .map(|s| s.geometry())
            .collect::<Result<_, _>>()?;
        let current = owners()?;
        let config = current.1;
        let refclk = e.dchub_refclk_khz(crystal_khz)?;
        let new_request = Request {
            sync: plan.sync,
            ..timing.request
        };
        let new_timing = new_request.plan()?;
        let provisional =
            |k: usize| SurfaceApplied::staged(planes[k], 0, geometry[k].0, geometry[k].1);
        let mut provisional_overlays = [None; MAX_OVERLAYS];
        for (k, o) in provisional_overlays
            .iter_mut()
            .enumerate()
            .take(planes.len() - 1)
        {
            *o = Some(provisional(k + 1));
        }
        let requestor = |surface, overlays, compbuf: u8| RequestorApplied {
            pipe,
            surface,
            overlays,
            det_bytes: plan.det_bytes,
            overlay_det_bytes: core::array::from_fn(|k| {
                plan.plane(k + 1).map_or(0, |p| p.det_bytes)
            }),
            compbuf_bytes: u32::from(compbuf) * super::requestor::SEGMENT_BYTES,
            pixel_chunk_bytes: 8192,
            minimum_chunk_bytes: 1024,
        };
        if !super::deadline::bound(
            plan,
            new_request,
            requestor(provisional(0), provisional_overlays, 0),
            current.0,
            refclk,
        ) {
            return Err(Error::Invalid);
        }
        // The live scanout is still the one its records name (another
        // display's update may have raised the shared watermarks).
        let old = self.scanout_bound_with(e, d, crystal_khz, current, WatermarkUpdate::Raise)?;
        e.live_fetch(pipe, running.address)?;
        e.flip_quiet(pipe)?;
        let old_mask = old.all_pipes().into_iter().fold(0u8, |m, q| m | bit(q));
        let enabled = used & !old_mask;
        let disabled = old_mask & !used;
        let mut powered = 0u8;
        // Every bit of `enabled`: one past the pool (or fused) is refused by
        // free_pipe; the later loops then see pool pipes only.
        let pipes = e.layout.pool.pipes();
        for q in (0..u8::BITS as u8).filter(|&q| enabled & bit(q) != 0) {
            if e.free_pipe(q)? {
                powered |= bit(q);
            }
        }
        let old_planes: Vec<SurfaceRequest> = core::iter::once(a.surface)
            .chain(a.overlays.iter().flatten().copied())
            .map(|s| s.request)
            .collect();
        let topology = enabled | disabled != 0;
        let update = planes_update_type(&old_planes, &planes, request.reset).max(if topology {
            UpdateType::Full
        } else {
            UpdateType::Fast
        });
        // Each plane's buffers: the same plane with the same allocation on
        // the same pipes keeps the surface (and what it shows), any other
        // (another plane moved onto the pipe included) takes a fresh,
        // cleared one, unpublished until the hardware is told of it.
        let mut applied: Vec<SurfaceApplied> = Vec::with_capacity(planes.len());
        let mut fresh: Vec<Surface> = Vec::new();
        for (k, s) in planes.iter().enumerate() {
            let (pitch_bytes, bytes) = geometry[k];
            let at = usize::from(s.pipe);
            let kept = self.0[at]
                .as_ref()
                .filter(|x| {
                    old_mask & bit(s.pipe) != 0
                        && x.applied.request.same_allocation(*s)
                        && e.status.surfaces[at] == Some(x.applied)
                })
                .filter(|_| !content.moved_to(s.pipe))
                .map(|x| x.applied);
            if let Some(x) = kept {
                // The plane keeps fetching what it shows, a client
                // framebuffer scanned out in place too, with its pitch.
                applied.push(SurfaceApplied { request: *s, ..x });
                continue;
            }
            let memory = pool.reserve(bytes).map_err(|_| Error::Allocation)?;
            if memory.address() < config.fb_base
                || memory
                    .address()
                    .checked_add(memory.size() - 1)
                    .is_none_or(|last| last > config.fb_top || last >= 1 << 48)
            {
                return Err(Error::Invalid);
            }
            let map = memory.mapping();
            for start in (0..map.len).step_by(65536) {
                let end = (start + 65536).min(map.len);
                e.access(|_| {
                    for offset in (start..end).step_by(4) {
                        // SAFETY: live authority and an owned, unpublished VRAM mapping.
                        unsafe { map.write32(offset, 0) };
                    }
                    Ok(())
                })?;
                if end < map.len {
                    narf_scheduler::yield_now().await;
                }
            }
            let mut a = SurfaceApplied::staged(*s, memory.address(), pitch_bytes, bytes);
            // A client framebuffer scanned out in place from the update
            // itself; its staged buffers stay cleared.
            let external = content.external(&a);
            if let Some(x) = external {
                if x.address < config.fb_base || x.last > config.fb_top || x.last >= 1 << 48 {
                    return Err(Error::Invalid);
                }
                a = x.applied(a)?;
            }
            // Otherwise its first content, before the hardware hears of it:
            // the update latches with the plane's framebuffer shown.
            let mut words = Vec::new();
            let mut index = 0u32;
            while let Some(offset) = external
                .is_none()
                .then(|| content.chunk(&a, index, &mut words))
                .flatten()
            {
                let end = (words.len() as u64)
                    .checked_mul(4)
                    .and_then(|n| n.checked_add(offset));
                if words.is_empty() || offset % 4 != 0 || end.is_none_or(|end| end > bytes) {
                    return Err(Error::Invalid);
                }
                e.access(|_| {
                    for (i, &word) in words.iter().enumerate() {
                        // SAFETY: live authority, checked bounds within an
                        // owned, unpublished VRAM mapping.
                        unsafe { map.write32(offset + i as u64 * 4, word) };
                    }
                    Ok(())
                })?;
                index += 1;
                if index % 16 == 0 {
                    narf_scheduler::yield_now().await;
                }
            }
            applied.push(a);
            fresh.push(Surface {
                memory,
                applied: a,
                back: None,
                cursor: None,
            });
        }
        e.flush_surface_writes()?;
        let mut new_overlays = [None; MAX_OVERLAYS];
        for (o, s) in new_overlays.iter_mut().zip(&applied[1..]) {
            *o = Some(*s);
        }
        let mut live: Vec<LivePlane> = Vec::with_capacity(applied.len());
        for &s in &applied {
            let dpp = DppApplied {
                surface: s,
                timing: blank.timing,
                line_buffer_config: super::dpp::line_buffer_config(s.request)?,
                coef_ram: Default::default(),
                pending: 0,
                post_csc_b: Default::default(),
            };
            let at = usize::from(s.request.pipe);
            live.push(LivePlane {
                applied: s,
                dpp,
                mpc: MpcApplied {
                    dpp,
                    depth: blank.request.depth,
                    limited: blank.request.limited,
                    encoding: blank.request.encoding,
                    colorspace: blank.request.colorspace,
                    pending: 0,
                },
                changed: s.request.pipe_mask() & enabled != 0 || e.status.surfaces[at] != Some(s),
            });
        }
        let new = Pipe {
            pipe,
            odm: t.odm,
            mpc: primary.mpc,
            address: applied[0].address,
            overlays: new_overlays.map(|o| o.map(OverlayScanout::of)),
            ..old
        };
        let cursor = e.status.cursor.filter(|c| c.pipe == pipe).map(|c| {
            let segments = super::cursor::placements(
                c,
                applied[0],
                &new_overlays,
                super::cursor::clocks_of(plan),
            );
            (super::cursor::shown(c, &segments), segments)
        });
        let mut change = Change {
            old,
            new,
            planes: live,
            enabled,
            disabled,
            full: update == UpdateType::Full,
            sync: (new_request.sync != timing.request.sync).then_some(new_timing),
            cursor,
        };
        // From here on the hardware hears of the change: failure or
        // cancellation quarantines the display.
        for s in fresh.iter_mut() {
            s.memory.publish();
        }
        e.status.state = State::UpdatingPlanes(pipe);
        let mut superseded: Vec<Surface> = Vec::new();
        let result = async {
            for q in pipes.clone().filter(|&q| enabled & bit(q) != 0) {
                if powered & bit(q) == 0 {
                    let on = HubpPower {
                        pipe: q,
                        powered: true,
                    };
                    e.gate_hubp(on).await?;
                    e.status.hubp_power[usize::from(q)] = Some(on);
                    e.hubp_transactions_stopped(q, false)?;
                    e.dpp_stopped(q, false)?;
                }
                e.enable_free_pipe(q, pipe, config).await?;
            }
            let crb = e.requestor_allocation(requestor(applied[0], new_overlays, 0))?;
            e.prepare_det_space(crb).await?;
            // The display's records name the new planes from now on.
            let old_slots = core::iter::once(a.surface)
                .chain(a.overlays.iter().flatten().copied())
                .map(|s| usize::from(s.request.pipe));
            for k in old_slots {
                e.status.surfaces[k] = None;
                e.status.memory[k] = None;
                e.status.dpps[k] = None;
                e.status.mpcs[k] = None;
            }
            for p in &change.planes {
                let k = usize::from(p.applied.request.pipe);
                e.status.surfaces[k] = Some(p.applied);
                e.status.memory[k] = Some(MemoryApplied {
                    pipe: k as u8,
                    framebuffer_base: config.fb_base,
                    framebuffer_top: config.fb_top,
                    framebuffer_offset: config.fb_offset,
                    page_table_base: config.root,
                });
                e.status.dpps[k] = Some(p.dpp);
                e.status.mpcs[k] = Some(p.mpc);
            }
            e.status.requestor = Some(requestor(applied[0], new_overlays, crb[0]));
            e.apply_planes(&mut change, plan).await?;
            e.settle_active_dets(crb).await?;
            for p in &change.planes {
                let k = usize::from(p.applied.request.pipe);
                e.status.dpps[k] = Some(p.dpp);
                e.status.mpcs[k] = Some(p.mpc);
            }
            if owners()? != current {
                return Err(Error::Busy);
            }
            for q in pipes.clone().filter(|&q| disabled & bit(q) != 0) {
                e.verify_freed(q)?;
            }
            // optimize_bandwidth's compbuf increase into the freed DETs
            // (dcn401_program_compbuf_segments with safe_to_increase, after
            // every DET_SIZE_CURRENT acknowledged its request), run on every
            // update as Linux; a grow a slow DET deferred is retried here
            // and by `retry_compbuf`.
            let crb = e.increase_compbuf().await?;
            e.settle_compbuf_minimum(plan.arbiter.compbuf_segments)
                .await?;
            e.status.requestor = Some(requestor(applied[0], new_overlays, crb[0]));
            // Every record of the timing carries the new sync.
            e.status.rebind_timing(pipe, |t| t.request.sync = plan.sync);
            let deadlines = DeadlinesApplied {
                pipe,
                plan: *plan,
                vready_after_vsync: super::deadline::vready_after_vsync(plan),
            };
            e.status.deadlines = Some(deadlines);
            e.status.cursor = change.cursor.as_ref().map(|(c, _)| *c);
            // The surfaces now fetched take their slots; those they replace
            // stay owned until released below.
            for (k, s) in applied.iter().enumerate() {
                let at = usize::from(s.request.pipe);
                match fresh.iter().position(|f| f.applied == *s) {
                    Some(i) => {
                        let mut f = fresh.swap_remove(i);
                        if let Some(mut old) = self.0[at].take() {
                            // The primary's cursor image stays with its slot.
                            if k == 0 {
                                f.cursor = old.cursor.take();
                            }
                            superseded.push(old);
                        }
                        self.0[at] = Some(f);
                    }
                    None => {
                        if let Some(x) = self.0[at].as_mut() {
                            x.applied = *s;
                        }
                    }
                }
            }
            for k in pipes
                .clone()
                .filter(|&q| disabled & bit(q) != 0)
                .map(usize::from)
            {
                let named = applied.iter().any(|s| usize::from(s.request.pipe) == k);
                if !named {
                    if let Some(old) = self.0[k].take() {
                        superseded.push(old);
                    }
                }
            }
            let report = ScanoutRunning {
                pipe,
                odm: t.odm,
                mpc: primary.mpc,
                stream: running.stream,
                plan: *plan,
                address: applied[0].address,
                overlays: change.new.overlays,
                frame_before: running.frame_before,
                frame_after: running.frame_after,
            };
            e.status.scanout = Some(report);
            let current = owners()?;
            let rebound = self.scanout_bound_with(
                e,
                deadlines,
                crystal_khz,
                current,
                WatermarkUpdate::Raise,
            )?;
            if rebound.fetches() != change.new.fetches() {
                return Err(Error::Invalid);
            }
            e.global_sync_writes(new_timing, true)?;
            e.live_fetch(pipe, applied[0].address)?;
            if let Some((c, segments)) = &change.cursor {
                e.verify_cursor(*c, segments)?;
            }
            Ok(report)
        }
        .await;
        match result {
            Ok(scanout) => {
                // Nothing fetches the superseded buffers: every plane's HUBP
                // reports its new surface in use, the freed ones are blank
                // and drained. Drain CPU writes before reuse.
                let mut released = 0;
                if !superseded.is_empty() {
                    if let Err(err) = e.flush_surface_writes() {
                        self.1.append(&mut superseded);
                        e.status.state = State::Failed(err);
                        return Err(err);
                    }
                    for s in superseded {
                        // SAFETY: the hardware proof above; the caller
                        // withdrew every CPU view of these buffers and
                        // excludes other engines from them.
                        released += unsafe { s.release() };
                    }
                }
                e.status.state = State::ScanoutRunning(pipe);
                // Boxed: a plan is large and callers' frames are small.
                Ok(alloc::boxed::Box::new(PlanesUpdated {
                    update,
                    enabled,
                    disabled,
                    kept: used & old_mask,
                    scanout,
                    released,
                }))
            }
            Err(err) => {
                // Retain everything the hardware may still fetch.
                self.1.append(&mut superseded);
                self.1.append(&mut fresh);
                e.status.state = State::Failed(err);
                Err(err)
            }
        }
    }
}

impl Otg {
    /// Move display `pipe`'s live scanout to the planes `request` under
    /// `plan` without relighting it (`Surfaces::update_live_planes`): every
    /// further pipe of the new planes (the primary's MPC slices, every
    /// overlay pipe) must already run on a DPP-only clock covering its
    /// plane's DPPCLK, from global clocks covering the plan's DPPREFCLK.
    /// # Safety
    /// As for `prepare_deadlines`; the scanout stays live. Withdraw every
    /// CPU view of a surface the update replaces (the console's of the
    /// primary) and exclude other engines from them: they are released
    /// once the update latched.
    #[allow(clippy::too_many_arguments)]
    pub async unsafe fn update_live_planes(
        &mut self,
        pool: &Pool,
        clocks: &mut clocks::ClockManager,
        dccg: &mut dccg::Dccg,
        gmc: &mut Gmc,
        pipe: u8,
        request: &LivePlanes,
        plan: &dml::Plan,
        crystal_khz: u32,
        content: &mut dyn PlaneContent,
    ) -> Result<alloc::boxed::Box<PlanesUpdated>, Error> {
        self.0.select_display(pipe)?;
        let regs = self.0.io.0;
        let held = self.all_held();
        let planes =
            core::iter::once(request.primary).chain(request.overlays.iter().flatten().copied());
        for (k, s) in planes.enumerate() {
            let want = plan.plane(k).ok_or(Error::Invalid)?.dppclk_khz;
            // The primary's pipe and ODM pipes run on the timing's clocks.
            let further: Vec<u8> = if k == 0 {
                s.mpc.iter().collect()
            } else {
                s.segments().map(|(q, _, _)| q).collect()
            };
            for q in further {
                let c = dccg
                    .segment_clock(regs, clocks, q, &held)
                    .map_err(Error::PipeClocks)?;
                if c.request.dpp_khz < want || c.global.dpp_khz < plan.clocks.dpprefclk_khz {
                    return Err(Error::Invalid);
                }
            }
        }
        self.1
            .update_live_planes(
                &mut self.0,
                pool,
                pipe,
                request,
                plan,
                crystal_khz,
                content,
                || {
                    Ok((
                        dccg.retained_timing_clock(regs, clocks, pipe)
                            .map_err(Error::PipeClocks)?,
                        gmc.display_context(regs).map_err(Error::Memory)?,
                    ))
                },
            )
            .await
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn401_plane_update_tests.rs"]
mod tests;
