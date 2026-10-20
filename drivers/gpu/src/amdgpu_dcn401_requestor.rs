//! Native DCN401 bounded physical-RGB requestor and CRB allocation.
//! Linux: hubp401_program_requestor/set_unbounded_requesting,
//! dcn401_init_crb/program_det_segments/program_compbuf_segments and
//! DML21 CalculateVMRowAndSwath/rq_dlg_get_rq_reg (GPUVM/HostVM off).
//! This stages geometry and storage, NOT bandwidth/deadline admission.
use super::*;
use crate::amdgpu_gmc_navi48::{DisplayContext, Gmc};

/// HUBP_UNDERFLOW_STATUS (HUBP_CNTL bits 30:28).
const HUBP_UNDERFLOW_STATUS: u32 = 0x7000_0000;
pub(super) const SEGMENTS: u8 = 21; // DCN4_01_CRB_SIZE_KB / DCN4_01_CRB_SEGMENT_SIZE_KB
pub(super) const DET_SEGMENTS: u8 = 5; // DCN4_01_DEFAULT_DET_SIZE = 320 KiB
pub(super) const SEGMENT_BYTES: u32 = 65536;

/// Overlay planes one display may stack above its primary: DCN401's
/// max_slave_planes, as amdgpu_dm creates its overlay planes.
pub const MAX_OVERLAYS: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestorApplied {
    pub pipe: u8,
    pub surface: SurfaceApplied,
    /// The overlay planes stacked above the primary, bottom first, each on
    /// its own pipe(s) under the primary's timing.
    pub overlays: [Option<SurfaceApplied>; MAX_OVERLAYS],
    pub det_bytes: u32,
    pub compbuf_bytes: u32,
    pub pixel_chunk_bytes: u32,
    pub minimum_chunk_bytes: u32,
}
/// dcn401_program_det_segments/compbuf_segments for the pipes in `det`:
/// each the default DET, the rest of the CRB compressed buffer (with four
/// pipes, DML's one-segment minimum).
fn allocation(det: u8) -> [u8; 5] {
    let mut sizes = [SEGMENTS, 0, 0, 0, 0];
    for p in (0..4).filter(|p| det & 1 << p != 0) {
        sizes[p + 1] = DET_SEGMENTS;
        sizes[0] -= DET_SEGMENTS;
    }
    sizes
}
/// One HUBP's requestor, its VTG the timing's own OTG `vtg` (an ODM
/// pipe's or overlay's HUBP follows the stream's timing).
pub(super) fn requestor(vtg: u8) -> [(u64, u32, u32); 7] {
    [
        (0x66d, 0x7ff0, 0),  // packed RGB: no second plane in DET
        (0x620, 0xff, 0x56), // DRQ=2, CRQ/MRQ/PRQ=1
        // Native six-field layout. Linear 1-line swaths, 8 KiB chunks with
        // 1 KiB minimum; no page-table groups for the physical FB aperture.
        (0x5f2, 0x07701f77, 0x1b00),
        (0x5f3, 0x00701f77, 0x1b00),
        (HUBP_CONTROL, 0x4f0, u32::from(vtg) << 4), // VTG and bounded requests
        (MALL, 0x1f, 8), // no MALL surface/cursor/prefetch; native command type
        (CURSOR, 4, 4),  // DCN4 mandates early cursor requests, even when disabled
    ]
}
impl Layout {
    fn crb(self, index: usize) -> u64 {
        self.base + (0x4ba + index as u64) * 4
    }
}
impl<I: Io> Engine<I> {
    pub(super) fn crb_stable(&mut self) -> Result<[u8; 5], Error> {
        let mut sizes = [0; 5];
        for (index, size) in sizes.iter_mut().enumerate() {
            let v = self.read(self.layout.crb(index))?;
            // Do not adopt an inherited allocation transaction or its IRQ.
            // CONFIG_ERROR is not a usable buffer allocation either.
            // The read-only DONE status may be set even with its IRQ disabled;
            // preserve it. Only the separate CLEAR field acknowledges it.
            if index == 0 && v & 0x80090000 != 0 || v & 0x1f != (v >> 8) & 0x1f {
                return Err(Error::Busy);
            }
            *size = (v & 0x1f) as u8;
        }
        if sizes.iter().map(|&n| u32::from(n)).sum::<u32>() > u32::from(SEGMENTS) {
            return Err(Error::Invalid);
        }
        Ok(sizes)
    }
    pub(super) async fn resize_crb(
        &mut self,
        sizes: &mut [u8; 5],
        index: usize,
        value: u8,
    ) -> Result<(), Error> {
        if self.crb_stable()? != *sizes {
            return Err(Error::Busy);
        }
        let mut next = *sizes;
        next[index] = value;
        if next.iter().map(|&n| u32::from(n)).sum::<u32>() > u32::from(SEGMENTS) {
            return Err(Error::Invalid);
        }
        let at = self.layout.crb(index);
        self.update(at, 0x1f, u32::from(value))?;
        // Request readback is not ownership of freed segments. Never grow
        // another allocation until the hardware's CURRENT field acknowledges.
        self.wait(at, 0x1f00, u32::from(value) << 8, 100_000)
            .await?;
        if self.crb_stable()? != next {
            return Err(Error::Busy);
        }
        *sizes = next;
        Ok(())
    }
    pub(super) fn requestor_errors(&mut self, pipe: u8) -> Result<(), Error> {
        self.requestor_faults(pipe, 0)
    }
    /// Every HUBP the display whose primary is on `pipe` fetches with: the
    /// primary's (`fetch_pipes`), then each staged overlay's, bottom first.
    pub(in crate::amdgpu_dcn401_otg) fn plane_pipes(&self, pipe: u8) -> alloc::vec::Vec<u8> {
        let mut pipes: alloc::vec::Vec<u8> = self.fetch_pipes(pipe).collect();
        if let Some(r) = self.status.requestor.filter(|r| r.pipe == pipe) {
            for o in r.overlays.iter().flatten() {
                pipes.extend(o.request.segments().map(|(p, _, _)| p));
            }
        }
        pipes
    }
    /// Error/status bits of HUBP_CONTROL other than `tolerated`, on every
    /// HUBP the display's planes fetch on.
    fn requestor_faults(&mut self, pipe: u8, tolerated: u32) -> Result<(), Error> {
        for p in self.plane_pipes(pipe) {
            self.hubp_faults(p, tolerated)?;
        }
        Ok(())
    }
    /// Keep error/status acknowledgements and timeout IRQ ownership out of
    /// the setup RMWs. A pre-existing error requires explicit recovery.
    pub(super) fn hubp_faults(&mut self, p: u8, tolerated: u32) -> Result<(), Error> {
        if self.read(self.layout.hubp(p, HUBP_CONTROL))? & 0xfcf00800 & !tolerated != 0 {
            return Err(Error::Busy);
        }
        Ok(())
    }
    pub(in crate::amdgpu_dcn401_otg) fn verify_requestor(&mut self, pipe: u8) -> Result<(), Error> {
        self.verify_requestor_with(pipe, 0)
    }
    /// The requestor of a pipe whose fetch may be live: an underflow there
    /// is the scanout's to detect and recover (back to black), so its
    /// status bits must not make the owners look foreign. Without this an
    /// underflowed live scanout could be neither checked nor stopped.
    pub(super) fn verify_live_requestor(&mut self, pipe: u8) -> Result<(), Error> {
        self.verify_requestor_with(pipe, HUBP_UNDERFLOW_STATUS)
    }
    /// This display's DETs (every plane's pipes) with every other display's.
    fn det_pipes(&self, pipe: u8) -> u8 {
        self.plane_pipes(pipe)
            .into_iter()
            .fold(0, |m, p| m | bit(p))
            | self.displays.siblings.det
    }
    fn verify_requestor_with(&mut self, pipe: u8, tolerated: u32) -> Result<(), Error> {
        // This pipe's and every other display's DET must stand. A display
        // that left while this one ran keeps its (unused) allocation until
        // the next configuration repartitions, and compbuf is unused.
        let sizes = self.crb_stable()?;
        let want = allocation(self.det_pipes(pipe));
        if (1..5).any(|i| want[i] != 0 && sizes[i] != want[i]) {
            return Err(Error::Busy);
        }
        let reserved = self.layout.base + 0x4c4 * 4;
        if self.read(reserved)? & 0xfff != 256 {
            return Err(Error::Readback(reserved));
        }
        // Every plane's HUBP follows the primary's timing (its VTG).
        for p in self.plane_pipes(pipe) {
            // A tiled or 4:2:0 plane's RQ fields are its plan's
            // (deadline_writes programs and checks them).
            let planned = self.status.surfaces.iter().flatten().any(|a| {
                a.request.pipe_mask() & bit(p) != 0
                    && (a.request.format.is_video()
                        || a.request.surface.tiling != crate::amdgpu_dcn401_otg::Tiling::LINEAR)
            });
            for (r, mut mask, value) in requestor(pipe) {
                if planned {
                    if matches!(r, 0x66d | 0x620 | 0x5f2 | 0x5f3) {
                        continue;
                    }
                    if r == HUBP_CONTROL {
                        mask &= !0x400;
                    }
                }
                let at = self.layout.hubp(p, r);
                if self.read(at)? & mask != value {
                    return Err(Error::Readback(at));
                }
            }
        }
        self.requestor_faults(pipe, tolerated)
    }
}
impl Surfaces {
    /// The staged composition of each overlay pipe in `overlays` (bottom
    /// first) above the primary `a`: each its own surface on its own free
    /// pipes (none another display's, the primary's or another overlay's)
    /// under the same blanked stream, at most `MAX_OVERLAYS`.
    fn overlay_mpcs<I: Io>(
        &self,
        e: &mut Engine<I>,
        a: MpcApplied,
        overlays: &[u8],
        current: (dccg::Applied, DisplayContext),
    ) -> Result<[Option<MpcApplied>; MAX_OVERLAYS], Error> {
        if overlays.len() > MAX_OVERLAYS {
            return Err(Error::Unsupported);
        }
        let mut used = a.dpp.surface.request.pipe_mask();
        let mut out = [None; MAX_OVERLAYS];
        // Bottom first: every underlay before the overlays above the primary.
        let mut above = false;
        for (slot, &o) in out.iter_mut().zip(overlays) {
            let m = e
                .status
                .mpcs
                .get(usize::from(o))
                .copied()
                .flatten()
                .ok_or(Error::Invalid)?;
            let mask = m.dpp.surface.request.pipe_mask();
            let underlay = m.dpp.surface.request.layout().underlay;
            if m.dpp.surface.request.pipe != o
                || m.dpp.surface.request.plane.is_none()
                || m.dpp.timing != a.dpp.timing
                || mask & used != 0
                || mask & e.displays.siblings.pipes != 0
                || (underlay && above)
            {
                return Err(Error::Invalid);
            }
            above |= !underlay;
            used |= mask;
            self.verify_mpc_source(e, m, current)?;
            e.verify_mpc(m)?;
            for p in m.dpp.surface.request.segments().map(|(p, _, _)| p) {
                e.hubp_faults(p, 0)?;
            }
            *slot = Some(m);
        }
        Ok(out)
    }
    #[cfg(feature = "kernel-test")]
    pub(in crate::amdgpu_dcn401_otg) async fn prepare_requestor<I: Io>(
        &mut self,
        e: &mut Engine<I>,
        pipe: u8,
        owners: impl FnMut() -> Result<(dccg::Applied, DisplayContext), Error>,
    ) -> Result<RequestorApplied, Error> {
        self.prepare_requestor_planes(e, pipe, &[], owners).await
    }
    pub(in crate::amdgpu_dcn401_otg) async fn prepare_requestor_planes<I: Io>(
        &mut self,
        e: &mut Engine<I>,
        pipe: u8,
        overlays: &[u8],
        mut owners: impl FnMut() -> Result<(dccg::Applied, DisplayContext), Error>,
    ) -> Result<RequestorApplied, Error> {
        let a = e
            .status
            .mpcs
            .get(usize::from(pipe))
            .copied()
            .flatten()
            .ok_or(Error::Invalid)?;
        if !e.status.state.reusable() || e.status.requestor.is_some() {
            return Err(Error::Busy);
        }
        let current = owners()?;
        if a.dpp.surface.request.pipe != pipe {
            return Err(Error::Invalid);
        }
        self.verify_mpc_source(e, a, current)?;
        e.verify_mpc(a)?;
        e.requestor_errors(pipe)?;
        let stack = self.overlay_mpcs(e, a, overlays, current)?;
        let mut sizes = e.crb_stable()?;
        let det = stack.iter().flatten().fold(e.det_pipes(pipe), |m, o| {
            m | o.dpp.surface.request.pipe_mask()
        });
        let target = allocation(det);
        let surface = a.dpp.surface;
        // Linear RGB stores one row per swath; leave room for at least two.
        let surfaces =
            core::iter::once(surface).chain(stack.iter().flatten().map(|m| m.dpp.surface));
        if surfaces.clone().any(|s| {
            u64::from(s.pitch_bytes) * 2 > u64::from(DET_SEGMENTS) * u64::from(SEGMENT_BYTES)
        }) {
            return Err(Error::Unsupported);
        }
        let pipes: alloc::vec::Vec<u8> = surfaces
            .flat_map(|s| s.request.segments().map(|(p, _, _)| p))
            .collect();
        e.status.state = State::PreparingRequestor(pipe);
        let result = async {
            let recheck = |this: &Self, e: &mut Engine<I>| -> Result<(), Error> {
                this.verify_mpc_source(e, a, current)?;
                e.verify_mpc(a)?;
                this.overlay_mpcs(e, a, overlays, current)?;
                e.requestor_errors(pipe)
            };
            // Shrink every allocation before any growth. This ordering works
            // for inherited DET-heavy and compbuf-heavy layouts alike.
            for grow in [false, true] {
                for index in 0..5 {
                    if sizes[index] == target[index] || (target[index] > sizes[index]) != grow {
                        continue;
                    }
                    e.resize_crb(&mut sizes, index, target[index]).await?;
                    if owners()? != current {
                        return Err(Error::Busy);
                    }
                    recheck(self, e)?;
                }
            }
            // Native reservation is pixel_chunk_size / 32 units of 64 bytes.
            e.update(e.layout.base + 0x4c4 * 4, 0xfff, 256)?;
            for &p in &pipes {
                e.update(e.layout.hubp(p, HUBP_CLOCK), 1, 1)?;
                e.wait(e.layout.hubp(p, HUBP_CONTROL), 0x1007, 3, 100_000)
                    .await?;
                e.hubp_faults(p, 0)?;
                for (r, mask, value) in requestor(pipe) {
                    e.update(e.layout.hubp(p, r), mask, value)?;
                }
                e.update(e.layout.hubp(p, HUBP_CLOCK), 1, 0)?;
            }
            if owners()? != current {
                return Err(Error::Busy);
            }
            recheck(self, e)
        }
        .await;
        let report = RequestorApplied {
            pipe,
            surface,
            overlays: stack.map(|m| m.map(|m| m.dpp.surface)),
            det_bytes: u32::from(DET_SEGMENTS) * SEGMENT_BYTES,
            compbuf_bytes: u32::from(target[0]) * SEGMENT_BYTES,
            pixel_chunk_bytes: 8192,
            minimum_chunk_bytes: 1024,
        };
        // The overlays' requestors are verified as the display's planes.
        let result = result.and_then(|()| {
            e.status.requestor = Some(report);
            let verified = e.verify_requestor(pipe);
            if verified.is_err() {
                e.status.requestor = None;
            }
            verified
        });
        match result {
            Ok(()) => {
                e.status.state = State::RequestorPrepared;
                Ok(report)
            }
            Err(err) => {
                e.status.state = State::Failed(err);
                Err(err)
            }
        }
    }
}
impl Otg {
    /// Stage bounded physical-RGB requests and native default DET/compbuf sizes
    /// for one pipe. Deadlines and watermarks are still required before fetching.
    /// # Safety
    /// Retain every owner and inherited resource on success, error and cancellation.
    /// Exclude firmware/FAMS and concurrent display/hub/VM/IRQ/clock/reset/power writers.
    pub async unsafe fn prepare_requestor(
        &mut self,
        clocks: &mut clocks::ClockManager,
        dccg: &mut dccg::Dccg,
        gmc: &mut Gmc,
        pipe: u8,
    ) -> Result<RequestorApplied, Error> {
        // SAFETY: the caller's obligations, with no overlay.
        unsafe { self.prepare_requestor_planes(clocks, dccg, gmc, pipe, &[]) }.await
    }
    /// `prepare_requestor` for the display's primary on `pipe` and the
    /// overlay planes staged (through their MPC) on the pipes `overlays`,
    /// bottom first: every plane's HUBP gets its DET and requestor, all
    /// following the primary's timing.
    /// # Safety
    /// As for `prepare_requestor`.
    pub async unsafe fn prepare_requestor_planes(
        &mut self,
        clocks: &mut clocks::ClockManager,
        dccg: &mut dccg::Dccg,
        gmc: &mut Gmc,
        pipe: u8,
        overlays: &[u8],
    ) -> Result<RequestorApplied, Error> {
        let regs = self.0.io.0;
        let (held, layout) = self.0.held();
        self.1
            .prepare_requestor_planes(&mut self.0, pipe, overlays, || {
                Ok((
                    dccg.timing_clock_except(regs, clocks, pipe, &|at| {
                        held_by_sibling(held, layout, at)
                    })
                    .map_err(Error::PipeClocks)?,
                    gmc.display_context(regs).map_err(Error::Memory)?,
                ))
            })
            .await
    }
}
