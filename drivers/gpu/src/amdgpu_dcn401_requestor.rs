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
/// dcn401_program_compbuf_segments' DET waits before a compbuf grow:
/// REG_WAIT(DET{n}_SIZE_CURRENT, 1, 100), 100 polls 1 us apart.
const DET_GROW_WAIT_US: u64 = 100;

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
    /// Per-HUBP DET for each overlay, in the same order as `overlays`.
    pub overlay_det_bytes: [u32; MAX_OVERLAYS],
    pub compbuf_bytes: u32,
    pub pixel_chunk_bytes: u32,
    pub minimum_chunk_bytes: u32,
}
impl RequestorApplied {
    pub(super) fn with_plan(mut self, plan: &dml::Plan) -> Result<Self, Error> {
        self.det_bytes = plan.plane(0).ok_or(Error::Invalid)?.det_bytes;
        for (k, d) in self.overlay_det_bytes.iter_mut().enumerate() {
            *d = if self.overlays[k].is_some() {
                plan.plane(k + 1).ok_or(Error::Invalid)?.det_bytes
            } else {
                0
            };
        }
        Ok(self)
    }
    pub(super) fn plane_det(self, plane: usize) -> u32 {
        if plane == 0 {
            self.det_bytes
        } else {
            self.overlay_det_bytes.get(plane - 1).copied().unwrap_or(0)
        }
    }
}
/// dcn401_program_det_segments/compbuf_segments for the HUBP instances in
/// `det` (DCHUBBUB_DET{hubp->inst}_CTRL, so a pipe mask goes through
/// `PipePool::hw_mask`): each the default DET, the rest of the CRB
/// compressed buffer (with four pipes, DML's one-segment minimum).
fn allocation(det: u8) -> [u8; 5] {
    let mut sizes = [SEGMENTS, 0, 0, 0, 0];
    for i in (0..4).filter(|i| det & 1 << i != 0) {
        sizes[i + 1] = DET_SEGMENTS;
        sizes[0] -= DET_SEGMENTS;
    }
    sizes
}
/// One HUBP's requestor, its VTG the timing's own OTG instance `vtg`
/// (HUBP_VTG_SEL = tg->inst; an ODM pipe's or overlay's HUBP follows the
/// stream's timing).
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
    /// DCHUBBUB_COMPBUF_CTRL (0), then DET0-3_CTRL by HUBP instance.
    fn crb(self, index: usize) -> u64 {
        self.base + (0x4ba + index as u64) * 4
    }
}
impl<I: Io> Engine<I> {
    /// Prepare bandwidth's compbuf reduction, before any DET can grow.
    /// DET changes themselves are latched under the stream's OTG lock.
    pub(in crate::amdgpu_dcn401_otg) async fn prepare_det_space(
        &mut self,
        target: [u8; 5],
    ) -> Result<(), Error> {
        let (mut requested, _) = self.crb_live()?;
        if requested[0] > target[0] {
            // The compbuf is not double-buffered with this stream. Finish
            // its own preceding grow, then acknowledge the reduction before
            // any DET can use the released capacity. Other known idle DET
            // retirements need not finish for this reduction to be safe.
            let at = self.layout.crb(0);
            self.wait(at, 0x1f00, u32::from(requested[0]) << 8, 100_000)
                .await?;
            self.update(at, 0x1f, u32::from(target[0]))?;
            self.wait(at, 0x1f00, u32::from(target[0]) << 8, 100_000)
                .await?;
            self.displays.compbuf_inflight = None;
            requested[0] = target[0];
        }
        let l = self.layout;
        let siblings = l.pool.hw_mask(self.displays.siblings.det);
        let mut selected = l.pool.hw_mask(self.staged_planes());
        for p in l.pool.pipes() {
            let i = usize::from(l.inst(p)) + 1;
            if target[i] != 0 && siblings & bit(l.inst(p)) == 0 {
                selected |= bit(l.inst(p));
            }
        }
        // Unclaimed idle allocations do not latch with the selected OTG.
        // Request their release now, recording ownership of each zero write.
        for p in l.pool.pipes() {
            let inst = l.inst(p);
            let i = usize::from(inst) + 1;
            if (selected | siblings) & bit(inst) == 0 && requested[i] != 0 {
                if target[i] != 0 {
                    return Err(Error::Invalid);
                }
                self.program_det_segments(p, 0)?;
            }
        }
        // Same-OTG changes latch together, so reserve the larger of its old
        // and new totals. All other allocations count their actual CURRENT;
        // a zero request alone never funds a different stream's growth.
        let required = |requested: [u8; 5], current: [u8; 5]| {
            let mut held = u32::from(requested[0].max(current[0]));
            let (mut old, mut new) = (0, 0);
            for i in 1..5 {
                if selected & bit((i - 1) as u8) != 0 {
                    old += u32::from(current[i]);
                    new += u32::from(target[i]);
                } else {
                    held += u32::from(requested[i].max(current[i]));
                }
            }
            held + old.max(new)
        };
        for p in l.pool.pipes() {
            let (requested, current) = self.crb_live()?;
            if required(requested, current) <= u32::from(SEGMENTS) {
                return Ok(());
            }
            let inst = l.inst(p);
            if (selected | siblings) & bit(inst) == 0 && current[usize::from(inst) + 1] != 0 {
                self.wait(l.crb(usize::from(inst) + 1), 0x1f00, 0, 100_000)
                    .await?;
            }
        }
        let (requested, current) = self.crb_live()?;
        if required(requested, current) > u32::from(SEGMENTS) {
            return Err(Error::Unsupported);
        }
        Ok(())
    }
    /// After VUPDATE, every active DET must acknowledge its admitted size
    /// before the new plan can become a reusable owner. Idle retirements
    /// remain owned and may defer only the optional compbuf grow.
    pub(in crate::amdgpu_dcn401_otg) async fn settle_active_dets(
        &mut self,
        target: [u8; 5],
    ) -> Result<(), Error> {
        for (i, &want) in target
            .iter()
            .enumerate()
            .skip(1)
            .filter(|(_, want)| **want != 0)
        {
            let at = self.layout.crb(i);
            if self.read(at)? & 0x1f != u32::from(want) {
                return Err(Error::Busy);
            }
            self.wait(at, 0x1f00, u32::from(want) << 8, 100_000).await?;
        }
        let (requested, _) = self.crb_live()?;
        if (1..5).any(|i| target[i] != 0 && requested[i] != target[i]) {
            return Err(Error::Busy);
        }
        Ok(())
    }
    /// The plan may rely on compressed storage for unbounded requesting.
    /// A requested floor or a stale software report is not actual capacity.
    pub(in crate::amdgpu_dcn401_otg) fn verify_compbuf_minimum(
        &mut self,
        segments: u32,
    ) -> Result<(), Error> {
        if segments == 0 || segments > u32::from(SEGMENTS) {
            return Err(Error::Invalid);
        }
        let value = self.read(self.layout.crb(0))?;
        if value & 0x80090000 != 0 || value & 0x1f < segments || (value >> 8) & 0x1f < segments {
            return Err(Error::Busy);
        }
        Ok(())
    }
    pub(in crate::amdgpu_dcn401_otg) async fn settle_compbuf_minimum(
        &mut self,
        segments: u32,
    ) -> Result<(), Error> {
        let at = self.layout.crb(0);
        let value = self.read(at)?;
        let requested = value & 0x1f;
        if requested < segments {
            return Err(Error::Busy);
        }
        if (value >> 8) & 0x1f < segments {
            self.wait(at, 0x1f00, requested << 8, 100_000).await?;
        }
        self.verify_compbuf_minimum(segments)
    }
    /// A live owner may retain only its own pending idle zero requests and
    /// a safe compbuf grow. Cold allocation adoption remains crb_stable.
    /// Conservatively count both requested and CURRENT storage so a pending
    /// release can never hide overlap with an active allocation.
    pub(in crate::amdgpu_dcn401_otg) fn crb_live(&mut self) -> Result<([u8; 5], [u8; 5]), Error> {
        let mut requested = [0; 5];
        let mut current = [0; 5];
        for i in 0..5 {
            let value = self.read(self.layout.crb(i))?;
            if i == 0 && value & 0x80090000 != 0 {
                return Err(Error::Busy);
            }
            requested[i] = (value & 0x1f) as u8;
            current[i] = ((value >> 8) & 0x1f) as u8;
            if requested[i] != current[i] {
                let owned = if i == 0 {
                    self.displays.compbuf_inflight == Some(requested[i])
                        && requested[i] > current[i]
                } else {
                    self.displays.retiring_dets & bit((i - 1) as u8) != 0 && requested[i] == 0
                };
                if !owned {
                    return Err(Error::Busy);
                }
            }
        }
        if (0..5)
            .map(|i| u32::from(requested[i].max(current[i])))
            .sum::<u32>()
            > u32::from(SEGMENTS)
        {
            return Err(Error::Invalid);
        }
        for i in 1..5 {
            if requested[i] == current[i] {
                self.displays.retiring_dets &= !bit((i - 1) as u8);
            }
        }
        if requested[0] == current[0] {
            self.displays.compbuf_inflight = None;
        }
        Ok((requested, current))
    }
    /// Program each changed DET, reductions first. Hardware applies these
    /// with the locked frontend update; CURRENT is checked after it latches.
    pub(in crate::amdgpu_dcn401_otg) fn program_dets(
        &mut self,
        target: [u8; 5],
    ) -> Result<(), Error> {
        let l = self.layout;
        let mut current = [0u8; 5];
        for (i, v) in current.iter_mut().enumerate().skip(1) {
            *v = (self.read(l.crb(i))? & 0x1f) as u8;
        }
        for grow in [false, true] {
            for p in l.pool.pipes() {
                let i = usize::from(l.inst(p)) + 1;
                if target[i] != current[i] && (target[i] > current[i]) == grow {
                    self.program_det_segments(p, target[i])?;
                }
            }
        }
        Ok(())
    }
    /// Preserve the other displays' retained allocations. DET indices are
    /// physical HUBP instances; surfaces and display slots use pool indices.
    pub(super) fn requestor_allocation(&self, a: RequestorApplied) -> Result<[u8; 5], Error> {
        let mut sizes = allocation(self.layout.pool.hw_mask(self.displays.siblings.det));
        let mut assign = |r: RequestorApplied| -> Result<(), Error> {
            for (k, s) in core::iter::once(r.surface)
                .chain(r.overlays.into_iter().flatten())
                .enumerate()
            {
                let bytes = r.plane_det(k);
                if bytes < 2 * SEGMENT_BYTES
                    || bytes % SEGMENT_BYTES != 0
                    || bytes / SEGMENT_BYTES > 20
                {
                    return Err(Error::Invalid);
                }
                for (p, _, _) in s.request.segments() {
                    sizes[usize::from(self.layout.inst(p)) + 1] = (bytes / SEGMENT_BYTES) as u8;
                }
            }
            Ok(())
        };
        for (k, st) in self.displays.parked.iter().enumerate() {
            if k != usize::from(self.displays.selected) {
                if let Some(r) = st.requestor {
                    assign(r)?;
                }
            }
        }
        assign(a)?;
        let det: u32 = sizes[1..].iter().map(|&v| u32::from(v)).sum();
        sizes[0] = u32::from(SEGMENTS)
            .checked_sub(det)
            .filter(|&v| v > 0)
            .ok_or(Error::Unsupported)? as u8;
        Ok(sizes)
    }
    pub(in crate::amdgpu_dcn401_otg) fn crb_stable(&mut self) -> Result<[u8; 5], Error> {
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
    /// dcn401_program_det_segments: request `segments` of DET for pipe
    /// `q`'s HUBP (DET{n} is HUBP instance n's). It takes effect when the
    /// hardware acknowledges it (DET_SIZE_CURRENT), which this does not
    /// wait for: Linux writes a freed pipe's 0 under the OTG lock, before
    /// its MPCC leaves the tree.
    pub(in crate::amdgpu_dcn401_otg) fn program_det_segments(
        &mut self,
        q: u8,
        segments: u8,
    ) -> Result<(), Error> {
        let l = self.layout;
        if q >= l.pool.count() || segments > SEGMENTS {
            return Err(Error::Invalid);
        }
        self.update(l.crb(usize::from(l.inst(q)) + 1), 0x1f, u32::from(segments))?;
        if segments == 0 {
            self.displays.retiring_dets |= bit(l.inst(q));
        } else {
            self.displays.retiring_dets &= !bit(l.inst(q));
        }
        Ok(())
    }
    /// dcn401_program_compbuf_segments(safe_to_increase = true), as
    /// optimize_bandwidth runs it: the compressed buffer grows to the rest
    /// of the CRB (DML's compbuf_size: CRB minus every requested DET). A
    /// compbuf already that size or larger is left (only increases here),
    /// with no wait, as Linux, whose DET waits run only for a grow.
    /// Before a grow every DET's DET_SIZE_CURRENT must equal its request,
    /// each wait bounded as Linux's REG_WAIT(DET{n}_SIZE_CURRENT, 1, 100).
    /// Returns the allocation.
    ///
    /// A slow acknowledgement is not an error: Linux's REG_WAIT only logs
    /// "REG_WAIT timeout". After a DET wait times out the grow is deferred:
    /// Linux writes COMPBUF_SIZE anyway, an overlap its own ASSERT calls an
    /// erroneous configuration, so NARF never grows the compbuf into
    /// segments a DET may still hold. The grow stays pending
    /// (`compbuf_pending`) and `retry_compbuf` tries it again on the next
    /// optimize pass. A grown compbuf whose COMPBUF_SIZE_CURRENT is slow is
    /// logged and kept, as Linux, which does not wait for it at all.
    pub(in crate::amdgpu_dcn401_otg) async fn increase_compbuf(
        &mut self,
    ) -> Result<[u8; 5], Error> {
        let mut requested = [0; 5];
        for (index, size) in requested.iter_mut().enumerate() {
            *size = (self.read(self.layout.crb(index))? & 0x1f) as u8;
        }
        let dets: u32 = requested[1..].iter().map(|&n| u32::from(n)).sum();
        let target = u32::from(SEGMENTS)
            .checked_sub(dets)
            .ok_or(Error::Invalid)? as u8;
        if target <= requested[0] {
            self.displays.compbuf_pending = false;
            return Ok(requested);
        }
        let mut acked = true;
        for (index, &segments) in requested.iter().enumerate().skip(1) {
            let at = self.layout.crb(index);
            if !self
                .slow_ack(at, u32::from(segments), DET_GROW_WAIT_US)
                .await?
            {
                acked = false;
            }
        }
        if !acked {
            self.displays.compbuf_pending = true;
            return Ok(requested);
        }
        // A preceding optional grow may still be applying. Keep ownership
        // of it and retry the additional growth once CURRENT catches up;
        // strict cold-adoption checks must not turn our own slow grow fatal.
        let compbuf = self.read(self.layout.crb(0))?;
        if self.displays.compbuf_inflight == Some(requested[0])
            && compbuf & 0x1f == u32::from(requested[0])
            && (compbuf >> 8) & 0x1f < u32::from(requested[0])
        {
            self.displays.compbuf_pending = true;
            return Ok(requested);
        }
        let mut sizes = self.crb_stable()?;
        if sizes[1..] != requested[1..] {
            self.displays.compbuf_pending = true;
            return Ok(requested);
        }
        let at = self.layout.crb(0);
        self.update(at, 0x1f, u32::from(target))?;
        self.displays.compbuf_inflight = Some(target);
        self.slow_ack(at, u32::from(target), 100_000).await?;
        sizes[0] = target;
        self.displays.compbuf_pending = false;
        Ok(sizes)
    }
    /// The compbuf grow a slow DET acknowledgement deferred, tried again
    /// (`increase_compbuf`): Linux's next optimize_bandwidth programs the
    /// compbuf again. On a grow every display's requestor record carries
    /// the new size. `None` when no grow was pending.
    pub(in crate::amdgpu_dcn401_otg) async fn retry_compbuf(
        &mut self,
    ) -> Result<Option<[u8; 5]>, Error> {
        if !self.displays.compbuf_pending {
            return Ok(None);
        }
        let crb = self.increase_compbuf().await?;
        if !self.displays.compbuf_pending {
            let bytes = u32::from(crb[0]) * SEGMENT_BYTES;
            let selected = &mut *self.status;
            for st in core::iter::once(selected).chain(self.displays.parked.iter_mut()) {
                if let Some(r) = st.requestor.as_mut() {
                    r.compbuf_bytes = bytes;
                }
            }
        }
        Ok(Some(crb))
    }
    /// Wait for a CRB register's CURRENT field (bits 12:8) to reach `want`
    /// for up to `us`; `false` after logging a timeout, as generic_reg_wait
    /// does.
    async fn slow_ack(&mut self, at: u64, want: u32, us: u64) -> Result<bool, Error> {
        match self.wait(at, 0x1f00, want << 8, us).await {
            Ok(()) => Ok(true),
            Err(Error::Timeout(_)) => {
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: dcn401 REG_WAIT timeout: CRB {at:#x} CURRENT != {want}"
                );
                Ok(false)
            }
            Err(e) => Err(e),
        }
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
        self.verify_requestor_with(pipe, 0, false)
    }
    /// The requestor of a pipe whose fetch may be live: an underflow there
    /// is the scanout's to detect and recover (back to black), so its
    /// status bits must not make the owners look foreign. Without this an
    /// underflowed live scanout could be neither checked nor stopped.
    pub(super) fn verify_live_requestor(&mut self, pipe: u8) -> Result<(), Error> {
        self.verify_requestor_with(pipe, HUBP_UNDERFLOW_STATUS, true)
    }
    fn verify_requestor_with(&mut self, pipe: u8, tolerated: u32, live: bool) -> Result<(), Error> {
        // This pipe's and every other display's DET must stand. A display
        // that left while this one ran keeps its (unused) allocation until
        // the next configuration repartitions, and compbuf is unused.
        let sizes = if live {
            self.crb_live()?.0
        } else {
            self.crb_stable()?
        };
        let a = self
            .status
            .requestor
            .filter(|r| r.pipe == pipe)
            .ok_or(Error::Invalid)?;
        let want = self.requestor_allocation(a)?;
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
            for (r, mut mask, value) in requestor(self.layout.inst(pipe)) {
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
        self.prepare_requestor_planes(e, pipe, &[], None, owners)
            .await
    }
    pub(in crate::amdgpu_dcn401_otg) async fn prepare_requestor_planes<I: Io>(
        &mut self,
        e: &mut Engine<I>,
        pipe: u8,
        overlays: &[u8],
        plan: Option<&dml::Plan>,
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
        let surface = a.dpp.surface;
        let mut dets = [0; MAX_OVERLAYS + 1];
        for (k, d) in dets.iter_mut().enumerate().take(overlays.len() + 1) {
            *d = match plan {
                Some(p) => p.plane(k).ok_or(Error::Invalid)?.det_bytes,
                None => u32::from(DET_SEGMENTS) * SEGMENT_BYTES,
            };
        }
        let mut report = RequestorApplied {
            pipe,
            surface,
            overlays: stack.map(|m| m.map(|m| m.dpp.surface)),
            det_bytes: dets[0],
            overlay_det_bytes: [dets[1], dets[2], dets[3]],
            compbuf_bytes: 0,
            pixel_chunk_bytes: 8192,
            minimum_chunk_bytes: 1024,
        };
        let target = e.requestor_allocation(report)?;
        report.compbuf_bytes = u32::from(target[0]) * SEGMENT_BYTES;
        // Linear RGB stores one row per swath; leave room for at least two.
        let surfaces =
            core::iter::once(surface).chain(stack.iter().flatten().map(|m| m.dpp.surface));
        if plan.is_none()
            && surfaces
                .clone()
                .enumerate()
                .any(|(k, s)| u64::from(s.pitch_bytes) * 2 > u64::from(dets[k]))
        {
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
                for (r, mask, value) in requestor(e.layout.inst(pipe)) {
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
    /// Whether a compbuf grow a slow DET acknowledgement deferred is still
    /// pending (`retry_compbuf`).
    pub fn compbuf_pending(&self) -> bool {
        self.0.displays.compbuf_pending
    }
    /// The next optimize pass's dcn401_program_compbuf_segments for a grow
    /// a slow DET acknowledgement deferred: once every DET acknowledged its
    /// request the compbuf takes the rest of the CRB. `None` with nothing
    /// pending; the allocation otherwise (the grow still pending while a
    /// DET is slow).
    /// # Safety
    /// As for `prepare_requestor`, between display operations.
    pub async unsafe fn retry_compbuf(&mut self) -> Result<Option<[u8; 5]>, Error> {
        self.0.retry_compbuf().await
    }
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
        unsafe { self.prepare_requestor_planes(clocks, dccg, gmc, pipe, &[], None) }.await
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
        plan: Option<&dml::Plan>,
    ) -> Result<RequestorApplied, Error> {
        let regs = self.0.io.0;
        let (held, layout) = self.0.held();
        self.1
            .prepare_requestor_planes(&mut self.0, pipe, overlays, plan, || {
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
