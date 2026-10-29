//! Reclaim display-only reservations after CPU withdrawal and fresh hardware
//! retirement checks. This never releases inherited or other-engine memory.
use super::*;

impl<I: Io> Engine<I> {
    fn surface_release_preflight(&mut self, pipe: u8) -> Result<(), Error> {
        if pipe >= self.layout.pool.count() {
            return Err(Error::Invalid);
        }
        if self.status.state != State::PlanesRetired
            || self
                .status
                .planes_retired
                .is_none_or(|p| (p.blanked | p.powered_off) & (1 << pipe) == 0)
        {
            return Err(Error::Busy);
        }
        self.preflight(pipe, false)?;
        // Unlike restaging retained buffers, reclamation cannot tolerate even
        // this pipe's pending flip. Verify detached routes, drained MPCCs,
        // timing/locks, cursor/metadata/LUT inactivity and every power state.
        // Live siblings must still fetch their own recorded addresses.
        self.hubp_power_tree_stopped()?;
        if self.read(self.layout.nbio + 0x12d * 4)? != 0x7f000 {
            return Err(Error::Busy);
        }
        // CUR_VUPDATE_LOCK_SET of the pipe's OPP instance (mpc1_cursor_lock).
        let lock = self.layout.mpc_base + (0x2c5 + u64::from(self.layout.inst(pipe)) * 5) * 4;
        if self.read(lock)? & 1 != 0 {
            return Err(Error::Busy);
        }
        if self.hubp_powered(pipe)?
            && self.read(self.layout.hubp(pipe, HUBP_CONTROL))? & 0x1007 != 3
        {
            return Err(Error::Busy);
        }
        Ok(())
    }

    fn forget_surface(&mut self, pipe: u8) {
        let k = usize::from(pipe);
        let s = &mut self.status;
        s.surfaces[k] = None;
        s.memory[k] = None;
        s.dpps[k] = None;
        s.mpcs[k] = None;
        s.pipes[k] = None;
        s.blanks[k] = None;
        if s.requestor.is_some_and(|r| r.pipe == pipe) {
            s.requestor = None;
        }
        if s.deadlines.is_some_and(|d| d.pipe == pipe) {
            s.deadlines = None;
        }
        if s.scanout.is_some_and(|r| r.pipe == pipe) {
            s.scanout = None;
        }
        if s.cursor.is_some_and(|c| c.pipe == pipe) {
            s.cursor = None;
        }
        if s.running_blank
            .is_some_and(|b| b.blank.timing.request.pipe == pipe)
        {
            s.running_blank = None;
        }
    }
}

impl Surface {
    /// Caller has proved CPU, display and other-engine access is excluded.
    pub(super) unsafe fn release(mut self) -> u64 {
        let mut bytes = 0;
        for memory in core::iter::once(&mut self.memory)
            .chain(self.back.iter_mut())
            .chain(self.cursor.iter_mut())
        {
            bytes += memory.size();
            // SAFETY: the caller proved complete retirement of these owned
            // allocations, including the CPU and non-display exclusions.
            unsafe { memory.stopped() };
        }
        // Drop returns every reservation to its own pool. No allocation,
        // hardware operation or await remains after the proof was accepted.
        bytes
    }
}

impl Surfaces {
    pub(in crate::amdgpu_dcn401_otg) unsafe fn release<I: Io>(
        &mut self,
        engine: &mut Engine<I>,
        pipe: u8,
    ) -> Result<u64, Error> {
        crate::amdgpu_dcn401_otg::surfaces_changed();
        // Every pipe that fetched these surfaces: ODM segments and MPC
        // slices too.
        let odm = self
            .0
            .get(usize::from(pipe))
            .into_iter()
            .flatten()
            .chain(self.1.iter().filter(|s| s.applied.request.pipe == pipe))
            .fold(0u8, |m, s| {
                m | s.applied.request.odm.mask() | s.applied.request.mpc.mask()
            });
        let preflight = |engine: &mut Engine<I>| {
            engine.surface_release_preflight(pipe)?;
            for q in engine.layout.pool.pipes().filter(|&q| odm & bit(q) != 0) {
                engine.surface_release_preflight(q)?;
            }
            Ok(())
        };
        preflight(engine)?;
        // CPU leases drain WC stores on their originating CPUs. HDP/PCIe
        // writes must also finish before another engine can reuse this VRAM.
        let proof = engine
            .flush_surface_writes()
            .and_then(|()| preflight(engine));
        if let Err(e) = proof {
            engine.status.state = State::Failed(e);
            return Err(e);
        }
        engine.forget_surface(pipe);
        let mut bytes = 0;
        if let Some(surface) = self.0[usize::from(pipe)].take() {
            // SAFETY: fresh hardware proof above; caller excludes all CPU
            // and other-engine references for the entire synchronous release.
            bytes += unsafe { surface.release() };
        }
        let mut k = 0;
        while k < self.1.len() {
            if self.1[k].applied.request.pipe == pipe {
                // SAFETY: same pipe's previously parked, still-owned buffers.
                bytes += unsafe { self.1.swap_remove(k).release() };
            } else {
                k += 1;
            }
        }
        Ok(bytes)
    }
}

impl Otg {
    /// Release this pipe's current and parked front/back/cursor reservations.
    /// Requires PlanesRetired and fresh idle/route/power/transaction evidence,
    /// then HDP/PCIe drain and a second check. Returns page-rounded bytes freed.
    /// Other displays' reservations are untouched.
    ///
    /// # Safety
    /// Unpublish the CPU scanout and finish its writer-quiescence barrier
    /// before calling. Exclude firmware/FAMS, raw CPU views, GPUVM/writeback and
    /// every other engine from these display-only allocations, and retain that
    /// exclusion throughout this call. Keep exclusive display/PM/reset ownership.
    /// Errors retain every reservation; a historical retirement report alone
    /// never authorizes release. No async cancellation point follows the proof.
    pub unsafe fn release_surfaces(&mut self, pipe: u8) -> Result<u64, Error> {
        // SAFETY: caller supplies CPU and non-display lifetime exclusions.
        unsafe { self.1.release(&mut self.0, pipe) }
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn401_surface_release_tests.rs"]
mod tests;
