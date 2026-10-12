//! Native DCN401 double-buffered page flip of a live single-pipe scanout.
//! Linux: hubp401_program_surface_flip_and_addr (VSYNC flip type; the low
//! address write publishes the high half) inside the pipe-control lock, and
//! completion as dcn401_post_unlock_program_front_end and amdgpu_dm's pflip
//! handling observe it: no flip pending and EARLIEST_INUSE at the new address.
use super::*;
use crate::amdgpu_gmc_navi48::{DisplayContext, Gmc};
use narf_graphics_driver::generic::GenericFb;
use scanout::Pipe;

/// A completed flip. The previous front is now the back buffer and may be
/// rewritten: the HUBP reported the new address in use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlipDone {
    pub pipe: u8,
    pub front: u64,
    pub back: u64,
    /// Frame count sampled after the new address latched.
    pub frame: u32,
}

impl<I: Io> Engine<I> {
    /// Every retained report names the surface by value; after a flip the
    /// front address changes in all of them together.
    fn retarget(&mut self, pipe: u8, from: SurfaceApplied, address: u64) -> Result<(), Error> {
        let slot = usize::from(pipe);
        let to = SurfaceApplied { address, ..from };
        let s = &mut self.status;
        let (Some(dpp), Some(mpc), Some(requestor), Some(scanout)) =
            (s.dpps[slot], s.mpcs[slot], s.requestor, s.scanout)
        else {
            return Err(Error::Invalid);
        };
        if s.surfaces[slot] != Some(from)
            || dpp.surface != from
            || mpc.dpp.surface != from
            || requestor.surface != from
            || scanout.address != from.address
        {
            return Err(Error::Invalid);
        }
        s.surfaces[slot] = Some(to);
        s.dpps[slot] = Some(DppApplied { surface: to, ..dpp });
        s.mpcs[slot] = Some(MpcApplied {
            dpp: DppApplied {
                surface: to,
                ..mpc.dpp
            },
            ..mpc
        });
        s.requestor = Some(RequestorApplied {
            surface: to,
            ..requestor
        });
        s.scanout = Some(ScanoutRunning { address, ..scanout });
        Ok(())
    }
}

impl Surfaces {
    /// Allocate, clear and publish a second buffer with the front's geometry.
    /// Allowed while staged or while the pipe scans out: it touches no
    /// display register, only owned VRAM and the HDP flush.
    pub(in crate::amdgpu_dcn401_otg) async fn prepare_back<I: Io>(
        &mut self,
        e: &mut Engine<I>,
        pool: &Pool,
        pipe: u8,
        config: DisplayContext,
    ) -> Result<u64, Error> {
        let slot = usize::from(pipe);
        let live = e.status.state == State::ScanoutRunning(pipe);
        if !(live || e.status.state.reusable()) {
            return Err(Error::Busy);
        }
        let surface = self
            .0
            .get_mut(slot)
            .and_then(Option::as_mut)
            .ok_or(Error::Invalid)?;
        if surface.back.is_some() || e.status.surfaces[slot] != Some(surface.applied) {
            return Err(Error::Busy);
        }
        let memory = pool
            .reserve(surface.applied.bytes)
            .map_err(|_| Error::Allocation)?;
        // As for the front: the whole allocation must translate through FB.
        if memory.address() < config.fb_base
            || memory
                .address()
                .checked_add(memory.size() - 1)
                .is_none_or(|last| last > config.fb_top || last >= 1 << 48)
        {
            return Err(Error::Invalid);
        }
        let mut memory = memory;
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
        e.flush_surface_writes()?;
        memory.publish();
        let address = memory.address();
        // Retained even if the state moved meanwhile: never freed once owned.
        let surface = self.0[slot].as_mut().ok_or(Error::Invalid)?;
        surface.back = Some(memory);
        if live && e.status.state != State::ScanoutRunning(pipe) {
            return Err(Error::Busy);
        }
        Ok(address)
    }
    /// CPU view of the back buffer, for drawing the next frame.
    pub(in crate::amdgpu_dcn401_otg) fn back_framebuffer(
        &self,
        pipe: u8,
    ) -> Result<GenericFb, Error> {
        let surface = self
            .0
            .get(usize::from(pipe))
            .and_then(Option::as_ref)
            .ok_or(Error::Invalid)?;
        let back = surface.back.as_ref().ok_or(Error::Invalid)?;
        let a = surface.applied;
        Ok(GenericFb::new(
            back.mapping().phys.raw(),
            a.request.width,
            a.request.height,
            a.pitch_bytes,
            32,
        ))
    }
    /// Present the back buffer at the next VUPDATE and wait for the HUBP to
    /// report it in use. Any failure quarantines the pipe; both buffers stay
    /// allocated because which one is still fetched is then unknown.
    pub(in crate::amdgpu_dcn401_otg) async fn flip<I: Io>(
        &mut self,
        e: &mut Engine<I>,
        pipe: u8,
        crystal_khz: u32,
        mut owners: impl FnMut() -> Result<(dccg::Applied, DisplayContext), Error>,
    ) -> Result<FlipDone, Error> {
        let slot = usize::from(pipe);
        let running = e.status.scanout.ok_or(Error::Invalid)?;
        if e.status.state != State::ScanoutRunning(pipe) || running.pipe != pipe {
            return Err(Error::Busy);
        }
        let deadlines = e.status.deadlines.ok_or(Error::Invalid)?;
        let back = self
            .0
            .get(slot)
            .and_then(Option::as_ref)
            .and_then(|s| s.back.as_ref())
            .map(Reservation::address)
            .ok_or(Error::Invalid)?;
        let current = owners()?;
        let p = self.scanout_bound(e, deadlines, crystal_khz, current)?;
        if p.address != running.address {
            return Err(Error::Invalid);
        }
        e.live_fetch(pipe, p.address)?;
        e.flip_quiet(pipe)?;
        // The producer's CPU writes to the back buffer must be in VRAM first.
        e.flush_surface_writes()?;
        e.status.state = State::Flipping(pipe);
        let result = async {
            let frame = e.flip_to(Pipe { address: back, ..p }).await?;
            if owners()? != current {
                return Err(Error::Busy);
            }
            let surface = self.0[slot].as_mut().ok_or(Error::Invalid)?;
            let from = surface.applied;
            e.retarget(pipe, from, back)?;
            let front = surface.back.take().ok_or(Error::Invalid)?;
            surface.back = Some(core::mem::replace(&mut surface.memory, front));
            surface.applied.address = back;
            self.scanout_bound(e, deadlines, crystal_khz, current)?;
            e.live_fetch(pipe, back)?;
            Ok(FlipDone {
                pipe,
                front: back,
                back: from.address,
                frame,
            })
        }
        .await;
        match result {
            Ok(done) => {
                e.status.state = State::ScanoutRunning(pipe);
                Ok(done)
            }
            Err(err) => {
                e.status.state = State::Failed(err);
                Err(err)
            }
        }
    }
}

impl Otg {
    /// Allocate the back buffer of a staged or live pipe.
    /// # Safety
    /// Exclude firmware/FAMS and concurrent display/HDP writers; the buffer
    /// is retained by the pipe for the owner's lifetime.
    pub async unsafe fn prepare_back_buffer(
        &mut self,
        pool: &Pool,
        gmc: &mut Gmc,
        pipe: u8,
    ) -> Result<u64, Error> {
        let config = gmc.display_context(self.0.io.0).map_err(Error::Memory)?;
        self.1.prepare_back(&mut self.0, pool, pipe, config).await
    }
    /// The back buffer as a CPU framebuffer (bus-physical BAR address).
    pub fn back_framebuffer(&self, pipe: u8) -> Result<GenericFb, Error> {
        self.1.back_framebuffer(pipe)
    }
    /// Flip a live scanout to its back buffer at the next VUPDATE.
    /// # Safety
    /// The back buffer must hold the complete next frame and no CPU writer
    /// may touch it until another flip. Exclude firmware/FAMS and concurrent
    /// display/hub/VM/IRQ/clock/reset/power writers.
    pub async unsafe fn flip(
        &mut self,
        clocks: &mut clocks::ClockManager,
        dccg: &mut dccg::Dccg,
        gmc: &mut Gmc,
        pipe: u8,
        crystal_khz: u32,
    ) -> Result<FlipDone, Error> {
        let regs = self.0.io.0;
        self.1
            .flip(&mut self.0, pipe, crystal_khz, || {
                Ok((
                    dccg.retained_timing_clock(regs, clocks, pipe)
                        .map_err(Error::PipeClocks)?,
                    gmc.display_context(regs).map_err(Error::Memory)?,
                ))
            })
            .await
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn401_flip_tests.rs"]
mod tests;
