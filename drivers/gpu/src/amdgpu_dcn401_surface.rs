//! Owned linear RGB surface staging for native DCN401. Linux references:
//! hubp401_program_surface_config, hubp401_set_viewport and
//! hubp401_program_surface_flip_and_addr. Fetch remains blank and disconnected.
use super::*;
use crate::amdgpu_vram::{Pool, Reservation};
use core::sync::atomic::{fence, Ordering};
#[path = "amdgpu_dcn401_vm.rs"]
mod vm;
pub use vm::MemoryApplied;
#[path = "amdgpu_dcn401_dpp.rs"]
mod dpp;
pub use dpp::DppApplied;
#[path = "amdgpu_dcn401_mpc.rs"]
mod mpc;
pub use mpc::MpcApplied;
#[path = "amdgpu_dcn401_requestor.rs"]
mod requestor;
pub use requestor::RequestorApplied;
#[path = "amdgpu_dcn401_deadline.rs"]
mod deadline;
pub use deadline::DeadlinesApplied;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SurfaceFormat {
    /// Little-endian packed 0xXXRRGGBB pixels.
    Xrgb8888,
    /// Little-endian packed 0xXXBBGGRR pixels.
    Xbgr8888,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SurfaceRequest {
    pub pipe: u8,
    pub width: u32,
    pub height: u32,
    pub format: SurfaceFormat,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SurfaceApplied {
    pub request: SurfaceRequest,
    /// GPU framebuffer address, never a CPU BAR or translated physical address.
    pub address: u64,
    pub pitch_bytes: u32,
    /// Visible rows including pitch padding; the reservation is page-rounded.
    pub bytes: u64,
}
impl SurfaceRequest {
    fn geometry(self) -> Result<(u32, u64), Error> {
        if self.pipe >= 4
            || self.width == 0
            || self.height == 0
            || self.width > 0x3fff
            || self.height > 0x3fff
        {
            return Err(Error::Invalid);
        }
        // Linear surfaces use 256-byte-aligned rows and page-aligned backing.
        let pitch = ((self.width + 63) & !63) * 4;
        Ok((pitch, u64::from(pitch) * u64::from(self.height)))
    }
}
impl SurfaceApplied {
    fn registers(self) -> [(u64, u32, u32); 18] {
        let dimensions = self.request.width | self.request.height << 16;
        let crossbar = match self.request.format {
            SurfaceFormat::Xrgb8888 => 0xe00000,
            SurfaceFormat::Xbgr8888 => 0xb00000,
        };
        [
            (0x612, 0x203, 0), // primary TMZ, both DCC enables
            (0x5e7, 7, 0),     // ADDR3 linear; DIM_TYPE stays at native 2D
            (0x607, 0xffff, self.pitch_bytes / 4 - 1),
            (0x5e5, 0xf7f, 8), // RGB8888, no rotation/mirror/alpha plane
            (0x66d, 0xf00000, crossbar),
            (0x5eb, 0x3fff3fff, dimensions),
            (0x5e9, u32::MAX, 0),
            (0x5ef, 0x3fff3fff, dimensions),
            (0x5ee, u32::MAX, 0),
            (0x5ed, 0x3fff3fff, 0),
            (0x5ec, u32::MAX, 0),
            (0x5f1, 0x3fff3fff, 0),
            (0x5f0, u32::MAX, 0),
            (0x609, 0xf, 0),    // VMID0, physical FB aperture still needs setup
            (FLIP, 0x130f2, 0), // normal, non-stereo, no skipped vupdates
            (FLIP2, 0x700, 0),  // no GSL or triple buffering
            (0x60b, 0xffff, (self.address >> 32) as u32),
            // Low address publishes the flip: it must be the last surface write.
            (0x60a, u32::MAX, self.address as u32),
        ]
    }
}

#[derive(Debug)]
struct Surface {
    memory: Reservation,
    applied: SurfaceApplied,
}
#[derive(Debug)]
pub(in super::super) struct Surfaces([Option<Surface>; 4]);
impl Surfaces {
    pub(in super::super) fn new() -> Self {
        Self(core::array::from_fn(|_| None))
    }
    pub(in super::super) async fn prepare<I: Io>(
        &mut self,
        engine: &mut Engine<I>,
        pool: &Pool,
        request: SurfaceRequest,
    ) -> Result<SurfaceApplied, Error> {
        let (pitch_bytes, bytes) = request.geometry()?;
        let slot = usize::from(request.pipe);
        if self.0[slot].is_some() || !engine.status.state.reusable() {
            return Err(Error::Busy);
        }
        engine.surface_preflight(request.pipe)?;
        let memory = pool.reserve(bytes).map_err(|_| Error::Allocation)?;
        if memory.address() == 0
            || memory
                .address()
                .checked_add(memory.size())
                .is_none_or(|end| end > 1 << 48)
        {
            return Err(Error::Invalid);
        }
        let applied = SurfaceApplied {
            request,
            address: memory.address(),
            pitch_bytes,
            bytes,
        };
        self.0[slot] = Some(Surface { memory, applied });
        engine.status.state = State::PreparingSurface(request.pipe);
        engine.status.surfaces[slot] = None;
        let result = self.initialize(engine, slot).await;
        match result {
            Ok(()) => {
                engine.status.surfaces[slot] = Some(applied);
                engine.status.state = State::SurfacePrepared;
                Ok(applied)
            }
            Err(e) => {
                engine.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
    async fn initialize<I: Io>(
        &mut self,
        engine: &mut Engine<I>,
        slot: usize,
    ) -> Result<(), Error> {
        let surface = self.0[slot].as_mut().ok_or(Error::Invalid)?;
        let map = surface.memory.mapping();
        // Clear padding too, with bounded CPU work and fresh authority per chunk.
        for start in (0..map.len).step_by(65536) {
            let end = (start + 65536).min(map.len);
            engine.access(|_| {
                for offset in (start..end).step_by(4) {
                    // SAFETY: live authority and an owned, permanent VRAM mapping.
                    unsafe { map.write32(offset, 0) };
                }
                Ok(())
            })?;
            if end < map.len {
                narf_scheduler::yield_now().await;
            }
        }
        engine.flush_surface_writes()?;
        // Recheck after cooperative clearing, before any surface register changes.
        engine.surface_preflight(surface.applied.request.pipe)?;
        surface.memory.publish();
        engine.program_surface(surface.applied).await
    }
    pub(in super::super) fn upload<I: Io>(
        &mut self,
        engine: &mut Engine<I>,
        pipe: u8,
        x: u32,
        y: u32,
        pixels: &[u32],
    ) -> Result<(), Error> {
        let surface = self
            .0
            .get(usize::from(pipe))
            .and_then(Option::as_ref)
            .ok_or(Error::Invalid)?;
        let a = surface.applied;
        let count = u32::try_from(pixels.len()).map_err(|_| Error::Invalid)?;
        if count == 0
            || y >= a.request.height
            || x.checked_add(count).is_none_or(|end| end > a.request.width)
        {
            return Err(Error::Invalid);
        }
        if !engine.status.state.reusable() || engine.status.surfaces[usize::from(pipe)] != Some(a) {
            return Err(Error::Busy);
        }
        engine.hubp_tree_stopped(Some(pipe))?;
        engine.verify_surface(a)?;
        let map = surface.memory.mapping();
        let start = u64::from(y) * u64::from(a.pitch_bytes) + u64::from(x) * 4;
        engine.status.state = State::PreparingSurface(pipe);
        let result = engine
            .access(|_| {
                for (index, &pixel) in pixels.iter().enumerate() {
                    // SAFETY: checked row bounds within the retained VRAM allocation.
                    unsafe { map.write32(start + index as u64 * 4, pixel) };
                }
                Ok(())
            })
            .and_then(|()| engine.flush_surface_writes())
            .and_then(|()| engine.hubp_tree_stopped(Some(pipe)))
            .and_then(|()| engine.verify_surface(a));
        if let Err(e) = result {
            engine.status.surfaces[usize::from(pipe)] = None;
            engine.status.state = State::Failed(e);
            return Err(e);
        }
        engine.status.state = State::SurfacePrepared;
        Ok(())
    }
}
impl<I: Io> Engine<I> {
    fn surface_preflight(&mut self, pipe: u8) -> Result<(), Error> {
        self.hubp_power_tree_stopped()?;
        if !self.hubp_powered(pipe)? {
            return Err(Error::Busy);
        }
        let l = self.layout;
        if self.read(l.hubp(pipe, HUBP_CONTROL))? & 0x1007 != 3
            || self.read(l.hubp(pipe, 0x5e7))? & 0x180 != 0x80
            || self.read(l.nbio + 0x12d * 4)? != 0x7f000
        {
            return Err(Error::Busy);
        }
        Ok(())
    }
    fn flush_surface_writes(&mut self) -> Result<(), Error> {
        if self.read(self.layout.nbio + 0x12d * 4)? != 0x7f000 {
            return Err(Error::Busy);
        }
        // Native CPU HDP flush: WC stores, remapped HDP write, PCIe read drain.
        fence(Ordering::SeqCst);
        self.access(|io| {
            io.write(0x7f000, 0);
            Ok(())
        })?;
        self.read(self.layout.nbio + 0xc3 * 4)?;
        fence(Ordering::SeqCst);
        Ok(())
    }
    fn verify_surface(&mut self, surface: SurfaceApplied) -> Result<(), Error> {
        let l = self.layout;
        let p = surface.request.pipe;
        if !self.hubp_powered(p)? {
            return Err(Error::Busy);
        }
        if self.read(l.hubp(p, 0x5e7))? & 0x180 != 0x80 {
            return Err(Error::Busy);
        }
        for (r, mask, value) in surface.registers() {
            let at = l.hubp(p, r);
            if self.read(at)? & mask != value {
                return Err(Error::Readback(at));
            }
        }
        Ok(())
    }
    async fn program_surface(&mut self, surface: SurfaceApplied) -> Result<(), Error> {
        let l = self.layout;
        let p = surface.request.pipe;
        self.update(l.hubp(p, HUBP_CLOCK), 1, 1)?;
        self.wait(l.hubp(p, HUBP_CONTROL), 0x1007, 3, 100_000)
            .await?;
        for (r, mask, value) in surface.registers() {
            self.update(l.hubp(p, r), mask, value)?;
        }
        // Address writes may leave a pending flip until timing runs. That is
        // not an active fetch and must never be treated as flip completion.
        self.wait(l.hubp(p, HUBP_CONTROL), 0x1007, 3, 100_000)
            .await?;
        self.update(l.hubp(p, HUBP_CLOCK), 1, 0)?;
        self.hubp_tree_stopped(Some(p))?;
        self.verify_surface(surface)
    }
}
impl Otg {
    /// Allocate, clear and stage a linear RGB framebuffer while fetch is blank.
    /// A staged address may remain pending; VM, bandwidth, DPP/MPC and output
    /// activation are separate prerequisites. Each pipe retains one allocation;
    /// replacement/release requires a future explicit retirement protocol.
    /// # Safety
    /// `pool` must exclusively own this GPU's correctly mapped VRAM. Exclude
    /// firmware/FAMS and concurrent display/HDP/clock/power writers. Retain all
    /// inherited resources and this owner on success, error and cancellation.
    pub async unsafe fn prepare_surface(
        &mut self,
        pool: &Pool,
        request: SurfaceRequest,
    ) -> Result<SurfaceApplied, Error> {
        self.1.prepare(&mut self.0, pool, request).await
    }
    /// Upload part of one visible row of a staged, stopped surface. No raw CPU
    /// pointer escapes. The native HDP flush publishes the CPU writes.
    /// # Safety
    /// Exclude concurrent firmware/FAMS/display/HDP/clock/power writers and
    /// retain the owner and all inherited resources on every outcome.
    pub unsafe fn upload_surface(
        &mut self,
        pipe: u8,
        x: u32,
        y: u32,
        pixels: &[u32],
    ) -> Result<(), Error> {
        self.1.upload(&mut self.0, pipe, x, y, pixels)
    }
}
