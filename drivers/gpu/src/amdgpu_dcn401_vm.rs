//! Native DCN401 memory setup. Linux hubbub3_init_dchub_sys_ctx,
//! dcn20_vmid_setup and hubp3_set_vm_system_aperture_settings.
use super::*;
use crate::amdgpu_gmc_navi48::{DisplayContext, Gmc};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryApplied {
    pub pipe: u8,
    pub framebuffer_base: u64,
    /// Inclusive GPU framebuffer limit.
    pub framebuffer_top: u64,
    pub framebuffer_offset: u64,
    /// Physical VRAM page directory entry, including its VALID bit.
    pub page_table_base: u64,
}
impl Surfaces {
    pub(in super::super::super) async fn prepare_memory<I: Io>(
        &mut self,
        engine: &mut Engine<I>,
        pipe: u8,
        mut context: impl FnMut() -> Result<DisplayContext, Error>,
    ) -> Result<MemoryApplied, Error> {
        let surface = self
            .0
            .get(usize::from(pipe))
            .and_then(Option::as_ref)
            .ok_or(Error::Invalid)?;
        if !engine.status.state.reusable()
            || engine.status.surfaces[usize::from(pipe)] != Some(surface.applied)
        {
            return Err(Error::Busy);
        }
        engine.hubp_tree_stopped(Some(pipe))?;
        engine.verify_surface(surface.applied)?;
        let config = context()?;
        // The whole retained allocation, including pitch/page padding, must
        // translate through FB. The GART test aperture never backs this surface.
        if surface.memory.address() < config.fb_base
            || surface
                .memory
                .address()
                .checked_add(surface.memory.size() - 1)
                .is_none_or(|last| last > config.fb_top)
        {
            return Err(Error::Invalid);
        }
        engine.status.state = State::PreparingMemory(pipe);
        engine.status.memory = [None; 4]; // global aperture/context will change
        engine.status.dpps = [None; 4];
        let result = engine.program_memory(pipe, config).await;
        let result = result.and_then(|()| {
            if context()? != config {
                return Err(Error::Busy);
            }
            engine.hubp_tree_stopped(Some(pipe))?;
            engine.verify_surface(surface.applied)?;
            engine.verify_memory(pipe, config)
        });
        if let Err(e) = result {
            engine.status.state = State::Failed(e);
            return Err(e);
        }
        let applied = MemoryApplied {
            pipe,
            framebuffer_base: config.fb_base,
            framebuffer_top: config.fb_top,
            framebuffer_offset: config.fb_offset,
            page_table_base: config.root,
        };
        engine.status.memory[usize::from(pipe)] = Some(applied);
        engine.status.state = State::MemoryPrepared;
        Ok(applied)
    }
}
// Native context uses logical page numbers, but its root is a physical byte
// address with PDE flags. BASE_LO is the final context write, not START_LO.
fn global_registers(c: DisplayContext) -> [(u64, u32, u32); 13] {
    [
        (0x475, 0xffffff, (c.fb_base >> 24) as u32),
        (0x476, 0xffffff, (c.fb_top >> 24) as u32),
        (0x477, 0xffffff, (c.fb_offset >> 24) as u32),
        (0x478, 0xffffff, 0xffffff), // disabled AGP: bottom > top
        (0x479, 0xffffff, 0),
        (0x47a, 0xffffff, 0),
        (0x55c, 0xf, (c.start >> 44) as u32),
        (0x55d, u32::MAX, (c.start >> 12) as u32),
        (0x55e, 0xf, (c.end >> 44) as u32),
        (0x55f, u32::MAX, (c.end >> 12) as u32),
        (0x559, 0x7e, 0), // flat, 4KiB blocks
        (0x55a, u32::MAX, (c.root >> 32) as u32),
        (0x55b, u32::MAX, c.root as u32),
    ]
}
fn pipe_registers(c: DisplayContext) -> [(u64, u32, u32); 3] {
    [
        (0x62c, 0x3fffffff, (c.fb_base >> 18) as u32),
        (0x62d, 0x3fffffff, (c.fb_top >> 18) as u32),
        (0x63a, 0x79, 0x19), // L1 on, system mode 3, no unmapped access or ADM
    ]
}
impl<I: Io> Engine<I> {
    async fn program_memory(&mut self, pipe: u8, config: DisplayContext) -> Result<(), Error> {
        let l = self.layout;
        for (r, mask, value) in global_registers(config) {
            let at = l.base + r * 4;
            // Native REG_SET clears the other fields. The root low word can
            // have VALID cleared by hardware until the context update is ready.
            self.access(|io| {
                io.write(at, value);
                Ok(())
            })?;
            if r != 0x55b && self.read(at)? & mask != value {
                return Err(Error::Readback(at));
            }
        }
        let at = l.base + 0x55b * 4;
        let deadline = narf_time::Deadline::after_ms(50);
        loop {
            let value = self.read(at)?;
            if value & !1 != config.root as u32 & !1 {
                return Err(Error::Readback(at));
            }
            if value & 1 != 0 {
                break;
            }
            if deadline.expired() {
                return Err(Error::Timeout(at));
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(5).as_instant()).await;
        }
        // Recheck the entire tree after the context wait, before touching a
        // potentially gated HUBP. Only the retained selected flip may be pending.
        self.hubp_tree_stopped(Some(pipe))?;
        if !self.hubp_powered(pipe)? {
            return Err(Error::Busy);
        }
        self.update(l.hubp(pipe, HUBP_CLOCK), 1, 1)?;
        self.wait(l.hubp(pipe, HUBP_CONTROL), 0x1007, 3, 100_000)
            .await?;
        for (r, mask, value) in pipe_registers(config) {
            let at = l.hubp(pipe, r);
            self.access(|io| {
                io.write(at, value);
                Ok(())
            })?;
            if self.read(at)? & mask != value {
                return Err(Error::Readback(at));
            }
        }
        self.update(l.hubp(pipe, HUBP_CLOCK), 1, 0)?;
        Ok(())
    }
    pub(super) fn verify_memory(&mut self, pipe: u8, config: DisplayContext) -> Result<(), Error> {
        let l = self.layout;
        for (at, mask, value) in global_registers(config)
            .map(|(r, m, v)| (l.base + r * 4, m, v))
            .into_iter()
            .chain(pipe_registers(config).map(|(r, m, v)| (l.hubp(pipe, r), m, v)))
        {
            if self.read(at)? & mask != value {
                return Err(Error::Readback(at));
            }
        }
        Ok(())
    }
}
impl Otg {
    /// Configure physical FB translation and VMID0 for a staged, stopped surface.
    /// Fetch remains blank; bandwidth, DPP/MPC and activation are separate steps.
    /// # Safety
    /// Retain this owner and the matching GMC owner and all inherited resources
    /// on every outcome, including cancellation. Exclude firmware/FAMS, hub/VM,
    /// display, clock, reset and power writers throughout the operation.
    pub async unsafe fn prepare_memory(
        &mut self,
        gmc: &mut Gmc,
        pipe: u8,
    ) -> Result<MemoryApplied, Error> {
        let regs = self.0.io.0;
        self.1
            .prepare_memory(&mut self.0, pipe, || {
                gmc.display_context(regs).map_err(Error::Memory)
            })
            .await
    }
}
