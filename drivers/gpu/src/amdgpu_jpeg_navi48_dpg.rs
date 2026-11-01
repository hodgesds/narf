// SPDX-License-Identifier: GPL-2.0-or-later
//! JPEG5 SRAM uses JPEG internal addresses, distinct from VCN's SOC24 mapping.
use super::*;
use crate::amdgpu_navi48_media_power::Sram;
impl<I: Io> Engine<I> {
    pub(super) async fn restore_dpg(&mut self, sram: &mut impl Sram) -> Result<(), Error> {
        let config = self.addr_config.ok_or(Error::Invalid)?;
        self.set(POWER, 1, 1)?;
        self.set(DLDO_CONFIG, 3 << 4, 2 << 4)?;
        self.wait(DLDO_STATUS, 4, 4).await?;
        self.set(POWER, 0x10, 0x10)?;
        // jpeg_engine_5_0_0_dpg_clock_gating_mode: both dies support MGCG.
        // Final NO_OP is required by PSP's SRAM payload size check.
        let words = [
            0x4161, 0x83, 0x4160, 0, 0x404a, config, 0x4141, 0x100, 0x29, 0,
        ];
        self.access(|_, _| Ok(()))?;
        sram.load(true, &words).await.map_err(Error::Sram)?;
        self.access(|_, _| Ok(()))?;
        self.set(DB, 0x4fff_fffc, DOORBELL << 2 | 1 << 30)?;
        self.set(VMID, u32::MAX, 0)?;
        self.set(CNTL, u32::MAX, 3)?;
        let base = self.memory.address() + RING;
        self.set(BASE_LO, u32::MAX, base as u32)?;
        self.set(BASE_HI, u32::MAX, (base >> 32) as u32)?;
        self.set(RPTR, u32::MAX, 0)?;
        self.set(WPTR, u32::MAX, 0)?;
        self.set(CNTL, u32::MAX, 2)?;
        self.set(SIZE, u32::MAX, 1024)?;
        self.wptr = 0;
        self.shared_range()?;
        self.dpg_probe().await
    }
    async fn dpg_probe(&mut self) -> Result<(), Error> {
        let map = self.memory.mapping();
        let probe = self.memory.address() + FENCE + 16;
        self.access(|io, l| {
            io.memory_write(map, FENCE + 16, 0);
            io.memory_write(map, FENCE + 20, 0);
            flush(io, l)
        })?;
        let next = self.emit(&[
            0x1bfff,
            0x69004,
            0x18000,
            0x80010000,
            0x404e,
            0xd09f0001,
            0x404f,
            0xd09f0001,
            0x40ab,
            probe as u32,
            0x40ac,
            (probe >> 32) as u32,
            0x404d,
            8,
            0x4000404d,
            0,
            words::NOP,
            0,
            words::NOP,
            0,
            0x70000000,
            0,
            0x1bfff,
            0x69004,
            0x18000,
            0x10000,
        ])?;
        for _ in 0..2000 {
            let done = self.access(|io, l| {
                flush(io, l)?;
                Ok(io.memory_read(map, FENCE + 16) == 0xd09f0001)
            })?;
            if done && self.reg(RPTR)? == next {
                return self.access(|io, l| {
                    io.memory_write(map, FENCE + 16, 0);
                    io.memory_write(map, FENCE + 20, 0);
                    flush(io, l)
                });
            }
            self.io.delay(50).await;
        }
        Err(Error::Timeout)
    }
    pub(super) async fn wake_dpg(&mut self) -> Result<(), Error> {
        if self.dpg {
            self.set(POWER, 0x10, 0)?;
            self.set(DLDO_CONFIG, 3 << 4, 1 << 4)?;
            self.wait(DLDO_STATUS, 4, 0).await?;
            self.set(POWER, 1, 0)?;
            self.set(CG_GATE, u32::MAX, 0)?;
            self.set(CG_CTRL, CG_MODES, 0)?;
        }
        Ok(())
    }
    pub(super) async fn enable_dpg(&mut self, sram: &mut impl Sram) -> Result<bool, Error> {
        if matches!(
            self.state,
            State::IdleStarting | State::IdleStopping | State::Failed(_)
        ) {
            return Err(Error::DeviceGone);
        }
        if self.dpg {
            return if matches!(
                self.state,
                State::Prepared | State::Starting | State::Stopping | State::Stopped
            ) {
                Err(Error::Busy)
            } else {
                Ok(true)
            };
        }
        if !self.idle().await? {
            return Ok(false);
        }
        self.state = State::IdleStarting;
        self.dpg = true;
        let result = self.restore_dpg(sram).await;
        self.state = match result {
            Ok(()) => self.idle_state.take().ok_or(Error::Invalid)?,
            Err(e) => State::Failed(e),
        };
        result.map(|()| true)
    }
}
impl Jpeg {
    /// # Safety
    /// Navi48 only; retain exclusive PSP/GMC/NBIO and registered IH ownership.
    pub(crate) async unsafe fn enable_dpg(
        &mut self,
        psp: &mut crate::amdgpu_psp_ring::Psp,
    ) -> Result<bool, Error> {
        self.engine.enable_dpg(psp).await
    }
}
