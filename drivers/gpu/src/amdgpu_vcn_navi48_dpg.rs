//! VCN5's indirect SRAM restore program (vcn_v5_0_0.c), after native proofs.
use super::*;
use crate::amdgpu_navi48_media_power::Sram;

// SOC24_DPG_MODE_OFFSET: the byte address is relative to the 1 MiB VCN
// aperture. The video window takes precedence over the overlapping AON tail.
pub(super) fn offset(base: u64, reg: u32) -> u32 {
    let at = (base as u32 + reg * 4) & 0xfffff;
    let at = if (0x1fc00..0x22200).contains(&at) {
        at - 0x1fc00
    } else if (0x1f800..0x1fe00).contains(&at) {
        at - 0x1f800 + 0x30000
    } else if (0x48300..0x4a900).contains(&at) {
        at - 0x48300
    } else if (0x48000..0x48600).contains(&at) {
        at - 0x48000 + 0x30000
    } else {
        at
    };
    at >> 2
}
impl<I: Io> Engine<I> {
    fn dpg_words(&self) -> Result<alloc::vec::Vec<u32>, Error> {
        let mut words = alloc::vec::Vec::with_capacity(64);
        let mut put = |reg, value| words.extend_from_slice(&[offset(self.layout.vcn, reg), value]);
        let vcpu = 0xff << 20 | VCPU_CLOCK;
        put(VCPU, vcpu | VCPU_RESET);
        put(MASTINT, 0);
        put(LMI, 0x0030_7308);
        // PSP patches firmware BAR/size and stack BAR; never substitute the
        // RDNA2 SRAM format or expose a host firmware address to this script.
        for (i, (address, size)) in [
            (0, 0),
            (0, STACK_BYTES as u32),
            (self.memory.address() + STACK_BYTES, CONTEXT_BYTES as u32),
        ]
        .into_iter()
        .enumerate()
        {
            put(CACHE_LO[i], address as u32);
            put(CACHE_LO[i] + 1, (address >> 32) as u32);
            put(CACHE_OFFSET[i], 0);
            put(CACHE_SIZE[i], size);
        }
        let shared = self.memory.address() + SHARED;
        put(NC_LO, shared as u32);
        put(NC_LO + 1, (shared >> 32) as u32);
        put(NC_OFFSET, 0);
        put(NC_SIZE, 4096);
        put(ADDR_CONFIG, self.addr_config.ok_or(Error::Invalid)?);
        put(VCPU, vcpu);
        put(LMI2, 0x1f << 17);
        put(MASTINT, 2);
        Ok(words)
    }
    pub(super) async fn restore_dpg(&mut self, sram: &mut impl Sram) -> Result<(), Error> {
        // Handoff from the static owner: power-cycle its reset/ARB state
        // before installing the automatic restore program. ONO1 is JPEG's.
        self.set(POWER_STATUS, 3, 1)?;
        for (config, status) in [(12, 6), (10, 5), (8, 4), (6, 3)] {
            self.set(DLDO_CONFIG, u32::MAX, 2 << config)?;
            self.wait(DLDO_STATUS, 1 << status, 1 << status).await?;
        }
        self.set(POWER_STATUS, 0x107, 0x105)?;
        let words = self.dpg_words()?;
        self.access(|_, _| Ok(()))?;
        sram.load(false, &words).await.map_err(Error::Sram)?;
        self.access(|_, _| Ok(()))?;
        let ring = self.memory.address() + RING;
        self.set(RB_LO, u32::MAX, ring as u32)?;
        self.set(RB_HI, u32::MAX, (ring >> 32) as u32)?;
        self.set(RB_SIZE, u32::MAX, 1024)?;
        self.set(RB_ENABLE, RB1, 0)?;
        self.shared_mode(1, 1)?;
        self.set(RPTR, u32::MAX, 0)?;
        self.set(WPTR, u32::MAX, 0)?;
        self.wptr = 0;
        self.set(RB_ENABLE, RB1, RB1)?;
        self.shared_mode(3, 0)?;
        self.set(DB_CTRL, 0x4fff_fffc, DOORBELL << 2 | 1 << 30)?;
        self.dpg_probe().await
    }
    async fn dpg_probe(&mut self) -> Result<(), Error> {
        // A separate word proves execution after every SRAM restore without
        // changing the client sequence or its retained completion word.
        let map = self.memory.mapping();
        let probe = self.memory.address() + FENCE + 16;
        self.access(|io, l| {
            io.memory_write(map, FENCE + 16, 0);
            io.memory_write(map, FENCE + 20, 0);
            flush(io, l)
        })?;
        let next = self.emit(&[3, probe as u32, (probe >> 32) as u32, 0xd09f0001, 4, 1])?;
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
    pub(super) async fn pause_dpg(&mut self) -> Result<(), Error> {
        self.wait(POWER_STATUS, 3, 1).await?;
        self.dpg_pause_request(true)?;
        self.wait(0x14, 8, 8).await
    }
    pub(super) fn dpg_pause_request(&mut self, pause: bool) -> Result<(), Error> {
        // ACK is read-only. Do not write a sampled ACK back as a request.
        self.access(|io, l| {
            let at = l.vcn + 0x14 * 4;
            let old = checked(io.read(at))?;
            io.write(at, (old & !12) | if pause { 4 } else { 0 });
            Ok(())
        })
    }
    pub(super) async fn idle_dpg(&mut self) -> Result<(), Error> {
        self.shared_mode(2, 2)?;
        self.dpg_pause_request(false)?;
        self.wait(POWER_STATUS, 3, 1).await?;
        self.wait(RPTR, 1023, self.wptr).await?;
        self.set(POWER_STATUS, 4, 0)?;
        self.access(|io, l| flush(io, l))
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
        // idle() performs the physical fence/RPTR checks and retains backing.
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
impl Vcn {
    /// # Safety
    /// Matching PSP/TMR, registered IH/GMC and exclusive drained client owner.
    pub(crate) async unsafe fn enable_dpg(
        &mut self,
        psp: &mut crate::amdgpu_psp_ring::Psp,
    ) -> Result<bool, Error> {
        self.engine.enable_dpg(psp).await
    }
}
