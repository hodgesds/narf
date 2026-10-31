//! JPEG5 retains its copy slots, fences and proof across static idle.
use super::*;
impl<I: Io> Engine<I> {
    pub(super) fn active_state(&self) -> State {
        if self.state == State::Idle {
            self.idle_state.unwrap_or(self.state)
        } else {
            self.state
        }
    }
    pub(super) async fn idle(&mut self) -> Result<bool, Error> {
        if self.state == State::Idle {
            return Ok(false);
        }
        if matches!(
            self.state,
            State::IdleStopping | State::IdleStarting | State::Failed(_)
        ) {
            return Err(Error::DeviceGone);
        }
        if self.state != State::Clients {
            return Ok(false);
        }
        let done = cs::retained_fence(
            &mut self.io,
            self.authority,
            self.layout,
            self.memory.mapping(),
            false,
        )?;
        if !crate::amdgpu_fence_navi22::signaled(done, self.seq)
            || self.reg(RPTR)? & 1023 != self.wptr
        {
            return Ok(false);
        }
        self.idle_state = Some(self.state);
        self.state = State::IdleStopping;
        self.io.media_idle(true, true);
        let result = if self.dpg {
            self.set(POWER, 0x10, 0)
        } else {
            self.stop_inner().await
        };
        self.state = match result {
            Ok(()) => State::Idle,
            Err(e) => State::Failed(e),
        };
        result.map(|()| true)
    }
    pub(super) async fn resume_idle(
        &mut self,
        power: crate::amdgpu_smu_navi48::PowerStatus,
        sram: &mut impl crate::amdgpu_navi48_media_power::Sram,
    ) -> Result<(), Error> {
        if self.state != State::Idle {
            return if matches!(
                self.state,
                State::IdleStarting | State::IdleStopping | State::Failed(_)
            ) {
                Err(Error::DeviceGone)
            } else {
                Ok(())
            };
        }
        if power.enabled & crate::amdgpu_navi48_media_power::FEATURES & !power.allowed != 0 {
            return Err(Error::PowerPolicy(power.enabled));
        }
        let old = self.idle_state.ok_or(Error::Invalid)?;
        self.state = State::IdleStarting;
        let result = if self.dpg {
            self.restore_dpg(sram).await
        } else {
            self.restore(false).await
        }
        .and_then(|()| {
            if self.dpg {
                Ok(())
            } else {
                self.set(IRQ, 0x100, 0x100)
            }
        })
        .and_then(|()| self.access(|_, _| Ok(())));
        self.state = match result {
            Ok(()) => old,
            Err(e) => State::Failed(e),
        };
        if result.is_ok() {
            self.idle_state = None;
            self.io.media_idle(
                true,
                self.dpg || power.enabled & crate::amdgpu_navi48_media_power::FEATURES != 0,
            );
        }
        result
    }
}
impl Jpeg {
    // Clock DPM can also sleep Navi44's static JPEG clocks. Drain active
    // STATUS readers before enabling that SMU policy, just as for DPG.
    pub(crate) fn allow_clock_sleep(&mut self) {
        self.engine.io.media_idle(true, true);
    }
    pub(crate) fn active_state(&self) -> State {
        self.engine.active_state()
    }
    /// # Safety
    /// Exclude publishers/PM and retain the shared NBIO, GMC and IRQ owner.
    pub(crate) async unsafe fn idle(&mut self) -> Result<bool, Error> {
        self.engine.idle().await
    }
    /// # Safety
    /// PowerUpJpeg completed; retain idle's matching VCN/NBIO/GMC owner.
    pub(crate) async unsafe fn resume_idle(
        &mut self,
        power: crate::amdgpu_smu_navi48::PowerStatus,
        psp: &mut crate::amdgpu_psp_ring::Psp,
    ) -> Result<(), Error> {
        self.engine.resume_idle(power, psp).await
    }
}
