//! Retained VCN5 static-power idle, separate from destructive recovery.
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
        if self.ib_result.is_none_or(|r| r.is_err()) {
            return Ok(false);
        }
        if !matches!(
            self.state,
            State::IbVerified
                | State::DecodeVerified
                | State::HevcVerified
                | State::Hevc10Verified
                | State::Vp9Verified
                | State::Vp9TenVerified
                | State::Av1Verified
                | State::Av1TenVerified
                | State::EncodeVerified
                | State::HevcEncodeVerified
                | State::Av1EncodeVerified
        ) {
            return Ok(false);
        }
        let done = self.completed_job()?;
        if !crate::amdgpu_fence_navi22::signaled(done, self.seq)
            || self.reg(RPTR)? & 1023 != self.wptr
        {
            return Ok(false);
        }
        self.idle_state = Some(self.state);
        self.state = State::IdleStopping;
        self.io.media_idle(false, true);
        // NBIO's media range belongs to both VCN and JPEG. Idle never
        // withdraws it, and never marks any retained backing reusable.
        let result = if self.dpg {
            self.idle_dpg().await
        } else {
            self.stop_hardware(false).await
        };
        self.state = match result {
            Ok(()) => State::Idle,
            Err(e) => State::Failed(e),
        };
        result.map(|()| true)
    }
    pub(super) async fn resume_idle(
        &mut self,
        image: u64,
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
        if power.enabled & crate::amdgpu_navi48_media_power::FEATURES != 0 && !self.dpg {
            return Err(Error::PowerPolicy(power.enabled));
        }
        let old = self.idle_state.ok_or(Error::Invalid)?;
        self.state = State::IdleStarting;
        let result = if self.dpg {
            self.restore_dpg(sram).await
        } else {
            self.restore(image, false).await
        }
        .and_then(|()| {
            if self.dpg {
                Ok(())
            } else {
                self.set(MASTINT, 2, 2)
            }
        })
        .and_then(|()| self.access(|_, _| Ok(())));
        self.state = match result {
            Ok(()) => old,
            Err(e) => State::Failed(e),
        };
        if result.is_ok() {
            self.idle_state = None;
            self.io.media_idle(false, self.dpg);
        }
        result
    }
}
impl Vcn {
    pub(crate) fn active_state(&self) -> State {
        self.engine.active_state()
    }
    /// # Safety
    /// Retain the matching TMR/GMC/IRQ owner and exclude all publishers/PM.
    pub(crate) async unsafe fn idle(&mut self) -> Result<bool, Error> {
        self.engine.idle().await
    }
    /// # Safety
    /// PowerUpVcn completed; retain idle's matching firmware and ownership.
    pub(crate) async unsafe fn resume_idle(
        &mut self,
        firmware: crate::amdgpu_psp_ring::MediaFirmware,
        power: crate::amdgpu_smu_navi48::PowerStatus,
        psp: &mut crate::amdgpu_psp_ring::Psp,
    ) -> Result<(), Error> {
        self.engine
            .resume_idle(firmware.vcn.ok_or(Error::Invalid)?, power, psp)
            .await
    }
}
