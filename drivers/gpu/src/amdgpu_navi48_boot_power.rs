//! Runtime workload and low-power admission under the platform owner.
use super::*;
impl ColdBoot {
    pub(crate) async fn configure_graphics_saving(&mut self) -> Result<(), Error> {
        if !crate::amdgpu_navi48_power::gfx_ulv_requested() {
            return Ok(());
        }
        if self.queue_state() != Some(queues::State::InterruptVerified)
            || self.sdma_state() != Some(sdma::State::InterruptVerified)
        {
            return Err(Error::Busy);
        }
        // SAFETY: fresh native GC/RLC/GMC and IRQ proofs, all retained under
        // OWNER before a client publisher or GFXOFF worker can enter.
        let power =
            unsafe { self.power_owner()?.admit_sleep(true, false).await }.map_err(Error::Smu)?;
        self.sequence.backend.power = Some(power);
        Ok(())
    }
    /// Watermark and floor acknowledgements belong to the matching DCN owner.
    pub(super) async fn configure_display_saving(&mut self) -> Result<(), clocks::Error> {
        let status = self.display_clock_status()?;
        if status.state != clocks::State::Applied || !status.watermarks_ready {
            return Ok(());
        }
        let regs = self.sequence.backend.gpu.regs;
        let held = self
            .otg
            .as_ref()
            .map_err(|_| clocks::Error::Busy)?
            .all_held();
        self.clocks
            .as_mut()
            .map_err(|e| *e)?
            .admit_dynamic_power(regs, &held)
            .await?;
        let status = self.display_clock_status()?;
        if status.bandwidth.deep_sleep_dcfclk_khz == 0
            || !crate::amdgpu_navi48_power::dcf_sleep_requested()
        {
            return Ok(());
        }
        let smu = self
            .sequence
            .backend
            .smu
            .as_mut()
            .ok_or(clocks::Error::Invalid)?;
        // SAFETY: DML supplied this floor, the DAL mailbox acknowledged it
        // and its watermark table, and matching native display owners persist.
        self.sequence.backend.power =
            Some(unsafe { smu.admit_sleep(false, true).await }.map_err(clocks::Error::Power)?);
        Ok(())
    }
    pub(crate) fn profile_coefficients(&self) -> Option<smu::ProfileCoefficients> {
        self.sequence
            .backend
            .smu
            .as_ref()
            .and_then(smu::Smu::profile_coefficients)
    }
    pub(crate) fn power_profile(&self) -> smu::PowerProfile {
        self.power_profile
    }
    pub(crate) async fn set_profile_tuned(
        &mut self,
        profile: smu::PowerProfile,
        custom: smu::CustomCoefficients,
    ) -> Result<(), Error> {
        // Resume replays the selection before the fresh IRQ proofs. This
        // PPSMC-only operation requires stable display owners, not proof-ready
        // client queues; their sleep admission is a later, separate step.
        if self.fams2_pending
            || self.dccg.as_ref().is_ok_and(|d| {
                !matches!(d.status().state, dccg::State::Ready | dccg::State::Applied)
            })
            || self.otg.as_ref().is_ok_and(|o| !o.status().state.settled())
            || self.clocks.as_ref().is_ok_and(|c| {
                matches!(
                    c.status().state,
                    clocks::State::Starting | clocks::State::Applying | clocks::State::Failed(_)
                )
            })
        {
            return Err(Error::Busy);
        }
        self.power_owner()?
            .set_profile_tuned(profile, custom)
            .await
            .map_err(Error::Smu)?;
        // The retained selection is also what a reset/resume successor replays.
        self.power_profile = profile;
        self.custom_profile = self.power_owner()?.custom_coefficients();
        self.sequence.backend.power = self
            .sequence
            .backend
            .smu
            .as_ref()
            .and_then(smu::Smu::power_status);
        Ok(())
    }
}
