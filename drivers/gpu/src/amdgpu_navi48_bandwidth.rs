//! dcn401_prepare_bandwidth's UCLK step as the Navi48 display owner runs it
//! before a configuration change, kept apart from `ColdBoot` so that the
//! sequencing a fresh owner (cold boot, S3 or runtime resume) runs can be
//! driven against a real clock owner in kernel tests.
use super::{clocks, otg};

/// What the pin needs from the display owner.
pub(crate) trait UclkPin {
    /// The DCN401 clock owner's status (`Err` without one).
    fn clock_status(&self) -> Result<clocks::Status, otg::Error>;
    /// dcn401_update_clocks in prepare_bandwidth (`safe_to_lower` false)
    /// towards `bandwidth` while the displays run.
    async fn raise_bandwidth(&mut self, bandwidth: clocks::Bandwidth) -> Result<(), otg::Error>;
    /// dcn401_dmub_hw_control_lock(true), dcn401_fams2_update_config with
    /// FAMS2 disabled, dcn401_dmub_hw_control_lock(false).
    async fn disable_fams2(&mut self) -> Result<(), otg::Error>;
}

/// dcn401_prepare_bandwidth for a configuration change while PMFW may switch
/// UCLK (`clocks::Status::uclk_switching`): p_state_change_support forced
/// false, so update_clocks raises UCLK and FCLK to their highest levels and
/// disallows switching, then, after the clocks (and the watermarks, which
/// are each display's own), FAMS2 is disabled under the HW lock. Nothing
/// when nothing allowed switching: a fresh owner (clocks not started, or
/// started and not yet prepared) or one already pinned.
pub(crate) async fn pin_uclk<P: UclkPin>(owner: &mut P) -> Result<(), otg::Error> {
    let Ok(status) = owner.clock_status() else {
        return Ok(());
    };
    if !status.uclk_switching() {
        return Ok(());
    }
    let levels = status.levels.ok_or(otg::Error::Busy)?;
    owner
        .raise_bandwidth(clocks::Bandwidth::pinned(&levels))
        .await?;
    owner.disable_fams2().await
}
