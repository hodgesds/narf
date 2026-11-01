//! Replay admitted clock constraints before allowing runtime clock relaxation.
use super::*;
impl<I: Io> Engine<I> {
    pub(super) async fn admit_dynamic_power(
        &mut self,
        held: &(dyn Fn(u64) -> bool + Sync),
    ) -> Result<Applied, Error> {
        if self.status.state != State::Applied || !self.status.watermarks_ready {
            return Err(Error::Busy);
        }
        let current = self.status.applied.ok_or(Error::Invalid)?;
        if self.status.dynamic_power {
            return Ok(current);
        }
        let levels = self.status.levels.ok_or(Error::Invalid)?;
        if self.unanswered_ignored {
            // A late legacy reply cannot acknowledge this admission replay.
            self.status.state = State::Failed(Error::Timeout);
            return Err(Error::Timeout);
        }
        if current.request.deep_sleep_dcfclk_khz > levels.range(Clock::Dcf).max_khz() {
            return Err(Error::Invalid);
        }
        self.idle_except(held)?;
        self.status.state = State::Applying;
        // Set before every await. Cancellation cannot reuse the old optional
        // mailbox policy or mistake a partially replayed floor for admission.
        self.status.dynamic_power = true;
        let result = async {
            self.command(0xe, u32::from(current.request.displays))
                .await?;
            let dcf = levels.range(Clock::Dcf).max_khz();
            self.hard_min(Clock::Dcf, dcf).await?;
            if !self.idle_dpm(&levels) {
                // Older PMFW has no active/idle FCLK pair: keep that fabric
                // floor pinned. Newer firmware replaces both through the pair.
                self.hard_min(Clock::Fabric, levels.range(Clock::Fabric).max_khz())
                    .await?;
            }
            self.status.bandwidth = Bandwidth::INIT;
            let pinned = Bandwidth {
                deep_sleep_dcfclk_khz: current.request.deep_sleep_dcfclk_khz,
                ..Bandwidth::pinned(&levels)
            };
            let (bandwidth, floor) = self
                .bandwidth(pinned, false, current.request.displays != 0)
                .await?;
            self.status.bandwidth = bandwidth;
            Ok(Applied {
                dcf_floor_khz: dcf,
                memory_floor_khz: floor,
                uclk_pstate: bandwidth.uclk_pstate,
                ..current
            })
        }
        .await;
        self.status.state = match result {
            Ok(_) => State::Applied,
            Err(e) => State::Failed(e),
        };
        if let Ok(applied) = result {
            self.status.applied = Some(applied);
        }
        result
    }
}
impl ClockManager {
    pub(crate) async fn admit_dynamic_power(
        &mut self,
        regs: MmioRegion,
        held: &(dyn Fn(u64) -> bool + Sync),
    ) -> Result<Applied, Error> {
        if regs.phys != self.0.io.0.phys || regs.len != self.0.io.0.len {
            return Err(Error::Invalid);
        }
        self.0.admit_dynamic_power(held).await
    }
}
