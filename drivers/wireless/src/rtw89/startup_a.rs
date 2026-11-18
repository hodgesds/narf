// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Retained A retune dispatch. Never borrows B's Radio/power/RFK state.
use super::*;
impl Startup {
    pub(super) async fn retune_channel_a(
        &mut self,
        profile: super::super::operating_channel::Profile,
        linked: bool,
    ) -> Result<u32, power::Error> {
        if self.phase != Phase::RadioReady
            || self.monitor.is_some()
            || (linked && self.station_controller.is_none())
            || self.ap_controller.is_some()
            || self
                .identity
                .is_none_or(|id| id.chip() != super::super::mac::ChipId::Rtl8852A)
        {
            return Err(power::Error::Terminal);
        }
        let mut attempt = Attempt::new(self);
        let result = async {
            let owner = &mut *attempt.owner;
            let fw = owner.firmware.as_mut().ok_or(power::Error::Terminal)?;
            if fw.phase() != firmware_boot::Phase::Running {
                return Err(power::Error::Terminal);
            }
            // SAFETY: same retained original A owner and immutable selected
            // tables/assets; outer Attempt terminalizes after grant withdrawal.
            unsafe {
                fw.transport_mut().retune_radio_a(
                    &mut owner.radio_a,
                    &owner.radio,
                    owner.assets.as_ref().ok_or(power::Error::Terminal)?,
                    profile,
                    linked,
                )
            }
            .await
        }
        .await;
        attempt.committed = result.is_ok()
            || attempt
                .owner
                .firmware
                .as_ref()
                .is_some_and(|fw| fw.transport().operating_channel().is_some());
        result
    }
}
