// SPDX-License-Identifier: GPL-2.0-or-later
//! Ordinary firmware station PS; no host-bus/system sleep or U-APSD claim.
use super::*;
use crate::ath10k::regulatory::Permission;
use narf_wireless::reg::RegulatoryDomain;

impl<T: Hif + HostMemory + HttMemory> Radio<T> {
    pub(in crate::ath10k) fn power_save_supported(&self) -> bool {
        // Linux core.h ATH10K_FW_FEATURE_NO_PS, independent of RAW mode.
        self.features & (1 << 17) == 0 && self.data_supported()
    }
    pub(in crate::ath10k) fn submitted_power_save(&self) -> Option<bool> {
        self.power_save
    }
    pub(in crate::ath10k) async fn set_station_power_save(
        &mut self,
        enabled: bool,
        current: impl Fn() -> Result<RegulatoryDomain, Error>,
    ) -> Result<(), Error> {
        if !self.power_save_supported() {
            return Err(Error::Unsupported);
        }
        if self.failed || self.station_link().is_none() {
            return Err(Error::Failed);
        }
        let previous = self.peer.as_ref().ok_or(Error::Failed)?.permission;
        let caps = self.htt.wmi.caps.as_ref().ok_or(Error::Failed)?.clone();
        let validate = || {
            if Permission::from_domain(&caps, &current()?, previous.frequency)? != previous {
                return Err(Error::Unsupported);
            }
            Ok(())
        };
        validate()?;
        let mut commands = Vec::new();
        commands.try_reserve_exact(6).map_err(|_| Error::NoMemory)?;
        if enabled {
            // Source mac.c non-UAPSD setup, then dynamic inactivity threshold.
            for (parameter, value) in [(0, 0), (1, 1), (2, 0), (4, 0), (3, 100)] {
                commands.push(self.wire.station_ps_parameter(parameter, value)?);
            }
        }
        commands.push(self.wire.station_ps_mode(enabled)?);
        // A cancelled native control publication cannot reopen this owner.
        self.failed = true;
        for command in &commands {
            active_scan::checked(
                async {
                    self.htt
                        .wmi
                        .htc
                        .send_wmi(command)
                        .await
                        .map_err(htt::Error::from)
                        .map_err(Error::from)
                },
                &validate,
            )
            .await?;
        }
        validate()?;
        self.power_save = Some(enabled); // Submission, not a sleep/air ACK.
        self.failed = false;
        Ok(())
    }
}
