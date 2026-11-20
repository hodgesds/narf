// SPDX-License-Identifier: GPL-2.0-or-later
//! Connected active-scan request admission over the retained station owner.
use super::*;
use crate::rtl8xxxu::{probe_runtime::Prepared, station_runtime::ActiveRequest};

impl<C: ControlIo, B: packet_transport::Io, E: Environment> Service<C, B, E> {
    pub(super) async fn associated_active_scan(
        &mut self,
        channels: &[u8],
        dwell_ms: u64,
        mandatory: bool,
        ssid: &[u8],
        extra: &[u8],
    ) -> Result<(), Error> {
        self.check_current()?;
        if !self.station.as_ref().is_some_and(Station::scan_admissible) {
            return Err(Error::State);
        }
        if channels.is_empty() || !(1..=1024).contains(&dwell_ms) || mandatory && dwell_ms > 125 {
            return Err(Error::Profile);
        }
        // Invalid content/timing/power never arms the terminal scan owner.
        // Current-source loss during enumeration is terminal independently.
        for &channel in channels {
            let permission = self.channel_permission(channel);
            self.check_current()?;
            permission?;
            Prepared::new(self.own, channel, ssid, 0, channel == 1, extra)
                .map_err(Error::Radio)?
                .timing(dwell_ms.min(125), mandatory)
                .map_err(Error::Radio)?;
        }
        let mut attempt = Attempt {
            failed: self.failed.clone(),
            armed: true,
        };
        let result = self
            .station
            .as_mut()
            .ok_or(Error::State)?
            .active_scan(
                ActiveRequest {
                    channels,
                    dwell_ms,
                    mandatory,
                    ssid,
                    extra,
                },
                &self.environment,
                &mut self.generation,
            )
            .await
            .map_err(Error::Station);
        attempt.armed = false;
        match result {
            Ok(observations) => {
                for observation in observations {
                    self.remember_scan_candidate(
                        observation.candidate,
                        observation.seen,
                        observation.generation,
                    );
                }
                self.check_current()
            }
            Err(error) => {
                self.fail();
                Err(error)
            }
        }
    }
}
