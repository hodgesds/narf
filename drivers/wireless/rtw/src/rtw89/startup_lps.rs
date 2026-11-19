// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Same Startup/verified WCPU owns packet ids, original peer and every await.
use super::Startup;
use crate::rtw89::{lps, power, station_control::Admission};
use narf_net::native_emission::Lifetime;
pub(super) type Runtime = lps::Manager;
impl Startup {
    pub(super) fn sleep_prepare(&mut self) -> Result<bool, power::Error> {
        let native = self
            .firmware
            .as_mut()
            .ok_or(power::Error::Terminal)?
            .transport_mut();
        let Some(profile) = native.sleep_profile()? else {
            return Ok(false);
        };
        if self.sleep.is_none() {
            self.sleep = Some(Runtime::after_firmware(profile)?);
        }
        Ok(true)
    }
    pub(super) async fn sleep_service(
        &mut self,
        identity: Option<Lifetime>,
        enabled: bool,
        idle: bool,
        force: bool,
        admission: &Admission,
    ) -> Result<(bool, bool), power::Error> {
        let Some(runtime) = self.sleep.as_mut() else {
            return Ok((false, false));
        };
        let native = self
            .firmware
            .as_mut()
            .ok_or(power::Error::Terminal)?
            .transport_mut();
        let peer = native.sleep_peer().ok();
        runtime
            .service(
                &mut native.sleep_port(),
                peer,
                admission,
                lps::Intent {
                    identity,
                    enabled,
                    idle,
                    force,
                },
            )
            .await
    }
}
