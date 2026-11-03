// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Retained receive-only controller on the same Startup/Firmware/Native.
use super::*;
use crate::rtw89::{monitor, station_control::Admission};
impl Startup {
    pub(super) async fn start_monitor(
        &mut self,
        desired: alloc::sync::Arc<monitor::Desired>,
        admission: Admission,
    ) -> Result<monitor::Source, power::Error> {
        if self.phase != Phase::RadioReady
            || self.monitor.is_some()
            || self.station_controller.is_some()
            || self.sleep.is_some()
        {
            return Err(power::Error::Terminal);
        }
        let controller = monitor::Controller::prepare(desired.clone(), admission.clone())?;
        self.station_native()?.monitor_prepare(desired, admission)?;
        self.monitor = Some(controller); // retained before first native wait
        let native = self
            .firmware
            .as_mut()
            .ok_or(power::Error::Terminal)?
            .transport_mut();
        let controller = self.monitor.as_mut().ok_or(power::Error::Terminal)?;
        controller.start(&mut native.monitor_access()).await?;
        native.monitor_source(controller.epoch())
    }
    pub(super) fn poll_monitor(
        &mut self,
    ) -> Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, power::Error> {
        if self.phase != Phase::RadioReady {
            return Err(power::Error::Terminal);
        }
        let native = self
            .firmware
            .as_mut()
            .ok_or(power::Error::Terminal)?
            .transport_mut();
        self.monitor
            .as_mut()
            .ok_or(power::Error::Terminal)?
            .poll(&mut native.monitor_access())
    }
    pub(super) fn stop_monitor(&mut self) -> Result<(), power::Error> {
        let native = self
            .firmware
            .as_mut()
            .ok_or(power::Error::Terminal)?
            .transport_mut();
        if let Some(controller) = self.monitor.as_mut() {
            controller.stop(&mut native.monitor_access())?;
        }
        self.fail();
        Ok(())
    }
}
