// SPDX-License-Identifier: GPL-2.0-or-later
//! Retained RTL8821CE firmware/PHY and separately qualified IQK/power/station.
use super::{
    efuse::Factory8821c,
    firmware_lifecycle::{Lifecycle, Stage, Status},
    firmware_transport::Error,
    pci_firmware::{self, Transport},
};
use alloc::sync::Arc;
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::mutex::Mutex;

pub(super) struct Sibling {
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
    mmio: MmioRegion,
    factory: Factory8821c,
    lifecycle: Arc<Lifecycle<Transport>>,
    admission: Mutex<()>,
}
impl Sibling {
    /// # Safety
    /// Exact exclusive RTL8821CE function immediately after source-matched
    /// cold power and its one factory EFUSE read, with BME/IRQs parked.
    pub(super) unsafe fn new(
        device: BusDevice,
        cap: Cap<BusDeviceCap, Write>,
        mmio: MmioRegion,
        factory: Factory8821c,
    ) -> Self {
        Self {
            device,
            cap,
            mmio,
            factory,
            lifecycle: Arc::new(Lifecycle::new(device.id.device)),
            admission: Mutex::new(()),
        }
    }
    pub(super) fn status(&self) -> Status {
        self.lifecycle.status()
    }
    pub(super) fn lifecycle(&self) -> Arc<Lifecycle<Transport>> {
        self.lifecycle.clone()
    }
    pub(super) async fn station_request(
        &self,
    ) -> Result<super::station_power8821c::Request, Error> {
        self.lifecycle.station_request8821c(&self.factory).await
    }
    pub(super) async fn station_radio_info(&self) -> Option<super::radio8821c::StationInfo> {
        self.lifecycle.station_radio_info8821c().await
    }
    pub(super) fn factory(&self) -> &Factory8821c {
        &self.factory
    }
    pub(super) async fn calibration_request(
        &self,
    ) -> Result<super::calibration8821c::Request, Error> {
        self.lifecycle.calibration_request8821c(&self.factory).await
    }
    pub(super) async fn calibration_info(&self) -> Option<super::radio8821c::Info> {
        self.lifecycle.calibration_info8821c().await
    }
    pub(super) async fn operating_request(&self) -> Result<super::operating8821c::Request, Error> {
        self.lifecycle.operating_request8821c(&self.factory).await
    }
    pub(super) async fn operating_info(&self) -> Option<super::operating8821c::Info> {
        self.lifecycle.operating_info8821c().await
    }
    pub(super) async fn provision(&self) -> Result<(), Error> {
        let _admission = self.admission.lock().await;
        loop {
            match self.status().stage {
                Stage::Detected => {
                    self.lifecycle
                        .initialize_registered(|| {
                            // SAFETY: the constructor retained the exact cold
                            // function; Lifecycle consumes this allocator once.
                            unsafe { pci_firmware::allocate(self.device, self.cap, self.mmio) }
                        })
                        .await?;
                }
                Stage::Ready => {
                    self.lifecycle.prepare_mac().await?;
                }
                Stage::MacPrepared => {
                    self.lifecycle.prepare_phy8821c(&self.factory).await?;
                }
                Stage::PhyTablesPrepared => {
                    self.lifecycle
                        .prepare_calibration8821c(&self.factory)
                        .await?;
                }
                Stage::Calibration8821cPrepared => {
                    self.lifecycle.prepare_operating8821c(&self.factory).await?;
                }
                Stage::Operating8821cPrepared => {
                    self.lifecycle
                        .prepare_station8821c(
                            &self.factory,
                            super::station_power8821c::Source::Registered,
                        )
                        .await?;
                }
                Stage::Radio8821cPrepared | Stage::StationReady => return Ok(()),
                _ => return Err(Error::State),
            }
        }
    }
}
