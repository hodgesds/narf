// SPDX-License-Identifier: GPL-2.0-or-later
//! Retained RTL8821CE firmware/inactive-MAC/PHY continuation. No RF/station entry.
use super::{
    efuse::Factory8821c,
    firmware_lifecycle::{Lifecycle, Stage, Status},
    firmware_transport::Error,
    pci_firmware::{self, Transport},
};
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::mutex::Mutex;

pub(super) struct Sibling {
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
    mmio: MmioRegion,
    factory: Factory8821c,
    lifecycle: Lifecycle<Transport>,
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
            lifecycle: Lifecycle::new(device.id.device),
            admission: Mutex::new(()),
        }
    }
    pub(super) fn status(&self) -> Status {
        self.lifecycle.status()
    }
    pub(super) fn factory(&self) -> &Factory8821c {
        &self.factory
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
                Stage::PhyTablesPrepared => return Ok(()),
                _ => return Err(Error::State),
            }
        }
    }
}
