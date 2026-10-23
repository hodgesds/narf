//! One retained cold-power RTL8822CE capability and firmware continuation.
use super::{
    firmware_lifecycle::{Lifecycle, Status},
    firmware_transport::{Error, Info},
    pci_firmware::{self, Transport},
};
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
pub(super) struct Firmware {
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
    mmio: MmioRegion,
    lifecycle: Lifecycle<Transport>,
}
impl core::fmt::Debug for Firmware {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtw8822ceFirmwareOwner")
            .field("status", &self.status())
            .finish_non_exhaustive()
    }
}
impl Firmware {
    /// # Safety
    /// These identify the same exclusively owned function immediately after
    /// successful chip/cut cold power and factory EFUSE, with BME/IRQs parked.
    /// No other native/firmware owner may run over this retained function.
    pub(super) unsafe fn new(
        device: BusDevice,
        cap: Cap<BusDeviceCap, Write>,
        mmio: MmioRegion,
    ) -> Self {
        Self {
            device,
            cap,
            mmio,
            lifecycle: Lifecycle::new(device.id.device),
        }
    }
    pub(super) fn status(&self) -> Status {
        self.lifecycle.status()
    }
    pub(super) async fn initialize_registered(&self) -> Result<Info, Error> {
        self.lifecycle
            .initialize_registered(|| {
                // SAFETY: constructor retained the exact exclusive post-cold-power
                // ownership; Lifecycle invokes this factory at most once.
                unsafe { pci_firmware::allocate(self.device, self.cap, self.mmio) }
            })
            .await
    }
}
