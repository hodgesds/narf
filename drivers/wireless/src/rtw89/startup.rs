// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Actual parked-device cold discovery → owned CH12 → WCPU. No NIC publication.
use super::{
    cold::{self, Cold},
    cold_native::Owned,
    command_native::Native,
    command_queue,
    download_plan::{self, DownloadPlan},
    factory::Identity,
    firmware_boot::{self, Firmware},
    firmware_registry,
    fw::FwError,
    power,
    secure::Blacklist,
};
use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    New,
    Cold,
    CommandPreparation,
    Firmware,
    Running,
    Terminal,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Register(power::Error),
    Cold(cold::Error),
    Command(command_queue::Error),
    Image(FwError),
    Plan(download_plan::Error),
    Boot(firmware_boot::Error),
    Terminal,
}
pub struct Startup {
    phase: Phase,
    cold: Option<Cold<Owned>>,
    native: Option<Native>,
    firmware: Option<Firmware<Native>>,
    identity: Option<Identity>,
}
impl core::fmt::Debug for Startup {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtw89ColdStartup")
            .field("phase", &self.phase)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}
pub(super) trait Terminalize {
    fn terminalize(&mut self);
}
pub(super) struct Attempt<'a, T: Terminalize> {
    owner: &'a mut T,
    committed: bool,
}
impl<'a, T: Terminalize> Attempt<'a, T> {
    pub(super) fn new(owner: &'a mut T) -> Self {
        Self {
            owner,
            committed: false,
        }
    }
}
impl<T: Terminalize> Drop for Attempt<'_, T> {
    fn drop(&mut self) {
        if !self.committed {
            self.owner.terminalize();
        }
    }
}
impl Terminalize for Native {
    fn terminalize(&mut self) {
        self.fail();
    }
}
impl Terminalize for Startup {
    fn terminalize(&mut self) {
        self.fail();
    }
}
impl Startup {
    /// # Safety
    /// Exact function is exclusively reserved, inherited DMA independently
    /// stopped/fenced, and no diagnostic, IRQ/reset, PHY or packet owner exists.
    /// This performs actual PCI parking, BAR mapping and physical cut access;
    /// BME-off/MAC-OFF never become reclamation evidence. No constructor is
    /// called by the diagnostic probe while packet/RF startup remains absent.
    pub unsafe fn claim(
        device: BusDevice,
        authority: Cap<BusDeviceCap, Write>,
    ) -> Result<Self, Error> {
        // SAFETY: delegated exclusive claim and independent old-DMA fence.
        let backend = unsafe { Owned::claim(device, authority) }.map_err(Error::Register)?;
        Ok(Self {
            phase: Phase::New,
            cold: Some(Cold::new(backend)),
            native: None,
            firmware: None,
            identity: None,
        })
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn identity(&self) -> Option<Identity> {
        self.identity
    }
    /// One attempt; cancellation parks any published command path while
    /// retaining its ring/packets. No channel/radio/IRQ/network producer starts.
    /// `ber` must be the qualified platform's exact PCI_BER quirk.
    pub async fn start(&mut self, ber: bool) -> Result<(), Error> {
        if self.phase != Phase::New {
            return Err(Error::Terminal);
        }
        self.phase = Phase::Cold;
        let mut attempt = Attempt::new(self);
        let result = attempt.owner.start_inner(ber).await;
        attempt.committed = result.is_ok();
        result
    }
    async fn start_inner(&mut self, ber: bool) -> Result<(), Error> {
        // SAFETY: claim's fence/exclusivity persists inside this single owner;
        // no DMA has yet been published and actual PCI BME remains parked.
        unsafe { self.cold.as_mut().ok_or(Error::Terminal)?.prepare().await }
            .map_err(Error::Cold)?;
        let prepared = self
            .cold
            .take()
            .ok_or(Error::Terminal)?
            .into_prepared()
            .map_err(Error::Cold)?;
        let native = Native::from_cold(prepared, 64).map_err(Error::Command)?;
        let identity = native.identity().ok_or(Error::Terminal)?;
        self.identity = Some(identity);
        self.native = Some(native);
        // Selection follows ECV-corrected physical cut and actual secure fuses.
        // A/51 programmed secure boot still requires authenticated host board
        // blacklist policy; no all-clear default is created for those chips.
        let image =
            firmware_registry::load(identity.chip(), identity.cut()).map_err(Error::Image)?;
        let plan = DownloadPlan::new(
            image,
            identity.fuses(),
            Blacklist::upstream(identity.chip()),
        )
        .map_err(Error::Plan)?;
        self.phase = Phase::CommandPreparation;
        let native = self.native.as_mut().ok_or(Error::Terminal)?;
        // SAFETY: the same cold-qualified backend and independent DMA fence
        // stay retained; no IRQ, power/reset or packet operation can coexist.
        unsafe { native.prepare_bdram(ber).await }.map_err(Error::Command)?;
        // SAFETY: this owner's actual FIFO/PCIe/BDRAM/mode receipts gate all
        // publication, with BME off and every packet/RX channel still stopped.
        unsafe { native.configure() }.map_err(Error::Command)?;
        native.enable_download().map_err(Error::Command)?;
        let native = self.native.take().ok_or(Error::Terminal)?;
        self.firmware = Some(Firmware::new(native, plan).map_err(Error::Boot)?);
        self.phase = Phase::Firmware;
        self.firmware
            .as_mut()
            .ok_or(Error::Terminal)?
            .start()
            .await
            .map_err(Error::Boot)?;
        self.phase = Phase::Running;
        Ok(())
    }
    fn fail(&mut self) {
        self.phase = Phase::Terminal;
        if let Some(native) = self.native.as_mut() {
            native.fail();
        }
        if let Some(firmware) = self.firmware.as_mut() {
            firmware.transport_mut().fail();
        }
    }
}
impl Drop for Startup {
    fn drop(&mut self) {
        self.fail();
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_capabilities::{object_table, CapKind, CapSlot, Rights};
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn device() -> BusDevice {
        let addr = narf_bus::PcieAddr::new(0, 0, 7, 0);
        BusDevice {
            addr: narf_bus::BusAddr::Pcie(addr),
            id: narf_bus::DeviceId {
                vendor: 0x10ec,
                device: 0xb852,
                class: 0x028000,
                subsystem_vendor: 0,
                subsystem_id: 0,
            },
            kind: narf_bus::BusKind::Pcie {
                addr,
                cfg_phys: narf_memory::PhysAddr::new(0),
            },
        }
    }
    fn authority() -> Cap<BusDeviceCap, Write> {
        let (index, generation) = object_table::register(CapKind::BusDevice);
        // SAFETY: fresh fixture object with exact BusDevice/Write type/rights.
        unsafe {
            Cap::mint(CapSlot::new(
                generation,
                index,
                Write::BITS,
                CapKind::BusDevice as u32,
            ))
        }
    }
    fn smoke_rtw89_cold_claim_revocation_precedes_unmapped_pci_and_dma() -> TestResult {
        let cap = authority();
        cap.revoke();
        // SAFETY: revoked authority must stop before deliberately unmapped
        // PCI config/BAR access, power activity or descriptor allocation.
        let claimed = unsafe { Startup::claim(device(), cap) };
        if !matches!(claimed, Err(Error::Register(power::Error::Access))) {
            return TestResult::Fail("revoked cold startup reached PCI or allocated DMA");
        }
        let mut device = device();
        device.id.vendor = 0xffff;
        // SAFETY: unsupported identity must reject before the same unmapped PCI.
        let claimed = unsafe { Startup::claim(device, authority()) };
        if !matches!(claimed, Err(Error::Register(power::Error::Unsupported))) {
            return TestResult::Fail("unsupported cold startup reached PCI");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtw89",
        smoke_rtw89_cold_claim_revocation_precedes_unmapped_pci_and_dma
    );
}
