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
    Discovered,
    CommandPreparation,
    Firmware,
    Running,
    MacPreparation,
    MacPrepared,
    ReceivePreparation,
    Receiving,
    RadioTablesPreparation,
    RadioTablesLoaded,
    BasicCalibration,
    BasicCalibrated,
    FullRadioPreparing,
    RadioReady,
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
    Mac(power::Error),
    Receive(super::rx_dma::Error),
    Assets(super::radio_assets::Error),
    Radio(super::radio_init::Error),
    Calibration(super::command_native::CalibrationError),
    Terminal,
}
pub struct Startup {
    phase: Phase,
    cold: Option<Cold<Owned>>,
    native: Option<Native>,
    firmware: Option<Firmware<Native>>,
    identity: Option<Identity>,
    mac: super::mac_runtime::Mac,
    radio: super::radio_init::Init,
    assets: Option<super::radio_assets::Assets>,
    coex: super::coex_native::Coex,
    rfk: super::rfk::Rfk,
    full_radio: super::radio_full::Radio,
    station_controller: Option<super::station_control::Controller>,
    station_binding: Option<[u8; 6]>,
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
    pub(super) fn owner_mut(&mut self) -> &mut T {
        self.owner
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
            mac: super::mac_runtime::Mac::default(),
            radio: super::radio_init::Init::default(),
            assets: None,
            coex: super::coex_native::Coex::default(),
            rfk: super::rfk::Rfk::default(),
            full_radio: super::radio_full::Radio::default(),
            station_controller: None,
            station_binding: None,
        })
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn identity(&self) -> Option<Identity> {
        self.identity
    }
    /// Read-only provisioning facts from this exact retained factory/image.
    /// These values confer no calibration, RF or readiness authority.
    pub(super) fn qualification_request(
        &self,
    ) -> Result<super::command_native::QualificationRequest, power::Error> {
        let full = match self.phase {
            Phase::RadioTablesLoaded => false,
            Phase::BasicCalibrated => true,
            _ => return Err(power::Error::Terminal),
        };
        self.firmware
            .as_ref()
            .ok_or(power::Error::Terminal)?
            .transport()
            .qualification_request(self.assets.as_ref().ok_or(power::Error::Terminal)?, full)
    }
    /// Exact initial B measured calibration continuation; packet/response TX,
    /// full channel calibration and station publication remain closed.
    pub async fn prepare_basic_calibration(&mut self) -> Result<(), Error> {
        if self.phase != Phase::RadioTablesLoaded {
            return Err(Error::Terminal);
        }
        let firmware = self.firmware.as_mut().ok_or(Error::Terminal)?;
        if firmware.phase() != firmware_boot::Phase::Running {
            return Err(Error::Terminal);
        }
        // Resolve exact signed board authority before consuming the hardware
        // attempt. Staging a missing asset later reuses this same owner.
        let preflight = firmware
            .transport_mut()
            .preflight_basic_rfk(self.assets.as_ref().ok_or(Error::Terminal)?)
            .map_err(Error::Calibration)?;
        self.phase = Phase::BasicCalibration;
        let mut attempt = Attempt::new(self);
        let result = async {
            let firmware = attempt.owner.firmware.as_mut().ok_or(Error::Terminal)?;
            if firmware.phase() != firmware_boot::Phase::Running {
                return Err(Error::Terminal);
            }
            // SAFETY: same actual cold/MAC/table/RX owner and retained outer
            // guard; signed board/current policy is checked before transitions.
            unsafe {
                firmware
                    .transport_mut()
                    .prepare_basic_rfk(
                        &attempt.owner.radio,
                        attempt.owner.assets.as_ref().ok_or(Error::Terminal)?,
                        &mut attempt.owner.coex,
                        &mut attempt.owner.rfk,
                        preflight,
                    )
                    .await
            }
            .map_err(Error::Calibration)?;
            attempt.owner.phase = Phase::BasicCalibrated;
            Ok(())
        }
        .await;
        attempt.committed = result.is_ok();
        result
    }
    /// Full channel/calibration/power preparation consumes the pure measured
    /// v2 preflight only after all exact external assets and policy are current.
    pub async fn prepare_full_radio(&mut self) -> Result<(), Error> {
        if self.phase != Phase::BasicCalibrated {
            return Err(Error::Terminal);
        }
        let firmware = self.firmware.as_mut().ok_or(Error::Terminal)?;
        if firmware.phase() != firmware_boot::Phase::Running {
            return Err(Error::Terminal);
        }
        let preflight: super::command_native::RadioPreflight = firmware
            .transport_mut()
            .preflight_full_radio(
                &self.radio,
                &self.rfk,
                self.assets.as_ref().ok_or(Error::Terminal)?,
            )
            .map_err(Error::Register)?;
        self.phase = Phase::FullRadioPreparing;
        let mut attempt = Attempt::new(self);
        let result = async {
            let firmware = attempt.owner.firmware.as_mut().ok_or(Error::Terminal)?;
            // SAFETY: exact same retained factory/firmware/table/basic owner;
            // full measured preflight above is consumed by one attempt. The
            // outer guard closes and retains Native on failure/cancellation.
            unsafe {
                firmware
                    .transport_mut()
                    .prepare_full_radio(
                        &mut attempt.owner.full_radio,
                        &attempt.owner.radio,
                        &attempt.owner.rfk,
                        attempt.owner.assets.as_ref().ok_or(Error::Terminal)?,
                        preflight,
                    )
                    .await
            }
            .map_err(Error::Register)?;
            attempt.owner.phase = Phase::RadioReady;
            Ok(())
        }
        .await;
        attempt.committed = result.is_ok();
        result
    }
    pub async fn prepare_radio_tables(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Receiving {
            return Err(Error::Terminal);
        }
        self.phase = Phase::RadioTablesPreparation;
        let mut attempt = Attempt::new(self);
        let result = async {
            let firmware = attempt.owner.firmware.as_mut().ok_or(Error::Terminal)?;
            if firmware.phase() != firmware_boot::Phase::Running {
                return Err(Error::Terminal);
            }
            // Actual firmware GET_FEATURE precedes all BB/RF table and
            // two-path calibration transitions on this retained owner.
            firmware
                .transport_mut()
                .query_firmware_phycap()
                .await
                .map_err(Error::Register)?;
            let assets = attempt.owner.assets.as_ref().ok_or(Error::Terminal)?;
            // SAFETY: same retained actual cold/firmware/MAC/RX attempt. Its
            // Drop terminalizes both the radio and all possibly published DMA.
            unsafe {
                firmware
                    .transport_mut()
                    .prepare_radio_tables(&mut attempt.owner.radio, assets)
                    .await
            }
            .map_err(Error::Radio)?;
            attempt.owner.phase = Phase::RadioTablesLoaded;
            Ok(())
        }
        .await;
        attempt.committed = result.is_ok();
        result
    }
    /// Publish only private RXQ/RPQ rings after actual B MAC preparation. The
    /// result is a polling transport, not qualified RF/channel/station service.
    pub async fn prepare_receive(&mut self) -> Result<(), Error> {
        if self.phase != Phase::MacPrepared {
            return Err(Error::Terminal);
        }
        self.phase = Phase::ReceivePreparation;
        let mut attempt = Attempt::new(self);
        let result = async {
            let firmware = attempt.owner.firmware.as_mut().ok_or(Error::Terminal)?;
            if firmware.phase() != firmware_boot::Phase::Running {
                return Err(Error::Terminal);
            }
            // SAFETY: same retained actual cold/firmware/MAC attempt. Its Drop
            // closes both RX layers and preserves published memory on failure.
            unsafe {
                firmware
                    .transport_mut()
                    .prepare_receive(&attempt.owner.mac)
                    .await
            }
            .map_err(Error::Receive)?;
            attempt.owner.phase = Phase::Receiving;
            Ok(())
        }
        .await;
        attempt.committed = result.is_ok();
        result
    }
    pub fn poll_receive(
        &mut self,
        budget: usize,
    ) -> Result<alloc::vec::Vec<super::rx_packet::Event>, Error> {
        if !matches!(
            self.phase,
            Phase::Receiving | Phase::RadioTablesLoaded | Phase::BasicCalibrated
        ) {
            return Err(Error::Terminal);
        }
        let result = self
            .firmware
            .as_mut()
            .ok_or(Error::Terminal)?
            .transport_mut()
            .poll_receive(budget)
            .map_err(Error::Receive);
        if result.is_err() {
            self.fail();
        }
        result
    }
    /// Complete B's post-WCPU MAC0/SCC setup on the same actual backend.
    /// MAC preparation is not RF/channel, packet, IRQ or station readiness.
    pub async fn prepare_mac(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Running {
            return Err(Error::Terminal);
        }
        self.phase = Phase::MacPreparation;
        let mut attempt = Attempt::new(self);
        let result = async {
            let firmware = attempt.owner.firmware.as_mut().ok_or(Error::Terminal)?;
            if firmware.phase() != firmware_boot::Phase::Running {
                return Err(Error::Terminal);
            }
            // SAFETY: this is the same retained cold/firmware attempt. Its
            // Drop/failure closes command DMA, retains mappings and forbids
            // any IRQ/reset/packet/radio producer through this private owner.
            unsafe {
                firmware
                    .transport_mut()
                    .prepare_mac(&mut attempt.owner.mac)
                    .await
            }
            .map_err(Error::Mac)?;
            attempt.owner.phase = Phase::MacPrepared;
            Ok(())
        }
        .await;
        attempt.committed = result.is_ok();
        result
    }
    /// Cold discovery ends before firmware/packet BME. The actual factory
    /// MAC can therefore name and register the same retained station shell
    /// before any asynchronous firmware producer becomes visible.
    pub async fn discover(&mut self) -> Result<Identity, Error> {
        if self.phase != Phase::New {
            return Err(Error::Terminal);
        }
        self.phase = Phase::Cold;
        let mut attempt = Attempt::new(self);
        let result = attempt.owner.discover_inner().await;
        attempt.committed = result.is_ok();
        result
    }
    async fn discover_inner(&mut self) -> Result<Identity, Error> {
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
        self.phase = Phase::Discovered;
        Ok(identity)
    }
    /// One hardware attempt after exact authenticated firmware preflight.
    /// Missing/replaced assets before that attempt leave the discovered owner
    /// intact. Cancellation after command preparation terminalizes it.
    /// `ber` must be the qualified platform's exact PCI_BER quirk.
    pub async fn start(&mut self, ber: bool) -> Result<(), Error> {
        if self.phase == Phase::New {
            self.discover().await?;
        }
        if self.phase != Phase::Discovered {
            return Err(Error::Terminal);
        }
        let identity = self.identity.ok_or(Error::Terminal)?;
        // Selection follows ECV-corrected physical cut and actual secure fuses.
        // A/51 programmed secure boot still requires authenticated host board
        // blacklist policy; no all-clear default is created for those chips.
        let image =
            firmware_registry::load(identity.chip(), identity.cut()).map_err(Error::Image)?;
        let assets = if identity.chip() == super::mac::ChipId::Rtl8852B {
            Some(super::radio_assets::Assets::from_prepared(&image).map_err(Error::Assets)?)
        } else {
            None
        };
        let plan = DownloadPlan::new(
            image,
            identity.fuses(),
            Blacklist::upstream(identity.chip()),
        )
        .map_err(Error::Plan)?;
        self.phase = Phase::CommandPreparation;
        self.assets = assets;
        let mut attempt = Attempt::new(self);
        let result = attempt.owner.start_plan(ber, plan).await;
        attempt.committed = result.is_ok();
        result
    }
    async fn start_plan(&mut self, ber: bool, plan: DownloadPlan) -> Result<(), Error> {
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
#[path = "startup_station.rs"]
mod station;

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
