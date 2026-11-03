//! RTW88 PCI probe.
//!
//! Driver-match registration and BAR2 control-register mapping, matching
//! Linux `rtw88/pci.c::rtw_pci_io_mapping` (`bar_id = 2`). BAR2 is
//! the register aperture; firmware bytes cannot be copied into it as SRAM.
//!
//! RTL8821CE/RTL8822CE publish one named station shell before retained firmware,
//! MAC/PHY, signed power qualification, radio and packet continuation. Bounded
//! polling drives the qualified awake channel1 profile with interrupts masked.
//! Each chip retains its own factory/PHY/RF/power owner; C22B stays diagnostic.

#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_bus::{BarError, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_ipc::{channel, Consumer, Producer};
use narf_lib::sync::IrqSafeSpinLock;
use narf_net::{Frame, Interface, RX_RING_N, TX_RING_N};
use narf_wireless::{
    AssociateRequest, BssInfo, ScanRequest, WirelessConfig, WirelessError, WirelessIfaceInfo,
    WirelessNetIface,
};

use super::efuse;
use super::power;
use super::regs::*;

/// One bound RTW88 device. Holds the BAR2 register mapping + the EFUSE-
/// derived MAC. Every live function keeps its own lifecycle and name.
pub struct Rtw88Device {
    /// Retained bus identity; a repeat probe must not park the active owner.
    pub(crate) bus_addr: narf_bus::BusAddr,
    pub registers: MmioRegion,
    pub mac: [u8; MAC_ADDR_LEN],
    /// PCI device id selecting the retained C21/C22 station or diagnostic C22B.
    pub device_id: u16,
    /// The exact post-power native owner, shared by controller and interface.
    pub(super) firmware: Option<Arc<super::firmware_native::Firmware>>,
    pub(super) sibling: Option<Arc<super::sibling::Sibling>>,
    pub(super) interface: Option<Arc<super::interface::Native>>,
    pub link_up: AtomicBool,
    pub rx_ring: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    pub tx_ring: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
    pub(super) diagnostic_name: &'static str,
    pub(super) provisioning: narf_lib::mutex::Mutex<()>,
    pub(super) reset_origin: Option<super::operating_reset::Origin>,
}

impl Rtw88Device {
    /// Exact H/R/T native RTS emission-program measurement metadata. No grant.
    pub async fn rts_request(&self) -> Result<super::RtsRequest, super::FirmwareError> {
        if let Some(s) = &self.sibling {
            s.lifecycle().rts_request().await
        } else {
            self.firmware
                .as_ref()
                .ok_or(super::FirmwareError::Unsupported)?
                .lifecycle()
                .rts_request()
                .await
        }
    }
    /// Exact-H/optional-R originator BA emission measurement metadata. No grant.
    pub async fn tx_ba_request(&self) -> Result<super::TxBaRequest, super::FirmwareError> {
        if let Some(s) = &self.sibling {
            s.lifecycle().tx_ba_request().await
        } else {
            self.firmware
                .as_ref()
                .ok_or(super::FirmwareError::Unsupported)?
                .lifecycle()
                .tx_ba_request()
                .await
        }
    }
    /// Separately signed N2xD dynamic-mechanism (watchdog/tracking)
    /// measurement metadata over the exact current base. No grant.
    pub async fn tracking_request(
        &self,
    ) -> Result<super::ContinuationRequest, super::FirmwareError> {
        if let Some(s) = &self.sibling {
            s.lifecycle().tracking_request().await
        } else {
            self.firmware
                .as_ref()
                .ok_or(super::FirmwareError::Unsupported)?
                .lifecycle()
                .tracking_request()
                .await
        }
    }
    /// Measurement metadata for the exact bound C21 HT/T/Q power-tracking
    /// program. No RF permission; the separate N21W asset must be installed
    /// before a fresh association to enable the runtime continuation.
    pub async fn rtl8821c_power_tracking_request(
        &self,
    ) -> Result<super::PowerTrackingRequest, super::FirmwareError> {
        self.sibling
            .as_ref()
            .ok_or(super::FirmwareError::Unsupported)?
            .lifecycle()
            .power_tracking_request()
            .await
    }
    /// Distinct exact-H recipient BA emission measurement metadata. No grant.
    pub async fn rx_ba_request(&self) -> Result<super::RxBaRequest, super::FirmwareError> {
        if let Some(s) = &self.sibling {
            s.lifecycle().rx_ba_request().await
        } else {
            self.firmware
                .as_ref()
                .ok_or(super::FirmwareError::Unsupported)?
                .lifecycle()
                .rx_ba_request()
                .await
        }
    }
    /// Exact distinct C21/C22 HT20 emission measurement metadata. No grant.
    pub async fn ht20_request(&self) -> Result<super::Ht20Request, super::FirmwareError> {
        if let Some(s) = &self.sibling {
            s.lifecycle().ht20_request().await
        } else {
            self.firmware
                .as_ref()
                .ok_or(super::FirmwareError::Unsupported)?
                .lifecycle()
                .ht20_request()
                .await
        }
    }
    /// Metadata for the distinct N21L extension; N21S alone remains legacy1M.
    pub async fn rtl8821c_legacy_wmm_request(
        &self,
    ) -> Result<super::C21LegacyWmmRequest, super::FirmwareError> {
        self.sibling
            .as_ref()
            .ok_or(super::FirmwareError::Unsupported)?
            .lifecycle()
            .legacy_wmm_request()
            .await
    }
    /// Metadata for a separately measured C22 legacy12/WMM station recipe.
    /// Neither this request nor N22Cv2 alone grants the optional profile.
    pub async fn rtl8822c_legacy_wmm_request(
        &self,
    ) -> Result<super::C22LegacyWmmRequest, super::FirmwareError> {
        self.firmware
            .as_ref()
            .ok_or(super::FirmwareError::Unsupported)?
            .lifecycle()
            .legacy_wmm_request()
            .await
    }
    /// Exact awake/native station program for external board qualification.
    /// This request and the parked N21P receipt grant no RF authority.
    pub async fn rtl8821c_station_request(
        &self,
    ) -> Result<super::C21StationRequest, super::FirmwareError> {
        self.sibling
            .as_ref()
            .ok_or(super::FirmwareError::Unsupported)?
            .station_request()
            .await
    }
    pub async fn rtl8821c_station_radio_info(&self) -> Option<super::C21StationRadioInfo> {
        match &self.sibling {
            Some(owner) => owner.station_radio_info().await,
            None => None,
        }
    }
    /// Firmware loading is independent of station/radio readiness.
    pub fn firmware_status(&self) -> Option<super::FirmwareStatus> {
        self.firmware
            .as_ref()
            .map(|owner| owner.status())
            .or_else(|| self.sibling.as_ref().map(|owner| owner.status()))
    }
    /// The same immutable factory map captured by the RTL8821CE probe.
    /// Factory country/power fields grant no regulatory or transmit authority.
    pub fn rtl8821c_factory(&self) -> Option<&efuse::Factory8821c> {
        self.sibling.as_ref().map(|owner| owner.factory())
    }
    /// Exact retained calibration-program metadata for external measurement/signing.
    /// This request is not an RF/operating-power authorization.
    pub async fn rtl8821c_calibration_request(
        &self,
    ) -> Result<super::C21CalibrationRequest, super::FirmwareError> {
        self.sibling
            .as_ref()
            .ok_or(super::FirmwareError::Unsupported)?
            .calibration_request()
            .await
    }
    /// Historical IQK receipt; it does not grant packet/automatic-response power.
    pub async fn rtl8821c_calibration_info(&self) -> Option<super::C21CalibrationInfo> {
        match &self.sibling {
            Some(owner) => owner.calibration_info().await,
            None => None,
        }
    }
    /// Exact post-IQK parked operating-power program to measure and sign.
    /// This request grants no packet, response or station authority.
    pub async fn rtl8821c_operating_power_request(
        &self,
    ) -> Result<super::C21OperatingPowerRequest, super::FirmwareError> {
        self.sibling
            .as_ref()
            .ok_or(super::FirmwareError::Unsupported)?
            .operating_request()
            .await
    }
    /// Historical parked TXAGC/readback receipt; MAC TX/RX remain closed.
    pub async fn rtl8821c_operating_power_info(&self) -> Option<super::C21OperatingPowerInfo> {
        match &self.sibling {
            Some(owner) => owner.operating_info().await,
            None => None,
        }
    }
}

impl Interface for Rtw88Device {
    fn name(&self) -> &str {
        self.interface
            .as_ref()
            .map_or(self.diagnostic_name, |device| device.name())
    }
    fn mac(&self) -> [u8; 6] {
        self.mac
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        self.interface
            .as_ref()
            .is_some_and(|device| device.link_up())
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        self.interface
            .as_ref()
            .map_or(&self.rx_ring, |device| device.rx_ring())
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        self.interface
            .as_ref()
            .map_or(&self.tx_ring, |device| device.tx_ring())
    }
}

#[async_trait::async_trait]
impl WirelessNetIface for Rtw88Device {
    fn supports_handshake_offload(&self) -> bool {
        self.interface
            .as_ref()
            .is_some_and(|d| d.supports_handshake_offload())
    }
    fn reports_disconnect_events(&self) -> bool {
        self.interface
            .as_ref()
            .is_some_and(|d| d.reports_disconnect_events())
    }
    fn supports_scan_dwell(&self) -> bool {
        self.interface
            .as_ref()
            .is_some_and(|d| d.supports_scan_dwell())
    }
    fn connected_bssid(&self) -> Option<[u8; 6]> {
        self.interface.as_ref()?.connected_bssid()
    }
    fn cipher_suites(&self) -> &'static [u32] {
        if self.interface.is_some() {
            &[0x000fac04]
        } else {
            &[]
        }
    }
    fn scan_information_elements(&self, bssid: [u8; 6]) -> Option<Vec<u8>> {
        self.interface.as_ref()?.scan_information_elements(bssid)
    }
    fn get_wireless_info(&self) -> WirelessIfaceInfo {
        if let Some(device) = &self.interface {
            return device.get_wireless_info();
        }
        WirelessIfaceInfo {
            base_name: self.name().into(),
            base_mac: self.mac(),
            bands: alloc::vec![],
            modes: narf_wireless::iface::WirelessModes::STATION,
            hw_caps: narf_wireless::iface::HwCaps {
                ht_supported: false,
                vht_supported: false,
                he_supported: false,
                eht_supported: false,
            },
        }
    }
    fn phy_capabilities(&self, band: u32) -> Option<narf_wireless::iface::PhyCapabilities> {
        self.interface.as_ref()?.phy_capabilities(band)
    }

    async fn scan(&self, req: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        match &self.interface {
            Some(device) => device.scan(req).await,
            None => Err(WirelessError::NotSupported),
        }
    }

    async fn associate(&self, req: AssociateRequest) -> Result<(), WirelessError> {
        // Firmware, management-frame exchange, and data rings are not live
        // yet.  Reporting success here used to raise carrier despite the
        // device being incapable of transmitting a single frame.
        match &self.interface {
            Some(device) => device.associate(req).await,
            None => Err(WirelessError::NotSupported),
        }
    }

    async fn disassociate(&self) -> Result<(), WirelessError> {
        if let Some(device) = &self.interface {
            return device.disassociate().await;
        }
        self.link_up.store(false, Ordering::Release);
        Ok(())
    }

    async fn set_config(&self, cfg: WirelessConfig) -> Result<(), WirelessError> {
        // There is no firmware-owned channel or power configuration path in
        // this baseline.  Keep control-plane state aligned with the hardware.
        match &self.interface {
            Some(device) => device.set_config(cfg).await,
            None => Err(WirelessError::NotSupported),
        }
    }
}

impl core::fmt::Debug for Rtw88Device {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtw88Device")
            .field("mac", &self.mac)
            .field("device_id", &self.device_id)
            .field("registers", &self.registers)
            .finish_non_exhaustive()
    }
}

/// Errors raised by the baseline probe path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProbeError {
    /// PCI access failed or bus mastering could not be verifiably parked.
    PciAccess,
    /// The mandatory BAR2 control window could not be mapped.
    RegisterBarMapFailed,
    /// BAR2 cannot cover the registers used by baseline power and EFUSE.
    RegisterBarTooSmall,
    /// Power-on / chip-reset prologue failed. See [`power::PowerError`].
    PowerOn(power::PowerError),
    /// EFUSE read failed. See [`efuse::EfuseError`].
    Efuse(efuse::EfuseError),
}

/// PCI driver match registration. One entry per supported device id —
/// mirrors the `rtw88/pci.c::rtw_pci_id_table` shape.
pub fn register_pci_driver() {
    for &did in ALL_DEV_IDS {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: REALTEK_VENDOR,
                device: did,
            },
            probe,
        });
        narf_bus::register_pci_remove(name_for(did), remove);
    }
}

/// Linux v7.2 `pci.c::rtw_pci_remove`: withdraw the netdev
/// (`rtw_unregister_hw`), then stop and prove the DMA engines idle before
/// the retained owner is dropped. Unproven mappings stay pinned and the
/// address is quarantined against re-initialization.
fn remove(device: BusDevice, _cap: Cap<BusDeviceCap, Write>) {
    let Some(owner) = super::functions::begin_remove(device.addr) else {
        return;
    };
    narf_scheduler::spawn(async move {
        let reclaimed = remove_owner(&owner).await;
        if reclaimed {
            super::functions::reclaimed(&owner);
        }
        narf_console::klog!(
            "rtw88: removed; DMA {}\n",
            if reclaimed {
                "reclaimed"
            } else {
                "pinned, address quarantined"
            }
        );
    });
}
pub(super) async fn remove_owner(owner: &Rtw88Device) -> bool {
    match &owner.interface {
        Some(interface) => {
            interface.withdraw();
            interface.wait_withdrawn().await;
        }
        None => {
            let name = owner.diagnostic_name;
            narf_wireless::registry::unregister(name);
            narf_net::iface::unregister(name);
        }
    }
    let lifecycle = owner
        .firmware
        .as_ref()
        .map(|firmware| firmware.lifecycle())
        .or_else(|| owner.sibling.as_ref().map(|sibling| sibling.lifecycle()));
    match lifecycle {
        Some(lifecycle) => lifecycle.remove().await,
        None => true,
    }
}

/// Probe entry called by `narf-bus::driver_match` when a Realtek
/// vendor/device pair we registered for surfaces.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    let Some(claim) = super::functions::Claim::acquire(device.addr)? else {
        return Ok(());
    };
    // SAFETY: caller (the bus dispatch layer) hands us exclusive
    // BusDeviceCap authority for this device's cfg + BARs.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let result = unsafe { bring_up(&device, &cap) };
    let dev = match result {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };

    let mut dev = dev;
    let mac = dev.mac;
    let did = dev.device_id;
    let interface = dev.interface.clone();
    // Registry authority and the one named shell precede the firmware worker
    // and every station packet publication. Diagnostic/controller views share
    // this exact shell and lifecycle, not a reconstructed radio or channel.
    if let Some(interface) = &interface {
        super::interface::publish(interface.clone())
            .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    } else {
        dev.diagnostic_name = narf_net::iface::register_static("wlan%d", mac, send_frame_unimpl);
    }
    let dev = Arc::new(dev);
    if interface.is_none() {
        narf_wireless::registry::register(dev.clone());
    }
    claim.publish(dev.clone());

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(name_for(did)),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });

    schedule_owner(dev);

    Ok(())
}

pub(super) fn schedule_owner(owner: Arc<Rtw88Device>) {
    if (owner.firmware.is_none() && owner.sibling.is_none()) || owner.interface.is_none() {
        return;
    }
    narf_scheduler::spawn(async move {
        let result = drive_scheduled(
            120,
            || retryable(&owner),
            || {
                let owner = owner.clone();
                async move { provision_owner(&owner).await }
            },
            || narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(500_000_000)),
        )
        .await;
        if let Err(error) = result {
            narf_console::klog!("rtw88 provisioning: {:?}\n", error);
        }
    });
}

/// Keep the runtime BAR choice and minimum register extent in one place.
/// The injected mapper lets smokes verify selection without touching host
/// PCI configuration or changing the global bus registry.
pub(super) fn map_registers_with(
    device: &BusDevice,
    map_control: impl FnOnce(&BusDevice, u8) -> Result<MmioRegion, BarError>,
) -> Result<MmioRegion, ProbeError> {
    // Linux rtw_pci_io_mapping uses PCI BAR2 on all supported rtw88 chips.
    let registers = map_control(device, 2).map_err(|_| ProbeError::RegisterBarMapFailed)?;
    if registers.len < register_window_min(device.id.device) {
        return Err(ProbeError::RegisterBarTooSmall);
    }
    Ok(registers)
}

pub(super) const fn register_window_min(did: u16) -> u64 {
    if matches!(did, RTL_DEV_8821CE | RTL_DEV_8822CE) {
        // Firmware LTE coexistence indirect data at 0x1708 is a dword.
        0x170c
    } else {
        power::REGISTER_WINDOW_MIN
    }
}

/// Bring the chip up: map BAR2 registers, run baseline power-on, read
/// MAC from EFUSE. Pure-IO; no TX/RX ring setup.
///
/// # Safety
/// Caller owns the device's PCI configuration and BARs exclusively.
pub unsafe fn bring_up(
    device: &BusDevice,
    cap: &Cap<BusDeviceCap, Write>,
) -> Result<Rtw88Device, ProbeError> {
    // SAFETY: forwarded exact-function cold probe contract.
    unsafe { bring_up_mode(device, cap, None, None) }
}
/// # Safety
/// Same exclusive BAR/function ownership as bring_up, plus original native
/// DMA/IRQ/callback retirement. Only operating_reset owns this contract.
pub(super) unsafe fn bring_up_reset(
    device: &BusDevice,
    cap: &Cap<BusDeviceCap, Write>,
    _retired: super::operating_reset::Retired,
    claim: &super::functions::ResetClaim,
    name: Option<&'static str>,
) -> Result<Rtw88Device, ProbeError> {
    // SAFETY: forwarded exclusive original-function recovery contract.
    unsafe { bring_up_mode(device, cap, Some(Recovery::Reset(claim)), name) }
}
enum Recovery<'a> {
    Reset(&'a super::functions::ResetClaim),
    Resume(&'a super::functions::ResetClaim, super::power::OffReceipt),
}
impl<'a> Recovery<'a> {
    fn claim(&self) -> &'a super::functions::ResetClaim {
        match self {
            Self::Reset(claim) | Self::Resume(claim, _) => claim,
        }
    }
}
/// # Safety
/// Same actual retired original function/BAR contract as bring_up_reset;
/// off is the original native card-off receipt, retained across system sleep.
pub(super) unsafe fn bring_up_resume(
    device: &BusDevice,
    cap: &Cap<BusDeviceCap, Write>,
    _retired: super::operating_reset::Retired,
    claim: &super::functions::ResetClaim,
    name: &'static str,
    off: super::power::OffReceipt,
) -> Result<Rtw88Device, ProbeError> {
    // SAFETY: forwarded original reserved native resume ownership above.
    unsafe { bring_up_mode(device, cap, Some(Recovery::Resume(claim, off)), Some(name)) }
}
unsafe fn bring_up_mode(
    device: &BusDevice,
    cap: &Cap<BusDeviceCap, Write>,
    mut reset: Option<Recovery<'_>>,
    name: Option<&'static str>,
) -> Result<Rtw88Device, ProbeError> {
    let (registers, mac, factory, sibling_factory) =
        super::pci_park::invoke(cap, || -> Result<_, ProbeError> {
            let registers = map_registers_with(device, |device, index| {
                super::pci_park::map_bar_control(device, cap, index)
            })?;

            let mut checked = reset.as_ref().map(|mode| {
                // SAFETY: original reset reservation and actual producer retirement
                // precede this complete exclusively owned BAR mapping.
                unsafe { power::RecoveryIo::new(&registers, device, cap, mode.claim()) }
            });
            if let Some(io) = checked.as_mut() {
                match reset.take().expect("retained native recovery mode") {
                    Recovery::Reset(_) => power::reset_with(io, device.id.device),
                    Recovery::Resume(_, off) => power::resume_with(io, device.id.device, off),
                }
                .map_err(ProbeError::PowerOn)?;
            } else {
                // SAFETY: original cold-probe exclusive BAR contract.
                unsafe { power::power_on(&registers, device.id.device) }
                    .map_err(ProbeError::PowerOn)?;
            }

            // Decode the sparse physical EFUSE map and select this chip's PCI MAC.
            // SAFETY: BAR2 control registers mapped, power-on done.
            let factory = if device.id.device == RTL_DEV_8822CE {
                // SAFETY: the same powered/exclusive BAR2 invocation above owns
                // this one physical map read, including factory radio identity.
                Some(
                    if let Some(io) = checked.as_mut() {
                        efuse::read_factory_with(io, device.id.device)
                    } else {
                        // SAFETY: original cold-probe exclusive powered BAR invocation;
                        // recovery uses the fixed guarded native backend above.
                        unsafe { efuse::read_factory(&registers, device.id.device) }
                    }
                    .map_err(ProbeError::Efuse)?,
                )
            } else {
                None
            };
            let sibling_factory = if device.id.device == RTL_DEV_8821CE {
                // SAFETY: same current exclusive powered BAR2 invocation. This
                // one read captures the C21 map; C22 offsets/trims are never used.
                Some(
                    if let Some(io) = checked.as_mut() {
                        efuse::read_factory8821c_with(io, device.id.device)
                    } else {
                        // SAFETY: original cold-probe exclusive powered BAR invocation;
                        // recovery uses the fixed guarded native backend above.
                        unsafe { efuse::read_factory8821c(&registers, device.id.device) }
                    }
                    .map_err(ProbeError::Efuse)?,
                )
            } else {
                None
            };
            let mac = match &factory {
                Some(factory) => factory.mac(),
                None if sibling_factory.is_some() => sibling_factory.as_ref().unwrap().mac(),
                // SAFETY: same powered/exclusive BAR2 invocation, sibling geometry.
                None => unsafe { efuse::read_mac(&registers, device.id.device) }
                    .map_err(ProbeError::Efuse)?,
            };

            if checked
                .as_mut()
                .is_some_and(|io| !power::Io::permission(io))
            {
                return Err(ProbeError::PowerOn(power::PowerError::Access));
            }

            Ok((registers, mac, factory, sibling_factory))
        })
        .map_err(|_| ProbeError::PciAccess)??;

    let firmware = if device.id.device == RTL_DEV_8822CE {
        // SAFETY: the exact exclusively owned function completed real chip/cut
        // power reset and factory EFUSE above, with PCI BME/IRQs parked. No
        // previous native owner exists; every later access rechecks authority.
        Some(Arc::new(unsafe {
            super::firmware_native::Firmware::new(
                *device,
                *cap,
                registers,
                factory.ok_or(ProbeError::Efuse(efuse::EfuseError::MacUninitialized))?,
            )
        }))
    } else {
        None
    };
    let sibling = sibling_factory.map(|factory| {
        // SAFETY: exact current C21 post-cold-power/factory ownership above;
        // BME/IRQs are parked and no native owner has been constructed yet.
        Arc::new(unsafe { super::sibling::Sibling::new(*device, *cap, registers, factory) })
    });

    let station_lifecycle = firmware
        .as_ref()
        .map(|firmware| firmware.lifecycle())
        .or_else(|| sibling.as_ref().map(|owner| owner.lifecycle()));
    let interface = station_lifecycle.map(|lifecycle| {
        let name = name.unwrap_or_else(|| narf_net::iface::reserve_name("wlan%d"));
        Arc::new(super::interface::Device::new(
            name,
            mac,
            lifecycle,
            Arc::new(super::station::NativeEnvironment),
        ))
    });
    // Each qualified C21/C22 packet runtime lives in its exact retained shell.
    let (rx_ring, tx_ring) = if interface.is_none() {
        let (_, rx) = channel::<Frame, RX_RING_N>();
        let (tx, _) = channel::<Frame, TX_RING_N>();
        (Some(rx), Some(tx))
    } else {
        (None, None)
    };
    Ok(Rtw88Device {
        bus_addr: device.addr,
        registers,
        mac,
        device_id: device.id.device,
        firmware,
        sibling,
        interface,
        link_up: AtomicBool::new(false),
        rx_ring: IrqSafeSpinLock::new(rx_ring),
        tx_ring: IrqSafeSpinLock::new(tx_ring),
        diagnostic_name: "",
        provisioning: narf_lib::mutex::Mutex::new(()),
        reset_origin: Some(super::operating_reset::Origin::new(*device, *cap)),
    })
}

/// SendFn registered with `narf_net::iface` at probe time. The
/// baseline only delivers "chip detected + MAC readable" — there's
/// no TX ring yet. Returning Err lets the kernel-side TCP stack
/// surface the unimplemented-ness without crashing.
pub fn send_frame_unimpl(_frame: &[u8], _meta: narf_net::TxMeta) -> Result<(), ()> {
    Err(())
}

/// Human-readable name for a known device id. Used as the
/// `PciMatch.name` key + the `BoundDriver.name` value.
pub const fn name_for(did: u16) -> &'static str {
    match did {
        RTL_DEV_8821CE => "rtw88-8821ce",
        RTL_DEV_8822CE => "rtw88-8822ce",
        RTL_DEV_8822BE => "rtw88-8822be",
        _ => "rtw88",
    }
}

/// Test helper — `true` if the static slot has a bound device.
pub fn is_probed() -> bool {
    super::functions::any()
}

/// Borrow the bound controller. Returns `None` if probe hasn't run.
pub fn with_controller<R>(f: impl FnOnce(&Rtw88Device) -> R) -> Option<R> {
    let owner = super::functions::sole()?;
    Some(f(&owner))
}

struct Provisioning {
    firmware: Arc<super::firmware_native::Firmware>,
    interface: Arc<super::interface::Native>,
}
fn provisioning(controller: Option<&Rtw88Device>) -> Result<Provisioning, super::FirmwareError> {
    use super::firmware_lifecycle::Stage;
    let controller = controller.ok_or(super::FirmwareError::State)?;
    if controller.device_id != RTL_DEV_8822CE {
        return Err(super::FirmwareError::Unsupported);
    }
    let firmware = controller
        .firmware
        .as_ref()
        .ok_or(super::FirmwareError::State)?;
    let interface = controller
        .interface
        .as_ref()
        .ok_or(super::FirmwareError::State)?;
    if interface.closed() {
        return Err(super::FirmwareError::Cancelled);
    }
    if !Arc::ptr_eq(&firmware.lifecycle(), &interface.lifecycle)
        || firmware.factory().mac() != controller.mac
        || interface.mac() != controller.mac
        || !matches!(
            firmware.status().stage,
            Stage::Detected
                | Stage::Ready
                | Stage::MacPrepared
                | Stage::PhyTablesPrepared
                | Stage::Calibrated
                | Stage::StationReady
        )
    {
        return Err(super::FirmwareError::State);
    }
    Ok(Provisioning {
        firmware: firmware.clone(),
        interface: interface.clone(),
    })
}
async fn provision_with(
    control: &narf_lib::mutex::Mutex<()>,
    binding: impl FnOnce() -> Result<Provisioning, super::FirmwareError>,
) -> Result<(), super::FirmwareError> {
    use super::firmware_lifecycle::Stage;
    let _control = control.lock().await;
    let retained = binding()?;
    loop {
        if retained.interface.closed() {
            return Err(super::FirmwareError::Cancelled);
        }
        match retained.firmware.status().stage {
            Stage::Detected => {
                retained.firmware.initialize_registered().await?;
            }
            Stage::Ready => {
                retained.firmware.prepare_mac().await?;
            }
            Stage::MacPrepared => {
                retained.firmware.prepare_phy_tables().await?;
            }
            Stage::PhyTablesPrepared => {
                // Asset/policy lookup is pure at this exact parked checkpoint.
                // Missing qualification preserves it for a later explicit call.
                let permission = retained.firmware.qualify_board().await?;
                retained.firmware.prepare_radio(permission).await?;
            }
            Stage::Calibrated => retained
                .interface
                .activate()
                .await
                .map_err(|_| super::FirmwareError::Prerequisite)?,
            Stage::StationReady => return Ok(()),
            _ => return Err(super::FirmwareError::State),
        }
    }
}
pub(crate) async fn drive_scheduled<Step, StepFut, Wait, WaitFut>(
    max_attempts: usize,
    mut retryable: impl FnMut() -> bool,
    mut step: Step,
    mut wait: Wait,
) -> Result<(), super::FirmwareError>
where
    Step: FnMut() -> StepFut,
    StepFut: core::future::Future<Output = Result<(), super::FirmwareError>>,
    Wait: FnMut() -> WaitFut,
    WaitFut: core::future::Future<Output = ()>,
{
    let mut last_err = super::FirmwareError::State;
    for attempt in 0..max_attempts {
        if attempt > 0 {
            wait().await;
        }
        match step().await {
            Ok(()) => return Ok(()),
            Err(err) => {
                last_err = err;
                if !retryable() {
                    return Err(err);
                }
            }
        }
    }
    Err(last_err)
}
/// Continue staged RTL8822CE assets on the exact registered owner. Only pure
/// Detected or completed parked checkpoints resume; started/failed/cancelled
/// work is never reconstructed, reset or replayed. Existing station is a no-op.
pub async fn provision() -> Result<(), super::FirmwareError> {
    let owner = super::functions::sole().ok_or(super::FirmwareError::State)?;
    provision_owner(&owner).await
}
/// Continue only the exact retained PCI function selected by the caller.
/// Retained firmware/device/source invocations still authorize all access.
pub async fn provision_function(addr: narf_bus::BusAddr) -> Result<(), super::FirmwareError> {
    let owner = super::functions::get(addr).ok_or(super::FirmwareError::State)?;
    provision_owner(&owner).await
}
pub fn with_controller_at<R>(
    addr: narf_bus::BusAddr,
    f: impl FnOnce(&Rtw88Device) -> R,
) -> Option<R> {
    let owner = super::functions::get(addr)?;
    Some(f(&owner))
}
fn retryable(owner: &Rtw88Device) -> bool {
    use super::firmware_lifecycle::Stage;
    let stage = owner
        .firmware
        .as_ref()
        .map(|fw| fw.status().stage)
        .or_else(|| owner.sibling.as_ref().map(|fw| fw.status().stage));
    matches!(
        stage,
        Some(
            Stage::Detected
                | Stage::PhyTablesPrepared
                | Stage::Calibration8821cPrepared
                | Stage::Operating8821cPrepared
        )
    ) && owner
        .interface
        .as_ref()
        .is_some_and(|iface| !iface.closed())
}
pub(super) async fn provision_owner(controller: &Rtw88Device) -> Result<(), super::FirmwareError> {
    if let Some(owner) = &controller.sibling {
        let _admission = controller.provisioning.lock().await;
        let interface = controller
            .interface
            .as_ref()
            .ok_or(super::FirmwareError::State)?;
        if interface.closed() {
            return Err(super::FirmwareError::Cancelled);
        }
        owner.provision().await?;
        if interface.closed() {
            return Err(super::FirmwareError::Cancelled);
        }
        if owner.status().stage == super::firmware_lifecycle::Stage::Radio8821cPrepared {
            interface
                .activate()
                .await
                .map_err(|_| super::FirmwareError::Prerequisite)?;
        }
        return Ok(());
    }
    provision_with(&controller.provisioning, || provisioning(Some(controller))).await
}

/// Test-only reset of the bound slot. Avoids cross-test leak when the
/// smoke suite re-probes; gated under `kernel-test`-style cfg so it
/// drops from production binaries.
#[cfg(any(test, feature = "kernel-test"))]
pub fn __reset_for_test() {
    super::functions::reset_for_test();
}

#[cfg(any(test, feature = "kernel-test"))]
mod provision_tests {
    use super::*;
    use core::{
        future::Future,
        task::{Context, Waker},
    };
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn fixture() -> Rtw88Device {
        let address = narf_bus::PcieAddr::new(0xfffd, 0xfc, 0x18, 0);
        let device = BusDevice {
            addr: narf_bus::BusAddr::Pcie(address),
            id: narf_bus::DeviceId {
                vendor: REALTEK_VENDOR,
                device: RTL_DEV_8822CE,
                class: 0x028000,
                subsystem_vendor: REALTEK_VENDOR,
                subsystem_id: 0xfffe,
            },
            kind: narf_bus::BusKind::Pcie {
                addr: address,
                cfg_phys: narf_memory::PhysAddr::new(0),
            },
        };
        let cap = Cap::<BusDeviceCap, Write>::bootstrap();
        cap.revoke();
        let registers = MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: 0,
            len: 0x5000,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        };
        let mut logical = [255; 768];
        logical[0x120..0x126].copy_from_slice(&[2, 4, 6, 8, 10, 12]);
        let factory = super::super::efuse::Factory::for_test_with_trims(logical, [1; 19]).unwrap();
        let mac = factory.mac();
        // SAFETY: explicitly inert revoked-cap owner. Admission tests never
        // start this object's deliberately invalid PCI/MMIO mappings.
        let firmware = Arc::new(unsafe {
            super::super::firmware_native::Firmware::new(device, cap, registers, factory)
        });
        let interface = Arc::new(super::super::interface::Device::new(
            "rtw88-provision-fixture",
            mac,
            firmware.lifecycle(),
            Arc::new(super::super::station::NativeEnvironment),
        ));
        Rtw88Device {
            bus_addr: device.addr,
            registers,
            mac,
            device_id: RTL_DEV_8822CE,
            firmware: Some(firmware),
            sibling: None,
            interface: Some(interface),
            link_up: AtomicBool::new(false),
            rx_ring: IrqSafeSpinLock::new(None),
            tx_ring: IrqSafeSpinLock::new(None),
            diagnostic_name: "rtw88-provision-fixture",
            provisioning: narf_lib::mutex::Mutex::new(()),
            reset_origin: None,
        }
    }
    fn smoke_rtw8822ce_public_provision_retains_bindings_and_cancels_before_admission() -> TestResult
    {
        if provisioning(None).is_ok() {
            return TestResult::Fail("provision admitted absent controller");
        }
        let mut controller = fixture();
        let admitted = provisioning(Some(&controller)).unwrap();
        if !Arc::ptr_eq(&admitted.firmware, controller.firmware.as_ref().unwrap())
            || !Arc::ptr_eq(&admitted.interface, controller.interface.as_ref().unwrap())
            || !Arc::ptr_eq(
                &admitted.firmware.lifecycle(),
                &admitted.interface.lifecycle,
            )
        {
            return TestResult::Fail("provision reconstructed exact firmware/interface lifecycle");
        }
        let control = narf_lib::mutex::Mutex::new(());
        let guard = control.try_lock().unwrap();
        let entered = AtomicBool::new(false);
        {
            let mut future = core::pin::pin!(provision_with(&control, || {
                entered.store(true, Ordering::Release);
                provisioning(Some(&controller))
            }));
            if !future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
            {
                return TestResult::Fail("provision bypassed async serialization");
            }
        }
        drop(guard);
        if entered.load(Ordering::Acquire)
            || controller.firmware_status().unwrap().stage != super::super::FirmwareStage::Detected
            || provisioning(Some(&controller)).is_err()
        {
            return TestResult::Fail("cancelled provisioning wait consumed retained owner");
        }
        controller.device_id = RTL_DEV_8821CE;
        if provisioning(Some(&controller)).is_ok() {
            return TestResult::Fail("diagnostic sibling admitted for station provisioning");
        }
        controller.device_id = RTL_DEV_8822CE;
        let original = controller.interface.take().unwrap();
        let mismatched = Arc::new(super::super::interface::Device::new(
            "rtw88-wrong-lifecycle",
            controller.mac,
            Arc::new(super::super::firmware_lifecycle::Lifecycle::new(
                RTL_DEV_8822CE,
            )),
            Arc::new(super::super::station::NativeEnvironment),
        ));
        controller.interface = Some(mismatched);
        if provisioning(Some(&controller)).is_ok() {
            return TestResult::Fail("provision accepted independent interface owner");
        }
        controller.interface = Some(original);
        let lifecycle = controller.firmware.as_ref().unwrap().lifecycle();
        if narf_scheduler::block_on(
            lifecycle.initialize_bytes(|| Err(super::super::FirmwareError::Memory), Vec::new()),
        ) != Err(super::super::FirmwareError::Memory)
            || lifecycle.status().stage != super::super::FirmwareStage::Failed
            || provisioning(Some(&controller)).is_ok()
        {
            return TestResult::Fail(
                "failed actual allocation attempt reopened public provisioning",
            );
        }
        controller.interface.as_ref().unwrap().admission().close();
        if provisioning(Some(&controller)).is_ok() {
            return TestResult::Fail("closed one-shot interface reopened provisioning");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtw88",
        smoke_rtw8822ce_public_provision_retains_bindings_and_cancels_before_admission
    );
    fn smoke_rtw88_multiple_function_selection_serialization_and_quarantine() -> TestResult {
        use super::super::functions;
        if functions::any() {
            return TestResult::Skip("physical RTW88 functions present");
        }
        struct Cleanup(Vec<Arc<Rtw88Device>>);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                for owner in &self.0 {
                    functions::reclaimed(owner);
                }
            }
        }
        let first = Arc::new(fixture());
        let mut other = fixture();
        other.bus_addr = narf_bus::BusAddr::Pcie(narf_bus::PcieAddr::new(0xfffd, 0xfc, 0x19, 0));
        let second = Arc::new(other);
        let mut cleanup = Cleanup(alloc::vec![first.clone(), second.clone()]);
        let Some(claim) = functions::Claim::acquire(first.bus_addr).ok().flatten() else {
            return TestResult::Fail("first exact-function reservation refused");
        };
        if functions::Claim::acquire(first.bus_addr).is_ok() {
            return TestResult::Fail("pending function claim admitted another native producer");
        }
        claim.publish(first.clone());
        functions::Claim::acquire(second.bus_addr)
            .unwrap()
            .unwrap()
            .publish(second.clone());
        if with_controller(|_| ()).is_some()
            || functions::sole().is_some()
            || with_controller_at(second.bus_addr, |owner| {
                core::ptr::eq(owner, second.as_ref())
            }) != Some(true)
        {
            return TestResult::Fail("implicit provisioning selected an arbitrary function");
        }
        let mut implicit = Box::pin(provision());
        if implicit
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            != core::task::Poll::Ready(Err(super::super::FirmwareError::State))
        {
            return TestResult::Fail("ambiguous public provisioning touched a retained owner");
        }
        let held = first.provisioning.try_lock().unwrap();
        let mut first_wait = Box::pin(provision_with(&first.provisioning, || {
            Err(super::super::FirmwareError::State)
        }));
        let mut second_step = Box::pin(provision_with(&second.provisioning, || {
            Err(super::super::FirmwareError::Unsupported)
        }));
        if !first_wait
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
            || second_step
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                != core::task::Poll::Ready(Err(super::super::FirmwareError::Unsupported))
        {
            return TestResult::Fail("provisioning mutex crossed native function lifetimes");
        }
        drop(first_wait);
        drop(second_step);
        drop(held);
        let removed = functions::begin_remove(first.bus_addr).unwrap();
        if !Arc::ptr_eq(&removed, &first)
            || functions::get(first.bus_addr).is_some()
            || functions::Claim::acquire(first.bus_addr).is_ok()
            || functions::get(second.bus_addr).is_none_or(|owner| !Arc::ptr_eq(&owner, &second))
        {
            return TestResult::Fail("quarantine escaped its original BDF");
        }
        functions::reclaimed(&first);
        let fresh = Arc::new(fixture());
        functions::Claim::acquire(fresh.bus_addr)
            .unwrap()
            .unwrap()
            .publish(fresh.clone());
        cleanup.0.push(fresh.clone());
        functions::reclaimed(&first);
        if functions::get(fresh.bus_addr).is_none_or(|owner| !Arc::ptr_eq(&owner, &fresh)) {
            return TestResult::Fail("stale removal released a new function owner");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtw88/multiple",
        smoke_rtw88_multiple_function_selection_serialization_and_quarantine
    );
}
