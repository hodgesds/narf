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
/// derived MAC. Single-instance for the baseline (every laptop ships
/// at most one of these); multi-radio comes with the follow-up.
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
}

/// This device's interface name, `wlan%d` as Linux `dev_alloc_name` picks
/// it; set when the interface registers.
static IFNAME: IrqSafeSpinLock<&'static str> = IrqSafeSpinLock::new("");

impl Rtw88Device {
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
            .map_or(*IFNAME.lock(), |device| device.name())
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

/// Single-instance live device. The baseline only supports one bound
/// RTW88; the follow-up will switch to a `Vec` keyed by domain id.
static CONTROLLER: IrqSafeSpinLock<Option<Arc<Rtw88Device>>> = IrqSafeSpinLock::new(None);
static PROBING: AtomicBool = AtomicBool::new(false);

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
    }
}

/// Probe entry called by `narf-bus::driver_match` when a Realtek
/// vendor/device pair we registered for surfaces.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    super::probe_guard::run(&PROBING, || probe_exclusive(device, cap))
        .unwrap_or(Err(narf_bus::ProbeError::BadDevice))
}

fn probe_exclusive(
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
    // Skip if a device is already bound. Real laptops only ship one
    // RTW88; a second probe is a re-enumeration race.
    let bound = CONTROLLER.lock().as_ref().map(|owner| owner.bus_addr);
    match crate::rtw88::pci_park::admission(bound, device.addr) {
        crate::rtw88::pci_park::Admission::Bound => return Ok(()),
        crate::rtw88::pci_park::Admission::ParkExtra => {
            super::pci_park::invoke(&cap, || super::pci_park::park(&device, &cap))
                .map_err(|_| narf_bus::ProbeError::BadDevice)?
                .map_err(|_| narf_bus::ProbeError::BadDevice)?;
            return Ok(());
        }
        crate::rtw88::pci_park::Admission::Initialize => {}
    }

    // SAFETY: caller (the bus dispatch layer) hands us exclusive
    // BusDeviceCap authority for this device's cfg + BARs.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let result = unsafe { bring_up(&device, &cap) };
    let dev = match result {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };

    let dev = Arc::new(dev);
    let mac = dev.mac;
    let did = dev.device_id;
    let firmware = dev.firmware.clone();
    let sibling = dev.sibling.clone();
    let interface = dev.interface.clone();
    // Registry authority and the one named shell precede the firmware worker
    // and every station packet publication. Diagnostic/controller views share
    // this exact shell and lifecycle, not a reconstructed radio or channel.
    if let Some(interface) = &interface {
        super::interface::publish(interface.clone())
            .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    } else {
        *IFNAME.lock() = narf_net::iface::register_static("wlan%d", mac, send_frame_unimpl);
        narf_wireless::registry::register(dev.clone());
    }
    *CONTROLLER.lock() = Some(dev);

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(name_for(did)),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });

    if firmware.is_some() && interface.is_some() {
        // Boot and public staged provisioning share the same admission lock
        // and phase-aware retained-owner continuation.
        narf_scheduler::spawn(async move {
            if let Err(error) = drive_scheduled(
                120,
                || {
                    with_controller(|dev| {
                        dev.firmware.as_ref().is_some_and(|fw| {
                            matches!(
                                fw.status().stage,
                                super::firmware_lifecycle::Stage::Detected
                                    | super::firmware_lifecycle::Stage::PhyTablesPrepared
                                    | super::firmware_lifecycle::Stage::Calibration8821cPrepared
                                    | super::firmware_lifecycle::Stage::Operating8821cPrepared
                            )
                        }) && dev.interface.as_ref().is_some_and(|iface| !iface.closed())
                    })
                    .unwrap_or(false)
                },
                provision,
                || narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(500_000_000)),
            )
            .await
            {
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "rtw88-8822ce provisioning: {:?}",
                    error
                );
            }
        });
    }
    if sibling.is_some() {
        narf_scheduler::spawn(async {
            if let Err(error) = drive_scheduled(
                120,
                || {
                    with_controller(|dev| {
                        dev.sibling.as_ref().is_some_and(|owner| {
                            matches!(
                                owner.status().stage,
                                super::firmware_lifecycle::Stage::Detected
                                    | super::firmware_lifecycle::Stage::PhyTablesPrepared
                            )
                        })
                    })
                    .unwrap_or(false)
                },
                provision,
                || narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(500_000_000)),
            )
            .await
            {
                narf_console::klog!(
                    "rtw88-8821ce retained calibration provisioning: {:?}\n",
                    error
                );
            }
        });
    }

    Ok(())
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
    let (registers, mac, factory, sibling_factory) =
        super::pci_park::invoke(cap, || -> Result<_, ProbeError> {
            let registers = map_registers_with(device, |device, index| {
                super::pci_park::map_bar_control(device, cap, index)
            })?;

            // Run the chip/cut-filtered Linux PCI power sequence. Bus mastering
            // remains parked throughout power cycling and read-only EFUSE access.
            // SAFETY: BAR2 control registers mapped + owned.
            unsafe {
                power::power_on(&registers, device.id.device).map_err(ProbeError::PowerOn)?;
            }

            // Decode the sparse physical EFUSE map and select this chip's PCI MAC.
            // SAFETY: BAR2 control registers mapped, power-on done.
            let factory = if device.id.device == RTL_DEV_8822CE {
                // SAFETY: the same powered/exclusive BAR2 invocation above owns
                // this one physical map read, including factory radio identity.
                Some(
                    unsafe { efuse::read_factory(&registers, device.id.device) }
                        .map_err(ProbeError::Efuse)?,
                )
            } else {
                None
            };
            let sibling_factory = if device.id.device == RTL_DEV_8821CE {
                // SAFETY: same current exclusive powered BAR2 invocation. This
                // one read captures the C21 map; C22 offsets/trims are never used.
                Some(
                    unsafe { efuse::read_factory8821c(&registers, device.id.device) }
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
        let name = narf_net::iface::reserve_name("wlan%d");
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
    CONTROLLER.lock().is_some()
}

/// Borrow the bound controller. Returns `None` if probe hasn't run.
pub fn with_controller<R>(f: impl FnOnce(&Rtw88Device) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(|owner| f(owner))
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
static PROVISIONING: narf_lib::mutex::Mutex<()> = narf_lib::mutex::Mutex::new(());
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
    let sibling = {
        CONTROLLER
            .lock()
            .as_ref()
            .and_then(|dev| dev.sibling.clone())
    };
    if let Some(owner) = sibling {
        let _admission = PROVISIONING.lock().await;
        let interface = CONTROLLER
            .lock()
            .as_ref()
            .and_then(|dev| dev.interface.clone())
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
    provision_with(&PROVISIONING, || {
        let controller = CONTROLLER.lock();
        provisioning(controller.as_deref())
    })
    .await
}

/// Test-only reset of the bound slot. Avoids cross-test leak when the
/// smoke suite re-probes; gated under `kernel-test`-style cfg so it
/// drops from production binaries.
#[cfg(any(test, feature = "kernel-test"))]
pub fn __reset_for_test() {
    *CONTROLLER.lock() = None;
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
}
