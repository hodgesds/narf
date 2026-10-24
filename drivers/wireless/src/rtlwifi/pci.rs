//! rtlwifi PCIe transport — device-ID table, BAR mapping, probe.
//!
//! Linux per-chip `rtl_hal_cfg.bar_id` selects BAR2 for the supported PCIe
//! parts. It is mapped as Device memory for all control-register accesses.
//!
//! ## Linux reference
//!
//! - `rtlwifi/pci.c::rtl_pci_probe` — probe entry, per-chip BAR2 ioremap
//! - `rtlwifi/pci.c::rtl_pci_id_tbl` — `pci_device_id` table
//! - `rtlwifi/pci.h` — queue / descriptor constants

#![allow(dead_code)]

extern crate alloc;

use alloc::{boxed::Box, sync::Arc};
use core::sync::atomic::{AtomicBool, Ordering};

use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_ipc::{channel, Consumer, Producer};
use narf_lib::sync::IrqSafeSpinLock;
use narf_net::{Frame, Interface, RX_RING_N, TX_RING_N};
use narf_wireless::{
    AssociateRequest, BssInfo, ScanRequest, WirelessConfig, WirelessError, WirelessIfaceInfo,
    WirelessNetIface,
};

use super::efuse;
use super::firmware_native::PciIo;
use super::firmware_transport::Owner as FirmwareOwner;
use super::irq;
use super::mac;
use super::power;
use super::regs::*;

/// A bound rtlwifi PCIe device.  Holds BAR2 + MAC + device-ID.
pub struct RtlwifiDevice {
    /// Retained bus identity; a repeat probe must not park the active owner.
    pub(crate) bus_addr: narf_bus::BusAddr,
    pub registers: MmioRegion,
    pub mac: [u8; MAC_ADDR_LEN],
    pub device_id: u16,
    /// One retained authenticated firmware attempt for the qualified 8188EE profile.
    pub(super) firmware: Option<Arc<FirmwareOwner<PciIo>>>,
    pub(super) prepared: Option<Arc<super::prepare_native::Retained>>,
    pub(super) factory: Option<Arc<super::efuse::Factory>>,
    pub link_up: AtomicBool,
    pub rx_ring: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    pub tx_ring: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
}

/// This device's interface name, `wlan%d` as Linux `dev_alloc_name` picks
/// it; set when the interface registers.
static IFNAME: IrqSafeSpinLock<&'static str> = IrqSafeSpinLock::new("");

impl RtlwifiDevice {
    /// Firmware-ready is diagnostic CPU readiness, never station readiness.
    pub fn firmware_status(&self) -> Option<super::firmware_transport::Status> {
        self.firmware.as_ref().map(|owner| owner.status())
    }
    /// Inactive descriptor/LLT readiness remains below RF and packet admission.
    /// None covers unallocated state or async preparation holding its guard.
    pub fn native_preparation_status(&self) -> Option<super::prepare::Phase> {
        let prepared = self.prepared.as_ref()?.try_lock()?;
        prepared.as_ref().map(|owner| owner.phase())
    }
}

impl Interface for RtlwifiDevice {
    fn name(&self) -> &str {
        *IFNAME.lock()
    }
    fn mac(&self) -> [u8; 6] {
        self.mac
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        self.link_up.load(Ordering::Acquire)
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.rx_ring
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx_ring
    }
}

#[async_trait::async_trait]
impl WirelessNetIface for RtlwifiDevice {
    fn get_wireless_info(&self) -> WirelessIfaceInfo {
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

    async fn scan(&self, _req: ScanRequest) -> Result<alloc::vec::Vec<BssInfo>, WirelessError> {
        Err(WirelessError::NotSupported)
    }

    async fn associate(&self, _req: AssociateRequest) -> Result<(), WirelessError> {
        // Firmware, management-frame exchange, and data rings are not live
        // yet.  Never report carrier merely because userspace requested an
        // association.
        Err(WirelessError::NotSupported)
    }

    async fn disassociate(&self) -> Result<(), WirelessError> {
        self.link_up.store(false, Ordering::Release);
        Ok(())
    }

    async fn set_config(&self, _cfg: WirelessConfig) -> Result<(), WirelessError> {
        // Channel/power configuration belongs to the firmware-backed MAC
        // path, which has not been implemented for this baseline.
        Err(WirelessError::NotSupported)
    }
}

impl core::fmt::Debug for RtlwifiDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RtlwifiDevice")
            .field("device_id", &self.device_id)
            .field("mac", &self.mac)
            .finish_non_exhaustive()
    }
}

/// Errors from the probe path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProbeError {
    /// PCI access failed or bus mastering could not be verifiably parked.
    PciAccess,
    RegisterBarMapFailed,
    Efuse(efuse::EfuseError),
    PowerOn(power::PwrSeqError),
    MacInit(mac::MacInitError),
}

impl From<power::PwrSeqError> for ProbeError {
    fn from(e: power::PwrSeqError) -> Self {
        ProbeError::PowerOn(e)
    }
}

impl From<mac::MacInitError> for ProbeError {
    fn from(e: mac::MacInitError) -> Self {
        ProbeError::MacInit(e)
    }
}

/// Single-device static slot.
static CONTROLLER: IrqSafeSpinLock<Option<RtlwifiDevice>> = IrqSafeSpinLock::new(None);

/// Register one PCI-match entry per supported device ID.
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

/// PCI probe callback.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    let bound = CONTROLLER.lock().as_ref().map(|owner| owner.bus_addr);
    match crate::rtw88::pci_park::admission(bound, device.addr) {
        crate::rtw88::pci_park::Admission::Bound => return Ok(()),
        crate::rtw88::pci_park::Admission::ParkExtra => {
            crate::rtw88::pci_park::invoke(&cap, || crate::rtw88::pci_park::park(&device, &cap))
                .map_err(|_| narf_bus::ProbeError::BadDevice)?
                .map_err(|_| narf_bus::ProbeError::BadDevice)?;
            return Ok(());
        }
        crate::rtw88::pci_park::Admission::Initialize => {}
    }

    // SAFETY: caller holds exclusive BusDeviceCap for this device.
    let result = unsafe { bring_up(&device, &cap) };
    let dev = match result {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };

    let mac = dev.mac;
    let did = dev.device_id;
    let firmware = dev.firmware.clone();
    let prepared = dev.prepared.clone();
    let factory = dev.factory.clone();
    *CONTROLLER.lock() = Some(dev);

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(name_for(did)),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });

    *IFNAME.lock() = narf_net::iface::register_static("wlan%d", mac, send_frame_unimpl);
    if let (Some(firmware), Some(prepared), Some(factory)) = (firmware, prepared, factory) {
        // The retained controller/interface own this attempt before its first
        // register access. No IRQ-disabling guard survives into the task.
        narf_scheduler::spawn(async move {
            if let Err(error) =
                super::prepare_native::initialize_registered(firmware, prepared, factory).await
            {
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "rtlwifi-8188ee firmware/native preparation: {:?}",
                    error
                );
            }
        });
    }
    Ok(())
}

/// Park PCI DMA, map BAR2, apply the existing power table and read factory
/// EFUSE identity with device IRQs masked. Retains the qualified 8188EE
/// firmware owner; probe starts it asynchronously after publishing ownership.
/// Its one-shot continuation retains inactive LLT/native rings. Packet DMA,
/// RF/BB, IRQ and station admission remain closed.
///
/// # Safety
/// Caller owns the device's PCI configuration and BARs exclusively.
pub unsafe fn bring_up(
    device: &BusDevice,
    cap: &Cap<BusDeviceCap, Write>,
) -> Result<RtlwifiDevice, ProbeError> {
    let did = device.id.device;
    let (registers, factory) = crate::rtw88::pci_park::invoke(cap, || -> Result<_, ProbeError> {
        let registers = crate::rtw88::pci_park::map_bar_control(device, cap, 2)
            .map_err(|_| ProbeError::RegisterBarMapFailed)?;
        if registers.len < REG_EFUSE_ACCESS + 1
            || (device.id.device == RTL_DEV_8188EE && registers.len < 0x2000)
        {
            return Err(ProbeError::RegisterBarMapFailed);
        }

        // Power-on (cardemu → active).  Optional — chips not in the table
        // are tolerated for forward compat; the rest fall through to MAC
        // init unchanged.
        if power::power_on_table_for(did).is_some() {
            // SAFETY: BAR2 mapped, no other thread holds the chip.
            unsafe { power::power_on(&registers, did) }?;
        }

        // The diagnostic identity stage does not own packet DMA or an IRQ
        // handler. Keep interrupt masks clear and defer MAC TX/RX/ring setup.
        // SAFETY: BAR2 mapped and owned.
        unsafe { irq::disable_interrupts(&registers) };

        let function = match device.addr {
            narf_bus::BusAddr::Pcie(addr) => addr.function,
            _ => return Err(ProbeError::Efuse(efuse::EfuseError::UnsupportedChip)),
        };
        // SAFETY: BAR2 mapped and owned, with EFUSE read clocks configured by
        // the helper. PCI function selects the dual-MAC 8192DE factory address.
        let factory =
            unsafe { efuse::read_factory(&registers, did, function) }.map_err(ProbeError::Efuse)?;

        Ok((registers, factory))
    })
    .map_err(|_| ProbeError::PciAccess)??;
    let mac = factory.mac;
    let factory = (did == RTL_DEV_8188EE).then(|| Arc::new(factory));

    let (_rx_prod, rx_cons) = channel::<Frame, RX_RING_N>();
    let (tx_prod, _tx_cons) = channel::<Frame, TX_RING_N>();

    let firmware = if did == RTL_DEV_8188EE {
        // SAFETY: probe parked this exact function and exclusively owns BAR2.
        // PciIo rechecks current authority and parked BME at every access.
        Some(Arc::new(FirmwareOwner::new(
            unsafe { PciIo::new(*device, *cap, registers) },
            did,
        )))
    } else {
        None
    };
    let prepared = firmware
        .as_ref()
        .map(|_| Arc::new(super::prepare_native::Retained::new(None)));
    let device_arc = Arc::new(RtlwifiDevice {
        bus_addr: device.addr,
        registers,
        mac,
        device_id: device.id.device,
        firmware: firmware.clone(),
        prepared: prepared.clone(),
        factory: factory.clone(),
        link_up: AtomicBool::new(false),
        rx_ring: IrqSafeSpinLock::new(Some(rx_cons)),
        tx_ring: IrqSafeSpinLock::new(Some(tx_prod)),
    });
    narf_wireless::registry::register(device_arc);

    Ok(RtlwifiDevice {
        bus_addr: device.addr,
        registers,
        mac,
        device_id: device.id.device,
        firmware,
        prepared,
        factory,
        link_up: AtomicBool::new(false),
        rx_ring: IrqSafeSpinLock::new(None),
        tx_ring: IrqSafeSpinLock::new(None),
    })
}

pub fn send_frame_unimpl(_frame: &[u8], _meta: narf_net::TxMeta) -> Result<(), ()> {
    Err(())
}

/// Human-readable driver name for a given device ID.
pub const fn name_for(did: u16) -> &'static str {
    match did {
        RTL_DEV_8188EE => "rtlwifi-8188ee",
        RTL_DEV_8192CE => "rtlwifi-8192ce",
        RTL_DEV_8192CE_ALT => "rtlwifi-8192ce-alt",
        RTL_DEV_8192DE => "rtlwifi-8192de",
        RTL_DEV_8192EE => "rtlwifi-8192ee",
        RTL_DEV_8723AE => "rtlwifi-8723ae",
        RTL_DEV_8723BE => "rtlwifi-8723be",
        RTL_DEV_8821AE => "rtlwifi-8821ae",
        _ => "rtlwifi",
    }
}

/// True if a device has been bound through probe.
pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Borrow the bound controller.
pub fn with_controller<R>(f: impl FnOnce(&RtlwifiDevice) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

/// Test-only reset.
#[cfg(any(test, feature = "kernel-test"))]
pub fn __reset_for_test() {
    *CONTROLLER.lock() = None;
}
