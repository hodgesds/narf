//! rtlwifi PCIe transport — device-ID table, BAR mapping, probe.
//!
//! The rtlwifi family uses a single BAR0 window (typically 16 KiB) for all
//! register accesses.  Unlike rtw88 there is no separate BAR2 data window.
//!
//! ## Linux reference
//!
//! - `rtlwifi/pci.c::rtl_pci_probe` — probe entry, BAR0 ioremap
//! - `rtlwifi/pci.c::rtl_pci_id_tbl` — `pci_device_id` table
//! - `rtlwifi/pci.h` — queue / descriptor constants

#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_bus::{map_bar, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_ipc::{channel, Consumer, Producer};
use narf_lib::sync::IrqSafeSpinLock;
use narf_net::{Frame, Interface, RX_RING_N, TX_RING_N};
use narf_wireless::{
    AssociateRequest, BssInfo, ScanRequest, WirelessConfig, WirelessError, WirelessIfaceInfo,
    WirelessNetIface,
};

use super::efuse;
use super::irq;
use super::mac;
use super::power;
use super::regs::*;

/// A bound rtlwifi PCIe device.  Holds BAR0 + MAC + device-ID.
pub struct RtlwifiDevice {
    pub mmio_bar0: MmioRegion,
    pub mac: [u8; MAC_ADDR_LEN],
    pub device_id: u16,
    pub link_up: AtomicBool,
    pub rx_ring: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    pub tx_ring: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
}

impl Interface for RtlwifiDevice {
    fn name(&self) -> &str {
        "wlan3"
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
                ht_supported: true,
                vht_supported: matches!(self.device_id, RTL_DEV_8821AE | RTL_DEV_8822BE),
                he_supported: false,
                eht_supported: false,
            },
        }
    }

    async fn scan(&self, _req: ScanRequest) -> Result<alloc::vec::Vec<BssInfo>, WirelessError> {
        Err(WirelessError::NotSupported)
    }

    async fn associate(&self, _req: AssociateRequest) -> Result<(), WirelessError> {
        self.link_up.store(true, Ordering::Release);
        Ok(())
    }

    async fn disassociate(&self) -> Result<(), WirelessError> {
        self.link_up.store(false, Ordering::Release);
        Ok(())
    }

    async fn set_config(&self, _cfg: WirelessConfig) -> Result<(), WirelessError> {
        Ok(())
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
    Bar0MapFailed,
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
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }

    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::BUS_MASTER,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    // SAFETY: caller holds exclusive BusDeviceCap for this device.
    let result = unsafe { bring_up(&device) };
    let dev = match result {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };

    let mac = dev.mac;
    let did = dev.device_id;
    *CONTROLLER.lock() = Some(dev);

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(name_for(did)),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });

    narf_net::iface::register("wlan1", mac, send_frame_unimpl);
    Ok(())
}

/// Map BAR0, walk the chip-specific power-on flow, run the MAC-init
/// sequence, read EFUSE MAC, unmask interrupts, build the device object.
///
/// This is the end-to-end bring-up path that takes the chip from
/// "BAR0 just mapped" to "ready for FW download" — every step Linux
/// runs between `rtl_pci_probe` (`rtlwifi/pci.c`) and the
/// `_rtl<ver>_init_mac` return.  FW download itself is deferred to
/// the wireless-runtime caller via [`crate::rtlwifi::h2c::download_fw`]
/// once the FS layer has the blob in memory.
///
/// # Safety
/// Caller must own the device BARs exclusively.
pub unsafe fn bring_up(device: &BusDevice) -> Result<RtlwifiDevice, ProbeError> {
    // SAFETY: caller-asserted.
    let mmio_bar0 = unsafe { map_bar(device, 0) }.map_err(|_| ProbeError::Bar0MapFailed)?;
    let did = device.id.device;

    // Power-on (cardemu → active).  Optional — chips not in the table
    // are tolerated for forward compat; the rest fall through to MAC
    // init unchanged.
    if power::power_on_table_for(did).is_some() {
        // SAFETY: BAR0 mapped, no other thread holds the chip.
        unsafe { power::power_on(&mmio_bar0, did) }?;
    }

    // MAC init (LLT, CR open, RCR/TCR seed, HISR clear).
    // SAFETY: BAR0 mapped + chip powered on.
    unsafe { mac::init_mac(&mmio_bar0, did) }?;

    // Mask in the default interrupts (HIMR + HIMRE).
    // SAFETY: same.
    unsafe { irq::enable_interrupts(&mmio_bar0) };

    // SAFETY: BAR0 mapped and owned.
    let mac = unsafe { efuse::read_mac(&mmio_bar0) }.map_err(ProbeError::Efuse)?;

    let (_rx_prod, rx_cons) = channel::<Frame, RX_RING_N>();
    let (tx_prod, _tx_cons) = channel::<Frame, TX_RING_N>();

    let device_arc = alloc::sync::Arc::new(RtlwifiDevice {
        mmio_bar0: mmio_bar0.clone(),
        mac,
        device_id: device.id.device,
        link_up: AtomicBool::new(false),
        rx_ring: IrqSafeSpinLock::new(Some(rx_cons)),
        tx_ring: IrqSafeSpinLock::new(Some(tx_prod)),
    });
    narf_wireless::registry::register(device_arc);

    Ok(RtlwifiDevice {
        mmio_bar0,
        mac,
        device_id: device.id.device,
        link_up: AtomicBool::new(false),
        rx_ring: IrqSafeSpinLock::new(None),
        tx_ring: IrqSafeSpinLock::new(None),
    })
}

pub fn send_frame_unimpl(_frame: &[u8]) -> Result<(), ()> {
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
        RTL_DEV_8822BE => "rtlwifi-8822be",
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
