//! RTW88 PCI probe.
//!
//! Driver-match registration and BAR2 control-register mapping, matching
//! Linux `rtw88/pci.c::rtw_pci_io_mapping` (`bar_id = 2`). BAR2 is
//! the register aperture; firmware bytes cannot be copied into it as SRAM.
//!
//! What this file does *not* do, intentionally:
//!   - MSI/MSI-X vector setup. The baseline is "chip detected + MAC
//!     readable"; IRQ delivery lands with the TX/RX ring follow-up.
//!   - Packet runtime. RTL8822CE starts one retained authenticated firmware
//!     attempt after probe publishes ownership; carrier and packet gates stay down.

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
    /// PCI device id we matched on — controls per-chip quirks in
    /// follow-up commits. Today it just feeds `name_for`.
    pub device_id: u16,
    /// The exact post-power native owner, shared by controller and interface.
    pub(super) firmware: Option<Arc<super::firmware_native::Firmware>>,
    pub link_up: AtomicBool,
    pub rx_ring: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    pub tx_ring: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
}

/// This device's interface name, `wlan%d` as Linux `dev_alloc_name` picks
/// it; set when the interface registers.
static IFNAME: IrqSafeSpinLock<&'static str> = IrqSafeSpinLock::new("");

impl Rtw88Device {
    /// Firmware loading is independent of station/radio readiness.
    pub fn firmware_status(&self) -> Option<super::FirmwareStatus> {
        self.firmware.as_ref().map(|owner| owner.status())
    }
}

impl Interface for Rtw88Device {
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
impl WirelessNetIface for Rtw88Device {
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

    async fn scan(&self, _req: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        Err(WirelessError::NotSupported)
    }

    async fn associate(&self, _req: AssociateRequest) -> Result<(), WirelessError> {
        // Firmware, management-frame exchange, and data rings are not live
        // yet.  Reporting success here used to raise carrier despite the
        // device being incapable of transmitting a single frame.
        Err(WirelessError::NotSupported)
    }

    async fn disassociate(&self) -> Result<(), WirelessError> {
        self.link_up.store(false, Ordering::Release);
        Ok(())
    }

    async fn set_config(&self, _cfg: WirelessConfig) -> Result<(), WirelessError> {
        // There is no firmware-owned channel or power configuration path in
        // this baseline.  Keep control-plane state aligned with the hardware.
        Err(WirelessError::NotSupported)
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
static CONTROLLER: IrqSafeSpinLock<Option<Rtw88Device>> = IrqSafeSpinLock::new(None);
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

    let mac = dev.mac;
    let did = dev.device_id;
    let firmware = dev.firmware.clone();
    *CONTROLLER.lock() = Some(dev);

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(name_for(did)),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });

    // Register the iface with `narf-net` so the kernel-side TCP
    // stack sees the MAC. send_frame returns Err for now — this
    // commit only delivers "chip detected + MAC readable."
    *IFNAME.lock() = narf_net::iface::register_static("wlan%d", mac, send_frame_unimpl);
    if let Some(firmware) = firmware {
        // The registered interface and controller retain this exact owner
        // before the first DMA base/BME publication. No spinlock crosses await.
        narf_scheduler::spawn(async move {
            if let Err(error) = firmware.initialize_registered().await {
                use core::fmt::Write as _;
                let _ = writeln!(narf_console::Writer, "rtw88-8822ce firmware: {:?}", error);
                return;
            }
            if let Err(error) = firmware.prepare_mac().await {
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "rtw88-8822ce inactive MAC: {:?}",
                    error
                );
                return;
            }
            if let Err(error) = firmware.prepare_phy_tables().await {
                use core::fmt::Write as _;
                let _ = writeln!(narf_console::Writer, "rtw88-8822ce PHY tables: {:?}", error);
                return;
            }
            if let Err(error) = firmware.qualify_board().await {
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "rtw88-8822ce board qualification: {:?}",
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
    if did == RTL_DEV_8822CE {
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
    let (registers, mac, factory) = super::pci_park::invoke(cap, || -> Result<_, ProbeError> {
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
        let mac = match &factory {
            Some(factory) => factory.mac(),
            // SAFETY: same powered/exclusive BAR2 invocation, sibling geometry.
            None => unsafe { efuse::read_mac(&registers, device.id.device) }
                .map_err(ProbeError::Efuse)?,
        };

        Ok((registers, mac, factory))
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

    // Initialize IPC rings.
    let (_rx_prod, rx_cons) = channel::<Frame, RX_RING_N>();
    let (tx_prod, _tx_cons) = channel::<Frame, TX_RING_N>();

    let device_obj = Arc::new(Rtw88Device {
        bus_addr: device.addr,
        registers,
        mac,
        device_id: device.id.device,
        firmware: firmware.clone(),
        link_up: AtomicBool::new(false),
        rx_ring: IrqSafeSpinLock::new(Some(rx_cons)),
        tx_ring: IrqSafeSpinLock::new(Some(tx_prod)),
    });

    narf_wireless::registry::register(device_obj.clone());

    Ok(Rtw88Device {
        bus_addr: device.addr,
        registers,
        mac,
        device_id: device.id.device,
        firmware,
        link_up: AtomicBool::new(false),
        rx_ring: IrqSafeSpinLock::new(None),
        tx_ring: IrqSafeSpinLock::new(None),
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
    CONTROLLER.lock().as_ref().map(f)
}

/// Test-only reset of the bound slot. Avoids cross-test leak when the
/// smoke suite re-probes; gated under `kernel-test`-style cfg so it
/// drops from production binaries.
#[cfg(any(test, feature = "kernel-test"))]
pub fn __reset_for_test() {
    *CONTROLLER.lock() = None;
}
