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
    pub(super) native: Option<Arc<super::interface::Native>>,
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
        self.native
            .as_ref()
            .map_or_else(|| *IFNAME.lock(), |native| native.name())
    }
    fn mac(&self) -> [u8; 6] {
        self.mac
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        self.native.as_ref().map_or_else(
            || self.link_up.load(Ordering::Acquire),
            |native| native.link_up(),
        )
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        self.native
            .as_ref()
            .map_or(&self.rx_ring, |native| native.rx_ring())
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        self.native
            .as_ref()
            .map_or(&self.tx_ring, |native| native.tx_ring())
    }
}

#[async_trait::async_trait]
impl WirelessNetIface for RtlwifiDevice {
    fn supports_handshake_offload(&self) -> bool {
        self.native
            .as_ref()
            .is_some_and(|native| native.supports_handshake_offload())
    }
    fn reports_disconnect_events(&self) -> bool {
        self.native.is_some()
    }
    fn supports_scan_dwell(&self) -> bool {
        self.native.is_some()
    }
    fn connected_bssid(&self) -> Option<[u8; 6]> {
        self.native.as_ref()?.connected_bssid()
    }
    fn cipher_suites(&self) -> &'static [u32] {
        self.native
            .as_ref()
            .map_or(&[], |native| native.cipher_suites())
    }
    fn scan_information_elements(&self, bssid: [u8; 6]) -> Option<alloc::vec::Vec<u8>> {
        self.native.as_ref()?.scan_information_elements(bssid)
    }
    fn get_wireless_info(&self) -> WirelessIfaceInfo {
        if let Some(native) = &self.native {
            return native.get_wireless_info();
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

    async fn scan(&self, req: ScanRequest) -> Result<alloc::vec::Vec<BssInfo>, WirelessError> {
        match &self.native {
            Some(native) => native.scan(req).await,
            None => Err(WirelessError::NotSupported),
        }
    }

    async fn associate(&self, req: AssociateRequest) -> Result<(), WirelessError> {
        match &self.native {
            Some(native) => native.associate(req).await,
            None => Err(WirelessError::NotSupported),
        }
    }

    async fn disassociate(&self) -> Result<(), WirelessError> {
        if let Some(native) = &self.native {
            return native.disassociate().await;
        }
        self.link_up.store(false, Ordering::Release);
        Ok(())
    }

    async fn set_config(&self, cfg: WirelessConfig) -> Result<(), WirelessError> {
        match &self.native {
            Some(native) => native.set_config(cfg).await,
            None => Err(WirelessError::NotSupported),
        }
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
    let native = dev.native.clone();
    *CONTROLLER.lock() = Some(dev);

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(name_for(did)),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });

    if let Some(native) = native {
        // The controller already retains the complete device before either
        // registry can expose it. Current net authority is required before
        // the station facade may open native DMA.
        super::interface::publish(native).map_err(|_| narf_bus::ProbeError::BadDevice)?;
    } else {
        *IFNAME.lock() = narf_net::iface::register_static("wlan%d", mac, send_frame_unimpl);
    }
    if firmware.is_some() && prepared.is_some() && factory.is_some() {
        // Initial boot and a later missing-input retry share the exact same
        // retained binding and async admission lock.
        narf_scheduler::spawn(async {
            if let Err(error) = provision().await {
                use core::fmt::Write;
                let _ = writeln!(
                    narf_console::Writer,
                    "rtlwifi-8188ee native preparation: {:?}",
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
/// Its one-shot continuation retains LLT/native rings and qualifies RF/BB/MAC.
/// Public native station control separately gates packet DMA and association
/// under signed board/current regulatory policy; device IRQs remain masked.
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
    let native = match (&firmware, &prepared, &factory) {
        (Some(firmware), Some(prepared), Some(factory)) => {
            Some(Arc::new(super::interface::Device::new(
                narf_net::iface::reserve_name("wlan%d"),
                prepared.clone(),
                factory.clone(),
                super::interface::NativeEnvironment::new(firmware.clone()),
            )))
        }
        _ => None,
    };
    let device_arc = Arc::new(RtlwifiDevice {
        bus_addr: device.addr,
        registers,
        mac,
        device_id: device.id.device,
        firmware: firmware.clone(),
        prepared: prepared.clone(),
        factory: factory.clone(),
        native: native.clone(),
        link_up: AtomicBool::new(false),
        rx_ring: IrqSafeSpinLock::new(Some(rx_cons)),
        tx_ring: IrqSafeSpinLock::new(Some(tx_prod)),
    });
    if native.is_none() {
        narf_wireless::registry::register(device_arc);
    }

    Ok(RtlwifiDevice {
        bus_addr: device.addr,
        registers,
        mac,
        device_id: device.id.device,
        firmware,
        prepared,
        factory,
        native,
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

struct Provisioning {
    firmware: Arc<FirmwareOwner<PciIo>>,
    prepared: Arc<super::prepare_native::Retained>,
    factory: Arc<efuse::Factory>,
}
fn provisioning(controller: Option<&RtlwifiDevice>) -> Result<Provisioning, super::prepare::Error> {
    let controller = controller.ok_or(super::prepare::Error::State)?;
    if controller.device_id != RTL_DEV_8188EE {
        return Err(super::prepare::Error::State);
    }
    let firmware = controller
        .firmware
        .as_ref()
        .ok_or(super::prepare::Error::State)?;
    if firmware.status().stage != super::firmware_transport::Stage::Detected {
        return Err(super::prepare::Error::State);
    }
    Ok(Provisioning {
        firmware: firmware.clone(),
        prepared: controller
            .prepared
            .as_ref()
            .ok_or(super::prepare::Error::State)?
            .clone(),
        factory: controller
            .factory
            .as_ref()
            .ok_or(super::prepare::Error::State)?
            .clone(),
    })
}
static PROVISIONING: narf_lib::mutex::Mutex<()> = narf_lib::mutex::Mutex::new(());
async fn provision_with(
    control: &narf_lib::mutex::Mutex<()>,
    binding: impl FnOnce() -> Result<Provisioning, super::prepare::Error>,
) -> Result<(), super::prepare::Error> {
    let _control = control.lock().await;
    let binding = binding()?;
    super::prepare_native::initialize_registered(
        binding.firmware,
        binding.prepared,
        binding.factory,
    )
    .await
}
/// Retry staged firmware only while the exact retained EE owner is Detected.
/// Started/failed firmware and existing preparation are never replayed/reset.
pub async fn provision() -> Result<(), super::prepare::Error> {
    provision_with(&PROVISIONING, || {
        let controller = CONTROLLER.lock();
        provisioning(controller.as_ref())
    })
    .await
}

/// Test-only reset.
#[cfg(any(test, feature = "kernel-test"))]
pub fn __reset_for_test() {
    *CONTROLLER.lock() = None;
}

#[cfg(feature = "kernel-test")]
mod provision_tests {
    use super::*;
    use core::{
        future::Future,
        task::{Context, Poll, Waker},
    };
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn fixture() -> RtlwifiDevice {
        let address = narf_bus::PcieAddr::new(0xfffe, 0xfd, 0x19, 0);
        let device = BusDevice {
            addr: narf_bus::BusAddr::Pcie(address),
            id: narf_bus::DeviceId {
                vendor: 0x10ec,
                device: RTL_DEV_8188EE,
                class: 0x028000,
                subsystem_vendor: 0x10ec,
                subsystem_id: 0xffff,
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
            len: 0x2000,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        };
        // SAFETY: inert revoked-cap fixture; no admission test may access the
        // deliberately invalid config/BAR or present it as a live radio.
        let io = unsafe { PciIo::new(device, cap, registers) };
        RtlwifiDevice {
            bus_addr: device.addr,
            registers,
            mac: [2, 1, 2, 3, 4, 5],
            device_id: RTL_DEV_8188EE,
            firmware: Some(Arc::new(FirmwareOwner::new(io, RTL_DEV_8188EE))),
            prepared: Some(Arc::new(narf_lib::mutex::Mutex::new(None))),
            factory: Some(Arc::new(efuse::Factory {
                mac: [2, 1, 2, 3, 4, 5],
                logical: [0xff; 512],
            })),
            native: None,
            link_up: AtomicBool::new(false),
            rx_ring: IrqSafeSpinLock::new(None),
            tx_ring: IrqSafeSpinLock::new(None),
        }
    }
    fn smoke_rtl8188ee_public_provision_admission_retains_exact_arcs_and_cancelled_wait(
    ) -> TestResult {
        if provisioning(None).is_ok() {
            return TestResult::Fail("EE retry admitted absent controller");
        }
        let controller = fixture();
        let admitted = provisioning(Some(&controller)).unwrap();
        if !Arc::ptr_eq(&admitted.firmware, controller.firmware.as_ref().unwrap())
            || !Arc::ptr_eq(&admitted.prepared, controller.prepared.as_ref().unwrap())
            || !Arc::ptr_eq(&admitted.factory, controller.factory.as_ref().unwrap())
        {
            return TestResult::Fail("EE retry cloned a new hardware/prepared/factory owner");
        }
        drop(admitted);
        let control = narf_lib::mutex::Mutex::new(());
        let guard = control.try_lock().unwrap();
        let entered = core::cell::Cell::new(false);
        {
            let mut future = core::pin::pin!(provision_with(&control, || {
                entered.set(true);
                provisioning(Some(&controller))
            }));
            if !matches!(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop())),
                Poll::Pending
            ) {
                return TestResult::Fail("EE public retry bypassed retained async admission lock");
            }
        }
        drop(guard);
        if entered.get()
            || controller.firmware_status().unwrap().stage
                != super::super::firmware_transport::Stage::Detected
            || !Arc::ptr_eq(
                &provisioning(Some(&controller)).unwrap().firmware,
                controller.firmware.as_ref().unwrap(),
            )
        {
            return TestResult::Fail("cancelled EE pre-admission wait consumed or replaced owner");
        }
        let firmware = controller.firmware.as_ref().unwrap();
        // The supplied-byte diagnostic retains its original one-shot rule:
        // invalid input consumes that attempt before native I/O, making this
        // genuinely Failed owner ineligible for the public staging retry.
        if narf_scheduler::block_on(firmware.initialize(&[])).is_ok()
            || firmware.status().stage != super::super::firmware_transport::Stage::Failed
            || provisioning(Some(&controller)).is_ok()
        {
            return TestResult::Fail(
                "EE public retry admitted an owner whose attempt already began",
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtlwifi/provision",
        smoke_rtl8188ee_public_provision_admission_retains_exact_arcs_and_cancelled_wait
    );
}
