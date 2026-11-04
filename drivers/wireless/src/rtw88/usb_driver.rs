// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821CU and RTL8822BU USB driver registration (Linux 7.3-rc4
//! `rtw88/rtw8821cu.c` `rtw_8821cu_driver` and `rtw88/rtw8822bu.c`
//! `rtw_8822bu_driver`, both over `usb.c::rtw_usb_probe`).
//!
//! RTL8822BU is the B22 die (`rtw8822b_hw_spec`) behind the same USB host
//! interface: `usb::Registers` runs the `rtw8822b.c` USB power rows and
//! `sys_func_en` 0xdc, the factory map is parsed as
//! `rtw8822bu_efuse_parsing` (MAC 0x107), `rtw_usb_phy_cfg` writes the one
//! cut-D `usb3_param_8822b` row and `rtw_usb_switch_mode` may ask the chip
//! to re-enumerate as USB 3 (no shell is then published). Provisioning then
//! runs the B22 stages of `native8822b.rs` (firmware, MAC, PHY, `N2BQ`
//! IQK, `N2BP` parked power, `N2BS` awake station) keyed by the claimed
//! VID/PID (`rtw8822bu-*` records).
//!
//! The class registry hands a matching function to [`probe`], which only
//! records the claim and spawns the asynchronous attach (every register
//! access is an EP0 transfer). Attach mirrors `rtw_usb_probe`:
//! `rtw_usb_intf_init` (`rtw_usb_parse` = [`Endpoints::parse`] over the full
//! configuration descriptor), then SET_CONFIGURATION and the xHCI endpoint
//! contexts for the bulk pipes Linux submits on (`usb_submit_urb` needs the
//! host endpoint; the interrupt-IN pipe is never used by rtw88), then
//! `rtw_chip_efuse_enable`'s `rtw_mac_power_on` ([`usb::Registers::power_on`])
//! and REG_C2HEVT = C2H_HW_FEATURE_REPORT, the factory map
//! ([`efuse::read_factory8821c_usb`]), and the retained lifecycle keyed by
//! the claimed VID/PID (`Interface::Usb`). `rtw_usb_phy_cfg` is a no-op for
//! 8821C (`usb2_param_8821c`/`usb3_param_8821c` hold only the terminator) and
//! `rtw_usb_switch_mode` applies only to 8822B/8822C/8812A/8814A.
//!
//! The named shell is published before any stage runs (`rtw_register_hw`),
//! as on PCI; firmware download, MAC, PHY and the C21 calibration/operating/
//! station stages then run as `sibling.rs::Sibling::provision` does, retried
//! like `pci.rs::schedule_owner` while the firmware or signed records are
//! not yet registered. An unprovisioned RTL8821CU (no `rtw8821cu-*` N21Q
//! record) stops at the calibration stage and is never admitted for radio TX.
use super::{
    efuse::{self, Factory8821c},
    efuse8822b::Factory8822b,
    firmware_lifecycle::{Lifecycle, Stage},
    firmware_transport::Error,
    interface,
    usb::{self, Endpoints, Speed},
    usb_firmware,
};
use crate::rtl8xxxu::{firmware_transport::UsbControl, packet_transport::UsbIo};
use alloc::{sync::Arc, vec::Vec};
use narf_drivers_usb::{
    class_registry::{UsbClassMatch, UsbProbeError},
    device::USBDevice,
    xhci::EndpointConfig,
};
use narf_lib::sync::IrqSafeSpinLock;

pub(super) type Backend = usb_firmware::Backend<UsbControl, UsbIo>;
type Station = interface::Device<Backend>;

/// USB 2.0 §9.4.7 SET_CONFIGURATION.
const SET_CONFIGURATION: u8 = 0x09;
/// Largest configuration descriptor accepted (as `r8152.rs`).
const CONFIG_MAX: usize = 4096;
/// `pci.rs::schedule_owner`'s retry budget: 120 attempts, 500 ms apart.
const ATTEMPTS: usize = 120;

const N: usize = usb::RTL8821CU_IDS.len();
const N22B: usize = usb::RTL8822BU_IDS.len();
/// `rtw_8821cu_id_table` / `rtw_8822bu_id_table`:
/// `USB_DEVICE_AND_INTERFACE_INFO(vid, pid, 0xff, 0xff, 0xff)` for every
/// entry.
const fn id_table<const M: usize>(ids: &[(u16, u16)]) -> [UsbClassMatch; M] {
    let mut out = [UsbClassMatch::vid_pid(0xffff, 0xffff); M];
    let mut i = 0;
    while i < M {
        let (vendor_id, product_id) = ids[i];
        out[i] = UsbClassMatch {
            vendor_id,
            product_id,
            class: Some(0xff),
            subclass: Some(0xff),
            protocol: Some(0xff),
        };
        i += 1;
    }
    out
}
pub(super) static RTW8821CU_USB_IDS: [UsbClassMatch; N] = id_table(usb::RTL8821CU_IDS);
pub(super) static RTW8822BU_USB_IDS: [UsbClassMatch; N22B] = id_table(usb::RTL8822BU_IDS);

/// The factory map of one claimed function: `rtw8821cu_efuse_parsing` or
/// `rtw8822bu_efuse_parsing` (both with the MAC at 0x107).
#[derive(Clone, Debug)]
pub(super) enum Factory {
    C21(alloc::boxed::Box<Factory8821c>),
    B22(alloc::boxed::Box<Factory8822b>),
}
impl Factory {
    pub(super) fn mac(&self) -> [u8; 6] {
        match self {
            Self::C21(f) => f.mac(),
            Self::B22(f) => f.mac(),
        }
    }
}
/// The die behind a claimed USB function (`id->driver_info`).
pub(super) fn chip(vendor: u16, product: u16) -> Option<u16> {
    if usb::is_rtl8821cu(vendor, product) {
        Some(0xc821)
    } else if usb::is_rtl8822bu(vendor, product) {
        Some(0xb822)
    } else {
        None
    }
}

struct Bound {
    device: Arc<USBDevice>,
    station: Option<Arc<Station>>,
    lifecycle: Option<Arc<Lifecycle<Backend>>>,
    /// Fixed by the first attach; every restart generation reuses it.
    origin: Option<Origin>,
    /// `pci.rs::Rtw88Device::provisioning` for this slot: one provisioning
    /// attempt, reset, rejoin or PM park/unpark at a time.
    provisioning: Arc<narf_lib::mutex::Mutex<()>>,
}

/// What `rtw_usb_probe` learned once (`rtw_usb_intf_init`, the bus speed
/// and the factory MAC); `usb_recovery.rs` restarts over it.
#[derive(Clone, Copy, Debug)]
pub(super) struct Origin {
    /// 0xc821 (RTL8821CU) or 0xb822 (RTL8822BU).
    pub(super) did: u16,
    pub(super) endpoints: Endpoints,
    pub(super) speed: Speed,
    pub(super) mac: [u8; 6],
}

/// The current generation of one bound slot.
pub(super) struct Current {
    pub(super) device: Arc<USBDevice>,
    pub(super) station: Arc<Station>,
    pub(super) lifecycle: Arc<Lifecycle<Backend>>,
    pub(super) origin: Origin,
}
static BOUND: IrqSafeSpinLock<Vec<Bound>> = IrqSafeSpinLock::new(Vec::new());

/// `module_usb_driver(rtw_8821cu_driver)` and
/// `module_usb_driver(rtw_8822bu_driver)`.
pub(super) fn register() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "rtw88-8821cu-usb-ids", || {
        let _ = narf_drivers_usb::class_registry::register_class_driver_with_unbind(
            "rtw8821cu",
            &RTW8821CU_USB_IDS,
            probe,
            unbind,
        );
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "rtw88-8822bu-usb-ids", || {
        let _ = narf_drivers_usb::class_registry::register_class_driver_with_unbind(
            "rtw8822bu",
            &RTW8822BU_USB_IDS,
            probe,
            unbind,
        );
        InitResult::Ok
    });
}

/// `rtw_8821cu_probe` / `rtw_8822bu_probe`: claim the function and start
/// the asynchronous `rtw_usb_probe` body; a second probe of the same handle
/// is a no-op.
pub(super) fn probe(device: Arc<USBDevice>) -> Result<(), UsbProbeError> {
    let Some(did) = chip(device.vendor_id(), device.product_id()) else {
        return Err(UsbProbeError::UnsupportedVariant);
    };
    {
        let mut bound = BOUND.lock();
        if bound.iter().any(|b| {
            b.device.controller().id() == device.controller().id()
                && b.device.slot_id() == device.slot_id()
        }) {
            return Ok(());
        }
        bound.push(Bound {
            device: device.clone(),
            station: None,
            lifecycle: None,
            origin: None,
            provisioning: Arc::new(narf_lib::mutex::Mutex::new(())),
        });
    }
    narf_scheduler::spawn(async move {
        if let Err(error) = attach(device.clone(), did).await {
            narf_console::klog!(
                "{} {:04x}:{:04x}: {:?}\n",
                driver_name(did),
                device.vendor_id(),
                device.product_id(),
                error
            );
        }
    });
    Ok(())
}

/// `rtw_usb_disconnect`: withdraw the published shell (`rtw_unregister_hw`)
/// and retire the owner (`Lifecycle::remove` stops every retained bulk
/// receipt). Idempotent; other slots are untouched.
fn unbind(controller: u8, slot_id: u8) -> Result<(), ()> {
    let bound = {
        let mut all = BOUND.lock();
        // Slot ids are per xHCI controller.
        let Some(index) = all.iter().position(|b| {
            b.device.controller().id() == controller && b.device.slot_id() == slot_id
        }) else {
            return Ok(());
        };
        all.swap_remove(index)
    };
    if let Some(station) = &bound.station {
        station.withdraw();
    }
    if let Some(lifecycle) = bound.lifecycle {
        narf_scheduler::spawn(async move {
            let _ = lifecycle.remove().await;
        });
    }
    Ok(())
}

/// Linux driver name of chip `did` on USB.
fn driver_name(did: u16) -> &'static str {
    if did == 0xb822 {
        "rtw8822bu"
    } else {
        "rtw8821cu"
    }
}

/// The published RTL8821CU/RTL8822BU station shell claimed on USB `slot_id`.
pub(super) fn station(slot_id: u8) -> Option<Arc<Station>> {
    BOUND
        .lock()
        .iter()
        .find(|b| b.device.slot_id() == slot_id)
        .and_then(|b| b.station.clone())
}

/// True while `device` is still bound and `station` is its generation.
pub(super) fn is_current(device: &Arc<USBDevice>, station: &Arc<Station>) -> bool {
    BOUND.lock().iter().any(|b| {
        Arc::ptr_eq(&b.device, device)
            && b.station.as_ref().is_some_and(|s| Arc::ptr_eq(s, station))
    })
}

/// The slot's current generation, once attach published one.
pub(super) fn current(slot_id: u8) -> Option<Current> {
    BOUND
        .lock()
        .iter()
        .find(|b| b.device.slot_id() == slot_id)
        .and_then(|b| {
            Some(Current {
                device: b.device.clone(),
                station: b.station.clone()?,
                lifecycle: b.lifecycle.clone()?,
                origin: b.origin?,
            })
        })
}

/// The slot's provisioning lock (`Rtw88Device::provisioning`).
pub(super) fn provisioning(slot_id: u8) -> Option<Arc<narf_lib::mutex::Mutex<()>>> {
    BOUND
        .lock()
        .iter()
        .find(|b| b.device.slot_id() == slot_id)
        .map(|b| b.provisioning.clone())
}

/// Every bound slot with a published generation (system PM fan-out).
pub(super) fn slots() -> Vec<u8> {
    BOUND
        .lock()
        .iter()
        .filter(|b| b.station.is_some())
        .map(|b| b.device.slot_id())
        .collect()
}

/// xHCI endpoint contexts for the pipes rtw88 submits on: the bulk-IN pipe
/// (`rtw_usb_rx_resubmit`) and every bulk-OUT pipe in `out` order
/// (`rtw_usb_write_port`). The interrupt-IN pipe is parsed but never used.
pub(super) fn endpoint_configs(endpoints: &Endpoints) -> Vec<EndpointConfig> {
    use narf_drivers_usb::device::{bulk_in_ep, bulk_out_ep};
    let mut out = Vec::with_capacity(1 + usize::from(endpoints.out_count));
    out.push(bulk_in_ep(
        endpoints.bulk_in & 0x0f,
        endpoints.bulk_in_packet,
    ));
    for pipe in 0..usize::from(endpoints.out_count) {
        out.push(bulk_out_ep(
            endpoints.out[pipe] & 0x0f,
            endpoints.out_packets[pipe],
        ));
    }
    out
}

/// `rtw_usb_intf_init` + host endpoint configuration.
async fn interface_init(device: &USBDevice) -> Result<Endpoints, Error> {
    let mut header = [0u8; 9];
    let n = device
        .get_config_descriptor(0, &mut header)
        .await
        .map_err(|_| Error::Access)?;
    if n != header.len() || header[1] != 2 {
        return Err(Error::Unsupported);
    }
    let total = usize::from(u16::from_le_bytes([header[2], header[3]]));
    if !(9..=CONFIG_MAX).contains(&total) {
        return Err(Error::Unsupported);
    }
    let mut config = alloc::vec![0u8; total];
    let n = device
        .get_config_descriptor(0, &mut config)
        .await
        .map_err(|_| Error::Access)?;
    if n != total {
        return Err(Error::Access);
    }
    let endpoints = Endpoints::parse(&config).map_err(usb_firmware::usb_error)?;
    device
        .control_out(0x00, SET_CONFIGURATION, u16::from(config[5]), 0, &[])
        .await
        .map_err(|_| Error::Access)?;
    device
        .configure_endpoints(&endpoint_configs(&endpoints))
        .await
        .map_err(|_| Error::Access)?;
    Ok(endpoints)
}

/// `rtw_chip_efuse_enable` up to the factory map: `rtw_mac_power_on`,
/// REG_C2HEVT = C2H_HW_FEATURE_REPORT, then the physical EFUSE dump.
pub(super) async fn power_and_factory<
    C: crate::rtl8xxxu::firmware_transport::ControlIo,
    P: crate::rtl8xxxu::packet_transport::Io + Clone,
>(
    backend: &mut usb_firmware::Backend<C, P>,
) -> Result<Factory8821c, Error> {
    power_on(backend).await?;
    efuse::read_factory8821c_usb(backend)
        .await
        .map_err(factory_error)
}
/// [`power_and_factory`] for the claimed chip `did`.
pub(super) async fn power_and_factory_for<
    C: crate::rtl8xxxu::firmware_transport::ControlIo,
    P: crate::rtl8xxxu::packet_transport::Io + Clone,
>(
    backend: &mut usb_firmware::Backend<C, P>,
    did: u16,
) -> Result<Factory, Error> {
    if did != 0xb822 {
        return power_and_factory(backend)
            .await
            .map(|f| Factory::C21(alloc::boxed::Box::new(f)));
    }
    power_on(backend).await?;
    efuse::read_factory8822b_usb(backend)
        .await
        .map(|f| Factory::B22(alloc::boxed::Box::new(f)))
        .map_err(factory_error)
}
fn factory_error(error: efuse::EfuseError) -> Error {
    match error {
        efuse::EfuseError::Timeout => Error::Timeout,
        // Erased/invalid USB map (no unicast MAC at 0x107) or a malformed
        // record: the function cannot be identified or keyed.
        _ => Error::Prerequisite,
    }
}
async fn power_on<
    C: crate::rtl8xxxu::firmware_transport::ControlIo,
    P: crate::rtl8xxxu::packet_transport::Io + Clone,
>(
    backend: &mut usb_firmware::Backend<C, P>,
) -> Result<(), Error> {
    let registers = backend.registers();
    registers
        .power_on()
        .await
        .map_err(usb_firmware::usb_error)?;
    registers
        .write8(0x1a0, 0xfd)
        .await
        .map_err(usb_firmware::usb_error)
}

async fn attach(device: Arc<USBDevice>, did: u16) -> Result<(), Error> {
    let endpoints = interface_init(&device).await?;
    let speed = Speed::from_port(device.speed());
    let mut backend = Backend::new_for(
        did,
        UsbControl::new(device.clone()),
        UsbIo::new(device.clone()),
        endpoints,
        speed,
    )?;
    let factory = power_and_factory_for(&mut backend, did).await?;
    if let Factory::B22(f) = &factory {
        // `rtw_usb_probe` after `rtw_chip_info_setup`: `rtw_usb_phy_cfg`
        // (HIGH, then SUPER) at the chip cut, then `rtw_usb_switch_mode`.
        let registers = backend.registers();
        let cut = (registers
            .read32(0xf0)
            .await
            .map_err(usb_firmware::usb_error)?
            >> 12
            & 15) as u8;
        registers
            .phy_cfg(cut)
            .await
            .map_err(usb_firmware::usb_error)?;
        if registers
            .switch_mode(f.usb_mode_switch())
            .await
            .map_err(usb_firmware::usb_error)?
        {
            // "switching to USB 3 mode": the chip re-enumerates; Linux
            // skips `rtw_register_hw` and the new function probes fresh.
            narf_console::klog!(
                "rtw8822bu {:04x}:{:04x}: switching to USB 3 mode\n",
                device.vendor_id(),
                device.product_id()
            );
            return Ok(());
        }
    }
    let origin = Origin {
        did,
        endpoints,
        speed,
        mac: factory.mac(),
    };
    {
        let mut all = BOUND.lock();
        let entry = all
            .iter_mut()
            .find(|b| Arc::ptr_eq(&b.device, &device))
            .ok_or(Error::Cancelled)?;
        entry.origin = Some(origin);
    }
    let name = narf_net::iface::reserve_name("wlan%d");
    let generation = Generation::publish(&device, None, name, factory, backend)?;
    // `pci.rs::probe`'s bound-driver record (no PCI IDs on USB).
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(if did == 0xb822 {
            "rtw88-8822bu"
        } else {
            "rtw88-8821cu"
        }),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: None,
        pci_did: None,
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });
    narf_console::klog!(
        "{} {:04x}:{:04x} {} {:?} {} bulk-out\n",
        driver_name(did),
        device.vendor_id(),
        device.product_id(),
        name,
        speed,
        endpoints.out_count
    );
    generation.drive().await
}

/// One generation of the slot's station: fresh lifecycle and published
/// shell over a powered backend whose factory map was just read. Restarts
/// (`usb_recovery.rs`) replace the whole generation, as `pci.rs::bring_up`
/// does for a reset function; nothing of the old owner is reused.
pub(super) struct Generation {
    device: Arc<USBDevice>,
    pub(super) lifecycle: Arc<Lifecycle<Backend>>,
    pub(super) station: Arc<Station>,
    factory: Factory,
    /// The backend moves into the lifecycle on the first attempt whose
    /// firmware image is registered; until then it stays here, unclaimed.
    pending: IrqSafeSpinLock<Option<Backend>>,
}
impl Generation {
    /// Publish the fresh shell (`rtw_register_hw`) under `name`, then make it
    /// the slot's generation iff the slot is still bound to `old`'s
    /// generation (`None`: the first attach). A slot unbound meanwhile gets
    /// the fresh shell withdrawn again.
    pub(super) fn publish(
        device: &Arc<USBDevice>,
        old: Option<&Arc<Station>>,
        name: &'static str,
        factory: Factory,
        backend: Backend,
    ) -> Result<Self, Error> {
        let (vendor, product) = (device.vendor_id(), device.product_id());
        let did = match factory {
            Factory::C21(_) => 0xc821,
            Factory::B22(_) => 0xb822,
        };
        let lifecycle: Arc<Lifecycle<Backend>> =
            Arc::new(Lifecycle::new(did).on(super::phy8821c::Interface::Usb { vendor, product }));
        let station = Arc::new(Station::new(
            name,
            factory.mac(),
            lifecycle.clone(),
            Arc::new(super::station::NativeEnvironment),
        ));
        interface::publish(station.clone()).map_err(|_| Error::State)?;
        let installed = {
            let mut all = BOUND.lock();
            match all.iter_mut().find(|b| Arc::ptr_eq(&b.device, device)) {
                Some(entry)
                    if match (old, entry.station.as_ref()) {
                        (None, None) => true,
                        (Some(old), Some(current)) => Arc::ptr_eq(old, current),
                        _ => false,
                    } =>
                {
                    entry.station = Some(station.clone());
                    entry.lifecycle = Some(lifecycle.clone());
                    true
                }
                _ => false,
            }
        };
        if !installed {
            station.withdraw();
            return Err(Error::Cancelled);
        }
        Ok(Self {
            device: device.clone(),
            lifecycle,
            station,
            factory,
            pending: IrqSafeSpinLock::new(Some(backend)),
        })
    }
    /// This generation is still the slot's current one.
    pub(super) fn current(&self) -> bool {
        is_current(&self.device, &self.station)
    }
    /// Whether a failed attempt may be retried (`pci.rs::retryable`).
    pub(super) fn retryable(&self) -> bool {
        retryable(&self.lifecycle, &self.station) && self.current()
    }
    /// One provisioning attempt under the slot's provisioning lock.
    pub(super) async fn provision_once(&self) -> Result<(), Error> {
        let lock = provisioning(self.device.slot_id()).ok_or(Error::Cancelled)?;
        let _provision = lock.lock().await;
        if !self.current() {
            return Err(Error::Cancelled);
        }
        provision(&self.lifecycle, &self.station, &self.factory, &self.pending).await
    }
    /// `pci.rs::schedule_owner`: retry while the firmware image or the signed
    /// records are not registered yet.
    pub(super) async fn drive(&self) -> Result<(), Error> {
        super::pci::drive_scheduled(
            ATTEMPTS,
            || self.retryable(),
            || self.provision_once(),
            || narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(500_000_000)),
        )
        .await
    }
    /// A fresh generation that cannot continue: withdraw it and retire its
    /// owner. The slot stays bound (unbind/replug starts over).
    pub(super) async fn abort(&self) {
        self.station.withdraw();
        let _ = self.lifecycle.remove().await;
    }
}

/// `main.c::rtw_core_start` -> `rtw_power_on` for a restart generation:
/// a fresh backend over the original pipes (the xHCI endpoint contexts stay
/// configured, as Linux keeps the interface bound), `rtw_mac_power_on`,
/// REG_C2HEVT and a fresh factory map whose MAC must equal the original
/// (`pci.rs::bring_up_mode`'s identity re-read).
pub(super) async fn power_up(
    device: &Arc<USBDevice>,
    origin: &Origin,
) -> Result<(Backend, Factory), super::operating_reset::Error> {
    use super::operating_reset::Error as Reset;
    let mut backend = Backend::new_for(
        origin.did,
        UsbControl::new(device.clone()),
        UsbIo::new(device.clone()),
        origin.endpoints,
        origin.speed,
    )
    .map_err(|_| Reset::Unsupported)?;
    let factory = power_and_factory_for(&mut backend, origin.did)
        .await
        .map_err(|_| Reset::Power)?;
    if factory.mac() != origin.mac {
        return Err(Reset::Identity);
    }
    Ok((backend, factory))
}

/// `pci.rs::retryable` for the USB owner: B22 `Calibrated` awaits `N2BP`.
fn retryable(lifecycle: &Lifecycle<Backend>, station: &Station) -> bool {
    let stage = lifecycle.status().stage;
    (matches!(
        stage,
        Stage::Detected
            | Stage::PhyTablesPrepared
            | Stage::Calibration8821cPrepared
            | Stage::Operating8821cPrepared
    ) || lifecycle.device_id() == 0xb822 && stage == Stage::Calibrated)
        && !station.closed()
}

/// `sibling.rs::Sibling::provision` + `pci.rs::provision_owner`'s station
/// activation, over the USB backend.
async fn provision(
    lifecycle: &Lifecycle<Backend>,
    station: &Station,
    factory: &Factory,
    pending: &IrqSafeSpinLock<Option<Backend>>,
) -> Result<(), Error> {
    let factory = match factory {
        Factory::C21(f) => f,
        Factory::B22(f) => return provision8822b(lifecycle, station, f, pending).await,
    };
    loop {
        if station.closed() {
            return Err(Error::Cancelled);
        }
        match lifecycle.status().stage {
            Stage::Detected => {
                lifecycle
                    .initialize_registered(|| pending.lock().take().ok_or(Error::State))
                    .await?;
            }
            Stage::Ready => {
                lifecycle.prepare_mac().await?;
            }
            Stage::MacPrepared => {
                lifecycle.prepare_phy8821c(factory).await?;
            }
            Stage::PhyTablesPrepared => {
                lifecycle.prepare_calibration8821c(factory).await?;
            }
            Stage::Calibration8821cPrepared => {
                lifecycle.prepare_operating8821c(factory).await?;
            }
            Stage::Operating8821cPrepared => {
                lifecycle
                    .prepare_station8821c(factory, super::station_power8821c::Source::Registered)
                    .await?;
            }
            Stage::Radio8821cPrepared => {
                return station.activate().await.map_err(|_| Error::Prerequisite);
            }
            Stage::StationReady => return Ok(()),
            _ => return Err(Error::State),
        }
    }
}

/// `native8822b.rs::Owner8822b::provision` + `pci.rs::provision_owner`'s
/// B22 station activation, over the USB backend. An unprovisioned
/// RTL8822BU (no `rtw8822bu-*` N2BQ/N2BP/N2BS record) stops at the pure
/// `PhyTablesPrepared` / `Calibrated` / `Operating8821cPrepared`
/// checkpoints and is never admitted for radio TX.
async fn provision8822b(
    lifecycle: &Lifecycle<Backend>,
    station: &Station,
    factory: &Factory8822b,
    pending: &IrqSafeSpinLock<Option<Backend>>,
) -> Result<(), Error> {
    loop {
        if station.closed() {
            return Err(Error::Cancelled);
        }
        match lifecycle.status().stage {
            Stage::Detected => {
                lifecycle
                    .initialize_registered(|| pending.lock().take().ok_or(Error::State))
                    .await?;
            }
            Stage::Ready => {
                lifecycle.prepare_mac().await?;
            }
            Stage::MacPrepared => {
                lifecycle.prepare_phy8822b(factory).await?;
            }
            Stage::PhyTablesPrepared => {
                lifecycle.prepare_calibration8822b(factory).await?;
            }
            Stage::Calibrated => {
                lifecycle.prepare_operating8822b(factory).await?;
            }
            Stage::Operating8821cPrepared => {
                lifecycle.prepare_station8822b(factory).await?;
            }
            Stage::Radio8821cPrepared => {
                return station.activate().await.map_err(|_| Error::Prerequisite);
            }
            Stage::StationReady => return Ok(()),
            _ => return Err(Error::State),
        }
    }
}
