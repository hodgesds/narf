// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821CU USB driver registration (Linux 7.3-rc4 `rtw88/rtw8821cu.c`
//! `rtw_8821cu_driver` over `usb.c::rtw_usb_probe`).
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

type Backend = usb_firmware::Backend<UsbControl, UsbIo>;
type Station = interface::Device<Backend>;

/// USB 2.0 §9.4.7 SET_CONFIGURATION.
const SET_CONFIGURATION: u8 = 0x09;
/// Largest configuration descriptor accepted (as `r8152.rs`).
const CONFIG_MAX: usize = 4096;
/// `pci.rs::schedule_owner`'s retry budget: 120 attempts, 500 ms apart.
const ATTEMPTS: usize = 120;

const N: usize = usb::RTL8821CU_IDS.len();
/// `rtw_8821cu_id_table`: `USB_DEVICE_AND_INTERFACE_INFO(vid, pid, 0xff,
/// 0xff, 0xff)` for every entry.
const fn id_table() -> [UsbClassMatch; N] {
    let mut out = [UsbClassMatch::vid_pid(0xffff, 0xffff); N];
    let mut i = 0;
    while i < N {
        let (vendor_id, product_id) = usb::RTL8821CU_IDS[i];
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
pub(super) static RTW8821CU_USB_IDS: [UsbClassMatch; N] = id_table();

struct Bound {
    device: Arc<USBDevice>,
    station: Option<Arc<Station>>,
    lifecycle: Option<Arc<Lifecycle<Backend>>>,
}
static BOUND: IrqSafeSpinLock<Vec<Bound>> = IrqSafeSpinLock::new(Vec::new());

/// `module_usb_driver(rtw_8821cu_driver)`.
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
}

/// `rtw_8821cu_probe`: claim the function and start the asynchronous
/// `rtw_usb_probe` body; a second probe of the same handle is a no-op.
pub(super) fn probe(device: Arc<USBDevice>) -> Result<(), UsbProbeError> {
    if !usb::is_rtl8821cu(device.vendor_id(), device.product_id()) {
        return Err(UsbProbeError::UnsupportedVariant);
    }
    {
        let mut bound = BOUND.lock();
        if bound.iter().any(|b| b.device.slot_id() == device.slot_id()) {
            return Ok(());
        }
        bound.push(Bound {
            device: device.clone(),
            station: None,
            lifecycle: None,
        });
    }
    narf_scheduler::spawn(async move {
        if let Err(error) = attach(device.clone()).await {
            narf_console::klog!(
                "rtw8821cu {:04x}:{:04x}: {:?}\n",
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
fn unbind(slot_id: u8) -> Result<(), ()> {
    let bound = {
        let mut all = BOUND.lock();
        let Some(index) = all.iter().position(|b| b.device.slot_id() == slot_id) else {
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

fn current(device: &Arc<USBDevice>) -> bool {
    BOUND.lock().iter().any(|b| Arc::ptr_eq(&b.device, device))
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
    let registers = backend.registers();
    registers
        .power_on()
        .await
        .map_err(usb_firmware::usb_error)?;
    registers
        .write8(0x1a0, 0xfd)
        .await
        .map_err(usb_firmware::usb_error)?;
    efuse::read_factory8821c_usb(backend)
        .await
        .map_err(|error| match error {
            efuse::EfuseError::Timeout => Error::Timeout,
            // Erased/invalid USB map (no unicast MAC at 0x107) or a malformed
            // record: the function cannot be identified or keyed.
            _ => Error::Prerequisite,
        })
}

async fn attach(device: Arc<USBDevice>) -> Result<(), Error> {
    let endpoints = interface_init(&device).await?;
    let speed = Speed::from_port(device.speed());
    let mut backend = Backend::new(
        UsbControl::new(device.clone()),
        UsbIo::new(device.clone()),
        endpoints,
        speed,
    )?;
    let factory = power_and_factory(&mut backend).await?;
    let (vendor, product) = (device.vendor_id(), device.product_id());
    let lifecycle: Arc<Lifecycle<Backend>> =
        Arc::new(Lifecycle::new(0xc821).on(super::phy8821c::Interface::Usb { vendor, product }));
    let name = narf_net::iface::reserve_name("wlan%d");
    let station = Arc::new(Station::new(
        name,
        factory.mac(),
        lifecycle.clone(),
        Arc::new(super::station::NativeEnvironment),
    ));
    {
        let mut all = BOUND.lock();
        let entry = all
            .iter_mut()
            .find(|b| Arc::ptr_eq(&b.device, &device))
            .ok_or(Error::Cancelled)?;
        entry.station = Some(station.clone());
        entry.lifecycle = Some(lifecycle.clone());
    }
    interface::publish(station.clone()).map_err(|_| Error::State)?;
    narf_console::klog!(
        "rtw8821cu {:04x}:{:04x} {} {:?} {} bulk-out\n",
        vendor,
        product,
        name,
        speed,
        endpoints.out_count
    );
    // The backend moves into the lifecycle on the first attempt whose
    // firmware image is registered; until then it stays here, unclaimed.
    let pending = IrqSafeSpinLock::new(Some(backend));
    super::pci::drive_scheduled(
        ATTEMPTS,
        || retryable(&lifecycle, &station) && current(&device),
        || provision(&lifecycle, &station, &factory, &pending),
        || narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(500_000_000)),
    )
    .await
}

/// `pci.rs::retryable` for the USB owner.
fn retryable(lifecycle: &Lifecycle<Backend>, station: &Station) -> bool {
    matches!(
        lifecycle.status().stage,
        Stage::Detected
            | Stage::PhyTablesPrepared
            | Stage::Calibration8821cPrepared
            | Stage::Operating8821cPrepared
    ) && !station.closed()
}

/// `sibling.rs::Sibling::provision` + `pci.rs::provision_owner`'s station
/// activation, over the USB backend.
async fn provision(
    lifecycle: &Lifecycle<Backend>,
    station: &Station,
    factory: &Factory8821c,
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
