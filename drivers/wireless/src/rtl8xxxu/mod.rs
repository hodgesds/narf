//! Realtek RTL8XXXU USB WiFi family driver — NARF port.
//!
//! Covers the following chip families:
//!
//! | Chip      | USB ID (native)   | 802.11 |
//! |-----------|-------------------|--------|
//! | RTL8188EU | 0x0BDA:0x8179     | n 1x1  |
//! | RTL8192EU | 0x0BDA:0x818B     | n 2x2  |
//! | RTL8723BU | 0x0BDA:0xB720     | n 1x1 + BT |
//! | RTL8821CU | 0x0BDA:0xC811     | ac 1x1 |
//! | RTL8822BU | 0x0BDA:0xB82C     | ac 2x2 |
//!
//! Plus ≥ 15 rebranded (TP-Link, D-Link, ASUS, Edimax, …) variants.
//!
//! ## Runtime scope
//!
//! The retained RTL8188EU probe powers and identifies the chip, selects
//! descriptor-derived USB endpoints, loads authenticated firmware, installs
//! FIFO/MAC/BB/RF tables and performs checked post-table LC/full IQK. MAC
//! TX/RX remain closed until signed board qualification and deployment policy
//! admit the retained channel1 station service. That service binds native USB,
//! Open/WPA2 MLME, retained shared RSNA/software CCMP and Narf-Ring Ethernet.
//! No real board qualification artifact is supplied by this software port.
//! Other matched families remain detection-only. Legacy register/descriptor
//! helpers are diagnostics, not proof of working transport for those chips.
//!
//! ## References (GPL-2.0-or-later)
//!
//! - `drivers/net/wireless/realtek/rtl8xxxu/` (Linux v6.13)
//! - `drivers/net/wireless/realtek/rtw88/` (register layout cross-ref)

#![allow(dead_code)]

extern crate alloc;

pub mod btcoex;
mod calibration;
mod calibration_regs;
pub mod ccmp_runtime;
mod channel_runtime;
pub mod device_init;
pub mod efuse;
pub mod firmware_transport;
pub mod fw;
pub mod interface;
pub mod intr;
pub mod mac;
pub mod management_runtime;
pub mod packet_codec;
pub mod packet_transport;
pub mod phy;
pub mod phy_tables;
pub mod power_policy;
mod radio_init;
pub mod rate;
pub mod receive_runtime;
pub mod regs;
pub mod rtl8188e;
pub mod rtl8192e;
pub mod rtl8723b;
pub mod rtl8821c;
pub mod rtl8822b;
pub mod rx;
pub mod security_runtime;
pub mod service_runtime;
pub mod station_runtime;
pub mod usb;
mod wmm_runtime;

pub use regs::{ChipFamily, RTL8XXXU_VENDOR};

// ── MLME scaffold ───────────────────────────────────────────────────
//
// For auth/assoc frame building we reuse the iwlwifi MLME structures
// from the sibling module. The 802.11 management frame wire format is
// chip-independent; only the TX submission path differs between
// iwlwifi (PCIe UMAC cmd) and rtl8xxxu (bulk-OUT with TxDesc header).

pub use crate::iwlwifi::mlme::{
    auth_algorithm, build_assoc_request, build_assoc_request_rsn, build_open_auth_body,
    parse_beacon, parse_beacon_to_bss, AssocParams, AssocParamsRsn, AssocResponseFields,
    AuthResponse, BeaconInfo, BssDescriptor, ScanRequest,
};

/// The static VID/PID match table for all RTL8XXXU chip families.
///
/// Combines `REALTEK_USB_IDS` (Realtek-vendor primary IDs) with
/// `REBRANDED_IDS` (TP-Link, D-Link, ASUS, Edimax, etc.) so the
/// class registry fires for any supported dongle regardless of the
/// USB vendor label on the packaging.
///
/// Linux analogue: `struct usb_device_id rtl8xxxu_dev_table[]` in
/// `drivers/net/wireless/realtek/rtl8xxxu/rtl8xxxu_core.c` (~L7942).
pub static RTL8XXXU_USB_IDS: &[narf_drivers_usb::class_registry::UsbClassMatch] = {
    use narf_drivers_usb::class_registry::UsbClassMatch;
    use regs::*;
    &[
        // Primary Realtek-vendor IDs.
        UsbClassMatch::vid_pid(RTL8XXXU_VENDOR, RTL8188EU_ID),
        UsbClassMatch::vid_pid(RTL8XXXU_VENDOR, RTL8188EU_ID_ALT),
        UsbClassMatch::vid_pid(RTL8XXXU_VENDOR, RTL8192EU_ID),
        UsbClassMatch::vid_pid(RTL8XXXU_VENDOR, RTL8723BU_ID),
        UsbClassMatch::vid_pid(RTL8XXXU_VENDOR, RTL8821CU_ID),
        UsbClassMatch::vid_pid(RTL8XXXU_VENDOR, RTL8822BU_ID),
        // RTL8710BU / RTL8188GU
        UsbClassMatch::vid_pid(RTL8XXXU_VENDOR, 0xB711),
        // RTL8188EU rosewill ffef
        UsbClassMatch::vid_pid(RTL8XXXU_VENDOR, 0xFFEF),
        // Rebranded — TP-Link
        UsbClassMatch::vid_pid(0x2357, 0x0108),
        UsbClassMatch::vid_pid(0x2357, 0x0109),
        UsbClassMatch::vid_pid(0x2357, 0x0135),
        UsbClassMatch::vid_pid(0x2357, 0x010C),
        UsbClassMatch::vid_pid(0x2357, 0x0111),
        // Rebranded — D-Link
        UsbClassMatch::vid_pid(0x2001, 0x3319),
        UsbClassMatch::vid_pid(0x2001, 0x3311),
        // Rebranded — Edimax
        UsbClassMatch::vid_pid(0x7392, 0xB722),
        UsbClassMatch::vid_pid(0x7392, 0xB811),
        UsbClassMatch::vid_pid(0x7392, 0xA611),
        // Rebranded — ASUS
        UsbClassMatch::vid_pid(0x0B05, 0x18F0),
        // Rebranded — Abocom
        UsbClassMatch::vid_pid(0x07B8, 0x8179),
    ]
};

/// USB class probe function. Called by the class registry when a
/// newly-enumerated USB device matches `RTL8XXXU_USB_IDS`. Stores
/// the `Arc<USBDevice>` in the global device table and logs the
/// chip family. RTL8188EU starts a retained async factory/power/firmware/table owner;
/// other families remain detection-only until their runtime is implemented.
///
/// Linux analogue: `rtl8xxxu_probe` in
/// `drivers/net/wireless/realtek/rtl8xxxu/rtl8xxxu_core.c` (~L7692).
pub fn rtl8xxxu_probe(
    device: alloc::sync::Arc<narf_drivers_usb::device::USBDevice>,
) -> Result<(), narf_drivers_usb::class_registry::UsbProbeError> {
    use narf_drivers_usb::class_registry::UsbProbeError;

    let vid = device.vendor_id();
    let pid = device.product_id();
    let family = regs::ChipFamily::from_usb_id(vid, pid);

    if family == regs::ChipFamily::Unknown {
        return Err(UsbProbeError::UnsupportedVariant);
    }

    // Store the device Arc in the global registry so the driver's
    // async init task can find it.
    let firmware = alloc::sync::Arc::new(firmware_transport::Owner::new(
        firmware_transport::UsbControl::new(alloc::sync::Arc::clone(&device)),
        family,
    ));
    {
        let mut g = DEVICES.lock();
        if g.iter()
            .any(|d| alloc::sync::Arc::ptr_eq(&d.device, &device))
        {
            // Already registered (e.g. double-probe after hub reset).
            return Ok(());
        }
        g.push(Rtl8xxxuDevice {
            device: alloc::sync::Arc::clone(&device),
            family,
            firmware: firmware.clone(),
        });
    }

    use core::fmt::Write as _;
    let _ = writeln!(
        narf_console::Writer,
        "  rtl8xxxu: {:04x}:{:04x} {} slot={}",
        vid,
        pid,
        family.name(),
        device.slot_id()
    );

    if family == regs::ChipFamily::Rtl8188eu {
        let _ = writeln!(
            narf_console::Writer,
            "  rtl8188eu:   firmware required at /firmware/rtlwifi/rtl8188eufw.bin"
        );
        narf_scheduler::spawn(async move {
            let result = firmware.wait_initialize_registered().await;
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "  rtl8188eu: firmware attempt {:?}",
                result
            );
            if result.is_ok() {
                if let Some(factory) = firmware.factory() {
                    let _ = writeln!(
                        narf_console::Writer,
                        "  rtl8188eu:   calibration required at /firmware/{}",
                        power_policy::Calibration::asset_name(factory),
                    );
                }
                let service = interface::wait_attach(firmware.clone()).await;
                let _ = writeln!(
                    narf_console::Writer,
                    "  rtl8188eu: channel1 station service {:?}",
                    service
                );
            }
        });
    }

    Ok(())
}

/// Entry for one bound RTL8XXXU device in the global registry.
#[derive(Debug)]
pub struct Rtl8xxxuDevice {
    pub device: alloc::sync::Arc<narf_drivers_usb::device::USBDevice>,
    pub family: regs::ChipFamily,
    pub firmware: alloc::sync::Arc<firmware_transport::Owner<firmware_transport::UsbControl>>,
}

/// Global registry of bound RTL8XXXU USB-WiFi devices.
pub static DEVICES: narf_lib::sync::IrqSafeSpinLock<alloc::vec::Vec<Rtl8xxxuDevice>> =
    narf_lib::sync::IrqSafeSpinLock::new(alloc::vec::Vec::new());

/// Entry point registered by `drivers/wireless/src/lib.rs`.
pub fn register() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "rtl8xxxu-usb-ids", || {
        let _ = crate::iwlwifi::mlme::build_open_auth_body; // force link

        // Register with the USB class-driver registry so any
        // RTL8XXXU dongle that enumerates on xHCI is handed to
        // rtl8xxxu_probe automatically.
        //
        // Linux analogue: `module_usb_driver(rtl8xxxu_driver)` in
        // `drivers/net/wireless/realtek/rtl8xxxu/rtl8xxxu_core.c`
        // (~L8068), which calls `usb_register_driver`.
        let _ = narf_drivers_usb::class_registry::register_class_driver(
            "rtl8xxxu",
            RTL8XXXU_USB_IDS,
            rtl8xxxu_probe,
        );
        InitResult::Ok
    });
}

// ──────────────────────────────────────────────────────────────────────
// Bring-up orchestrator
//
// Walks a transport through every step needed to make the chip ready
// for association: power-on → FW upload → MAC init → PHY init →
// RF init → IQK → LC cal → channel set → RX enable.
//
// This is the "bring-up" entry point real hardware will eventually
// call once the USB stack delivers the device to `rtl8xxxu_probe`.
// Smokes call it against `FakeUsbTransport` to verify the full
// register-write order.
// ──────────────────────────────────────────────────────────────────────

/// Errors from the bring-up sequence.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BringUpError {
    /// Transport-level failure in one of the register pokes.
    Transport(usb::TransportError),
    /// FW download failed (checksum, plan, poll, etc).
    FwDownload(fw::FwDlError),
    /// Caller asked for a chip family this routine doesn't support yet.
    UnsupportedChip(regs::ChipFamily),
    /// Channel argument outside the chip's valid range.
    BadChannel(u8),
    /// The synchronous helper has no verified full radio/station lifecycle.
    NotImplemented,
}

impl From<usb::TransportError> for BringUpError {
    fn from(e: usb::TransportError) -> Self {
        BringUpError::Transport(e)
    }
}

/// Retired synchronous all-in-one bring-up. The old implementation ignored
/// table-write errors and IQK results and enabled RX before a complete MAC
/// lifecycle. Live probe initialization now uses `firmware_transport::Owner`
/// and the separately admitted retained station service.
pub fn bring_up_8188eu<T: usb::Rtl8xxxuTransport>(
    _transport: &T,
    _fw_payload: &[u8],
    channel: u8,
) -> Result<usize, BringUpError> {
    if !rtl8188e::channel_valid(channel) {
        return Err(BringUpError::BadChannel(channel));
    }
    Err(BringUpError::NotImplemented)
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests;

#[cfg(any(test, feature = "kernel-test"))]
mod firmware_transport_tests;

#[cfg(feature = "kernel-test")]
mod management_tests;
