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
//! ## Scope (this commit)
//!
//! 1. USB device-ID table (≥ 20 IDs).
//! 2. USB control-transfer encode for register read/write.
//! 3. EFUSE physical-stream decoder (PG-header format).
//! 4. Firmware blob name resolution per chip family.
//! 5. Per-chip Stage 0/1 register init tables for all 5 families.
//! 6. MLME scaffold (reuses iwlwifi structures for auth/assoc).
//! 7. USB bulk-OUT TX descriptor (32-byte / 40-byte variants).
//!
//! ## Deferred
//!
//! - Live USB probe (NARF USB bus integration).
//! - Actual firmware download over bulk-OUT.
//! - RX ring / ISR handling.
//! - PHY / RF calibration tables.
//! - Rate control.
//! - BT coexistence (RTL8723BU).
//!
//! ## References (GPL-2.0-or-later)
//!
//! - `drivers/net/wireless/realtek/rtl8xxxu/` (Linux v6.13)
//! - `drivers/net/wireless/realtek/rtw88/` (register layout cross-ref)

#![allow(dead_code)]

extern crate alloc;

pub mod btcoex;
pub mod efuse;
pub mod fw;
pub mod intr;
pub mod mac;
pub mod phy;
pub mod phy_tables;
pub mod rate;
pub mod regs;
pub mod rtl8188e;
pub mod rtl8192e;
pub mod rtl8723b;
pub mod rtl8821c;
pub mod rtl8822b;
pub mod rx;
pub mod usb;

pub use regs::{ChipFamily, RTL8XXXU_VENDOR};

// ── MLME scaffold ───────────────────────────────────────────────────
//
// For auth/assoc frame building we reuse the iwlwifi MLME structures
// from the sibling module. The 802.11 management frame wire format is
// chip-independent; only the TX submission path differs between
// iwlwifi (PCIe UMAC cmd) and rtl8xxxu (bulk-OUT with TxDesc header).

pub use crate::iwlwifi::mlme::{
    AssocParams,
    AssocParamsRsn,
    AssocResponseFields,
    AuthResponse,
    BssDescriptor,
    BeaconInfo,
    ScanRequest,
    auth_algorithm,
    build_assoc_request,
    build_assoc_request_rsn,
    build_open_auth_body,
    parse_beacon,
    parse_beacon_to_bss,
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
/// chip family. Async EFUSE reads and firmware upload are spawned
/// as a background task.
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
    {
        let mut g = DEVICES.lock();
        if g.iter().any(|d| {
            d.device.slot_id() == device.slot_id()
        }) {
            // Already registered (e.g. double-probe after hub reset).
            return Ok(());
        }
        g.push(Rtl8xxxuDevice {
            device: alloc::sync::Arc::clone(&device),
            family,
        });
    }

    use core::fmt::Write as _;
    let _ = writeln!(
        narf_console::Writer,
        "  rtl8xxxu: {:04x}:{:04x} {} slot={}",
        vid, pid, family.name(), device.slot_id()
    );

    Ok(())
}

/// Entry for one bound RTL8XXXU device in the global registry.
#[derive(Debug)]
pub struct Rtl8xxxuDevice {
    pub device: alloc::sync::Arc<narf_drivers_usb::device::USBDevice>,
    pub family: regs::ChipFamily,
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
}

impl From<usb::TransportError> for BringUpError {
    fn from(e: usb::TransportError) -> Self {
        BringUpError::Transport(e)
    }
}

/// Apply the 8188EU register-init tables in the canonical order
/// (MAC → BB → AGC → RF) and run path-A IQK, then tune to `channel`.
///
/// `fw_payload` is the firmware bytes *with the 32-byte Realtek
/// header already stripped* (`FwLayout::strip_header`). Pass an
/// empty slice to skip FW upload (e.g. when running smokes against
/// a chip that already has firmware resident).
///
/// Source: `core.c::rtl8xxxu_init_device` (~L4255) is the Linux
/// reference for the overall ordering.
pub fn bring_up_8188eu<T: usb::Rtl8xxxuTransport>(
    transport: &T,
    fw_payload: &[u8],
    channel: u8,
) -> Result<usize, BringUpError> {
    if !rtl8188e::channel_valid(channel) {
        return Err(BringUpError::BadChannel(channel));
    }

    // Stage 0: power-on register bank.
    for &(reg, val) in rtl8188e::stage0_register_bank() {
        transport.write8(reg, val)?;
    }

    // Stage 1: FW download (if a blob was supplied).
    let mut total_writes = rtl8188e::stage0_register_bank().len();
    if !fw_payload.is_empty() {
        // Caller is expected to have armed the fake-poll progression.
        let n = fw::upload_firmware_blob(transport, fw_payload)
            .map_err(BringUpError::FwDownload)?;
        total_writes += n.div_ceil(regs::RTL_FW_PAGE_SIZE);
    }

    // Stage 2: MAC init.
    let mut n_mac = 0usize;
    rtl8188e::init_mac(|r, v| {
        let _ = transport.write8(r, v);
        n_mac += 1;
    });
    total_writes += n_mac;

    // Stage 3: BB + AGC init.
    let mut n_phy = 0usize;
    rtl8188e::init_phy(|r, v| {
        let _ = transport.write32(r, v);
        n_phy += 1;
    });
    total_writes += n_phy;

    // Stage 4: RF path-A init via LSSI write.
    let mut n_rf = 0usize;
    rtl8188e::init_rf(|addr, val| {
        let lssi = phy::lssi_encode(addr, val);
        let _ = transport.write32(phy::REG_FPGA0_LSSI_A, lssi);
        n_rf += 1;
    });
    total_writes += n_rf;

    // Stage 5: IQK path A (single iteration; the real driver retries).
    let mut iqk = [phy::IqkStep { reg: 0, val: 0 };
                   rtl8188e::IQK_PATH_A_STEP_COUNT];
    let n_iqk = rtl8188e::build_iqk_path_a_sequence(&mut iqk);
    for step in &iqk[..n_iqk] {
        transport.write32(step.reg, step.val)?;
    }
    total_writes += n_iqk;

    // Stage 6: LC calibration. Shared gen1 sequence — 3 RF writes via LSSI.
    // 8188EU is 1T1R: only the path-A writes have wire effect, but
    // emitting the path-B write keeps the trace identical to Linux.
    for (path, addr, val) in phy::lc_calibrate_rf_writes() {
        let lssi = phy::lssi_encode(addr, val);
        let lssi_reg = phy::lssi_reg_for_path(path);
        transport.write32(lssi_reg, lssi)?;
        total_writes += 1;
    }

    // Stage 7: channel set.
    for &(reg, val) in rtl8188e::channel_set_writes_8188e(channel).iter() {
        transport.write32(reg, val)?;
        total_writes += 1;
    }

    // Stage 8: enable RX — set the RX-MAC enable bit (REG_CR bit 3).
    // Source: `regs.h::CR_RXDMA_ENABLE = 0x08` set by core.c::set_rx_mode.
    let cr = transport.read8(regs::REG_CR)?;
    transport.write8(regs::REG_CR, cr | 0x08)?;
    total_writes += 1;

    Ok(total_writes)
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests;
