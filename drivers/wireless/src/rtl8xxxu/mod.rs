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

pub mod efuse;
pub mod fw;
pub mod regs;
pub mod rtl8188e;
pub mod rtl8192e;
pub mod rtl8723b;
pub mod rtl8821c;
pub mod rtl8822b;
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

/// Entry point registered by `drivers/wireless/src/lib.rs`.
pub fn register() {
    // USB bus integration is deferred — no USB bus framework exists yet
    // in NARF. This function is a placeholder that will register USB
    // device-ID match callbacks once the USB host-controller driver
    // and bus matcher land.
    //
    // For now, print the chip families we support so the boot log
    // reflects that the driver is loaded.
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "rtl8xxxu-usb-ids", || {
        let _ = crate::iwlwifi::mlme::build_open_auth_body; // force link
        InitResult::Ok
    });
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests;
