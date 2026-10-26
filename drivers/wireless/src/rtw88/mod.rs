//! Realtek RTW88 family PCIe bring-up and retained RTL8822CE station.
//!
//! Targets the three chips most common on AMD Zen2 laptops:
//!
//! - **RTL8821CE** — Wi-Fi 5 1x1 (`10ec:c821`).
//! - **RTL8822CE** — Wi-Fi 5 2x2 (`10ec:c822`).
//! - **RTL8822BE** — Wi-Fi 5 2x2, older B-cut (`10ec:b822`).
//!
//! RTL8822CE retains one owner through factory/OTP capture, authenticated
//! section firmware, MAC/PHY tables, signed measured board qualification,
//! bounded calibration and an awake channel1 legacy20 station. Its native
//! DMA/CCX receipts drive host Open/WPA2-PSK and software CCMP through the
//! same registered Device used by kernel DHCP. The initial data profile
//! requires basic1Mbps and a fresh lifecycle after terminal closure.
//!
//! RTL8821CE retains factory/firmware and inactive MAC ownership; its RF and
//! station remain gated. RTL8822BE retains diagnostic identification. Physical
//! validation and deployment board/power assets remain separate gates.
//!
//! ## References (all GPL-2.0; NARF is GPL-2.0-or-later)
//!
//! - Linux `drivers/net/wireless/realtek/rtw88/pci.c`
//!   — `rtw_pci_probe`, `rtw_pci_id_table` (v6.6 ~L1620..L1750)
//! - Linux `drivers/net/wireless/realtek/rtw88/main.c`
//!   — `rtw_power_on` (v6.6 ~L1900..L2100)
//! - Linux `drivers/net/wireless/realtek/rtw88/mac.c`
//!   — `rtw_pwr_seq_parser`, `rtw_mac_init` (v6.6 ~L140..L280)
//! - Linux `drivers/net/wireless/realtek/rtw88/efuse.c`
//!   — `rtw_efuse_read` (v6.6 ~L50..L200)
//! - Linux `drivers/net/wireless/realtek/rtw88/reg.h`
//!   — REG_* offsets
//! - Linux `drivers/net/wireless/realtek/rtw88/rtw8822c.c` /
//!   `rtw8821c.c` — per-chip PWR-seq tables (only the cross-chip
//!   prologue is used here)
//! - Realtek public RTL8822C datasheet — vendor signage on register
//!   names

#![allow(dead_code)]

extern crate alloc;

mod calibration8821c;
mod command;
mod dack;
pub mod efuse;
mod firmware_lifecycle;
mod firmware_native;
mod firmware_transport;
pub mod fw;
mod hardware;
pub(super) mod interface;
mod mac;
mod operating8821c;
pub(super) mod packet_core;
pub(super) mod packet_format;
mod pci_firmware;
mod phy;
#[path = "phy/rtl8821c.rs"]
mod phy8821c;
mod power_policy;
mod probe_guard;
mod radio;
mod radio8821c;
mod reserved_page;
mod sibling;
mod station;
pub(super) mod station_control;
mod station_power8821c;
pub use calibration8821c::{Error as C21CalibrationError, Request as C21CalibrationRequest};
pub use firmware_lifecycle::{Stage as FirmwareStage, Status as FirmwareStatus};
pub use firmware_transport::{Error as FirmwareError, Info as FirmwareInfo};
pub use mac::Info as MacInfo;
pub use operating8821c::{Info as C21OperatingPowerInfo, Request as C21OperatingPowerRequest};
pub use phy::Info as PhyTablesInfo;
pub use power_policy::{Error as PowerError, Permission as PowerPermission};
pub use radio::Info as RadioInfo;
pub use radio8821c::Info as C21CalibrationInfo;
pub use radio8821c::StationInfo as C21StationRadioInfo;
pub use station_power8821c::Request as C21StationRequest;
pub mod pci;
pub(crate) mod pci_park;

#[cfg(any(test, feature = "kernel-test"))]
mod pci_park_tests;
pub mod power;
mod power_tables;
pub mod regs;

pub use pci::{name_for, probe, provision, register_pci_driver, Rtw88Device};
pub use regs::{REALTEK_VENDOR, RTL_DEV_8821CE, RTL_DEV_8822BE, RTL_DEV_8822CE};

/// Entry point invoked from the wireless crate's `register_initcalls`
/// (one level up in `drivers/wireless/src/lib.rs`).
pub fn register() {
    register_pci_driver();
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests;

#[cfg(any(test, feature = "kernel-test"))]
mod efuse_tests;

#[cfg(any(test, feature = "kernel-test"))]
mod pci_tests;

#[cfg(any(test, feature = "kernel-test"))]
mod power_tests;

#[cfg(any(test, feature = "kernel-test"))]
mod authority_tests;
