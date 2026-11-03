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
//! RTL8821CE retains the same firmware/DMA owner through exact-chip calibration,
//! separately qualified operating power and native station. Both C21/C22 may
//! separately qualify legacy rates/WMM, HT20 and RX/TX Block Ack. RTL8822BE
//! retains diagnostic identification. Physical validation and genuine measured
//! deployment board/power assets remain separate gates.
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

mod band5;
mod bf;
mod calibration8821c;
mod calibration8822b;
mod channel_policy;
mod coding;
#[cfg(feature = "kernel-test")]
mod coding_tests;
mod coex;
#[cfg(feature = "kernel-test")]
mod coex_tests;
mod command;
mod dack;
mod dm;
#[cfg(feature = "kernel-test")]
mod dm_station_tests;
#[cfg(feature = "kernel-test")]
mod dm_tests;
mod dma_stop;
mod dpk;
#[cfg(feature = "kernel-test")]
mod dpk_tests;
pub mod efuse;
pub mod efuse8822b;
mod endpoints;
mod fallback;
#[cfg(feature = "kernel-test")]
mod fallback_tests;
mod firmware_lifecycle;
mod firmware_native;
mod firmware_transport;
mod functions;
pub mod fw;
mod hardware;
mod ht;
mod ht40;
pub mod operating_reset;
mod vht;
pub use operating_reset::{reset_function, Error as OperatingResetError};
mod rejoin;
mod runtime_idle;
mod runtime_ps_scope;
mod runtime_ps_wire;
pub use firmware_transport::runtime_lps::{
    lps_function, lps_request_function, Error as RuntimeSleepError,
};
pub use runtime_idle::{idle_function, RuntimeIdle};
mod system_pm;
mod system_pm_native;
mod system_pm_wire;
mod system_pm_worker;
pub use rejoin::{rejoin_function, Error as RejoinError};
mod rx_ba;
mod rx_ba_power;
mod tracking8821c;
mod tracking8822b;
pub use tracking8821c::Request as PowerTrackingRequest;
mod tx_ba;
mod tx_ba_power;
#[cfg(feature = "kernel-test")]
mod tx_ba_tests;
#[cfg(feature = "kernel-test")]
mod tx_ba_tid_tests;
pub use tx_ba_power::Request as TxBaRequest;
#[cfg(feature = "kernel-test")]
mod rx_ba_tests;
pub use rx_ba_power::Request as RxBaRequest;
#[cfg(feature = "kernel-test")]
mod ht_tests;
pub(super) mod interface;
mod mac;
mod operating8821c;
mod operating8822b;
pub(super) mod packet_core;
pub(super) mod packet_format;
mod packet_phy;
mod pci_firmware;
mod phy;
#[path = "phy/rtl8821c.rs"]
mod phy8821c;
mod phy8822b;
mod power_policy;
mod probe_guard;
mod protection;
#[cfg(feature = "kernel-test")]
mod protection_tests;
mod qos;
#[cfg(feature = "kernel-test")]
mod qos_tests;
pub use protection::Request as RtsRequest;
mod publication;
mod qualification;
pub use qualification::Request as ContinuationRequest;
mod native8822b;
mod radio;
mod radio8821c;
mod radio8822b;
mod reserved_page;
mod scan;
#[cfg(feature = "kernel-test")]
mod scan_tests;
mod security_cam;
mod sibling;
mod station;
pub(super) mod station_control;
mod station_power8821c;
mod station_profile;
/// RTL8821CU USB host-interface transport (Linux rtw88/usb.c).
mod usb;
/// RTL8821CU firmware/register backend (Linux rtw88/usb.c `rtw_usb_ops`).
mod usb_firmware;
#[cfg(feature = "kernel-test")]
mod usb_firmware_tests;
/// RTL8821CU USB driver registration (Linux rtw88/rtw8821cu.c).
mod usb_driver;
/// RTL8821CU USB packet owner (Linux rtw88/usb.c TX queues, RX split).
mod usb_packet;
#[cfg(feature = "kernel-test")]
mod usb_packet_tests;
#[cfg(feature = "kernel-test")]
mod usb_tests;
mod wmm;
mod wow;
pub use calibration8821c::{Error as C21CalibrationError, Request as C21CalibrationRequest};
pub use firmware_lifecycle::{Stage as FirmwareStage, Status as FirmwareStatus};
pub use firmware_transport::{Error as FirmwareError, Info as FirmwareInfo};
pub use ht::Request as Ht20Request;
pub use mac::Info as MacInfo;
pub use operating8821c::{Info as C21OperatingPowerInfo, Request as C21OperatingPowerRequest};
pub use phy::Info as PhyTablesInfo;
pub use power_policy::{Error as PowerError, Permission as PowerPermission};
pub use radio::Info as RadioInfo;
pub use radio8821c::Info as C21CalibrationInfo;
pub use radio8821c::StationInfo as C21StationRadioInfo;
pub use station_power8821c::Request as C21StationRequest;
pub use station_profile::Request as C22LegacyWmmRequest;
pub use station_profile::Request as C21LegacyWmmRequest;
pub mod pci;
pub(crate) mod pci_park;

#[cfg(any(test, feature = "kernel-test"))]
mod pci_park_tests;
pub mod power;
mod power_tables;
pub mod regs;

pub use pci::{name_for, probe, provision, provision_function, register_pci_driver, Rtw88Device};
pub use regs::{REALTEK_VENDOR, RTL_DEV_8821CE, RTL_DEV_8822BE, RTL_DEV_8822CE};

/// Entry point invoked from the wireless crate's `register_initcalls`
/// (one level up in `drivers/wireless/src/lib.rs`).
pub fn register() {
    register_pci_driver();
    usb_driver::register();
    narf_power::system_pm::register_async_system_pm(
        "rtw88",
        alloc::sync::Arc::new(system_pm::SystemPm),
    );
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
