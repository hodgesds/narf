//! Realtek rtlwifi PCIe Wi-Fi family.
//!
//! Covers the legacy Realtek PCIe Wi-Fi generation that shipped circa
//! 2010–2017, predating the `rtw88` driver rewrite.  Supported chips:
//!
//! | Chip        | PCI ID | Standard        | Notes                   |
//! |-------------|--------|-----------------|-------------------------|
//! | RTL8188EE   | 0x8179 | 802.11n 1T1R    | Budget 2.4 GHz          |
//! | RTL8192CE   | 0x8178 | 802.11n 2T2R    | Common 2.4 GHz          |
//! | RTL8192CE   | 0x8176 | 802.11n 2T2R    | Alternate DID           |
//! | RTL8192DE   | 0x8193 | 802.11n 2T2R    | Dual-band               |
//! | RTL8192EE   | 0x818B | 802.11n 2T2R    | 2014 refresh            |
//! | RTL8723AE   | 0x8723 | 802.11n 1T1R+BT | Combo A-cut             |
//! | RTL8723BE   | 0xB723 | 802.11n 1T1R+BT | Combo B-cut             |
//! | RTL8821AE   | 0x8821 | 802.11ac 1T1R   | Wi-Fi 5                 |
//!
//! RTL8822BE (0xB822) is not in this family: it belongs to `rtw88`
//! (`specification/rtlwifi.md` §1) and must never be matched here.
//!
//! ## Retained native ownership
//!
//! 1. PCI device-ID table — all 8 IDs registered with `narf-bus`.
//! 2. BAR2 control mapping and verifiably parked PCI bus mastering.
//! 3. EFUSE read — per-byte LDO-switched access (`REG_EFUSE_CTRL` / `REG_EFUSE_TEST`).
//! 4. Per-chip register-bank / MMIO-size constants.
//! 5. TX descriptor layout (BE queue) + RX descriptor layout.
//! 6. Per-chip authenticated firmware, linked-ring/LLT and calibrated station
//!    continuations; exact profiles and prerequisites live in the family spec.
//! 7. Separate RTL8723AE NASR station, RTL8723BE NBTH thermal and RTL8821AE
//!    N21C coexistence programs retain their original radio/firmware owners.
//!
//! ## Admission
//!
//! Probe alone grants no station or RF authority. Actual signed qualification,
//! current host policy and original PCI/firmware sources enclose native effects
//! and publication. Missing optional coexistence/tracking inputs preserve their
//! documented closed/coarse baseline. Broader profiles and physical acceptance
//! remain pending; a restrictive park does not prove DMA idle or RF reset.
//!
//! ## References (all GPL-2.0; NARF is GPL-2.0-or-later)
//!
//! - `rtlwifi/pci.c` — probe, BAR mapping, queue init
//! - `rtlwifi/efuse.c` — EFUSE byte-access and LDO power-switch
//! - `rtlwifi/rtl8188ee/reg.h`, `def.h`, `trx.h`
//! - `rtlwifi/rtl8192ee/reg.h`, `def.h`, `fw.h`
//! - `rtlwifi/rtl8821ae/def.h`

#![allow(dead_code)]

// One driver source in both builds. Only the PCI binding differs: built in,
// `pci::probe` / `firmware_native::PciIo` use `narf-bus` and the function's
// live capability; in `rtl.ko`, `pci_kabi` and `firmware_native_kabi` provide
// the same names over the KABI (`crate::platform`).
mod aspm;
pub mod btcoex;
pub mod channel;
pub mod channel_power;
pub mod dma;
pub mod efuse;
mod fallback;
#[cfg(feature = "builtin")]
mod firmware_native;
#[cfg(feature = "module")]
#[path = "firmware_native_kabi.rs"]
mod firmware_native;
pub mod firmware_transport;
pub mod fw;
pub mod h2c;
mod ht;
pub mod identity;
mod interface;
mod power_runtime;
mod probe_scan;
pub use fallback::Request as RateFallbackRequest;
pub use ht::Request as Ht20Request;
pub use ht::Request as Ht40Request;
mod antenna;
pub use antenna::Request as AntennaDiversityRequest;
mod tracking;
pub use rtl8723be::tracking::Request as Rtl8723beThermalTrackingRequest;
pub use rtl8821ae::coex_program::Request as Rtl8821aeCoexistenceRequest;
pub use tracking::Request as ThermalTrackingRequest;
mod protection;
pub use protection::Request as ProtectionRequest;
pub mod irq;
pub mod mac;
mod packet_mac;
pub mod pci;
pub mod phy;
pub mod power;
pub mod prepare;
mod prepare_native;
pub mod radio;
mod rate_adaptive;
pub mod regs;
pub mod rf;
pub mod rx;
mod station_control;
mod station_power;
pub mod tx;
pub mod vht;
pub(crate) mod wmm;

pub mod rtl8188ee;
pub mod rtl8192ce;
pub mod rtl8192de;
pub mod rtl8192ee;
pub mod rtl8723ae;
pub mod rtl8723be;
pub mod rtl8821ae;

// The module build's PCI binding (`rtl.ko`).
#[cfg(feature = "module")]
pub mod pci_kabi;

pub use interface::set_inactive_power_save;
pub use interface::set_leisure_power_save;
pub use interface::set_pcie_aspm;
pub use pci::RtlwifiDevice;
#[cfg(feature = "builtin")]
pub use pci::{probe, register_pci_driver};
pub use regs::{name_for, ALL_DEV_IDS, REALTEK_VENDOR};

/// Entry point invoked from `drivers/wireless/src/lib.rs`.
#[cfg(feature = "builtin")]
pub fn register() {
    register_pci_driver();
}

#[cfg(any(test, feature = "kernel-test"))]
mod efuse_tests;

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests;

// Source-identical base.c arithmetic; each chip owns its observations.
pub(crate) mod watchdog_traffic;
