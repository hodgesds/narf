//! Broadcom FullMAC PCIe — `brcmfmac` PCIe-bus path.
//!
//! Targets the PCIe-attached Broadcom FullMAC Wi-Fi parts. SDIO-attached
//! relatives (CYW43439, the BCM43xxx mobile family) live in
//! `crate::cyw43439`; this crate covers the desktop / Apple / enterprise
//! parts that ride PCIe and speak the **msgbuf** protocol over Broadcom's
//! H2D / D2H common-ring layout.
//!
//! PCI ownership, AI core discovery, explicit BCM43602 board-profile boot,
//! retained BAR2/DMA common rings, correlated control IOCTL/event ownership,
//! and bounded workers now have production implementations. Admission still
//! requires an exact platform calibration policy; no default board is invented.
//! Owned flow TX/RX rings now implement create/delete, posted receive buffers,
//! correlated retirement and fair bounded polling. Station lifecycle and
//! fixed-BSSID station integration now has a native publication path after
//! authenticated policy and firmware validation. Reset/recovery remain software
//! work. No interface is published from the control-only owner.
//!
//! ## References (all ISC / BSD-3 / GPL-2.0; NARF is GPL-2.0-or-later)
//!
//! - Linux `drivers/net/wireless/broadcom/brcm80211/brcmfmac/pcie.c`
//!   — `brcmf_pcie_probe`, register window + soft-reset
//!   (v6.6 ~L117..L300 for the register map, ~L2700..L2780 for
//!   the PCI ID table).
//! - Linux `drivers/net/wireless/broadcom/brcm80211/brcmfmac/commonring.c`
//!   — `brcmf_commonring_*` ring index dance (entire file).
//! - Linux `drivers/net/wireless/broadcom/brcm80211/brcmfmac/msgbuf.c`
//!   — `msgbuf_*` message structs + IOCTL flow
//!   (v6.6 ~L30..L180).
//! - Linux `drivers/net/wireless/broadcom/brcm80211/brcmfmac/msgbuf.h`
//!   — per-ring depth + item-size table (~L10..L23).
//! - Linux `drivers/net/wireless/broadcom/brcm80211/brcmfmac/bus.h`
//!   — `BRCMF_{H2D,D2H}_MSGRING_*` ring-id assignment (~L14..L26).
//! - Linux `drivers/net/wireless/broadcom/brcm80211/include/brcm_hw_ids.h`
//!   — the canonical PCIe device-id table (lines 16..101).
//!
//! NARF is GPL-2.0-or-later (root `LICENSE`), so direct reference to
//! these ISC / GPL-2.0 Linux files is in-policy.

#![allow(dead_code)]

// The module build (`brcmfmac.ko`) is the PCIe station: the AP, monitor,
// built-in PCI binding and provisioning owners stay built in. The three
// role-scope types the shared FullMAC seam names (`ap_source::Source`,
// `ap_scope::Capture`, `monitor_scope::Capture`) are uninhabited in the
// module (`*_module.rs`): no AP or monitor role can be entered there.
#[cfg(feature = "builtin")]
pub(crate) mod ap;
#[cfg(feature = "builtin")]
pub(crate) mod ap_beacon;
#[cfg(feature = "builtin")]
pub(crate) mod ap_key;
#[cfg(feature = "builtin")]
pub(crate) mod ap_keys;
#[cfg(feature = "builtin")]
pub(crate) mod ap_native;
#[cfg(feature = "builtin")]
pub(crate) mod ap_operation;
#[cfg(feature = "builtin")]
pub(crate) mod ap_packet;
#[cfg(feature = "builtin")]
pub(crate) mod ap_peer;
#[cfg(feature = "builtin")]
pub(crate) mod ap_plan;
#[cfg(feature = "builtin")]
pub mod ap_scope;
#[cfg(feature = "module")]
#[path = "ap_scope_module.rs"]
pub mod ap_scope;
#[cfg(feature = "builtin")]
pub mod ap_source;
#[cfg(feature = "module")]
#[path = "ap_source_module.rs"]
pub mod ap_source;
#[cfg(feature = "builtin")]
pub(crate) mod ap_station;
#[cfg(feature = "builtin")]
pub(crate) mod ap_stop;
pub mod ap_tx;
pub(crate) mod ap_wire;
pub mod boot;
pub mod bus;
#[cfg(feature = "builtin")]
pub mod cfg80211;
pub mod chip;
pub mod chip_profile;
#[cfg(feature = "builtin")]
pub mod connect;
pub mod event_mask;
pub mod firmware;
pub mod fweh;
pub mod fwil;

pub mod irq;
#[cfg(feature = "builtin")]
pub(crate) mod monitor;
pub mod monitor_native;
#[cfg(feature = "builtin")]
pub mod monitor_scope;
#[cfg(feature = "module")]
#[path = "monitor_scope_module.rs"]
pub mod monitor_scope;
pub(crate) mod monitor_wire;
pub mod msgbuf;
#[cfg(feature = "builtin")]
pub mod native_runtime;
pub mod p2p;
pub mod p2p_wire;
#[cfg(feature = "builtin")]
pub mod pcie;
pub mod pcie_ids;
#[cfg(feature = "module")]
pub mod pcie_kabi;
pub mod provision;
pub mod ringbuf;
pub mod runtime;
pub mod shared;
pub mod station_transport;
pub mod vif_bsscfg;
pub mod vif_demux;
pub mod vif_owner;
pub mod vif_wire;

#[cfg(feature = "builtin")]
pub use pcie::{name_for, probe, register_pci_driver, BrcmfmacDevice, BROADCOM_VENDOR};

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests;

/// Entry point invoked from the wireless crate's `register_initcalls`
/// (one level up in `drivers/wireless/src/lib.rs`).
#[cfg(feature = "builtin")]
pub fn register() {
    register_pci_driver();
    // Linux `brcmf_pciedrvr_pm` suspend/resume: the D3_INFORM/D0_INFORM
    // mailbox exchange is interrupt/poll driven, so it runs in the async
    // phase before the interrupt-gated device fan-out.
    narf_power::system_pm::register_async_system_pm("brcmfmac", alloc::sync::Arc::new(SystemPm));
}

#[cfg(feature = "builtin")]
struct SystemPm;
#[cfg(feature = "builtin")]
impl narf_power::system_pm::AsyncSystemPm for SystemPm {
    fn prepare_suspend<'a>(&'a self) -> narf_power::system_pm::SystemPmFuture<'a> {
        alloc::boxed::Box::pin(async {
            crate::cyw43439::interface::suspend_pcie()
                .await
                .map_err(pm_error)
        })
    }
    fn resume_from_suspend<'a>(&'a self) -> narf_power::system_pm::SystemPmFuture<'a> {
        alloc::boxed::Box::pin(async {
            // brcmf_pcie_pm_leave_D3: hot resume, or remove + probe again
            // (a generation swap keeping the netdev) when power was lost.
            let result = match native_runtime::resume().await {
                Some(result) => result,
                None => crate::cyw43439::interface::resume_pcie().await,
            };
            result.map_err(pm_error)
        })
    }
}
#[cfg(feature = "builtin")]
fn pm_error(error: crate::cyw43439::runtime::Error) -> narf_power::device_pm::DevicePmError {
    match error {
        crate::cyw43439::runtime::Error::Busy => narf_power::device_pm::DevicePmError::Busy,
        _ => narf_power::device_pm::DevicePmError::DriverError,
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub(crate) mod runtime_tests;

#[cfg(any(test, feature = "kernel-test"))]
mod data_wire_tests;

#[cfg(any(test, feature = "kernel-test"))]
mod vif_wire_tests;

#[cfg(any(test, feature = "kernel-test"))]
mod vif_owner_tests;

#[cfg(any(test, feature = "kernel-test"))]
mod vif_bsscfg_tests;

#[cfg(any(test, feature = "kernel-test"))]
mod p2p_tests;

#[cfg(any(test, feature = "kernel-test"))]
pub(crate) mod p2p_transport_cases;

/// `narf_module_init` (module build): install the kernel DRBG as the
/// protocol code's entropy source, then register the PCI matches.
#[cfg(feature = "module")]
pub fn register_module() {
    crate::platform::install_entropy();
    pcie_kabi::register_pci_driver();
}
