//! What ath9k needs from the kernel, in both builds.
//!
//! ath9k is a softMAC driver: it programs the MAC/PHY directly, does its own
//! calibration, rate control and regulatory enforcement, and has no firmware
//! in between. Its source is written against the kernel's crates
//! (`narf_bus`, `narf_lib`, `narf_time`, `narf_io`, ...) by name. Built in,
//! those are the real crates and nothing here changes them; [`kernel`] adds
//! only the two names whose module-side form differs in path ([`regdb`] and
//! [`WirelessNetIface`]).
//!
//! As a loadable `.ko` a module can cross only the primitive C KABI, so
//! [`kabi`] provides the same names over `narf-module-rt` and KABI exports.
//! The crates the driver names but cannot link (`narf_bus`, `narf_lib`,
//! `narf_time`, `narf_scheduler`, `narf_console`, `narf_io`,
//! `narf_capabilities`, `narf_firmware`, `narf_net`, `narf_ipc`,
//! `narf_power`) are [`kabi::compat`] modules of the same name, the subset
//! of each API ath9k uses; a driver file imports them under
//! `#[cfg(feature = "module")]`, so its paths read the same in both builds.
//! `narf-crypto`, `narf-wireless` and `narf-drivers-wireless-ath-core` are
//! linked kernel-free (their `kernel` feature off).
//!
//! The PCI binding and the netdev/wiphy glue differ in shape, not only in
//! name: built in they are `ath9k::probe` and `interface.rs` over
//! `narf_bus`/`narf_net`; in the module `pci_kabi.rs` and `iface_module.rs`
//! over the KABI and the `WIFI` family host.

#[cfg(feature = "builtin")]
mod kernel;
#[cfg(feature = "builtin")]
pub use kernel::*;

#[cfg(feature = "module")]
pub(crate) mod kabi;
#[cfg(feature = "module")]
pub use kabi::*;
