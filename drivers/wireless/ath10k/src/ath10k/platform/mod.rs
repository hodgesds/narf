//! What ath10k needs from the kernel, under one name in both builds.
//!
//! The driver logic (BMI, firmware/board download, CE, HTC, WMI, HTT and the
//! station radio) is written against a small set of services: locks, an
//! async mutex, a monotonic clock and sleeps, coherent DMA32 memory, task
//! spawning, console output, the PCI function's command/ASPM/config access,
//! firmware lookup and the regulatory domain. Built in, those are the
//! kernel's own crates ([`kernel`], plain re-exports — the built-in driver is
//! unchanged). As a loadable `.ko`, a module can cross only the primitive C
//! KABI, so the same names are provided over `narf-module-rt` and KABI
//! exports ([`kabi`]). Driver files import from here instead of naming a
//! kernel crate, which is what lets one source tree build both ways.
//!
//! The probe binding and the netdev/wiphy glue differ in shape, not just in
//! name; they live in `pci.rs`/`interface.rs` (built in) and
//! `pci_kabi.rs`/`iface_module.rs` (module).

#[cfg(feature = "builtin")]
mod kernel;
#[cfg(feature = "builtin")]
pub use kernel::*;

#[cfg(feature = "module")]
pub(crate) mod kabi;
#[cfg(feature = "module")]
pub use kabi::*;
