//! What the MT76 driver needs from the kernel, under one name in both builds.
//!
//! The driver logic (WFDMA rings, MCU framing, firmware download, the
//! station join and the packet path) is written against a small set of
//! services: locks, an async mutex, a monotonic clock and sleeps, coherent
//! DMA, task spawning, console output, the PCI command register, the
//! regulatory policy snapshot and the AP/radio control authorities. Built in,
//! those are the kernel's own crates ([`kernel`], plain re-exports — the
//! built-in driver is unchanged). As a loadable `.ko`, a module can cross only
//! the primitive C KABI, so the same names are provided over `narf-module-rt`
//! and KABI exports ([`kabi`]). Driver files import from here instead of
//! naming a kernel crate, which is what lets one source tree build both ways
//! (the `drivers/wireless/ath11k` precedent).
//!
//! The PCI binding (probe, BAR mapping, MSI) and the netdev/wiphy glue differ
//! in shape, not just in name; they live in `mt7921/pci.rs` / `iface.rs`
//! (built in) and `mt7921/pci_kabi.rs` / `iface_module.rs` (module).

#[cfg(feature = "builtin")]
mod kernel;
#[cfg(feature = "builtin")]
pub use kernel::*;

#[cfg(feature = "module")]
pub(crate) mod kabi;
#[cfg(feature = "module")]
pub use kabi::*;
