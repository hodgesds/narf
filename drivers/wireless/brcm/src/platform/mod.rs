//! What the shared Broadcom FullMAC code needs from the kernel, under one
//! name in both builds.
//!
//! The chip, boot, msgbuf runtime and FullMAC station logic is written
//! against a small set of services: an IRQ-safe spin lock, an async mutex,
//! a monotonic clock with deadlines and sleeps, a bounded responsive spin,
//! the `block_on` bridges and the IOMMU block verdict. Built in, those are
//! the kernel's own crates ([`kernel`], plain re-exports: the built-in driver
//! is unchanged). As a loadable `.ko` a module can cross only the primitive
//! C KABI, so the same names are provided over `narf-module-rt` and KABI
//! exports (`kabi`). Shared files import from here instead of naming a
//! kernel crate, which is what lets one source tree build both ways (the
//! `ath11k.ko` precedent, `drivers/wireless/ath11k/src/ath11k/platform/`).
//!
//! The PCI binding, provisioning and the netdev/wiphy glue differ in shape,
//! not just in name: built in they are `brcmfmac/{pcie,native_runtime}.rs`
//! and `cyw43439/interface.rs`; in the module they are
//! `brcmfmac/{pcie_kabi,provision_kabi}.rs` and `cyw43439/interface_module.rs`.

#[cfg(feature = "builtin")]
mod kernel;
#[cfg(feature = "builtin")]
pub use kernel::*;

#[cfg(feature = "module")]
pub(crate) mod kabi;
#[cfg(feature = "module")]
pub use kabi::*;
