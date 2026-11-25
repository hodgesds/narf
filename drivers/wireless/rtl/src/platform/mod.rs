//! What the legacy Realtek drivers need from the kernel, under one name in
//! both builds.
//!
//! The register-level code the loadable module runs (the rtlwifi power-on
//! table walker, interrupt masking and the EFUSE factory reader) is written
//! against a handful of services: a mapped BAR with 8/16/32-bit accessors,
//! a monotonic deadline, a responsive register spin and a spin lock. Built
//! in, those are the kernel's own crates ([`kernel`], plain re-exports, so
//! the built-in driver is unchanged). As a loadable `.ko` a module can cross
//! only the primitive C KABI, so the same names are provided over
//! `narf-module-rt` and KABI exports ([`kabi`]). Driver files import from
//! here instead of naming a kernel crate, which is what lets one source
//! file build both ways (the `ath11k.ko` precedent).

#[cfg(feature = "builtin")]
mod kernel;
#[cfg(feature = "builtin")]
pub use kernel::*;

#[cfg(feature = "module")]
pub(crate) mod kabi;
#[cfg(feature = "module")]
pub use kabi::*;
