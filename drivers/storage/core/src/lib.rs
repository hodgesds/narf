//! Shared helpers for NARF storage drivers.
//!
//! The leaf modules the storage drivers and smokes share: SD/MMC protocol
//! (`sd_proto`), eMMC (`emmc`), UFS (`ufs`), and the request gate
//! (`req_gate`). Per-driver crates depend on this; the `narf-drivers-storage`
//! facade re-exports it. Mirrors `narf-drivers-net-core`.
#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]
extern crate alloc;
pub mod emmc;
pub mod req_gate;
pub mod sd_proto;
pub mod ufs;
