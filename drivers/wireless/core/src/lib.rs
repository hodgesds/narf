// SPDX-License-Identifier: GPL-2.0-or-later
//! Shared surface for NARF Wi-Fi drivers.
//!
//! The driver-agnostic helpers factored out of the `narf-drivers-wireless`
//! facade so per-driver crates depend on this crate rather than on the facade
//! that aggregates them — the same split `narf-drivers-net-core` provides for
//! the NIC drivers, so no driver crate forms a cycle with the facade.
//!
//! The facade re-exports both modules, so existing `crate::firmware_asset` /
//! `crate::future_heap` references in the still-inlined drivers are
//! unaffected.

#![no_std]

extern crate alloc;

pub mod firmware_asset;
pub mod future_heap;
