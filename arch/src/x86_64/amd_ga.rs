//! AMD GA / IA mode predicates.
//!
//! Spec: `arch/specification/irq-cache-numa.md` §2.
//!
//! Thin layer on top of `amd_vi::EXT_FEATURES` so callers don't
//! have to reach into the bitmap directly. v0.1 surfaces the
//! Guest Address (GASUP) and IOMMU Address (IASUP) gates;
//! richer GA programming lives in the IOMMU bring-up pipeline
//! in `bus/iommu/amd`.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::amd_vi::{EFR_GASUP, EFR_IASUP};

/// `true` iff the AMD-Vi engine advertises Guest Address mode.
pub fn ga_supported(amd_vi_efr: u64) -> bool {
    amd_vi_efr & EFR_GASUP != 0
}

/// `true` iff the AMD-Vi engine advertises IOMMU Address mode.
pub fn ia_supported(amd_vi_efr: u64) -> bool {
    amd_vi_efr & EFR_IASUP != 0
}
