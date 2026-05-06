//! x86_64 NUMA primitives.
//!
//! Spec: `arch/specification/irq-cache-numa.md` §6.
//!
//! The arch crate doesn't parse SRAT itself (that's `acpi/`'s
//! job) — it just exposes a hook for the SRAT-aware caller to
//! plug in an `apic_id → domain` mapping that the scheduler /
//! memory allocator can consult later.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use core::sync::atomic::{AtomicPtr, Ordering};

static APIC_TO_DOMAIN: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

type Cb = fn(u32) -> u8;

/// Install the SRAT-derived mapping. Subsequent
/// `domain_for_apic_id` calls dispatch through `cb`. Calling
/// twice with different callbacks is allowed; the most recent
/// wins.
pub fn set_apic_to_domain(cb: Cb) {
    APIC_TO_DOMAIN.store(cb as *mut (), Ordering::Release);
}

/// Resolve `apic_id` to a NUMA domain. Returns `0` (the
/// implicit single-node fallback) if no mapping is installed.
pub fn domain_for_apic_id(apic_id: u32) -> u8 {
    let p = APIC_TO_DOMAIN.load(Ordering::Acquire);
    if p.is_null() {
        return 0;
    }
    // SAFETY: `p` was stored as a `Cb` function pointer via
    // `set_apic_to_domain`; the round-trip preserves provenance.
    let cb: Cb = unsafe { core::mem::transmute(p) };
    cb(apic_id)
}
