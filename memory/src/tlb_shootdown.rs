//! Cross-CPU TLB shootdown.
//!
//! Spec: `memory/specification/asid-pcid-isolation.md` §4.
//!
//! On a single-CPU boot the local invalidation suffices and
//! `shootdown` reduces to running the arch-specific INVPCID /
//! TLBI on this CPU. When SMP bring-up wires APs (see
//! `arch/specification/smp-topology.md` §2), a peer-IPI fan-out
//! becomes the next iteration here.

#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ShootdownRequest {
    /// Tag (PCID / ASID). `None` = flush across all tags.
    pub tag:  Option<u16>,
    /// Single VA to invalidate. `None` = full per-tag flush.
    pub addr: Option<u64>,
    /// Range size in bytes (used when `addr` is set + range
    /// invalidation is needed). `None` = single page.
    pub size: Option<u64>,
}

impl ShootdownRequest {
    pub const fn full() -> Self {
        Self { tag: None, addr: None, size: None }
    }
    pub const fn for_tag(tag: u16) -> Self {
        Self { tag: Some(tag), addr: None, size: None }
    }
    pub const fn for_va(tag: u16, va: u64) -> Self {
        Self { tag: Some(tag), addr: Some(va), size: None }
    }
}

static SHOOTDOWN_COUNT: AtomicU64 = AtomicU64::new(0);

/// Per-CPU count of shootdowns observed (incremented by every
/// invocation). Useful for liveness assertions in smokes.
pub fn shootdown_count() -> u64 {
    SHOOTDOWN_COUNT.load(Ordering::Acquire)
}

/// Apply `req` locally + (when SMP is wired) IPI peer CPUs.
/// Single-CPU path is the default until APs come up.
pub fn shootdown(req: ShootdownRequest) {
    apply_local(req);
    SHOOTDOWN_COUNT.fetch_add(1, Ordering::AcqRel);
    // Peer-CPU fan-out lands when SMP bring-up wires APs:
    //
    //   for cpu in peers() {
    //       send_ipi(cpu, IPI_TLB_SHOOTDOWN);
    //       wait_ack();
    //   }
    //
    // The IPI handler on each peer calls `apply_local(req)` itself
    // and bumps a per-CPU ack counter the writer polls.
}

#[cfg(target_arch = "x86_64")]
fn apply_local(req: ShootdownRequest) {
    use narf_arch::x86_64::pcid;
    // SAFETY: kernel-test runs at CPL=0; INVPCID legality
    // gated below.
    if !pcid::invpcid_supported() {
        // Fall back to MOV-CR3 self-flush — global pages stay.
        // SAFETY: CR4.PCIDE may or may not be on; this is a
        // best-effort cleanup.
        unsafe {
            let cr3 = narf_arch::x86_64::cr::read_cr3();
            narf_arch::x86_64::cr::write_cr3(cr3);
        }
        return;
    }
    match (req.tag, req.addr) {
        (Some(t), Some(va)) => {
            // SAFETY: caller-asserted CPL=0.
            unsafe { pcid::invpcid_addr(t, va); }
        }
        (Some(t), None) => {
            // SAFETY: same.
            unsafe { pcid::invpcid_single(t); }
        }
        (None, _) => {
            // SAFETY: same.
            unsafe { pcid::invpcid_all_with_globals(); }
        }
    }
}

#[cfg(target_arch = "aarch64")]
fn apply_local(req: ShootdownRequest) {
    use narf_arch::aarch64::sysreg;
    match (req.tag, req.addr) {
        (Some(t), Some(va)) => {
            // SAFETY: kernel-test runs at EL1.
            unsafe { sysreg::tlbi_va_asid_inner_shareable(t, va); }
        }
        (Some(t), None) => {
            // SAFETY: same.
            unsafe { sysreg::tlbi_asid_inner_shareable(t); }
        }
        (None, _) => {
            // SAFETY: same.
            unsafe { sysreg::tlb_flush_all(); }
        }
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn apply_local(_req: ShootdownRequest) {}

#[doc(hidden)]
pub fn __reset_for_test() {
    SHOOTDOWN_COUNT.store(0, Ordering::Release);
}
