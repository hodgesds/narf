//! Epoch variant — crossbeam-style reclamation.
//!
//! Spec: `rcu/specification/spec.md` §3.4. Each `pin()` snapshots the
//! current global epoch into a per-CPU slot. Writers advance the epoch
//! and reclaim any object queued at an epoch strictly older than the
//! minimum slot value.
//!
//! Stage-2 scope: API surface + functional single-CPU implementation.
//! The variant is used where the QSBR poll-boundary assumption doesn't
//! apply (e.g. code called from an IRQ handler). On Stage-2 single-CPU
//! the QSBR and Epoch variants behave identically in practice; the
//! distinction becomes visible once SMP lands and an IRQ handler runs
//! on a CPU whose executor is between polls.
//!
//! The Epoch collector's global state is deliberately separate from
//! QSBR's so the two are independent. A consumer picks one and uses the
//! matching `Atomic<T>` methods. (Stage-2 only the QSBR-backed
//! `Atomic<T>` ships; epoch-variant `Atomic` types are a main-track
//! follow-up.)

extern crate alloc;

use core::marker::PhantomData;
use core::sync::atomic::{AtomicU64, Ordering};

use alloc::boxed::Box;
use narf_lib::percpu::MAX_CPUS;

/// Epoch-collector global epoch (separate from QSBR's).
static EPOCH: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
struct PinnedCell {
    /// `u64::MAX` = unpinned; otherwise this reader's pin epoch.
    pinned: AtomicU64,
}

impl PinnedCell {
    const NEW: Self = Self { pinned: AtomicU64::new(u64::MAX) };
}

static PINNED: [PinnedCell; MAX_CPUS] = [const { PinnedCell::NEW }; MAX_CPUS];

#[inline]
fn this_cpu() -> &'static PinnedCell {
    let idx = narf_arch::current_cpu_id().raw() as usize;
    &PINNED[if idx < MAX_CPUS { idx } else { 0 }]
}

/// RAII pin handle. `!Send + !Sync`: one CPU owns it; drop unpins.
#[derive(Debug)]
pub struct EpochGuard {
    _not_send: PhantomData<*const ()>,
}

impl EpochGuard {
    /// Snapshot epoch at pin time.
    pub fn epoch(&self) -> u64 {
        this_cpu().pinned.load(Ordering::Relaxed)
    }
}

impl Drop for EpochGuard {
    fn drop(&mut self) {
        this_cpu().pinned.store(u64::MAX, Ordering::Release);
    }
}

/// Take an epoch-collector pin. Read side: one atomic load + one store.
pub fn pin() -> EpochGuard {
    let e = EPOCH.load(Ordering::Acquire);
    this_cpu().pinned.store(e, Ordering::Release);
    EpochGuard { _not_send: PhantomData }
}

/// Advance the global epoch.
pub fn advance() -> u64 {
    EPOCH.fetch_add(1, Ordering::AcqRel) + 1
}

/// Minimum currently-pinned epoch across all CPUs. Objects queued at
/// an epoch strictly less than this value have no live reader.
pub fn min_pinned() -> u64 {
    let mut min = u64::MAX;
    for c in PINNED.iter() {
        let v = c.pinned.load(Ordering::Acquire);
        if v < min { min = v; }
    }
    min
}

/// Wait until every previously-pinned reader has released.
/// Stage-2 single-CPU: no preemption, so any reader that existed at
/// `advance()` has already released by the time we check. Left as a
/// loop stub so SMP can replace the body.
pub fn sync_blocking() {
    let target = advance();
    let _ = target;
    // No-op on Stage-2 single-CPU.
}

/// Simple Epoch-backed `defer_drop`. Stage-2 minimal implementation —
/// advances once and drops inline. Safe on single-CPU with !Send guards
/// because any live reader is on the same CPU and has already released
/// by the time we reach this point (no preemption within a code path).
pub fn defer_drop<T: Send + 'static>(value: Box<T>) {
    sync_blocking();
    drop(value);
}
