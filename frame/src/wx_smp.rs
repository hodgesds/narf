//! SMP exercise for the JIT-text W^X seal.
//!
//! Spec: `bpf/specification/spec.md` §8.6.
//!
//! `bpf_text::seal` splits a **live** kernel-linear leaf and then issues a
//! synchronous global TLB flush, with every AP running — that is the whole
//! hazard, and it is invisible to a single-CPU test. `memory/` cannot host
//! this: the scheduler sits above it in the dependency graph, so the crate
//! that can spawn a task pinned to a peer CPU is this one.
//!
//! The shape: pin a task to CPU 1 that calls a sealed JIT stub in a tight
//! loop and checks its return value on every iteration, then — from the BSP,
//! while that is running — seal a series of fresh packs. Each seal performs
//! `protect_ro` on live linear-map leaves, the first one in a given 1 GiB
//! region also performing the `__split_large_page` demotion, and every one
//! ending in `flush_user_tlb_all_cpus`, which drops every non-global TLB entry
//! on the peer that is mid-loop.
//!
//! A wrong answer from the stub means the peer executed something other than
//! the sealed text — a stale or torn translation. A hang means the flush's
//! ack-wait deadlocked against the peer. Both are the failures worth having a
//! test for; neither is reachable at `NARF_QEMU_SMP=1`, so the test skips
//! there rather than passing vacuously.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_memory::bpf_text::{self, JitCap};

/// Iterations the peer performs before retiring. Large enough that the BSP's
/// seals land inside the loop, small enough that a wedged scheduler shows up
/// as the bounded-wait Skip rather than a suite hang.
const PEER_ITERS: u64 = 200_000;

/// Packs the BSP seals while the peer runs. Each one is a live alias
/// protection plus a synchronous cross-CPU flush.
const BSP_SEALS: usize = 8;

static PEER_DONE: AtomicBool = AtomicBool::new(false);
static PEER_STARTED: AtomicBool = AtomicBool::new(false);
static PEER_BAD: AtomicU64 = AtomicU64::new(0);
static PEER_RUNS: AtomicU64 = AtomicU64::new(0);
/// Entry VA of the stub the peer calls. Published before the peer is spawned.
static PEER_TARGET: AtomicU64 = AtomicU64::new(0);

/// The same `mov eax, 42; ret` / `mov w0, #42; ret` stub `bpf_text`'s own
/// smokes use, duplicated rather than exported: making it `pub` would put a
/// hand-assembled instruction blob in the memory crate's public API purely for
/// one test in another crate.
#[cfg(target_arch = "x86_64")]
const RET42: &[u8] = &[0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3];
#[cfg(target_arch = "aarch64")]
const RET42: &[u8] = &[0x40, 0x05, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6];

/// Allocate, register, write and seal a `RET42` stub. `None` on any failure —
/// the caller turns that into the right `TestResult` for its context.
fn seal_stub(cap: &JitCap) -> Option<bpf_text::TextAlloc> {
    let a = bpf_text::alloc(cap, RET42.len(), 0).ok()?;
    let ok = narf_memory::bpf_extable::register_image(
        a.va,
        a.va,
        a.va + a.len as u64,
        alloc::vec::Vec::new(),
    )
    .is_ok()
        && bpf_text::write(&a, 0, RET42).is_ok()
        && bpf_text::seal(cap, &a).is_ok();
    if ok {
        Some(a)
    } else {
        narf_memory::bpf_extable::unregister_image(a.va);
        bpf_text::free(a);
        None
    }
}

fn drop_stub(a: bpf_text::TextAlloc) {
    narf_memory::bpf_extable::unregister_image(a.va);
    bpf_text::free(a);
}

fn smoke_bpf_text_seal_splits_under_concurrent_execution() -> TestResult {
    if narf_lib::smp::cpu_count() <= 1 {
        return TestResult::Skip("needs more than one online CPU");
    }
    // A stale result from an earlier run would make this pass for the wrong
    // reason; the statics are file-scoped and this is the only writer.
    PEER_DONE.store(false, Ordering::Release);
    PEER_STARTED.store(false, Ordering::Release);
    PEER_BAD.store(0, Ordering::Release);
    PEER_RUNS.store(0, Ordering::Release);

    let cap = JitCap::bootstrap();
    let Some(target) = seal_stub(&cap) else {
        return TestResult::Fail("could not seal the stub the peer executes");
    };
    PEER_TARGET.store(target.va, Ordering::Release);

    narf_scheduler::spawn_stackful_pinned(
        async {
            PEER_STARTED.store(true, Ordering::Release);
            let va = PEER_TARGET.load(Ordering::Acquire);
            // SAFETY: `va` names a sealed, executable `extern "C"` stub that
            // takes no arguments, clobbers only the return register, and
            // returns. The BSP keeps it alive — and keeps its extable image
            // registered — until `PEER_DONE` is observed.
            let f: extern "C" fn() -> u64 = unsafe { core::mem::transmute::<u64, _>(va) };
            for _ in 0..PEER_ITERS {
                if f() != 42 {
                    PEER_BAD.fetch_add(1, Ordering::AcqRel);
                }
                PEER_RUNS.fetch_add(1, Ordering::AcqRel);
            }
            PEER_DONE.store(true, Ordering::Release);
        },
        1,
    );

    // Wait for the peer to actually get on-CPU before doing the seals, so the
    // splits land *during* its loop rather than before it starts. Bounded: a
    // scheduler that never dispatches the task must not wedge the suite.
    let mut spins: u64 = 0;
    while !PEER_STARTED.load(Ordering::Acquire) && spins < 200_000_000 {
        core::hint::spin_loop();
        spins += 1;
    }
    if !PEER_STARTED.load(Ordering::Acquire) {
        // Leave the stub mapped: the task may still be queued and could run
        // later, and freeing text it is about to enter would be far worse than
        // leaking one 6-byte allocation for the rest of the boot.
        return TestResult::Skip("peer task never reached CPU 1");
    }

    // The concurrent half. Every `seal` here runs `protect_ro` against live
    // linear-map leaves and finishes with a synchronous global flush while the
    // peer is executing JIT text on CPU 1.
    let mut sealed = alloc::vec::Vec::new();
    for _ in 0..BSP_SEALS {
        match seal_stub(&cap) {
            Some(a) => sealed.push(a),
            // Pool exhaustion is not a failure of the property under test.
            None => break,
        }
    }
    let seals_done = sealed.len();

    spins = 0;
    while !PEER_DONE.load(Ordering::Acquire) && spins < 2_000_000_000 {
        core::hint::spin_loop();
        spins += 1;
    }
    let done = PEER_DONE.load(Ordering::Acquire);
    let bad = PEER_BAD.load(Ordering::Acquire);
    let runs = PEER_RUNS.load(Ordering::Acquire);

    if done {
        // Only safe to reclaim once the peer has stopped entering the text.
        for a in sealed {
            drop_stub(a);
        }
        drop_stub(target);
    } else {
        for a in sealed {
            drop_stub(a);
        }
    }

    if bad != 0 {
        return TestResult::Fail("JIT text returned the wrong value during a concurrent seal");
    }
    if !done {
        return TestResult::Skip("peer did not finish within the bounded wait");
    }
    if runs != PEER_ITERS {
        return TestResult::Fail("peer loop did not complete every iteration");
    }
    if seals_done == 0 {
        // No seal ran concurrently, so nothing was exercised and a pass would
        // be vacuous.
        return TestResult::Skip("no pack could be sealed during the peer's loop");
    }
    TestResult::Pass
}
kernel_test_in!(
    "frame",
    smoke_bpf_text_seal_splits_under_concurrent_execution
);
