//! Per-crate kernel-test smokes for `narf-abi`.
//!
//! Tests register via `narf_kernel_test::kernel_test_in!` so the
//! runner groups output under `"abi"`. Bodies are copied verbatim
//! from `verification/src/lib.rs` — only paths change
//! (`narf_abi::xxx` → `crate::xxx`).

extern crate alloc;

use narf_kernel_test::{kernel_test_in, TestResult};

// ── layout / wire-format pins ──────────────────────────────────────

fn smoke_abi_submission_layout() -> TestResult {
    // Wire-format pin. Spec §3 field order is op, flags, caps, tag,
    // inline; under `#[repr(C)]` the 16-aligned `CapSlot` forces an
    // 8-byte interior pad and an 8-byte tail pad, for 144 bytes total
    // at 16-byte alignment. The naive 4+4+64+8+48=128 undercounts both.
    use core::mem::{align_of, size_of};
    if size_of::<crate::Submission>() != 144 {
        return TestResult::Fail("Submission size drifted from 144");
    }
    if align_of::<crate::Submission>() != 16 {
        return TestResult::Fail("Submission alignment drifted from 16");
    }
    // Every OpCode discriminant must match the spec-pinned wire tag.
    // Adding a variant is fine; changing one of these is an ABI break.
    let opcode_pins: &[(crate::OpCode, u32)] = &[
        (crate::OpCode::Noop, 0x0000),
        (crate::OpCode::Cancel, 0x0001),
        (crate::OpCode::RingSend, 0x0002),
        (crate::OpCode::RingRecv, 0x0003),
        (crate::OpCode::Yield, 0x0004),
        (crate::OpCode::DomainEnter, 0x0005),
        (crate::OpCode::DomainExit, 0x0006),
    ];
    for &(op, wire) in opcode_pins {
        if op.as_u32() != wire {
            return TestResult::Fail("OpCode wire discriminant drifted");
        }
    }
    TestResult::Pass
}
kernel_test_in!("abi", smoke_abi_submission_layout);

fn smoke_abi_completion_layout() -> TestResult {
    // Same pin for completions: 64 bytes, 8-byte aligned (status is u32
    // at offset 8, Rust inserts 4 bytes of tail padding before result).
    use core::mem::{align_of, size_of};
    if size_of::<crate::Completion>() != 64 {
        return TestResult::Fail("Completion size drifted from 64");
    }
    if align_of::<crate::Completion>() != 8 {
        return TestResult::Fail("Completion alignment drifted from 8");
    }
    let status_pins: &[(crate::NarfStatus, u32)] = &[
        (crate::NarfStatus::Ok, 0x0000),
        (crate::NarfStatus::Pending, 0x0001),
        (crate::NarfStatus::Cancelled, 0x0002),
        (crate::NarfStatus::CancelRequested, 0x0003),
        (crate::NarfStatus::CapRevoked, 0x0004),
        (crate::NarfStatus::InvalidOp, 0x0005),
        (crate::NarfStatus::Busy, 0x0006),
        (crate::NarfStatus::Closed, 0x0007),
    ];
    for &(st, wire) in status_pins {
        if st.as_u32() != wire {
            return TestResult::Fail("NarfStatus wire discriminant drifted");
        }
    }
    TestResult::Pass
}
kernel_test_in!("abi", smoke_abi_completion_layout);

// ── ring round-trip / dispatcher ───────────────────────────────────

fn smoke_abi_ring_roundtrip() -> TestResult {
    // Submit a Submission through the submission ring, on the kernel
    // side turn it into a Completion, then verify the tag round-trips
    // through the completion ring. This proves the `narf_ipc` SPSC ring
    // happily carries the wire-layout-pinned `Submission`/`Completion`
    // types at their declared sizes (i.e. we haven't accidentally made
    // the payload an un-transferable type).
    use core::sync::atomic::{AtomicU64, Ordering};
    static RECEIVED_TAG: AtomicU64 = AtomicU64::new(0);

    RECEIVED_TAG.store(0, Ordering::Relaxed);
    narf_scheduler::__reset_queues_for_test();

    let (mut sq_tx, mut sq_rx) = crate::submission_channel::<4>();
    let (mut cq_tx, mut cq_rx) = crate::completion_channel::<4>();

    // Userland side: submit, await completion, stash the tag.
    narf_scheduler::spawn(async move {
        let sub = crate::Submission::noop(crate::Tag::new(0xDEADBEEF));
        let _ = sq_tx.send(sub).await;
        if let Ok(c) = cq_rx.recv().await {
            RECEIVED_TAG.store(c.tag, Ordering::Relaxed);
        }
    });

    // Kernel side: drain one submission, emit a matching completion.
    narf_scheduler::spawn(async move {
        if let Ok(sub) = sq_rx.recv().await {
            let c = crate::Completion::ok(sub.tag());
            let _ = cq_tx.send(c).await;
        }
    });

    narf_scheduler::run_until_empty();
    if RECEIVED_TAG.load(Ordering::Relaxed) == 0xDEADBEEF {
        TestResult::Pass
    } else {
        TestResult::Fail("submission→completion tag did not round-trip")
    }
}
kernel_test_in!("abi", smoke_abi_ring_roundtrip);

fn smoke_abi_dispatcher_roundtrip() -> TestResult {
    use crate::{
        completion_channel, submission_channel, Dispatcher, NarfStatus, OpCode, Submission, Tag,
    };
    use core::sync::atomic::{AtomicU8, Ordering};

    static OUTCOME: AtomicU8 = AtomicU8::new(0);

    narf_scheduler::__reset_queues_for_test();

    let (mut sq_tx, sq_rx) = submission_channel::<4>();
    let (cq_tx, mut cq_rx) = completion_channel::<4>();

    // 1. Spawn "Kernel" task: the dispatcher.
    narf_scheduler::spawn(async move {
        let mut dispatcher = Dispatcher::new(sq_rx, cq_tx);
        dispatcher.run().await;
    });

    // 2. Spawn "Userland" task: the producer.
    narf_scheduler::spawn(async move {
        // Op 1: Noop
        let tag1 = Tag::new(0x1111);
        sq_tx.send(Submission::noop(tag1)).await.unwrap();

        let c1 = cq_rx.recv().await.unwrap();
        if c1.tag() != tag1 || c1.status != NarfStatus::Ok {
            OUTCOME.store(2, Ordering::Relaxed);
            return;
        }

        // Op 2: Yield
        let tag2 = Tag::new(0x2222);
        let mut sub2 = Submission::noop(tag2);
        sub2.op = OpCode::Yield;
        sq_tx.send(sub2).await.unwrap();

        let c2 = cq_rx.recv().await.unwrap();
        if c2.tag() != tag2 || c2.status != NarfStatus::Ok {
            OUTCOME.store(3, Ordering::Relaxed);
            return;
        }

        OUTCOME.store(1, Ordering::Relaxed);

        // Signal termination by dropping SQ/CQ.
        core::mem::drop(sq_tx);
        core::mem::drop(cq_rx);
    });

    narf_scheduler::run_until_empty();

    match OUTCOME.load(Ordering::Relaxed) {
        1 => TestResult::Pass,
        2 => TestResult::Fail("Noop failed or tag mismatch"),
        3 => TestResult::Fail("Yield failed or tag mismatch"),
        _ => TestResult::Fail("Dispatcher never completed roundtrip"),
    }
}
kernel_test_in!("abi", smoke_abi_dispatcher_roundtrip);

// ── cancel protocol ────────────────────────────────────────────────

fn smoke_abi_cancel_before_target_marks_cancelled() -> TestResult {
    // §3.1 protocol: a Cancel submitted *before* its target is drained
    // must complete the target with `Cancelled` (when CANCELLABLE is
    // set on the target). The cancel op itself always completes `Ok`.
    use crate::{
        completion_channel, submission_channel, Dispatcher, NarfStatus, Submission,
        SubmissionFlags, Tag,
    };
    use core::sync::atomic::{AtomicU8, Ordering};

    static OUTCOME: AtomicU8 = AtomicU8::new(0);

    narf_scheduler::__reset_queues_for_test();
    let (mut sq_tx, sq_rx) = submission_channel::<4>();
    let (cq_tx, mut cq_rx) = completion_channel::<4>();

    narf_scheduler::spawn(async move {
        let mut d = Dispatcher::new(sq_rx, cq_tx);
        d.run().await;
    });

    narf_scheduler::spawn(async move {
        let target = Tag::new(0x7777);
        let canceller = Tag::new(0xC001);

        // 1. Submit the cancel first — dispatcher records the target.
        sq_tx
            .send(Submission::cancel(canceller, target))
            .await
            .unwrap();
        let c1 = cq_rx.recv().await.unwrap();
        if c1.tag() != canceller || c1.status != NarfStatus::Ok {
            OUTCOME.store(2, Ordering::Relaxed);
            return;
        }

        // 2. Submit the target with CANCELLABLE — must come back Cancelled.
        let mut sub = Submission::noop(target);
        sub.flags = SubmissionFlags::CANCELLABLE;
        sq_tx.send(sub).await.unwrap();
        let c2 = cq_rx.recv().await.unwrap();
        if c2.tag() != target || c2.status != NarfStatus::Cancelled {
            OUTCOME.store(3, Ordering::Relaxed);
            return;
        }

        OUTCOME.store(1, Ordering::Relaxed);
        core::mem::drop(sq_tx);
        core::mem::drop(cq_rx);
    });

    narf_scheduler::run_until_empty();
    match OUTCOME.load(Ordering::Relaxed) {
        1 => TestResult::Pass,
        2 => TestResult::Fail("cancel submission did not complete Ok"),
        3 => TestResult::Fail("cancellable target did not complete Cancelled"),
        _ => TestResult::Fail("cancel protocol round-trip did not run"),
    }
}
kernel_test_in!("abi", smoke_abi_cancel_before_target_marks_cancelled);

fn smoke_abi_cancel_non_cancellable_marks_request() -> TestResult {
    // §3.1: a target without CANCELLABLE completes with
    // `CancelRequested` so the caller knows the op ran to completion.
    use crate::{completion_channel, submission_channel, Dispatcher, NarfStatus, Submission, Tag};
    use core::sync::atomic::{AtomicU8, Ordering};

    static OUTCOME: AtomicU8 = AtomicU8::new(0);

    narf_scheduler::__reset_queues_for_test();
    let (mut sq_tx, sq_rx) = submission_channel::<4>();
    let (cq_tx, mut cq_rx) = completion_channel::<4>();

    narf_scheduler::spawn(async move {
        let mut d = Dispatcher::new(sq_rx, cq_tx);
        d.run().await;
    });

    narf_scheduler::spawn(async move {
        let target = Tag::new(0x8888);
        let canceller = Tag::new(0xC002);

        sq_tx
            .send(Submission::cancel(canceller, target))
            .await
            .unwrap();
        let _ = cq_rx.recv().await.unwrap();

        // No CANCELLABLE flag on the target.
        sq_tx.send(Submission::noop(target)).await.unwrap();
        let c = cq_rx.recv().await.unwrap();
        if c.tag() != target || c.status != NarfStatus::CancelRequested {
            OUTCOME.store(2, Ordering::Relaxed);
            return;
        }

        OUTCOME.store(1, Ordering::Relaxed);
        core::mem::drop(sq_tx);
        core::mem::drop(cq_rx);
    });

    narf_scheduler::run_until_empty();
    match OUTCOME.load(Ordering::Relaxed) {
        1 => TestResult::Pass,
        2 => TestResult::Fail("non-cancellable target did not surface CancelRequested"),
        _ => TestResult::Fail("dispatcher did not run the protocol"),
    }
}
kernel_test_in!("abi", smoke_abi_cancel_non_cancellable_marks_request);

fn smoke_abi_dispatch_latency_accumulates() -> TestResult {
    // The Dispatcher wraps each dispatch_one in a FnTime::scope guard,
    // so after N successful submissions the public ABI_DISPATCH_LATENCY
    // accumulator reports at least N samples. Welford's mean must be
    // non-zero (the measured elapsed cycle-count per dispatch is
    // non-zero on any real timer source).
    use crate::{
        completion_channel, submission_channel, Dispatcher, Submission, Tag, ABI_DISPATCH_LATENCY,
    };
    use core::sync::atomic::{AtomicU8, Ordering};

    static OUTCOME: AtomicU8 = AtomicU8::new(0);

    let before = ABI_DISPATCH_LATENCY.welford().count;

    narf_scheduler::__reset_queues_for_test();
    let (mut sq_tx, sq_rx) = submission_channel::<4>();
    let (cq_tx, mut cq_rx) = completion_channel::<4>();

    narf_scheduler::spawn(async move {
        let mut d = Dispatcher::new(sq_rx, cq_tx);
        d.run().await;
    });

    narf_scheduler::spawn(async move {
        for i in 0..3 {
            sq_tx
                .send(Submission::noop(Tag::new(0xF00 + i)))
                .await
                .unwrap();
            let _ = cq_rx.recv().await.unwrap();
        }
        OUTCOME.store(1, Ordering::Relaxed);
        core::mem::drop(sq_tx);
        core::mem::drop(cq_rx);
    });

    narf_scheduler::run_until_empty();
    if OUTCOME.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("producer did not round-trip all three ops");
    }

    let w = ABI_DISPATCH_LATENCY.welford();
    if w.count < before + 3 {
        return TestResult::Fail("FnTime sample count did not grow by the number of dispatches");
    }
    if w.mean <= 0.0 {
        return TestResult::Fail("FnTime mean dispatch latency was non-positive");
    }
    // Histogram must have registered non-zero samples too.
    let hist = ABI_DISPATCH_LATENCY.histogram();
    if hist.count() < before + 3 {
        return TestResult::Fail("FnTime histogram missed samples");
    }
    TestResult::Pass
}
kernel_test_in!("abi", smoke_abi_dispatch_latency_accumulates);

fn smoke_abi_linked_chain_cancels_forward() -> TestResult {
    // §3.1 "Linked submissions": cancelling any member of a LINKED
    // chain auto-cancels the rest of the chain. Here the producer
    // submits A (starts a chain), then B (LINKED, inherits A's chain),
    // then Cancel(A), then C (LINKED, still same chain). The chain
    // registry flagged chain_id when Cancel(A) ran; C must short-
    // circuit with Cancelled even though it was never named directly.
    use crate::{
        completion_channel, submission_channel, Dispatcher, NarfStatus, Submission,
        SubmissionFlags, Tag,
    };
    use core::sync::atomic::{AtomicU8, Ordering};

    static OUTCOME: AtomicU8 = AtomicU8::new(0);

    narf_scheduler::__reset_queues_for_test();
    let (mut sq_tx, sq_rx) = submission_channel::<8>();
    let (cq_tx, mut cq_rx) = completion_channel::<8>();

    narf_scheduler::spawn(async move {
        let mut d = Dispatcher::new(sq_rx, cq_tx);
        d.run().await;
    });

    narf_scheduler::spawn(async move {
        let ta = Tag::new(0xA0);
        let tb = Tag::new(0xB0);
        let tc = Tag::new(0xC0);
        let tcan = Tag::new(0xCA);

        // A — fresh chain, CANCELLABLE. Runs to completion before the
        // cancel arrives (serial dispatch) → Ok.
        let mut a = Submission::noop(ta);
        a.flags = SubmissionFlags::CANCELLABLE;
        sq_tx.send(a).await.unwrap();

        // B — LINKED, CANCELLABLE. Part of A's chain.
        let mut b = Submission::noop(tb);
        b.flags = SubmissionFlags::CANCELLABLE | SubmissionFlags::LINKED;
        sq_tx.send(b).await.unwrap();

        // Cancel A. The Dispatcher marks A's chain_id pending.
        sq_tx.send(Submission::cancel(tcan, ta)).await.unwrap();

        // C — LINKED, CANCELLABLE. Must short-circuit with Cancelled.
        let mut c = Submission::noop(tc);
        c.flags = SubmissionFlags::CANCELLABLE | SubmissionFlags::LINKED;
        sq_tx.send(c).await.unwrap();

        // Drain: A (Ok), B (Ok — entered chain before cancel marked it),
        // cancel (Ok), C (Cancelled).
        let ca = cq_rx.recv().await.unwrap();
        if ca.tag() != ta || ca.status != NarfStatus::Ok {
            OUTCOME.store(2, Ordering::Relaxed);
            return;
        }
        let cb = cq_rx.recv().await.unwrap();
        if cb.tag() != tb || cb.status != NarfStatus::Ok {
            OUTCOME.store(3, Ordering::Relaxed);
            return;
        }
        let ccan = cq_rx.recv().await.unwrap();
        if ccan.tag() != tcan || ccan.status != NarfStatus::Ok {
            OUTCOME.store(4, Ordering::Relaxed);
            return;
        }
        let cc = cq_rx.recv().await.unwrap();
        if cc.tag() != tc || cc.status != NarfStatus::Cancelled {
            OUTCOME.store(5, Ordering::Relaxed);
            return;
        }

        OUTCOME.store(1, Ordering::Relaxed);
        core::mem::drop(sq_tx);
        core::mem::drop(cq_rx);
    });

    narf_scheduler::run_until_empty();
    match OUTCOME.load(Ordering::Relaxed) {
        1 => TestResult::Pass,
        2 => TestResult::Fail("A did not complete Ok"),
        3 => TestResult::Fail("B did not complete Ok (chain not yet cancelled when B dispatched)"),
        4 => TestResult::Fail("Cancel op did not complete Ok"),
        5 => TestResult::Fail("C was not auto-cancelled via its chain"),
        _ => TestResult::Fail("linked chain roundtrip did not run"),
    }
}
kernel_test_in!("abi", smoke_abi_linked_chain_cancels_forward);

fn smoke_abi_cancel_stale_tag_is_noop() -> TestResult {
    // §3.1: the cancel op is non-blocking and always succeeds even
    // when the target tag never shows up. A subsequent unrelated
    // submission must not inherit the cancel.
    use crate::{completion_channel, submission_channel, Dispatcher, NarfStatus, Submission, Tag};
    use core::sync::atomic::{AtomicU8, Ordering};

    static OUTCOME: AtomicU8 = AtomicU8::new(0);

    narf_scheduler::__reset_queues_for_test();
    let (mut sq_tx, sq_rx) = submission_channel::<4>();
    let (cq_tx, mut cq_rx) = completion_channel::<4>();

    narf_scheduler::spawn(async move {
        let mut d = Dispatcher::new(sq_rx, cq_tx);
        d.run().await;
    });

    narf_scheduler::spawn(async move {
        let stale = Tag::new(0xDEAD);
        let other = Tag::new(0xAAAA);
        let canceller = Tag::new(0xC003);

        // Cancel a tag the producer will never submit.
        sq_tx
            .send(Submission::cancel(canceller, stale))
            .await
            .unwrap();
        let c1 = cq_rx.recv().await.unwrap();
        if c1.status != NarfStatus::Ok {
            OUTCOME.store(2, Ordering::Relaxed);
            return;
        }

        // Now submit an unrelated tag — must complete Ok.
        sq_tx.send(Submission::noop(other)).await.unwrap();
        let c2 = cq_rx.recv().await.unwrap();
        if c2.tag() != other || c2.status != NarfStatus::Ok {
            OUTCOME.store(3, Ordering::Relaxed);
            return;
        }

        OUTCOME.store(1, Ordering::Relaxed);
        core::mem::drop(sq_tx);
        core::mem::drop(cq_rx);
    });

    narf_scheduler::run_until_empty();
    match OUTCOME.load(Ordering::Relaxed) {
        1 => TestResult::Pass,
        2 => TestResult::Fail("cancel for a never-submitted tag did not return Ok"),
        3 => TestResult::Fail("unrelated tag inherited a stale cancel"),
        _ => TestResult::Fail("dispatcher never drained"),
    }
}
kernel_test_in!("abi", smoke_abi_cancel_stale_tag_is_noop);

// ── extended abi coverage ──────────────────────────────────────────
//
// Existing smokes pin layout + dispatcher round-trip + the cancel
// protocol. These close the remaining wire-stability and accessor
// surfaces: per-field offsets, every OpCode/NarfStatus discriminant,
// SubmissionFlags algebra, accessor invariants, and Dispatcher
// behaviour on more than one consecutive submission.

fn smoke_abi_submission_field_offsets() -> TestResult {
    // Per-field offset pin. The total size is checked above; this
    // catches a reorder that preserves total size but shifts a
    // single field — e.g. swapping `tag` and `inline` would keep
    // 144 bytes but break every wire consumer.
    use core::mem::offset_of;
    let pins: &[(usize, usize, &str)] = &[
        (offset_of!(crate::Submission, op), 0, "op"),
        (offset_of!(crate::Submission, flags), 4, "flags"),
        (offset_of!(crate::Submission, caps), 16, "caps"),
        (offset_of!(crate::Submission, tag), 80, "tag"),
        (offset_of!(crate::Submission, inline), 88, "inline"),
    ];
    for &(got, want, name) in pins {
        if got != want {
            // Box::leak gives the message a 'static lifetime.
            let msg = alloc::format!(
                "Submission::{} offset {} (expected {})",
                name, got, want
            );
            let s: &'static str = alloc::boxed::Box::leak(msg.into_boxed_str());
            return TestResult::Fail(s);
        }
    }
    TestResult::Pass
}
kernel_test_in!("abi", smoke_abi_submission_field_offsets);

fn smoke_abi_completion_field_offsets() -> TestResult {
    // Completion layout: tag(0), status(8), result(16). Catches a
    // reorder of `result` ahead of `status` (would silently shift
    // every payload word).
    use core::mem::offset_of;
    let pins: &[(usize, usize, &str)] = &[
        (offset_of!(crate::Completion, tag), 0, "tag"),
        (offset_of!(crate::Completion, status), 8, "status"),
        (offset_of!(crate::Completion, result), 16, "result"),
    ];
    for &(got, want, name) in pins {
        if got != want {
            let msg = alloc::format!(
                "Completion::{} offset {} (expected {})",
                name, got, want
            );
            let s: &'static str = alloc::boxed::Box::leak(msg.into_boxed_str());
            return TestResult::Fail(s);
        }
    }
    TestResult::Pass
}
kernel_test_in!("abi", smoke_abi_completion_field_offsets);

fn smoke_abi_opcode_full_wire_pins() -> TestResult {
    // Exhaustive enumeration of every OpCode variant's wire tag.
    // The existing layout smoke covers the first 7; this catches
    // drift in the file-op + power-management blocks the existing
    // pins skip.
    let pins: &[(crate::OpCode, u32, &str)] = &[
        (crate::OpCode::Noop, 0x0000, "Noop"),
        (crate::OpCode::Cancel, 0x0001, "Cancel"),
        (crate::OpCode::RingSend, 0x0002, "RingSend"),
        (crate::OpCode::RingRecv, 0x0003, "RingRecv"),
        (crate::OpCode::Yield, 0x0004, "Yield"),
        (crate::OpCode::DomainEnter, 0x0005, "DomainEnter"),
        (crate::OpCode::DomainExit, 0x0006, "DomainExit"),
        (crate::OpCode::OpenFile, 0x0010, "OpenFile"),
        (crate::OpCode::Read, 0x0011, "Read"),
        (crate::OpCode::Write, 0x0012, "Write"),
        (crate::OpCode::Close, 0x0013, "Close"),
        (crate::OpCode::Mmap, 0x0014, "Mmap"),
        (crate::OpCode::Munmap, 0x0015, "Munmap"),
        (crate::OpCode::CpuTopology, 0x0020, "CpuTopology"),
        (crate::OpCode::CpuPerfState, 0x0021, "CpuPerfState"),
        (crate::OpCode::RaplEnergy, 0x0022, "RaplEnergy"),
        (crate::OpCode::CpuIdleLatencyHint, 0x0030, "CpuIdleLatencyHint"),
        (crate::OpCode::CpuIdleRelease, 0x0031, "CpuIdleRelease"),
        (crate::OpCode::CpuSetFreqRange, 0x0040, "CpuSetFreqRange"),
        (crate::OpCode::CpuSetEpp, 0x0041, "CpuSetEpp"),
        (crate::OpCode::CpuSetGovernor, 0x0042, "CpuSetGovernor"),
        (crate::OpCode::CpuSetEnergyBudget, 0x0050, "CpuSetEnergyBudget"),
        (crate::OpCode::CpuClearEnergyBudget, 0x0051, "CpuClearEnergyBudget"),
    ];
    for &(op, wire, name) in pins {
        if op.as_u32() != wire {
            let msg = alloc::format!(
                "OpCode::{} wire {:#x} (expected {:#x})",
                name, op.as_u32(), wire
            );
            let s: &'static str = alloc::boxed::Box::leak(msg.into_boxed_str());
            return TestResult::Fail(s);
        }
    }
    TestResult::Pass
}
kernel_test_in!("abi", smoke_abi_opcode_full_wire_pins);

fn smoke_abi_narfstatus_full_wire_pins() -> TestResult {
    // Existing smoke pins 0..7; this also covers Forbidden(0x8) and
    // Unsupported(0x9) so a future variant inserted before them
    // doesn't silently shift those.
    let pins: &[(crate::NarfStatus, u32, &str)] = &[
        (crate::NarfStatus::Ok, 0x0000, "Ok"),
        (crate::NarfStatus::Pending, 0x0001, "Pending"),
        (crate::NarfStatus::Cancelled, 0x0002, "Cancelled"),
        (crate::NarfStatus::CancelRequested, 0x0003, "CancelRequested"),
        (crate::NarfStatus::CapRevoked, 0x0004, "CapRevoked"),
        (crate::NarfStatus::InvalidOp, 0x0005, "InvalidOp"),
        (crate::NarfStatus::Busy, 0x0006, "Busy"),
        (crate::NarfStatus::Closed, 0x0007, "Closed"),
        (crate::NarfStatus::Forbidden, 0x0008, "Forbidden"),
        (crate::NarfStatus::Unsupported, 0x0009, "Unsupported"),
    ];
    for &(st, wire, name) in pins {
        if st.as_u32() != wire {
            let msg = alloc::format!(
                "NarfStatus::{} wire {:#x} (expected {:#x})",
                name, st.as_u32(), wire
            );
            let s: &'static str = alloc::boxed::Box::leak(msg.into_boxed_str());
            return TestResult::Fail(s);
        }
    }
    TestResult::Pass
}
kernel_test_in!("abi", smoke_abi_narfstatus_full_wire_pins);

fn smoke_abi_submission_flags_algebra() -> TestResult {
    // Bit-set algebra: NONE is empty, named flags are distinct
    // singletons, union/intersection/contains/BitOr/BitAnd round
    // through `bits()` correctly.
    use crate::SubmissionFlags;
    if SubmissionFlags::NONE.bits() != 0 {
        return TestResult::Fail("NONE.bits != 0");
    }
    if SubmissionFlags::CANCELLABLE.bits() != 1 {
        return TestResult::Fail("CANCELLABLE wire bit drifted");
    }
    if SubmissionFlags::LINKED.bits() != 2 {
        return TestResult::Fail("LINKED wire bit drifted");
    }
    if SubmissionFlags::DRAIN.bits() != 4 {
        return TestResult::Fail("DRAIN wire bit drifted");
    }
    let cl = SubmissionFlags::CANCELLABLE | SubmissionFlags::LINKED;
    if !cl.contains(SubmissionFlags::CANCELLABLE) || !cl.contains(SubmissionFlags::LINKED) {
        return TestResult::Fail("union didn't contain both bits");
    }
    if cl.contains(SubmissionFlags::DRAIN) {
        return TestResult::Fail("contains reported a bit that's NOT set");
    }
    if (cl & SubmissionFlags::CANCELLABLE).bits() != 1 {
        return TestResult::Fail("BitAnd didn't isolate CANCELLABLE");
    }
    let round_trip = SubmissionFlags::from_bits(cl.bits());
    if round_trip != cl {
        return TestResult::Fail("from_bits(bits) didn't round-trip");
    }
    // Unknown bits preserved verbatim by from_bits (per documented
    // contract; dispatcher validates, decoder doesn't).
    let unknown = SubmissionFlags::from_bits(0xFFFF_0000);
    if unknown.bits() != 0xFFFF_0000 {
        return TestResult::Fail("from_bits dropped unknown bits");
    }
    TestResult::Pass
}
kernel_test_in!("abi", smoke_abi_submission_flags_algebra);

fn smoke_abi_submission_accessors() -> TestResult {
    // `Submission::noop(tag)` builds a Noop-tagged op; `.tag()`
    // round-trips the value. `Submission::cancel(tag, target)`
    // exposes the target via `cancel_target()`.
    use crate::{OpCode, Submission, SubmissionFlags, Tag};
    let s = Submission::noop(Tag::new(0xDEAD_BEEF));
    if s.tag() != Tag::new(0xDEAD_BEEF) {
        return TestResult::Fail("Submission::tag round-trip");
    }
    if s.op != OpCode::Noop {
        return TestResult::Fail("noop didn't set op to Noop");
    }
    if s.flags != SubmissionFlags::NONE {
        return TestResult::Fail("noop set unexpected flags");
    }
    let c = Submission::cancel(Tag::new(0x11), Tag::new(0x22));
    if c.tag() != Tag::new(0x11) {
        return TestResult::Fail("cancel tag accessor wrong");
    }
    if c.cancel_target() != Tag::new(0x22) {
        return TestResult::Fail("cancel_target accessor wrong");
    }
    if c.op != OpCode::Cancel {
        return TestResult::Fail("cancel didn't set op to Cancel");
    }
    TestResult::Pass
}
kernel_test_in!("abi", smoke_abi_submission_accessors);

fn smoke_abi_completion_accessors() -> TestResult {
    // `Completion::ok(tag)` builds an Ok-status completion with empty
    // result. `Completion::with(tag, status, result)` carries them
    // verbatim. `.tag()` round-trips.
    use crate::{Completion, NarfStatus, Tag};
    let c = Completion::ok(Tag::new(0x4242));
    if c.tag() != Tag::new(0x4242) {
        return TestResult::Fail("Completion::tag round-trip");
    }
    if c.status != NarfStatus::Ok {
        return TestResult::Fail("ok didn't set status to Ok");
    }
    if c.result != [0; 6] {
        return TestResult::Fail("ok left non-zero result");
    }
    let res = [1u64, 2, 3, 4, 5, 6];
    let c2 = Completion::with(Tag::new(0x77), NarfStatus::Cancelled, res);
    if c2.result != res {
        return TestResult::Fail("with() didn't carry result verbatim");
    }
    if c2.status != NarfStatus::Cancelled {
        return TestResult::Fail("with() didn't carry status");
    }
    TestResult::Pass
}
kernel_test_in!("abi", smoke_abi_completion_accessors);

fn smoke_abi_tag_round_trip_and_default() -> TestResult {
    // Tag is `pub struct Tag(pub u64)`; constructor + accessor must
    // round-trip; Default produces Tag(0).
    use crate::Tag;
    let t = Tag::new(0xFEED_FACE_DEAD_BEEF);
    if t.raw() != 0xFEED_FACE_DEAD_BEEF {
        return TestResult::Fail("Tag::raw didn't round-trip");
    }
    if Tag::default() != Tag::new(0) {
        return TestResult::Fail("Tag::default != Tag(0)");
    }
    if Tag::new(1) == Tag::new(2) {
        return TestResult::Fail("distinct tags compared equal");
    }
    TestResult::Pass
}
kernel_test_in!("abi", smoke_abi_tag_round_trip_and_default);

fn smoke_abi_dispatcher_handles_multiple_back_to_back() -> TestResult {
    // The existing dispatcher smoke runs two submissions. This one
    // runs eight in a row and asserts strict in-order completion.
    // Catches a regression where the dispatcher accidentally pumps
    // submissions concurrently and surfaces completions out of order.
    use crate::{completion_channel, submission_channel, Dispatcher, NarfStatus, Submission, Tag};
    use core::sync::atomic::{AtomicU8, Ordering};

    static OUTCOME: AtomicU8 = AtomicU8::new(0);

    narf_scheduler::__reset_queues_for_test();
    let (mut sq_tx, sq_rx) = submission_channel::<8>();
    let (cq_tx, mut cq_rx) = completion_channel::<8>();

    narf_scheduler::spawn(async move {
        let mut d = Dispatcher::new(sq_rx, cq_tx);
        d.run().await;
    });

    narf_scheduler::spawn(async move {
        for i in 0u64..8 {
            sq_tx
                .send(Submission::noop(Tag::new(0x1000 + i)))
                .await
                .unwrap();
        }
        for i in 0u64..8 {
            let c = cq_rx.recv().await.unwrap();
            if c.tag() != Tag::new(0x1000 + i) {
                OUTCOME.store(2, Ordering::Relaxed);
                return;
            }
            if c.status != NarfStatus::Ok {
                OUTCOME.store(3, Ordering::Relaxed);
                return;
            }
        }
        OUTCOME.store(1, Ordering::Relaxed);
        core::mem::drop(sq_tx);
        core::mem::drop(cq_rx);
    });

    narf_scheduler::run_until_empty();
    match OUTCOME.load(Ordering::Relaxed) {
        1 => TestResult::Pass,
        2 => TestResult::Fail("completion ordering broken"),
        3 => TestResult::Fail("completion status not Ok"),
        _ => TestResult::Fail("dispatcher never finished 8 ops"),
    }
}
kernel_test_in!("abi", smoke_abi_dispatcher_handles_multiple_back_to_back);

fn smoke_abi_dispatcher_invalid_opcode_surfaces_invalid_op() -> TestResult {
    // A submission with an OpCode the dispatcher doesn't recognise
    // (e.g. RingSend without a wired ring) must complete with
    // `InvalidOp`, not silently disappear. Pick `RingSend` since
    // the bare Dispatcher under test has no ring registered.
    use crate::{
        completion_channel, submission_channel, Dispatcher, NarfStatus, OpCode, Submission, Tag,
    };
    use core::sync::atomic::{AtomicU8, Ordering};

    static OUTCOME: AtomicU8 = AtomicU8::new(0);

    narf_scheduler::__reset_queues_for_test();
    let (mut sq_tx, sq_rx) = submission_channel::<2>();
    let (cq_tx, mut cq_rx) = completion_channel::<2>();

    narf_scheduler::spawn(async move {
        let mut d = Dispatcher::new(sq_rx, cq_tx);
        d.run().await;
    });

    narf_scheduler::spawn(async move {
        let tag = Tag::new(0xBADF00D);
        let mut s = Submission::noop(tag);
        s.op = OpCode::RingSend;
        sq_tx.send(s).await.unwrap();
        let c = cq_rx.recv().await.unwrap();
        if c.tag() != tag {
            OUTCOME.store(2, Ordering::Relaxed);
            return;
        }
        // The bare Dispatcher returns InvalidOp for any op it doesn't
        // explicitly handle (Noop / Yield / Cancel). RingSend isn't
        // wired so it falls into the catch-all.
        if c.status != NarfStatus::InvalidOp {
            OUTCOME.store(3, Ordering::Relaxed);
            return;
        }
        OUTCOME.store(1, Ordering::Relaxed);
        core::mem::drop(sq_tx);
        core::mem::drop(cq_rx);
    });

    narf_scheduler::run_until_empty();
    match OUTCOME.load(Ordering::Relaxed) {
        1 => TestResult::Pass,
        2 => TestResult::Fail("completion tag mismatch"),
        3 => TestResult::Fail("unhandled OpCode didn't surface InvalidOp"),
        _ => TestResult::Fail("dispatcher never drained"),
    }
}
kernel_test_in!("abi", smoke_abi_dispatcher_invalid_opcode_surfaces_invalid_op);

fn smoke_abi_submission_inline_words_constant() -> TestResult {
    // The INLINE_WORDS and CAP_SLOTS constants are part of the public
    // ABI; bumping them is a wire-format break.
    if crate::Submission::INLINE_WORDS != 6 {
        return TestResult::Fail("INLINE_WORDS drifted from 6");
    }
    if crate::Submission::CAP_SLOTS != 4 {
        return TestResult::Fail("CAP_SLOTS drifted from 4");
    }
    if crate::Completion::RESULT_WORDS != 6 {
        return TestResult::Fail("RESULT_WORDS drifted from 6");
    }
    TestResult::Pass
}
kernel_test_in!("abi", smoke_abi_submission_inline_words_constant);
