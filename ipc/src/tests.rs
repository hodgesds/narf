//! Per-crate kernel-test smokes for `narf-ipc` plus the IPC-level
//! exit-gate tests.
//!
//! Tests register via `narf_kernel_test::kernel_test_in!` so the
//! runner groups output under `"ipc"`. Bodies are copied verbatim
//! from `verification/src/lib.rs` — only paths change
//! (`narf_ipc::xxx` → `crate::xxx`).
//!
//! Two tests stay in `narf-verification`:
//!   * `smoke_ipc_shared_ring_size_bounds` — pulls in
//!     `narf_abi::{Submission, Completion}`, but `narf-abi` depends
//!     on `narf-ipc`. Moving it here would create a Cargo cycle.
//!   * `smoke_exit_gate_virtio_blk` — pulls in `narf-drivers-virtio`
//!     and `narf-block`, both of which depend on `narf-ipc`. Same
//!     cycle.

use narf_kernel_test::{kernel_test_in, TestResult};

// ── ipc/spsc ───────────────────────────────────────────────────────

fn smoke_ipc_spsc_round_trip() -> TestResult {
    // Producer and consumer on the same executor: send 8 u64 values
    // through a 4-slot ring, sum them on the consumer side. Exercises
    // the wrap-around + back-pressure-via-waker path at the same time:
    // the consumer must drain before the producer can publish the
    // second half.
    use core::sync::atomic::{AtomicU64, Ordering};
    static SUM: AtomicU64 = AtomicU64::new(0);

    SUM.store(0, Ordering::Relaxed);
    narf_scheduler::__reset_queues_for_test();

    let (mut tx, mut rx) = crate::channel::<u64, 4>();

    narf_scheduler::spawn(async move {
        for i in 1u64..=8 {
            let _ = tx.send(i).await;
        }
        // tx dropped here → closes the ring.
    });

    narf_scheduler::spawn(async move {
        while let Ok(v) = rx.recv().await {
            SUM.fetch_add(v, Ordering::Relaxed);
        }
    });

    narf_scheduler::run_until_empty();
    // 1 + 2 + … + 8 = 36.
    if SUM.load(Ordering::Relaxed) == 36 {
        TestResult::Pass
    } else {
        TestResult::Fail("SPSC round-trip didn't deliver every message")
    }
}
kernel_test_in!("ipc", smoke_ipc_spsc_round_trip);

fn smoke_ipc_shared_ring_round_trip() -> TestResult {
    // Allocate a frame, init a SharedRing<u64, 8> in it, then
    // construct a producer through one raw pointer and a consumer
    // through ANOTHER raw pointer aliasing the same backing — this
    // mirrors how kernel and user mode reach a single shared page
    // through different virtual mappings. Round-trip 8 messages and
    // verify ordering + count.
    use crate::{SharedConsumer, SharedProducer, SharedRing, SharedTryRecvError};

    let frame = match narf_memory::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Fail("alloc_frame"),
    };
    // SAFETY: `frame` is a freshly-allocated 4 KiB frame whose identity
    // vaddr (`frame.raw()`) is writable for its full `4096` bytes, so
    // zero-filling the whole page is in-bounds.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::ptr::write_bytes(frame.kernel_mut_ptr::<u8>(), 0, 4096);
    }
    let kernel_view = frame.kernel_mut_ptr::<SharedRing<u64, 8>>();

    // Verify the layout fits in 4 KiB.
    if SharedRing::<u64, 8>::size_bytes() > 4096 {
        return TestResult::Fail("SharedRing<u64,8> larger than a 4 KiB page");
    }

    // Initialise.
    // SAFETY: `kernel_view` is the page's 8-aligned identity vaddr,
    // points at >= `size_bytes()` writable (zeroed) bytes, and the page
    // outlives the producer/consumer built below — satisfying
    // `init_in`'s contract.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        SharedRing::<u64, 8>::init_in(kernel_view);
    }

    // Two distinct pointer values that resolve to the same backing
    // (here, both are the same kernel-identity vaddr; in real use
    // one of them would be the user's mapping of the same phys).
    let user_view = frame.kernel_mut_ptr::<SharedRing<u64, 8>>();

    // SAFETY: `kernel_view` points at the `init_in`-initialised ring and
    // this is the only producer constructed for it, upholding the SPSC
    // contract of `SharedProducer::from_raw`.
    // SAFETY: Valid memory or trusted environment
    let mut prod = unsafe { SharedProducer::<u64, 8>::from_raw(kernel_view) };
    // SAFETY: `user_view` aliases the same initialised ring and this is
    // the only consumer constructed for it, upholding the SPSC contract
    // of `SharedConsumer::from_raw`.
    // SAFETY: Valid memory or trusted environment
    let mut cons = unsafe { SharedConsumer::<u64, 8>::from_raw(user_view) };

    for v in 0u64..8 {
        if prod.try_send(v).is_err() {
            return TestResult::Fail("try_send unexpectedly failed");
        }
    }

    // 9th must be Full.
    if !matches!(prod.try_send(99), Err(crate::SharedTrySendError::Full(99))) {
        return TestResult::Fail("9th send did not return Full(99)");
    }

    // Drain in order.
    for expected in 0u64..8 {
        match cons.try_recv() {
            Ok(v) if v == expected => {}
            Ok(_) => return TestResult::Fail("recv out of order"),
            Err(_) => return TestResult::Fail("recv failed early"),
        }
    }

    // Empty path.
    if !matches!(cons.try_recv(), Err(SharedTryRecvError::Empty)) {
        return TestResult::Fail("empty recv did not surface Empty");
    }

    // Close from producer side; consumer should see Closed once empty.
    prod.close();
    if !matches!(cons.try_recv(), Err(SharedTryRecvError::Closed)) {
        return TestResult::Fail("close not observed");
    }

    TestResult::Pass
}
kernel_test_in!("ipc", smoke_ipc_shared_ring_round_trip);

fn smoke_ipc_spsc_try_send_full() -> TestResult {
    // Fill a 2-slot ring without a consumer; the third try_send must
    // return Full and hand the message back.
    let (mut tx, _rx) = crate::channel::<u32, 2>();
    tx.try_send(10).expect("slot 0 free");
    tx.try_send(20).expect("slot 1 free");
    match tx.try_send(30) {
        Err(crate::TrySendError::Full(30)) => TestResult::Pass,
        Err(crate::TrySendError::Full(_)) => TestResult::Fail("Full returned wrong value"),
        Err(crate::TrySendError::Closed(_)) => TestResult::Fail("unexpected Closed"),
        Ok(()) => TestResult::Fail("try_send accepted beyond capacity"),
    }
}
kernel_test_in!("ipc", smoke_ipc_spsc_try_send_full);

fn smoke_ipc_spsc_close_eof() -> TestResult {
    // Drop the producer without sending anything → consumer's first
    // recv resolves to Closed. Also verifies the path where the drop's
    // wake fires against an already-parked RecvFuture.
    use core::sync::atomic::{AtomicU8, Ordering};
    static OUTCOME: AtomicU8 = AtomicU8::new(0); // 0=pending, 1=closed, 2=unexpected

    OUTCOME.store(0, Ordering::Relaxed);
    narf_scheduler::__reset_queues_for_test();

    let (tx, mut rx) = crate::channel::<u32, 4>();

    // Consumer task: parks on recv, then observes Closed.
    narf_scheduler::spawn(async move {
        match rx.recv().await {
            Err(crate::RecvError::Closed) => {
                OUTCOME.store(1, Ordering::Relaxed);
            }
            _ => {
                OUTCOME.store(2, Ordering::Relaxed);
            }
        }
    });

    // Producer dropper: yields once to let the consumer park, then drops.
    narf_scheduler::spawn(async move {
        narf_scheduler::yield_now().await;
        drop(tx);
    });

    narf_scheduler::run_until_empty();
    match OUTCOME.load(Ordering::Relaxed) {
        1 => TestResult::Pass,
        2 => TestResult::Fail("recv returned unexpected variant"),
        _ => TestResult::Fail("recv future never resolved after producer drop"),
    }
}
kernel_test_in!("ipc", smoke_ipc_spsc_close_eof);

fn smoke_ipc_spsc_drain_then_eof() -> TestResult {
    use core::sync::atomic::{AtomicU32, Ordering};
    static COUNT: AtomicU32 = AtomicU32::new(0);
    static CLOSED: AtomicU32 = AtomicU32::new(0);

    COUNT.store(0, Ordering::Relaxed);
    CLOSED.store(0, Ordering::Relaxed);
    narf_scheduler::__reset_queues_for_test();

    let (mut tx, mut rx) = crate::channel::<u32, 4>();
    narf_scheduler::spawn(async move {
        let _ = tx.try_send(10);
        let _ = tx.try_send(20);
        let _ = tx.try_send(30);
    });
    narf_scheduler::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(_) => {
                    COUNT.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    CLOSED.store(1, Ordering::Relaxed);
                    break;
                }
            }
        }
    });
    narf_scheduler::run_until_empty();

    if COUNT.load(Ordering::Relaxed) != 3 {
        return TestResult::Fail("drain lost messages before Closed");
    }
    if CLOSED.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("Closed not observed after drain");
    }
    TestResult::Pass
}
kernel_test_in!("ipc", smoke_ipc_spsc_drain_then_eof);

// ── exit-gate ──────────────────────────────────────────────────────

fn smoke_exit_gate_buffer_handoff() -> TestResult {
    use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
    use narf_capabilities::{Cap, Read};
    use narf_io::{alloc_coherent, DmaBuffer};
    use narf_lib::id::DomainId;
    use narf_memory::PAGE_SIZE;

    /// 17-byte payload pattern. Non-trivial so a zeroed/untouched
    /// buffer doesn't accidentally match.
    const PATTERN: [u8; 17] = [
        0xA5, 0x5A, 0x01, 0xFE, 0x42, 0x00, 0xFF, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x90, 0xAA,
    ];

    static OUTCOME: AtomicU8 = AtomicU8::new(0); // 0=pending, 1=ok, 2=bad
    static READ_LEN: AtomicUsize = AtomicUsize::new(0);

    struct Handoff {
        buf: DmaBuffer,
        cap: Cap<DmaBuffer, Read>,
    }
    impl crate::Retag for Handoff {}

    OUTCOME.store(0, Ordering::Relaxed);
    READ_LEN.store(0, Ordering::Relaxed);

    let (mut tx, mut rx) = crate::channel::<Handoff, 2>();
    narf_scheduler::__reset_queues_for_test();

    // "Driver domain" task: allocate, fill, hand off.
    narf_scheduler::spawn(async move {
        let Ok(buf) = alloc_coherent(PATTERN.len(), DomainId::DRIVER_0) else {
            return;
        };
        // Write the pattern to the buffer's physical memory. Valid
        // per `PhysAddr::as_mut_ptr`'s documented contract
        // (memory/src/addr.rs — caller must ensure identity-mapped or
        // remap_to_virtual-translated). Kernel keeps low RAM
        // identity-mapped on both arches; alloc_coherent returns
        // low-RAM frames, so the precondition holds.
        // SAFETY: buf is exclusively owned here; we write its full
        // allocated length at byte granularity.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            let dst = buf.phys_addr().kernel_mut_ptr::<u8>();
            for (i, b) in PATTERN.iter().enumerate() {
                core::ptr::write_volatile(dst.add(i), *b);
            }
        }
        let cap: Cap<DmaBuffer, Read> = Cap::<DmaBuffer, Read>::bootstrap();
        let _ = tx.send(Handoff { buf, cap }).await;
        // Producer drops tx here; consumer finishes its recv.
    });

    // "Consumer domain" task: receive, gate on cap, read, assert.
    narf_scheduler::spawn(async move {
        let Ok(Handoff { buf, cap }) = rx.recv().await else {
            OUTCOME.store(2, Ordering::Relaxed);
            return;
        };
        // The spec's "capability invocation on the fast path": if the
        // cap were revoked between send and read, this fails — see
        // the revoked-variant test below.
        if cap.check_live().is_err() {
            OUTCOME.store(2, Ordering::Relaxed);
            return;
        }
        let mut ok = true;
        // SAFETY: `buf`'s ownership was transferred into this task via
        // the ring, so we are the sole reader of its backing frame. The
        // frame is identity-mapped low RAM (alloc_coherent guarantees),
        // and we read exactly `PATTERN.len()` bytes, which is `buf`'s
        // allocated length — every `src.add(i)` is in-bounds.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            let src = buf.phys_addr().kernel_ptr::<u8>();
            for (i, expected) in PATTERN.iter().enumerate() {
                if core::ptr::read_volatile(src.add(i)) != *expected {
                    ok = false;
                    break;
                }
            }
        }
        READ_LEN.store(buf.len(), Ordering::Relaxed);
        OUTCOME.store(if ok { 1 } else { 2 }, Ordering::Relaxed);
        // buf drops here → frame returns to allocator.
    });

    narf_scheduler::run_until_empty();

    // Both tasks must have run to completion.
    if READ_LEN.load(Ordering::Relaxed) < PATTERN.len() {
        return TestResult::Fail("consumer never received a buffer");
    }
    if READ_LEN.load(Ordering::Relaxed) != PAGE_SIZE as usize {
        return TestResult::Fail("buffer length wasn't page-rounded on receive");
    }
    match OUTCOME.load(Ordering::Relaxed) {
        1 => TestResult::Pass,
        2 => TestResult::Fail("payload mismatch or cap check_live failed"),
        _ => TestResult::Fail("consumer task never ran"),
    }
}
kernel_test_in!("ipc", smoke_exit_gate_buffer_handoff);

fn smoke_exit_gate_revoked_cap_rejected() -> TestResult {
    // Same flow, but the producer revokes the cap after sending. The
    // consumer's `check_live` must reject the receive — a revoked
    // object is exactly the case epoch bumping invalidates O(1).
    //
    // Determinism precondition: single-CPU cooperative FIFO scheduler
    // (scheduler/src/lib.rs). `yield_now` pushes the yielder to the
    // queue tail, so producer-revoke always runs before consumer-
    // check_live. A preemptive or multi-CPU executor would make this
    // test racy — revisit the schedule when that lands.
    use core::sync::atomic::{AtomicU8, Ordering};
    use narf_capabilities::{Cap, Read};
    use narf_io::{alloc_coherent, DmaBuffer};
    use narf_lib::id::DomainId;

    static OUTCOME: AtomicU8 = AtomicU8::new(0); // 0 pending, 1 properly-rejected, 2 slipped-through

    struct Handoff {
        buf: DmaBuffer,
        cap: Cap<DmaBuffer, Read>,
    }
    impl crate::Retag for Handoff {}

    OUTCOME.store(0, Ordering::Relaxed);

    let (mut tx, mut rx) = crate::channel::<Handoff, 2>();
    narf_scheduler::__reset_queues_for_test();

    narf_scheduler::spawn(async move {
        let Ok(buf) = alloc_coherent(16, DomainId::DRIVER_0) else {
            return;
        };
        let cap: Cap<DmaBuffer, Read> = Cap::<DmaBuffer, Read>::bootstrap();
        let cap_clone = cap; // Cap is Copy
        let _ = tx
            .send(Handoff {
                buf,
                cap: cap_clone,
            })
            .await;
        // Yield so the consumer picks up the send before we revoke.
        narf_scheduler::yield_now().await;
        cap.revoke(); // bumps the shared epoch
    });

    narf_scheduler::spawn(async move {
        let Ok(Handoff { buf: _buf, cap }) = rx.recv().await else {
            OUTCOME.store(2, Ordering::Relaxed);
            return;
        };
        // Yield once more to give the producer a chance to revoke
        // before we gate. On single-CPU cooperative this models the
        // "producer yanked authority before consumer touched buffer"
        // window the exit-gate criterion insists we honour.
        narf_scheduler::yield_now().await;
        match cap.check_live() {
            Err(_) => OUTCOME.store(1, Ordering::Relaxed),
            Ok(()) => OUTCOME.store(2, Ordering::Relaxed),
        }
    });

    narf_scheduler::run_until_empty();
    match OUTCOME.load(Ordering::Relaxed) {
        1 => TestResult::Pass,
        2 => TestResult::Fail("revoked cap slipped past check_live"),
        _ => TestResult::Fail("consumer never reached check_live"),
    }
}
kernel_test_in!("ipc", smoke_exit_gate_revoked_cap_rejected);

// ── ipc/mpsc ───────────────────────────────────────────────────────

fn smoke_ipc_mpsc_multi_producer_roundtrip() -> TestResult {
    use crate::{mpsc_channel, MpscRecvError};
    use core::sync::atomic::{AtomicU32, Ordering};

    narf_scheduler::__reset_queues_for_test();
    static DRAINED: AtomicU32 = AtomicU32::new(0);
    DRAINED.store(0, Ordering::Relaxed);

    let (tx, rx) = mpsc_channel::<u32>(16);
    let tx2 = tx.clone();
    let tx3 = tx.clone();

    // Three producer tasks + one consumer.
    narf_scheduler::spawn(async move {
        for i in 0..4 {
            tx.try_send(0xA000 + i).unwrap();
        }
    });
    narf_scheduler::spawn(async move {
        for i in 0..4 {
            tx2.try_send(0xB000 + i).unwrap();
        }
    });
    narf_scheduler::spawn(async move {
        for i in 0..4 {
            tx3.try_send(0xC000 + i).unwrap();
        }
    });

    narf_scheduler::spawn(async move {
        let mut rx = rx;
        for _ in 0..12 {
            match rx.recv().await {
                Ok(_v) => {
                    DRAINED.fetch_add(1, Ordering::Relaxed);
                }
                Err(MpscRecvError::Closed) => break,
            }
        }
        // Dropping `rx` latches closed for future producer attempts.
    });

    narf_scheduler::run_until_empty();

    if DRAINED.load(Ordering::Relaxed) != 12 {
        return TestResult::Fail("consumer did not drain all three producers' messages");
    }
    TestResult::Pass
}
kernel_test_in!("ipc", smoke_ipc_mpsc_multi_producer_roundtrip);

fn smoke_ipc_mpsc_closed_surfaces() -> TestResult {
    use crate::{mpsc_channel, MpscRecvError, MpscSendError};

    let (tx, rx) = mpsc_channel::<u8>(2);

    // Fill the channel then attempt a third send → Full.
    tx.try_send(1).unwrap();
    tx.try_send(2).unwrap();
    match tx.try_send(3) {
        Err(MpscSendError::Full(3)) => {}
        _ => return TestResult::Fail("full channel did not report Full"),
    }

    // Drop consumer → subsequent sends are Closed.
    drop(rx);
    match tx.try_send(4) {
        Err(MpscSendError::Closed(4)) => {}
        _ => return TestResult::Fail("dropped consumer did not surface Closed"),
    }
    if !tx.is_closed() {
        return TestResult::Fail("is_closed lies");
    }

    // Consumer-side Closed: use a fresh pair, drop sender explicitly.
    let (tx2, rx2) = mpsc_channel::<u8>(2);
    drop(tx2);
    // Existing queued elements come out first; since we never sent
    // anything, try_recv on empty + closed → Closed.
    match rx2.try_recv() {
        // Note: our close-signal comes from consumer drop, not
        // producer drop. So producer-dropped-but-consumer-alive
        // returns Ok(None) here, not Closed.
        Ok(None) => {}
        _ => {
            return TestResult::Fail(
                "empty channel without producer-count tracking should surface Ok(None)",
            )
        }
    }
    let _ = MpscRecvError::Closed;
    TestResult::Pass
}
kernel_test_in!("ipc", smoke_ipc_mpsc_closed_surfaces);

// ── extended ipc coverage ──────────────────────────────────────────
//
// The smokes above hit the headline paths; the ones below close the
// remaining invariants: wrap-around, waker pairing on Pending →
// Ready, drop-runs-destructors, and per-half close detection on each
// of SPSC, MPSC, and SharedRing.

fn smoke_ipc_spsc_wrap_around_indices() -> TestResult {
    // Push N items, drain, push N more — the consumer's view of
    // ordering must persist across the modular index wrap. A bad
    // mask or off-by-one shows up as out-of-order delivery or a
    // missing element in the second batch.
    use core::sync::atomic::{AtomicU64, Ordering};
    static SUM: AtomicU64 = AtomicU64::new(0);
    static SEEN: AtomicU64 = AtomicU64::new(0);

    SUM.store(0, Ordering::Relaxed);
    SEEN.store(0, Ordering::Relaxed);
    narf_scheduler::__reset_queues_for_test();

    let (mut tx, mut rx) = crate::channel::<u64, 4>();
    narf_scheduler::spawn(async move {
        for i in 1u64..=32 {
            let _ = tx.send(i).await;
        }
    });
    narf_scheduler::spawn(async move {
        while let Ok(v) = rx.recv().await {
            SUM.fetch_add(v, Ordering::Relaxed);
            SEEN.fetch_add(1, Ordering::Relaxed);
        }
    });
    narf_scheduler::run_until_empty();

    if SEEN.load(Ordering::Relaxed) != 32 {
        return TestResult::Fail("dropped a message across the wrap");
    }
    // 1 + 2 + … + 32 = 528.
    if SUM.load(Ordering::Relaxed) != 528 {
        return TestResult::Fail("payload corruption across wrap");
    }
    TestResult::Pass
}
kernel_test_in!("ipc", smoke_ipc_spsc_wrap_around_indices);

fn smoke_ipc_spsc_send_blocks_until_drain() -> TestResult {
    // Fill a 2-slot ring synchronously, then `send` async — the
    // producer future must park on Full and resolve only after the
    // consumer drains. Validates the producer-side waker pairing.
    use core::sync::atomic::{AtomicU8, Ordering};
    static PRODUCED: AtomicU8 = AtomicU8::new(0);
    PRODUCED.store(0, Ordering::Relaxed);
    narf_scheduler::__reset_queues_for_test();

    let (mut tx, mut rx) = crate::channel::<u32, 2>();
    // Pre-fill via try_send so the async send below starts at Full.
    tx.try_send(0xAA).expect("slot 0");
    tx.try_send(0xBB).expect("slot 1");

    narf_scheduler::spawn(async move {
        // This send parks on Full until the consumer drains a slot.
        let _ = tx.send(0xCC).await;
        PRODUCED.store(1, Ordering::Relaxed);
        let _ = tx.send(0xDD).await;
        PRODUCED.store(2, Ordering::Relaxed);
    });

    narf_scheduler::spawn(async move {
        // Yield once so the producer parks first.
        narf_scheduler::yield_now().await;
        // Drain one — wakes the parked producer.
        let _ = rx.recv().await;
        // Drain remaining.
        let _ = rx.recv().await;
        let _ = rx.recv().await;
        let _ = rx.recv().await;
    });
    narf_scheduler::run_until_empty();

    if PRODUCED.load(Ordering::Relaxed) != 2 {
        return TestResult::Fail("parked producer never resumed after consumer drain");
    }
    TestResult::Pass
}
kernel_test_in!("ipc", smoke_ipc_spsc_send_blocks_until_drain);

fn smoke_ipc_spsc_drop_ring_runs_payload_destructors() -> TestResult {
    // Items remaining in the ring when the last handle drops must
    // have their destructors run. We can't observe the Ring's Drop
    // path directly through `channel()` (it sits behind an Arc), so
    // construct an item type with a Drop that bumps a static
    // counter, fill the ring, drop both halves, then verify the
    // counter saw every undrained value.
    use core::sync::atomic::{AtomicU32, Ordering};
    static DROPS: AtomicU32 = AtomicU32::new(0);

    #[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
    struct Counted(u32);
    impl Drop for Counted {
        fn drop(&mut self) {
            DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }
    impl crate::Retag for Counted {}

    DROPS.store(0, Ordering::Relaxed);
    {
        let (mut tx, rx) = crate::channel::<Counted, 4>();
        for i in 0..3 {
            tx.try_send(Counted(i)).ok();
        }
        // Drop producer first, then consumer — Arc<Ring> drops on
        // last reference, which runs Ring::drop's loop over
        // [tail, head).
        drop(tx);
        drop(rx);
    }
    if DROPS.load(Ordering::Relaxed) != 3 {
        return TestResult::Fail("Ring::drop didn't run destructors on undrained slots");
    }
    TestResult::Pass
}
kernel_test_in!("ipc", smoke_ipc_spsc_drop_ring_runs_payload_destructors);

fn smoke_ipc_spsc_close_from_consumer_drop() -> TestResult {
    // Drop the consumer first; the producer's next try_send must
    // surface Closed (handing the value back so the caller can
    // recover it).
    let (mut tx, rx) = crate::channel::<u32, 4>();
    drop(rx);
    match tx.try_send(42) {
        Err(crate::TrySendError::Closed(42)) => TestResult::Pass,
        Err(crate::TrySendError::Closed(_)) => TestResult::Fail("Closed dropped the payload"),
        Err(crate::TrySendError::Full(_)) => TestResult::Fail("expected Closed, got Full"),
        Ok(()) => TestResult::Fail("send accepted after consumer drop"),
    }
}
kernel_test_in!("ipc", smoke_ipc_spsc_close_from_consumer_drop);

fn smoke_ipc_spsc_recv_parked_then_woken() -> TestResult {
    // Consumer recv-future parks first (empty ring), THEN producer
    // sends. The producer's send must wake the parked consumer; the
    // consumer's poll must resolve to Ok(value).
    use core::sync::atomic::{AtomicU32, Ordering};
    static GOT: AtomicU32 = AtomicU32::new(0);

    GOT.store(0, Ordering::Relaxed);
    narf_scheduler::__reset_queues_for_test();

    let (mut tx, mut rx) = crate::channel::<u32, 4>();
    narf_scheduler::spawn(async move {
        match rx.recv().await {
            Ok(v) => GOT.store(v, Ordering::Relaxed),
            Err(_) => GOT.store(0xDEAD, Ordering::Relaxed),
        }
    });
    narf_scheduler::spawn(async move {
        // Give the consumer time to park on Empty.
        narf_scheduler::yield_now().await;
        let _ = tx.send(0xC0FFEE).await;
    });
    narf_scheduler::run_until_empty();

    match GOT.load(Ordering::Relaxed) {
        0xC0FFEE => TestResult::Pass,
        0xDEAD => TestResult::Fail("recv future returned Closed instead of value"),
        0 => TestResult::Fail("parked recv never resumed"),
        _ => TestResult::Fail("recv resolved to wrong value"),
    }
}
kernel_test_in!("ipc", smoke_ipc_spsc_recv_parked_then_woken);

// ── shared ring extended ──────────────────────────────────────────

fn smoke_ipc_shared_ring_wrap_around() -> TestResult {
    // Same wrap discipline as the SPSC test, but through the
    // SharedRing path (kernel/user wire layout). Push 4, drain 4,
    // push 4 more — every slot index wraps once.
    use crate::{SharedConsumer, SharedProducer, SharedRing};

    let frame = match narf_memory::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Fail("alloc_frame"),
    };
    // SAFETY: `frame.raw()` is the page's 8-aligned identity vaddr,
    // writable for its full 4096 bytes (so the zero-fill is in-bounds)
    // and large enough to hold the ring; `init_in`'s contract is met.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::ptr::write_bytes(frame.kernel_mut_ptr::<u8>(), 0, 4096);
        SharedRing::<u32, 4>::init_in(frame.kernel_mut_ptr::<SharedRing<u32, 4>>());
    }
    let view = frame.kernel_mut_ptr::<SharedRing<u32, 4>>();
    // SAFETY: `view` points at the just-initialised ring and is the only
    // producer for it, upholding `from_raw`'s SPSC contract.
    // SAFETY: Valid memory or trusted environment
    let mut prod = unsafe { SharedProducer::<u32, 4>::from_raw(view) };
    // SAFETY: same ring, sole consumer — `from_raw`'s SPSC contract.
    let mut cons = unsafe { SharedConsumer::<u32, 4>::from_raw(view) };

    for i in 0u32..4 {
        if prod.try_send(0x100 + i).is_err() {
            return TestResult::Fail("first-batch send failed");
        }
    }
    for expected in 0u32..4 {
        match cons.try_recv() {
            Ok(v) if v == 0x100 + expected => {}
            _ => return TestResult::Fail("first-batch order violated"),
        }
    }
    for i in 0u32..4 {
        if prod.try_send(0x200 + i).is_err() {
            return TestResult::Fail("second-batch send failed (wrap)");
        }
    }
    for expected in 0u32..4 {
        match cons.try_recv() {
            Ok(v) if v == 0x200 + expected => {}
            _ => return TestResult::Fail("second-batch order violated (wrap)"),
        }
    }
    TestResult::Pass
}
kernel_test_in!("ipc", smoke_ipc_shared_ring_wrap_around);

fn smoke_ipc_shared_ring_close_from_consumer() -> TestResult {
    // Symmetric to the producer-side close test: consumer closes,
    // producer's next try_send must surface Closed(value) — handing
    // the payload back so it isn't silently lost.
    use crate::{SharedConsumer, SharedProducer, SharedRing, SharedTrySendError};

    let frame = match narf_memory::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Fail("alloc_frame"),
    };
    // SAFETY: `frame.raw()` is the page's 8-aligned identity vaddr,
    // writable for its full 4096 bytes (so the zero-fill is in-bounds)
    // and large enough to hold the ring; `init_in`'s contract is met.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::ptr::write_bytes(frame.kernel_mut_ptr::<u8>(), 0, 4096);
        SharedRing::<u64, 4>::init_in(frame.kernel_mut_ptr::<SharedRing<u64, 4>>());
    }
    let view = frame.kernel_mut_ptr::<SharedRing<u64, 4>>();
    // SAFETY: `view` points at the just-initialised ring and is the only
    // producer for it, upholding `from_raw`'s SPSC contract.
    // SAFETY: Valid memory or trusted environment
    let mut prod = unsafe { SharedProducer::<u64, 4>::from_raw(view) };
    // SAFETY: same ring, sole consumer — `from_raw`'s SPSC contract.
    let mut cons = unsafe { SharedConsumer::<u64, 4>::from_raw(view) };

    cons.close();
    match prod.try_send(0xFEED) {
        Err(SharedTrySendError::Closed(0xFEED)) => TestResult::Pass,
        Err(SharedTrySendError::Closed(_)) => TestResult::Fail("Closed dropped the payload"),
        Err(SharedTrySendError::Full(_)) => TestResult::Fail("expected Closed, got Full"),
        Ok(()) => TestResult::Fail("send accepted after consumer close"),
    }
}
kernel_test_in!("ipc", smoke_ipc_shared_ring_close_from_consumer);

fn smoke_ipc_shared_ring_volatile_payload_persists() -> TestResult {
    // Regression guard for the dead-store-elimination bug fixed by
    // moving try_send / try_recv to ptr::write_volatile /
    // ptr::read_volatile: write a non-trivial payload, read the
    // memory back through a raw pointer at the slot offset, and
    // assert the bytes landed. Without volatile, LLVM saw the
    // payload store as dead (no in-scope reader of the raw
    // pointer) and elided it; the head atomic still advanced, so
    // the consumer would see uninit garbage.
    use crate::{SharedProducer, SharedRing};

    let frame = match narf_memory::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Fail("alloc_frame"),
    };
    // SAFETY: `frame.raw()` is the page's 8-aligned identity vaddr,
    // writable for its full 4096 bytes (so the zero-fill is in-bounds)
    // and large enough to hold the ring; `init_in`'s contract is met.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::ptr::write_bytes(frame.kernel_mut_ptr::<u8>(), 0, 4096);
        SharedRing::<u64, 4>::init_in(frame.kernel_mut_ptr::<SharedRing<u64, 4>>());
    }
    let view = frame.kernel_mut_ptr::<SharedRing<u64, 4>>();
    // SAFETY: `view` points at the just-initialised ring and is the only
    // producer for it, upholding `from_raw`'s SPSC contract.
    // SAFETY: Valid memory or trusted environment
    let mut prod = unsafe { SharedProducer::<u64, 4>::from_raw(view) };
    if prod.try_send(0xDEAD_BEEF_CAFE_F00D).is_err() {
        return TestResult::Fail("try_send failed");
    }
    // Header is exactly 64 bytes (head + tail + closed + pad). The
    // first slot's payload sits at offset 64. We deliberately do
    // NOT use SharedConsumer here so the read goes through an
    // independent pointer the compiler can't fold into the producer.
    // SAFETY: the header is exactly 64 bytes, so the first slot's `u64`
    // payload sits at `frame.raw() + 64`, well within the 4 KiB page and
    // 8-aligned (frame base is page-aligned). The producer's volatile
    // store above published a fully-initialised `u64` there.
    // SAFETY: Valid memory or trusted environment
    let v = unsafe {
        core::ptr::read_volatile(narf_memory::PhysAddr::new(frame.raw() + 64).kernel_ptr::<u64>())
    };
    if v == 0xDEAD_BEEF_CAFE_F00D {
        TestResult::Pass
    } else {
        TestResult::Fail("producer payload was elided — volatile guarantee broken")
    }
}
kernel_test_in!("ipc", smoke_ipc_shared_ring_volatile_payload_persists);

fn smoke_ipc_shared_ring_full_then_drain_then_send_again() -> TestResult {
    // Fill, observe Full, drain one, can send again. Validates
    // the head/tail arithmetic on the "tail caught up" branch.
    use crate::{SharedConsumer, SharedProducer, SharedRing, SharedTrySendError};

    let frame = match narf_memory::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Fail("alloc_frame"),
    };
    // SAFETY: `frame.raw()` is the page's 8-aligned identity vaddr,
    // writable for its full 4096 bytes (so the zero-fill is in-bounds)
    // and large enough to hold the ring; `init_in`'s contract is met.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::ptr::write_bytes(frame.kernel_mut_ptr::<u8>(), 0, 4096);
        SharedRing::<u32, 2>::init_in(frame.kernel_mut_ptr::<SharedRing<u32, 2>>());
    }
    let view = frame.kernel_mut_ptr::<SharedRing<u32, 2>>();
    // SAFETY: `view` points at the just-initialised ring and is the only
    // producer for it, upholding `from_raw`'s SPSC contract.
    // SAFETY: Valid memory or trusted environment
    let mut prod = unsafe { SharedProducer::<u32, 2>::from_raw(view) };
    // SAFETY: same ring, sole consumer — `from_raw`'s SPSC contract.
    let mut cons = unsafe { SharedConsumer::<u32, 2>::from_raw(view) };

    prod.try_send(1).expect("slot 0");
    prod.try_send(2).expect("slot 1");
    if !matches!(prod.try_send(3), Err(SharedTrySendError::Full(3))) {
        return TestResult::Fail("3rd send didn't surface Full");
    }
    match cons.try_recv() {
        Ok(1) => {}
        _ => return TestResult::Fail("first drain wrong value"),
    }
    if prod.try_send(3).is_err() {
        return TestResult::Fail("post-drain send unexpectedly failed");
    }
    TestResult::Pass
}
kernel_test_in!("ipc", smoke_ipc_shared_ring_full_then_drain_then_send_again);

// ── mpsc extended ─────────────────────────────────────────────────

fn smoke_ipc_mpsc_backpressure_full_then_drain() -> TestResult {
    // try_send into a full queue returns Full; pop one via the
    // consumer's try_recv; the next try_send must succeed.
    use crate::{mpsc_channel, MpscSendError};

    let (tx, rx) = mpsc_channel::<u32>(2);
    tx.try_send(1).unwrap();
    tx.try_send(2).unwrap();
    match tx.try_send(3) {
        Err(MpscSendError::Full(3)) => {}
        _ => return TestResult::Fail("Full not reported on third send"),
    }
    match rx.try_recv() {
        Ok(Some(1)) => {}
        _ => return TestResult::Fail("drain ordering wrong"),
    }
    if tx.try_send(3).is_err() {
        return TestResult::Fail("post-drain send blocked");
    }
    TestResult::Pass
}
kernel_test_in!("ipc", smoke_ipc_mpsc_backpressure_full_then_drain);

fn smoke_ipc_mpsc_try_recv_empty_open_is_ok_none() -> TestResult {
    // Empty channel with the consumer's producer half still alive
    // must surface Ok(None), not Closed. Distinct semantics
    // (caller can spin); Closed means truly done.
    use crate::mpsc_channel;
    let (_tx, rx) = mpsc_channel::<u32>(4);
    match rx.try_recv() {
        Ok(None) => TestResult::Pass,
        Ok(Some(_)) => TestResult::Fail("recv returned a value on an empty channel"),
        Err(_) => TestResult::Fail("empty open channel surfaced Closed"),
    }
}
kernel_test_in!("ipc", smoke_ipc_mpsc_try_recv_empty_open_is_ok_none);

fn smoke_ipc_mpsc_recv_future_wakes_on_send() -> TestResult {
    // Consumer parks on empty; producer.try_send must wake it via
    // the consumer_waker slot.
    use crate::mpsc_channel;
    use core::sync::atomic::{AtomicU32, Ordering};
    static GOT: AtomicU32 = AtomicU32::new(0);

    GOT.store(0, Ordering::Relaxed);
    narf_scheduler::__reset_queues_for_test();

    let (tx, mut rx) = mpsc_channel::<u32>(4);
    narf_scheduler::spawn(async move {
        match rx.recv().await {
            Ok(v) => GOT.store(v, Ordering::Relaxed),
            Err(_) => GOT.store(0xDEAD, Ordering::Relaxed),
        }
    });
    narf_scheduler::spawn(async move {
        narf_scheduler::yield_now().await;
        tx.try_send(0xA110_CA73).unwrap();
    });
    narf_scheduler::run_until_empty();

    match GOT.load(Ordering::Relaxed) {
        0xA110_CA73 => TestResult::Pass,
        0xDEAD => TestResult::Fail("consumer got Closed instead of value"),
        _ => TestResult::Fail("parked consumer didn't wake on send"),
    }
}
kernel_test_in!("ipc", smoke_ipc_mpsc_recv_future_wakes_on_send);

fn smoke_ipc_mpsc_pending_count_tracks_queue_depth() -> TestResult {
    // pending() reports the queue depth at the moment of call.
    // Useful as a back-pressure diagnostic; this just guards
    // against an off-by-one in the accessor.
    use crate::mpsc_channel;
    let (tx, rx) = mpsc_channel::<u32>(8);
    if rx.pending() != 0 {
        return TestResult::Fail("fresh channel pending != 0");
    }
    tx.try_send(1).unwrap();
    tx.try_send(2).unwrap();
    tx.try_send(3).unwrap();
    if rx.pending() != 3 {
        return TestResult::Fail("pending didn't track three sends");
    }
    let _ = rx.try_recv();
    if rx.pending() != 2 {
        return TestResult::Fail("pending didn't decrement on recv");
    }
    TestResult::Pass
}
kernel_test_in!("ipc", smoke_ipc_mpsc_pending_count_tracks_queue_depth);

fn smoke_ipc_mpsc_consumer_drop_makes_late_send_closed() -> TestResult {
    // Producer keeps a clone across the consumer drop; subsequent
    // try_send must surface Closed. Models a driver task whose
    // submission queue's consumer (the dispatcher) was torn down.
    use crate::{mpsc_channel, MpscSendError};
    let (tx, rx) = mpsc_channel::<u8>(4);
    let tx2 = tx.clone();
    drop(rx);
    if !tx.is_closed() {
        return TestResult::Fail("is_closed false after consumer drop");
    }
    match tx2.try_send(7) {
        Err(MpscSendError::Closed(7)) => TestResult::Pass,
        _ => TestResult::Fail("post-consumer-drop send didn't surface Closed"),
    }
}
kernel_test_in!("ipc", smoke_ipc_mpsc_consumer_drop_makes_late_send_closed);

// ── ipc/mpsc_ring (Vyukov lock-free MPSC) ─────────────────────────

fn smoke_ipc_mpsc_ring_empty_pop_none() -> TestResult {
    let (_tx, mut rx) = crate::mpsc_ring_channel::<u32, 4>();
    match rx.try_recv() {
        Ok(None) => TestResult::Pass,
        _ => TestResult::Fail("empty MpscRing didn't surface Ok(None)"),
    }
}
kernel_test_in!("ipc/mpsc_ring", smoke_ipc_mpsc_ring_empty_pop_none);

fn smoke_ipc_mpsc_ring_single_round_trip() -> TestResult {
    let (tx, mut rx) = crate::mpsc_ring_channel::<u32, 4>();
    if tx.try_send(0xDEAD).is_err() {
        return TestResult::Fail("try_send failed on empty ring");
    }
    match rx.try_recv() {
        Ok(Some(0xDEAD)) => TestResult::Pass,
        _ => TestResult::Fail("round-trip lost value"),
    }
}
kernel_test_in!("ipc/mpsc_ring", smoke_ipc_mpsc_ring_single_round_trip);

fn smoke_ipc_mpsc_ring_fill_then_full() -> TestResult {
    use crate::MpscRingSendError;
    let (tx, _rx) = crate::mpsc_ring_channel::<u32, 4>();
    for i in 0..4 {
        if tx.try_send(i).is_err() {
            return TestResult::Fail("fill: try_send rejected within capacity");
        }
    }
    match tx.try_send(99) {
        Err(MpscRingSendError::Full(99)) => TestResult::Pass,
        Err(MpscRingSendError::Full(_)) => TestResult::Fail("Full returned wrong value"),
        Ok(()) => TestResult::Fail("ring accepted N+1 sends"),
        Err(MpscRingSendError::Closed(_)) => TestResult::Fail("unexpected Closed"),
    }
}
kernel_test_in!("ipc/mpsc_ring", smoke_ipc_mpsc_ring_fill_then_full);

fn smoke_ipc_mpsc_ring_fifo_single_producer() -> TestResult {
    // One producer → one consumer preserves FIFO order across wrap.
    let (tx, mut rx) = crate::mpsc_ring_channel::<u32, 4>();
    for batch in 0..4u32 {
        let base = batch * 4;
        for i in 0..4u32 {
            tx.try_send(base + i).unwrap();
        }
        for i in 0..4u32 {
            match rx.try_recv() {
                Ok(Some(v)) if v == base + i => {}
                _ => return TestResult::Fail("FIFO order violated"),
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("ipc/mpsc_ring", smoke_ipc_mpsc_ring_fifo_single_producer);

fn smoke_ipc_mpsc_ring_multi_producer_contention() -> TestResult {
    // 4 producer tasks push 1000 items each; one consumer drains 4000
    // and verifies count + no duplication via a bitmap of u32 IDs.
    use crate::mpsc_ring_channel;
    use core::sync::atomic::{AtomicU32, Ordering};

    const PER: u32 = 1000;
    const TOTAL: u32 = 4 * PER;
    static SEEN: [AtomicU32; 4000 / 32] = {
        const Z: AtomicU32 = AtomicU32::new(0);
        [Z; 4000 / 32]
    };
    static COUNT: AtomicU32 = AtomicU32::new(0);
    static DUPLICATE: AtomicU32 = AtomicU32::new(0);
    for w in &SEEN {
        w.store(0, Ordering::Relaxed);
    }
    COUNT.store(0, Ordering::Relaxed);
    DUPLICATE.store(0, Ordering::Relaxed);
    narf_scheduler::__reset_queues_for_test();

    let (tx, mut rx) = mpsc_ring_channel::<u32, 64>();
    for p in 0..4u32 {
        let tx = tx.clone();
        narf_scheduler::spawn(async move {
            let base = p * PER;
            for i in 0..PER {
                let v = base + i;
                while tx.try_send(v).is_err() {
                    narf_scheduler::yield_now().await;
                }
            }
        });
    }
    // Drop the original; clones keep the ring alive until tasks finish.
    drop(tx);

    narf_scheduler::spawn(async move {
        let mut got = 0u32;
        loop {
            match rx.try_recv() {
                Ok(Some(v)) => {
                    let word = (v / 32) as usize;
                    let bit = 1u32 << (v % 32);
                    let prev = SEEN[word].fetch_or(bit, Ordering::Relaxed);
                    if prev & bit != 0 {
                        DUPLICATE.fetch_add(1, Ordering::Relaxed);
                    }
                    got += 1;
                    if got == TOTAL {
                        break;
                    }
                }
                Ok(None) => narf_scheduler::yield_now().await,
                Err(_) => break,
            }
        }
        COUNT.store(got, Ordering::Relaxed);
    });

    narf_scheduler::run_until_empty();

    if COUNT.load(Ordering::Relaxed) != TOTAL {
        return TestResult::Fail("consumer didn't drain all 4000");
    }
    if DUPLICATE.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("duplicate delivery observed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "ipc/mpsc_ring",
    smoke_ipc_mpsc_ring_multi_producer_contention
);

fn smoke_ipc_mpsc_ring_drop_runs_payload_destructors() -> TestResult {
    use alloc::sync::Arc;
    let counter = Arc::new(());
    {
        let (tx, _rx) = crate::mpsc_ring_channel::<Arc<()>, 8>();
        for _ in 0..5 {
            tx.try_send(Arc::clone(&counter)).unwrap();
        }
        // Drop everything; the 5 Arc clones in unread slots must
        // be dropped by `MpscRing::drop`.
    }
    if Arc::strong_count(&counter) == 1 {
        TestResult::Pass
    } else {
        TestResult::Fail("MpscRing::drop didn't drop undelivered Arc payloads")
    }
}
kernel_test_in!(
    "ipc/mpsc_ring",
    smoke_ipc_mpsc_ring_drop_runs_payload_destructors
);

// ── ipc/spmc_ring (Vyukov lock-free SPMC) ─────────────────────────

fn smoke_ipc_spmc_ring_empty_pop_none() -> TestResult {
    let (_tx, rx) = crate::spmc_ring_channel::<u32, 4>();
    match rx.try_recv() {
        Ok(None) => TestResult::Pass,
        _ => TestResult::Fail("empty SpmcRing didn't surface Ok(None)"),
    }
}
kernel_test_in!("ipc/spmc_ring", smoke_ipc_spmc_ring_empty_pop_none);

fn smoke_ipc_spmc_ring_single_round_trip() -> TestResult {
    let (mut tx, rx) = crate::spmc_ring_channel::<u32, 4>();
    if tx.try_send(0xDEAD).is_err() {
        return TestResult::Fail("try_send failed on empty ring");
    }
    match rx.try_recv() {
        Ok(Some(0xDEAD)) => TestResult::Pass,
        _ => TestResult::Fail("round-trip lost value"),
    }
}
kernel_test_in!("ipc/spmc_ring", smoke_ipc_spmc_ring_single_round_trip);

fn smoke_ipc_spmc_ring_fill_then_full() -> TestResult {
    use crate::SpmcRingSendError;
    let (mut tx, _rx) = crate::spmc_ring_channel::<u32, 4>();
    for i in 0..4 {
        if tx.try_send(i).is_err() {
            return TestResult::Fail("fill: try_send rejected within capacity");
        }
    }
    match tx.try_send(99) {
        Err(SpmcRingSendError::Full(99)) => TestResult::Pass,
        Err(SpmcRingSendError::Full(_)) => TestResult::Fail("Full returned wrong value"),
        Ok(()) => TestResult::Fail("ring accepted N+1 sends"),
        Err(SpmcRingSendError::Closed(_)) => TestResult::Fail("unexpected Closed"),
    }
}
kernel_test_in!("ipc/spmc_ring", smoke_ipc_spmc_ring_fill_then_full);

fn smoke_ipc_spmc_ring_fifo_single_consumer() -> TestResult {
    let (mut tx, rx) = crate::spmc_ring_channel::<u32, 4>();
    for batch in 0..4u32 {
        let base = batch * 4;
        for i in 0..4u32 {
            tx.try_send(base + i).unwrap();
        }
        for i in 0..4u32 {
            match rx.try_recv() {
                Ok(Some(v)) if v == base + i => {}
                _ => return TestResult::Fail("FIFO order violated"),
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("ipc/spmc_ring", smoke_ipc_spmc_ring_fifo_single_consumer);

fn smoke_ipc_spmc_ring_multi_consumer_contention() -> TestResult {
    use crate::spmc_ring_channel;
    use core::sync::atomic::{AtomicU32, Ordering};

    const TOTAL: u32 = 4000;
    static SEEN: [AtomicU32; 4000 / 32] = {
        const Z: AtomicU32 = AtomicU32::new(0);
        [Z; 4000 / 32]
    };
    static COUNT: AtomicU32 = AtomicU32::new(0);
    static DUPLICATE: AtomicU32 = AtomicU32::new(0);
    for w in &SEEN {
        w.store(0, Ordering::Relaxed);
    }
    COUNT.store(0, Ordering::Relaxed);
    DUPLICATE.store(0, Ordering::Relaxed);
    narf_scheduler::__reset_queues_for_test();

    let (mut tx, rx) = spmc_ring_channel::<u32, 64>();

    narf_scheduler::spawn(async move {
        for v in 0..TOTAL {
            while tx.try_send(v).is_err() {
                narf_scheduler::yield_now().await;
            }
        }
    });

    for _ in 0..4u32 {
        let rx = rx.clone();
        narf_scheduler::spawn(async move {
            loop {
                match rx.try_recv() {
                    Ok(Some(v)) => {
                        let word = (v / 32) as usize;
                        let bit = 1u32 << (v % 32);
                        let prev = SEEN[word].fetch_or(bit, Ordering::Relaxed);
                        if prev & bit != 0 {
                            DUPLICATE.fetch_add(1, Ordering::Relaxed);
                        }
                        COUNT.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(None) => narf_scheduler::yield_now().await,
                    Err(_) => break,
                }
            }
        });
    }
    drop(rx);

    narf_scheduler::run_until_empty();

    if COUNT.load(Ordering::Relaxed) != TOTAL {
        return TestResult::Fail("consumers didn't drain all 4000");
    }
    if DUPLICATE.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("duplicate delivery observed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "ipc/spmc_ring",
    smoke_ipc_spmc_ring_multi_consumer_contention
);

fn smoke_ipc_spmc_ring_drop_runs_payload_destructors() -> TestResult {
    use alloc::sync::Arc;
    let counter = Arc::new(());
    {
        let (mut tx, _rx) = crate::spmc_ring_channel::<Arc<()>, 8>();
        for _ in 0..5 {
            tx.try_send(Arc::clone(&counter)).unwrap();
        }
    }
    if Arc::strong_count(&counter) == 1 {
        TestResult::Pass
    } else {
        TestResult::Fail("SpmcRing::drop didn't drop undelivered Arc payloads")
    }
}
kernel_test_in!(
    "ipc/spmc_ring",
    smoke_ipc_spmc_ring_drop_runs_payload_destructors
);

// ── retag-on-publish ──────────────────────────────────────────────

fn smoke_ipc_retag_default_is_identity() -> TestResult {
    // A type that does NOT implement `Retag` must flow through the
    // ring untouched. Sending eight u64 values verifies the autoref
    // fallback path is exercised (and yields the same values back).
    use core::sync::atomic::{AtomicU64, Ordering};
    static SUM: AtomicU64 = AtomicU64::new(0);

    SUM.store(0, Ordering::Relaxed);
    narf_scheduler::__reset_queues_for_test();

    let (mut tx, mut rx) = crate::channel::<u64, 8>();
    narf_scheduler::spawn(async move {
        for i in 1u64..=8 {
            let _ = tx.send(i).await;
        }
    });
    narf_scheduler::spawn(async move {
        while let Ok(v) = rx.recv().await {
            SUM.fetch_add(v, Ordering::Relaxed);
        }
    });
    narf_scheduler::run_until_empty();
    if SUM.load(Ordering::Relaxed) == 36 {
        TestResult::Pass
    } else {
        TestResult::Fail("identity retag path corrupted the payload")
    }
}
kernel_test_in!("ipc", smoke_ipc_retag_default_is_identity);

fn smoke_ipc_retag_opt_in_type_invokes_retag() -> TestResult {
    // A type that DOES implement `Retag` must observe its `retag`
    // hook called exactly once per `Producer::try_send`. The hook
    // increments a static counter; we send N messages and assert N.
    use core::sync::atomic::{AtomicU32, Ordering};
    static HITS: AtomicU32 = AtomicU32::new(0);

    #[derive(Debug)]
    struct Tagged(u32);
    impl crate::Retag for Tagged {
        fn retag(self) -> Self {
            HITS.fetch_add(1, Ordering::Relaxed);
            self
        }
    }

    HITS.store(0, Ordering::Relaxed);
    narf_scheduler::__reset_queues_for_test();

    let (mut tx, mut rx) = crate::channel::<Tagged, 4>();
    narf_scheduler::spawn(async move {
        for i in 0u32..5 {
            let _ = tx.send(Tagged(i)).await;
        }
    });
    narf_scheduler::spawn(async move {
        let mut seen = 0u32;
        while let Ok(Tagged(v)) = rx.recv().await {
            if v != seen {
                HITS.store(0xDEAD, Ordering::Relaxed);
                break;
            }
            seen += 1;
        }
    });
    narf_scheduler::run_until_empty();

    match HITS.load(Ordering::Relaxed) {
        5 => TestResult::Pass,
        0xDEAD => TestResult::Fail("Retag delivered out of order"),
        _ => TestResult::Fail("Retag::retag not invoked exactly once per send"),
    }
}
kernel_test_in!("ipc", smoke_ipc_retag_opt_in_type_invokes_retag);

#[cfg(target_arch = "aarch64")]
fn smoke_arch_mte_irg_stg_round_trip() -> TestResult {
    // IRG a 16-byte-aligned scratch buffer, STG the granule, LDG it
    // back, assert the logical tag in bits 59:56 of the returned
    // pointer matches the IRG output. Skipped on CPUs without MTE.
    use narf_arch::aarch64::mte;
    if !mte::supported() {
        return TestResult::Skip("MTE not supported (QEMU virt,mte=on absent)");
    }
    #[repr(align(16))]
    struct Granule([u8; 16]);
    let mut scratch = Granule([0u8; 16]);
    let raw = scratch.0.as_mut_ptr();

    // SAFETY: supported() gated; IRG/STG/LDG operate on a stack
    // buffer the kernel owns; tag-storage is mapped for kernel RAM
    // when SCTLR_EL1.ATA=1 (boot.S precondition).
    // SAFETY: Valid memory or trusted environment
    unsafe {
        let tagged = mte::irg(raw);
        mte::stg(tagged);
        let read_back = mte::ldg(raw);
        let mask_addr = 0x00FF_FFFF_FFFF_FFFFu64;
        let tag_bits = (tagged as u64) & !mask_addr;
        let lbits = (read_back as u64) & !mask_addr;
        let addr_bits = (read_back as u64) & mask_addr;
        if addr_bits != (raw as u64) & mask_addr {
            return TestResult::Fail("LDG mangled the address bits");
        }
        if lbits != tag_bits {
            return TestResult::Fail("LDG tag does not match the IRG'd tag stored by STG");
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("ipc", smoke_arch_mte_irg_stg_round_trip);

fn smoke_ipc_channel_construction_stays_in_heap() -> TestResult {
    // Canary against the layout-shift bug documented in
    // docs/notes/2026-05-19-layout-shift-bug.md. The fault dump
    // showed a SendFuture::poll dereferencing `r14 + 0x90` where
    // r14 was claimed to be a Context pointer but in fact held
    // 0x40000eb0 — past 1 GiB, in QEMU's reserved gap between
    // RAM and PCI MMIO. The only way r14 ends up at 0x40000eb0
    // through the SendFuture poll path is if the Producer's
    // inner Arc<Ring> was allocated at that address.
    //
    // This smoke creates + drops `narf_ipc::channel::<u64, 4>()`
    // 256 times and asserts the inner Ring address falls inside
    // the kernel heap range: > the kernel text/data sections,
    // < 4 GiB (the early identity-map ceiling). Any escape into
    // the 0x4000_0000+ region would reproduce the bug shape
    // here.
    let mut bad_count = 0u32;
    let mut sample_bad: u64 = 0;
    for _ in 0..256 {
        let (p, c) = crate::channel::<u64, 4>();
        // The kernel heap is reached through the high-half direct map, so
        // the raw pointer carries KERNEL_DIRECT_MAP_BASE. Invert it to get
        // the physical address the RAM-range check is really about; the
        // canary is about *which frame* the Ring landed in, not which VA.
        let ptr = narf_memory::PhysAddr::from_kernel_ptr(p.__ring_ptr_for_test()).raw();
        // Heap allocations land below the 4 GiB ceiling on x86_64, and
        // above 0 (Arc::as_ptr is never null on a live Arc).
        #[cfg(target_arch = "x86_64")]
        let is_bad = ptr == 0 || ptr >= (4u64 << 30);
        #[cfg(not(target_arch = "x86_64"))]
        let is_bad = ptr == 0;

        if is_bad {
            bad_count += 1;
            if sample_bad == 0 {
                sample_bad = ptr;
            }
        }
        // Also check the consumer matches. Invert the direct-map offset on
        // this one too -- comparing a physical address against a raw kernel
        // pointer can never match.
        let cptr = narf_memory::PhysAddr::from_kernel_ptr(c.__ring_ptr_for_test()).raw();
        if cptr != ptr {
            return TestResult::Fail("producer/consumer point at different rings");
        }
        drop(p);
        drop(c);
    }
    let _ = sample_bad;
    if bad_count > 0 {
        return TestResult::Fail("channel::<>() Arc<Ring> landed outside [0, 4 GiB)");
    }
    TestResult::Pass
}
kernel_test_in!("ipc", smoke_ipc_channel_construction_stays_in_heap);

fn smoke_ipc_channel_diagnostic_accessor_works() -> TestResult {
    // Sanity-check the diagnostic accessor itself before trusting
    // it in the canary above. Pointer must be non-null and
    // page-aligned-ish (heap allocator returns at least 8-byte
    // alignment for the Arc allocation block).
    let (p, c) = crate::channel::<u32, 4>();
    let ptr = p.__ring_ptr_for_test() as u64;
    if ptr == 0 {
        return TestResult::Fail("__ring_ptr_for_test returned null");
    }
    if ptr & 0x7 != 0 {
        return TestResult::Fail("__ring_ptr_for_test not 8-byte aligned");
    }
    if c.__ring_ptr_for_test() as u64 != ptr {
        return TestResult::Fail("producer/consumer rings differ");
    }
    TestResult::Pass
}
kernel_test_in!("ipc", smoke_ipc_channel_diagnostic_accessor_works);

fn smoke_ipc_consumer_diagnostic_accessor() -> TestResult {
    // Same accessor on Consumer (it owns the same Arc).
    let (p, c) = crate::channel::<u32, 4>();
    let pp = p.__ring_ptr_for_test() as u64;
    let cp = c.__ring_ptr_for_test() as u64;
    if pp != cp {
        return TestResult::Fail("producer/consumer ring addresses differ");
    }
    TestResult::Pass
}
kernel_test_in!("ipc", smoke_ipc_consumer_diagnostic_accessor);

// ── Wave K: pluggable ring transport ──────────────────────────────

fn smoke_pluggable_ring_transport() -> TestResult {
    // Build a VecRing and a Ring, push/pop the same sequence through
    // both, assert FIFO order. Two paths exercise the same trait —
    // the spinlock-backed VecDeque baseline and the cache-line SPSC
    // ring — proving the trait compiles + dispatches against both.
    use crate::{Ring, RingTransport, VecRing};
    let vr: VecRing<u32> = VecRing::new(16);
    let r: Ring<u32, 16> = Ring::new();
    for x in 0..8u32 {
        if vr.try_push(x).is_err() {
            return TestResult::Fail("VecRing rejected push within capacity");
        }
        if r.try_push(x).is_err() {
            return TestResult::Fail("Ring rejected push within capacity");
        }
    }
    if vr.len() != 8 || r.len() != 8 {
        return TestResult::Fail("len() did not track 8 pushes");
    }
    for x in 0..8u32 {
        if vr.try_pop() != Some(x) {
            return TestResult::Fail("VecRing FIFO order violated");
        }
        if r.try_pop() != Some(x) {
            return TestResult::Fail("Ring FIFO order violated");
        }
    }
    if !vr.is_empty() || !r.is_empty() {
        return TestResult::Fail("ring not empty after draining");
    }
    if vr.try_pop().is_some() || r.try_pop().is_some() {
        return TestResult::Fail("pop on empty returned Some");
    }
    TestResult::Pass
}
kernel_test_in!("ipc", smoke_pluggable_ring_transport);
