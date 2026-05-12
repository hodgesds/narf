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
        loop {
            match rx.recv().await {
                Ok(v) => {
                    SUM.fetch_add(v, Ordering::Relaxed);
                }
                Err(crate::RecvError::Closed) => break,
            }
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
    unsafe {
        core::ptr::write_bytes(frame.raw() as *mut u8, 0, 4096);
    }
    let kernel_view = frame.raw() as *mut SharedRing<u64, 8>;

    // Verify the layout fits in 4 KiB.
    if SharedRing::<u64, 8>::size_bytes() > 4096 {
        return TestResult::Fail("SharedRing<u64,8> larger than a 4 KiB page");
    }

    // Initialise.
    unsafe {
        SharedRing::<u64, 8>::init_in(kernel_view);
    }

    // Two distinct pointer values that resolve to the same backing
    // (here, both are the same kernel-identity vaddr; in real use
    // one of them would be the user's mapping of the same phys).
    let user_view = frame.raw() as *mut SharedRing<u64, 8>;

    let mut prod = unsafe { SharedProducer::<u64, 8>::from_raw(kernel_view) };
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
        unsafe {
            let dst = buf.phys_addr().as_mut_ptr::<u8>();
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
        // SAFETY: buf ownership transferred to this task; identity-
        // mapped phys address readable.
        let mut ok = true;
        unsafe {
            let src = buf.phys_addr().as_ptr::<u8>();
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
    use core::sync::atomic::{AtomicU32, Ordering};
    use crate::{mpsc_channel, MpscRecvError};

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
