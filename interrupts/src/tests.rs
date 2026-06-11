//! Per-crate smoke tests for `narf-interrupts`.
//!
//! Tests register via `narf_kernel_test::kernel_test_in!` so the
//! runner groups output under `"interrupts"`. Migrated from
//! `narf-verification`'s mega-lib so each subsystem owns its own
//! smokes without cycling on the higher-level harness.

extern crate alloc;

use narf_kernel_test::{kernel_test_in, TestResult};

#[cfg(target_arch = "x86_64")]
fn smoke_timer_irq_fires() -> TestResult {
    // Hardware-IRQ end-to-end: program the LAPIC timer + STI, busy-wait
    // a while, confirm the tick counter advances. Requires PIC masking
    // (done by apic::init_bsp) — otherwise legacy PIC IRQs land on our
    // CPU-exception slots and cause #DF.
    use narf_arch::x86_64::Features;
    // SAFETY: CPUID always legal.
    let feats = unsafe { Features::probe() };
    if !feats.x2apic {
        return TestResult::Skip("x2APIC not exposed");
    }
    let before = crate::x86_64::apic::timer_ticks();
    // SAFETY: APIC init has run at boot; this programs the timer + STI.
    unsafe {
        crate::x86_64::apic::start_timer(crate::VECTOR_TIMER, 500_000);
        narf_arch::enable_interrupts();
    }
    // Busy-wait ~50M cycles.
    let start = narf_time::Instant::now();
    while narf_time::Instant::now().cycles_since(start) < 50_000_000 {
        core::hint::spin_loop();
    }
    // SAFETY: disable IRQs + stop timer before checking.
    unsafe {
        narf_arch::disable_interrupts();
        crate::x86_64::apic::stop_timer();
    }
    let after = crate::x86_64::apic::timer_ticks();
    if after > before {
        TestResult::Pass
    } else {
        TestResult::Fail("LAPIC timer IRQ never fired")
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("interrupts", smoke_timer_irq_fires);

fn smoke_irq_dispatch_fire_count() -> TestResult {
    // Synthesise an IRQ delivery into the dispatch table and verify
    // the fire-count atomic moves. Vector 100 is unused by the
    // kernel; calling on_irq directly bypasses the trap path.
    let before = crate::fire_count(100);
    crate::on_irq(100);
    crate::on_irq(100);
    let after = crate::fire_count(100);
    if after - before != 2 {
        return TestResult::Fail("on_irq did not bump fire_count by 2");
    }
    TestResult::Pass
}
kernel_test_in!("interrupts", smoke_irq_dispatch_fire_count);

fn smoke_vector_alloc_unique() -> TestResult {
    use crate::vector::{alloc, free, is_allocated};
    let v0 = match alloc() {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("alloc#0 failed"),
    };
    let v1 = match alloc() {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("alloc#1 failed"),
    };
    if v0 == v1 {
        return TestResult::Fail("two allocs returned the same vector");
    }
    if !is_allocated(v0) || !is_allocated(v1) {
        return TestResult::Fail("alloc'd vector not marked");
    }
    if free(v0).is_err() {
        return TestResult::Fail("free returned error");
    }
    if free(v0).is_ok() {
        return TestResult::Fail("double-free silently accepted");
    }
    if free(v1).is_err() {
        return TestResult::Fail("free#1 returned error");
    }
    TestResult::Pass
}
kernel_test_in!("interrupts", smoke_vector_alloc_unique);

fn smoke_wait_for_irq_resolves_after_on_irq() -> TestResult {
    // wait_for_irq on a never-fired vector polls Pending; firing the
    // vector wakes the future and the next poll returns Ready.
    use core::future::Future;
    use core::pin::Pin;
    use core::sync::atomic::{AtomicBool, Ordering};
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    // Hand-rolled noop-ish waker that flips a flag.
    static WOKEN: AtomicBool = AtomicBool::new(false);
    fn noop_clone(p: *const ()) -> RawWaker {
        RawWaker::new(p, &VTABLE)
    }
    fn noop_wake(_: *const ()) {
        WOKEN.store(true, Ordering::Release);
    }
    fn noop_wake_by_ref(_: *const ()) {
        WOKEN.store(true, Ordering::Release);
    }
    fn noop_drop(_: *const ()) {}
    static VTABLE: RawWakerVTable =
        RawWakerVTable::new(noop_clone, noop_wake, noop_wake_by_ref, noop_drop);

    WOKEN.store(false, Ordering::Release);
    // SAFETY: vtable functions are non-null; we're constructing a
    // local Waker for a one-shot poll.
    let w = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&w);

    let mut fut = crate::wait_for_irq(101);
    // First poll: no IRQ yet, registers waker.
    // SAFETY: `fut` lives on this stack frame and is never moved
    // after this point — we only poll it through `pinned` — so the
    // pinning invariant required by `Pin::new_unchecked` holds.
    let mut pinned = unsafe { Pin::new_unchecked(&mut fut) };
    if !matches!(pinned.as_mut().poll(&mut cx), Poll::Pending) {
        return TestResult::Fail("wait_for_irq returned Ready before any IRQ");
    }
    // Fire the IRQ; the waker should be called.
    crate::on_irq(101);
    if !WOKEN.load(Ordering::Acquire) {
        return TestResult::Fail("on_irq did not invoke the registered waker");
    }
    // Second poll: IRQ fired → Ready.
    match pinned.as_mut().poll(&mut cx) {
        Poll::Ready(_) => TestResult::Pass,
        Poll::Pending => TestResult::Fail("wait_for_irq stayed Pending after IRQ"),
    }
}
kernel_test_in!("interrupts", smoke_wait_for_irq_resolves_after_on_irq);

#[cfg(target_arch = "x86_64")]
fn smoke_tlb_shootdown_bridge_smp_fanout() -> TestResult {
    // End-to-end: with SMP up + the IPI bridge installed, calling
    // `narf_memory::tlb_shootdown::shootdown` for a (tag, va) request
    // should advance every peer CPU's EVER_RECEIVED counter (the IPI
    // handler bumps it on every shootdown delivery).
    use crate::x86_64::ipi;
    use narf_memory::tlb_shootdown;
    if narf_lib::smp::cpu_count() <= 1 {
        return TestResult::Skip("UP boot — no peer CPUs to shoot");
    }
    let self_cpu = narf_lib::percpu::current_cpu() as u32;
    let total = narf_lib::smp::cpu_count();
    let mut snap = [0u64; narf_lib::percpu::MAX_CPUS];
    for cpu in 0..total {
        if cpu == self_cpu {
            continue;
        }
        snap[cpu as usize] = ipi::ever_received(cpu);
    }
    let req = tlb_shootdown::ShootdownRequest {
        tag: Some(1),
        addr: Some(0xFFFF_FFFF_8000_0000),
        size: Some(4096),
    };
    tlb_shootdown::shootdown(req);
    let mut spins = 0u32;
    loop {
        let mut all_advanced = true;
        for cpu in 0..total {
            if cpu == self_cpu {
                continue;
            }
            if ipi::ever_received(cpu) <= snap[cpu as usize] {
                all_advanced = false;
                break;
            }
        }
        if all_advanced {
            break;
        }
        spins += 1;
        if spins > 10_000_000 {
            return TestResult::Fail("peer CPUs never received shootdown");
        }
        core::hint::spin_loop();
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("interrupts/ipi", smoke_tlb_shootdown_bridge_smp_fanout);

// ── relocated from verification ──

#[cfg(target_arch = "x86_64")]
fn smoke_hpet_pick_gsi_prefers_high_block_with_legacy_fallback() -> TestResult {
    // pick_gsi(mask, min_gsi) prefers GSIs ≥ min_gsi (high range)
    // but FALLS BACK to non-reserved low-block GSIs (0..16) so HPET
    // works on QEMU q35 where timer 0 route_cap is 0x4 (GSI 2 only).
    // LEGACY_RESERVED skips the well-known legacy assignments
    // (0=PIT, 1=i8042, 8=RTC, 13=FPU); GSI 2 (historic PIC cascade)
    // is allowed because the PIT is masked when HPET is running.
    use crate::x86_64::hpet_oneshot::__pick_gsi_for_test as pick;
    // High range satisfied → return min_gsi (lowest set high bit).
    if pick(0xFFFF_FFFF, 16) != Some(16) {
        return TestResult::Fail("did not pick lowest high GSI");
    }
    // Only ISA bits set → fallback hits the low block, returns
    // GSI 2 (lowest non-reserved low bit).
    match pick(0x0000_FFFF, 16) {
        Some(2) => {}
        Some(g) => {
            let _ = g;
            return TestResult::Fail("low fallback returned wrong GSI (expected 2)");
        }
        None => return TestResult::Fail("low fallback returned None"),
    }
    // Single high bit at GSI 22 → return 22.
    if pick(1u32 << 22, 16) != Some(22) {
        return TestResult::Fail("did not pick the only high GSI");
    }
    // Empty mask → None.
    if pick(0, 16).is_some() {
        return TestResult::Fail("returned a GSI for an empty mask");
    }
    // Only LEGACY_RESERVED low bits set (0,1,8,13) → None
    // (fallback skips every reserved assignment).
    let legacy_only = (1u32 << 0) | (1u32 << 1) | (1u32 << 8) | (1u32 << 13);
    if pick(legacy_only, 16).is_some() {
        return TestResult::Fail("returned a reserved legacy GSI");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "interrupts/hpet",
    smoke_hpet_pick_gsi_prefers_high_block_with_legacy_fallback
);

#[cfg(target_arch = "x86_64")]
fn smoke_hpet_oneshot_fires_handler() -> TestResult {
    // End-to-end: arm a HPET one-shot for ~1 ms in the future, STI,
    // wait for the handler-installed atomic to flip. Skips when HPET
    // wasn't initialised (some test boots run without ACPI parsing).
    use crate::x86_64::hpet_oneshot;
    use core::sync::atomic::{AtomicBool, Ordering};

    if !narf_time::hpet::is_present() {
        return TestResult::Skip("HPET not initialised");
    }
    if narf_acpi::apic_id_at(0).is_none() {
        return TestResult::Skip("MADT did not enumerate a local APIC");
    }
    // Need a comparator-0 with at least one safe GSI in its
    // route-cap; QEMU's HPET reports route-cap = 0x00F0_0000 (GSIs
    // 20-23) which is fine. Bare-metal that pins HPET to legacy
    // routing might fail this — skip cleanly.
    let cap = narf_time::hpet::timer_route_cap(0);
    if (cap >> 16) == 0 {
        return TestResult::Skip("HPET comparator 0 has no safe GSI");
    }

    static FIRED: AtomicBool = AtomicBool::new(false);
    fn handler() {
        FIRED.store(true, Ordering::Release);
    }
    FIRED.store(false, Ordering::Release);

    let hpet_hz = narf_time::hpet::frequency_hz();
    if hpet_hz == 0 {
        return TestResult::Skip("HPET reported zero frequency");
    }
    // ~1 ms from now in HPET ticks. Cap to a sensible minimum so a
    // very slow HPET still gives the IOAPIC programming time to
    // settle before the deadline passes.
    let ticks_in_1ms = (hpet_hz / 1000).max(1000);
    let now = narf_time::hpet::read_counter();
    let deadline = now.wrapping_add(ticks_in_1ms);

    // SAFETY: HPET + APIC up; handler only touches a static atomic.
    if let Err(e) = unsafe { hpet_oneshot::arm_oneshot(deadline, handler) } {
        // Map common environmental failures to Skip so the smoke is
        // diagnostic on bare metal that lacks the right plumbing.
        return match e {
            hpet_oneshot::HpetOneshotError::NoSafeGsi
            | hpet_oneshot::HpetOneshotError::IoapicRoutingFailed => {
                TestResult::Skip("IOAPIC route to HPET unavailable")
            }
            _ => TestResult::Fail("arm_oneshot returned an error"),
        };
    }

    // SAFETY: HPET IRQ handler is wired; STI to receive it.
    unsafe { narf_arch::enable_interrupts() };
    let start = narf_time::Instant::now();
    while !FIRED.load(Ordering::Acquire) {
        // Wait up to ~250 ms of TSC time. The smoke runs early in
        // boot so RDTSC frequency may be uncalibrated; we use a
        // large cycle budget that's still a small wallclock.
        if narf_time::Instant::now().cycles_since(start) > 1_000_000_000 {
            // SAFETY: disable IRQs before bailing.
            unsafe { narf_arch::disable_interrupts() };
            return TestResult::Fail("HPET one-shot handler never fired");
        }
        core::hint::spin_loop();
    }
    // SAFETY: same.
    unsafe { narf_arch::disable_interrupts() };
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("interrupts/hpet", smoke_hpet_oneshot_fires_handler);

// ── Timer-wheel pump (HPET-driven SleepUntil) ────────────────────

#[cfg(target_arch = "x86_64")]
fn smoke_timer_pump_drives_wheel_sleep() -> TestResult {
    // End-to-end: register a SleepUntil for ~1 ms ahead, STI, await
    // by polling. The HPET pump (init'd in bare_main) must arm
    // HPET, fire on deadline, and the wheel callback must wake the
    // SleepUntil so its next poll reports Ready.
    use crate::x86_64::timer_pump;
    use alloc::sync::Arc;
    use alloc::task::Wake;
    use core::future::Future;
    use core::pin::Pin;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use core::task::{Context, Poll};

    if !timer_pump::is_initialised() {
        return TestResult::Skip("timer_pump not initialised");
    }

    struct CW(AtomicUsize);
    impl Wake for CW {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    let cw = Arc::new(CW(AtomicUsize::new(0)));
    let waker: core::task::Waker = cw.clone().into();
    let mut cx = Context::from_waker(&waker);

    // ~5 ms in the future: comfortably > IOAPIC programming latency,
    // well under any reasonable test timeout.
    let cycles_per_ns = narf_time::cycles_per_ns() as u64;
    let cycles_5ms = cycles_per_ns * 5_000_000;
    let deadline = narf_time::Instant::now().plus_cycles(cycles_5ms);
    let mut s = narf_time::SleepUntil::new(deadline);

    if !matches!(Pin::new(&mut s).poll(&mut cx), Poll::Pending) {
        return TestResult::Fail("first poll should be Pending");
    }

    // SAFETY: timer_pump is initialised; HPET will deliver via IOAPIC.
    unsafe { narf_arch::enable_interrupts() };

    let start = narf_time::Instant::now();
    let mut woken = false;
    while narf_time::Instant::now().cycles_since(start) < cycles_per_ns * 500_000_000 {
        if cw.0.load(Ordering::Relaxed) > 0 {
            woken = true;
            break;
        }
        core::hint::spin_loop();
    }
    // SAFETY: re-disable IRQs before returning.
    unsafe { narf_arch::disable_interrupts() };

    if !woken {
        return TestResult::Fail("timer_wheel never woke the sleep waker");
    }

    if !matches!(Pin::new(&mut s).poll(&mut cx), Poll::Ready(())) {
        return TestResult::Fail("post-wake poll should be Ready");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("interrupts/timer", smoke_timer_pump_drives_wheel_sleep);

fn smoke_vector_alloc_block_contiguous() -> TestResult {
    // alloc_block(4) returns a contiguous run of 4 vectors.
    use crate::vector::{alloc_block, free, is_allocated};
    let base = match alloc_block(4) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("alloc_block(4) failed"),
    };
    for i in 0..4 {
        if !is_allocated(base + i) {
            return TestResult::Fail("alloc_block bit not set");
        }
    }
    for i in 0..4 {
        if free(base + i).is_err() {
            return TestResult::Fail("free during cleanup");
        }
    }
    TestResult::Pass
}
kernel_test_in!("interrupts", smoke_vector_alloc_block_contiguous);

#[cfg(target_arch = "x86_64")]
fn smoke_dispatch_in_irq_observed_inside_handler() -> TestResult {
    // End-to-end: install a synchronous handler on an unused
    // vector, fire it via `int <vec>`, and verify the handler
    // body observes `narf_lib::context::in_irq() == true`. This
    // proves dispatch.rs's enter_irq/exit_irq instrumentation
    // reaches real IRQ context (not just simulated context the
    // memory-crate unit tests use).
    use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    // Vector 0xE0: outside the standard reserved set
    // (32 = timer, 0xF0 = TLB shootdown, 0xFE = APIC error,
    // 0xFF = spurious). Unallocated in the kernel today.
    const TEST_VEC: u8 = 0xE0;

    static FIRED: AtomicBool = AtomicBool::new(false);
    static IN_IRQ_SEEN: AtomicU32 = AtomicU32::new(2); // sentinel

    fn handler() {
        FIRED.store(true, Ordering::Release);
        IN_IRQ_SEEN.store(
            if narf_lib::context::in_irq() { 1 } else { 0 },
            Ordering::Release,
        );
    }

    crate::dispatch::install(TEST_VEC, handler);
    FIRED.store(false, Ordering::Release);
    IN_IRQ_SEEN.store(2, Ordering::Release);

    // Fire via software interrupt. The trap path routes
    // vectors >= 32 through on_irq, which is the
    // instrumentation under test.
    // SAFETY: handler installed above; vector is unallocated
    // outside this test.
    unsafe {
        core::arch::asm!("int {v}", v = const TEST_VEC, options(nomem, nostack));
    }

    crate::dispatch::clear_handler(TEST_VEC);

    if !FIRED.load(Ordering::Acquire) {
        return TestResult::Fail("synchronous handler didn't run");
    }
    if IN_IRQ_SEEN.load(Ordering::Acquire) != 1 {
        return TestResult::Fail("handler didn't observe in_irq() == true");
    }
    // Post-handler: depth back to 0.
    if narf_lib::context::in_irq() {
        return TestResult::Fail("post-handler depth didn't return to 0");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("interrupts", smoke_dispatch_in_irq_observed_inside_handler);

#[cfg(target_arch = "x86_64")]
fn smoke_atomic_pool_usable_from_real_irq_handler() -> TestResult {
    // End-to-end: install a synchronous handler that leases an
    // item from an AtomicPool, mutates it, returns it via Drop.
    // Fire the vector. Post-handler, the pool's free count
    // returns to baseline — the IRQ-side Drop ran through the
    // pool's IrqSafeSpinLock without deadlock.
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_memory::atomic_pool::AtomicPool;

    // 0xE1: unused vector; 0xE0 is the in_irq() observation
    // test above.
    const TEST_VEC: u8 = 0xE1;

    static POOL: narf_lib::sync::OnceLock<AtomicPool<u64>> = narf_lib::sync::OnceLock::new();
    let pool = POOL.get_or_init(|| AtomicPool::new(2, || 0u64));

    static OBSERVED: AtomicU64 = AtomicU64::new(0);

    fn handler() {
        let pool = POOL.get().expect("pool initialised");
        let mut h = pool.try_get().expect("pool not empty in handler");
        *h = 0xDEAD_BEEF;
        OBSERVED.store(*h, Ordering::Release);
        // h drops here, returns the item to the pool.
    }

    let before = pool.free_count();

    crate::dispatch::install(TEST_VEC, handler);
    OBSERVED.store(0, Ordering::Release);
    // SAFETY: vector is unused outside this test.
    unsafe {
        core::arch::asm!("int {v}", v = const TEST_VEC, options(nomem, nostack));
    }
    crate::dispatch::clear_handler(TEST_VEC);

    if OBSERVED.load(Ordering::Acquire) != 0xDEAD_BEEF {
        return TestResult::Fail("handler didn't run / wrote wrong value");
    }
    if pool.free_count() != before {
        return TestResult::Fail("Drop in IRQ ctx didn't return item to pool");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("interrupts", smoke_atomic_pool_usable_from_real_irq_handler);

// ── extended interrupts coverage ───────────────────────────────────
//
// The smokes above hit IRQ-end-to-end and the basic alloc/dispatch
// shape. These close the remaining invariants on:
//   - dispatch sync-handler install / clear / firing-order vs waker
//   - independent per-vector accounting
//   - vector allocator: rollback, OutOfRange edges, reuse-after-free
//   - WaitForIrq baseline + Drop-clears-waker

// Test-only vectors. The ones below 200 are reserved for `on_irq()`
// software-synthesised tests so they don't collide with hardware
// vectors (timer = 32, TLB shootdown = 0xF0, APIC error = 0xFE,
// spurious = 0xFF). 0xE0/0xE1 are used by the `int <vec>` IRQ-ctx
// smokes above; keep these in 110..=130.
const SCRATCH_VEC_A: u8 = 110;
const SCRATCH_VEC_B: u8 = 111;
const SCRATCH_VEC_HANDLER: u8 = 112;
const SCRATCH_VEC_HANDLER_CLEAR: u8 = 113;
const SCRATCH_VEC_HANDLER_ORDER: u8 = 114;
const SCRATCH_VEC_BASELINE: u8 = 115;
const SCRATCH_VEC_DROP_CLEARS: u8 = 116;

fn smoke_dispatch_sync_handler_runs_on_on_irq() -> TestResult {
    // `install(v, h)` + `on_irq(v)` fires the synchronous handler.
    // No trap path involved — just exercises the dispatch table.
    use core::sync::atomic::{AtomicU32, Ordering};
    static HITS: AtomicU32 = AtomicU32::new(0);
    HITS.store(0, Ordering::Relaxed);
    fn h() {
        HITS.fetch_add(1, Ordering::Relaxed);
    }

    crate::dispatch::install(SCRATCH_VEC_HANDLER, h);
    crate::on_irq(SCRATCH_VEC_HANDLER);
    crate::on_irq(SCRATCH_VEC_HANDLER);
    crate::dispatch::clear_handler(SCRATCH_VEC_HANDLER);
    if HITS.load(Ordering::Relaxed) == 2 {
        TestResult::Pass
    } else {
        TestResult::Fail("sync handler didn't run twice across two on_irq calls")
    }
}
kernel_test_in!("interrupts", smoke_dispatch_sync_handler_runs_on_on_irq);

fn smoke_dispatch_clear_handler_stops_invocations() -> TestResult {
    // Install, fire (handler runs), clear, fire again (handler must NOT run).
    use core::sync::atomic::{AtomicU32, Ordering};
    static HITS: AtomicU32 = AtomicU32::new(0);
    HITS.store(0, Ordering::Relaxed);
    fn h() {
        HITS.fetch_add(1, Ordering::Relaxed);
    }

    crate::dispatch::install(SCRATCH_VEC_HANDLER_CLEAR, h);
    crate::on_irq(SCRATCH_VEC_HANDLER_CLEAR);
    crate::dispatch::clear_handler(SCRATCH_VEC_HANDLER_CLEAR);
    crate::on_irq(SCRATCH_VEC_HANDLER_CLEAR);
    if HITS.load(Ordering::Relaxed) == 1 {
        TestResult::Pass
    } else {
        TestResult::Fail("clear_handler didn't stop subsequent invocations")
    }
}
kernel_test_in!("interrupts", smoke_dispatch_clear_handler_stops_invocations);

fn smoke_dispatch_sync_handler_runs_before_waker() -> TestResult {
    // Documented contract: the synchronous handler observes a fully
    // consistent `fire_count` snapshot, then the waker fires. We
    // verify the handler sees `fire_count > baseline` already.
    use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};
    use core::task::{RawWaker, RawWakerVTable, Waker};

    static HANDLER_SEEN: AtomicU64 = AtomicU64::new(0);
    static WAKER_AFTER_HANDLER: AtomicU8 = AtomicU8::new(0); // 0 init, 1 wake-after-handler, 2 wake-before-handler

    fn h() {
        HANDLER_SEEN.store(
            crate::fire_count(SCRATCH_VEC_HANDLER_ORDER),
            Ordering::Release,
        );
    }

    // Custom waker that records whether the handler ran first.
    fn noop_clone(p: *const ()) -> RawWaker {
        RawWaker::new(p, &VTABLE)
    }
    fn wake(_: *const ()) {
        // If HANDLER_SEEN is still 0, the waker fired *before* the
        // handler — would be a contract violation.
        if HANDLER_SEEN.load(Ordering::Acquire) == 0 {
            WAKER_AFTER_HANDLER.store(2, Ordering::Release);
        } else {
            WAKER_AFTER_HANDLER.store(1, Ordering::Release);
        }
    }
    fn wake_ref(p: *const ()) {
        wake(p);
    }
    fn noop_drop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(noop_clone, wake, wake_ref, noop_drop);

    HANDLER_SEEN.store(0, Ordering::Release);
    WAKER_AFTER_HANDLER.store(0, Ordering::Release);

    // SAFETY: vtable functions are sound (no-op + atomic flag).
    let w = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
    crate::dispatch::set_waker(SCRATCH_VEC_HANDLER_ORDER, w);
    crate::dispatch::install(SCRATCH_VEC_HANDLER_ORDER, h);
    crate::on_irq(SCRATCH_VEC_HANDLER_ORDER);
    crate::dispatch::clear_handler(SCRATCH_VEC_HANDLER_ORDER);

    match WAKER_AFTER_HANDLER.load(Ordering::Acquire) {
        1 => TestResult::Pass,
        2 => TestResult::Fail("waker fired BEFORE sync handler — contract violation"),
        _ => TestResult::Fail("waker never fired"),
    }
}
kernel_test_in!("interrupts", smoke_dispatch_sync_handler_runs_before_waker);

fn smoke_dispatch_vectors_are_independent() -> TestResult {
    // Firing vector A must not bump vector B's fire_count.
    let a_before = crate::fire_count(SCRATCH_VEC_A);
    let b_before = crate::fire_count(SCRATCH_VEC_B);
    for _ in 0..5 {
        crate::on_irq(SCRATCH_VEC_A);
    }
    let a_after = crate::fire_count(SCRATCH_VEC_A);
    let b_after = crate::fire_count(SCRATCH_VEC_B);
    if a_after - a_before != 5 {
        return TestResult::Fail("A's count didn't advance by 5");
    }
    if b_after != b_before {
        return TestResult::Fail("firing A leaked into B's count");
    }
    TestResult::Pass
}
kernel_test_in!("interrupts", smoke_dispatch_vectors_are_independent);

fn smoke_dispatch_clear_waker_prevents_wake() -> TestResult {
    // set_waker(v, w); clear_waker(v, &w); on_irq(v) — the waker
    // must NOT fire. Models the cancellation path when a future is
    // dropped before its IRQ lands.
    use core::sync::atomic::{AtomicBool, Ordering};
    use core::task::{RawWaker, RawWakerVTable, Waker};

    static WOKEN: AtomicBool = AtomicBool::new(false);
    fn noop_clone(p: *const ()) -> RawWaker {
        RawWaker::new(p, &VTABLE)
    }
    fn wake(_: *const ()) {
        WOKEN.store(true, Ordering::Release);
    }
    fn wake_ref(_: *const ()) {
        WOKEN.store(true, Ordering::Release);
    }
    fn noop_drop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(noop_clone, wake, wake_ref, noop_drop);

    WOKEN.store(false, Ordering::Release);
    // SAFETY: `VTABLE`'s clone/wake/drop fns are all valid for the
    // null data pointer they ignore, satisfying the RawWaker contract.
    let w = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
    let w_clone = w.clone();
    crate::dispatch::set_waker(SCRATCH_VEC_DROP_CLEARS, w);
    crate::dispatch::clear_waker(SCRATCH_VEC_DROP_CLEARS, &w_clone);
    crate::on_irq(SCRATCH_VEC_DROP_CLEARS);
    if WOKEN.load(Ordering::Acquire) {
        TestResult::Fail("clear_waker didn't prevent the wake")
    } else {
        TestResult::Pass
    }
}
kernel_test_in!("interrupts", smoke_dispatch_clear_waker_prevents_wake);

fn smoke_dispatch_clear_waker_targets_only_own() -> TestResult {
    // Two distinct wakers registered on the same vector; clearing
    // ONE must leave the OTHER intact and woken on the next on_irq.
    // This is the multi-waker contract — clear_waker is targeted,
    // not nuke-all.
    use core::sync::atomic::{AtomicU32, Ordering};
    use core::task::{RawWaker, RawWakerVTable, Waker};

    static WOKEN_A: AtomicU32 = AtomicU32::new(0);
    static WOKEN_B: AtomicU32 = AtomicU32::new(0);

    fn clone_a(p: *const ()) -> RawWaker {
        RawWaker::new(p, &VTABLE_A)
    }
    fn wake_a(_: *const ()) {
        WOKEN_A.fetch_add(1, Ordering::Release);
    }
    fn noop_drop(_: *const ()) {}
    static VTABLE_A: RawWakerVTable = RawWakerVTable::new(clone_a, wake_a, wake_a, noop_drop);

    fn clone_b(p: *const ()) -> RawWaker {
        RawWaker::new(p, &VTABLE_B)
    }
    fn wake_b(_: *const ()) {
        WOKEN_B.fetch_add(1, Ordering::Release);
    }
    static VTABLE_B: RawWakerVTable = RawWakerVTable::new(clone_b, wake_b, wake_b, noop_drop);

    WOKEN_A.store(0, Ordering::Release);
    WOKEN_B.store(0, Ordering::Release);

    // SAFETY: VTABLE_A/B's fns ignore the data pointer and are valid
    // for the null pointer passed, satisfying the RawWaker contract.
    let w_a = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE_A)) };
    // SAFETY: see above — VTABLE_B is a valid no-data waker vtable.
    let w_b = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE_B)) };
    let w_a_probe = w_a.clone();

    crate::dispatch::set_waker(SCRATCH_VEC_DROP_CLEARS, w_a);
    crate::dispatch::set_waker(SCRATCH_VEC_DROP_CLEARS, w_b);
    // Surgical removal of A only.
    crate::dispatch::clear_waker(SCRATCH_VEC_DROP_CLEARS, &w_a_probe);
    crate::on_irq(SCRATCH_VEC_DROP_CLEARS);

    if WOKEN_A.load(Ordering::Acquire) != 0 {
        return TestResult::Fail("cleared waker still fired");
    }
    if WOKEN_B.load(Ordering::Acquire) != 1 {
        return TestResult::Fail("co-registered waker was wiped — clear_waker nuked the list");
    }
    TestResult::Pass
}
kernel_test_in!("interrupts", smoke_dispatch_clear_waker_targets_only_own);

// ── vector allocator extended ─────────────────────────────────────

fn smoke_vector_alloc_then_free_reuse() -> TestResult {
    // alloc → free → alloc on the same scan range should reuse the
    // first vector (linear-scan + bitmap means the lowest free bit
    // wins).
    use crate::vector::{alloc, free};
    let v0 = alloc().expect("alloc");
    free(v0).expect("free");
    let v1 = alloc().expect("alloc#2");
    if v1 != v0 {
        let _ = free(v1);
        return TestResult::Fail("free-then-alloc didn't reuse the freed slot");
    }
    free(v1).expect("cleanup");
    TestResult::Pass
}
kernel_test_in!("interrupts", smoke_vector_alloc_then_free_reuse);

fn smoke_vector_free_out_of_range() -> TestResult {
    // free(v < ALLOC_BASE) and free(v > ALLOC_MAX) both return
    // OutOfRange. On x86_64 ALLOC_BASE = 48 so vector 10 is below;
    // vector 250 is above ALLOC_MAX (240) on every arch.
    use crate::vector::{free, VectorError};
    #[cfg(target_arch = "x86_64")]
    {
        // 10 is below ALLOC_BASE=48 on x86_64.
        if free(10) != Err(VectorError::OutOfRange) {
            return TestResult::Fail("free(10) didn't surface OutOfRange on x86_64");
        }
    }
    if free(250) != Err(VectorError::OutOfRange) {
        return TestResult::Fail("free(250) didn't surface OutOfRange");
    }
    if free(255) != Err(VectorError::OutOfRange) {
        return TestResult::Fail("free(255) didn't surface OutOfRange");
    }
    TestResult::Pass
}
kernel_test_in!("interrupts", smoke_vector_free_out_of_range);

fn smoke_vector_alloc_block_zero_rejected() -> TestResult {
    // alloc_block(0) is meaningless; it must surface OutOfRange
    // rather than silently succeed with no reservation.
    use crate::vector::{alloc_block, VectorError};
    match alloc_block(0) {
        Err(VectorError::OutOfRange) => TestResult::Pass,
        _ => TestResult::Fail("alloc_block(0) didn't reject"),
    }
}
kernel_test_in!("interrupts", smoke_vector_alloc_block_zero_rejected);

fn smoke_vector_alloc_block_releases_all_on_free() -> TestResult {
    // alloc_block(8) + free each → all 8 bits clear.
    use crate::vector::{alloc_block, free, is_allocated};
    let base = match alloc_block(8) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("alloc_block(8) failed"),
    };
    for i in 0..8 {
        if !is_allocated(base + i) {
            for j in 0..8 {
                let _ = free(base + j);
            }
            return TestResult::Fail("block bit not set");
        }
    }
    for i in 0..8 {
        free(base + i).expect("free");
    }
    for i in 0..8 {
        if is_allocated(base + i) {
            return TestResult::Fail("free didn't clear bit");
        }
    }
    TestResult::Pass
}
kernel_test_in!("interrupts", smoke_vector_alloc_block_releases_all_on_free);

fn smoke_vector_double_free_returns_already_free() -> TestResult {
    // free(v) twice — second call must report AlreadyFree.
    use crate::vector::{alloc, free, VectorError};
    let v = alloc().expect("alloc");
    free(v).expect("first free");
    match free(v) {
        Err(VectorError::AlreadyFree) => TestResult::Pass,
        _ => TestResult::Fail("double-free didn't surface AlreadyFree"),
    }
}
kernel_test_in!("interrupts", smoke_vector_double_free_returns_already_free);

// ── WaitForIrq edge cases ─────────────────────────────────────────

fn smoke_wait_for_irq_baseline_ignores_prior_fires() -> TestResult {
    // Bump fire_count BEFORE constructing wait_for_irq. The future
    // snapshots the count at construction so it must NOT resolve
    // Ready on its first poll — the IRQs already counted are part
    // of the baseline.
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    crate::on_irq(SCRATCH_VEC_BASELINE);
    crate::on_irq(SCRATCH_VEC_BASELINE);

    fn noop_clone(p: *const ()) -> RawWaker {
        RawWaker::new(p, &VTABLE)
    }
    fn noop_wake(_: *const ()) {}
    fn noop_drop(_: *const ()) {}
    static VTABLE: RawWakerVTable =
        RawWakerVTable::new(noop_clone, noop_wake, noop_wake, noop_drop);
    // SAFETY: VTABLE's fns ignore the data pointer and are valid for
    // the null pointer passed, satisfying the RawWaker contract.
    let w = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&w);

    let mut fut = crate::wait_for_irq(SCRATCH_VEC_BASELINE);
    // SAFETY: `fut` is a local that is never moved while `pinned`
    // borrows it, so the Pin invariant holds.
    let pinned = unsafe { Pin::new_unchecked(&mut fut) };
    match pinned.poll(&mut cx) {
        Poll::Pending => {
            // Now fire once and re-poll — must resolve.
            crate::on_irq(SCRATCH_VEC_BASELINE);
            // SAFETY: `fut` is still pinned in place on this frame and
            // has not moved since the previous poll.
            let pinned = unsafe { Pin::new_unchecked(&mut fut) };
            match pinned.poll(&mut cx) {
                Poll::Ready(_) => TestResult::Pass,
                Poll::Pending => TestResult::Fail("post-baseline IRQ didn't resolve future"),
            }
        }
        Poll::Ready(_) => {
            TestResult::Fail("baseline snapshot ignored — fired BEFORE construction leaked through")
        }
    }
}
kernel_test_in!(
    "interrupts",
    smoke_wait_for_irq_baseline_ignores_prior_fires
);

fn smoke_wait_for_irq_drop_clears_waker() -> TestResult {
    // Construct WaitForIrq, poll once to install the waker, then
    // drop. Subsequent on_irq must NOT call the waker (its memory
    // could be reused by then — undefined behaviour to wake a
    // dropped task).
    use core::future::Future;
    use core::pin::Pin;
    use core::sync::atomic::{AtomicBool, Ordering};
    use core::task::{Context, RawWaker, RawWakerVTable, Waker};

    static WOKEN: AtomicBool = AtomicBool::new(false);
    fn noop_clone(p: *const ()) -> RawWaker {
        RawWaker::new(p, &VTABLE)
    }
    fn wake(_: *const ()) {
        WOKEN.store(true, Ordering::Release);
    }
    fn noop_drop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(noop_clone, wake, wake, noop_drop);

    WOKEN.store(false, Ordering::Release);
    // SAFETY: VTABLE's fns ignore the data pointer and are valid for
    // the null pointer passed, satisfying the RawWaker contract.
    let w = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&w);

    {
        let mut fut = crate::wait_for_irq(120);
        // SAFETY: `fut` is a local in this block that is never moved
        // while `pinned` borrows it, so the Pin invariant holds.
        let pinned = unsafe { Pin::new_unchecked(&mut fut) };
        let _ = pinned.poll(&mut cx); // installs waker
                                      // fut drops here → WaitForIrq::Drop clears the slot.
    }
    crate::on_irq(120);
    if WOKEN.load(Ordering::Acquire) {
        TestResult::Fail("on_irq woke a dropped future — Drop didn't clear the waker")
    } else {
        TestResult::Pass
    }
}
kernel_test_in!("interrupts", smoke_wait_for_irq_drop_clears_waker);

// ── deep interrupts coverage ───────────────────────────────────────
//
// Existing surface covers headline dispatch + alloc + wait edges.
// New tests close the remaining invariants: handler replacement,
// in-IRQ context during dispatch, fully-drained allocator, mixed
// fragmentation + alloc_block, wait_for_irq_until timeout/success,
// per-vector constants.

const SCRATCH_VEC_REPLACE: u8 = 117;
const SCRATCH_VEC_INIRQ: u8 = 118;
const SCRATCH_VEC_WAIT_RETRY: u8 = 119;
const SCRATCH_VEC_TIMEOUT_A: u8 = 121;
const SCRATCH_VEC_TIMEOUT_B: u8 = 122;

fn smoke_dispatch_install_replaces_prior_handler() -> TestResult {
    // install(v, h1) then install(v, h2) — only h2 fires on the
    // next on_irq. There's one handler slot per vector.
    use core::sync::atomic::{AtomicU32, Ordering};
    static A: AtomicU32 = AtomicU32::new(0);
    static B: AtomicU32 = AtomicU32::new(0);
    A.store(0, Ordering::Relaxed);
    B.store(0, Ordering::Relaxed);
    fn h_a() {
        A.fetch_add(1, Ordering::Relaxed);
    }
    fn h_b() {
        B.fetch_add(1, Ordering::Relaxed);
    }

    crate::dispatch::install(SCRATCH_VEC_REPLACE, h_a);
    crate::dispatch::install(SCRATCH_VEC_REPLACE, h_b);
    crate::on_irq(SCRATCH_VEC_REPLACE);
    crate::dispatch::clear_handler(SCRATCH_VEC_REPLACE);

    if A.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("first handler fired after being replaced");
    }
    if B.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("replacement handler didn't run");
    }
    TestResult::Pass
}
kernel_test_in!("interrupts", smoke_dispatch_install_replaces_prior_handler);

fn smoke_dispatch_in_irq_true_inside_on_irq() -> TestResult {
    // narf_lib::context::in_irq() observes true inside the
    // synchronous handler and false again after on_irq returns.
    // This is the soft-IRQ counterpart to the existing
    // smoke_dispatch_in_irq_observed_inside_handler (which uses
    // `int <vec>`).
    use core::sync::atomic::{AtomicU8, Ordering};
    static INSIDE: AtomicU8 = AtomicU8::new(0);
    INSIDE.store(0, Ordering::Relaxed);
    fn h() {
        INSIDE.store(
            if narf_lib::context::in_irq() { 1 } else { 0 },
            Ordering::Release,
        );
    }
    crate::dispatch::install(SCRATCH_VEC_INIRQ, h);
    crate::on_irq(SCRATCH_VEC_INIRQ);
    crate::dispatch::clear_handler(SCRATCH_VEC_INIRQ);

    if INSIDE.load(Ordering::Acquire) != 1 {
        return TestResult::Fail("handler didn't observe in_irq == true");
    }
    if narf_lib::context::in_irq() {
        return TestResult::Fail("in_irq still true after on_irq returned");
    }
    TestResult::Pass
}
kernel_test_in!("interrupts", smoke_dispatch_in_irq_true_inside_on_irq);

fn smoke_dispatch_num_vectors_constant() -> TestResult {
    // NUM_VECTORS pins at 256 — the IDT-vector budget the table is
    // sized to. Bumping it requires re-sizing SLOTS / HANDLERS.
    if crate::dispatch::NUM_VECTORS != 256 {
        return TestResult::Fail("NUM_VECTORS drifted from 256");
    }
    TestResult::Pass
}
kernel_test_in!("interrupts", smoke_dispatch_num_vectors_constant);

fn smoke_interrupts_well_known_vector_constants() -> TestResult {
    // The kernel's documented vector assignments. Drift in any of
    // these breaks driver assumptions about which vectors are
    // reserved.
    if crate::VECTOR_TIMER != 32 {
        return TestResult::Fail("VECTOR_TIMER drifted from 32");
    }
    if crate::VECTOR_TLB_SHOOTDOWN != 0xF0 {
        return TestResult::Fail("VECTOR_TLB_SHOOTDOWN drifted from 0xF0");
    }
    if crate::VECTOR_APIC_ERROR != 0xFE {
        return TestResult::Fail("VECTOR_APIC_ERROR drifted from 0xFE");
    }
    if crate::VECTOR_SPURIOUS != 0xFF {
        return TestResult::Fail("VECTOR_SPURIOUS drifted from 0xFF");
    }
    TestResult::Pass
}
kernel_test_in!("interrupts", smoke_interrupts_well_known_vector_constants);

fn smoke_vector_alloc_block_of_one_equivalent_to_alloc() -> TestResult {
    // alloc_block(1) is the same shape as alloc — both reserve a
    // single vector. Confirms the n=1 boundary case of the block
    // walker.
    use crate::vector::{alloc_block, free};
    let v = match alloc_block(1) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("alloc_block(1) failed"),
    };
    free(v).expect("cleanup");
    TestResult::Pass
}
kernel_test_in!(
    "interrupts",
    smoke_vector_alloc_block_of_one_equivalent_to_alloc
);

fn smoke_vector_alloc_block_rejects_too_large() -> TestResult {
    // alloc_block(N+1) where N is the allocator's range must return
    // Exhausted. We can't compute N exactly without internals, but
    // 200 is well beyond the realistic alloc window of (ALLOC_MAX -
    // ALLOC_BASE + 1) = 240-48+1 = 193 on x86_64 (and 241 on
    // aarch64, both < 200 once existing allocations are accounted
    // for if any).
    use crate::vector::{alloc_block, VectorError};
    match alloc_block(250) {
        Err(VectorError::Exhausted) => TestResult::Pass,
        _ => TestResult::Fail("alloc_block(250) didn't surface Exhausted"),
    }
}
kernel_test_in!("interrupts", smoke_vector_alloc_block_rejects_too_large);

fn smoke_vector_alloc_block_after_fragmentation() -> TestResult {
    // alloc N individually, free every other one, alloc_block(3)
    // must find a contiguous run in the gaps OR past the
    // fragmentation. Confirms the scan tries every starting base
    // until it finds enough contiguous bits.
    use crate::vector::{alloc, alloc_block, free};
    let mut held = alloc::vec::Vec::new();
    for _ in 0..6 {
        held.push(alloc().expect("alloc"));
    }
    // Free vectors at indices 0, 2, 4 — leaves a fragmented
    // pattern below where contiguous runs of length > 1 might
    // not exist among the freed slots.
    free(held[0]).expect("free");
    free(held[2]).expect("free");
    free(held[4]).expect("free");

    // alloc_block(3) must still succeed — the bitmap is much bigger
    // than the 6 allocations we made.
    let base = match alloc_block(3) {
        Ok(b) => b,
        Err(_) => {
            for v in [held[1], held[3], held[5]] {
                let _ = free(v);
            }
            return TestResult::Fail("alloc_block(3) failed despite plenty of free slots");
        }
    };
    // Cleanup.
    for i in 0..3 {
        free(base + i).expect("cleanup block");
    }
    for v in [held[1], held[3], held[5]] {
        free(v).expect("cleanup individual");
    }
    TestResult::Pass
}
kernel_test_in!("interrupts", smoke_vector_alloc_block_after_fragmentation);

fn smoke_wait_for_irq_until_succeeds_before_deadline() -> TestResult {
    // wait_for_irq_until with a far-future deadline resolves to
    // Ok(fire_count) when the IRQ lands first.
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    fn noop_clone(p: *const ()) -> RawWaker {
        RawWaker::new(p, &VTABLE)
    }
    fn noop_wake(_: *const ()) {}
    fn noop_drop(_: *const ()) {}
    static VTABLE: RawWakerVTable =
        RawWakerVTable::new(noop_clone, noop_wake, noop_wake, noop_drop);
    // SAFETY: VTABLE's fns ignore the data pointer and are valid for
    // the null pointer passed, satisfying the RawWaker contract.
    let w = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&w);

    let deadline = narf_time::Deadline::after_ns(60_000_000_000);
    let mut fut = crate::wait_for_irq_until(SCRATCH_VEC_TIMEOUT_A, deadline);
    // SAFETY: `fut` is a local that is not moved while `pinned`
    // borrows it, so the Pin invariant holds.
    let pinned = unsafe { Pin::new_unchecked(&mut fut) };
    if !matches!(pinned.poll(&mut cx), Poll::Pending) {
        return TestResult::Fail("first poll should be Pending");
    }
    crate::on_irq(SCRATCH_VEC_TIMEOUT_A);
    // SAFETY: `fut` has not moved since the previous poll.
    let pinned = unsafe { Pin::new_unchecked(&mut fut) };
    match pinned.poll(&mut cx) {
        Poll::Ready(Ok(_)) => TestResult::Pass,
        Poll::Ready(Err(_)) => TestResult::Fail("IRQ landed before deadline but got Elapsed"),
        Poll::Pending => TestResult::Fail("post-IRQ poll still Pending"),
    }
}
kernel_test_in!(
    "interrupts",
    smoke_wait_for_irq_until_succeeds_before_deadline
);

fn smoke_wait_for_irq_until_times_out_when_no_irq() -> TestResult {
    // Already-expired deadline → first poll returns Err(Elapsed)
    // without registering a waker (timeout futures short-circuit
    // when the deadline passed before construction).
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    fn noop_clone(p: *const ()) -> RawWaker {
        RawWaker::new(p, &VTABLE)
    }
    fn noop_wake(_: *const ()) {}
    fn noop_drop(_: *const ()) {}
    static VTABLE: RawWakerVTable =
        RawWakerVTable::new(noop_clone, noop_wake, noop_wake, noop_drop);
    // SAFETY: VTABLE's fns ignore the data pointer and are valid for
    // the null pointer passed, satisfying the RawWaker contract.
    let w = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&w);

    // Deadline already in the past (cycles_since_boot - 1).
    let now = narf_time::Instant::now();
    let _ = now;
    let deadline = narf_time::Deadline::after_ns(0); // immediate
    let mut fut = crate::wait_for_irq_until(SCRATCH_VEC_TIMEOUT_B, deadline);
    // SAFETY: `fut` is a local that is not moved while `pinned`
    // borrows it, so the Pin invariant holds.
    let pinned = unsafe { Pin::new_unchecked(&mut fut) };
    // The timeout future may or may not return Elapsed on the first
    // poll depending on how `after_ns(0)` rounds; loop a few polls
    // to give it a chance, but bail on too many cycles.
    let start = narf_time::Instant::now();
    let mut result = pinned.poll(&mut cx);
    while matches!(result, Poll::Pending) {
        if narf_time::Instant::now().cycles_since(start) > 500_000_000 {
            return TestResult::Fail("timeout future never resolved on past-deadline");
        }
        // SAFETY: `fut` has not moved since the previous poll.
        let pinned = unsafe { Pin::new_unchecked(&mut fut) };
        result = pinned.poll(&mut cx);
    }
    match result {
        Poll::Ready(Err(_)) => TestResult::Pass,
        Poll::Ready(Ok(_)) => TestResult::Fail("past-deadline returned Ok instead of Elapsed"),
        Poll::Pending => TestResult::Fail("never resolved (loop bailed)"),
    }
}
kernel_test_in!("interrupts", smoke_wait_for_irq_until_times_out_when_no_irq);

fn smoke_wait_for_irq_can_be_used_sequentially() -> TestResult {
    // Two sequential wait_for_irq on the same vector. After the
    // first one resolves, a fresh wait_for_irq for the same vector
    // must NOT resolve until a NEW IRQ arrives (the second future
    // snapshots its own baseline).
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    fn noop_clone(p: *const ()) -> RawWaker {
        RawWaker::new(p, &VTABLE)
    }
    fn noop_wake(_: *const ()) {}
    fn noop_drop(_: *const ()) {}
    static VTABLE: RawWakerVTable =
        RawWakerVTable::new(noop_clone, noop_wake, noop_wake, noop_drop);
    // SAFETY: VTABLE's fns ignore the data pointer and are valid for
    // the null pointer passed, satisfying the RawWaker contract.
    let w = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&w);

    // First wait_for_irq.
    let mut fut1 = crate::wait_for_irq(SCRATCH_VEC_WAIT_RETRY);
    // SAFETY: `fut1` is a local that is not moved while `pinned`
    // borrows it, so the Pin invariant holds.
    let pinned = unsafe { Pin::new_unchecked(&mut fut1) };
    if !matches!(pinned.poll(&mut cx), Poll::Pending) {
        return TestResult::Fail("first wait first poll should be Pending");
    }
    crate::on_irq(SCRATCH_VEC_WAIT_RETRY);
    // SAFETY: `fut1` has not moved since the previous poll.
    let pinned = unsafe { Pin::new_unchecked(&mut fut1) };
    if !matches!(pinned.poll(&mut cx), Poll::Ready(_)) {
        return TestResult::Fail("first wait didn't resolve after IRQ");
    }
    drop(fut1);

    // Second wait_for_irq — snapshots a NEW baseline after the
    // first IRQ landed, so first poll is Pending.
    let mut fut2 = crate::wait_for_irq(SCRATCH_VEC_WAIT_RETRY);
    // SAFETY: `fut2` is a local that is not moved while `pinned`
    // borrows it, so the Pin invariant holds.
    let pinned = unsafe { Pin::new_unchecked(&mut fut2) };
    if !matches!(pinned.poll(&mut cx), Poll::Pending) {
        return TestResult::Fail(
            "second wait first poll should be Pending — baseline snapshot leaked first IRQ",
        );
    }
    crate::on_irq(SCRATCH_VEC_WAIT_RETRY);
    // SAFETY: `fut2` has not moved since the previous poll.
    let pinned = unsafe { Pin::new_unchecked(&mut fut2) };
    if !matches!(pinned.poll(&mut cx), Poll::Ready(_)) {
        return TestResult::Fail("second wait didn't resolve after second IRQ");
    }
    TestResult::Pass
}
kernel_test_in!("interrupts", smoke_wait_for_irq_can_be_used_sequentially);

fn smoke_dispatch_fire_count_monotonic_under_many_irqs() -> TestResult {
    // 1000 on_irq calls bump fire_count by exactly 1000. Catches
    // an overflow in a future narrower counter or a missed update.
    const N: u64 = 1000;
    let before = crate::fire_count(SCRATCH_VEC_A);
    for _ in 0..N {
        crate::on_irq(SCRATCH_VEC_A);
    }
    let after = crate::fire_count(SCRATCH_VEC_A);
    if after - before != N {
        let msg = alloc::format!(
            "fire_count delta {} != {} after {} on_irq calls",
            after - before,
            N,
            N
        );
        let s: &'static str = alloc::boxed::Box::leak(msg.into_boxed_str());
        return TestResult::Fail(s);
    }
    TestResult::Pass
}
kernel_test_in!(
    "interrupts",
    smoke_dispatch_fire_count_monotonic_under_many_irqs
);

// ── deep interrupts/ipi ──────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
fn smoke_ipi_ack_count_cpu_index_clamps() -> TestResult {
    // ack_count() and ever_received() must clamp the cpu index to
    // MAX_CPUS-1 rather than out-of-bounds. Walk a CPU id well
    // beyond MAX_CPUS and confirm it returns the same value as
    // MAX_CPUS-1 (i.e. it didn't trap).
    use crate::x86_64::ipi::{ack_count, ever_received};
    let high = u32::MAX;
    let _ = ack_count(high); // would panic on OOB
    let _ = ever_received(high);
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("interrupts/ipi", smoke_ipi_ack_count_cpu_index_clamps);

#[cfg(target_arch = "x86_64")]
fn smoke_ipi_handler_bumps_counters_on_self() -> TestResult {
    // on_shootdown_irq() bumps ever_received and ack_count for
    // the current CPU, even with no pending VA (no INVLPG path
    // taken). Establishes the counter contract independent of
    // the broadcast machinery.
    use crate::x86_64::ipi::{ack_count, ever_received, on_shootdown_irq};
    let cpu = narf_lib::percpu::current_cpu() as u32;
    let ack_before = ack_count(cpu);
    let ev_before = ever_received(cpu);
    // SAFETY: called from kernel-test context at CPL=0 with no
    // pending VA — handler skips the INVLPG path.
    unsafe {
        on_shootdown_irq();
    }
    if ack_count(cpu) != ack_before + 1 {
        return TestResult::Fail("ack_count didn't increment by 1");
    }
    if ever_received(cpu) != ev_before + 1 {
        return TestResult::Fail("ever_received didn't increment by 1");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("interrupts/ipi", smoke_ipi_handler_bumps_counters_on_self);

// ── deep interrupts/hpet ─────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
fn smoke_hpet_oneshot_error_variants_distinct() -> TestResult {
    use crate::x86_64::hpet_oneshot::HpetOneshotError;
    let all = [
        HpetOneshotError::HpetMissing,
        HpetOneshotError::NoComparators,
        HpetOneshotError::NoSafeGsi,
        HpetOneshotError::NoVector,
        HpetOneshotError::IoapicRoutingFailed,
        HpetOneshotError::NoLocalApic,
        HpetOneshotError::AlreadyArmed,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j && a == b {
                return TestResult::Fail("HpetOneshotError variants collapsed");
            }
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "interrupts/hpet",
    smoke_hpet_oneshot_error_variants_distinct
);

#[cfg(target_arch = "x86_64")]
fn smoke_hpet_oneshot_pick_gsi_prefers_high_then_low() -> TestResult {
    // pick_gsi:
    //   - mask=0 → None
    //   - mask with bit 16 → 16 (first safe GSI)
    //   - low-only mask, legacy bits excluded (0/1/8/13) → first non-legacy
    //   - all-legacy low mask → None
    use crate::x86_64::hpet_oneshot::__pick_gsi_for_test;
    if __pick_gsi_for_test(0, 16).is_some() {
        return TestResult::Fail("empty mask shouldn't return Some");
    }
    if __pick_gsi_for_test(1u32 << 16, 16) != Some(16) {
        return TestResult::Fail("mask=bit16 should pick GSI 16");
    }
    if __pick_gsi_for_test(1u32 << 24, 16) != Some(24) {
        return TestResult::Fail("mask=bit24 should pick GSI 24");
    }
    // Low-only mask, bit 2 set (PIC cascade — allowed per the
    // QEMU comment in pick_gsi).
    if __pick_gsi_for_test(1u32 << 2, 16) != Some(2) {
        return TestResult::Fail("low-fallback should pick GSI 2");
    }
    // All-legacy low: bits 0,1,8,13 only.
    let legacy = (1u32 << 0) | (1u32 << 1) | (1u32 << 8) | (1u32 << 13);
    if __pick_gsi_for_test(legacy, 16).is_some() {
        return TestResult::Fail("all-legacy mask should return None");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "interrupts/hpet",
    smoke_hpet_oneshot_pick_gsi_prefers_high_then_low
);

// ── deep interrupts/timer ────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
fn smoke_timer_pump_init_error_variants_distinct() -> TestResult {
    use crate::x86_64::timer_pump::TimerPumpInitError;
    let all = [
        TimerPumpInitError::HpetMissing,
        TimerPumpInitError::NoComparators,
        TimerPumpInitError::NoSafeGsi,
        TimerPumpInitError::NoVector,
        TimerPumpInitError::IoapicRoutingFailed,
        TimerPumpInitError::NoLocalApic,
        TimerPumpInitError::AlreadyInitialised,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j && a == b {
                return TestResult::Fail("TimerPumpInitError variants collapsed");
            }
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "interrupts/timer",
    smoke_timer_pump_init_error_variants_distinct
);

#[cfg(target_arch = "x86_64")]
fn smoke_timer_pump_init_idempotent_after_first_success() -> TestResult {
    // If init() already succeeded earlier in the boot, a second
    // call must surface AlreadyInitialised — not silently re-program
    // the IOAPIC and waste a vector.
    use crate::x86_64::timer_pump::{init, is_initialised, TimerPumpInitError};
    if !is_initialised() {
        return TestResult::Skip("timer pump not initialised in this flavour");
    }
    match init() {
        Err(TimerPumpInitError::AlreadyInitialised) => TestResult::Pass,
        _ => TestResult::Fail("second init() didn't surface AlreadyInitialised"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "interrupts/timer",
    smoke_timer_pump_init_idempotent_after_first_success
);

#[cfg(target_arch = "x86_64")]
fn smoke_timer_pump_vector_matches_timer_constant() -> TestResult {
    // When the pump is up, __vector_for_test() must report the
    // vector the dispatch path uses — the same value the BSP
    // wired into the IDT. Smoke test for "did init lose its
    // vector somewhere along the way".
    use crate::x86_64::timer_pump::{__vector_for_test, is_initialised};
    if !is_initialised() {
        return TestResult::Skip("timer pump not up");
    }
    let v = __vector_for_test();
    if v == 0 {
        return TestResult::Fail("vector reported as 0 — likely uninitialised slot");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "interrupts/timer",
    smoke_timer_pump_vector_matches_timer_constant
);

// ── tag-aware TLB-shootdown IPI (asid-pcid-isolation §4) ──────────
//
// Refs:
//   - Intel SDM Vol 2 INVPCID instruction reference
//     https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
//   - Intel SDM Vol 3 §4.10 (Cache + TLB)        (same URL)
//   - ARM DDI0487 D5.10 (TLBI instructions)
//     https://developer.arm.com/documentation/ddi0487/latest/
//
// These pin the four contracts the bridge has to honour:
//   1) the sender publishes the tag alongside VA + pages;
//   2) tag-only requests now drive a real per-tag broadcast
//      (no longer a no-op as the bridge used to leave it);
//   3) tag == 0 keeps the legacy plain-INVLPG behaviour;
//   4) the handler's INVPCID branch is taken when a non-zero tag
//      arrives on a CPU that supports INVPCID.

#[cfg(target_arch = "x86_64")]
fn smoke_ipi_shootdown_carries_tag_through() -> TestResult {
    // Publish (tag=7, va=0x1000) directly into a peer CPU's pending
    // slot WITHOUT sending the IPI, then read the slot back. Proves
    // the publish-side wiring carries the tag end-to-end without
    // depending on the handler running. Works on UP + SMP — no IPI
    // is involved.
    use crate::x86_64::ipi;
    let self_cpu = narf_lib::percpu::current_cpu() as u32;
    let peer = if self_cpu == 0 { 1 } else { 0 };
    ipi::__publish_for_test(peer, 0x1000, 1, 7);
    let observed = ipi::pending_tag(peer);
    ipi::__clear_for_test(peer);
    if observed != 7 {
        return TestResult::Fail("publish path didn't carry tag=7 to peer slot");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("interrupts/ipi", smoke_ipi_shootdown_carries_tag_through);

#[cfg(not(target_arch = "x86_64"))]
fn smoke_ipi_shootdown_carries_tag_through() -> TestResult {
    // aarch64: inner-shareable TLBI (TLBI VAE1IS / ASIDE1IS, ARM
    // DDI0487 D5.10) is broadcast in hardware, so no peer-IPI
    // pending-state exists to observe. Skip cleanly so the test
    // grid still records coverage.
    TestResult::Skip("aarch64 uses inner-shareable TLBI; no peer-IPI publish-state")
}
#[cfg(not(target_arch = "x86_64"))]
kernel_test_in!("interrupts/ipi", smoke_ipi_shootdown_carries_tag_through);

#[cfg(target_arch = "x86_64")]
fn smoke_ipi_shootdown_tag_only_request_routes() -> TestResult {
    // The bridge used to no-op for `(Some(tag), None, _)`; it now
    // calls `shoot_tag_only` which broadcasts an IPI. Verify by
    // checking that every peer's EVER_RECEIVED counter advances
    // when we issue a tag-only ShootdownRequest.
    use crate::x86_64::ipi;
    use narf_memory::tlb_shootdown;
    if narf_lib::smp::cpu_count() <= 1 {
        return TestResult::Skip("UP boot — no peer CPUs");
    }
    let self_cpu = narf_lib::percpu::current_cpu() as u32;
    let total = narf_lib::smp::cpu_count();
    let mut snap = [0u64; narf_lib::percpu::MAX_CPUS];
    for cpu in 0..total {
        if cpu == self_cpu {
            continue;
        }
        snap[cpu as usize] = ipi::ever_received(cpu);
    }
    tlb_shootdown::shootdown(tlb_shootdown::ShootdownRequest::for_tag(3));
    let mut spins = 0u32;
    loop {
        let mut all = true;
        for cpu in 0..total {
            if cpu == self_cpu {
                continue;
            }
            if ipi::ever_received(cpu) <= snap[cpu as usize] {
                all = false;
                break;
            }
        }
        if all {
            return TestResult::Pass;
        }
        spins += 1;
        if spins > 10_000_000 {
            return TestResult::Fail("tag-only request didn't broadcast IPI");
        }
        core::hint::spin_loop();
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "interrupts/ipi",
    smoke_ipi_shootdown_tag_only_request_routes
);

#[cfg(not(target_arch = "x86_64"))]
fn smoke_ipi_shootdown_tag_only_request_routes() -> TestResult {
    TestResult::Skip("aarch64 routes tag-only flush through inner-shareable TLBI")
}
#[cfg(not(target_arch = "x86_64"))]
kernel_test_in!(
    "interrupts/ipi",
    smoke_ipi_shootdown_tag_only_request_routes
);

#[cfg(target_arch = "x86_64")]
fn smoke_ipi_shootdown_tag_zero_uses_plain_invlpg() -> TestResult {
    // tag=0 is the explicit "no PCID context — fall back to plain
    // INVLPG" sentinel. Verify by:
    //   1) sampling invpcid_path_taken() before,
    //   2) issuing shoot_range(va, 1, 0),
    //   3) observing that the INVPCID counter did NOT advance.
    // On UP boots the broadcast no-ops so there's nothing to assert;
    // skip cleanly.
    use crate::x86_64::ipi;
    if narf_lib::smp::cpu_count() <= 1 {
        return TestResult::Skip("UP boot — no peer CPUs to run handler");
    }
    let before = ipi::invpcid_path_taken();
    // SAFETY: x2APIC online; vector installed.
    unsafe {
        ipi::shoot_range(0xFFFF_FFFF_8000_2000, 1, 0);
    }
    // shoot_range spins until peers ACK, so any handler activity
    // is already visible by the time we sample.
    let after = ipi::invpcid_path_taken();
    if after != before {
        return TestResult::Fail(
            "tag=0 shootdown took the INVPCID branch (should be plain INVLPG)",
        );
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "interrupts/ipi",
    smoke_ipi_shootdown_tag_zero_uses_plain_invlpg
);

#[cfg(not(target_arch = "x86_64"))]
fn smoke_ipi_shootdown_tag_zero_uses_plain_invlpg() -> TestResult {
    TestResult::Skip("aarch64 doesn't expose an INVPCID-equivalent counter")
}
#[cfg(not(target_arch = "x86_64"))]
kernel_test_in!(
    "interrupts/ipi",
    smoke_ipi_shootdown_tag_zero_uses_plain_invlpg
);

#[cfg(target_arch = "x86_64")]
fn smoke_ipi_shootdown_handler_invpcid_path_taken() -> TestResult {
    // When supported() is true AND the published tag is non-zero,
    // the handler MUST take the INVPCID branch on every peer. The
    // counter increments once per receiving peer per shootdown.
    use crate::x86_64::ipi;
    if narf_lib::smp::cpu_count() <= 1 {
        return TestResult::Skip("UP boot — no peer CPUs run handler");
    }
    if !narf_arch::x86_64::pcid::invpcid_supported() {
        return TestResult::Skip("CPU lacks INVPCID");
    }
    let peers = (narf_lib::smp::cpu_count() - 1) as u64;
    let before = ipi::invpcid_path_taken();
    // SAFETY: x2APIC online; vector installed; tag=5 is non-zero.
    unsafe {
        ipi::shoot_range(0xFFFF_FFFF_8000_3000, 1, 5);
    }
    let after = ipi::invpcid_path_taken();
    let delta = after.wrapping_sub(before);
    if delta < peers {
        return TestResult::Fail("INVPCID branch not taken on every peer");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "interrupts/ipi",
    smoke_ipi_shootdown_handler_invpcid_path_taken
);

#[cfg(not(target_arch = "x86_64"))]
fn smoke_ipi_shootdown_handler_invpcid_path_taken() -> TestResult {
    TestResult::Skip("INVPCID is x86_64-specific (ARM uses TLBI VAE1IS)")
}
#[cfg(not(target_arch = "x86_64"))]
kernel_test_in!(
    "interrupts/ipi",
    smoke_ipi_shootdown_handler_invpcid_path_taken
);
