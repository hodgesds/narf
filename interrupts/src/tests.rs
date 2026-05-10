//! Per-crate smoke tests for `narf-interrupts`.
//!
//! Tests register via `narf_kernel_test::kernel_test_in!` so the
//! runner groups output under `"interrupts"`. Migrated from
//! `narf-verification`'s mega-lib so each subsystem owns its own
//! smokes without cycling on the higher-level harness.

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
    let total = narf_lib::smp::cpu_count() as u32;
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
fn smoke_hpet_pick_gsi_skips_low_block() -> TestResult {
    // pick_gsi(mask, 16) must skip GSIs in the legacy ISA block
    // (0..16) even when `mask` bits there are set.
    use crate::x86_64::hpet_oneshot::__pick_gsi_for_test as pick;
    // Mask = 0..32 all set. With min_gsi=16 we expect GSI 16.
    if pick(0xFFFF_FFFF, 16) != Some(16) {
        return TestResult::Fail("did not skip ISA block");
    }
    // Mask = ISA-only. Expect None.
    if pick(0x0000_FFFF, 16).is_some() {
        return TestResult::Fail("returned a low GSI when only ISA bits set");
    }
    // Mask with a single high bit at GSI 22. Expect 22.
    if pick(1u32 << 22, 16) != Some(22) {
        return TestResult::Fail("did not pick the only high GSI");
    }
    // Empty mask.
    if pick(0, 16).is_some() {
        return TestResult::Fail("returned a GSI for an empty mask");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("interrupts/hpet", smoke_hpet_pick_gsi_skips_low_block);

#[cfg(target_arch = "x86_64")]
fn smoke_hpet_oneshot_fires_handler() -> TestResult {
    // End-to-end: arm a HPET one-shot for ~1 ms in the future, STI,
    // wait for the handler-installed atomic to flip. Skips when HPET
    // wasn't initialised (some test boots run without ACPI parsing).
    use core::sync::atomic::{AtomicBool, Ordering};
    use crate::x86_64::hpet_oneshot;

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

    static POOL: narf_lib::sync::OnceLock<AtomicPool<u64>> =
        narf_lib::sync::OnceLock::new();
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
