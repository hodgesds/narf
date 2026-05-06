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
