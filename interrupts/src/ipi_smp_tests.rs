//! SMP smokes for the reschedule and TLB-shootdown IPIs on real CPUs.
//!
//! Two groups:
//!
//! - `interrupts/ipi_rate`: per-CPU reschedule / shootdown IPI counts on an
//!   idle system, for a burst of cross-CPU wakes, and for timer-driven wakes,
//!   with the bounds Linux holds: at most one IPI per wake of an idle CPU,
//!   none when that CPU polls in idle (`set_nr_if_polling`), and one
//!   shootdown per kernel unmap (`flush_tlb_kernel_range`) rather than one
//!   per page. A polling idle must still wake on an interrupt.
//! - `interrupts/tlb_smp`: a translation changed on one CPU is never used
//!   again by another — a peer running the address space, a peer that ran it
//!   and switched away (deferred flush, then switch back), a peer that idled
//!   in between, a peer reading concurrently with the change, and a kernel
//!   mapping a peer cached under another address space's PCID.
//!
//! Every peer-side step runs in a kernel task pinned to a real AP; the boot
//! CPU drives the phases and waits with a bound, so a regression fails the
//! smoke instead of hanging the run (except where the kernel's own
//! shootdown ack-wait cannot time out by design).

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::percpu::MAX_CPUS;
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};
use narf_scheduler::{Affinity, CpuId, TaskSpec};

use crate::{VECTOR_RESCHED, VECTOR_TLB_SHOOTDOWN};

fn wait_for(ns: u64, mut done: impl FnMut() -> bool) -> bool {
    let deadline = narf_time::now_cycles().saturating_add(narf_time::ns_to_cycles(ns));
    loop {
        if done() {
            return true;
        }
        if narf_time::now_cycles() >= deadline {
            return false;
        }
        core::hint::spin_loop();
    }
}

/// Online CPUs other than this one that really came up.
fn peers() -> Vec<usize> {
    let me = narf_lib::percpu::current_cpu();
    let live = narf_lib::smp::ever_online_bitmap() & narf_lib::smp::online_bitmap();
    (0..MAX_CPUS)
        .filter(|cpu| *cpu != me && live & (1u64 << cpu) != 0)
        .collect()
}

fn pinned(cpu: usize) -> TaskSpec {
    TaskSpec {
        affinity: Affinity::pinned(CpuId(cpu as u32)),
        ..TaskSpec::kernel_any()
    }
}

fn resched_rcvd(cpu: usize) -> u64 {
    crate::dispatch::fire_count_on_cpu(VECTOR_RESCHED, cpu)
}

fn tlb_rcvd(cpu: usize) -> u64 {
    crate::dispatch::fire_count_on_cpu(VECTOR_TLB_SHOOTDOWN, cpu)
}

fn report(line: core::fmt::Arguments<'_>) {
    let _ = writeln!(narf_console::Writer, "  ipi-smp: {line}");
}

// ── A task that parks until woken, on a chosen CPU ──────────────────────

const PROBES: usize = 4;
static PROBE_WAKER: [IrqSafeSpinLock<Option<Waker>>; PROBES] =
    [const { IrqSafeSpinLock::new(None) }; PROBES];
static PROBE_POLLS: [AtomicU64; PROBES] = [const { AtomicU64::new(0) }; PROBES];
static PROBE_STOP: [AtomicBool; PROBES] = [const { AtomicBool::new(false) }; PROBES];

/// Parks, publishing its waker, until told to stop.
struct Probe(usize);

impl Future for Probe {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let slot = self.0;
        PROBE_POLLS[slot].fetch_add(1, Ordering::AcqRel);
        if PROBE_STOP[slot].load(Ordering::Acquire) {
            return Poll::Ready(());
        }
        *PROBE_WAKER[slot].lock() = Some(cx.waker().clone());
        Poll::Pending
    }
}

fn start_probe(slot: usize, cpu: usize) -> bool {
    *PROBE_WAKER[slot].lock() = None;
    PROBE_POLLS[slot].store(0, Ordering::Release);
    PROBE_STOP[slot].store(false, Ordering::Release);
    narf_scheduler::spawn_with_spec(Probe(slot), pinned(cpu));
    wait_for(1_000_000_000, || {
        PROBE_POLLS[slot].load(Ordering::Acquire) >= 1 && PROBE_WAKER[slot].lock().is_some()
    })
}

fn wake_probe(slot: usize) -> bool {
    let waker = PROBE_WAKER[slot].lock().take();
    waker.map(Waker::wake).is_some()
}

fn stop_probe(slot: usize) {
    PROBE_STOP[slot].store(true, Ordering::Release);
    let _ = wake_probe(slot);
    let _ = wait_for(1_000_000_000, || PROBE_WAKER[slot].lock().is_none());
}

/// Wait until `cpu` sits in its executor idle (and, if `polling`, in a
/// polling state), so the next wake meets a sleeping CPU.
fn settle_idle(cpu: usize, polling: bool) -> bool {
    wait_for(200_000_000, || {
        narf_scheduler::__test_cpu_halted(cpu)
            && (!polling || narf_scheduler::cpu_idle_polling(cpu))
    })
}

// ── interrupts/ipi_rate ─────────────────────────────────────────────────

/// Per-CPU reschedule and shootdown IPIs while this CPU waits idle for
/// 500 ms. The bound is far above Linux's idle desktop (RES ≈ 7/s and
/// TLB ≈ 9/s per CPU on the reference 12-CPU Zen 4) yet three orders of
/// magnitude below the storm the hardware showed (up to ~250 resched/s
/// and ~190 shootdown/s per CPU on an idle desktop); the counts are printed
/// for the record.
fn smoke_ipi_rate_idle_system() -> TestResult {
    let peers = peers();
    if peers.is_empty() {
        return TestResult::Skip("needs a second CPU");
    }
    let before: Vec<(u64, u64)> = (0..MAX_CPUS)
        .map(|c| (resched_rcvd(c), tlb_rcvd(c)))
        .collect();
    let t0 = narf_time::now_cycles();
    let _ = wait_for(500_000_000, || false);
    let ms = narf_time::cycles_to_ns(narf_time::now_cycles().wrapping_sub(t0)) / 1_000_000;
    let mut worst = (0u64, 0u64);
    for &cpu in &peers {
        let resched = resched_rcvd(cpu) - before[cpu].0;
        let tlb = tlb_rcvd(cpu) - before[cpu].1;
        report(format_args!(
            "idle {ms} ms cpu{cpu}: resched {resched} tlb {tlb} polling {}",
            narf_scheduler::cpu_idle_polling(cpu)
        ));
        worst = (worst.0.max(resched), worst.1.max(tlb));
    }
    let per_s = |n: u64| n * 1000 / ms.max(1);
    if per_s(worst.1) > 100 {
        return TestResult::Fail("an idle CPU took more than 100 TLB shootdowns per second");
    }
    if per_s(worst.0) > 500 {
        return TestResult::Fail("an idle CPU took more than 500 reschedule IPIs per second");
    }
    TestResult::Pass
}
kernel_test_in!("interrupts/ipi_rate", smoke_ipi_rate_idle_system);

/// A burst of cross-CPU wakes, each of a task parked on an idle peer: Linux
/// sends at most one IPI per wake (the wake list's first entry) and none to
/// a CPU polling in idle. Counted on the receiving CPU's vector, so IPIs
/// from any source to that CPU count against the bound.
fn smoke_ipi_rate_remote_wakes_of_idle_cpu() -> TestResult {
    const WAKES: u64 = 64;
    let peers = peers();
    let Some(&cpu) = peers.first() else {
        return TestResult::Skip("needs a second CPU");
    };
    if !start_probe(0, cpu) {
        return TestResult::Fail("the probe never parked on its CPU");
    }
    let me = narf_lib::percpu::current_cpu();
    let kicks_before = narf_scheduler::resched_kick_stats(me);
    let rcvd_before = resched_rcvd(cpu);
    let mut polled_wakes = 0u64;
    let mut ok = true;
    for n in 1..=WAKES {
        let _ = settle_idle(cpu, false);
        polled_wakes += u64::from(narf_scheduler::cpu_idle_polling(cpu));
        ok &= wake_probe(0);
        ok &= wait_for(100_000_000, || {
            PROBE_POLLS[0].load(Ordering::Acquire) > n && PROBE_WAKER[0].lock().is_some()
        });
        if !ok {
            break;
        }
    }
    let received = resched_rcvd(cpu) - rcvd_before;
    let kicks = narf_scheduler::resched_kick_stats(me);
    stop_probe(0);
    if !ok {
        return TestResult::Fail("a woken task on an idle CPU did not run within 100 ms");
    }
    let sent = kicks.ipi_sent - kicks_before.ipi_sent;
    let by_store = kicks.skip_polling - kicks_before.skip_polling;
    report(format_args!(
        "{WAKES} wakes of cpu{cpu}: resched received {received}, sent by waker {sent}, \
         polling-store kicks {by_store}, wakes that met a polling idle {polled_wakes}"
    ));
    // Before this change every one of these wakes cost an IPI; `by_store`
    // of them are now a store instead.
    if received > WAKES + WAKES / 4 {
        return TestResult::Fail("an idle CPU took more than one reschedule IPI per wake");
    }
    if polled_wakes == WAKES && received > WAKES / 4 {
        return TestResult::Fail("wakes of a CPU polling in idle still sent IPIs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "interrupts/ipi_rate",
    smoke_ipi_rate_remote_wakes_of_idle_cpu
);

static TIMER_ROUNDS: [AtomicU64; PROBES] = [const { AtomicU64::new(0) }; PROBES];

/// Many short timer-driven wakes: tasks on up to four peers each sleep
/// 200 µs, 250 times. A task's own timer fires on its CPU, so Linux wakes
/// it locally without an IPI; any wake routed through another CPU costs at
/// most one IPI. Bound: reschedule IPIs received by the sleepers' CPUs stay
/// at or below their wakes.
fn smoke_ipi_rate_timer_driven_wakes() -> TestResult {
    const ROUNDS: u64 = 250;
    let peers: Vec<usize> = peers().into_iter().take(PROBES).collect();
    if peers.is_empty() {
        return TestResult::Skip("needs a second CPU");
    }
    let before: Vec<u64> = peers.iter().map(|&c| resched_rcvd(c)).collect();
    let goidle_before: Vec<u64> = peers
        .iter()
        .map(|&c| narf_scheduler::schedstat::cpu_schedstat(c).sched_goidle)
        .collect();
    for (slot, &cpu) in peers.iter().enumerate() {
        TIMER_ROUNDS[slot].store(0, Ordering::Release);
        narf_scheduler::spawn_with_spec(
            async move {
                for _ in 0..ROUNDS {
                    narf_time::sleep_ns(200_000).await;
                    TIMER_ROUNDS[slot].fetch_add(1, Ordering::AcqRel);
                }
            },
            pinned(cpu),
        );
    }
    let done = wait_for(10_000_000_000, || {
        (0..peers.len()).all(|slot| TIMER_ROUNDS[slot].load(Ordering::Acquire) >= ROUNDS)
    });
    let mut worst = 0u64;
    for (i, &cpu) in peers.iter().enumerate() {
        let received = resched_rcvd(cpu) - before[i];
        let idles = narf_scheduler::schedstat::cpu_schedstat(cpu).sched_goidle - goidle_before[i];
        report(format_args!(
            "timer wakes cpu{cpu}: {ROUNDS} sleeps, {idles} idle entries, resched received {received}"
        ));
        worst = worst.max(received);
    }
    if !done {
        return TestResult::Fail("timer-driven sleepers did not finish within 10 s");
    }
    if worst > ROUNDS + ROUNDS / 4 {
        return TestResult::Fail("timer-driven wakes cost more than one reschedule IPI each");
    }
    TestResult::Pass
}
kernel_test_in!("interrupts/ipi_rate", smoke_ipi_rate_timer_driven_wakes);

/// A CPU idling in a polling state (MWAIT) still wakes for an interrupt that
/// is not a wake: a TLB-shootdown request published to it is serviced within
/// a bound, and it then returns to polling idle.
fn smoke_ipi_polling_idle_wakes_on_irq() -> TestResult {
    let Some(&cpu) = peers().first() else {
        return TestResult::Skip("needs a second CPU");
    };
    if !settle_idle(cpu, true) {
        return TestResult::Skip("the peer does not idle in a polling state (no usable MWAIT)");
    }
    let before = crate::x86_64::ipi::ever_received(cpu as u32);
    crate::x86_64::ipi::__publish_for_test(cpu as u32, 0xFFFF_FFFF_8000_6000, 1, 0);
    crate::x86_64::apic::send_fixed_ipi(1u64 << cpu, VECTOR_TLB_SHOOTDOWN);
    let serviced = wait_for(20_000_000, || {
        crate::x86_64::ipi::ever_received(cpu as u32) > before
    });
    if !serviced {
        crate::x86_64::ipi::__clear_for_test(cpu as u32);
        return TestResult::Fail("a CPU in MWAIT idle did not take an interrupt within 20 ms");
    }
    if !settle_idle(cpu, true) {
        return TestResult::Fail("the CPU did not return to polling idle after the interrupt");
    }
    TestResult::Pass
}
kernel_test_in!("interrupts/ipi_rate", smoke_ipi_polling_idle_wakes_on_irq);

/// Unmapping a 16-page kernel range sends one shootdown per peer, not one
/// per page (Linux: one `flush_tlb_kernel_range` per `vunmap`).
fn smoke_ipi_rate_kernel_unmap_is_one_shootdown() -> TestResult {
    const PAGES: usize = 16;
    if peers().is_empty() {
        return TestResult::Skip("needs a second CPU");
    }
    let me = narf_lib::percpu::current_cpu() as u32;
    let Some(ptr) = narf_memory::vmalloc::valloc(PAGES * 4096) else {
        return TestResult::Skip("vmalloc window exhausted");
    };
    // SAFETY: freshly allocated; touch every page so every leaf exists.
    unsafe { core::ptr::write_bytes(ptr.as_ptr(), 0x5a, PAGES * 4096) };
    let before = crate::x86_64::ipi::cpu_stats(me);
    // SAFETY: allocated above with this size and no longer referenced.
    unsafe { narf_memory::vmalloc::vfree(ptr, PAGES * 4096) };
    let after = crate::x86_64::ipi::cpu_stats(me);
    let requests = after.kernel_requests - before.kernel_requests;
    report(format_args!(
        "vfree of {PAGES} pages: {requests} kernel shootdown requests, {} IPIs \
         (one request per page before)",
        after.ipis_sent - before.ipis_sent
    ));
    // One batch for the leaves, plus at most one if the vfree emptied and
    // freed the page table.
    if requests > 2 {
        return TestResult::Fail("a kernel unmap sent more than one shootdown per batch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "interrupts/ipi_rate",
    smoke_ipi_rate_kernel_unmap_is_one_shootdown
);

// ── interrupts/tlb_smp ──────────────────────────────────────────────────

const USER_VA: u64 = 0x0000_0080_0000_0000;

/// Load `space` on this CPU through `AddressSpace::activate` and return the
/// CR3 to restore.
fn enter_space(space: &AddressSpace) -> Option<u64> {
    // SAFETY: CPL=0 read.
    let saved = unsafe { narf_arch::x86_64::cr::read_cr3() };
    space.activate().ok()?;
    Some(saved)
}

/// Reload `saved` exactly as `activate` would, so the residency and
/// deferred-flush protocol sees this CPU's CR3 again.
fn leave_space(saved: u64) {
    let root = saved & 0x000F_FFFF_FFFF_F000;
    let tag = (saved & 0xFFF) as u16;
    narf_lib::sync::without_interrupts(|| {
        let cpu = narf_lib::percpu::current_cpu() as u32;
        if narf_memory::tlb_shootdown::begin_context_load(cpu, tag, root) {
            // SAFETY: CPL=0; over-invalidation is always correct.
            unsafe { narf_memory::x86_64::paging::flush_nonglobal_all_pcids_local() };
        }
        let value = root | u64::from(tag) | if tag != 0 { 1u64 << 63 } else { 0 };
        // SAFETY: `saved` was this CPU's live CR3 before `enter_space`.
        unsafe { narf_arch::x86_64::cr::write_cr3(value) };
        narf_memory::tlb_shootdown::finish_context_load(cpu, tag, root);
    });
}

/// Read a word through the current CR3 from kernel mode.
fn read_word(va: u64) -> u64 {
    // SAFETY: callers read only VAs mapped in the CR3 they just loaded.
    unsafe {
        narf_arch::x86_64::smap::with_user_access(|| core::ptr::read_volatile(va as *const u64))
    }
}

/// Fault-tolerant read for a VA that may be unmapped mid-change.
fn try_read_word(va: u64) -> Option<u64> {
    let mut out = 0u64;
    // SAFETY: the kernel side is a live local; the user side may fault.
    unsafe {
        narf_arch::x86_64::smap::copy_user_guarded(
            (&mut out as *mut u64).cast(),
            va as *const u8,
            8,
        )
    }
    .ok()
    .map(|()| out)
}

fn frame_with(value: u64) -> Option<PhysAddr> {
    let frame = narf_memory::alloc_frame().ok()?.start_address();
    // SAFETY: a fresh frame through the direct map.
    unsafe { frame.kernel_mut_ptr::<u64>().write_volatile(value) };
    Some(frame)
}

fn map_user_page(space: &AddressSpace, value: u64) -> bool {
    let Some(frame) = frame_with(value) else {
        return false;
    };
    space
        .map_region(Region {
            base: VirtAddr::new(USER_VA),
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![frame].into(),
        })
        .is_ok()
        // SAFETY: fresh user root built by `new_for_user`.
        && unsafe { space.materialize() }.is_ok()
}

/// Replace the page at `USER_VA` with a new frame holding `value` through
/// the real munmap path (`unmap_region` → owner-targeted shootdown).
fn remap_user_page(space: &AddressSpace, value: u64) -> bool {
    space.unmap_region(VirtAddr::new(USER_VA)).is_ok() && map_user_page(space, value)
}

static PHASE: AtomicUsize = AtomicUsize::new(0);
static PEER_SAW: AtomicU64 = AtomicU64::new(0);
static PEER_DONE: AtomicBool = AtomicBool::new(false);

fn new_space(value: u64) -> Option<Arc<AddressSpace>> {
    // SAFETY: builds a fresh user root sharing the kernel half.
    let space = Arc::new(unsafe { AddressSpace::new_for_user() }.ok()?);
    map_user_page(&space, value).then_some(space)
}

/// Shared shape of the user-TLB smokes: the peer loads `space`, reads the
/// page (caching `1`), runs `after_first_read`, signals, waits for the boot
/// CPU to replace the page with `2`, runs `before_second_read`, reads again.
fn user_tlb_case(
    name: &'static str,
    after_first_read: fn(&AddressSpace, &AddressSpace) -> Option<u64>,
    before_second_read: fn(&AddressSpace, Option<u64>),
) -> TestResult {
    let Some(&cpu) = peers().first() else {
        return TestResult::Skip("needs a second CPU");
    };
    let (Some(space), Some(other)) = (new_space(1), new_space(7)) else {
        return TestResult::Skip("could not build test address spaces");
    };
    PHASE.store(0, Ordering::SeqCst);
    PEER_SAW.store(0, Ordering::SeqCst);
    PEER_DONE.store(false, Ordering::SeqCst);
    let (a, b) = (space.clone(), other.clone());
    narf_scheduler::spawn_with_spec(
        async move {
            let Some(saved) = enter_space(&a) else {
                PEER_DONE.store(true, Ordering::SeqCst);
                return;
            };
            let first = read_word(USER_VA);
            let token = after_first_read(&a, &b);
            PHASE.store(if first == 1 { 1 } else { 9 }, Ordering::SeqCst);
            let _ = wait_for(2_000_000_000, || PHASE.load(Ordering::SeqCst) == 2);
            before_second_read(&a, token);
            PEER_SAW.store(read_word(USER_VA), Ordering::SeqCst);
            leave_space(saved);
            PEER_DONE.store(true, Ordering::SeqCst);
        },
        pinned(cpu),
    );
    if !wait_for(1_000_000_000, || PHASE.load(Ordering::SeqCst) != 0) {
        return TestResult::Fail("the peer never loaded the address space");
    }
    let remapped = PHASE.load(Ordering::SeqCst) == 1 && remap_user_page(&space, 2);
    PHASE.store(2, Ordering::SeqCst);
    let done = wait_for(2_000_000_000, || PEER_DONE.load(Ordering::SeqCst));
    let saw = PEER_SAW.load(Ordering::SeqCst);
    report(format_args!(
        "{name}: cpu{cpu} tag {} read {saw} after the remap",
        space.translation_tag()
    ));
    if !remapped || !done {
        return TestResult::Fail("the test could not drive both CPUs through the remap");
    }
    if saw != 2 {
        return TestResult::Fail("a peer used a stale translation after the shootdown returned");
    }
    TestResult::Pass
}

/// The peer keeps running the address space: the munmap interrupts it.
fn smoke_tlb_unmap_seen_by_running_peer() -> TestResult {
    user_tlb_case("running peer", |_, _| None, |_, _| {})
}
kernel_test_in!("interrupts/tlb_smp", smoke_tlb_unmap_seen_by_running_peer);

/// The peer switches to another address space before the munmap, so it is
/// not interrupted but owes a flush; switching back must pay it before the
/// stale translation can be used (Linux `switch_mm_irqs_off` `tlb_gen`).
fn smoke_tlb_unmap_seen_after_switch_back() -> TestResult {
    user_tlb_case(
        "switch-away peer",
        |_, other| enter_space(other),
        |space, saved_other| {
            if let Some(saved) = saved_other {
                let _ = saved;
                let _ = space.activate();
            }
        },
    )
}
kernel_test_in!("interrupts/tlb_smp", smoke_tlb_unmap_seen_after_switch_back);

/// The peer leaves the address space and idles through the munmap (idle
/// deferral), then loads it again and reads.
fn smoke_tlb_unmap_seen_by_idle_peer() -> TestResult {
    let Some(&cpu) = peers().first() else {
        return TestResult::Skip("needs a second CPU");
    };
    let Some(space) = new_space(1) else {
        return TestResult::Skip("could not build a test address space");
    };
    PEER_SAW.store(0, Ordering::SeqCst);
    // First visit: load, read (cache), leave, park.
    let a = space.clone();
    PEER_DONE.store(false, Ordering::SeqCst);
    narf_scheduler::spawn_with_spec(
        async move {
            if let Some(saved) = enter_space(&a) {
                PEER_SAW.store(read_word(USER_VA), Ordering::SeqCst);
                leave_space(saved);
            }
            PEER_DONE.store(true, Ordering::SeqCst);
        },
        pinned(cpu),
    );
    if !wait_for(1_000_000_000, || PEER_DONE.load(Ordering::SeqCst))
        || PEER_SAW.load(Ordering::SeqCst) != 1
    {
        return TestResult::Fail("the peer did not read the first mapping");
    }
    let idled = settle_idle(cpu, false);
    if !remap_user_page(&space, 2) {
        return TestResult::Skip("could not remap the test page");
    }
    let a = space.clone();
    PEER_DONE.store(false, Ordering::SeqCst);
    narf_scheduler::spawn_with_spec(
        async move {
            if let Some(saved) = enter_space(&a) {
                PEER_SAW.store(read_word(USER_VA), Ordering::SeqCst);
                leave_space(saved);
            }
            PEER_DONE.store(true, Ordering::SeqCst);
        },
        pinned(cpu),
    );
    let done = wait_for(1_000_000_000, || PEER_DONE.load(Ordering::SeqCst));
    let saw = PEER_SAW.load(Ordering::SeqCst);
    report(format_args!(
        "idle peer: cpu{cpu} idled {idled}, tag {}, read {saw} after the remap",
        space.translation_tag()
    ));
    if !done || saw != 2 {
        return TestResult::Fail("an idle peer used a stale translation after waking");
    }
    TestResult::Pass
}
kernel_test_in!("interrupts/tlb_smp", smoke_tlb_unmap_seen_by_idle_peer);

static RACE_PUBLISHED: AtomicU64 = AtomicU64::new(0);
static RACE_STALE: AtomicU64 = AtomicU64::new(0);
static RACE_READS: AtomicU64 = AtomicU64::new(0);
static RACE_STOP: AtomicBool = AtomicBool::new(false);

/// Concurrent unmap/access: the peer reads the page in a loop while the boot
/// CPU replaces it 200 times. Once generation `g` is published (its munmap
/// shootdown returned and the new page is mapped), no later read may return
/// an older generation.
fn smoke_tlb_concurrent_unmap_access_race() -> TestResult {
    const GENERATIONS: u64 = 200;
    let Some(&cpu) = peers().first() else {
        return TestResult::Skip("needs a second CPU");
    };
    let Some(space) = new_space(1) else {
        return TestResult::Skip("could not build a test address space");
    };
    RACE_PUBLISHED.store(1, Ordering::SeqCst);
    RACE_STALE.store(0, Ordering::SeqCst);
    RACE_READS.store(0, Ordering::SeqCst);
    RACE_STOP.store(false, Ordering::SeqCst);
    PEER_DONE.store(false, Ordering::SeqCst);
    let a = space.clone();
    narf_scheduler::spawn_with_spec(
        async move {
            if let Some(saved) = enter_space(&a) {
                while !RACE_STOP.load(Ordering::SeqCst) {
                    let floor = RACE_PUBLISHED.load(Ordering::SeqCst);
                    if let Some(seen) = try_read_word(USER_VA) {
                        RACE_READS.fetch_add(1, Ordering::Relaxed);
                        if seen < floor {
                            RACE_STALE.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
                leave_space(saved);
            }
            PEER_DONE.store(true, Ordering::SeqCst);
        },
        pinned(cpu),
    );
    let _ = wait_for(100_000_000, || RACE_READS.load(Ordering::Relaxed) > 0);
    let mut remapped = true;
    for generation in 2..=GENERATIONS {
        remapped &= remap_user_page(&space, generation);
        RACE_PUBLISHED.store(generation, Ordering::SeqCst);
        if !remapped {
            break;
        }
    }
    let _ = wait_for(10_000_000, || false);
    RACE_STOP.store(true, Ordering::SeqCst);
    let done = wait_for(1_000_000_000, || PEER_DONE.load(Ordering::SeqCst));
    let stale = RACE_STALE.load(Ordering::SeqCst);
    report(format_args!(
        "race: cpu{cpu} tag {} {} reads over {GENERATIONS} remaps, {stale} stale",
        space.translation_tag(),
        RACE_READS.load(Ordering::Relaxed)
    ));
    if !remapped || !done {
        return TestResult::Fail("the race could not run to completion");
    }
    if stale != 0 {
        return TestResult::Fail("a peer read a page generation older than the published one");
    }
    TestResult::Pass
}
kernel_test_in!("interrupts/tlb_smp", smoke_tlb_concurrent_unmap_access_race);

static KVA: AtomicU64 = AtomicU64::new(0);

/// A kernel (vmalloc) mapping the peer cached while running one address
/// space's PCID, then switched away from: unmapping it and mapping the VA to
/// a new frame must not leave the old translation live under that PCID.
/// INVLPG alone only reaches the current PCID (Intel SDM Vol. 3A §4.10.4.1).
fn smoke_tlb_kernel_unmap_flushes_other_pcids() -> TestResult {
    use narf_memory::x86_64::paging::{self, PtFlags};
    let Some(&cpu) = peers().first() else {
        return TestResult::Skip("needs a second CPU");
    };
    let (Some(space), Some(other)) = (new_space(1), new_space(7)) else {
        return TestResult::Skip("could not build test address spaces");
    };
    if space.translation_tag() == 0 {
        return TestResult::Skip("no PCIDs on this machine: every CR3 load flushes");
    }
    let Some(root) = narf_memory::bpf_text::kernel_root_for_mapping() else {
        return TestResult::Skip("no kernel root");
    };
    let Some(ptr) = narf_memory::vmalloc::valloc(4096) else {
        return TestResult::Skip("vmalloc window exhausted");
    };
    let va = ptr.as_ptr() as u64;
    // SAFETY: freshly allocated page.
    unsafe { core::ptr::write_volatile(va as *mut u64, 1) };
    KVA.store(va, Ordering::SeqCst);
    PHASE.store(0, Ordering::SeqCst);
    PEER_SAW.store(0, Ordering::SeqCst);
    PEER_DONE.store(false, Ordering::SeqCst);
    let (a, b) = (space.clone(), other.clone());
    narf_scheduler::spawn_with_spec(
        async move {
            let va = KVA.load(Ordering::SeqCst);
            let Some(saved) = enter_space(&a) else {
                PEER_DONE.store(true, Ordering::SeqCst);
                return;
            };
            // SAFETY: a live kernel page while PHASE < 2.
            let first = unsafe { core::ptr::read_volatile(va as *const u64) };
            let _ = b.activate();
            PHASE.store(if first == 1 { 1 } else { 9 }, Ordering::SeqCst);
            let _ = wait_for(2_000_000_000, || PHASE.load(Ordering::SeqCst) == 2);
            let _ = a.activate();
            // SAFETY: remapped to a live frame before PHASE 2.
            PEER_SAW.store(
                unsafe { core::ptr::read_volatile(va as *const u64) },
                Ordering::SeqCst,
            );
            leave_space(saved);
            PEER_DONE.store(true, Ordering::SeqCst);
        },
        pinned(cpu),
    );
    if !wait_for(1_000_000_000, || PHASE.load(Ordering::SeqCst) != 0) {
        return TestResult::Fail("the peer never cached the kernel page");
    }
    let mut old = None;
    let new = frame_with(2);
    let flags = PtFlags::PRESENT | PtFlags::WRITABLE | PtFlags::NO_EXEC;
    let mut remapped = false;
    if let (1, Some(new)) = (PHASE.load(Ordering::SeqCst), new) {
        // SAFETY: the page is ours; the peer does not touch it until PHASE 2.
        unsafe {
            paging::unmap_kernel_pages(root, VirtAddr::new(va), 1, &mut |pa| old = Some(pa));
            remapped = paging::map_4kb(root, VirtAddr::new(va), new, flags).is_ok();
        }
    }
    PHASE.store(2, Ordering::SeqCst);
    let done = wait_for(2_000_000_000, || PEER_DONE.load(Ordering::SeqCst));
    let saw = PEER_SAW.load(Ordering::SeqCst);
    // Restore the original frame for vfree.
    if let Some(old) = old {
        // SAFETY: our page; `new` is released after the batch flush.
        unsafe {
            paging::unmap_kernel_pages(root, VirtAddr::new(va), 1, &mut |pa| {
                narf_memory::frame::free_frame(narf_memory::frame::PhysFrame::new(pa))
            });
            let _ = paging::map_4kb(root, VirtAddr::new(va), old, flags);
        }
    }
    // SAFETY: allocated above with this size.
    unsafe { narf_memory::vmalloc::vfree(ptr, 4096) };
    report(format_args!(
        "kernel page under tag {}: cpu{cpu} read {saw} after the remap",
        space.translation_tag()
    ));
    if !remapped || !done {
        return TestResult::Fail("the test could not drive both CPUs through the remap");
    }
    if saw != 2 {
        return TestResult::Fail(
            "a kernel translation cached under another PCID survived its unmap",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "interrupts/tlb_smp",
    smoke_tlb_kernel_unmap_flushes_other_pcids
);
