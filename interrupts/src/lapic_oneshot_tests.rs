//! LAPIC one-shot clockevent smokes (`interrupts/oneshot`).
//!
//! Every CPU programs its own LAPIC one-shot — TSC-deadline, or the LVT
//! one-shot `TMICT` mode on CPUs without it (AMD Zen 2/3/4) — and HPET
//! broadcasts only for a LAPIC that stops in idle. The SMP smoke is meant to
//! run with TSC-deadline masked from the guest
//! (`NARF_QEMU_CPU=max,-tsc-deadline`); it also passes, in TSC-deadline mode,
//! on the default CPU model.

#![cfg(target_arch = "x86_64")]

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_time::hrtimer::{ClockId, HrTimer, HrtimerMode, HrtimerRestart};

use crate::x86_64::apic::{self, LocalTimerMode};
use crate::x86_64::timer_pump;

/// CPUID(0) vendor words (EBX, EDX, ECX).
const AMD: [u32; 3] = [0x6874_7541, 0x6974_6E65, 0x444D_4163];
const HYGON: [u32; 3] = [0x6F67_7948, 0x6E65_476E, 0x656E_6975];
const INTEL: [u32; 3] = [0x756E_6547, 0x4965_6E69, 0x6C65_746E];

/// CPUID(1) EAX for `family` (extended family encoding above 0xF).
const fn signature(family: u32) -> u32 {
    if family >= 0xF {
        (0xF << 8) | ((family - 0xF) << 20)
    } else {
        family << 8
    }
}

fn oneshot_hpet_broadcast_selection() -> TestResult {
    use narf_arch::x86_64::cpuid::arat_implied_by_vendor;
    use timer_pump::needs_hpet_broadcast;
    // Linux tick-broadcast: only a one-shot LAPIC that keeps counting in
    // idle lets every CPU go without the HPET broadcast.
    if !needs_hpet_broadcast(false, false)
        || !needs_hpet_broadcast(false, true)
        || !needs_hpet_broadcast(true, false)
        || needs_hpet_broadcast(true, true)
    {
        return TestResult::Fail("broadcast policy is not 'unless one-shot LAPIC with ARAT'");
    }
    // Linux `init_amd`: family 12h and later; `init_hygon`: every part.
    let cases = [
        (AMD, 0x19, true),  // Zen 4 (Ryzen 7600X)
        (AMD, 0x17, true),  // Zen 2 (Renoir)
        (AMD, 0x1A, true),  // Zen 5
        (AMD, 0x12, true),  // Llano, the first family with ARAT
        (AMD, 0x11, false), // Griffin
        (AMD, 0x10, false), // K10
        (HYGON, 0x18, true),
        (INTEL, 0x6, false), // Intel reports ARAT through CPUID(6) only
    ];
    for (vendor, family, want) in cases {
        if arat_implied_by_vendor(vendor, signature(family)) != want {
            return TestResult::Fail("ARAT vendor/family implication differs from Linux");
        }
    }
    TestResult::Pass
}
kernel_test_in!("interrupts/oneshot", oneshot_hpet_broadcast_selection);

/// A TMICT one-shot loaded through the production conversion counts out no
/// earlier than the requested delta and no later than the `latest` bound
/// `program_next_event` records as the armed time. Checked with the LVT
/// masked, by polling the current count, on the boot CPU's stopped timer.
fn oneshot_tmict_conversion_matches_tsc() -> TestResult {
    let cpu = narf_lib::percpu::current_cpu();
    if apic::local_timer_mode(cpu) != LocalTimerMode::Stopped {
        return TestResult::Skip("this CPU's LAPIC timer is in use");
    }
    let Some(scale) = apic::lapic_timer_scale() else {
        return TestResult::Fail("the LAPIC timer did not calibrate");
    };
    // A divide-by-16 tick between 1 ns (16 GHz APIC clock) and 1 µs.
    let tick_ns = narf_time::cycles_to_ns(scale.ticks_to_units(1_000)) / 1_000;
    if !(1..=1_000).contains(&tick_ns) {
        return TestResult::Fail("calibrated LAPIC tick outside 1 ns..1 us");
    }
    // Long deltas make a ratio error of ~1e-4 exceed the TMCCT polling
    // granularity (a VM exit per read under KVM).
    for delta_ns in [1_000_000u64, 20_000_000] {
        let delta = narf_time::ns_to_cycles(delta_ns);
        let Some(m) = apic::__test_masked_oneshot(delta) else {
            return TestResult::Fail("masked one-shot did not count out");
        };
        // The countdown started in [before_write, after_write]; it expired
        // after the last non-zero read began and before the first zero read
        // ended. Preemption can only widen that window, never invert it.
        if m.zero_read_end.saturating_sub(m.before_write) < delta {
            return TestResult::Fail("TMICT one-shot expired before the requested delta");
        }
        if m.last_nonzero_start.saturating_sub(m.after_write) > m.programmed.latest {
            return TestResult::Fail("TMICT one-shot ran past its recorded latest expiry");
        }
    }
    TestResult::Pass
}
kernel_test_in!("interrupts/oneshot", oneshot_tmict_conversion_matches_tsc);

/// Sleep length per CPU, and how long the parked task outlives its probe.
const SLEEP_NS: u64 = 20_000_000;
const SLEEPER_LAG_NS: u64 = 100_000_000;
/// Wake latency allowed past a probe's expiry (interrupt delivery, host
/// scheduling of the vCPU: an overcommitted KVM host was seen to deliver
/// 2.5 ms late, and TCG round-robins vCPUs). Must stay below
/// `SLEEPER_LAG_NS`, so a probe whose own event was never programmed —
/// expired only alongside the sleeper — fails.
const LATE_NS: u64 = 50_000_000;
const _: () = assert!(LATE_NS < SLEEPER_LAG_NS);

/// Per-CPU hard hrtimer that records which CPU expired it, and when.
#[repr(C)]
struct Probe {
    timer: HrTimer,
    fired_cpu: AtomicU32,
    fired_ns: AtomicU64,
    deadline_ns: AtomicU64,
    timer_irqs: AtomicU64,
    done: AtomicBool,
}

impl Probe {
    const fn new() -> Self {
        Self {
            timer: HrTimer::new(probe_fired, ClockId::Monotonic, HrtimerMode::HARD),
            fired_cpu: AtomicU32::new(u32::MAX),
            fired_ns: AtomicU64::new(0),
            deadline_ns: AtomicU64::new(0),
            timer_irqs: AtomicU64::new(0),
            done: AtomicBool::new(false),
        }
    }

    fn reset(&self) {
        self.fired_cpu.store(u32::MAX, Ordering::Relaxed);
        self.fired_ns.store(0, Ordering::Relaxed);
        self.timer_irqs.store(0, Ordering::Relaxed);
        self.done.store(false, Ordering::Release);
    }

    /// Arm for `SLEEP_NS` from now on the calling CPU's base, pinned.
    fn arm(&self) {
        let deadline = narf_time::monotonic_ns() + SLEEP_NS;
        self.deadline_ns.store(deadline, Ordering::Relaxed);
        // SAFETY: the probe is a static, so it never moves or is freed; the
        // test cancels every probe before returning.
        unsafe {
            narf_time::hrtimer::hrtimer_start_range_ns(
                &self.timer,
                deadline,
                0,
                HrtimerMode::ABS_PINNED,
            )
        };
    }
}

static PROBES: [Probe; narf_lib::percpu::MAX_CPUS] =
    [const { Probe::new() }; narf_lib::percpu::MAX_CPUS];

fn probe_fired(t: &HrTimer) -> HrtimerRestart {
    // SAFETY: only `Probe`s use this callback, and `timer` is the first field
    // of the `repr(C)` struct, so this is `container_of`.
    let p = unsafe { &*(t as *const HrTimer as *const Probe) };
    p.fired_ns
        .store(narf_time::monotonic_ns(), Ordering::Relaxed);
    p.fired_cpu
        .store(narf_lib::percpu::current_cpu() as u32, Ordering::Release);
    HrtimerRestart::NoRestart
}

fn timer_irqs_on(cpu: usize) -> u64 {
    crate::fire_count_on_cpu(crate::VECTOR_TIMER, cpu)
}

/// Every CPU's sleep is expired by that CPU's own LAPIC interrupt, and the
/// HPET broadcast takes none. The boot CPU selects the LAPIC as the primary
/// clockevent exactly as `bare_main` does, `timer_pump` re-evaluates the
/// broadcast, then each online CPU parks on a 20 ms hrtimer: the expiry must
/// run on that CPU, on time, with the `hpet-timer` count unchanged. The boot
/// CPU additionally stops its tick (NOHZ) and must take only the event's
/// interrupt instead of one per tick.
fn oneshot_smp_cpus_wake_from_own_lapic() -> TestResult {
    let online = narf_lib::smp::online_bitmap();
    let me = narf_lib::percpu::current_cpu();
    if online.count_ones() < 2 {
        return TestResult::Skip("UP boot: no AP to wake");
    }
    if narf_time::clockevent::primary().is_some() {
        return TestResult::Skip("a primary clockevent is already selected");
    }
    if apic::local_timer_mode(me) != LocalTimerMode::Stopped {
        return TestResult::Skip("this CPU's LAPIC timer is in use");
    }
    // SAFETY: CPUID is always legal at CPL=0.
    let feats = unsafe { narf_arch::x86_64::Features::probe() };
    // Every AP started its LAPIC as a one-shot clockevent at bring-up
    // (`smp.rs`): TMICT without TSC-deadline, never the periodic mode.
    let mut m = online & !(1u64 << me);
    while m != 0 {
        let cpu = m.trailing_zeros() as usize;
        m &= m - 1;
        let mode = apic::local_timer_mode(cpu);
        if !mode.is_oneshot() {
            return TestResult::Fail("an AP's LAPIC timer is not a one-shot clockevent");
        }
        if !feats.tsc_deadline && mode != LocalTimerMode::Oneshot {
            return TestResult::Fail("without TSC-deadline an AP must run the TMICT one-shot");
        }
    }
    if !feats.arat {
        return TestResult::Skip("no ARAT: the HPET broadcast stays armed by design");
    }
    let hpet_vector = match timer_pump::init() {
        Ok(()) | Err(timer_pump::TimerPumpInitError::AlreadyInitialised) => {
            Some(timer_pump::__vector_for_test())
        }
        Err(_) => None,
    };

    let nohz_was = narf_time::nohz_idle_enabled();
    let reliable_was = narf_time::tick_reliable();
    let irqs_were_on = narf_arch::interrupts_enabled();
    narf_time::clockevent::register(&apic::LAPIC_CLOCKEVENT);
    // SAFETY: the probe in `select_primary` needs timer interrupts delivered.
    unsafe { narf_arch::enable_interrupts() };
    let result = run_smp_wake(online, me, hpet_vector);
    // Teardown: cancel the probes, stop the boot CPU's timer, drop the
    // selection and restore the broadcast, NOHZ and IRQ state, then kick
    // every AP so it restarts the tick it stopped while NOHZ was on.
    for p in PROBES.iter() {
        narf_time::hrtimer::hrtimer_cancel(&p.timer);
    }
    // SAFETY: the test owns the boot CPU's LAPIC timer (it was stopped).
    unsafe { narf_time::clockevent::ClockEvent::disarm(&apic::LAPIC_CLOCKEVENT) };
    narf_time::clockevent::__reset_for_test();
    let _ = timer_pump::update_broadcast();
    narf_time::set_nohz_idle_enabled(nohz_was);
    narf_time::set_tick_reliable(reliable_was);
    apic::send_fixed_ipi(online & !(1u64 << me), crate::VECTOR_RESCHED);
    if !irqs_were_on {
        // SAFETY: restore the runner's IRQ state.
        unsafe { narf_arch::disable_interrupts() };
    }
    result
}
kernel_test_in!("interrupts/oneshot", oneshot_smp_cpus_wake_from_own_lapic);

fn run_smp_wake(online: u64, me: usize, hpet_vector: Option<u8>) -> TestResult {
    use core::fmt::Write as _;
    let selected = narf_time::clockevent::select_primary(1000, crate::VECTOR_TIMER);
    if selected.is_none_or(|d| d.name() != "lapic") {
        return TestResult::Fail("the LAPIC was not selected as the primary clockevent");
    }
    if !apic::local_timer_mode(me).is_oneshot() {
        return TestResult::Fail("select_primary left the boot CPU's LAPIC periodic");
    }
    if timer_pump::update_broadcast() || timer_pump::uses_hpet_fallback() {
        return TestResult::Fail("a one-shot ARAT LAPIC still uses the HPET broadcast");
    }
    narf_time::set_nohz_idle_enabled(true);
    let hpet_before = hpet_vector.map(crate::fire_count);

    // APs: each parks a pinned task on its own hrtimer and goes idle.
    let aps = online & !(1u64 << me);
    let mut m = aps;
    while m != 0 {
        let cpu = m.trailing_zeros();
        m &= m - 1;
        PROBES[cpu as usize].reset();
        narf_scheduler::spawn_stackful_pinned(
            async move {
                let cpu = narf_lib::percpu::current_cpu();
                let p = &PROBES[cpu];
                let irqs = timer_irqs_on(cpu);
                p.arm();
                let park = narf_time::ns_to_cycles(SLEEP_NS + SLEEPER_LAG_NS);
                narf_time::SleepUntil::new(narf_time::Instant::now().plus_cycles(park)).await;
                p.timer_irqs
                    .store(timer_irqs_on(cpu) - irqs, Ordering::Relaxed);
                p.done.store(true, Ordering::Release);
            },
            cpu,
        );
    }

    // Boot CPU: stop the tick as idle does, then wait (spinning, interrupts
    // on) for the probe. Only the probe's event may interrupt.
    let bsp = &PROBES[me];
    bsp.reset();
    let irqs = timer_irqs_on(me);
    narf_lib::sync::without_interrupts(|| {
        bsp.arm();
        narf_time::clockevent::set_idle_tick(true, None);
    });
    let give_up = narf_time::monotonic_ns() + SLEEP_NS + LATE_NS;
    while bsp.fired_cpu.load(Ordering::Acquire) == u32::MAX && narf_time::monotonic_ns() < give_up {
        core::hint::spin_loop();
    }
    let bsp_irqs = timer_irqs_on(me) - irqs;
    narf_time::clockevent::restart_local_tick();

    // Wait for every AP task.
    let give_up = narf_time::monotonic_ns() + 2_000_000_000;
    while narf_time::monotonic_ns() < give_up {
        let mut all = true;
        let mut m = aps;
        while m != 0 {
            let cpu = m.trailing_zeros() as usize;
            m &= m - 1;
            all &= PROBES[cpu].done.load(Ordering::Acquire);
        }
        if all {
            break;
        }
        core::hint::spin_loop();
    }
    let hpet_delta = match (hpet_vector, hpet_before) {
        (Some(v), Some(b)) => crate::fire_count(v) - b,
        _ => 0,
    };

    let bsp_period = apic::local_tick_period_cycles(me).max(1);
    let bsp_ticks = narf_time::ns_to_cycles(SLEEP_NS) / bsp_period;
    let _ = writeln!(
        narf_console::Writer,
        "  oneshot: cpu{me} {} {bsp_irqs} timer IRQs in {} ms (tick would be {bsp_ticks}), \
         hpet-timer +{hpet_delta}",
        apic::local_timer_mode(me).name(),
        SLEEP_NS / 1_000_000,
    );
    let mut m = aps;
    while m != 0 {
        let cpu = m.trailing_zeros() as usize;
        m &= m - 1;
        let p = &PROBES[cpu];
        let period = apic::local_tick_period_cycles(cpu).max(1);
        let _ = writeln!(
            narf_console::Writer,
            "  oneshot: cpu{cpu} {} expired by cpu{} +{} us, {} timer IRQs (tick would be {})",
            apic::local_timer_mode(cpu).name(),
            p.fired_cpu.load(Ordering::Relaxed) as i32,
            p.fired_ns
                .load(Ordering::Relaxed)
                .saturating_sub(p.deadline_ns.load(Ordering::Relaxed))
                / 1_000,
            p.timer_irqs.load(Ordering::Relaxed),
            narf_time::ns_to_cycles(SLEEP_NS + SLEEPER_LAG_NS) / period,
        );
    }

    if check_probe(bsp, me).is_some() {
        return TestResult::Fail("the boot CPU's sleep was not expired by its own LAPIC");
    }
    // Tickless: the event's interrupt (plus the rare other local timer),
    // not one per tick.
    if bsp_irqs == 0 || bsp_irqs * 4 > bsp_ticks {
        return TestResult::Fail("the boot CPU's stopped tick kept interrupting");
    }
    let mut m = aps;
    while m != 0 {
        let cpu = m.trailing_zeros() as usize;
        m &= m - 1;
        let p = &PROBES[cpu];
        if !p.done.load(Ordering::Acquire) {
            return TestResult::Fail("an AP's sleeping task never woke");
        }
        if let Some(why) = check_probe(p, cpu) {
            return TestResult::Fail(why);
        }
        if p.timer_irqs.load(Ordering::Relaxed) == 0 {
            return TestResult::Fail("an AP woke without a LAPIC timer interrupt");
        }
    }
    if hpet_delta != 0 {
        return TestResult::Fail("the HPET broadcast took interrupts");
    }
    TestResult::Pass
}

/// `None` when `p` was expired by `cpu` itself within `LATE_NS` of its
/// deadline (and not before it).
fn check_probe(p: &Probe, cpu: usize) -> Option<&'static str> {
    let fired_cpu = p.fired_cpu.load(Ordering::Acquire);
    if fired_cpu == u32::MAX {
        return Some("a CPU's hrtimer never expired");
    }
    if fired_cpu as usize != cpu {
        return Some("a CPU's hrtimer was expired by another CPU");
    }
    let fired = p.fired_ns.load(Ordering::Relaxed);
    let deadline = p.deadline_ns.load(Ordering::Relaxed);
    if fired < deadline {
        return Some("a CPU's hrtimer expired early");
    }
    if fired - deadline > LATE_NS {
        return Some("a CPU's hrtimer expired late (not by its own one-shot)");
    }
    None
}
