use crate::{executor, *};
use narf_kernel_test::{kernel_test_in, TestResult};

fn fixture() -> (Cap<Power, Grant>, IdleHints) {
    init();
    let cap = bootstrap_power_authority();
    register_cstate(
        &cap,
        CState {
            id: 3,
            exit_latency_us: 50,
            target_residency_us: 100,
            power_draw_mw: 100,
            entry: || {},
        },
    )
    .unwrap();
    install_idle_governor(&bootstrap_idle_governor_authority(), MenuGovernor).unwrap();
    (
        cap,
        IdleHints {
            cpu: narf_lib::percpu::current_cpu(),
            now_cycles: 0,
            next_deadline_cycles: None,
        },
    )
}

fn idle_deadline_and_qos() -> TestResult {
    let (cap, mut hints) = fixture();
    if executor::prepare_idle(hints).state().id != 3 {
        return TestResult::Fail("long idle did not select deep state");
    }
    hints.next_deadline_cycles = Some(narf_time::ns_to_cycles(20_000));
    if executor::prepare_idle(hints).state().id != 1 {
        return TestResult::Fail("deep state exceeded real deadline");
    }
    hints.next_deadline_cycles = None;
    executor::set_idle_latency_limit(&cap, hints.cpu, 20).unwrap();
    if executor::prepare_idle(hints).state().id != 1 {
        return TestResult::Fail("deep state exceeded QoS");
    }
    executor::set_idle_latency_limit(&cap, hints.cpu, 0).unwrap();
    if executor::prepare_idle(hints).state().id != 0 {
        return TestResult::Fail("zero latency constraint did not poll");
    }
    init();
    TestResult::Pass
}
kernel_test_in!("power/idle", idle_deadline_and_qos);

fn idle_history_is_per_cpu() -> TestResult {
    let (_, hints) = fixture();
    let plan = executor::prepare_idle(hints);
    executor::reflect_idle(hints.cpu, plan, narf_time::ns_to_cycles(10_000));
    if executor::prepare_idle(hints).state().id != 1 {
        return TestResult::Fail("short residency was ignored");
    }
    let peer = (hints.cpu + 1) % narf_lib::percpu::MAX_CPUS;
    if executor::idle_stats(peer).unwrap().entries != 0 {
        return TestResult::Fail("residency leaked between CPUs");
    }
    let _ = executor::prepare_idle(IdleHints { cpu: peer, ..hints });
    if executor::idle_stats(peer).unwrap().entries != 0 {
        return TestResult::Fail("remote hint mutated peer residency");
    }
    // A zero-length sample must not permanently pin the native governor in C0.
    let plan = executor::prepare_idle(hints);
    executor::reflect_idle(hints.cpu, plan, 0);
    if executor::prepare_idle(hints).state().id == 0 {
        return TestResult::Fail("short history caused unbounded polling");
    }
    init();
    TestResult::Pass
}
kernel_test_in!("power/idle", idle_history_is_per_cpu);

struct Fixed(u8);
impl IdleGovernor for Fixed {
    fn name(&self) -> &'static str {
        "fixture"
    }
    fn select_idle_state(&self, _: u64, _: u64) -> CStateIdx {
        CStateIdx(self.0)
    }
    fn select(&self, _: &IdleContext, _: &[IdleState]) -> IdleDecision {
        IdleDecision {
            state: CStateIdx(self.0),
            stop_tick: false,
        }
    }
}

fn idle_policy_replacement_and_validation() -> TestResult {
    let (cap, hints) = fixture();
    let authority = bootstrap_idle_governor_authority();
    let _ = executor::prepare_idle(hints);
    install_idle_governor(&authority, Fixed(0)).unwrap();
    let selected = executor::prepare_idle(hints);
    if selected.state().id != 0 || selected.stop_tick() {
        return TestResult::Fail("cached governor not replaced");
    }
    install_idle_governor(&authority, Fixed(255)).unwrap();
    if executor::prepare_idle(hints).state().id != 1 {
        return TestResult::Fail("unknown state did not fall back");
    }
    install_idle_governor(&authority, Fixed(3)).unwrap();
    executor::set_idle_latency_limit(&cap, hints.cpu, 2).unwrap();
    if executor::prepare_idle(hints).state().id != 1 {
        return TestResult::Fail("custom governor bypassed latency limit");
    }
    cap.revoke();
    if executor::set_idle_latency_limit(&cap, hints.cpu, u64::MAX)
        != Err(PowerError::AuthorityRevoked)
    {
        return TestResult::Fail("revoked power authority changed latency");
    }
    init();
    TestResult::Pass
}
kernel_test_in!("power/idle", idle_policy_replacement_and_validation);

#[cfg(target_arch = "x86_64")]
fn idle_x86_capability_boundaries() -> TestResult {
    use crate::x86::CpuIdleCaps;
    let caps = CpuIdleCaps {
        mwait: true,
        interrupt_break: true,
        sub_states: 0x220,
        invariant_tsc: true,
        arat: true,
        amd_zen: true,
        ..CpuIdleCaps::default()
    };
    for (hint, expected) in [
        (0, true),
        (1, true),
        (2, false),
        (0x10, true),
        (0x11, true),
        (0x12, false),
        (0x20, false),
        (0x70, false),
        (u32::MAX, false),
    ] {
        if caps.supports(IdleEntry::Mwait { hint }) != expected {
            return TestResult::Fail("MWAIT substate validation");
        }
    }
    let deep = IdleEntry::Mwait { hint: 0x10 };
    if (CpuIdleCaps {
        arat: false,
        ..caps
    })
    .supports(deep)
        || (CpuIdleCaps {
            invariant_tsc: false,
            ..caps
        })
        .supports(deep)
        || (CpuIdleCaps {
            interrupt_break: false,
            ..caps
        })
        .supports(IdleEntry::Mwait { hint: 0 })
    {
        return TestResult::Fail("unsafe timer/interrupt capability admitted");
    }
    let io = IdleEntry::SystemIo {
        port: 0x415,
        acpi_type: 3,
    };
    if !caps.supports(io)
        || (CpuIdleCaps {
            amd_zen: false,
            ..caps
        })
        .supports(io)
        || caps.supports(IdleEntry::SystemIo {
            port: 0,
            acpi_type: 3,
        })
    {
        return TestResult::Fail("ACPI I/O platform gate");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("power/idle", idle_x86_capability_boundaries);

/// The default C1 follows Linux `prefer_mwait_c1_over_halt`, and only MWAIT
/// states that a monitored store can end are reported as polling.
#[cfg(target_arch = "x86_64")]
fn idle_mwait_c1_selection_matches_linux() -> TestResult {
    use crate::x86::{prefer_mwait_c1_over_halt, CpuIdleCaps};
    // (MWAIT enumerated, MONITOR/C1E bug, CPUID.05H:ECX, CPUID.05H:EDX, expected)
    for (mwait, bug, ecx, edx, expected) in [
        // Ryzen 5 7600X (Zen 4): ECX=EMX|IBE, EDX=0x11 (one C0 and one C1 sub-state).
        (true, false, 3, 0x11, true),
        // Extensions without a C1 sub-state (QEMU TCG leaf 5): HALT.
        (true, false, 3, 0x00, false),
        // No extensions: EAX=0/ECX=0 is always a valid MWAIT.
        (true, false, 0, 0x00, true),
        // MWAIT hidden (KVM default, no `cpu-pm=on`): HALT.
        (false, false, 3, 0x11, false),
        // X86_BUG_MONITOR / X86_BUG_AMD_APIC_C1E: HALT.
        (true, true, 3, 0x11, false),
    ] {
        if prefer_mwait_c1_over_halt(mwait, bug, ecx, edx) != expected {
            return TestResult::Fail("prefer_mwait_c1_over_halt diverged from Linux");
        }
    }
    let caps = CpuIdleCaps {
        mwait: true,
        interrupt_break: true,
        sub_states: 0x11,
        mwait_c1: true,
        ..CpuIdleCaps::default()
    };
    if !caps.supports(IdleEntry::MwaitIdle)
        || (CpuIdleCaps {
            mwait_c1: false,
            ..caps
        })
        .supports(IdleEntry::MwaitIdle)
    {
        return TestResult::Fail("MwaitIdle admitted without prefer_mwait_c1_over_halt");
    }
    if !caps.polls(IdleEntry::MwaitIdle)
        || !caps.polls(IdleEntry::Mwait { hint: 0 })
        || !caps.polls(IdleEntry::Poll)
        || caps.polls(IdleEntry::Halt)
        || caps.polls(IdleEntry::SystemIo {
            port: 0x414,
            acpi_type: 2,
        })
    {
        return TestResult::Fail("polling classification: only MWAIT/poll watch the wake word");
    }
    let buggy = CpuIdleCaps {
        monitor_bug: true,
        ..caps
    };
    if buggy.polls(IdleEntry::Mwait { hint: 0 }) || buggy.polls(IdleEntry::MwaitIdle) {
        return TestResult::Fail("X86_BUG_MONITOR MWAIT reported as polling");
    }
    // This CPU: the live C1 is MWAIT exactly when its CPUID says Linux would
    // prefer it (a firmware C1 may replace it, as acpi_idle replaces x86_idle).
    let live = CpuIdleCaps::probe();
    init();
    let plan = executor::prepare_idle(IdleHints {
        cpu: narf_lib::percpu::current_cpu(),
        now_cycles: 0,
        next_deadline_cycles: Some(narf_time::ns_to_cycles(10_000_000)),
    });
    let c1_is_mwait = matches!(plan.state().entry, IdleEntry::MwaitIdle);
    if plan.state().id == 1 && c1_is_mwait != live.mwait_c1 {
        return TestResult::Fail("built-in C1 disagrees with this CPU's MWAIT preference");
    }
    if plan.polls() != live.polls(plan.state().entry) {
        return TestResult::Fail("plan polling flag disagrees with the CPU's MONITOR behaviour");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("power/idle", idle_mwait_c1_selection_matches_linux);

/// A polling plan whose wake word already moved off its armed value does not
/// wait: the store that a waker makes instead of an IPI is never slept over,
/// even when it lands before MONITOR is armed.
fn idle_polling_entry_observes_prior_wake_store() -> TestResult {
    init();
    let hints = IdleHints {
        cpu: narf_lib::percpu::current_cpu(),
        now_cycles: 0,
        next_deadline_cycles: Some(narf_time::ns_to_cycles(10_000_000)),
    };
    let plan = executor::prepare_idle(hints);
    if !plan.polls() || matches!(plan.state().entry, IdleEntry::Poll) {
        return TestResult::Skip("this CPU's C1 is not an MWAIT polling idle (no usable MWAIT)");
    }
    const ARMED: u32 = 1;
    let wake = core::sync::atomic::AtomicU32::new(ARMED | 2);
    let enabled = narf_arch::interrupts_enabled();
    let t0 = narf_time::now_cycles();
    // SAFETY: IRQs masked across the entry; the word already differs from
    // `ARMED`, so the post-MONITOR recheck returns without MWAIT.
    unsafe {
        narf_arch::disable_interrupts();
        let _ = executor::enter_idle(plan, &wake, ARMED);
        if enabled {
            narf_arch::enable_interrupts();
        }
    }
    let elapsed = narf_time::cycles_to_ns(narf_time::now_cycles().wrapping_sub(t0));
    // Generous bound: far below any tick period, far above a MONITOR + load.
    if elapsed > 500_000 {
        return TestResult::Fail("polling idle slept over a wake store made before MONITOR");
    }
    TestResult::Pass
}
kernel_test_in!("power/idle", idle_polling_entry_observes_prior_wake_store);

fn idle_stale_plan_does_not_enter() -> TestResult {
    let (cap, hints) = fixture();
    let plan = executor::prepare_idle(hints);
    executor::set_idle_latency_limit(&cap, hints.cpu, 0).unwrap();
    let enabled = narf_arch::interrupts_enabled();
    // SAFETY: stale-generation rejection must occur before any hardware entry.
    let entered = unsafe {
        narf_arch::disable_interrupts();
        let wake = core::sync::atomic::AtomicU32::new(0);
        let entered = executor::enter_idle(plan, &wake, 0);
        if enabled {
            narf_arch::enable_interrupts();
        }
        entered
    };
    init();
    if entered {
        TestResult::Fail("entered a stale idle plan")
    } else {
        TestResult::Pass
    }
}
kernel_test_in!("power/idle", idle_stale_plan_does_not_enter);
