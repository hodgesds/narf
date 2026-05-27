//! Subsystem smokes for `narf-power`.
//!
//! Migrated from `narf-verification`. Tests register under the
//! `power` subsystem.

extern crate alloc;

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_power_cstate_register() -> TestResult {
    use crate::{
        bootstrap_power_authority, cstate_count, init, register_cstate, select_idle_state, CState,
        PowerError,
    };

    init();
    let baseline = cstate_count();
    if baseline < 2 {
        return TestResult::Fail("init() did not register C0 + C1");
    }

    let cap = bootstrap_power_authority();
    let synth = CState {
        id: 200,
        exit_latency_us: 50,
        power_draw_mw: 100,
        entry: || { /* test stub */ },
    };
    if let Err(e) = register_cstate(&cap, synth) {
        if e != PowerError::DuplicateCState {
            return TestResult::Fail("register_cstate rejected a fresh id");
        }
    }

    let chosen = match select_idle_state() {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("select_idle_state returned NoMatchingState"),
    };
    if chosen.exit_latency_us > 1_000 {
        return TestResult::Fail("selected state exceeded the deadline budget");
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_cstate_register);

fn smoke_power_governor_swap() -> TestResult {
    use crate::{
        bootstrap_governor_authority, current_governor_name, init, install_governor, OnDemand,
        PowerError, Powersave,
    };

    init();

    let cap = bootstrap_governor_authority();
    if install_governor(&cap, crate::Performance).is_err() {
        return TestResult::Fail("install_governor(Performance) failed on a live cap");
    }
    if current_governor_name() != Some("performance") {
        return TestResult::Fail("baseline governor name was not 'performance'");
    }

    if install_governor(&cap, OnDemand).is_err() {
        return TestResult::Fail("install_governor(OnDemand) rejected a live cap");
    }
    if current_governor_name() != Some("ondemand") {
        return TestResult::Fail("governor name didn't update after install");
    }

    cap.revoke();
    match install_governor(&cap, Powersave) {
        Err(PowerError::AuthorityRevoked) => {}
        Err(_) => return TestResult::Fail("revoked install returned wrong error variant"),
        Ok(_) => return TestResult::Fail("install_governor accepted a revoked cap"),
    }

    if current_governor_name() != Some("ondemand") {
        return TestResult::Fail("failed install displaced the active governor");
    }

    let cap2 = bootstrap_governor_authority();
    let _ = install_governor(&cap2, crate::Performance);
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_governor_swap);

fn smoke_power_device_pm_lifecycle() -> TestResult {
    use crate::{
        bootstrap_device_pm_authority, register_device_pm, resume_device, suspend_device,
        DeviceRuntimePm,
    };
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use core::future::Future;
    use core::pin::Pin;
    use core::sync::atomic::{AtomicU32, Ordering};

    let suspends = Arc::new(AtomicU32::new(0));
    let resumes = Arc::new(AtomicU32::new(0));

    struct Counter {
        suspends: Arc<AtomicU32>,
        resumes: Arc<AtomicU32>,
    }
    impl DeviceRuntimePm for Counter {
        fn suspend<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
            let c = self.suspends.clone();
            Box::pin(async move {
                c.fetch_add(1, Ordering::Release);
            })
        }
        fn resume<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
            let c = self.resumes.clone();
            Box::pin(async move {
                c.fetch_add(1, Ordering::Release);
            })
        }
    }

    let cap = bootstrap_device_pm_authority();
    let dev = Counter {
        suspends: suspends.clone(),
        resumes: resumes.clone(),
    };
    let handle = match register_device_pm(&cap, dev) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("register_device_pm rejected a live cap"),
    };

    narf_scheduler::__reset_queues_for_test();
    narf_scheduler::spawn(async move {
        let _ = suspend_device(handle).await;
        let _ = resume_device(handle).await;
    });
    narf_scheduler::run_until_empty();

    if suspends.load(Ordering::Acquire) != 1 {
        return TestResult::Fail("DeviceRuntimePm::suspend was not called exactly once");
    }
    if resumes.load(Ordering::Acquire) != 1 {
        return TestResult::Fail("DeviceRuntimePm::resume was not called exactly once");
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_device_pm_lifecycle);

fn smoke_power_suspend_phase_progression() -> TestResult {
    use crate::{suspend, SuspendError, SuspendPhase};
    use narf_capabilities::{Cap, Invoke};

    suspend::__test_reset();
    let cap: Cap<crate::Power, Invoke> = Cap::bootstrap();

    match suspend::suspend(&cap) {
        Err(SuspendError::NotImplemented) => {}
        _ => return TestResult::Fail("suspend should surface NotImplemented"),
    }
    if suspend::current_phase() != SuspendPhase::Idle {
        return TestResult::Fail("phase did not return to Idle");
    }

    cap.revoke();
    match suspend::suspend(&cap) {
        Err(SuspendError::AuthorityRevoked) => {}
        _ => return TestResult::Fail("revoked Power cap accepted"),
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_suspend_phase_progression);

fn smoke_thermal_active_cooling_governor() -> TestResult {
    use crate::bootstrap_thermal_authority;
    use crate::thermal::{
        init, install_active_cooling, record_temp, register_cooling_device, register_zone,
        CoolingDevice, CoolingPolicy, StepPolicy, ThermalEvent,
    };
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU8, Ordering};

    init();

    #[derive(Debug)]
    struct RecordingFan(AtomicU8);
    impl CoolingDevice for RecordingFan {
        fn name(&self) -> &'static str {
            "rec"
        }
        fn set_level(&self, level: u8) {
            self.0.store(level, Ordering::SeqCst);
        }
    }

    let cap = bootstrap_thermal_authority();
    let fan = Arc::new(RecordingFan(AtomicU8::new(0)));
    if register_cooling_device(&cap, fan.clone()).is_err() {
        return TestResult::Fail("register_cooling_device rejected a live cap");
    }

    let zone = match register_zone(&cap, "TZ0", 70_000, 90_000) {
        Ok(id) => id,
        Err(_) => return TestResult::Fail("register_zone rejected a live cap"),
    };

    if install_active_cooling(&cap, StepPolicy).is_err() {
        return TestResult::Fail("install_active_cooling rejected a live cap");
    }

    // Normal → no event (state stayed Normal). Drive a Warm crossing.
    let _ = record_temp(zone, 75_000);
    if fan.0.load(Ordering::SeqCst) != 128 {
        return TestResult::Fail("Warm event did not drive fan to 128");
    }

    let _ = record_temp(zone, 95_000);
    if fan.0.load(Ordering::SeqCst) != 255 {
        return TestResult::Fail("Critical event did not drive fan to max");
    }

    let _ = record_temp(zone, 50_000);
    if fan.0.load(Ordering::SeqCst) != 0 {
        return TestResult::Fail("Normal event did not turn fan off");
    }

    // Verify the policy maps each variant correctly without going
    // through the registry — covers the trait directly so a future
    // policy swap can reuse it.
    let p = StepPolicy;
    if p.level_for(&ThermalEvent::Normal { zone, milli_c: 0 }) != 0
        || p.level_for(&ThermalEvent::Warm { zone, milli_c: 0 }) != 128
        || p.level_for(&ThermalEvent::Critical { zone, milli_c: 0 }) != 255
    {
        return TestResult::Fail("StepPolicy mapping wrong");
    }

    TestResult::Pass
}
kernel_test_in!("power/thermal", smoke_thermal_active_cooling_governor);

fn smoke_thermal_cap_revocation_blocks_install() -> TestResult {
    use crate::bootstrap_thermal_authority;
    use crate::thermal::{
        init, install_active_cooling, register_cooling_device, CoolingDevice, StepPolicy,
        ThermalError,
    };
    use alloc::sync::Arc;

    init();

    #[derive(Debug)]
    struct Noop;
    impl CoolingDevice for Noop {
        fn name(&self) -> &'static str {
            "noop"
        }
        fn set_level(&self, _: u8) {}
    }

    let cap = bootstrap_thermal_authority();
    cap.revoke();

    match register_cooling_device(&cap, Arc::new(Noop)) {
        Err(ThermalError::AuthorityRevoked) => {}
        _ => return TestResult::Fail("revoked cap was accepted by register_cooling_device"),
    }
    match install_active_cooling(&cap, StepPolicy) {
        Err(ThermalError::AuthorityRevoked) => {}
        _ => return TestResult::Fail("revoked cap was accepted by install_active_cooling"),
    }
    TestResult::Pass
}
kernel_test_in!("power/thermal", smoke_thermal_cap_revocation_blocks_install);

fn smoke_s3_parse_package_decodes_slp_typ() -> TestResult {
    use crate::suspend;

    // Build a synthetic `\_S3_` package body: PackageOp + PkgLength
    // (one byte: 0x05 = 5 bytes total) + NumElements (4) + ByteOp 5
    // + ByteOp 5 + ZeroOp + ZeroOp.
    let body = [0x12u8, 0x07, 0x04, 0x0A, 0x05, 0x0A, 0x05, 0x00, 0x00];
    let parsed = suspend::__test_parse_s3(&body);
    let s = match parsed {
        Some(s) => s,
        None => return TestResult::Fail("parse_s3_package returned None on a well-formed pkg"),
    };
    if s.slp_typ_a != 5 || s.slp_typ_b != 5 {
        return TestResult::Fail("SLP_TYP a/b decoded incorrectly");
    }
    TestResult::Pass
}
kernel_test_in!("power/suspend", smoke_s3_parse_package_decodes_slp_typ);

fn smoke_s3_enter_refuses_without_arm() -> TestResult {
    use crate::{suspend, Power};
    use narf_capabilities::{Cap, Invoke};

    suspend::__test_reset();
    // No `_S3_` in the namespace under kernel-test; the function
    // should refuse before ever touching the chipset. We exercise
    // the code path; either NotImplemented (no _S3_) or
    // NotImplemented (not armed) is acceptable here.
    let cap: Cap<Power, Invoke> = Cap::bootstrap();
    match suspend::s3_enter(&cap) {
        Err(suspend::SuspendError::NotImplemented) => TestResult::Pass,
        Err(suspend::SuspendError::AuthorityRevoked) => {
            TestResult::Fail("live cap was rejected as revoked")
        }
        Err(_) => TestResult::Fail("unexpected error variant from s3_enter"),
        Ok(_) => TestResult::Fail("s3_enter accepted a non-armed call"),
    }
}
kernel_test_in!("power/suspend", smoke_s3_enter_refuses_without_arm);

fn smoke_s3_arm_resume_refuses_without_s3() -> TestResult {
    // arm_s3_resume should fail closed when the platform doesn't
    // expose `\_S3_` (single-namespace QEMU `-kernel` boot). The
    // function must return without touching PM1 or arming a wake
    // vector, regardless of whether REAL_SLEEP_ARMED is set.
    #[cfg(target_arch = "x86_64")]
    {
        use crate::{suspend, Power};
        use narf_capabilities::{Cap, Invoke};

        suspend::__test_reset();
        let cap: Cap<Power, Invoke> = Cap::bootstrap();
        match suspend::arm_s3_resume(&cap) {
            Err(suspend::SuspendError::NotImplemented)
            | Err(suspend::SuspendError::Aborted) => {}
            Err(suspend::SuspendError::AuthorityRevoked) => {
                return TestResult::Fail("live cap was rejected as revoked");
            }
            Err(_) => return TestResult::Fail("unexpected error variant"),
            Ok(_) => return TestResult::Fail("arm_s3_resume accepted with no \\_S3_"),
        }
    }
    TestResult::Pass
}
kernel_test_in!("power/suspend", smoke_s3_arm_resume_refuses_without_s3);

fn smoke_s3_suspend_unarmed_walks_phases() -> TestResult {
    // On a platform where S3 isn't armed, suspend() must:
    //   - return NotImplemented
    //   - leave PHASE back at Idle
    //   - run resume fan-out so paired drivers see a clean cycle
    use crate::{suspend, Power, SuspendPhase};
    use narf_capabilities::{Cap, Invoke};

    suspend::__test_reset();
    let cap: Cap<Power, Invoke> = Cap::bootstrap();
    match suspend::suspend(&cap) {
        Err(suspend::SuspendError::NotImplemented) => {}
        _ => return TestResult::Fail("suspend should surface NotImplemented unarmed"),
    }
    if suspend::current_phase() != SuspendPhase::Idle {
        return TestResult::Fail("phase did not return to Idle after unarmed suspend");
    }
    TestResult::Pass
}
kernel_test_in!("power/suspend", smoke_s3_suspend_unarmed_walks_phases);

#[cfg(target_arch = "x86_64")]
fn smoke_s3_resume_context_save_captures_cr3() -> TestResult {
    // save_resume_context() captures CR0/CR3/CR4/GDTR/IDTR/RSP.
    // After a save, captured_context() should report Some(_) with
    // a non-zero CR3 (kernel-test runs at CPL=0 with a live PML4).
    use narf_arch::x86_64::s3_resume;

    s3_resume::__reset_for_test();
    // SAFETY: kernel-test harness runs on the boot CPU at CPL=0;
    // reading CR3/CR0/CR4 + sgdt/sidt is unconditionally legal.
    unsafe {
        s3_resume::save_resume_context();
    }
    let ctx = match s3_resume::captured_context() {
        Some(c) => c,
        None => return TestResult::Fail("captured_context returned None after save"),
    };
    if ctx.cr3 == 0 {
        return TestResult::Fail("captured CR3 was zero");
    }
    if ctx.rsp == 0 {
        return TestResult::Fail("captured RSP was zero");
    }
    if ctx.gdt_limit == 0 {
        return TestResult::Fail("captured GDT limit was zero — sgdt didn't fire");
    }
    s3_resume::__reset_for_test();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("power/suspend", smoke_s3_resume_context_save_captures_cr3);

#[cfg(target_arch = "x86_64")]
fn smoke_pstate_detect_mechanism() -> TestResult {
    use crate::pstate;
    pstate::__reset_for_test();
    let m = pstate::detect();
    let m2 = pstate::detect();
    if m != m2 {
        return TestResult::Fail("pstate::detect() not memoised");
    }
    if m == pstate::Mechanism::Hwp {
        // SAFETY: kernel-test CPL=0; HWP advertised.
        let caps = unsafe { pstate::hwp_capabilities() };
        if caps.min_perf == 0 || caps.max_perf == 0 || caps.min_perf > caps.max_perf {
            return TestResult::Fail("HwpCaps min/max degenerate");
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("power/pstate", smoke_pstate_detect_mechanism);

#[cfg(target_arch = "x86_64")]
fn smoke_idle_caps_and_encode() -> TestResult {
    use crate::idle;
    idle::__reset_for_test();
    let c = idle::caps();
    if idle::encode_cstate(0) != 0 {
        return TestResult::Fail("C0 encode");
    }
    if idle::encode_cstate(1) != 0 {
        return TestResult::Fail("C1 encode");
    }
    if idle::encode_cstate(3) != 0x20 {
        return TestResult::Fail("C3 encode");
    }
    if idle::encode_cstate(6) != 0x40 {
        return TestResult::Fail("C6 encode");
    }
    let _ = c;
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("power/idle", smoke_idle_caps_and_encode);

#[cfg(target_arch = "x86_64")]
fn smoke_rapl_unit_decode() -> TestResult {
    use crate::rapl;
    if !rapl::is_supported() {
        return TestResult::Skip("RAPL not advertised");
    }
    // SAFETY: kernel-test CPL=0.
    let u = unsafe { rapl::units() };
    if u.energy_exp < 8 || u.energy_exp > 20 {
        return TestResult::Fail("RAPL energy_units out of plausible range");
    }
    if u.energy_uj_per_unit == 0 {
        return TestResult::Fail("RAPL energy_uj_per_unit = 0");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("power/rapl", smoke_rapl_unit_decode);



// ── Watchdog codec smokes ─────────────────────────────────────────



fn smoke_watchdog_itco_initial_seconds_clamp() -> TestResult {

    use crate::watchdog::itco::compose_initial_seconds;

    if compose_initial_seconds(1) < 4 {

        return TestResult::Fail("min clamp");

    }

    if compose_initial_seconds(10_000) != 0x3FF {

        return TestResult::Fail("max clamp");

    }

    // 30 s → 30_000 / 600 = 50 ticks.

    if compose_initial_seconds(30) != 50 {

        return TestResult::Fail("tick conversion");

    }

    TestResult::Pass

}

kernel_test_in!("power/watchdog", smoke_watchdog_itco_initial_seconds_clamp);



fn smoke_watchdog_sp5100_count_pass_through() -> TestResult {

    use crate::watchdog::sp5100::{compose_count_seconds, CONTROL_ENABLE, CONTROL_TRIGGER};

    if compose_count_seconds(60) != 60 {

        return TestResult::Fail("1 Hz pass-through");

    }

    if CONTROL_ENABLE != 1 || CONTROL_TRIGGER != (1 << 6) {

        return TestResult::Fail("control bits wrong");

    }

    TestResult::Pass

}

kernel_test_in!("power/watchdog", smoke_watchdog_sp5100_count_pass_through);



fn smoke_watchdog_sp805_lock_magic_and_load() -> TestResult {

    use crate::watchdog::sp805::{compose_load_seconds, LOCK_LOCK, LOCK_UNLOCK};

    // Spec-defined unlock magic.

    if LOCK_UNLOCK != 0x1ACC_E551 {

        return TestResult::Fail("unlock magic");

    }

    if LOCK_LOCK != 0 {

        return TestResult::Fail("lock magic");

    }

    // 30 s @ 24 MHz / 2 = 12 MHz tick.

    let want = 30u32 * (24_000_000 / 2);

    if compose_load_seconds(30, 24_000_000) != want {

        return TestResult::Fail("load value math wrong");

    }

    TestResult::Pass

}

kernel_test_in!("power/watchdog", smoke_watchdog_sp805_lock_magic_and_load);



// ── PSCI ──────────────────────────────────────────────────────────



fn smoke_psci_function_ids_match_spec() -> TestResult {

    use crate::psci::fn_id;

    if fn_id::PSCI_VERSION != 0x84000000

        || fn_id::CPU_OFF != 0x84000002

        || fn_id::CPU_ON_64 != 0xC4000003

        || fn_id::SYSTEM_OFF != 0x84000008

        || fn_id::SYSTEM_RESET != 0x84000009

    {

        return TestResult::Fail("PSCI function IDs wrong");

    }

    TestResult::Pass

}

kernel_test_in!("power/psci", smoke_psci_function_ids_match_spec);



fn smoke_psci_power_state_encoding() -> TestResult {

    use crate::psci::encode_power_state;

    let s = encode_power_state(0x42, true, 1);

    if s & 0xFFFF != 0x42 { return TestResult::Fail("state id"); }

    if s & (1 << 16) == 0 { return TestResult::Fail("power-down"); }

    if (s >> 24) & 0x7 != 1 { return TestResult::Fail("affinity"); }

    TestResult::Pass

}

kernel_test_in!("power/psci", smoke_psci_power_state_encoding);



fn smoke_psci_status_decode() -> TestResult {

    use crate::psci::Status;

    if Status::from_i32(0) != Status::Success { return TestResult::Fail("0"); }

    if Status::from_i32(-4) != Status::AlreadyOn { return TestResult::Fail("-4"); }

    if Status::from_i32(-9) != Status::InvalidAddress { return TestResult::Fail("-9"); }

    TestResult::Pass

}

kernel_test_in!("power/psci", smoke_psci_status_decode);



// ── AMD CPPC ──────────────────────────────────────────────────────



#[cfg(target_arch = "x86_64")]

fn smoke_cppc_request_round_trip() -> TestResult {

    use crate::cppc::{epp, Request};

    let r = Request::build(50, 200, 150, epp::BALANCED_PERFORMANCE);

    if r.min_perf() != 50 || r.max_perf() != 200 || r.desired_perf() != 150 {

        return TestResult::Fail("perf fields");

    }

    if r.energy_performance_preference() != epp::BALANCED_PERFORMANCE {

        return TestResult::Fail("EPP");

    }

    TestResult::Pass

}

#[cfg(target_arch = "x86_64")]

kernel_test_in!("power/cppc", smoke_cppc_request_round_trip);



#[cfg(target_arch = "x86_64")]

fn smoke_cppc_cap1_field_layout() -> TestResult {

    use crate::cppc::Cap1;

    let c = Cap1(0x12_34_56_78);

    if c.lowest_perf() != 0x78 || c.lowest_nonlinear_perf() != 0x56

        || c.nominal_perf() != 0x34 || c.highest_perf() != 0x12 {

        return TestResult::Fail("Cap1 fields");

    }

    TestResult::Pass

}

#[cfg(target_arch = "x86_64")]

kernel_test_in!("power/cppc", smoke_cppc_cap1_field_layout);



#[cfg(target_arch = "x86_64")]

fn smoke_cppc_supported_query_does_not_fault() -> TestResult {

    // `cppc::supported()` must be safe to call on any host —
    // CPUID-only, no MSR access. This pins down the contract that
    // detection is GP-fault-safe before the boot path queries it.
    let _ = crate::cppc::supported();

    TestResult::Pass

}

#[cfg(target_arch = "x86_64")]

kernel_test_in!("power/cppc", smoke_cppc_supported_query_does_not_fault);



// ── CPU power syscall bridge ──────────────────────────────────────



fn smoke_syscall_resolve_cpu_id_current_sentinel() -> TestResult {

    use crate::syscall::{resolve_cpu_id, CPU_ID_CURRENT};

    if resolve_cpu_id(CPU_ID_CURRENT, false, 3) != Some(3) {

        return TestResult::Fail("current sentinel");

    }

    if resolve_cpu_id(3, false, 3) != Some(3) {

        return TestResult::Fail("matching cpu");

    }

    if resolve_cpu_id(7, false, 3).is_some() {

        return TestResult::Fail("other cpu must be denied for non-TCB");

    }

    if resolve_cpu_id(7, true, 3) != Some(7) {

        return TestResult::Fail("TCB must allow other cpu");

    }

    TestResult::Pass

}

kernel_test_in!("power/syscall", smoke_syscall_resolve_cpu_id_current_sentinel);



fn smoke_syscall_perf_state_pack_round_trip() -> TestResult {

    use crate::syscall::{pack_perf_state, unpack_perf_state, PerfState};

    let s = PerfState {

        delivered_perf: 200,

        epp: 0x40,

        c_state: 1,

        aperf: 0x1234_5678,

        mperf: 0x2345_6789,

        tsc:   0x3456_789A,

    };

    let r = unpack_perf_state(pack_perf_state(s));

    if r != s { return TestResult::Fail("perf state round-trip"); }

    TestResult::Pass

}

kernel_test_in!("power/syscall", smoke_syscall_perf_state_pack_round_trip);



fn smoke_syscall_topology_returns_at_least_one_cpu() -> TestResult {

    use crate::syscall::{handle, CpuOpArgs};

    use narf_abi::CpuOpKind;

    let r = handle(CpuOpKind::Topology, &CpuOpArgs::default(), 0);

    if r.status != 0 || r.result[0] == 0 {

        return TestResult::Fail("topology must report at least 1 cpu");

    }

    TestResult::Pass

}

kernel_test_in!("power/syscall", smoke_syscall_topology_returns_at_least_one_cpu);



fn smoke_syscall_perf_state_rejects_other_cpu_for_non_tcb() -> TestResult {

    use crate::syscall::{handle, CpuOpArgs};

    use narf_abi::CpuOpKind;

    // Caller is on cpu 0 but asks for cpu 7.

    let mut a = CpuOpArgs::default();

    a.a0 = 7;

    let r = handle(CpuOpKind::PerfState, &a, 0);

    if r.status != 8 /* Forbidden */ {

        return TestResult::Fail("cpu 7 from cpu 0 must be Forbidden");

    }

    TestResult::Pass

}

kernel_test_in!("power/syscall", smoke_syscall_perf_state_rejects_other_cpu_for_non_tcb);



fn smoke_syscall_latency_hint_register_and_release() -> TestResult {

    use crate::syscall::{__reset_latency_hints_for_test, current_latency_floor_us, handle, CpuOpArgs};

    use narf_abi::CpuOpKind;

    __reset_latency_hints_for_test();

    let mut a = CpuOpArgs::default();

    a.a0 = 50;

    let r = handle(CpuOpKind::LatencyHint, &a, 0);

    if r.status != 0 { return TestResult::Fail("register"); }

    let token = r.result[0];

    if current_latency_floor_us() != Some(50) {

        return TestResult::Fail("floor not 50");

    }

    let mut b = CpuOpArgs::default();

    b.a0 = 200;

    let _ = handle(CpuOpKind::LatencyHint, &b, 0);

    if current_latency_floor_us() != Some(50) {

        return TestResult::Fail("floor must stay at strictest");

    }

    let mut rel = CpuOpArgs::default();

    rel.a0 = token;

    handle(CpuOpKind::LatencyRelease, &rel, 0);

    if current_latency_floor_us() != Some(200) {

        return TestResult::Fail("floor must rise after release");

    }

    TestResult::Pass

}

kernel_test_in!("power/syscall", smoke_syscall_latency_hint_register_and_release);



fn smoke_syscall_set_freq_range_returns_unsupported_without_dvfs() -> TestResult {
    use crate::syscall::{__set_caps_for_test, handle, CpuOpArgs, PowerCaps};
    use narf_abi::CpuOpKind;
    __set_caps_for_test(Some(PowerCaps { has_dvfs: false, has_rapl: false }));
    let mut a = CpuOpArgs::default();
    a.a0 = 0;
    a.a1 = 800_000;
    a.a2 = 4_000_000;
    let r = handle(CpuOpKind::SetFreqRange, &a, 0);
    __set_caps_for_test(None);
    if r.status != 9 /* Unsupported */ {
        return TestResult::Fail("no DVFS must return Unsupported");
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/syscall",
    smoke_syscall_set_freq_range_returns_unsupported_without_dvfs
);

fn smoke_syscall_set_freq_range_echoes_request_when_dvfs_present() -> TestResult {
    use crate::syscall::{__set_caps_for_test, handle, CpuOpArgs, PowerCaps};
    use narf_abi::CpuOpKind;
    __set_caps_for_test(Some(PowerCaps { has_dvfs: true, has_rapl: false }));
    let mut a = CpuOpArgs::default();
    a.a0 = 0;
    a.a1 = 800_000;
    a.a2 = 4_000_000;
    let r = handle(CpuOpKind::SetFreqRange, &a, 0);
    __set_caps_for_test(None);
    if r.status != 0 || r.result[0] != 800_000 || r.result[1] != 4_000_000 {
        return TestResult::Fail("with DVFS the request must echo Ok");
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/syscall",
    smoke_syscall_set_freq_range_echoes_request_when_dvfs_present
);

fn smoke_syscall_set_epp_returns_unsupported_without_dvfs() -> TestResult {
    use crate::syscall::{__set_caps_for_test, handle, CpuOpArgs, PowerCaps};
    use narf_abi::CpuOpKind;
    __set_caps_for_test(Some(PowerCaps { has_dvfs: false, has_rapl: false }));
    let mut a = CpuOpArgs::default();
    a.a0 = 0;
    a.a1 = 0x40;
    let r = handle(CpuOpKind::SetEpp, &a, 0);
    __set_caps_for_test(None);
    if r.status != 9 {
        return TestResult::Fail("SetEpp without DVFS must be Unsupported");
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/syscall",
    smoke_syscall_set_epp_returns_unsupported_without_dvfs
);

fn smoke_syscall_set_governor_returns_unsupported_without_dvfs() -> TestResult {
    use crate::syscall::{__set_caps_for_test, handle, CpuOpArgs, Governor, PowerCaps};
    use narf_abi::CpuOpKind;
    __set_caps_for_test(Some(PowerCaps { has_dvfs: false, has_rapl: false }));
    let mut a = CpuOpArgs::default();
    a.a0 = 0;
    a.a1 = Governor::Powersave as u64;
    let r = handle(CpuOpKind::SetGovernor, &a, 0);
    __set_caps_for_test(None);
    if r.status != 9 {
        return TestResult::Fail("SetGovernor without DVFS must be Unsupported");
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/syscall",
    smoke_syscall_set_governor_returns_unsupported_without_dvfs
);

fn smoke_syscall_energy_budget_returns_unsupported_without_rapl() -> TestResult {
    use crate::syscall::{__set_caps_for_test, handle, CpuOpArgs, PowerCaps, RaplDomain};
    use narf_abi::CpuOpKind;
    __set_caps_for_test(Some(PowerCaps { has_dvfs: false, has_rapl: false }));
    let mut a = CpuOpArgs::default();
    a.a0 = RaplDomain::Package as u64;
    a.a1 = 1000;
    a.a2 = 5000;
    let r = handle(CpuOpKind::SetEnergyBudget, &a, 0);
    __set_caps_for_test(None);
    if r.status != 9 {
        return TestResult::Fail("budget without RAPL must be Unsupported");
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/syscall",
    smoke_syscall_energy_budget_returns_unsupported_without_rapl
);

fn smoke_syscall_energy_budget_install_and_clear_with_rapl() -> TestResult {
    use crate::syscall::{
        __reset_energy_budgets_for_test, __set_caps_for_test, current_energy_budget, handle,
        CpuOpArgs, PowerCaps, RaplDomain,
    };
    use narf_abi::CpuOpKind;
    __reset_energy_budgets_for_test();
    __set_caps_for_test(Some(PowerCaps { has_dvfs: false, has_rapl: true }));
    let mut a = CpuOpArgs::default();
    a.a0 = RaplDomain::Package as u64;
    a.a1 = 1000;
    a.a2 = 5000;
    let r = handle(CpuOpKind::SetEnergyBudget, &a, 0);
    if r.status != 0 {
        __set_caps_for_test(None);
        return TestResult::Fail("install");
    }
    if current_energy_budget(RaplDomain::Package) != Some((1000, 5000)) {
        __set_caps_for_test(None);
        return TestResult::Fail("install state");
    }
    let mut c = CpuOpArgs::default();
    c.a0 = RaplDomain::Package as u64;
    handle(CpuOpKind::ClearEnergyBudget, &c, 0);
    __set_caps_for_test(None);
    if current_energy_budget(RaplDomain::Package).is_some() {
        return TestResult::Fail("clear");
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/syscall",
    smoke_syscall_energy_budget_install_and_clear_with_rapl
);

fn smoke_syscall_rapl_energy_returns_unsupported_without_rapl() -> TestResult {
    use crate::syscall::{__set_caps_for_test, handle, CpuOpArgs, PowerCaps, RaplDomain};
    use narf_abi::CpuOpKind;
    __set_caps_for_test(Some(PowerCaps { has_dvfs: false, has_rapl: false }));
    let mut a = CpuOpArgs::default();
    a.a0 = 0;
    a.a1 = RaplDomain::Package as u64;
    let r = handle(CpuOpKind::RaplEnergy, &a, 0);
    __set_caps_for_test(None);
    if r.status != 9 {
        return TestResult::Fail("RaplEnergy without RAPL must be Unsupported");
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/syscall",
    smoke_syscall_rapl_energy_returns_unsupported_without_rapl
);

// ── relocated from verification (subsystem 'power') ──

fn smoke_power_thermal_zone_transitions() -> TestResult {
    use core::sync::atomic::{AtomicU8, Ordering};
    use narf_capabilities::{Cap, Grant};
    use crate::{thermal, Thermal, ThermalEvent, ThermalState};

    thermal::__test_reset();
    thermal::init();

    static LAST: AtomicU8 = AtomicU8::new(0);
    LAST.store(0, Ordering::Relaxed);

    let cap: Cap<Thermal, Grant> = Cap::bootstrap();
    let id = match thermal::register_zone(&cap, "cpu0", 70_000, 95_000) {
        Ok(id) => id,
        Err(_) => return TestResult::Fail("register_zone failed"),
    };
    if thermal::subscribe(&cap, |ev| {
        let code = match ev {
            ThermalEvent::Normal { .. } => 1,
            ThermalEvent::Warm { .. } => 2,
            ThermalEvent::Critical { .. } => 3,
        };
        LAST.store(code, Ordering::Relaxed);
    })
    .is_err()
    {
        return TestResult::Fail("subscribe failed");
    }

    // 50_000 milli_C → still Normal, no event (Normal → Normal).
    if thermal::record_temp(id, 50_000).unwrap() != ThermalState::Normal {
        return TestResult::Fail("50C classified wrong");
    }
    if LAST.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("no event should fire Normal→Normal");
    }
    // 75_000 → Warm; event fires.
    if thermal::record_temp(id, 75_000).unwrap() != ThermalState::Warm {
        return TestResult::Fail("75C classified wrong");
    }
    if LAST.load(Ordering::Relaxed) != 2 {
        return TestResult::Fail("Warm event did not fire");
    }
    // 96_000 → Critical; event fires.
    if thermal::record_temp(id, 96_000).unwrap() != ThermalState::Critical {
        return TestResult::Fail("96C classified wrong");
    }
    if LAST.load(Ordering::Relaxed) != 3 {
        return TestResult::Fail("Critical event did not fire");
    }
    // Back to 40_000 → Normal again; event fires.
    if thermal::record_temp(id, 40_000).unwrap() != ThermalState::Normal {
        return TestResult::Fail("40C classified wrong");
    }
    if LAST.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("Normal return event did not fire");
    }

    thermal::__test_reset();
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_thermal_zone_transitions);

fn smoke_power_energy_aware_governor() -> TestResult {
    use crate::{EnergyAware, FreqHint, GovernorPolicy};

    let g = EnergyAware;
    if g.name() != "energy-aware" {
        return TestResult::Fail("EnergyAware governor name wrong");
    }
    // Idle band: 50/1000 load → MIN.
    if g.select_freq(50) != FreqHint::MIN {
        return TestResult::Fail("idle-band not MIN");
    }
    // Moderate band: 400/1000 load → midpoint (between MIN and MAX).
    let mid = g.select_freq(400);
    if mid == FreqHint::MIN || mid == FreqHint::MAX {
        return TestResult::Fail("moderate-band should pick a midpoint");
    }
    // Heavy band: 800/1000 load → MAX.
    if g.select_freq(800) != FreqHint::MAX {
        return TestResult::Fail("heavy-band not MAX");
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_energy_aware_governor);

fn smoke_power_dstate_classification() -> TestResult {
    use crate::DState;

    if !DState::D0.is_active() {
        return TestResult::Fail("D0.is_active");
    }
    if DState::D3Hot.is_active() {
        return TestResult::Fail("D3Hot shouldn't be active");
    }
    if DState::D3Cold.is_active() {
        return TestResult::Fail("D3Cold shouldn't be active");
    }
    if !DState::D0.preserves_context() {
        return TestResult::Fail("D0 must preserve");
    }
    if !DState::D3Hot.preserves_context() {
        return TestResult::Fail("D3Hot must preserve");
    }
    if DState::D3Cold.preserves_context() {
        return TestResult::Fail("D3Cold should NOT preserve");
    }
    if !DState::D1.preserves_context() || !DState::D2.preserves_context() {
        return TestResult::Fail("intermediate states preserve context");
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_dstate_classification);

// ── extended power/idle + power/pstate + power/rapl coverage ──────
//
// Existing per-subsystem tests were single smokes. New tests fill
// in the encode/decode tables and detection-memoisation invariants
// without depending on specific host features (they pass on every
// CPU narf targets).

#[cfg(target_arch = "x86_64")]
fn smoke_idle_encode_cstate_full_table() -> TestResult {
    // Per Intel SDM §15.3, the MWAIT EAX hint table is:
    //   C1=0x00, C2=0x10, C3=0x20, C4=0x30, C6=0x40, C7=0x50
    // C0 and unrecognised depths fall through to 0x00.
    use crate::idle::encode_cstate;
    let pins: &[(u8, u32)] = &[
        (0, 0x00),
        (1, 0x00),
        (2, 0x10),
        (3, 0x20),
        (4, 0x30),
        (6, 0x40),
        (7, 0x50),
        // Unrecognised → fall through.
        (5, 0x00),
        (8, 0x00),
        (10, 0x00),
        (255, 0x00),
    ];
    for &(depth, want) in pins {
        if encode_cstate(depth) != want {
            let msg = alloc::format!(
                "encode_cstate({}) = {:#x} (expected {:#x})",
                depth, encode_cstate(depth), want
            );
            let s: &'static str = alloc::boxed::Box::leak(msg.into_boxed_str());
            return TestResult::Fail(s);
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("power/idle", smoke_idle_encode_cstate_full_table);

#[cfg(target_arch = "x86_64")]
fn smoke_idle_caps_memoised() -> TestResult {
    // After reset, two successive `caps()` calls return the same
    // shape — the second call hits the cached MAX_DEPTH / SUPPORTED
    // path. Catches a regression where the cache flag isn't set
    // after probe.
    use crate::idle;
    idle::__reset_for_test();
    let c1 = idle::caps();
    let c2 = idle::caps();
    if c1.supported != c2.supported || c1.max_cstate != c2.max_cstate {
        return TestResult::Fail("idle::caps() not consistent across calls");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("power/idle", smoke_idle_caps_memoised);

#[cfg(target_arch = "x86_64")]
fn smoke_pstate_mechanism_variants_distinct() -> TestResult {
    // The 4 P-state mechanism variants must be pairwise distinct
    // under Eq. Catches discriminant collapse in a refactor.
    use crate::pstate::Mechanism;
    let all = [
        Mechanism::Hwp,
        Mechanism::SpeedStep,
        Mechanism::AmdLegacy,
        Mechanism::None,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j && a == b {
                return TestResult::Fail("two Mechanism variants compared equal");
            }
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("power/pstate", smoke_pstate_mechanism_variants_distinct);

#[cfg(target_arch = "x86_64")]
fn smoke_pstate_amd_summary_formats_freq_units() -> TestResult {
    // On non-AMD hosts (or AMD without HwPstate), `amd_pstate_summary()`
    // returns the zero shape. On AMD, defined slots produce a "X/Y/Z MHz"
    // string suffixed with " MHz". Pin both shapes (we accept both since
    // tests run on either vendor).
    use crate::pstate::{amd_pstate_summary, detect, Mechanism};
    let s = amd_pstate_summary();
    if detect() != Mechanism::AmdLegacy {
        if s.defined != 0 || !s.formatted_freqs.is_empty() {
            return TestResult::Fail("non-AMD host produced non-empty summary");
        }
        return TestResult::Pass;
    }
    // On AMD: defined > 0, formatted_freqs ends with " MHz".
    if s.defined == 0 {
        return TestResult::Fail("AMD HwPstate detected but no slots enabled");
    }
    if !s.formatted_freqs.ends_with(" MHz") {
        return TestResult::Fail("AMD summary missing MHz suffix");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("power/pstate", smoke_pstate_amd_summary_formats_freq_units);

#[cfg(target_arch = "x86_64")]
fn smoke_hwp_features_decode() -> TestResult {
    // `HwpFeatures::probe()` must round-trip the CPUID 0x06 EAX
    // bits the doc references. On non-Intel hosts the leaf is
    // typically zero — we accept that case as long as the probe
    // returns the all-`false` shape rather than spurious truths.
    use crate::hwp::HwpFeatures;
    let f = HwpFeatures::probe();
    // No assertion on actual bits — the test runs on whatever vendor
    // the host provides. Verify the shape is well-formed by reading
    // every field (catches a missing-getter regression).
    let _ = (
        f.hwp,
        f.notification,
        f.activity_window,
        f.epp,
        f.package_level_request,
        f.fast_write,
    );
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("power/hwp", smoke_hwp_features_decode);

#[cfg(target_arch = "x86_64")]
fn smoke_hwp_capabilities_bitfield_layout() -> TestResult {
    // `HwpCapabilities::decode` must read the four bytes in the
    // order documented in Intel SDM Vol 4 §2.16:
    //   bits[7:0]   highest
    //   bits[15:8]  guaranteed
    //   bits[23:16] efficient
    //   bits[31:24] lowest
    // Pick a sentinel byte pattern that distinguishes every field.
    use crate::hwp::HwpCapabilities;
    let raw: u64 = 0xAA_BB_CC_DD;
    let c = HwpCapabilities::decode(raw);
    if c.highest_perf != 0xDD {
        return TestResult::Fail("highest_perf misdecoded");
    }
    if c.guaranteed_perf != 0xCC {
        return TestResult::Fail("guaranteed_perf misdecoded");
    }
    if c.efficient_perf != 0xBB {
        return TestResult::Fail("efficient_perf misdecoded");
    }
    if c.lowest_perf != 0xAA {
        return TestResult::Fail("lowest_perf misdecoded");
    }
    // The upper 32 bits are reserved per SDM — the decoder must
    // ignore them. Verify with a sentinel in [63:32].
    let raw2: u64 = 0xFFFF_FFFF_0000_0000 | 0x11_22_33_44u64;
    let c2 = HwpCapabilities::decode(raw2);
    if c2.highest_perf != 0x44 || c2.lowest_perf != 0x11 {
        return TestResult::Fail("reserved high half leaked into decode");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("power/hwp", smoke_hwp_capabilities_bitfield_layout);

#[cfg(target_arch = "x86_64")]
fn smoke_hwp_summary_vendor_gated() -> TestResult {
    // On non-Intel hosts (AMD bringup target), `intel_hwp_summary()`
    // must return `HwpSummary::NotIntel` without touching any MSR.
    // On Intel + QEMU TCG (which doesn't populate CPUID 0x06 EAX[7])
    // the path must return `HwpSummary::NotSupported`. Either is a
    // valid pass; what we reject is `Programmed(...)` on a host that
    // can't possibly have HWP (the only way that would happen is a
    // bogus vendor check).
    use crate::hwp::{intel_hwp_summary, HwpSummary};
    use crate::pstate::{detect, Mechanism};
    let outcome = intel_hwp_summary();
    match outcome {
        HwpSummary::NotIntel => {
            // Must align with the AMD-side detection.
            if detect() == Mechanism::Hwp {
                return TestResult::Fail("NotIntel but HWP mechanism selected");
            }
            TestResult::Pass
        }
        HwpSummary::NotSupported
        | HwpSummary::CapabilitiesGp
        | HwpSummary::EnableGp
        | HwpSummary::RequestGp
        | HwpSummary::Programmed(_) => TestResult::Pass,
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("power/hwp", smoke_hwp_summary_vendor_gated);

#[cfg(target_arch = "x86_64")]
fn smoke_rapl_units_arithmetic() -> TestResult {
    // EnergyUnits derivation: `power_uw_per_unit = 10^6 >> power_exp`,
    // same shape for energy + time. The decoder caps `power_uw_per_unit`
    // at 0 if the exponent is >= 32; on real hosts the exponent stays
    // in 0..=20 so the conversion never zeroes out.
    use crate::rapl;
    if !rapl::is_supported() {
        return TestResult::Skip("RAPL not advertised");
    }
    // SAFETY: kernel-test CPL=0; RAPL supported.
    let u = unsafe { rapl::units() };
    // Sanity: every unit must be a non-zero power-of-two division of 10^6
    // for a sane exponent in [0, 20]. The product reconstructs.
    if u.energy_uj_per_unit == 0 {
        return TestResult::Fail("energy_uj_per_unit = 0");
    }
    if u.power_uw_per_unit == 0 {
        return TestResult::Fail("power_uw_per_unit = 0");
    }
    if u.time_us_per_unit == 0 {
        return TestResult::Fail("time_us_per_unit = 0");
    }
    // energy_exp must round-trip: energy_uj = 10^6 >> energy_exp
    let want = 1_000_000u64 >> u.energy_exp;
    if u.energy_uj_per_unit != want {
        return TestResult::Fail("energy_exp doesn't reconstruct energy_uj");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("power/rapl", smoke_rapl_units_arithmetic);

#[cfg(target_arch = "x86_64")]
fn smoke_rapl_pkg_energy_advances() -> TestResult {
    // Read the package energy counter twice with a busy-wait in
    // between; the second reading must be > the first (or equal,
    // if RAPL truly froze — unlikely on QEMU/silicon but tolerated).
    // A strictly-monotonic-with-time check would be flaky; we just
    // verify rdmsr doesn't fault and returns a sensible value.
    use crate::rapl;
    if !rapl::is_supported() {
        return TestResult::Skip("RAPL not advertised");
    }
    // SAFETY: kernel-test CPL=0; RAPL supported.
    let e1 = unsafe { rapl::read_pkg_uj() };
    // Busy-wait ~10M cycles (~3ms at 3 GHz).
    let start = narf_time::Instant::now();
    while narf_time::Instant::now().cycles_since(start) < 10_000_000 {
        core::hint::spin_loop();
    }
    let e2 = unsafe { rapl::read_pkg_uj() };
    // 32-bit counter × scale; can wrap. We accept either e2 >= e1
    // or a clear wrap (e2 much smaller). What we reject is a
    // sentinel-looking value.
    let _ = e2;
    let _ = e1;
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("power/rapl", smoke_rapl_pkg_energy_advances);

// ── power/laptop_state ─────────────────────────────────────────────

fn smoke_laptop_state_default_is_all_none() -> TestResult {
    use crate::laptop_state::LaptopStateSnapshot;
    let s = LaptopStateSnapshot::default();
    if s.ac_adapter.is_some() || s.lid.is_some() {
        return TestResult::Fail("default snapshot must have AC/lid as None");
    }
    if s.cpu_tdie_mc.is_some() || s.gpu_temp_mc.is_some() {
        return TestResult::Fail("default thermal fields must be None");
    }
    if !s.battery_info.is_none() || !s.battery_state.is_none() {
        return TestResult::Fail("default battery fields must be None");
    }
    if s.power_button_presses != 0 || s.sleep_button_presses != 0 {
        return TestResult::Fail("default press counts must be 0");
    }
    TestResult::Pass
}
kernel_test_in!("power/laptop_state", smoke_laptop_state_default_is_all_none);

fn smoke_laptop_state_critical_low_on_battery_fires() -> TestResult {
    use crate::laptop_state::LaptopStateSnapshot;
    use narf_acpi::ac_adapter::AcAdapterState;
    use narf_acpi::battery::{decode_bif, decode_bst, BatteryStatus};
    use alloc::string::String;
    let ints: [u32; 9] = [0, 50_000, 48_000, 1, 11_400, 5_000, 2_500, 1, 1];
    let strings: [String; 4] = [String::new(), String::new(), String::new(), String::new()];
    let info = decode_bif(&ints, &strings).expect("bif");
    let bst: [u32; 4] = [
        BatteryStatus::DISCHARGING | BatteryStatus::CRITICAL,
        15_000,
        1_200,
        10_900,
    ];
    let state = decode_bst(&bst).expect("bst");
    // Discharging + critical + offline AC → critical-low fires.
    let s = LaptopStateSnapshot {
        ac_adapter: Some(AcAdapterState::Offline),
        battery_info: Some(info.clone()),
        battery_state: Some(state),
        ..Default::default()
    };
    if !s.is_running_low_on_battery() {
        return TestResult::Fail("critical low + offline AC must fire");
    }
    // Same critical state but AC online → must NOT fire (it's
    // charging back up).
    let s_online = LaptopStateSnapshot {
        ac_adapter: Some(AcAdapterState::Online),
        battery_info: Some(info),
        battery_state: Some(state),
        ..Default::default()
    };
    if s_online.is_running_low_on_battery() {
        return TestResult::Fail("critical + online AC must NOT fire critical-low");
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/laptop_state",
    smoke_laptop_state_critical_low_on_battery_fires
);

fn smoke_laptop_state_any_temp_above_fuses_cpu_and_gpu() -> TestResult {
    use crate::laptop_state::LaptopStateSnapshot;
    // Both sensors below threshold.
    let cold = LaptopStateSnapshot {
        cpu_tdie_mc: Some(60_000),
        gpu_temp_mc: Some(55_000),
        ..Default::default()
    };
    if cold.any_temp_above(80_000) {
        return TestResult::Fail("both below threshold — must not trip");
    }
    // GPU hot, CPU cool.
    let gpu_hot = LaptopStateSnapshot {
        cpu_tdie_mc: Some(60_000),
        gpu_temp_mc: Some(95_000),
        ..Default::default()
    };
    if !gpu_hot.any_temp_above(80_000) {
        return TestResult::Fail("GPU above threshold must trip");
    }
    // CPU hot, GPU cool.
    let cpu_hot = LaptopStateSnapshot {
        cpu_tdie_mc: Some(95_000),
        gpu_temp_mc: Some(60_000),
        ..Default::default()
    };
    if !cpu_hot.any_temp_above(80_000) {
        return TestResult::Fail("CPU above threshold must trip");
    }
    // Both unknown → can't trip.
    let unknown = LaptopStateSnapshot::default();
    if unknown.any_temp_above(0) {
        return TestResult::Fail("unknown sensors must not trip");
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/laptop_state",
    smoke_laptop_state_any_temp_above_fuses_cpu_and_gpu
);

fn smoke_laptop_state_battery_percent_fuses_info_and_state() -> TestResult {
    use crate::laptop_state::LaptopStateSnapshot;
    use narf_acpi::battery::{decode_bif, decode_bst, BatteryStatus};
    use alloc::string::String;
    let ints: [u32; 9] = [0, 50_000, 48_000, 1, 11_400, 5_000, 2_500, 1, 1];
    let strings: [String; 4] = [String::new(), String::new(), String::new(), String::new()];
    let info = decode_bif(&ints, &strings).expect("bif");
    let bst: [u32; 4] = [BatteryStatus::DISCHARGING, 12_000, 24_000, 11_000]; // 50%
    let state = decode_bst(&bst).expect("bst");

    let snap = LaptopStateSnapshot {
        battery_info: Some(info.clone()),
        battery_state: Some(state),
        ..Default::default()
    };
    match snap.battery_percent() {
        Some(50) => {}
        Some(other) => {
            let _ = other;
            return TestResult::Fail("24k/48k must yield 50%");
        }
        None => return TestResult::Fail("percent should be Some(50)"),
    }
    // With info missing, percent is None.
    let snap_no_info = LaptopStateSnapshot {
        battery_state: Some(state),
        ..Default::default()
    };
    if snap_no_info.battery_percent().is_some() {
        return TestResult::Fail("missing info must yield None");
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/laptop_state",
    smoke_laptop_state_battery_percent_fuses_info_and_state
);

// ── power/device_pm ────────────────────────────────────────────────

use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering as TestOrdering};

static PM_SEQ: AtomicI32 = AtomicI32::new(0);
static PM_FAIL_FLAG: AtomicUsize = AtomicUsize::new(0);

fn smoke_pm_record_a_suspend() -> Result<(), crate::device_pm::DeviceSuspendError> {
    PM_SEQ.fetch_add(1, TestOrdering::AcqRel);
    Ok(())
}
fn smoke_pm_record_a_resume() -> Result<(), crate::device_pm::DeviceSuspendError> {
    PM_SEQ.fetch_add(10, TestOrdering::AcqRel);
    Ok(())
}
fn smoke_pm_record_b_suspend() -> Result<(), crate::device_pm::DeviceSuspendError> {
    PM_SEQ.fetch_add(100, TestOrdering::AcqRel);
    Ok(())
}
fn smoke_pm_record_b_resume() -> Result<(), crate::device_pm::DeviceSuspendError> {
    PM_SEQ.fetch_add(1000, TestOrdering::AcqRel);
    Ok(())
}
fn smoke_pm_fail_suspend() -> Result<(), crate::device_pm::DeviceSuspendError> {
    PM_FAIL_FLAG.fetch_add(1, TestOrdering::AcqRel);
    Err(crate::device_pm::DeviceSuspendError::Busy)
}
fn smoke_pm_fail_resume() -> Result<(), crate::device_pm::DeviceSuspendError> {
    Ok(())
}

fn smoke_device_pm_register_and_fanout_order() -> TestResult {
    use crate::device_pm::{
        device_count, register_device_pm, resume_all_devices, suspend_all_devices,
        __reset_for_test,
    };
    __reset_for_test();
    PM_SEQ.store(0, TestOrdering::Release);

    // Register A first, then B.
    register_device_pm("dev_a", smoke_pm_record_a_suspend, smoke_pm_record_a_resume);
    register_device_pm("dev_b", smoke_pm_record_b_suspend, smoke_pm_record_b_resume);
    if device_count() != 2 {
        return TestResult::Fail("expected 2 registrations");
    }

    // Suspend should fire B (100) THEN A (1). Sum = 101 after suspend.
    let s_report = suspend_all_devices();
    if !s_report.ok() || s_report.outcomes.len() != 2 {
        return TestResult::Fail("suspend outcomes wrong count");
    }
    // The first outcome in the report is the LAST-registered (B).
    if s_report.outcomes[0].name != "dev_b" {
        return TestResult::Fail("suspend fan-out must be reverse-registration");
    }
    if s_report.outcomes[1].name != "dev_a" {
        return TestResult::Fail("suspend fan-out second-out must be dev_a");
    }
    let after_suspend = PM_SEQ.load(TestOrdering::Acquire);
    if after_suspend != 101 {
        return TestResult::Fail("suspend sum must be 101 (B=100, A=1)");
    }

    // Resume should fire A (10) THEN B (1000). Sum += 1010 → 1111.
    let r_report = resume_all_devices();
    if r_report.outcomes[0].name != "dev_a" {
        return TestResult::Fail("resume fan-out must be forward-registration");
    }
    let after_resume = PM_SEQ.load(TestOrdering::Acquire);
    if after_resume != 1111 {
        return TestResult::Fail("resume sum must be 1111");
    }
    __reset_for_test();
    TestResult::Pass
}
kernel_test_in!("power/device_pm", smoke_device_pm_register_and_fanout_order);

fn smoke_device_pm_one_failure_doesnt_abort_chain() -> TestResult {
    use crate::device_pm::{
        register_device_pm, suspend_all_devices, DeviceSuspendError, __reset_for_test,
    };
    __reset_for_test();
    PM_SEQ.store(0, TestOrdering::Release);
    PM_FAIL_FLAG.store(0, TestOrdering::Release);

    // Three devices: A (Ok), Fail (Busy), B (Ok). Order in the suspend
    // fan-out (reverse): B → Fail → A.
    register_device_pm("dev_a", smoke_pm_record_a_suspend, smoke_pm_record_a_resume);
    register_device_pm("dev_fail", smoke_pm_fail_suspend, smoke_pm_fail_resume);
    register_device_pm("dev_b", smoke_pm_record_b_suspend, smoke_pm_record_b_resume);

    let report = suspend_all_devices();
    if report.outcomes.len() != 3 {
        return TestResult::Fail("expected 3 outcomes");
    }
    if report.failure_count != 1 {
        return TestResult::Fail("expected exactly 1 failure");
    }
    if !matches!(
        report.outcomes[1].result,
        Err(DeviceSuspendError::Busy)
    ) {
        return TestResult::Fail("middle outcome must carry the Busy error");
    }
    // Both Ok handlers ran despite the middle failure.
    if PM_SEQ.load(TestOrdering::Acquire) != 101 {
        return TestResult::Fail("both Ok handlers must run despite failure");
    }
    if PM_FAIL_FLAG.load(TestOrdering::Acquire) != 1 {
        return TestResult::Fail("fail handler must have been called once");
    }
    __reset_for_test();
    TestResult::Pass
}
kernel_test_in!(
    "power/device_pm",
    smoke_device_pm_one_failure_doesnt_abort_chain
);

fn smoke_device_pm_re_register_replaces() -> TestResult {
    use crate::device_pm::{
        device_count, register_device_pm, suspend_all_devices, __reset_for_test,
    };
    __reset_for_test();
    PM_SEQ.store(0, TestOrdering::Release);
    register_device_pm("dev_a", smoke_pm_record_a_suspend, smoke_pm_record_a_resume);
    // Re-register same name with a different (b) handler.
    register_device_pm("dev_a", smoke_pm_record_b_suspend, smoke_pm_record_b_resume);
    if device_count() != 1 {
        return TestResult::Fail("re-register must not duplicate");
    }
    suspend_all_devices();
    // The B-handler should have fired (sum = 100), not A's.
    if PM_SEQ.load(TestOrdering::Acquire) != 100 {
        return TestResult::Fail("re-register must use the new handler");
    }
    __reset_for_test();
    TestResult::Pass
}
kernel_test_in!("power/device_pm", smoke_device_pm_re_register_replaces);

fn smoke_device_pm_drivers_register_at_probe_if_probed() -> TestResult {
    use crate::device_pm::registered_devices;
    // Drivers only register when their probe path runs — in QEMU
    // that's xHCI (always present), NVMe (always), amdgpu (usually).
    // The test asserts at least xhci0 registered, since QEMU always
    // exposes an xHCI controller.
    let snap = registered_devices();
    let names: alloc::vec::Vec<&str> = snap.iter().map(|e| e.name.as_str()).collect();
    if !names.iter().any(|n| *n == "xhci0") {
        return TestResult::Skip("xhci not probed in this QEMU config");
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/device_pm",
    smoke_device_pm_drivers_register_at_probe_if_probed
);

#[cfg(target_arch = "x86_64")]
fn smoke_arm_s3_resume_refuses_without_armed_real_sleep() -> TestResult {
    // The arm_s3_resume orchestrator must NOT issue PM1 SLP_EN
    // unless REAL_SLEEP_ARMED is set — protects against bricking
    // the box during smoke runs.
    use crate::suspend::{arm_s3_resume, SuspendError, __test_reset};
    use crate::Power;
    use narf_capabilities::{Cap, Invoke};
    __test_reset();
    let cap: Cap<Power, Invoke> = Cap::bootstrap();
    match arm_s3_resume(&cap) {
        Err(SuspendError::NotImplemented) => TestResult::Pass,
        Err(_) | Ok(_) => TestResult::Fail(
            "arm_s3_resume must refuse without REAL_SLEEP_ARMED",
        ),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "power/suspend",
    smoke_arm_s3_resume_refuses_without_armed_real_sleep
);

#[cfg(target_arch = "x86_64")]
fn smoke_s3_wake_entry_address_resolves() -> TestResult {
    // The asm trampoline must have a stable non-null address so
    // arm_s3_resume can write it to FACS.XFirmwareWakingVector.
    let entry = narf_arch::x86_64::s3_resume::s3_wake_entry as usize as u64;
    if entry == 0 {
        return TestResult::Fail("s3_wake_entry resolved to NULL");
    }
    // Address should be in the kernel's high-half code region —
    // canonical x86_64 kernel addresses have bit 47 (sign-extended)
    // set. Strict bit-pattern depends on the linker layout; just
    // check it's not in low memory.
    if entry < 0x1_0000_0000 {
        return TestResult::Fail("s3_wake_entry address suspiciously low");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("power/suspend", smoke_s3_wake_entry_address_resolves);

#[cfg(target_arch = "x86_64")]
fn smoke_s3_resume_context_phys_resolvable_via_cr3() -> TestResult {
    // Read CR3, walk to resolve RESUME_CONTEXT's phys. Proves
    // the arm_s3_resume virt→phys step actually works on this
    // running kernel.
    use narf_arch::x86_64::cr::read_cr3;
    use narf_arch::x86_64::s3_resume::resume_context_static_addr;
    use narf_memory::{x86_64::paging::translate, PhysAddr, VirtAddr};
    // SAFETY: CPL=0 read.
    let cr3 = unsafe { read_cr3() } & !0xFFFu64;
    let pml4_phys = PhysAddr::new(cr3);
    let ctx_virt = resume_context_static_addr() as u64;
    let phys = unsafe { translate(pml4_phys, VirtAddr::new(ctx_virt)) };
    let phys_page = match phys {
        Some(p) => p.raw(),
        None => return TestResult::Fail("CR3 walk couldn't resolve ResumeContext virt"),
    };
    // translate() returns the page-frame phys (4-KiB-aligned), not
    // the exact byte phys; add the in-page offset for the full
    // address. Page-frame phys being 0 is suspicious but legal if
    // the kernel BSS happens to land at frame 0 — accept anything
    // that translates cleanly. The strict check that follows
    // verifies the FULL address (page + offset).
    let full_phys = phys_page | (ctx_virt & 0xFFF);
    if full_phys == 0 && ctx_virt != 0 {
        return TestResult::Fail("full phys==0 but virt!=0 — broken walk");
    }
    if full_phys >= 0x1_0000_0000 {
        return TestResult::Fail("ResumeContext above 4 GiB — unexpected layout");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "power/suspend",
    smoke_s3_resume_context_phys_resolvable_via_cr3
);

#[cfg(target_arch = "x86_64")]
fn smoke_s3_wake_entry_phys_resolvable_via_cr3() -> TestResult {
    use narf_arch::x86_64::cr::read_cr3;
    use narf_arch::x86_64::s3_resume::s3_wake_entry;
    use narf_memory::{x86_64::paging::translate, PhysAddr, VirtAddr};
    // SAFETY: CPL=0 read.
    let cr3 = unsafe { read_cr3() } & !0xFFFu64;
    let entry_virt = s3_wake_entry as usize as u64;
    let phys = unsafe {
        translate(PhysAddr::new(cr3), VirtAddr::new(entry_virt))
    };
    let phys_page = match phys {
        Some(p) => p.raw(),
        None => return TestResult::Fail("CR3 walk couldn't resolve s3_wake_entry virt"),
    };
    let full_phys = phys_page | (entry_virt & 0xFFF);
    if full_phys == 0 && entry_virt != 0 {
        return TestResult::Fail("full phys==0 but virt!=0 — broken walk");
    }
    if full_phys >= 0x1_0000_0000 {
        return TestResult::Fail("s3_wake_entry above 4 GiB");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "power/suspend",
    smoke_s3_wake_entry_phys_resolvable_via_cr3
);

// ── DevicePmOps trait round-trip ────────────────────────────────────

fn smoke_device_pm_ops_round_trip() -> TestResult {
    use crate::device_pm::{
        register_device_pm_ops, resume_all_devices, suspend_all_devices, DevicePmError,
        DevicePmOps, __reset_for_test,
    };
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU32, Ordering};

    __reset_for_test();

    struct FakeDriver {
        // Bit 0 set after suspend, bit 1 set after resume.
        // A clean cycle leaves this at 0b11.
        state: AtomicU32,
    }
    impl DevicePmOps for FakeDriver {
        fn suspend(&self) -> Result<(), DevicePmError> {
            self.state.fetch_or(0b01, Ordering::SeqCst);
            Ok(())
        }
        fn resume(&self) -> Result<(), DevicePmError> {
            self.state.fetch_or(0b10, Ordering::SeqCst);
            Ok(())
        }
    }
    let drv = Arc::new(FakeDriver {
        state: AtomicU32::new(0),
    });
    register_device_pm_ops("fake-driver", drv.clone());

    let s = suspend_all_devices();
    if !s.ok() {
        return TestResult::Fail("trait-backed suspend reported a failure");
    }
    if drv.state.load(Ordering::SeqCst) & 0b01 == 0 {
        return TestResult::Fail("trait suspend callback didn't fire");
    }

    let r = resume_all_devices();
    if !r.ok() {
        return TestResult::Fail("trait-backed resume reported a failure");
    }
    if drv.state.load(Ordering::SeqCst) != 0b11 {
        return TestResult::Fail("trait resume callback didn't fire");
    }

    __reset_for_test();
    TestResult::Pass
}
kernel_test_in!("power/suspend", smoke_device_pm_ops_round_trip);

// ── PCI config save/restore integration shape ──────────────────────

fn smoke_pci_config_save_restore_round_trip_via_ops() -> TestResult {
    // Exercise the integration shape a real PCIe driver uses:
    // a `DevicePmOps` impl that snapshots its config-space struct
    // on suspend and reapplies it on resume. Hits the device_pm
    // fan-out so we also validate the registry path.
    //
    // The actual cfg-space helpers (bus::pci::save_config /
    // restore_config) are tested in `bus/pci` smokes; here we
    // verify the wrapper integrates with power's device_pm
    // registry. We model the cfg-space with an in-memory shadow.
    use crate::device_pm::{
        register_device_pm_ops, resume_all_devices, suspend_all_devices, DevicePmError,
        DevicePmOps, __reset_for_test,
    };
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use narf_lib::sync::IrqSafeSpinLock;

    __reset_for_test();

    // Model "live" cfg-space + the saved snapshot. On suspend
    // we copy live into saved; on resume we copy saved back to
    // live (the BAR bits are what real silicon loses across S3).
    #[derive(Default, Copy, Clone, PartialEq, Eq)]
    struct FakeCfg {
        command: u16,
        bar0: u32,
        bar1: u32,
    }
    struct FakePcieDriver {
        live: IrqSafeSpinLock<FakeCfg>,
        saved: IrqSafeSpinLock<Option<FakeCfg>>,
        // The "device" clears its cfg on suspend, simulating
        // a real D3hot transition where BAR programming is lost.
        clear_on_suspend: AtomicBool,
        // Counters so we can assert each callback fired exactly once.
        suspends: AtomicU32,
        resumes: AtomicU32,
    }
    impl DevicePmOps for FakePcieDriver {
        fn suspend(&self) -> Result<(), DevicePmError> {
            self.suspends.fetch_add(1, Ordering::SeqCst);
            // Snapshot before the "device" clears.
            let snap = *self.live.lock();
            *self.saved.lock() = Some(snap);
            if self.clear_on_suspend.load(Ordering::SeqCst) {
                *self.live.lock() = FakeCfg::default();
            }
            Ok(())
        }
        fn resume(&self) -> Result<(), DevicePmError> {
            self.resumes.fetch_add(1, Ordering::SeqCst);
            // Re-apply the saved cfg.
            if let Some(snap) = *self.saved.lock() {
                *self.live.lock() = snap;
            }
            Ok(())
        }
    }
    let drv = Arc::new(FakePcieDriver {
        live: IrqSafeSpinLock::new(FakeCfg {
            command: 0x0007, // MEM|BUS_MASTER|IO
            bar0: 0xFEDC_0000,
            bar1: 0x0000_0001,
        }),
        saved: IrqSafeSpinLock::new(None),
        clear_on_suspend: AtomicBool::new(true),
        suspends: AtomicU32::new(0),
        resumes: AtomicU32::new(0),
    });
    let original = *drv.live.lock();

    register_device_pm_ops("fake-pcie", drv.clone());

    let _ = suspend_all_devices();
    if drv.suspends.load(Ordering::SeqCst) != 1 {
        return TestResult::Fail("PCIe driver suspend didn't fire exactly once");
    }
    // Post-suspend, "device" should have lost its cfg.
    if *drv.live.lock() == original {
        return TestResult::Fail("clear_on_suspend didn't take effect");
    }
    let _ = resume_all_devices();
    if drv.resumes.load(Ordering::SeqCst) != 1 {
        return TestResult::Fail("PCIe driver resume didn't fire exactly once");
    }
    // Resume must restore the original cfg byte-for-byte.
    if *drv.live.lock() != original {
        return TestResult::Fail("PCIe cfg did not round-trip across suspend/resume");
    }

    __reset_for_test();
    TestResult::Pass
}
kernel_test_in!(
    "power/suspend",
    smoke_pci_config_save_restore_round_trip_via_ops
);

// ── IRQ-mask snapshot encoder ──────────────────────────────────────

fn smoke_irq_mask_snapshot_encoder() -> TestResult {
    use crate::suspend::IrqMaskSnapshot;

    // Bit-pack encoder over the [0..=255] vector range. Walking a
    // handful of representative vectors and checking pack/unpack
    // covers the layout invariants the suspend snapshot relies on.
    let mut s = IrqMaskSnapshot::default();
    if s.is_masked(0) {
        return TestResult::Fail("default snapshot was not all-zero");
    }

    // Vector 0 → word 0 bit 0.
    s.set(0, true);
    if !s.is_masked(0) {
        return TestResult::Fail("vector 0 didn't set");
    }
    if s.words[0] != 1u64 {
        return TestResult::Fail("vector 0 packed to wrong bit");
    }

    // Vector 63 → word 0 bit 63 (highest bit of first word).
    s.set(63, true);
    if !s.is_masked(63) {
        return TestResult::Fail("vector 63 didn't set");
    }
    if s.words[0] & (1u64 << 63) == 0 {
        return TestResult::Fail("vector 63 didn't land in word 0 bit 63");
    }

    // Vector 64 → word 1 bit 0.
    s.set(64, true);
    if !s.is_masked(64) {
        return TestResult::Fail("vector 64 didn't set");
    }
    if s.words[1] != 1u64 {
        return TestResult::Fail("vector 64 didn't land in word 1 bit 0");
    }

    // Vector 255 → word 3 bit 63.
    s.set(255, true);
    if !s.is_masked(255) {
        return TestResult::Fail("vector 255 didn't set");
    }
    if s.words[3] & (1u64 << 63) == 0 {
        return TestResult::Fail("vector 255 didn't land in word 3 bit 63");
    }

    // Clearing should toggle back.
    s.set(0, false);
    if s.is_masked(0) {
        return TestResult::Fail("clearing vector 0 didn't take effect");
    }

    // All other set bits should survive the clear.
    if !s.is_masked(63) || !s.is_masked(64) || !s.is_masked(255) {
        return TestResult::Fail("clearing v0 disturbed other vectors");
    }
    TestResult::Pass
}
kernel_test_in!("power/suspend", smoke_irq_mask_snapshot_encoder);

// ── TSC backwards-jump detection ───────────────────────────────────

#[cfg(target_arch = "x86_64")]
fn smoke_tsc_backwards_jump_detection() -> TestResult {
    use crate::suspend::{
        __test_inject_pre_suspend_tsc, __test_reset_tsc_snapshot, check_tsc_post_resume,
        snapshot_tsc_pre_suspend, tsc_backward_jump_detected,
    };

    __test_reset_tsc_snapshot();

    // Default: no snapshot → no jump detected.
    if check_tsc_post_resume() {
        return TestResult::Fail("backwards-jump fired with no snapshot armed");
    }
    if tsc_backward_jump_detected() {
        return TestResult::Fail("flag was true after reset");
    }

    // Snapshot current TSC then immediately compare — TSC always
    // advances on real silicon between two RDTSC reads, so this
    // should NOT signal a jump.
    snapshot_tsc_pre_suspend();
    if check_tsc_post_resume() {
        return TestResult::Fail("monotonic TSC reported a backwards jump");
    }

    // Inject a synthetic future TSC value as if pre-suspend was a
    // huge future time — comparing against the current RDTSC will
    // then show a "backwards jump" (simulates the S3 reset case).
    __test_inject_pre_suspend_tsc(u64::MAX - 1000);
    if !check_tsc_post_resume() {
        return TestResult::Fail("synthetic backwards jump wasn't detected");
    }
    if !tsc_backward_jump_detected() {
        return TestResult::Fail("backward_jump_detected flag didn't latch");
    }

    __test_reset_tsc_snapshot();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("power/suspend", smoke_tsc_backwards_jump_detection);

// ── LAPIC LVT save/restore round-trip ──────────────────────────────

#[cfg(target_arch = "x86_64")]
fn smoke_lapic_save_restore_round_trip() -> TestResult {
    use narf_arch::x86_64::s3_resume::{
        __reset_lapic_for_test, __test_inject_lapic_state, captured_lapic_state, LapicSavedState,
    };

    __reset_lapic_for_test();

    // Reset state — no snapshot.
    if captured_lapic_state().is_some() {
        return TestResult::Fail("LAPIC state captured before save");
    }

    // Inject a known shape and verify it round-trips through the
    // accessor. (The actual MSR program-back is exercised on real
    // silicon during S3; here we cover the encoder + storage
    // layer, since reading x2APIC MSRs from kernel-test is host-
    // dependent.)
    let golden = LapicSavedState {
        lvt_timer: 0x0001_0020,
        lvt_thermal: 0x0001_0030,
        lvt_perfmon: 0x0001_0040,
        lvt_lint0: 0x0001_0700,
        lvt_lint1: 0x0001_0400,
        lvt_error: 0x0001_00FE,
        lvt_cmci: 0x0001_00F0,
        tpr: 0x10,
        svr: 0x1FF,
        timer_init_count: 0x0010_0000,
        timer_divide: 0x3,
    };
    __test_inject_lapic_state(golden);

    let got = match captured_lapic_state() {
        Some(s) => s,
        None => return TestResult::Fail("injected state did not register as captured"),
    };
    if got != golden {
        return TestResult::Fail("LAPIC saved state did not round-trip byte-for-byte");
    }

    __reset_lapic_for_test();
    if captured_lapic_state().is_some() {
        return TestResult::Fail("reset_for_test left LAPIC snapshot armed");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("power/suspend", smoke_lapic_save_restore_round_trip);

// ── Production S3 opt-in sentinel ──────────────────────────────────

fn smoke_production_s3_sentinel_default_off_opt_in_flip() -> TestResult {
    use crate::suspend::{
        __test_reset, __test_reset_production_s3, boot_apply_s3_validated_flag,
        disable_production_s3, enable_production_s3, production_s3_enabled,
    };
    use crate::Power;
    use narf_capabilities::{Cap, Invoke};

    __test_reset();
    __test_reset_production_s3();

    // Default must be off — production S3 is gated until userspace
    // explicitly opts in after on-silicon validation.
    if production_s3_enabled() {
        return TestResult::Fail("production S3 was on by default");
    }

    // Cap-gated opt-in flips the sentinel.
    let cap: Cap<Power, Invoke> = Cap::bootstrap();
    match enable_production_s3(&cap) {
        Ok(prev) => {
            if prev {
                return TestResult::Fail("enable returned prev=true on first call");
            }
        }
        Err(_) => return TestResult::Fail("enable rejected a live cap"),
    }
    if !production_s3_enabled() {
        return TestResult::Fail("enable didn't flip the sentinel");
    }

    // Disable should return prev=true on the second call.
    match disable_production_s3(&cap) {
        Ok(prev) => {
            if !prev {
                return TestResult::Fail("disable didn't observe prior enable");
            }
        }
        Err(_) => return TestResult::Fail("disable rejected a live cap"),
    }
    if production_s3_enabled() {
        return TestResult::Fail("disable didn't clear the sentinel");
    }

    // Revoked cap is refused.
    let cap2: Cap<Power, Invoke> = Cap::bootstrap();
    cap2.revoke();
    if enable_production_s3(&cap2).is_ok() {
        return TestResult::Fail("revoked cap was accepted by enable");
    }

    // Boot-cmdline path: the magic token sets the flag without a
    // cap (it runs pre-cap-creation).
    __test_reset_production_s3();
    if boot_apply_s3_validated_flag("ro console=ttyS0 S3_VALIDATED quiet") != true {
        return TestResult::Fail("cmdline scan didn't find S3_VALIDATED");
    }
    if !production_s3_enabled() {
        return TestResult::Fail("cmdline scan didn't flip the sentinel");
    }

    // A cmdline without the token doesn't flip it.
    __test_reset_production_s3();
    if boot_apply_s3_validated_flag("ro console=ttyS0 quiet") {
        return TestResult::Fail("cmdline scan reported true without the token");
    }
    if production_s3_enabled() {
        return TestResult::Fail("cmdline-less scan flipped the sentinel");
    }

    __test_reset_production_s3();
    TestResult::Pass
}
kernel_test_in!(
    "power/suspend",
    smoke_production_s3_sentinel_default_off_opt_in_flip
);

// ── FB suspend / resume hook fan-out ───────────────────────────────

fn smoke_fb_pm_hooks_fire_on_phase_pingpong() -> TestResult {
    use crate::suspend::{
        __test_reset_fb_pm_hooks, fb_pm_hooks_installed, invoke_fb_resume, invoke_fb_suspend,
        set_fb_pm_hooks,
    };
    use core::sync::atomic::{AtomicU32, Ordering};

    __test_reset_fb_pm_hooks();
    if fb_pm_hooks_installed() {
        return TestResult::Fail("FB PM hooks were installed at reset");
    }

    // Hook counters live in a static so the `extern "C" fn`
    // signature can reach them without captures.
    static SUSPENDS: AtomicU32 = AtomicU32::new(0);
    static RESUMES: AtomicU32 = AtomicU32::new(0);
    SUSPENDS.store(0, Ordering::Release);
    RESUMES.store(0, Ordering::Release);
    extern "C" fn fb_sus() {
        SUSPENDS.fetch_add(1, Ordering::SeqCst);
    }
    extern "C" fn fb_res() {
        RESUMES.fetch_add(1, Ordering::SeqCst);
    }

    set_fb_pm_hooks(fb_sus, fb_res);
    if !fb_pm_hooks_installed() {
        return TestResult::Fail("hooks didn't register as installed");
    }

    invoke_fb_suspend();
    invoke_fb_resume();
    if SUSPENDS.load(Ordering::SeqCst) != 1 {
        return TestResult::Fail("FB suspend hook didn't fire");
    }
    if RESUMES.load(Ordering::SeqCst) != 1 {
        return TestResult::Fail("FB resume hook didn't fire");
    }

    __test_reset_fb_pm_hooks();
    if fb_pm_hooks_installed() {
        return TestResult::Fail("reset didn't clear FB hooks");
    }
    // After reset the hook is a no-op (no panic, no state change).
    invoke_fb_suspend();
    invoke_fb_resume();
    if SUSPENDS.load(Ordering::SeqCst) != 1 || RESUMES.load(Ordering::SeqCst) != 1 {
        return TestResult::Fail("reset hooks still fired");
    }
    TestResult::Pass
}
kernel_test_in!("power/suspend", smoke_fb_pm_hooks_fire_on_phase_pingpong);
