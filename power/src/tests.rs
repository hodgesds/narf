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
