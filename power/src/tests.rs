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

    narf_scheduler::init();
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
