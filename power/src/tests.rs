//! Subsystem smokes for `narf-power`.
//!
//! Migrated from `narf-verification`. Tests register under the
//! `power` subsystem.

extern crate alloc;

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_power_cstate_register() -> TestResult {
    use crate::{
        bootstrap_power_authority, cstate_count, init, register_cstate,
        select_idle_state, CState, PowerError,
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
        Ok(s)  => s,
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
        bootstrap_governor_authority, current_governor_name, init,
        install_governor, OnDemand, Powersave, PowerError,
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
        Ok(_)  => return TestResult::Fail("install_governor accepted a revoked cap"),
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
    use core::future::Future;
    use core::pin::Pin;
    use core::sync::atomic::{AtomicU32, Ordering};
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use crate::{
        bootstrap_device_pm_authority, register_device_pm, resume_device,
        suspend_device, DeviceRuntimePm,
    };

    let suspends = Arc::new(AtomicU32::new(0));
    let resumes  = Arc::new(AtomicU32::new(0));

    struct Counter {
        suspends: Arc<AtomicU32>,
        resumes:  Arc<AtomicU32>,
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
    let dev = Counter { suspends: suspends.clone(), resumes: resumes.clone() };
    let handle = match register_device_pm(&cap, dev) {
        Ok(h)  => h,
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
    use narf_capabilities::{Cap, Invoke};
    use crate::{suspend, SuspendError, SuspendPhase};

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
    if idle::encode_cstate(0) != 0    { return TestResult::Fail("C0 encode"); }
    if idle::encode_cstate(1) != 0    { return TestResult::Fail("C1 encode"); }
    if idle::encode_cstate(3) != 0x20 { return TestResult::Fail("C3 encode"); }
    if idle::encode_cstate(6) != 0x40 { return TestResult::Fail("C6 encode"); }
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
