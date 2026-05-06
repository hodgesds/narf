//! Per-crate smoke tests for `narf-init`.
//!
//! Tests register via `narf_kernel_test::kernel_test_in!` so the
//! runner groups output under the `"init"` subsystem.

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_init_stages_run_in_order() -> TestResult {
    use crate::{__reset_for_test, register, run_all_through, InitResult, Stage};
    use core::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    static EARLY_RAN: AtomicU32 = AtomicU32::new(0);
    static CORE_RAN: AtomicU32 = AtomicU32::new(0);
    static DEVICE_RAN: AtomicU32 = AtomicU32::new(0);
    static LATE_RAN: AtomicU32 = AtomicU32::new(0);

    fn early() -> InitResult {
        EARLY_RAN.store(COUNTER.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
        InitResult::Ok
    }
    fn core() -> InitResult {
        CORE_RAN.store(COUNTER.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
        InitResult::Ok
    }
    fn device() -> InitResult {
        DEVICE_RAN.store(COUNTER.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
        InitResult::Ok
    }
    fn late() -> InitResult {
        LATE_RAN.store(COUNTER.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
        InitResult::Ok
    }

    __reset_for_test();
    COUNTER.store(0, Ordering::SeqCst);
    EARLY_RAN.store(0, Ordering::SeqCst);
    CORE_RAN.store(0, Ordering::SeqCst);
    DEVICE_RAN.store(0, Ordering::SeqCst);
    LATE_RAN.store(0, Ordering::SeqCst);

    // Register out of stage order; the registry should still run
    // them in Stage order regardless of insertion sequence.
    register(Stage::Late, "late", late);
    register(Stage::Early, "early", early);
    register(Stage::Device, "device", device);
    register(Stage::Core, "core", core);

    run_all_through(Stage::Late);

    let e = EARLY_RAN.load(Ordering::SeqCst);
    let c = CORE_RAN.load(Ordering::SeqCst);
    let d = DEVICE_RAN.load(Ordering::SeqCst);
    let l = LATE_RAN.load(Ordering::SeqCst);
    if !(e < c && c < d && d < l) {
        __reset_for_test();
        return TestResult::Fail("stages didn't run in order");
    }
    __reset_for_test();
    TestResult::Pass
}
kernel_test_in!("init", smoke_init_stages_run_in_order);

fn smoke_init_not_present_does_not_count_as_error() -> TestResult {
    use crate::{__reset_for_test, register, run_stage, stats, InitResult, Stage};
    fn absent() -> InitResult {
        InitResult::NotPresent
    }
    fn ok() -> InitResult {
        InitResult::Ok
    }

    __reset_for_test();
    register(Stage::Subsys, "absent", absent);
    register(Stage::Subsys, "ok", ok);
    let s = run_stage(Stage::Subsys);
    if s.total != 2 || s.ok != 1 || s.not_present != 1 || s.error != 0 {
        __reset_for_test();
        return TestResult::Fail("stage stats wrong");
    }
    let s2 = stats(Stage::Subsys);
    if s2 != s {
        __reset_for_test();
        return TestResult::Fail("stats() didn't reflect run_stage");
    }
    __reset_for_test();
    TestResult::Pass
}
kernel_test_in!("init", smoke_init_not_present_does_not_count_as_error);

fn smoke_init_error_continues_to_next_call() -> TestResult {
    use crate::{__reset_for_test, register, run_stage, InitResult, Stage};
    use core::sync::atomic::{AtomicBool, Ordering};
    static AFTER_RAN: AtomicBool = AtomicBool::new(false);
    fn fails() -> InitResult {
        InitResult::Error("synthetic")
    }
    fn after() -> InitResult {
        AFTER_RAN.store(true, Ordering::SeqCst);
        InitResult::Ok
    }

    __reset_for_test();
    AFTER_RAN.store(false, Ordering::SeqCst);
    register(Stage::Device, "fails", fails);
    register(Stage::Device, "after", after);
    let s = run_stage(Stage::Device);
    if s.error != 1 || s.ok != 1 {
        __reset_for_test();
        return TestResult::Fail("error count wrong");
    }
    if !AFTER_RAN.load(Ordering::SeqCst) {
        __reset_for_test();
        return TestResult::Fail("error short-circuited the stage");
    }
    __reset_for_test();
    TestResult::Pass
}
kernel_test_in!("init", smoke_init_error_continues_to_next_call);

fn smoke_init_records_cycle_totals() -> TestResult {
    use crate::{__reset_for_test, register, run_stage, InitResult, Stage};
    fn slow() -> InitResult {
        // Spin a small loop so cycles accumulate above zero.
        for _ in 0..1000 {
            core::hint::spin_loop();
        }
        InitResult::Ok
    }
    fn fast() -> InitResult {
        InitResult::Ok
    }

    __reset_for_test();
    register(Stage::Subsys, "slow", slow);
    register(Stage::Subsys, "fast", fast);
    let s = run_stage(Stage::Subsys);
    if s.total != 2 || s.ok != 2 {
        __reset_for_test();
        return TestResult::Fail("counts wrong");
    }
    if s.total_cycles == 0 {
        __reset_for_test();
        return TestResult::Fail("cycles not accumulated");
    }
    if s.max_cycles == 0 {
        __reset_for_test();
        return TestResult::Fail("max_cycles not recorded");
    }
    if s.max_name != "slow" && s.max_name != "fast" {
        __reset_for_test();
        return TestResult::Fail("max_name unexpected");
    }
    __reset_for_test();
    TestResult::Pass
}
kernel_test_in!("init", smoke_init_records_cycle_totals);
