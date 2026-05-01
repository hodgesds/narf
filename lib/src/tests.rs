//! Subsystem smokes for `narf-lib`.
//!
//! Migrated from `narf-verification` so the primitives validate
//! themselves rather than relying on the mega-harness. Tests register
//! via `narf_kernel_test::kernel_test_in!("lib", _)` so the runner
//! groups output under the lib subsystem.

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_typed_id_sanity() -> TestResult {
    use crate::id::{CpuId, DomainId, TaskId};
    if CpuId::new(7).raw() != 7 { return TestResult::Fail("CpuId::raw mismatch"); }
    if DomainId::FRAME.raw() != 0 { return TestResult::Fail("FRAME != 0"); }
    if DomainId::SCRATCH.raw() != 15 { return TestResult::Fail("SCRATCH != 15"); }
    if TaskId::new(0xDEAD).raw() != 0xDEAD { return TestResult::Fail("TaskId::raw mismatch"); }
    TestResult::Pass
}
kernel_test_in!("lib", smoke_typed_id_sanity);

fn smoke_spin_lock_cycle() -> TestResult {
    use crate::sync::{SpinLock, IrqsEnabled};
    let l = SpinLock::new(0u32);
    {
        let mut g = l.lock(IrqsEnabled);
        *g = 42;
    }
    if *l.lock(IrqsEnabled) == 42 { TestResult::Pass }
    else { TestResult::Fail("SpinLock round-trip lost its value") }
}
kernel_test_in!("lib", smoke_spin_lock_cycle);

fn smoke_bitmap_first_set() -> TestResult {
    use crate::bitmap::Bitmap;
    let mut b: Bitmap<128> = Bitmap::new();
    b.set(5);
    b.set(70);
    match (b.first_set(), b.count_ones()) {
        (Some(5), 2) => TestResult::Pass,
        _            => TestResult::Fail("Bitmap first_set/count_ones wrong"),
    }
}
kernel_test_in!("lib", smoke_bitmap_first_set);

fn smoke_box_roundtrip() -> TestResult {
    extern crate alloc;
    use alloc::boxed::Box;
    let b: Box<[u32; 4]> = Box::new([1, 2, 3, 4]);
    let sum: u32 = b.iter().sum();
    if sum == 10 { TestResult::Pass } else { TestResult::Fail("Box<[u32;4]> sum wrong") }
}
kernel_test_in!("lib", smoke_box_roundtrip);

fn smoke_lib_current_domain_hook() -> TestResult {
    // narf-arch provides `narf_arch_current_domain` as the weak hook
    // `narf-lib` calls. Stage-3 default: 0 == DomainId::FRAME. Any
    // drift here breaks every assert_in_domain / assert_tcb caller.
    use crate::assert::current_domain;
    use crate::id::DomainId;

    if current_domain() != DomainId::FRAME {
        return TestResult::Fail("arch hook returned non-FRAME domain at boot");
    }
    TestResult::Pass
}
kernel_test_in!("lib", smoke_lib_current_domain_hook);

fn smoke_lib_assert_in_domain_passes_on_frame() -> TestResult {
    // The always-on assert variant must not panic when the expected
    // domain matches. Stage-3 default has every task running in FRAME.
    use crate::id::DomainId;
    crate::assert_in_domain!(DomainId::FRAME);
    crate::assert_tcb!();
    TestResult::Pass
}
kernel_test_in!("lib", smoke_lib_assert_in_domain_passes_on_frame);

fn smoke_lib_bug_on_false_is_silent() -> TestResult {
    // bug_on! is a panic-path macro; a false condition must NOT panic.
    // Also implicitly tests the format-args path compiles.
    crate::bug_on!(false, "should not fire");
    crate::bug_on!(1 + 1 != 2, "arithmetic drift: {}", 42);
    TestResult::Pass
}
kernel_test_in!("lib", smoke_lib_bug_on_false_is_silent);
