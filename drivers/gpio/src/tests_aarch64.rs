//! aarch64-only smokes for `narf-drivers-gpio` — the PL061 DT
//! binding against the live QEMU virt device tree (DT programme
//! step 5). The crate's `tests` module carries the arch-neutral
//! synthetic-MMIO smokes.

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_pl061_dt_bound_live() -> TestResult {
    // The frame's probe-all walk ran before the smoke phase: the
    // virt PL061 (0x0903_0000, INTID 39) must be bound and present
    // in the shared controller registry consumers resolve through.
    let Some(intid) = crate::pl061::bound_intid_for_test() else {
        return TestResult::Fail("PL061 DT binding did not run on QEMU virt");
    };
    if intid != 39 {
        return TestResult::Fail("PL061 binding resolved the wrong INTID (want 39)");
    }
    let list = crate::registry::list();
    let Some(ctrl) = list.iter().find(|c| c.name().starts_with("pl061@")) else {
        return TestResult::Fail("no pl061 controller in the GPIO registry");
    };
    if ctrl.pin_count() != 8 {
        return TestResult::Fail("PL061 registry record has the wrong pin count");
    }
    // Input readback on the real cell: pins reset to inputs, and a
    // masked DATA read must not fault.
    if ctrl.read_pin(0).is_err() {
        return TestResult::Fail("PL061 live masked DATA read failed");
    }
    TestResult::Pass
}
kernel_test_in!("drivers-gpio", smoke_pl061_dt_bound_live);
