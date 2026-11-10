//! MSI-X servicing tests against a recording register model.

use crate::{
    hardware::Registers,
    igc::{isr_rearm_mask, service_vector},
};
use alloc::vec::Vec;
use core::cell::RefCell;
use narf_kernel_test::{kernel_test_in, TestResult};

/// Records every access in order; `true` marks a write.
struct Recorder(RefCell<Vec<(bool, u64, u32)>>);

impl Registers for Recorder {
    fn read(&self, reg: u64) -> u32 {
        self.0.borrow_mut().push((false, reg, 0));
        0
    }
    fn write(&self, reg: u64, value: u32) {
        self.0.borrow_mut().push((true, reg, value));
    }
    fn wait(&self, _us: u64, mut ready: impl FnMut() -> bool) -> bool {
        ready()
    }
    fn delay(&self, _us: u64) {}
}

fn smoke_igc_admin_vector_rearms_itself() -> TestResult {
    // Physical I225: EIAM auto-masked vector 0 on its first interrupt and
    // nothing re-enabled it, so EIMS read 0x1e for the rest of the boot.
    // Linux igc_msix_other reads ICR, then writes eims_other back to EIMS.
    let admin = Recorder(RefCell::new(Vec::new()));
    service_vector(&admin, isr_rearm_mask(0));
    if admin.0.borrow().as_slice() != [(false, 0x1500, 0), (true, 0x1524, 1)] {
        return TestResult::Fail("administrative vector did not read ICR then re-arm EIMS bit 0");
    }
    // A queue vector stays masked until its pump has polled the ring and
    // re-arms it; the handler must not re-enable it early.
    for index in 1..5 {
        let queue = Recorder(RefCell::new(Vec::new()));
        service_vector(&queue, isr_rearm_mask(index));
        if queue.0.borrow().as_slice() != [(false, 0x1500, 0)] {
            return TestResult::Fail("queue vector handler wrote an interrupt mask");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/igc", smoke_igc_admin_vector_rearms_itself);
