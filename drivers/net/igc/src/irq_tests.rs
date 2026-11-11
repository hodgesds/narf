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

fn smoke_igc_receive_coalescing_is_enabled_at_probe() -> TestResult {
    // Linux igc reports `generic-receive-offload: on` and feeds
    // napi_gro_receive; the physical I225 boot reported `off [fixed]` and
    // ran one full TCP pass per 1500-byte segment.
    fn sink(_: &[u8], _: narf_net::TxMeta) -> Result<(), ()> {
        Ok(())
    }
    let name = narf_net::iface::register("igc-gro-selftest", [2, 0, 0, 0, 0, 9], sink);
    let before = narf_net::iface::lookup(&name).is_some_and(|iface| iface.software_gro);
    let accepted = crate::igc::enable_receive_coalescing(&name);
    let after = narf_net::iface::lookup(&name).is_some_and(|iface| iface.software_gro);
    let _ = narf_net::iface::unregister(&name);
    if before {
        return TestResult::Fail("software GRO was already on for a fresh interface");
    }
    if !accepted || !after {
        return TestResult::Fail("igc probe hook did not enable software GRO");
    }
    if crate::igc::enable_receive_coalescing("igc-gro-missing") {
        return TestResult::Fail("coalescing accepted an unregistered interface");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/igc",
    smoke_igc_receive_coalescing_is_enabled_at_probe
);
