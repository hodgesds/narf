//! Actual retained function registry: no fake BDF reset can replace another
//! original generation, and removal/cancellation cannot admit a cold producer.
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};
fn owner(function: u8) -> Arc<Rtw88Device> {
    Arc::new(Rtw88Device {
        bus_addr: BusAddr::Pcie(narf_bus::PcieAddr::new(0xfffb, 0xfa, 0x17, function)),
        registers: narf_bus::MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: 0,
            len: 0,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        },
        mac: [2, 4, 6, 8, 10, 12],
        device_id: 0xc822,
        firmware: None,
        sibling: None,
        interface: None,
        link_up: core::sync::atomic::AtomicBool::new(false),
        rx_ring: IrqSafeSpinLock::new(None),
        tx_ring: IrqSafeSpinLock::new(None),
        diagnostic_name: "reset-registry-fixture",
        provisioning: narf_lib::mutex::Mutex::new(()),
        reset_origin: None,
    })
}
struct Cleanup(Vec<Arc<Rtw88Device>>);
impl Drop for Cleanup {
    fn drop(&mut self) {
        for owner in &self.0 {
            reclaimed(owner);
        }
    }
}
fn smoke_rtw88_operating_reset_exact_original_function_and_new_generation() -> TestResult {
    let old = owner(0);
    let fresh = owner(0);
    let foreign = owner(1);
    let _cleanup = Cleanup(alloc::vec![old.clone(), fresh.clone(), foreign.clone()]);
    let claim = match Claim::acquire(old.bus_addr) {
        Ok(Some(claim)) => claim,
        _ => return TestResult::Skip("no spare isolated RTW88 function slot"),
    };
    claim.publish(old.clone());
    let reset = ResetClaim::acquire(&old).unwrap();
    if get(old.bus_addr).is_some()
        || Claim::acquire(old.bus_addr).is_ok()
        || ResetClaim::acquire(&old).is_ok()
        || reset.current().is_err()
    {
        return TestResult::Fail("reset did not exclusively retain original reservation");
    }
    // Foreign owner cannot consume or retarget the original reset claim.
    if ResetClaim::acquire(&foreign).is_ok() {
        return TestResult::Fail("foreign reset claimed original BDF");
    }
    if reset.publish(fresh.clone()).is_err()
        || !get(fresh.bus_addr).is_some_and(|current| Arc::ptr_eq(&current, &fresh))
        || ResetClaim::acquire(&old).is_ok()
    {
        return TestResult::Fail("fresh publication aliased original generation");
    }
    reclaimed(&old);
    if get(fresh.bus_addr).is_none() {
        return TestResult::Fail("late old cleanup removed fresh generation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/reset",
    smoke_rtw88_operating_reset_exact_original_function_and_new_generation
);
fn smoke_rtw88_operating_reset_cancel_and_hot_remove_quarantine_original_bdf() -> TestResult {
    for hot_remove in [false, true] {
        let old = owner(0);
        let fresh = owner(0);
        let _cleanup = Cleanup(alloc::vec![old.clone(), fresh.clone()]);
        let claim = match Claim::acquire(old.bus_addr) {
            Ok(Some(claim)) => claim,
            _ => return TestResult::Skip("no spare isolated RTW88 function slot"),
        };
        claim.publish(old.clone());
        let reset = ResetClaim::acquire(&old).unwrap();
        if hot_remove {
            if crate::rtw88::power::reset_tests::remove_during_power(&reset, old.bus_addr)
                != Err(crate::rtw88::power::PowerError::Access)
                || reset.current().is_ok()
                || reset.publish(fresh).is_ok()
            {
                return TestResult::Fail("hot removal lost to reset publication");
            }
        } else {
            drop(reset);
        }
        if get(old.bus_addr).is_some() || Claim::acquire(old.bus_addr).is_ok() {
            return TestResult::Fail("cancelled/removed original reset reopened BDF");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/reset",
    smoke_rtw88_operating_reset_cancel_and_hot_remove_quarantine_original_bdf
);
fn smoke_rtw88_system_pm_barrier_excludes_new_function_and_reset_producers() -> TestResult {
    let old = owner(0);
    let extra = owner(1);
    let _cleanup = Cleanup(alloc::vec![old.clone(), extra.clone()]);
    let claim = match Claim::acquire(old.bus_addr) {
        Ok(Some(claim)) => claim,
        _ => return TestResult::Skip("no spare isolated RTW88 function slot"),
    };
    claim.publish(old.clone());
    let barrier = match Barrier::begin() {
        Ok(barrier) => barrier,
        _ => return TestResult::Skip("other RTW88 function currently changing"),
    };
    if Claim::acquire(extra.bus_addr).is_ok()
        || ResetClaim::acquire(&old).is_ok()
        || Barrier::begin().is_ok()
    {
        return TestResult::Fail("system suspend admitted competing probe/reset/session");
    }
    drop(barrier);
    if ResetClaim::acquire(&old).is_err() {
        return TestResult::Fail("released PM barrier retained stale exclusion");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/system_pm",
    smoke_rtw88_system_pm_barrier_excludes_new_function_and_reset_producers
);
