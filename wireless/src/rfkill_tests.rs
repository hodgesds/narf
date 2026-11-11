use super::*;
use alloc::string::String;
use narf_kernel_test::{kernel_test_in, TestResult};

static REGISTERED: IrqSafeSpinLock<Vec<String>> = IrqSafeSpinLock::new(Vec::new());
static UNREGISTERED: IrqSafeSpinLock<Vec<usize>> = IrqSafeSpinLock::new(Vec::new());
fn register(name: &str) -> usize {
    let mut registered = REGISTERED.lock();
    registered.push(String::from(name));
    100 + registered.len() - 1
}
fn unregister(handle: usize) {
    UNREGISTERED.lock().push(handle);
}

/// cfg80211's wiphy rfkill: a wiphy seen before the core is connected is
/// registered on install, a later one at once; the core's switch blocks
/// and unblocks exactly that wiphy; the last interface leaving
/// unregisters it.
fn smoke_wiphy_rfkill_registration_and_block() -> TestResult {
    __test_reset();
    REGISTERED.lock().clear();
    UNREGISTERED.lock().clear();
    const EARLY: u64 = 0x51_0001;
    const LATE: u64 = 0x51_0002;
    wiphy_added(EARLY);
    wiphy_added(EARLY);
    if !REGISTERED.lock().is_empty() || blocked(EARLY) {
        return TestResult::Fail("registered or blocked without an rfkill core");
    }
    install(Backend {
        register,
        unregister,
    });
    wiphy_added(LATE);
    if REGISTERED.lock().len() != 2 || !REGISTERED.lock().iter().all(|n| n.starts_with("phy")) {
        return TestResult::Fail("each wiphy is not one phyN radio");
    }
    // Handles 100 (EARLY) and 101 (LATE).
    if !set_soft_blocked(100, true) || !blocked(EARLY) || blocked(LATE) {
        return TestResult::Fail("soft block did not reach exactly its wiphy");
    }
    if !set_soft_blocked(100, false) || blocked(EARLY) {
        return TestResult::Fail("soft block not cleared");
    }
    if set_soft_blocked(7, true) {
        return TestResult::Fail("unknown radio accepted");
    }
    wiphy_removed(LATE);
    if *UNREGISTERED.lock() != [101] || set_soft_blocked(101, true) {
        return TestResult::Fail("removed wiphy still registered");
    }
    __test_reset();
    TestResult::Pass
}
kernel_test_in!("wireless/rfkill", smoke_wiphy_rfkill_registration_and_block);
