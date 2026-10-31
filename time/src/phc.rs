//! Precision hardware clock registry. Device lifetime is retained by open
//! descriptors; unregistration never redirects an old fd to a new device.
extern crate alloc;
use alloc::{sync::Arc, vec::Vec};
use narf_lib::sync::IrqSafeSpinLock;

pub trait HardwareClock: core::fmt::Debug + Send + Sync {
    fn read_ns(&self) -> Result<u64, i32>;
    fn set_ns(&self, ns: u64) -> Result<(), i32>;
    fn adjust(&self, delta_ns: i64, ppb: i32) -> Result<(), i32>;
    fn frequency_ppb(&self) -> i32 {
        0
    }
    fn max_adjust_ppb(&self) -> u32;
}
static CLOCKS: IrqSafeSpinLock<Vec<Option<Arc<dyn HardwareClock>>>> =
    IrqSafeSpinLock::new(Vec::new());
pub fn register(clock: Arc<dyn HardwareClock>) -> u32 {
    let mut clocks = CLOCKS.lock();
    if let Some(i) = clocks.iter().position(Option::is_none) {
        clocks[i] = Some(clock);
        i as u32
    } else {
        clocks.push(Some(clock));
        (clocks.len() - 1) as u32
    }
}
pub fn get(index: u32) -> Option<Arc<dyn HardwareClock>> {
    CLOCKS.lock().get(index as usize)?.clone()
}
pub fn unregister(index: u32) -> bool {
    let old = {
        let mut clocks = CLOCKS.lock();
        clocks.get_mut(index as usize).and_then(Option::take)
    };
    old.is_some()
}
pub fn indices() -> Vec<u32> {
    CLOCKS
        .lock()
        .iter()
        .enumerate()
        .filter_map(|(i, c)| c.as_ref().map(|_| i as u32))
        .collect()
}

mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_kernel_test::{kernel_test_in, TestResult};
    #[derive(Debug)]
    struct Clock(AtomicU64);
    impl HardwareClock for Clock {
        fn read_ns(&self) -> Result<u64, i32> {
            Ok(self.0.load(Ordering::Relaxed))
        }
        fn set_ns(&self, v: u64) -> Result<(), i32> {
            self.0.store(v, Ordering::Relaxed);
            Ok(())
        }
        fn adjust(&self, v: i64, _: i32) -> Result<(), i32> {
            self.0.fetch_add(v as u64, Ordering::Relaxed);
            Ok(())
        }
        fn max_adjust_ppb(&self) -> u32 {
            1000
        }
    }
    fn smoke_phc_unregister_preserves_open_reference() -> TestResult {
        let index = register(Arc::new(Clock(AtomicU64::new(100))));
        let open = get(index).unwrap();
        if !unregister(index) || get(index).is_some() {
            return TestResult::Fail("clock not withdrawn");
        }
        let replacement = register(Arc::new(Clock(AtomicU64::new(200))));
        let result = open.read_ns() == Ok(100) && get(replacement).unwrap().read_ns() == Ok(200);
        unregister(replacement);
        if result {
            TestResult::Pass
        } else {
            TestResult::Fail("old clock reference redirected to replacement")
        }
    }
    kernel_test_in!("time", smoke_phc_unregister_preserves_open_reference);
}
