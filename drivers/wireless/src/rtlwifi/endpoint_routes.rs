// SPDX-License-Identifier: GPL-2.0-or-later
//! Per-logical-device stack dispatch. Cookies never wrap or identify a new
//! device after removal; callers clone the exact endpoint before unlocking.
use super::*;
pub(super) struct Routes {
    next: u64,
    entries: Vec<(u64, Arc<dyn Endpoint>)>,
}
impl Routes {
    pub(super) const fn new() -> Self {
        Self {
            next: 0,
            entries: Vec::new(),
        }
    }
    pub(super) fn insert(&mut self, endpoint: Arc<dyn Endpoint>) -> Result<u64, Error> {
        let cookie = self.next.checked_add(1).ok_or(Error::State)?;
        self.entries.try_reserve(1).map_err(|_| Error::Allocation)?;
        self.entries.push((cookie, endpoint));
        self.next = cookie;
        Ok(cookie)
    }
    pub(super) fn get(&self, cookie: u64) -> Option<Arc<dyn Endpoint>> {
        self.entries
            .iter()
            .find(|entry| entry.0 == cookie)
            .map(|entry| entry.1.clone())
    }
    pub(super) fn remove(&mut self, cookie: u64, endpoint: *const ()) {
        self.entries
            .retain(|entry| entry.0 != cookie || Arc::as_ptr(&entry.1) as *const () != endpoint);
    }
    pub(super) fn snapshot(&self) -> Vec<Arc<dyn Endpoint>> {
        self.entries.iter().map(|entry| entry.1.clone()).collect()
    }
}
#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicUsize;
    use narf_kernel_test::{kernel_test_in, TestResult};
    struct Sink {
        sends: AtomicUsize,
        drains: AtomicUsize,
    }
    impl Sink {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                sends: AtomicUsize::new(0),
                drains: AtomicUsize::new(0),
            })
        }
    }
    impl Endpoint for Sink {
        fn send(&self, _: &[u8], _: narf_net::TxMeta) -> Result<(), ()> {
            self.sends.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
        fn drain(&self) -> bool {
            self.drains.fetch_add(1, Ordering::AcqRel);
            true
        }
    }
    fn smoke_rtl8188ee_independent_logical_routes_keep_old_callback_identity() -> TestResult {
        let mut routes = Routes::new();
        let a = Sink::new();
        let b = Sink::new();
        let first = routes.insert(a.clone()).unwrap();
        let second = routes.insert(b.clone()).unwrap();
        let old = routes.get(first).unwrap();
        routes
            .get(second)
            .unwrap()
            .send(&[], narf_net::TxMeta::default())
            .unwrap();
        routes.remove(first, Arc::as_ptr(&a) as *const ());
        let third = routes.insert(a.clone()).unwrap();
        old.send(&[], narf_net::TxMeta::default()).unwrap();
        if routes.get(first).is_some()
            || third <= second
            || a.sends.load(Ordering::Acquire) != 1
            || b.sends.load(Ordering::Acquire) != 1
        {
            return TestResult::Fail(
                "EE retired stack cookie targeted a different radio or wrapped",
            );
        }
        for endpoint in routes.snapshot() {
            endpoint.drain();
        }
        if a.drains.load(Ordering::Acquire) != 1 || b.drains.load(Ordering::Acquire) != 1 {
            return TestResult::Fail("EE receive snapshot skipped another live radio");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtlwifi/multi_radio",
        smoke_rtl8188ee_independent_logical_routes_keep_old_callback_identity
    );
    fn smoke_rtl8188ee_route_exhaustion_and_foreign_withdrawal_do_not_alias() -> TestResult {
        let mut routes = Routes::new();
        let a = Sink::new();
        let b = Sink::new();
        let cookie = routes.insert(a.clone()).unwrap();
        routes.remove(cookie, Arc::as_ptr(&b) as *const ());
        routes.next = u64::MAX;
        if routes.insert(b).is_ok() || routes.entries.len() != 1 || routes.get(cookie).is_none() {
            return TestResult::Fail(
                "EE route exhaustion or foreign withdrawal changed an owned endpoint",
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtlwifi/multi_radio",
        smoke_rtl8188ee_route_exhaustion_and_foreign_withdrawal_do_not_alias
    );
}
