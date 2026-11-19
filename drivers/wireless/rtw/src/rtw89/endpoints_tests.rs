// SPDX-License-Identifier: GPL-2.0-or-later
use super::*;
use core::sync::atomic::{AtomicUsize, Ordering};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Sink(AtomicUsize);
impl Endpoint for Sink {
    fn send(&self, bytes: &[u8], _: narf_net::TxMeta) -> Result<(), ()> {
        self.0.fetch_add(bytes.len(), Ordering::AcqRel);
        Ok(())
    }
    fn drain(&self) -> bool {
        false
    }
}
fn smoke_rtw8852b_endpoint_cookie_cannot_alias_a_rebound_generation() -> TestResult {
    let mut pool = Pool::new();
    let old = Arc::new(Sink(AtomicUsize::new(0)));
    let other = Arc::new(Sink(AtomicUsize::new(0)));
    let retired = pool.insert("first", old.clone()).unwrap();
    let live = pool.insert("second", other.clone()).unwrap();
    if pool.insert("first", other.clone()).is_ok() {
        return TestResult::Fail("duplicate netdev replaced another endpoint");
    }
    pool.remove(Arc::as_ptr(&old) as *const ());
    let replacement = Arc::new(Sink(AtomicUsize::new(0)));
    let fresh = pool.insert("first", replacement.clone()).unwrap();
    if retired == fresh || pool.get(retired).is_some() {
        return TestResult::Fail("retired send callback aliased a new generation");
    }
    pool.get(live)
        .unwrap()
        .send(&[1, 2], narf_net::TxMeta::plain())
        .unwrap();
    pool.get(fresh)
        .unwrap()
        .send(&[3], narf_net::TxMeta::plain())
        .unwrap();
    // Late cleanup of an old Arc must leave the replacement registered.
    pool.remove(Arc::as_ptr(&old) as *const ());
    if old.0.load(Ordering::Acquire) != 0
        || other.0.load(Ordering::Acquire) != 2
        || replacement.0.load(Ordering::Acquire) != 1
        || pool.get(fresh).is_none()
    {
        return TestResult::Fail("endpoint dispatch or stale cleanup crossed functions");
    }
    pool.next = u64::MAX;
    if pool.insert("exhausted", old).is_ok() || pool.get(0).is_some() {
        return TestResult::Fail("dispatch identity wrapped");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/multiple",
    smoke_rtw8852b_endpoint_cookie_cannot_alias_a_rebound_generation
);
