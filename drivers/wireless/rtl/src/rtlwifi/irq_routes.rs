// SPDX-License-Identifier: GPL-2.0-or-later
//! One retained signal for each allocated hardware vector. No singleton
//! device, pointer cookie, allocation or table lock across a wake callback.
use super::super::irq::Signal;
use alloc::sync::Arc;
pub(super) struct Routes {
    slots: [Option<Arc<Signal>>; 256],
}
impl Routes {
    pub(super) const fn new() -> Self {
        Self {
            slots: [const { None }; 256],
        }
    }
    pub(super) fn get(&self, cookie: u64) -> Option<Arc<Signal>> {
        self.slots.get(usize::try_from(cookie).ok()?)?.clone()
    }
    pub(super) fn insert(&mut self, vector: u8, signal: Arc<Signal>) -> bool {
        let slot = &mut self.slots[usize::from(vector)];
        if slot.is_some() {
            return false;
        }
        *slot = Some(signal);
        true
    }
    pub(super) fn remove(&mut self, vector: u8, expected: &Arc<Signal>) -> bool {
        let slot = &mut self.slots[usize::from(vector)];
        if !slot
            .as_ref()
            .is_some_and(|signal| Arc::ptr_eq(signal, expected))
        {
            return false;
        }
        *slot = None;
        true
    }
}
#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn smoke_rtl8188ee_two_native_irq_routes_raise_only_their_owned_signal() -> TestResult {
        let mut routes = Routes::new();
        let a = Signal::new();
        let b = Signal::new();
        if !routes.insert(61, a.clone())
            || !routes.insert(62, b.clone())
            || routes.insert(61, b.clone())
        {
            return TestResult::Fail("EE vector routes replaced or refused independent signals");
        }
        routes.get(61).unwrap().raise();
        if a.count() != 1 || b.count() != 0 {
            return TestResult::Fail("EE vector61 woke another radio");
        }
        routes.get(62).unwrap().raise();
        if a.count() != 1 || b.count() != 1 {
            return TestResult::Fail("EE vector62 woke another radio");
        }
        if routes.get(256).is_some() || routes.get(u64::MAX).is_some() {
            return TestResult::Fail("EE IRQ cookie truncated into a live vector");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtlwifi/multi_radio",
        smoke_rtl8188ee_two_native_irq_routes_raise_only_their_owned_signal
    );
    fn smoke_rtl8188ee_retired_irq_identity_cannot_remove_reused_vector_owner() -> TestResult {
        let mut routes = Routes::new();
        let old = Signal::new();
        let fresh = Signal::new();
        routes.insert(63, old.clone());
        let entered = routes.get(63).unwrap();
        if !routes.remove(63, &old) || !routes.insert(63, fresh.clone()) || routes.remove(63, &old)
        {
            return TestResult::Fail("EE stale IRQ teardown removed a replacement signal");
        }
        entered.raise();
        if old.count() != 1 || fresh.count() != 0 || !Arc::ptr_eq(&routes.get(63).unwrap(), &fresh)
        {
            return TestResult::Fail("EE old IRQ snapshot was relabelled as the new radio");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtlwifi/multi_radio",
        smoke_rtl8188ee_retired_irq_identity_cannot_remove_reused_vector_owner
    );
}
