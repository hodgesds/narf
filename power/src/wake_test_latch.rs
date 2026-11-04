//! Scoped generic-latch isolation. Retained device evidence is deliberately
//! untouched, allowing tests to model the real pre-park generic clear.

use core::sync::atomic::Ordering;

#[derive(Debug)]
pub(crate) struct Snapshot {
    latched: bool,
    source: u8,
}

impl Snapshot {
    pub(crate) fn capture() -> Self {
        Self {
            latched: super::WAKE_LATCH.swap(false, Ordering::AcqRel),
            source: super::LAST_WAKE_SOURCE.swap(0, Ordering::AcqRel),
        }
    }

    pub(crate) fn clear(&self) {
        super::WAKE_LATCH.store(false, Ordering::Release);
    }
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        super::WAKE_LATCH.store(self.latched, Ordering::Release);
        super::LAST_WAKE_SOURCE.store(self.source, Ordering::Release);
    }
}
