// SPDX-License-Identifier: GPL-2.0-or-later
//! Logical publication leases for replacement of a retained native owner.
//! Leases hold no lock through a stack callback. A closed generation must
//! drain them before its frontend can admit a replacement hardware owner.
use super::station::{Admission, Error};
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use narf_lib::mutex::Mutex;

pub(super) struct Lifecycle {
    pub(super) control: Mutex<()>,
    pub(super) channel: AtomicU8,
    generation: AtomicU64,
    publications: AtomicUsize,
    pub(super) rebuilding: AtomicBool,
    pub(super) suspended: AtomicBool,
    pub(super) inactive: AtomicBool,
    pub(super) sleep_complete: AtomicBool,
    pub(super) activity_ms: AtomicU64,
    pub(super) pm_requests: Mutex<()>,
    pub(super) pm_preparing: AtomicBool,
    pub(super) pm_rollback: AtomicBool,
}

impl Lifecycle {
    pub(super) fn new() -> Self {
        Self {
            control: Mutex::new(()),
            channel: AtomicU8::new(1),
            generation: AtomicU64::new(1),
            publications: AtomicUsize::new(0),
            rebuilding: AtomicBool::new(false),
            suspended: AtomicBool::new(false),
            inactive: AtomicBool::new(false),
            sleep_complete: AtomicBool::new(false),
            activity_ms: AtomicU64::new(0),
            pm_requests: Mutex::new(()),
            pm_preparing: AtomicBool::new(false),
            pm_rollback: AtomicBool::new(false),
        }
    }
    pub(super) fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }
    /// Caller holds Admission::publication and the async control mutex.
    /// Generation exhaustion is terminal; an old operation is never relabelled.
    pub(super) fn advance(&self) -> Result<u64, Error> {
        self.generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |generation| {
                generation.checked_add(1)
            })
            .map(|generation| generation + 1)
            .map_err(|_| Error::State)
    }
    pub(super) fn lease<'a>(
        &'a self,
        admission: &Admission,
        expected: u64,
    ) -> Option<PublicationLease<'a>> {
        let _gate = admission.publication.lock();
        if admission.closed.load(Ordering::Acquire) || self.generation() != expected {
            return None;
        }
        self.publications
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_add(1)
            })
            .ok()?;
        Some(PublicationLease { lifecycle: self })
    }
    /// Admission is already closed. This waits for synchronous callbacks and
    /// TX queue publications that entered before close; it does not drive or
    /// infer a hardware/DMA completion. No lock crosses the cooperative yield.
    pub(super) async fn drain_publications(&self) -> Result<(), Error> {
        let deadline = narf_time::Deadline::after_ms(1000);
        while self.publications.load(Ordering::Acquire) != 0 {
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            narf_scheduler::yield_now().await;
        }
        Ok(())
    }
}

pub(super) struct PublicationLease<'a> {
    lifecycle: &'a Lifecycle,
}
impl Drop for PublicationLease<'_> {
    fn drop(&mut self) {
        self.lifecycle.publications.fetch_sub(1, Ordering::Release);
    }
}
