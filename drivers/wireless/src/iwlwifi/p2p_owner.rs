//! P2P native publication/copy retirement. These gates only deny; actual
//! admitted MAC/link/PHY/AUX, native START and current NVM/MCC/power remain
//! independent requirements owned by runtime::p2p and the physical worker.
use super::p2p_host::Request;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// One physical P2P device's never-reused copy/publication clock. Bump before
/// REMOVE/filter closure and before a new grant, not after event preparation.
#[derive(Default)]
pub(super) struct Epoch(Arc<AtomicU64>);
impl Epoch {
    pub fn advance(&self) -> Result<Capture, &'static str> {
        let old = self
            .0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                old.checked_add(1)
            })
            .map_err(|_| "Intel P2P native capture epoch exhausted")?;
        let generation = old + 1;
        if generation == u64::MAX {
            return Err("Intel P2P native capture epoch exhausted");
        }
        Ok(Capture {
            epoch: self.0.clone(),
            generation,
        })
    }
}
#[derive(Clone)]
pub(super) struct Capture {
    epoch: Arc<AtomicU64>,
    generation: u64,
}
impl Capture {
    pub fn current(&self) -> bool {
        self.generation != u64::MAX && self.epoch.load(Ordering::Acquire) == self.generation
    }
    pub fn same(&self, other: &Self) -> bool {
        self.generation == other.generation && Arc::ptr_eq(&self.epoch, &other.epoch)
    }
    pub fn fence<'a>(
        &'a self,
        receiver: &'a Request,
        origin: &'a Request,
    ) -> narf_wireless::ap_control::RadioReceiveFence<'a> {
        narf_wireless::ap_control::RadioReceiveFence {
            epoch: &self.epoch,
            generation: self.generation,
            receiver: receiver.emission(),
            origin: origin.emission(),
        }
    }
}

/// Opening is private to the matching native START consumer. Neither a
/// command ACK nor a host clock can construct an opened grant.
pub(super) struct Grant {
    pub capture: Capture,
    open: Arc<AtomicBool>,
    deadline: Arc<AtomicU64>,
}
impl Grant {
    pub fn pending(capture: Capture) -> Self {
        Self {
            capture,
            open: Arc::new(AtomicBool::new(false)),
            deadline: Arc::new(AtomicU64::new(0)),
        }
    }
    pub fn native_start(&self, duration_us: u64) -> Result<(), &'static str> {
        if !self.capture.current() {
            return Err("Intel P2P START belongs to a retired native capture");
        }
        let deadline = narf_time::wall::monotonic_ns()
            .checked_add(
                duration_us
                    .checked_mul(1000)
                    .ok_or("P2P native interval overflow")?,
            )
            .filter(|_| duration_us != 0)
            .ok_or("P2P native interval overflow")?;
        self.deadline
            .compare_exchange(0, deadline, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "P2P duplicate START cannot reopen a grant")?;
        self.open.store(true, Ordering::Release);
        Ok(())
    }
    pub fn started(&self) -> bool {
        self.deadline.load(Ordering::Acquire) != 0
    }
    pub fn close(&self) {
        self.open.store(false, Ordering::Release);
    }
    pub fn current(&self) -> bool {
        self.open.load(Ordering::Acquire)
            && self.capture.current()
            && narf_time::wall::monotonic_ns() < self.deadline.load(Ordering::Acquire)
    }
    pub fn publication(&self) -> Publication {
        Publication {
            capture: self.capture.clone(),
            open: self.open.clone(),
            deadline: self.deadline.clone(),
        }
    }
}
#[derive(Clone)]
pub(super) struct Publication {
    pub capture: Capture,
    open: Arc<AtomicBool>,
    deadline: Arc<AtomicU64>,
}
impl Publication {
    pub fn current(&self) -> bool {
        self.open.load(Ordering::Acquire)
            && self.capture.current()
            && narf_time::wall::monotonic_ns() < self.deadline.load(Ordering::Acquire)
    }
}

/// Captured at the physical owner before its actual command/TX future. It
/// remains in Hardware/source::Fence across every native credit/receipt wait.
/// Cleanup explicitly detaches this emitting request after closing its grant;
/// continuing device/source authority still governs non-emitting retirement.
pub(super) struct Gate {
    start: Arc<Request>,
    operation: Option<Arc<Request>>,
    related: Option<Arc<Request>>,
    grant: Option<Publication>,
}
impl Gate {
    pub fn new(
        start: Arc<Request>,
        operation: Option<Arc<Request>>,
        grant: Option<Publication>,
    ) -> Arc<Self> {
        Arc::new(Self {
            start,
            operation,
            related: None,
            grant,
        })
    }
    pub fn frame(
        start: Arc<Request>,
        operation: Arc<Request>,
        roc: Arc<Request>,
        grant: Publication,
    ) -> Arc<Self> {
        Arc::new(Self {
            start,
            operation: Some(operation),
            related: Some(roc),
            grant: Some(grant),
        })
    }
    pub fn check(&self) -> Result<(), &'static str> {
        self.start.check()?;
        if let Some(operation) = &self.operation {
            if !self.start.same_receiver(operation) {
                return Err("Intel P2P operation belongs to another actual control child");
            }
            operation.check()?;
        }
        if let Some(related) = &self.related {
            if !self.start.same_receiver(related) {
                return Err("Intel P2P grant belongs to another actual control child");
            }
            related.check()?;
        }
        if self.grant.as_ref().is_some_and(|grant| !grant.current()) {
            return Err("Intel P2P native grant closed before publication");
        }
        Ok(())
    }
    /// Only FRAME carries a received finite native Publication. A live
    /// START/request alone cannot authorize any actual packet publication.
    pub fn transmission(&self) -> Result<(), &'static str> {
        self.check()?;
        self.grant
            .as_ref()
            .filter(|grant| grant.current())
            .map(|_| ())
            .ok_or("Intel P2P TX lacks its actual native grant")
    }
}
