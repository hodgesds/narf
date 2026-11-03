//! Software [`IommuHw`] model for tests (io, bus and driver crates).
//!
//! It walks the real NARF page tables the way a unit would, but has no
//! device table, command queue or IOTLB: it records each backend call so
//! tests can check ordering (PTEs cleared before the invalidation, IOVA
//! only reusable after it completed) and can fail invalidations on
//! demand. It is never registered by the boot path and proves nothing
//! about AMD-Vi / VT-d / SMMU silicon.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::iommu::{self, Bdf, IommuHw, PageTableFormat};
use crate::IoError;

/// One recorded backend call.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ModelEvent {
    Attach {
        bdf: Bdf,
        domain_id: u16,
        root: u64,
    },
    Detach {
        bdf: Bdf,
        domain_id: u16,
    },
    /// `cleared`: every page of the range was absent from the domain's
    /// table when the invalidation was issued (`None` = no attached
    /// device, so no root to walk).
    Flush {
        domain_id: u16,
        iova: u64,
        len: u64,
        cleared: Option<bool>,
        ok: bool,
    },
}

/// Recording backend. Coherent walker.
#[derive(Debug)]
pub struct ModelIommu {
    format: PageTableFormat,
    fail_flush: AtomicBool,
    events: IrqSafeSpinLock<Vec<ModelEvent>>,
    roots: IrqSafeSpinLock<Vec<(u16, u64)>>,
}

impl ModelIommu {
    pub const fn new(format: PageTableFormat) -> Self {
        Self {
            format,
            fail_flush: AtomicBool::new(false),
            events: IrqSafeSpinLock::new(Vec::new()),
            roots: IrqSafeSpinLock::new(Vec::new()),
        }
    }

    /// Make every following `flush_iotlb` fail (invalidation timeout).
    pub fn set_fail_flush(&self, fail: bool) {
        self.fail_flush.store(fail, Ordering::SeqCst);
    }

    /// Snapshot of recorded calls.
    pub fn events(&self) -> Vec<ModelEvent> {
        self.events.lock().clone()
    }

    /// Forget recorded calls only (attached roots stay walkable).
    pub fn clear_events(&self) {
        self.events.lock().clear();
    }

    /// Forget recorded calls and roots.
    pub fn clear(&self) {
        self.events.lock().clear();
        self.roots.lock().clear();
        self.fail_flush.store(false, Ordering::SeqCst);
    }

    /// Reset NARF's IOMMU state, then enter `PerDomain` with this model.
    pub fn install(&'static self) -> Result<(), IoError> {
        iommu::__reset_for_test();
        self.clear();
        iommu::enable_per_domain(self)
    }
}

impl IommuHw for ModelIommu {
    fn name(&self) -> &'static str {
        "model"
    }

    fn format(&self) -> PageTableFormat {
        self.format
    }

    fn coherent_walk(&self) -> bool {
        true
    }

    fn attach(&self, bdf: Bdf, domain_id: u16, root: u64, _levels: u8) -> Result<(), IoError> {
        self.roots.lock().push((domain_id, root));
        self.events.lock().push(ModelEvent::Attach {
            bdf,
            domain_id,
            root,
        });
        Ok(())
    }

    fn detach(&self, bdf: Bdf, domain_id: u16) -> Result<(), IoError> {
        self.events
            .lock()
            .push(ModelEvent::Detach { bdf, domain_id });
        Ok(())
    }

    fn flush_iotlb(&self, domain_id: u16, iova: u64, len: u64) -> Result<(), IoError> {
        let root = self
            .roots
            .lock()
            .iter()
            .find(|(d, _)| *d == domain_id)
            .map(|(_, r)| *r);
        let cleared = root.map(|root| {
            (0..len.div_ceil(4096))
                .all(|i| iommu::walk(self.format, root, iova + (i << 12)).is_none())
        });
        let ok = !self.fail_flush.load(Ordering::SeqCst);
        self.events.lock().push(ModelEvent::Flush {
            domain_id,
            iova,
            len,
            cleared,
            ok,
        });
        if ok {
            Ok(())
        } else {
            Err(IoError::NotMapped)
        }
    }
}
