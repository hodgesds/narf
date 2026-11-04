//! Retained source and actual administrative/interface owner for autonomous
//! AP emission. This object contains no installed peer/key authority.
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use narf_wireless::ap_control::{ApEmissionAuthority, ApEventAuthority, ApInterfaceIdentity};

/// Host DATA denial only. A snapshot never grants native/source/key admission;
/// those independent proofs remain mandatory at every publication boundary.
#[derive(Default)]
pub(super) struct DataEpoch(Arc<AtomicU64>);
#[derive(Clone)]
pub(super) struct DataPublication {
    generation: Arc<AtomicU64>,
    epoch: u64,
}
impl DataEpoch {
    pub(super) fn publication(&self) -> DataPublication {
        DataPublication {
            generation: self.0.clone(),
            epoch: self.0.load(Ordering::Acquire),
        }
    }
    pub(super) fn advance(&self) -> Result<(), &'static str> {
        let prior = self
            .0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                old.checked_add(1)
            })
            .map_err(|_| "AP DATA publication generation exhausted")?;
        // MAX is permanently denied, including every later snapshot. Never
        // wrap a copied frame back into authority after generation exhaustion.
        if prior == u64::MAX - 1 {
            return Err("AP DATA publication generation exhausted");
        }
        Ok(())
    }
}
impl DataPublication {
    pub(super) fn current(&self) -> bool {
        self.epoch != u64::MAX && self.generation.load(Ordering::Acquire) == self.epoch
    }
    pub(super) fn same_epoch(&self, other: &Self) -> bool {
        self.epoch == other.epoch && Arc::ptr_eq(&self.generation, &other.generation)
    }
}

pub(super) struct Request {
    pub authority: ApEmissionAuthority,
    pub related: Arc<[ApEmissionAuthority]>,
    pub cancel: Arc<AtomicBool>,
}
impl Request {
    pub fn check(&self) -> Result<(), &'static str> {
        if self.cancel.load(Ordering::Acquire)
            || !self.authority.current()
            || self.related.iter().any(|authority| !authority.current())
        {
            Err("Intel AP original operation cancelled/retired")
        } else {
            Ok(())
        }
    }
    pub fn watch(&self, waker: &core::task::Waker) -> bool {
        self.authority.watch(waker)
            && self.related.iter().all(|authority| authority.watch(waker))
            && self.check().is_ok()
    }
}

pub(super) struct Owner {
    device: Weak<dyn narf_wireless::WirelessNetIface>,
    identity: ApInterfaceIdentity,
    event: ApEventAuthority,
    emission: ApEmissionAuthority,
    role: narf_net::native_emission::Lifetime,
    cancel: Arc<AtomicBool>,
    live: AtomicBool,
}
impl Owner {
    pub fn new(
        device: Weak<dyn narf_wireless::WirelessNetIface>,
        identity: ApInterfaceIdentity,
        event: ApEventAuthority,
        emission: ApEmissionAuthority,
        role: narf_net::native_emission::Lifetime,
        cancel: Arc<AtomicBool>,
    ) -> Result<Arc<Self>, &'static str> {
        let owner = Arc::new(Self {
            device,
            identity,
            event,
            emission,
            role,
            cancel,
            live: AtomicBool::new(true),
        });
        owner.check()?;
        Ok(owner)
    }
    pub fn check(&self) -> Result<(), &'static str> {
        if !self.live.load(Ordering::Acquire) || self.cancel.load(Ordering::Acquire) {
            return Err("Intel AP native owner retired");
        }
        if self.device.strong_count() == 0 || !self.role.current() || !self.emission.current() {
            return Err("Intel AP actual source/admin/role generation retired");
        }
        Ok(())
    }
    pub fn retire(&self) {
        self.live.store(false, Ordering::Release);
    }
    pub fn event(&self) -> ApEventAuthority {
        self.event.clone()
    }
    pub fn identity(&self) -> ApInterfaceIdentity {
        self.identity.clone()
    }
    /// Called by the retained pump outside State. Providers wake it on
    /// retirement; a bounded pump timer additionally checks actual cap epochs.
    pub fn watch(&self, waker: &core::task::Waker) -> bool {
        self.role.watch(waker.clone()) && self.emission.watch(waker) && self.check().is_ok()
    }
}
