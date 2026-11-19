//! Exact firmware/PCI and qualified-power authority around a publication.
use super::{mvm_boot::PowerFence, runtime::Authority};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use narf_capabilities::{Cap, CapError, CapOp, Read};
use narf_firmware::FirmwareBlob;
use narf_wireless::reg::RegulatoryDomain;

#[derive(Clone)]
pub(super) struct Source {
    pub(super) firmware: Cap<FirmwareBlob, Read>,
    pub(super) pci: Authority,
}
impl Source {
    pub(super) fn invoke<T>(
        &self,
        operation: impl FnOnce() -> Result<T, &'static str>,
    ) -> Result<T, &'static str> {
        struct Live<F>(F);
        impl<T, F: FnOnce() -> Result<T, &'static str>> CapOp<FirmwareBlob, Read> for Live<F> {
            type Output = Result<T, &'static str>;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((self.0)())
            }
        }
        self.firmware
            .invoke(Live(|| self.pci.invoke(operation)))
            .map_err(|_| "MVM executable firmware authority revoked")?
    }
}
#[derive(Clone)]
pub(super) struct Publication {
    pub(super) source: Source,
    pub(super) power: Arc<Power>,
    pub(super) generation: (Arc<AtomicU64>, u64),
}
pub(super) enum Power {
    Station(PowerFence),
    Ap(Ap),
}
pub(super) struct Ap(alloc::vec::Vec<ApProof>);
struct ApProof {
    source: super::runtime::source::Fence,
    receive: super::runtime::rx_epoch::Publication,
    data: super::ap_owner::DataPublication,
}
impl Ap {
    pub(super) fn new(
        source: super::runtime::source::Fence,
        receive: super::runtime::rx_epoch::Publication,
        data: super::ap_owner::DataPublication,
    ) -> Result<Self, &'static str> {
        // Exactly one immutable bundle. Stable fallible Vec allocation keeps
        // OOM a denial/owned-cleanup error without introducing unsafe boxing.
        let mut proof = alloc::vec::Vec::new();
        proof
            .try_reserve_exact(1)
            .map_err(|_| "MVM AP publication proof allocation failed")?;
        proof.push(ApProof {
            source,
            receive,
            data,
        });
        Ok(Self(proof))
    }
    pub(super) fn current(&self) -> bool {
        self.0[0].receive.current() && self.0[0].data.current()
    }
    pub(super) fn same_epoch(
        &self,
        receive: &super::runtime::rx_epoch::Publication,
        data: &super::ap_owner::DataPublication,
    ) -> bool {
        self.0[0].receive.same_epoch(receive) && self.0[0].data.same_epoch(data)
    }
}
impl Power {
    pub(super) fn invoke<T>(
        &self,
        domain: &RegulatoryDomain,
        operation: impl FnOnce() -> Result<T, &'static str>,
    ) -> Result<T, &'static str> {
        match self {
            Self::Station(power) => power.invoke(domain, operation),
            Self::Ap(ap) => ap.0[0].source.invoke(|| {
                if !ap.current() {
                    return Err("MVM AP native receive/key epoch retired");
                }
                operation()
            }),
        }
    }
}
impl Publication {
    pub(super) fn current(&self) -> bool {
        self.generation.0.load(Ordering::Acquire) == self.generation.1
            && match self.power.as_ref() {
                Power::Station(_) => true,
                Power::Ap(ap) => ap.current(),
            }
    }
    pub(super) fn invoke<T>(
        &self,
        domain: &RegulatoryDomain,
        operation: impl FnOnce() -> Result<T, &'static str>,
    ) -> Result<T, &'static str> {
        if !self.current() {
            return Err("MVM stale controlled-port publication generation");
        }
        self.source.invoke(|| {
            self.power.invoke(domain, || {
                if !self.current() {
                    return Err("MVM stale controlled-port publication generation");
                }
                operation()
            })
        })
    }
}
