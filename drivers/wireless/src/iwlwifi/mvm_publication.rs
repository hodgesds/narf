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
    pub(super) power: PowerFence,
    pub(super) generation: (Arc<AtomicU64>, u64),
}
impl Publication {
    pub(super) fn current(&self) -> bool {
        self.generation.0.load(Ordering::Acquire) == self.generation.1
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
