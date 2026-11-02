// SPDX-License-Identifier: GPL-2.0-or-later
//! Exact-function reservation before PCI access, retained through DMA
//! reclamation. A pinned function does not quarantine another BDF.
use super::pci::Rtw88Device;
use alloc::{sync::Arc, vec::Vec};
use narf_bus::{BusAddr, ProbeError};
use narf_lib::sync::IrqSafeSpinLock;

struct Entry {
    addr: BusAddr,
    owner: Option<Arc<Rtw88Device>>,
    removing: bool,
}
struct Registry(Vec<Entry>);
static FUNCTIONS: IrqSafeSpinLock<Registry> = IrqSafeSpinLock::new(Registry(Vec::new()));
pub(super) struct Claim(BusAddr);
impl Claim {
    pub(super) fn acquire(addr: BusAddr) -> Result<Option<Self>, ProbeError> {
        let mut registry = FUNCTIONS.lock();
        if let Some(entry) = registry.0.iter().find(|entry| entry.addr == addr) {
            return if entry.owner.is_some() && !entry.removing {
                Ok(None)
            } else {
                Err(ProbeError::BadDevice)
            };
        }
        if registry.0.len() == super::endpoints::MAX_FUNCTIONS {
            return Err(ProbeError::BadDevice);
        }
        registry.0.push(Entry {
            addr,
            owner: None,
            removing: false,
        });
        Ok(Some(Self(addr)))
    }
    pub(super) fn publish(self, owner: Arc<Rtw88Device>) {
        assert_eq!(self.0, owner.bus_addr);
        let mut registry = FUNCTIONS.lock();
        let entry = registry
            .0
            .iter_mut()
            .find(|entry| entry.addr == self.0)
            .expect("retained RTW88 function claim");
        assert!(entry.owner.is_none() && !entry.removing);
        entry.owner = Some(owner);
    }
}
impl Drop for Claim {
    fn drop(&mut self) {
        FUNCTIONS
            .lock()
            .0
            .retain(|entry| entry.addr != self.0 || entry.owner.is_some());
    }
}
pub(super) fn sole() -> Option<Arc<Rtw88Device>> {
    let registry = FUNCTIONS.lock();
    let mut owners = registry
        .0
        .iter()
        .filter(|entry| !entry.removing)
        .filter_map(|entry| entry.owner.clone());
    let owner = owners.next()?;
    owners.next().is_none().then_some(owner)
}
pub(super) fn get(addr: BusAddr) -> Option<Arc<Rtw88Device>> {
    FUNCTIONS
        .lock()
        .0
        .iter()
        .find(|entry| entry.addr == addr && !entry.removing)?
        .owner
        .clone()
}
pub(super) fn any() -> bool {
    FUNCTIONS
        .lock()
        .0
        .iter()
        .any(|entry| entry.owner.is_some() && !entry.removing)
}
pub(super) fn begin_remove(addr: BusAddr) -> Option<Arc<Rtw88Device>> {
    let mut registry = FUNCTIONS.lock();
    let entry = registry
        .0
        .iter_mut()
        .find(|entry| entry.addr == addr && !entry.removing)?;
    let owner = entry.owner.clone()?;
    entry.removing = true;
    Some(owner)
}
pub(super) fn reclaimed(owner: &Arc<Rtw88Device>) {
    FUNCTIONS.lock().0.retain(|entry| {
        entry
            .owner
            .as_ref()
            .is_none_or(|current| !Arc::ptr_eq(current, owner))
    });
}
#[cfg(any(test, feature = "kernel-test"))]
pub(super) fn reset_for_test() {
    FUNCTIONS.lock().0.clear();
}
