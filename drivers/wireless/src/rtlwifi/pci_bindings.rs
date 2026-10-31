// SPDX-License-Identifier: GPL-2.0-or-later
//! Reserve a PCI function before hardware access and quarantine only that
//! function until its actual retirement completes. No guard crosses I/O.
use super::RtlwifiDevice;
use alloc::vec::Vec;
use narf_bus::BusAddr;
pub(super) enum Admission {
    Bound,
    Initialize,
    Blocked,
}
enum Slot {
    Probing(BusAddr),
    Bound(RtlwifiDevice),
    Quarantined(BusAddr),
}
impl Slot {
    fn address(&self) -> BusAddr {
        match self {
            Self::Probing(a) | Self::Quarantined(a) => *a,
            Self::Bound(d) => d.bus_addr,
        }
    }
}
pub(super) struct Bindings {
    slots: Vec<Slot>,
}
impl Bindings {
    pub(super) const fn new() -> Self {
        Self { slots: Vec::new() }
    }
    pub(super) fn reserve(&mut self, address: BusAddr) -> Admission {
        if let Some(slot) = self.slots.iter().find(|slot| slot.address() == address) {
            return match slot {
                Slot::Bound(_) => Admission::Bound,
                _ => Admission::Blocked,
            };
        }
        if self.slots.try_reserve(1).is_err() {
            return Admission::Blocked;
        }
        self.slots.push(Slot::Probing(address));
        Admission::Initialize
    }
    pub(super) fn commit(&mut self, device: RtlwifiDevice) -> bool {
        let Some(slot) = self
            .slots
            .iter_mut()
            .find(|slot| slot.address() == device.bus_addr)
        else {
            return false;
        };
        if !matches!(slot, Slot::Probing(_)) {
            return false;
        }
        *slot = Slot::Bound(device);
        true
    }
    pub(super) fn abandon(&mut self, address: BusAddr) {
        self.slots
            .retain(|slot| !matches!(slot, Slot::Probing(a) if *a == address));
    }
    pub(super) fn detach(&mut self, address: BusAddr) -> Option<RtlwifiDevice> {
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| slot.address() == address)?;
        if !matches!(slot, Slot::Bound(_)) {
            return None;
        }
        match core::mem::replace(slot, Slot::Quarantined(address)) {
            Slot::Bound(device) => Some(device),
            _ => unreachable!(),
        }
    }
    pub(super) fn reclaimed(&mut self, address: BusAddr) {
        self.slots
            .retain(|slot| !matches!(slot, Slot::Quarantined(a) if *a == address));
    }
    pub(super) fn quarantined(&self, address: BusAddr) -> bool {
        self.slots
            .iter()
            .any(|slot| matches!(slot, Slot::Quarantined(a) if *a == address))
    }
    pub(super) fn first(&self) -> Option<&RtlwifiDevice> {
        self.slots.iter().find_map(|slot| match slot {
            Slot::Bound(device) => Some(device),
            _ => None,
        })
    }
    pub(super) fn get(&self, address: BusAddr) -> Option<&RtlwifiDevice> {
        self.slots.iter().find_map(|slot| match slot {
            Slot::Bound(device) if device.bus_addr == address => Some(device),
            _ => None,
        })
    }
}
