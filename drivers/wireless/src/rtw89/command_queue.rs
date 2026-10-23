//! Retained CH12 DMA ownership with Linux's eight-command multi-tag delay.
use super::mac::ChipId;
use alloc::{collections::VecDeque, vec::Vec};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    NoMemory,
    BadLength,
    BadAddress,
    Full,
    BadIndex,
    Publish,
    Terminal,
    Access,
    Busy,
    Timeout,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Header,
    Section,
}

/// The descriptor goes immediately before the H2C header or raw section. It
/// has no WP sequence/address-info extension. C uses RX-like16; A/B/51 TXWD24.
pub fn descriptor(chip: ChipId, kind: Kind, length: usize) -> Result<Vec<u8>, Error> {
    if length == 0 || length > 2020 {
        return Err(Error::BadLength);
    }
    let size = match chip {
        ChipId::Rtl8852C => 16,
        ChipId::Rtl8852A | ChipId::Rtl8852B | ChipId::Rtl8851B => 24,
        ChipId::Rtl8922A => return Err(Error::Unsupported),
    };
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(size).map_err(|_| Error::NoMemory)?;
    bytes.resize(size, 0);
    if chip == ChipId::Rtl8852C {
        let packet_type = if kind == Kind::Section { 14 } else { 13 };
        bytes[..4].copy_from_slice(&((length as u32) | (packet_type << 24)).to_le_bytes());
    } else {
        bytes[..4].copy_from_slice(
            &(12u32 << 16 | if kind == Kind::Section { 1 << 20 } else { 0 }).to_le_bytes(),
        );
        bytes[8..12].copy_from_slice(&(length as u32).to_le_bytes());
    }
    Ok(bytes)
}
/// Linux TXBD length includes the command descriptor and all command bytes.
pub fn txbd(address: u64, length: usize) -> Result<[u8; 8], Error> {
    if length == 0 || length > 2044 {
        return Err(Error::BadLength);
    }
    if address
        .checked_add(length as u64 - 1)
        .is_none_or(|end| end >= 1 << 40)
    {
        return Err(Error::BadAddress);
    }
    let mut bytes = [0; 8];
    bytes[..2].copy_from_slice(&(length as u16).to_le_bytes());
    let options = 0x4000u16 | (((address >> 32) as u16) << 6);
    bytes[2..4].copy_from_slice(&options.to_le_bytes());
    bytes[4..].copy_from_slice(&(address as u32).to_le_bytes());
    Ok(bytes)
}
struct Entry<T> {
    issued: bool,
    resource: Option<T>,
}
pub struct CommandQueue<T> {
    slots: Vec<Option<Entry<T>>>,
    quarantine: VecDeque<T>,
    wp: u16,
    rp: u16,
    terminal: bool,
}
impl<T> CommandQueue<T> {
    pub fn new(depth: u16) -> Result<Self, Error> {
        if !(2..=512).contains(&depth) {
            return Err(Error::BadIndex);
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(depth as usize)
            .map_err(|_| Error::NoMemory)?;
        slots.resize_with(depth as usize, || None);
        let mut quarantine = VecDeque::new();
        quarantine
            .try_reserve_exact(9)
            .map_err(|_| Error::NoMemory)?;
        Ok(Self {
            slots,
            quarantine,
            wp: 0,
            rp: 0,
            terminal: false,
        })
    }
    pub fn write_pointer(&self) -> u16 {
        self.wp
    }
    pub fn pending(&self) -> usize {
        (self.wp + self.slots.len() as u16 - self.rp) as usize % self.slots.len()
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub fn model_resource(&self, slot: usize) -> Option<&T> {
        self.slots.get(slot)?.as_ref()?.resource.as_ref()
    }
    /// # Safety
    /// The owning native device has completed its hardware stop/idle fence;
    /// no DMA or prefetch can reference any queued/quarantined allocation.
    pub unsafe fn reclaim_fenced(&mut self) {
        for entry in self.slots.iter_mut().flatten() {
            drop(entry.resource.take());
        }
        self.slots.iter_mut().for_each(|slot| *slot = None);
        self.quarantine.clear();
        self.terminal = true;
    }
    pub fn is_full(&self) -> bool {
        (self.wp + 1) % self.slots.len() as u16 == self.rp
    }
    /// The owner is retained and marked issued BEFORE any external descriptor
    /// or doorbell access. An ambiguous failure returns no resource and closes
    /// the queue; caller/drop cannot recycle published mappings.
    pub fn submit(
        &mut self,
        resource: T,
        publish: impl FnOnce(u16, u16, &T) -> Result<(), Error>,
    ) -> Result<u16, (Error, Option<T>)> {
        if self.terminal {
            return Err((Error::Terminal, Some(resource)));
        }
        if self.is_full() {
            return Err((Error::Full, Some(resource)));
        }
        let slot = self.wp;
        let next = (slot + 1) % self.slots.len() as u16;
        if self.slots[slot as usize].is_some() {
            self.terminal = true;
            return Err((Error::BadIndex, Some(resource)));
        }
        self.slots[slot as usize] = Some(Entry {
            issued: true,
            resource: Some(resource),
        });
        let entry = self.slots[slot as usize].as_ref().unwrap();
        let result = publish(slot, next, entry.resource.as_ref().unwrap());
        self.wp = next;
        if result.is_err() {
            self.terminal = true;
            return Err((Error::Publish, None));
        }
        Ok(slot)
    }
    pub fn observe(&mut self, rp: u16) -> Result<Vec<T>, Error> {
        if self.terminal {
            return Err(Error::Terminal);
        }
        let depth = self.slots.len() as u16;
        if rp >= depth {
            self.terminal = true;
            return Err(Error::BadIndex);
        }
        let count = (rp + depth - self.rp) % depth;
        let pending = (self.wp + depth - self.rp) % depth;
        if count > pending {
            self.terminal = true;
            return Err(Error::BadIndex);
        }
        // Validate the entire movement before changing any retained ownership.
        for offset in 0..count {
            let slot = (self.rp + offset) % depth;
            if !self.slots[slot as usize]
                .as_ref()
                .is_some_and(|entry| entry.issued && entry.resource.is_some())
            {
                self.terminal = true;
                return Err(Error::BadIndex);
            }
        }
        let mut retired = Vec::new();
        retired
            .try_reserve_exact(count as usize)
            .map_err(|_| Error::NoMemory)?;
        for _ in 0..count {
            let mut entry = self.slots[self.rp as usize].take().unwrap();
            self.quarantine.push_back(entry.resource.take().unwrap());
            self.rp = (self.rp + 1) % depth;
            if self.quarantine.len() > 8 {
                retired.push(self.quarantine.pop_front().unwrap());
            }
        }
        Ok(retired)
    }
}
impl<T> Drop for CommandQueue<T> {
    fn drop(&mut self) {
        for entry in self.slots.iter_mut().filter_map(Option::as_mut) {
            if entry.issued {
                if let Some(resource) = entry.resource.take() {
                    core::mem::forget(resource);
                }
            }
        }
        while let Some(resource) = self.quarantine.pop_front() {
            core::mem::forget(resource);
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "command_queue_tests.rs"]
mod tests;
