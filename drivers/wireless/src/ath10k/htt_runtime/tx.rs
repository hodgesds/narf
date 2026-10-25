// SPDX-License-Identifier: GPL-2.0-or-later
//! Payload ownership ends at the HTT terminal TX indication, never CE completion.
use super::storage::{write32, zero};
use super::{Config, Error};
use crate::ath10k::dma::{barrier, Memory};
use alloc::vec::Vec;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath10k) enum Kind {
    Raw,
    Native,
    Ethernet,
    Management,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath10k) struct Parameters {
    pub kind: Kind,
    pub vdev: u8,
    pub tid: u8,
    pub hardware_crypto: bool,
}
#[derive(Debug)]
struct Pending<B> {
    _payload: B,
    _fragments: Option<B>,
    management: bool,
}
#[derive(Debug)]
pub(in crate::ath10k) struct Pool<B> {
    slots: Vec<Option<Pending<B>>>,
    next: usize,
}
impl<B: Memory> Pool<B> {
    pub fn new(limit: u16) -> Result<Self, Error> {
        if limit == 0 || limit > 2500 {
            return Err(Error::Memory);
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(usize::from(limit))
            .map_err(|_| Error::NoMemory)?;
        slots.extend(core::iter::repeat_with(|| None).take(usize::from(limit)));
        Ok(Self { slots, next: 0 })
    }
    pub fn pending(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub fn snapshot(&self, id: u16) -> Option<(u64, Vec<u8>)> {
        let slot = self.slots.get(usize::from(id))?.as_ref()?;
        Some((
            slot._payload.dma_address(),
            (0..slot._payload.len())
                .map(|at| slot._payload.read(at))
                .collect(),
        ))
    }
    pub fn prepare(
        &mut self,
        config: Config,
        shared: Option<&mut B>,
        parameters: Parameters,
        bytes: &[u8],
        mut allocate: impl FnMut(usize) -> Result<B, Error>,
    ) -> Result<(u16, Vec<u8>), Error> {
        if parameters.vdev >= 64
            || parameters.tid > 17
            || bytes.len() > u16::MAX as usize
            || bytes.len()
                < if parameters.kind == Kind::Ethernet {
                    14
                } else {
                    24
                }
        {
            return Err(Error::Malformed);
        }
        let id = (0..self.slots.len())
            .map(|i| (self.next + i) % self.slots.len())
            .find(|&i| self.slots[i].is_none())
            .ok_or(Error::Busy)?;
        let prefetch = bytes.len().min(50).div_ceil(4) * 4;
        let mut payload = zero(
            allocate(bytes.len().max(prefetch))?,
            bytes.len().max(prefetch),
        )?;
        for (at, byte) in bytes.iter().enumerate() {
            payload.write(at, *byte);
        }
        if parameters.kind == Kind::Management && config.major < 3 {
            if bytes[1] & 0x40 != 0 && !parameters.hardware_crypto {
                return Err(Error::Unsupported);
            }
            let mut body = Vec::new();
            body.try_reserve_exact(56).map_err(|_| Error::NoMemory)?;
            body.resize(56, 0);
            body[0] = 7;
            for (at, value) in [
                (4, payload.dma_address() as u32),
                (8, id as u32),
                (12, bytes.len() as u32),
                (16, u32::from(parameters.vdev)),
            ] {
                body[at..at + 4].copy_from_slice(&value.to_le_bytes());
            }
            let length = bytes.len().min(32);
            body[20..20 + length].copy_from_slice(&bytes[..length]);
            self.slots[id] = Some(Pending {
                _payload: payload,
                _fragments: None,
                management: true,
            });
            self.next = (id + 1) % self.slots.len();
            barrier();
            return Ok((id as u16, body));
        }
        let (mut flags0, mut frags) = (
            match parameters.kind {
                Kind::Raw => 1,
                Kind::Native => 0x21,
                Kind::Ethernet => 0x40,
                Kind::Management => 0x61,
            },
            None,
        );
        if !parameters.hardware_crypto {
            flags0 |= 4;
        }
        let address = if parameters.kind == Kind::Management {
            payload.dma_address() as u32
        } else if config.continuous {
            let shared = shared.ok_or(Error::Memory)?;
            let at = id * 64;
            if at + 64 > shared.len() {
                return Err(Error::Memory);
            }
            for offset in at..at + 64 {
                shared.write(offset, 0);
            }
            // Wave2 fragment uses the packed triple-word-address view: low32,
            // high16, len16. The descriptor's TSO prefix occupies16 bytes.
            write32(shared, at + 16, payload.dma_address() as u32);
            for (offset, byte) in (bytes.len() as u16).to_le_bytes().iter().enumerate() {
                shared.write(at + 22 + offset, *byte);
            }
            (shared.dma_address() + at as u64) as u32
        } else {
            let mut list = zero(allocate(16)?, 16)?;
            write32(&mut list, 0, payload.dma_address() as u32);
            write32(&mut list, 4, bytes.len() as u32);
            let address = list.dma_address() as u32;
            frags = Some(list);
            address
        };
        let mut body = Vec::new();
        body.try_reserve_exact(16 + prefetch)
            .map_err(|_| Error::NoMemory)?;
        body.extend_from_slice(&[1, flags0]);
        let flags1 = 0x800 | u16::from(parameters.vdev) | (u16::from(parameters.tid) << 6);
        for word in [flags1, bytes.len() as u16, id as u16] {
            body.extend_from_slice(&word.to_le_bytes());
        }
        body.extend_from_slice(&address.to_le_bytes());
        body.extend_from_slice(&0xffffu32.to_le_bytes());
        for at in 0..prefetch {
            body.push(payload.read(at));
        }
        // Store before any command can advertise the payload/fragment address.
        self.slots[id] = Some(Pending {
            _payload: payload,
            _fragments: frags,
            management: false,
        });
        self.next = (id + 1) % self.slots.len();
        barrier();
        Ok((id as u16, body))
    }
    pub fn complete(&mut self, ids: &[u16], management: bool) -> Result<(), Error> {
        for (at, id) in ids.iter().enumerate() {
            if ids[..at].contains(id)
                || self.slots.get(usize::from(*id)).is_none_or(|s| {
                    s.as_ref()
                        .is_none_or(|pending| pending.management != management)
                })
            {
                return Err(Error::Malformed);
            }
        }
        // All IDs are validated first: a malformed batch cannot partially free DMA.
        barrier();
        for id in ids {
            self.slots[usize::from(*id)] = None;
        }
        Ok(())
    }
}
pub(in crate::ath10k) fn completion(bytes: &[u8]) -> Result<(u8, Vec<u16>), Error> {
    if bytes.len() < 4 || bytes[0] != 7 || bytes[1] & 7 > 3 || bytes[2] == 0 {
        return Err(Error::Malformed);
    }
    let count = usize::from(bytes[2]);
    let ids = bytes.get(4..4 + count * 2).ok_or(Error::Malformed)?;
    let mut result = Vec::new();
    result
        .try_reserve_exact(count)
        .map_err(|_| Error::NoMemory)?;
    for id in ids.chunks_exact(2) {
        result.push(u16::from_le_bytes(id.try_into().unwrap()));
    }
    Ok((bytes[1] & 7, result))
}
