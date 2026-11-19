// SPDX-License-Identifier: GPL-2.0-or-later
//! Native legacy RX: validate/copy a complete A-MSDU before buffer repost.
use super::{
    storage::{write32, Storage, RX_BUFFER, RX_DESCRIPTOR, RX_SLOTS},
    Error,
};
use crate::ath10k::dma::{barrier, Memory};
use alloc::vec::Vec;
#[derive(Debug)]
pub(in crate::ath10k) struct Msdu {
    pub descriptor: [u8; RX_DESCRIPTOR],
    pub payload: Vec<u8>,
    pub offload: Option<Offload>,
}
impl<B: Memory> Storage<B> {
    pub fn pop_amsdu(&mut self, authorized: impl Fn() -> bool) -> Result<Vec<Msdu>, Error> {
        if !authorized() {
            return Err(Error::Memory);
        }
        let mut frames = Vec::new();
        frames.try_reserve_exact(3).map_err(|_| Error::NoMemory)?;
        let mut consumed = 0;
        loop {
            if frames.len() == 31 {
                return Err(Error::Malformed);
            }
            let index = *self.order.get(consumed).ok_or(Error::Malformed)?;
            let buffer = self.buffers[index].as_ref().ok_or(Error::Memory)?;
            let attention = buffer.read32(4);
            if attention & (1 << 31) == 0 {
                return Err(Error::Malformed);
            }
            barrier();
            let mut descriptor = [0; RX_DESCRIPTOR];
            for (at, byte) in descriptor.iter_mut().enumerate() {
                *byte = buffer.read(at);
            }
            let invalid = attention & ((1 << 17) | (1 << 27)) != 0;
            let length = if invalid {
                0
            } else {
                (buffer.read32(24) & 0x3fff) as usize
            };
            let chains = usize::from(buffer.read(10));
            let mut payload = Vec::new();
            payload
                .try_reserve_exact(length)
                .map_err(|_| Error::NoMemory)?;
            let first = length.min(RX_BUFFER - RX_DESCRIPTOR);
            for at in RX_DESCRIPTOR..RX_DESCRIPTOR + first {
                payload.push(buffer.read(at));
            }
            let mut left = length - first;
            consumed += 1;
            for _ in 0..chains {
                let index = *self.order.get(consumed).ok_or(Error::Malformed)?;
                let buffer = self.buffers[index].as_ref().ok_or(Error::Memory)?;
                let count = left.min(RX_BUFFER);
                for at in 0..count {
                    payload.push(buffer.read(at));
                }
                left -= count;
                consumed += 1;
            }
            if left != 0 {
                return Err(Error::Malformed);
            }
            let last = u32::from_le_bytes(descriptor[56..60].try_into().unwrap()) & (1 << 15) != 0;
            frames.try_reserve(1).map_err(|_| Error::NoMemory)?;
            frames.push(Msdu {
                descriptor,
                payload,
                offload: None,
            });
            if last {
                break;
            }
        }
        if !authorized() {
            return Err(Error::Memory);
        }
        // At this point every descriptor and chained byte is copied; MSDU_DONE
        // proves target completion for the complete chain. Preserve allocations,
        // clear attention, and publish these same buffers at the producer tail.
        for _ in 0..consumed {
            let index = self.order.pop_front().ok_or(Error::Memory)?;
            let buffer = self.buffers[index].as_mut().ok_or(Error::Memory)?;
            write32(buffer, 4, 0);
            write32(&mut self.ring, self.next * 4, buffer.dma_address() as u32);
            self.order.push_back(index);
            self.next = (self.next + 1) & (RX_SLOTS - 1);
            self.read = (self.read + 1) & (RX_SLOTS - 1);
        }
        barrier();
        write32(&mut self.producer, 0, self.next as u32);
        barrier();
        Ok(frames)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath10k) struct Range {
    pub count: u8,
    pub status: u8,
}
#[derive(Debug)]
pub(in crate::ath10k) struct Indication {
    pub peer: u16,
    pub tid: u8,
    pub ranges: Vec<Range>,
}
pub(in crate::ath10k) fn indication(bytes: &[u8]) -> Result<Indication, Error> {
    if bytes.len() < 48 || bytes[0] != 1 {
        return Err(Error::Malformed);
    }
    let count = usize::from(bytes[7]);
    let desc = usize::from(u16::from_le_bytes(bytes[44..46].try_into().unwrap()));
    let begin = 48 + desc.div_ceil(4) * 4;
    let ranges = bytes
        .get(begin..begin + count * 4)
        .ok_or(Error::Malformed)?;
    let mut result = Vec::new();
    result
        .try_reserve_exact(count)
        .map_err(|_| Error::NoMemory)?;
    for range in ranges.chunks_exact(4) {
        if range[0] == 0 {
            return Err(Error::Malformed);
        }
        result.push(Range {
            count: range[0],
            status: range[1],
        });
    }
    Ok(Indication {
        peer: u16::from_le_bytes(bytes[2..4].try_into().unwrap()),
        tid: bytes[1] & 31,
        ranges: result,
    })
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath10k) struct Offload {
    pub peer: u16,
    pub vdev: u8,
    pub tid: u8,
    pub flags: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath10k) struct Pointer {
    pub address: u32,
    pub length: u16,
    pub fw_desc: u8,
}
#[derive(Debug)]
pub(in crate::ath10k) struct InOrder {
    pub peer: u16,
    pub vdev: u8,
    pub tid: u8,
    pub offload: bool,
    pub fragment: bool,
    pub pointers: Vec<Pointer>,
}
pub(in crate::ath10k) fn in_order(bytes: &[u8]) -> Result<InOrder, Error> {
    if bytes.len() < 8 || bytes[0] != 0x12 {
        return Err(Error::Malformed);
    }
    let count = usize::from(u16::from_le_bytes(bytes[6..8].try_into().unwrap()));
    if count > 1023 {
        return Err(Error::Malformed);
    }
    let raw = bytes.get(8..8 + count * 8).ok_or(Error::Malformed)?;
    let mut pointers = Vec::new();
    pointers
        .try_reserve_exact(count)
        .map_err(|_| Error::NoMemory)?;
    for pointer in raw.chunks_exact(8) {
        pointers.push(Pointer {
            address: u32::from_le_bytes(pointer[..4].try_into().unwrap()),
            length: u16::from_le_bytes(pointer[4..6].try_into().unwrap()),
            fw_desc: pointer[6],
        });
    }
    Ok(InOrder {
        peer: u16::from_le_bytes(bytes[2..4].try_into().unwrap()),
        vdev: bytes[4],
        tid: bytes[1] & 31,
        offload: bytes[1] & 0x20 != 0,
        fragment: bytes[1] & 0x40 != 0,
        pointers,
    })
}
impl<B: Memory> Storage<B> {
    pub fn pop_in_order(
        &mut self,
        indication: &InOrder,
        authorized: impl Fn() -> bool,
    ) -> Result<Vec<Msdu>, Error> {
        if !authorized() {
            return Err(Error::Memory);
        }
        let mut indices = Vec::new();
        indices
            .try_reserve_exact(indication.pointers.len())
            .map_err(|_| Error::NoMemory)?;
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(indication.pointers.len())
            .map_err(|_| Error::NoMemory)?;
        for pointer in &indication.pointers {
            let index = self
                .order
                .iter()
                .copied()
                .find(|index| {
                    self.buffers[*index]
                        .as_ref()
                        .is_some_and(|b| b.dma_address() == u64::from(pointer.address))
                })
                .ok_or(Error::Malformed)?;
            if indices.contains(&index) {
                return Err(Error::Malformed);
            }
            indices.push(index);
            let buffer = self.buffers[index].as_ref().ok_or(Error::Memory)?;
            let mut descriptor = [0; RX_DESCRIPTOR];
            let (start, length, offload) = if indication.offload {
                barrier();
                let length = usize::from(buffer.read16(0));
                let meta = Offload {
                    peer: buffer.read16(2),
                    vdev: buffer.read(4),
                    tid: buffer.read(5),
                    flags: buffer.read(6),
                };
                (7, length, Some(meta))
            } else {
                if buffer.read32(4) & (1 << 31) == 0 {
                    return Err(Error::Malformed);
                }
                barrier();
                for (at, byte) in descriptor.iter_mut().enumerate() {
                    *byte = buffer.read(at);
                }
                (RX_DESCRIPTOR, usize::from(pointer.length), None)
            };
            if start + length > RX_BUFFER {
                return Err(Error::Malformed);
            }
            let mut payload = Vec::new();
            payload
                .try_reserve_exact(length)
                .map_err(|_| Error::NoMemory)?;
            for at in start..start + length {
                payload.push(buffer.read(at));
            }
            frames.push(Msdu {
                descriptor,
                payload,
                offload,
            });
        }
        if !authorized() {
            return Err(Error::Memory);
        }
        for index in indices {
            let position = self
                .order
                .iter()
                .position(|&entry| entry == index)
                .ok_or(Error::Memory)?;
            self.order.remove(position);
            let buffer = self.buffers[index].as_mut().ok_or(Error::Memory)?;
            write32(buffer, 4, 0);
            write32(&mut self.ring, self.next * 4, buffer.dma_address() as u32);
            self.order.push_back(index);
            self.next = (self.next + 1) & (RX_SLOTS - 1);
            self.read = (self.read + 1) & (RX_SLOTS - 1);
        }
        barrier();
        write32(&mut self.producer, 0, self.next as u32);
        barrier();
        Ok(frames)
    }
}
