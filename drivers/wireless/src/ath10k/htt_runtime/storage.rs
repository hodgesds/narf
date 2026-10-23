// SPDX-License-Identifier: GPL-2.0-or-later
//! Retained native ath10k PCI HTT DMA layout. Linux htt{,_rx,_tx}.{c,h}.
use super::{Config, DmaConfig, Error};
use crate::ath10k::dma::{barrier, Memory};
use alloc::{collections::VecDeque, vec::Vec};

pub(super) const RX_SLOTS: usize = 2048;
pub(super) const RX_FILL: usize = RX_SLOTS / 2 - 1;
pub(super) const RX_BUFFER: usize = 2048;
pub(super) const RX_DESCRIPTOR: usize = 300;
pub(super) const EXT_DESCRIPTOR: usize = 64;
const QSTATE_PEERS: usize = 528;
const QSTATE_TIDS: usize = 8;
const QSTATE_BYTES: usize =
    QSTATE_PEERS * QSTATE_TIDS + QSTATE_PEERS.div_ceil(32) * QSTATE_TIDS * 4 + 4;

#[derive(Debug)]
pub(in crate::ath10k) struct Storage<B> {
    pub ring: B,
    pub producer: B,
    pub buffers: Vec<Option<B>>,
    pub fragments: Option<B>,
    pub qstate: Option<B>,
    pub next: usize,
    pub read: usize,
    pub order: VecDeque<usize>,
    pub filled: usize,
    pub tx: super::tx::Pool<B>,
}
pub(super) fn zero<B: Memory>(mut memory: B, minimum: usize) -> Result<B, Error> {
    let address = memory.dma_address();
    if memory.len() < minimum
        || address == 0
        || address & 3 != 0
        || address
            .checked_add(memory.len() as u64)
            .is_none_or(|v| v > 1 << 32)
    {
        return Err(Error::Memory);
    }
    for at in 0..memory.len() {
        memory.write(at, 0);
    }
    Ok(memory)
}
pub(super) fn write32(memory: &mut impl Memory, at: usize, value: u32) {
    for (offset, byte) in value.to_le_bytes().iter().enumerate() {
        memory.write(at + offset, *byte);
    }
}
impl<B: Memory> Storage<B> {
    /// Nothing is advertised while this owner is being constructed. The
    /// physical transport installs it under fail-safe Drop before returning
    /// any address to an HTT command encoder.
    pub fn allocate(
        config: Config,
        mut allocate: impl FnMut(usize) -> Result<B, Error>,
    ) -> Result<Self, Error> {
        if config.pending == 0 || config.pending > 2500 {
            return Err(Error::Memory);
        }
        let mut order = VecDeque::new();
        order
            .try_reserve_exact(RX_FILL)
            .map_err(|_| Error::NoMemory)?;
        order.extend(0..RX_FILL);
        let mut ring = zero(allocate(RX_SLOTS * 4)?, RX_SLOTS * 4)?;
        let mut producer = zero(allocate(4)?, 4)?;
        let mut buffers = Vec::new();
        buffers
            .try_reserve_exact(RX_SLOTS)
            .map_err(|_| Error::NoMemory)?;
        for index in 0..RX_SLOTS {
            if index < RX_FILL {
                let buffer = zero(allocate(RX_BUFFER)?, RX_BUFFER)?;
                write32(&mut ring, index * 4, buffer.dma_address() as u32);
                buffers.push(Some(buffer));
            } else {
                buffers.push(None);
            }
        }
        let fragments = if config.continuous {
            Some(zero(
                allocate(usize::from(config.pending) * EXT_DESCRIPTOR)?,
                usize::from(config.pending) * EXT_DESCRIPTOR,
            )?)
        } else {
            None
        };
        let qstate = if config.pfc {
            Some(zero(allocate(QSTATE_BYTES)?, QSTATE_BYTES)?)
        } else {
            None
        };
        // Producer belongs to the host. Descriptors and the zero attention
        // fields must become visible before firmware observes this index.
        barrier();
        write32(&mut producer, 0, RX_FILL as u32);
        barrier();
        Ok(Self {
            ring,
            producer,
            buffers,
            fragments,
            qstate,
            next: RX_FILL,
            read: 0,
            order,
            filled: RX_FILL,
            tx: super::tx::Pool::new(config.pending)?,
        })
    }
    pub fn configuration(&self) -> DmaConfig {
        DmaConfig {
            ring: self.ring.dma_address() as u32,
            producer: self.producer.dma_address() as u32,
            initial: self.next as u16,
            fragments: self
                .fragments
                .as_ref()
                .map_or(0, |b| b.dma_address() as u32),
            qstate: self.qstate.as_ref().map_or(0, |b| b.dma_address() as u32),
        }
    }
}
