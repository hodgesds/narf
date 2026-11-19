// SPDX-License-Identifier: GPL-2.0-or-later
//! WMI host-memory allocations are retained with all CE/runtime DMA before
//! INIT publishes their addresses; reset/drain is required before recycling.
use super::{allocate, PciBoot};
use crate::ath10k::{
    dma::{barrier, Memory},
    wmi_boot::{Error, HostMemory, MemoryChunk, MemoryPlan},
};
use alloc::vec::Vec;
impl HostMemory for PciBoot {
    fn retain_wmi_memory(&mut self, plans: &[MemoryPlan]) -> Result<Vec<MemoryChunk>, Error> {
        if !super::Ath10kMmio::authorized(&self.mmio) {
            return Err(Error::Memory);
        }
        if self.poisoned || !self.hif_live || plans.len() > 16 {
            return Err(Error::Memory);
        }
        let runtime = self.hif.as_mut().ok_or(Error::Memory)?;
        if runtime.wmi_memory.is_some() {
            return Err(Error::Failed);
        }
        let mut memories = Vec::new();
        let mut chunks = Vec::new();
        memories
            .try_reserve_exact(plans.len())
            .map_err(|_| Error::NoMemory)?;
        chunks
            .try_reserve_exact(plans.len())
            .map_err(|_| Error::NoMemory)?;
        for plan in plans {
            if plan.bytes == 0 {
                return Err(Error::Memory);
            }
            let mut buffer = allocate(plan.bytes as usize).map_err(|_| Error::NoMemory)?;
            let address = buffer.dma_address();
            if address == 0
                || address & 3 != 0
                || address
                    .checked_add(u64::from(plan.bytes))
                    .is_none_or(|v| v > 1 << 32)
            {
                return Err(Error::Memory);
            }
            for offset in 0..buffer.len() {
                buffer.write(offset, 0);
            }
            chunks.push(MemoryChunk {
                id: plan.id,
                address: address as u32,
                bytes: plan.bytes,
            });
            memories.push(buffer);
        }
        runtime.wmi_memory = Some(memories);
        barrier();
        Ok(chunks)
    }
}
