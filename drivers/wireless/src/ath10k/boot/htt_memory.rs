// SPDX-License-Identifier: GPL-2.0-or-later
//! HTT RX, continuous fragments and PFC memory remain with mission-mode DMA.
use super::{allocate, PciBoot};
use crate::ath10k::{
    ce::Ath10kMmio,
    dma::barrier,
    htt_runtime::{storage::Storage, Config, DmaConfig, Error, HttMemory},
};
impl HttMemory for PciBoot {
    fn prepare_htt_tx(
        &mut self,
        config: Config,
        parameters: crate::ath10k::htt_runtime::tx::Parameters,
        bytes: &[u8],
    ) -> Result<(u16, alloc::vec::Vec<u8>), Error> {
        if !self.mmio.authorized() || self.poisoned || !self.hif_live {
            return Err(Error::Memory);
        }
        let storage = self
            .hif
            .as_mut()
            .and_then(|h| h.htt_memory.as_mut())
            .ok_or(Error::Memory)?;
        storage.tx.prepare(
            config,
            storage.fragments.as_mut(),
            parameters,
            bytes,
            |bytes| allocate(bytes).map_err(|_| Error::NoMemory),
        )
    }
    fn pop_htt_in_order(
        &mut self,
        indication: &crate::ath10k::htt_runtime::rx::InOrder,
    ) -> Result<alloc::vec::Vec<crate::ath10k::htt_runtime::rx::Msdu>, Error> {
        if self.poisoned || !self.hif_live {
            return Err(Error::Memory);
        }
        let mmio = &self.mmio;
        let storage = self
            .hif
            .as_mut()
            .and_then(|h| h.htt_memory.as_mut())
            .ok_or(Error::Memory)?;
        storage.pop_in_order(indication, || mmio.authorized())
    }
    fn pop_htt_amsdu(
        &mut self,
    ) -> Result<alloc::vec::Vec<crate::ath10k::htt_runtime::rx::Msdu>, Error> {
        if self.poisoned || !self.hif_live {
            return Err(Error::Memory);
        }
        let mmio = &self.mmio;
        let storage = self
            .hif
            .as_mut()
            .and_then(|h| h.htt_memory.as_mut())
            .ok_or(Error::Memory)?;
        storage.pop_amsdu(|| mmio.authorized())
    }
    fn complete_htt_tx(&mut self, ids: &[u16], management: bool) -> Result<(), Error> {
        if !self.mmio.authorized() || self.poisoned || !self.hif_live {
            return Err(Error::Memory);
        }
        let storage = self
            .hif
            .as_mut()
            .and_then(|h| h.htt_memory.as_mut())
            .ok_or(Error::Memory)?;
        storage.tx.complete(ids, management)
    }
    fn retain_htt_memory(&mut self, config: Config) -> Result<DmaConfig, Error> {
        if !self.mmio.authorized() || self.poisoned || !self.hif_live {
            return Err(Error::Memory);
        }
        let runtime = self.hif.as_mut().ok_or(Error::Memory)?;
        if runtime.htt_memory.is_some() {
            return Err(Error::Failed);
        }
        let storage =
            Storage::allocate(config, |bytes| allocate(bytes).map_err(|_| Error::NoMemory))?;
        let result = storage.configuration();
        // Address production follows ownership transfer. No future can drop
        // this allocation when RX_RING_CFG/FRAG_DESC_BANK_CFG is cancelled.
        runtime.htt_memory = Some(storage);
        barrier();
        if !self.mmio.authorized() {
            return Err(Error::Memory);
        }
        Ok(result)
    }
}
