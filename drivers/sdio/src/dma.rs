// SPDX-License-Identifier: GPL-2.0-or-later
//! SDHCI host DMA engine state: ADMA2 descriptor table, align buffer and
//! the bounce buffer every data command goes through.
//!
//! Linux references (`drivers/mmc/host/sdhci.c`): `sdhci_setup_host`
//! (one `dma_alloc_coherent` region holding the align buffer then the ADMA
//! table, 8-byte table alignment check), `sdhci_allocate_bounce_buffer` /
//! `sdhci_pre_dma_transfer` (bounce copy + `dma_sync_single_for_device`
//! with the request direction), `sdhci_prepare_dma` / `sdhci_config_dma` /
//! `sdhci_set_adma_addr` / `sdhci_set_sdma_addr`, the `SDHCI_INT_DMA_END`
//! boundary restart in `sdhci_data_irq`, and `sdhci_request_done`
//! (`dma_sync_single_for_cpu` + copy out for reads).
//!
//! Caller transfer slices are ordinary kernel memory, not `narf_io` DMA
//! memory, so they are never handed to the device: the payload is copied
//! through a host-owned [`narf_io::DmaBuffer`]. That bounce buffer is
//! page-aligned, so the ADMA align-buffer path (`sdhci_adma_table_pre`
//! unaligned head) is never taken here; it remains in the shared table
//! builder for completeness.

use crate::pio::{Data, Registers, MAX_TRANSFER};
use crate::sdhci::adma::{self, Mode, Segment};
use crate::sdhci::regs::*;
use core::sync::atomic::{compiler_fence, fence, Ordering};
use narf_io::{DmaBuffer, DmaDevice, DmaDirection};
use narf_lib::id::DomainId;

/// Host-owned DMA buffers for one controller.
pub struct Engine {
    mode: Mode,
    /// Align buffer ([`adma::ALIGN_BUFFER_SIZE`]) followed by the
    /// descriptor table; absent for SDMA.
    table: Option<DmaBuffer>,
    bounce: DmaBuffer,
    /// Bus address the next SDMA boundary restart programs.
    sdma_next: u64,
    /// Length and direction of the armed transfer.
    armed: Option<(usize, DmaDirection)>,
}
impl core::fmt::Debug for Engine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SdhciDma")
            .field("mode", &self.mode)
            .field("armed", &self.armed.is_some())
            .finish_non_exhaustive()
    }
}

fn within(buffer: &DmaBuffer, mask: u64) -> bool {
    buffer
        .dma_addr()
        .raw()
        .checked_add(buffer.len() as u64 - 1)
        .is_some_and(|end| end <= mask)
}

impl Engine {
    /// Allocate the coherent ADMA region (when `mode` is ADMA) and the
    /// bounce buffer below the mode's DMA mask. `Err` means "this mode
    /// cannot be used" (Linux falls back to SDMA, then PIO).
    pub fn new(device: &DmaDevice, mode: Mode) -> Result<Self, ()> {
        let mask = mode.dma_mask();
        let table = if mode.is_adma() {
            let size = adma::ALIGN_BUFFER_SIZE + adma::TABLE_COUNT * mode.desc_size();
            let table = narf_io::alloc_coherent_for(device, size, DomainId::DRIVER_0, mask)
                .map_err(|_| ())?;
            // Linux: "unable to allocate aligned ADMA descriptor".
            if (table.dma_addr().raw() + adma::ALIGN_BUFFER_SIZE as u64) & (adma::DESC_ALIGN - 1)
                != 0
                || !within(&table, mask)
            {
                return Err(());
            }
            Some(table)
        } else {
            None
        };
        let bounce = narf_io::alloc_coherent_for(device, MAX_TRANSFER, DomainId::DRIVER_0, mask)
            .map_err(|_| ())?;
        if bounce.len() < MAX_TRANSFER
            || bounce.dma_addr().raw() & (adma::ALIGN - 1) != 0
            || !within(&bounce, mask)
        {
            return Err(());
        }
        Ok(Self {
            mode,
            table,
            bounce,
            sdma_next: 0,
            armed: None,
        })
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Bus address of the bounce buffer (tests and diagnostics).
    pub fn bounce_addr(&self) -> u64 {
        self.bounce.dma_addr().raw()
    }

    /// Bus address of the descriptor table, if ADMA.
    pub fn table_addr(&self) -> Option<u64> {
        self.table
            .as_ref()
            .map(|t| t.dma_addr().raw() + adma::ALIGN_BUFFER_SIZE as u64)
    }

    /// `sdhci_prepare_dma` for one bounced segment: copy write data in,
    /// hand the bounce buffer to the device with the request direction,
    /// build the ADMA table (or program the SDMA address), program the
    /// table address and select the DMA mode in HOST_CONTROL. Nothing is
    /// issued here; an `Err` leaves the transfer to PIO.
    pub fn prepare<R: Registers>(&mut self, io: &mut R, data: &Data<'_>) -> Result<(), ()> {
        let (len, direction) = match data {
            Data::Read { bytes, .. } => (bytes.len(), DmaDirection::FromDevice),
            Data::Write { bytes, .. } => (bytes.len(), DmaDirection::ToDevice),
        };
        if len == 0 || len > MAX_TRANSFER {
            return Err(());
        }
        if let Data::Write { bytes, .. } = data {
            self.bounce.as_mut_slice()[..len].copy_from_slice(bytes);
        }
        // Invariant #4: fence around the cache maintenance (narf_io also
        // fences inside) so no payload store is reordered past the clean.
        compiler_fence(Ordering::SeqCst);
        self.bounce.sync_for_device(0, len, direction);
        compiler_fence(Ordering::SeqCst);
        let addr = self.bounce.dma_addr().raw();
        if let Some(table) = self.table.as_mut() {
            let align_addr = table.dma_addr().raw();
            let table_addr = align_addr + adma::ALIGN_BUFFER_SIZE as u64;
            let built = adma::table_pre(
                &mut table.as_mut_slice()[adma::ALIGN_BUFFER_SIZE..],
                self.mode.desc_size(),
                &[Segment { addr, len }],
                align_addr,
                false,
            )
            .map_err(|_| ())?;
            if !built.align.is_empty() {
                return Err(());
            }
            // Descriptor stores must be visible before the doorbell-like
            // ADMA address/COMMAND MMIO writes (Linux relies on writel's
            // wmb()).
            fence(Ordering::SeqCst);
            io.write32(ADMA_ADDRESS, table_addr as u32);
            if self.mode == Mode::Adma64 {
                io.write32(ADMA_ADDRESS_HI, (table_addr >> 32) as u32);
            }
        } else {
            fence(Ordering::SeqCst);
            io.write32(DMA_ADDRESS, addr as u32);
            self.sdma_next = addr;
        }
        let control = io.read8(HOST_CONTROL);
        io.write8(
            HOST_CONTROL,
            (control & !CTRL_DMA_MASK) | self.mode.host_control(),
        );
        self.armed = Some((len, direction));
        Ok(())
    }

    /// `sdhci_data_irq` `SDHCI_INT_DMA_END`: SDMA stopped at a buffer
    /// boundary; restart at the next 512 KiB boundary (the controller's
    /// own address is not trusted, as in Linux).
    pub fn sdma_boundary<R: Registers>(&mut self, io: &mut R) {
        if self.mode != Mode::Sdma {
            return;
        }
        self.sdma_next = (self.sdma_next & !(DEFAULT_BOUNDARY_SIZE - 1)) + DEFAULT_BOUNDARY_SIZE;
        io.write32(DMA_ADDRESS, self.sdma_next as u32);
    }

    /// `sdhci_request_done`: return the bounce buffer to the CPU with the
    /// request direction and copy read data out.
    pub fn complete(&mut self, data: &mut Data<'_>) {
        let Some((len, direction)) = self.armed.take() else {
            return;
        };
        compiler_fence(Ordering::SeqCst);
        self.bounce.sync_for_cpu(0, len, direction);
        compiler_fence(Ordering::SeqCst);
        if let Data::Read { bytes, .. } = data {
            bytes[..len].copy_from_slice(&self.bounce.as_slice()[..len]);
        }
    }

    /// Length and streaming direction of the armed transfer.
    pub fn armed(&self) -> Option<(usize, DmaDirection)> {
        self.armed
    }

    /// Forget an armed transfer whose command was never issued.
    pub fn disarm(&mut self) {
        self.armed = None;
    }

    /// Descriptor `index` of the current table (tests and diagnostics,
    /// Linux `sdhci_adma_show_error`).
    pub fn descriptor(&self, index: usize) -> Option<(u16, u16, u64)> {
        let table = self.table.as_ref()?;
        adma::read_desc(
            &table.as_slice()[adma::ALIGN_BUFFER_SIZE..],
            index,
            self.mode.desc_size(),
        )
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "dma_tests.rs"]
mod tests;
