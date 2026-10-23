// SPDX-License-Identifier: GPL-2.0-or-later
//! Serialized boot Copy Engine rings, shared by PCI BMI and CE7 diagnostics.
//!
//! Linux references: `ath10k/ce.c` ring init, send, RX post and completion
//! paths. Addresses are DMA32; CPU access always uses the coherent mapping.
//! The PCI owner must stop these engines before releasing their memory.

use core::sync::atomic::{compiler_fence, Ordering};

use super::ce::{self, Ath10kMmio, RingConfig};
use super::hw::{ce_off, HwRev};

/// Order coherent descriptor/data access against a PCI peripheral. A Rust
/// atomic fence alone is inner-shareable on ARM and does not order PCI DMA.
pub(super) fn barrier() {
    compiler_fence(Ordering::SeqCst);
    #[cfg(target_arch = "aarch64")]
    // SAFETY: orders outer-shareable memory; no object or stack is accessed.
    unsafe {
        core::arch::asm!("dmb osh", options(nostack, preserves_flags));
    }
    #[cfg(not(target_arch = "aarch64"))]
    core::sync::atomic::fence(Ordering::SeqCst);
    compiler_fence(Ordering::SeqCst);
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DmaError {
    Authority,
    BadConfig,
    Busy,
    DeviceGone,
    BadCompletion,
}

/// Byte access to coherent storage. Implementations retain a stable DMA
/// address and use volatile CPU accesses when the device can update bytes.
pub(super) trait Memory {
    fn len(&self) -> usize;
    fn dma_address(&self) -> u64;
    fn read(&self, offset: usize) -> u8;
    fn write(&mut self, offset: usize, value: u8);
    fn read16(&self, offset: usize) -> u16 {
        u16::from_le_bytes([self.read(offset), self.read(offset + 1)])
    }
}

impl Memory for narf_io::DmaBuffer {
    fn len(&self) -> usize {
        self.len()
    }
    fn dma_address(&self) -> u64 {
        self.dma_addr().raw()
    }
    fn read(&self, offset: usize) -> u8 {
        assert!(offset < self.len());
        // SAFETY: checked offset in the retained coherent CPU mapping.
        unsafe { self.cpu_ptr::<u8>().add(offset).read_volatile() }
    }
    fn write(&mut self, offset: usize, value: u8) {
        assert!(offset < self.len());
        // SAFETY: checked offset; ownership/CE completion controls access.
        unsafe { self.cpu_mut_ptr::<u8>().add(offset).write_volatile(value) }
    }
    fn read16(&self, offset: usize) -> u16 {
        assert!(offset & 1 == 0 && offset + 2 <= self.len());
        // SAFETY: aligned u16 completion field in the retained allocation.
        // A single access avoids tearing across the device's publication.
        u16::from_le(unsafe {
            self.cpu_ptr::<u8>()
                .add(offset)
                .cast::<u16>()
                .read_volatile()
        })
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) enum Direction {
    Source,
    Destination,
}

/// One outstanding boot transfer at a time; wrap and completion indices
/// still follow the real CE protocol. Timeout never cancels ownership.
#[derive(Debug)]
pub(super) struct Ring<B> {
    memory: B,
    base: u64,
    entries: u32,
    next: u32,
    pending: Option<(u32, u16)>,
    direction: Direction,
}

impl<B: Memory> Ring<B> {
    pub fn new(
        memory: B,
        hw: HwRev,
        pipe: u8,
        entries: u32,
        direction: Direction,
    ) -> Result<Self, DmaError> {
        let base = hw
            .registers()
            .and_then(|r| r.ce_base(pipe))
            .ok_or(DmaError::BadConfig)?;
        let end = memory
            .dma_address()
            .checked_add(memory.len() as u64)
            .ok_or(DmaError::BadConfig)?;
        if !entries.is_power_of_two()
            || !(2..=8192).contains(&entries)
            || memory.len() < entries as usize * 8
            || memory.dma_address() & 7 != 0
            || end > 1u64 << 32
        {
            return Err(DmaError::BadConfig);
        }
        Ok(Self {
            memory,
            base,
            entries,
            next: 0,
            pending: None,
            direction,
        })
    }

    pub fn initialize(
        &mut self,
        mmio: &mut impl Ath10kMmio,
        hw: HwRev,
        pipe: u8,
        max: u16,
    ) -> Result<(), DmaError> {
        if !mmio.authorized() {
            return Err(DmaError::Authority);
        }
        if self.pending.is_some() || hw.registers().and_then(|r| r.ce_base(pipe)) != Some(self.base)
        {
            return Err(DmaError::Busy);
        }
        let (read_reg, write_reg) = match self.direction {
            Direction::Source => (ce_off::CURRENT_SRRI, ce_off::SR_WR_INDEX),
            Direction::Destination => (ce_off::CURRENT_DRRI, ce_off::DR_WR_INDEX),
        };
        let read = mmio.read32(self.base + read_reg);
        let write = mmio.read32(self.base + write_reg);
        if read == u32::MAX || write == u32::MAX {
            return Err(DmaError::DeviceGone);
        }
        // The reset must have stopped inherited descriptors. Do not point
        // hardware at a new allocation if its previous ring was nonempty.
        if read != write || read >= self.entries {
            return Err(DmaError::Busy);
        }
        for i in 0..self.entries as usize * 8 {
            self.memory.write(i, 0);
        }
        barrier();
        let config = RingConfig {
            hw_rev: hw,
            pipe,
            base_phys_lo: self.memory.dma_address() as u32,
            nentries: self.entries,
            dmax_length: max,
            host_int_disabled: true,
            src_byte_swap: false,
        };
        match self.direction {
            Direction::Source => ce::program_src_ring(mmio, &config),
            Direction::Destination => ce::program_dst_ring(mmio, &config),
        }
        .map_err(|_| DmaError::BadConfig)?;
        self.next = read;
        mmio.write32(self.base + write_reg, read);
        // Low watermark=0, high watermark=entry count (qcax_wm_*).
        mmio.write32(
            self.base
                + if self.direction == Direction::Source {
                    0x4c
                } else {
                    0x50
                },
            self.entries,
        );
        if !mmio.authorized() {
            return Err(DmaError::Authority);
        }
        Ok(())
    }

    pub fn post(
        &mut self,
        mmio: &mut impl Ath10kMmio,
        address: u32,
        bytes: u16,
    ) -> Result<(), DmaError> {
        if !mmio.authorized() {
            return Err(DmaError::Authority);
        }
        if self.pending.is_some() {
            return Err(DmaError::Busy);
        }
        if bytes == 0 {
            return Err(DmaError::BadConfig);
        }
        let slot = self.next;
        let offset = slot as usize * 8;
        for (i, byte) in address.to_le_bytes().iter().enumerate() {
            self.memory.write(offset + i, *byte);
        }
        let length = if self.direction == Direction::Source {
            bytes
        } else {
            0
        };
        for (i, byte) in length.to_le_bytes().iter().enumerate() {
            self.memory.write(offset + 4 + i, *byte);
        }
        self.memory.write(offset + 6, 0);
        self.memory.write(offset + 7, 0);
        self.next = (slot + 1) & (self.entries - 1);
        self.pending = Some((slot, bytes));
        barrier();
        mmio.write32(
            self.base
                + if self.direction == Direction::Source {
                    ce_off::SR_WR_INDEX
                } else {
                    ce_off::DR_WR_INDEX
                },
            self.next,
        );
        if !mmio.authorized() {
            return Err(DmaError::Authority);
        }
        Ok(())
    }

    pub fn completion(&mut self, mmio: &mut impl Ath10kMmio) -> Result<Option<u16>, DmaError> {
        if !mmio.authorized() {
            return Err(DmaError::Authority);
        }
        let Some((slot, capacity)) = self.pending else {
            return Ok(None);
        };
        let count = match self.direction {
            Direction::Source => {
                let read = mmio.read32(self.base + ce_off::CURRENT_SRRI);
                if read == u32::MAX {
                    return Err(DmaError::DeviceGone);
                }
                if read == slot {
                    return Ok(None);
                }
                if read != self.next {
                    return Err(DmaError::BadCompletion);
                }
                capacity
            }
            Direction::Destination => {
                let offset = slot as usize * 8 + 4;
                let count = self.memory.read16(offset);
                if count == 0 {
                    return Ok(None);
                }
                if count > capacity {
                    return Err(DmaError::BadCompletion);
                }
                count
            }
        };
        barrier();
        self.pending = None;
        let offset = slot as usize * 8 + 4;
        self.memory.write(offset, 0);
        self.memory.write(offset + 1, 0);
        Ok(Some(count))
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests;
