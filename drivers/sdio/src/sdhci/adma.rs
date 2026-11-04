// SPDX-License-Identifier: GPL-2.0-or-later
//! SDHCI DMA mode selection and the ADMA2 descriptor table.
//!
//! Pure functions over byte slices so the layout is testable without a
//! device. Adapted from Linux `drivers/mmc/host/sdhci.{c,h}`
//! (`sdhci_setup_host` DMA flags, `sdhci_adma_write_desc`,
//! `sdhci_adma_mark_end`, `sdhci_adma_table_pre`, `sdhci_adma_table_post`).

use super::regs::*;

/// Linux `SDHCI_ADMA2_32_DESC_SZ`.
pub const DESC_SIZE_32: usize = 8;
/// Linux `SDHCI_ADMA2_64_DESC_SZ(host)` without v4 mode (packed, 12 bytes).
pub const DESC_SIZE_64: usize = 12;
/// Linux `SDHCI_ADMA2_ALIGN`: ADMA2 data addresses must be 32-bit aligned.
pub const ALIGN: u64 = 4;
/// Linux `SDHCI_ADMA2_DESC_ALIGN`: descriptor table base alignment.
pub const DESC_ALIGN: u64 = 8;
/// Linux `SDHCI_MAX_SEGS`.
pub const MAX_SEGS: usize = 128;
/// Linux `adma_table_cnt = SDHCI_MAX_SEGS * 2 + 1`.
pub const TABLE_COUNT: usize = MAX_SEGS * 2 + 1;
/// Linux `align_buffer_sz = SDHCI_MAX_SEGS * SDHCI_ADMA2_ALIGN`.
pub const ALIGN_BUFFER_SIZE: usize = MAX_SEGS * ALIGN as usize;
/// Linux `host->max_adma` (16-bit length field; 0 encodes 65536).
pub const MAX_ADMA: usize = 65536;
/// Linux `sdhci_adma_table_pre` split size for an over-long segment.
const SPLIT: usize = 32 * 1024;

/// Linux `ADMA2_TRAN_VALID`.
pub const ATTR_TRAN_VALID: u16 = 0x21;
/// Linux `ADMA2_NOP_END_VALID`.
pub const ATTR_NOP_END_VALID: u16 = 0x3;
/// Linux `ADMA2_END`.
pub const ATTR_END: u16 = 0x2;

/// Host data-path DMA mode selected by [`select`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// Single-address SDMA with a 32-bit system address.
    Sdma,
    /// ADMA2, 32-bit descriptors (`SDHCI_CTRL_ADMA32`).
    Adma32,
    /// ADMA2, 12-byte 64-bit descriptors (`SDHCI_CTRL_ADMA64`).
    Adma64,
}
impl Mode {
    pub const fn is_adma(self) -> bool {
        matches!(self, Self::Adma32 | Self::Adma64)
    }
    pub const fn desc_size(self) -> usize {
        match self {
            Self::Adma64 => DESC_SIZE_64,
            _ => DESC_SIZE_32,
        }
    }
    /// Linux `sdhci_set_dma_mask`: 64-bit only for 64-bit ADMA.
    pub const fn dma_mask(self) -> u64 {
        match self {
            Self::Adma64 => u64::MAX,
            _ => u32::MAX as u64,
        }
    }
    /// HOST_CONTROL DMA select (Linux `sdhci_config_dma`).
    pub const fn host_control(self) -> u8 {
        match self {
            Self::Sdma => CTRL_SDMA,
            Self::Adma32 => CTRL_ADMA32,
            Self::Adma64 => CTRL_ADMA64,
        }
    }
    /// The mode left when ADMA buffers cannot be set up (Linux "Unable to
    /// allocate ADMA buffers - falling back to standard DMA").
    pub const fn without_adma(self, caps: u32) -> Option<Self> {
        // SDMA was already removed for a 64-bit host without v4 mode.
        if self.is_adma() && caps & CAPS_CAN_DO_SDMA != 0 && caps & CAPS_CAN_64BIT == 0 {
            Some(Self::Sdma)
        } else {
            None
        }
    }
}

/// Linux `sdhci_setup_host` DMA flag selection for a host without v4 mode,
/// external DMA or DMA-affecting vendor quirks (the platform owner refuses
/// DMA for hosts that need them): SDMA from `SDHCI_CAN_DO_SDMA`; ADMA2 from
/// spec >= 2.00 and `SDHCI_CAN_DO_ADMA2`; 64-bit from `SDHCI_CAN_64BIT`,
/// which removes SDMA (32-bit SDMA address register without v4 mode). ADMA
/// is preferred over SDMA. `None` keeps PIO.
pub const fn select(spec_version: u8, caps: u32) -> Option<Mode> {
    let bits64 = caps & CAPS_CAN_64BIT != 0;
    if spec_version >= SPEC_200 as u8 && caps & CAPS_CAN_DO_ADMA2 != 0 {
        return Some(if bits64 { Mode::Adma64 } else { Mode::Adma32 });
    }
    if caps & CAPS_CAN_DO_SDMA != 0 && !bits64 {
        return Some(Mode::Sdma);
    }
    None
}

/// One device-visible data segment (Linux `sg_dma_address`/`sg_dma_len`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Segment {
    pub addr: u64,
    pub len: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TableError {
    /// Too many segments, zero-length segment or table overflow.
    Overflow,
    /// A 32-bit descriptor cannot express this address.
    Address,
}

/// Head bytes of one misaligned segment that go through the align buffer
/// (Linux `sdhci_adma_table_pre` offset handling). `slot` is the 4-byte
/// align-buffer slot; the caller copies write data in before the transfer
/// and read data out afterwards (`sdhci_adma_table_post`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AlignSlot {
    pub segment: usize,
    pub slot: usize,
    pub bytes: usize,
}

/// Result of [`table_pre`].
#[derive(Debug, Eq, PartialEq)]
pub struct Table {
    /// Descriptors written, including the terminating one.
    pub descriptors: usize,
    pub align: alloc::vec::Vec<AlignSlot>,
}

/// Linux `sdhci_adma_write_desc`: little-endian attribute, length, low
/// address and (64-bit descriptors) high address.
pub fn write_desc(
    table: &mut [u8],
    index: usize,
    desc_size: usize,
    addr: u64,
    len: usize,
    attr: u16,
) -> Result<(), TableError> {
    let at = index * desc_size;
    let desc = table
        .get_mut(at..at + desc_size)
        .ok_or(TableError::Overflow)?;
    if desc_size == DESC_SIZE_32 && addr > u64::from(u32::MAX) {
        return Err(TableError::Address);
    }
    // A 65536-byte descriptor encodes its length as 0 (`cpu_to_le16(len)`).
    desc[0..2].copy_from_slice(&attr.to_le_bytes());
    desc[2..4].copy_from_slice(&(len as u16).to_le_bytes());
    desc[4..8].copy_from_slice(&(addr as u32).to_le_bytes());
    if desc_size == DESC_SIZE_64 {
        desc[8..12].copy_from_slice(&((addr >> 32) as u32).to_le_bytes());
    }
    Ok(())
}

/// Linux `sdhci_adma_mark_end`: set END in an existing descriptor.
pub fn mark_end(table: &mut [u8], index: usize, desc_size: usize) -> Result<(), TableError> {
    let at = index * desc_size;
    let attr = table.get_mut(at..at + 2).ok_or(TableError::Overflow)?;
    let value = u16::from_le_bytes([attr[0], attr[1]]) | ATTR_END;
    attr.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

/// Linux `sdhci_adma_table_pre`: one TRAN descriptor per segment after an
/// optional align-buffer descriptor for the unaligned head; segments longer
/// than [`MAX_ADMA`] are split into 32 KiB pieces; the table ends with a
/// NOP/END/VALID descriptor, or with END set in the last data descriptor
/// for `SDHCI_QUIRK_NO_ENDATTR_IN_NOPDESC`.
pub fn table_pre(
    table: &mut [u8],
    desc_size: usize,
    segments: &[Segment],
    align_addr: u64,
    no_end_attr_in_nop: bool,
) -> Result<Table, TableError> {
    if segments.len() > MAX_SEGS {
        return Err(TableError::Overflow);
    }
    let mut index = 0;
    let mut align = alloc::vec::Vec::new();
    for (number, segment) in segments.iter().enumerate() {
        if segment.len == 0 {
            return Err(TableError::Overflow);
        }
        let mut addr = segment.addr;
        let mut len = segment.len;
        let offset = ((ALIGN - (addr & (ALIGN - 1))) & (ALIGN - 1)) as usize;
        if offset != 0 {
            let head = offset.min(len);
            let slot = align.len();
            write_desc(
                table,
                index,
                desc_size,
                align_addr + slot as u64 * ALIGN,
                head,
                ATTR_TRAN_VALID,
            )?;
            index += 1;
            align.push(AlignSlot {
                segment: number,
                slot,
                bytes: head,
            });
            addr += head as u64;
            len -= head;
        }
        while len > MAX_ADMA {
            write_desc(table, index, desc_size, addr, SPLIT, ATTR_TRAN_VALID)?;
            index += 1;
            addr += SPLIT as u64;
            len -= SPLIT;
        }
        if len != 0 {
            write_desc(table, index, desc_size, addr, len, ATTR_TRAN_VALID)?;
            index += 1;
        }
    }
    if no_end_attr_in_nop {
        if index != 0 {
            mark_end(table, index - 1, desc_size)?;
        }
    } else {
        write_desc(table, index, desc_size, 0, 0, ATTR_NOP_END_VALID)?;
        index += 1;
    }
    if index > TABLE_COUNT {
        return Err(TableError::Overflow);
    }
    Ok(Table {
        descriptors: index,
        align,
    })
}

/// Decoded descriptor (attribute, length, address); `len` 0 means 65536
/// for a TRAN descriptor.
pub fn read_desc(table: &[u8], index: usize, desc_size: usize) -> Option<(u16, u16, u64)> {
    let at = index * desc_size;
    let desc = table.get(at..at + desc_size)?;
    let attr = u16::from_le_bytes([desc[0], desc[1]]);
    let len = u16::from_le_bytes([desc[2], desc[3]]);
    let mut addr = u64::from(u32::from_le_bytes([desc[4], desc[5], desc[6], desc[7]]));
    if desc_size == DESC_SIZE_64 {
        addr |= u64::from(u32::from_le_bytes([desc[8], desc[9], desc[10], desc[11]])) << 32;
    }
    Some((attr, len, addr))
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "adma_tests.rs"]
mod tests;
