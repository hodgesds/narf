// SPDX-License-Identifier: GPL-2.0-or-later
//! AX200/AX201 (22000) self-load context. Reference local Linux
//! pcie/{iwl-context-info.h,ctxt-info.c}; this is distinct from v2/IML.
use super::{
    boot_context::{self, BootQueues},
    ParsedUcode,
};
pub const CONTEXT_BYTES: usize = 1792;
pub const DRAM_OFFSET: usize = 192;
pub const DRAM_ENTRIES: usize = 64;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Authority,
    Geometry,
    Address,
    Sections,
    Extent,
}
/// Hardware self-load regions must not cross a 4GiB boundary even though
/// addresses themselves are64-bit. Validate before any device publication.
pub fn dma_extent(address: u64, length: usize) -> bool {
    length != 0
        && address != 0
        && address
            .checked_add(length as u64 - 1)
            .is_some_and(|last| address >> 32 == last >> 32)
}
pub fn header(hw_rev: u16, queues: BootQueues) -> Result<[u8; CONTEXT_BYTES], Error> {
    if !queues.rx_depth.is_power_of_two()
        || !(8..=4096).contains(&queues.rx_depth)
        || !queues.command_depth.is_power_of_two()
        || !(8..=256).contains(&queues.command_depth)
    {
        return Err(Error::Geometry);
    }
    for (address, length, alignment) in [
        (queues.free, usize::from(queues.rx_depth) * 8, 256),
        (queues.used, usize::from(queues.rx_depth) * 4, 256),
        (queues.status, 16, 16),
        (queues.command, usize::from(queues.command_depth) * 256, 256),
    ] {
        if address & (alignment - 1) != 0 || !dma_extent(address, length) {
            return Err(Error::Address);
        }
    }
    let mut out = [0; CONTEXT_BYTES];
    boot_context::put16(&mut out, 0, hw_rev);
    boot_context::put16(&mut out, 4, (CONTEXT_BYTES / 4) as u16);
    // Long256-byteTFH + RX ring exponent +4KiB buffers (value4 inbits9..12).
    boot_context::put32(&mut out, 8, 0x100 | queues.rx_depth.ilog2() << 4 | 4 << 9);
    boot_context::put64(&mut out, 24, queues.free);
    boot_context::put64(&mut out, 32, queues.used);
    boot_context::put64(&mut out, 40, queues.status);
    boot_context::put64(&mut out, 48, queues.command);
    out[56] = (queues.command_depth.ilog2() - 3) as u8;
    Ok(out)
}
/// Reuse the strict LMAC/UMAC/paging phase validator. Only the DRAM array
/// placement changes from scratch-v2 offset124 to context-v1 offset192.
pub fn section_map(parsed: &ParsedUcode<'_>) -> Result<alloc::vec::Vec<(usize, usize)>, Error> {
    boot_context::section_map(parsed)
        .map_err(|_| Error::Sections)
        .map(|map| {
            map.into_iter()
                .map(|(index, offset)| {
                    (index, offset - boot_context::DRAM_MAP_OFFSET + DRAM_OFFSET)
                })
                .collect()
        })
}
pub fn set_section(
    context: &mut [u8; CONTEXT_BYTES],
    offset: usize,
    address: u64,
    length: usize,
) -> Result<(), Error> {
    if !(DRAM_OFFSET..DRAM_OFFSET + 3 * DRAM_ENTRIES * 8).contains(&offset)
        || (offset - DRAM_OFFSET) % 8 != 0
        || length > 32768
        || !dma_extent(address, length)
    {
        return Err(Error::Extent);
    }
    boot_context::put64(context, offset, address);
    Ok(())
}
/// Gen2 RFH free entries combine page address and a12-bit virtual buffer ID.
/// This is not the16-byte AX210 tagged structure or the old FH addr>>8 form.
pub fn free_descriptor(address: u64, id: u16) -> Result<[u8; 8], Error> {
    if address & 0xfff != 0 || id == 0 || id > 0xfff || !dma_extent(address, 4096) {
        return Err(Error::Address);
    }
    Ok((address | u64::from(id)).to_le_bytes())
}
pub fn used_descriptor(bytes: &[u8]) -> Result<u16, Error> {
    let bytes = bytes.get(..4).ok_or(Error::Extent)?;
    let id = (u32::from_le_bytes(bytes.try_into().unwrap()) & 0xfff) as u16;
    if id == 0 {
        return Err(Error::Address);
    }
    Ok(id)
}
/// Publish contextV1 at CSR0x40/44, then release CPU via a20-bit PRPH
/// address with dword width encoded. Caller owns queues/image mappings,
/// orders DMA, enables bus mastering and services RFH before this sequence.
pub fn publish(mmio: &mut impl super::transport::IwlMmio, address: u64) -> Result<(), Error> {
    if !mmio.authorized() {
        return Err(Error::Authority);
    }
    if address & 0xff != 0 || !dma_extent(address, CONTEXT_BYTES) {
        return Err(Error::Address);
    }
    mmio.write(0x40, address as u32);
    mmio.write(0x44, (address >> 32) as u32);
    Ok(())
}
/// CPU release is separate so the native owner can apply the ROM LTR
/// workaround after context publication and before the ROM runs.
pub fn release(mmio: &mut impl super::transport::IwlMmio) -> Result<(), Error> {
    if !mmio.authorized() {
        return Err(Error::Authority);
    }
    mmio.write(
        super::regs::HBUS_TARG_PRPH_WADDR,
        (0xa05c44 & 0x000fffff) | (3 << 24),
    );
    mmio.write(super::regs::HBUS_TARG_PRPH_WDAT, 1);
    Ok(())
}

/// Complete publication sequence for callers with an independently
/// established LTR profile; native runtime uses publish/LTR/release.
pub fn start(mmio: &mut impl super::transport::IwlMmio, address: u64) -> Result<(), Error> {
    publish(mmio, address)?;
    release(mmio)
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "context_v1_tests.rs"]
mod tests;
