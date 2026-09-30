//! Byte-exact AX210+ firmware self-load context (`pcie/ctxt-info-v2.c`).
//! Encode explicitly: the firmware structure has unaligned u64 fields
//! and its size fields use different units despite similar names.

use super::{ParsedUcode, CPU1_CPU2_SEPARATOR, PAGING_SEPARATOR};

pub const CONTEXT_BYTES: usize = 104;
pub const SCRATCH_BYTES: usize = 1724;
pub const SCRATCH_WITHOUT_FSEQ_BYTES: usize = 1660;
pub const DRAM_MAP_OFFSET: usize = 124;
pub const DRAM_ENTRIES: usize = 64;

#[derive(Copy, Clone, Debug)]
pub struct BootQueues {
    pub free: u64,
    pub used: u64,
    pub status: u64,
    pub command: u64,
    pub rx_depth: u16,
    pub command_depth: u16,
}

pub fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
pub fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
pub fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

/// Linux leaves the context version/config/optional fields zero.
pub fn context(
    queues: BootQueues,
    info: u64,
    scratch: u64,
) -> Result<[u8; CONTEXT_BYTES], &'static str> {
    if !queues.rx_depth.is_power_of_two()
        || queues.rx_depth < 8
        || !queues.command_depth.is_power_of_two()
        || queues.command_depth < 8
    {
        return Err("invalid boot queue geometry");
    }
    let mut out = [0; CONTEXT_BYTES];
    put64(&mut out, 8, info);
    put64(&mut out, 16, queues.status);
    // Hardware touches these even in legacy response mode; never
    // leave the dummy TR/CR pointers targeting physical address zero.
    put64(&mut out, 24, info + 2048);
    put64(&mut out, 32, info + 3072);
    put64(&mut out, 52, queues.command);
    put64(&mut out, 60, queues.used);
    put16(&mut out, 68, (queues.command_depth.ilog2() - 3) as u16);
    put16(&mut out, 70, queues.rx_depth.ilog2() as u16);
    put64(&mut out, 88, scratch);
    // Despite the header comment, ctxt-info-v2.c writes bytes here.
    put32(&mut out, 96, SCRATCH_WITHOUT_FSEQ_BYTES as u32);
    Ok(out)
}

pub fn scratch(hw_rev: u16, free: u64) -> [u8; SCRATCH_BYTES] {
    let mut out = [0; SCRATCH_BYTES];
    put16(&mut out, 0, hw_rev);
    put16(&mut out, 4, (SCRATCH_BYTES / 4) as u16);
    // 4K RX buffers, legacy responses, 256-byte TFH descriptors.
    put32(&mut out, 8, (1 << 16) | (1 << 17) | (3 << 18));
    put64(&mut out, 48, free);
    out
}

/// Validate ordered LMAC / UMAC / paging sections before allocating.
/// Returns the scratch-map byte offset for each non-separator section.
pub fn section_map(
    parsed: &ParsedUcode<'_>,
) -> Result<alloc::vec::Vec<(usize, usize)>, &'static str> {
    let mut result = alloc::vec::Vec::new();
    let mut phase = 0;
    let mut counts = [0usize; 3];
    for (index, section) in parsed.rt_sections.iter().enumerate() {
        match section.dest_offset {
            CPU1_CPU2_SEPARATOR if phase == 0 && counts[0] != 0 => {
                phase = 1;
                continue;
            }
            PAGING_SEPARATOR if phase == 1 && counts[1] != 0 => {
                phase = 2;
                continue;
            }
            CPU1_CPU2_SEPARATOR | PAGING_SEPARATOR => {
                return Err("out-of-order firmware separator")
            }
            _ => {}
        }
        if section.payload.is_empty()
            || section.payload.len() > 32768
            || counts[phase] >= DRAM_ENTRIES
        {
            return Err("invalid firmware DRAM section");
        }
        // The wire map is UMAC then LMAC, opposite the section stream.
        let map = match phase {
            0 => 1,
            1 => 0,
            _ => 2,
        };
        result.push((
            index,
            DRAM_MAP_OFFSET + (map * DRAM_ENTRIES + counts[phase]) * 8,
        ));
        counts[phase] += 1;
    }
    if counts[0] == 0 || counts[1] == 0 {
        return Err("firmware lacks LMAC/UMAC images");
    }
    Ok(result)
}
