//! Bounded retained job-VM snapshots. MIT Linux b90c984d xe_vm.c
//! xe_vm_snapshot_capture/capture_delayed: only DUMPABLE ranges disclose BO
//! contents. NARF copies retained pages synchronously into a preallocated,
//! privileged native format, with explicit truncation and no device freeze.
use super::{put32, put64, VM_OFFSET};
use crate::{intel_gpu_exec::ResidentBatch, intel_gpu_gt::GtPlatform, intel_gpu_ppgtt::PtMemory};

const HEADER: usize = 64;
const LIMIT: usize = 4;
const ENTRY: usize = 128;
const TABLES: usize = 16;
const TABLE_DESC: usize = 16;
const RANGES: usize = 8;
const RANGE_DESC: usize = 64;
const PAYLOAD: usize = 16384;
const TABLE_DATA: usize = ENTRY + TABLES * TABLE_DESC;
const RANGE_DIRECTORY: usize = TABLE_DATA + TABLES * 4096;
const RANGE_DATA: usize = RANGE_DIRECTORY + RANGES * RANGE_DESC;
const STRIDE: usize = RANGE_DATA + RANGES * PAYLOAD;
pub(super) const BYTES: usize = HEADER + LIMIT * STRIDE;

const OMITTED: u32 = 1;
const LOST: u32 = 2;
const TABLE_TRUNCATED: u32 = 4;
const RANGE_TRUNCATED: u32 = 8;
const PREFIX: u32 = 16;
const REFUSED: u32 = 32;
const INVALID: u32 = 64;
const VRAM: u32 = 128;

pub(crate) struct VmCapture<'a> {
    bytes: &'a mut [u8],
    platform: GtPlatform,
    recorded: usize,
    complete: usize,
    pub(super) flags: u32,
}
impl<'a> VmCapture<'a> {
    pub(super) fn new(bytes: &'a mut [u8], platform: GtPlatform) -> Self {
        Self {
            bytes,
            platform,
            recorded: 0,
            complete: 0,
            flags: 0,
        }
    }

    pub(crate) fn push(
        &mut self,
        id: u16,
        stamp: u32,
        batch: &ResidentBatch,
        access: &mut dyn FnMut() -> bool,
    ) {
        if self.recorded == LIMIT {
            return;
        }
        let view = batch.diagnostic_vm();
        let slot = HEADER + self.recorded * STRIDE;
        self.recorded += 1;
        put32(self.bytes, slot, u32::from(id));
        put32(self.bytes, slot + 4, stamp);
        put64(self.bytes, slot + 8, view.address);
        put64(self.bytes, slot + 16, view.length);
        put64(self.bytes, slot + 24, view.root);
        let tables = view.memory.diagnostic_tables();
        put32(self.bytes, slot + 32, tables.len() as u32);
        put32(self.bytes, slot + 40, view.mappings.len() as u32);
        put32(self.bytes, slot + 48, view.flags);
        let mut flags = 0;
        if tables.len() > TABLES {
            flags |= TABLE_TRUNCATED;
        }
        if view.mappings.len() > RANGES {
            flags |= RANGE_TRUNCATED;
        }
        let mut table_count = 0;
        for (index, phys) in tables.take(TABLES).enumerate() {
            if !access() {
                flags |= LOST;
                break;
            }
            let descriptor = slot + ENTRY + index * TABLE_DESC;
            let data = slot + TABLE_DATA + index * 4096;
            put64(self.bytes, descriptor, phys);
            table_count += 1;
            // Select only allocator-owned pages. Neither the root's entries
            // nor any device address can select a source or change its extent.
            core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
            for (entry, output) in self.bytes[data..data + 4096]
                .chunks_exact_mut(8)
                .enumerate()
            {
                output.copy_from_slice(&view.memory.read_entry(phys, entry).to_le_bytes());
            }
            if !access() {
                self.bytes[data..data + 4096].fill(0);
                flags |= LOST;
                break;
            }
            put32(self.bytes, descriptor + 8, (VM_OFFSET + data) as u32);
            put32(self.bytes, descriptor + 12, 4096);
        }
        put32(self.bytes, slot + 36, table_count);
        let mut range_count = 0;
        if flags & LOST == 0 {
            for (index, mapping) in view.mappings.iter().take(RANGES).enumerate() {
                if !access() {
                    flags |= LOST;
                    break;
                }
                let descriptor = slot + RANGE_DIRECTORY + index * RANGE_DESC;
                let data = slot + RANGE_DATA + index * PAYLOAD;
                range_count += 1;
                put64(self.bytes, descriptor, mapping.va);
                put64(self.bytes, descriptor + 8, mapping.length);
                put64(self.bytes, descriptor + 16, mapping.offset);
                put32(self.bytes, descriptor + 36, u32::from(mapping.pat));
                let mut kind = u32::from(!mapping.writable);
                if let Some(object) = &mapping.object {
                    put64(self.bytes, descriptor + 24, object.size());
                    kind |= u32::from(object.is_userptr()) << 2
                        | u32::from(object.is_vram()) << 3
                        | u32::from(object.is_wc()) << 4;
                    let valid = mapping.dumpable
                        && mapping.va % 4096 == 0
                        && mapping.length != 0
                        && mapping.length % 4096 == 0
                        && mapping.offset % 4096 == 0
                        && mapping
                            .va
                            .checked_add(mapping.length)
                            .is_some_and(|v| v <= 1 << 48)
                        && mapping
                            .offset
                            .checked_add(mapping.length)
                            .is_some_and(|end| end <= object.size());
                    let coherent =
                        crate::intel_gpu_xe_vm::pat_allowed(self.platform, u16::from(mapping.pat))
                            || (object.is_wc()
                                && crate::intel_gpu_xe_vm::pat_noncoherent(
                                    self.platform,
                                    u16::from(mapping.pat),
                                ));
                    if !valid {
                        flags |= INVALID;
                        kind |= 128;
                    } else if object.is_vram() {
                        // A lost GT cannot grant the live VRAM BAR/epoch proof.
                        // Preserve range identity without guessing a CPU alias.
                        flags |= VRAM;
                        kind |= 128;
                    } else if !coherent {
                        flags |= REFUSED;
                        kind |= 128;
                    } else {
                        let length = mapping.length.min(PAYLOAD as u64) as usize;
                        if mapping.length > length as u64 {
                            flags |= PREFIX;
                            kind |= 64;
                        }
                        if object.diagnostic_read(
                            mapping.offset,
                            &mut self.bytes[data..data + length],
                            access,
                        ) {
                            kind |= 32;
                            put32(self.bytes, descriptor + 40, (VM_OFFSET + data) as u32);
                            put32(self.bytes, descriptor + 44, length as u32);
                        } else {
                            flags |= REFUSED;
                            kind |= 128;
                            if !access() {
                                flags |= LOST;
                            }
                        }
                    }
                } else {
                    kind |= 2; // NULL: metadata only, no CPU source to follow.
                }
                put32(self.bytes, descriptor + 32, kind);
                if flags & LOST != 0 {
                    break;
                }
            }
        }
        put32(self.bytes, slot + 44, range_count);
        put32(self.bytes, slot + 52, flags);
        self.flags |= flags;
        if flags == 0 {
            self.complete += 1;
        }
    }

    pub(super) fn finish(mut self, total: Option<usize>) -> u32 {
        let Some(total) = total else {
            return 0;
        };
        if total > self.recorded {
            self.flags |= OMITTED;
        }
        self.bytes[..8].copy_from_slice(b"NARFVMEM");
        for (at, value) in [
            (8, 1),
            (12, HEADER as u32),
            (16, STRIDE as u32),
            (20, LIMIT as u32),
            (24, total as u32),
            (28, self.recorded as u32),
            (32, self.complete as u32),
            (36, self.flags),
        ] {
            put32(self.bytes, at, value);
        }
        self.flags
    }
}
