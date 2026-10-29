//! Intel softpin execbuffer admission and immutable PPGTT residency.
//!
//! This layer copies hostile wire data, resolves this open's handles and
//! constructs a complete owned address space. It does not grant a hardware
//! queue: generation-specific GT setup, nonsecure context execution, terminal
//! completion and reset/loss ownership must precede queue publication.

use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use narf_filesystem::{FsError, IoctlContext};

use crate::intel_gpu_gem::{GemObject, GemState};
use crate::intel_gpu_gtt::PteFormat;
use crate::intel_gpu_ppgtt::{FramePtMemory, Ppgtt, PpgttError, WalkOutcome};
use crate::intel_gpu_uapi::{self as abi, u32_at, u64_at};

const MAX_OBJECTS: usize = 4096;
const VA_SIZE: u64 = 1 << 48;
const PAGE: u64 = 4096;

#[derive(Debug)]
pub struct ExecObject {
    pub object: Arc<GemObject>,
    pub va: u64,
    pub writable: bool,
}

#[derive(Debug)]
pub struct ExecRequest {
    pub context_id: u32,
    pub batch_va: u64,
    pub batch_len: u64,
    pub objects: Vec<ExecObject>,
}

impl ExecRequest {
    /// Freeze a validated request into one owned batch. Revalidate even when
    /// the request was constructed by a kernel caller rather than `read`.
    pub fn prepare(&self, format: PteFormat, pat_index: u8) -> Result<ResidentBatch, FsError> {
        if self.objects.is_empty()
            || self.objects.len() > MAX_OBJECTS
            || self.objects.iter().any(|entry| {
                entry.va < PAGE
                    || entry.va % PAGE != 0
                    || entry
                        .va
                        .checked_add(entry.object.size())
                        .is_none_or(|end| end > VA_SIZE - PAGE)
            })
        {
            return Err(FsError::InvalidData);
        }
        let end = self
            .batch_va
            .checked_add(self.batch_len)
            .ok_or(FsError::InvalidData)?;
        if self.batch_len == 0
            || self.batch_va % 8 != 0
            || self.batch_len % 8 != 0
            || end > VA_SIZE
            || !self.objects.iter().any(|entry| {
                self.batch_va >= entry.va
                    && entry
                        .va
                        .checked_add(entry.object.size())
                        .is_some_and(|limit| end <= limit)
            })
        {
            return Err(FsError::InvalidData);
        }
        Ok(ResidentBatch {
            space: self.address_space(format, pat_index)?,
            format,
            address: self.batch_va,
            length: self.batch_len,
        })
    }

    /// Admit the modern no-relocation, fixed-placement subset. Rejection
    /// changes no object, VM or context and never writes an output offset.
    pub fn read(user: &dyn IoctlContext, address: u64, gem: &GemState) -> Result<Self, FsError> {
        let mut request = [0; 64];
        user.read(address, &mut request)?;
        let count = u32_at(&request, 8) as usize;
        let start = u32_at(&request, 12) as u64;
        let length = u32_at(&request, 16) as u64;
        let flags = u64_at(&request, 40);
        let supported = 0x3f | abi::EXEC_NO_RELOC | abi::EXEC_HANDLE_LUT | abi::EXEC_BATCH_FIRST;
        if count == 0
            || count > MAX_OBJECTS
            || flags & !supported != 0
            || flags & abi::EXEC_NO_RELOC == 0
            || flags & 0x3f > abi::EXEC_RENDER
            || u32_at(&request, 20) != 0
            || u32_at(&request, 24) != 0
            || u32_at(&request, 28) != 0
            || u64_at(&request, 32) != 0
            || u64_at(&request, 48) > u32::MAX as u64
            || u64_at(&request, 56) != 0
            || start % 8 != 0
            || length % 8 != 0
        {
            return Err(FsError::InvalidData);
        }
        let mut wire = vec![0; count * 56];
        user.read(u64_at(&request, 0), &mut wire)?;
        let mut handles = BTreeSet::new();
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(count)
            .map_err(|_| FsError::OutOfMemory)?;
        for entry in wire.chunks_exact(56) {
            let handle = u32_at(entry, 0);
            let alignment = u64_at(entry, 16);
            let offset = u64_at(entry, 24);
            let object_flags = u64_at(entry, 32);
            let allowed = abi::OBJECT_WRITE | abi::OBJECT_SUPPORTS_48B | abi::OBJECT_PINNED;
            if !handles.insert(handle)
                || u32_at(entry, 4) != 0
                || u64_at(entry, 8) != 0
                || object_flags & !allowed != 0
                || object_flags & abi::OBJECT_PINNED == 0
                || u64_at(entry, 40) != 0
                || u64_at(entry, 48) != 0
                || (alignment != 0 && (!alignment.is_power_of_two() || alignment < PAGE))
            {
                return Err(FsError::InvalidData);
            }
            let va = decanonicalize(offset)?;
            let object = gem.object(handle)?;
            let end = va.checked_add(object.size()).ok_or(FsError::InvalidData)?;
            if va < PAGE
                || va % PAGE != 0
                || (alignment != 0 && va % alignment != 0)
                || end > VA_SIZE - PAGE
                || (object_flags & abi::OBJECT_SUPPORTS_48B == 0 && end > 1 << 32)
            {
                return Err(FsError::InvalidData);
            }
            objects.push(ExecObject {
                object,
                va,
                writable: object_flags & abi::OBJECT_WRITE != 0,
            });
        }
        // Detect overlap without sorting the original residency order: batch
        // selection is defined by the first/last element of that original list.
        let mut ranges: Vec<_> = objects
            .iter()
            .map(|entry| (entry.va, entry.va + entry.object.size()))
            .collect();
        ranges.sort_unstable();
        if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
            return Err(FsError::InvalidData);
        }
        let batch_index = if flags & abi::EXEC_BATCH_FIRST != 0 {
            0
        } else {
            count - 1
        };
        let batch = &objects[batch_index];
        let batch_len = if length == 0 {
            batch
                .object
                .size()
                .checked_sub(start)
                .ok_or(FsError::InvalidData)?
        } else {
            length
        };
        if batch_len == 0
            || start
                .checked_add(batch_len)
                .is_none_or(|end| end > batch.object.size())
        {
            return Err(FsError::InvalidData);
        }
        Ok(Self {
            context_id: u64_at(&request, 48) as u32,
            batch_va: batch.va + start,
            batch_len,
            objects,
        })
    }

    /// Build private tables without touching any engine or existing VM. A
    /// failed build drops all table pages; successful ownership includes all
    /// leaf objects and survives GEM_CLOSE or the submitting fd's destruction.
    pub fn address_space(&self, format: PteFormat, pat_index: u8) -> Result<AddressSpace, FsError> {
        let mut memory = FramePtMemory::new();
        let tables = Ppgtt::with_format(&mut memory, format).map_err(map_error)?;
        let mut space = AddressSpace {
            tables: Some(tables),
            memory,
            objects: Vec::new(),
        };
        for entry in &self.objects {
            space.objects.push(entry.object.clone());
            for (i, phys) in entry.object.pages().enumerate() {
                space
                    .tables
                    .as_mut()
                    .expect("owned tables")
                    .map_with_pat(
                        &mut space.memory,
                        entry.va + i as u64 * PAGE,
                        phys,
                        pat_index,
                        entry.writable,
                    )
                    .map_err(map_error)?;
            }
        }
        Ok(space)
    }
}

/// Tables and leaf objects move together into the hardware request. The
/// engine may release them only after verified completion or a proven reset.
#[derive(Debug)]
pub struct ResidentBatch {
    space: AddressSpace,
    format: PteFormat,
    address: u64,
    length: u64,
}

impl ResidentBatch {
    pub fn format(&self) -> PteFormat {
        self.format
    }
    pub fn address(&self) -> u64 {
        self.address
    }
    pub fn length(&self) -> u64 {
        self.length
    }
    pub fn space(&self) -> &AddressSpace {
        &self.space
    }
}

fn decanonicalize(address: u64) -> Result<u64, FsError> {
    let low = address & (VA_SIZE - 1);
    // Accept the canonical sign-extended representation or the zero-extended
    // 48-bit address. Reject arbitrary high bits rather than truncating them.
    let canonical = (((low << 16) as i64) >> 16) as u64;
    if address != low && address != canonical {
        return Err(FsError::InvalidData);
    }
    Ok(low)
}

fn map_error(error: PpgttError) -> FsError {
    match error {
        PpgttError::OutOfMemory => FsError::OutOfMemory,
        _ => FsError::InvalidData,
    }
}

#[derive(Debug)]
pub struct AddressSpace {
    tables: Option<Ppgtt>,
    memory: FramePtMemory,
    objects: Vec<Arc<GemObject>>,
}

impl AddressSpace {
    pub fn root_phys(&self) -> u64 {
        self.tables.as_ref().expect("owned tables").root_phys()
    }
    pub fn translate(&self, address: u64) -> Result<WalkOutcome, PpgttError> {
        self.tables
            .as_ref()
            .expect("owned tables")
            .translate(&self.memory, address)
    }
}

impl Drop for AddressSpace {
    fn drop(&mut self) {
        if let Some(tables) = self.tables.take() {
            tables.teardown(&mut self.memory);
        }
    }
}
