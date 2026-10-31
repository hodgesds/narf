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
use crate::intel_gpu_gt::GtPlatform;
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
    /// I915_EXEC_RING_MASK: a legacy ring or an index into the context's
    /// engine map. Selection belongs to the context, as in eb_select_engine.
    pub ring: u32,
    pub batch_va: u64,
    pub batch_len: u64,
    pub objects: Vec<ExecObject>,
}

impl ExecRequest {
    pub fn prepare_user(
        &self,
        platform: GtPlatform,
    ) -> Result<crate::intel_gpu_user::UserBatch, FsError> {
        self.prepare_for_gt(platform)
            .map(crate::intel_gpu_user::UserBatch)
    }
    /// Freeze a validated request into one owned batch. Revalidate even when
    /// the request was constructed by a kernel caller rather than `read`.
    pub fn prepare(&self, format: PteFormat, pat_index: u8) -> Result<ResidentBatch, FsError> {
        self.prepare_inner(format, pat_index, 0, None)
    }

    /// System-memory WB leaves with the independently installed non-leaf
    /// policy, also used by PDP0/PTBP (xe_vm.c, xe_pat.c).
    pub fn prepare_for_gt(&self, platform: GtPlatform) -> Result<ResidentBatch, FsError> {
        let (format, pat, table_pat) = match platform {
            GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake) => {
                (PteFormat::XeLpg, 3, 2)
            }
            GtPlatform::Alchemist => (PteFormat::Gen12, 0, 0),
            GtPlatform::Battlemage => (PteFormat::XeLpg, 2, 2),
            _ => return Err(FsError::NotImplemented),
        };
        self.prepare_inner(format, pat, table_pat, Some(platform))
    }

    fn prepare_inner(
        &self,
        format: PteFormat,
        pat_index: u8,
        table_pat: u8,
        platform: Option<GtPlatform>,
    ) -> Result<ResidentBatch, FsError> {
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
            space: self.address_space_inner(format, pat_index, table_pat)?,
            format,
            platform,
            address: self.batch_va,
            length: self.batch_len,
            user_fence: None,
            skip_batch: false,
            implicit_sync: true,
        })
    }

    /// Admit the modern no-relocation, fixed-placement subset. Rejection
    /// changes no object, VM or context and never writes an output offset.
    pub fn read(user: &dyn IoctlContext, address: u64, gem: &GemState) -> Result<Self, FsError> {
        let mut request = [0; 64];
        user.read(address, &mut request)?;
        Self::read_wire(user, &request, gem, false)
    }

    pub(crate) fn read_submission(
        user: &dyn IoctlContext,
        address: u64,
        gem: &GemState,
    ) -> Result<(Self, crate::intel_gpu_exec_sync::SyncRequest), FsError> {
        let mut request = [0; 64];
        user.read(address, &mut request)?;
        let sync = crate::intel_gpu_exec_sync::SyncRequest::read(user, &request)?;
        Ok((Self::read_wire(user, &request, gem, true)?, sync))
    }

    fn read_wire(
        user: &dyn IoctlContext,
        request: &[u8; 64],
        gem: &GemState,
        explicit: bool,
    ) -> Result<Self, FsError> {
        let count = u32_at(request, 8) as usize;
        let start = u32_at(request, 12) as u64;
        let length = u32_at(request, 16) as u64;
        let flags = u64_at(request, 40);
        let mut supported =
            0x3f | abi::EXEC_NO_RELOC | abi::EXEC_HANDLE_LUT | abi::EXEC_BATCH_FIRST;
        if explicit {
            supported |= abi::EXEC_FENCE_IN
                | abi::EXEC_FENCE_OUT
                | abi::EXEC_FENCE_ARRAY
                | abi::EXEC_FENCE_SUBMIT
                | abi::EXEC_USE_EXTENSIONS;
        }
        if count == 0
            || count > MAX_OBJECTS
            || flags & !supported != 0
            || flags & abi::EXEC_NO_RELOC == 0
            || u32_at(request, 20) != 0
            || u32_at(request, 24) != 0
            || (!explicit
                && (u32_at(request, 28) != 0
                    || u64_at(request, 32) != 0
                    || u64_at(request, 56) != 0))
            || u64_at(request, 48) > u32::MAX as u64
            || start % 8 != 0
            || length % 8 != 0
        {
            return Err(FsError::InvalidData);
        }
        let mut wire = vec![0; count * 56];
        user.read(u64_at(request, 0), &mut wire)?;
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
            context_id: u64_at(request, 48) as u32,
            ring: (flags & 0x3f) as u32,
            batch_va: batch.va + start,
            batch_len,
            objects,
        })
    }

    /// Build private tables without touching any engine or existing VM. A
    /// failed build drops all table pages; successful ownership includes all
    /// leaf objects and survives GEM_CLOSE or the submitting fd's destruction.
    pub fn address_space(&self, format: PteFormat, pat_index: u8) -> Result<AddressSpace, FsError> {
        self.address_space_inner(format, pat_index, 0)
    }

    fn address_space_inner(
        &self,
        format: PteFormat,
        pat_index: u8,
        table_pat: u8,
    ) -> Result<AddressSpace, FsError> {
        let mut memory = FramePtMemory::new();
        let tables = Ppgtt::with_table_pat(&mut memory, format, table_pat).map_err(map_error)?;
        let mut space = AddressSpace {
            tables: Some(tables),
            memory,
            objects: Vec::new(),
        };
        for entry in &self.objects {
            space.objects.push((entry.object.clone(), entry.writable));
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
    platform: Option<GtPlatform>,
    address: u64,
    length: u64,
    user_fence: Option<(u64, u64)>,
    skip_batch: bool,
    implicit_sync: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct VmMapping {
    pub object: Option<Arc<GemObject>>,
    pub va: u64,
    pub offset: u64,
    pub length: u64,
    pub writable: bool,
    pub pat: u8,
}

impl ResidentBatch {
    pub(crate) fn from_vm(
        platform: GtPlatform,
        mappings: &[VmMapping],
        address: Option<u64>,
        scratch: bool,
        user_fence: Option<(u64, u64)>,
    ) -> Result<Self, FsError> {
        let (format, leaf_pat, table_pat) = match platform {
            GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake) => {
                (PteFormat::XeLpg, 3, 2)
            }
            GtPlatform::Alchemist => (PteFormat::Gen12, 0, 0),
            GtPlatform::Battlemage => (PteFormat::XeLpg, 2, 2),
            _ => return Err(FsError::NotImplemented),
        };
        if mappings.len() > 4096 {
            return Err(FsError::OutOfMemory);
        }
        let mut bytes = 0u64;
        for m in mappings {
            if m.va % PAGE != 0
                || m.length == 0
                || m.length % PAGE != 0
                || m.offset % PAGE != 0
                || m.va.checked_add(m.length).is_none_or(|end| end > VA_SIZE)
            {
                return Err(FsError::InvalidData);
            }
            if let Some(object) = &m.object {
                if m.offset
                    .checked_add(m.length)
                    .is_none_or(|end| end > object.size())
                {
                    return Err(FsError::InvalidData);
                }
            }
            if m.object.is_some() || !scratch {
                bytes = bytes.checked_add(m.length).ok_or(FsError::OutOfMemory)?;
            }
        }
        if bytes > 512 * 1024 * 1024 {
            return Err(FsError::OutOfMemory);
        }
        let length = if let Some(address) = address {
            if address & 7 != 0 {
                return Err(FsError::InvalidData);
            }
            let batch = mappings
                .iter()
                .find(|m| m.object.is_some() && address >= m.va && address < m.va + m.length)
                .ok_or(FsError::InvalidData)?;
            batch.va + batch.length - address
        } else {
            0
        };
        if let Some((addr, _)) = user_fence {
            if addr & 7 != 0
                || !mappings.iter().any(|m| {
                    m.object.is_some()
                        && m.writable
                        && addr >= m.va
                        && addr
                            .checked_add(8)
                            .is_some_and(|end| end <= m.va + m.length)
                })
            {
                return Err(FsError::InvalidData);
            }
        }
        let mut memory = FramePtMemory::new();
        let tables = if scratch {
            Ppgtt::with_scratch(&mut memory, format, table_pat, leaf_pat)
        } else {
            Ppgtt::with_table_pat(&mut memory, format, table_pat)
        }
        .map_err(map_error)?;
        let mut space = AddressSpace {
            tables: Some(tables),
            memory,
            objects: Vec::new(),
        };
        for mapping in mappings {
            if let Some(object) = &mapping.object {
                if let Some((_, writable)) = space
                    .objects
                    .iter_mut()
                    .find(|(old, _)| Arc::ptr_eq(old, object))
                {
                    *writable |= mapping.writable;
                } else {
                    space.objects.push((object.clone(), mapping.writable));
                }
                for (i, phys) in object
                    .pages()
                    .skip((mapping.offset / PAGE) as usize)
                    .take((mapping.length / PAGE) as usize)
                    .enumerate()
                {
                    space
                        .tables
                        .as_mut()
                        .expect("owned tables")
                        .map_with_pat(
                            &mut space.memory,
                            mapping.va + i as u64 * PAGE,
                            phys,
                            mapping.pat,
                            mapping.writable,
                        )
                        .map_err(map_error)?;
                }
            } else if !scratch {
                for page in 0..mapping.length / PAGE {
                    space
                        .tables
                        .as_mut()
                        .expect("owned tables")
                        .map_null(&mut space.memory, mapping.va + page * PAGE, mapping.pat)
                        .map_err(map_error)?;
                }
            }
        }
        Ok(Self {
            space,
            format,
            platform: Some(platform),
            address: address.unwrap_or(0),
            length,
            user_fence,
            skip_batch: address.is_none(),
            implicit_sync: false,
        })
    }

    pub(crate) fn user_fence(&self) -> Option<(u64, u64)> {
        self.user_fence
    }
    pub(crate) fn skip_batch(&self) -> bool {
        self.skip_batch
    }
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

    pub(crate) fn platform(&self) -> Option<GtPlatform> {
        self.platform
    }

    pub(crate) fn reserve(
        &self,
        completion: &Arc<crate::intel_gpu_fence::CompletionFence>,
    ) -> Result<(), FsError> {
        if self.implicit_sync {
            crate::intel_gpu_gem::reserve_gpu(&self.space.objects, completion)
        } else {
            crate::intel_gpu_gem::reserve_gpu_explicit(&self.space.objects, completion);
            Ok(())
        }
    }

    /// Tables are private and immutable; CPU WB mappings therefore need a
    /// one-time clean, even on Xe-LPG's non-snooping table walker. The caller
    /// must also prevent writes to the leaf objects until terminal completion.
    pub(crate) fn publish_for_device(&self) -> bool {
        self.space.memory.publish_for_device()
            && self
                .space
                .objects
                .iter()
                .all(|(object, _)| object.publish_for_device())
    }
}

/// Read-only ownership of the private kernel probe's code and result. Neither
/// object is installed in a GEM namespace, exported or mapped to userspace.
#[derive(Debug)]
pub struct PpgttProbeResult {
    code: Arc<GemObject>,
    data: Arc<GemObject>,
}

#[derive(Debug)]
pub struct PpgttProbeSubmission {
    pub context_id: u16,
    pub completion: Arc<crate::intel_gpu_fence::CompletionFence>,
    pub result: PpgttProbeResult,
}

const PROBE_CODE: u64 = 0x1234_0000_0000;
const PROBE_DATA: u64 = 0x2345_0000_0000;
const PROBE_VALUE: u32 = 0x4e41_5246;
const PROBE_WORDS: [u32; 6] = [
    0x10000002, // MI_STORE_DATA_IMM, PPGTT, one dword (xe_mi_commands.h)
    (PROBE_DATA + 0x80) as u32,
    ((PROBE_DATA + 0x80) >> 32) as u32,
    PROBE_VALUE,
    0x05000000, // MI_BATCH_BUFFER_END
    0,
];

impl PpgttProbeResult {
    #[cfg(feature = "kernel-test")]
    pub(crate) fn weak_objects(&self) -> [alloc::sync::Weak<GemObject>; 2] {
        [Arc::downgrade(&self.code), Arc::downgrade(&self.data)]
    }

    pub(crate) fn prepare(platform: GtPlatform) -> Result<(ResidentBatch, Self), FsError> {
        let gem = GemState::new();
        let code = gem.object(gem.create(PAGE, |_, _| Ok(()))?)?;
        let data = gem.object(gem.create(PAGE, |_, _| Ok(()))?)?;
        for (i, word) in PROBE_WORDS.into_iter().enumerate() {
            code.write(i as u64 * 4, &word.to_le_bytes())?;
        }
        let batch = ExecRequest {
            ring: 0,
            context_id: 0,
            batch_va: PROBE_CODE,
            batch_len: PROBE_WORDS.len() as u64 * 4,
            objects: alloc::vec![
                ExecObject {
                    object: code.clone(),
                    va: PROBE_CODE,
                    writable: false
                },
                ExecObject {
                    object: data.clone(),
                    va: PROBE_DATA,
                    writable: true
                },
            ],
        }
        .prepare_for_gt(platform)?;
        Ok((batch, Self { code, data }))
    }

    /// Call after a successful terminal fence. Check the complete destination
    /// and unchanged code page, including all bytes outside the written word.
    pub fn verify(&self) -> Result<(), FsError> {
        let mut bytes = [0; 4096];
        self.data.read(0, &mut bytes)?;
        for (i, byte) in bytes.iter().enumerate() {
            let expected = if (0x80..0x84).contains(&i) {
                PROBE_VALUE.to_le_bytes()[i - 0x80]
            } else {
                0
            };
            if *byte != expected {
                return Err(FsError::InvalidData);
            }
        }
        self.code.read(0, &mut bytes)?;
        for (i, word) in bytes.chunks_exact(4).enumerate() {
            if u32::from_le_bytes(word.try_into().expect("dword"))
                != PROBE_WORDS.get(i).copied().unwrap_or(0)
            {
                return Err(FsError::InvalidData);
            }
        }
        Ok(())
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
    objects: Vec<(Arc<GemObject>, bool)>,
}

impl AddressSpace {
    pub fn root_phys(&self) -> u64 {
        self.tables.as_ref().expect("owned tables").root_phys()
    }
    pub fn root_descriptor(&self) -> u64 {
        self.tables
            .as_ref()
            .expect("owned tables")
            .root_descriptor()
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
