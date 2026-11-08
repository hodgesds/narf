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

#[path = "intel_gpu_vram_clear.rs"]
pub(crate) mod vram_clear;
pub(crate) use vram_clear::{prepare_smallbar_clear, prepare_vram_clear};

#[path = "intel_gpu_copy.rs"]
pub mod copy;

#[derive(Debug)]
pub struct ExecObject {
    pub object: Arc<GemObject>,
    pub va: u64,
    pub writable: bool,
    /// i915 EXEC_OBJECT_ASYNC: skip prior implicit GPU dependencies only.
    /// The terminal READ/WRITE reservation and mandatory publication remain.
    pub asynchronous: bool,
    /// i915 EXEC_OBJECT_CAPTURE: retained diagnostic payload selection only.
    pub capture: bool,
}

#[derive(Debug)]
pub struct ExecRequest {
    pub context_id: u32,
    /// Legacy ring/index plus BSD selector bits. The context resolves its
    /// engine-map index before interpreting legacy-only selector flags.
    pub ring: u32,
    /// Linux `I915_REQUEST_NOPREEMPT` for this request: set by the
    /// execbuffer path when the submission carries the ext_perf extension
    /// on a context pinned by a HOLD_PREEMPTION OA stream. The scheduler
    /// honors it at submit; submission is NotImplemented today, so the
    /// flag is recorded here as the software-complete seam.
    pub no_preempt: bool,
    pub batch_va: u64,
    pub batch_len: u64,
    pub objects: Vec<ExecObject>,
}

/// First qualified object-ASYNC profile: source Xe2 PAT2 is uncompressed,
/// two-way coherent WB. Other families require independent qualification.
pub(crate) fn object_async_profile(platform: GtPlatform) -> bool {
    platform == GtPlatform::Battlemage
}

impl ExecRequest {
    pub(crate) fn has_async(&self) -> bool {
        self.objects.iter().any(|entry| entry.asynchronous)
    }

    fn validate_storage(&self) -> Result<(), FsError> {
        let asynchronous = self.has_async();
        if self.objects.iter().any(|entry| {
            entry.object.is_vram()
                || entry.object.is_wc()
                || entry.object.vm_owner().is_some()
                || (asynchronous && entry.object.is_userptr())
        }) {
            return Err(FsError::InvalidData);
        }
        Ok(())
    }

    /// Check imports and the immutable profile before context finalization,
    /// dependency waits or any private page-table/reservation publication.
    pub(crate) fn validate_for_gt(&self, platform: GtPlatform) -> Result<(), FsError> {
        self.validate_storage()?;
        if self.has_async() && !object_async_profile(platform) {
            return Err(FsError::InvalidData);
        }
        Ok(())
    }

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
            GtPlatform::Alchemist | GtPlatform::Gen12(_) => (PteFormat::Gen12, 0, 0),
            GtPlatform::Battlemage => (PteFormat::XeLpg, 2, 2),
            _ if platform.is_headless_integrated() => (PteFormat::Xe2, 2, 2),
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
        self.validate_storage()?;
        if self.has_async() && !platform.is_some_and(object_async_profile) {
            return Err(FsError::InvalidData);
        }
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
        let space = self.address_space_inner(format, pat_index, table_pat)?;
        if platform.is_some_and(|p| !space.within_dma_bits(p)) {
            return Err(FsError::InvalidData);
        }
        Ok(ResidentBatch {
            space,
            format,
            platform,
            address: self.batch_va,
            length: self.batch_len,
            user_fence: None,
            skip_batch: false,
            implicit_sync: true,
            parallel: None,
        })
    }

    /// Admit the modern no-relocation, fixed-placement subset. Rejection
    /// changes no object, VM or context and never writes an output offset.
    pub fn read(user: &dyn IoctlContext, address: u64, gem: &GemState) -> Result<Self, FsError> {
        ExecWire::read(user, address, false)?.resolve(gem)
    }

    /// i915_gem_execbuffer2_ioctl:3555 and i915_gem_do_execbuffer:3339 in
    /// their order: the argument checks and the exec-object copy
    /// (ExecWire::read), then the fences (parse_execbuf2_extensions,
    /// add_fence_array, the IN/SUBMIT sync_file), and only then the objects
    /// eb_lookup_vmas resolves.
    #[allow(dead_code)]
    pub(crate) fn read_submission(
        user: &dyn IoctlContext,
        address: u64,
        gem: &GemState,
        syncobjs: &narf_lib::sync::IrqSafeSpinLock<crate::drm::syncobj::SyncObjTable>,
    ) -> Result<(Self, crate::intel_gpu_exec_sync::SyncRequest), FsError> {
        let wire = ExecWire::read(user, address, true)?;
        let sync = crate::intel_gpu_exec_sync::SyncRequest::read(user, &wire.request, syncobjs)?;
        Ok((wire.resolve(gem)?, sync))
    }
}

/// The copied drm_i915_gem_execbuffer2 and its exec-object array: what
/// i915_gem_execbuffer2_ioctl hands i915_gem_do_execbuffer.
pub(crate) struct ExecWire {
    request: [u8; 64],
    objects: Vec<u8>,
}

impl ExecWire {
    /// i915_gem_execbuffer2_ioctl's check_buffer_count:3541 and
    /// i915_gem_check_execbuffer:2180 (each -EINVAL), the exec-object copy
    /// (-EFAULT), then i915_gem_do_execbuffer's first refusal: I915_EXEC_SECURE
    /// is -ENODEV on GRAPHICS_VER >= 11. No fence, handle or context is read.
    pub(crate) fn read(
        user: &dyn IoctlContext,
        address: u64,
        explicit: bool,
    ) -> Result<Self, FsError> {
        let mut request = [0; 64];
        user.read(address, &mut request)?;
        let count = u32_at(&request, 8) as usize;
        let flags = u64_at(&request, 40);
        // __I915_EXEC_ILLEGAL_FLAGS is every unknown bit, CONSTANTS_MASK and
        // RESOURCE_STREAMER. IS_PINNED only steers gen2 dispatch.
        let mut supported = 0x3f
            | abi::EXEC_BSD_MASK
            | abi::EXEC_SECURE
            | abi::EXEC_IS_PINNED
            | abi::EXEC_NO_RELOC
            | abi::EXEC_HANDLE_LUT
            | abi::EXEC_BATCH_FIRST;
        if explicit {
            supported |= abi::EXEC_FENCE_IN
                | abi::EXEC_FENCE_OUT
                | abi::EXEC_FENCE_ARRAY
                | abi::EXEC_FENCE_SUBMIT
                | abi::EXEC_USE_EXTENSIONS;
        }
        // DRI1 cliprects: FENCE_ARRAY and USE_EXTENSIONS reuse the fields.
        let cliprects = flags & (abi::EXEC_FENCE_ARRAY | abi::EXEC_USE_EXTENSIONS) == 0
            && (u32_at(&request, 28) != 0 || u64_at(&request, 32) != 0);
        // "UXA submitting garbage DR4, fixing up": 0xffffffff counts as 0.
        let dr4 = u32_at(&request, 24);
        // check_buffer_count refuses no buffers (NARF bounds the list at
        // MAX_OBJECTS beside it), then i915_gem_check_execbuffer's illegal
        // flags, cliprects, DR1/DR4 and batch alignment. NARF also refuses
        // here what it cannot execute: relocations, and on the synchronous
        // kernel path fences. rsvd1's upper half is ignored, as
        // i915_gem_context_lookup takes a u32, and rsvd2 is read only by
        // the fence flags.
        if count == 0
            || count > MAX_OBJECTS
            || flags & !supported != 0
            || flags & abi::EXEC_NO_RELOC == 0
            || cliprects
            || u32_at(&request, 20) != 0
            || (dr4 != 0 && dr4 != u32::MAX)
            || (u32_at(&request, 12) | u32_at(&request, 16)) % 8 != 0
        {
            return Err(FsError::InvalidData);
        }
        let mut objects = vec![0; count * 56];
        user.read(u64_at(&request, 0), &mut objects)?;
        if flags & abi::EXEC_SECURE != 0 {
            return Err(FsError::NoDevice);
        }
        Ok(Self { request, objects })
    }

    pub(crate) fn raw_request(&self) -> &[u8; 64] {
        &self.request
    }

    pub(crate) fn context_id(&self) -> u32 {
        u64_at(&self.request, 48) as u32
    }

    pub(crate) fn ring(&self) -> u32 {
        u64_at(&self.request, 40) as u32
    }

    pub(crate) fn dr4_fixed_up(&self) -> bool {
        u32_at(&self.request, 24) == u32::MAX
    }

    pub(crate) fn flags(&self) -> u64 {
        u64_at(&self.request, 40)
    }

    /// With I915_EXEC_USE_EXTENSIONS set, the extension chain head; with
    /// it clear, the DRI1 cliprects pointer. Only the extension path reads
    /// it as a chain (see `perf_extension`).
    pub(crate) fn cliprects_ptr(&self) -> u64 {
        u64_at(&self.request, 32)
    }

    /// Linux `parse_execbuf2_extensions`: when I915_EXEC_USE_EXTENSIONS is
    /// set, `cliprects_ptr` heads a chain of `i915_user_extension`
    /// structs; walk it and return the OA format selector of the
    /// `drm_i915_gem_execbuffer_ext_perf` extension, if present. Any other
    /// extension name is rejected (NARF defines no other execbuffer
    /// extension), a second perf extension is rejected (Linux requires the
    /// chain to hold each extension at most once), and a nonzero perf
    /// `flags` word is rejected (MBZ). Without USE_EXTENSIONS the
    /// cliprects fields are clip rects, not extensions, and no walk
    /// happens. The caller applies the HOLD_PREEMPTION rule to the
    /// returned selector; this function only parses and validates it.
    pub(crate) fn perf_extension(&self, user: &dyn IoctlContext) -> Result<Option<u64>, FsError> {
        if self.flags() & abi::EXEC_USE_EXTENSIONS == 0 {
            return Ok(None);
        }
        let mut perf: Option<u64> = None;
        abi::user_extensions(user, self.cliprects_ptr(), |address, name| {
            if name != abi::EXECBUFFER_EXT_PERF {
                return Err(FsError::InvalidData);
            }
            if perf.is_some() {
                return Err(FsError::InvalidData);
            }
            let mut word = [0u8; 8];
            user.read(
                address
                    .checked_add(abi::EXECBUFFER_EXT_PERF_FLAGS_OFF)
                    .ok_or(FsError::BadAddress)?,
                &mut word,
            )?;
            if u64::from_le_bytes(word) != 0 {
                return Err(FsError::InvalidData);
            }
            user.read(
                address
                    .checked_add(abi::EXECBUFFER_EXT_PERF_OA_FORMAT_OFF)
                    .ok_or(FsError::BadAddress)?,
                &mut word,
            )?;
            perf = Some(u64::from_le_bytes(word));
            Ok(())
        })?;
        Ok(perf)
    }

    /// eb_lookup_vmas and the batch selection, after the fences.
    pub(crate) fn resolve(self, gem: &GemState) -> Result<ExecRequest, FsError> {
        let request = &self.request;
        let count = u32_at(request, 8) as usize;
        let start = u32_at(request, 12) as u64;
        let length = u32_at(request, 16) as u64;
        let flags = u64_at(request, 40);
        let mut handles = BTreeSet::new();
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(count)
            .map_err(|_| FsError::OutOfMemory)?;
        for entry in self.objects.chunks_exact(56) {
            let handle = u32_at(entry, 0);
            let alignment = u64_at(entry, 16);
            let offset = u64_at(entry, 24);
            let object_flags = u64_at(entry, 32);
            let allowed = abi::OBJECT_WRITE
                | abi::OBJECT_SUPPORTS_48B
                | abi::OBJECT_PINNED
                | abi::OBJECT_ASYNC
                | abi::OBJECT_CAPTURE;
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
                asynchronous: object_flags & abi::OBJECT_ASYNC != 0,
                capture: object_flags & abi::OBJECT_CAPTURE != 0,
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
        Ok(ExecRequest {
            context_id: u64_at(request, 48) as u32,
            ring: (flags & (0x3f | abi::EXEC_BSD_MASK)) as u32,
            // Set by the execbuffer path after the HOLD_PREEMPTION check;
            // resolution alone cannot see the extension or the namespace.
            no_preempt: false,
            batch_va: batch.va + start,
            batch_len,
            objects,
        })
    }
}

impl ExecRequest {
    /// Build private tables without touching any engine or existing VM. A
    /// failed build drops all table pages; successful ownership includes all
    /// leaf objects and survives GEM_CLOSE or the submitting fd's destruction.
    pub fn address_space(&self, format: PteFormat, pat_index: u8) -> Result<AddressSpace, FsError> {
        if self.has_async() {
            return Err(FsError::InvalidData); // this entry has no qualified GT profile
        }
        self.address_space_inner(format, pat_index, 0)
    }

    fn address_space_inner(
        &self,
        format: PteFormat,
        pat_index: u8,
        table_pat: u8,
    ) -> Result<AddressSpace, FsError> {
        self.validate_storage()?;
        let mut memory = FramePtMemory::new();
        let tables = Ppgtt::with_root_level(
            &mut memory,
            format,
            table_pat,
            if format == PteFormat::Xe2 { 4 } else { 3 },
        )
        .map_err(map_error)?;
        let mut space = AddressSpace {
            tables: Some(tables),
            memory,
            objects: Vec::new(),
            asynchronous: Vec::new(),
            dumpable: Vec::new(),
        };
        space
            .dumpable
            .try_reserve_exact(self.objects.iter().filter(|entry| entry.capture).count())
            .map_err(|_| FsError::OutOfMemory)?;
        for entry in &self.objects {
            // Compatibility owns a separate private VM and uses one WB host
            // PAT for every leaf. Shared Xe handles retain explicit native
            // cache placement and optional VM ownership; passing a handle
            // through softpin cannot grant a different VM or cache policy.
            if entry.object.is_vram() || entry.object.is_wc() || entry.object.vm_owner().is_some() {
                return Err(FsError::InvalidData);
            }
            space.objects.push((entry.object.clone(), entry.writable));
            space.asynchronous.push(entry.asynchronous);
            if entry.capture {
                space.dumpable.push(VmMapping {
                    object: Some(entry.object.clone()),
                    va: entry.va,
                    offset: 0,
                    length: entry.object.size(),
                    writable: entry.writable,
                    pat: pat_index,
                    dumpable: true,
                });
            }
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
    /// All lanes share this owned immutable VM graph. Lane zero retains
    /// the ordinary address; children are copied before any wait.
    parallel: Option<Vec<u64>>,
}

#[derive(Clone, Debug)]
pub(crate) struct VmMapping {
    pub object: Option<Arc<GemObject>>,
    pub va: u64,
    pub offset: u64,
    pub length: u64,
    pub writable: bool,
    pub pat: u8,
    /// DRM_XE_VM_BIND_FLAG_DUMPABLE; copied with every split/replacement.
    pub dumpable: bool,
}

/// Whether `[address, address + size)` is fully covered by writable VM
/// mappings. The exec path uses this to fail closed before submitting a
/// batch whose OA query sampler would write its report outside the
/// context's resident-writable VM (the MI write would otherwise fault
/// the batch on the GPU). Coverage is computed over the mappings that
/// overlap the range, walked in VA order, so a range spanning several
/// mappings is handled; a read-only mapping does not cover (the query
/// writes the report).
pub(crate) fn mappings_cover(mappings: &[VmMapping], address: u64, size: u64) -> bool {
    if size == 0 {
        return false;
    }
    let Some(end) = address.checked_add(size) else {
        return false;
    };
    let mut spans: Vec<(u64, u64)> = Vec::new();
    for m in mappings {
        if !m.writable {
            continue;
        }
        let Some(m_end) = m.va.checked_add(m.length) else {
            continue;
        };
        if m.va < end && address < m_end {
            spans.push((m.va.max(address), m_end.min(end)));
        }
    }
    spans.sort_unstable();
    let mut covered = address;
    for (start, span_end) in spans {
        if start > covered {
            return false;
        }
        covered = covered.max(span_end);
        if covered >= end {
            return true;
        }
    }
    covered >= end
}

pub(crate) struct DiagnosticVm<'a> {
    pub address: u64,
    pub length: u64,
    pub root: u64,
    pub flags: u32,
    pub memory: &'a FramePtMemory,
    pub mappings: &'a [VmMapping],
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
            GtPlatform::Alchemist | GtPlatform::Gen12(_) => (PteFormat::Gen12, 0, 0),
            GtPlatform::Battlemage => (PteFormat::XeLpg, 2, 2),
            _ if platform.is_headless_integrated() => (PteFormat::Xe2, 2, 2),
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
                if (platform.is_gen12() || platform.is_headless_integrated()) && object.is_vram() {
                    return Err(FsError::InvalidData);
                }
                if object.is_vram()
                    && object.vram_page_size() == 65536
                    && (platform != GtPlatform::Alchemist
                        || (m.va | m.offset | m.length) & 65535 != 0)
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
                || mappings.iter().any(|m| {
                    m.object.as_ref().is_some_and(|o| o.is_gpu_only())
                        && addr >= m.va
                        && addr < m.va + m.length
                })
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
            Ppgtt::with_scratch_root_level(
                &mut memory,
                format,
                table_pat,
                leaf_pat,
                platform.ppgtt_root_level(),
            )
        } else {
            Ppgtt::with_root_level(
                &mut memory,
                format,
                table_pat,
                if format == PteFormat::Xe2 { 4 } else { 3 },
            )
        }
        .map_err(map_error)?;
        let mut space = AddressSpace {
            tables: Some(tables),
            memory,
            objects: Vec::new(),
            asynchronous: Vec::new(),
            dumpable: Vec::new(),
        };
        space
            .dumpable
            .try_reserve_exact(mappings.iter().filter(|m| m.dumpable).count())
            .map_err(|_| FsError::OutOfMemory)?;
        space
            .dumpable
            .extend(mappings.iter().filter(|m| m.dumpable).cloned());
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
                    let tables = space.tables.as_mut().expect("owned tables");
                    let va = mapping.va + i as u64 * PAGE;
                    if object.is_vram() && object.vram_page_size() == 65536 {
                        if i % 16 != 0 {
                            continue;
                        }
                        tables.map_device_64k_with_pat(
                            &mut space.memory,
                            va,
                            phys,
                            mapping.pat,
                            mapping.writable,
                        )
                    } else if object.is_vram() {
                        tables.map_device_with_pat(
                            &mut space.memory,
                            va,
                            phys,
                            mapping.pat,
                            mapping.writable,
                        )
                    } else {
                        tables.map_with_pat(
                            &mut space.memory,
                            va,
                            phys,
                            mapping.pat,
                            mapping.writable,
                        )
                    }
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
        if !space.within_dma_bits(platform) {
            return Err(FsError::InvalidData);
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
            parallel: None,
        })
    }

    pub(crate) fn from_vm_parallel(
        platform: GtPlatform,
        mappings: &[VmMapping],
        addresses: Option<&[u64]>,
        width: usize,
        scratch: bool,
        user_fence: Option<(u64, u64)>,
    ) -> Result<Self, FsError> {
        if !(2..=crate::intel_gpu_user::MAX_PARALLEL_WIDTH).contains(&width)
            || addresses.is_some_and(|a| a.len() != width)
        {
            return Err(FsError::InvalidData);
        }
        if let Some(addresses) = addresses {
            for &address in &addresses[1..] {
                if address & 7 != 0
                    || !mappings.iter().any(|m| {
                        m.object.is_some()
                            && address
                                .checked_sub(m.va)
                                .is_some_and(|delta| delta < m.length)
                    })
                {
                    return Err(FsError::InvalidData);
                }
            }
        }
        let mut children = Vec::new();
        children
            .try_reserve_exact(width - 1)
            .map_err(|_| FsError::OutOfMemory)?;
        if let Some(addresses) = addresses {
            children.extend_from_slice(&addresses[1..]);
        } else {
            children.resize(width - 1, 0);
        }
        let mut batch = Self::from_vm(
            platform,
            mappings,
            addresses.map(|a| a[0]),
            scratch,
            user_fence,
        )?;
        batch.parallel = Some(children);
        Ok(batch)
    }
    pub(crate) fn parallel(&self) -> Option<&[u64]> {
        self.parallel.as_deref()
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
        if self.implicit_sync && self.space.asynchronous.iter().any(|value| *value) {
            crate::intel_gpu_gem::reserve_gpu_mixed(
                &self.space.objects,
                &self.space.asynchronous,
                completion,
            )
        } else if self.implicit_sync {
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

    /// The execution owns this immutable graph even after VM/GEM close.
    /// No VM mutex, allocation, device read or reservation wait is needed.
    pub(crate) fn diagnostic_vm(&self) -> DiagnosticVm<'_> {
        DiagnosticVm {
            address: self.address,
            length: self.length,
            root: self.space.root_phys(),
            flags: u32::from(self.skip_batch) | u32::from(self.parallel.is_some()) << 1,
            memory: &self.space.memory,
            mappings: &self.space.dumpable,
        }
    }

    /// Per-lane batch addresses (xe_sched_job_snapshot_capture), lane zero
    /// first; none for a batchless submission.
    pub(crate) fn diagnostic_batches(&self) -> impl Iterator<Item = u64> + '_ {
        (!self.skip_batch)
            .then_some(self.address)
            .into_iter()
            .chain(
                self.parallel
                    .iter()
                    .flatten()
                    .copied()
                    .filter(|_| !self.skip_batch),
            )
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
            no_preempt: false,
            batch_va: PROBE_CODE,
            batch_len: PROBE_WORDS.len() as u64 * 4,
            objects: alloc::vec![
                ExecObject {
                    object: code.clone(),
                    va: PROBE_CODE,
                    writable: false,
                    asynchronous: false,
                    capture: false,
                },
                ExecObject {
                    object: data.clone(),
                    va: PROBE_DATA,
                    writable: true,
                    asynchronous: false,
                    capture: false,
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
    // Aligned with objects for compatibility; native Xe uses its existing
    // globally explicit path and leaves this empty.
    asynchronous: Vec<bool>,
    dumpable: Vec<VmMapping>,
}

impl AddressSpace {
    // The common PTE format admits more bits than the Gen12 PCI DMA mask.
    // Validate the entire owned graph before publishing its root to GuC.
    fn within_dma_bits(&self, platform: GtPlatform) -> bool {
        let bits = platform.physical_bits();
        self.memory
            .diagnostic_tables()
            .all(|phys| phys >> bits == 0)
            && self.objects.iter().all(|(object, _)| {
                (!platform.is_gen12() || !object.is_vram())
                    && object.pages().all(|phys| phys >> bits == 0)
            })
    }
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
