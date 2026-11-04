//! i915 explicit submission synchronization, Linux MIT b90c984d615e8ce2af96f5b1411a962d83fed2ad:
//! i915_gem_execbuffer.c (fence arrays and timeline extensions), drm_syncobj.c.
use crate::{
    drm::syncobj::{self as so, SyncObjCore, SyncObjTable},
    intel_gpu_fence::CompletionFence,
    intel_gpu_uapi::{self as abi, u32_at, u64_at},
};
use alloc::{sync::Arc, vec, vec::Vec};
use narf_filesystem::{DrmFence, FsError, IoctlContext};
use narf_lib::sync::IrqSafeSpinLock;

/// I915_EXEC_FENCE_WAIT / I915_EXEC_FENCE_SIGNAL; every other bit is
/// __I915_EXEC_FENCE_UNKNOWN_FLAGS.
const FENCE_WAIT: u32 = 1;
const FENCE_SIGNAL: u32 = 2;
/// sizeof(struct eb_fence): syncobj, dma_fence, value and chain_fence.
const EB_FENCE_BYTES: u64 = 32;
/// add_{timeline_,}fence_array's overflow bound, `min(ULONG_MAX /
/// sizeof(struct drm_i915_gem_exec_fence), SIZE_MAX / sizeof(*f))` on a
/// 64-bit kernel: more entries than this, less those already added, are
/// -EINVAL.
const FENCE_ENTRIES_MAX: u64 = u64::MAX / EB_FENCE_BYTES;
/// KMALLOC_MAX_SIZE, `1 << (MAX_PAGE_ORDER + PAGE_SHIFT)` with the x86_64
/// and 4K-page arm64 MAX_PAGE_ORDER of 10. The eb->fences krealloc of
/// `(num_fences + nfences) * sizeof(*f)` returns NULL above it (-ENOMEM),
/// so at most 131072 entries are ever added: the only fence bound Linux
/// has, and the one NARF keeps. Allocation failure below it is -ENOMEM too.
const KMALLOC_MAX_SIZE: u64 = 1 << 22;
/// The highest `ptr + size` access_ok admits. x86_64:
/// arch/x86/kernel/cpu/common.c sets USER_PTR_MAX = TASK_SIZE_MAX, which
/// page_64.h::task_size_max makes `(1 << 47) - PAGE_SIZE` with 4-level
/// paging; uaccess_64.h::valid_user_address compares `<=` it.
#[cfg(not(target_arch = "aarch64"))]
const USER_PTR_MAX: u64 = (1 << 47) - 4096;
/// aarch64: asm-generic/access_ok.h::__access_ok's limit is TASK_SIZE_MAX,
/// `1 << VA_BITS` (processor.h), 48-bit here; `addr <= limit - size`.
#[cfg(target_arch = "aarch64")]
const USER_PTR_MAX: u64 = 1 << 48;

struct Dependency {
    fence: Arc<dyn DrmFence>,
    submit: bool,
}
/// The parsed request: like Linux's eb->fences, every syncobj and payload
/// is retained as its entry is parsed, before any wait or publication, so
/// handle destruction/replacement in another thread cannot retarget them.
pub(crate) struct SyncRequest {
    pub output: bool,
    pub input_word: u32,
    /// eb->num_fences: entries added so far (a skipped entry is not).
    fences: u64,
    dependencies: Vec<Dependency>,
    signals: Vec<(Arc<SyncObjCore>, u64)>,
}
pub(crate) struct Resolved {
    dependencies: Vec<Dependency>,
    signals: Vec<(Arc<SyncObjCore>, u64)>,
}

fn read(user: &dyn IoctlContext, address: u64, bytes: usize) -> Result<Vec<u8>, FsError> {
    if bytes == 0 {
        return Ok(Vec::new());
    }
    address
        .checked_add(bytes as u64)
        .ok_or(FsError::BadAddress)?;
    let mut data = vec![0; bytes];
    user.read(address, &mut data)?;
    Ok(data)
}

/// `__get_user`/`__copy_from_user` of the `n`th 8-byte array element.
fn element(user: &dyn IoctlContext, array: u64, n: u64) -> Result<[u8; 8], FsError> {
    let mut bytes = [0; 8];
    let address = array.checked_add(n * 8).ok_or(FsError::BadAddress)?;
    user.read(address, &mut bytes)?;
    Ok(bytes)
}

/// `__access_ok` for a non-constant size: `ptr + size` must not wrap and
/// must not pass USER_PTR_MAX (x86_64's `valid_user_address(sum) && sum >=
/// ptr`; arm64's u65 `addr + size <= TASK_SIZE_MAX`). Null passes, as in
/// Linux; its first element copy faults instead. LINUX-GAP: arm64 untags a
/// TIF_TAGGED_ADDR pointer first; NARF has no tagged-address ABI.
fn access_ok(address: u64, size: u64) -> bool {
    address
        .checked_add(size)
        .is_some_and(|end| end <= USER_PTR_MAX)
}

/// drm_syncobj_find: the object behind `handle`, referenced; -ENOENT.
fn find(table: &IrqSafeSpinLock<SyncObjTable>, handle: u32) -> Result<Arc<SyncObjCore>, FsError> {
    let core = table.lock().get(handle).map(|object| object.core().clone());
    core.map_err(|_| FsError::NotFound)
}

impl SyncRequest {
    /// The fence half of i915_gem_do_execbuffer, in its order:
    /// parse_execbuf2_extensions (TIMELINE_FENCES), add_fence_array, then
    /// the IN/SUBMIT sync_file. The caller has already run
    /// i915_gem_check_execbuffer, which refuses cliprects without
    /// FENCE_ARRAY or USE_EXTENSIONS, and copied the exec objects.
    pub fn read(
        user: &dyn IoctlContext,
        wire: &[u8; 64],
        table: &IrqSafeSpinLock<SyncObjTable>,
    ) -> Result<Self, FsError> {
        let flags = u64_at(wire, 40);
        let array = flags & abi::EXEC_FENCE_ARRAY != 0;
        let extensions = flags & abi::EXEC_USE_EXTENSIONS != 0;
        let count = u32_at(wire, 28);
        let pointer = u64_at(wire, 32);
        // parse_execbuf2_extensions refuses FENCE_ARRAY or num_cliprects
        // beside USE_EXTENSIONS before walking the chain.
        if extensions && (array || count != 0) {
            return Err(FsError::InvalidData);
        }
        let input_word = u64_at(wire, 56) as u32;
        let mut result = Self {
            output: flags & abi::EXEC_FENCE_OUT != 0,
            input_word,
            fences: 0,
            dependencies: Vec::new(),
            signals: Vec::new(),
        };
        if extensions {
            // parse_execbuf2_extensions: i915_user_extensions over
            // execbuf_extensions[], whose only entry is
            // DRM_I915_GEM_EXECBUFFER_EXT_TIMELINE_FENCES (0).
            abi::user_extensions(user, pointer, |address, name| {
                if name != 0 {
                    return Err(FsError::InvalidData);
                }
                // parse_timeline_fences copies the whole 56-byte
                // drm_i915_gem_execbuffer_ext_timeline_fences.
                let ext = read(user, address, 56)?;
                result.timeline(user, table, &ext)
            })?;
        }
        if array {
            result.binary(user, table, pointer, count)?;
        }
        let inputs = flags & (abi::EXEC_FENCE_IN | abi::EXEC_FENCE_SUBMIT);
        if inputs != 0 {
            if inputs == abi::EXEC_FENCE_IN | abi::EXEC_FENCE_SUBMIT {
                return Err(FsError::InvalidData);
            }
            // sync_file_get_fence: a bad fd and a non-sync_file are -EINVAL.
            let fences = user
                .sync_file_fences(input_word as i32)
                .ok_or(FsError::InvalidData)?;
            result.depend(fences, inputs == abi::EXEC_FENCE_SUBMIT)?;
        }
        // Without FENCE_IN, FENCE_SUBMIT or FENCE_OUT, i915_gem_do_execbuffer
        // never reads rsvd2: any value is ignored.
        Ok(result)
    }

    /// The common add_{timeline_,}fence_array preamble: the overflow bound
    /// (-EINVAL), access_ok of each user array (-EFAULT), then the
    /// eb->fences krealloc (-ENOMEM), all before any element is copied.
    fn reserve(&self, entries: u64, arrays: &[u64]) -> Result<(), FsError> {
        if entries > FENCE_ENTRIES_MAX - self.fences {
            return Err(FsError::InvalidData);
        }
        for array in arrays {
            if !access_ok(*array, entries * 8) {
                return Err(FsError::BadAddress);
            }
        }
        if (self.fences + entries) * EB_FENCE_BYTES > KMALLOC_MAX_SIZE {
            return Err(FsError::OutOfMemory);
        }
        Ok(())
    }

    /// Retain `fences` as dependencies; allocation failure is -ENOMEM.
    fn depend(&mut self, fences: Vec<Arc<dyn DrmFence>>, submit: bool) -> Result<(), FsError> {
        self.dependencies
            .try_reserve(fences.len())
            .map_err(|_| FsError::OutOfMemory)?;
        self.dependencies
            .extend(fences.into_iter().map(|fence| Dependency { fence, submit }));
        Ok(())
    }

    /// One eb_fence: await_fence_array waits on every present fence, and
    /// signal_fence_array signals every SIGNAL entry (point 0: replace).
    fn add(
        &mut self,
        core: Arc<SyncObjCore>,
        flags: u32,
        fence: Option<Arc<dyn so::DmaFence>>,
        point: u64,
    ) -> Result<(), FsError> {
        if let Some(fence) = fence {
            self.depend(so::to_drm_leaves(&fence), false)?;
        }
        if flags & FENCE_SIGNAL != 0 {
            self.signals
                .try_reserve(1)
                .map_err(|_| FsError::OutOfMemory)?;
            self.signals.push((core, point));
        }
        self.fences += 1;
        Ok(())
    }

    /// i915_gem_execbuffer.c::add_timeline_fence_array, entry by entry.
    fn timeline(
        &mut self,
        user: &dyn IoctlContext,
        table: &IrqSafeSpinLock<SyncObjTable>,
        ext: &[u8],
    ) -> Result<(), FsError> {
        let entries = u64_at(ext, 32);
        if entries == 0 {
            return Ok(());
        }
        let (handles, values) = (u64_at(ext, 40), u64_at(ext, 48));
        self.reserve(entries, &[handles, values])?;
        // Linux's `err` is function-scoped and assigned only while a fence
        // is present, so a find_seqno failure a SIGNAL entry tolerated is
        // still set at a later fence-less entry of this extension.
        let mut seqno_error = false;
        for n in 0..entries {
            let entry = element(user, handles, n)?;
            let (handle, flags) = (u32_at(&entry, 0), u32_at(&entry, 4));
            if flags & !(FENCE_WAIT | FENCE_SIGNAL) != 0 {
                return Err(FsError::InvalidData);
            }
            let point = u64::from_le_bytes(element(user, values, n)?);
            let core = find(table, handle)?;
            let mut fence = core.fence();
            if fence.is_none() && flags != 0 && flags & FENCE_SIGNAL == 0 {
                return Err(FsError::InvalidData);
            }
            if let Some(payload) = fence.clone() {
                // dma_fence_chain_find_seqno leaves the payload on -EINVAL.
                match so::find_seqno(Some(payload), point) {
                    Ok(found) => {
                        fence = found;
                        seqno_error = false;
                    }
                    Err(()) => seqno_error = true,
                }
            }
            if seqno_error && flags & FENCE_SIGNAL == 0 {
                return Err(FsError::InvalidData);
            }
            // A signalled, collected point is ignored.
            if fence.is_none() && flags & FENCE_SIGNAL == 0 {
                continue;
            }
            // Waiting and signalling the same nonzero point would break the
            // timeline.
            if point != 0 && flags & FENCE_SIGNAL != 0 && flags & FENCE_WAIT != 0 {
                return Err(FsError::InvalidData);
            }
            self.add(core, flags, fence, point)?;
        }
        Ok(())
    }

    /// i915_gem_execbuffer.c::add_fence_array, entry by entry.
    fn binary(
        &mut self,
        user: &dyn IoctlContext,
        table: &IrqSafeSpinLock<SyncObjTable>,
        array: u64,
        count: u32,
    ) -> Result<(), FsError> {
        if count == 0 {
            return Ok(());
        }
        self.reserve(u64::from(count), &[array])?;
        for n in 0..u64::from(count) {
            let entry = element(user, array, n)?;
            let (handle, flags) = (u32_at(&entry, 0), u32_at(&entry, 4));
            if flags & !(FENCE_WAIT | FENCE_SIGNAL) != 0 {
                return Err(FsError::InvalidData);
            }
            let core = find(table, handle)?;
            let fence = if flags & FENCE_WAIT != 0 {
                Some(core.fence().ok_or(FsError::InvalidData)?)
            } else {
                None
            };
            self.add(core, flags, fence, 0)?;
        }
        Ok(())
    }

    /// Every syncobj and payload was retained while parsing.
    pub fn resolve(self) -> Resolved {
        Resolved {
            dependencies: self.dependencies,
            signals: self.signals,
        }
    }
}
impl Resolved {
    pub async fn wait(&self) {
        while self.dependencies.iter().any(|dependency| {
            if dependency.submit {
                !dependency.fence.is_submit_ready()
            } else {
                !dependency.fence.is_signalled()
            }
        }) {
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(100).as_instant()).await;
        }
    }
    pub fn publish(self, fence: Arc<CompletionFence>) {
        if self.signals.is_empty() {
            return;
        }
        let fence = so::from_drm_leaves(vec![fence]);
        for (core, point) in self.signals {
            if point == 0 {
                core.replace_fence(Some(fence.clone()));
            } else {
                core.add_point(fence.clone(), point);
            }
        }
    }
}
