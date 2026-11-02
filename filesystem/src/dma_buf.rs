//! Generic dma-buf core: the reservation object and Linux `dma_buf_ioctl`.
//!
//! Linux keeps this in `drivers/dma-buf/` rather than in any exporter: every
//! dma-buf, whatever driver backs it, answers the same `DMA_BUF_IOCTL_*`
//! set against its `struct dma_resv`. NARF mirrors the split. An exporter
//! (the DRM PRIME files in `drivers/gpu`, or any future V4L2 `VIDIOC_EXPBUF`
//! file) owns one [`DmaBufObject`] per underlying buffer, shares it among
//! every fd and handle naming that buffer, and forwards its
//! `FileOps::ioctl_user` to [`dma_buf_ioctl`].
//!
//! sync_file fds belong to the syscall layer, which owns the fd table. The
//! core reaches them only through [`IoctlContext::sync_file_fences`] and
//! [`IoctlContext::install_sync_file`].
//!
//! Linux refs: `drivers/dma-buf/dma-buf.c` (`dma_buf_ioctl`,
//! `dma_buf_export_sync_file`, `dma_buf_import_sync_file`,
//! `dma_buf_set_name`, `__dma_buf_begin_cpu_access`),
//! `drivers/dma-buf/dma-resv.c`, `include/uapi/linux/dma-buf.h`.

use crate::{DrmFence, FsError, InstallFdError, IoctlContext};
use alloc::sync::Arc;
use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

/// `DMA_BUF_SYNC_READ` = `(1 << 0)` (`include/uapi/linux/dma-buf.h`).
pub const DMA_BUF_SYNC_READ: u64 = 1;
/// `DMA_BUF_SYNC_WRITE` = `(2 << 0)`.
pub const DMA_BUF_SYNC_WRITE: u64 = 2;
/// `DMA_BUF_SYNC_RW`.
pub const DMA_BUF_SYNC_RW: u64 = DMA_BUF_SYNC_READ | DMA_BUF_SYNC_WRITE;
/// `DMA_BUF_SYNC_START` = `(0 << 2)`: the absence of END.
pub const DMA_BUF_SYNC_START: u64 = 0;
/// `DMA_BUF_SYNC_END` = `(1 << 2)`.
pub const DMA_BUF_SYNC_END: u64 = 4;
/// `DMA_BUF_SYNC_VALID_FLAGS_MASK`.
pub const DMA_BUF_SYNC_VALID_FLAGS_MASK: u64 = DMA_BUF_SYNC_RW | DMA_BUF_SYNC_END;
/// `DMA_BUF_NAME_LEN`, including the terminating NUL.
pub const DMA_BUF_NAME_LEN: usize = 32;

/// `_IOW('b', 0, struct dma_buf_sync)` — one `__u64 flags`.
pub const DMA_BUF_IOCTL_SYNC: u32 = 0x4008_6200;
/// `_IOW('b', 1, __u32)`.
pub const DMA_BUF_SET_NAME_A: u32 = 0x4004_6201;
/// `_IOW('b', 1, __u64)`.
pub const DMA_BUF_SET_NAME_B: u32 = 0x4008_6201;
/// `_IOWR('b', 2, struct dma_buf_export_sync_file)` — `{ __u32 flags; __s32 fd; }`.
pub const DMA_BUF_IOCTL_EXPORT_SYNC_FILE: u32 = 0xc008_6202;
/// `_IOW('b', 3, struct dma_buf_import_sync_file)` — `{ __u32 flags; __s32 fd; }`.
pub const DMA_BUF_IOCTL_IMPORT_SYNC_FILE: u32 = 0x4008_6203;

const EINVAL: i64 = 22;
const EMFILE: i64 = 24;
const ENOTTY: i64 = 25;

/// Linux `enum dma_resv_usage`, in its documented total order: querying a
/// usage returns every fence whose usage is less than or equal to it. NARF
/// produces only WRITE and READ fences; KERNEL and BOOKKEEP exist so the
/// ordering reads the same as Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DmaResvUsage {
    Kernel,
    Write,
    Read,
    Bookkeep,
}

/// Linux `dma_resv_usage_rw(write)`: a new write must wait for every existing
/// reader and writer (`READ`), a new read only for existing writers (`WRITE`).
pub fn dma_resv_usage_rw(write: bool) -> DmaResvUsage {
    if write {
        DmaResvUsage::Read
    } else {
        DmaResvUsage::Write
    }
}

/// Immutable fence identity, sampled before entering a driver's admission lock.
/// Linux dma_fence context/seqno do not change during the fence lifetime.
#[derive(Clone)]
pub struct DmaResvFence {
    fence: Arc<dyn DrmFence>,
    context: Option<u64>,
    seqno: u64,
}
impl core::fmt::Debug for DmaResvFence {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DmaResvFence")
            .field("context", &self.context)
            .field("seqno", &self.seqno)
            .finish_non_exhaustive()
    }
}
impl DmaResvFence {
    pub fn new(fence: Arc<dyn DrmFence>) -> Self {
        Self {
            context: fence.context(),
            seqno: fence.seqno(),
            fence,
        }
    }
    fn same_context(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.fence, &other.fence)
            || (self.context.is_some() && self.context == other.context)
    }
}

#[derive(Clone, Debug)]
struct ReservationEntry {
    fence: DmaResvFence,
    usage: DmaResvUsage,
}

/// Completed observations and an addition generation from one reservation.
/// Construct outside all driver admission locks: polling foreign fences may
/// enter their driver. A completed fence remains terminal forever.
pub struct DmaResvSnapshot<'a> {
    owner: &'a DmaResv,
    generation: u64,
    entries: Vec<(ReservationEntry, bool)>,
}
impl core::fmt::Debug for DmaResvSnapshot<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DmaResvSnapshot")
            .field("generation", &self.generation)
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}
impl DmaResvSnapshot<'_> {
    pub fn has_fences(&self, usage: DmaResvUsage) -> bool {
        self.entries
            .iter()
            .any(|(entry, done)| !done && entry.usage <= usage)
    }
    /// Check under the exporter admission lock before CPU access or an
    /// implicit GPU admission. All exporter mutation paths must share it.
    pub fn is_current(&self) -> bool {
        self.owner.generation() == self.generation
    }
}

/// Removed references, retained until after the exporter's admission lock is
/// dropped. Dropping an arbitrary fence can enter another device's driver.
#[must_use = "drop retired fences only after releasing driver admission locks"]
#[derive(Debug)]
pub struct DmaResvRetired(Vec<ReservationEntry>);
impl Drop for DmaResvRetired {
    fn drop(&mut self) {
        self.0.clear();
    }
}

/// Linux `struct dma_resv`: the implicit-sync fences attached to one buffer.
pub struct DmaResv {
    fences: IrqSafeSpinLock<Vec<ReservationEntry>>,
    /// Counts additions, including same-context replacements.
    generation: core::sync::atomic::AtomicU64,
}
impl core::fmt::Debug for DmaResv {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DmaResv")
            .field("fences", &self.fences.lock().len())
            .finish()
    }
}
impl Default for DmaResv {
    fn default() -> Self {
        Self {
            fences: IrqSafeSpinLock::new(Vec::new()),
            generation: core::sync::atomic::AtomicU64::new(0),
        }
    }
}
impl DmaResv {
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot under the reservation lock, then invoke foreign callbacks
    /// only after releasing it. Identity metadata was captured at insertion.
    pub fn snapshot(&self) -> DmaResvSnapshot<'_> {
        let (entries, generation) = {
            let fences = self.fences.lock();
            (
                fences.clone(),
                self.generation.load(core::sync::atomic::Ordering::Acquire),
            )
        };
        DmaResvSnapshot {
            owner: self,
            generation,
            entries: entries
                .into_iter()
                .map(|entry| {
                    let done = entry.fence.fence.is_signalled();
                    (entry, done)
                })
                .collect(),
        }
    }

    /// Publish a batch without any fence callback or final foreign reference
    /// drop under this or the caller's admission lock. Stale snapshots may
    /// prune only their proven-terminal entries; they never remove later work.
    /// A conflict decision additionally requires Snapshot::is_current under
    /// the exporter's common admission lock before calling this operation.
    pub fn add_prepared(
        &self,
        snapshot: &DmaResvSnapshot<'_>,
        additions: &[(DmaResvFence, DmaResvUsage)],
    ) -> DmaResvRetired {
        assert!(
            core::ptr::eq(self, snapshot.owner),
            "reservation snapshot owner"
        );
        let mut retired = Vec::new();
        let mut fences = self.fences.lock();
        if additions.is_empty() {
            return DmaResvRetired(retired);
        }
        let mut index = 0;
        while index < fences.len() {
            if snapshot.entries.iter().any(|(old, done)| {
                *done && Arc::ptr_eq(&old.fence.fence, &fences[index].fence.fence)
            }) {
                retired.push(fences.remove(index));
            } else {
                index += 1;
            }
        }
        for (fence, usage) in additions {
            let entry = ReservationEntry {
                fence: fence.clone(),
                usage: *usage,
            };
            if let Some(slot) = fences.iter_mut().find(|old| {
                old.fence.same_context(fence)
                    && old.usage >= *usage
                    && fence.seqno >= old.fence.seqno
            }) {
                retired.push(core::mem::replace(slot, entry));
            } else {
                fences.push(entry);
            }
        }
        self.generation
            .fetch_add(additions.len() as u64, core::sync::atomic::Ordering::AcqRel);
        DmaResvRetired(retired)
    }

    /// Linux dma_resv_add_fence: same-context later/stronger replacement and
    /// terminal pruning. All callbacks and retired drops occur without locks.
    pub fn add_fence(&self, fence: Arc<dyn DrmFence>, usage: DmaResvUsage) {
        let prepared = DmaResvFence::new(fence);
        let snapshot = self.snapshot();
        drop(self.add_prepared(&snapshot, &[(prepared, usage)]));
    }
    pub fn generation(&self) -> u64 {
        let _fences = self.fences.lock();
        self.generation.load(core::sync::atomic::Ordering::Acquire)
    }
    /// Linux dma_resv_get_fences: no foreign callback under the lock.
    pub fn fences(&self, usage: DmaResvUsage) -> Vec<Arc<dyn DrmFence>> {
        let candidates: Vec<_> = self
            .fences
            .lock()
            .iter()
            .filter(|entry| entry.usage <= usage)
            .map(|entry| entry.fence.fence.clone())
            .collect();
        candidates
            .into_iter()
            .filter(|f| !f.is_signalled())
            .collect()
    }
}

/// One exported buffer's dma-buf state, shared by every fd and GEM handle
/// that names the buffer (Linux `struct dma_buf`'s `resv` and `name`).
pub struct DmaBufObject {
    pub resv: DmaResv,
    name: IrqSafeSpinLock<Option<Vec<u8>>>,
}

impl Default for DmaBufObject {
    fn default() -> Self {
        Self {
            resv: DmaResv::new(),
            name: IrqSafeSpinLock::new(None),
        }
    }
}

impl core::fmt::Debug for DmaBufObject {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DmaBufObject")
            .field("resv", &self.resv)
            .field("name", &self.name.lock().as_deref())
            .finish()
    }
}

impl DmaBufObject {
    pub fn new() -> Self {
        Self::default()
    }

    /// The `DMA_BUF_SET_NAME` name (without its NUL), if one was set.
    pub fn name(&self) -> Option<Vec<u8>> {
        self.name.lock().clone()
    }
}

fn neg(errno: i64) -> Result<u64, FsError> {
    Ok((-errno) as u64)
}

/// Re-poll interval of a parked implicit-sync wait.
const WAIT_REPOLL_NS: u64 = 1_000_000;
/// Slice of the synchronous in-kernel fallback wait.
const WAIT_SLICE_MS: u64 = 50;

/// Linux `dma_buf_ioctl` for any dma-buf `obj`.
///
/// Errors Linux reports with an errno that has no [`FsError`] mapping in the
/// syscall layer (`EMFILE`, `ENOTTY`) are returned in the `Ok(-errno)` wire
/// form, as other device ioctls in NARF do. `Err(WouldBlock)` follows a
/// successful [`IoctlContext::restart_after`].
pub fn dma_buf_ioctl(
    obj: &DmaBufObject,
    cmd: u32,
    arg: u64,
    ctx: &dyn IoctlContext,
) -> Result<u64, FsError> {
    match cmd {
        DMA_BUF_IOCTL_SYNC => {
            let mut raw = [0u8; 8];
            ctx.read(arg, &mut raw)?;
            let flags = u64::from_ne_bytes(raw);
            if flags & !DMA_BUF_SYNC_VALID_FLAGS_MASK != 0 {
                return neg(EINVAL);
            }
            // DMA_FROM_DEVICE / DMA_TO_DEVICE / DMA_BIDIRECTIONAL; neither
            // direction bit is -EINVAL.
            let write = match flags & DMA_BUF_SYNC_RW {
                DMA_BUF_SYNC_READ => false,
                DMA_BUF_SYNC_WRITE | DMA_BUF_SYNC_RW => true,
                _ => return neg(EINVAL),
            };
            if flags & DMA_BUF_SYNC_END != 0 {
                // dma_buf_end_cpu_access: NARF's exporters are CPU-coherent
                // and have no `end_cpu_access` hook, so this is 0.
                return Ok(0);
            }
            // dma_buf_begin_cpu_access → __dma_buf_begin_cpu_access: wait,
            // interruptibly and without timeout, on the implicit fences of
            // `dma_resv_usage_rw(write)`. (The DRM PRIME exporters,
            // `drm_gem_prime_dmabuf_ops`, have no `begin_cpu_access`, and
            // coherent memory needs no cache maintenance.)
            //
            // The wait is `dma_resv_wait_timeout(.., intr = true, ..)`: a
            // user task parks and re-executes this ioctl (everything above is
            // validation only, so re-execution is idempotent), and a signal
            // over the parked ioctl restarts it under SA_RESTART or completes
            // it with -EINTR, exactly as -ERESTARTSYS does. Fence completion
            // has no task waker, so the park re-polls every millisecond (the
            // same policy as a sync_file's device-fence `poll_deadline`).
            for fence in obj.resv.fences(dma_resv_usage_rw(write)) {
                if fence.is_signalled() {
                    continue;
                }
                if ctx.restart_after(WAIT_REPOLL_NS) {
                    return Err(FsError::WouldBlock);
                }
                // No executor to park on: only an in-kernel caller (the
                // kernel-test harness) reaches this, never a user task, so
                // there is no signal to be interrupted by.
                while !fence.wait(WAIT_SLICE_MS) {}
            }
            Ok(0)
        }
        DMA_BUF_SET_NAME_A | DMA_BUF_SET_NAME_B => {
            // strndup_user(buf, DMA_BUF_NAME_LEN): strnlen_user faulting is
            // -EFAULT, a string longer than 31 bytes (no NUL within 32) is
            // -EINVAL.
            let mut name = Vec::with_capacity(DMA_BUF_NAME_LEN);
            let mut terminated = false;
            for index in 0..DMA_BUF_NAME_LEN as u64 {
                let mut byte = [0u8; 1];
                ctx.read(arg.wrapping_add(index), &mut byte)?;
                if byte[0] == 0 {
                    terminated = true;
                    break;
                }
                name.push(byte[0]);
            }
            if !terminated {
                return neg(EINVAL);
            }
            *obj.name.lock() = Some(name);
            Ok(0)
        }
        DMA_BUF_IOCTL_EXPORT_SYNC_FILE => {
            let mut raw = [0u8; 8];
            ctx.read(arg, &mut raw)?;
            let flags = u32::from_ne_bytes(raw[0..4].try_into().unwrap()) as u64;
            if flags & !DMA_BUF_SYNC_RW != 0 || flags & DMA_BUF_SYNC_RW == 0 {
                return neg(EINVAL);
            }
            // get_unused_fd_flags precedes the snapshot; the context reserves
            // first. dma_resv_get_singleton(resv, usage_rw(write)).
            let fences = obj
                .resv
                .fences(dma_resv_usage_rw(flags & DMA_BUF_SYNC_WRITE != 0));
            let mut report = |fd: i32| {
                let mut out = raw;
                out[4..8].copy_from_slice(&fd.to_ne_bytes());
                ctx.write(arg, &out)
            };
            match ctx.install_sync_file(fences, &mut report) {
                Ok(_) => Ok(0),
                Err(InstallFdError::NoDescriptor) => neg(EMFILE),
                Err(InstallFdError::Report(error)) => Err(error),
            }
        }
        DMA_BUF_IOCTL_IMPORT_SYNC_FILE => {
            let mut raw = [0u8; 8];
            ctx.read(arg, &mut raw)?;
            let flags = u32::from_ne_bytes(raw[0..4].try_into().unwrap()) as u64;
            if flags & !DMA_BUF_SYNC_RW != 0 || flags & DMA_BUF_SYNC_RW == 0 {
                return neg(EINVAL);
            }
            let fd = i32::from_ne_bytes(raw[4..8].try_into().unwrap());
            // sync_file_get_fence: a bad fd and a non-sync_file are one NULL.
            let Some(fences) = ctx.sync_file_fences(fd) else {
                return neg(EINVAL);
            };
            let usage = if flags & DMA_BUF_SYNC_WRITE != 0 {
                DmaResvUsage::Write
            } else {
                DmaResvUsage::Read
            };
            // dma_fence_unwrap_for_each → dma_resv_add_fence per leaf.
            for fence in fences {
                obj.resv.add_fence(fence, usage);
            }
            Ok(0)
        }
        _ => neg(ENOTTY),
    }
}
