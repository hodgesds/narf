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

/// Linux `struct dma_resv`: the implicit-sync fences attached to one buffer.
pub struct DmaResv {
    fences: IrqSafeSpinLock<Vec<(Arc<dyn DrmFence>, DmaResvUsage)>>,
}

impl core::fmt::Debug for DmaResv {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DmaResv")
            .field("fences", &self.fences.lock().len())
            .finish()
    }
}

fn same_context(a: &Arc<dyn DrmFence>, b: &Arc<dyn DrmFence>) -> bool {
    Arc::ptr_eq(a, b) || (a.context().is_some() && a.context() == b.context())
}

impl Default for DmaResv {
    fn default() -> Self {
        Self {
            fences: IrqSafeSpinLock::new(Vec::new()),
        }
    }
}

impl DmaResv {
    pub fn new() -> Self {
        Self::default()
    }

    /// Linux `dma_resv_add_fence`: a fence replaces an existing one of the
    /// same context that it is later than or equal to (when the old usage is
    /// at least as strong), or any already-signalled fence; otherwise it is
    /// appended.
    ///
    /// Driver fences may take their device's request gate to reap
    /// completions, so signalled-ness is sampled with the lock dropped;
    /// signalled entries are pruned rather than reused slot-by-slot, which
    /// no query can distinguish (every query skips signalled fences).
    pub fn add_fence(&self, fence: Arc<dyn DrmFence>, usage: DmaResvUsage) {
        let snapshot: Vec<Arc<dyn DrmFence>> =
            self.fences.lock().iter().map(|(f, _)| f.clone()).collect();
        let signalled: Vec<Arc<dyn DrmFence>> =
            snapshot.into_iter().filter(|f| f.is_signalled()).collect();
        let mut fences = self.fences.lock();
        fences.retain(|(old, _)| !signalled.iter().any(|s| Arc::ptr_eq(s, old)));
        for slot in fences.iter_mut() {
            let (old, old_usage) = slot;
            // dma_fence_is_later_or_same(fence, old).
            if same_context(old, &fence) && *old_usage >= usage && fence.seqno() >= old.seqno() {
                *slot = (fence, usage);
                return;
            }
        }
        fences.push((fence, usage));
    }

    /// Linux `dma_resv_get_fences(obj, usage)`: the unsignalled fences whose
    /// usage is at most `usage`, in insertion order.
    pub fn fences(&self, usage: DmaResvUsage) -> Vec<Arc<dyn DrmFence>> {
        let candidates: Vec<Arc<dyn DrmFence>> = self
            .fences
            .lock()
            .iter()
            .filter(|(_, fence_usage)| *fence_usage <= usage)
            .map(|(fence, _)| fence.clone())
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
