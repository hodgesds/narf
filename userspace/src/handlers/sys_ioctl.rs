#[allow(unused_imports)]
use super::*;
use alloc::boxed::Box;
use alloc::vec::Vec;

struct DeviceIoctlContext {
    nonblocking: bool,
}

impl narf_filesystem::IoctlContext for DeviceIoctlContext {
    fn read(&self, address: u64, destination: &mut [u8]) -> Result<(), narf_filesystem::FsError> {
        // SAFETY: this context is used only inside the calling syscall while
        // its address space is active. The helper validates and guards faults.
        unsafe { copy_from_user(destination, address) }
            .map_err(|_| narf_filesystem::FsError::BadAddress)
    }

    fn write(&self, address: u64, source: &[u8]) -> Result<(), narf_filesystem::FsError> {
        // SAFETY: same syscall/address-space contract as read; racing unmaps
        // are caught by the guarded copy rather than faulting the kernel.
        unsafe { copy_to_user(address, source) }
            .map_err(|_| narf_filesystem::FsError::BadAddress)
    }

    fn nonblocking(&self) -> bool {
        self.nonblocking
    }
    fn file(&self, number: i32) -> Result<Arc<dyn narf_filesystem::FileOps>, narf_filesystem::FsError> {
        crate::fd::with_table(current_task_id(), |t| {
            t.get(number as u32).map(|entry| entry.ops.clone())
        })
        .flatten()
        .ok_or(narf_filesystem::FsError::BadFd)
    }
    fn process_id(&self) -> u32 {
        task_to_pid_raw(current_task_id()).unwrap_or(current_task_id()) as u32
    }
    fn install_file(
        &self,
        file: Arc<dyn narf_filesystem::FileOps>,
        cloexec: bool,
    ) -> Result<i32, narf_filesystem::FsError> {
        let flags = if cloexec { crate::fd::FD_CLOEXEC } else { 0 };
        crate::fd::install(
            current_task_id(),
            crate::fd::FdEntry {
                ops: file,
                offset: 0,
                flags,
                status_flags: 0,
            },
        )
        .map(|n| n as i32)
        .ok_or(narf_filesystem::FsError::OutOfMemory)
    }

    fn sync_file_fences(&self, fd: i32) -> Option<Vec<Arc<dyn narf_filesystem::DrmFence>>> {
        sync_file_leaves(current_task_id(), fd)
    }

    fn install_sync_file(
        &self,
        fences: Vec<Arc<dyn narf_filesystem::DrmFence>>,
        report: &mut dyn FnMut(i32) -> Result<(), narf_filesystem::FsError>,
    ) -> Result<i32, narf_filesystem::InstallFdError> {
        // get_unused_fd_flags(O_CLOEXEC) first, then dma_resv_get_singleton
        // + sync_file_create, then copy_to_user, and fd_install only once the
        // number reached the caller (put_unused_fd otherwise).
        let reservation = fd::reserve(current_task_id())
            .ok_or(narf_filesystem::InstallFdError::NoDescriptor)?;
        let file = DrmSyncFile::from_singleton(fences);
        report(reservation.fd() as i32).map_err(narf_filesystem::InstallFdError::Report)?;
        reservation
            .install(fd::FdEntry {
                ops: Arc::new(file),
                offset: 0,
                flags: fd::FD_CLOEXEC,
                status_flags: 0,
            })
            .map(|n| n as i32)
            .ok_or(narf_filesystem::InstallFdError::Report(
                narf_filesystem::FsError::OutOfMemory,
            ))
    }

    fn signal_pending(&self) -> bool {
        has_interrupting_signal(current_task_id())
    }
}

/// `sync_file_fdget(fd)` + `dma_fence_unwrap`: the leaf fences of the
/// sync_file at `fd` in `task`'s table, or `None` for a bad descriptor or a
/// file of another type.
fn sync_file_leaves(task: u64, fd: i32) -> Option<Vec<Arc<dyn narf_filesystem::DrmFence>>> {
    let ops = fd::with_table(task, |table| {
        table.get(u32::try_from(fd).ok()?).map(|entry| entry.ops.clone())
    })
    .flatten()?;
    ops.as_any()
        .and_then(|any| any.downcast_ref::<DrmSyncFile>())
        .map(DrmSyncFile::leaves)
}

/// Source of `dma_fence.context` values for the fences this layer creates
/// (atomic vblank fences, `dma_fence_array` containers). Linux draws every
/// context from one `dma_fence_context_alloc` counter. NARF driver fences
/// carry driver-chosen keys (virtio-gpu: `ctx_id << 32 | ring_idx`), so the
/// syscall layer allocates from the top half of the u64 space, which no
/// driver key reaches.
static NEXT_FENCE_CONTEXT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(1 << 63);

fn fence_context_alloc() -> u64 {
    NEXT_FENCE_CONTEXT.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
}

/// Linux's stub fence (`dma_fence_get_stub` / `dma_fence_allocate_private_stub`):
/// signalled from birth, context 0, seqno 0, driver and timeline `"stub"`.
struct StubFence {
    timestamp_ns: u64,
}

impl narf_filesystem::DrmFence for StubFence {
    fn is_signalled(&self) -> bool {
        true
    }

    fn wait(&self, _timeout_ms: u64) -> bool {
        true
    }

    fn context(&self) -> Option<u64> {
        Some(0)
    }

    fn driver_name(&self) -> &str {
        "stub"
    }

    fn timeline_name(&self) -> &str {
        "stub"
    }

    fn timestamp_ns(&self) -> Option<u64> {
        Some(self.timestamp_ns)
    }
}

/// Signal time of the global stub. Linux signals `dma_fence_stub` from a
/// `subsys_initcall`, so its timestamp is boot time; NARF stamps it the
/// first time the stub is handed out.
static STUB_TIMESTAMP_NS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// `dma_fence_get_stub()`.
fn global_stub_fence() -> Arc<dyn narf_filesystem::DrmFence> {
    use core::sync::atomic::Ordering;
    let now = narf_time::wall::monotonic_ns().max(1);
    let _ = STUB_TIMESTAMP_NS.compare_exchange(0, now, Ordering::AcqRel, Ordering::Acquire);
    Arc::new(StubFence {
        timestamp_ns: STUB_TIMESTAMP_NS.load(Ordering::Acquire),
    })
}

/// An atomic commit's `OUT_FENCE_PTR` fence. It signals at the commit's
/// SIMULATED VBLANK, a `CLOCK_MONOTONIC` instant, and is reported with driver
/// name `"narf_kms"` and timeline `"vblank"`. (Linux names a CRTC fence
/// after the DRM driver and `"CRTC:<id>-<name>"`; the out-fence hand-off
/// from the DRM bridge carries no CRTC identity, so the names are fixed.)
/// Each fence is its own context: commits on different CRTCs carry no
/// ordering that would let a merge keep only the later one.
struct VblankFence {
    deadline_ns: u64,
    context: u64,
}

impl narf_filesystem::DrmFence for VblankFence {
    fn is_signalled(&self) -> bool {
        narf_time::wall::monotonic_ns() >= self.deadline_ns
    }

    fn wait(&self, timeout_ms: u64) -> bool {
        narf_scheduler::responsive_spin_until(
            || narf_time::wall::monotonic_ns() >= self.deadline_ns,
            narf_time::Deadline::after_ms(timeout_ms),
        )
    }

    fn context(&self) -> Option<u64> {
        Some(self.context)
    }

    fn seqno(&self) -> u64 {
        1
    }

    fn driver_name(&self) -> &str {
        "narf_kms"
    }

    fn timeline_name(&self) -> &str {
        "vblank"
    }

    fn timestamp_ns(&self) -> Option<u64> {
        Some(self.deadline_ns)
    }
}

/// How a leaf fence's completion is discovered, which decides the file's
/// `poll_deadline`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PointKind {
    /// Driver completion object: no interrupt waker yet, re-polled every 1 ms.
    Device,
    /// Time-based fence signalling at this `CLOCK_MONOTONIC` instant.
    Vblank(u64),
    /// Signalled from birth.
    Stub,
}

/// One leaf of a sync_file's fence (Linux `dma_fence_unwrap` yields these).
struct SyncPoint {
    fence: Arc<dyn narf_filesystem::DrmFence>,
    kind: PointKind,
    /// First `CLOCK_MONOTONIC` instant this file saw the fence signalled; the
    /// reported timestamp for fences whose driver records none.
    observed_ns: core::sync::atomic::AtomicU64,
}

impl SyncPoint {
    fn new(fence: Arc<dyn narf_filesystem::DrmFence>, kind: PointKind) -> Self {
        Self {
            fence,
            kind,
            observed_ns: core::sync::atomic::AtomicU64::new(0),
        }
    }

    /// The same leaf in another file, keeping its observed signal time.
    fn fork(&self) -> Self {
        let point = Self::new(self.fence.clone(), self.kind);
        point.observed_ns.store(
            self.observed_ns.load(core::sync::atomic::Ordering::Acquire),
            core::sync::atomic::Ordering::Release,
        );
        point
    }

    fn signalled(&self) -> bool {
        use core::sync::atomic::Ordering;
        let signalled = self.fence.is_signalled();
        if signalled && self.observed_ns.load(Ordering::Acquire) == 0 {
            let now = narf_time::wall::monotonic_ns().max(1);
            let _ = self
                .observed_ns
                .compare_exchange(0, now, Ordering::AcqRel, Ordering::Acquire);
        }
        signalled
    }

    /// Linux `dma_fence_timestamp`, for a signalled fence.
    fn timestamp_ns(&self) -> u64 {
        self.fence
            .timestamp_ns()
            .unwrap_or_else(|| self.observed_ns.load(core::sync::atomic::Ordering::Acquire))
    }
}

/// `strscpy(dst, src, dst.len())` over byte strings: copy up to the first
/// NUL of `src`, truncate to leave room for one, NUL-terminate, and leave the
/// rest of `dst` untouched (strscpy does not pad).
fn strscpy(dst: &mut [u8], src: &[u8]) {
    let len = src
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(src.len())
        .min(dst.len().saturating_sub(1));
    dst[..len].copy_from_slice(&src[..len]);
    if len < dst.len() {
        dst[len] = 0;
    }
}

/// A dma-fence exposed through Linux's `sync_file` fd ABI
/// (`drivers/dma-buf/sync_file.c`).
///
/// Linux's sync_file holds ONE `dma_fence`, which may be a
/// `dma_fence_array` container; `dma_fence_unwrap` iterates its leaves. NARF
/// stores the unwrapped leaves directly plus whether they sit in a container
/// (`array_context`), which is all the ABI can observe: FILE_INFO lists the
/// leaves, the file is readable once every leaf has signalled (an array
/// built with `signal_on_any = false`), and the generated name describes
/// the container.
///
/// Producers: `VIRTGPU_EXECBUF_FENCE_FD_OUT` device fences (a driver that
/// produced no fence falls back to the signalled stub); atomic
/// `OUT_FENCE_PTR` [`VblankFence`]s; `SYNC_IOC_MERGE`; and
/// `DMA_BUF_IOCTL_EXPORT_SYNC_FILE` through
/// [`narf_filesystem::IoctlContext::install_sync_file`]. It is a distinct
/// file type so `VIRTGPU_EXECBUF_FENCE_FD_IN`, `SYNC_IOC_MERGE` and
/// `DMA_BUF_IOCTL_IMPORT_SYNC_FILE` reject arbitrary descriptors exactly
/// like `sync_file_fdget()` does on Linux.
struct DrmSyncFile {
    /// `dma_fence_unwrap` leaves; never empty.
    points: Vec<SyncPoint>,
    /// `Some(context)` when the file's fence is a `dma_fence_array`.
    array_context: Option<u64>,
    /// `sync_file->user_name`: the SYNC_IOC_MERGE name, all-zero otherwise.
    user_name: [u8; 32],
}

/// `struct sync_merge_data`: name[32] fd2@32 fence@36 flags@40 pad@44.
const SYNC_MERGE_DATA_SIZE: usize = 48;
/// `struct sync_file_info`: name[32] status@32 flags@36 num_fences@40
/// pad@44 sync_fence_info@48.
const SYNC_FILE_INFO_SIZE: usize = 56;
/// `struct sync_fence_info`: obj_name[32] driver_name[32] status@64
/// flags@68 timestamp_ns@72.
const SYNC_FENCE_INFO_SIZE: usize = 80;
/// `_IOWR('>', 3, struct sync_merge_data)`.
const SYNC_IOC_MERGE: u32 = 0xc030_3e03;
/// `_IOWR('>', 4, struct sync_file_info)`.
const SYNC_IOC_FILE_INFO: u32 = 0xc038_3e04;
/// `_IOW('>', 5, struct sync_set_deadline)` — `{ __u64 deadline_ns; __u64 pad; }`.
const SYNC_IOC_SET_DEADLINE: u32 = 0x4010_3e05;

fn sync_neg(errno: i64) -> Result<u64, narf_filesystem::FsError> {
    Ok((-errno) as u64)
}

impl DrmSyncFile {
    fn single(fence: Arc<dyn narf_filesystem::DrmFence>, kind: PointKind) -> Self {
        Self {
            points: alloc::vec![SyncPoint::new(fence, kind)],
            array_context: None,
            user_name: [0; 32],
        }
    }

    /// `sync_file_create(dma_fence_get_stub())`: signalled from birth.
    fn signalled_stub() -> Self {
        Self::single(global_stub_fence(), PointKind::Stub)
    }

    /// An atomic `OUT_FENCE_PTR` fence signalling at `deadline_ns`.
    fn vblank(deadline_ns: u64) -> Self {
        Self::single(
            Arc::new(VblankFence {
                deadline_ns,
                context: fence_context_alloc(),
            }),
            PointKind::Vblank(deadline_ns),
        )
    }

    /// `sync_file_create(fence)` for a driver device fence.
    fn device(fence: Arc<dyn narf_filesystem::DrmFence>) -> Self {
        Self::single(fence, PointKind::Device)
    }

    /// `dma_resv_get_singleton` + stub fallback, as
    /// `dma_buf_export_sync_file` composes them: no fence is the stub, one
    /// fence is itself, several become one `dma_fence_array` (context from
    /// `dma_fence_context_alloc(1)`, seqno 1, no de-duplication).
    fn from_singleton(fences: Vec<Arc<dyn narf_filesystem::DrmFence>>) -> Self {
        match fences.len() {
            0 => Self::signalled_stub(),
            1 => Self::device(fences.into_iter().next().unwrap()),
            _ => Self {
                points: fences
                    .into_iter()
                    .map(|fence| SyncPoint::new(fence, PointKind::Device))
                    .collect(),
                array_context: Some(fence_context_alloc()),
                user_name: [0; 32],
            },
        }
    }

    fn leaves(&self) -> Vec<Arc<dyn narf_filesystem::DrmFence>> {
        self.points.iter().map(|point| point.fence.clone()).collect()
    }

    /// `dma_fence_is_signaled(sync_file->fence)`. Every leaf is sampled so
    /// each records its observed signal time.
    fn signalled(&self) -> bool {
        self.points
            .iter()
            .fold(true, |all, point| point.signalled() && all)
    }

    /// `sync_file_merge` → `dma_fence_unwrap_merge(a, b)`
    /// (`drivers/dma-buf/dma-fence-unwrap.c::__dma_fence_unwrap_merge`):
    /// signalled leaves are dropped; none left is a private signalled stub
    /// stamped with the latest signal time; one left is that fence; more are
    /// sorted by context, de-duplicated to the latest fence per context
    /// (`dma_fence_dedup_array`), and wrapped in a new `dma_fence_array`
    /// unless only one survives. The new file takes `name`
    /// (`strscpy(user_name, name)`).
    fn merge(a: &Self, b: &Self, name: &[u8]) -> Self {
        let mut pending: Vec<&SyncPoint> = Vec::new();
        let mut timestamp = 0u64;
        for point in a.points.iter().chain(b.points.iter()) {
            if point.signalled() {
                timestamp = timestamp.max(point.timestamp_ns());
            } else {
                pending.push(point);
            }
        }
        let mut user_name = [0u8; 32];
        strscpy(&mut user_name, name);
        if pending.is_empty() {
            let mut file = Self::single(
                Arc::new(StubFence {
                    timestamp_ns: timestamp,
                }),
                PointKind::Stub,
            );
            file.user_name = user_name;
            return file;
        }
        // fence_cmp: ascending context, later seqno first within a context.
        pending.sort_by(|x, y| {
            let (xc, yc) = (x.fence.context().unwrap_or(0), y.fence.context().unwrap_or(0));
            xc.cmp(&yc).then(y.fence.seqno().cmp(&x.fence.seqno()))
        });
        let mut points: Vec<SyncPoint> = Vec::with_capacity(pending.len());
        for point in pending {
            let duplicate = points.last().is_some_and(|kept: &SyncPoint| {
                Arc::ptr_eq(&kept.fence, &point.fence)
                    || (kept.fence.context().is_some()
                        && kept.fence.context() == point.fence.context())
            });
            if !duplicate {
                points.push(point.fork());
            }
        }
        let array_context = (points.len() > 1).then(fence_context_alloc);
        Self {
            points,
            array_context,
            user_name,
        }
    }

    /// `sync_file_get_name`: the merge name if one was given, else
    /// `"%s-%s%llu-%lld"` of the file's fence (driver, timeline, context,
    /// seqno). `dma_fence_driver_name`/`_timeline_name` answer
    /// `"detached-driver"`/`"signaled-timeline"` once the fence signalled; a
    /// `dma_fence_array` is `"dma_fence_array"`/`"unbound"` with seqno 1.
    fn get_name(&self, buf: &mut [u8]) {
        if self.user_name[0] != 0 {
            strscpy(buf, &self.user_name);
            return;
        }
        let signalled = self.signalled();
        let (driver, timeline, context, seqno) = match self.array_context {
            Some(context) => ("dma_fence_array", "unbound", context, 1u64),
            None => {
                let fence = &self.points[0].fence;
                (
                    fence.driver_name(),
                    fence.timeline_name(),
                    fence.context().unwrap_or(0),
                    fence.seqno(),
                )
            }
        };
        let (driver, timeline) = if signalled {
            ("detached-driver", "signaled-timeline")
        } else {
            (driver, timeline)
        };
        let name = alloc::format!("{driver}-{timeline}{context}-{}", seqno as i64);
        strscpy(buf, name.as_bytes());
    }

    /// `sync_file_ioctl_merge`. The descriptor is reserved before anything
    /// is read, so a full table is -EMFILE ahead of every other error.
    fn ioctl_merge(
        &self,
        arg: u64,
        ctx: &dyn narf_filesystem::IoctlContext,
    ) -> Result<u64, narf_filesystem::FsError> {
        let task = current_task_id();
        let Some(reservation) = fd::reserve(task) else {
            return sync_neg(EMFILE);
        };
        let mut data = [0u8; SYNC_MERGE_DATA_SIZE];
        ctx.read(arg, &mut data)?;
        let flags = u32::from_ne_bytes(data[40..44].try_into().unwrap());
        let pad = u32::from_ne_bytes(data[44..48].try_into().unwrap());
        if flags != 0 || pad != 0 {
            return sync_neg(EINVAL);
        }
        let fd2 = i32::from_ne_bytes(data[32..36].try_into().unwrap());
        let other_ops = u32::try_from(fd2).ok().and_then(|fd2| {
            fd::with_table(task, |table| table.get(fd2).map(|entry| entry.ops.clone())).flatten()
        });
        let Some(other) = other_ops
            .as_ref()
            .and_then(|ops| ops.as_any())
            .and_then(|any| any.downcast_ref::<DrmSyncFile>())
        else {
            return sync_neg(ENOENT);
        };
        data[31] = 0;
        let merged = Self::merge(self, other, &data[..32]);
        data[36..40].copy_from_slice(&(reservation.fd() as i32).to_ne_bytes());
        ctx.write(arg, &data)?;
        reservation
            .install(fd::FdEntry {
                ops: Arc::new(merged),
                offset: 0,
                flags: fd::FD_CLOEXEC,
                status_flags: 0,
            })
            .ok_or(narf_filesystem::FsError::OutOfMemory)?;
        Ok(0)
    }

    /// `sync_file_ioctl_fence_info`: `num_fences == 0` asks only for the
    /// count and the overall status; otherwise the array at
    /// `sync_fence_info` must hold every leaf (-EINVAL if smaller), and
    /// `status` becomes the first non-positive leaf status, else 1.
    fn ioctl_fence_info(
        &self,
        arg: u64,
        ctx: &dyn narf_filesystem::IoctlContext,
    ) -> Result<u64, narf_filesystem::FsError> {
        let mut info = [0u8; SYNC_FILE_INFO_SIZE];
        ctx.read(arg, &mut info)?;
        let flags = u32::from_ne_bytes(info[36..40].try_into().unwrap());
        let pad = u32::from_ne_bytes(info[44..48].try_into().unwrap());
        if flags != 0 || pad != 0 {
            return sync_neg(EINVAL);
        }
        let num_fences = self.points.len() as u32;
        let requested = u32::from_ne_bytes(info[40..44].try_into().unwrap());
        let status: i32 = if requested == 0 {
            // dma_fence_get_status(sync_file->fence); NARF fences carry no
            // error, so it is 1 or 0.
            i32::from(self.signalled())
        } else {
            if requested < num_fences {
                return sync_neg(EINVAL);
            }
            let mut status = 1i32;
            let mut array = alloc::vec![0u8; self.points.len() * SYNC_FENCE_INFO_SIZE];
            for (point, entry) in self
                .points
                .iter()
                .zip(array.chunks_exact_mut(SYNC_FENCE_INFO_SIZE))
            {
                // sync_fill_fence_info.
                let signalled = point.signalled();
                let (timeline, driver) = if signalled {
                    ("signaled-timeline", "detached-driver")
                } else {
                    (point.fence.timeline_name(), point.fence.driver_name())
                };
                strscpy(&mut entry[0..32], timeline.as_bytes());
                strscpy(&mut entry[32..64], driver.as_bytes());
                let fence_status = i32::from(signalled);
                entry[64..68].copy_from_slice(&fence_status.to_ne_bytes());
                let timestamp = if signalled { point.timestamp_ns() } else { 0 };
                entry[72..80].copy_from_slice(&timestamp.to_ne_bytes());
                status = if status <= 0 { status } else { fence_status };
            }
            let user_array = u64::from_ne_bytes(info[48..56].try_into().unwrap());
            ctx.write(user_array, &array)?;
            status
        };
        self.get_name(&mut info[0..32]);
        info[32..36].copy_from_slice(&status.to_ne_bytes());
        info[40..44].copy_from_slice(&num_fences.to_ne_bytes());
        ctx.write(arg, &info)?;
        Ok(0)
    }

    /// `sync_file_ioctl_set_deadline`: `pad` must be zero; the deadline is
    /// a hint (`dma_fence_set_deadline` is a no-op for fences without a
    /// `set_deadline` op, which no NARF fence has).
    fn ioctl_set_deadline(
        &self,
        arg: u64,
        ctx: &dyn narf_filesystem::IoctlContext,
    ) -> Result<u64, narf_filesystem::FsError> {
        let mut deadline = [0u8; 16];
        ctx.read(arg, &mut deadline)?;
        if u64::from_ne_bytes(deadline[8..16].try_into().unwrap()) != 0 {
            return sync_neg(EINVAL);
        }
        Ok(0)
    }
}

impl narf_filesystem::FileOps for DrmSyncFile {
    /// Linux `sync_file_alloc` uses `anon_inode_getfile("sync_file")`: every such file shares the ONE `anon_inodefs` inode
    /// (`fs/anon_inodes.c::anon_inode_inode`), so all of them report the
    /// same `(st_dev, st_ino)`.
    fn ino(&self) -> u64 {
        narf_filesystem::inode_id::anon_inode().ino
    }

    fn inode_attrs(&self) -> narf_filesystem::InodeAttrs {
        narf_filesystem::inode_id::anon_inode().attrs()
    }

    fn read<'a>(
        &'a self,
        _offset: u64,
        _buf: &'a mut [u8],
    ) -> narf_filesystem::FsFuture<'a, usize> {
        Box::pin(async { Err(narf_filesystem::FsError::Unsupported) })
    }

    fn write<'a>(
        &'a self,
        _offset: u64,
        _buf: &'a [u8],
    ) -> narf_filesystem::FsFuture<'a, usize> {
        Box::pin(async { Err(narf_filesystem::FsError::Unsupported) })
    }

    fn stat(&self) -> narf_filesystem::Stat {
        narf_filesystem::Stat {
            size: 0,
            blocks: 0,
            mode: narf_filesystem::Mode {
                file_type: narf_filesystem::FileType::Special,
                perms: 0o600,
            },
            mtime_cycles: 0,
        }
    }

    /// `sync_file_ioctl`: MERGE, FILE_INFO and SET_DEADLINE; everything else
    /// is -ENOTTY, answered here rather than through the generic relay so an
    /// unknown command never touches its argument pointer.
    fn ioctl_user<'a>(
        &'a self,
        cmd: u32,
        arg: u64,
        context: &'a dyn narf_filesystem::IoctlContext,
    ) -> narf_filesystem::FsFuture<'a, u64> {
        Box::pin(async move {
            match cmd {
                SYNC_IOC_MERGE => self.ioctl_merge(arg, context),
                SYNC_IOC_FILE_INFO => self.ioctl_fence_info(arg, context),
                SYNC_IOC_SET_DEADLINE => self.ioctl_set_deadline(arg, context),
                _ => sync_neg(ENOTTY),
            }
        })
    }

    /// `sync_file_poll`: EPOLLIN once the file's fence (every leaf) signalled.
    fn poll_readiness(&self) -> u32 {
        if self.signalled() {
            narf_filesystem::POLL_IN
        } else {
            0
        }
    }

    /// The earliest instant an unsignalled leaf needs re-examining: a
    /// time-based leaf's signal time (`poll.rs::poll_nearest_deadline`
    /// clamps a parked poll to it, so a compositor sleeping on an atomic
    /// out-fence wakes at the vblank), or a 1 ms re-poll for a device leaf,
    /// whose completion has no interrupt waker yet and is reaped on the
    /// re-poll without busy-spinning.
    ///
    /// Once everything has signalled the file keeps publishing an (expired)
    /// deadline until poll observes the level: expiry between poll's
    /// readiness scan and this lookup would otherwise produce `None` and
    /// park the caller forever with no future edge to wake it. Only a file
    /// made solely of born-signalled stubs, which no scan can see pending,
    /// publishes none.
    fn poll_deadline(&self) -> Option<u64> {
        let now = narf_time::wall::monotonic_ns();
        let mut pending = None::<u64>;
        let mut settled = None::<u64>;
        for point in &self.points {
            let deadline = match point.kind {
                PointKind::Stub => continue,
                PointKind::Vblank(deadline) => deadline,
                PointKind::Device => now.saturating_add(1_000_000),
            };
            let slot = if point.signalled() {
                &mut settled
            } else {
                &mut pending
            };
            *slot = Some(slot.map_or(deadline, |current| current.min(deadline)));
        }
        pending.or(settled)
    }

    /// Parkable readiness source. Device-fence completion is discovered by
    /// the one-millisecond `poll_deadline` recheck above; time-based fences
    /// wake at their exact deadline.
    fn readiness_notifies(&self) -> bool {
        true
    }

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}

#[cfg(target_arch = "x86_64")]
mod tests {
    use super::*;
    use narf_filesystem::{DrmFence, FileOps};
    use narf_kernel_test::{kernel_test_in, TestResult};

    struct PendingFence;

    impl DrmFence for PendingFence {
        fn is_signalled(&self) -> bool {
            false
        }

        fn wait(&self, _timeout_ms: u64) -> bool {
            false
        }

        fn context(&self) -> Option<u64> {
            None
        }
    }

    fn smoke_drm_sync_file_poll_deadlines_close_lost_wake_races() -> TestResult {
        let device = DrmSyncFile::device(Arc::new(PendingFence));
        let before = narf_time::wall::monotonic_ns();
        let Some(repoll) = FileOps::poll_deadline(&device) else {
            return TestResult::Fail("device fence has no completion re-poll deadline");
        };
        if repoll < before.saturating_add(1_000_000) {
            return TestResult::Fail("device fence re-poll deadline is not in the future");
        }

        // An expired non-zero time fence must retain its deadline until the
        // readiness scan observes it. Returning None here strands a poll when
        // expiry races the scan-to-park window.
        let expired = DrmSyncFile::vblank(1);
        if FileOps::poll_deadline(&expired) != Some(1) {
            return TestResult::Fail("expired time fence stopped publishing its deadline");
        }

        let signalled = DrmSyncFile::signalled_stub();
        if FileOps::poll_deadline(&signalled).is_some() {
            return TestResult::Fail("pre-signalled time fence published a deadline");
        }

        // A multi-leaf file waits on its earliest pending leaf: the pending
        // vblank, not the already-expired one.
        let far = narf_time::wall::monotonic_ns().saturating_add(60_000_000_000);
        let mixed = DrmSyncFile::merge(&DrmSyncFile::vblank(far), &expired, &[0; 32]);
        if FileOps::poll_deadline(&mixed) != Some(far) {
            return TestResult::Fail("merged file did not publish its pending leaf deadline");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "syscall_abi",
        smoke_drm_sync_file_poll_deadlines_close_lost_wake_races
    );

    // __dma_fence_unwrap_merge drops signalled leaves, keeps one fence per
    // context (the later seqno), and only wraps survivors in a
    // dma_fence_array when more than one remains.
    fn smoke_drm_sync_file_merge_unwrap_rules() -> TestResult {
        struct Seq(u64, u64);
        impl DrmFence for Seq {
            fn is_signalled(&self) -> bool {
                false
            }
            fn wait(&self, _timeout_ms: u64) -> bool {
                false
            }
            fn context(&self) -> Option<u64> {
                Some(self.0)
            }
            fn seqno(&self) -> u64 {
                self.1
            }
        }
        let early = DrmSyncFile::device(Arc::new(Seq(7, 1)));
        let late = DrmSyncFile::device(Arc::new(Seq(7, 9)));
        let same = DrmSyncFile::merge(&early, &late, &[0; 32]);
        if same.points.len() != 1 || same.array_context.is_some() || same.points[0].fence.seqno() != 9
        {
            return TestResult::Fail("same-context merge must keep only the later fence");
        }
        let other = DrmSyncFile::device(Arc::new(Seq(3, 1)));
        let both = DrmSyncFile::merge(&late, &other, &[0; 32]);
        if both.points.len() != 2
            || both.array_context.is_none()
            || both.points[0].fence.context() != Some(3)
        {
            return TestResult::Fail("cross-context merge must be a context-sorted array");
        }
        let stub = DrmSyncFile::merge(&DrmSyncFile::vblank(2), &DrmSyncFile::vblank(1), &[0; 32]);
        if stub.points.len() != 1
            || stub.points[0].kind != PointKind::Stub
            || stub.points[0].timestamp_ns() != 2
        {
            return TestResult::Fail("all-signalled merge must be a stub at the latest timestamp");
        }
        TestResult::Pass
    }
    kernel_test_in!("syscall_abi", smoke_drm_sync_file_merge_unwrap_rules);
}

// `drivers/tty/pty.c::ptm_open_peer` ends in `FD_ADD`, which is
// `FD_PREPARE` + `fd_publish` over `get_unused_fd_flags`: a descriptor table
// at RLIMIT_NOFILE is -EMFILE (the shared `errno::EMFILE`). These arms only
// became reachable when the fd table started enforcing the limit, and the
// -EBADF they inherited blamed the caller's ioctl descriptor, which was
// perfectly valid.
pub(crate) fn sys_ioctl(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let cmd = args.arg1 as u32;
    let arg = args.arg2 as usize;
    let task = current_task_id();
    // Clone the Arc out of the fd table so we drop the table lock
    // before invoking the FileOps::ioctl body (which may take
    // device-internal locks of its own).
    let entry = fd::with_table(task, |t| {
        t.get(fd)
            .map(|e| (e.ops.clone(), t.status_flags(fd).unwrap_or(e.status_flags)))
    });
    let (ops, status_flags) = match entry {
        Some(Some(entry)) => entry,
        _ => {
            ctx.set_return(errno_ret(EBADF));
            return;
        }
    };
    if cmd == 0x541B {
        if let Some(fifo) = ops
            .as_any()
            .and_then(|any| any.downcast_ref::<narf_filesystem::fifo::FifoHandle>())
        {
            let bytes = (fifo.shared().unread_bytes() as i32).to_ne_bytes();
            // SAFETY: FIONREAD's output is one Linux int; the guarded copy
            // validates user memory and reports a protection fault as EFAULT.
            let result = unsafe { copy_to_user(arg as u64, &bytes) };
            ctx.set_return(if result.is_ok() {
                SyscallReturn::ok(0)
            } else {
                errno_ret(EFAULT)
            });
            return;
        }
    }
    // ── FIONBIO (0x5421) — generic O_NONBLOCK toggle ──────────────────
    //
    // `fs/ioctl.c::ioctl_fionbio`: read the `int` at `argp`; a non-zero value
    // sets O_NONBLOCK on the open file, zero clears it; return 0 (or EFAULT for
    // a bad pointer). Linux dispatches this in `do_vfs_ioctl` BEFORE reaching
    // `f_op->unlocked_ioctl`, so it works on any fd type — pipe, file, socket,
    // tty. Handled here for the same reason: it is a VFS flag toggle, not a
    // device op, and returning ENOTTY for it (the old default) broke every
    // Linux Rust binary — `std`'s `FileDesc::set_nonblocking` is
    // `ioctl(fd, FIONBIO, &on)`, so `Command::output()` (which sets its
    // stdout/stderr pipes non-blocking) panicked with "Inappropriate ioctl".
    const FIONBIO: u32 = 0x5421;
    if cmd == FIONBIO {
        let mut raw = [0u8; 4];
        // SAFETY: the UAPI argument is a single `int`; copy_from_user
        // range-validates the four bytes.
        if unsafe { copy_from_user(&mut raw, arg as u64) }.is_err() {
            ctx.set_return(errno_ret(EFAULT));
            return;
        }
        let on = i32::from_ne_bytes(raw) != 0;
        // Keep O_NONBLOCK in sync across the same three sinks F_SETFL updates
        // (see sys_fcntl `F_SETFL`): a socket's own nonblock flag, the mqueue
        // state, and the fd-table status flags F_GETFL reports.
        if let Some(sock) = current_socket(fd) {
            sock.set_nonblock(on);
        }
        crate::mqueue::set_fd_nonblock(task, fd, on);
        let _ = fd::with_table(task, |t| {
            if let Some(old) = t.status_flags(fd) {
                let new = if on {
                    old | crate::fd::O_NONBLOCK
                } else {
                    old & !crate::fd::O_NONBLOCK
                };
                let _ = t.set_status_flags(fd, new);
            }
        });
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    // ── nsfs (`fs/nsfs.c::ns_ioctl`) ──────────────────────────────────
    //
    // Handled here rather than behind `FileOps::ioctl` because four of
    // these mint a new fd, and the fd table belongs to this layer — the
    // same reason TIOCGPTPEER and DRM_IOCTL_PRIME_HANDLE_TO_FD are here.
    //
    // Gated on the fd actually being an ns-fd: the 0xb7 ioctl type is
    // nsfs's, but a caller aiming it at some other descriptor should get
    // that descriptor's answer, not a namespace error.
    #[cfg(feature = "container")]
    if super::handler_nsfs::is_nsfs_ioctl(cmd) {
        if let Some(held) = ops
            .as_any()
            .and_then(|a| a.downcast_ref::<crate::namespaces::NsFd>())
            .map(|nsfd| nsfd.held().clone())
        {
            let r = super::handler_nsfs::nsfs_ioctl(task, &held, cmd, arg);
            ctx.set_return(SyscallReturn::ok(r as u64));
            return;
        }
    }
    // ── FS_IOC_GETFLAGS / FS_IOC_SETFLAGS — `chattr`'s inode flags ────
    //
    // `fs/file_attr.c`. Handled here rather than in `FileOps::ioctl`
    // because the flags are a VFS concept the VFS enforces; a filesystem
    // only stores them.
    const FS_IOC_GETFLAGS: u32 = 0x8008_6601;
    const FS_IOC_SETFLAGS: u32 = 0x4008_6602;
    if cmd == FS_IOC_GETFLAGS {
        let flags = ops.inode_flags();
        // SAFETY: the UAPI argument is a single `int`; copy_to_user
        // range-validates the four bytes.
        if unsafe { copy_to_user(arg as u64, &flags.to_ne_bytes()) }.is_err() {
            ctx.set_return(errno_ret(EFAULT));
            return;
        }
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    if cmd == FS_IOC_SETFLAGS {
        let mut raw = [0u8; 4];
        // SAFETY: as above — a single `int` argument.
        if unsafe { copy_from_user(&mut raw, arg as u64) }.is_err() {
            ctx.set_return(errno_ret(EFAULT));
            return;
        }
        let requested = u32::from_ne_bytes(raw);
        let current = ops.inode_flags();
        // `fileattr_set_prepare`:
        //
        //     /*
        //      * The IMMUTABLE and APPEND_ONLY flags can only be changed by
        //      * the relevant capability.
        //      */
        //     if ((fa->flags ^ old_ma->flags) & (FS_APPEND_FL | FS_IMMUTABLE_FL) &&
        //         !capable(CAP_LINUX_IMMUTABLE))
        //             return -EPERM;
        //
        // Note it is the CHANGE that is privileged, not the value: a
        // caller may rewrite the word as long as these two bits keep the
        // value they already had.
        if (requested ^ current) & narf_filesystem::FS_PRIVILEGED_FL != 0
            && !capable(CAP_LINUX_IMMUTABLE)
        {
            ctx.set_return(errno_ret(EPERM));
            return;
        }
        // `vfs_fileattr_set` -> `may_fileattr_set` requires ownership:
        // "Verify that we are the owner or have CAP_FOWNER".
        let (uid, gid) = ops.owners();
        if !inode_owner_or_capable(task, uid, gid) {
            ctx.set_return(errno_ret(EPERM));
            return;
        }
        let result = match ops.set_inode_flags(requested) {
            Ok(()) => 0,
            // A filesystem that cannot store them must not pretend it
            // did: userspace would believe a file is immutable while
            // nothing enforces it. ENOTTY is what an unsupported ioctl
            // reports.
            Err(_) => -ENOTTY,
        };
        ctx.set_return(SyscallReturn::ok(result as u64));
        return;
    }

    // Btrfs snapshot ioctls embed a source directory fd in their 4096-byte
    // argument. Resolve that process-local fd here, then pass a stable DirOps
    // object through the VFS snapshot surface; filesystem drivers must never
    // reach into a caller's descriptor table.
    const BTRFS_IOC_SNAP_CREATE: u32 = 0x5000_9401;
    const BTRFS_IOC_SNAP_CREATE_V2: u32 = 0x5000_9417;
    const BTRFS_SUBVOL_RDONLY: u64 = 1 << 1;
    const BTRFS_SUBVOL_QGROUP_INHERIT: u64 = 1 << 2;
    if matches!(cmd, BTRFS_IOC_SNAP_CREATE | BTRFS_IOC_SNAP_CREATE_V2) {
        let mut input = [0u8; 4096];
        // SAFETY: both snapshot UAPIs are _IOW with an exact 4096-byte
        // argument; copy_from_user validates the complete range.
        if unsafe { copy_from_user(&mut input, arg as u64) }.is_err() {
            ctx.set_return(errno_ret(EFAULT));
            return;
        }
        let source_fd = i64::from_ne_bytes(input[0..8].try_into().unwrap());
        if source_fd < 0 || source_fd > i64::from(u32::MAX) {
            ctx.set_return(errno_ret(EBADF));
            return;
        }
        let (name_offset, readonly, quota) = if cmd == BTRFS_IOC_SNAP_CREATE_V2 {
            let flags = u64::from_ne_bytes(input[16..24].try_into().unwrap());
            if flags & !(BTRFS_SUBVOL_RDONLY | BTRFS_SUBVOL_QGROUP_INHERIT) != 0 {
                ctx.set_return(errno_ret(EINVAL));
                return;
            }
            let quota = if flags & BTRFS_SUBVOL_QGROUP_INHERIT != 0 {
                let inherit_size =
                    match usize::try_from(u64::from_ne_bytes(input[24..32].try_into().unwrap())) {
                        Ok(n) if (72..=4096).contains(&n) => n,
                        _ => {
                            ctx.set_return(errno_ret(EINVAL));
                            return;
                        }
                    };
                let inherit_ptr = u64::from_ne_bytes(input[32..40].try_into().unwrap());
                let mut payload = alloc::vec![0u8; inherit_size];
                // SAFETY: the UAPI size is page-bounded and copy_from_user
                // validates the separately pointed-to inheritance payload.
                if unsafe { copy_from_user(&mut payload, inherit_ptr) }.is_err() {
                    ctx.set_return(errno_ret(EFAULT));
                    return;
                }
                let inherit_flags = u64::from_ne_bytes(payload[0..8].try_into().unwrap());
                let count =
                    match usize::try_from(u64::from_ne_bytes(payload[8..16].try_into().unwrap())) {
                        Ok(count) => count,
                        Err(_) => {
                            ctx.set_return(errno_ret(EINVAL));
                            return;
                        }
                    };
                if inherit_flags & !1 != 0
                    || u64::from_ne_bytes(payload[16..24].try_into().unwrap()) != 0
                    || u64::from_ne_bytes(payload[24..32].try_into().unwrap()) != 0
                    || inherit_size != 72usize.saturating_add(count.saturating_mul(8))
                {
                    ctx.set_return(errno_ret(EINVAL));
                    return;
                }
                let mut limit = [0u64; 5];
                for (idx, value) in limit.iter_mut().enumerate() {
                    let off = 32 + idx * 8;
                    *value = u64::from_ne_bytes(payload[off..off + 8].try_into().unwrap());
                }
                if limit[0] & !0x3f != 0 {
                    ctx.set_return(errno_ret(EINVAL));
                    return;
                }
                let mut parents = alloc::vec::Vec::with_capacity(count);
                for idx in 0..count {
                    let off = 72 + idx * 8;
                    parents.push(u64::from_ne_bytes(
                        payload[off..off + 8].try_into().unwrap(),
                    ));
                }
                Some(narf_filesystem::FsQuotaInherit {
                    flags: inherit_flags,
                    parents,
                    limit,
                })
            } else {
                None
            };
            (56usize, flags & BTRFS_SUBVOL_RDONLY != 0, quota)
        } else {
            (8usize, false, None)
        };
        let raw_name = &input[name_offset..];
        let Some(end) = raw_name.iter().position(|&byte| byte == 0) else {
            ctx.set_return(errno_ret(EINVAL));
            return;
        };
        let Ok(name) = core::str::from_utf8(&raw_name[..end]) else {
            ctx.set_return(errno_ret(EINVAL));
            return;
        };
        let source = fd::with_table(task, |t| {
            t.get(source_fd as u32).and_then(|entry| entry.ops.as_dir())
        })
        .flatten();
        let Some(source) = source else {
            ctx.set_return(errno_ret(EBADF));
            return;
        };
        let Some(destination) = ops.as_dir() else {
            ctx.set_return(errno_ret(ENOTTY));
            return;
        };
        let result = match quota {
            Some(quota) => {
                poll_blocking(destination.snapshot_with_quota_async(source, name, readonly, quota))
            }
            None => poll_blocking(destination.snapshot_async(source, name, readonly)),
        };
        let rc = match result {
            Some(Ok(())) => 0,
            Some(Err(narf_filesystem::FsError::CrossDevice)) => -EXDEV,
            Some(Err(narf_filesystem::FsError::ReadOnly)) => -EROFS,
            Some(Err(narf_filesystem::FsError::Unsupported)) => -EOPNOTSUPP,
            Some(Err(narf_filesystem::FsError::NotFound)) => -ENOENT,
            Some(Err(narf_filesystem::FsError::QuotaExceeded)) => -EDQUOT,
            _ => -(EINVAL),
        };
        ctx.set_return(SyscallReturn::ok(rc as u64));
        return;
    }
    // FUSE_DEV_IOC_CLONE attaches this freshly opened `/dev/fuse` fd to
    // the connection named by the u32 source fd at `arg`. Linux implements
    // this in fs/fuse/dev.c because it must inspect and replace fd-private
    // state; keep the same split here rather than exposing fd tables to VFS.
    if cmd == narf_filesystem::fuse_conn::DevFuse::DEV_IOC_CLONE {
        let mut oldfd_bytes = [0u8; core::mem::size_of::<u32>()];
        // SAFETY: copy_from_user validates the user range and performs the
        // architecture's required user-access bracketing.
        if unsafe { copy_from_user(&mut oldfd_bytes, arg as u64) }.is_err() {
            ctx.set_return(errno_ret(EFAULT));
            return;
        }
        let oldfd = u32::from_ne_bytes(oldfd_bytes);
        let source = fd::with_table(task, |t| t.get(oldfd).map(|e| e.ops.clone())).flatten();
        let Some(source) = source else {
            ctx.set_return(errno_ret(EINVAL));
            return;
        };
        let cloned = match narf_filesystem::fuse_conn::DevFuse::clone_endpoint(&ops, &source) {
            Ok(cloned) => cloned,
            Err(_) => {
                ctx.set_return(errno_ret(EINVAL));
                return;
            }
        };
        let replaced = fd::with_table(task, |t| {
            let Some(entry) = t.get_mut(fd) else {
                return false;
            };
            entry.ops = cloned;
            let _ = entry;
            t.set_offset(fd, 0);
            true
        })
        .unwrap_or(false);
        ctx.set_return(SyscallReturn::ok(if replaced {
            0
        } else {
            (-EBADF) as u64
        }));
        return;
    }
    if cmd == narf_filesystem::fuse_conn::DevFuse::DEV_IOC_BACKING_OPEN {
        let Some(conn) = narf_filesystem::fuse_conn::DevFuse::connection_of(&ops) else {
            ctx.set_return(errno_ret(EINVAL));
            return;
        };
        let mut map = [0u8; 16];
        // SAFETY: copy_from_user validates and brackets the declared UAPI
        // `struct fuse_backing_map`.
        if unsafe { copy_from_user(&mut map, arg as u64) }.is_err() {
            ctx.set_return(errno_ret(EFAULT));
            return;
        }
        let backing_fd = i32::from_ne_bytes(map[0..4].try_into().unwrap());
        let flags = u32::from_ne_bytes(map[4..8].try_into().unwrap());
        let padding = u64::from_ne_bytes(map[8..16].try_into().unwrap());
        if backing_fd < 0 || flags != 0 || padding != 0 {
            ctx.set_return(errno_ret(EINVAL));
            return;
        }
        let backing =
            fd::with_table(task, |t| t.get(backing_fd as u32).map(|e| e.ops.clone())).flatten();
        let Some(backing) = backing else {
            ctx.set_return(errno_ret(EINVAL));
            return;
        };
        match conn.register_backing(backing) {
            Ok(id) => ctx.set_return(SyscallReturn::ok(id as u64)),
            Err(narf_filesystem::FsError::Unsupported) => {
                ctx.set_return(errno_ret(EOPNOTSUPP));
            }
            Err(_) => ctx.set_return(errno_ret(EINVAL)),
        }
        return;
    }
    if cmd == narf_filesystem::fuse_conn::DevFuse::DEV_IOC_BACKING_CLOSE {
        let Some(conn) = narf_filesystem::fuse_conn::DevFuse::connection_of(&ops) else {
            ctx.set_return(errno_ret(EINVAL));
            return;
        };
        let mut id_bytes = [0u8; core::mem::size_of::<u32>()];
        // SAFETY: copy_from_user validates and brackets the u32 argument.
        if unsafe { copy_from_user(&mut id_bytes, arg as u64) }.is_err() {
            ctx.set_return(errno_ret(EFAULT));
            return;
        }
        let id = i32::from_ne_bytes(id_bytes);
        match conn.unregister_backing(id) {
            Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
            Err(_) => ctx.set_return(errno_ret(EINVAL)),
        }
        return;
    }
    // PTY job-control ioctls need caller process state, fd access mode, PID
    // namespace translation, and Linux errno ordering. Keep that policy here;
    // the filesystem object owns only the shared raw tty control state.
    {
        use narf_filesystem::devfs_pty::{TIOCGPGRP, TIOCGSID, TIOCSCTTY, TIOCSPGRP};

        let master_id = ops.as_pty_master_id();
        let slave_id = ops
            .tty_id()
            .filter(|&id| id != crate::handlers::CTTY_CONSOLE);
        if let Some(pty_id) = master_id.or(slave_id) {
            match cmd {
                TIOCSCTTY => {
                    // O_PATH has no tty file_operations on Linux.
                    if status_flags & crate::fd::O_PATH != 0 {
                        ctx.set_return(errno_ret(EBADF));
                        return;
                    }
                    let readable = status_flags & crate::fd::O_ACCMODE != crate::fd::O_WRONLY;
                    let result = ops.tty_acquire_controlling(arg, readable);
                    let rc = match result {
                        Ok(true) => 0,
                        Ok(false) | Err(narf_filesystem::FsError::Unsupported) => -ENOTTY,
                        Err(narf_filesystem::FsError::OperationNotPermitted) => -EPERM,
                        Err(_) => -EINVAL,
                    };
                    ctx.set_return(SyscallReturn::ok(rc as u64));
                    return;
                }
                TIOCGPGRP | TIOCGSID => {
                    // Linux lets a PTY master query its slave control state,
                    // but a slave fd must be the caller's controlling tty.
                    if master_id.is_none() && task_ctty(task) != Some(pty_id) {
                        ctx.set_return(errno_ret(ENOTTY));
                        return;
                    }
                    let raw = if cmd == TIOCGPGRP {
                        ops.tty_fg_pgrp().unwrap_or(0)
                    } else {
                        match ops.tty_session() {
                            Some(0) | None => {
                                ctx.set_return(errno_ret(ENOTTY));
                                return;
                            }
                            Some(sid) => sid,
                        }
                    };
                    let visible = pgid_to_user(raw) as i32;
                    // SAFETY: copy_to_user validates the complete pid_t output
                    // after all ownership/session checks, matching Linux.
                    if unsafe { copy_to_user(arg as u64, &visible.to_ne_bytes()) }.is_err() {
                        ctx.set_return(errno_ret(EFAULT));
                    } else {
                        ctx.set_return(SyscallReturn::ok(0));
                    }
                    return;
                }
                TIOCSPGRP => {
                    let caller_sid = read_sid(process_state_key(task));
                    if task_ctty(task) != Some(pty_id)
                        || ops.tty_session() != Some(caller_sid)
                    {
                        ctx.set_return(errno_ret(ENOTTY));
                        return;
                    }
                    let mut raw_input = [0u8; core::mem::size_of::<i32>()];
                    // SAFETY: copy_from_user validates the complete pid_t
                    // after tty ownership, preserving Linux's errno order.
                    if unsafe { copy_from_user(&mut raw_input, arg as u64) }.is_err() {
                        ctx.set_return(errno_ret(EFAULT));
                        return;
                    }
                    let visible = i32::from_ne_bytes(raw_input);
                    if visible < 0 {
                        ctx.set_return(errno_ret(EINVAL));
                        return;
                    }
                    let pgrp = pgid_from_user(visible as u64);
                    let Some(group_sid) = (pgrp != 0).then(|| session_of_pgrp(pgrp)).flatten()
                    else {
                        ctx.set_return(errno_ret(ESRCH));
                        return;
                    };
                    if group_sid != caller_sid {
                        ctx.set_return(errno_ret(EPERM));
                        return;
                    }
                    if !ops.set_tty_fg_pgrp(pgrp) {
                        ctx.set_return(errno_ret(ENOTTY));
                    } else {
                        ctx.set_return(SyscallReturn::ok(0));
                    }
                    return;
                }
                _ => {}
            }
        }
    }

    // Wave-76 special-case: TIOCGPTPEER allocates a fresh slave fd in
    // the caller's table. The fd-allocation side lives here (not in the
    // filesystem crate), so we hijack the dispatch before delegating.
    if cmd == narf_filesystem::devfs_pty::TIOCGPTPEER {
        // `tty_ioctl` handles TIOCGPTPEER for every tty and `ptm_open_peer`
        // refuses anything but a pty master with EIO
        // (`if (tty->driver != ptm_driver) return -EIO;`). A file that is no
        // tty never reaches `tty_ioctl`: vfs_ioctl answers ENOTTY.
        let idx = match ops.as_pty_master_id() {
            Some(i) => i,
            None => {
                let errno = if ops.tty_id().is_some() { EIO } else { ENOTTY };
                ctx.set_return(errno_ret(errno));
                return;
            }
        };
        let slave = match narf_filesystem::devfs_pty::pts_open_peer(idx) {
            Some(Ok(s)) => s,
            Some(Err(())) => {
                // EIO: slave still locked.
                ctx.set_return(errno_ret(EIO));
                return;
            }
            None => {
                ctx.set_return(errno_ret(ENOTTY));
                return;
            }
        };
        let ops_dyn: Arc<dyn narf_filesystem::FileOps> = slave;
        // `FD_ADD(flags, dentry_open(slave, flags))`: O_CLOEXEC becomes the
        // new descriptor's FD_CLOEXEC, and the open file description keeps
        // the access mode and the F_SETFL bits (O_NONBLOCK, O_APPEND, ...)
        // exactly as open(2) would — `do_dentry_open` drops O_CREAT/O_EXCL/
        // O_NOCTTY/O_TRUNC, and O_CLOEXEC is not a file status flag.
        let open_flags = arg as u32;
        let new_fd = fd::install(task, fd::FdEntry {
                ops: ops_dyn,
                offset: 0,
                flags: if open_flags & fd::O_CLOEXEC != 0 { fd::FD_CLOEXEC } else { 0 },
                status_flags: open_flags & (fd::O_ACCMODE | fd::O_SETFL_MASK),
            });
        match new_fd {
            Some(f) => ctx.set_return(SyscallReturn::ok(f as u64)),
            None => ctx.set_return(errno_ret(EMFILE)),
        }
        return;
    }
    // DRM_IOCTL_PRIME_HANDLE_TO_FD (_IOWR('d'=0x64, 0x2d, drm_prime_handle)):
    // export a GEM handle on a DRM card as a fresh mmap-able dma-buf fd. Like
    // TIOCGPTPEER, the fd-allocation side must live HERE (the syscall layer
    // owns the fd table); the gpu driver only supplies the buffer FileOps via
    // the registered PRIME hook. Mesa GBM's gbm_bo_get_fd relies on this to
    // CPU-mmap the kwin QPainter swapchain buffer — without it kwin logged
    // "drmPrimeHandleToFD() failed: Not a tty" and could not render.
    if (cmd & 0xFF) == 0x2d && ((cmd >> 8) & 0xFF) == 0x64 {
        // Export works from a card node OR a render node (a render node reports
        // the card index it renders for); `drm_prime_export` keys on that index
        // either way. Mesa may export from either fd it holds.
        if let Some(card_idx) = ops.as_drm_card_index().or_else(|| ops.as_drm_render_index()) {
            // struct drm_prime_handle { u32 handle; u32 flags; s32 fd; }
            let handle = read_user_u32(arg as u64);
            // UAPI drm.h aliases DRM_CLOEXEC to O_CLOEXEC (0x80000) and
            // DRM_RDWR to O_RDWR (0x2); they are open(2) flags, not compact
            // DRM-private bits.
            let prime_flags = read_user_u32(arg as u64 + 4);
            // Linux validates flags before looking up the GEM handle.
            const DRM_CLOEXEC: u32 = 0x80000;
            const DRM_RDWR: u32 = 0x2;
            if prime_flags & !(DRM_CLOEXEC | DRM_RDWR) != 0 {
                ctx.set_return(errno_ret(EINVAL));
                return;
            }
            let dmabuf = match ops.drm_prime_export_file(handle) {
                Ok(file) => file,
                // Non-VirtIO cards and dumb buffers retain the legacy
                // card-global export hook.
                Err(narf_filesystem::FsError::Unsupported) => {
                    match narf_filesystem::drm_prime_export(card_idx, handle) {
                        Some(file) => file,
                        None => {
                            ctx.set_return(errno_ret(ENOENT));
                            return;
                        }
                    }
                }
                Err(narf_filesystem::FsError::NotFound) => {
                    ctx.set_return(errno_ret(ENOENT));
                    return;
                }
                Err(narf_filesystem::FsError::OutOfMemory) => {
                    ctx.set_return(errno_ret(ENOMEM));
                    return;
                }
                Err(_) => {
                    ctx.set_return(errno_ret(EINVAL));
                    return;
                }
            };
            let new_fd = fd::install(task, fd::FdEntry {
                    ops: dmabuf,
                    offset: 0,
                    flags: if prime_flags & DRM_CLOEXEC != 0 { 1 } else { 0 },
                    status_flags: 0,
                });
            match new_fd {
                Some(f) => {
                    write_user_u32(arg as u64 + 8, f); // drm_prime_handle.fd
                    ctx.set_return(SyscallReturn::ok(0));
                }
                None => ctx.set_return(errno_ret(EMFILE)),
            }
            return;
        }
    }
    // DRM_IOCTL_PRIME_FD_TO_HANDLE (_IOWR('d'=0x64, 0x2e, drm_prime_handle)):
    // re-import a PRIME dma-buf fd back to a GEM handle on this card — the
    // partner of HANDLE_TO_FD. A compositor exports its render buffer, then
    // imports it to build a scannable KMS framebuffer. Without it kwin logged
    // "drmPrimeFDToHandle() failed" → "Failed to create dumb framebuffer" →
    // "Applying output config failed!".
    //
    // The gate accepts EITHER a card node OR a render node: Mesa opens the
    // RENDER node (renderD128) for its GBM/EGL context and imports the
    // compositor's scanout dma-buf THERE, not on the card node. Gating this on
    // `as_drm_card_index()` alone (a card-only check) made the render-node
    // import fall through to the driver dispatch → -EOPNOTSUPP →
    // `eglCreateImageKHR(EGL_LINUX_DMA_BUF_EXT)` = EGL_BAD_ALLOC → kwin never
    // reached OpenGL compositing / modeset (the CachyOS greeter stayed black).
    // The import body itself is node-independent — it only resolves the
    // dma-buf's `as_prime_gem_handle`, never the DRM index — so accepting the
    // render node here is sufficient.
    if (cmd & 0xFF) == 0x2e
        && ((cmd >> 8) & 0xFF) == 0x64
        && (ops.as_drm_card_index().is_some() || ops.as_drm_render_index().is_some())
    {
        // struct drm_prime_handle { u32 handle; u32 flags; s32 fd; }
        let dmabuf_fd = read_user_u32(arg as u64 + 8);
        let Some(buf_ops) =
            fd::with_table(task, |t| t.get(dmabuf_fd).map(|e| e.ops.clone())).flatten()
        else {
            // dma_buf_get() returns EBADF when the descriptor is not open.
            ctx.set_return(errno_ret(EBADF));
            return;
        };
        let imported = match ops.drm_prime_import_file(&buf_ops) {
            Ok(handle) => Ok(handle),
            Err(narf_filesystem::FsError::Unsupported) => {
                buf_ops.as_prime_gem_handle().ok_or(())
            }
            Err(narf_filesystem::FsError::OutOfMemory) => {
                ctx.set_return(errno_ret(ENOMEM));
                return;
            }
            Err(_) => Err(()),
        };
        match imported {
            Ok(h) => {
                write_user_u32(arg as u64, h); // drm_prime_handle.handle
                ctx.set_return(SyscallReturn::ok(0));
            }
            Err(()) => {
                ctx.set_return(errno_ret(EINVAL));
            }
        }
        return;
    }
    // PIDFD_GET_*_NAMESPACE (_IO(0xFF, 1..=10)): mint an fd on the pidfd
    // target's namespace of the requested flavour (Linux 6.13 pidfs
    // ioctls; `fs/pidfs.c::pidfd_ioctl`). systemd 258's
    // `pidref_namespace_open_by_type()` tries this FIRST; on ENOTTY it
    // falls back to opening `/proc/<pid>/ns/<flavour>`, and when THAT
    // ENOENTs with /proc mounted it maps the miss to -ENOPKG — an errno
    // its callers treat as a hard error. Concretely: the service
    // executor's `is_idmapping_supported()` probe (setup_exec_directory,
    // RuntimeDirectory=) calls `userns_acquire()` → this ioctl; without
    // it every service with RuntimeDirectory= exits 233/RUNTIME_DIRECTORY
    // ("journald/logind/udevd failed with result 'exit-code'"). The fd
    // returned here is a real `NsFd`, so a later `setns(2)` on it works
    // (sys_setns downcasts via as_any).
    #[cfg(feature = "container")]
    if (0xff01..=0xff0a).contains(&cmd) {
        if let Some(target) = ops.pidfd_target_pid() {
            use crate::namespaces::NsFlavour;
            let flavour = match cmd & 0xFF {
                1 => Some(NsFlavour::Cgroup),
                2 => Some(NsFlavour::Ipc),
                3 => Some(NsFlavour::Mnt),
                4 => Some(NsFlavour::Net),
                // 5 = PID ns, 6 = PID-for-children: NARF tracks one
                // per-task pid-ns, serve it for both.
                5 | 6 => Some(NsFlavour::Pid),
                9 => Some(NsFlavour::User),
                10 => Some(NsFlavour::Uts),
                // 7/8 = time namespaces — not modelled; fall through to
                // the generic ENOTTY arm below (Linux pre-6.13 shape).
                _ => None,
            };
            let target_task = pid_to_task_raw(target).unwrap_or(target);
            if let Some(nsfd) = flavour.and_then(|f| namespace_fd_for_task(target_task, f)) {
                let ops_dyn: Arc<dyn narf_filesystem::FileOps> = nsfd;
                // Linux mints these O_CLOEXEC (pidfs open_namespace).
                let new_fd = fd::install(task, fd::FdEntry {
                        ops: ops_dyn,
                        offset: 0,
                        flags: crate::fd::FD_CLOEXEC,
                        status_flags: 0,
                    });
                match new_fd {
                    Some(f) => ctx.set_return(SyscallReturn::ok(f as u64)),
                    None => ctx.set_return(errno_ret(EMFILE)),
                }
                return;
            }
        }
        // Not a pidfd / unmodelled flavour: fall through → generic
        // ENOTTY, which systemd tolerates (pre-pidfs kernel shape).
    }
    // PIDFD_GET_INFO (_IOWR(0xFF, 11, struct pidfd_info)): resolve a pidfd
    // to its target's pid/creds. systemd 258's `pidfd_get_pid()` tries this
    // ioctl FIRST (kernel 6.13+ path) after `pidfd_spawn`, to turn the
    // clone3-minted pidfd into a PidRef; on failure it falls back to parsing
    // `/proc/self/fdinfo/<n>` (which NARF doesn't render a "Pid:" line for).
    // Matched on magic+nr+direction with ANY size so binaries built against
    // older/newer uapi headers (the size is baked into the cmd) all land here.
    // Linux ref: `fs/pidfs.c::pidfd_info` + `include/uapi/linux/pidfd.h`.
    if (cmd & 0xFF) == 11 && ((cmd >> 8) & 0xFF) == 0xFF && (cmd >> 30) == 0x3 {
        if let Some(target) = ops.pidfd_target_pid() {
            let user_size = ((cmd >> 16) & 0x3FFF) as usize;
            const PIDFD_INFO_SIZE_VER0: usize = 64;
            if user_size < PIDFD_INFO_SIZE_VER0 {
                ctx.set_return(errno_ret(EINVAL));
                return;
            }
            const PIDFD_INFO_PID: u64 = 1 << 0;
            const PIDFD_INFO_CREDS: u64 = 1 << 1;
            // struct pidfd_info (uapi VER2, 80 bytes): mask@0 cgroupid@8
            // pid@16 tgid@20 ppid@24 ruid@28 rgid@32 euid@36 egid@40
            // suid@44 sgid@48 fsuid@52 fsgid@56 exit_code@60
            // coredump_mask@64 coredump_signal@68 supported_mask@72.
            let mut info = [0u8; 80];
            info[0..8].copy_from_slice(&(PIDFD_INFO_PID | PIDFD_INFO_CREDS).to_ne_bytes());
            // Report pid/tgid/ppid in the CALLER's PID namespace view (the
            // process issuing the ioctl) — `target` and the parent are outer
            // ProcessIds. Identity in the root namespace.
            let caller = current_task_id();
            let pid32 = report_pid_to(caller, target) as u32;
            info[16..20].copy_from_slice(&pid32.to_ne_bytes()); // pid
            info[20..24].copy_from_slice(&pid32.to_ne_bytes()); // tgid
            let ppid = parent_of_get(target)
                .map(|p| report_pid_to(caller, task_to_pid_raw(p).unwrap_or(p)) as u32)
                .unwrap_or(0);
            info[24..28].copy_from_slice(&ppid.to_ne_bytes());
            let cred_task = pid_to_task_raw(target).unwrap_or(target);
            let ug = read_uidgid(cred_task);
            info[28..32].copy_from_slice(&ug.uid.to_ne_bytes()); // ruid
            info[32..36].copy_from_slice(&ug.gid.to_ne_bytes()); // rgid
            info[36..40].copy_from_slice(&ug.euid.to_ne_bytes()); // euid
            info[40..44].copy_from_slice(&ug.egid.to_ne_bytes()); // egid
            info[44..48].copy_from_slice(&ug.euid.to_ne_bytes()); // suid (= euid)
            info[48..52].copy_from_slice(&ug.egid.to_ne_bytes()); // sgid (= egid)
            info[52..56].copy_from_slice(&ug.fsuid.to_ne_bytes());
            info[56..60].copy_from_slice(&ug.fsgid.to_ne_bytes());
            let n = core::cmp::min(user_size, info.len());
            // SAFETY: `arg` is the user struct pointer for an _IOWR ioctl;
            // copy_to_user range-validates and SMAP-brackets the write of
            // min(user-declared size, our struct) bytes.
            // SAFETY: Valid memory or trusted environment
            if unsafe { copy_to_user(arg as u64, &info[..n]) }.is_err() {
                ctx.set_return(errno_ret(EINVAL));
                return;
            }
            ctx.set_return(SyscallReturn::ok(0));
            return;
        }
        // Not a pidfd: fall through — Linux returns ENOTTY via the
        // default file_operations dispatch, which the generic arm below
        // reproduces (FsError::Unsupported → ENOTTY).
    }
    // `virtio_gpu_execbuffer_ioctl()` creates an optional sync_file, while fd
    // allocation belongs to the syscall layer in NARF.  Reserve the output fd
    // before submitting, matching Linux's get_unused_fd_flags(O_CLOEXEC): an
    // exhausted descriptor table returns EMFILE and no GPU work is queued.
    const DRM_IOCTL_VIRTGPU_EXECBUFFER: u32 = 0xc040_6442;
    const VIRTGPU_EXECBUF_FENCE_FD_IN: u32 = 0x01;
    const VIRTGPU_EXECBUF_FENCE_FD_OUT: u32 = 0x02;
    const VIRTGPU_EXECBUF_RING_IDX: u32 = 0x04;
    let is_virtgpu_execbuffer = cmd == DRM_IOCTL_VIRTGPU_EXECBUFFER
        && (ops.as_drm_card_index().is_some() || ops.as_drm_render_index().is_some());
    let mut out_fence = None;
    if is_virtgpu_execbuffer {
        let mut execbuf = [0u8; 64];
        // SAFETY: the ioctl encoding fixes the payload at 64 bytes and the
        // uaccess helper validates that complete input range.
        if unsafe { copy_from_user(&mut execbuf, arg as u64) }.is_err() {
            ctx.set_return(errno_ret(EFAULT));
            return;
        }
        let flags = u32::from_ne_bytes(execbuf[0..4].try_into().unwrap());
        let known_flags = VIRTGPU_EXECBUF_FENCE_FD_IN
            | VIRTGPU_EXECBUF_FENCE_FD_OUT
            | VIRTGPU_EXECBUF_RING_IDX;
        if flags & !known_flags != 0 {
            ctx.set_return(errno_ret(EINVAL));
            return;
        }
        if flags & VIRTGPU_EXECBUF_FENCE_FD_OUT != 0 {
            let Some(reservation) = fd::reserve(task) else {
                ctx.set_return(errno_ret(EMFILE));
                return;
            };
            out_fence = Some(reservation);
        }
        if flags & VIRTGPU_EXECBUF_FENCE_FD_IN != 0 {
            let in_fence = i32::from_ne_bytes(execbuf[28..32].try_into().unwrap());
            let Some(leaves) = sync_file_leaves(task, in_fence) else {
                // Linux's sync_file_get_fence() deliberately folds both a bad
                // fd and a non-sync-file fd into EINVAL for this ioctl.
                ctx.set_return(errno_ret(EINVAL));
                return;
            };
            let ring_idx = if flags & VIRTGPU_EXECBUF_RING_IDX != 0 {
                u32::from_ne_bytes(execbuf[32..36].try_into().unwrap())
            } else {
                0
            };
            let submission_context = ops.drm_execbuf_context(ring_idx);
            // A merged sync_file is a dma_fence_array: the dependency is
            // every leaf.
            let signalled = leaves.iter().all(|fence| {
                if fence.context().is_some() && fence.context() == submission_context {
                    // This ring is ordered: queueing the later EXECBUFFER
                    // carries the dependency without serializing the async
                    // pipeline.
                    true
                } else {
                    fence.wait(15_000)
                }
            });
            if !signalled {
                // Bound a wedged/foreign GPU wait so an ioctl cannot hang the
                // kernel indefinitely. This matches VIRTGPU_WAIT's busy
                // timeout policy in the driver bridge.
                ctx.set_return(errno_ret(EBUSY));
                return;
            }
        }
    }

    let ioctl_context = DeviceIoctlContext {
        nonblocking: status_flags & crate::fd::O_NONBLOCK != 0,
    };
    let ioctl_result = poll_blocking(ops.ioctl_user(cmd, arg as u64, &ioctl_context))
        .unwrap_or(Err(narf_filesystem::FsError::WouldBlock));
    if ioctl_result.is_ok() {
        // Atomic OUT_FENCE_PTR: the DRM bridge recorded one (user pointer,
        // vblank deadline) pair per requesting CRTC; mint the sync_file fds
        // here and write them through the pointers, in commit order. Linux
        // pre-allocates the fds before committing; NARF's commit has already
        // applied by this point, so descriptor exhaustion surfaces as EMFILE
        // with the commit in effect — the fence request, not the commit, is
        // what fails (document over pre-scan: the ioctl arrays would need a
        // second full decode up here to reserve ahead of dispatch).
        const DRM_IOCTL_MODE_ATOMIC: u32 = 0xc038_64bc;
        if cmd == DRM_IOCTL_MODE_ATOMIC {
            for (user_ptr, deadline_ns) in ops.drm_take_out_fences() {
                let Some(reservation) = fd::reserve(task) else {
                    ctx.set_return(errno_ret(EMFILE));
                    return;
                };
                let fence_fd = reservation
                    .install(fd::FdEntry {
                        ops: Arc::new(DrmSyncFile::vblank(deadline_ns)),
                        offset: 0,
                        flags: fd::FD_CLOEXEC,
                        status_flags: 0,
                    })
                    .expect("reserved atomic out-fence fd disappeared");
                let fence_bytes = (fence_fd as i32).to_ne_bytes();
                // SAFETY: `user_ptr` is the OUT_FENCE_PTR property value the
                // caller provided — an `s32*` in its own address space; the
                // uaccess helper validates the 4-byte destination range.
                if unsafe { copy_to_user(user_ptr, &fence_bytes) }.is_err() {
                    ctx.set_return(errno_ret(EFAULT));
                    return;
                }
            }
        }
        if let Some(reservation) = out_fence {
            // Back the sync_file with the EXECBUFFER's device fence when the
            // driver produced one; a driver without fenced submission keeps
            // the pre-signalled fallback (the stub fence).
            let file = match ops.drm_execbuf_fence() {
                Some(fence) => DrmSyncFile::device(fence),
                None => DrmSyncFile::signalled_stub(),
            };
            let fence_fd = reservation
                .install(fd::FdEntry {
                    ops: Arc::new(file),
                    offset: 0,
                    flags: fd::FD_CLOEXEC,
                    status_flags: 0,
                })
                .expect("reserved VirtIO-GPU fence fd disappeared");
            // Linux installs the sync_file before drm_ioctl_kernel copies the
            // modified struct back.  Preserve that order (including the
            // installed-but-unreported fd if this final copy faults).
            let fence_bytes = (fence_fd as i32).to_ne_bytes();
            // SAFETY: fence_fd is the 32-bit field at byte offset 28 in the
            // already-validated 64-byte EXECBUFFER payload.
            if unsafe { copy_to_user(arg as u64 + 28, &fence_bytes) }.is_err() {
                ctx.set_return(errno_ret(EFAULT));
                return;
            }
        }
    }

    match ioctl_result {
        Ok(rc) => ctx.set_return(SyscallReturn::ok(rc)),
        Err(narf_filesystem::FsError::Unsupported) => {
            // Recognised DRM feature ioctls use EOPNOTSUPP when the driver
            // lacks the advertised feature. They must not fall through to
            // the generic unknown-ioctl ENOTTY translation.
            const DRM_IOCTL_SET_CLIENT_CAP: u32 = 0x4010_640d;
            const DRM_IOCTL_MODE_ATOMIC: u32 = 0xc038_64bc;
            // SIOCETHTOOL: a command the device's driver does not implement
            // is `__dev_ethtool`'s -EOPNOTSUPP, not an unknown ioctl.
            const SIOCETHTOOL: u32 = 0x8946;
            if cmd == DRM_IOCTL_SET_CLIENT_CAP || cmd == DRM_IOCTL_MODE_ATOMIC || cmd == SIOCETHTOOL
            {
                ctx.set_return(errno_ret(EOPNOTSUPP));
                return;
            }
            if ops.inotify_instance().is_some() {
                // `inotify_ioctl` handles its small command set directly and
                // returns ENOTTY for every other request, irrespective of
                // that request's `_IOC` direction/size bits. Do this before
                // the generic filesystem ioctl relay: decoding an arbitrary
                // unknown request there can instead fault its invented input
                // buffer and incorrectly turn ENOTTY into EINVAL/EFAULT.
                ctx.set_return(errno_ret(ENOTTY));
                return;
            }
            if ops.stat().mode.file_type == narf_filesystem::FileType::Fifo {
                // pipe_ioctl's -ENOIOCTLCMD is translated by vfs_ioctl to
                // ENOTTY. Do this before the generic filesystem-ioctl relay:
                // an arbitrary command's encoded direction must not make a
                // pipe ioctl touch its otherwise-ignored argument pointer.
                ctx.set_return(errno_ret(ENOTTY));
                return;
            }
            // Linux restricted FUSE ioctls derive their transfer buffers
            // solely from the command's _IOC direction and size fields.
            const IOC_WRITE: u32 = 1;
            const IOC_READ: u32 = 2;
            let dir = cmd >> 30;
            let size = ((cmd >> 16) & 0x3fff) as usize;
            let mut input = alloc::vec::Vec::new();
            if dir & IOC_WRITE != 0 && size != 0 {
                input.resize(size, 0);
                // SAFETY: the encoded ioctl input size bounds the copy and
                // copy_from_user validates the entire user range.
                if unsafe { copy_from_user(&mut input, arg as u64) }.is_err() {
                    ctx.set_return(errno_ret(EFAULT));
                    return;
                }
            }
            // Linux historically encoded QGROUP_LIMIT as `_IOR` even though
            // its 48-byte argument is input. Preserve that ABI quirk while
            // still keeping user-pointer access in the syscall layer.
            const BTRFS_IOC_QGROUP_LIMIT: u32 = 0x8030_942b;
            if cmd == BTRFS_IOC_QGROUP_LIMIT && input.is_empty() {
                input.resize(48, 0);
                // SAFETY: the fixed UAPI structure is 48 bytes and
                // copy_from_user validates the whole pointed-to range.
                if unsafe { copy_from_user(&mut input, arg as u64) }.is_err() {
                    ctx.set_return(errno_ret(EFAULT));
                    return;
                }
            }
            // `btrfs_ioctl_vol_args_v2` carries qgroup inheritance through a
            // second userspace pointer. Flatten that bounded payload after the
            // 4096-byte ioctl struct so the filesystem driver never
            // dereferences process memory itself.
            const BTRFS_IOC_SUBVOL_CREATE_V2: u32 = 0x5000_9418;
            const BTRFS_SUBVOL_QGROUP_INHERIT: u64 = 1 << 2;
            if cmd == BTRFS_IOC_SUBVOL_CREATE_V2
                && input.len() == 4096
                && u64::from_ne_bytes(input[16..24].try_into().unwrap())
                    & BTRFS_SUBVOL_QGROUP_INHERIT
                    != 0
            {
                let inherit_size =
                    match usize::try_from(u64::from_ne_bytes(input[24..32].try_into().unwrap())) {
                        Ok(n) if (72..=4096).contains(&n) => n,
                        _ => {
                            ctx.set_return(errno_ret(EINVAL));
                            return;
                        }
                    };
                let inherit_ptr = u64::from_ne_bytes(input[32..40].try_into().unwrap());
                let old_len = input.len();
                input.resize(old_len + inherit_size, 0);
                // SAFETY: the UAPI size is capped at one page and
                // copy_from_user validates the complete pointed-to range.
                if unsafe { copy_from_user(&mut input[old_len..], inherit_ptr) }.is_err() {
                    ctx.set_return(errno_ret(EFAULT));
                    return;
                }
            }
            let out_size = if dir & IOC_READ != 0 { size } else { 0 };
            // btrfs opens every quota and qgroup ioctl with
            //
            //     if (!capable(CAP_SYS_ADMIN))
            //             return -EPERM;
            //
            // (`fs/btrfs/ioctl.c`, all seven of them). The check has to live
            // here rather than in the driver: `FsOps::ioctl_async` carries no
            // credential, by design — the filesystem layer never inspects the
            // calling process — so the syscall boundary is the only place the
            // caller's capabilities are still in scope.
            //
            // `task_capable` is host-scoped, which is what `capable()` means:
            // `ns_capable(&init_user_ns, cap)`. A container root holding
            // CAP_SYS_ADMIN only in its own user namespace does NOT get to
            // reconfigure the host's quotas, and unprivileged callers got to
            // set qgroup limits until this existed.
            const BTRFS_QUOTA_IOCTLS: [u32; 7] = [
                0xc010_9428, // QUOTA_CTL
                0x4018_9429, // QGROUP_ASSIGN
                0x4010_942a, // QGROUP_CREATE
                0x8030_942b, // QGROUP_LIMIT
                0x4040_942c, // QUOTA_RESCAN
                0x8040_942d, // QUOTA_RESCAN_STATUS
                0x0000_942e, // QUOTA_RESCAN_WAIT
            ];
            if BTRFS_QUOTA_IOCTLS.contains(&cmd) && !task_capable(task, CAP_SYS_ADMIN) {
                ctx.set_return(errno_ret(EPERM));
                return;
            }
            match poll_blocking(ops.ioctl_async(cmd, arg as u64, &input, out_size)) {
                Some(Ok(reply)) => {
                    if !reply.output.is_empty() {
                        // SAFETY: output length was bounded by _IOC_SIZE in
                        // the filesystem layer; copy_to_user validates arg.
                        if unsafe { copy_to_user(arg as u64, &reply.output) }.is_err() {
                            ctx.set_return(errno_ret(EFAULT));
                            return;
                        }
                    }
                    ctx.set_return(SyscallReturn::ok((reply.result as i64) as u64));
                }
                Some(Err(narf_filesystem::FsError::Unsupported)) => {
                    ctx.set_return(errno_ret(ENOTTY));
                }
                Some(Err(narf_filesystem::FsError::PermissionDenied)) => {
                    ctx.set_return(errno_ret(EACCES));
                }
                Some(Err(narf_filesystem::FsError::Busy)) => {
                    let errno = match cmd {
                        0x5000_940f | 0x5000_943f => -ENOTEMPTY,
                        0x4010_942a => -EEXIST,
                        _ => -EBUSY,
                    };
                    ctx.set_return(SyscallReturn::ok(errno as u64));
                }
                Some(Err(narf_filesystem::FsError::NotFound)) => {
                    ctx.set_return(errno_ret(ENOENT));
                }
                Some(Err(narf_filesystem::FsError::NoSpace)) => {
                    ctx.set_return(errno_ret(ENOSPC));
                }
                Some(Err(narf_filesystem::FsError::ReadOnly)) => {
                    ctx.set_return(errno_ret(EROFS));
                }
                Some(Err(narf_filesystem::FsError::QuotaExceeded)) => {
                    ctx.set_return(errno_ret(EDQUOT));
                }
                Some(Err(narf_filesystem::FsError::NotConnected)) => {
                    // ENOTCONN. btrfs answers every qgroup ioctl this way when
                    // quotas are off, rather than ENOENT, so `btrfs qgroup
                    // show` can say "quotas are not enabled" instead of
                    // reporting a missing qgroup.
                    ctx.set_return(errno_ret(ENOTCONN));
                }
                _ => ctx.set_return(errno_ret(EINVAL)),
            }
        }
        Err(narf_filesystem::FsError::PermissionDenied) => {
            // EACCES = 13
            ctx.set_return(errno_ret(EACCES));
        }
        Err(narf_filesystem::FsError::NoSuchProcess) => {
            // ESRCH — TIOCSPGRP for a process group that does not exist.
            ctx.set_return(errno_ret(ESRCH));
        }
        Err(narf_filesystem::FsError::BadAddress) => {
            ctx.set_return(errno_ret(EFAULT));
        }
        Err(narf_filesystem::FsError::BrokenPipe | narf_filesystem::FsError::StreamXrun) => ctx.set_return(errno_ret(EPIPE)),
        Err(narf_filesystem::FsError::NoDevice) => ctx.set_return(errno_ret(ENODEV)),
        Err(narf_filesystem::FsError::BadFileState) => ctx.set_return(errno_ret(77)),
        Err(narf_filesystem::FsError::StreamSuspended) => ctx.set_return(errno_ret(86)),
        Err(narf_filesystem::FsError::NoSpace) => ctx.set_return(errno_ret(28)),
        Err(narf_filesystem::FsError::NoDeviceAddress) => ctx.set_return(errno_ret(6)),
        Err(narf_filesystem::FsError::OutOfMemory) => {
            ctx.set_return(errno_ret(ENOMEM));
        }
        Err(narf_filesystem::FsError::NotImplemented) => {
            ctx.set_return(errno_ret(ENOSYS));
        }
        Err(narf_filesystem::FsError::AlreadyExists) => {
            ctx.set_return(errno_ret(EEXIST));
        }
        Err(narf_filesystem::FsError::OperationNotPermitted) => {
            ctx.set_return(errno_ret(EPERM));
        }
        Err(narf_filesystem::FsError::NotFound)
            if matches!(
                cmd,
                0x8910
                    | 0x8913
                    | 0x8914
                    | 0x8915
                    | 0x891b
                    | 0x8921
                    | 0x8922
                    | 0x8924
                    | 0x8927
                    | 0x8933
                    | 0x8946
            ) =>
        {
            // `dev_ioctl` resolves the ifreq name with `__dev_get_by_name`;
            // an absent network device is ENODEV, never pathname ENOENT.
            ctx.set_return(errno_ret(ENODEV));
        }
        Err(narf_filesystem::FsError::NotFound) => {
            ctx.set_return(errno_ret(ENOENT));
        }
        Err(narf_filesystem::FsError::InvalidData)
            if matches!(
                cmd,
                0x8910
                    | 0x8913
                    | 0x8914
                    | 0x8915
                    | 0x891b
                    | 0x8921
                    | 0x8922
                    | 0x8924
                    | 0x8927
                    | 0x8933
            ) =>
        {
            ctx.set_return(errno_ret(EFAULT));
        }
        Err(narf_filesystem::FsError::InvalidData)
            if cmd == 0x541B
                && ops.stat().mode.file_type == narf_filesystem::FileType::Fifo =>
        {
            // pipe_ioctl(FIONREAD) returns put_user() directly, so an invalid
            // result pointer is EFAULT rather than an invalid ioctl argument.
            ctx.set_return(errno_ret(EFAULT));
        }
        Err(narf_filesystem::FsError::InvalidData) | Err(narf_filesystem::FsError::InvalidPath) => {
            ctx.set_return(errno_ret(EINVAL));
        }
        Err(narf_filesystem::FsError::Busy) => {
            // EBUSY = 16. A device ioctl that reports the resource is held —
            // e.g. DRM_IOCTL_SET_MASTER when another client already holds DRM
            // master. Without this arm the direct ioctl path folds Busy into
            // the blanket -EINVAL below, giving the wrong errno.
            ctx.set_return(errno_ret(EBUSY));
        }
        Err(narf_filesystem::FsError::WouldBlock)
            if cmd & 0xff == 0xc3
                && (ops.as_drm_card_index().is_some() || ops.as_drm_render_index().is_some()) =>
        {
            // DRM_SYNCOBJ_WAIT reports an expired absolute timeout as ETIME,
            // not the EAGAIN used by nonblocking file readiness.
            ctx.set_return(errno_ret(62)); // ETIME
        }
        Err(narf_filesystem::FsError::WouldBlock) => ctx.set_return(errno_ret(EAGAIN)),
        Err(_) => {
            ctx.set_return(errno_ret(EINVAL));
        }
    }
}
