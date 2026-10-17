//! The DRM syncobj ioctls (`drm_syncobj.c`) against one open's table.
//!
//! | nr   | ioctl | needs |
//! |------|-------|-------|
//! | 0xbf | `SYNCOBJ_CREATE` | |
//! | 0xc0 | `SYNCOBJ_DESTROY` | |
//! | 0xc1 | `SYNCOBJ_HANDLE_TO_FD` (opaque fd, or `EXPORT_SYNC_FILE`) | an [`IoctlContext`] |
//! | 0xc2 | `SYNCOBJ_FD_TO_HANDLE` (opaque fd, or `IMPORT_SYNC_FILE`) | an [`IoctlContext`] |
//! | 0xc3 | `SYNCOBJ_WAIT` | |
//! | 0xc4 | `SYNCOBJ_RESET` | |
//! | 0xc5 | `SYNCOBJ_SIGNAL` | |
//! | 0xca | `SYNCOBJ_TIMELINE_WAIT` | `DRIVER_SYNCOBJ_TIMELINE` |
//! | 0xcb | `SYNCOBJ_QUERY` | `DRIVER_SYNCOBJ_TIMELINE` |
//! | 0xcc | `SYNCOBJ_TRANSFER` | `DRIVER_SYNCOBJ_TIMELINE` |
//! | 0xcd | `SYNCOBJ_TIMELINE_SIGNAL` | `DRIVER_SYNCOBJ_TIMELINE` |
//! | 0xcf | `SYNCOBJ_EVENTFD` | `DRIVER_SYNCOBJ_TIMELINE`, an [`IoctlContext`] |
//!
//! Errnos follow Linux, including its oddities: DESTROY and HANDLE_TO_FD
//! of an unknown handle are -EINVAL (every other lookup is -ENOENT), a wait
//! with no handles succeeds while RESET/SIGNAL/QUERY with none are -EINVAL,
//! and a timeline ioctl on a driver without timelines is -EOPNOTSUPP.
//!
//! Waiting: [`step`] evaluates a request once without side effects before
//! its outcome is known, so a pending wait can be re-executed from the
//! original arguments. [`dispatch`] drives it: an array wait (absolute
//! deadline) asks the syscall layer for an interruptible restart
//! (`IoctlContext::restart_after`, Linux's `-ERESTARTSYS` path) and
//! otherwise sleeps; a WAIT_FOR_SUBMIT lookup (`drm_syncobj_find_fence`,
//! bounded at 5 s) sleeps within the call. [`dispatch_sync`] is the
//! kernel-caller form, with no descriptor operations.
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_filesystem::{FileOps, FileType, FsError, FsFuture, IoctlContext, Mode, Stat};
use narf_lib::sync::IrqSafeSpinLock;

use super::syncobj::{self as so, SyncObjCore, SyncObjTable, WaitPoll};
use crate::drm_ioctl_bridge::{copy_in, copy_out};

const ETIME: i64 = 62;
const EOPNOTSUPP: i64 = 95;
const EMFILE: i64 = 24;
const EBADF: i64 = 9;

/// A Linux errno no `FsError` carries, returned raw (the syscall layer
/// passes a negative ioctl result through).
fn errno(e: i64) -> Result<u64, FsError> {
    Ok((-e) as u64)
}

/// `DRM_SYNCOBJ_WAIT_FOR_SUBMIT_TIMEOUT`.
pub const WAIT_FOR_SUBMIT_TIMEOUT_NS: u64 = 5_000_000_000;
/// How long a parked array wait sleeps before it is evaluated again.
const REPOLL_NS: u64 = 250_000;
/// Bound on a handle array (Linux bounds it only by the allocator).
const MAX_HANDLES: usize = 1 << 16;

/// `DRM_SYNCOBJ_HANDLE_TO_FD_FLAGS_EXPORT_SYNC_FILE` /
/// `DRM_SYNCOBJ_FD_TO_HANDLE_FLAGS_IMPORT_SYNC_FILE`.
pub const SYNCOBJ_FD_SYNC_FILE: u32 = 1 << 0;
/// `DRM_SYNCOBJ_{HANDLE_TO_FD,FD_TO_HANDLE}_FLAGS_TIMELINE`.
pub const SYNCOBJ_FD_TIMELINE: u32 = 1 << 1;

/// Whether `nr` is one of the syncobj ioctls this module answers.
pub fn is_syncobj_ioctl(nr: u32) -> bool {
    matches!(nr, 0xbf..=0xc5 | 0xca..=0xcd | 0xcf)
}

/// One evaluation of a syncobj ioctl.
#[derive(Debug)]
pub enum Step {
    /// Finished with this result.
    Done(Result<u64, FsError>),
    /// Not yet. `restartable`: the request is an array wait whose deadline is
    /// absolute, so re-executing it later is the same request.
    Pending { restartable: bool },
}
use Step::{Done, Pending};

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// Copy `count` u32 handles from user `ptr` (`drm_syncobj_array_find`'s
/// copy: EFAULT on a bad pointer).
fn read_handles(ptr: u64, count: usize) -> Result<Vec<u32>, FsError> {
    if count > MAX_HANDLES {
        return Err(FsError::OutOfMemory);
    }
    // SAFETY: `ptr` is the caller's handle array; copy_in bounds the length
    // and SMAP-brackets the read.
    let raw = unsafe { copy_in(ptr as usize, count * 4)? };
    Ok(raw
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
        .collect())
}

/// Copy `count` u64 points from user `ptr`; a null pointer is all zero.
fn read_points(ptr: u64, count: usize) -> Result<Vec<u64>, FsError> {
    if ptr == 0 {
        return Ok(alloc::vec![0; count]);
    }
    if count > MAX_HANDLES {
        return Err(FsError::OutOfMemory);
    }
    // SAFETY: as `read_handles`.
    let raw = unsafe { copy_in(ptr as usize, count * 8)? };
    Ok(raw
        .chunks_exact(8)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
        .collect())
}

/// `drm_syncobj_array_find`: handles copied in, each resolved (-ENOENT).
fn find_array(
    table: &IrqSafeSpinLock<SyncObjTable>,
    ptr: u64,
    count: usize,
) -> Result<Vec<Arc<SyncObjCore>>, FsError> {
    let ids = read_handles(ptr, count)?;
    table.lock().find_all(&ids).map_err(|_| FsError::NotFound)
}

fn lookup(table: &IrqSafeSpinLock<SyncObjTable>, handle: u32) -> Option<Arc<SyncObjCore>> {
    table.lock().get(handle).ok().map(|o| o.core().clone())
}

/// `drm_syncobj_find_fence(handle, point, flags)` once the object is found:
/// flags other than WAIT_FOR_SUBMIT are -EINVAL; a missing fence or point is
/// -EINVAL, or with WAIT_FOR_SUBMIT pending until `started_ns` + 5 s and
/// then -ETIME.
pub fn find_fence_step(
    core: &SyncObjCore,
    point: u64,
    flags: u64,
    started_ns: u64,
) -> Result<Option<Arc<dyn so::DmaFence>>, Result<u64, FsError>> {
    if flags & !u64::from(so::SYNCOBJ_WAIT_FLAGS_WAIT_FOR_SUBMIT) != 0 {
        return Err(Err(FsError::InvalidData));
    }
    match core.find_fence(point) {
        Ok(f) => Ok(Some(f)),
        Err(()) if flags != 0 => {
            if narf_time::monotonic_ns() >= started_ns.saturating_add(WAIT_FOR_SUBMIT_TIMEOUT_NS) {
                Err(errno(ETIME))
            } else {
                Ok(None)
            }
        }
        Err(()) => Err(Err(FsError::InvalidData)),
    }
}

/// Evaluate syncobj ioctl `nr` once. `timeline`: the driver has
/// `DRIVER_SYNCOBJ_TIMELINE`. `started_ns`: when the ioctl began (the
/// WAIT_FOR_SUBMIT bound).
pub fn step(
    nr: u32,
    arg: usize,
    table: &IrqSafeSpinLock<SyncObjTable>,
    timeline: bool,
    ctx: Option<&dyn IoctlContext>,
    started_ns: u64,
) -> Step {
    match step_inner(nr, arg, table, timeline, ctx, started_ns) {
        Ok(step) => step,
        Err(e) => Done(Err(e)),
    }
}

fn step_inner(
    nr: u32,
    arg: usize,
    table: &IrqSafeSpinLock<SyncObjTable>,
    timeline: bool,
    ctx: Option<&dyn IoctlContext>,
    started_ns: u64,
) -> Result<Step, FsError> {
    if matches!(nr, 0xca..=0xcd | 0xcf) && !timeline {
        return Ok(Done(errno(EOPNOTSUPP)));
    }
    match nr {
        // CREATE { u32 handle (out), u32 flags }
        0xbf => {
            // SAFETY: `arg` is the ioctl struct pointer; 8 bytes.
            let b = unsafe { copy_in(arg, 8)? };
            if le32(&b, 4) & !so::SYNCOBJ_CREATE_SIGNALED != 0 {
                return Err(FsError::InvalidData);
            }
            let handle = table
                .lock()
                .create(le32(&b, 4))
                .map_err(|_| FsError::OutOfMemory)?;
            // SAFETY: as above.
            unsafe { copy_out(arg, &handle.to_le_bytes())? };
            Ok(Done(Ok(0)))
        }
        // DESTROY { u32 handle, u32 pad }: an unknown handle is -EINVAL.
        0xc0 => {
            // SAFETY: as above.
            let b = unsafe { copy_in(arg, 8)? };
            if le32(&b, 4) != 0 {
                return Err(FsError::InvalidData);
            }
            table
                .lock()
                .destroy(le32(&b, 0))
                .map_err(|_| FsError::InvalidData)?;
            Ok(Done(Ok(0)))
        }
        // HANDLE_TO_FD { u32 handle, u32 flags, s32 fd (out), u32 pad, u64 point }
        0xc1 => {
            // SAFETY: as above; 24 bytes.
            let b = unsafe { copy_in(arg, 24)? };
            let (handle, flags, pad) = (le32(&b, 0), le32(&b, 4), le32(&b, 12));
            if pad != 0 || flags & !(SYNCOBJ_FD_SYNC_FILE | SYNCOBJ_FD_TIMELINE) != 0 {
                return Err(FsError::InvalidData);
            }
            let point = if flags & SYNCOBJ_FD_TIMELINE != 0 {
                le64(&b, 16)
            } else {
                0
            };
            let Some(ctx) = ctx else {
                return Ok(Done(errno(EOPNOTSUPP)));
            };
            let report = |fd: i32| {
                // SAFETY: the `fd` field at offset 8 of the caller's struct.
                unsafe { copy_out(arg + 8, &fd.to_le_bytes()) }
            };
            if flags & SYNCOBJ_FD_SYNC_FILE != 0 {
                // drm_syncobj_export_sync_file.
                let core = lookup(table, handle).ok_or(FsError::NotFound)?;
                let fence = core.find_fence(point).map_err(|()| FsError::InvalidData)?;
                let mut report = report;
                return Ok(Done(
                    match ctx.install_sync_file(so::to_drm_leaves(&fence), &mut report) {
                        Ok(_) => Ok(0),
                        Err(narf_filesystem::InstallFdError::NoDescriptor) => errno(EMFILE),
                        Err(narf_filesystem::InstallFdError::Report(e)) => Err(e),
                    },
                ));
            }
            if le64(&b, 16) != 0 {
                return Err(FsError::InvalidData);
            }
            // drm_syncobj_handle_to_fd: an unknown handle is -EINVAL.
            let core = lookup(table, handle).ok_or(FsError::InvalidData)?;
            let fd = ctx
                .install_file(Arc::new(SyncobjFile { core }), true)
                .map_err(|_| FsError::OutOfMemory);
            let fd = match fd {
                Ok(fd) => fd,
                Err(_) => return Ok(Done(errno(EMFILE))),
            };
            report(fd)?;
            Ok(Done(Ok(0)))
        }
        // FD_TO_HANDLE { u32 handle (in/out), u32 flags, s32 fd, u32 pad, u64 point }
        0xc2 => {
            // SAFETY: as above; 24 bytes.
            let b = unsafe { copy_in(arg, 24)? };
            let (handle, flags, fd, pad) =
                (le32(&b, 0), le32(&b, 4), le32(&b, 8) as i32, le32(&b, 12));
            if pad != 0 || flags & !(SYNCOBJ_FD_SYNC_FILE | SYNCOBJ_FD_TIMELINE) != 0 {
                return Err(FsError::InvalidData);
            }
            let point = if flags & SYNCOBJ_FD_TIMELINE != 0 {
                le64(&b, 16)
            } else {
                0
            };
            let Some(ctx) = ctx else {
                return Ok(Done(errno(EOPNOTSUPP)));
            };
            if flags & SYNCOBJ_FD_SYNC_FILE != 0 {
                // drm_syncobj_import_sync_file_fence: a bad fd or a
                // non-sync_file is -EINVAL, then an unknown handle -ENOENT.
                let leaves = ctx.sync_file_fences(fd).ok_or(FsError::InvalidData)?;
                let core = lookup(table, handle).ok_or(FsError::NotFound)?;
                let fence = so::from_drm_leaves(leaves);
                if point != 0 {
                    core.add_point(fence, point);
                } else {
                    core.replace_fence(Some(fence));
                }
                return Ok(Done(Ok(0)));
            }
            if le64(&b, 16) != 0 {
                return Err(FsError::InvalidData);
            }
            // drm_syncobj_fd_to_handle: anything but a syncobj file is -EINVAL.
            let file = ctx.file(fd).map_err(|_| FsError::InvalidData)?;
            let core = file
                .as_any()
                .and_then(|a| a.downcast_ref::<SyncobjFile>())
                .map(|f| f.core.clone())
                .ok_or(FsError::InvalidData)?;
            let handle = table
                .lock()
                .insert(core)
                .map_err(|_| FsError::OutOfMemory)?;
            // SAFETY: the `handle` field at offset 0.
            unsafe { copy_out(arg, &handle.to_le_bytes())? };
            Ok(Done(Ok(0)))
        }
        // WAIT { u64 handles, s64 timeout, u32 count, u32 flags,
        //   u32 first_signaled (out), u32 pad, u64 deadline }
        // TIMELINE_WAIT { u64 handles, u64 points, s64 timeout, u32 count,
        //   u32 flags, u32 first_signaled (out), u32 pad, u64 deadline }
        0xc3 | 0xca => {
            let timeline_wait = nr == 0xca;
            let size = if timeline_wait { 48 } else { 40 };
            // SAFETY: as above.
            let b = unsafe { copy_in(arg, size)? };
            let off = if timeline_wait { 8 } else { 0 };
            let timeout = le64(&b, 8 + off) as i64;
            let count = le32(&b, 16 + off) as usize;
            let flags = le32(&b, 20 + off);
            let mut possible = so::SYNCOBJ_WAIT_FLAGS_WAIT_ALL
                | so::SYNCOBJ_WAIT_FLAGS_WAIT_FOR_SUBMIT
                | so::SYNCOBJ_WAIT_FLAGS_WAIT_DEADLINE;
            if timeline_wait {
                possible |= so::SYNCOBJ_WAIT_FLAGS_WAIT_AVAILABLE;
            }
            if flags & !possible != 0 {
                return Err(FsError::InvalidData);
            }
            if count == 0 {
                return Ok(Done(Ok(0)));
            }
            let objs = find_array(table, le64(&b, 0), count)?;
            let points = if timeline_wait {
                read_points(le64(&b, 8), count)?
            } else {
                alloc::vec![0; count]
            };
            match so::poll_wait(&objs, &points, flags) {
                WaitPoll::Ready(first) => {
                    // SAFETY: the `first_signaled` field.
                    unsafe { copy_out(arg + 24 + off, &first.to_le_bytes())? };
                    Ok(Done(Ok(0)))
                }
                WaitPoll::Invalid => Err(FsError::InvalidData),
                // drm_timeout_abs_to_jiffies: 0 polls; a past instant too.
                WaitPoll::Pending
                    if timeout <= 0 || timeout as u64 <= narf_time::monotonic_ns() =>
                {
                    Ok(Done(errno(ETIME)))
                }
                WaitPoll::Pending => Ok(Pending { restartable: true }),
            }
        }
        // RESET (0xc4) / SIGNAL (0xc5) { u64 handles, u32 count, u32 pad }
        0xc4 | 0xc5 => {
            // SAFETY: as above; 16 bytes.
            let b = unsafe { copy_in(arg, 16)? };
            let count = le32(&b, 8) as usize;
            if le32(&b, 12) != 0 || count == 0 {
                return Err(FsError::InvalidData);
            }
            for core in find_array(table, le64(&b, 0), count)? {
                core.replace_fence((nr == 0xc5).then(so::stub));
            }
            Ok(Done(Ok(0)))
        }
        // QUERY (0xcb) / TIMELINE_SIGNAL (0xcd)
        // { u64 handles, u64 points, u32 count, u32 flags }
        0xcb | 0xcd => {
            // SAFETY: as above; 24 bytes.
            let b = unsafe { copy_in(arg, 24)? };
            let (points_ptr, count, flags) = (le64(&b, 8), le32(&b, 16) as usize, le32(&b, 20));
            let valid = if nr == 0xcb {
                so::SYNCOBJ_QUERY_FLAGS_LAST_SUBMITTED
            } else {
                0
            };
            if flags & !valid != 0 || count == 0 {
                return Err(FsError::InvalidData);
            }
            let objs = find_array(table, le64(&b, 0), count)?;
            if nr == 0xcd {
                let points = read_points(points_ptr, count)?;
                for (core, point) in objs.iter().zip(points) {
                    core.add_point(so::stub(), point);
                }
                return Ok(Done(Ok(0)));
            }
            let last = flags & so::SYNCOBJ_QUERY_FLAGS_LAST_SUBMITTED != 0;
            for (i, core) in objs.iter().enumerate() {
                let point = so::query_point(core.fence(), last);
                // SAFETY: element `i` of the caller's `points` array.
                unsafe { copy_out(points_ptr as usize + i * 8, &point.to_le_bytes())? };
            }
            Ok(Done(Ok(0)))
        }
        // TRANSFER { u32 src, u32 dst, u64 src_point, u64 dst_point,
        //   u32 flags, u32 pad }
        0xcc => {
            // SAFETY: as above; 32 bytes.
            let b = unsafe { copy_in(arg, 32)? };
            if le32(&b, 28) != 0 {
                return Err(FsError::InvalidData);
            }
            let dst = lookup(table, le32(&b, 4)).ok_or(FsError::NotFound)?;
            let flags = u64::from(le32(&b, 24));
            if flags & !u64::from(so::SYNCOBJ_WAIT_FLAGS_WAIT_FOR_SUBMIT) != 0 {
                return Err(FsError::InvalidData);
            }
            let src = lookup(table, le32(&b, 0)).ok_or(FsError::NotFound)?;
            let fence = match find_fence_step(&src, le64(&b, 8), flags, started_ns) {
                Ok(Some(f)) => f,
                Ok(None) => return Ok(Pending { restartable: false }),
                Err(r) => return Ok(Done(r)),
            };
            let dst_point = le64(&b, 16);
            if dst_point != 0 {
                // drm_syncobj_transfer_to_timeline (dma_fence_unwrap_merge
                // happens in add_point).
                dst.add_point(fence, dst_point);
            } else {
                dst.replace_fence(Some(fence));
            }
            Ok(Done(Ok(0)))
        }
        // EVENTFD { u32 handle, u32 flags, u64 point, s32 fd, u32 pad }
        0xcf => {
            // SAFETY: as above; 24 bytes.
            let b = unsafe { copy_in(arg, 24)? };
            let (handle, flags, point, fd, pad) = (
                le32(&b, 0),
                le32(&b, 4),
                le64(&b, 8),
                le32(&b, 16) as i32,
                le32(&b, 20),
            );
            if flags & !so::SYNCOBJ_WAIT_FLAGS_WAIT_AVAILABLE != 0 || pad != 0 {
                return Err(FsError::InvalidData);
            }
            let core = lookup(table, handle).ok_or(FsError::NotFound)?;
            let Some(ctx) = ctx else {
                return Ok(Done(errno(EBADF)));
            };
            // eventfd_ctx_fdget: -EBADF for no file, -EINVAL for another type.
            let Ok(file) = ctx.file(fd) else {
                return Ok(Done(errno(EBADF)));
            };
            if file.anon_name() != Some("[eventfd]") {
                return Err(FsError::InvalidData);
            }
            let available = flags & so::SYNCOBJ_WAIT_FLAGS_WAIT_AVAILABLE != 0;
            narf_scheduler::spawn(eventfd_watch(core, point, available, file));
            Ok(Done(Ok(0)))
        }
        _ => Err(FsError::Unsupported),
    }
}

/// `syncobj_eventfd_entry_func` and its fence callback, polled: once
/// `point` is attached, signal the eventfd (WAIT_AVAILABLE) or wait for that
/// fence and then signal it. Ends without signalling if the syncobj is
/// freed first (Linux frees its entries with the syncobj) or nobody holds
/// the eventfd any more.
pub(crate) async fn eventfd_watch(
    core: Arc<SyncObjCore>,
    point: u64,
    available: bool,
    file: Arc<dyn FileOps>,
) {
    let nap = || narf_time::SleepUntil::new(narf_time::Deadline::after_us(1_000).as_instant());
    let fence = loop {
        if Arc::strong_count(&file) == 1 {
            return;
        }
        if let Ok(f) = core.find_fence(point) {
            break f;
        }
        if Arc::strong_count(&core) == 1 {
            return;
        }
        nap().await;
    };
    drop(core);
    if !available {
        while !fence.is_signalled() {
            if Arc::strong_count(&file) == 1 {
                return;
            }
            nap().await;
        }
    }
    let _ = file.write(0, &1u64.to_le_bytes()).await;
}

/// Syncobj ioctl `nr` from a user open, or `None` for another ioctl. A
/// pending array wait parks for an interruptible re-execution when the
/// context can arrange one; everything else pending sleeps here.
pub async fn dispatch(
    nr: u32,
    arg: usize,
    table: &IrqSafeSpinLock<SyncObjTable>,
    timeline: bool,
    ctx: &dyn IoctlContext,
) -> Option<Result<u64, FsError>> {
    if !is_syncobj_ioctl(nr) {
        return None;
    }
    let started = narf_time::monotonic_ns();
    loop {
        match step(nr, arg, table, timeline, Some(ctx), started) {
            Done(result) => return Some(result),
            Pending { restartable } => {
                if restartable && ctx.restart_after(REPOLL_NS) {
                    return Some(Err(FsError::WouldBlock));
                }
                narf_time::SleepUntil::new(narf_time::Deadline::after_us(100).as_instant()).await;
            }
        }
    }
}

/// Syncobj ioctl `nr` from a kernel caller (no descriptor table: the fd
/// ioctls are -EOPNOTSUPP), waiting synchronously; `None` for another
/// ioctl. Spins, so a wait is capped at 15 s (-ETIME), the bound the
/// synchronous GPU waits use.
pub fn dispatch_sync(
    nr: u32,
    arg: usize,
    table: &IrqSafeSpinLock<SyncObjTable>,
    timeline: bool,
) -> Option<Result<u64, FsError>> {
    if !is_syncobj_ioctl(nr) {
        return None;
    }
    let started = narf_time::monotonic_ns();
    loop {
        match step(nr, arg, table, timeline, None, started) {
            Done(result) => return Some(result),
            Pending { .. } => {
                if narf_time::monotonic_ns() >= started.saturating_add(15_000_000_000) {
                    return Some(errno(ETIME));
                }
                let until = narf_time::monotonic_ns().saturating_add(50_000);
                while narf_time::monotonic_ns() < until {
                    core::hint::spin_loop();
                }
            }
        }
    }
}

/// `anon_inode_getfile("syncobj_file", &drm_syncobj_file_fops, syncobj)`:
/// an opaque syncobj fd, importable into any open (`FD_TO_HANDLE`) as a
/// handle to the same object.
#[derive(Debug)]
pub struct SyncobjFile {
    core: Arc<SyncObjCore>,
}

impl SyncobjFile {
    /// The object this fd names.
    pub fn core(&self) -> &Arc<SyncObjCore> {
        &self.core
    }
}

/// A syncobj fd for `core`, for callers that mint one themselves
/// (`AMDGPU_FENCE_TO_HANDLE_GET_SYNCOBJ_FD`).
pub fn syncobj_file(core: Arc<SyncObjCore>) -> Arc<dyn FileOps> {
    Arc::new(SyncobjFile { core })
}

impl FileOps for SyncobjFile {
    fn ino(&self) -> u64 {
        narf_filesystem::inode_id::anon_inode().ino
    }
    fn anon_name(&self) -> Option<&'static str> {
        Some("syncobj_file")
    }
    fn inode_attrs(&self) -> narf_filesystem::InodeAttrs {
        narf_filesystem::inode_id::anon_inode().attrs()
    }
    /// `drm_syncobj_file_fops` has no read or write.
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::InvalidData) })
    }
    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::InvalidData) })
    }
    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o600,
            },
            mtime_cycles: 0,
        }
    }
    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}
