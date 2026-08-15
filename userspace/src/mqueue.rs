//! Batch 8 — POSIX message queues (`mq_*`) and inotify watches.
//!
//! Both are fd-backed objects living in the per-task fd table like every
//! other event-style fd. Resolution from an fd back to the underlying
//! object goes through the `FileOps::mq_queue_id` / `inotify_instance`
//! hooks (mirroring `pidfd_target_pid`) rather than a downcast.
//!
//! Message queues are Linux-shaped mqueuefs inodes held by
//! `narf_filesystem::mqueuefs`; `mq_open` and mounted `mqueue` instances share
//! those namespace-keyed objects. inotify instances each own a
//! watch-descriptor table plus a queue of serialized `struct
//! inotify_event` records; the syscall handlers call the `notify_*`
//! entry points here after a successful filesystem mutation, which fan
//! the matching events out to every watching instance for read(2)/poll.
//!
//! Gated under `#[cfg(feature = "linux-compat")]` via the `pub mod`
//! line in `lib.rs`.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use narf_filesystem::{
    mqueuefs, FileOps, FsError, FsFuture, Mode, MqueueAttr, MqueueOpenOptions, Stat,
};
use narf_lib::sync::IrqSafeSpinLock;

use crate::fd;
use crate::handlers::{copy_user_cstr, current_task_id};
use crate::syscall::{SyscallReturn, TrapContext};

// ── errno values returned as negated longs ──────────────────────────
const ENOENT: i64 = 2;
const EBADF: i64 = 9;
const EAGAIN: i64 = 11;
const EFAULT: i64 = 14;
const EEXIST: i64 = 17;
const EINVAL: i64 = 22;
const ENOSPC: i64 = 28;
const ENAMETOOLONG: i64 = 36;
const EMSGSIZE: i64 = 90;
const ETIMEDOUT: i64 = 110;

fn err(e: i64) -> SyscallReturn {
    SyscallReturn::ok((-e) as u64)
}

// open-flag bits we honour (shared with the generic open path).
const O_NONBLOCK: u64 = 0o4000;

// ════════════════════════════════════════════════════════════════════
// POSIX message queues
// ════════════════════════════════════════════════════════════════════

/// Resolve an mqd to its open-description id via the FileOps hook.
fn queue_id_of(task: u64, mqd: u32) -> Option<u64> {
    fd::with_table(task, |t| t.get(mqd).and_then(|e| e.ops.mq_queue_id())).flatten()
}

pub(crate) fn set_fd_nonblock(task: u64, mqd: u32, enabled: bool) {
    if let Some(id) = queue_id_of(task, mqd) {
        let _ = mqueuefs::set_nonblock(id, enabled);
    }
}

pub(crate) fn fd_nonblock(task: u64, mqd: u32) -> Option<bool> {
    queue_id_of(task, mqd).and_then(|id| mqueuefs::is_nonblock(id).ok())
}

fn read_i64(buf: &[u8]) -> i64 {
    i64::from_le_bytes(buf[..8].try_into().unwrap())
}

fn namespace_id(task: u64) -> u64 {
    #[cfg(feature = "container")]
    {
        crate::namespaces::current_ipc_ns(task)
            .map(|namespace| namespace.id())
            .unwrap_or(0)
    }
    #[cfg(not(feature = "container"))]
    {
        let _ = task;
        0
    }
}

/// Build a mount of the IPC namespace visible to the calling task.
pub fn mount_current_namespace() -> Arc<dyn narf_filesystem::FsInstance> {
    Arc::new(narf_filesystem::MqueueFs::new(namespace_id(
        current_task_id(),
    )))
}

fn mq_errno(error: narf_filesystem::MqueueError) -> i64 {
    use narf_filesystem::MqueueError;
    match error {
        MqueueError::NotFound => ENOENT,
        MqueueError::Exists => EEXIST,
        MqueueError::Invalid => EINVAL,
        MqueueError::NameTooLong => ENAMETOOLONG,
        MqueueError::PermissionDenied => 13,
        MqueueError::NoSpace => ENOSPC,
        MqueueError::BadDescriptor => EBADF,
        MqueueError::MessageTooLarge => EMSGSIZE,
        MqueueError::WouldBlock => EAGAIN,
        MqueueError::Busy => 16,
    }
}

/// Convert the Linux syscall ABI's leaf name into the POSIX-shaped name used
/// by the typed mqueue backend.  libc validates the public leading slash and
/// removes it before issuing `mq_open(2)` / `mq_unlink(2)`; Linux therefore
/// receives `"queue"`, not `"/queue"`, at this boundary.
fn backend_mq_name(syscall_name: &str) -> String {
    let mut name = String::with_capacity(syscall_name.len() + 1);
    name.push('/');
    name.push_str(syscall_name);
    name
}

fn timeout_deadline(timeout_ptr: u64) -> Result<Option<u64>, i64> {
    if timeout_ptr == 0 {
        return Ok(None);
    }
    let mut bytes = [0u8; 16];
    // SAFETY: the syscall supplied a `const struct timespec *`; the uaccess
    // helper validates and SMAP-brackets the fixed-size read.
    unsafe { crate::handlers::copy_from_user(&mut bytes, timeout_ptr) }.map_err(|_| EFAULT)?;
    let seconds = i64::from_ne_bytes(bytes[0..8].try_into().unwrap());
    let nanoseconds = i64::from_ne_bytes(bytes[8..16].try_into().unwrap());
    if seconds < 0 || !(0..1_000_000_000).contains(&nanoseconds) {
        return Err(EINVAL);
    }
    let absolute = i128::from(seconds) * 1_000_000_000 + i128::from(nanoseconds);
    let wall_now = narf_scheduler::narf_time::now_wall().as_nanos();
    let monotonic_now = narf_scheduler::narf_time::monotonic_ns();
    if absolute <= wall_now {
        return Ok(Some(monotonic_now));
    }
    let remaining = u64::try_from(absolute - wall_now).unwrap_or(u64::MAX);
    Ok(Some(monotonic_now.saturating_add(remaining)))
}

/// Handle the full/empty slow path. Linux interprets the supplied timeout as
/// an absolute CLOCK_REALTIME deadline. NARF parks and re-executes the syscall;
/// queue state is rechecked after a readiness wake or a 1ms safety deadline.
fn park_would_block(ctx: &mut dyn TrapContext, handle_id: u64, timeout_ptr: u64) {
    if mqueuefs::is_nonblock(handle_id).unwrap_or(true) {
        ctx.set_return(err(EAGAIN));
        return;
    }
    let absolute_deadline = match timeout_deadline(timeout_ptr) {
        Ok(deadline) => deadline,
        Err(errno) => {
            ctx.set_return(err(errno));
            return;
        }
    };
    let now = narf_scheduler::narf_time::monotonic_ns();
    if absolute_deadline.is_some_and(|deadline| deadline <= now) {
        ctx.set_return(err(ETIMEDOUT));
        return;
    }
    if let (Some(user_task), Some(hook)) = (
        crate::user_task::current_user_task(),
        crate::user_task::yield_hook(),
    ) {
        let deadline = absolute_deadline
            .unwrap_or(u64::MAX)
            .min(now.saturating_add(1_000_000));
        #[cfg(target_arch = "x86_64")]
        let resume_rip = ctx.rip().wrapping_sub(2);
        #[cfg(target_arch = "aarch64")]
        let resume_rip = ctx.rip().wrapping_sub(4);
        ctx.set_rip(resume_rip);
        // SAFETY: `user_task` is the live task context. State is published
        // before the scheduler handoff, and no filesystem lock is held here.
        unsafe {
            let user = &*user_task;
            user.sleep_deadline_ns.store(deadline, Ordering::Release);
            user.net_io_wait.store(true, Ordering::Release);
            user.epoll_park_gen
                .store(narf_net::readiness::generation(), Ordering::Release);
            ctx.save_user_state(user.state.get() as *mut u8);
            *user.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
            if narf_scheduler::stackful::user_own_stack_enabled() {
                crate::handlers::own_stack_block(ctx);
                return;
            }
            hook(user_task);
        }
    }
    // The kernel-test harness has no runnable user task to park.
    ctx.set_return(err(EAGAIN));
}

/// `mq_open(name, oflag, mode, attr)`.
pub fn sys_mq_open(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let name = match copy_user_cstr(a.arg0, 256) {
        Some(n) if !n.is_empty() => n,
        Some(_) => {
            ctx.set_return(err(EINVAL));
            return;
        }
        None => {
            ctx.set_return(err(EFAULT));
            return;
        }
    };
    let oflag = a.arg1 as u32;
    let attr_ptr = a.arg3;

    let attr = if attr_ptr != 0 {
        let mut buf = [0u8; 64];
        // SAFETY: attr_ptr is non-zero; copy_from_user range-validates and
        // SMAP-brackets the mq_attr prefix consumed by the kernel.
        if unsafe { crate::handlers::copy_from_user(&mut buf, attr_ptr) }.is_err() {
            ctx.set_return(err(EFAULT));
            return;
        }
        Some(MqueueAttr {
            flags: read_i64(&buf[0..8]),
            maxmsg: read_i64(&buf[8..16]),
            msgsize: read_i64(&buf[16..24]),
            curmsgs: read_i64(&buf[24..32]),
        })
    } else {
        None
    };
    let task = current_task_id();
    let (uid, gid) = crate::handlers::current_fs_ids();
    let mode = a.arg2 as u16;
    let name = backend_mq_name(&name);
    let file = match mqueuefs::open(
        namespace_id(task),
        &name,
        MqueueOpenOptions {
            flags: oflag,
            mode,
            umask: crate::handlers::current_umask() as u16,
            uid,
            gid,
            attr,
        },
    ) {
        Ok(file) => file,
        Err(error) => {
            ctx.set_return(err(mq_errno(error)));
            return;
        }
    };

    // Linux do_mq_open installs every mqd with O_CLOEXEC, independent of the
    // caller's flags (`FD_ADD(O_CLOEXEC, ...)`).
    let status_flags = oflag & (fd::O_ACCMODE | fd::O_NONBLOCK);
    match task_open_call(task_open(file, fd::FD_CLOEXEC, status_flags)) {
        Some(n) => ctx.set_return(SyscallReturn::ok(n as u64)),
        None => ctx.set_return(err(EBADF)),
    }
}

/// Helper bundling the closure for `fd::with_table` open — keeps the
/// borrow of `task` short and the call sites readable.
fn task_open(
    file: Arc<dyn FileOps>,
    flags: u32,
    status_flags: u32,
) -> impl FnOnce(&mut fd::FdTable) -> u32 {
    move |t| {
        t.open(fd::FdEntry {
            ops: file,
            offset: 0,
            flags,
            status_flags,
        })
    }
}

// `fd::with_table` takes (task, closure); wrap so sys_mq_open reads cleanly.
fn task_open_call<R>(f: impl FnOnce(&mut fd::FdTable) -> R) -> Option<R> {
    fd::with_table(current_task_id(), f)
}

/// `mq_unlink(name)`.
pub fn sys_mq_unlink(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let name = match copy_user_cstr(a.arg0, 256) {
        Some(n) if !n.is_empty() => n,
        Some(_) => {
            ctx.set_return(err(EINVAL));
            return;
        }
        None => {
            ctx.set_return(err(EFAULT));
            return;
        }
    };
    let task = current_task_id();
    let (uid, _) = crate::handlers::current_fs_ids();
    let name = backend_mq_name(&name);
    match mqueuefs::unlink(namespace_id(task), &name, uid) {
        Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
        Err(error) => ctx.set_return(err(mq_errno(error))),
    }
}

/// `mq_timedsend(mqd, msg_ptr, msg_len, msg_prio, timeout)`.
pub fn sys_mq_timedsend(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let task = current_task_id();
    let id = match queue_id_of(task, a.arg0 as u32) {
        Some(id) => id,
        None => {
            ctx.set_return(err(EBADF));
            return;
        }
    };
    let msg_ptr = a.arg1;
    let msg_len = a.arg2 as usize;
    let prio = a.arg3 as u32;
    if let Err(errno) = timeout_deadline(a.arg4) {
        ctx.set_return(err(errno));
        return;
    }
    // SAFETY: msg_ptr is the user message buffer; copy_from_user_vec
    // range-validates and SMAP-brackets the read of msg_len bytes.
    let bytes = match unsafe { crate::handlers::copy_from_user_vec(msg_ptr, msg_len) } {
        Ok(b) => b,
        Err(_) => {
            ctx.set_return(err(EFAULT));
            return;
        }
    };
    match mqueuefs::send(id, bytes, prio) {
        Ok(notification) => {
            if let Some(notification) = notification {
                if notification.method == 0 {
                    // Linux mqueue.c __do_notify delivers si_code = SI_MESGQ,
                    // si_value = the registered sigev_value, and si_pid =
                    // task_tgid_nr_ns(sender, receiver_ns) — the SENDER's pid in
                    // the RECEIVER's namespace, NOT 0. (#25)
                    const SI_MESGQ: i32 = -3;
                    let receiver = notification.task_id;
                    let sender = current_task_id();
                    let sender_outer = crate::handlers::task_to_pid_raw(sender).unwrap_or(sender);
                    let si_pid = crate::handlers::report_pid_to(receiver, sender_outer) as u32;
                    crate::handlers::store_sigqueue_info(
                        receiver,
                        notification.signal as u32,
                        SI_MESGQ,
                        notification.value,
                        si_pid,
                    );
                    crate::handlers::raise_signal_pending(receiver, notification.signal as u32);
                }
            }
            narf_net::readiness::notify(0);
            ctx.set_return(SyscallReturn::ok(0));
        }
        Err(narf_filesystem::MqueueError::WouldBlock) => park_would_block(ctx, id, a.arg4),
        Err(error) => ctx.set_return(err(mq_errno(error))),
    }
}

/// `mq_notify(mqd, sigevent*)` — one-shot SIGEV_SIGNAL/SIGEV_NONE support.
/// SIGEV_THREAD remains a libc/netlink protocol and is rejected until NARF's
/// netlink layer exposes the Linux notification-cookie path.
pub fn sys_mq_notify(ctx: &mut dyn TrapContext) {
    const SIGEV_SIGNAL: i32 = 0;
    const SIGEV_NONE: i32 = 1;
    let args = *ctx.args();
    let task = current_task_id();
    let id = match queue_id_of(task, args.arg0 as u32) {
        Some(id) => id,
        None => {
            ctx.set_return(err(EBADF));
            return;
        }
    };
    let notification = if args.arg1 == 0 {
        None
    } else {
        let mut bytes = [0u8; 64];
        // SAFETY: Linux copies the complete native `struct sigevent` before
        // validating its sigval/signo/notify preamble.
        if unsafe { crate::handlers::copy_from_user(&mut bytes, args.arg1) }.is_err() {
            ctx.set_return(err(EFAULT));
            return;
        }
        // struct sigevent: sigev_value (sigval union, 8 bytes) then
        // sigev_signo (bytes[8..12]) then sigev_notify (bytes[12..16]).
        let value = u64::from_ne_bytes(bytes[0..8].try_into().unwrap());
        let signal = i32::from_ne_bytes(bytes[8..12].try_into().unwrap());
        let method = i32::from_ne_bytes(bytes[12..16].try_into().unwrap());
        if !matches!(method, SIGEV_SIGNAL | SIGEV_NONE)
            || (method == SIGEV_SIGNAL && !(0..=64).contains(&signal))
        {
            ctx.set_return(err(EINVAL));
            return;
        }
        Some(narf_filesystem::MqueueNotification {
            task_id: task,
            method,
            signal: if method == SIGEV_SIGNAL { signal } else { 0 },
            value,
        })
    };
    match mqueuefs::notify(id, task, notification) {
        Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
        Err(error) => ctx.set_return(err(mq_errno(error))),
    }
}

/// `mq_timedreceive(mqd, msg_ptr, msg_len, prio_ptr, timeout)`.
pub fn sys_mq_timedreceive(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let task = current_task_id();
    let id = match queue_id_of(task, a.arg0 as u32) {
        Some(id) => id,
        None => {
            ctx.set_return(err(EBADF));
            return;
        }
    };
    let msg_ptr = a.arg1;
    let msg_len = a.arg2 as usize;
    let prio_ptr = a.arg3;
    if let Err(errno) = timeout_deadline(a.arg4) {
        ctx.set_return(err(errno));
        return;
    }

    let (bytes, priority) = match mqueuefs::receive(id, msg_len) {
        Ok(message) => message,
        Err(narf_filesystem::MqueueError::WouldBlock) => {
            park_would_block(ctx, id, a.arg4);
            return;
        }
        Err(error) => {
            ctx.set_return(err(mq_errno(error)));
            return;
        }
    };

    // SAFETY: msg_ptr is the user receive buffer; copy_to_user range-validates
    // and SMAP-brackets the write of the message payload.
    if unsafe { crate::handlers::copy_to_user(msg_ptr, &bytes) }.is_err() {
        ctx.set_return(err(EFAULT));
        return;
    }
    if prio_ptr != 0 {
        // SAFETY: prio_ptr is a user u32 out-pointer; copy_to_user validates it.
        if unsafe { crate::handlers::copy_to_user(prio_ptr, &priority.to_le_bytes()) }.is_err() {
            ctx.set_return(err(EFAULT));
            return;
        }
    }
    narf_net::readiness::notify(0);
    ctx.set_return(SyscallReturn::ok(bytes.len() as u64));
}

/// `mq_getsetattr(mqd, newattr_ptr, oldattr_ptr)`.
pub fn sys_mq_getsetattr(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let task = current_task_id();
    let id = match queue_id_of(task, a.arg0 as u32) {
        Some(id) => id,
        None => {
            ctx.set_return(err(EBADF));
            return;
        }
    };
    let new_ptr = a.arg1;
    let old_ptr = a.arg2;

    let new_flags = if new_ptr != 0 {
        let mut buf = [0u8; 64];
        // SAFETY: new_ptr non-zero; copy_from_user validates + SMAP-brackets the read.
        if unsafe { crate::handlers::copy_from_user(&mut buf, new_ptr) }.is_err() {
            ctx.set_return(err(EFAULT));
            return;
        }
        let flags = read_i64(&buf[0..8]);
        if flags & !(O_NONBLOCK as i64) != 0 {
            ctx.set_return(err(EINVAL));
            return;
        }
        Some(flags)
    } else {
        None
    };

    let attr = match mqueuefs::attributes(id) {
        Ok(attr) => attr,
        Err(error) => {
            ctx.set_return(err(mq_errno(error)));
            return;
        }
    };

    if old_ptr != 0 {
        let mut out = [0u8; 64];
        out[0..8].copy_from_slice(&attr.flags.to_le_bytes());
        out[8..16].copy_from_slice(&attr.maxmsg.to_le_bytes());
        out[16..24].copy_from_slice(&attr.msgsize.to_le_bytes());
        out[24..32].copy_from_slice(&attr.curmsgs.to_le_bytes());
        // SAFETY: old_ptr is the user struct mq_attr out-pointer; validated by copy_to_user.
        if unsafe { crate::handlers::copy_to_user(old_ptr, &out) }.is_err() {
            ctx.set_return(err(EFAULT));
            return;
        }
    }
    if let Some(flags) = new_flags {
        if let Err(error) = mqueuefs::set_nonblock(id, flags & O_NONBLOCK as i64 != 0) {
            ctx.set_return(err(mq_errno(error)));
            return;
        }
        let _ = fd::with_table(task, |table| {
            if let Some(entry) = table.get_mut(a.arg0 as u32) {
                entry.status_flags = (entry.status_flags & !fd::O_NONBLOCK)
                    | if flags & O_NONBLOCK as i64 != 0 {
                        fd::O_NONBLOCK
                    } else {
                        0
                    };
            }
        });
    }
    ctx.set_return(SyscallReturn::ok(0));
}

// ════════════════════════════════════════════════════════════════════
// inotify
// ════════════════════════════════════════════════════════════════════

// inotify event mask bits (subset; see <sys/inotify.h>).
pub(crate) const IN_MODIFY: u32 = 0x0000_0002;
pub(crate) const IN_ATTRIB: u32 = 0x0000_0004;
pub(crate) const IN_CLOSE_WRITE: u32 = 0x0000_0008;
pub(crate) const IN_OPEN: u32 = 0x0000_0020;
pub(crate) const IN_MOVED_FROM: u32 = 0x0000_0040;
pub(crate) const IN_MOVED_TO: u32 = 0x0000_0080;
pub(crate) const IN_CREATE: u32 = 0x0000_0100;
pub(crate) const IN_DELETE: u32 = 0x0000_0200;
const IN_ISDIR: u32 = 0x4000_0000;

/// One registered watch: the absolute path it covers and the mask of
/// events the caller asked to be told about.
struct Watch {
    path: String,
    mask: u32,
}

struct InotifyState {
    next_wd: i32,
    watches: BTreeMap<i32, Watch>,
    /// Pre-serialized `struct inotify_event` records awaiting read(2).
    events: VecDeque<Vec<u8>>,
    /// Monotonic cookie source for pairing IN_MOVED_FROM/IN_MOVED_TO.
    next_cookie: u32,
    /// Empty-to-nonempty generation used by edge-triggered epoll.
    readable_token: u64,
}

impl InotifyState {
    fn enqueue(&mut self, event: Vec<u8>) {
        if self.events.is_empty() {
            self.readable_token = self.readable_token.wrapping_add(1);
        }
        self.events.push_back(event);
    }
}

static INOTIFY: IrqSafeSpinLock<Option<BTreeMap<u64, InotifyState>>> = IrqSafeSpinLock::new(None);
static INOTIFY_NEXT_ID: AtomicU64 = AtomicU64::new(1);

fn with_inotify<R>(f: impl FnOnce(&mut BTreeMap<u64, InotifyState>) -> R) -> R {
    let mut g = INOTIFY.lock();
    f(g.get_or_insert_with(BTreeMap::new))
}

// ── fd → path side table ────────────────────────────────────────────
// The fd table stores only an `Arc<dyn FileOps>`, so sys_write (which has
// just an fd) can't recover the file's path to fire IN_MODIFY. We record
// (task, fd) → absolute path at open and consult it on write; close drops
// the entry. The path is part of descriptor identity, so every duplication
// path preserves it as well; *at syscalls also rely on it for directory fds.
type FdPathIdentity = (String, Option<u64>);
static FD_PATHS: IrqSafeSpinLock<Option<BTreeMap<(u64, u32), FdPathIdentity>>> =
    IrqSafeSpinLock::new(None);

fn with_fd_paths<R>(f: impl FnOnce(&mut BTreeMap<(u64, u32), FdPathIdentity>) -> R) -> R {
    let mut g = FD_PATHS.lock();
    f(g.get_or_insert_with(BTreeMap::new))
}

/// Record the absolute path an fd was opened on (for later IN_MODIFY).
pub(crate) fn register_fd_path(task: u64, fd: u32, path: &str, mount_id: Option<u64>) {
    with_fd_paths(|m| {
        m.insert((task, fd), (String::from(path), mount_id));
    });
}

/// Drop an fd → path mapping on close.
pub(crate) fn forget_fd_path(task: u64, fd: u32) {
    with_fd_paths(|m| {
        m.remove(&(task, fd));
    });
}

/// Duplicate (or replace) a descriptor's pathname identity.
///
/// `dup2`/`dup3` may replace an existing destination, so an untracked source
/// must explicitly clear any former identity at the destination.
pub(crate) fn duplicate_fd_path(task: u64, source_fd: u32, destination_fd: u32) {
    with_fd_paths(|m| {
        if let Some(identity) = m.get(&(task, source_fd)).cloned() {
            m.insert((task, destination_fd), identity);
        } else {
            m.remove(&(task, destination_fd));
        }
    });
}

/// Look up the absolute path an fd was opened on, if recorded. Used by
/// `landlock_add_rule` to turn a `parent_fd` back into a path.
pub(crate) fn fd_path(task: u64, fd: u32) -> Option<String> {
    with_fd_paths(|m| m.get(&(task, fd)).map(|(path, _)| path.clone()))
}

/// Mount that was visible when `fd` was opened.
pub(crate) fn fd_mount_id(task: u64, fd: u32) -> Option<u64> {
    with_fd_paths(|m| m.get(&(task, fd)).and_then(|(_, id)| *id))
}

/// Copy fd-path identities along with the descriptor table during fork/clone.
/// The table is task-keyed even when CLONE_FILES shares the underlying file
/// descriptions, because proc-fd lookups and *at syscalls resolve through the
/// calling task.  Without this, a forked systemd mount helper inherited a
/// valid O_PATH parent fd but `mkdirat(parent_fd, ...)` saw EBADF.
pub(crate) fn fork_fd_paths(parent: u64, child: u64) {
    let inherited: Vec<(u32, FdPathIdentity)> = with_fd_paths(|m| {
        m.iter()
            .filter(|&(&(task, _), _)| task == parent)
            .map(|(&(_, fd), identity)| (fd, identity.clone()))
            .collect()
    });
    with_fd_paths(|m| {
        m.retain(|&(task, _), _| task != child);
        for (fd, identity) in inherited {
            m.insert((child, fd), identity);
        }
    });
}

fn parent_and_base(abs: &str) -> (&str, &str) {
    match abs.rfind('/') {
        Some(0) => ("/", &abs[1..]),
        Some(i) => (&abs[..i], &abs[i + 1..]),
        None => ("", abs),
    }
}

/// Serialize one `struct inotify_event` (16-byte header + padded name).
fn serialize_event(wd: i32, mask: u32, cookie: u32, name: &str) -> Vec<u8> {
    // Name field is NUL-terminated and padded so the record length is a
    // multiple of sizeof(struct inotify_event) = 16 (Linux's `len`).
    let name_len = if name.is_empty() {
        0
    } else {
        (name.len() + 1).div_ceil(16) * 16
    };
    let mut buf = Vec::with_capacity(16 + name_len);
    buf.extend_from_slice(&wd.to_ne_bytes());
    buf.extend_from_slice(&mask.to_ne_bytes());
    buf.extend_from_slice(&cookie.to_ne_bytes());
    buf.extend_from_slice(&(name_len as u32).to_ne_bytes());
    if name_len > 0 {
        buf.extend_from_slice(name.as_bytes());
        buf.resize(16 + name_len, 0);
    }
    buf
}

/// Central filesystem-change dispatch. Called from the syscall handlers
/// after a successful mutation; fans out to both the inotify and fanotify
/// notification groups. The mask bits for the events we deliver
/// (MODIFY/CLOSE_WRITE/OPEN/MOVED/CREATE/DELETE) are numerically identical
/// between the two ABIs, so one `mask` drives both.
fn fs_notify(abs_path: &str, mask: u32, is_dir: bool) {
    inotify_dispatch(abs_path, mask, is_dir);
    fanotify_dispatch(abs_path, mask as u64);
    // Filesystem event fds participate in poll/epoll. Publishing after both
    // queues are updated avoids a check-before-park waiter sleeping until the
    // periodic backstop despite an event already being available.
    narf_net::readiness::notify(0);
}

/// inotify half of [`fs_notify`]: for every instance, every watch whose
/// mask includes `mask` and whose path is the object itself (no name) or
/// its parent directory (name = leaf) gets a serialized event queued.
fn inotify_dispatch(abs_path: &str, mask: u32, is_dir: bool) {
    // Cheap early-out: nothing watching → nothing to do.
    {
        let g = INOTIFY.lock();
        match g.as_ref() {
            Some(m) if !m.is_empty() => {}
            _ => return,
        }
    }
    let full_mask = if is_dir { mask | IN_ISDIR } else { mask };
    let (parent, base) = parent_and_base(abs_path);
    with_inotify(|m| {
        for st in m.values_mut() {
            let cookie = 0u32;
            let matched: Vec<(i32, &'static str, bool)> = st
                .watches
                .iter()
                .filter_map(|(wd, w)| {
                    if w.mask & mask == 0 {
                        None
                    } else if w.path == abs_path {
                        Some((*wd, "", false)) // watch on the object: no name
                    } else if w.path == parent {
                        Some((*wd, "", true)) // watch on the parent: name = base
                    } else {
                        None
                    }
                })
                .collect();
            for (wd, _, use_base) in matched {
                let name = if use_base { base } else { "" };
                st.enqueue(serialize_event(wd, full_mask, cookie, name));
            }
        }
    });
}

/// IN_CREATE on `abs_path` (a newly created file or, with `is_dir`, dir).
pub(crate) fn notify_create(abs_path: &str, is_dir: bool) {
    fs_notify(abs_path, IN_CREATE, is_dir);
}

/// IN_DELETE on `abs_path`.
pub(crate) fn notify_delete(abs_path: &str, is_dir: bool) {
    fs_notify(abs_path, IN_DELETE, is_dir);
}

/// IN_OPEN on `abs_path`.
pub(crate) fn notify_open(abs_path: &str) {
    fs_notify(abs_path, IN_OPEN, false);
}

/// IN_ATTRIB on `abs_path` — metadata changed (chmod/chown/utimes). Used
/// for a path we can name directly (not via an fd).
pub(crate) fn notify_attrib(abs_path: &str, is_dir: bool) {
    fs_notify(abs_path, IN_ATTRIB, is_dir);
}

/// IN_ATTRIB for the file behind `fd` (fchmod/fchown/futimens), looked up
/// via the fd → path table.
pub(crate) fn notify_attrib_fd(task: u64, fd: u32) {
    let path = fd_path(task, fd);
    if let Some(p) = path {
        fs_notify(&p, IN_ATTRIB, false);
    }
}

/// IN_MODIFY on `abs_path` — content changed via a path-keyed call
/// (truncate(2)) with no fd to consult.
pub fn notify_modify_path(abs_path: &str) {
    fs_notify(abs_path, IN_MODIFY, false);
}

/// IN_MODIFY for the file behind `fd`, looked up via the fd → path table.
pub(crate) fn notify_modify_fd(task: u64, fd: u32) {
    let path = fd_path(task, fd);
    if let Some(p) = path {
        fs_notify(&p, IN_MODIFY, false);
    }
}

/// IN_CLOSE_WRITE for the file behind `fd`.
pub(crate) fn notify_close_fd(task: u64, fd: u32) {
    if let Some(handle_id) = queue_id_of(task, fd) {
        mqueuefs::close_notification(handle_id, task);
    }
    let path = fd_path(task, fd);
    if let Some(p) = path {
        fs_notify(&p, IN_CLOSE_WRITE, false);
    }
}

/// Paired IN_MOVED_FROM/IN_MOVED_TO sharing a cookie, for a rename.
pub(crate) fn notify_moved(from: &str, to: &str) {
    // Allocate one cookie per rename and stamp both legs with it.
    let (fp, fb) = parent_and_base(from);
    let (tp, tb) = parent_and_base(to);
    with_inotify(|m| {
        for st in m.values_mut() {
            let cookie = st.next_cookie.wrapping_add(1);
            st.next_cookie = cookie;
            let from_hits: Vec<(i32, bool)> = st
                .watches
                .iter()
                .filter_map(|(wd, w)| {
                    if w.mask & IN_MOVED_FROM == 0 {
                        None
                    } else if w.path == from {
                        Some((*wd, false))
                    } else if w.path == fp {
                        Some((*wd, true))
                    } else {
                        None
                    }
                })
                .collect();
            for (wd, use_base) in from_hits {
                let name = if use_base { fb } else { "" };
                st.enqueue(serialize_event(wd, IN_MOVED_FROM, cookie, name));
            }
            let to_hits: Vec<(i32, bool)> = st
                .watches
                .iter()
                .filter_map(|(wd, w)| {
                    if w.mask & IN_MOVED_TO == 0 {
                        None
                    } else if w.path == to {
                        Some((*wd, false))
                    } else if w.path == tp {
                        Some((*wd, true))
                    } else {
                        None
                    }
                })
                .collect();
            for (wd, use_base) in to_hits {
                let name = if use_base { tb } else { "" };
                st.enqueue(serialize_event(wd, IN_MOVED_TO, cookie, name));
            }
        }
    });
    // fanotify sees the same move as two events on the affected objects.
    fanotify_dispatch(from, IN_MOVED_FROM as u64);
    fanotify_dispatch(to, IN_MOVED_TO as u64);
    narf_net::readiness::notify(0);
}

struct InotifyFile {
    id: u64,
}

impl FileOps for InotifyFile {
    /// Readable ONLY when events are queued (an inotify fd is never
    /// writable and has no EOF). Without this override the always-ready
    /// default (POLL_IN|POLL_OUT) makes an epoll-driven consumer busy-spin:
    /// epoll reports ready, read() returns 0 (no events), loop — which
    /// wedged dbus-daemon watching its config dirs and stalled the whole
    /// Plasma session bus.
    fn poll_readiness(&self) -> u32 {
        let has_events = with_inotify(|m| {
            m.get(&self.id)
                .map(|s| !s.events.is_empty())
                .unwrap_or(false)
        });
        if has_events {
            narf_filesystem::POLL_IN
        } else {
            0
        }
    }

    fn poll_edge_token(&self) -> (u64, u64) {
        (
            with_inotify(|m| m.get(&self.id).map(|s| s.readable_token).unwrap_or(0)),
            0,
        )
    }

    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let id = self.id;
        Box::pin(async move {
            // Drain whole events that fit; inotify never returns a partial
            // event. If the first queued event is larger than the buffer,
            // Linux returns EINVAL — mirror that.
            with_inotify(|m| {
                let st = match m.get_mut(&id) {
                    Some(s) => s,
                    None => return Ok(0),
                };
                let mut written = 0usize;
                while let Some(front) = st.events.front() {
                    if written == 0 && front.len() > buf.len() {
                        return Err(FsError::InvalidData);
                    }
                    if written + front.len() > buf.len() {
                        break;
                    }
                    let ev = st.events.pop_front().unwrap();
                    buf[written..written + ev.len()].copy_from_slice(&ev);
                    written += ev.len();
                }
                if written == 0 {
                    // inotify has no end-of-file: an empty queue is
                    // would-block (Linux fs/notify/inotify/inotify_user.c
                    // returns -EAGAIN). A 0 here made an epoll loop spin —
                    // epoll says ready, read says "closed", repeat.
                    return Err(FsError::WouldBlock);
                }
                Ok(written)
            })
        })
    }
    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::InvalidData) })
    }
    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode::FILE_RW,
            mtime_cycles: 0,
        }
    }
    fn inotify_instance(&self) -> Option<u64> {
        Some(self.id)
    }
}

fn instance_of(task: u64, fd_no: u32) -> Option<u64> {
    fd::with_table(task, |t| {
        t.get(fd_no).and_then(|e| e.ops.inotify_instance())
    })
    .flatten()
}

const IN_NONBLOCK: u64 = 0o4000;
const IN_CLOEXEC: u64 = 0o2000000;

/// `inotify_init1(flags)`.
pub fn sys_inotify_init1(ctx: &mut dyn TrapContext) {
    let flags = ctx.args().arg0;
    inotify_init_common(ctx, flags)
}

/// Legacy `inotify_init(void)` — x86_64 253. The ABI has NO flags
/// argument, so arg0 is whatever the caller left in the register and
/// must not be read: a stale IN_NONBLOCK bit would make every read on
/// the new fd spuriously EAGAIN.
pub fn sys_inotify_init_no_flags(ctx: &mut dyn TrapContext) {
    inotify_init_common(ctx, 0)
}

fn inotify_init_common(ctx: &mut dyn TrapContext, flags: u64) {
    let id = INOTIFY_NEXT_ID.fetch_add(1, Ordering::Relaxed);
    with_inotify(|m| {
        m.insert(
            id,
            InotifyState {
                next_wd: 1,
                watches: BTreeMap::new(),
                events: VecDeque::new(),
                next_cookie: 0,
                readable_token: 0,
            },
        )
    });
    let file: Arc<dyn FileOps> = Arc::new(InotifyFile { id });
    let cloexec = if flags & IN_CLOEXEC != 0 {
        fd::FD_CLOEXEC
    } else {
        0
    };
    let status = if flags & IN_NONBLOCK != 0 {
        fd::O_NONBLOCK
    } else {
        0
    };
    match task_open_call(task_open(file, cloexec, status)) {
        Some(n) => ctx.set_return(SyscallReturn::ok(n as u64)),
        None => ctx.set_return(err(EBADF)),
    }
}

/// `inotify_add_watch(fd, path, mask)`.
pub fn sys_inotify_add_watch(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let task = current_task_id();
    let id = match instance_of(task, a.arg0 as u32) {
        Some(id) => id,
        None => {
            ctx.set_return(err(EBADF));
            return;
        }
    };
    let path = match copy_user_cstr(a.arg1, 4096) {
        Some(p) if !p.is_empty() => p,
        _ => {
            ctx.set_return(err(EINVAL));
            return;
        }
    };
    let mask = a.arg2 as u32;
    let wd = with_inotify(|m| {
        let st = m.get_mut(&id)?;
        // Re-adding an already-watched path returns the existing wd and
        // refreshes its mask (Linux replaces the mask unless IN_MASK_ADD).
        if let Some((wd, w)) = st.watches.iter_mut().find(|(_, w)| w.path == path) {
            w.mask = mask;
            return Some(*wd);
        }
        let wd = st.next_wd;
        st.next_wd = st.next_wd.wrapping_add(1);
        st.watches.insert(wd, Watch { path, mask });
        Some(wd)
    });
    match wd {
        Some(wd) => ctx.set_return(SyscallReturn::ok(wd as u64)),
        None => ctx.set_return(err(EBADF)),
    }
}

/// `inotify_rm_watch(fd, wd)`.
pub fn sys_inotify_rm_watch(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let task = current_task_id();
    let id = match instance_of(task, a.arg0 as u32) {
        Some(id) => id,
        None => {
            ctx.set_return(err(EBADF));
            return;
        }
    };
    let wd = a.arg1 as i32;
    let removed = with_inotify(|m| m.get_mut(&id).map(|st| st.watches.remove(&wd).is_some()));
    match removed {
        Some(true) => ctx.set_return(SyscallReturn::ok(0)),
        Some(false) => ctx.set_return(err(EINVAL)),
        None => ctx.set_return(err(EBADF)),
    }
}

// ════════════════════════════════════════════════════════════════════
// fanotify
// ════════════════════════════════════════════════════════════════════
//
// A fanotify group is an fd-backed notification queue, like inotify, but
// its events are fixed 24-byte `struct fanotify_event_metadata` records
// that each carry an OPEN fd to the affected object (the default
// FAN_CLASS_NOTIF behaviour). Marks live on absolute paths; when fs_notify
// fires, every group with a matching inode mark queues an event. At read
// time we resolve the stored path, install a fresh fd in the reading
// task's table, and hand its number back in the metadata — the reader
// owns and must close it, exactly as on Linux.
//
// The event mask bits we deliver (FAN_MODIFY/FAN_CLOSE_WRITE/FAN_OPEN/
// FAN_MOVED_*/FAN_CREATE/FAN_DELETE) are numerically equal to the matching
// IN_* bits, so the shared fs_notify mask drives both subsystems.

// fanotify_init flags.
const FAN_CLOEXEC: u64 = 0x0000_0001;
const FAN_NONBLOCK: u64 = 0x0000_0002;
// fanotify_mark flags.
const FAN_MARK_ADD: u64 = 0x0000_0001;
const FAN_MARK_REMOVE: u64 = 0x0000_0002;
const FAN_MARK_FLUSH: u64 = 0x0000_0080;
/// `struct fanotify_event_metadata` is a fixed 24 bytes.
pub(crate) const FAN_EVENT_METADATA_LEN: usize = 24;
const FANOTIFY_METADATA_VERSION: u8 = 3;

struct FanGroup {
    /// Absolute path → mark mask (inode marks only).
    marks: BTreeMap<String, u64>,
    /// Queued events: (affected path, event mask, causing pid).
    events: VecDeque<(String, u64, i32)>,
}

static FANOTIFY: IrqSafeSpinLock<Option<BTreeMap<u64, FanGroup>>> = IrqSafeSpinLock::new(None);
static FANOTIFY_NEXT_ID: AtomicU64 = AtomicU64::new(1);
/// Set once any fanotify group exists; lets the fs_notify dispatch and
/// sys_read skip fanotify work entirely on the common path.
static FANOTIFY_ACTIVE: AtomicBool = AtomicBool::new(false);

fn with_fanotify<R>(f: impl FnOnce(&mut BTreeMap<u64, FanGroup>) -> R) -> R {
    let mut g = FANOTIFY.lock();
    f(g.get_or_insert_with(BTreeMap::new))
}

/// fanotify half of [`fs_notify`]: queue an event on every group holding
/// an inode mark for `abs_path` whose mark mask intersects the event.
fn fanotify_dispatch(abs_path: &str, mask: u64) {
    if !FANOTIFY_ACTIVE.load(Ordering::Relaxed) {
        return;
    }
    let pid = current_task_id() as i32;
    with_fanotify(|m| {
        for group in m.values_mut() {
            if let Some(&mark_mask) = group.marks.get(abs_path) {
                let hit = mark_mask & mask;
                if hit != 0 {
                    group.events.push_back((String::from(abs_path), hit, pid));
                }
            }
        }
    });
}

struct FanotifyFile {
    id: u64,
}

impl FileOps for FanotifyFile {
    fn poll_readiness(&self) -> u32 {
        let has_events = with_fanotify(|m| {
            m.get(&self.id)
                .map(|group| !group.events.is_empty())
                .unwrap_or(false)
        });
        if has_events {
            narf_filesystem::POLL_IN
        } else {
            0
        }
    }

    fn nonblock_read_eagain(&self) -> bool {
        true
    }

    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        // fanotify delivery installs an fd per event, which needs the
        // fd-table lock — and the generic sys_read holds that lock across
        // this call. So reads on a fanotify fd are intercepted up front in
        // sys_read (see `fanotify_read_into`), never reaching here. This
        // path is only hit by other read entry points; surface 0 (no
        // events delivered) rather than risk the re-entrant lock.
        let _ = buf;
        // No events queued is would-block, not EOF. When events ARE queued
        // this still reports 0: delivery needs an fd installed per event and
        // that path lives in sys_read. Pre-existing limitation, narrowed here
        // to the case where it cannot mislead.
        let id = self.id;
        let empty = with_fanotify(|m| {
            m.get(&id)
                .map(|group| group.events.is_empty())
                .unwrap_or(false)
        });
        Box::pin(async move {
            if empty {
                Err(FsError::WouldBlock)
            } else {
                Ok(0)
            }
        })
    }
    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        // Writing to a fanotify fd issues access-permission responses,
        // which NARF's notify-class groups don't use.
        Box::pin(async { Err(FsError::InvalidData) })
    }
    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode::FILE_RW,
            mtime_cycles: 0,
        }
    }
    fn fanotify_instance(&self) -> Option<u64> {
        Some(self.id)
    }
}

/// Pop up to `max` queued events from a fanotify group as
/// `(path, mask, pid)` tuples, WITHOUT opening fds — the caller
/// (`sys_read`) installs the per-event fds once the fd-table lock is free.
pub(crate) fn fanotify_drain(group_id: u64, max: usize) -> Vec<(String, u64, i32)> {
    let mut out = Vec::new();
    with_fanotify(|m| {
        if let Some(g) = m.get_mut(&group_id) {
            for _ in 0..max {
                match g.events.pop_front() {
                    Some(e) => out.push(e),
                    None => break,
                }
            }
        }
    });
    out
}

/// True once any fanotify group has been created — a cheap guard so
/// sys_read skips the fd-table probe on the common (no-fanotify) path.
pub(crate) fn fanotify_active() -> bool {
    FANOTIFY_ACTIVE.load(Ordering::Relaxed)
}

/// Map an fd to its fanotify group id, if it is one.
pub(crate) fn fanotify_instance_of(task: u64, fd_no: u32) -> Option<u64> {
    fd::with_table(task, |t| {
        t.get(fd_no).and_then(|e| e.ops.fanotify_instance())
    })
    .flatten()
}

/// Serialize one `struct fanotify_event_metadata` (24 bytes).
pub(crate) fn build_fan_metadata(mask: u64, fd: i32, pid: i32) -> [u8; FAN_EVENT_METADATA_LEN] {
    let mut meta = [0u8; FAN_EVENT_METADATA_LEN];
    meta[0..4].copy_from_slice(&(FAN_EVENT_METADATA_LEN as u32).to_ne_bytes());
    meta[4] = FANOTIFY_METADATA_VERSION;
    meta[5] = 0; // reserved
    meta[6..8].copy_from_slice(&(FAN_EVENT_METADATA_LEN as u16).to_ne_bytes());
    meta[8..16].copy_from_slice(&mask.to_ne_bytes());
    meta[16..20].copy_from_slice(&fd.to_ne_bytes());
    meta[20..24].copy_from_slice(&pid.to_ne_bytes());
    meta
}

/// `fanotify_init(flags, event_f_flags)` → group fd.
pub fn sys_fanotify_init(ctx: &mut dyn TrapContext) {
    let flags = ctx.args().arg0;
    let id = FANOTIFY_NEXT_ID.fetch_add(1, Ordering::Relaxed);
    FANOTIFY_ACTIVE.store(true, Ordering::Relaxed);
    with_fanotify(|m| {
        m.insert(
            id,
            FanGroup {
                marks: BTreeMap::new(),
                events: VecDeque::new(),
            },
        )
    });
    let file: Arc<dyn FileOps> = Arc::new(FanotifyFile { id });
    let cloexec = if flags & FAN_CLOEXEC != 0 {
        fd::FD_CLOEXEC
    } else {
        0
    };
    let status = if flags & FAN_NONBLOCK != 0 {
        fd::O_NONBLOCK
    } else {
        0
    };
    match task_open_call(task_open(file, cloexec, status)) {
        Some(n) => ctx.set_return(SyscallReturn::ok(n as u64)),
        None => ctx.set_return(err(EBADF)),
    }
}

/// `fanotify_mark(fanotify_fd, flags, mask, dirfd, pathname)`.
pub fn sys_fanotify_mark(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let task = current_task_id();
    let id = match fanotify_instance_of(task, a.arg0 as u32) {
        Some(id) => id,
        None => {
            ctx.set_return(err(EBADF));
            return;
        }
    };
    let flags = a.arg1;
    let mask = a.arg2;
    // dirfd (arg3) is ignored — NARF resolves absolute paths / AT_FDCWD.
    if flags & FAN_MARK_FLUSH != 0 {
        with_fanotify(|m| {
            if let Some(g) = m.get_mut(&id) {
                g.marks.clear();
            }
        });
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    let path = match copy_user_cstr(a.arg4, 4096) {
        Some(p) if !p.is_empty() => p,
        _ => {
            ctx.set_return(err(EINVAL));
            return;
        }
    };
    let r = with_fanotify(|m| {
        let g = m.get_mut(&id)?;
        if flags & FAN_MARK_ADD != 0 {
            let e = g.marks.entry(path).or_insert(0);
            *e |= mask;
            Some(true)
        } else if flags & FAN_MARK_REMOVE != 0 {
            if let Some(cur) = g.marks.get_mut(&path) {
                *cur &= !mask;
                if *cur == 0 {
                    g.marks.remove(&path);
                }
                Some(true)
            } else {
                Some(false)
            }
        } else {
            // Neither ADD nor REMOVE nor FLUSH set.
            Some(false)
        }
    });
    match r {
        Some(true) => ctx.set_return(SyscallReturn::ok(0)),
        Some(false) => ctx.set_return(err(EINVAL)),
        None => ctx.set_return(err(EBADF)),
    }
}
