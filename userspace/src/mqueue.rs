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
use crate::handlers::{copy_user_cstr, copy_user_cstr_checked, current_task_id};
use crate::syscall::{SyscallReturn, TrapContext};

use crate::errno::{to_ret as err, *};

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

fn read_i64(buf: &[u8]) -> i64 {
    i64::from_le_bytes(buf[..8].try_into().unwrap())
}

fn namespace_id(task: u64) -> u64 {
    #[cfg(feature = "container")]
    {
        crate::namespaces::current_ipc_namespace(task).id()
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
            // Keep the signalfd park guard's snapshot fresh on this net_io_wait
            // park too (see UserTaskCtx::signal_park_gen); without it a signal
            // pending during an mq wait would trip the guard's stale-generation
            // compare and spin.
            user.signal_park_gen.store(
                crate::handlers::signal_raise_generation(crate::handlers::current_task_id()),
                Ordering::Release,
            );
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
    match task_open_call(task_open(file, fd::FD_CLOEXEC, status_flags)).flatten() {
        Some(n) => ctx.set_return(SyscallReturn::ok(n as u64)),
        // `do_mq_open` allocates the descriptor with `get_unused_fd_flags`,
        // so an exhausted table is -EMFILE.
        None => ctx.set_return(err(EMFILE)),
    }
}

/// Helper bundling the closure for `fd::with_table` open — keeps the
/// borrow of `task` short and the call sites readable.
fn task_open(
    file: Arc<dyn FileOps>,
    flags: u32,
    status_flags: u32,
) -> impl FnOnce(&mut fd::FdTable) -> Option<u32> {
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
            let descriptor = a.arg0 as u32;
            let old = table.status_flags(descriptor)?;
            table.set_status_flags(
                descriptor,
                (old & !fd::O_NONBLOCK)
                    | if flags & O_NONBLOCK as i64 != 0 {
                        fd::O_NONBLOCK
                    } else {
                        0
                    },
            )
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
    /// True while an `IN_Q_OVERFLOW` record sits in `events`. Linux tracks
    /// this by testing whether its single pre-allocated overflow event is
    /// still linked; the effect is the same — at most one overflow record is
    /// outstanding, however many events are dropped behind it.
    overflow_queued: bool,
    /// Durable per-fd readiness cell (see `narf_lib::readiness`) — the SOLE
    /// readiness mechanism (there is no edge token). An inotify fd is read-only
    /// and never EOFs, so the cell only ever carries POLL_IN: `set`+`notify` when
    /// an event is queued (the produce sites, `inotify_dispatch`/`notify_moved`)
    /// — `notify` fires the wait-queue on EVERY event so an EPOLLET consumer
    /// re-fires even at the same readable level — and cleared by the read that
    /// drains the queue (the consume site). It lives behind the global `INOTIFY`
    /// lock, so — like the lock-guarded ring cells in `socket.rs` — `InotifyFile`
    /// reaches it by cloning this `Arc` out UNDER that lock and arming/`set`ting
    /// OFF it (the cell has its own lock; never nest it under `INOTIFY`).
    readiness: Arc<narf_lib::readiness::Readiness>,
}

/// `IN_Q_OVERFLOW` — the queue overflowed and events were lost.
const IN_Q_OVERFLOW: u32 = 0x0000_4000;

/// The watch descriptor Linux reports on an overflow record: it belongs to no
/// watch.
const OVERFLOW_WD: i32 = -1;

impl InotifyState {
    /// Queue one event, honouring `fs.inotify.max_queued_events`.
    ///
    /// The queue used to be unbounded, so the knob capped nothing and a
    /// watched directory under churn could grow it without limit while the
    /// reader was away. Linux drops the event at the ceiling and queues a
    /// single `IN_Q_OVERFLOW` in its place, which is how a reader learns its
    /// stream has a hole in it.
    ///
    /// Linux ref: `fsnotify_add_event()` in fs/notify/notification.c.
    fn enqueue(&mut self, event: Vec<u8>) {
        let max = narf_filesystem::procfs::sys_fs::inotify_max_queued_events();
        if self.events.len() >= max {
            if !self.overflow_queued {
                self.events
                    .push_back(serialize_event(OVERFLOW_WD, IN_Q_OVERFLOW, 0, ""));
                self.overflow_queued = true;
            }
            return;
        }
        self.events.push_back(event);
    }

    /// True iff `record` is the overflow marker, by its watch descriptor.
    fn is_overflow(record: &[u8]) -> bool {
        record.len() >= 4
            && i32::from_ne_bytes([record[0], record[1], record[2], record[3]]) == OVERFLOW_WD
    }
}

/// Republish an inotify instance's durable readiness after its event queue
/// changed occupancy: POLL_IN iff events remain, else clear it. Snapshots the
/// occupancy and clones the cell UNDER the `INOTIFY` lock, then `set`s OFF the
/// lock — the cell has its own lock and must never be nested under `INOTIFY`.
/// A no-op if the instance has been torn down. Called on the read that drains
/// the queue (the consume site); the produce sites (`inotify_dispatch`,
/// `notify_moved`) publish the rising POLL_IN edge inline once they have
/// enqueued, since a dispatch only ever adds events.
fn sync_inotify_readiness(id: u64) {
    let snapshot = with_inotify(|m| {
        m.get(&id)
            .map(|st| (st.readiness.clone(), !st.events.is_empty()))
    });
    if let Some((cell, has_events)) = snapshot {
        if has_events {
            cell.set(narf_filesystem::POLL_IN, 0);
        } else {
            cell.set(0, narf_filesystem::POLL_IN);
        }
    }
}

static INOTIFY: IrqSafeSpinLock<Option<BTreeMap<u64, InotifyState>>> = IrqSafeSpinLock::new(None);
static INOTIFY_NEXT_ID: AtomicU64 = AtomicU64::new(1);
/// Set once an inotify instance exists. Like Linux's fsnotify static-key
/// bypass, this keeps ordinary filesystem mutations off the notification
/// machinery until a consumer has actually requested it.
static INOTIFY_ACTIVE: AtomicBool = AtomicBool::new(false);

fn with_inotify<R>(f: impl FnOnce(&mut BTreeMap<u64, InotifyState>) -> R) -> R {
    let mut g = INOTIFY.lock();
    f(g.get_or_insert_with(BTreeMap::new))
}

// ── fd → path side table ────────────────────────────────────────────
// The fd table stores only an `Arc<dyn FileOps>`, so sys_write (which has
// just an fd) can't recover the file's path to fire IN_MODIFY. We record
// task → fd-indexed absolute paths at open and consult it on write; close
// clears the reusable slot. The path is part of descriptor identity, so every
// duplication path preserves it as well; *at syscalls also rely on it for
// directory fds. An fd-indexed vector mirrors FdTable: a hot open/close loop
// reuses slot 3 instead of allocating and freeing a B-tree node every time.
type FdPathIdentity = (String, Option<u64>);
type FdPathSlots = Vec<Option<FdPathIdentity>>;
type FdPathTasks = BTreeMap<u64, FdPathSlots>;
const FD_PATH_SHARDS: usize = 32;

#[repr(align(64))]
struct FdPathShard {
    paths: IrqSafeSpinLock<Option<FdPathTasks>>,
}

impl FdPathShard {
    const fn new() -> Self {
        Self {
            paths: IrqSafeSpinLock::new(None),
        }
    }
}

static FD_PATHS: [FdPathShard; FD_PATH_SHARDS] = [const { FdPathShard::new() }; FD_PATH_SHARDS];

#[inline]
fn fd_path_shard(task: u64) -> usize {
    (task as usize) & (FD_PATH_SHARDS - 1)
}

fn with_fd_paths<R>(task: u64, f: impl FnOnce(&mut FdPathTasks) -> R) -> R {
    let mut g = FD_PATHS[fd_path_shard(task)].paths.lock();
    f(g.get_or_insert_with(BTreeMap::new))
}

/// Record the absolute path an fd was opened on (for later IN_MODIFY).
pub(crate) fn register_fd_path(task: u64, fd: u32, path: &str, mount_id: Option<u64>) {
    register_fd_path_owned(task, fd, String::from(path), mount_id);
}

/// Owned counterpart for open paths that no longer need their normalized
/// pathname after registration.
pub(crate) fn register_fd_path_owned(task: u64, fd: u32, path: String, mount_id: Option<u64>) {
    with_fd_paths(task, |m| {
        let slots = m.entry(task).or_default();
        let index = fd as usize;
        if slots.len() <= index {
            slots.resize_with(index + 1, || None);
        }
        slots[index] = Some((path, mount_id));
    });
}

/// Drop an fd → path mapping on close.
pub(crate) fn forget_fd_path(task: u64, fd: u32) {
    with_fd_paths(task, |m| {
        if let Some(slot) = m
            .get_mut(&task)
            .and_then(|slots| slots.get_mut(fd as usize))
        {
            *slot = None;
        }
    });
}

/// Drop every descriptor-path identity owned by an exiting task.
///
/// `CLONE_FILES` shares the descriptor table but the compatibility metadata
/// remains task-keyed, so detaching the shared fd-table reference cannot
/// retire these rows. Leaving them behind retains one cloned pathname (and
/// its B-tree entry) per inherited descriptor for every exited thread.
pub(crate) fn release_task_fd_paths(task: u64) {
    let mut paths = FD_PATHS[fd_path_shard(task)].paths.lock();
    if let Some(paths) = paths.as_mut() {
        paths.remove(&task);
    }
}

/// Test-only residue probe for the central task-exit sweep.
pub(crate) fn task_has_fd_paths(task: u64) -> bool {
    FD_PATHS[fd_path_shard(task)]
        .paths
        .lock()
        .as_ref()
        .and_then(|paths| paths.get(&task))
        .is_some_and(|slots| slots.iter().any(Option::is_some))
}

/// Duplicate (or replace) a descriptor's pathname identity.
///
/// `dup2`/`dup3` may replace an existing destination, so an untracked source
/// must explicitly clear any former identity at the destination.
pub(crate) fn duplicate_fd_path(task: u64, source_fd: u32, destination_fd: u32) {
    with_fd_paths(task, |m| {
        let identity = m
            .get(&task)
            .and_then(|slots| slots.get(source_fd as usize))
            .and_then(Clone::clone);
        if let Some(identity) = identity {
            let slots = m.entry(task).or_default();
            let index = destination_fd as usize;
            if slots.len() <= index {
                slots.resize_with(index + 1, || None);
            }
            slots[index] = Some(identity);
        } else if let Some(slot) = m
            .get_mut(&task)
            .and_then(|slots| slots.get_mut(destination_fd as usize))
        {
            *slot = None;
        }
    });
}

/// Look up the absolute path an fd was opened on, if recorded. Used by
/// `landlock_add_rule` to turn a `parent_fd` back into a path.
pub(crate) fn fd_path(task: u64, fd: u32) -> Option<String> {
    with_fd_paths(task, |m| {
        m.get(&task)
            .and_then(|slots| slots.get(fd as usize))
            .and_then(|slot| slot.as_ref())
            .map(|(path, _)| path.clone())
    })
}

/// Mount that was visible when `fd` was opened.
pub(crate) fn fd_mount_id(task: u64, fd: u32) -> Option<u64> {
    with_fd_paths(task, |m| {
        m.get(&task)
            .and_then(|slots| slots.get(fd as usize))
            .and_then(|slot| slot.as_ref())
            .and_then(|(_, id)| *id)
    })
}

/// Copy fd-path identities along with the descriptor table during fork/clone.
/// The table is task-keyed even when CLONE_FILES shares the underlying file
/// descriptions, because proc-fd lookups and *at syscalls resolve through the
/// calling task.  Without this, a forked systemd mount helper inherited a
/// valid O_PATH parent fd but `mkdirat(parent_fd, ...)` saw EBADF.
pub(crate) fn fork_fd_paths(parent: u64, child: u64) {
    let inherited = with_fd_paths(parent, |m| m.get(&parent).cloned());
    with_fd_paths(child, |m| {
        if let Some(slots) = inherited {
            m.insert(child, slots);
        } else {
            m.remove(&child);
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
    if !fs_notify_active() {
        return;
    }
    // Each dispatch wakes ONLY the inotify/fanotify instances whose watch
    // actually matched this path, via that instance's durable `Readiness` cell
    // (see the `cell.set`/`cell.notify` at the end of each). A poll/epoll waiter
    // on an inotify/fanotify fd arms that same cell, so the targeted wake covers
    // it. We must NOT also fire the global `readiness::notify(0)` here: that is a
    // system-wide wake-ALL of every parked io-waiter, and fs_notify runs on
    // EVERY open/close/modify of ANY file — including the vast majority that no
    // watch matches. During a desktop/systemd startup (thousands of library and
    // config opens) that turned ordinary file I/O into a thundering-herd wake
    // storm: every parked poll/epoll waiter (kwin, dbus, the whole session) woke
    // on each unrelated open, re-scanned, found nothing, and re-parked — a
    // system-wide busy-poll livelock that never let the greeter present.
    inotify_dispatch(abs_path, mask, is_dir);
    fanotify_dispatch(abs_path, mask as u64);
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
    let woken = with_inotify(|m| {
        let mut woken: Vec<Arc<narf_lib::readiness::Readiness>> = Vec::new();
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
            let produced = !matched.is_empty();
            for (wd, _, use_base) in matched {
                let name = if use_base { base } else { "" };
                st.enqueue(serialize_event(wd, full_mask, cookie, name));
            }
            if produced {
                woken.push(st.readiness.clone());
            }
        }
        woken
    });
    // Produce site: a dispatch only ADDS events, so every instance that queued
    // one crosses an empty→non-empty POLL_IN edge (or stays readable). Publish
    // it OFF the INOTIFY lock (the cell has its own lock) so a poll/epoll armed
    // on this inotify fd wakes via its durable cell — additive to the kept
    // notify(0) fired by fs_notify after this returns.
    for cell in woken {
        cell.set(narf_filesystem::POLL_IN, 0);
        // Linux wait-queue: fire on every queued event so an EPOLLET consumer
        // re-fires even when the fd stays readable at the same level.
        cell.notify(narf_filesystem::POLL_IN);
    }
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
    if !fs_notify_active() {
        return;
    }
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
    if !fs_notify_active() {
        return;
    }
    let path = fd_path(task, fd);
    if let Some(p) = path {
        fs_notify(&p, IN_MODIFY, false);
    }
}

/// Release an mqueue notification and emit IN_CLOSE_WRITE for `fd`.
///
/// `sys_close` removes the descriptor before running close hooks, matching
/// Linux's close ordering.  Carry the mqueue handle from the retained file
/// object instead of looking the now-closed descriptor up again.
pub(crate) fn notify_close_fd(task: u64, fd: u32, queue_id: Option<u64>) {
    if let Some(handle_id) = queue_id {
        mqueuefs::close_notification(handle_id, task);
    }
    if !fs_notify_active() {
        return;
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
    let woken = with_inotify(|m| {
        let mut woken: Vec<Arc<narf_lib::readiness::Readiness>> = Vec::new();
        for st in m.values_mut() {
            let cookie = st.next_cookie.wrapping_add(1);
            st.next_cookie = cookie;
            let mut produced = false;
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
                produced = true;
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
                produced = true;
            }
            if produced {
                woken.push(st.readiness.clone());
            }
        }
        woken
    });
    // Produce site: publish the rising POLL_IN edge for every instance that
    // queued a MOVED_* record, OFF the INOTIFY lock — additive to the kept
    // notify(0) fired below.
    for cell in woken {
        cell.set(narf_filesystem::POLL_IN, 0);
        // Linux wait-queue: fire on every queued event so an EPOLLET consumer
        // re-fires even when the fd stays readable at the same level.
        cell.notify(narf_filesystem::POLL_IN);
    }
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

    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let id = self.id;
        Box::pin(async move {
            // Drain whole events that fit; inotify never returns a partial
            // event. If the first queued event is larger than the buffer,
            // Linux returns EINVAL — mirror that.
            let result = with_inotify(|m| {
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
                    if InotifyState::is_overflow(&ev) {
                        // The hole has been reported; a later drop may queue
                        // another marker.
                        st.overflow_queued = false;
                    }
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
            });
            // Consume site: draining may have emptied the queue (clear POLL_IN)
            // or left events queued (keep it readable). Republish the durable
            // cell's absolute level OFF the INOTIFY lock so a later arm and an
            // epoll ET edge reflect the new occupancy — without this an emptied
            // fd would stay POLL_IN in the cell and a re-arm would busy-spin.
            // Idempotent on the WouldBlock/InvalidData paths (no occupancy
            // change). The kept notify(0)/poll_readiness path is unchanged.
            sync_inotify_readiness(id);
            result
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

    /// Durable per-fd wake. The instance's readiness cell lives behind the
    /// global `INOTIFY` lock, so a plain `readiness()` borrow can't cross it;
    /// like the lock-guarded ring cells in `socket.rs`, clone the `Arc` out
    /// UNDER the lock and `arm` OFF it. `None` if the fd's instance has been
    /// torn down, so the caller keeps the legacy edge-token + backstop path.
    fn arm_readiness(
        &self,
        task_id: u64,
        interest: u32,
        waker: &core::task::Waker,
    ) -> Option<core::task::Poll<u32>> {
        let cell = with_inotify(|m| m.get(&self.id).map(|st| st.readiness.clone()))?;
        Some(cell.arm(task_id, interest, waker))
    }

    /// Persistent arm (epoll `eppoll_entry`): register a never-consumed waiter on
    /// the instance cell so an EPOLLET consumer re-fires on every queued event.
    fn arm_readiness_persistent(
        &self,
        id: u64,
        interest: u32,
        waker: &core::task::Waker,
    ) -> Option<u32> {
        let cell = with_inotify(|m| m.get(&self.id).map(|st| st.readiness.clone()))?;
        Some(cell.arm_persistent(id, interest, waker))
    }

    /// Remove this task's waiter from the instance cell; `false` if the instance
    /// is gone (the caller then runs its legacy disarm path).
    fn disarm_readiness(&self, task_id: u64) -> bool {
        match with_inotify(|m| m.get(&self.id).map(|st| st.readiness.clone())) {
            Some(cell) => {
                cell.disarm(task_id);
                true
            }
            None => false,
        }
    }

    fn inotify_instance(&self) -> Option<u64> {
        Some(self.id)
    }
}

const IN_NONBLOCK: u64 = 0o4000;
const IN_CLOEXEC: u64 = 0o2000000;

/// `inotify_init1(flags)`.
///
/// `if (flags & ~(IN_CLOEXEC | IN_NONBLOCK)) return -EINVAL;` — checked
/// before anything is allocated. An unknown bit used to be silently ignored.
pub fn sys_inotify_init1(ctx: &mut dyn TrapContext) {
    let flags = ctx.args().arg0 as u32 as u64;
    if flags & !(IN_CLOEXEC | IN_NONBLOCK) != 0 {
        ctx.set_return(err(EINVAL));
        return;
    }
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
    // Publish the slow-path gate before the instance can become visible via
    // its fd. A concurrent mutation may see an empty registry in this small
    // window, but no userspace observer can yet own the unpublished fd.
    INOTIFY_ACTIVE.store(true, Ordering::Release);
    with_inotify(|m| {
        m.insert(
            id,
            InotifyState {
                next_wd: 1,
                watches: BTreeMap::new(),
                events: VecDeque::new(),
                overflow_queued: false,
                next_cookie: 0,
                // Fresh instance: no events queued, never writable → mask 0.
                readiness: Arc::new(narf_lib::readiness::Readiness::new(0)),
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
    match task_open_call(task_open(file, cloexec, status)).flatten() {
        Some(n) => ctx.set_return(SyscallReturn::ok(n as u64)),
        // `get_unused_fd_flags` failing is RLIMIT_NOFILE: -EMFILE.
        None => ctx.set_return(err(EMFILE)),
    }
}

// inotify_add_watch mask bits (`include/uapi/linux/inotify.h`).
const IN_ALL_EVENTS: u32 = 0x0000_0fff;
const IN_UNMOUNT: u32 = 0x0000_2000;
const IN_IGNORED: u32 = 0x0000_8000;
const IN_ONLYDIR: u32 = 0x0100_0000;
const IN_DONT_FOLLOW: u32 = 0x0200_0000;
const IN_EXCL_UNLINK: u32 = 0x0400_0000;
const IN_MASK_CREATE: u32 = 0x1000_0000;
const IN_MASK_ADD: u32 = 0x2000_0000;
const IN_ONESHOT: u32 = 0x8000_0000;
/// `ALL_INOTIFY_BITS` (`include/linux/inotify.h`).
const ALL_INOTIFY_BITS: u32 = IN_ALL_EVENTS
    | IN_UNMOUNT
    | IN_Q_OVERFLOW
    | IN_IGNORED
    | IN_ONLYDIR
    | IN_DONT_FOLLOW
    | IN_EXCL_UNLINK
    | IN_MASK_CREATE
    | IN_MASK_ADD
    | IN_ISDIR
    | IN_ONESHOT;

/// `inotify_add_watch(fd, path, mask)`.
///
/// `fs/notify/inotify/inotify_user.c` validates in this order:
///
/// ```text
///   if (mask & ~ALL_INOTIFY_BITS)    return -EINVAL;
///   if (!(mask & ALL_INOTIFY_BITS))  return -EINVAL;
///   CLASS(fd, f)(fd); if (fd_empty(f)) return -EBADF;
///   if ((mask & IN_MASK_ADD) && (mask & IN_MASK_CREATE)) return -EINVAL;
///   if (fd_file(f)->f_op != &inotify_fops)               return -EINVAL;
///   inotify_find_inode():  user_path_at(..., LOOKUP_FOLLOW unless IN_DONT_FOLLOW,
///                          LOOKUP_DIRECTORY if IN_ONLYDIR)   /* -EFAULT/-ENOENT/-ENOTDIR/... */
///                          path_permission(&path, MAY_READ)  /* -EACCES */
///   inotify_update_watch(): IN_MASK_CREATE on a watched inode -> -EEXIST
/// ```
///
/// This used to accept any mask, report a non-inotify fd as -EBADF, an
/// unreadable path pointer as -EINVAL, and watch names that did not exist.
pub fn sys_inotify_add_watch(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let task = current_task_id();
    let mask = a.arg2 as u32;
    if mask & !ALL_INOTIFY_BITS != 0 || mask & ALL_INOTIFY_BITS == 0 {
        ctx.set_return(err(EINVAL));
        return;
    }
    let is_inotify = match fd::with_table(task, |t| {
        t.get(a.arg0 as u32).map(|e| e.ops.inotify_instance())
    })
    .flatten()
    {
        Some(instance) => instance,
        None => {
            ctx.set_return(err(EBADF));
            return;
        }
    };
    if mask & IN_MASK_ADD != 0 && mask & IN_MASK_CREATE != 0 {
        ctx.set_return(err(EINVAL));
        return;
    }
    let Some(id) = is_inotify else {
        ctx.set_return(err(EINVAL));
        return;
    };
    let raw = match copy_user_cstr_checked(a.arg1, 4096) {
        Ok(p) => p,
        Err(errno) => {
            ctx.set_return(err(errno));
            return;
        }
    };
    let follow = mask & IN_DONT_FOLLOW == 0;
    let found =
        match crate::handlers::user_path_lookup(task, -100, &raw, follow, mask & IN_ONLYDIR != 0) {
            Ok(found) => found,
            Err(errno) => {
                ctx.set_return(err(errno));
                return;
            }
        };
    if let Err(errno) = crate::handlers::looked_up_permission(
        task,
        &found,
        follow,
        narf_filesystem::AccessRequest {
            read: true,
            write: false,
            exec: false,
        },
    ) {
        ctx.set_return(err(errno));
        return;
    }
    // Watches are keyed by the caller-view absolute path (events are
    // dispatched by absolute path), so `f`, `./f` and `/cwd/f` name one
    // watch the way they name one inode on Linux.
    let path = found.user_path;
    let wd = with_inotify(|m| {
        let st = m.get_mut(&id)?;
        // Re-adding an already-watched path returns the existing wd and
        // replaces its mask (ORs into it under IN_MASK_ADD); IN_MASK_CREATE
        // refuses an existing watch.
        if let Some((wd, w)) = st.watches.iter_mut().find(|(_, w)| w.path == path) {
            if mask & IN_MASK_CREATE != 0 {
                return Some(Err(EEXIST));
            }
            if mask & IN_MASK_ADD != 0 {
                w.mask |= mask;
            } else {
                w.mask = mask;
            }
            return Some(Ok(*wd));
        }
        let wd = st.next_wd;
        st.next_wd = st.next_wd.wrapping_add(1);
        st.watches.insert(wd, Watch { path, mask });
        Some(Ok(wd))
    });
    match wd {
        Some(Ok(wd)) => ctx.set_return(SyscallReturn::ok(wd as u64)),
        Some(Err(errno)) => ctx.set_return(err(errno)),
        None => ctx.set_return(err(EBADF)),
    }
}

/// `inotify_rm_watch(fd, wd)`.
pub fn sys_inotify_rm_watch(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let task = current_task_id();
    // `CLASS(fd, f)` -> -EBADF; an open fd that is not an inotify instance
    // is `if (fd_file(f)->f_op != &inotify_fops) return -EINVAL;`.
    let id = match fd::with_table(task, |t| {
        t.get(a.arg0 as u32).map(|e| e.ops.inotify_instance())
    })
    .flatten()
    {
        Some(Some(id)) => id,
        Some(None) => {
            ctx.set_return(err(EINVAL));
            return;
        }
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
const FAN_CLASS_CONTENT: u64 = 0x0000_0004;
const FAN_CLASS_PRE_CONTENT: u64 = 0x0000_0008;
const FAN_CLASS_BITS: u64 = FAN_CLASS_CONTENT | FAN_CLASS_PRE_CONTENT;
const FAN_REPORT_PIDFD: u64 = 0x0000_0080;
const FAN_REPORT_TID: u64 = 0x0000_0100;
const FAN_REPORT_FID: u64 = 0x0000_0200;
const FAN_REPORT_DIR_FID: u64 = 0x0000_0400;
const FAN_REPORT_NAME: u64 = 0x0000_0800;
const FAN_REPORT_TARGET_FID: u64 = 0x0000_1000;
const FAN_REPORT_MNT: u64 = 0x0000_4000;
const FANOTIFY_FID_BITS: u64 =
    FAN_REPORT_FID | FAN_REPORT_DIR_FID | FAN_REPORT_NAME | FAN_REPORT_TARGET_FID;
/// `FANOTIFY_INIT_FLAGS` (incl. FAN_ENABLE_AUDIT): every defined init bit.
/// Probed on Linux 6.18: bits 0..=14 are known, 15+ are -EINVAL.
const FANOTIFY_INIT_FLAGS: u64 = 0x0000_7fff;
/// `FANOTIFY_ADMIN_INIT_FLAGS`: the permission classes, unlimited
/// queue/marks, audit, pidfd/tid reporting and FAN_REPORT_FD_ERROR — the
/// bits an unprivileged group may not ask for (probed: -EPERM).
const FANOTIFY_ADMIN_INIT_FLAGS: u64 = 0x0000_21fc;
/// `FANOTIFY_INIT_ALL_EVENT_F_BITS`: O_ACCMODE | O_APPEND | O_NONBLOCK |
/// O_DSYNC | O_LARGEFILE | O_NOATIME | O_CLOEXEC | __O_SYNC.
const FANOTIFY_INIT_ALL_EVENT_F_BITS: u64 = 0x001c_dc03;
// fanotify_mark flags.
const FAN_MARK_ADD: u64 = 0x0000_0001;
const FAN_MARK_REMOVE: u64 = 0x0000_0002;
const FAN_MARK_DONT_FOLLOW: u64 = 0x0000_0004;
const FAN_MARK_ONLYDIR: u64 = 0x0000_0008;
const FAN_MARK_FLUSH: u64 = 0x0000_0080;
/// `FANOTIFY_MARK_TYPE_BITS`: FAN_MARK_MOUNT | FAN_MARK_FILESYSTEM (and
/// their union, FAN_MARK_MNTNS).
const FANOTIFY_MARK_TYPE_BITS: u64 = 0x0000_0110;
/// `FANOTIFY_MARK_FLAGS`: every defined mark flag (probed: 0x800+ is -EINVAL).
const FANOTIFY_MARK_FLAGS: u64 = 0x0000_07ff;
/// `struct fanotify_event_metadata` is a fixed 24 bytes.
pub(crate) const FAN_EVENT_METADATA_LEN: usize = 24;
const FANOTIFY_METADATA_VERSION: u8 = 3;

struct FanGroup {
    /// Absolute path → mark mask (inode marks only).
    marks: BTreeMap<String, u64>,
    /// Queued events: (affected path, event mask, causing pid).
    events: VecDeque<(String, u64, i32)>,
    /// Durable per-fd readiness cell (see `narf_lib::readiness`) — the migration
    /// target that fuses the arm/notify wake for a poll/epoll parked on this
    /// fanotify group fd. A fanotify group fd is read-only, so the cell carries
    /// only POLL_IN: set inline when `fanotify_dispatch` queues an event (the
    /// produce site) and cleared by `fanotify_drain` when the queue empties (the
    /// consume site). Behind the global `FANOTIFY` lock, so `FanotifyFile`
    /// clones this `Arc` out UNDER the lock and arms/`set`s OFF it (the cell has
    /// its own lock; never nest it under `FANOTIFY`), like the ring cells in
    /// `socket.rs`. Additive to the kept `narf_net::readiness::notify(0)`.
    readiness: Arc<narf_lib::readiness::Readiness>,
}

static FANOTIFY: IrqSafeSpinLock<Option<BTreeMap<u64, FanGroup>>> = IrqSafeSpinLock::new(None);
static FANOTIFY_NEXT_ID: AtomicU64 = AtomicU64::new(1);
/// Set once any fanotify group exists; lets the fs_notify dispatch and
/// sys_read skip fanotify work entirely on the common path.
static FANOTIFY_ACTIVE: AtomicBool = AtomicBool::new(false);

#[inline]
fn fs_notify_active() -> bool {
    INOTIFY_ACTIVE.load(Ordering::Acquire) || FANOTIFY_ACTIVE.load(Ordering::Acquire)
}

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
    let woken = with_fanotify(|m| {
        let mut woken: Vec<Arc<narf_lib::readiness::Readiness>> = Vec::new();
        for group in m.values_mut() {
            if let Some(&mark_mask) = group.marks.get(abs_path) {
                let hit = mark_mask & mask;
                if hit != 0 {
                    group.events.push_back((String::from(abs_path), hit, pid));
                    woken.push(group.readiness.clone());
                }
            }
        }
        woken
    });
    // Produce site: a dispatch only ADDS an event, so each group that queued one
    // crosses a rising POLL_IN edge. Publish it OFF the FANOTIFY lock (the cell
    // has its own lock) to wake a poll/epoll armed on this group fd via its
    // durable cell — additive to the kept notify(0) fired by the fs_notify /
    // notify_moved caller after this returns.
    for cell in woken {
        cell.set(narf_filesystem::POLL_IN, 0);
        // Linux wait-queue: fire on every queued event so an EPOLLET consumer
        // re-fires even when the fd stays readable at the same level.
        cell.notify(narf_filesystem::POLL_IN);
    }
}

/// Republish a fanotify group's durable readiness after its queue changed:
/// POLL_IN iff events remain, else clear it. Snapshots occupancy and clones the
/// cell UNDER the `FANOTIFY` lock, then `set`s OFF the lock. Called by
/// `fanotify_drain` (the consume site); the produce side publishes inline in
/// `fanotify_dispatch`.
fn sync_fanotify_readiness(id: u64) {
    let snapshot = with_fanotify(|m| {
        m.get(&id)
            .map(|g| (g.readiness.clone(), !g.events.is_empty()))
    });
    if let Some((cell, has_events)) = snapshot {
        if has_events {
            cell.set(narf_filesystem::POLL_IN, 0);
        } else {
            cell.set(0, narf_filesystem::POLL_IN);
        }
    }
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

    /// Durable per-fd wake. The group's readiness cell lives behind the global
    /// `FANOTIFY` lock, so — like the lock-guarded ring cells in `socket.rs` —
    /// clone the `Arc` out UNDER the lock and `arm` OFF it. `None` if the group
    /// has been torn down, so the caller keeps the legacy backstop path.
    fn arm_readiness(
        &self,
        task_id: u64,
        interest: u32,
        waker: &core::task::Waker,
    ) -> Option<core::task::Poll<u32>> {
        let cell = with_fanotify(|m| m.get(&self.id).map(|g| g.readiness.clone()))?;
        Some(cell.arm(task_id, interest, waker))
    }

    /// Persistent arm (epoll `eppoll_entry`): register a never-consumed waiter on
    /// the group cell so an EPOLLET consumer re-fires on every queued event.
    fn arm_readiness_persistent(
        &self,
        id: u64,
        interest: u32,
        waker: &core::task::Waker,
    ) -> Option<u32> {
        let cell = with_fanotify(|m| m.get(&self.id).map(|g| g.readiness.clone()))?;
        Some(cell.arm_persistent(id, interest, waker))
    }

    /// Remove this task's waiter from the group cell; `false` if the group is
    /// gone (the caller then runs its legacy disarm path).
    fn disarm_readiness(&self, task_id: u64) -> bool {
        match with_fanotify(|m| m.get(&self.id).map(|g| g.readiness.clone())) {
            Some(cell) => {
                cell.disarm(task_id);
                true
            }
            None => false,
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
    // Consume site: draining may have emptied the queue — republish the cell's
    // absolute level OFF the FANOTIFY lock so it stops reporting readable (else
    // a re-arm / epoll ET on an emptied group would busy-spin). No-op when
    // events remain. The kept notify(0)/poll_readiness path is unchanged.
    sync_fanotify_readiness(group_id);
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
///
/// `fs/notify/fanotify/fanotify_user.c` validates before creating the group:
///
/// ```text
///   if (!capable(CAP_SYS_ADMIN) &&
///       ((flags & FANOTIFY_ADMIN_INIT_FLAGS) ||
///        !(flags & (FANOTIFY_FID_BITS | FAN_REPORT_MNT))))  return -EPERM;
///   if (flags & ~FANOTIFY_INIT_FLAGS)                        return -EINVAL;
///   if ((flags & FAN_REPORT_PIDFD) && (flags & FAN_REPORT_TID)) return -EINVAL;
///   if (event_f_flags & ~FANOTIFY_INIT_ALL_EVENT_F_BITS)     return -EINVAL;
///   if ((event_f_flags & O_ACCMODE) == 3)                    return -EINVAL;
///   if (fid_mode && class != FAN_CLASS_NOTIF)                return -EINVAL;
///   if ((fid_mode & FAN_REPORT_NAME) && !(fid_mode & FAN_REPORT_DIR_FID)) -EINVAL;
///   if ((fid_mode & FAN_REPORT_TARGET_FID) && !(NAME && FID))             -EINVAL;
///   ... class CONTENT|PRE_CONTENT together                   -> -EINVAL
/// ```
///
/// Every flag combination used to be accepted, including from an
/// unprivileged caller. (The group itself still delivers fd-style events
/// whatever FAN_REPORT_* asked for — a LINUX-GAP outside errno parity.)
pub fn sys_fanotify_init(ctx: &mut dyn TrapContext) {
    let flags = ctx.args().arg0 as u32 as u64;
    let event_f_flags = ctx.args().arg1 as u32 as u64;
    if !crate::handlers::capable(crate::handlers::CAP_SYS_ADMIN)
        && (flags & FANOTIFY_ADMIN_INIT_FLAGS != 0
            || flags & (FANOTIFY_FID_BITS | FAN_REPORT_MNT) == 0)
    {
        ctx.set_return(err(EPERM));
        return;
    }
    let fid_mode = flags & FANOTIFY_FID_BITS;
    let invalid = flags & !FANOTIFY_INIT_FLAGS != 0
        || (flags & FAN_REPORT_PIDFD != 0 && flags & FAN_REPORT_TID != 0)
        || event_f_flags & !FANOTIFY_INIT_ALL_EVENT_F_BITS != 0
        || event_f_flags & 0o3 == 0o3
        || (fid_mode != 0 && flags & FAN_CLASS_BITS != 0)
        || (fid_mode & FAN_REPORT_NAME != 0 && fid_mode & FAN_REPORT_DIR_FID == 0)
        || (fid_mode & FAN_REPORT_TARGET_FID != 0
            && (fid_mode & FAN_REPORT_NAME == 0 || fid_mode & FAN_REPORT_FID == 0))
        // Probed: FAN_REPORT_MNT cannot be combined with fid reporting.
        || (flags & FAN_REPORT_MNT != 0 && fid_mode != 0)
        || flags & FAN_CLASS_BITS == FAN_CLASS_BITS;
    if invalid {
        ctx.set_return(err(EINVAL));
        return;
    }
    let id = FANOTIFY_NEXT_ID.fetch_add(1, Ordering::Relaxed);
    FANOTIFY_ACTIVE.store(true, Ordering::Relaxed);
    with_fanotify(|m| {
        m.insert(
            id,
            FanGroup {
                marks: BTreeMap::new(),
                events: VecDeque::new(),
                // Fresh group: no events queued, never writable → mask 0.
                readiness: Arc::new(narf_lib::readiness::Readiness::new(0)),
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
    match task_open_call(task_open(file, cloexec, status)).flatten() {
        Some(n) => ctx.set_return(SyscallReturn::ok(n as u64)),
        // `get_unused_fd_flags` failing is RLIMIT_NOFILE: -EMFILE.
        None => ctx.set_return(err(EMFILE)),
    }
}

/// `fanotify_mark(fanotify_fd, flags, mask, dirfd, pathname)`.
///
/// `do_fanotify_mark` validates the arguments BEFORE resolving the group fd:
///
/// ```text
///   if (upper_32_bits(mask))             return -EINVAL;
///   if (flags & ~FANOTIFY_MARK_FLAGS)    return -EINVAL;
///   switch (flags & (ADD | REMOVE | FLUSH)) {
///   case ADD: case REMOVE: if (!mask) return -EINVAL; break;
///   case FLUSH: if (flags & ~(FANOTIFY_MARK_TYPE_BITS | FLUSH)) return -EINVAL; break;
///   default: return -EINVAL;
///   }
///   CLASS(fd, f)(fanotify_fd);  if (fd_empty(f)) return -EBADF;
///   if (fd_file(f)->f_op != &fanotify_fops)     return -EINVAL;
///   fanotify_find_path(): pathname NULL -> dfd itself (-EBADF, ONLYDIR -ENOTDIR),
///                         else user_path_at(dfd, pathname, ...) + MAY_READ
///   fanotify_remove_mark(): no such mark -> -ENOENT
/// ```
///
/// This used to report a non-fanotify fd as -EBADF, validate nothing, mark
/// names that did not exist, and answer a missing mark with -EINVAL.
pub fn sys_fanotify_mark(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let task = current_task_id();
    let flags = a.arg1 as u32 as u64;
    let mask = a.arg2;
    let dirfd = a.arg3 as i32 as i64;
    if mask >> 32 != 0 || flags & !FANOTIFY_MARK_FLAGS != 0 {
        ctx.set_return(err(EINVAL));
        return;
    }
    let cmd = flags & (FAN_MARK_ADD | FAN_MARK_REMOVE | FAN_MARK_FLUSH);
    let args_ok = match cmd {
        FAN_MARK_ADD | FAN_MARK_REMOVE => mask != 0,
        FAN_MARK_FLUSH => flags & !(FANOTIFY_MARK_TYPE_BITS | FAN_MARK_FLUSH) == 0,
        _ => false,
    };
    if !args_ok {
        ctx.set_return(err(EINVAL));
        return;
    }
    let id = match fd::with_table(task, |t| {
        t.get(a.arg0 as u32).map(|e| e.ops.fanotify_instance())
    })
    .flatten()
    {
        Some(Some(id)) => id,
        Some(None) => {
            ctx.set_return(err(EINVAL));
            return;
        }
        None => {
            ctx.set_return(err(EBADF));
            return;
        }
    };
    if cmd == FAN_MARK_FLUSH {
        // NARF keeps inode marks only; a mount/filesystem flush has none
        // of its kind to remove.
        if flags & FANOTIFY_MARK_TYPE_BITS == 0 {
            with_fanotify(|m| {
                if let Some(g) = m.get_mut(&id) {
                    g.marks.clear();
                }
            });
        }
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    let only_dir = flags & FAN_MARK_ONLYDIR != 0;
    let path = if a.arg4 == 0 {
        // A NULL pathname marks the object `dfd` itself refers to.
        let is_dir = if dirfd < 0 {
            None
        } else {
            fd::with_table(task, |t| {
                t.get(dirfd as u32).map(|e| e.ops.as_dir().is_some())
            })
            .flatten()
        };
        let Some(is_dir) = is_dir else {
            ctx.set_return(err(EBADF));
            return;
        };
        if only_dir && !is_dir {
            ctx.set_return(err(ENOTDIR));
            return;
        }
        fd_path(task, dirfd as u32)
    } else {
        let raw = match copy_user_cstr_checked(a.arg4, 4096) {
            Ok(p) => p,
            Err(errno) => {
                ctx.set_return(err(errno));
                return;
            }
        };
        let follow = flags & FAN_MARK_DONT_FOLLOW == 0;
        let found = match crate::handlers::user_path_lookup(task, dirfd, &raw, follow, only_dir) {
            Ok(found) => found,
            Err(errno) => {
                ctx.set_return(err(errno));
                return;
            }
        };
        if let Err(errno) = crate::handlers::looked_up_permission(
            task,
            &found,
            follow,
            narf_filesystem::AccessRequest {
                read: true,
                write: false,
                exec: false,
            },
        ) {
            ctx.set_return(err(errno));
            return;
        }
        Some(found.user_path)
    };
    // An anonymous object (no path to key an inode mark on) is accepted, as
    // Linux accepts it; NARF simply has no path event that could match it.
    let Some(path) = path else {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    };
    let r = with_fanotify(|m| {
        let g = m.get_mut(&id)?;
        if cmd == FAN_MARK_ADD {
            let e = g.marks.entry(path).or_insert(0);
            *e |= mask;
            Some(Ok(()))
        } else if let Some(cur) = g.marks.get_mut(&path) {
            *cur &= !mask;
            if *cur == 0 {
                g.marks.remove(&path);
            }
            Some(Ok(()))
        } else {
            // `fanotify_remove_mark`: no mark on this object -> -ENOENT.
            Some(Err(ENOENT))
        }
    });
    match r {
        Some(Ok(())) => ctx.set_return(SyscallReturn::ok(0)),
        Some(Err(errno)) => ctx.set_return(err(errno)),
        None => ctx.set_return(err(EBADF)),
    }
}
