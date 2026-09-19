#[allow(unused_imports)]
use super::*;

/// `F_UNLCK` from `include/uapi/asm-generic/fcntl.h` (`#define F_UNLCK 2`),
/// as returned by the `!CONFIG_FILE_LOCKING` `fcntl_getlease` stub to mean
/// "no lease is held". Spelled out here because the neighbouring `F_RDLCK`
/// is 0, and 0 is also what a missing arm returns by accident — the whole
/// point of the F_GETLEASE arm below is that those two must not coincide.
const F_UNLCK_LEASE: u64 = 2;

fn write_flock_to_user(ptr: u64, flock: &UFlock) -> Result<(), ()> {
    let mut bytes = alloc::vec![0u8; flock_size()];
    // SAFETY: `UFlock` is repr(C) and `bytes` has the architecture's
    // exported flock size.
    unsafe {
        core::ptr::copy_nonoverlapping(
            flock as *const _ as *const u8,
            bytes.as_mut_ptr(),
            flock_size(),
        );
    }
    // SAFETY: the syscall supplied `ptr`; copy_to_user validates the range.
    unsafe { copy_to_user(ptr, &bytes) }.map_err(|_| ())
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct FOwnerEx {
    type_: i32,
    pid: i32,
}

const F_OWNER_TID: i32 = 0;
const F_OWNER_PID: i32 = 1;
const F_OWNER_PGRP: i32 = 2;

/// One persistent readiness callback per async-enabled open description. It
/// retains the description weakly so a FileOps readiness cell cannot keep a
/// closed file alive. The callback itself does no signal-table work: it may be
/// invoked by an IRQ producer while the relevant locks are interrupted.
struct FasyncWake {
    description: alloc::sync::Weak<crate::fd::OpenFileDescription>,
}

static FASYNC_EVENT_VTABLE: core::task::RawWakerVTable = core::task::RawWakerVTable::new(
    fasync_event_clone,
    fasync_event_wake,
    fasync_event_wake_by_ref,
    fasync_waker_drop,
);
static FASYNC_ACTION_VTABLE: core::task::RawWakerVTable = core::task::RawWakerVTable::new(
    fasync_action_clone,
    fasync_action_wake,
    fasync_action_wake_by_ref,
    fasync_waker_drop,
);

unsafe fn fasync_clone_with(
    ptr: *const (),
    vtable: &'static core::task::RawWakerVTable,
) -> core::task::RawWaker {
    // SAFETY: every pointer paired with either fasync vtable was minted by
    // Arc::into_raw for FasyncWake, and the source Waker keeps one count live.
    unsafe { alloc::sync::Arc::<FasyncWake>::increment_strong_count(ptr.cast()) };
    core::task::RawWaker::new(ptr, vtable)
}

unsafe fn fasync_event_clone(ptr: *const ()) -> core::task::RawWaker {
    // SAFETY: forwarded RawWaker clone contract.
    unsafe { fasync_clone_with(ptr, &FASYNC_EVENT_VTABLE) }
}

unsafe fn fasync_action_clone(ptr: *const ()) -> core::task::RawWaker {
    // SAFETY: forwarded RawWaker clone contract.
    unsafe { fasync_clone_with(ptr, &FASYNC_ACTION_VTABLE) }
}

fn fasync_defer(wake: &alloc::sync::Arc<FasyncWake>) {
    let action = alloc::sync::Arc::clone(wake);
    let raw = core::task::RawWaker::new(
        alloc::sync::Arc::into_raw(action).cast(),
        &FASYNC_ACTION_VTABLE,
    );
    // SAFETY: `raw` owns exactly one Arc<FasyncWake> count and the action
    // vtable observes the RawWaker clone/wake/drop ownership rules.
    let action = unsafe { core::task::Waker::from_raw(raw) };
    if let Err(action) = narf_lib::deferred_wake::try_push_one(action) {
        // The Readiness cell's event waker remains live throughout this
        // callback, so dropping the extra action count cannot deallocate in
        // IRQ context even if the bounded deferred queue is temporarily full.
        drop(action);
    }
}

unsafe fn fasync_event_wake(ptr: *const ()) {
    // SAFETY: wake-by-value consumes the Arc count held by this RawWaker.
    let wake = unsafe { alloc::sync::Arc::<FasyncWake>::from_raw(ptr.cast()) };
    fasync_defer(&wake);
}

unsafe fn fasync_event_wake_by_ref(ptr: *const ()) {
    // SAFETY: wake_by_ref borrows the RawWaker's live Arc count.
    let wake = core::mem::ManuallyDrop::new(unsafe {
        alloc::sync::Arc::<FasyncWake>::from_raw(ptr.cast())
    });
    fasync_defer(&wake);
}

unsafe fn fasync_waker_drop(ptr: *const ()) {
    // SAFETY: drop consumes the one Arc count owned by this RawWaker.
    drop(unsafe { alloc::sync::Arc::<FasyncWake>::from_raw(ptr.cast()) });
}

unsafe fn fasync_action_wake(ptr: *const ()) {
    // SAFETY: wake-by-value consumes the Arc count held by this action waker.
    let wake = unsafe { alloc::sync::Arc::<FasyncWake>::from_raw(ptr.cast()) };
    deliver_fasync(&wake);
}

unsafe fn fasync_action_wake_by_ref(ptr: *const ()) {
    // SAFETY: wake_by_ref borrows the action waker's live Arc count.
    let wake = core::mem::ManuallyDrop::new(unsafe {
        alloc::sync::Arc::<FasyncWake>::from_raw(ptr.cast())
    });
    deliver_fasync(&wake);
}

fn fasync_event_waker(
    description: &crate::fd::Description,
) -> core::task::Waker {
    let wake = alloc::sync::Arc::new(FasyncWake {
        description: alloc::sync::Arc::downgrade(description),
    });
    let raw = core::task::RawWaker::new(
        alloc::sync::Arc::into_raw(wake).cast(),
        &FASYNC_EVENT_VTABLE,
    );
    // SAFETY: `raw` owns exactly one Arc<FasyncWake> count and its vtable
    // implements the complete RawWaker ownership contract above.
    unsafe { core::task::Waker::from_raw(raw) }
}

fn sigio_permitted(target: u64, state: crate::fd::FasyncSnapshot) -> bool {
    if crate::task::task_get(target).is_none() && target != current_task_id() {
        return false;
    }
    let target_ids = read_uidgid(target);
    state.owner_euid == 0
        || state.owner_euid == target_ids.suid
        || state.owner_euid == target_ids.uid
        || state.owner_uid == target_ids.suid
        || state.owner_uid == target_ids.uid
}

fn deliver_fasync(wake: &FasyncWake) {
    let Some(description) = wake.description.upgrade() else {
        return;
    };
    let state = description.fasync_snapshot();
    if !state.enabled || state.owner == crate::fd::FasyncOwner::None {
        return;
    }
    let readiness = description
        .fasync_ops()
        .map_or(0, |ops| ops.poll_readiness());
    // Linux's send_sigio reason -> band_table mapping. The readiness callback
    // does not carry an event argument, so prefer the strongest currently
    // observable level and fall back to POLL_IN if an edge was consumed before
    // this deferred action ran.
    let (poll_code, poll_band) = if readiness & narf_filesystem::POLL_ERR != 0 {
        (4, 0x008)
    } else if readiness & narf_filesystem::POLL_HUP != 0 {
        (6, 0x018)
    } else if readiness & narf_filesystem::POLL_PRI != 0 {
        (5, 0x082)
    } else if readiness & narf_filesystem::POLL_IN != 0 {
        (1, 0x041)
    } else if readiness & narf_filesystem::POLL_OUT != 0 {
        (2, 0x304)
    } else {
        (1, 0x041)
    };
    let targets = match state.owner {
        crate::fd::FasyncOwner::None => alloc::vec::Vec::new(),
        crate::fd::FasyncOwner::Tid(task) | crate::fd::FasyncOwner::Process(task) => {
            alloc::vec![task]
        }
        crate::fd::FasyncOwner::ProcessGroup(group) => pgrp_task_snapshot(group),
    };
    for target in targets {
        if sigio_permitted(target, state) {
            raise_sigio_pending(target, state.signal, poll_code, poll_band, state.fd);
        }
    }
}

fn resolve_fasync_task(caller: u64, visible: i32, thread: bool) -> Option<u64> {
    if visible <= 0 {
        return None;
    }
    let outer = accept_pid_from(caller, visible as u64)?;
    if thread {
        linux_tid_to_task_raw(outer).or_else(|| pid_to_task_raw(outer))
    } else {
        pid_to_task_raw(outer)
    }
}

fn fasync_owner_to_user(
    caller: u64,
    state: crate::fd::FasyncSnapshot,
) -> (i32, i32) {
    match state.owner {
        crate::fd::FasyncOwner::None => (state.owner_type, 0),
        crate::fd::FasyncOwner::Tid(task) => {
            let outer = task_to_linux_tid_raw(task)
                .or_else(|| task_to_pid_raw(task))
                .unwrap_or(0);
            (F_OWNER_TID, report_pid_to(caller, outer) as i32)
        }
        crate::fd::FasyncOwner::Process(task) => {
            let outer = task_to_pid_raw(task).unwrap_or(0);
            (F_OWNER_PID, report_pid_to(caller, outer) as i32)
        }
        crate::fd::FasyncOwner::ProcessGroup(group) => (
            F_OWNER_PGRP,
            if pgrp_task_snapshot(group).is_empty() {
                0
            } else {
                pgid_to_user(group) as i32
            },
        ),
    }
}

struct RwHintEntry {
    hint: u64,
    /// Pointer-identity fallback keys need a lifetime witness so address reuse
    /// cannot inherit an old hint. Stable `(dev, ino)` keys deliberately keep
    /// the hint after the opening FileOps is dropped: Linux stores it in the
    /// inode, whose lifetime is not tied to an open file description.
    witness: Option<alloc::sync::Weak<dyn narf_filesystem::FileOps>>,
}

type RwHintKey = (u64, u64, usize);
const RW_HINT_SHARDS: usize = 32;
static RW_HINTS: [
    narf_lib::sync::IrqSafeSpinLock<
        Option<alloc::collections::BTreeMap<RwHintKey, RwHintEntry>>,
    >;
    RW_HINT_SHARDS
] = [const { narf_lib::sync::IrqSafeSpinLock::new(None) }; RW_HINT_SHARDS];

fn rw_hint_key(ops: &alloc::sync::Arc<dyn narf_filesystem::FileOps>) -> RwHintKey {
    let attrs = ops.inode_attrs();
    let ino = ops.ino();
    if attrs.tracked && ino != 0 {
        (attrs.dev, ino, 0)
    } else {
        (0, 0, alloc::sync::Arc::as_ptr(ops) as *const () as usize)
    }
}

fn rw_hint_shard(key: RwHintKey) -> usize {
    (key.0 as usize ^ key.1 as usize ^ key.2) & (RW_HINT_SHARDS - 1)
}

fn rw_hint_get(ops: &alloc::sync::Arc<dyn narf_filesystem::FileOps>) -> u64 {
    let key = rw_hint_key(ops);
    let mut guard = RW_HINTS[rw_hint_shard(key)].lock();
    let Some(map) = guard.as_mut() else {
        return 0;
    };
    if map
        .get(&key)
        .and_then(|entry| entry.witness.as_ref())
        .is_some_and(|witness| witness.upgrade().is_none())
    {
        map.remove(&key);
        return 0;
    }
    map.get(&key).map_or(0, |entry| entry.hint)
}

fn rw_hint_set(ops: &alloc::sync::Arc<dyn narf_filesystem::FileOps>, hint: u64) {
    let key = rw_hint_key(ops);
    let mut guard = RW_HINTS[rw_hint_shard(key)].lock();
    let map = guard.get_or_insert_with(alloc::collections::BTreeMap::new);
    if hint == 0 {
        map.remove(&key);
    } else {
        map.insert(
            key,
            RwHintEntry {
                hint,
                witness: (key.2 != 0).then(|| alloc::sync::Arc::downgrade(ops)),
            },
        );
    }
}

pub(crate) fn sys_fcntl(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let cmd = args.arg1;
    let arg = args.arg2;
    let task = current_task_id();

    // Linux's hot F_GETFL path is `fdget_raw(fd)` followed by a load of
    // `file::f_flags`. Keep the same shape here: resolve the descriptor once,
    // read its shared-description flags, and inspect socket/mqueue state
    // through the borrowed FileOps object. The old generic path first called
    // `current_socket` and `mqueue::fd_nonblock`, then called `with_table`
    // again. Besides three table lookups, `current_socket` cloned the shared
    // stdio FileOps Arc on every call, making unrelated workers contend on one
    // reference-count cache line.
    if cmd == F_GETFL {
        let snapshot = fd::with_table(task, |table| {
            let entry = table.get(fd)?;
            let flags = table.status_flags(fd)? as u64;
            let socket_nonblock = entry
                .ops
                .as_any()
                .and_then(|ops| ops.downcast_ref::<crate::socket::SocketFile>())
                .map(|socket| socket.is_nonblock());
            Some((flags, socket_nonblock, entry.ops.mq_queue_id()))
        })
        .flatten();

        let Some((mut flags, socket_nonblock, mqueue_id)) = snapshot else {
            ctx.set_return(SyscallReturn::ok((-(EBADF as i64)) as u64));
            return;
        };
        if let Some(nonblock) = socket_nonblock {
            if nonblock {
                flags |= crate::socket::O_NONBLOCK as u64;
            } else {
                flags &= !(crate::socket::O_NONBLOCK as u64);
            }
        }
        // Do not nest the mqueuefs lock under the fd-table lock. Other mqueue
        // operations may reach the same objects in the opposite direction.
        if let Some(nonblock) = mqueue_id
            .and_then(|id| narf_filesystem::mqueuefs::is_nonblock(id).ok())
        {
            if nonblock {
                flags |= crate::fd::O_NONBLOCK as u64;
            } else {
                flags &= !(crate::fd::O_NONBLOCK as u64);
            }
        }
        ctx.set_return(SyscallReturn::ok(flags));
        return;
    }

    if cmd == F_SETFL {
        let mask = crate::fd::O_SETFL_MASK;
        let requested = arg as u32;
        let snapshot = fd::with_table(task, |table| {
            let entry = table.get(fd)?;
            let old = table.status_flags(fd)?;
            // fcntl's syscall entry rejects every command except the small
            // `check_fcntl_cmd` whitelist on an FMODE_PATH file. F_SETFL is
            // therefore EBADF, even though F_GETFL above is allowed to report
            // O_PATH in the shared status word.
            if old & crate::fd::O_PATH != 0 {
                return None;
            }
            // Pin the open file across the mirror updates below. This matches
            // Linux's fdget_raw lifetime if a CLONE_FILES sibling closes the
            // descriptor concurrently, and prevents returning EBADF after
            // already changing socket or mqueue state.
            Some((entry.ops.clone(), table.description(fd)?, old))
        })
        .flatten();

        let Some((ops, description, old)) = snapshot else {
            ctx.set_return(SyscallReturn::ok((-(EBADF as i64)) as u64));
            return;
        };
        let mut new_flags = (old & !mask) | (requested & mask);
        let wanted_async = requested & crate::fd::O_ASYNC != 0;
        let had_async = old & crate::fd::O_ASYNC != 0;
        if wanted_async != had_async {
            if wanted_async {
                let waker = fasync_event_waker(&description);
                let interest = narf_filesystem::POLL_IN
                    | narf_filesystem::POLL_OUT
                    | narf_filesystem::POLL_PRI
                    | narf_filesystem::POLL_ERR
                    | narf_filesystem::POLL_HUP;
                if ops
                    .arm_readiness_persistent(
                        description.fasync_waiter_id(),
                        interest,
                        &waker,
                    )
                    .is_some()
                {
                    description.set_fasync_enabled(true, fd as i32);
                    new_flags |= crate::fd::O_ASYNC;
                }
            } else {
                let _ = ops.disarm_readiness(description.fasync_waiter_id());
                description.set_fasync_enabled(false, -1);
                new_flags &= !crate::fd::O_ASYNC;
            }
        } else if had_async {
            new_flags |= crate::fd::O_ASYNC;
        }
        // Publish the description word only after `fasync` succeeds, matching
        // Linux setfl: an async-provider error leaves f_flags unchanged. The
        // pinned description stays valid even if a CLONE_FILES sibling closes
        // this numeric fd while the readiness callback is installed.
        description.set_status_flags(new_flags);
        let _ = fd::with_table(task, |table| {
            if table
                .description(fd)
                .is_some_and(|current| alloc::sync::Arc::ptr_eq(&current, &description))
            {
                let _ = table.set_status_flags(fd, new_flags);
            }
        });
        let new = requested & mask;
        if let Some(socket) = ops
            .as_any()
            .and_then(|any| any.downcast_ref::<crate::socket::SocketFile>())
        {
            socket.set_nonblock(new & crate::socket::O_NONBLOCK != 0);
        }
        if let Some(id) = ops.mq_queue_id() {
            let _ = narf_filesystem::mqueuefs::set_nonblock(
                id,
                new & crate::fd::O_NONBLOCK != 0,
            );
        }
        // `fs/pipe.c::is_packetized` re-reads `filp->f_flags` on every
        // write, so O_DIRECT set (or cleared) here changes subsequent packet
        // framing rather than merely changing what F_GETFL reports.
        if let Some(pipe) = ops
            .as_any()
            .and_then(|any| any.downcast_ref::<crate::pipe::PipeWrite>())
        {
            pipe.set_packetized(new & crate::fd::O_DIRECT != 0);
        }
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }

    // F_DUPFD / F_DUPFD_CLOEXEC: dup oldfd into the lowest free slot
    // >= arg. Linux returns the new fd. CLOEXEC variant stamps
    // FD_CLOEXEC atomically.
    {
        if cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC {
            // `do_fcntl` receives an already-resolved `struct file *`, so a
            // closed descriptor is -EBADF from the entry's fdget_raw before
            // any per-command argument check runs.
            if !fd::with_table(task, |t| t.get(fd).is_some()).unwrap_or(false) {
                ctx.set_return(SyscallReturn::ok((-(EBADF as i64)) as u64));
                return;
            }
            // `f_dupfd`: `if (from >= nofile) return -EINVAL;` — the floor is
            // rejected before any allocation is attempted, and separately from
            // the -EMFILE that a full table would produce. A caller doing
            // `fcntl(fd, F_DUPFD, 1024)` to park a descriptor above the
            // limit needs EINVAL to learn the floor is the problem.
            //
            // The floor is `int argi = (int)arg` widened back to `unsigned
            // int` by f_dupfd's parameter, i.e. the low 32 bits — NOT the
            // full register. `fcntl(fd, F_DUPFD, 1 << 32)` is a floor of 0 on
            // Linux and duplicates; comparing the untruncated value rejected
            // it with EINVAL instead.
            let min_fd = arg as u32;
            let nofile = read_rlimit(task, RLIMIT_NOFILE_RESOURCE)
                .map(|limit| limit.cur)
                .unwrap_or_else(|| default_rlimits()[RLIMIT_NOFILE_RESOURCE].cur);
            if u64::from(min_fd) >= nofile {
                ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
                return;
            }
            let cloexec = cmd == F_DUPFD_CLOEXEC;
            let outcome = fd::with_table_alloc(task, |t| {
                t.duplicate(fd, min_fd, if cloexec { crate::fd::FD_CLOEXEC } else { 0 })
            });
            match outcome {
                Some(Ok(new_fd)) => {
                    crate::mqueue::duplicate_fd_path(task, fd, new_fd);
                    ctx.set_return(SyscallReturn::ok(new_fd as u64));
                }
                // `f_dupfd` finishes with `alloc_fd(from, nofile, flags)`,
                // whose -EMFILE is distinct from the -EINVAL the floor check
                // above reports: the floor was legal, the table is simply
                // full between it and the limit.
                Some(Err(crate::fd::FdAllocError::TooManyFiles)) => {
                    ctx.set_return(SyscallReturn::ok((-24i64) as u64)); // -EMFILE
                }
                // F_DUPFD on a fd that isn't open → -EBADF (was InvalidOp).
                _ => ctx.set_return(SyscallReturn::ok((-9i64) as u64)),
            }
            return;
        }
    }

    // Linux applies its FMODE_PATH command gate after fdget_raw and before
    // do_fcntl dispatch. F_GETFL/F_SETFL and the dup commands have already
    // returned above; of the commands that reach this point, only the
    // descriptor-local CLOEXEC pair is legal on an O_PATH description.
    if cmd != F_GETFD && cmd != F_SETFD {
        let path_only = fd::with_table(task, |table| {
            table
                .status_flags(fd)
                .map(|flags| flags & crate::fd::O_PATH != 0)
        })
        .flatten();
        match path_only {
            None => {
                ctx.set_return(SyscallReturn::ok((-(EBADF as i64)) as u64));
                return;
            }
            Some(true) => {
                ctx.set_return(SyscallReturn::ok((-(EBADF as i64)) as u64));
                return;
            }
            Some(false) => {}
        }
    }

    if matches!(
        cmd,
        F_SETOWN | F_GETOWN | F_SETSIG | F_GETSIG | F_SETOWN_EX | F_GETOWN_EX
    ) {
        let Some(description) = fd::with_table(task, |table| table.description(fd)).flatten()
        else {
            ctx.set_return(SyscallReturn::ok((-(EBADF as i64)) as u64));
            return;
        };
        match cmd {
            F_SETOWN => {
                let who = arg as i32;
                let owner = if who == 0 {
                    crate::fd::FasyncOwner::None
                } else if who > 0 {
                    match resolve_fasync_task(task, who, false) {
                        Some(target) => crate::fd::FasyncOwner::Process(target),
                        None => {
                            ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // -ESRCH
                            return;
                        }
                    }
                } else {
                    if who == i32::MIN {
                        ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
                        return;
                    }
                    let group = pgid_from_user((-who) as u64);
                    if group == 0 || pgrp_task_snapshot(group).is_empty() {
                        ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // -ESRCH
                        return;
                    }
                    crate::fd::FasyncOwner::ProcessGroup(group)
                };
                let ids = read_uidgid(task);
                let owner_type = if who < 0 { F_OWNER_PGRP } else { F_OWNER_PID };
                description.set_fasync_owner(owner, owner_type, ids.uid, ids.euid);
                ctx.set_return(SyscallReturn::ok(0));
            }
            F_GETOWN => {
                let state = description.fasync_snapshot();
                let (owner_type, visible) = fasync_owner_to_user(task, state);
                let value = if owner_type == F_OWNER_PGRP && visible != 0 {
                    -visible
                } else {
                    visible
                };
                // Linux calls force_successful_syscall_return here so a
                // negative pgrp id is data, not an errno.
                ctx.set_return(SyscallReturn::ok(value as i64 as u64));
            }
            F_SETSIG => {
                let signal = arg as i32;
                if !(0..=64).contains(&signal) {
                    ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
                    return;
                }
                description.set_fasync_signal(signal as u32);
                ctx.set_return(SyscallReturn::ok(0));
            }
            F_GETSIG => {
                ctx.set_return(SyscallReturn::ok(
                    description.fasync_snapshot().signal as u64,
                ));
            }
            F_SETOWN_EX => {
                let mut bytes = [0u8; core::mem::size_of::<FOwnerEx>()];
                // SAFETY: Linux copies the complete fixed-size f_owner_ex
                // before validating its type or pid; copy_from_user performs
                // the range/fault checks for the supplied pointer.
                if unsafe { copy_from_user(&mut bytes, arg) }.is_err() {
                    ctx.set_return(SyscallReturn::ok((-(EFAULT as i64)) as u64));
                    return;
                }
                let owner_type = i32::from_ne_bytes(bytes[0..4].try_into().unwrap());
                let visible = i32::from_ne_bytes(bytes[4..8].try_into().unwrap());
                if !matches!(owner_type, F_OWNER_TID | F_OWNER_PID | F_OWNER_PGRP) {
                    ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
                    return;
                }
                let owner = if visible == 0 {
                    crate::fd::FasyncOwner::None
                } else if visible < 0 {
                    ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // -ESRCH
                    return;
                } else {
                    match owner_type {
                        F_OWNER_TID => resolve_fasync_task(task, visible, true)
                            .map(crate::fd::FasyncOwner::Tid),
                        F_OWNER_PID => resolve_fasync_task(task, visible, false)
                            .map(crate::fd::FasyncOwner::Process),
                        F_OWNER_PGRP => {
                            let group = pgid_from_user(visible as u64);
                            (!pgrp_task_snapshot(group).is_empty())
                                .then_some(crate::fd::FasyncOwner::ProcessGroup(group))
                        }
                        _ => None,
                    }
                    .unwrap_or(crate::fd::FasyncOwner::None)
                };
                if visible != 0 && owner == crate::fd::FasyncOwner::None {
                    ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // -ESRCH
                    return;
                }
                let ids = read_uidgid(task);
                description.set_fasync_owner(owner, owner_type, ids.uid, ids.euid);
                ctx.set_return(SyscallReturn::ok(0));
            }
            F_GETOWN_EX => {
                let state = description.fasync_snapshot();
                let (owner_type, visible) = fasync_owner_to_user(task, state);
                let mut bytes = [0u8; core::mem::size_of::<FOwnerEx>()];
                bytes[0..4].copy_from_slice(&owner_type.to_ne_bytes());
                bytes[4..8].copy_from_slice(&visible.to_ne_bytes());
                // SAFETY: fixed-size copy to the caller's f_owner_ex pointer;
                // copy_to_user validates and fault-brackets the destination.
                if unsafe { copy_to_user(arg, &bytes) }.is_err() {
                    ctx.set_return(SyscallReturn::ok((-(EFAULT as i64)) as u64));
                } else {
                    ctx.set_return(SyscallReturn::ok(0));
                }
            }
            _ => unreachable!(),
        }
        return;
    }

    if cmd == F_GET_RW_HINT || cmd == F_SET_RW_HINT {
        let Some(ops) = fd::with_table(task, |table| table.get(fd).map(|entry| entry.ops.clone()))
            .flatten()
        else {
            ctx.set_return(SyscallReturn::ok((-(EBADF as i64)) as u64));
            return;
        };
        if cmd == F_GET_RW_HINT {
            let bytes = rw_hint_get(&ops).to_ne_bytes();
            // SAFETY: fixed-size u64 copy to the caller's hint pointer;
            // copy_to_user validates and fault-brackets the destination.
            if unsafe { copy_to_user(arg, &bytes) }.is_err() {
                ctx.set_return(SyscallReturn::ok((-(EFAULT as i64)) as u64));
            } else {
                ctx.set_return(SyscallReturn::ok(0));
            }
            return;
        }

        // Linux checks inode ownership/CAP_FOWNER before dereferencing arg.
        // This ordering is observable when an unprivileged caller supplies a
        // bad pointer: EPERM wins over EFAULT.
        let (uid, gid) = ops.owners();
        if !inode_owner_or_capable(task, uid, gid) {
            ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // -EPERM
            return;
        }
        let mut bytes = [0u8; 8];
        // SAFETY: fixed-size u64 copy from the caller's hint pointer;
        // copy_from_user validates and fault-brackets the source.
        if unsafe { copy_from_user(&mut bytes, arg) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-(EFAULT as i64)) as u64));
            return;
        }
        let hint = u64::from_ne_bytes(bytes);
        if hint > 5 {
            ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
            return;
        }
        rw_hint_set(&ops, hint);
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }

    // F_GETLK / F_SETLK / F_SETLKW and their F_OFD_* counterparts:
    // advisory record locking. Always compiled in (the Linux ABI surface is
    // unconditional); the wire `struct flock` layout + BTreeMap lock table
    // serve Linux ABI consumers.
    //
    // The OFD trio shares this entire path. `fcntl_setlk`/`fcntl_getlk`
    // reuse the POSIX implementation and differ in three places, all of
    // them below: `l_pid` must be zero on input, the owner is the open file
    // description instead of the process, and a reported OFD lock has
    // `l_pid = -1` because `locks_translate_pid` refuses to invent a
    // process for an owner that is not one.
    {
        let is_ofd = cmd == F_OFD_GETLK || cmd == F_OFD_SETLK || cmd == F_OFD_SETLKW;
        let is_getlk = cmd == F_GETLK || cmd == F_OFD_GETLK;
        let is_wait = cmd == F_SETLKW || cmd == F_OFD_SETLKW;
        if cmd == F_GETLK || cmd == F_SETLK || cmd == F_SETLKW || is_ofd {
            // Resolve the open-file identity from the fd table. `key` is the
            // FileOps identity (per inode — locks are a property of the file,
            // whoever opened it); `owner_desc` is the description identity,
            // which is what an OFD lock is owned BY.
            let ops_key = fd::with_table(task, |t| {
                t.get(fd).map(|e| {
                    (
                        e.ops.clone(),
                        alloc::sync::Arc::as_ptr(&e.ops) as *const () as usize,
                    )
                })
            });
            let (ops, key) = match ops_key {
                Some(Some(v)) => v,
                _ => {
                    ctx.set_return(SyscallReturn::ok((-(EBADF as i64)) as u64));
                    return;
                }
            };
            let owner_desc = fd::with_table(task, |t| t.description_lock_owner(fd)).flatten();
            let (lock_owner, lock_kind) = if is_ofd {
                match owner_desc {
                    Some(d) => (d, crate::fd::locks::LockKind::Ofd),
                    None => {
                        ctx.set_return(SyscallReturn::ok((-(EBADF as i64)) as u64));
                        return;
                    }
                }
            } else {
                (task, crate::fd::locks::LockKind::Posix)
            };
            // Pull the `struct flock` from user memory.
            let mut bytes = alloc::vec![0u8; flock_size()];
            // SAFETY: `arg` is the user `struct flock` pointer; copy_from_user
            // range-validates it and SMAP-brackets the read into the sized `bytes`.
            // SAFETY: Valid memory or trusted environment
            if unsafe { copy_from_user(&mut bytes, arg) }.is_err() {
                ctx.set_return(SyscallReturn::ok((-(EFAULT as i64)) as u64));
                return;
            }
            // SAFETY: `bytes` holds exactly `flock_size()` validated bytes and
            // `tmp` is a default-initialized UFlock with at least that many bytes;
            // the copy reinterprets the wire layout into the repr(C) struct.
            // SAFETY: Valid memory or trusted environment
            let uf: UFlock = unsafe {
                let mut tmp = UFlock::default();
                core::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    &mut tmp as *mut _ as *mut u8,
                    flock_size(),
                );
                tmp
            };
            // `flock_to_posix_lock`: l_start is relative to l_whence, and
            // all three origins are legal. This used to accept only
            // SEEK_SET and call the rest "OFD-tier work" — both inputs it
            // needs are right here, the description's offset and the file
            // size, so the restriction went away with the OFD commands that
            // prompted it. `sqlite` locks at SEEK_SET offsets, but plenty of
            // code locks the tail of a file with SEEK_END.
            const SEEK_SET: i16 = 0;
            const SEEK_CUR: i16 = 1;
            const SEEK_END: i16 = 2;
            let origin: i64 = match uf.l_whence {
                SEEK_SET => 0,
                SEEK_CUR => fd::with_table(task, |t| t.offset(fd))
                    .flatten()
                    .unwrap_or(0) as i64,
                SEEK_END => ops.stat().size as i64,
                _ => {
                    ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
                    return;
                }
            };
            // `if (l->l_start > OFFSET_MAX - start) return -EOVERFLOW;`
            let Some(abs_start) = origin.checked_add(uf.l_start) else {
                ctx.set_return(SyscallReturn::ok((-75i64) as u64)); // -EOVERFLOW
                return;
            };
            let mut uf = uf;
            uf.l_start = abs_start;
            // `if (flock->l_pid != 0) goto out;` — the OFD commands reject a
            // non-zero l_pid outright rather than ignoring it, so a caller
            // that filled the field in (as it would for F_GETLK) learns the
            // struct means something different here.
            if is_ofd && uf.l_pid != 0 {
                ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
                return;
            }
            let req = crate::fd::locks::Lock {
                owner: lock_owner,
                kind: lock_kind,
                // Captured here because the lock table keys by FileOps
                // pointer and cannot resolve one later — see `Lock::dev`.
                dev: ops.inode_attrs().dev,
                ino: ops.ino(),
                ty: uf.l_type,
                start: uf.l_start,
                len: uf.l_len,
            };
            let (lock_start, end) = if uf.l_len == 0 {
                (uf.l_start, u64::MAX)
            } else if uf.l_len > 0 {
                (
                    uf.l_start,
                    (uf.l_start as u64).saturating_add(uf.l_len as u64 - 1),
                )
            } else {
                (
                    uf.l_start.saturating_add(uf.l_len),
                    (uf.l_start as u64).saturating_sub(1),
                )
            };
            if lock_start < 0 {
                ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
                return;
            }
            let native = narf_filesystem::FileLock {
                start: lock_start as u64,
                end,
                type_: uf.l_type as u32,
                pid: task as u32,
            };
            if is_getlk {
                // `lock_owner`, not `task`: a filesystem that implements
                // locking itself (FUSE forwards them to its server) is
                // handed Linux's `fl_owner`, which is the description for an
                // OFD lock and the process for a POSIX one. Passing `task`
                // for both would make a server see two distinct OFD locks
                // from one process as the same owner, and stop them
                // conflicting.
                match poll_blocking(ops.get_lock(lock_owner, native)) {
                    Some(Ok(lock)) => {
                        let mut out = uf;
                        out.l_type = lock.type_ as i16;
                        out.l_start = lock.start as i64;
                        out.l_len = if lock.end == u64::MAX {
                            0
                        } else {
                            lock.end.saturating_sub(lock.start).saturating_add(1) as i64
                        };
                        // l_pid is the CALLER's-namespace pid of the lock
                        // owner (Linux locks_translate_pid). The lock table
                        // stamps owners in TaskId space, so translate TaskId
                        // -> outer -> caller's ns view rather than leaking a
                        // raw scheduler id to lslocks/sqlite.
                        out.l_pid = report_pid_to(
                            task,
                            task_to_pid_raw(lock.pid as u64).unwrap_or(lock.pid as u64),
                        ) as i32;
                        if write_flock_to_user(arg, &out).is_err() {
                            ctx.set_return(SyscallReturn::ok((-(EFAULT as i64)) as u64));
                        } else {
                            ctx.set_return(SyscallReturn::ok(0));
                        }
                        return;
                    }
                    Some(Err(narf_filesystem::FsError::Unsupported)) | None => {}
                    _ => {
                        ctx.set_return(SyscallReturn::ok((-5i64) as u64));
                        return;
                    }
                }
                let blocker = crate::fd::locks::probe(key, req);
                let mut out = uf;
                match blocker {
                    None => out.l_type = crate::fd::locks::F_UNLCK,
                    Some(b) => {
                        out.l_type = b.ty;
                        out.l_start = b.start;
                        out.l_len = b.len;
                        // `locks_translate_pid`: an OFD lock reports -1,
                        // whatever asked. Its owner is an open file
                        // description, so there is no process to name — and
                        // the description may well outlive the task that
                        // created it, or be shared by several. Reporting the
                        // creator's pid would send `lslocks` (and anything
                        // else acting on l_pid) after the wrong process.
                        out.l_pid = if b.kind == crate::fd::locks::LockKind::Ofd {
                            -1
                        } else {
                            report_pid_to(task, task_to_pid_raw(b.owner).unwrap_or(b.owner)) as i32
                        };
                    }
                }
                if write_flock_to_user(arg, &out).is_err() {
                    ctx.set_return(SyscallReturn::ok((-(EFAULT as i64)) as u64));
                    return;
                }
                ctx.set_return(SyscallReturn::ok(0));
                return;
            }
            // F_SETLK / F_SETLKW.
            match poll_blocking(ops.set_lock(lock_owner, native, is_wait)) {
                Some(Ok(())) => {
                    ctx.set_return(SyscallReturn::ok(0));
                    return;
                }
                Some(Err(narf_filesystem::FsError::Unsupported)) | None => {}
                Some(Err(narf_filesystem::FsError::Busy)) => {
                    ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
                    return;
                }
                _ => {
                    ctx.set_return(SyscallReturn::ok((-5i64) as u64));
                    return;
                }
            }
            match crate::fd::locks::try_set(key, req) {
                Ok(()) => {
                    // A re-executed SETLKW arrives here with the uctx
                    // routing still set — clear it so a later unrelated
                    // park can't spuriously register on the flock queue.
                    clear_flock_routing();
                    if uf.l_type == crate::fd::locks::F_UNLCK {
                        // A range was released — wake every parked
                        // F_SETLKW waiter on this file so it retries NOW
                        // instead of riding out its 1 ms backstop. Fired
                        // after the waiter lock drops (drain collects).
                        for (tid, w) in crate::fd::locks::drain_waiters(key) {
                            wake_one(tid, w);
                        }
                    } else {
                        // Acquire (possibly a re-executed SETLKW that just
                        // won): retire any waiter entry left from the park.
                        crate::fd::locks::drop_waiter(key, task);
                    }
                    ctx.set_return(SyscallReturn::ok(0));
                }
                Err(_) if is_wait => {
                    // Blocking acquire. Linux F_SETLKW is signal-
                    // interruptible (EINTR) — check before parking so a
                    // pending signal breaks the wait instead of being
                    // starved by the retry loop.
                    if is_signal_pending(task) {
                        crate::fd::locks::drop_waiter(key, task);
                        clear_flock_routing();
                        ctx.set_return(SyscallReturn::ok((-4i64) as u64)); // -EINTR
                        return;
                    }
                    // Park ~1ms with RIP rewound so the WHOLE fcntl
                    // re-executes on resume and retries try_set — the
                    // same re-execute shape as the blocking console
                    // read; the holder's unlock (or exit — see
                    // `locks::release_owner` in the exit sweep) makes a
                    // later retry succeed. No executor wired (the
                    // kernel-test harness) → degrade to the
                    // non-blocking EAGAIN answer, like flock's
                    // no-executor tail.
                    if let (Some(uctx), Some(hook)) = (
                        crate::user_task::current_user_task(),
                        crate::user_task::yield_hook(),
                    ) {
                        let resume_rip = ctx.rip().wrapping_sub(2);
                        ctx.set_rip(resume_rip);
                        let dl =
                            narf_scheduler::narf_time::monotonic_ns().saturating_add(1_000_000);
                        // SAFETY: `uctx` is the live per-task UserTaskCtx from
                        // current_user_task(); we hold the only reference while
                        // setting the deadline and saving the RIP-rewound CPU
                        // state before the yield hook hands the task over.
                        // SAFETY: Valid memory or trusted environment
                        unsafe {
                            let uc = &*uctx;
                            // Clear a stale futex_uaddr so the park can't
                            // mis-route into the futex branch (same guard
                            // as the blocking pipe-read park).
                            uc.futex_uaddr
                                .store(0, core::sync::atomic::Ordering::Release);
                            // Route the park to the lock key's waiter queue
                            // (park_should_block registers the waker there),
                            // so the holder's unlock wakes us immediately.
                            uc.flock_key
                                .store(key, core::sync::atomic::Ordering::Release);
                            uc.sleep_deadline_ns
                                .store(dl, core::sync::atomic::Ordering::Release);
                            ctx.save_user_state(uc.state.get() as *mut u8);
                            *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
                            if narf_scheduler::stackful::user_own_stack_enabled() {
                                own_stack_block(ctx);
                                return;
                            }
                            hook(uctx);
                        }
                        // unreachable when parked
                    }
                    crate::fd::locks::drop_waiter(key, task);
                    clear_flock_routing();
                    ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
                }
                Err(_) => {
                    ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
                }
            }
            return;
        }
    }

    // Wave-70: memfd seals. Route F_ADD_SEALS / F_GET_SEALS before
    // the generic fd-table lookup so the seal word lives on the
    // concrete MemFdFile rather than as a per-fd flag.
    {
        // `fs/fcntl.c` routes both seal commands into `mm/memfd.c::
        // memfd_fcntl`, which reaches `memfd_file_seals_ptr(file)`:
        // a file that is not a sealable memfd yields NULL and the command
        // fails -EINVAL. Answering -EPERM instead (the old `-1` sentinel)
        // reads as "you are not allowed to seal this", which sends a caller
        // looking for a privilege it does not need — the file simply has no
        // seal word. A closed descriptor is still -EBADF, from the fdget in
        // the syscall entry, ahead of any of this.
        if cmd == F_ADD_SEALS || cmd == F_GET_SEALS {
            let open = fd::with_table(task, |t| t.get(fd).is_some()).unwrap_or(false);
            if !open {
                ctx.set_return(SyscallReturn::ok((-(EBADF as i64)) as u64));
                return;
            }
            let Some(mfd) = memfd_arc_from_fd(task, fd) else {
                ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
                return;
            };
            if cmd == F_GET_SEALS {
                ctx.set_return(SyscallReturn::ok(mfd.seals() as u64));
                return;
            }
            // `memfd_add_seals` opens with
            // `if (!(file->f_mode & FMODE_WRITE)) return -EPERM;`: sealing
            // mutates shared state, so a read-only handle may not do it.
            let writable = fd::with_table(task, |t| {
                t.status_flags(fd).map(|flags| {
                    flags & crate::fd::O_ACCMODE != crate::fd::O_RDONLY
                        && flags & crate::fd::O_PATH == 0
                })
            })
            .flatten()
            .unwrap_or(false);
            if !writable {
                ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // -EPERM
                return;
            }
            let r = match mfd.add_seals(arg as u32) {
                Ok(()) => SyscallReturn::ok(0),
                Err(crate::linux_compat::SealError::Invalid) => {
                    SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64)
                }
                Err(crate::linux_compat::SealError::Denied) => {
                    SyscallReturn::ok((-1i64) as u64) // -EPERM
                }
            };
            ctx.set_return(r);
            return;
        }
    }

    let outcome = fd::with_table(task, |t| {
        let entry = t.get(fd)?;
        Some(match cmd {
            F_GETFD => SyscallReturn::ok((entry.flags & crate::fd::FD_CLOEXEC) as u64),
            F_SETFD => {
                // `set_close_on_exec(fd, argi & FD_CLOEXEC)`: unknown bits
                // are ignored and must never reappear through F_GETFD.
                t.get_mut(fd)?.flags = (arg as u32) & crate::fd::FD_CLOEXEC;
                SyscallReturn::ok(0)
            }
            // F_GETPIPE_SZ (1032) / F_SETPIPE_SZ (1031): report or resize the
            // pipe buffer. `pipe_fcntl()` returns EBADF, not EINVAL, when the
            // descriptor is valid but not a pipe. stress-ng's pipe stressor
            // queries F_GETPIPE_SZ to size its I/O buffer.
            1032 => match entry.ops.pipe_capacity() {
                Some(cap) => SyscallReturn::ok(cap as u64),
                None => SyscallReturn::ok((-(EBADF as i64)) as u64),
            },
            1031 => {
                // fcntl truncates arg through `int argi`; pipe_fcntl receives
                // that low 32-bit value as unsigned int.
                let size_arg = arg as u32;
                let resized = entry.ops.as_any().and_then(|any| {
                    if let Some(pipe) = any.downcast_ref::<crate::pipe::PipeRead>() {
                        Some(pipe.set_capacity(size_arg))
                    } else {
                        any.downcast_ref::<crate::pipe::PipeWrite>()
                            .map(|pipe| pipe.set_capacity(size_arg))
                    }
                });
                match resized {
                    Some(Ok(cap)) => SyscallReturn::ok(cap as u64),
                    Some(Err(errno)) => SyscallReturn::ok((-(errno as i64)) as u64),
                    // FIFOs expose pipe_capacity too. Their fixed backing is a
                    // compatibility implementation: validate Linux's global
                    // size errors, then report the live capacity.
                    None => match entry.ops.pipe_capacity() {
                        None => SyscallReturn::ok((-(EBADF as i64)) as u64),
                        Some(_) if size_arg > (1u32 << 31) => {
                            SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64)
                        }
                        Some(_) if (size_arg as usize).max(4096).next_power_of_two() > 1_048_576 => {
                            SyscallReturn::ok((-1i64) as u64) // -EPERM
                        }
                        Some(cap) => SyscallReturn::ok(cap as u64),
                    },
                }
            }
            // F_GETLEASE (1024+1). NARF has no lease machinery: there is no
            // lease break on a conflicting open, no `lease_break_time` timer
            // and no SIGIO to deliver the break. Linux ships an answer for
            // exactly that configuration — `include/linux/filelock.h` under
            // `#else /* !CONFIG_FILE_LOCKING */`:
            //
            //   static inline int fcntl_getlease(struct file *filp)
            //   { return F_UNLCK; }
            //
            // F_UNLCK (2) is "no lease is held on this file", which is the
            // truth here. The default arm below used to answer this with
            // `invalid_op()`, whose `value` is 0 — and 0 is F_RDLCK, so every
            // caller that asked was told a read lease existed. A file server
            // reading that answer concludes it may serve cached content
            // without revalidating, because it believes the kernel will break
            // the lease if anyone else opens the file.
            1025 => SyscallReturn::ok(F_UNLCK_LEASE),
            // F_SETLEASE (1024). Same stub block, one line up:
            //
            //   static inline int fcntl_setlease(unsigned int fd,
            //                   struct file *filp, int arg) { return -EINVAL; }
            //
            // `shmem_file_operations.setlease = generic_setlease`, so tmpfs
            // does support leases on Linux and this is a real gap rather than
            // a nonexistent command — but -EINVAL is the answer Linux itself
            // gives when the machinery is compiled out, and it is the one a
            // caller can act on. `fcntl_setlease` also rejects directories
            // with -EINVAL regardless of config, so both shapes agree.
            1024 => SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64),
            // Every command NARF does not implement. `fs/fcntl.c::do_fcntl`
            // opens with `long err = -EINVAL;` and its `default:` arm is a
            // bare `break`, so an unhandled command is -EINVAL.
            //
            // This arm was `invalid_op()`, which sets `value = 0` and reports
            // the real status in rdx/x1 — a register the Linux ABI does not
            // read. Userspace therefore saw rax = 0: success. Every
            // unimplemented command was silently granted. The concrete
            // damage, beyond the leases above:
            //
            //   * F_OFD_SETLK / F_OFD_SETLKW (37/38) returned "lock acquired"
            //     to every caller at once, so two processes could each believe
            //     they held the same exclusive range. That was then narrowed
            //     to -EINVAL, which callers that probe for OFD support
            //     (sqlite, LMDB) read as "not available" so they fall back to
            //     POSIX locks. The three commands are now implemented and
            //     handled above, so neither answer applies to them any more.
            //   * F_SETOWN / F_SETSIG (8/10) returned "owner installed", so a
            //     caller waiting for SIGIO on that descriptor waits forever
            //     instead of learning async I/O is unavailable.
            //   * F_NOTIFY (1026) returned "directory watch armed".
            //
            // Answering -EINVAL cannot regress a working command: the arms
            // above, and the F_DUPFD / F_GETLK / F_SETLK / F_SETLKW /
            // F_ADD_SEALS / F_GET_SEALS blocks earlier in this function, all
            // return before reaching here. Only commands whose sole previous
            // answer was a fabricated 0 land in this arm.
            _ => SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64),
        })
    });
    match outcome {
        Some(Some(r)) => ctx.set_return(r),
        // Linux validates the descriptor before dispatching the command
        // (`fs/fcntl.c::SYSCALL_DEFINE3(fcntl)`).  In particular, callers such
        // as D-Bus use F_GETFD to probe inherited descriptors and must observe
        // -EBADF for a closed slot, not NARF's internal InvalidOp value (zero
        // on the Linux return-value wire).
        _ => ctx.set_return(SyscallReturn::ok((-(EBADF as i64)) as u64)),
    }
}
