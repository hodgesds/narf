//! System V IPC — semaphores (`sem*`) and message queues (`msg*`).
//!
//! Self-contained side-table implementations that work in any
//! `linux-compat` build (independent of the container IPC-namespace
//! infrastructure, which provides only the id-by-key `*get` surface).
//! Shared memory (`shm*`) lives separately since it needs address-space
//! frame mapping.
//!
//! Blocking semaphore operations and message receives use the userspace
//! executor's interruptible I/O park/re-execute bridge.  `IPC_NOWAIT`
//! retains Linux's immediate `EAGAIN`/`ENOMSG` behavior.
//!
//! Gated under `#[cfg(feature = "linux-compat")]` via the `pub mod`
//! line in `lib.rs`.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::syscall::{SyscallReturn, TrapContext};

// ── errno + IPC constants ────────────────────────────────────────────
const ENOENT: i64 = 2;
const EPERM: i64 = 1;
const EINTR: i64 = 4;
const E2BIG: i64 = 7;
const EAGAIN: i64 = 11;
const EACCES: i64 = 13;
const EFAULT: i64 = 14;
const EEXIST: i64 = 17;
const EINVAL: i64 = 22;
const ENOMSG: i64 = 42;
const EIDRM: i64 = 43;
const ERANGE: i64 = 34;

fn err(e: i64) -> SyscallReturn {
    SyscallReturn::ok((-e) as u64)
}

type IpcObjectKey = (u64, u64); // (IPC namespace id, namespace-local object id)

#[cfg(feature = "container")]
fn current_ipc_namespace_id() -> u64 {
    crate::namespaces::current_ipc_namespace(crate::handlers::current_task_id()).id()
}

#[cfg(not(feature = "container"))]
fn current_ipc_namespace_id() -> u64 {
    0
}

#[cfg(feature = "container")]
fn alloc_sem_id() -> u64 {
    u64::from(
        crate::namespaces::current_ipc_namespace(crate::handlers::current_task_id()).alloc_sem_id(),
    )
}

#[cfg(not(feature = "container"))]
fn alloc_sem_id() -> u64 {
    SEM_NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

#[cfg(feature = "container")]
fn alloc_msg_id() -> u64 {
    u64::from(
        crate::namespaces::current_ipc_namespace(crate::handlers::current_task_id()).alloc_msg_id(),
    )
}

#[cfg(not(feature = "container"))]
fn alloc_msg_id() -> u64 {
    MSG_NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

const IPC_CREAT: u64 = 0o1000;
const IPC_EXCL: u64 = 0o2000;
const IPC_NOWAIT: i16 = 0o4000;
const IPC_PRIVATE: u64 = 0;
const IPC_PERM_MASK: u32 = 0o777;
const SEM_UNDO: i16 = 0o10000;
const SEMVMX: i32 = 32767;

// ipc control cmds (low bits; libc ORs IPC_64 = 0x100 which we mask off).
const IPC_RMID: u64 = 0;
const IPC_SET: u64 = 1;
const IPC_STAT: u64 = 2;

// semctl cmds.
const GETVAL: u64 = 12;
const GETALL: u64 = 13;
const SETVAL: u64 = 16;
const SETALL: u64 = 17;

#[cfg(target_arch = "x86_64")]
const SEMID64_SIZE: usize = 104;
#[cfg(target_arch = "x86_64")]
const SEM_OTIME_OFFSET: usize = 48;
#[cfg(target_arch = "x86_64")]
const SEM_CTIME_OFFSET: usize = 64;
#[cfg(target_arch = "x86_64")]
const SEM_NSEMS_OFFSET: usize = 80;
#[cfg(target_arch = "aarch64")]
const SEMID64_SIZE: usize = 88;
#[cfg(target_arch = "aarch64")]
const SEM_OTIME_OFFSET: usize = 48;
#[cfg(target_arch = "aarch64")]
const SEM_CTIME_OFFSET: usize = 56;
#[cfg(target_arch = "aarch64")]
const SEM_NSEMS_OFFSET: usize = 64;
const MSQID64_SIZE: usize = 120;

fn put_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
}

fn put_i32(out: &mut [u8], offset: usize, value: i32) {
    out[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
}

fn put_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
}

fn put_i64(out: &mut [u8], offset: usize, value: i64) {
    out[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
}

fn get_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes(input[offset..offset + 4].try_into().unwrap())
}

fn get_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_ne_bytes(input[offset..offset + 8].try_into().unwrap())
}

fn encode_perm(out: &mut [u8], key: u32, uid: u32, gid: u32, cuid: u32, cgid: u32, mode: u32) {
    put_u32(out, 0, key);
    put_u32(out, 4, uid);
    put_u32(out, 8, gid);
    put_u32(out, 12, cuid);
    put_u32(out, 16, cgid);
    put_u32(out, 20, mode & IPC_PERM_MASK);
}

// ════════════════════════════════════════════════════════════════════
// Semaphores
// ════════════════════════════════════════════════════════════════════

struct SemSet {
    key: u32,
    sems: Vec<i32>,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    mode: u32,
    otime: i64,
    ctime: i64,
}

static SEMS: IrqSafeSpinLock<Option<BTreeMap<IpcObjectKey, SemSet>>> = IrqSafeSpinLock::new(None);
#[cfg(not(feature = "container"))]
static SEM_NEXT_ID: AtomicU64 = AtomicU64::new(1);
type SemUndoTable = BTreeMap<(u64, u64, u64, usize), i32>;
static SEM_UNDOS: IrqSafeSpinLock<Option<SemUndoTable>> = IrqSafeSpinLock::new(None);
#[derive(Default)]
struct SemUndoSharing {
    owner_of: BTreeMap<u64, u64>,
    refs: BTreeMap<u64, usize>,
}
static SEM_UNDO_SHARING: IrqSafeSpinLock<Option<SemUndoSharing>> = IrqSafeSpinLock::new(None);
static SEM_UNDO_OBSERVER_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Linux's default SEMOPM limit.  This sizes the fixed import buffer as well
/// as defining the observable E2BIG boundary.
const MAX_SOPS: usize = 500;

fn with_sems<R>(f: impl FnOnce(&mut BTreeMap<IpcObjectKey, SemSet>) -> R) -> R {
    let mut g = SEMS.lock();
    f(g.get_or_insert_with(BTreeMap::new))
}

fn now_seconds() -> i64 {
    narf_scheduler::narf_time::now_wall().secs
}

fn current_identity() -> (u64, u32, u32, Vec<u32>) {
    let cred = crate::handlers::current_ucred();
    (
        u64::from(cred.pid),
        cred.uid,
        cred.gid,
        crate::handlers::current_groups(),
    )
}

#[allow(clippy::too_many_arguments)] // Mirrors all five ipc64_perm identity fields explicitly.
fn ipc_allowed(
    caller_uid: u32,
    caller_gid: u32,
    caller_groups: &[u32],
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    mode: u32,
    request: u32,
) -> bool {
    if caller_uid == 0 {
        return true;
    }
    let granted = if caller_uid == uid || caller_uid == cuid {
        (mode >> 6) & 0o7
    } else if caller_gid == gid
        || caller_gid == cgid
        || caller_groups.contains(&gid)
        || caller_groups.contains(&cgid)
    {
        (mode >> 3) & 0o7
    } else {
        mode & 0o7
    };
    granted & request == request
}

fn ipc_owner(caller_uid: u32, uid: u32, cuid: u32) -> bool {
    caller_uid == 0 || caller_uid == uid || caller_uid == cuid
}

fn ipc_ids_to_user(uid: u32, gid: u32) -> (u32, u32) {
    #[cfg(feature = "container")]
    {
        let ns = crate::namespaces::current_user_ns(crate::handlers::current_task_id());
        (
            ns.translate_uid_from_host(uid)
                .unwrap_or(crate::namespaces::OVERFLOW_ID),
            ns.translate_gid_from_host(gid)
                .unwrap_or(crate::namespaces::OVERFLOW_ID),
        )
    }
    #[cfg(not(feature = "container"))]
    (uid, gid)
}

fn ipc_ids_from_user(uid: u32, gid: u32) -> Result<(u32, u32), i64> {
    #[cfg(feature = "container")]
    {
        let ns = crate::namespaces::current_user_ns(crate::handlers::current_task_id());
        if !ns.uid_is_mapped(uid) || !ns.gid_is_mapped(gid) {
            return Err(EINVAL);
        }
        Ok((ns.translate_uid_to_host(uid), ns.translate_gid_to_host(gid)))
    }
    #[cfg(not(feature = "container"))]
    Ok((uid, gid))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WaitKind {
    Sem,
    MsgSend,
    MsgRecv,
}

#[derive(Clone)]
enum WaitData {
    None,
    Sem {
        sops: Vec<u8>,
        nsops: usize,
        timeout: Option<(i64, i64)>,
    },
    MsgSend {
        mtype: i64,
        payload: Vec<u8>,
        msgflg: u64,
    },
}

#[derive(Clone)]
struct IpcWait {
    kind: WaitKind,
    ipc_ns: u64,
    id: u64,
    errno: i64,
    data: WaitData,
}

static IPC_WAITS: IrqSafeSpinLock<Option<BTreeMap<u64, IpcWait>>> = IrqSafeSpinLock::new(None);

fn with_waits<R>(f: impl FnOnce(&mut BTreeMap<u64, IpcWait>) -> R) -> R {
    let mut waits = IPC_WAITS.lock();
    f(waits.get_or_insert_with(BTreeMap::new))
}

fn begin_wait(task: u64, kind: WaitKind, ipc_ns: u64, id: u64) {
    with_waits(|waits| {
        waits.entry(task).or_insert_with(|| IpcWait {
            kind,
            ipc_ns,
            id,
            errno: 0,
            data: WaitData::None,
        });
    });
}

fn begin_sem_wait(
    task: u64,
    ipc_ns: u64,
    id: u64,
    sops: &[u8],
    nsops: usize,
    timeout: Option<(i64, i64)>,
) {
    with_waits(|waits| {
        waits.entry(task).or_insert_with(|| IpcWait {
            kind: WaitKind::Sem,
            ipc_ns,
            id,
            errno: 0,
            data: WaitData::Sem {
                sops: sops.to_vec(),
                nsops,
                timeout,
            },
        });
    });
}

fn begin_msg_send_wait(task: u64, ipc_ns: u64, id: u64, mtype: i64, payload: Vec<u8>, msgflg: u64) {
    with_waits(|waits| {
        waits.entry(task).or_insert_with(|| IpcWait {
            kind: WaitKind::MsgSend,
            ipc_ns,
            id,
            errno: 0,
            data: WaitData::MsgSend {
                mtype,
                payload,
                msgflg,
            },
        });
    });
}

type StagedSemWait = (Vec<u8>, usize, Option<(i64, i64)>);

fn staged_sem_wait(task: u64, ipc_ns: u64, id: u64) -> Option<StagedSemWait> {
    with_waits(|waits| {
        let wait = waits.get(&task)?;
        if wait.kind != WaitKind::Sem || wait.ipc_ns != ipc_ns || wait.id != id || wait.errno != 0 {
            return None;
        }
        match &wait.data {
            WaitData::Sem {
                sops,
                nsops,
                timeout,
            } => Some((sops.clone(), *nsops, *timeout)),
            _ => None,
        }
    })
}

fn staged_msg_send_wait(task: u64, ipc_ns: u64, id: u64) -> Option<(i64, Vec<u8>, u64)> {
    with_waits(|waits| {
        let wait = waits.get(&task)?;
        if wait.kind != WaitKind::MsgSend
            || wait.ipc_ns != ipc_ns
            || wait.id != id
            || wait.errno != 0
        {
            return None;
        }
        match &wait.data {
            WaitData::MsgSend {
                mtype,
                payload,
                msgflg,
            } => Some((*mtype, payload.clone(), *msgflg)),
            _ => None,
        }
    })
}

fn clear_wait(task: u64, kind: WaitKind, ipc_ns: u64, id: u64) {
    with_waits(|waits| {
        if waits
            .get(&task)
            .is_some_and(|wait| wait.kind == kind && wait.ipc_ns == ipc_ns && wait.id == id)
        {
            waits.remove(&task);
        }
    });
}

fn wait_active(task: u64, kind: WaitKind, ipc_ns: u64, id: u64) -> bool {
    with_waits(|waits| {
        waits.get(&task).is_some_and(|wait| {
            wait.kind == kind && wait.ipc_ns == ipc_ns && wait.id == id && wait.errno == 0
        })
    })
}

fn take_wait_error(task: u64, kind: WaitKind, ipc_ns: u64, id: u64) -> Option<i64> {
    with_waits(|waits| match waits.get(&task) {
        Some(wait)
            if wait.kind == kind && wait.ipc_ns == ipc_ns && wait.id == id && wait.errno != 0 =>
        {
            let errno = wait.errno;
            waits.remove(&task);
            Some(errno)
        }
        Some(wait) if wait.kind != kind || wait.ipc_ns != ipc_ns || wait.id != id => {
            waits.remove(&task);
            None
        }
        _ => None,
    })
}

fn mark_waiters_error(kind: WaitKind, ipc_ns: u64, id: u64, errno: i64) {
    with_waits(|waits| {
        for wait in waits.values_mut() {
            if wait.kind == kind && wait.ipc_ns == ipc_ns && wait.id == id {
                wait.errno = errno;
            }
        }
    });
    narf_net::readiness::notify(0);
}

#[doc(hidden)]
pub(crate) fn __test_begin_removed_wait(kind: u8, id: u64) {
    let kind = match kind {
        0 => WaitKind::Sem,
        1 => WaitKind::MsgSend,
        _ => WaitKind::MsgRecv,
    };
    begin_wait(
        crate::handlers::current_task_id(),
        kind,
        current_ipc_namespace_id(),
        id,
    );
}

#[doc(hidden)]
pub(crate) fn __test_stage_sem_wait(id: u64, sops: &[u8]) {
    begin_sem_wait(
        crate::handlers::current_task_id(),
        current_ipc_namespace_id(),
        id,
        sops,
        sops.len() / 6,
        None,
    );
}

#[doc(hidden)]
pub(crate) fn __test_stage_msg_send(id: u64, mtype: i64, payload: &[u8], msgflg: u64) {
    begin_msg_send_wait(
        crate::handlers::current_task_id(),
        current_ipc_namespace_id(),
        id,
        mtype,
        payload.to_vec(),
        msgflg,
    );
}

fn ensure_sem_undo_observer() {
    if SEM_UNDO_OBSERVER_INSTALLED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        crate::user_task::register_thread_exit_observer(ipc_thread_exit);
        crate::user_task::register_process_exit_observer(sem_undo_process_exit);
    }
}

fn ipc_thread_exit(_pid: u64, tid: u64) {
    with_waits(|waits| {
        waits.remove(&tid);
    });
}

pub(crate) fn sem_undo_process_exit(pid: u64, _tid: u64) {
    let undo_owner = {
        let mut sharing = SEM_UNDO_SHARING.lock();
        let sharing = sharing.get_or_insert_with(SemUndoSharing::default);
        let owner = sharing.owner_of.remove(&pid).unwrap_or(pid);
        if let Some(refs) = sharing.refs.get_mut(&owner) {
            *refs -= 1;
            if *refs != 0 {
                return;
            }
            sharing.refs.remove(&owner);
        }
        owner
    };
    let adjustments = {
        let mut undos = SEM_UNDOS.lock();
        let table = undos.get_or_insert_with(BTreeMap::new);
        let owned: Vec<_> = table
            .iter()
            .filter(|((owner, _, _, _), _)| *owner == undo_owner)
            .map(|(key, adjustment)| (*key, *adjustment))
            .collect();
        for (key, _) in &owned {
            table.remove(key);
        }
        owned
    };
    if adjustments.is_empty() {
        return;
    }
    with_sems(|sets| {
        for ((_, ipc_ns, semid, semnum), adjustment) in adjustments {
            if let Some(sem) = sets
                .get_mut(&(ipc_ns, semid))
                .and_then(|set| set.sems.get_mut(semnum))
            {
                *sem = sem.saturating_add(adjustment).clamp(0, SEMVMX);
            }
        }
    });
    narf_net::readiness::notify(0);
}

/// Install Linux's `copy_semundo()` relationship for a newly-created process.
/// Threads already share by process id; a separate process shares only when
/// `CLONE_SYSVSEM` was requested, and the final member applies the adjustments.
pub(crate) fn clone_sem_undo(parent_pid: u64, child_pid: u64, share: bool) {
    if !share || parent_pid == child_pid {
        return;
    }
    let mut sharing = SEM_UNDO_SHARING.lock();
    let sharing = sharing.get_or_insert_with(SemUndoSharing::default);
    let owner = sharing
        .owner_of
        .get(&parent_pid)
        .copied()
        .unwrap_or(parent_pid);
    sharing.owner_of.insert(child_pid, owner);
    match sharing.refs.get_mut(&owner) {
        Some(refs) => *refs += 1,
        None => {
            sharing.refs.insert(owner, 2);
        }
    }
}

fn sem_undo_owner(pid: u64) -> u64 {
    let mut sharing = SEM_UNDO_SHARING.lock();
    sharing
        .get_or_insert_with(SemUndoSharing::default)
        .owner_of
        .get(&pid)
        .copied()
        .unwrap_or(pid)
}

fn finish_semtimedop_wait(timed: bool) {
    if timed {
        if let Some(user_task) = crate::user_task::current_user_task() {
            // SAFETY: current_user_task returns the live context for this trap.
            unsafe {
                (*user_task)
                    .blocking_deadline_ns
                    .store(0, Ordering::Release);
                (*user_task).sleep_deadline_ns.store(0, Ordering::Release);
            }
        }
    }
}

fn semtimedop_expired(timeout: Option<(i64, i64)>) -> bool {
    let Some((sec, nsec)) = timeout else {
        return false;
    };
    if sec == 0 && nsec == 0 {
        return true;
    }
    let Some(user_task) = crate::user_task::current_user_task() else {
        return false;
    };
    // SAFETY: current_user_task returns the live context for this trap.
    let deadline = unsafe { (*user_task).blocking_deadline_ns.load(Ordering::Acquire) };
    deadline != 0 && narf_scheduler::narf_time::monotonic_ns() >= deadline
}

/// Park a semaphore waiter and re-execute the syscall.  A timed operation's
/// absolute deadline is persisted in UserTaskCtx because its API supplies a
/// relative duration that must not restart after every wake/re-execution.
fn park_sem_wait(ctx: &mut dyn TrapContext, timeout: Option<(i64, i64)>) -> bool {
    if let (Some(user_task), Some(hook)) = (
        crate::user_task::current_user_task(),
        crate::user_task::yield_hook(),
    ) {
        let now = narf_scheduler::narf_time::monotonic_ns();
        // SAFETY: current_user_task returns the live context for this trap.
        let user = unsafe { &*user_task };
        let real_deadline = if let Some((sec, nsec)) = timeout {
            let persisted = user.blocking_deadline_ns.load(Ordering::Acquire);
            let deadline = if persisted != 0 {
                persisted
            } else {
                let duration = (sec as u64)
                    .saturating_mul(1_000_000_000)
                    .saturating_add(nsec as u64);
                let deadline = now.saturating_add(duration);
                user.blocking_deadline_ns.store(deadline, Ordering::Release);
                deadline
            };
            if now >= deadline {
                finish_semtimedop_wait(true);
                return false;
            }
            deadline
        } else {
            u64::MAX
        };

        #[cfg(target_arch = "x86_64")]
        const SYSCALL_INSN_LEN: u64 = 2;
        #[cfg(target_arch = "aarch64")]
        const SYSCALL_INSN_LEN: u64 = 4;
        ctx.set_rip(ctx.rip().wrapping_sub(SYSCALL_INSN_LEN));
        // A 1 ms safety wake closes the generic readiness scan/register race;
        // blocking_deadline_ns still preserves the caller's real timed deadline.
        user.sleep_deadline_ns.store(
            real_deadline.min(now.saturating_add(1_000_000)),
            Ordering::Release,
        );
        user.futex_uaddr.store(0, Ordering::Release);
        user.net_io_wait.store(true, Ordering::Release);
        user.epoll_park_gen
            .store(narf_net::readiness::generation(), Ordering::Release);
        // SAFETY: the live UserTaskCtx is exclusively being prepared for the
        // scheduler handoff, exactly as the shared I/O park bridge does.
        unsafe {
            ctx.save_user_state(user.state.get() as *mut u8);
            *user.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
            if narf_scheduler::stackful::user_own_stack_enabled() {
                crate::handlers::own_stack_block(ctx);
                return true;
            }
            hook(user_task);
        }
    }
    false
}

/// `semget(key, nsems, semflg)`.
pub fn sys_semget(ctx: &mut dyn TrapContext) {
    ensure_sem_undo_observer();
    let a = *ctx.args();
    let key = a.arg0 as u32;
    let nsems = a.arg1 as usize;
    let flg = a.arg2;
    let ipc_ns = current_ipc_namespace_id();
    let (_, uid, gid, groups) = current_identity();
    let id = with_sems(|m| {
        if key as u64 != IPC_PRIVATE {
            if let Some(((_, id), set)) = m
                .iter()
                .find(|((namespace, _), s)| *namespace == ipc_ns && s.key == key)
            {
                let id = *id;
                if flg & IPC_CREAT != 0 && flg & IPC_EXCL != 0 {
                    return Err(EEXIST);
                }
                if nsems > set.sems.len() {
                    return Err(EINVAL);
                }
                let requested_bits = (flg as u32) & IPC_PERM_MASK;
                let requested =
                    ((requested_bits >> 6) | (requested_bits >> 3) | requested_bits) & 0o7;
                if requested != 0
                    && !ipc_allowed(
                        uid, gid, &groups, set.uid, set.gid, set.cuid, set.cgid, set.mode,
                        requested,
                    )
                {
                    return Err(EACCES);
                }
                return Ok(id);
            }
            if flg & IPC_CREAT == 0 {
                return Err(ENOENT);
            }
        }
        if nsems == 0 || nsems > 1024 {
            return Err(EINVAL);
        }
        let id = alloc_sem_id();
        m.insert(
            (ipc_ns, id),
            SemSet {
                key,
                sems: alloc::vec![0i32; nsems],
                uid,
                gid,
                cuid: uid,
                cgid: gid,
                mode: (flg as u32) & IPC_PERM_MASK,
                otime: 0,
                ctime: now_seconds(),
            },
        );
        Ok(id)
    });
    match id {
        Ok(id) => ctx.set_return(SyscallReturn::ok(id)),
        Err(e) => ctx.set_return(err(e)),
    }
}

/// `semop(semid, sops, nsops)` — all-or-nothing.
pub fn sys_semop(ctx: &mut dyn TrapContext) {
    semop_common(ctx, false);
}

/// `semtimedop(semid, sops, nsops, timeout)`.
pub fn sys_semtimedop(ctx: &mut dyn TrapContext) {
    semop_common(ctx, true);
}

fn semop_common(ctx: &mut dyn TrapContext, timed: bool) {
    ensure_sem_undo_observer();
    let a = *ctx.args();
    let semid_raw = a.arg0 as i32;
    let semid = semid_raw as u32 as u64;
    let sops_ptr = a.arg1;
    let task = crate::handlers::current_task_id();
    let ipc_ns = current_ipc_namespace_id();
    let object = (ipc_ns, semid);
    let (pid, caller_uid, caller_gid, caller_groups) = current_identity();
    let resumed_wait = wait_active(task, WaitKind::Sem, ipc_ns, semid);
    if let Some(errno) = take_wait_error(task, WaitKind::Sem, ipc_ns, semid) {
        finish_semtimedop_wait(timed);
        ctx.set_return(err(errno));
        return;
    }
    let staged = staged_sem_wait(task, ipc_ns, semid);
    let nsops = staged
        .as_ref()
        .map_or(a.arg2 as u32 as usize, |(_, nsops, _)| *nsops);

    // ksys_semtimedop imports the timeout before do_semtimedop performs any
    // nsops or sops validation.  Preserve that externally visible ordering.
    let timeout = if let Some((_, _, timeout)) = &staged {
        *timeout
    } else if timed && a.arg3 != 0 {
        let mut raw = [0u8; 16];
        // SAFETY: copy_from_user validates the complete __kernel_timespec.
        if unsafe { crate::handlers::copy_from_user(&mut raw, a.arg3) }.is_err() {
            finish_semtimedop_wait(timed);
            clear_wait(task, WaitKind::Sem, ipc_ns, semid);
            ctx.set_return(err(EFAULT));
            return;
        }
        Some((
            i64::from_ne_bytes(raw[..8].try_into().unwrap()),
            i64::from_ne_bytes(raw[8..].try_into().unwrap()),
        ))
    } else {
        None
    };

    if nsops > MAX_SOPS {
        finish_semtimedop_wait(timed);
        clear_wait(task, WaitKind::Sem, ipc_ns, semid);
        ctx.set_return(err(E2BIG));
        return;
    }
    if nsops == 0 {
        finish_semtimedop_wait(timed);
        clear_wait(task, WaitKind::Sem, ipc_ns, semid);
        ctx.set_return(err(EINVAL));
        return;
    }
    // struct sembuf { unsigned short sem_num; short sem_op; short sem_flg; } — 6 B.
    // Read the sops array into a fixed on-stack buffer so a semop costs no
    // heap traffic (the hot stress path is a single-sembuf P/V pair).
    let nbytes = nsops * 6;
    let mut buf = [0u8; MAX_SOPS * 6];
    // SAFETY: copy_from_user range-validates sops_ptr and SMAP-brackets the
    // read of the complete sembuf array into the stack slice.
    if let Some((staged_sops, _, _)) = &staged {
        buf[..nbytes].copy_from_slice(staged_sops);
    } else {
        // SAFETY: this is the first execution; copy_from_user range-validates
        // and snapshots the complete operation array before any possible park.
        if unsafe { crate::handlers::copy_from_user(&mut buf[..nbytes], sops_ptr) }.is_err() {
            finish_semtimedop_wait(timed);
            clear_wait(task, WaitKind::Sem, ipc_ns, semid);
            ctx.set_return(err(EFAULT));
            return;
        }
    }
    // Linux validates the imported timeout in __do_semtimedop, after importing
    // the sops array and before looking up the semaphore set.
    if let Some((sec, nsec)) = timeout {
        if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
            finish_semtimedop_wait(timed);
            clear_wait(task, WaitKind::Sem, ipc_ns, semid);
            ctx.set_return(err(EINVAL));
            return;
        }
    }
    if semid_raw < 0 {
        finish_semtimedop_wait(timed);
        clear_wait(task, WaitKind::Sem, ipc_ns, semid);
        ctx.set_return(err(EINVAL));
        return;
    }
    let parse = |i: usize| -> (usize, i16, i16) {
        let o = i * 6;
        let num = u16::from_le_bytes(buf[o..o + 2].try_into().unwrap()) as usize;
        let op = i16::from_le_bytes(buf[o + 2..o + 4].try_into().unwrap());
        let flg = i16::from_le_bytes(buf[o + 4..o + 6].try_into().unwrap());
        (num, op, flg)
    };
    let has_undo = (0..nsops).any(|i| parse(i).2 & SEM_UNDO != 0);
    let undo_owner = has_undo.then(|| sem_undo_owner(pid));
    let mut undo_guard = has_undo.then(|| SEM_UNDOS.lock());
    let mut undo_updates = BTreeMap::<usize, i32>::new();
    if let Some(guard) = undo_guard.as_mut() {
        let table = guard.get_or_insert_with(BTreeMap::new);
        for i in 0..nsops {
            let (num, op, flg) = parse(i);
            if flg & SEM_UNDO == 0 || op == 0 {
                continue;
            }
            let prior = undo_updates.get(&num).copied().unwrap_or_else(|| {
                table
                    .get(&(undo_owner.expect("SEM_UNDO owner"), ipc_ns, semid, num))
                    .copied()
                    .unwrap_or(0)
            });
            let next = prior - i32::from(op);
            if !(-SEMVMX..=SEMVMX).contains(&next) {
                clear_wait(task, WaitKind::Sem, ipc_ns, semid);
                finish_semtimedop_wait(timed);
                ctx.set_return(err(ERANGE));
                return;
            }
            undo_updates.insert(num, next);
        }
    }
    let result: Result<(), (i64, bool)> = with_sems(|m| {
        let set = m.get_mut(&object).ok_or((EINVAL, true))?;
        let needs_write = (0..nsops).any(|i| parse(i).1 != 0);
        let request = if needs_write { 0o2 } else { 0o4 };
        if !resumed_wait
            && !ipc_allowed(
                caller_uid,
                caller_gid,
                &caller_groups,
                set.uid,
                set.gid,
                set.cuid,
                set.cgid,
                set.mode,
                request,
            )
        {
            return Err((EACCES, true));
        }
        // Bounds-check every referenced sem_num up front so the apply pass
        // (which mutates the live vector) can only be reached once the whole
        // sops array is known-valid.
        for i in 0..nsops {
            let (num, _, _) = parse(i);
            if num >= set.sems.len() {
                return Err((EINVAL, true));
            }
        }
        // Apply each op in order against the RUNNING value (accumulating
        // repeated sem_num within this call, as Linux's atomic block does).
        // On the first op that would block, roll back every applied delta so
        // the operation is all-or-nothing without cloning the vector.
        let mut applied = 0usize;
        let mut fail: Option<(i64, bool)> = None;
        for i in 0..nsops {
            let (num, op, flg) = parse(i);
            let cur = set.sems[num];
            let next = cur + i32::from(op);
            if op == 0 {
                if cur != 0 {
                    fail = Some((EAGAIN, flg & IPC_NOWAIT != 0));
                    break;
                }
            } else if next > SEMVMX {
                fail = Some((ERANGE, true));
                break;
            } else if next >= 0 {
                set.sems[num] = next;
            } else {
                fail = Some((EAGAIN, flg & IPC_NOWAIT != 0));
                break;
            }
            applied = i + 1;
        }
        if let Some(failure) = fail {
            for i in (0..applied).rev() {
                let (num, op, _) = parse(i);
                if op != 0 {
                    set.sems[num] -= op as i32;
                }
            }
            return Err(failure);
        }
        set.otime = now_seconds();
        Ok(())
    });
    match result {
        Ok(()) => {
            if let Some(guard) = undo_guard.as_mut() {
                let table = guard.get_or_insert_with(BTreeMap::new);
                for (semnum, adjustment) in undo_updates {
                    if adjustment == 0 {
                        table.remove(&(undo_owner.expect("SEM_UNDO owner"), ipc_ns, semid, semnum));
                    } else {
                        table.insert(
                            (undo_owner.expect("SEM_UNDO owner"), ipc_ns, semid, semnum),
                            adjustment,
                        );
                    }
                }
            }
            drop(undo_guard);
            clear_wait(task, WaitKind::Sem, ipc_ns, semid);
            finish_semtimedop_wait(timed);
            narf_net::readiness::notify(0);
            ctx.set_return(SyscallReturn::ok(0));
        }
        Err((e, true)) => {
            drop(undo_guard);
            clear_wait(task, WaitKind::Sem, ipc_ns, semid);
            finish_semtimedop_wait(timed);
            ctx.set_return(err(e));
        }
        Err((e, false)) if e == EAGAIN => {
            drop(undo_guard);
            let task = crate::handlers::current_task_id();
            if semtimedop_expired(timeout) {
                clear_wait(task, WaitKind::Sem, ipc_ns, semid);
                finish_semtimedop_wait(timed);
                ctx.set_return(err(EAGAIN));
            } else if crate::handlers::has_interrupting_signal(task) {
                clear_wait(task, WaitKind::Sem, ipc_ns, semid);
                finish_semtimedop_wait(timed);
                ctx.set_return(err(EINTR));
            } else {
                begin_sem_wait(task, ipc_ns, semid, &buf[..nbytes], nsops, timeout);
                if !with_sems(|sets| sets.contains_key(&object)) {
                    clear_wait(task, WaitKind::Sem, ipc_ns, semid);
                    finish_semtimedop_wait(timed);
                    ctx.set_return(err(EIDRM));
                } else if !park_sem_wait(ctx, timeout) {
                    // Unit-test contexts have no executor. Runtime callers park
                    // and re-execute; a synchronous harness needs a finite result.
                    clear_wait(task, WaitKind::Sem, ipc_ns, semid);
                    finish_semtimedop_wait(timed);
                    ctx.set_return(err(EAGAIN));
                }
            }
        }
        Err((e, _)) => {
            drop(undo_guard);
            clear_wait(task, WaitKind::Sem, ipc_ns, semid);
            finish_semtimedop_wait(timed);
            ctx.set_return(err(e));
        }
    }
}

/// `semctl(semid, semnum, cmd, arg)`.
pub fn sys_semctl(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let semid_raw = a.arg0 as i32;
    let semnum_raw = a.arg1 as i32;
    let cmd_raw = a.arg2 as i32;
    if semid_raw < 0 || cmd_raw < 0 {
        ctx.set_return(err(EINVAL));
        return;
    }
    let semid = semid_raw as u64;
    let ipc_ns = current_ipc_namespace_id();
    let object = (ipc_ns, semid);
    let semnum = semnum_raw as usize;
    let cmd = cmd_raw as u64;
    let arg = a.arg3;
    let (_, caller_uid, caller_gid, caller_groups) = current_identity();
    match cmd {
        IPC_RMID => {
            let mut undo_guard = SEM_UNDOS.lock();
            let removed = with_sems(|m| {
                let set = m.get(&object).ok_or(EINVAL)?;
                if !ipc_owner(caller_uid, set.uid, set.cuid) {
                    return Err(EPERM);
                }
                m.remove(&object);
                Ok(())
            });
            match removed {
                Ok(()) => {
                    undo_guard
                        .get_or_insert_with(BTreeMap::new)
                        .retain(|(_, namespace, id, _), _| *namespace != ipc_ns || *id != semid);
                    drop(undo_guard);
                    mark_waiters_error(WaitKind::Sem, ipc_ns, semid, EIDRM);
                    ctx.set_return(SyscallReturn::ok(0));
                }
                Err(e) => ctx.set_return(err(e)),
            }
        }
        IPC_STAT => {
            let snapshot = with_sems(|m| {
                let set = m.get(&object).ok_or(EINVAL)?;
                if !ipc_allowed(
                    caller_uid,
                    caller_gid,
                    &caller_groups,
                    set.uid,
                    set.gid,
                    set.cuid,
                    set.cgid,
                    set.mode,
                    0o4,
                ) {
                    return Err(EACCES);
                }
                Ok((
                    set.key,
                    set.uid,
                    set.gid,
                    set.cuid,
                    set.cgid,
                    set.mode,
                    set.otime,
                    set.ctime,
                    set.sems.len(),
                ))
            });
            let (key, uid, gid, cuid, cgid, mode, otime, ctime, nsems) = match snapshot {
                Ok(snapshot) => snapshot,
                Err(e) => {
                    ctx.set_return(err(e));
                    return;
                }
            };
            let (uid, gid) = ipc_ids_to_user(uid, gid);
            let (cuid, cgid) = ipc_ids_to_user(cuid, cgid);
            let mut out = alloc::vec![0u8; SEMID64_SIZE];
            encode_perm(&mut out, key, uid, gid, cuid, cgid, mode);
            put_i64(&mut out, SEM_OTIME_OFFSET, otime);
            put_i64(&mut out, SEM_CTIME_OFFSET, ctime);
            put_u64(&mut out, SEM_NSEMS_OFFSET, nsems as u64);
            // SAFETY: copy_to_user validates the complete architecture-specific
            // semid64_ds output range after the object snapshot is taken.
            if unsafe { crate::handlers::copy_to_user(arg, &out) }.is_err() {
                ctx.set_return(err(EFAULT));
            } else {
                ctx.set_return(SyscallReturn::ok(0));
            }
        }
        IPC_SET => {
            // SAFETY: copy_from_user_vec validates the full semid64_ds. Linux
            // imports it before lookup; ignored/padding fields remain required.
            let input = match unsafe { crate::handlers::copy_from_user_vec(arg, SEMID64_SIZE) } {
                Ok(input) => input,
                Err(_) => {
                    ctx.set_return(err(EFAULT));
                    return;
                }
            };
            let new_uid = get_u32(&input, 4);
            let new_gid = get_u32(&input, 8);
            let new_mode = get_u32(&input, 20) & IPC_PERM_MASK;
            let authorized = with_sems(|m| {
                let set = m.get(&object).ok_or(EINVAL)?;
                if !ipc_owner(caller_uid, set.uid, set.cuid) {
                    return Err(EPERM);
                }
                Ok(())
            });
            if let Err(e) = authorized {
                ctx.set_return(err(e));
                return;
            }
            let (new_uid, new_gid) = match ipc_ids_from_user(new_uid, new_gid) {
                Ok(ids) => ids,
                Err(e) => {
                    ctx.set_return(err(e));
                    return;
                }
            };
            let result = with_sems(|m| {
                let set = m.get_mut(&object).ok_or(EINVAL)?;
                if !ipc_owner(caller_uid, set.uid, set.cuid) {
                    return Err(EPERM);
                }
                set.uid = new_uid;
                set.gid = new_gid;
                set.mode = new_mode;
                set.ctime = now_seconds();
                Ok(())
            });
            ctx.set_return(match result {
                Ok(()) => SyscallReturn::ok(0),
                Err(e) => err(e),
            });
        }
        SETVAL => {
            let mut undo_guard = SEM_UNDOS.lock();
            let r = with_sems(|m| {
                let set = m.get_mut(&object).ok_or(EINVAL)?;
                if semnum_raw < 0 || semnum >= set.sems.len() {
                    return Err(EINVAL);
                }
                if !ipc_allowed(
                    caller_uid,
                    caller_gid,
                    &caller_groups,
                    set.uid,
                    set.gid,
                    set.cuid,
                    set.cgid,
                    set.mode,
                    0o2,
                ) {
                    return Err(EACCES);
                }
                let value = arg as i32;
                if !(0..=SEMVMX).contains(&value) {
                    return Err(ERANGE);
                }
                set.sems[semnum] = value;
                set.ctime = now_seconds();
                Ok(())
            });
            ctx.set_return(match r {
                Ok(()) => {
                    undo_guard.get_or_insert_with(BTreeMap::new).retain(
                        |(_, namespace, id, num), _| {
                            *namespace != ipc_ns || *id != semid || *num != semnum
                        },
                    );
                    drop(undo_guard);
                    narf_net::readiness::notify(0);
                    SyscallReturn::ok(0)
                }
                Err(e) => err(e),
            });
        }
        GETVAL => {
            let r = with_sems(|m| {
                let set = m.get(&object).ok_or(EINVAL)?;
                if semnum_raw < 0 {
                    return Err(EINVAL);
                }
                if !ipc_allowed(
                    caller_uid,
                    caller_gid,
                    &caller_groups,
                    set.uid,
                    set.gid,
                    set.cuid,
                    set.cgid,
                    set.mode,
                    0o4,
                ) {
                    return Err(EACCES);
                }
                set.sems.get(semnum).copied().ok_or(EINVAL)
            });
            ctx.set_return(match r {
                Ok(v) => SyscallReturn::ok(v as u64),
                Err(e) => err(e),
            });
        }
        SETALL => {
            let n = match with_sems(|m| {
                let set = m.get(&object).ok_or(EINVAL)?;
                if !ipc_allowed(
                    caller_uid,
                    caller_gid,
                    &caller_groups,
                    set.uid,
                    set.gid,
                    set.cuid,
                    set.cgid,
                    set.mode,
                    0o2,
                ) {
                    return Err(EACCES);
                }
                Ok(set.sems.len())
            }) {
                Ok(n) => n,
                Err(e) => {
                    ctx.set_return(err(e));
                    return;
                }
            };
            // SAFETY: copy_from_user_vec validates and imports the complete
            // ushort array after set lookup/permission, matching semctl_main.
            let bytes = match unsafe { crate::handlers::copy_from_user_vec(arg, n * 2) } {
                Ok(bytes) => bytes,
                Err(_) => {
                    ctx.set_return(err(EFAULT));
                    return;
                }
            };
            let mut values = Vec::with_capacity(n);
            for i in 0..n {
                let value = u16::from_ne_bytes(bytes[i * 2..i * 2 + 2].try_into().unwrap());
                if i32::from(value) > SEMVMX {
                    ctx.set_return(err(ERANGE));
                    return;
                }
                values.push(i32::from(value));
            }
            let mut undo_guard = SEM_UNDOS.lock();
            let r = with_sems(|m| {
                let set = m.get_mut(&object).ok_or(EIDRM)?;
                if set.sems.len() != values.len() {
                    return Err(EIDRM);
                }
                set.sems.copy_from_slice(&values);
                set.ctime = now_seconds();
                Ok(())
            });
            ctx.set_return(match r {
                Ok(()) => {
                    undo_guard
                        .get_or_insert_with(BTreeMap::new)
                        .retain(|(_, namespace, id, _), _| *namespace != ipc_ns || *id != semid);
                    drop(undo_guard);
                    narf_net::readiness::notify(0);
                    SyscallReturn::ok(0)
                }
                Err(e) => err(e),
            });
        }
        GETALL => {
            let r = with_sems(|m| {
                let set = m.get(&object).ok_or(EINVAL)?;
                if !ipc_allowed(
                    caller_uid,
                    caller_gid,
                    &caller_groups,
                    set.uid,
                    set.gid,
                    set.cuid,
                    set.cgid,
                    set.mode,
                    0o4,
                ) {
                    return Err(EACCES);
                }
                let mut out = Vec::with_capacity(set.sems.len() * 2);
                for &v in &set.sems {
                    out.extend_from_slice(&(v as u16).to_le_bytes());
                }
                Ok(out)
            });
            match r {
                Ok(out) => {
                    // SAFETY: `arg` is the user GETALL buffer; copy_to_user validates it.
                    if unsafe { crate::handlers::copy_to_user(arg, &out) }.is_err() {
                        ctx.set_return(err(EFAULT));
                    } else {
                        ctx.set_return(SyscallReturn::ok(0));
                    }
                }
                Err(e) => ctx.set_return(err(e)),
            }
        }
        _ => ctx.set_return(err(EINVAL)),
    }
}

// ════════════════════════════════════════════════════════════════════
// Message queues
// ════════════════════════════════════════════════════════════════════

struct MsgQueue {
    key: u32,
    msgs: VecDeque<QueuedMessage>,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    mode: u32,
    stime: i64,
    rtime: i64,
    ctime: i64,
    current_bytes: usize,
    max_bytes: usize,
    last_send_pid: i32,
    last_recv_pid: i32,
}

struct QueuedMessage {
    id: u64,
    mtype: i64,
    payload: Vec<u8>,
    reserved: bool,
}

static MSGS: IrqSafeSpinLock<Option<BTreeMap<IpcObjectKey, MsgQueue>>> = IrqSafeSpinLock::new(None);
#[cfg(not(feature = "container"))]
static MSG_NEXT_ID: AtomicU64 = AtomicU64::new(1);
static MSG_NEXT_MESSAGE_ID: AtomicU64 = AtomicU64::new(1);
const MSG_MAX_BYTES: usize = 8192;
const MSG_DEFAULT_QUEUE_BYTES: usize = 16384;
const MSG_NOERROR: i64 = 0o10000;
const MSG_EXCEPT: i64 = 0o20000;
const MSG_COPY: i64 = 0o40000;

fn with_msgs<R>(f: impl FnOnce(&mut BTreeMap<IpcObjectKey, MsgQueue>) -> R) -> R {
    let mut g = MSGS.lock();
    f(g.get_or_insert_with(BTreeMap::new))
}

/// `msgget(key, msgflg)`.
pub fn sys_msgget(ctx: &mut dyn TrapContext) {
    ensure_sem_undo_observer();
    let a = *ctx.args();
    let key = a.arg0 as u32;
    let flg = a.arg1;
    let ipc_ns = current_ipc_namespace_id();
    let (_, uid, gid, groups) = current_identity();
    let id = with_msgs(|m| {
        if key as u64 != IPC_PRIVATE {
            if let Some(((_, id), q)) = m
                .iter()
                .find(|((namespace, _), q)| *namespace == ipc_ns && q.key == key)
            {
                let id = *id;
                if flg & IPC_CREAT != 0 && flg & IPC_EXCL != 0 {
                    return Err(EEXIST);
                }
                let requested_bits = (flg as u32) & IPC_PERM_MASK;
                let requested =
                    ((requested_bits >> 6) | (requested_bits >> 3) | requested_bits) & 0o7;
                if requested != 0
                    && !ipc_allowed(
                        uid, gid, &groups, q.uid, q.gid, q.cuid, q.cgid, q.mode, requested,
                    )
                {
                    return Err(EACCES);
                }
                return Ok(id);
            }
            if flg & IPC_CREAT == 0 {
                return Err(ENOENT);
            }
        }
        let id = alloc_msg_id();
        m.insert(
            (ipc_ns, id),
            MsgQueue {
                key,
                msgs: VecDeque::new(),
                uid,
                gid,
                cuid: uid,
                cgid: gid,
                mode: (flg as u32) & IPC_PERM_MASK,
                stime: 0,
                rtime: 0,
                ctime: now_seconds(),
                current_bytes: 0,
                max_bytes: MSG_DEFAULT_QUEUE_BYTES,
                last_send_pid: 0,
                last_recv_pid: 0,
            },
        );
        Ok(id)
    });
    match id {
        Ok(id) => ctx.set_return(SyscallReturn::ok(id)),
        Err(e) => ctx.set_return(err(e)),
    }
}

/// `msgsnd(msqid, msgp, msgsz, msgflg)` — msgp = `{ long mtype; char mtext[]; }`.
pub fn sys_msgsnd(ctx: &mut dyn TrapContext) {
    ensure_sem_undo_observer();
    let a = *ctx.args();
    let msqid_raw = a.arg0 as i32;
    let msqid = msqid_raw as u32 as u64;
    let msgp = a.arg1;
    let task = crate::handlers::current_task_id();
    let ipc_ns = current_ipc_namespace_id();
    let object = (ipc_ns, msqid);
    let (pid, caller_uid, caller_gid, caller_groups) = current_identity();
    if let Some(errno) = take_wait_error(task, WaitKind::MsgSend, ipc_ns, msqid) {
        ctx.set_return(err(errno));
        return;
    }
    if wait_active(task, WaitKind::MsgSend, ipc_ns, msqid)
        && crate::handlers::has_interrupting_signal(task)
    {
        clear_wait(task, WaitKind::MsgSend, ipc_ns, msqid);
        ctx.set_return(err(EINTR));
        return;
    }
    let staged = staged_msg_send_wait(task, ipc_ns, msqid);
    let (mtype, payload, msgflg) = if let Some(staged) = staged {
        staged
    } else {
        let msgsz = a.arg2 as usize;
        let msgflg = a.arg3;
        // ksys_msgsnd imports mtype before do_msgsnd validates size, id, or type.
        let mut hdr = [0u8; 8];
        // SAFETY: copy_from_user validates and brackets the complete mtype read.
        if unsafe { crate::handlers::copy_from_user(&mut hdr, msgp) }.is_err() {
            clear_wait(task, WaitKind::MsgSend, ipc_ns, msqid);
            ctx.set_return(err(EFAULT));
            return;
        }
        let mtype = i64::from_le_bytes(hdr);
        if msgsz > MSG_MAX_BYTES || msqid_raw < 0 || mtype <= 0 {
            clear_wait(task, WaitKind::MsgSend, ipc_ns, msqid);
            ctx.set_return(err(EINVAL));
            return;
        }
        let mut payload = alloc::vec![0u8; msgsz];
        if msgsz != 0 {
            let Some(payload_ptr) = msgp.checked_add(8) else {
                clear_wait(task, WaitKind::MsgSend, ipc_ns, msqid);
                ctx.set_return(err(EFAULT));
                return;
            };
            // SAFETY: copy_from_user validates the complete payload range and
            // snapshots it before any possible park.
            if unsafe { crate::handlers::copy_from_user(&mut payload, payload_ptr) }.is_err() {
                clear_wait(task, WaitKind::MsgSend, ipc_ns, msqid);
                ctx.set_return(err(EFAULT));
                return;
            }
        }
        (mtype, payload, msgflg)
    };
    let msgsz = payload.len();
    let message_id = MSG_NEXT_MESSAGE_ID.fetch_add(1, Ordering::Relaxed);
    let mut pending_payload = Some(payload);
    let r: Result<bool, i64> = with_msgs(|m| {
        let q = m.get_mut(&object).ok_or(EINVAL)?;
        if !ipc_allowed(
            caller_uid,
            caller_gid,
            &caller_groups,
            q.uid,
            q.gid,
            q.cuid,
            q.cgid,
            q.mode,
            0o2,
        ) {
            return Err(EACCES);
        }
        if msgsz.saturating_add(q.current_bytes) > q.max_bytes
            || q.msgs.len().saturating_add(1) > q.max_bytes
        {
            return Ok(false);
        }
        q.msgs.push_back(QueuedMessage {
            id: message_id,
            mtype,
            payload: pending_payload.take().expect("pending SysV message"),
            reserved: false,
        });
        q.current_bytes += msgsz;
        q.stime = now_seconds();
        q.last_send_pid = pid as i32;
        Ok(true)
    });
    match r {
        Ok(true) => {
            clear_wait(task, WaitKind::MsgSend, ipc_ns, msqid);
            narf_net::readiness::notify(0);
            ctx.set_return(SyscallReturn::ok(0));
        }
        Ok(false) if msgflg & IPC_NOWAIT as u64 != 0 => {
            clear_wait(task, WaitKind::MsgSend, ipc_ns, msqid);
            ctx.set_return(err(EAGAIN));
        }
        Ok(false) => {
            if crate::handlers::has_interrupting_signal(task) {
                clear_wait(task, WaitKind::MsgSend, ipc_ns, msqid);
                ctx.set_return(err(EINTR));
            } else {
                begin_msg_send_wait(
                    task,
                    ipc_ns,
                    msqid,
                    mtype,
                    pending_payload.take().expect("blocked SysV message"),
                    msgflg,
                );
                if !with_msgs(|queues| queues.contains_key(&object)) {
                    clear_wait(task, WaitKind::MsgSend, ipc_ns, msqid);
                    ctx.set_return(err(EIDRM));
                } else if !crate::handlers::park_reexecute_on_io(ctx) {
                    clear_wait(task, WaitKind::MsgSend, ipc_ns, msqid);
                    ctx.set_return(err(EAGAIN));
                }
            }
        }
        Err(e) => {
            clear_wait(task, WaitKind::MsgSend, ipc_ns, msqid);
            ctx.set_return(err(e));
        }
    }
}

/// `msgrcv(msqid, msgp, msgsz, msgtyp, msgflg)`.
pub fn sys_msgrcv(ctx: &mut dyn TrapContext) {
    ensure_sem_undo_observer();
    let a = *ctx.args();
    let msqid_raw = a.arg0 as i32;
    let msqid = msqid_raw as u32 as u64;
    let msgp = a.arg1;
    let msgsz = a.arg2 as usize;
    let msgtyp = a.arg3 as i64;
    let flg = a.arg4 as i64;
    let task = crate::handlers::current_task_id();
    let ipc_ns = current_ipc_namespace_id();
    let object = (ipc_ns, msqid);
    let (pid, caller_uid, caller_gid, caller_groups) = current_identity();
    if let Some(errno) = take_wait_error(task, WaitKind::MsgRecv, ipc_ns, msqid) {
        ctx.set_return(err(errno));
        return;
    }
    if (a.arg2 as i64) < 0 || msqid_raw < 0 {
        clear_wait(task, WaitKind::MsgRecv, ipc_ns, msqid);
        ctx.set_return(err(EINVAL));
        return;
    }
    if flg & MSG_COPY != 0 && (flg & (IPC_NOWAIT as i64) == 0 || flg & MSG_EXCEPT != 0) {
        clear_wait(task, WaitKind::MsgRecv, ipc_ns, msqid);
        ctx.set_return(err(EINVAL));
        return;
    }

    // Select and reserve while holding the queue lock. Reservation makes the
    // subsequent userspace copy transactional without letting a concurrent
    // receiver select the same message.
    let picked = with_msgs(|m| {
        let q = m.get_mut(&object).ok_or(EINVAL)?;
        if !ipc_allowed(
            caller_uid,
            caller_gid,
            &caller_groups,
            q.uid,
            q.gid,
            q.cuid,
            q.cgid,
            q.mode,
            0o4,
        ) {
            return Err(EACCES);
        }
        let idx = if flg & MSG_COPY != 0 {
            usize::try_from(msgtyp).ok().and_then(|ordinal| {
                q.msgs
                    .iter()
                    .enumerate()
                    .filter(|(_, msg)| !msg.reserved)
                    .nth(ordinal)
                    .map(|(idx, _)| idx)
            })
        } else if msgtyp < 0 {
            let limit = if msgtyp == i64::MIN {
                i64::MAX
            } else {
                -msgtyp
            };
            q.msgs
                .iter()
                .enumerate()
                .filter(|(_, msg)| !msg.reserved && msg.mtype <= limit)
                .min_by_key(|(_, msg)| msg.mtype)
                .map(|(idx, _)| idx)
        } else {
            q.msgs.iter().position(|msg| {
                !msg.reserved
                    && (msgtyp == 0
                        || if flg & MSG_EXCEPT != 0 {
                            msg.mtype != msgtyp
                        } else {
                            msg.mtype == msgtyp
                        })
            })
        };
        match idx {
            Some(i) => {
                let msg = &mut q.msgs[i];
                if msg.payload.len() > msgsz && flg & MSG_NOERROR == 0 {
                    return Err(E2BIG);
                }
                let copied_len = core::cmp::min(msg.payload.len(), msgsz);
                let snapshot = (
                    msg.id,
                    msg.mtype,
                    msg.payload[..copied_len].to_vec(),
                    msg.payload.len(),
                );
                if flg & MSG_COPY == 0 {
                    msg.reserved = true;
                }
                Ok(Some(snapshot))
            }
            None => Ok(None),
        }
    });
    let (message_id, mtype, payload, original_len) = match picked {
        Ok(Some(msg)) => msg,
        Ok(None) => {
            if flg & IPC_NOWAIT as i64 != 0 {
                clear_wait(task, WaitKind::MsgRecv, ipc_ns, msqid);
                ctx.set_return(err(ENOMSG));
            } else if crate::handlers::has_interrupting_signal(task) {
                clear_wait(task, WaitKind::MsgRecv, ipc_ns, msqid);
                ctx.set_return(err(EINTR));
            } else {
                begin_wait(task, WaitKind::MsgRecv, ipc_ns, msqid);
                let permission = with_msgs(|queues| {
                    queues.get(&object).map(|q| {
                        ipc_allowed(
                            caller_uid,
                            caller_gid,
                            &caller_groups,
                            q.uid,
                            q.gid,
                            q.cuid,
                            q.cgid,
                            q.mode,
                            0o4,
                        )
                    })
                });
                match permission {
                    None => {
                        clear_wait(task, WaitKind::MsgRecv, ipc_ns, msqid);
                        ctx.set_return(err(EIDRM));
                    }
                    Some(false) => {
                        clear_wait(task, WaitKind::MsgRecv, ipc_ns, msqid);
                        ctx.set_return(err(EAGAIN));
                    }
                    Some(true) if !crate::handlers::park_reexecute_on_io(ctx) => {
                        // The in-kernel ABI harness has no executor to park on.
                        clear_wait(task, WaitKind::MsgRecv, ipc_ns, msqid);
                        ctx.set_return(err(ENOMSG));
                    }
                    Some(true) => {}
                }
            }
            return;
        }
        Err(e) => {
            clear_wait(task, WaitKind::MsgRecv, ipc_ns, msqid);
            ctx.set_return(err(e));
            return;
        }
    };
    let mut out = Vec::with_capacity(8 + payload.len());
    out.extend_from_slice(&mtype.to_le_bytes());
    out.extend_from_slice(&payload);
    // SAFETY: one range-validated copy makes header+payload publication
    // atomic with respect to message removal.
    if unsafe { crate::handlers::copy_to_user(msgp, &out) }.is_err() {
        if flg & MSG_COPY == 0 {
            with_msgs(|m| {
                if let Some(msg) = m
                    .get_mut(&object)
                    .and_then(|q| q.msgs.iter_mut().find(|msg| msg.id == message_id))
                {
                    msg.reserved = false;
                }
            });
            narf_net::readiness::notify(0);
        }
        clear_wait(task, WaitKind::MsgRecv, ipc_ns, msqid);
        ctx.set_return(err(EFAULT));
        return;
    }
    if flg & MSG_COPY == 0 {
        with_msgs(|m| {
            if let Some(q) = m.get_mut(&object) {
                if let Some(idx) = q.msgs.iter().position(|msg| msg.id == message_id) {
                    q.msgs.remove(idx);
                    q.current_bytes = q.current_bytes.saturating_sub(original_len);
                    q.rtime = now_seconds();
                    q.last_recv_pid = pid as i32;
                }
            }
        });
        narf_net::readiness::notify(0);
    }
    clear_wait(task, WaitKind::MsgRecv, ipc_ns, msqid);
    ctx.set_return(SyscallReturn::ok(payload.len() as u64));
}

/// `msgctl(msqid, cmd, buf)`.
pub fn sys_msgctl(ctx: &mut dyn TrapContext) {
    ensure_sem_undo_observer();
    let a = *ctx.args();
    let msqid_raw = a.arg0 as i32;
    let cmd_raw = a.arg1 as i32;
    if msqid_raw < 0 || cmd_raw < 0 {
        ctx.set_return(err(EINVAL));
        return;
    }
    let msqid = msqid_raw as u64;
    let ipc_ns = current_ipc_namespace_id();
    let object = (ipc_ns, msqid);
    let cmd = cmd_raw as u64;
    let buf = a.arg2;
    let (_, caller_uid, caller_gid, caller_groups) = current_identity();
    match cmd {
        IPC_RMID => {
            let removed = with_msgs(|m| {
                let q = m.get(&object).ok_or(EINVAL)?;
                if !ipc_owner(caller_uid, q.uid, q.cuid) {
                    return Err(EPERM);
                }
                m.remove(&object);
                Ok(())
            });
            match removed {
                Ok(()) => {
                    mark_waiters_error(WaitKind::MsgSend, ipc_ns, msqid, EIDRM);
                    mark_waiters_error(WaitKind::MsgRecv, ipc_ns, msqid, EIDRM);
                    ctx.set_return(SyscallReturn::ok(0));
                }
                Err(e) => ctx.set_return(err(e)),
            }
        }
        IPC_STAT => {
            let snapshot = with_msgs(|m| {
                let q = m.get(&object).ok_or(EINVAL)?;
                if !ipc_allowed(
                    caller_uid,
                    caller_gid,
                    &caller_groups,
                    q.uid,
                    q.gid,
                    q.cuid,
                    q.cgid,
                    q.mode,
                    0o4,
                ) {
                    return Err(EACCES);
                }
                Ok((
                    q.key,
                    q.uid,
                    q.gid,
                    q.cuid,
                    q.cgid,
                    q.mode,
                    q.stime,
                    q.rtime,
                    q.ctime,
                    q.current_bytes,
                    q.msgs.len(),
                    q.max_bytes,
                    q.last_send_pid,
                    q.last_recv_pid,
                ))
            });
            let (
                key,
                uid,
                gid,
                cuid,
                cgid,
                mode,
                stime,
                rtime,
                ctime,
                current_bytes,
                qnum,
                max_bytes,
                last_send_pid,
                last_recv_pid,
            ) = match snapshot {
                Ok(snapshot) => snapshot,
                Err(e) => {
                    ctx.set_return(err(e));
                    return;
                }
            };
            let (uid, gid) = ipc_ids_to_user(uid, gid);
            let (cuid, cgid) = ipc_ids_to_user(cuid, cgid);
            let mut out = [0u8; MSQID64_SIZE];
            encode_perm(&mut out, key, uid, gid, cuid, cgid, mode);
            put_i64(&mut out, 48, stime);
            put_i64(&mut out, 56, rtime);
            put_i64(&mut out, 64, ctime);
            put_u64(&mut out, 72, current_bytes as u64);
            put_u64(&mut out, 80, qnum as u64);
            put_u64(&mut out, 88, max_bytes as u64);
            put_i32(&mut out, 96, last_send_pid);
            put_i32(&mut out, 100, last_recv_pid);
            // SAFETY: copy_to_user validates the full native msqid64_ds range
            // after the readable queue has been snapshotted.
            if unsafe { crate::handlers::copy_to_user(buf, &out) }.is_err() {
                ctx.set_return(err(EFAULT));
            } else {
                ctx.set_return(SyscallReturn::ok(0));
            }
        }
        IPC_SET => {
            // SAFETY: Linux imports the complete msqid64_ds before queue lookup
            // or owner checks, including all ignored and padding fields.
            let input = match unsafe { crate::handlers::copy_from_user_vec(buf, MSQID64_SIZE) } {
                Ok(input) => input,
                Err(_) => {
                    ctx.set_return(err(EFAULT));
                    return;
                }
            };
            let new_uid = get_u32(&input, 4);
            let new_gid = get_u32(&input, 8);
            let new_mode = get_u32(&input, 20) & IPC_PERM_MASK;
            let new_max = get_u64(&input, 88);
            let authorized = with_msgs(|m| {
                let q = m.get(&object).ok_or(EINVAL)?;
                if !ipc_owner(caller_uid, q.uid, q.cuid) {
                    return Err(EPERM);
                }
                if new_max > MSG_DEFAULT_QUEUE_BYTES as u64 && caller_uid != 0 {
                    return Err(EPERM);
                }
                Ok(())
            });
            if let Err(e) = authorized {
                ctx.set_return(err(e));
                return;
            }
            let (new_uid, new_gid) = match ipc_ids_from_user(new_uid, new_gid) {
                Ok(ids) => ids,
                Err(e) => {
                    ctx.set_return(err(e));
                    return;
                }
            };
            let result = with_msgs(|m| {
                let q = m.get_mut(&object).ok_or(EINVAL)?;
                if !ipc_owner(caller_uid, q.uid, q.cuid) {
                    return Err(EPERM);
                }
                if new_max > MSG_DEFAULT_QUEUE_BYTES as u64 && caller_uid != 0 {
                    return Err(EPERM);
                }
                q.uid = new_uid;
                q.gid = new_gid;
                q.mode = new_mode;
                q.max_bytes = usize::try_from(new_max).map_err(|_| EINVAL)?;
                q.ctime = now_seconds();
                Ok(())
            });
            match result {
                Ok(()) => {
                    mark_waiters_error(WaitKind::MsgRecv, ipc_ns, msqid, EAGAIN);
                    ctx.set_return(SyscallReturn::ok(0));
                }
                Err(e) => ctx.set_return(err(e)),
            }
        }
        _ => ctx.set_return(err(EINVAL)),
    }
}

/// Tear down the SysV semaphore/message tables owned by a dying IPC
/// namespace. IDs in other namespaces may have the same numeric value and are
/// deliberately untouched. Blocked operations in the removed namespace wake
/// with EIDRM, matching Linux free_ipcs().
#[cfg(feature = "container")]
pub(crate) fn ipc_namespace_drop(ipc_ns: u64) {
    with_sems(|sets| sets.retain(|(namespace, _), _| *namespace != ipc_ns));
    with_msgs(|queues| queues.retain(|(namespace, _), _| *namespace != ipc_ns));
    SEM_UNDOS
        .lock()
        .get_or_insert_with(BTreeMap::new)
        .retain(|(_, namespace, _, _), _| *namespace != ipc_ns);
    with_waits(|waits| {
        for wait in waits.values_mut() {
            if wait.ipc_ns == ipc_ns {
                wait.errno = EIDRM;
            }
        }
    });
    narf_net::readiness::notify(0);
}
