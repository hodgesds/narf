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

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;
#[cfg(feature = "kernel-test")]
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::Waker;

use narf_lib::sync::IrqSafeSpinLock;

use crate::syscall::{SyscallReturn, TrapContext};

// ── errno + IPC constants ────────────────────────────────────────────
const ENOENT: i64 = 2;
const EPERM: i64 = 1;
const EINTR: i64 = 4;
const E2BIG: i64 = 7;
const EFBIG: i64 = 27;
const EAGAIN: i64 = 11;
const ENOMEM: i64 = 12;
const EACCES: i64 = 13;
const EFAULT: i64 = 14;
const EEXIST: i64 = 17;
const EINVAL: i64 = 22;
const ENOSPC: i64 = 28;
const ENOMSG: i64 = 42;
const EIDRM: i64 = 43;
const ERANGE: i64 = 34;

fn err(e: i64) -> SyscallReturn {
    SyscallReturn::ok((-e) as u64)
}

type IpcObjectKey = (u64, u64); // (IPC namespace id, namespace-local object id)
type IpcLookupKey = (u64, u32); // (IPC namespace id, user-supplied key)

// Linux's default SysV IPC identifier layout (`ipc/util.h`): bits 0..14
// select an IDR slot and bits 15..30 carry a sequence number. Keeping the
// sequence in the public id makes a removed id fail with EINVAL after its slot
// is reused instead of silently naming the replacement object.
const IPCMNI_SHIFT: u32 = 15;
const IPCMNI: u32 = 1 << IPCMNI_SHIFT;
const IPCMNI_IDX_MASK: u32 = IPCMNI - 1;
const IPCID_SEQ_MAX: u32 = i32::MAX as u32 >> IPCMNI_SHIFT;

#[derive(Default)]
struct IpcIdTable {
    /// Full sequence-bearing id by Linux-visible slot index.
    slots: BTreeMap<u32, u64>,
    /// Removed holes below `next_unused`; tail holes are collapsed instead.
    free: BTreeSet<u32>,
    next_unused: u32,
    last_idx: Option<u32>,
    sequence: u32,
}

impl IpcIdTable {
    fn allocate(&mut self, limit: usize) -> Result<u64, i64> {
        let limit = u32::try_from(limit.min(IPCMNI as usize)).unwrap_or(IPCMNI);
        let idx = if self.next_unused < limit {
            let idx = self.next_unused;
            self.next_unused += 1;
            idx
        } else {
            let idx = self.free.range(..limit).next().copied().ok_or(ENOSPC)?;
            assert!(self.free.remove(&idx), "missing free SysV IPC slot");
            idx
        };

        // This is Linux's sequence rule: advance only when allocation cycles
        // to an index no greater than the previous allocation.
        if self.last_idx.is_some_and(|last_idx| idx <= last_idx) {
            self.sequence += 1;
            if self.sequence >= IPCID_SEQ_MAX {
                self.sequence = 0;
            }
        }
        self.last_idx = Some(idx);
        let id = u64::from((self.sequence << IPCMNI_SHIFT) | idx);
        assert!(
            self.slots.insert(idx, id).is_none(),
            "occupied SysV IPC slot"
        );
        Ok(id)
    }

    fn release(&mut self, id: u64) {
        let idx = id as u32 & IPCMNI_IDX_MASK;
        assert_eq!(
            self.slots.remove(&idx),
            Some(id),
            "SysV IPC id table diverged"
        );
        assert!(self.free.insert(idx), "duplicate free SysV IPC slot");

        // Avoid retaining one BTree node for every formerly occupied tail
        // slot. Each slot is collapsed at most once between allocations.
        while self.next_unused != 0 {
            let tail = self.next_unused - 1;
            if self.slots.contains_key(&tail) {
                break;
            }
            self.free.remove(&tail);
            self.next_unused = tail;
        }
    }

    fn full_id_at(&self, index: u64) -> Option<u64> {
        self.slots.get(&(index as u32 & IPCMNI_IDX_MASK)).copied()
    }

    fn max_index(&self) -> u64 {
        self.slots.keys().next_back().copied().map_or(0, u64::from)
    }
}

#[cfg(feature = "container")]
fn current_ipc_namespace_id() -> u64 {
    crate::namespaces::current_ipc_namespace(crate::handlers::current_task_id()).id()
}

#[cfg(not(feature = "container"))]
fn current_ipc_namespace_id() -> u64 {
    0
}

const IPC_CREAT: u64 = 0o1000;
const IPC_EXCL: u64 = 0o2000;
const IPC_NOWAIT: i16 = 0o4000;
const IPC_PRIVATE: u64 = 0;
const IPC_PERM_MASK: u32 = 0o777;
const SEM_UNDO: i16 = 0o10000;
/// Linux treats every other `sem_flg` bit as an ignored extension bit.
/// Masking at import makes it explicit that unknown bits neither reject the
/// operation nor accidentally acquire behavior in later bit tests.
const SEM_BEHAVIOR_FLAGS: i16 = IPC_NOWAIT | SEM_UNDO;
const SEMVMX: i32 = 32767;
const SEMMNI: usize = 32_000;
const SEMMSL: usize = 32_000;
const SEMMNS: usize = SEMMNI * SEMMSL;
const SEMOPM: usize = 500;
const SEMUME: i32 = SEMOPM as i32;
const SEMUSZ: i32 = 20;

// ipc control cmds (low bits; libc ORs IPC_64 = 0x100 which we mask off).
const IPC_RMID: u64 = 0;
const IPC_SET: u64 = 1;
const IPC_STAT: u64 = 2;
const IPC_INFO: u64 = 3;

// semctl cmds.
const GETPID: u64 = 11;
const GETVAL: u64 = 12;
const GETALL: u64 = 13;
const GETNCNT: u64 = 14;
const GETZCNT: u64 = 15;
const SETVAL: u64 = 16;
const SETALL: u64 = 17;
const SEM_STAT: u64 = 18;
const SEM_INFO: u64 = 19;
const SEM_STAT_ANY: u64 = 20;

// msgctl cmds.
const MSG_STAT: u64 = 11;
const MSG_INFO: u64 = 12;
const MSG_STAT_ANY: u64 = 13;

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
const MSGINFO_SIZE: usize = 32;
const SEMINFO_SIZE: usize = 40;

fn put_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
}

fn put_u16(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_ne_bytes());
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
    /// Outer process id of the last successful operator for each semaphore.
    /// It is translated into the reader's pid namespace by GETPID, just as
    /// Linux retains `struct pid` and calls `pid_vnr()` at query time.
    pids: Vec<u64>,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    mode: u32,
    otime: i64,
    ctime: i64,
    /// Tasks are appended once and considered in insertion order.  As on
    /// Linux, an older operation that is still unsatisfiable does not block a
    /// younger satisfiable operation.
    pending: VecDeque<u64>,
    ncnt: Vec<usize>,
    zcnt: Vec<usize>,
}

type SemUndoKey = (u64, u64, u64, usize);
type SemUndoTable = Vec<(SemUndoKey, i32)>;

type SemWaitBlocker = (usize, bool); // (sem_num, waits-for-zero)
type SemOpFailure = (i64, bool, Option<SemWaitBlocker>); // (errno, terminal, blocker)
type SemStagedSnapshot = (usize, Option<(i64, i64)>, bool); // (nsops, timeout, linked)

struct SemWait {
    task: u64,
    ipc_ns: u64,
    id: u64,
    sops: Vec<u8>,
    nsops: usize,
    timeout: Option<(i64, i64)>,
    blocking: Option<SemWaitBlocker>,
    pid: u64,
    undo_owner: Option<u64>,
    /// `None` while linked; otherwise the positive errno (zero is success).
    result: Option<i64>,
    /// Replaced on every scheduler poll and taken exactly once on completion.
    waker: Option<Waker>,
}

#[derive(Clone, Copy, Default)]
struct SemUsage {
    set_count: usize,
    sem_count: usize,
}

#[derive(Default)]
struct SemState {
    sets: BTreeMap<IpcObjectKey, SemSet>,
    ids: BTreeMap<u64, IpcIdTable>,
    /// Linux keeps a per-namespace key index rather than walking every set.
    /// IPC_PRIVATE is deliberately absent because it never names an object.
    key_ids: BTreeMap<IpcLookupKey, u64>,
    /// Exact per-namespace limit/SEM_INFO counters, updated in the same
    /// critical section as `sets`.
    usage: BTreeMap<u64, SemUsage>,
    /// Sorted by task id: O(log N) park registration/lookup with fallible
    /// capacity reservation before an O(N) queued-path insertion.
    waits: Vec<SemWait>,
    undos: SemUndoTable,
}

static SEMS: IrqSafeSpinLock<Option<SemState>> = IrqSafeSpinLock::new(None);
static FAIL_NEXT_SEM_UNDO_RESERVE: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "kernel-test")]
static TEST_SEMMNI: AtomicUsize = AtomicUsize::new(0);
#[derive(Default)]
struct SemUndoSharing {
    owner_of: BTreeMap<u64, u64>,
    refs: BTreeMap<u64, usize>,
}
static SEM_UNDO_SHARING: IrqSafeSpinLock<Option<SemUndoSharing>> = IrqSafeSpinLock::new(None);
static SEM_UNDO_OBSERVER_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Linux's default SEMOPM limit.  This sizes the fixed import buffer as well
/// as defining the observable E2BIG boundary.
const MAX_SOPS: usize = SEMOPM;

fn semmni() -> usize {
    #[cfg(feature = "kernel-test")]
    {
        let override_limit = TEST_SEMMNI.load(Ordering::Acquire);
        if override_limit != 0 {
            return override_limit;
        }
    }
    SEMMNI
}

fn with_sem_state<R>(f: impl FnOnce(&mut SemState) -> R) -> R {
    let mut g = SEMS.lock();
    f(g.get_or_insert_with(SemState::default))
}

fn with_sems<R>(f: impl FnOnce(&mut BTreeMap<IpcObjectKey, SemSet>) -> R) -> R {
    with_sem_state(|state| f(&mut state.sets))
}

fn sem_wait_index(waits: &[SemWait], task: u64) -> Result<usize, usize> {
    waits.binary_search_by_key(&task, |wait| wait.task)
}

fn sem_undo_index(undos: &SemUndoTable, key: SemUndoKey) -> Result<usize, usize> {
    undos.binary_search_by_key(&key, |(entry_key, _)| *entry_key)
}

fn ensure_sem_undo_set(state: &mut SemState, object: IpcObjectKey, owner: u64) -> Result<(), i64> {
    let nsems = state.sets.get(&object).ok_or(EINVAL)?.sems.len();
    let missing = (0..nsems)
        .filter(|num| sem_undo_index(&state.undos, (owner, object.0, object.1, *num)).is_err())
        .count();
    if missing == 0 {
        return Ok(());
    }
    if FAIL_NEXT_SEM_UNDO_RESERVE.swap(false, Ordering::AcqRel) {
        return Err(ENOMEM);
    }
    state.undos.try_reserve(missing).map_err(|_| ENOMEM)?;
    for semnum in 0..nsems {
        let key = (owner, object.0, object.1, semnum);
        if sem_undo_index(&state.undos, key).is_err() {
            state.undos.push((key, 0));
        }
    }
    state.undos.sort_unstable_by_key(|(key, _)| *key);
    Ok(())
}

#[doc(hidden)]
pub(crate) fn __test_fail_next_sem_undo_reserve() {
    FAIL_NEXT_SEM_UNDO_RESERVE.store(true, Ordering::Release);
}

#[cfg(feature = "kernel-test")]
pub(crate) fn __test_set_semmni(limit: usize) {
    TEST_SEMMNI.store(limit, Ordering::Release);
}

#[cfg(feature = "kernel-test")]
pub(crate) fn __test_sem_set_count() -> usize {
    let ipc_ns = current_ipc_namespace_id();
    with_sem_state(|state| {
        state
            .usage
            .get(&ipc_ns)
            .copied()
            .unwrap_or_default()
            .set_count
    })
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

type SemStatSnapshot = (u32, u32, u32, u32, u32, u32, i64, i64, usize);

fn sem_stat_snapshot(set: &SemSet) -> SemStatSnapshot {
    (
        set.key,
        set.uid,
        set.gid,
        set.cuid,
        set.cgid,
        set.mode,
        set.otime,
        set.ctime,
        set.sems.len(),
    )
}

fn encode_sem_stat(snapshot: SemStatSnapshot) -> Vec<u8> {
    let (key, uid, gid, cuid, cgid, mode, otime, ctime, nsems) = snapshot;
    let (uid, gid) = ipc_ids_to_user(uid, gid);
    let (cuid, cgid) = ipc_ids_to_user(cuid, cgid);
    let mut out = alloc::vec![0u8; SEMID64_SIZE];
    encode_perm(&mut out, key, uid, gid, cuid, cgid, mode);
    put_i64(&mut out, SEM_OTIME_OFFSET, otime);
    put_i64(&mut out, SEM_CTIME_OFFSET, ctime);
    put_u64(&mut out, SEM_NSEMS_OFFSET, nsems as u64);
    out
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

enum WaitData {
    None,
    MsgSend {
        mtype: i64,
        /// Owned by the wait record while parked and temporarily taken by the
        /// re-executing syscall.  A still-full queue restores the same buffer
        /// without allocating or copying under the IRQ-safe state lock.
        payload: Option<Vec<u8>>,
        msgflg: u64,
    },
}

struct IpcWait {
    kind: WaitKind,
    ipc_ns: u64,
    id: u64,
    errno: i64,
    /// A queue transition made this operation worth re-evaluating.  This is
    /// retained until the syscall re-executes, closing notify-before-waker-
    /// registration without a polling deadline.
    ready: bool,
    /// The task's current scheduler waker. Replaced on repeated polls and
    /// always fired after dropping the message-state lock.
    waker: Option<Waker>,
    data: WaitData,
}

fn with_waits<R>(f: impl FnOnce(&mut BTreeMap<u64, IpcWait>) -> R) -> R {
    with_msg_state(|state| f(&mut state.waits))
}

fn begin_wait(task: u64, kind: WaitKind, ipc_ns: u64, id: u64) {
    with_waits(|waits| {
        waits.entry(task).or_insert_with(|| IpcWait {
            kind,
            ipc_ns,
            id,
            errno: 0,
            ready: false,
            waker: None,
            data: WaitData::None,
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
            ready: false,
            waker: None,
            data: WaitData::MsgSend {
                mtype,
                payload: Some(payload),
                msgflg,
            },
        });
    });
}

fn copy_staged_sem_wait(
    task: u64,
    ipc_ns: u64,
    id: u64,
    out: &mut [u8],
) -> Option<SemStagedSnapshot> {
    with_sem_state(|state| {
        let wait = &state.waits[sem_wait_index(&state.waits, task).ok()?];
        if wait.ipc_ns != ipc_ns || wait.id != id || wait.result.is_some() {
            return None;
        }
        out[..wait.sops.len()].copy_from_slice(&wait.sops);
        Some((wait.nsops, wait.timeout, wait.blocking.is_some()))
    })
}

enum MsgSendResume {
    Fresh,
    Staged(i64, Vec<u8>, u64),
    Error(i64),
}

fn take_msg_send_resume(task: u64, ipc_ns: u64, id: u64) -> MsgSendResume {
    let (resume, removed) = with_waits(|waits| {
        let Some(wait) = waits.get(&task) else {
            return (MsgSendResume::Fresh, None);
        };
        if wait.kind != WaitKind::MsgSend || wait.ipc_ns != ipc_ns || wait.id != id {
            return (MsgSendResume::Fresh, waits.remove(&task));
        }
        if wait.errno != 0 {
            let errno = wait.errno;
            return (MsgSendResume::Error(errno), waits.remove(&task));
        }
        let wait = waits.get_mut(&task).expect("checked SysV sender missing");
        wait.ready = false;
        let WaitData::MsgSend {
            mtype,
            payload,
            msgflg,
        } = &mut wait.data
        else {
            panic!("staged SysV sender lost its payload state");
        };
        (
            MsgSendResume::Staged(
                *mtype,
                payload
                    .take()
                    .expect("staged SysV sender payload already taken"),
                *msgflg,
            ),
            None,
        )
    });
    // A stale or terminal wait can own a waker/payload whose drop reaches
    // scheduler or allocator state; release it after restoring IRQ state.
    drop(removed);
    resume
}

#[allow(clippy::too_many_arguments)] // One complete retained msgsnd operation.
fn restore_msg_send_wait(
    state: &mut MsgState,
    task: u64,
    ipc_ns: u64,
    id: u64,
    mtype: i64,
    payload: Vec<u8>,
    msgflg: u64,
) {
    match state.waits.entry(task) {
        alloc::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(IpcWait {
                kind: WaitKind::MsgSend,
                ipc_ns,
                id,
                errno: 0,
                ready: false,
                waker: None,
                data: WaitData::MsgSend {
                    mtype,
                    payload: Some(payload),
                    msgflg,
                },
            });
        }
        alloc::collections::btree_map::Entry::Occupied(mut entry) => {
            let wait = entry.get_mut();
            assert!(
                wait.kind == WaitKind::MsgSend
                    && wait.ipc_ns == ipc_ns
                    && wait.id == id
                    && wait.errno == 0,
                "staged SysV sender changed while rechecking"
            );
            wait.ready = false;
            let WaitData::MsgSend {
                mtype: retained_type,
                payload: retained_payload,
                msgflg: retained_flags,
            } = &mut wait.data
            else {
                panic!("staged SysV sender lost its payload state");
            };
            debug_assert_eq!(*retained_type, mtype);
            debug_assert_eq!(*retained_flags, msgflg);
            assert!(
                retained_payload.replace(payload).is_none(),
                "staged SysV sender payload restored twice"
            );
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum MsgParkState {
    NotWaiting,
    Pending,
    Ready,
}

/// Install one durable scheduler waker for a blocked message operation. A
/// queue transition or terminal error that won before registration is returned
/// as `Ready`, so the caller re-executes instead of sleeping for a timer poll.
pub(crate) fn register_msg_wait_waker(task: u64, waker: Waker) -> MsgParkState {
    let mut incoming = Some(waker);
    let (state, replaced) = with_waits(|waits| match waits.get_mut(&task) {
        Some(wait) if wait.errno != 0 || wait.ready => (MsgParkState::Ready, None),
        Some(wait) => {
            if wait
                .waker
                .as_ref()
                .is_some_and(|old| old.will_wake(incoming.as_ref().expect("incoming waker")))
            {
                (MsgParkState::Pending, None)
            } else {
                (
                    MsgParkState::Pending,
                    core::mem::replace(&mut wait.waker, incoming.take()),
                )
            }
        }
        None => (MsgParkState::NotWaiting, None),
    });
    // Waker drops may release the final scheduler Arc; never do so under the
    // IRQ-safe message-state lock.
    drop(replaced);
    drop(incoming);
    state
}

fn notify_msg_waiters(state: &mut MsgState, kind: WaitKind, object: IpcObjectKey) {
    for wait in state.waits.values_mut() {
        if wait.kind == kind && (wait.ipc_ns, wait.id) == object && wait.errno == 0 {
            wait.ready = true;
        }
    }
}

/// Error observed when a blocked message operation loses the queue lookup
/// race against IPC_RMID.  The queue and terminal wait record live under the
/// same lock, so checking both in one transaction preserves EIDRM even when
/// removal occurs after the syscall's initial fast-path error check.
fn missing_msg_queue_errno(
    state: &MsgState,
    task: u64,
    kind: WaitKind,
    object: IpcObjectKey,
) -> i64 {
    state
        .waits
        .get(&task)
        .filter(|wait| wait.kind == kind && (wait.ipc_ns, wait.id) == object && wait.errno != 0)
        .map_or(EINVAL, |wait| wait.errno)
}

/// Fire all message wakers whose condition changed. Taking one waker per lock
/// acquisition keeps wake/drop paths outside the IRQ-disabled critical section
/// without allocating a temporary wake vector.
fn drain_msg_wakes() {
    loop {
        let waker = with_waits(|waits| {
            waits
                .values_mut()
                .find(|wait| {
                    wait.kind != WaitKind::Sem
                        && (wait.errno != 0 || wait.ready)
                        && wait.waker.is_some()
                })
                .and_then(|wait| wait.waker.take())
        });
        match waker {
            Some(waker) => waker.wake(),
            None => break,
        }
    }
}

fn clear_wait(task: u64, kind: WaitKind, ipc_ns: u64, id: u64) {
    let removed = with_waits(|waits| {
        if waits
            .get(&task)
            .is_some_and(|wait| wait.kind == kind && wait.ipc_ns == ipc_ns && wait.id == id)
        {
            waits.remove(&task)
        } else {
            None
        }
    });
    drop(removed);
}

fn take_wait_error(task: u64, kind: WaitKind, ipc_ns: u64, id: u64) -> Option<i64> {
    let (errno, removed) = with_waits(|waits| match waits.get(&task) {
        Some(wait)
            if wait.kind == kind && wait.ipc_ns == ipc_ns && wait.id == id && wait.errno != 0 =>
        {
            let errno = wait.errno;
            (Some(errno), waits.remove(&task))
        }
        Some(wait) if wait.kind != kind || wait.ipc_ns != ipc_ns || wait.id != id => {
            (None, waits.remove(&task))
        }
        _ => (None, None),
    });
    drop(removed);
    errno
}

/// Retire an interrupted message wait in the same transaction that observes
/// its terminal RMID status.  Linux tests a deleted queue before a pending
/// signal after wakeup; whichever state mutation acquires this lock first is
/// therefore the observable winner (`EIDRM` or `EINTR`).
fn finish_interrupted_msg_wait(task: u64, kind: WaitKind, ipc_ns: u64, id: u64) -> Option<i64> {
    let (result, removed) = with_waits(|waits| {
        let wait = waits.get(&task)?;
        if wait.kind != kind || wait.ipc_ns != ipc_ns || wait.id != id {
            return None;
        }
        let result = if wait.errno != 0 { wait.errno } else { EINTR };
        Some((result, waits.remove(&task)))
    })
    .map_or((None, None), |(result, removed)| (Some(result), removed));
    drop(removed);
    result
}

#[doc(hidden)]
pub(crate) fn __test_begin_removed_wait(kind: u8, id: u64) {
    let kind = match kind {
        0 => WaitKind::Sem,
        1 => WaitKind::MsgSend,
        _ => WaitKind::MsgRecv,
    };
    let task = crate::handlers::current_task_id();
    let ipc_ns = current_ipc_namespace_id();
    if kind == WaitKind::Sem {
        with_sem_state(|state| {
            if state.waits.try_reserve(1).is_ok() {
                let index = sem_wait_index(&state.waits, task).unwrap_or_else(|index| index);
                state.waits.insert(
                    index,
                    SemWait {
                        task,
                        ipc_ns,
                        id,
                        sops: Vec::new(),
                        nsops: 0,
                        timeout: None,
                        blocking: None,
                        pid: task,
                        undo_owner: None,
                        result: None,
                        waker: None,
                    },
                );
            }
        });
    } else {
        begin_wait(task, kind, ipc_ns, id);
    }
}

#[doc(hidden)]
pub(crate) fn __test_stage_sem_wait(id: u64, sops: &[u8]) {
    let task = crate::handlers::current_task_id();
    with_sem_state(|state| {
        if state.waits.try_reserve(1).is_ok() {
            let index = sem_wait_index(&state.waits, task).unwrap_or_else(|index| index);
            state.waits.insert(
                index,
                SemWait {
                    task,
                    ipc_ns: current_ipc_namespace_id(),
                    id,
                    sops: sops.to_vec(),
                    nsops: sops.len() / 6,
                    timeout: None,
                    blocking: None,
                    pid: task,
                    undo_owner: None,
                    result: None,
                    waker: None,
                },
            );
        }
    });
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

#[doc(hidden)]
pub(crate) fn __test_reblock_staged_msg_send(id: u64) -> bool {
    let task = crate::handlers::current_task_id();
    let ipc_ns = current_ipc_namespace_id();
    let MsgSendResume::Staged(mtype, payload, msgflg) = take_msg_send_resume(task, ipc_ns, id)
    else {
        return false;
    };
    with_msg_state(|state| {
        restore_msg_send_wait(state, task, ipc_ns, id, mtype, payload, msgflg);
    });
    true
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
    let removed = with_waits(|waits| waits.remove(&tid));
    drop(removed);
    with_sem_state(|state| unlink_sem_wait(state, tid));
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
    with_sem_state(|state| {
        while let Some(index) = state
            .undos
            .iter()
            .position(|((owner, _, _, _), _)| *owner == undo_owner)
        {
            let (_, ipc_ns, semid, _) = state.undos[index].0;
            let object = (ipc_ns, semid);
            let mut changed = false;
            // One Linux sem_undo contains the adjustment vector for a whole
            // set. Apply every member while holding this transaction, then
            // expose the final state to queued operations exactly once.
            while index < state.undos.len() {
                let ((owner, namespace, id, semnum), adjustment) = state.undos[index];
                if owner != undo_owner || (namespace, id) != object {
                    break;
                }
                state.undos.remove(index);
                if adjustment == 0 {
                    continue;
                }
                if let Some(set) = state.sets.get_mut(&object) {
                    if let Some(sem) = set.sems.get_mut(semnum) {
                        *sem = sem.saturating_add(adjustment).clamp(0, SEMVMX);
                        set.pids[semnum] = pid;
                        changed = true;
                    }
                }
            }
            if changed {
                scan_sem_waiters(state, object);
            }
        }
    });
    drain_sem_wakes();
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

#[inline]
fn parse_sem_op(sops: &[u8], i: usize) -> (usize, i16, i16) {
    let o = i * 6;
    (
        u16::from_le_bytes(sops[o..o + 2].try_into().unwrap()) as usize,
        i16::from_le_bytes(sops[o + 2..o + 4].try_into().unwrap()),
        i16::from_le_bytes(sops[o + 4..o + 6].try_into().unwrap()) & SEM_BEHAVIOR_FLAGS,
    )
}

#[allow(clippy::too_many_arguments)]
fn perform_sem_ops(
    set: &mut SemSet,
    undos: &mut SemUndoTable,
    ipc_ns: u64,
    semid: u64,
    sops: &[u8],
    nsops: usize,
    pid: u64,
    undo_owner: Option<u64>,
) -> Result<(), SemOpFailure> {
    let mut applied = 0usize;
    let mut fail = None;
    for i in 0..nsops {
        let (num, op, flg) = parse_sem_op(sops, i);
        let cur = set.sems[num];
        let next = cur + i32::from(op);
        if op == 0 {
            if cur != 0 {
                fail = Some((EAGAIN, flg & IPC_NOWAIT != 0, Some((num, true))));
                break;
            }
        } else if next > SEMVMX {
            fail = Some((ERANGE, true, None));
            break;
        } else if next < 0 {
            fail = Some((EAGAIN, flg & IPC_NOWAIT != 0, Some((num, false))));
            break;
        }
        if flg & SEM_UNDO != 0 && op != 0 {
            let owner = undo_owner.expect("SEM_UNDO owner");
            let index = sem_undo_index(undos, (owner, ipc_ns, semid, num))
                .expect("SEM_UNDO key preallocated");
            let next_undo = undos[index].1 - i32::from(op);
            if !((-SEMVMX - 1)..=SEMVMX).contains(&next_undo) {
                fail = Some((ERANGE, true, None));
                break;
            }
            undos[index].1 = next_undo;
        }
        if op != 0 {
            set.sems[num] = next;
        }
        applied = i + 1;
    }
    if let Some(failure) = fail {
        for i in (0..applied).rev() {
            let (num, op, flg) = parse_sem_op(sops, i);
            if op != 0 {
                set.sems[num] -= i32::from(op);
                if flg & SEM_UNDO != 0 {
                    let owner = undo_owner.expect("SEM_UNDO owner");
                    let index = sem_undo_index(undos, (owner, ipc_ns, semid, num))
                        .expect("SEM_UNDO key preallocated");
                    undos[index].1 += i32::from(op);
                }
            }
        }
        return Err(failure);
    }
    for i in 0..nsops {
        let (num, _, _) = parse_sem_op(sops, i);
        set.pids[num] = pid;
    }
    set.otime = now_seconds();
    Ok(())
}

fn adjust_wait_count(set: &mut SemSet, blocker: SemWaitBlocker, add: bool) {
    let (num, zero) = blocker;
    let count = if zero {
        &mut set.zcnt[num]
    } else {
        &mut set.ncnt[num]
    };
    if add {
        *count += 1;
    } else {
        *count = count.saturating_sub(1);
    }
}

fn drain_sem_wakes() {
    loop {
        let waker = with_sem_state(|state| {
            state
                .waits
                .iter_mut()
                .find(|wait| wait.result.is_some() && wait.waker.is_some())
                .and_then(|wait| wait.waker.take())
        });
        match waker {
            Some(waker) => waker.wake(),
            None => break,
        }
    }
}

/// Complete every currently eligible waiter before exposing the mutation.
/// The queue is scanned in insertion order, but an unsatisfied entry is
/// skipped, matching Linux rather than imposing head-of-line blocking.
fn scan_sem_waiters(state: &mut SemState, object: IpcObjectKey) {
    let SemState {
        sets, waits, undos, ..
    } = state;
    let Some(set) = sets.get_mut(&object) else {
        return;
    };
    let mut pending = core::mem::take(&mut set.pending);
    loop {
        let pass_len = pending.len();
        let mut altered = false;
        for _ in 0..pass_len {
            let Some(task) = pending.pop_front() else {
                break;
            };
            let Ok(wait_index) = sem_wait_index(waits, task) else {
                continue;
            };
            let wait = &waits[wait_index];
            if wait.result.is_some() {
                continue;
            }
            let nsops = wait.nsops;
            let pid = wait.pid;
            let undo_owner = wait.undo_owner;
            let old_blocker = wait.blocking;
            let changes_value = (0..nsops).any(|i| parse_sem_op(&wait.sops, i).1 != 0);
            let result = perform_sem_ops(
                set, undos, object.0, object.1, &wait.sops, nsops, pid, undo_owner,
            );
            match result {
                Ok(()) => {
                    if let Some(blocker) = old_blocker {
                        adjust_wait_count(set, blocker, false);
                    }
                    if let Ok(index) = sem_wait_index(waits, task) {
                        let wait = &mut waits[index];
                        wait.result = Some(0);
                    }
                    altered |= changes_value;
                }
                Err((errno, true, _)) => {
                    if let Some(blocker) = old_blocker {
                        adjust_wait_count(set, blocker, false);
                    }
                    if let Ok(index) = sem_wait_index(waits, task) {
                        let wait = &mut waits[index];
                        wait.result = Some(errno);
                    }
                }
                Err((EAGAIN, false, blocker)) => {
                    if blocker != old_blocker {
                        if let Some(old) = old_blocker {
                            adjust_wait_count(set, old, false);
                        }
                        if let Some(new) = blocker {
                            adjust_wait_count(set, new, true);
                        }
                        if let Ok(index) = sem_wait_index(waits, task) {
                            let wait = &mut waits[index];
                            wait.blocking = blocker;
                        }
                    }
                    pending.push_back(task);
                }
                Err((errno, _, _)) => {
                    if let Some(blocker) = old_blocker {
                        adjust_wait_count(set, blocker, false);
                    }
                    if let Ok(index) = sem_wait_index(waits, task) {
                        let wait = &mut waits[index];
                        wait.result = Some(errno);
                    }
                }
            }
        }
        if !altered {
            break;
        }
    }
    set.pending = pending;
}

fn unlink_sem_wait(state: &mut SemState, task: u64) -> Option<SemWait> {
    let Ok(index) = sem_wait_index(&state.waits, task) else {
        return None;
    };
    let wait = state.waits.remove(index);
    if wait.result.is_some() {
        return Some(wait);
    }
    if let Some(set) = state.sets.get_mut(&(wait.ipc_ns, wait.id)) {
        if let Some(pos) = set.pending.iter().position(|queued| *queued == task) {
            set.pending.remove(pos);
        }
        if let Some(blocker) = wait.blocking {
            adjust_wait_count(set, blocker, false);
        }
    }
    Some(wait)
}

fn finish_pending_sem_wait(task: u64, errno: i64) -> i64 {
    let (result, waker) = with_sem_state(|state| {
        let Ok(index) = sem_wait_index(&state.waits, task) else {
            return (errno, None);
        };
        let mut wait = state.waits.remove(index);
        if let Some(result) = wait.result {
            let index = sem_wait_index(&state.waits, task).unwrap_or_else(|index| index);
            state.waits.insert(index, wait);
            return (result, None);
        }
        if let Some(set) = state.sets.get_mut(&(wait.ipc_ns, wait.id)) {
            if let Some(pos) = set.pending.iter().position(|queued| *queued == task) {
                set.pending.remove(pos);
            }
            if let Some(blocker) = wait.blocking {
                adjust_wait_count(set, blocker, false);
            }
        }
        wait.result = Some(errno);
        let waker = wait.waker.take();
        let index = sem_wait_index(&state.waits, task).unwrap_or_else(|index| index);
        state.waits.insert(index, wait);
        (errno, waker)
    });
    if let Some(waker) = waker {
        waker.wake();
    }
    result
}

fn take_sem_wait_result(task: u64, ipc_ns: u64, id: u64) -> Option<i64> {
    let (result, wait) = with_sem_state(|state| {
        let index = sem_wait_index(&state.waits, task).ok()?;
        let result = state.waits.get(index).and_then(|wait| {
            (wait.ipc_ns == ipc_ns && wait.id == id)
                .then_some(wait.result)
                .flatten()
        })?;
        Some((result, state.waits.remove(index)))
    })?;
    // SemWait owns a retained operation and possibly the final task-waker Arc.
    // Drop both only after the IRQ-safe global semaphore lock is released.
    drop(wait);
    Some(result)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SemParkState {
    NotWaiting,
    Pending,
    Ready,
}

/// Install the current scheduler waker in the task's single durable wait
/// record.  Replacing it deduplicates repeated polls.  A completion that won
/// before registration is observed as `Ready`, closing the lost-wake window.
pub(crate) fn register_sem_wait_waker(task: u64, waker: Waker) -> SemParkState {
    let mut incoming = Some(waker);
    let (park_state, replaced) = with_sem_state(|state| match sem_wait_index(&state.waits, task) {
        Ok(index) if state.waits[index].result.is_none() => {
            let wait = &mut state.waits[index];
            if wait
                .waker
                .as_ref()
                .is_some_and(|old| old.will_wake(incoming.as_ref().expect("incoming waker")))
            {
                (SemParkState::Pending, None)
            } else {
                (
                    SemParkState::Pending,
                    core::mem::replace(&mut wait.waker, incoming.take()),
                )
            }
        }
        Ok(_) => (SemParkState::Ready, None),
        Err(_) => (SemParkState::NotWaiting, None),
    });
    // Waker drops may release the final Arc; never do that under an IRQ-safe
    // global semaphore lock.
    drop(replaced);
    drop(incoming);
    park_state
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
enum SemParkResult {
    Parked,
    Expired,
    Unavailable,
}

fn park_sem_wait(ctx: &mut dyn TrapContext, timeout: Option<(i64, i64)>) -> SemParkResult {
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
                return SemParkResult::Expired;
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
        // The scheduler installs a durable waker in the semaphore queue and
        // rechecks terminal status after registration. Infinite waits need no
        // polling deadline; finite waits arm only at their real timeout.
        user.sleep_deadline_ns
            .store(real_deadline, Ordering::Release);
        user.futex_uaddr.store(0, Ordering::Release);
        user.net_io_wait.store(false, Ordering::Release);
        user.sem_wait_pending.store(true, Ordering::Release);
        // SAFETY: the live UserTaskCtx is exclusively being prepared for the
        // scheduler handoff, exactly as the shared I/O park bridge does.
        unsafe {
            ctx.save_user_state(user.state.get() as *mut u8);
            *user.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
            if narf_scheduler::stackful::user_own_stack_enabled() {
                crate::handlers::own_stack_block(ctx);
                return SemParkResult::Parked;
            }
            hook(user_task);
        }
    }
    SemParkResult::Unavailable
}

/// Park a System V message sender/receiver on its durable wait record and
/// re-execute the syscall after a targeted queue transition. Unlike the legacy
/// generic I/O bridge this has no 1 ms polling deadline: registration rechecks
/// `ready`/`errno` under the same lock that publishes queue mutations.
fn park_msg_wait(ctx: &mut dyn TrapContext) -> bool {
    if let (Some(user_task), Some(hook)) = (
        crate::user_task::current_user_task(),
        crate::user_task::yield_hook(),
    ) {
        #[cfg(target_arch = "x86_64")]
        const SYSCALL_INSN_LEN: u64 = 2;
        #[cfg(target_arch = "aarch64")]
        const SYSCALL_INSN_LEN: u64 = 4;
        ctx.set_rip(ctx.rip().wrapping_sub(SYSCALL_INSN_LEN));
        // SAFETY: current_user_task returns the live context for this trap.
        let user = unsafe { &*user_task };
        user.sleep_deadline_ns.store(u64::MAX, Ordering::Release);
        user.futex_uaddr.store(0, Ordering::Release);
        user.net_io_wait.store(false, Ordering::Release);
        user.sem_wait_pending.store(false, Ordering::Release);
        user.msg_wait_pending.store(true, Ordering::Release);
        // SAFETY: the live UserTaskCtx is exclusively prepared for the same
        // scheduler handoff used by semaphore waits and generic I/O waits.
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
    let nsems_raw = a.arg1 as i32;
    if nsems_raw < 0 || nsems_raw as usize > SEMMSL {
        ctx.set_return(err(EINVAL));
        return;
    }
    let nsems = nsems_raw as usize;
    let flg = a.arg2;
    let ipc_ns = current_ipc_namespace_id();
    let (_, uid, gid, groups) = current_identity();
    let id = with_sem_state(|state| {
        if key as u64 != IPC_PRIVATE {
            if let Some(&id) = state.key_ids.get(&(ipc_ns, key)) {
                let set = state
                    .sets
                    .get(&(ipc_ns, id))
                    .expect("indexed SysV semaphore set missing");
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
        if nsems == 0 {
            return Err(EINVAL);
        }
        let usage = state.usage.get(&ipc_ns).copied().unwrap_or_default();
        if usage.sem_count.saturating_add(nsems) > SEMMNS || usage.set_count >= semmni() {
            return Err(ENOSPC);
        }
        let mut sems = Vec::new();
        let mut pids = Vec::new();
        let mut ncnt = Vec::new();
        let mut zcnt = Vec::new();
        if sems.try_reserve_exact(nsems).is_err()
            || pids.try_reserve_exact(nsems).is_err()
            || ncnt.try_reserve_exact(nsems).is_err()
            || zcnt.try_reserve_exact(nsems).is_err()
        {
            return Err(ENOMEM);
        }
        sems.resize(nsems, 0);
        pids.resize(nsems, 0);
        ncnt.resize(nsems, 0);
        zcnt.resize(nsems, 0);
        let id = state.ids.entry(ipc_ns).or_default().allocate(semmni())?;
        state.sets.insert(
            (ipc_ns, id),
            SemSet {
                key,
                sems,
                pids,
                uid,
                gid,
                cuid: uid,
                cgid: gid,
                mode: (flg as u32) & IPC_PERM_MASK,
                otime: 0,
                ctime: now_seconds(),
                pending: VecDeque::new(),
                ncnt,
                zcnt,
            },
        );
        if key as u64 != IPC_PRIVATE {
            assert!(
                state.key_ids.insert((ipc_ns, key), id).is_none(),
                "duplicate SysV semaphore key index"
            );
        }
        let usage = state.usage.entry(ipc_ns).or_default();
        usage.set_count += 1;
        usage.sem_count += nsems;
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
    if let Some(result) = take_sem_wait_result(task, ipc_ns, semid) {
        if let Some(user_task) = crate::user_task::current_user_task() {
            // SAFETY: current_user_task returns this live trap's context.
            unsafe {
                (*user_task)
                    .sem_wait_pending
                    .store(false, Ordering::Release);
            }
        }
        finish_semtimedop_wait(timed);
        ctx.set_return(if result == 0 {
            SyscallReturn::ok(0)
        } else {
            err(result)
        });
        return;
    }
    let mut buf = [0u8; MAX_SOPS * 6];
    let staged = copy_staged_sem_wait(task, ipc_ns, semid, &mut buf);
    let nsops = staged.map_or(a.arg2 as u32 as usize, |(nsops, _, _)| nsops);

    // ksys_semtimedop imports the timeout before do_semtimedop performs any
    // nsops or sops validation.  Preserve that externally visible ordering.
    let timeout = if let Some((_, timeout, _)) = staged {
        timeout
    } else if timed && a.arg3 != 0 {
        let mut raw = [0u8; 16];
        // SAFETY: copy_from_user validates the complete __kernel_timespec.
        if unsafe { crate::handlers::copy_from_user(&mut raw, a.arg3) }.is_err() {
            finish_semtimedop_wait(timed);
            with_sem_state(|state| unlink_sem_wait(state, task));
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
        with_sem_state(|state| unlink_sem_wait(state, task));
        ctx.set_return(err(E2BIG));
        return;
    }
    if nsops == 0 {
        finish_semtimedop_wait(timed);
        with_sem_state(|state| unlink_sem_wait(state, task));
        ctx.set_return(err(EINVAL));
        return;
    }
    // struct sembuf { unsigned short sem_num; short sem_op; short sem_flg; } — 6 B.
    // Read the sops array into a fixed on-stack buffer so a semop costs no
    // heap traffic (the hot stress path is a single-sembuf P/V pair).
    let nbytes = nsops * 6;
    // SAFETY: copy_from_user range-validates sops_ptr and SMAP-brackets the
    // read of the complete sembuf array into the stack slice.
    if staged.is_none() {
        // SAFETY: this is the first execution; copy_from_user range-validates
        // and snapshots the complete operation array before any possible park.
        if unsafe { crate::handlers::copy_from_user(&mut buf[..nbytes], sops_ptr) }.is_err() {
            finish_semtimedop_wait(timed);
            with_sem_state(|state| unlink_sem_wait(state, task));
            ctx.set_return(err(EFAULT));
            return;
        }
    }
    // do_semtimedop imports the entire array before __do_semtimedop validates
    // the signed id.  The id check then precedes timespec field validation.
    if semid_raw < 0 {
        finish_semtimedop_wait(timed);
        with_sem_state(|state| unlink_sem_wait(state, task));
        ctx.set_return(err(EINVAL));
        return;
    }
    // Linux validates the imported timeout in __do_semtimedop before looking
    // up the semaphore set.
    if let Some((sec, nsec)) = timeout {
        if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
            finish_semtimedop_wait(timed);
            with_sem_state(|state| unlink_sem_wait(state, task));
            ctx.set_return(err(EINVAL));
            return;
        }
    }
    // A linked waiter is completed only by the queue scanner. A timeout or
    // signal can win only while its cached status is still pending.
    if staged.is_some_and(|(_, _, linked)| linked) {
        let reason = if semtimedop_expired(timeout) {
            Some(EAGAIN)
        } else if crate::handlers::has_interrupting_signal(task) {
            Some(EINTR)
        } else {
            None
        };
        if let Some(errno) = reason {
            let winner = finish_pending_sem_wait(task, errno);
            let result = take_sem_wait_result(task, ipc_ns, semid).unwrap_or(winner);
            finish_semtimedop_wait(timed);
            ctx.set_return(if result == 0 {
                SyscallReturn::ok(0)
            } else {
                err(result)
            });
        } else if matches!(park_sem_wait(ctx, timeout), SemParkResult::Expired) {
            let winner = finish_pending_sem_wait(task, EAGAIN);
            let result = take_sem_wait_result(task, ipc_ns, semid).unwrap_or(winner);
            finish_semtimedop_wait(timed);
            ctx.set_return(if result == 0 {
                SyscallReturn::ok(0)
            } else {
                err(result)
            });
        }
        return;
    }

    let has_undo = (0..nsops).any(|i| parse_sem_op(&buf[..nbytes], i).2 & SEM_UNDO != 0);
    let undo_owner = has_undo.then(|| sem_undo_owner(pid));
    let result = with_sem_state(|state| {
        // Linux find_alloc_undo() creates one dense per-set adjustment array
        // before EFBIG and permission validation.  Do the same, including for
        // a zero operation carrying SEM_UNDO, so ENOMEM has Linux precedence.
        if let Some(owner) = undo_owner {
            if let Err(errno) = ensure_sem_undo_set(state, object, owner) {
                return Err((errno, true, None));
            }
        }
        let SemState { sets, undos, .. } = state;
        let set = match sets.get_mut(&object) {
            Some(set) => set,
            None => return Err((EINVAL, true, None)),
        };
        let needs_write = (0..nsops).any(|i| parse_sem_op(&buf[..nbytes], i).1 != 0);
        let request = if needs_write { 0o2 } else { 0o4 };
        // Linux reports EFBIG for an imported sem_num outside this set, and
        // performs this check before ipcperms.
        for i in 0..nsops {
            let (num, _, _) = parse_sem_op(&buf[..nbytes], i);
            if num >= set.sems.len() {
                return Err((EFBIG, true, None));
            }
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
            request,
        ) {
            return Err((EACCES, true, None));
        }
        let result = perform_sem_ops(
            set,
            undos,
            ipc_ns,
            semid,
            &buf[..nbytes],
            nsops,
            pid,
            undo_owner,
        );
        if result.is_ok() {
            scan_sem_waiters(state, object);
        }
        result
    });
    drain_sem_wakes();
    match result {
        Ok(()) => {
            with_sem_state(|state| unlink_sem_wait(state, task));
            finish_semtimedop_wait(timed);
            ctx.set_return(SyscallReturn::ok(0));
        }
        Err((e, true, _)) => {
            with_sem_state(|state| unlink_sem_wait(state, task));
            finish_semtimedop_wait(timed);
            ctx.set_return(err(e));
        }
        Err((e, false, blocking)) if e == EAGAIN => {
            let mut retained = Vec::new();
            if retained.try_reserve_exact(nbytes).is_err() {
                finish_semtimedop_wait(timed);
                ctx.set_return(err(ENOMEM));
                return;
            }
            retained.extend_from_slice(&buf[..nbytes]);
            let enqueue_result = with_sem_state(|state| {
                let result = {
                    let SemState {
                        sets, waits, undos, ..
                    } = state;
                    let Some(set) = sets.get_mut(&object) else {
                        return Err(EIDRM);
                    };
                    let retry = perform_sem_ops(
                        set, undos, ipc_ns, semid, &retained, nsops, pid, undo_owner,
                    );
                    match retry {
                        Ok(()) => Ok(Some(())),
                        Err((errno, true, _)) => Err(errno),
                        Err((EAGAIN, false, retry_blocking)) => {
                            if set.pending.try_reserve(1).is_err() || waits.try_reserve(1).is_err()
                            {
                                return Err(ENOMEM);
                            }
                            let blocker = retry_blocking.or(blocking);
                            if let Some(blocker) = blocker {
                                adjust_wait_count(set, blocker, true);
                            }
                            set.pending.push_back(task);
                            let wait_index =
                                sem_wait_index(waits, task).unwrap_or_else(|index| index);
                            waits.insert(
                                wait_index,
                                SemWait {
                                    task,
                                    ipc_ns,
                                    id: semid,
                                    sops: retained,
                                    nsops,
                                    timeout,
                                    blocking: blocker,
                                    pid,
                                    undo_owner,
                                    result: None,
                                    waker: None,
                                },
                            );
                            Ok(None)
                        }
                        Err((errno, _, _)) => Err(errno),
                    }
                };
                if matches!(result, Ok(Some(()))) {
                    scan_sem_waiters(state, object);
                }
                result
            });
            match enqueue_result {
                Ok(Some(())) => {
                    drain_sem_wakes();
                    finish_semtimedop_wait(timed);
                    ctx.set_return(SyscallReturn::ok(0));
                }
                Err(errno) => {
                    finish_semtimedop_wait(timed);
                    ctx.set_return(err(errno));
                }
                Ok(None) => {
                    let reason = if semtimedop_expired(timeout) {
                        Some(EAGAIN)
                    } else if crate::handlers::has_interrupting_signal(task) {
                        Some(EINTR)
                    } else {
                        None
                    };
                    if let Some(errno) = reason {
                        let winner = finish_pending_sem_wait(task, errno);
                        let result = take_sem_wait_result(task, ipc_ns, semid).unwrap_or(winner);
                        finish_semtimedop_wait(timed);
                        ctx.set_return(if result == 0 {
                            SyscallReturn::ok(0)
                        } else {
                            err(result)
                        });
                    } else if matches!(park_sem_wait(ctx, timeout), SemParkResult::Expired) {
                        let winner = finish_pending_sem_wait(task, EAGAIN);
                        let result = take_sem_wait_result(task, ipc_ns, semid).unwrap_or(winner);
                        finish_semtimedop_wait(timed);
                        ctx.set_return(if result == 0 {
                            SyscallReturn::ok(0)
                        } else {
                            err(result)
                        });
                    }
                }
            }
        }
        Err((e, _, _)) => {
            with_sem_state(|state| unlink_sem_wait(state, task));
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
        IPC_INFO | SEM_INFO => {
            let (usage, max_index) = with_sem_state(|state| {
                let usage = state.usage.get(&ipc_ns).copied().unwrap_or_default();
                let max_index = state.ids.get(&ipc_ns).map_or(0, IpcIdTable::max_index);
                (usage, max_index)
            });
            let clamp_i32 = |value: usize| i32::try_from(value).unwrap_or(i32::MAX);
            let mut out = [0u8; SEMINFO_SIZE];
            put_i32(&mut out, 0, SEMMNS as i32); // semmap (legacy)
            put_i32(&mut out, 4, semmni() as i32);
            put_i32(&mut out, 8, SEMMNS as i32);
            put_i32(&mut out, 12, SEMMNS as i32); // semmnu (legacy)
            put_i32(&mut out, 16, SEMMSL as i32);
            put_i32(&mut out, 20, SEMOPM as i32);
            put_i32(&mut out, 24, SEMUME);
            if cmd == SEM_INFO {
                put_i32(&mut out, 28, clamp_i32(usage.set_count));
                put_i32(&mut out, 36, clamp_i32(usage.sem_count));
            } else {
                put_i32(&mut out, 28, SEMUSZ);
                put_i32(&mut out, 36, SEMVMX);
            }
            put_i32(&mut out, 32, SEMVMX);
            // SAFETY: Linux takes the namespace snapshot before validating
            // the output range; copy_to_user performs that final validation.
            if unsafe { crate::handlers::copy_to_user(arg, &out) }.is_err() {
                ctx.set_return(err(EFAULT));
            } else {
                ctx.set_return(SyscallReturn::ok(max_index));
            }
        }
        IPC_RMID => {
            let removed = with_sem_state(|state| {
                let set = state.sets.get(&object).ok_or(EINVAL)?;
                if !ipc_owner(caller_uid, set.uid, set.cuid) {
                    return Err(EPERM);
                }
                let set = state.sets.remove(&object).ok_or(EINVAL)?;
                state
                    .ids
                    .get_mut(&ipc_ns)
                    .expect("SysV semaphore id table missing")
                    .release(semid);
                if set.key as u64 != IPC_PRIVATE {
                    assert_eq!(
                        state.key_ids.remove(&(ipc_ns, set.key)),
                        Some(semid),
                        "SysV semaphore key index diverged"
                    );
                }
                let remove_usage = {
                    let usage = state
                        .usage
                        .get_mut(&ipc_ns)
                        .expect("SysV semaphore usage missing");
                    usage.set_count = usage
                        .set_count
                        .checked_sub(1)
                        .expect("SysV semaphore set count underflow");
                    usage.sem_count = usage
                        .sem_count
                        .checked_sub(set.sems.len())
                        .expect("SysV semaphore member count underflow");
                    usage.set_count == 0
                };
                if remove_usage {
                    state.usage.remove(&ipc_ns);
                }
                state
                    .undos
                    .retain(|((_, namespace, id, _), _)| *namespace != ipc_ns || *id != semid);
                for wait in &mut state.waits {
                    if wait.ipc_ns == ipc_ns && wait.id == semid && wait.result.is_none() {
                        wait.result = Some(EIDRM);
                    }
                }
                Ok(())
            });
            match removed {
                Ok(()) => {
                    drain_sem_wakes();
                    ctx.set_return(SyscallReturn::ok(0));
                }
                Err(e) => ctx.set_return(err(e)),
            }
        }
        IPC_STAT | SEM_STAT | SEM_STAT_ANY => {
            let snapshot = with_sem_state(|state| {
                let returned_id = if cmd == IPC_STAT {
                    semid
                } else {
                    state
                        .ids
                        .get(&ipc_ns)
                        .and_then(|ids| ids.full_id_at(semid))
                        .ok_or(EINVAL)?
                };
                let set = state.sets.get(&(ipc_ns, returned_id)).ok_or(EINVAL)?;
                if cmd != SEM_STAT_ANY
                    && !ipc_allowed(
                        caller_uid,
                        caller_gid,
                        &caller_groups,
                        set.uid,
                        set.gid,
                        set.cuid,
                        set.cgid,
                        set.mode,
                        0o4,
                    )
                {
                    return Err(EACCES);
                }
                Ok((returned_id, sem_stat_snapshot(set)))
            });
            let (returned_id, snapshot) = match snapshot {
                Ok(snapshot) => snapshot,
                Err(e) => {
                    ctx.set_return(err(e));
                    return;
                }
            };
            let out = encode_sem_stat(snapshot);
            // SAFETY: copy_to_user validates the complete architecture-specific
            // semid64_ds output range after the object snapshot is taken.
            if unsafe { crate::handlers::copy_to_user(arg, &out) }.is_err() {
                ctx.set_return(err(EFAULT));
            } else {
                ctx.set_return(SyscallReturn::ok(if cmd == IPC_STAT {
                    0
                } else {
                    returned_id
                }));
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
            // Linux validates the immediate SETVAL value before set lookup,
            // sem_num bounds, or permissions.
            let value = arg as i32;
            if !(0..=SEMVMX).contains(&value) {
                ctx.set_return(err(ERANGE));
                return;
            }
            let pid = current_identity().0;
            let r = with_sem_state(|state| {
                let set = state.sets.get_mut(&object).ok_or(EINVAL)?;
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
                set.sems[semnum] = value;
                set.pids[semnum] = pid;
                set.ctime = now_seconds();
                for ((_, namespace, id, num), adjustment) in &mut state.undos {
                    if *namespace == ipc_ns && *id == semid && *num == semnum {
                        *adjustment = 0;
                    }
                }
                scan_sem_waiters(state, object);
                Ok(())
            });
            ctx.set_return(match r {
                Ok(()) => {
                    drain_sem_wakes();
                    SyscallReturn::ok(0)
                }
                Err(e) => err(e),
            });
        }
        GETVAL | GETPID | GETNCNT | GETZCNT => {
            let r = with_sems(|m| {
                let set = m.get(&object).ok_or(EINVAL)?;
                // semctl_main performs read permission before validating the
                // semaphore number for all four per-semaphore read commands.
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
                if semnum_raw < 0 || semnum >= set.sems.len() {
                    return Err(EINVAL);
                }
                let value = match cmd {
                    GETVAL => set.sems[semnum] as u64,
                    GETPID => {
                        let outer = set.pids[semnum];
                        if outer == 0 {
                            0
                        } else {
                            crate::handlers::report_pid_to(
                                crate::handlers::current_task_id(),
                                outer,
                            )
                        }
                    }
                    GETNCNT => set.ncnt[semnum] as u64,
                    GETZCNT => set.zcnt[semnum] as u64,
                    _ => unreachable!(),
                };
                Ok(value)
            });
            ctx.set_return(match r {
                Ok(v) => SyscallReturn::ok(v),
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
            let pid = current_identity().0;
            let r = with_sem_state(|state| {
                let set = state.sets.get_mut(&object).ok_or(EIDRM)?;
                if set.sems.len() != values.len() {
                    return Err(EIDRM);
                }
                set.sems.copy_from_slice(&values);
                set.pids.fill(pid);
                set.ctime = now_seconds();
                for ((_, namespace, id, _), adjustment) in &mut state.undos {
                    if *namespace == ipc_ns && *id == semid {
                        *adjustment = 0;
                    }
                }
                scan_sem_waiters(state, object);
                Ok(())
            });
            ctx.set_return(match r {
                Ok(()) => {
                    drain_sem_wakes();
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
    /// Outer PID retained for translation into each observer's PID namespace.
    last_send_pid: u64,
    /// Outer PID retained for translation into each observer's PID namespace.
    last_recv_pid: u64,
}

struct QueuedMessage {
    mtype: i64,
    payload: Vec<u8>,
}

#[derive(Clone, Copy, Default)]
struct MsgUsage {
    queue_count: usize,
    message_count: usize,
    byte_count: usize,
}

#[derive(Default)]
struct MsgState {
    queues: BTreeMap<IpcObjectKey, MsgQueue>,
    ids: BTreeMap<u64, IpcIdTable>,
    /// Per-namespace key lookup; IPC_PRIVATE queues are intentionally absent.
    key_ids: BTreeMap<IpcLookupKey, u64>,
    /// Exact per-namespace limit/MSG_INFO counters.
    usage: BTreeMap<u64, MsgUsage>,
    waits: BTreeMap<u64, IpcWait>,
}

static MSG_STATE: IrqSafeSpinLock<Option<MsgState>> = IrqSafeSpinLock::new(None);
const MSG_MAX_BYTES: usize = 8192;
const MSG_DEFAULT_QUEUE_BYTES: usize = 16384;
const MSG_MAX_QUEUES: usize = 32_000;
const MSG_POOL_KIB: i32 = (MSG_MAX_QUEUES * MSG_DEFAULT_QUEUE_BYTES / 1024) as i32;
const MSG_MAP: i32 = MSG_DEFAULT_QUEUE_BYTES as i32;
const MSG_TQL: i32 = MSG_DEFAULT_QUEUE_BYTES as i32;
const MSG_SEGMENT_BYTES: i32 = 16;
const MSG_SEGMENTS: u16 = u16::MAX;
const MSG_NOERROR: i64 = 0o10000;
const MSG_EXCEPT: i64 = 0o20000;
const MSG_COPY: i64 = 0o40000;

#[cfg(feature = "kernel-test")]
static TEST_MSG_MAX_QUEUES: AtomicUsize = AtomicUsize::new(0);

fn msg_max_queues() -> usize {
    #[cfg(feature = "kernel-test")]
    {
        let override_limit = TEST_MSG_MAX_QUEUES.load(Ordering::Acquire);
        if override_limit != 0 {
            return override_limit;
        }
    }
    MSG_MAX_QUEUES
}

fn with_msg_state<R>(f: impl FnOnce(&mut MsgState) -> R) -> R {
    let mut state = MSG_STATE.lock();
    f(state.get_or_insert_with(MsgState::default))
}

fn with_msgs<R>(f: impl FnOnce(&mut BTreeMap<IpcObjectKey, MsgQueue>) -> R) -> R {
    with_msg_state(|state| f(&mut state.queues))
}

#[cfg(feature = "kernel-test")]
pub(crate) fn __test_set_msg_max_queues(limit: usize) {
    TEST_MSG_MAX_QUEUES.store(limit, Ordering::Release);
}

#[cfg(feature = "kernel-test")]
pub(crate) fn __test_msg_queue_count() -> usize {
    let ipc_ns = current_ipc_namespace_id();
    with_msg_state(|state| {
        state
            .usage
            .get(&ipc_ns)
            .copied()
            .unwrap_or_default()
            .queue_count
    })
}

/// `msgget(key, msgflg)`.
pub fn sys_msgget(ctx: &mut dyn TrapContext) {
    ensure_sem_undo_observer();
    let a = *ctx.args();
    let key = a.arg0 as u32;
    let flg = a.arg1;
    let ipc_ns = current_ipc_namespace_id();
    let (_, uid, gid, groups) = current_identity();
    let id = with_msg_state(|state| {
        if key as u64 != IPC_PRIVATE {
            if let Some(&id) = state.key_ids.get(&(ipc_ns, key)) {
                let q = state
                    .queues
                    .get(&(ipc_ns, id))
                    .expect("indexed SysV message queue missing");
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
        let usage = state.usage.get(&ipc_ns).copied().unwrap_or_default();
        if usage.queue_count >= msg_max_queues() {
            return Err(ENOSPC);
        }
        let id = state
            .ids
            .entry(ipc_ns)
            .or_default()
            .allocate(msg_max_queues())?;
        state.queues.insert(
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
        if key as u64 != IPC_PRIVATE {
            assert!(
                state.key_ids.insert((ipc_ns, key), id).is_none(),
                "duplicate SysV message key index"
            );
        }
        state.usage.entry(ipc_ns).or_default().queue_count += 1;
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
    let resumed = match take_msg_send_resume(task, ipc_ns, msqid) {
        MsgSendResume::Fresh => None,
        MsgSendResume::Staged(mtype, payload, msgflg) => Some((mtype, payload, msgflg)),
        MsgSendResume::Error(errno) => {
            ctx.set_return(err(errno));
            return;
        }
    };
    if resumed.is_some() && crate::handlers::has_interrupting_signal(task) {
        let errno =
            finish_interrupted_msg_wait(task, WaitKind::MsgSend, ipc_ns, msqid).unwrap_or(EINTR);
        ctx.set_return(err(errno));
        return;
    }
    let (mtype, payload, msgflg) = if let Some(resumed) = resumed {
        resumed
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
        let mut payload = Vec::new();
        if payload.try_reserve_exact(msgsz).is_err() {
            clear_wait(task, WaitKind::MsgSend, ipc_ns, msqid);
            ctx.set_return(err(ENOMEM));
            return;
        }
        payload.resize(msgsz, 0);
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
    let mut pending_payload = Some(payload);
    let r: Result<bool, i64> = with_msg_state(|state| {
        let fits = {
            let Some(q) = state.queues.get_mut(&object) else {
                return Err(missing_msg_queue_errno(
                    state,
                    task,
                    WaitKind::MsgSend,
                    object,
                ));
            };
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
            msgsz.saturating_add(q.current_bytes) <= q.max_bytes
                && q.msgs.len().saturating_add(1) <= q.max_bytes
        };
        if !fits {
            if msgflg & IPC_NOWAIT as u64 == 0 {
                restore_msg_send_wait(
                    state,
                    task,
                    ipc_ns,
                    msqid,
                    mtype,
                    pending_payload.take().expect("blocked SysV message"),
                    msgflg,
                );
            }
            return Ok(false);
        }
        let Some(q) = state.queues.get_mut(&object) else {
            return Err(missing_msg_queue_errno(
                state,
                task,
                WaitKind::MsgSend,
                object,
            ));
        };
        q.msgs.try_reserve(1).map_err(|_| ENOMEM)?;
        q.msgs.push_back(QueuedMessage {
            mtype,
            payload: pending_payload.take().expect("pending SysV message"),
        });
        q.current_bytes += msgsz;
        q.stime = now_seconds();
        q.last_send_pid = pid;
        let usage = state
            .usage
            .get_mut(&ipc_ns)
            .expect("SysV message usage missing");
        usage.message_count += 1;
        usage.byte_count += msgsz;
        notify_msg_waiters(state, WaitKind::MsgRecv, object);
        Ok(true)
    });
    match r {
        Ok(true) => {
            clear_wait(task, WaitKind::MsgSend, ipc_ns, msqid);
            drain_msg_wakes();
            narf_net::readiness::notify(0);
            ctx.set_return(SyscallReturn::ok(0));
        }
        Ok(false) if msgflg & IPC_NOWAIT as u64 != 0 => {
            clear_wait(task, WaitKind::MsgSend, ipc_ns, msqid);
            ctx.set_return(err(EAGAIN));
        }
        Ok(false) => {
            if crate::handlers::has_interrupting_signal(task) {
                let errno = finish_interrupted_msg_wait(task, WaitKind::MsgSend, ipc_ns, msqid)
                    .unwrap_or(EINTR);
                ctx.set_return(err(errno));
            } else if let Some(errno) = take_wait_error(task, WaitKind::MsgSend, ipc_ns, msqid) {
                ctx.set_return(err(errno));
            } else if !park_msg_wait(ctx) {
                clear_wait(task, WaitKind::MsgSend, ipc_ns, msqid);
                ctx.set_return(err(EAGAIN));
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
    // Linux prepares MSG_COPY scratch before looking up the queue.  Reserve
    // the same bounded capacity here, both preserving ENOMEM precedence and
    // keeping allocation out of the global queue lock below.
    let mut copy_payload = Vec::new();
    if flg & MSG_COPY != 0 {
        let copy_capacity = core::cmp::min(msgsz, MSG_MAX_BYTES);
        if copy_payload.try_reserve_exact(copy_capacity).is_err() {
            clear_wait(task, WaitKind::MsgRecv, ipc_ns, msqid);
            ctx.set_return(err(ENOMEM));
            return;
        }
        copy_payload.resize(copy_capacity, 0);
        // Linux prepare_copy() uses load_msg() on the output buffer before
        // queue lookup.  Although the bytes are only scratch, this makes an
        // unreadable output pointer report EFAULT ahead of id/permission and
        // selection errors.
        // SAFETY: copy_from_user validates the complete MSG_COPY scratch read.
        if unsafe { crate::handlers::copy_from_user(&mut copy_payload, msgp) }.is_err() {
            clear_wait(task, WaitKind::MsgRecv, ipc_ns, msqid);
            ctx.set_return(err(EFAULT));
            return;
        }
    }

    // Linux unlinks an ordinary selected message and updates queue metadata
    // under the queue lock before copying it to userspace.  Consequently an
    // EFAULT from either output copy still consumes the message.  Take
    // ownership of the payload here so ordinary receives need no heap copy.
    // MSG_COPY is deliberately non-destructive and therefore retains one
    // fallibly allocated snapshot outside the queue lock.
    let picked = with_msg_state(|state| {
        let Some(q) = state.queues.get_mut(&object) else {
            return Err(missing_msg_queue_errno(
                state,
                task,
                WaitKind::MsgRecv,
                object,
            ));
        };
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
            usize::try_from(msgtyp)
                .ok()
                .and_then(|ordinal| q.msgs.iter().enumerate().nth(ordinal).map(|(idx, _)| idx))
        } else if msgtyp < 0 {
            let limit = if msgtyp == i64::MIN {
                i64::MAX
            } else {
                -msgtyp
            };
            q.msgs
                .iter()
                .enumerate()
                .filter(|(_, msg)| msg.mtype <= limit)
                .min_by_key(|(_, msg)| msg.mtype)
                .map(|(idx, _)| idx)
        } else {
            q.msgs.iter().position(|msg| {
                msgtyp == 0
                    || if flg & MSG_EXCEPT != 0 {
                        msg.mtype != msgtyp
                    } else {
                        msg.mtype == msgtyp
                    }
            })
        };
        let mut removed_bytes = None;
        let selected: Option<(i64, Vec<u8>)> = match idx {
            Some(i) => {
                let msg = &q.msgs[i];
                if msg.payload.len() > msgsz && flg & MSG_NOERROR == 0 {
                    return Err(E2BIG);
                }
                if flg & MSG_COPY != 0 && msg.payload.len() > msgsz {
                    // copy_msg() rejects a source larger than its prepared
                    // destination even when MSG_NOERROR bypassed E2BIG.
                    return Err(EINVAL);
                }
                let copied_len = core::cmp::min(msg.payload.len(), msgsz);
                if flg & MSG_COPY != 0 {
                    copy_payload[..copied_len].copy_from_slice(&msg.payload[..copied_len]);
                    copy_payload.truncate(copied_len);
                    return Ok(Some((msg.mtype, core::mem::take(&mut copy_payload))));
                }
                let msg = q.msgs.remove(i).expect("selected SysV message");
                q.current_bytes = q.current_bytes.saturating_sub(msg.payload.len());
                q.rtime = now_seconds();
                q.last_recv_pid = pid;
                removed_bytes = Some(msg.payload.len());
                Some((msg.mtype, msg.payload))
            }
            None => None,
        };
        if let Some(bytes) = removed_bytes {
            let usage = state
                .usage
                .get_mut(&ipc_ns)
                .expect("SysV message usage missing");
            usage.message_count = usage
                .message_count
                .checked_sub(1)
                .expect("SysV message count underflow");
            usage.byte_count = usage
                .byte_count
                .checked_sub(bytes)
                .expect("SysV message byte count underflow");
        }
        if selected.is_some() {
            if flg & MSG_COPY == 0 {
                notify_msg_waiters(state, WaitKind::MsgSend, object);
            }
        } else if flg & IPC_NOWAIT as i64 == 0 {
            match state.waits.entry(task) {
                alloc::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(IpcWait {
                        kind: WaitKind::MsgRecv,
                        ipc_ns,
                        id: msqid,
                        errno: 0,
                        ready: false,
                        waker: None,
                        data: WaitData::None,
                    });
                }
                alloc::collections::btree_map::Entry::Occupied(mut entry) => {
                    let wait = entry.get_mut();
                    if wait.kind == WaitKind::MsgRecv
                        && wait.ipc_ns == ipc_ns
                        && wait.id == msqid
                        && wait.errno == 0
                    {
                        wait.ready = false;
                    }
                }
            }
        }
        Ok(selected)
    });
    let (mtype, payload) = match picked {
        Ok(Some(msg)) => msg,
        Ok(None) => {
            if flg & IPC_NOWAIT as i64 != 0 {
                clear_wait(task, WaitKind::MsgRecv, ipc_ns, msqid);
                ctx.set_return(err(ENOMSG));
            } else if crate::handlers::has_interrupting_signal(task) {
                let errno = finish_interrupted_msg_wait(task, WaitKind::MsgRecv, ipc_ns, msqid)
                    .unwrap_or(EINTR);
                ctx.set_return(err(errno));
            } else if let Some(errno) = take_wait_error(task, WaitKind::MsgRecv, ipc_ns, msqid) {
                ctx.set_return(err(errno));
            } else {
                // Kernel-test contexts cannot sleep. Leave the receive staged
                // rather than returning IPC_NOWAIT's ENOMSG; a later invocation
                // retries after a sender publishes.
                let _ = park_msg_wait(ctx);
            }
            return;
        }
        Err(e) => {
            clear_wait(task, WaitKind::MsgRecv, ipc_ns, msqid);
            ctx.set_return(err(e));
            return;
        }
    };
    if flg & MSG_COPY == 0 {
        // As in Linux, publish freed queue capacity after unlocking and before
        // the potentially faulting userspace copy.
        drain_msg_wakes();
        narf_net::readiness::notify(0);
    }
    let copied_len = core::cmp::min(payload.len(), msgsz);
    // Linux's do_msg_fill publishes mtype first, then mtext.  Either copy may
    // fault after an ordinary message has already been unlinked.
    // SAFETY: copy_to_user range-validates and SMAP-brackets each output.
    let copy_result = unsafe { crate::handlers::copy_to_user(msgp, &mtype.to_le_bytes()) }
        .and_then(|()| {
            if copied_len == 0 {
                return Ok(());
            }
            let payload_ptr = msgp.checked_add(8).ok_or(EFAULT as u64)?;
            // SAFETY: payload_ptr was checked above; copy_to_user validates
            // the complete destination range.
            unsafe { crate::handlers::copy_to_user(payload_ptr, &payload[..copied_len]) }
        });
    if copy_result.is_err() {
        clear_wait(task, WaitKind::MsgRecv, ipc_ns, msqid);
        ctx.set_return(err(EFAULT));
        return;
    }
    clear_wait(task, WaitKind::MsgRecv, ipc_ns, msqid);
    ctx.set_return(SyscallReturn::ok(copied_len as u64));
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
        IPC_INFO | MSG_INFO => {
            let (usage, max_index) = with_msg_state(|state| {
                let usage = state.usage.get(&ipc_ns).copied().unwrap_or_default();
                let max_index = state.ids.get(&ipc_ns).map_or(0, IpcIdTable::max_index);
                (usage, max_index)
            });
            let clamp_i32 = |value: usize| i32::try_from(value).unwrap_or(i32::MAX);
            let mut out = [0u8; MSGINFO_SIZE];
            if cmd == MSG_INFO {
                put_i32(&mut out, 0, clamp_i32(usage.queue_count));
                put_i32(&mut out, 4, clamp_i32(usage.message_count));
                put_i32(&mut out, 24, clamp_i32(usage.byte_count));
            } else {
                put_i32(&mut out, 0, MSG_POOL_KIB);
                put_i32(&mut out, 4, MSG_MAP);
                put_i32(&mut out, 24, MSG_TQL);
            }
            put_i32(&mut out, 8, MSG_MAX_BYTES as i32);
            put_i32(&mut out, 12, MSG_DEFAULT_QUEUE_BYTES as i32);
            put_i32(&mut out, 16, msg_max_queues().min(i32::MAX as usize) as i32);
            put_i32(&mut out, 20, MSG_SEGMENT_BYTES);
            put_u16(&mut out, 28, MSG_SEGMENTS);
            // SAFETY: Linux computes the namespace snapshot before validating
            // the output range; copy_to_user performs that final validation.
            if unsafe { crate::handlers::copy_to_user(buf, &out) }.is_err() {
                ctx.set_return(err(EFAULT));
            } else {
                ctx.set_return(SyscallReturn::ok(max_index));
            }
        }
        IPC_RMID => {
            let removed = with_msg_state(|state| {
                let q = state.queues.get(&object).ok_or(EINVAL)?;
                if !ipc_owner(caller_uid, q.uid, q.cuid) {
                    return Err(EPERM);
                }
                let queue = state.queues.remove(&object).ok_or(EINVAL)?;
                state
                    .ids
                    .get_mut(&ipc_ns)
                    .expect("SysV message id table missing")
                    .release(msqid);
                if queue.key as u64 != IPC_PRIVATE {
                    assert_eq!(
                        state.key_ids.remove(&(ipc_ns, queue.key)),
                        Some(msqid),
                        "SysV message key index diverged"
                    );
                }
                let remove_usage = {
                    let usage = state
                        .usage
                        .get_mut(&ipc_ns)
                        .expect("SysV message usage missing");
                    usage.queue_count = usage
                        .queue_count
                        .checked_sub(1)
                        .expect("SysV message queue count underflow");
                    usage.message_count = usage
                        .message_count
                        .checked_sub(queue.msgs.len())
                        .expect("SysV message count underflow");
                    usage.byte_count = usage
                        .byte_count
                        .checked_sub(queue.current_bytes)
                        .expect("SysV message byte count underflow");
                    usage.queue_count == 0
                };
                if remove_usage {
                    state.usage.remove(&ipc_ns);
                }
                for wait in state.waits.values_mut() {
                    if wait.kind != WaitKind::Sem && (wait.ipc_ns, wait.id) == object {
                        wait.errno = EIDRM;
                    }
                }
                Ok(queue)
            });
            match removed {
                Ok(queue) => {
                    // Queue payload destruction and task wakeups can release
                    // allocator/scheduler state; perform both after unlocking.
                    drop(queue);
                    drain_msg_wakes();
                    narf_net::readiness::notify(0);
                    ctx.set_return(SyscallReturn::ok(0));
                }
                Err(e) => ctx.set_return(err(e)),
            }
        }
        IPC_STAT | MSG_STAT | MSG_STAT_ANY => {
            let snapshot = with_msg_state(|state| {
                let returned_id = if cmd == IPC_STAT {
                    msqid
                } else {
                    state
                        .ids
                        .get(&ipc_ns)
                        .and_then(|ids| ids.full_id_at(msqid))
                        .ok_or(EINVAL)?
                };
                let q = state.queues.get(&(ipc_ns, returned_id)).ok_or(EINVAL)?;
                if cmd != MSG_STAT_ANY
                    && !ipc_allowed(
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
                {
                    return Err(EACCES);
                }
                Ok((
                    returned_id,
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
                returned_id,
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
            let observer = crate::handlers::current_task_id();
            let last_send_pid =
                i32::try_from(crate::handlers::report_pid_to(observer, last_send_pid)).unwrap_or(0);
            let last_recv_pid =
                i32::try_from(crate::handlers::report_pid_to(observer, last_recv_pid)).unwrap_or(0);
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
                ctx.set_return(SyscallReturn::ok(if cmd == IPC_STAT {
                    0
                } else {
                    returned_id
                }));
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
            let result = with_msg_state(|state| {
                {
                    let q = state.queues.get_mut(&object).ok_or(EINVAL)?;
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
                }
                notify_msg_waiters(state, WaitKind::MsgRecv, object);
                notify_msg_waiters(state, WaitKind::MsgSend, object);
                Ok(())
            });
            match result {
                Ok(()) => {
                    // Linux uses its internal -EAGAIN receiver sentinel to
                    // wake and recheck after IPC_SET; it does not return that
                    // sentinel to userspace. A readiness bump retries both
                    // receivers (including stricter permissions) and senders
                    // that may now fit under a larger qbytes.
                    drain_msg_wakes();
                    narf_net::readiness::notify(0);
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
    with_sem_state(|state| {
        state.sets.retain(|(namespace, _), _| *namespace != ipc_ns);
        state.ids.remove(&ipc_ns);
        state
            .key_ids
            .retain(|(namespace, _), _| *namespace != ipc_ns);
        state.usage.remove(&ipc_ns);
        state
            .undos
            .retain(|((_, namespace, _, _), _)| *namespace != ipc_ns);
        for wait in &mut state.waits {
            if wait.ipc_ns == ipc_ns && wait.result.is_none() {
                wait.result = Some(EIDRM);
            }
        }
    });
    drain_sem_wakes();
    with_msg_state(|state| {
        state
            .queues
            .retain(|(namespace, _), _| *namespace != ipc_ns);
        state.ids.remove(&ipc_ns);
        state
            .key_ids
            .retain(|(namespace, _), _| *namespace != ipc_ns);
        state.usage.remove(&ipc_ns);
        for wait in state.waits.values_mut() {
            if wait.ipc_ns == ipc_ns {
                wait.errno = EIDRM;
            }
        }
    });
    drain_msg_wakes();
    narf_net::readiness::notify(0);
}
