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
use alloc::sync::Arc;
use alloc::vec::Vec;
#[cfg(feature = "kernel-test")]
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
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
    /// Set once IPC_RMID has detached this object from the namespace registry.
    /// References obtained before removal remain valid long enough to observe
    /// Linux's EIDRM result under the per-set lock.
    removed: bool,
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
    /// Intrusive FIFO of blocked tasks, linked through `SemWait`.  Linux puts
    /// each `sem_queue` directly on a per-array/per-semaphore list so timeout
    /// and signal cancellation can unlink without searching the whole queue.
    /// As on Linux, an older unsatisfiable operation does not block a younger
    /// satisfiable operation.
    pending_head: Option<u64>,
    pending_tail: Option<u64>,
    ncnt: Vec<usize>,
    zcnt: Vec<usize>,
    /// SEM_UNDO adjustments are owned by the semaphore array in Linux.  Keep
    /// them under the same per-set lock so unrelated arrays never contend.
    undos: SemUndoTable,
}

type SemSetRef = Arc<IrqSafeSpinLock<SemSet>>;

type SemUndoKey = (u64, u64, u64, usize);
type SemUndoTable = Vec<(SemUndoKey, i32)>;

type SemWaitBlocker = (usize, bool); // (sem_num, waits-for-zero)
type SemOpFailure = (i64, bool, Option<SemWaitBlocker>); // (errno, terminal, blocker)
type SemStagedSnapshot = (usize, Option<(i64, i64)>, bool); // (nsops, timeout, linked)

struct SemWait {
    task: u64,
    /// Production waiters retain their set across IPC_RMID.  Synthetic ABI
    /// race tests may intentionally stage a waiter for an already-missing id.
    set: Option<SemSetRef>,
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
    /// Intrusive membership in the owning semaphore set's pending FIFO.
    pending_prev: Option<u64>,
    pending_next: Option<u64>,
    /// Replaced on every scheduler poll and taken exactly once on completion.
    waker: Option<Waker>,
    /// Intrusive membership in the global ready-to-wake queue. Task ids are
    /// stable for the lifetime of a wait record and avoid wake-path allocation.
    wake_prev: Option<u64>,
    wake_next: Option<u64>,
}

#[derive(Clone, Copy, Default)]
struct SemUsage {
    set_count: usize,
    sem_count: usize,
}

#[derive(Default)]
struct SemState {
    /// Namespace registry only.  Semaphore values and metadata live behind
    /// each set's own lock, matching Linux's `sem_array` locking boundary.
    sets: BTreeMap<IpcObjectKey, SemSetRef>,
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
    /// Completed waits with an installed waker, linked through `SemWait`.
    /// This mirrors Linux's deduplicated wake_q and avoids repeated full scans.
    wake_head: Option<u64>,
    wake_tail: Option<u64>,
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

fn lookup_sem_set(object: IpcObjectKey) -> Option<SemSetRef> {
    with_sem_state(|state| state.sets.get(&object).cloned())
}

fn with_sem_set<R>(
    object: IpcObjectKey,
    f: impl FnOnce(&mut SemSet) -> Result<R, i64>,
) -> Result<R, i64> {
    let set_ref = lookup_sem_set(object).ok_or(EINVAL)?;
    let mut set = set_ref.lock();
    if set.removed {
        return Err(EIDRM);
    }
    f(&mut set)
}

fn sem_wait_index(waits: &[SemWait], task: u64) -> Result<usize, usize> {
    waits.binary_search_by_key(&task, |wait| wait.task)
}

fn sem_pending_is_linked(set: &SemSet, wait: &SemWait) -> bool {
    wait.pending_prev.is_some()
        || wait.pending_next.is_some()
        || set.pending_head == Some(wait.task)
}

fn queue_sem_pending(set: &mut SemSet, state: &mut SemState, index: usize) {
    assert!(
        !sem_pending_is_linked(set, &state.waits[index]),
        "SysV semaphore wait queued twice"
    );
    let task = state.waits[index].task;
    let previous = set.pending_tail;
    if let Some(previous) = previous {
        let previous_index = sem_wait_index(&state.waits, previous)
            .expect("SysV semaphore pending predecessor disappeared");
        state.waits[previous_index].pending_next = Some(task);
    } else {
        set.pending_head = Some(task);
    }
    state.waits[index].pending_prev = previous;
    state.waits[index].pending_next = None;
    set.pending_tail = Some(task);
}

fn unlink_sem_pending(set: &mut SemSet, state: &mut SemState, index: usize) -> bool {
    if !sem_pending_is_linked(set, &state.waits[index]) {
        return false;
    }
    let task = state.waits[index].task;
    let previous = state.waits[index].pending_prev;
    let next = state.waits[index].pending_next;
    if let Some(previous) = previous {
        let previous_index = sem_wait_index(&state.waits, previous)
            .expect("SysV semaphore pending predecessor disappeared");
        state.waits[previous_index].pending_next = next;
    } else {
        assert_eq!(set.pending_head, Some(task));
        set.pending_head = next;
    }
    if let Some(next) = next {
        let next_index = sem_wait_index(&state.waits, next)
            .expect("SysV semaphore pending successor disappeared");
        state.waits[next_index].pending_prev = previous;
    } else {
        assert_eq!(set.pending_tail, Some(task));
        set.pending_tail = previous;
    }
    state.waits[index].pending_prev = None;
    state.waits[index].pending_next = None;
    true
}

fn sem_wake_is_queued(state: &SemState, index: usize) -> bool {
    let wait = &state.waits[index];
    wait.wake_prev.is_some() || wait.wake_next.is_some() || state.wake_head == Some(wait.task)
}

fn queue_sem_wake(state: &mut SemState, index: usize) {
    if state.waits[index].waker.is_none() || sem_wake_is_queued(state, index) {
        return;
    }
    let task = state.waits[index].task;
    let previous = state.wake_tail;
    if let Some(previous) = previous {
        let previous_index = sem_wait_index(&state.waits, previous)
            .expect("queued SysV semaphore wake predecessor disappeared");
        state.waits[previous_index].wake_next = Some(task);
    } else {
        state.wake_head = Some(task);
    }
    state.waits[index].wake_prev = previous;
    state.waits[index].wake_next = None;
    state.wake_tail = Some(task);
}

fn unlink_sem_wake(state: &mut SemState, index: usize) {
    if !sem_wake_is_queued(state, index) {
        return;
    }
    let task = state.waits[index].task;
    let previous = state.waits[index].wake_prev;
    let next = state.waits[index].wake_next;
    if let Some(previous) = previous {
        let previous_index = sem_wait_index(&state.waits, previous)
            .expect("queued SysV semaphore wake predecessor disappeared");
        state.waits[previous_index].wake_next = next;
    } else {
        assert_eq!(state.wake_head, Some(task));
        state.wake_head = next;
    }
    if let Some(next) = next {
        let next_index = sem_wait_index(&state.waits, next)
            .expect("queued SysV semaphore wake successor disappeared");
        state.waits[next_index].wake_prev = previous;
    } else {
        assert_eq!(state.wake_tail, Some(task));
        state.wake_tail = previous;
    }
    state.waits[index].wake_prev = None;
    state.waits[index].wake_next = None;
}

fn sem_undo_index(undos: &SemUndoTable, key: SemUndoKey) -> Result<usize, usize> {
    undos.binary_search_by_key(&key, |(entry_key, _)| *entry_key)
}

fn ensure_sem_undo_set(set: &mut SemSet, object: IpcObjectKey, owner: u64) -> Result<(), i64> {
    let nsems = set.sems.len();
    let missing = (0..nsems)
        .filter(|num| sem_undo_index(&set.undos, (owner, object.0, object.1, *num)).is_err())
        .count();
    if missing == 0 {
        return Ok(());
    }
    if FAIL_NEXT_SEM_UNDO_RESERVE.swap(false, Ordering::AcqRel) {
        return Err(ENOMEM);
    }
    set.undos.try_reserve(missing).map_err(|_| ENOMEM)?;
    for semnum in 0..nsems {
        let key = (owner, object.0, object.1, semnum);
        if sem_undo_index(&set.undos, key).is_err() {
            set.undos.push((key, 0));
        }
    }
    set.undos.sort_unstable_by_key(|(key, _)| *key);
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

/// Prove distinct semaphore arrays have independently acquirable mutation
/// locks after both references have been resolved from the namespace index.
#[cfg(feature = "kernel-test")]
pub(crate) fn __test_sem_sets_lock_independently(first: u64, second: u64) -> Option<bool> {
    let ipc_ns = current_ipc_namespace_id();
    let (first, second) = with_sem_state(|state| {
        Some((
            Arc::clone(state.sets.get(&(ipc_ns, first))?),
            Arc::clone(state.sets.get(&(ipc_ns, second))?),
        ))
    })?;
    let _first_guard = first.lock();
    let independent = second.try_lock().is_some();
    Some(independent)
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
    /// always fired after dropping the owning queue's lock.
    waker: Option<Waker>,
    data: WaitData,
}

struct MsgWaitNode {
    task: u64,
    queue: MsgQueueRef,
    wait: IpcWait,
    hash_prev: Option<usize>,
    hash_next: Option<usize>,
    list_prev: Option<usize>,
    list_next: Option<usize>,
    wake_prev: Option<usize>,
    wake_next: Option<usize>,
}

enum MsgWaitSlot {
    Free,
    Occupied(MsgWaitNode),
}

#[derive(Clone)]
struct MsgWaitHandle {
    slot: usize,
    task: u64,
    queue: MsgQueueRef,
}

// The executor admits at most 1024 simultaneous user tasks. Two slots per
// admitted task keep allocation-free slot acquisition at or below 50%
// occupancy even when every task is blocked in SysV message IPC. Stable
// bucket chains make lookup proportional to live hash collisions rather than
// accumulating tombstones over the kernel's lifetime.
const MSG_WAIT_SLOT_COUNT: usize = narf_scheduler::MAX_USER_TASKS * 2;
const MSG_WAIT_BUCKET_COUNT: usize = 256;
static MSG_WAIT_SLOTS: [IrqSafeSpinLock<MsgWaitSlot>; MSG_WAIT_SLOT_COUNT] =
    [const { IrqSafeSpinLock::new(MsgWaitSlot::Free) }; MSG_WAIT_SLOT_COUNT];
static MSG_WAIT_BUCKETS: [IrqSafeSpinLock<Option<usize>>; MSG_WAIT_BUCKET_COUNT] =
    [const { IrqSafeSpinLock::new(None) }; MSG_WAIT_BUCKET_COUNT];

#[inline]
fn msg_wait_hash(task: u64) -> usize {
    debug_assert!(MSG_WAIT_BUCKET_COUNT.is_power_of_two());
    (task as usize).wrapping_mul(0x9e37_79b9_7f4a_7c15usize) & (MSG_WAIT_BUCKET_COUNT - 1)
}

#[inline]
fn msg_wait_slot_candidate(task: u64, probe: usize) -> usize {
    debug_assert!(MSG_WAIT_SLOT_COUNT.is_power_of_two());
    (task as usize)
        .wrapping_mul(0x9e37_79b9_7f4a_7c15usize)
        .wrapping_add(probe)
        & (MSG_WAIT_SLOT_COUNT - 1)
}

fn msg_wait_handle(task: u64) -> Option<MsgWaitHandle> {
    let bucket = MSG_WAIT_BUCKETS[msg_wait_hash(task)].lock();
    let mut current = *bucket;
    while let Some(index) = current {
        let slot = MSG_WAIT_SLOTS[index].lock();
        match &*slot {
            MsgWaitSlot::Occupied(node) if node.task == task => {
                return Some(MsgWaitHandle {
                    slot: index,
                    task,
                    queue: Arc::clone(&node.queue),
                });
            }
            MsgWaitSlot::Occupied(node) => current = node.hash_next,
            MsgWaitSlot::Free => panic!("free SysV message wait linked from hash bucket"),
        }
    }
    None
}

fn wait_list_ends(queue: &MsgQueue, kind: WaitKind) -> (Option<usize>, Option<usize>) {
    match kind {
        WaitKind::MsgSend => (queue.send_wait_head, queue.send_wait_tail),
        WaitKind::MsgRecv => (queue.recv_wait_head, queue.recv_wait_tail),
        WaitKind::Sem => panic!("semaphore wait linked into message queue"),
    }
}

fn set_wait_list_head(queue: &mut MsgQueue, kind: WaitKind, head: Option<usize>) {
    match kind {
        WaitKind::MsgSend => queue.send_wait_head = head,
        WaitKind::MsgRecv => queue.recv_wait_head = head,
        WaitKind::Sem => panic!("semaphore wait linked into message queue"),
    }
}

fn set_wait_list_tail(queue: &mut MsgQueue, kind: WaitKind, tail: Option<usize>) {
    match kind {
        WaitKind::MsgSend => queue.send_wait_tail = tail,
        WaitKind::MsgRecv => queue.recv_wait_tail = tail,
        WaitKind::Sem => panic!("semaphore wait linked into message queue"),
    }
}

fn link_msg_wait(queue: &mut MsgQueue, index: usize, kind: WaitKind) {
    let (_, tail) = wait_list_ends(queue, kind);
    {
        let mut slot = MSG_WAIT_SLOTS[index].lock();
        let MsgWaitSlot::Occupied(node) = &mut *slot else {
            panic!("new SysV message wait slot disappeared");
        };
        node.list_prev = tail;
        node.list_next = None;
    }
    if let Some(tail) = tail {
        let mut slot = MSG_WAIT_SLOTS[tail].lock();
        let MsgWaitSlot::Occupied(node) = &mut *slot else {
            panic!("SysV message wait-list tail disappeared");
        };
        node.list_next = Some(index);
    } else {
        set_wait_list_head(queue, kind, Some(index));
    }
    set_wait_list_tail(queue, kind, Some(index));
}

fn insert_msg_wait(
    queue_ref: &MsgQueueRef,
    queue: &mut MsgQueue,
    task: u64,
    wait: IpcWait,
) -> MsgWaitHandle {
    assert!(
        msg_wait_handle(task).is_none(),
        "task linked to two SysV message waits"
    );
    let kind = wait.kind;
    let mut node = Some(MsgWaitNode {
        task,
        queue: Arc::clone(queue_ref),
        wait,
        hash_prev: None,
        hash_next: None,
        list_prev: None,
        list_next: None,
        wake_prev: None,
        wake_next: None,
    });

    for probe in 0..MSG_WAIT_SLOT_COUNT {
        let index = msg_wait_slot_candidate(task, probe);
        let mut slot = MSG_WAIT_SLOTS[index].lock();
        if matches!(*slot, MsgWaitSlot::Free) {
            *slot = MsgWaitSlot::Occupied(node.take().expect("SysV message wait inserted twice"));
            drop(slot);

            let mut bucket = MSG_WAIT_BUCKETS[msg_wait_hash(task)].lock();
            let old_head = *bucket;
            {
                let mut slot = MSG_WAIT_SLOTS[index].lock();
                let MsgWaitSlot::Occupied(node) = &mut *slot else {
                    panic!("new SysV message wait slot disappeared");
                };
                node.hash_next = old_head;
            }
            if let Some(old_head) = old_head {
                let mut slot = MSG_WAIT_SLOTS[old_head].lock();
                let MsgWaitSlot::Occupied(node) = &mut *slot else {
                    panic!("SysV message wait hash head disappeared");
                };
                node.hash_prev = Some(index);
            }
            *bucket = Some(index);
            drop(bucket);

            link_msg_wait(queue, index, kind);
            return MsgWaitHandle {
                slot: index,
                task,
                queue: Arc::clone(queue_ref),
            };
        }
    }
    panic!("SysV message wait pool exceeds scheduler task admission limit");
}

fn queue_msg_wake(queue: &mut MsgQueue, index: usize) {
    let tail = queue.wake_tail;
    {
        let mut slot = MSG_WAIT_SLOTS[index].lock();
        let MsgWaitSlot::Occupied(node) = &mut *slot else {
            panic!("ready SysV message wait disappeared");
        };
        if node.wake_prev.is_some() || node.wake_next.is_some() || queue.wake_head == Some(index) {
            return;
        }
        node.wake_prev = tail;
        node.wake_next = None;
    }
    if let Some(tail) = tail {
        let mut slot = MSG_WAIT_SLOTS[tail].lock();
        let MsgWaitSlot::Occupied(node) = &mut *slot else {
            panic!("SysV message wake-list tail disappeared");
        };
        node.wake_next = Some(index);
    } else {
        queue.wake_head = Some(index);
    }
    queue.wake_tail = Some(index);
}

fn unlink_msg_wake(queue: &mut MsgQueue, index: usize, prev: Option<usize>, next: Option<usize>) {
    if queue.wake_head != Some(index) && prev.is_none() && next.is_none() {
        return;
    }
    if let Some(prev) = prev {
        let mut slot = MSG_WAIT_SLOTS[prev].lock();
        let MsgWaitSlot::Occupied(node) = &mut *slot else {
            panic!("SysV message wake predecessor disappeared");
        };
        node.wake_next = next;
    } else {
        queue.wake_head = next;
    }
    if let Some(next) = next {
        let mut slot = MSG_WAIT_SLOTS[next].lock();
        let MsgWaitSlot::Occupied(node) = &mut *slot else {
            panic!("SysV message wake successor disappeared");
        };
        node.wake_prev = prev;
    } else {
        queue.wake_tail = prev;
    }
}

fn remove_msg_wait(queue: &mut MsgQueue, handle: &MsgWaitHandle) -> Option<MsgWaitNode> {
    let (kind, hash_prev, hash_next, list_prev, list_next, wake_prev, wake_next) = {
        let slot = MSG_WAIT_SLOTS[handle.slot].lock();
        let MsgWaitSlot::Occupied(node) = &*slot else {
            return None;
        };
        if node.task != handle.task || !Arc::ptr_eq(&node.queue, &handle.queue) {
            return None;
        }
        (
            node.wait.kind,
            node.hash_prev,
            node.hash_next,
            node.list_prev,
            node.list_next,
            node.wake_prev,
            node.wake_next,
        )
    };

    if let Some(prev) = list_prev {
        let mut slot = MSG_WAIT_SLOTS[prev].lock();
        let MsgWaitSlot::Occupied(node) = &mut *slot else {
            panic!("SysV message wait predecessor disappeared");
        };
        node.list_next = list_next;
    } else {
        set_wait_list_head(queue, kind, list_next);
    }
    if let Some(next) = list_next {
        let mut slot = MSG_WAIT_SLOTS[next].lock();
        let MsgWaitSlot::Occupied(node) = &mut *slot else {
            panic!("SysV message wait successor disappeared");
        };
        node.list_prev = list_prev;
    } else {
        set_wait_list_tail(queue, kind, list_prev);
    }
    unlink_msg_wake(queue, handle.slot, wake_prev, wake_next);

    let mut bucket = MSG_WAIT_BUCKETS[msg_wait_hash(handle.task)].lock();
    if let Some(prev) = hash_prev {
        let mut slot = MSG_WAIT_SLOTS[prev].lock();
        let MsgWaitSlot::Occupied(node) = &mut *slot else {
            panic!("SysV message wait hash predecessor disappeared");
        };
        node.hash_next = hash_next;
    } else {
        assert_eq!(
            *bucket,
            Some(handle.slot),
            "SysV message wait hash head diverged"
        );
        *bucket = hash_next;
    }
    if let Some(next) = hash_next {
        let mut slot = MSG_WAIT_SLOTS[next].lock();
        let MsgWaitSlot::Occupied(node) = &mut *slot else {
            panic!("SysV message wait hash successor disappeared");
        };
        node.hash_prev = hash_prev;
    }
    let mut slot = MSG_WAIT_SLOTS[handle.slot].lock();
    let old = core::mem::replace(&mut *slot, MsgWaitSlot::Free);
    let MsgWaitSlot::Occupied(node) = old else {
        panic!("SysV message wait disappeared during unlink");
    };
    drop(slot);
    drop(bucket);
    Some(node)
}

fn msg_wait_matches(wait: &IpcWait, kind: WaitKind, ipc_ns: u64, id: u64) -> bool {
    wait.kind == kind && wait.ipc_ns == ipc_ns && wait.id == id
}

fn begin_wait(task: u64, kind: WaitKind, ipc_ns: u64, id: u64) {
    let Some(queue) = lookup_msg_queue((ipc_ns, id)) else {
        return;
    };
    {
        let mut q = queue.lock();
        if msg_wait_handle(task).is_none() {
            insert_msg_wait(
                &queue,
                &mut q,
                task,
                IpcWait {
                    kind,
                    ipc_ns,
                    id,
                    errno: 0,
                    ready: false,
                    waker: None,
                    data: WaitData::None,
                },
            );
        }
    }
}

fn begin_msg_send_wait(task: u64, ipc_ns: u64, id: u64, mtype: i64, payload: Vec<u8>, msgflg: u64) {
    let Some(queue) = lookup_msg_queue((ipc_ns, id)) else {
        return;
    };
    {
        let mut q = queue.lock();
        if msg_wait_handle(task).is_none() {
            insert_msg_wait(
                &queue,
                &mut q,
                task,
                IpcWait {
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
                },
            );
        }
    }
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
    let Some(handle) = msg_wait_handle(task) else {
        return MsgSendResume::Fresh;
    };
    let mut q = handle.queue.lock();
    let (resume, remove) = {
        let mut slot = MSG_WAIT_SLOTS[handle.slot].lock();
        let MsgWaitSlot::Occupied(node) = &mut *slot else {
            return MsgSendResume::Fresh;
        };
        if node.task != task || !Arc::ptr_eq(&node.queue, &handle.queue) {
            return MsgSendResume::Fresh;
        }
        let wait = &mut node.wait;
        if !msg_wait_matches(wait, WaitKind::MsgSend, ipc_ns, id) {
            (MsgSendResume::Fresh, true)
        } else if wait.errno != 0 {
            (MsgSendResume::Error(wait.errno), true)
        } else {
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
                false,
            )
        }
    };
    let removed = remove.then(|| remove_msg_wait(&mut q, &handle)).flatten();
    drop(q);
    // A stale or terminal wait can own a waker/payload whose drop reaches
    // scheduler or allocator state; release it after restoring IRQ state.
    drop(removed);
    resume
}

#[allow(clippy::too_many_arguments)] // One complete retained msgsnd operation.
fn restore_msg_send_wait(
    queue_ref: &MsgQueueRef,
    queue: &mut MsgQueue,
    task: u64,
    ipc_ns: u64,
    id: u64,
    mtype: i64,
    payload: Vec<u8>,
    msgflg: u64,
) {
    if let Some(handle) = msg_wait_handle(task) {
        assert!(
            Arc::ptr_eq(&handle.queue, queue_ref),
            "staged SysV sender changed queues while rechecking"
        );
        let mut slot = MSG_WAIT_SLOTS[handle.slot].lock();
        let MsgWaitSlot::Occupied(node) = &mut *slot else {
            panic!("staged SysV sender wait disappeared");
        };
        assert_eq!(node.task, task, "staged SysV sender slot was reused");
        let wait = &mut node.wait;
        assert!(
            msg_wait_matches(wait, WaitKind::MsgSend, ipc_ns, id) && wait.errno == 0,
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
    } else {
        insert_msg_wait(
            queue_ref,
            queue,
            task,
            IpcWait {
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
            },
        );
    }
}

fn restore_msg_recv_wait(
    queue_ref: &MsgQueueRef,
    queue: &mut MsgQueue,
    task: u64,
    ipc_ns: u64,
    id: u64,
) {
    if let Some(handle) = msg_wait_handle(task) {
        assert!(
            Arc::ptr_eq(&handle.queue, queue_ref),
            "blocked SysV receiver changed queues while rechecking"
        );
        let mut slot = MSG_WAIT_SLOTS[handle.slot].lock();
        let MsgWaitSlot::Occupied(node) = &mut *slot else {
            panic!("blocked SysV receiver wait disappeared");
        };
        assert_eq!(node.task, task, "blocked SysV receiver slot was reused");
        assert!(
            msg_wait_matches(&node.wait, WaitKind::MsgRecv, ipc_ns, id) && node.wait.errno == 0,
            "blocked SysV receiver changed while rechecking"
        );
        node.wait.ready = false;
    } else {
        insert_msg_wait(
            queue_ref,
            queue,
            task,
            IpcWait {
                kind: WaitKind::MsgRecv,
                ipc_ns,
                id,
                errno: 0,
                ready: false,
                waker: None,
                data: WaitData::None,
            },
        );
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
    let Some(handle) = msg_wait_handle(task) else {
        return MsgParkState::NotWaiting;
    };
    let mut incoming = Some(waker);
    let q = handle.queue.lock();
    let (state, replaced) =
        {
            let mut slot = MSG_WAIT_SLOTS[handle.slot].lock();
            match &mut *slot {
                MsgWaitSlot::Occupied(node)
                    if node.task == task && Arc::ptr_eq(&node.queue, &handle.queue) =>
                {
                    let wait = &mut node.wait;
                    if wait.errno != 0 || wait.ready {
                        (MsgParkState::Ready, None)
                    } else if wait.waker.as_ref().is_some_and(|old| {
                        old.will_wake(incoming.as_ref().expect("incoming waker"))
                    }) {
                        (MsgParkState::Pending, None)
                    } else {
                        (
                            MsgParkState::Pending,
                            core::mem::replace(&mut wait.waker, incoming.take()),
                        )
                    }
                }
                MsgWaitSlot::Free | MsgWaitSlot::Occupied(_) => (MsgParkState::NotWaiting, None),
            }
        };
    drop(q);
    // Waker drops may release the final scheduler Arc; never do so under the
    // IRQ-safe per-queue lock.
    drop(replaced);
    drop(incoming);
    state
}

fn notify_msg_waiters(queue: &mut MsgQueue, kind: WaitKind) {
    let (mut current, _) = wait_list_ends(queue, kind);
    while let Some(index) = current {
        let (next, should_queue) = {
            let mut slot = MSG_WAIT_SLOTS[index].lock();
            let MsgWaitSlot::Occupied(node) = &mut *slot else {
                panic!("SysV message wait disappeared during notification");
            };
            let next = node.list_next;
            let condition_changed = match kind {
                WaitKind::MsgRecv => true,
                WaitKind::MsgSend => {
                    let WaitData::MsgSend { payload, .. } = &node.wait.data else {
                        panic!("SysV sender wait lost its payload state");
                    };
                    let payload_len = payload
                        .as_ref()
                        .expect("linked SysV sender payload is being rechecked")
                        .len();
                    payload_len.saturating_add(queue.current_bytes) <= queue.max_bytes
                        && queue.msgs.len().saturating_add(1) <= queue.max_bytes
                }
                WaitKind::Sem => panic!("semaphore wait notified through message queue"),
            };
            if node.wait.errno == 0 && condition_changed {
                node.wait.ready = true;
            }
            let queued = node.wake_prev.is_some()
                || node.wake_next.is_some()
                || queue.wake_head == Some(index);
            (
                next,
                node.wait.ready && node.wait.waker.is_some() && !queued,
            )
        };
        if should_queue {
            queue_msg_wake(queue, index);
        }
        current = next;
    }
}

fn retire_msg_waiters(queue: &mut MsgQueue) {
    for kind in [WaitKind::MsgSend, WaitKind::MsgRecv] {
        let (mut current, _) = wait_list_ends(queue, kind);
        while let Some(index) = current {
            let (next, should_queue) = {
                let mut slot = MSG_WAIT_SLOTS[index].lock();
                let MsgWaitSlot::Occupied(node) = &mut *slot else {
                    panic!("SysV message wait disappeared during queue removal");
                };
                let next = node.list_next;
                node.wait.errno = EIDRM;
                let queued = node.wake_prev.is_some()
                    || node.wake_next.is_some()
                    || queue.wake_head == Some(index);
                (next, node.wait.waker.is_some() && !queued)
            };
            if should_queue {
                queue_msg_wake(queue, index);
            }
            current = next;
        }
    }
}

/// Error observed when a blocked message operation loses the queue lookup
/// race against IPC_RMID.  The queue and terminal wait record live under the
/// same lock, so checking both in one transaction preserves EIDRM even when
/// removal occurs after the syscall's initial fast-path error check.
fn missing_msg_queue_errno(task: u64, kind: WaitKind, object: IpcObjectKey) -> i64 {
    let Some(handle) = msg_wait_handle(task) else {
        return EINVAL;
    };
    let _q = handle.queue.lock();
    let slot = MSG_WAIT_SLOTS[handle.slot].lock();
    let MsgWaitSlot::Occupied(node) = &*slot else {
        return EINVAL;
    };
    if node.task == task
        && Arc::ptr_eq(&node.queue, &handle.queue)
        && msg_wait_matches(&node.wait, kind, object.0, object.1)
        && node.wait.errno != 0
    {
        node.wait.errno
    } else {
        EINVAL
    }
}

/// Fire all message wakers whose condition changed. Taking one waker per lock
/// acquisition keeps wake/drop paths outside the IRQ-disabled critical section
/// without allocating a temporary wake vector or rescanning unrelated waits.
fn drain_msg_wakes(queue: &MsgQueueRef) {
    loop {
        let waker = {
            let mut q = queue.lock();
            let Some(index) = q.wake_head else {
                break;
            };
            let (next, waker) = {
                let mut slot = MSG_WAIT_SLOTS[index].lock();
                let MsgWaitSlot::Occupied(node) = &mut *slot else {
                    panic!("queued SysV message waker disappeared");
                };
                let next = node.wake_next;
                node.wake_prev = None;
                node.wake_next = None;
                (
                    next,
                    node.wait
                        .waker
                        .take()
                        .expect("queued SysV message wait lost its waker"),
                )
            };
            q.wake_head = next;
            if let Some(next) = next {
                let mut slot = MSG_WAIT_SLOTS[next].lock();
                let MsgWaitSlot::Occupied(node) = &mut *slot else {
                    panic!("SysV message wake successor disappeared");
                };
                node.wake_prev = None;
            } else {
                q.wake_tail = None;
            }
            waker
        };
        waker.wake();
    }
}

fn clear_wait(task: u64, kind: WaitKind, ipc_ns: u64, id: u64) {
    let Some(handle) = msg_wait_handle(task) else {
        return;
    };
    let mut q = handle.queue.lock();
    let matches = {
        let slot = MSG_WAIT_SLOTS[handle.slot].lock();
        matches!(&*slot, MsgWaitSlot::Occupied(node) if node.task == task
            && Arc::ptr_eq(&node.queue, &handle.queue)
            && msg_wait_matches(&node.wait, kind, ipc_ns, id))
    };
    let removed = matches.then(|| remove_msg_wait(&mut q, &handle)).flatten();
    drop(q);
    drop(removed);
}

fn take_wait_error(task: u64, kind: WaitKind, ipc_ns: u64, id: u64) -> Option<i64> {
    let handle = msg_wait_handle(task)?;
    let mut q = handle.queue.lock();
    let (errno, remove) = {
        let slot = MSG_WAIT_SLOTS[handle.slot].lock();
        let MsgWaitSlot::Occupied(node) = &*slot else {
            return None;
        };
        if node.task != task || !Arc::ptr_eq(&node.queue, &handle.queue) {
            return None;
        }
        if msg_wait_matches(&node.wait, kind, ipc_ns, id) && node.wait.errno != 0 {
            (Some(node.wait.errno), true)
        } else if !msg_wait_matches(&node.wait, kind, ipc_ns, id) {
            (None, true)
        } else {
            (None, false)
        }
    };
    let removed = remove.then(|| remove_msg_wait(&mut q, &handle)).flatten();
    drop(q);
    drop(removed);
    errno
}

/// Retire an interrupted message wait in the same transaction that observes
/// its terminal RMID status.  Linux tests a deleted queue before a pending
/// signal after wakeup; whichever state mutation acquires this lock first is
/// therefore the observable winner (`EIDRM` or `EINTR`).
fn finish_interrupted_msg_wait(task: u64, kind: WaitKind, ipc_ns: u64, id: u64) -> Option<i64> {
    let handle = msg_wait_handle(task)?;
    let mut q = handle.queue.lock();
    let result = {
        let slot = MSG_WAIT_SLOTS[handle.slot].lock();
        let MsgWaitSlot::Occupied(node) = &*slot else {
            return None;
        };
        if node.task != task
            || !Arc::ptr_eq(&node.queue, &handle.queue)
            || !msg_wait_matches(&node.wait, kind, ipc_ns, id)
        {
            return None;
        }
        if node.wait.errno != 0 {
            node.wait.errno
        } else {
            EINTR
        }
    };
    let removed = remove_msg_wait(&mut q, &handle);
    drop(q);
    drop(removed);
    Some(result)
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
                        set: None,
                        ipc_ns,
                        id,
                        sops: Vec::new(),
                        nsops: 0,
                        timeout: None,
                        blocking: None,
                        pid: task,
                        undo_owner: None,
                        result: None,
                        pending_prev: None,
                        pending_next: None,
                        waker: None,
                        wake_prev: None,
                        wake_next: None,
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
    let ipc_ns = current_ipc_namespace_id();
    let set_ref = lookup_sem_set((ipc_ns, id));
    with_sem_state(|state| {
        if state.waits.try_reserve(1).is_ok() {
            let index = sem_wait_index(&state.waits, task).unwrap_or_else(|index| index);
            state.waits.insert(
                index,
                SemWait {
                    task,
                    set: set_ref,
                    ipc_ns,
                    id,
                    sops: sops.to_vec(),
                    nsops: sops.len() / 6,
                    timeout: None,
                    blocking: None,
                    pid: task,
                    undo_owner: None,
                    result: None,
                    pending_prev: None,
                    pending_next: None,
                    waker: None,
                    wake_prev: None,
                    wake_next: None,
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
    let Some(handle) = msg_wait_handle(task) else {
        return false;
    };
    {
        let mut q = handle.queue.lock();
        restore_msg_send_wait(
            &handle.queue,
            &mut q,
            task,
            ipc_ns,
            id,
            mtype,
            payload,
            msgflg,
        );
    }
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
    if let Some(handle) = msg_wait_handle(tid) {
        let mut q = handle.queue.lock();
        let removed = remove_msg_wait(&mut q, &handle);
        drop(q);
        drop(removed);
    }
    drop(unlink_sem_wait(tid));
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
    let mut after = None;
    loop {
        let next = with_sem_state(|state| match after {
            Some(object) => state
                .sets
                .range((
                    core::ops::Bound::Excluded(object),
                    core::ops::Bound::Unbounded,
                ))
                .next()
                .map(|(&object, set)| (object, Arc::clone(set))),
            None => state
                .sets
                .iter()
                .next()
                .map(|(&object, set)| (object, Arc::clone(set))),
        });
        let Some((object, set_ref)) = next else {
            break;
        };
        after = Some(object);
        let mut set = set_ref.lock();
        if set.removed {
            continue;
        }
        let mut changed = false;
        let SemSet {
            undos, sems, pids, ..
        } = &mut *set;
        // Linux owns one semadj vector per process and semaphore array, then
        // applies the whole vector under the array lock at final process exit.
        // Remove this owner's entries in one pass so cleanup is O(n), while
        // retaining every other process's undo vector unchanged.
        undos.retain(|((owner, _, _, semnum), adjustment)| {
            if *owner != undo_owner {
                return true;
            }
            if *adjustment != 0 {
                if let Some(sem) = sems.get_mut(*semnum) {
                    *sem = sem.saturating_add(*adjustment).clamp(0, SEMVMX);
                    pids[*semnum] = pid;
                    changed = true;
                }
            }
            false
        });
        if changed && set.pending_head.is_some() {
            with_sem_state(|state| scan_sem_waiters(&mut set, state, object));
        }
    }
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
            let index = sem_undo_index(&set.undos, (owner, ipc_ns, semid, num))
                .expect("SEM_UNDO key preallocated");
            let next_undo = set.undos[index].1 - i32::from(op);
            if !((-SEMVMX - 1)..=SEMVMX).contains(&next_undo) {
                fail = Some((ERANGE, true, None));
                break;
            }
            set.undos[index].1 = next_undo;
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
                    let index = sem_undo_index(&set.undos, (owner, ipc_ns, semid, num))
                        .expect("SEM_UNDO key preallocated");
                    set.undos[index].1 += i32::from(op);
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

#[allow(clippy::too_many_arguments)]
fn perform_semop_locked(
    set: &mut SemSet,
    object: IpcObjectKey,
    sops: &[u8],
    nsops: usize,
    pid: u64,
    undo_owner: Option<u64>,
    caller_uid: u32,
    caller_gid: u32,
    caller_groups: &[u32],
) -> Result<(), SemOpFailure> {
    let needs_write = (0..nsops).any(|i| parse_sem_op(sops, i).1 != 0);
    let request = if needs_write { 0o2 } else { 0o4 };
    // Linux reports EFBIG for an imported sem_num outside this set, and
    // performs this check before ipcperms.
    for i in 0..nsops {
        let (num, _, _) = parse_sem_op(sops, i);
        if num >= set.sems.len() {
            return Err((EFBIG, true, None));
        }
    }
    if !ipc_allowed(
        caller_uid,
        caller_gid,
        caller_groups,
        set.uid,
        set.gid,
        set.cuid,
        set.cgid,
        set.mode,
        request,
    ) {
        return Err((EACCES, true, None));
    }
    let result = perform_sem_ops(set, object.0, object.1, sops, nsops, pid, undo_owner);
    if result.is_ok() && set.pending_head.is_some() {
        with_sem_state(|state| scan_sem_waiters(set, state, object));
    }
    result
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
            let task = state.wake_head?;
            let index = sem_wait_index(&state.waits, task)
                .expect("queued SysV semaphore waker disappeared");
            unlink_sem_wake(state, index);
            Some(
                state.waits[index]
                    .waker
                    .take()
                    .expect("queued SysV semaphore wait lost its waker"),
            )
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
fn scan_sem_waiters(set: &mut SemSet, state: &mut SemState, object: IpcObjectKey) {
    loop {
        let pass_tail = set.pending_tail;
        let mut altered = false;
        loop {
            let Some(task) = set.pending_head else {
                break;
            };
            let wait_index = sem_wait_index(&state.waits, task)
                .expect("SysV semaphore pending waiter disappeared");
            let last_in_pass = pass_tail == Some(task);
            assert!(unlink_sem_pending(set, state, wait_index));
            let wait = &state.waits[wait_index];
            if wait.result.is_some() {
                if last_in_pass {
                    break;
                }
                continue;
            }
            let nsops = wait.nsops;
            let pid = wait.pid;
            let undo_owner = wait.undo_owner;
            let old_blocker = wait.blocking;
            let changes_value = (0..nsops).any(|i| parse_sem_op(&wait.sops, i).1 != 0);
            let result =
                perform_sem_ops(set, object.0, object.1, &wait.sops, nsops, pid, undo_owner);
            match result {
                Ok(()) => {
                    if let Some(blocker) = old_blocker {
                        adjust_wait_count(set, blocker, false);
                    }
                    if let Ok(index) = sem_wait_index(&state.waits, task) {
                        state.waits[index].result = Some(0);
                        queue_sem_wake(state, index);
                    }
                    altered |= changes_value;
                }
                Err((errno, true, _)) => {
                    if let Some(blocker) = old_blocker {
                        adjust_wait_count(set, blocker, false);
                    }
                    if let Ok(index) = sem_wait_index(&state.waits, task) {
                        state.waits[index].result = Some(errno);
                        queue_sem_wake(state, index);
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
                        if let Ok(index) = sem_wait_index(&state.waits, task) {
                            state.waits[index].blocking = blocker;
                        }
                    }
                    let index = sem_wait_index(&state.waits, task)
                        .expect("SysV semaphore pending waiter disappeared during retry");
                    queue_sem_pending(set, state, index);
                }
                Err((errno, _, _)) => {
                    if let Some(blocker) = old_blocker {
                        adjust_wait_count(set, blocker, false);
                    }
                    if let Ok(index) = sem_wait_index(&state.waits, task) {
                        state.waits[index].result = Some(errno);
                        queue_sem_wake(state, index);
                    }
                }
            }
            if last_in_pass {
                break;
            }
        }
        if !altered {
            break;
        }
    }
}

fn unlink_sem_wait(task: u64) -> Option<SemWait> {
    let set_ref = with_sem_state(|state| {
        sem_wait_index(&state.waits, task)
            .ok()
            .and_then(|index| state.waits[index].set.as_ref().map(Arc::clone))
    });
    let Some(set_ref) = set_ref else {
        return with_sem_state(|state| {
            let index = sem_wait_index(&state.waits, task).ok()?;
            unlink_sem_wake(state, index);
            Some(state.waits.remove(index))
        });
    };
    let mut set = set_ref.lock();
    let wait = with_sem_state(|state| {
        let index = sem_wait_index(&state.waits, task).ok()?;
        unlink_sem_pending(&mut set, state, index);
        unlink_sem_wake(state, index);
        Some(state.waits.remove(index))
    })?;
    if wait.result.is_some() {
        return Some(wait);
    }
    if let Some(blocker) = wait.blocking {
        adjust_wait_count(&mut set, blocker, false);
    }
    Some(wait)
}

fn finish_pending_sem_wait(task: u64, errno: i64) -> i64 {
    let set_ref = with_sem_state(|state| {
        sem_wait_index(&state.waits, task)
            .ok()
            .and_then(|index| state.waits[index].set.as_ref().map(Arc::clone))
    });
    let Some(set_ref) = set_ref else {
        let (result, waker) = with_sem_state(|state| {
            let Ok(index) = sem_wait_index(&state.waits, task) else {
                return (errno, None);
            };
            unlink_sem_wake(state, index);
            let wait = &mut state.waits[index];
            let result = wait.result.unwrap_or(errno);
            wait.result = Some(result);
            (result, wait.waker.take())
        });
        if let Some(waker) = waker {
            waker.wake();
        }
        return result;
    };
    let mut set = set_ref.lock();
    let (result, waker) = with_sem_state(|state| {
        let Ok(index) = sem_wait_index(&state.waits, task) else {
            return (errno, None);
        };
        if let Some(result) = state.waits[index].result {
            return (result, None);
        }
        unlink_sem_pending(&mut set, state, index);
        if let Some(blocker) = state.waits[index].blocking {
            adjust_wait_count(&mut set, blocker, false);
        }
        let wait = &mut state.waits[index];
        wait.result = Some(errno);
        let waker = wait.waker.take();
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
        unlink_sem_wake(state, index);
        Some((result, state.waits.remove(index)))
    })?;
    // SemWait owns a retained operation and possibly the final task-waker Arc.
    // Drop both only after the IRQ-safe waiter-registry lock is released.
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
    let id = loop {
        if key as u64 != IPC_PRIVATE {
            let existing = with_sem_state(|state| {
                state.key_ids.get(&(ipc_ns, key)).map(|&id| {
                    let set = state
                        .sets
                        .get(&(ipc_ns, id))
                        .expect("indexed SysV semaphore set missing");
                    (id, Arc::clone(set))
                })
            });
            if let Some((id, set_ref)) = existing {
                let set = set_ref.lock();
                if set.removed {
                    continue;
                }
                if flg & IPC_CREAT != 0 && flg & IPC_EXCL != 0 {
                    break Err(EEXIST);
                }
                if nsems > set.sems.len() {
                    break Err(EINVAL);
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
                    break Err(EACCES);
                }
                break Ok(id);
            }
            if flg & IPC_CREAT == 0 {
                break Err(ENOENT);
            }
        }
        if nsems == 0 {
            break Err(EINVAL);
        }
        let created = with_sem_state(|state| {
            // Another creator may have published this key while we inspected
            // the old object. Retry so its permissions and size are checked.
            if key as u64 != IPC_PRIVATE && state.key_ids.contains_key(&(ipc_ns, key)) {
                return Ok(None);
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
            let set = Arc::try_new(IrqSafeSpinLock::new(SemSet {
                removed: false,
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
                pending_head: None,
                pending_tail: None,
                ncnt,
                zcnt,
                undos: Vec::new(),
            }))
            .map_err(|_| ENOMEM)?;
            let id = state.ids.entry(ipc_ns).or_default().allocate(semmni())?;
            state.sets.insert((ipc_ns, id), set);
            if key as u64 != IPC_PRIVATE {
                assert!(
                    state.key_ids.insert((ipc_ns, key), id).is_none(),
                    "duplicate SysV semaphore key index"
                );
            }
            let usage = state.usage.entry(ipc_ns).or_default();
            usage.set_count += 1;
            usage.sem_count += nsems;
            Ok(Some(id))
        });
        match created {
            Ok(Some(id)) => break Ok(id),
            Ok(None) => continue,
            Err(errno) => break Err(errno),
        }
    };
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
            drop(unlink_sem_wait(task));
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
        drop(unlink_sem_wait(task));
        ctx.set_return(err(E2BIG));
        return;
    }
    if nsops == 0 {
        finish_semtimedop_wait(timed);
        drop(unlink_sem_wait(task));
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
            drop(unlink_sem_wait(task));
            ctx.set_return(err(EFAULT));
            return;
        }
    }
    // do_semtimedop imports the entire array before __do_semtimedop validates
    // the signed id.  The id check then precedes timespec field validation.
    if semid_raw < 0 {
        finish_semtimedop_wait(timed);
        drop(unlink_sem_wait(task));
        ctx.set_return(err(EINVAL));
        return;
    }
    // Linux validates the imported timeout in __do_semtimedop before looking
    // up the semaphore set.
    if let Some((sec, nsec)) = timeout {
        if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
            finish_semtimedop_wait(timed);
            drop(unlink_sem_wait(task));
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
    let set_ref = lookup_sem_set(object);
    let result = match set_ref.as_ref() {
        None => Err((EINVAL, true, None)),
        Some(set_ref) => {
            let mut set = set_ref.lock();
            if set.removed {
                Err((EIDRM, true, None))
            } else {
                // Linux find_alloc_undo() creates one dense per-set adjustment array
                // before EFBIG and permission validation.  Do the same, including for
                // a zero operation carrying SEM_UNDO, so ENOMEM has Linux precedence.
                if let Some(owner) = undo_owner {
                    if let Err(errno) = ensure_sem_undo_set(&mut set, object, owner) {
                        Err((errno, true, None))
                    } else {
                        perform_semop_locked(
                            &mut set,
                            object,
                            &buf[..nbytes],
                            nsops,
                            pid,
                            undo_owner,
                            caller_uid,
                            caller_gid,
                            &caller_groups,
                        )
                    }
                } else {
                    perform_semop_locked(
                        &mut set,
                        object,
                        &buf[..nbytes],
                        nsops,
                        pid,
                        undo_owner,
                        caller_uid,
                        caller_gid,
                        &caller_groups,
                    )
                }
            }
        }
    };
    drain_sem_wakes();
    match result {
        Ok(()) => {
            drop(unlink_sem_wait(task));
            finish_semtimedop_wait(timed);
            ctx.set_return(SyscallReturn::ok(0));
        }
        Err((e, true, _)) => {
            drop(unlink_sem_wait(task));
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
            let enqueue_result = if let Some(set_ref) = set_ref {
                let mut set = set_ref.lock();
                if set.removed {
                    Err(EIDRM)
                } else {
                    let retry =
                        perform_sem_ops(&mut set, ipc_ns, semid, &retained, nsops, pid, undo_owner);
                    let retry_result = (|| -> Result<Option<()>, i64> {
                        match retry {
                            Ok(()) => Ok(Some(())),
                            Err((errno, true, _)) => Err(errno),
                            Err((EAGAIN, false, retry_blocking)) => {
                                let blocker = retry_blocking.or(blocking);
                                with_sem_state(|state| {
                                    state.waits.try_reserve(1).map_err(|_| ENOMEM)?;
                                    if let Some(blocker) = blocker {
                                        adjust_wait_count(&mut set, blocker, true);
                                    }
                                    let wait_index = sem_wait_index(&state.waits, task)
                                        .unwrap_or_else(|index| index);
                                    state.waits.insert(
                                        wait_index,
                                        SemWait {
                                            task,
                                            set: Some(Arc::clone(&set_ref)),
                                            ipc_ns,
                                            id: semid,
                                            sops: retained,
                                            nsops,
                                            timeout,
                                            blocking: blocker,
                                            pid,
                                            undo_owner,
                                            result: None,
                                            pending_prev: None,
                                            pending_next: None,
                                            waker: None,
                                            wake_prev: None,
                                            wake_next: None,
                                        },
                                    );
                                    queue_sem_pending(&mut set, state, wait_index);
                                    Ok::<(), i64>(())
                                })?;
                                Ok(None)
                            }
                            Err((errno, _, _)) => Err(errno),
                        }
                    })();
                    if matches!(retry_result, Ok(Some(()))) && set.pending_head.is_some() {
                        with_sem_state(|state| scan_sem_waiters(&mut set, state, object));
                    }
                    retry_result
                }
            } else {
                Err(EIDRM)
            };
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
            drop(unlink_sem_wait(task));
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
            let removed = match lookup_sem_set(object) {
                None => Err(EINVAL),
                Some(set_ref) => {
                    let mut set = set_ref.lock();
                    if set.removed {
                        Err(EIDRM)
                    } else if !ipc_owner(caller_uid, set.uid, set.cuid) {
                        Err(EPERM)
                    } else {
                        with_sem_state(|state| {
                            let Some(current) = state.sets.get(&object) else {
                                return Err(EIDRM);
                            };
                            if !Arc::ptr_eq(current, &set_ref) {
                                return Err(EIDRM);
                            }
                            state.sets.remove(&object);
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
                            for index in 0..state.waits.len() {
                                let matches_set = {
                                    let wait = &state.waits[index];
                                    wait.ipc_ns == ipc_ns && wait.id == semid
                                };
                                if !matches_set {
                                    continue;
                                }
                                state.waits[index].pending_prev = None;
                                state.waits[index].pending_next = None;
                                if state.waits[index].result.is_none() {
                                    state.waits[index].result = Some(EIDRM);
                                    queue_sem_wake(state, index);
                                }
                            }
                            set.removed = true;
                            set.pending_head = None;
                            set.pending_tail = None;
                            set.ncnt.fill(0);
                            set.zcnt.fill(0);
                            set.undos.clear();
                            Ok(())
                        })
                    }
                }
            };
            match removed {
                Ok(()) => {
                    drain_sem_wakes();
                    ctx.set_return(SyscallReturn::ok(0));
                }
                Err(e) => ctx.set_return(err(e)),
            }
        }
        IPC_STAT | SEM_STAT | SEM_STAT_ANY => {
            let resolved = with_sem_state(|state| {
                let returned_id = if cmd == IPC_STAT {
                    semid
                } else {
                    state
                        .ids
                        .get(&ipc_ns)
                        .and_then(|ids| ids.full_id_at(semid))?
                };
                state
                    .sets
                    .get(&(ipc_ns, returned_id))
                    .map(|set| (returned_id, Arc::clone(set)))
            });
            let snapshot = resolved.ok_or(EINVAL).and_then(|(returned_id, set_ref)| {
                let set = set_ref.lock();
                if set.removed {
                    return Err(EIDRM);
                }
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
                Ok((returned_id, sem_stat_snapshot(&set)))
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
            let authorized = with_sem_set(object, |set| {
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
            let result = with_sem_set(object, |set| {
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
            let r = with_sem_set(object, |set| {
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
                for ((_, namespace, id, num), adjustment) in &mut set.undos {
                    if *namespace == ipc_ns && *id == semid && *num == semnum {
                        *adjustment = 0;
                    }
                }
                if set.pending_head.is_some() {
                    with_sem_state(|state| scan_sem_waiters(set, state, object));
                }
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
            let r = with_sem_set(object, |set| {
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
            let set_ref = match lookup_sem_set(object) {
                Some(set_ref) => set_ref,
                None => {
                    ctx.set_return(err(EINVAL));
                    return;
                }
            };
            let set_size = {
                let set = set_ref.lock();
                if set.removed {
                    Err(EIDRM)
                } else if !ipc_allowed(
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
                    Err(EACCES)
                } else {
                    Ok(set.sems.len())
                }
            };
            let n = match set_size {
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
            let r = {
                let mut set = set_ref.lock();
                if set.removed || set.sems.len() != values.len() {
                    Err(EIDRM)
                } else {
                    set.sems.copy_from_slice(&values);
                    set.pids.fill(pid);
                    set.ctime = now_seconds();
                    for ((_, namespace, id, _), adjustment) in &mut set.undos {
                        if *namespace == ipc_ns && *id == semid {
                            *adjustment = 0;
                        }
                    }
                    if set.pending_head.is_some() {
                        with_sem_state(|state| scan_sem_waiters(&mut set, state, object));
                    }
                    Ok(())
                }
            };
            ctx.set_return(match r {
                Ok(()) => {
                    drain_sem_wakes();
                    SyscallReturn::ok(0)
                }
                Err(e) => err(e),
            });
        }
        GETALL => {
            let r = with_sem_set(object, |set| {
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
    removed: bool,
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
    /// Blocked operations belong to the queue whose condition they observe.
    /// Keeping them under the same per-queue lock closes check-to-park and
    /// IPC_RMID races without serializing unrelated queues.
    send_wait_head: Option<usize>,
    send_wait_tail: Option<usize>,
    recv_wait_head: Option<usize>,
    recv_wait_tail: Option<usize>,
    wake_head: Option<usize>,
    wake_tail: Option<usize>,
    counters: Arc<MsgNamespaceCounters>,
}

type MsgQueueRef = Arc<IrqSafeSpinLock<MsgQueue>>;

struct QueuedMessage {
    mtype: i64,
    payload: Vec<u8>,
}

#[repr(align(64))]
struct MsgCounterCell {
    message_count: AtomicIsize,
    byte_count: AtomicIsize,
}

struct MsgNamespaceCounters {
    cells: [MsgCounterCell; narf_lib::percpu::MAX_CPUS],
}

impl MsgNamespaceCounters {
    fn new() -> Self {
        Self {
            cells: core::array::from_fn(|_| MsgCounterCell {
                message_count: AtomicIsize::new(0),
                byte_count: AtomicIsize::new(0),
            }),
        }
    }

    fn add_message(&self, bytes: usize) {
        let cpu = narf_lib::percpu::current_cpu();
        self.cells[cpu]
            .message_count
            .fetch_add(1, Ordering::Relaxed);
        self.cells[cpu]
            .byte_count
            .fetch_add(bytes as isize, Ordering::Relaxed);
    }

    fn remove_messages(&self, messages: usize, bytes: usize) {
        let cpu = narf_lib::percpu::current_cpu();
        self.cells[cpu]
            .message_count
            .fetch_sub(messages as isize, Ordering::Relaxed);
        self.cells[cpu]
            .byte_count
            .fetch_sub(bytes as isize, Ordering::Relaxed);
    }

    fn snapshot(&self) -> (usize, usize) {
        (
            self.cells
                .iter()
                .map(|cell| cell.message_count.load(Ordering::Relaxed))
                .sum::<isize>()
                .max(0) as usize,
            self.cells
                .iter()
                .map(|cell| cell.byte_count.load(Ordering::Relaxed))
                .sum::<isize>()
                .max(0) as usize,
        )
    }
}

struct MsgUsage {
    queue_count: usize,
    counters: Arc<MsgNamespaceCounters>,
}

#[derive(Default)]
struct MsgState {
    queues: BTreeMap<IpcObjectKey, MsgQueueRef>,
    ids: BTreeMap<u64, IpcIdTable>,
    /// Per-namespace key lookup; IPC_PRIVATE queues are intentionally absent.
    key_ids: BTreeMap<IpcLookupKey, u64>,
    /// Exact per-namespace limit/MSG_INFO counters.
    usage: BTreeMap<u64, MsgUsage>,
}

static MSG_STATE: IrqSafeSpinLock<Option<MsgState>> = IrqSafeSpinLock::new(None);
/// Task-to-queue index for the scheduler's waker registration path. Only
/// blocked operations touch this lock; successful queue traffic does not.
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

fn lookup_msg_queue(object: IpcObjectKey) -> Option<MsgQueueRef> {
    with_msg_state(|state| state.queues.get(&object).cloned())
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
            .map_or(0, |usage| usage.queue_count)
    })
}

/// Prove two registry entries own distinct, independently acquirable object
/// locks. Both references are resolved before either object lock is taken, so
/// the test follows the production registry-before-object lock hierarchy.
#[cfg(feature = "kernel-test")]
pub(crate) fn __test_msg_queues_lock_independently(first: u64, second: u64) -> Option<bool> {
    let ipc_ns = current_ipc_namespace_id();
    let (first, second) = with_msg_state(|state| {
        Some((
            state.queues.get(&(ipc_ns, first))?.clone(),
            state.queues.get(&(ipc_ns, second))?.clone(),
        ))
    })?;
    let _first_guard = first.lock();
    let independent = second.try_lock().is_some();
    Some(independent)
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
                let queue = state
                    .queues
                    .get(&(ipc_ns, id))
                    .expect("indexed SysV message queue missing");
                let q = queue.lock();
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
        if state
            .usage
            .get(&ipc_ns)
            .is_some_and(|usage| usage.queue_count >= msg_max_queues())
        {
            return Err(ENOSPC);
        }
        // Allocate the comparatively large per-CPU counter block and queue
        // object before reserving an ID or publishing any registry indexes.
        // Linux likewise allocates the queue before ipc_addid(); allocation
        // failure must return ENOMEM without leaving a half-created object.
        let counters = match state.usage.get(&ipc_ns) {
            Some(usage) => Arc::clone(&usage.counters),
            None => Arc::try_new(MsgNamespaceCounters::new()).map_err(|_| ENOMEM)?,
        };
        let queue = Arc::try_new(IrqSafeSpinLock::new(MsgQueue {
            removed: false,
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
            send_wait_head: None,
            send_wait_tail: None,
            recv_wait_head: None,
            recv_wait_tail: None,
            wake_head: None,
            wake_tail: None,
            counters: Arc::clone(&counters),
        }))
        .map_err(|_| ENOMEM)?;
        let id = state
            .ids
            .entry(ipc_ns)
            .or_default()
            .allocate(msg_max_queues())?;
        state.queues.insert((ipc_ns, id), queue);
        if key as u64 != IPC_PRIVATE {
            assert!(
                state.key_ids.insert((ipc_ns, key), id).is_none(),
                "duplicate SysV message key index"
            );
        }
        match state.usage.entry(ipc_ns) {
            alloc::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(MsgUsage {
                    queue_count: 1,
                    counters,
                });
            }
            alloc::collections::btree_map::Entry::Occupied(mut entry) => {
                entry.get_mut().queue_count += 1;
            }
        }
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
    let Some(queue) = lookup_msg_queue(object) else {
        ctx.set_return(err(missing_msg_queue_errno(
            task,
            WaitKind::MsgSend,
            object,
        )));
        return;
    };
    let r: Result<bool, i64> = {
        let mut q = queue.lock();
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
            Err(EACCES)
        } else if q.removed {
            // Linux checks ipcperms() before ipc_valid_object() after taking
            // the queue lock. Initial lookup failure remains EINVAL, while a
            // removal race after a successful lookup is EIDRM.
            Err(EIDRM)
        } else {
            let fits = msgsz.saturating_add(q.current_bytes) <= q.max_bytes
                && q.msgs.len().saturating_add(1) <= q.max_bytes;
            if !fits {
                if msgflg & IPC_NOWAIT as u64 == 0 {
                    restore_msg_send_wait(
                        &queue,
                        &mut q,
                        task,
                        ipc_ns,
                        msqid,
                        mtype,
                        pending_payload.take().expect("blocked SysV message"),
                        msgflg,
                    );
                }
                Ok(false)
            } else if q.msgs.try_reserve(1).is_err() {
                Err(ENOMEM)
            } else {
                q.msgs.push_back(QueuedMessage {
                    mtype,
                    payload: pending_payload.take().expect("pending SysV message"),
                });
                q.current_bytes += msgsz;
                q.stime = now_seconds();
                q.last_send_pid = pid;
                q.counters.add_message(msgsz);
                notify_msg_waiters(&mut q, WaitKind::MsgRecv);
                Ok(true)
            }
        }
    };
    match r {
        Ok(true) => {
            clear_wait(task, WaitKind::MsgSend, ipc_ns, msqid);
            drain_msg_wakes(&queue);
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
    let Some(queue) = lookup_msg_queue(object) else {
        ctx.set_return(err(missing_msg_queue_errno(
            task,
            WaitKind::MsgRecv,
            object,
        )));
        return;
    };
    let picked = {
        let mut q = queue.lock();
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
            Err(EACCES)
        } else if q.removed {
            Err(EIDRM)
        } else {
            'select: {
                let idx = if flg & MSG_COPY != 0 {
                    usize::try_from(msgtyp).ok().and_then(|ordinal| {
                        q.msgs.iter().enumerate().nth(ordinal).map(|(idx, _)| idx)
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
                            break 'select Err(E2BIG);
                        }
                        if flg & MSG_COPY != 0 && msg.payload.len() > msgsz {
                            // copy_msg() rejects a source larger than its prepared
                            // destination even when MSG_NOERROR bypassed E2BIG.
                            break 'select Err(EINVAL);
                        }
                        let copied_len = core::cmp::min(msg.payload.len(), msgsz);
                        if flg & MSG_COPY != 0 {
                            copy_payload[..copied_len].copy_from_slice(&msg.payload[..copied_len]);
                            copy_payload.truncate(copied_len);
                            break 'select Ok(Some((
                                msg.mtype,
                                core::mem::take(&mut copy_payload),
                            )));
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
                    q.counters.remove_messages(1, bytes);
                }
                if selected.is_some() {
                    if flg & MSG_COPY == 0 {
                        notify_msg_waiters(&mut q, WaitKind::MsgSend);
                    }
                } else if flg & IPC_NOWAIT as i64 == 0 {
                    restore_msg_recv_wait(&queue, &mut q, task, ipc_ns, msqid);
                }
                Ok(selected)
            }
        }
    };
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
        drain_msg_wakes(&queue);
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
            let (queue_count, counters, max_index) = with_msg_state(|state| {
                let (queue_count, counters) = state.usage.get(&ipc_ns).map_or((0, None), |usage| {
                    (usage.queue_count, Some(Arc::clone(&usage.counters)))
                });
                let max_index = state.ids.get(&ipc_ns).map_or(0, IpcIdTable::max_index);
                (queue_count, counters, max_index)
            });
            let (message_count, byte_count) = counters.map_or((0, 0), |c| c.snapshot());
            let clamp_i32 = |value: usize| i32::try_from(value).unwrap_or(i32::MAX);
            let mut out = [0u8; MSGINFO_SIZE];
            if cmd == MSG_INFO {
                put_i32(&mut out, 0, clamp_i32(queue_count));
                put_i32(&mut out, 4, clamp_i32(message_count));
                put_i32(&mut out, 24, clamp_i32(byte_count));
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
                let queue = state.queues.get(&object).cloned().ok_or(EINVAL)?;
                let mut q = queue.lock();
                if q.removed {
                    return Err(EINVAL);
                }
                if !ipc_owner(caller_uid, q.uid, q.cuid) {
                    return Err(EPERM);
                }
                let removed_queue = state.queues.remove(&object).ok_or(EINVAL)?;
                assert!(Arc::ptr_eq(&removed_queue, &queue));
                q.removed = true;
                state
                    .ids
                    .get_mut(&ipc_ns)
                    .expect("SysV message id table missing")
                    .release(msqid);
                if q.key as u64 != IPC_PRIVATE {
                    assert_eq!(
                        state.key_ids.remove(&(ipc_ns, q.key)),
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
                    usage.queue_count == 0
                };
                if remove_usage {
                    state.usage.remove(&ipc_ns);
                }
                retire_msg_waiters(&mut q);
                q.counters.remove_messages(q.msgs.len(), q.current_bytes);
                let messages = core::mem::take(&mut q.msgs);
                q.current_bytes = 0;
                drop(q);
                Ok((queue, messages))
            });
            match removed {
                Ok((queue, messages)) => {
                    // Queue payload destruction and task wakeups can release
                    // allocator/scheduler state; perform both after unlocking.
                    drop(messages);
                    drain_msg_wakes(&queue);
                    narf_net::readiness::notify(0);
                    ctx.set_return(SyscallReturn::ok(0));
                }
                Err(e) => ctx.set_return(err(e)),
            }
        }
        IPC_STAT | MSG_STAT | MSG_STAT_ANY => {
            let target = with_msg_state(|state| {
                let returned_id = if cmd == IPC_STAT {
                    msqid
                } else {
                    state
                        .ids
                        .get(&ipc_ns)
                        .and_then(|ids| ids.full_id_at(msqid))
                        .ok_or(EINVAL)?
                };
                let queue = state
                    .queues
                    .get(&(ipc_ns, returned_id))
                    .cloned()
                    .ok_or(EINVAL)?;
                Ok((returned_id, queue))
            });
            let snapshot = target.and_then(|(returned_id, queue)| {
                let q = queue.lock();
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
                if q.removed {
                    return Err(EIDRM);
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
            let queue = match lookup_msg_queue(object) {
                Some(queue) => queue,
                None => {
                    ctx.set_return(err(EINVAL));
                    return;
                }
            };
            let authorized = {
                let q = queue.lock();
                if q.removed {
                    Err(EINVAL)
                } else if !ipc_owner(caller_uid, q.uid, q.cuid)
                    || new_max > MSG_DEFAULT_QUEUE_BYTES as u64 && caller_uid != 0
                {
                    Err(EPERM)
                } else {
                    Ok(())
                }
            };
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
            let max_bytes = match usize::try_from(new_max) {
                Ok(max_bytes) => max_bytes,
                Err(_) => {
                    ctx.set_return(err(EINVAL));
                    return;
                }
            };
            let result = {
                let mut q = queue.lock();
                if q.removed {
                    Err(EINVAL)
                } else if !ipc_owner(caller_uid, q.uid, q.cuid)
                    || new_max > MSG_DEFAULT_QUEUE_BYTES as u64 && caller_uid != 0
                {
                    Err(EPERM)
                } else {
                    q.uid = new_uid;
                    q.gid = new_gid;
                    q.mode = new_mode;
                    q.max_bytes = max_bytes;
                    q.ctime = now_seconds();
                    notify_msg_waiters(&mut q, WaitKind::MsgRecv);
                    notify_msg_waiters(&mut q, WaitKind::MsgSend);
                    Ok(())
                }
            };
            match result {
                Ok(()) => {
                    // Linux uses its internal -EAGAIN receiver sentinel to
                    // wake and recheck after IPC_SET; it does not return that
                    // sentinel to userspace. A readiness bump retries both
                    // receivers (including stricter permissions) and senders
                    // that may now fit under a larger qbytes.
                    drain_msg_wakes(&queue);
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
    // Detach and retire one set at a time.  Namespace-registry code never
    // waits for an object lock; all paths use object -> registry ordering.
    while let Some((object, set_ref)) = with_sem_state(|state| {
        let object = state
            .sets
            .keys()
            .find(|(namespace, _)| *namespace == ipc_ns)
            .copied()?;
        Some((object, Arc::clone(state.sets.get(&object)?)))
    }) {
        let mut set = set_ref.lock();
        with_sem_state(|state| {
            if state
                .sets
                .get(&object)
                .is_some_and(|current| Arc::ptr_eq(current, &set_ref))
            {
                state.sets.remove(&object);
            }
            for index in 0..state.waits.len() {
                let matches_set = {
                    let wait = &state.waits[index];
                    wait.ipc_ns == ipc_ns && wait.id == object.1
                };
                if !matches_set {
                    continue;
                }
                state.waits[index].pending_prev = None;
                state.waits[index].pending_next = None;
                if state.waits[index].result.is_none() {
                    state.waits[index].result = Some(EIDRM);
                    queue_sem_wake(state, index);
                }
            }
        });
        set.removed = true;
        set.pending_head = None;
        set.pending_tail = None;
        set.ncnt.fill(0);
        set.zcnt.fill(0);
        set.undos.clear();
    }
    with_sem_state(|state| {
        state.ids.remove(&ipc_ns);
        state
            .key_ids
            .retain(|(namespace, _), _| *namespace != ipc_ns);
        state.usage.remove(&ipc_ns);
    });
    drain_sem_wakes();
    // Retire one queue at a time so dropping queued payloads and firing wakers
    // happens outside all IRQ-safe locks without requiring a fallible staging
    // allocation during namespace teardown.
    while let Some((queue, messages)) = with_msg_state(|state| {
        let object = state
            .queues
            .keys()
            .find(|(namespace, _)| *namespace == ipc_ns)
            .copied()?;
        let queue = state
            .queues
            .remove(&object)
            .expect("indexed SysV message queue missing during namespace drop");
        let mut q = queue.lock();
        q.removed = true;
        retire_msg_waiters(&mut q);
        q.counters.remove_messages(q.msgs.len(), q.current_bytes);
        let messages = core::mem::take(&mut q.msgs);
        q.current_bytes = 0;
        state
            .ids
            .get_mut(&ipc_ns)
            .expect("SysV message id table missing during namespace drop")
            .release(object.1);
        if q.key as u64 != IPC_PRIVATE {
            assert_eq!(
                state.key_ids.remove(&(ipc_ns, q.key)),
                Some(object.1),
                "SysV message key index diverged during namespace drop"
            );
        }
        let usage = state
            .usage
            .get_mut(&ipc_ns)
            .expect("SysV message usage missing during namespace drop");
        usage.queue_count = usage
            .queue_count
            .checked_sub(1)
            .expect("SysV message queue count underflow during namespace drop");
        drop(q);
        Some((queue, messages))
    }) {
        drop(messages);
        drain_msg_wakes(&queue);
    }
    with_msg_state(|state| {
        state.ids.remove(&ipc_ns);
        state
            .key_ids
            .retain(|(namespace, _), _| *namespace != ipc_ns);
        state.usage.remove(&ipc_ns);
    });
    narf_net::readiness::notify(0);
}
