//! System V IPC — semaphores (`sem*`) and message queues (`msg*`).
//!
//! Self-contained side-table implementations that work in any
//! `linux-compat` build (independent of the container IPC-namespace
//! infrastructure, which provides only the id-by-key `*get` surface).
//! Shared memory (`shm*`) lives separately since it needs address-space
//! frame mapping.
//!
//! Semaphores are non-blocking: an operation that would block returns
//! EAGAIN rather than parking (the cooperative kernel has no clean
//! IPC-wait primitive yet); message queues are likewise non-blocking on
//! a full/empty queue. Both round-trip faithfully for the common
//! create → op → control → remove flow.
//!
//! Gated under `#[cfg(feature = "linux-compat")]` via the `pub mod`
//! line in `lib.rs`.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::syscall::{SyscallReturn, TrapContext};

// ── errno + IPC constants ────────────────────────────────────────────
const ENOENT: i64 = 2;
const EAGAIN: i64 = 11;
const EEXIST: i64 = 17;
const EINVAL: i64 = 22;
const ENOMSG: i64 = 42;

fn err(e: i64) -> SyscallReturn {
    SyscallReturn::ok((-e) as u64)
}

const IPC_CREAT: u64 = 0o1000;
const IPC_EXCL: u64 = 0o2000;
const IPC_PRIVATE: u64 = 0;

// ipc control cmds (low bits; libc ORs IPC_64 = 0x100 which we mask off).
const IPC_RMID: u64 = 0;
const IPC_SET: u64 = 1;
const IPC_STAT: u64 = 2;
const IPC_64: u64 = 0x100;

// semctl cmds.
const GETVAL: u64 = 12;
const GETALL: u64 = 13;
const SETVAL: u64 = 16;
const SETALL: u64 = 17;

// ════════════════════════════════════════════════════════════════════
// Semaphores
// ════════════════════════════════════════════════════════════════════

struct SemSet {
    key: u32,
    sems: Vec<i32>,
}

static SEMS: IrqSafeSpinLock<Option<BTreeMap<u64, SemSet>>> = IrqSafeSpinLock::new(None);
static SEM_NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Upper bound on `nsops` for a single `semop`, matching the accepted
/// `nsems` cap. Sizes the on-stack sops read buffer (MAX_SOPS * 6 B) so a
/// semop performs no heap allocation.
const MAX_SOPS: usize = 1024;

fn with_sems<R>(f: impl FnOnce(&mut BTreeMap<u64, SemSet>) -> R) -> R {
    let mut g = SEMS.lock();
    f(g.get_or_insert_with(BTreeMap::new))
}

/// `semget(key, nsems, semflg)`.
pub fn sys_semget(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let key = a.arg0 as u32;
    let nsems = a.arg1 as usize;
    let flg = a.arg2;
    let id = with_sems(|m| {
        if key as u64 != IPC_PRIVATE {
            if let Some((id, _)) = m.iter().find(|(_, s)| s.key == key) {
                let id = *id;
                if flg & IPC_CREAT != 0 && flg & IPC_EXCL != 0 {
                    return Err(EEXIST);
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
        let id = SEM_NEXT_ID.fetch_add(1, Ordering::Relaxed);
        m.insert(
            id,
            SemSet {
                key,
                sems: alloc::vec![0i32; nsems],
            },
        );
        Ok(id)
    });
    match id {
        Ok(id) => ctx.set_return(SyscallReturn::ok(id)),
        Err(e) => ctx.set_return(err(e)),
    }
}

/// `semop(semid, sops, nsops)` — all-or-nothing, non-blocking.
pub fn sys_semop(ctx: &mut dyn TrapContext) {
    semop_common(ctx, false);
}

/// `semtimedop(semid, sops, nsops, timeout)` — same, timeout ignored
/// (we never block, so a timeout has no effect).
pub fn sys_semtimedop(ctx: &mut dyn TrapContext) {
    semop_common(ctx, true);
}

fn semop_common(ctx: &mut dyn TrapContext, _timed: bool) {
    let a = *ctx.args();
    let semid = a.arg0;
    let sops_ptr = a.arg1;
    let nsops = a.arg2 as usize;
    if nsops == 0 || nsops > MAX_SOPS || sops_ptr == 0 {
        ctx.set_return(err(EINVAL));
        return;
    }
    // struct sembuf { unsigned short sem_num; short sem_op; short sem_flg; } — 6 B.
    // Read the sops array into a fixed on-stack buffer so a semop costs no
    // heap traffic (the hot stress path is a single-sembuf P/V pair).
    let nbytes = nsops * 6;
    let mut buf = [0u8; MAX_SOPS * 6];
    // SAFETY: sops_ptr is checked non-zero; copy_from_user range-validates and
    // SMAP-brackets the read of the nbytes sembuf entries into the stack slice.
    if unsafe { crate::handlers::copy_from_user(&mut buf[..nbytes], sops_ptr) }.is_err() {
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
    let result = with_sems(|m| {
        let set = m.get_mut(&semid).ok_or(EINVAL)?;
        // Bounds-check every referenced sem_num up front so the apply pass
        // (which mutates the live vector) can only be reached once the whole
        // sops array is known-valid.
        for i in 0..nsops {
            let (num, _, _) = parse(i);
            if num >= set.sems.len() {
                return Err(EINVAL);
            }
        }
        // Apply each op in order against the RUNNING value (accumulating
        // repeated sem_num within this call, as Linux's atomic block does).
        // On the first op that would block, roll back every applied delta so
        // the operation is all-or-nothing without cloning the vector.
        let mut applied = 0usize;
        let mut fail: Option<i64> = None;
        for i in 0..nsops {
            let (num, op, _flg) = parse(i);
            let cur = set.sems[num];
            if op == 0 {
                if cur != 0 {
                    fail = Some(EAGAIN); // wait-for-zero would block
                    break;
                }
            } else if cur + op as i32 >= 0 {
                set.sems[num] = cur + op as i32;
            } else {
                fail = Some(EAGAIN); // would block; non-blocking → EAGAIN
                break;
            }
            applied = i + 1;
        }
        if let Some(e) = fail {
            for i in (0..applied).rev() {
                let (num, op, _) = parse(i);
                if op != 0 {
                    set.sems[num] -= op as i32;
                }
            }
            return Err(e);
        }
        Ok(())
    });
    match result {
        Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
        Err(e) => ctx.set_return(err(e)),
    }
}

/// `semctl(semid, semnum, cmd, arg)`.
pub fn sys_semctl(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let semid = a.arg0;
    let semnum = a.arg1 as usize;
    let cmd = a.arg2 & !IPC_64;
    let arg = a.arg3;
    match cmd {
        IPC_RMID => {
            let removed = with_sems(|m| m.remove(&semid).is_some());
            ctx.set_return(if removed {
                SyscallReturn::ok(0)
            } else {
                err(EINVAL)
            });
        }
        SETVAL => {
            let r = with_sems(|m| {
                let set = m.get_mut(&semid).ok_or(EINVAL)?;
                if semnum >= set.sems.len() {
                    return Err(EINVAL);
                }
                set.sems[semnum] = arg as i32;
                Ok(())
            });
            ctx.set_return(match r {
                Ok(()) => SyscallReturn::ok(0),
                Err(e) => err(e),
            });
        }
        GETVAL => {
            let r = with_sems(|m| {
                let set = m.get(&semid).ok_or(EINVAL)?;
                set.sems.get(semnum).copied().ok_or(EINVAL)
            });
            ctx.set_return(match r {
                Ok(v) => SyscallReturn::ok(v as u64),
                Err(e) => err(e),
            });
        }
        SETALL => {
            let r = with_sems(|m| {
                let set = m.get_mut(&semid).ok_or(EINVAL)?;
                let n = set.sems.len();
                // SAFETY: copy_from_user_vec range-validates `arg` and brackets
                // the read of the `n` u16 semaphore values.
                let bytes = unsafe { crate::handlers::copy_from_user_vec(arg, n * 2) }
                    .map_err(|_| EINVAL)?;
                for i in 0..n {
                    set.sems[i] =
                        u16::from_le_bytes(bytes[i * 2..i * 2 + 2].try_into().unwrap()) as i32;
                }
                Ok(())
            });
            ctx.set_return(match r {
                Ok(()) => SyscallReturn::ok(0),
                Err(e) => err(e),
            });
        }
        GETALL => {
            let r = with_sems(|m| {
                let set = m.get(&semid).ok_or(EINVAL)?;
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
                        ctx.set_return(err(EINVAL));
                    } else {
                        ctx.set_return(SyscallReturn::ok(0));
                    }
                }
                Err(e) => ctx.set_return(err(e)),
            }
        }
        IPC_STAT | IPC_SET => {
            // Minimal: succeed if the set exists.
            let ok = with_sems(|m| m.contains_key(&semid));
            ctx.set_return(if ok {
                SyscallReturn::ok(0)
            } else {
                err(EINVAL)
            });
        }
        _ => ctx.set_return(err(EINVAL)),
    }
}

// ════════════════════════════════════════════════════════════════════
// Message queues
// ════════════════════════════════════════════════════════════════════

struct MsgQueue {
    key: u32,
    msgs: VecDeque<(i64, Vec<u8>)>,
}

static MSGS: IrqSafeSpinLock<Option<BTreeMap<u64, MsgQueue>>> = IrqSafeSpinLock::new(None);
static MSG_NEXT_ID: AtomicU64 = AtomicU64::new(1);
const MSG_MAX_BYTES: usize = 8192;

fn with_msgs<R>(f: impl FnOnce(&mut BTreeMap<u64, MsgQueue>) -> R) -> R {
    let mut g = MSGS.lock();
    f(g.get_or_insert_with(BTreeMap::new))
}

/// `msgget(key, msgflg)`.
pub fn sys_msgget(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let key = a.arg0 as u32;
    let flg = a.arg1;
    let id = with_msgs(|m| {
        if key as u64 != IPC_PRIVATE {
            if let Some((id, _)) = m.iter().find(|(_, q)| q.key == key) {
                let id = *id;
                if flg & IPC_CREAT != 0 && flg & IPC_EXCL != 0 {
                    return Err(EEXIST);
                }
                return Ok(id);
            }
            if flg & IPC_CREAT == 0 {
                return Err(ENOENT);
            }
        }
        let id = MSG_NEXT_ID.fetch_add(1, Ordering::Relaxed);
        m.insert(
            id,
            MsgQueue {
                key,
                msgs: VecDeque::new(),
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
    let a = *ctx.args();
    let msqid = a.arg0;
    let msgp = a.arg1;
    let msgsz = a.arg2 as usize;
    if msgp == 0 || msgsz > MSG_MAX_BYTES {
        ctx.set_return(err(EINVAL));
        return;
    }
    // Read the 8-byte mtype header into a stack slot; validate it before
    // touching the heap so a bad type costs no allocation.
    let mut hdr = [0u8; 8];
    // SAFETY: msgp checked non-zero; copy_from_user range-validates and
    // brackets the read of the 8-byte mtype header.
    if unsafe { crate::handlers::copy_from_user(&mut hdr, msgp) }.is_err() {
        ctx.set_return(err(EINVAL));
        return;
    }
    let mtype = i64::from_le_bytes(hdr);
    if mtype <= 0 {
        ctx.set_return(err(EINVAL));
        return;
    }
    // Allocate the queued payload buffer exactly once and fill it directly
    // from userspace (no intermediate header+payload copy).
    let mut payload = alloc::vec![0u8; msgsz];
    if msgsz != 0 {
        // SAFETY: copy_from_user range-validates `msgp + 8` and brackets the
        // read of the msgsz payload bytes into the freshly sized buffer.
        if unsafe { crate::handlers::copy_from_user(&mut payload, msgp + 8) }.is_err() {
            ctx.set_return(err(EINVAL));
            return;
        }
    }
    let r = with_msgs(|m| {
        let q = m.get_mut(&msqid).ok_or(EINVAL)?;
        q.msgs.push_back((mtype, payload));
        Ok(())
    });
    match r {
        Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
        Err(e) => ctx.set_return(err(e)),
    }
}

/// `msgrcv(msqid, msgp, msgsz, msgtyp, msgflg)`.
pub fn sys_msgrcv(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let msqid = a.arg0;
    let msgp = a.arg1;
    let msgsz = a.arg2 as usize;
    let msgtyp = a.arg3 as i64;
    let flg = a.arg4 as i64;
    if msgp == 0 {
        ctx.set_return(err(EINVAL));
        return;
    }
    // Pick the first message matching msgtyp: 0 = any; >0 = first of that
    // type; <0 = lowest type <= |msgtyp|.
    let picked = with_msgs(|m| {
        let q = m.get_mut(&msqid).ok_or(EINVAL)?;
        let idx = q.msgs.iter().position(|(t, _)| {
            if msgtyp == 0 {
                true
            } else if msgtyp > 0 {
                *t == msgtyp
            } else {
                *t <= -msgtyp
            }
        });
        match idx {
            Some(i) => Ok(Some(q.msgs.remove(i).unwrap())),
            None => Ok(None),
        }
    });
    let (mtype, mut payload) = match picked {
        Ok(Some(msg)) => msg,
        Ok(None) => {
            // Empty / no match: non-blocking always (IPC_NOWAIT or not).
            let _ = flg;
            ctx.set_return(err(ENOMSG));
            return;
        }
        Err(e) => {
            ctx.set_return(err(e));
            return;
        }
    };
    if payload.len() > msgsz {
        // MSG_NOERROR (0o10000) truncates; otherwise E2BIG. We truncate
        // for simplicity — the common path passes a large-enough buffer.
        payload.truncate(msgsz);
    }
    // Write the mtype header and payload directly to the user buffer with no
    // intermediate combined allocation. The header goes down first; if the
    // payload write faults the message is already dequeued (matches the
    // truncate-on-small-buffer relaxation above).
    // SAFETY: msgp checked non-zero; copy_to_user validates the mtype write range.
    if unsafe { crate::handlers::copy_to_user(msgp, &mtype.to_le_bytes()) }.is_err() {
        ctx.set_return(err(EINVAL));
        return;
    }
    if !payload.is_empty() {
        // SAFETY: copy_to_user validates the `msgp + 8` payload write range.
        if unsafe { crate::handlers::copy_to_user(msgp + 8, &payload) }.is_err() {
            ctx.set_return(err(EINVAL));
            return;
        }
    }
    ctx.set_return(SyscallReturn::ok(payload.len() as u64));
}

/// `msgctl(msqid, cmd, buf)`.
pub fn sys_msgctl(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let msqid = a.arg0;
    let cmd = a.arg1 & !IPC_64;
    match cmd {
        IPC_RMID => {
            let removed = with_msgs(|m| m.remove(&msqid).is_some());
            ctx.set_return(if removed {
                SyscallReturn::ok(0)
            } else {
                err(EINVAL)
            });
        }
        IPC_STAT | IPC_SET => {
            let ok = with_msgs(|m| m.contains_key(&msqid));
            ctx.set_return(if ok {
                SyscallReturn::ok(0)
            } else {
                err(EINVAL)
            });
        }
        _ => ctx.set_return(err(EINVAL)),
    }
}
