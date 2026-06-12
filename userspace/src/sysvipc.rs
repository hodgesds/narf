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
    if nsops == 0 || nsops > 1024 || sops_ptr == 0 {
        ctx.set_return(err(EINVAL));
        return;
    }
    // struct sembuf { unsigned short sem_num; short sem_op; short sem_flg; } — 6 B.
    // SAFETY: sops_ptr is checked non-zero; copy_from_user_vec range-validates
    // and SMAP-brackets the read of the nsops sembuf entries.
    let buf = match unsafe { crate::handlers::copy_from_user_vec(sops_ptr, nsops * 6) } {
        Ok(b) => b,
        Err(_) => {
            ctx.set_return(err(EINVAL));
            return;
        }
    };
    let parse = |i: usize| -> (usize, i16, i16) {
        let o = i * 6;
        let num = u16::from_le_bytes(buf[o..o + 2].try_into().unwrap()) as usize;
        let op = i16::from_le_bytes(buf[o + 2..o + 4].try_into().unwrap());
        let flg = i16::from_le_bytes(buf[o + 4..o + 6].try_into().unwrap());
        (num, op, flg)
    };
    let result = with_sems(|m| {
        let set = m.get_mut(&semid).ok_or(EINVAL)?;
        // Phase 1: verify every op can proceed against a scratch copy.
        let mut scratch = set.sems.clone();
        for i in 0..nsops {
            let (num, op, flg) = parse(i);
            if num >= scratch.len() {
                return Err(EINVAL);
            }
            let cur = scratch[num];
            let _ = flg; // IPC_NOWAIT vs block: we never block, so always EAGAIN.
            if op == 0 {
                if cur != 0 {
                    return Err(EAGAIN); // wait-for-zero would block
                }
            } else {
                let next = cur + op as i32;
                if next < 0 {
                    return Err(EAGAIN); // would block; non-blocking → EAGAIN
                }
                scratch[num] = next;
            }
        }
        // Phase 2: commit.
        set.sems = scratch;
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
    // Read mtype (8 B) + msgsz payload bytes.
    // SAFETY: msgp checked non-zero; copy_from_user_vec range-validates and
    // brackets the read of the 8-byte mtype + msgsz payload.
    let raw = match unsafe { crate::handlers::copy_from_user_vec(msgp, 8 + msgsz) } {
        Ok(b) => b,
        Err(_) => {
            ctx.set_return(err(EINVAL));
            return;
        }
    };
    let mtype = i64::from_le_bytes(raw[0..8].try_into().unwrap());
    if mtype <= 0 {
        ctx.set_return(err(EINVAL));
        return;
    }
    let payload = raw[8..8 + msgsz].to_vec();
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
    let mut out = Vec::with_capacity(8 + payload.len());
    out.extend_from_slice(&mtype.to_le_bytes());
    out.extend_from_slice(&payload);
    // SAFETY: msgp checked non-zero; copy_to_user validates the mtype+payload write.
    if unsafe { crate::handlers::copy_to_user(msgp, &out) }.is_err() {
        ctx.set_return(err(EINVAL));
        return;
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
