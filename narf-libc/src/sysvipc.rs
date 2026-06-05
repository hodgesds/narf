//! `<sys/ipc.h>` + `<sys/shm.h>` + `<sys/msg.h>` + `<sys/sem.h>` —
//! System V IPC surface.
//!
//! NARF doesn't model the System V IPC namespace (no shared-memory
//! segments, no message queues, no semaphore arrays). All entries
//! refuse with `errno = ENOSYS`. The struct shapes (`shmid_ds`,
//! `msqid_ds`, `semid_ds`, `ipc_perm`) match Linux/glibc on x86_64
//! so a binary's compile-time `sizeof` and `offsetof` line up.
//!
//! `ftok` is the one entry we provide a real implementation for —
//! it's pure path/proj_id arithmetic with no kernel dependency, and
//! library code uses it to derive a key before calling the
//! ENOSYS-laden shm/msg/sem entries. Returning a real key lets that
//! upstream computation succeed even though the eventual *get
//! call fails.

#![allow(non_camel_case_types)]

use crate::posix::{c_char, c_int};

pub const ENOSYS: c_int = 38;
pub type key_t = i32;
pub type mode_t = u32;
pub type uid_t = u32;
pub type gid_t = u32;
pub type pid_t = i32;
pub type time_t = i64;
pub type size_t = usize;
pub type c_void = core::ffi::c_void;

// ── struct ipc_perm ─────────────────────────────────────────────────

/// `<sys/ipc.h>` `struct ipc_perm` — glibc layout. Common header for
/// shm/msg/sem control blocks.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ipc_perm {
    pub __key: key_t,
    pub uid: uid_t,
    pub gid: gid_t,
    pub cuid: uid_t,
    pub cgid: gid_t,
    pub mode: mode_t,
    pub __seq: u16,
    pub __pad1: u16,
    pub __pad2: u64,
    pub __pad3: u64,
}

// ipc / shm / msg / sem flag constants — values match Linux.
pub const IPC_CREAT: c_int = 0o1000;
pub const IPC_EXCL: c_int = 0o2000;
pub const IPC_NOWAIT: c_int = 0o4000;

pub const IPC_RMID: c_int = 0;
pub const IPC_SET: c_int = 1;
pub const IPC_STAT: c_int = 2;
pub const IPC_INFO: c_int = 3;

pub const IPC_PRIVATE: key_t = 0;

// ── ftok ────────────────────────────────────────────────────────────

/// `ftok(path, proj_id)` — derive an IPC key from a filesystem path
/// and an 8-bit project id. NARF doesn't model inodes, so we hash
/// the path bytes with the proj_id mixed in. Two distinct paths
/// almost always hash to distinct keys; same path + same proj_id
/// hash deterministically — that's the contract callers rely on.
///
/// Returns -1 on a NULL path; otherwise a non-negative key.
///
/// # Safety
/// `path`, when non-null, must be a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ftok(path: *const c_char, proj_id: c_int) -> key_t {
    if path.is_null() {
        crate::errno::set_errno(2 /* ENOENT */);
        return -1;
    }
    // FNV-1a 32-bit over the path bytes, mixed with proj_id.
    let mut h: u32 = 0x811C_9DC5;
    // SAFETY: caller-asserted NUL-termination.
    unsafe {
        let mut i = 0usize;
        while *path.add(i) != 0 {
            h ^= *path.add(i) as u8 as u32;
            h = h.wrapping_mul(0x0100_0193);
            i += 1;
        }
    }
    h ^= (proj_id as u8 as u32) << 24;
    // POSIX spec: low 8 bits are the proj_id; we follow the same
    // convention so keys are stable across independent recomputes.
    let key = (h & 0x00FF_FFFF) as i32 | ((proj_id & 0xFF) << 24);
    if key < 0 {
        0x0FFF_FFFF
    } else {
        key
    }
}

// ── shm ─────────────────────────────────────────────────────────────

/// `<sys/shm.h>` `struct shmid_ds` — glibc layout, padded to match.
#[repr(C)]
pub struct shmid_ds {
    pub shm_perm: ipc_perm,
    pub shm_segsz: size_t,
    pub shm_atime: time_t,
    pub shm_dtime: time_t,
    pub shm_ctime: time_t,
    pub shm_cpid: pid_t,
    pub shm_lpid: pid_t,
    pub shm_nattch: u64,
    pub __unused4: u64,
    pub __unused5: u64,
}

pub const SHM_RDONLY: c_int = 0o10000;
pub const SHM_RND: c_int = 0o20000;
pub const SHM_REMAP: c_int = 0o40000;
pub const SHM_EXEC: c_int = 0o100000;

#[inline]
fn enosys_minus_one_int() -> c_int {
    crate::errno::set_errno(ENOSYS);
    -1
}

/// `shmget(key, size, shmflg)` — Sys-V shared memory routed
/// through POSIX shm_open. The returned fd doubles as the
/// Sys-V shmid; consumers that ftruncate before mmap get the
/// expected shape.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shmget(key: key_t, size: size_t, shmflg: c_int) -> c_int {
    let fd = unsafe { crate::ipc::shmget_real(key as i32, size as usize, shmflg) };
    if fd < 0 {
        return -1;
    }
    // Size the underlying memfile to `size`.
    let _ = unsafe { crate::posix::ftruncate(fd, size as i64) };
    fd
}

/// `shmat(shmid, shmaddr, shmflg)` — stub returning `(void*)-1`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shmat(
    _shmid: c_int,
    _shmaddr: *const c_void,
    _shmflg: c_int,
) -> *mut c_void {
    crate::errno::set_errno(ENOSYS);
    !0usize as *mut c_void
}

/// `shmdt(shmaddr)` — stub.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shmdt(_shmaddr: *const c_void) -> c_int {
    enosys_minus_one_int()
}

/// `shmctl(shmid, cmd, buf)` — stub.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shmctl(_shmid: c_int, _cmd: c_int, _buf: *mut shmid_ds) -> c_int {
    enosys_minus_one_int()
}

// ── msg ─────────────────────────────────────────────────────────────

/// `<sys/msg.h>` `struct msqid_ds` — glibc layout.
#[repr(C)]
pub struct msqid_ds {
    pub msg_perm: ipc_perm,
    pub msg_stime: time_t,
    pub msg_rtime: time_t,
    pub msg_ctime: time_t,
    pub __msg_cbytes: u64,
    pub msg_qnum: u64,
    pub msg_qbytes: u64,
    pub msg_lspid: pid_t,
    pub msg_lrpid: pid_t,
    pub __unused4: u64,
    pub __unused5: u64,
}

pub const MSG_NOERROR: c_int = 0o10000;
pub const MSG_EXCEPT: c_int = 0o20000;

/// `msgget(key, msgflg)` — Sys-V message queue. Routes through
/// POSIX MQ — name "/sysv-mq-<key-hex>".
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msgget(key: key_t, msgflg: c_int) -> c_int {
    let mut name = [0u8; 24];
    let prefix = b"/sysv-mq-";
    for (i, &b) in prefix.iter().enumerate() {
        name[i] = b;
    }
    let hex = b"0123456789abcdef";
    let kraw = key as u32;
    for i in 0..8 {
        name[9 + i] = hex[((kraw >> ((7 - i) * 4)) & 0xF) as usize];
    }
    name[17] = 0;
    let oflag = if msgflg & 0o1000 /* IPC_CREAT */ != 0 {
        0o100
    } else {
        0
    };
    unsafe { crate::ipc::mq_open(name.as_ptr() as *const i8, oflag, 0o600, core::ptr::null()) }
}

/// `msgsnd(msqid, msgp, msgsz, msgflg)` — Sys-V message send.
/// The first 8 bytes of `msgp` are the type field; we forward the
/// payload (type + bytes) as-is to mq_send.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msgsnd(
    msqid: c_int,
    msgp: *const c_void,
    msgsz: size_t,
    _msgflg: c_int,
) -> c_int {
    if msgp.is_null() {
        return -1;
    }
    // Sys-V message: { mtype: i64, mtext[msgsz] }
    let total = msgsz.saturating_add(8);
    unsafe { crate::ipc::mq_send(msqid, msgp as *const i8, total, 0) }
}

/// `msgrcv(msqid, msgp, msgsz, msgtyp, msgflg)` — Sys-V receive.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msgrcv(
    msqid: c_int,
    msgp: *mut c_void,
    msgsz: size_t,
    _msgtyp: i64,
    _msgflg: c_int,
) -> isize {
    if msgp.is_null() {
        return -1;
    }
    let total = msgsz.saturating_add(8);
    let n = unsafe { crate::ipc::mq_receive(msqid, msgp as *mut i8, total, core::ptr::null_mut()) };
    if n < 0 {
        -1
    } else {
        n - 8
    } // Sys-V returns text length (excluding mtype)
}

/// `msgctl(msqid, cmd, buf)` — stub.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msgctl(_msqid: c_int, _cmd: c_int, _buf: *mut msqid_ds) -> c_int {
    enosys_minus_one_int()
}

// ── sem ─────────────────────────────────────────────────────────────

/// `<sys/sem.h>` `struct sembuf` — glibc layout.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct sembuf {
    pub sem_num: u16,
    pub sem_op: i16,
    pub sem_flg: i16,
}

/// `<sys/sem.h>` `struct semid_ds` — glibc layout.
#[repr(C)]
pub struct semid_ds {
    pub sem_perm: ipc_perm,
    pub sem_otime: time_t,
    pub __unused1: u64,
    pub sem_ctime: time_t,
    pub __unused2: u64,
    pub sem_nsems: u64,
    pub __unused3: u64,
    pub __unused4: u64,
}

pub const SEM_UNDO: c_int = 0x1000;
pub const GETPID: c_int = 11;
pub const GETVAL: c_int = 12;
pub const GETALL: c_int = 13;
pub const GETNCNT: c_int = 14;
pub const GETZCNT: c_int = 15;
pub const SETVAL: c_int = 16;
pub const SETALL: c_int = 17;

/// `semget(key, nsems, semflg)` — Sys-V counter array. Backed by
/// a per-semid sem_t in a libc-side table; semop's per-element
/// `sem_num` indexes the array.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn semget(key: key_t, nsems: c_int, semflg: c_int) -> c_int {
    unsafe { crate::ipc::semget_real(key as i32, nsems, semflg) }
}

/// `semop(semid, sops, nsops)` — stub.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn semop(_semid: c_int, _sops: *mut sembuf, _nsops: usize) -> c_int {
    enosys_minus_one_int()
}

/// `semctl(semid, semnum, cmd, ...)` — three-arg form. The C ABI
/// accepts a fourth variadic `union semun` argument that we drop —
/// callers that pass a fourth arg simply have it ignored. ENOSYS in
/// any case.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn semctl(_semid: c_int, _semnum: c_int, _cmd: c_int) -> c_int {
    enosys_minus_one_int()
}
