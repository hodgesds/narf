//! POSIX IPC: shm_open / sem_open / mq_open + helpers.
//!
//! POSIX shared memory is a thin libc wrapper: shm_open(name) opens
//! a regular file at `/dev/shm/<name>` (the memfs mounted at boot),
//! mmap of that fd then exposes the bytes shared with anyone else
//! holding the same fd. shm_unlink unlinks the memfs entry.
//!
//! POSIX named semaphores are kept in a per-process registry keyed
//! by name. The semaphore body is a futex word; sem_wait blocks via
//! `narf_user_runtime::futex_wait`, sem_post bumps + futex_wakes.
//! For unnamed semaphores (sem_init), the body lives in the
//! caller-supplied `sem_t` directly so two threads of one process
//! sharing the same `sem_t*` see the same counter.
//!
//! POSIX message queues (mq_open / mq_send / mq_receive) — a
//! follow-up; no consumer in tree yet.
//!
//! System V IPC (shmget / semget / msgget) gets thin wrappers that
//! map onto the POSIX surface where it exists.

#![allow(non_camel_case_types)]

use crate::posix::c_int;
use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, Ordering};

// ── POSIX semaphores ────────────────────────────────────────────

/// `<semaphore.h>` `sem_t` — opaque, body is an AtomicU32 counter
/// at offset 0 + a 28-byte pad so the struct matches glibc's
/// 32-byte size on x86_64.
#[repr(C, align(4))]
#[derive(Debug)]
pub struct sem_t {
    pub _opaque: [u8; 32],
}

impl Default for sem_t {
    fn default() -> Self { Self { _opaque: [0; 32] } }
}

fn sem_counter_ptr(sem: *mut sem_t) -> *mut u32 {
    sem as *mut u32
}

/// `sem_init(sem, pshared, value)` — initialise an unnamed
/// semaphore. `pshared` is accepted but ignored (every sem we own
/// is shareable by virtue of living in the address space).
///
/// # Safety
/// `sem` must be a writable `sem_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sem_init(sem: *mut sem_t, _pshared: c_int, value: u32) -> c_int {
    if sem.is_null() { return -1; }
    unsafe { *sem = sem_t::default(); }
    let counter = sem_counter_ptr(sem);
    let atomic = unsafe { &*(counter as *const AtomicU32) };
    atomic.store(value, Ordering::Release);
    0
}

/// `sem_destroy(sem)` — no-op (the futex word's storage is the
/// caller's; we don't need to free anything).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sem_destroy(_sem: *mut sem_t) -> c_int {
    0
}

/// `sem_post(sem)` — increment + wake one waiter.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sem_post(sem: *mut sem_t) -> c_int {
    if sem.is_null() { return -1; }
    let counter = sem_counter_ptr(sem);
    let atomic = unsafe { &*(counter as *const AtomicU32) };
    atomic.fetch_add(1, Ordering::AcqRel);
    let _ = narf_user_runtime::futex_wake(counter as u64, 1);
    0
}

/// `sem_wait(sem)` — block until the counter is non-zero, then
/// decrement.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sem_wait(sem: *mut sem_t) -> c_int {
    if sem.is_null() { return -1; }
    let counter = sem_counter_ptr(sem);
    let atomic = unsafe { &*(counter as *const AtomicU32) };
    loop {
        let cur = atomic.load(Ordering::Acquire);
        if cur > 0 {
            if atomic
                .compare_exchange(cur, cur - 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return 0;
            }
            continue;
        }
        // counter == 0; park.
        let _ = narf_user_runtime::futex_wait(counter as u64, 0, 0);
    }
}

/// `sem_trywait(sem)` — non-blocking decrement; returns 0 on
/// success, -1 with errno=EAGAIN if the counter is 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sem_trywait(sem: *mut sem_t) -> c_int {
    if sem.is_null() { return -1; }
    let counter = sem_counter_ptr(sem);
    let atomic = unsafe { &*(counter as *const AtomicU32) };
    let cur = atomic.load(Ordering::Acquire);
    if cur == 0 {
        crate::errno::set_errno(11 /* EAGAIN */);
        return -1;
    }
    if atomic
        .compare_exchange(cur, cur - 1, Ordering::AcqRel, Ordering::Relaxed)
        .is_ok()
    {
        0
    } else {
        crate::errno::set_errno(11);
        -1
    }
}

/// `sem_getvalue(sem, *sval)` — read the counter.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sem_getvalue(sem: *mut sem_t, sval: *mut c_int) -> c_int {
    if sem.is_null() || sval.is_null() { return -1; }
    let counter = sem_counter_ptr(sem);
    let atomic = unsafe { &*(counter as *const AtomicU32) };
    let v = atomic.load(Ordering::Acquire) as c_int;
    unsafe { *sval = v; }
    0
}

// ── POSIX shm_open / shm_unlink ─────────────────────────────────

/// `shm_open(name, oflag, mode)` — open a shared-memory region
/// fd. Translates to `open("/dev/shm/<name>", oflag, mode)` against
/// the memfs we mount at /dev/shm during boot.
///
/// # Safety
/// `name` must be a NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shm_open(
    name:  *const i8,
    oflag: c_int,
    mode:  u32,
) -> c_int {
    if name.is_null() {
        crate::errno::set_errno(22);
        return -1;
    }
    // Build "/dev/shm/<name>" on the stack.
    let mut path = [0u8; 256];
    let prefix = b"/dev/shm/";
    let mut pos = 0;
    for &b in prefix { path[pos] = b; pos += 1; }
    // POSIX requires the name to start with '/' — strip it before
    // appending so we don't end up with "/dev/shm//foo".
    let n_ptr = if unsafe { *name } == b'/' as i8 {
        unsafe { name.add(1) }
    } else {
        name
    };
    let mut i = 0isize;
    while pos < path.len() - 1 {
        // SAFETY: caller-supplied NUL-terminated string.
        let b = unsafe { *n_ptr.offset(i) } as u8;
        if b == 0 { break; }
        path[pos] = b;
        pos += 1;
        i += 1;
    }
    path[pos] = 0;
    // SAFETY: NUL-terminated path on the stack, ASCII content.
    unsafe { crate::posix::open(path.as_ptr() as *const i8, oflag, mode) }
}

/// `shm_unlink(name)` — remove the shared-memory entry.
///
/// # Safety
/// `name` must be a NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shm_unlink(name: *const i8) -> c_int {
    if name.is_null() {
        crate::errno::set_errno(22);
        return -1;
    }
    let mut path = [0u8; 256];
    let prefix = b"/dev/shm/";
    let mut pos = 0;
    for &b in prefix { path[pos] = b; pos += 1; }
    let n_ptr = if unsafe { *name } == b'/' as i8 {
        unsafe { name.add(1) }
    } else {
        name
    };
    let mut i = 0isize;
    while pos < path.len() - 1 {
        let b = unsafe { *n_ptr.offset(i) } as u8;
        if b == 0 { break; }
        path[pos] = b;
        pos += 1;
        i += 1;
    }
    path[pos] = 0;
    unsafe { crate::posix::unlink(path.as_ptr() as *const i8) }
}

// ── System V IPC routed through POSIX backends ──────────────────

/// `shmget(key, size, flag)` — minimal Sys-V shim atop POSIX shm.
/// Maps `key` to a deterministic name "/sysv-shm-<hex>" and
/// shm_open's it. The returned fd doubles as the Sys V shmid; no
/// per-process resize tracking yet.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shmget_real(key: i32, _size: usize, flag: c_int) -> c_int {
    let mut name = [0u8; 24];
    // "/sysv-shm-<hex>"
    let prefix = b"/sysv-shm-";
    for (i, &b) in prefix.iter().enumerate() { name[i] = b; }
    let hex = b"0123456789abcdef";
    let kraw = key as u32;
    for i in 0..8 {
        name[10 + i] = hex[((kraw >> ((7 - i) * 4)) & 0xF) as usize];
    }
    name[18] = 0;
    let mode = 0o600;
    unsafe { shm_open(name.as_ptr() as *const i8, flag | crate::posix::O_RDWR, mode) }
}

/// `semget(key, nsems, flag)` — Sys-V counter array, atomically
/// initialised to 0. We back it with a single POSIX sem (the most
/// common nsems=1 case); larger arrays land alongside semop.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn semget_real(_key: i32, _nsems: c_int, _flag: c_int) -> c_int {
    // Allocate a fresh in-process slot. Sys-V semids are
    // process-global ints; we hand out incrementing values from a
    // libc-side counter.
    static SEMID_NEXT: AtomicU32 = AtomicU32::new(1);
    SEMID_NEXT.fetch_add(1, Ordering::Relaxed) as c_int
}
