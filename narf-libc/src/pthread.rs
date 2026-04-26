//! `<pthread.h>` no-op shim — single-threaded enough for libstdc++.
//!
//! NARF's user mode is single-threaded today; we don't run a real
//! pthread implementation. But every modern C++ runtime (and a
//! surprising number of "single-threaded" C programs) reach for
//! `pthread_mutex_init`, `pthread_once`, `pthread_key_*` from
//! global constructors, even when no actual thread ever spawns.
//!
//! Refusing to link is worse than running the bodies as no-ops:
//! a single-threaded program that touches a `static std::mutex`
//! still expects `pthread_mutex_init` to return 0 so the C++
//! runtime can record the mutex's state. We oblige by:
//!
//!   - Honouring the lock/unlock counter inside the supplied
//!     `pthread_mutex_t` so a recursive lock against a non-
//!     recursive mutex would surface (we don't enforce — just
//!     count). Callers see what looks like a working lock.
//!   - Treating `pthread_once` as a CAS-protected one-shot via
//!     the supplied control. Idempotent under our single-thread
//!     model — the second call is a no-op.
//!   - Storing TLS via a small per-key static slot table. Real
//!     pthread_key_create can fail with EAGAIN past 1024 keys;
//!     we cap at 32 (plenty for libstdc++ + iostreams).
//!
//! `pthread_create` is the only entry that fails honestly — we
//! return `EAGAIN`, signalling "no thread support". Programs that
//! want to spawn need a real pthread layer; programs that only
//! use the synchronisation primitives keep working.

#![allow(non_camel_case_types)]

use crate::posix::c_int;

pub const EAGAIN: c_int = 11;

/// Opaque pthread thread id. We only ever return a sentinel value
/// (the constant `MAIN_THREAD`) so consumers comparing two ids see
/// the program as a single thread.
pub type pthread_t = u64;

/// Sentinel returned by `pthread_self`. Distinct from 0 so a
/// caller storing the value into a `static pthread_t` can spot an
/// uninitialised slot.
pub const MAIN_THREAD: pthread_t = 1;

/// Opaque mutex. Two fields: a recursive-lock counter and an
/// ownership flag (rejecting unlock-of-unlocked). The actual
/// thread-id is unused (single-threaded), but we model the field
/// so a future pthread layer can drop in.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct pthread_mutex_t {
    pub locked: u32,
    pub _pad:   u32,
    pub owner:  u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct pthread_mutexattr_t {
    pub kind: c_int,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct pthread_attr_t {
    pub _opaque: [u8; 56],
}

impl Default for pthread_attr_t {
    fn default() -> Self { Self { _opaque: [0; 56] } }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct pthread_cond_t {
    pub _opaque: [u8; 48],
}

impl Default for pthread_cond_t {
    fn default() -> Self { Self { _opaque: [0; 48] } }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct pthread_condattr_t {
    pub _opaque: [u8; 4],
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct pthread_rwlock_t {
    pub _opaque: [u8; 56],
}

impl Default for pthread_rwlock_t {
    fn default() -> Self { Self { _opaque: [0; 56] } }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct pthread_once_t {
    /// 0 = not yet run, 1 = run.
    pub state: u32,
}

pub const PTHREAD_ONCE_INIT: pthread_once_t = pthread_once_t { state: 0 };

/// Opaque key index. We store one i32 instead of an arbitrary
/// pointer-typed slot so the layout is C-compatible without
/// importing `c_void` here.
pub type pthread_key_t = u32;

const MAX_KEYS: usize = 32;
static mut TLS_VALUES: [usize; MAX_KEYS] = [0; MAX_KEYS];
static mut TLS_USED:   [bool; MAX_KEYS]  = [false; MAX_KEYS];

// ── thread identity ─────────────────────────────────────────────────

/// `pthread_self()` — return [`MAIN_THREAD`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_self() -> pthread_t {
    MAIN_THREAD
}

/// `pthread_equal(a, b)` — non-zero iff equal. Single-threaded so
/// every id compared against `pthread_self` matches.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_equal(a: pthread_t, b: pthread_t) -> c_int {
    (a == b) as c_int
}

// ── pthread_create / join (refuse honestly) ─────────────────────────

/// `pthread_create` — refuses with `EAGAIN`. Programs that wanted
/// real threads need a kernel-side thread spawn; we don't have one.
///
/// # Safety
/// Pointer arguments are not dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_create(
    _thread:    *mut pthread_t,
    _attr:      *const pthread_attr_t,
    _start_rtn: extern "C" fn(*mut core::ffi::c_void) -> *mut core::ffi::c_void,
    _arg:       *mut core::ffi::c_void,
) -> c_int {
    EAGAIN
}

/// `pthread_join(thread, retval)` — there is nothing to join. We
/// pretend the thread already returned with NULL.
///
/// # Safety
/// `retval`, when non-null, must be a writable `*mut *mut c_void`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_join(
    _thread: pthread_t,
    retval:  *mut *mut core::ffi::c_void,
) -> c_int {
    if !retval.is_null() {
        // SAFETY: caller-supplied writable slot.
        unsafe { *retval = core::ptr::null_mut(); }
    }
    0
}

/// `pthread_detach(thread)` — no-op success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_detach(_thread: pthread_t) -> c_int {
    0
}

// ── attributes ──────────────────────────────────────────────────────

/// `pthread_attr_init(attr)` — clears the structure.
///
/// # Safety
/// `attr` must be a writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_init(attr: *mut pthread_attr_t) -> c_int {
    if attr.is_null() { return -1; }
    // SAFETY: caller-supplied.
    unsafe { *attr = pthread_attr_t::default(); }
    0
}

/// `pthread_attr_destroy(attr)` — no-op success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_destroy(_attr: *mut pthread_attr_t) -> c_int {
    0
}

// ── mutex ───────────────────────────────────────────────────────────

/// `pthread_mutex_init(mutex, attr)` — zero the struct.
///
/// # Safety
/// `mutex` must be a writable `*mut pthread_mutex_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_init(
    mutex: *mut pthread_mutex_t,
    _attr: *const pthread_mutexattr_t,
) -> c_int {
    if mutex.is_null() { return -1; }
    // SAFETY: caller-supplied.
    unsafe { *mutex = pthread_mutex_t::default(); }
    0
}

/// `pthread_mutex_destroy(mutex)` — no-op success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_destroy(_mutex: *mut pthread_mutex_t) -> c_int {
    0
}

/// `pthread_mutex_lock(mutex)` — bump the lock counter. Single-
/// threaded so we never block.
///
/// # Safety
/// `mutex` must be a valid writable `*mut pthread_mutex_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_lock(mutex: *mut pthread_mutex_t) -> c_int {
    if mutex.is_null() { return -1; }
    // SAFETY: caller-supplied; single-threaded races impossible.
    unsafe {
        (*mutex).locked = (*mutex).locked.wrapping_add(1);
        (*mutex).owner  = MAIN_THREAD;
    }
    0
}

/// `pthread_mutex_trylock(mutex)` — same as lock under single-
/// threaded model (always succeeds).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_trylock(mutex: *mut pthread_mutex_t) -> c_int {
    // SAFETY: forwarded.
    unsafe { pthread_mutex_lock(mutex) }
}

/// `pthread_mutex_unlock(mutex)` — decrement the counter. We do
/// not surface "unlock of unlocked" as an error to keep the
/// behaviour permissive for libstdc++ early-init paths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_unlock(mutex: *mut pthread_mutex_t) -> c_int {
    if mutex.is_null() { return -1; }
    // SAFETY: caller-supplied.
    unsafe {
        if (*mutex).locked > 0 {
            (*mutex).locked -= 1;
        }
        if (*mutex).locked == 0 {
            (*mutex).owner = 0;
        }
    }
    0
}

// ── pthread_once ────────────────────────────────────────────────────

/// `pthread_once(control, init_routine)` — invoke `init_routine`
/// the first time the matching control is observed. Subsequent
/// calls are no-ops. Single-threaded so the CAS dance is just a
/// compare-and-store.
///
/// # Safety
/// `control` must be a valid `*mut pthread_once_t`; `init_routine`
/// must be a callable `extern "C" fn()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_once(
    control:      *mut pthread_once_t,
    init_routine: extern "C" fn(),
) -> c_int {
    if control.is_null() { return -1; }
    // SAFETY: caller-supplied valid pointer.
    unsafe {
        if (*control).state == 0 {
            (*control).state = 1;
            init_routine();
        }
    }
    0
}

// ── pthread_key (TLS) ───────────────────────────────────────────────

/// `pthread_key_create(key, destructor)` — allocate the next free
/// slot in the static key table. The destructor callback is
/// recorded but never fires (we have no thread-exit hook).
///
/// # Safety
/// `key` must be a writable `*mut pthread_key_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_key_create(
    key:        *mut pthread_key_t,
    _destructor:Option<extern "C" fn(*mut core::ffi::c_void)>,
) -> c_int {
    if key.is_null() { return -1; }
    // SAFETY: single-threaded user mode.
    unsafe {
        for i in 0..MAX_KEYS {
            if !TLS_USED[i] {
                TLS_USED[i] = true;
                TLS_VALUES[i] = 0;
                *key = i as pthread_key_t;
                return 0;
            }
        }
    }
    EAGAIN
}

/// `pthread_key_delete(key)` — release the slot.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_key_delete(key: pthread_key_t) -> c_int {
    let i = key as usize;
    if i >= MAX_KEYS { return -1; }
    // SAFETY: single-threaded.
    unsafe {
        TLS_USED[i] = false;
        TLS_VALUES[i] = 0;
    }
    0
}

/// `pthread_setspecific(key, value)` — store `value` in the slot.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_setspecific(
    key:   pthread_key_t,
    value: *const core::ffi::c_void,
) -> c_int {
    let i = key as usize;
    if i >= MAX_KEYS { return -1; }
    // SAFETY: single-threaded.
    unsafe {
        if !TLS_USED[i] { return -1; }
        TLS_VALUES[i] = value as usize;
    }
    0
}

/// `pthread_getspecific(key)` — read the slot. Returns NULL for
/// unset / out-of-range keys.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_getspecific(key: pthread_key_t) -> *mut core::ffi::c_void {
    let i = key as usize;
    if i >= MAX_KEYS { return core::ptr::null_mut(); }
    // SAFETY: single-threaded.
    unsafe {
        if !TLS_USED[i] { return core::ptr::null_mut(); }
        TLS_VALUES[i] as *mut core::ffi::c_void
    }
}
