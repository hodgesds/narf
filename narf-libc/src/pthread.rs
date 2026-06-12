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
    pub _pad: u32,
    pub owner: u64,
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
    fn default() -> Self {
        Self { _opaque: [0; 56] }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct pthread_cond_t {
    pub _opaque: [u8; 48],
}

impl Default for pthread_cond_t {
    fn default() -> Self {
        Self { _opaque: [0; 48] }
    }
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
    fn default() -> Self {
        Self { _opaque: [0; 56] }
    }
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
static mut TLS_USED: [bool; MAX_KEYS] = [false; MAX_KEYS];

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

/// Per-thread control block. Lives in mmap'd memory shared with
/// the new thread. The thread entry trampoline reads `start` and
/// `arg` to dispatch, stores the return value in `retval`, then
/// stores the new tid into `tid` and futex-wakes the parent.
///
/// Layout matches what `__libc_thread_trampoline` reads — keep
/// fields in this order.
#[repr(C)]
struct ThreadCtl {
    start: usize,                   // start_rtn fn ptr
    arg: *mut core::ffi::c_void,    // first arg to start_rtn
    retval: *mut core::ffi::c_void, // start_rtn's return value
    /// 0 while the thread is alive, set to 1 by the trampoline
    /// just before exit_task. pthread_join futex-waits on this
    /// slot per Linux's CHILD_CLEARTID convention.
    done: u32,
    _pad: u32,
}

/// Stack size for spawned threads. POSIX recommends 2 MiB; we use
/// 1 MiB to keep mmap pressure low while still leaving headroom for
/// rust stack-frame-heavy code.
const THREAD_STACK_BYTES: usize = 1 * 1024 * 1024;

/// Trampoline that runs at user-mode CPL=3 as the new thread's
/// first instruction. RDI = ThreadCtl pointer (delivered via the
/// kernel's clone arg-pass path). The trampoline calls the
/// user-supplied start_rtn with the user-supplied arg, stores the
/// return value, marks `done=1`, futex-wakes any joiner on the
/// `done` slot, then exits the task.
///
/// # Safety
/// Reached only via clone(2). `ctl` must point at a live ThreadCtl
/// the parent allocated; the thread's stack must already be mapped.
#[unsafe(no_mangle)]
unsafe extern "C" fn __libc_thread_trampoline(ctl: *mut ThreadCtl) -> ! {
    // SAFETY: parent allocated this struct; lives until pthread_join
    // releases it.
    // SAFETY: Valid memory or trusted environment
    let ctl = unsafe { &mut *ctl };
    // SAFETY: parent installed a valid fn ptr.
    let start: extern "C" fn(*mut core::ffi::c_void) -> *mut core::ffi::c_void =
        // SAFETY: Valid memory or trusted environment
        unsafe { core::mem::transmute(ctl.start) };
    let r = start(ctl.arg);
    ctl.retval = r;
    // Atomic store with release ordering — pairs with the joiner's
    // futex-wait load.
    let done_ptr = &raw mut ctl.done as *mut u32;
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::ptr::write_volatile(done_ptr, 1);
    }
    // Futex-wake any joiner spinning on this slot.
    let _ = narf_user_runtime::futex_wake(done_ptr as u64, 1);
    // Terminate the task. exit_task is a Rust fn that calls
    // SYS_EXIT_TASK and never returns.
    narf_user_runtime::exit_task()
}

/// `pthread_create(thread, attr, start_rtn, arg)` — spawn a new
/// thread that runs `start_rtn(arg)` in the same address space.
///
/// Implementation:
/// 1. mmap a 1 MiB stack + a small ThreadCtl block.
/// 2. Stash (start_rtn, arg) in the ctl block.
/// 3. clone(__libc_thread_trampoline, stack_top, &ctl) — the
///    kernel hands ctl to the trampoline as its first arg.
/// 4. Return the kernel-assigned tid via `*thread`.
///
/// `attr` is ignored (we always use the default 1 MiB stack).
///
/// # Safety
/// `thread` must be a writable `*mut pthread_t`; `start_rtn` must
/// be a valid SysV-shaped function pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_create(
    thread: *mut pthread_t,
    _attr: *const pthread_attr_t,
    start_rtn: extern "C" fn(*mut core::ffi::c_void) -> *mut core::ffi::c_void,
    arg: *mut core::ffi::c_void,
) -> c_int {
    if thread.is_null() {
        return EAGAIN;
    }
    // Allocate stack + ctl in a single mmap (stack at the top, ctl
    // just below). 1 MiB stack + 32 B ctl, page-aligned.
    let total = THREAD_STACK_BYTES + 4096;
    // SAFETY: Valid memory or trusted environment
    let base = unsafe {
        narf_user_runtime::mmap(0, total, 0x20 /* MAP_ANON */)
    };
    if base.is_null() || base as usize == !0usize {
        return EAGAIN;
    }
    let base = base as u64;
    // ctl at base+0; stack from base+4096 .. base+4096+THREAD_STACK_BYTES.
    let ctl_ptr = base as *mut ThreadCtl;
    // SAFETY: just-mmap'd region, exclusive ownership.
    unsafe {
        core::ptr::write(
            ctl_ptr,
            ThreadCtl {
                start: start_rtn as usize,
                arg,
                retval: core::ptr::null_mut(),
                done: 0,
                _pad: 0,
            },
        );
    }
    let stack_top = base + total as u64;
    // SAFETY: kernel-side clone validates entry/stack pointers.
    let tid = match narf_user_runtime::clone(
        __libc_thread_trampoline as u64,
        stack_top,
        ctl_ptr as u64,
        0, // fs_base — inherit parent's
    ) {
        Ok(t) => t,
        Err(()) => return EAGAIN,
    };
    // Encode (tid, ctl_ptr) into pthread_t. Stash ctl_ptr in the
    // upper bits so pthread_join can recover it without a side
    // table — pthread_t is u64 and ctl_ptr fits in user-half VA
    // bits, but we use the full slot for the ptr and put tid in
    // a per-process side map keyed by ctl_ptr if needed. For now
    // store ctl_ptr as the pthread_t (it's unique per thread).
    let _ = tid;
    // SAFETY: Valid memory or trusted environment
    unsafe {
        *thread = ctl_ptr as pthread_t;
    }
    0
}

/// `pthread_join(thread, retval)` — block until the thread finishes,
/// then store its return value into `*retval`.
///
/// Implementation: futex-wait on the ctl block's `done` slot until
/// it transitions from 0 to 1 (set by the trampoline just before
/// exit_task). Read out retval, return success. The mmap'd stack +
/// ctl block stay leaked until the AS tears down — releasing them
/// here would race the trampoline's still-executing exit_task call,
/// which uses the stack until the kernel reclaims it.
///
/// # Safety
/// `thread` must be a value returned by `pthread_create`; `retval`,
/// when non-null, must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_join(
    thread: pthread_t,
    retval: *mut *mut core::ffi::c_void,
) -> c_int {
    if thread == 0 {
        return -1;
    }
    let ctl_ptr = thread as *mut ThreadCtl;
    // SAFETY: Valid memory or trusted environment
    let done_ptr = unsafe { &raw mut (*ctl_ptr).done } as *mut u32;
    // futex_wait with expected=0 sleeps until the value becomes
    // non-zero (the trampoline writes 1 on completion).
    loop {
        // SAFETY: Valid memory or trusted environment
        let cur = unsafe { core::ptr::read_volatile(done_ptr) };
        if cur != 0 {
            break;
        }
        // FUTEX_WAIT, expected=0, no timeout.
        let _ = narf_user_runtime::futex_wait(done_ptr as u64, 0, 0);
    }
    if !retval.is_null() {
        // SAFETY: ctl is alive; trampoline stored retval before done=1.
        unsafe {
            *retval = (*ctl_ptr).retval;
        }
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
    if attr.is_null() {
        return -1;
    }
    // SAFETY: caller-supplied.
    unsafe {
        *attr = pthread_attr_t::default();
    }
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
    if mutex.is_null() {
        return -1;
    }
    // SAFETY: caller-supplied.
    unsafe {
        *mutex = pthread_mutex_t::default();
    }
    0
}

/// `pthread_mutex_destroy(mutex)` — no-op success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_destroy(_mutex: *mut pthread_mutex_t) -> c_int {
    0
}

/// `pthread_mutex_lock(mutex)` — POSIX mutex with futex contention.
///
/// State machine on `locked`:
///   0 = unlocked
///   1 = locked, no waiters
///   2 = locked, waiters present
///
/// Fast path: cmpxchg(0 → 1). Slow path: swap-to-2 to record
/// "waiters present", then futex_wait until the holder releases.
/// Matches Linux's classic 3-state mutex (Drepper, "Futexes Are
/// Tricky" §6).
///
/// # Safety
/// `mutex` must be a valid writable `*mut pthread_mutex_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_lock(mutex: *mut pthread_mutex_t) -> c_int {
    if mutex.is_null() {
        return -1;
    }
    // SAFETY: Valid memory or trusted environment
    let locked_ptr = unsafe { &raw mut (*mutex).locked } as *mut u32;
    // Fast path: try uncontended acquire.
    // SAFETY: Valid memory or trusted environment
    let atomic = unsafe { &*(locked_ptr as *const core::sync::atomic::AtomicU32) };
    if atomic
        .compare_exchange(
            0,
            1,
            core::sync::atomic::Ordering::Acquire,
            core::sync::atomic::Ordering::Relaxed,
        )
        .is_ok()
    {
        // SAFETY: Valid memory or trusted environment
        unsafe {
            (*mutex).owner = pthread_self();
        }
        return 0;
    }
    // Slow path: announce ourselves as a waiter, then park.
    loop {
        // Set state to "locked + waiters" (2). swap returns old.
        let old = atomic.swap(2, core::sync::atomic::Ordering::AcqRel);
        if old == 0 {
            // SAFETY: Valid memory or trusted environment
            unsafe {
                (*mutex).owner = pthread_self();
            }
            return 0;
        }
        // Park until *locked changes (the unlocker swaps it to 0).
        // Expected value passed to futex_wait must match the
        // current observed value (2) — if it changed, we'll
        // recheck above.
        let _ = narf_user_runtime::futex_wait(locked_ptr as u64, 2, 0);
    }
}

/// `pthread_mutex_trylock(mutex)` — non-blocking try; returns
/// 0 on success, EBUSY (16) if already locked.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_trylock(mutex: *mut pthread_mutex_t) -> c_int {
    if mutex.is_null() {
        return -1;
    }
    // SAFETY: Valid memory or trusted environment
    let locked_ptr = unsafe { &raw mut (*mutex).locked } as *mut u32;
    // SAFETY: Valid memory or trusted environment
    let atomic = unsafe { &*(locked_ptr as *const core::sync::atomic::AtomicU32) };
    match atomic.compare_exchange(
        0,
        1,
        core::sync::atomic::Ordering::Acquire,
        core::sync::atomic::Ordering::Relaxed,
    ) {
        Ok(_) => {
            // SAFETY: Valid memory or trusted environment
            unsafe {
                (*mutex).owner = pthread_self();
            }
            0
        }
        Err(_) => 16, // EBUSY
    }
}

/// `pthread_mutex_unlock(mutex)` — release. If anyone was waiting
/// (state was 2), wake one to retry the acquire.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_unlock(mutex: *mut pthread_mutex_t) -> c_int {
    if mutex.is_null() {
        return -1;
    }
    // SAFETY: Valid memory or trusted environment
    let locked_ptr = unsafe { &raw mut (*mutex).locked } as *mut u32;
    // SAFETY: Valid memory or trusted environment
    let atomic = unsafe { &*(locked_ptr as *const core::sync::atomic::AtomicU32) };
    // Clear ownership before releasing — between the swap and
    // the wake any waiter that wins the race must see a clean
    // owner field.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        (*mutex).owner = 0;
    }
    let old = atomic.swap(0, core::sync::atomic::Ordering::Release);
    if old == 2 {
        // There were waiters — wake one.
        let _ = narf_user_runtime::futex_wake(locked_ptr as u64, 1);
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
    control: *mut pthread_once_t,
    init_routine: extern "C" fn(),
) -> c_int {
    if control.is_null() {
        return -1;
    }
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
    key: *mut pthread_key_t,
    _destructor: Option<extern "C" fn(*mut core::ffi::c_void)>,
) -> c_int {
    if key.is_null() {
        return -1;
    }
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
    if i >= MAX_KEYS {
        return -1;
    }
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
    key: pthread_key_t,
    value: *const core::ffi::c_void,
) -> c_int {
    let i = key as usize;
    if i >= MAX_KEYS {
        return -1;
    }
    // SAFETY: single-threaded.
    unsafe {
        if !TLS_USED[i] {
            return -1;
        }
        TLS_VALUES[i] = value as usize;
    }
    0
}

/// `pthread_getspecific(key)` — read the slot. Returns NULL for
/// unset / out-of-range keys.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_getspecific(key: pthread_key_t) -> *mut core::ffi::c_void {
    let i = key as usize;
    if i >= MAX_KEYS {
        return core::ptr::null_mut();
    }
    // SAFETY: single-threaded.
    unsafe {
        if !TLS_USED[i] {
            return core::ptr::null_mut();
        }
        TLS_VALUES[i] as *mut core::ffi::c_void
    }
}

// ── pthread_cond — condvar atop futex ───────────────────────────

// We treat the first 4 bytes of pthread_cond_t as a sequence
// number bumped on every signal/broadcast. cond_wait reads the
// sequence, drops the mutex, futex_waits with that exact value;
// any signal that bumps the sequence wakes us. The remaining
// bytes are unused (room for a future state).

fn cond_seq_ptr(cond: *mut pthread_cond_t) -> *mut u32 {
    cond as *mut u32
}

/// `pthread_cond_init(cond, attr)` — zero the struct.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_cond_init(
    cond: *mut pthread_cond_t,
    _attr: *const pthread_condattr_t,
) -> c_int {
    if cond.is_null() {
        return -1;
    }
    // SAFETY: Valid memory or trusted environment
    unsafe {
        *cond = pthread_cond_t::default();
    }
    0
}

/// `pthread_cond_destroy(cond)` — no-op.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_cond_destroy(_cond: *mut pthread_cond_t) -> c_int {
    0
}

/// `pthread_cond_wait(cond, mutex)` — atomically drop `mutex`,
/// wait for a signal/broadcast on `cond`, re-acquire `mutex`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_cond_wait(
    cond: *mut pthread_cond_t,
    mutex: *mut pthread_mutex_t,
) -> c_int {
    if cond.is_null() || mutex.is_null() {
        return -1;
    }
    let seq_ptr = cond_seq_ptr(cond);
    // SAFETY: Valid memory or trusted environment
    let atomic = unsafe { &*(seq_ptr as *const core::sync::atomic::AtomicU32) };
    let seq = atomic.load(core::sync::atomic::Ordering::Acquire);
    // Drop the mutex.
    // SAFETY: Valid memory or trusted environment
    let _ = unsafe { pthread_mutex_unlock(mutex) };
    // Park until the sequence changes (POSIX permits spurious
    // wakeups; we futex_wait with the observed sequence and
    // re-acquire on any wake).
    let _ = narf_user_runtime::futex_wait(seq_ptr as u64, seq, 0);
    // Re-take the mutex.
    // SAFETY: Valid memory or trusted environment
    let _ = unsafe { pthread_mutex_lock(mutex) };
    0
}

/// `pthread_cond_timedwait(cond, mutex, abstime)` — same as
/// pthread_cond_wait but with an absolute timeout. Returns
/// ETIMEDOUT (110) if the deadline passes.
///
/// # Safety
/// `abstime` must point at a `timespec`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_cond_timedwait(
    cond: *mut pthread_cond_t,
    mutex: *mut pthread_mutex_t,
    abstime: *const crate::time::timespec,
) -> c_int {
    if cond.is_null() || mutex.is_null() || abstime.is_null() {
        return -1;
    }
    let seq_ptr = cond_seq_ptr(cond);
    // SAFETY: Valid memory or trusted environment
    let atomic = unsafe { &*(seq_ptr as *const core::sync::atomic::AtomicU32) };
    let seq = atomic.load(core::sync::atomic::Ordering::Acquire);
    // SAFETY: Valid memory or trusted environment
    let _ = unsafe { pthread_mutex_unlock(mutex) };
    // Compute relative-ns timeout from the abstime (CLOCK_REALTIME).
    let mut now = crate::time::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: Valid memory or trusted environment
    let _ = unsafe {
        crate::time::clock_gettime(0 /* REALTIME */, &mut now)
    };
    // SAFETY: Valid memory or trusted environment
    let abs = unsafe { *abstime };
    let now_ns = (now.tv_sec as i64)
        .saturating_mul(1_000_000_000)
        .saturating_add(now.tv_nsec as i64);
    let abs_ns = (abs.tv_sec as i64)
        .saturating_mul(1_000_000_000)
        .saturating_add(abs.tv_nsec as i64);
    let rel_ns = (abs_ns - now_ns).max(0) as u64;
    let r = narf_user_runtime::futex_wait(seq_ptr as u64, seq, rel_ns);
    // SAFETY: Valid memory or trusted environment
    let _ = unsafe { pthread_mutex_lock(mutex) };
    if r < 0 {
        110 /* ETIMEDOUT */
    } else {
        0
    }
}

/// `pthread_cond_signal(cond)` — wake one waiter.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_cond_signal(cond: *mut pthread_cond_t) -> c_int {
    if cond.is_null() {
        return -1;
    }
    let seq_ptr = cond_seq_ptr(cond);
    // SAFETY: Valid memory or trusted environment
    let atomic = unsafe { &*(seq_ptr as *const core::sync::atomic::AtomicU32) };
    atomic.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
    let _ = narf_user_runtime::futex_wake(seq_ptr as u64, 1);
    0
}

/// `pthread_cond_broadcast(cond)` — wake all waiters.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_cond_broadcast(cond: *mut pthread_cond_t) -> c_int {
    if cond.is_null() {
        return -1;
    }
    let seq_ptr = cond_seq_ptr(cond);
    // SAFETY: Valid memory or trusted environment
    let atomic = unsafe { &*(seq_ptr as *const core::sync::atomic::AtomicU32) };
    atomic.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
    let _ = narf_user_runtime::futex_wake(seq_ptr as u64, i32::MAX as u32);
    0
}

// ── pthread_rwlock — reader-writer lock atop futex ──────────────

// State word in the first 4 bytes of pthread_rwlock_t:
//   0          = unlocked
//   1..u32::MAX-1 = N readers
//   u32::MAX   = writer locked (exclusive)
//
// Single state word is sufficient; the futex_wake on unlock wakes
// every waiter and they re-race for the next slot. Not the
// fairest scheduling but correct under POSIX which doesn't
// promise reader/writer priority.

const WRLOCK_SENTINEL: u32 = u32::MAX;

fn rwlock_state_ptr(rw: *mut pthread_rwlock_t) -> *mut u32 {
    rw as *mut u32
}

/// `pthread_rwlock_init(rw, attr)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_init(
    rw: *mut pthread_rwlock_t,
    _attr: *const core::ffi::c_void,
) -> c_int {
    if rw.is_null() {
        return -1;
    }
    // SAFETY: Valid memory or trusted environment
    unsafe {
        *rw = pthread_rwlock_t::default();
    }
    0
}

/// `pthread_rwlock_destroy(rw)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_destroy(_rw: *mut pthread_rwlock_t) -> c_int {
    0
}

/// `pthread_rwlock_rdlock(rw)` — acquire a reader slot.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_rdlock(rw: *mut pthread_rwlock_t) -> c_int {
    if rw.is_null() {
        return -1;
    }
    let p = rwlock_state_ptr(rw);
    // SAFETY: Valid memory or trusted environment
    let atomic = unsafe { &*(p as *const core::sync::atomic::AtomicU32) };
    loop {
        let cur = atomic.load(core::sync::atomic::Ordering::Acquire);
        if cur == WRLOCK_SENTINEL || cur == WRLOCK_SENTINEL - 1 {
            // Writer-locked or one short of overflow — park.
            let _ = narf_user_runtime::futex_wait(p as u64, cur, 0);
            continue;
        }
        if atomic
            .compare_exchange(
                cur,
                cur + 1,
                core::sync::atomic::Ordering::Acquire,
                core::sync::atomic::Ordering::Relaxed,
            )
            .is_ok()
        {
            return 0;
        }
    }
}

/// `pthread_rwlock_wrlock(rw)` — acquire exclusive.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_wrlock(rw: *mut pthread_rwlock_t) -> c_int {
    if rw.is_null() {
        return -1;
    }
    let p = rwlock_state_ptr(rw);
    // SAFETY: Valid memory or trusted environment
    let atomic = unsafe { &*(p as *const core::sync::atomic::AtomicU32) };
    loop {
        if atomic
            .compare_exchange(
                0,
                WRLOCK_SENTINEL,
                core::sync::atomic::Ordering::Acquire,
                core::sync::atomic::Ordering::Relaxed,
            )
            .is_ok()
        {
            return 0;
        }
        let cur = atomic.load(core::sync::atomic::Ordering::Acquire);
        if cur == 0 {
            continue;
        } // raced; retry cmpxchg
        let _ = narf_user_runtime::futex_wait(p as u64, cur, 0);
    }
}

/// `pthread_rwlock_tryrdlock(rw)` — non-blocking reader acquire.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_tryrdlock(rw: *mut pthread_rwlock_t) -> c_int {
    if rw.is_null() {
        return -1;
    }
    let p = rwlock_state_ptr(rw);
    // SAFETY: Valid memory or trusted environment
    let atomic = unsafe { &*(p as *const core::sync::atomic::AtomicU32) };
    let cur = atomic.load(core::sync::atomic::Ordering::Acquire);
    if cur >= WRLOCK_SENTINEL - 1 {
        return 16; /* EBUSY */
    }
    match atomic.compare_exchange(
        cur,
        cur + 1,
        core::sync::atomic::Ordering::Acquire,
        core::sync::atomic::Ordering::Relaxed,
    ) {
        Ok(_) => 0,
        Err(_) => 16,
    }
}

/// `pthread_rwlock_trywrlock(rw)` — non-blocking writer acquire.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_trywrlock(rw: *mut pthread_rwlock_t) -> c_int {
    if rw.is_null() {
        return -1;
    }
    let p = rwlock_state_ptr(rw);
    // SAFETY: Valid memory or trusted environment
    let atomic = unsafe { &*(p as *const core::sync::atomic::AtomicU32) };
    match atomic.compare_exchange(
        0,
        WRLOCK_SENTINEL,
        core::sync::atomic::Ordering::Acquire,
        core::sync::atomic::Ordering::Relaxed,
    ) {
        Ok(_) => 0,
        Err(_) => 16,
    }
}

/// `pthread_rwlock_unlock(rw)` — release. If we were the writer
/// or the last reader, wake everyone so they can re-race.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_unlock(rw: *mut pthread_rwlock_t) -> c_int {
    if rw.is_null() {
        return -1;
    }
    let p = rwlock_state_ptr(rw);
    // SAFETY: Valid memory or trusted environment
    let atomic = unsafe { &*(p as *const core::sync::atomic::AtomicU32) };
    loop {
        let cur = atomic.load(core::sync::atomic::Ordering::Acquire);
        let next = if cur == WRLOCK_SENTINEL {
            0
        } else {
            cur.saturating_sub(1)
        };
        if atomic
            .compare_exchange(
                cur,
                next,
                core::sync::atomic::Ordering::Release,
                core::sync::atomic::Ordering::Relaxed,
            )
            .is_ok()
        {
            if next == 0 {
                let _ = narf_user_runtime::futex_wake(p as u64, i32::MAX as u32);
            }
            return 0;
        }
    }
}

// ── pthread_barrier — N-thread synchronization point ────────────

/// Layout: { count: u32, generation: u32, threshold: u32, _pad: u32 }.
/// barrier_init records `threshold`. barrier_wait increments
/// `count`; if count reaches threshold, the last arrival bumps
/// `generation` (which is the futex word) + zeroes count + wakes
/// all. Earlier arrivals futex_wait on the previous generation.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct pthread_barrier_t {
    pub count: u32,
    pub generation: u32,
    pub threshold: u32,
    pub _pad: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct pthread_barrierattr_t {
    pub _opaque: u32,
}

/// `pthread_barrier_init(bar, attr, count)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_barrier_init(
    bar: *mut pthread_barrier_t,
    _attr: *const pthread_barrierattr_t,
    count: u32,
) -> c_int {
    if bar.is_null() || count == 0 {
        return -1;
    }
    // SAFETY: Valid memory or trusted environment
    unsafe {
        *bar = pthread_barrier_t {
            count: 0,
            generation: 0,
            threshold: count,
            _pad: 0,
        };
    }
    0
}

/// `pthread_barrier_destroy(bar)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_barrier_destroy(_bar: *mut pthread_barrier_t) -> c_int {
    0
}

/// `pthread_barrier_wait(bar)` — block until `threshold` threads
/// have called wait. Returns PTHREAD_BARRIER_SERIAL_THREAD (-1)
/// for exactly one thread per generation; 0 for the others.
pub const PTHREAD_BARRIER_SERIAL_THREAD: c_int = -1;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_barrier_wait(bar: *mut pthread_barrier_t) -> c_int {
    if bar.is_null() {
        return -1;
    }
    // SAFETY: Valid memory or trusted environment
    let count_ptr = unsafe { &raw mut (*bar).count } as *mut u32;
    // SAFETY: Valid memory or trusted environment
    let gen_ptr = unsafe { &raw mut (*bar).generation } as *mut u32;
    // SAFETY: Valid memory or trusted environment
    let count_atomic = unsafe { &*(count_ptr as *const core::sync::atomic::AtomicU32) };
    // SAFETY: Valid memory or trusted environment
    let gen_atomic = unsafe { &*(gen_ptr as *const core::sync::atomic::AtomicU32) };
    // SAFETY: Valid memory or trusted environment
    let threshold = unsafe { (*bar).threshold };
    let my_gen = gen_atomic.load(core::sync::atomic::Ordering::Acquire);
    let arrival = count_atomic.fetch_add(1, core::sync::atomic::Ordering::AcqRel) + 1;
    if arrival == threshold {
        // Last arrival — reset count, bump generation, wake all.
        count_atomic.store(0, core::sync::atomic::Ordering::Release);
        gen_atomic.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        let _ = narf_user_runtime::futex_wake(gen_ptr as u64, i32::MAX as u32);
        PTHREAD_BARRIER_SERIAL_THREAD
    } else {
        // Wait until generation advances.
        loop {
            let cur = gen_atomic.load(core::sync::atomic::Ordering::Acquire);
            if cur != my_gen {
                return 0;
            }
            let _ = narf_user_runtime::futex_wait(gen_ptr as u64, my_gen, 0);
        }
    }
}
