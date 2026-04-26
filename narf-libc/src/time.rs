//! Time surface: `clock_gettime` / `time` / `gettimeofday`.
//!
//! All three resolve to the same kernel monotonic clock today. Stage-4
//! has no realtime / wall-clock distinction — the kernel only exposes
//! a single nanosecond counter — so `clock_id` is accepted and ignored.
//! When a real RT clock lands the dispatch will fan out per id.

#![allow(non_camel_case_types)]

pub type time_t      = i64;
pub type suseconds_t = i64;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct timespec {
    pub tv_sec:  time_t,
    pub tv_nsec: i64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct timeval {
    pub tv_sec:  time_t,
    pub tv_usec: suseconds_t,
}

/// `clock_gettime(clk_id, *mut timespec)`. Returns 0 on success,
/// -1 if `tp` is null. `clk_id` is currently ignored; all clocks
/// alias to the kernel monotonic counter.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn clock_gettime(clk_id: i32, tp: *mut timespec) -> i32 {
    if tp.is_null() {
        return -1;
    }
    let (sec, nsec) = narf_user_runtime::clock_gettime(clk_id as u32);
    // SAFETY: caller supplies a writable timespec; we write one.
    unsafe {
        (*tp).tv_sec  = sec;
        (*tp).tv_nsec = nsec;
    }
    0
}

/// `time(*mut time_t)`. Returns the current second count and, if
/// `t` is non-null, also writes it through the pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn time(t: *mut time_t) -> time_t {
    let (sec, _nsec) = narf_user_runtime::clock_gettime(0);
    if !t.is_null() {
        // SAFETY: caller-supplied writable `time_t`.
        unsafe { *t = sec; }
    }
    sec
}

/// `gettimeofday(*mut timeval, *mut c_void)`. The second argument is
/// the legacy `struct timezone *` — POSIX deprecated it; we ignore
/// it. Returns 0 on success, -1 if `tv` is null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gettimeofday(
    tv: *mut timeval,
    _tz: *mut core::ffi::c_void,
) -> i32 {
    if tv.is_null() {
        return -1;
    }
    let (sec, nsec) = narf_user_runtime::clock_gettime(0);
    // SAFETY: caller supplies a writable timeval.
    unsafe {
        (*tv).tv_sec  = sec;
        (*tv).tv_usec = nsec / 1_000;
    }
    0
}
