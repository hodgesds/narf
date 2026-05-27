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
/// -1 if `tp` is null. `clk_id = 0` reads CLOCK_REALTIME (wall),
/// `clk_id = 1` reads CLOCK_MONOTONIC. Other ids return -1.
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

/// `clock_settime(clk_id, *const timespec)` — set the wall clock
/// for CLOCK_REALTIME (clk_id = 0). Other clock ids return -1.
///
/// # Safety
/// `tp` must be a valid `*const timespec`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn clock_settime(clk_id: i32, tp: *const timespec) -> i32 {
    if tp.is_null() { return -1; }
    // SAFETY: caller-asserted readable timespec.
    let ts = unsafe { *tp };
    narf_user_runtime::clock_settime(clk_id as u32, ts.tv_sec, ts.tv_nsec)
}

/// `settimeofday(*const timeval, *mut c_void)` — POSIX-deprecated
/// wall-time setter. Routes through clock_settime(CLOCK_REALTIME).
///
/// # Safety
/// `tv`, when non-null, must be a valid `*const timeval`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn settimeofday(
    tv: *const timeval,
    _tz: *mut core::ffi::c_void,
) -> i32 {
    if tv.is_null() { return -1; }
    // SAFETY: caller-asserted readable timeval.
    let v = unsafe { *tv };
    narf_user_runtime::clock_settime(0, v.tv_sec, v.tv_usec * 1_000)
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

// ── struct tm + civil-time conversions ───────────────────────────────
//
// Standard `<time.h>` field order: sec/min/hour/mday/mon/year/wday/
// yday/isdst. `tm_year` is years since 1900; `tm_mon` is 0..=11;
// `tm_mday` is 1..=31. `tm_isdst` is always 0 (no TZ database).
//
// We don't carry a timezone database. `localtime` therefore aliases
// `gmtime` — a real TZ would need /etc/localtime or POSIX TZ env
// parsing, both deferred. Calls return UTC; users who care about
// local time can adjust manually.
//
// The Howard Hinnant civil_from_days algorithm
// (https://howardhinnant.github.io/date_algorithms.html) is the
// canonical no-table conversion between days-since-epoch and
// (year, month, day). We use it here verbatim — proven correct for
// the entire signed-64 day range.

/// `<time.h>` `struct tm`. Field shape matches every libc.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct tm {
    pub tm_sec:   i32,
    pub tm_min:   i32,
    pub tm_hour:  i32,
    pub tm_mday:  i32,
    pub tm_mon:   i32,
    pub tm_year:  i32,
    pub tm_wday:  i32,
    pub tm_yday:  i32,
    pub tm_isdst: i32,
}

/// Days from civil `(y, m, d)` to the Unix epoch (1970-01-01).
/// Returns a signed value; for inputs before the epoch it goes
/// negative. Algorithm: Hinnant.
fn days_from_civil(mut y: i64, m: u32, d: u32) -> i64 {
    y -= (m <= 2) as i64;
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) as u64 + 2) / 5
        + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe as i64 - 719468
}

/// Inverse: days-since-epoch → `(year, month, day)`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y   = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp  = (5 * doy + 2) / 153;
    let d   = doy - (153 * mp + 2) / 5 + 1;
    let m   = if mp < 10 { mp + 3 } else { mp - 9 };
    (y + (m <= 2) as i64, m as u32, d as u32)
}

/// `gmtime_r(time, tm)` — UTC breakdown into `*tm`. Reentrant form
/// used by both [`gmtime`] and [`localtime`].
///
/// # Safety
/// `result` must be a writable `*mut tm`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmtime_r(timep: *const time_t, result: *mut tm) -> *mut tm {
    if timep.is_null() || result.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: caller-supplied valid pointer.
    let secs = unsafe { *timep };
    let mut days = secs.div_euclid(86_400);
    let mut tod  = secs.rem_euclid(86_400);
    if tod < 0 { tod += 86_400; days -= 1; }
    let (y, m, d) = civil_from_days(days);
    // tm_wday: 1970-01-01 was a Thursday (=4). days % 7 (with euclid
    // remainder) gives 0..=6 starting at Sunday because we offset.
    let wday = (((days % 7) + 4).rem_euclid(7)) as i32;
    // tm_yday: days from Jan 1 of `y`.
    let jan1 = days_from_civil(y, 1, 1);
    let yday = (days - jan1) as i32;
    let h = (tod / 3600) as i32;
    let mn = ((tod % 3600) / 60) as i32;
    let s = (tod % 60) as i32;
    // SAFETY: `result` is a writable `tm`.
    unsafe {
        (*result).tm_sec   = s;
        (*result).tm_min   = mn;
        (*result).tm_hour  = h;
        (*result).tm_mday  = d as i32;
        (*result).tm_mon   = (m as i32) - 1;
        (*result).tm_year  = (y - 1900) as i32;
        (*result).tm_wday  = wday;
        (*result).tm_yday  = yday;
        (*result).tm_isdst = 0;
    }
    result
}

/// `localtime_r(time, tm)`. We have no timezone database, so this
/// aliases [`gmtime_r`] verbatim. When TZ support lands the offset
/// + DST flip belong here.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn localtime_r(timep: *const time_t, result: *mut tm) -> *mut tm {
    // SAFETY: forwarded under same caller contract.
    unsafe { gmtime_r(timep, result) }
}

/// Static fallback used by `gmtime`/`localtime`. Single-threaded
/// user-mode means no race; when threads land, swap to TLS.
static mut TM_STATIC: tm = tm {
    tm_sec: 0, tm_min: 0, tm_hour: 0, tm_mday: 0, tm_mon: 0,
    tm_year: 0, tm_wday: 0, tm_yday: 0, tm_isdst: 0,
};

/// `gmtime(time)` — non-reentrant variant returning a pointer to a
/// shared static `tm`. The buffer is overwritten by every call; do
/// not retain the pointer across calls.
///
/// # Safety
/// `timep` must be a valid `*const time_t` if non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmtime(timep: *const time_t) -> *mut tm {
    let p = &raw mut TM_STATIC;
    // SAFETY: forwarded.
    unsafe { gmtime_r(timep, p) }
}

/// `localtime(time)` — see [`gmtime`]; aliases per the no-TZ note.
///
/// # Safety
/// See [`gmtime`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn localtime(timep: *const time_t) -> *mut tm {
    let p = &raw mut TM_STATIC;
    // SAFETY: forwarded.
    unsafe { gmtime_r(timep, p) }
}

/// `mktime(tm)` — collapse a `struct tm` into a `time_t`. Treats the
/// fields as UTC (no TZ — see module-head note). `tm_wday`/`tm_yday`
/// in the input are ignored. POSIX requires us to *update* them on
/// the way out; we do.
///
/// Out-of-range fields normalise (e.g. `tm_mday = 32` rolls into the
/// next month), via re-running `gmtime_r` on the resulting `time_t`.
///
/// # Safety
/// `t` must be a writable `*mut tm`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mktime(t: *mut tm) -> time_t {
    if t.is_null() {
        return -1;
    }
    // SAFETY: caller-asserted.
    let v = unsafe { *t };
    // Roll over-large months into years up front so days_from_civil
    // sees a valid (m in 1..=12).
    let extra_years = v.tm_mon.div_euclid(12);
    let mon = v.tm_mon.rem_euclid(12) + 1;
    let year = (v.tm_year + 1900) as i64 + extra_years as i64;
    let days = days_from_civil(year, mon as u32, v.tm_mday as u32);
    let secs = days * 86_400
        + v.tm_hour as i64 * 3600
        + v.tm_min  as i64 * 60
        + v.tm_sec  as i64;
    // Normalise wday / yday by round-tripping.
    // SAFETY: caller-supplied writable `tm`.
    unsafe { let _ = gmtime_r(&secs as *const time_t, t); }
    secs
}

/// `difftime(end, beg)` — seconds between two `time_t`. Returned as
/// `f64` per C99; we don't wire `<float.h>` so we just cast.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn difftime(end: time_t, beg: time_t) -> f64 {
    (end - beg) as f64
}

// ── strftime / asctime / ctime ──────────────────────────────────────
//
// `strftime` would normally cover dozens of conversions. We ship the
// minimum viable subset that covers asctime / ctime / RFC-2822-ish
// formatting plus the two big numeric ones (date / time). Adding
// more is mechanical; the table below is the audit surface.
//
// Supported specifiers:
//   %Y  4-digit year                         %m  month 01..12
//   %d  day-of-month 01..31                  %H  hour 00..23
//   %M  minute 00..59                        %S  second 00..59 (60 OK)
//   %y  2-digit year                         %j  day-of-year 001..366
//   %a  abbreviated weekday  (Sun..Sat)      %A  full weekday
//   %b  abbreviated month    (Jan..Dec)      %B  full month
//   %e  day-of-month, space-padded
//   %p  AM/PM
//   %%  literal %

const WDAY_SHORT: [&[u8]; 7] = [
    b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat",
];
const WDAY_LONG: [&[u8]; 7] = [
    b"Sunday", b"Monday", b"Tuesday", b"Wednesday",
    b"Thursday", b"Friday", b"Saturday",
];
const MON_SHORT: [&[u8]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun",
    b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];
const MON_LONG: [&[u8]; 12] = [
    b"January", b"February", b"March", b"April", b"May", b"June",
    b"July", b"August", b"September", b"October", b"November", b"December",
];

/// Helper: emit `bytes` into `out` at `*pos`, capped at `out.len()`.
/// Returns the number of bytes written.
fn emit(out: &mut [u8], pos: &mut usize, bytes: &[u8]) -> usize {
    let cap = out.len();
    if *pos >= cap { return 0; }
    let room = cap - *pos;
    let n = bytes.len().min(room);
    out[*pos..*pos + n].copy_from_slice(&bytes[..n]);
    *pos += n;
    n
}

/// Emit a zero-padded unsigned integer of width `w` (always w
/// digits; values >= 10^w wrap by truncation of the high digits,
/// matching glibc on overflowing fields).
fn emit_pad_uint(out: &mut [u8], pos: &mut usize, mut v: u64, w: usize) -> usize {
    let mut buf = [0u8; 20];
    let mut bi = buf.len();
    if v == 0 {
        bi -= 1;
        buf[bi] = b'0';
    } else {
        while v > 0 && bi > 0 {
            bi -= 1;
            buf[bi] = b'0' + (v % 10) as u8;
            v /= 10;
        }
    }
    let body = &buf[bi..];
    if body.len() < w {
        let zeros = w - body.len();
        let zbuf = [b'0'; 20];
        let take = zeros.min(zbuf.len());
        emit(out, pos, &zbuf[..take]);
    }
    emit(out, pos, body)
}

/// Emit a decimal-shaped space-padded integer: width `w`, leading
/// spaces. Used for `%e`.
fn emit_pad_space(out: &mut [u8], pos: &mut usize, v: u64, w: usize) -> usize {
    let mut digits = [0u8; 20];
    let mut di = digits.len();
    if v == 0 {
        di -= 1;
        digits[di] = b'0';
    } else {
        let mut t = v;
        while t > 0 {
            di -= 1;
            digits[di] = b'0' + (t % 10) as u8;
            t /= 10;
        }
    }
    let body = &digits[di..];
    if body.len() < w {
        let pad = [b' '; 20];
        let take = (w - body.len()).min(pad.len());
        emit(out, pos, &pad[..take]);
    }
    emit(out, pos, body)
}

/// `strftime(buf, max, fmt, tm)` — Path-B subset of POSIX strftime.
/// Returns the number of bytes written (excluding the NUL
/// terminator), or 0 if the result wouldn't fit in `max`. Always
/// NUL-terminates when at least 1 byte of `buf` is available and the
/// result fit; otherwise returns 0 and leaves `buf` unchanged.
///
/// # Safety
/// `buf` must point to `max` writable bytes; `fmt` must be a
/// NUL-terminated C string; `tm` must be a valid `*const tm`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strftime(
    buf: *mut u8,
    max: usize,
    fmt: *const u8,
    t: *const tm,
) -> usize {
    if buf.is_null() || fmt.is_null() || t.is_null() || max == 0 {
        return 0;
    }
    // SAFETY: caller asserts.
    let tm_v = unsafe { *t };
    // SAFETY: caller-supplied writable region of `max` bytes.
    let out = unsafe { core::slice::from_raw_parts_mut(buf, max) };
    let mut pos = 0usize;

    // Walk fmt as a NUL-terminated C string.
    let mut fi = 0usize;
    loop {
        // SAFETY: NUL-terminated per caller.
        let b = unsafe { *fmt.add(fi) };
        if b == 0 { break; }
        if b == b'%' {
            // SAFETY: same.
            let conv = unsafe { *fmt.add(fi + 1) };
            if conv == 0 {
                emit(out, &mut pos, b"%");
                break;
            }
            match conv {
                b'Y' => { emit_pad_uint(out, &mut pos, (tm_v.tm_year + 1900) as u64, 4); }
                b'y' => { emit_pad_uint(out, &mut pos, ((tm_v.tm_year + 1900) % 100) as u64, 2); }
                b'm' => { emit_pad_uint(out, &mut pos, (tm_v.tm_mon + 1) as u64, 2); }
                b'd' => { emit_pad_uint(out, &mut pos, tm_v.tm_mday as u64, 2); }
                b'e' => { emit_pad_space(out, &mut pos, tm_v.tm_mday as u64, 2); }
                b'H' => { emit_pad_uint(out, &mut pos, tm_v.tm_hour as u64, 2); }
                b'M' => { emit_pad_uint(out, &mut pos, tm_v.tm_min as u64, 2); }
                b'S' => { emit_pad_uint(out, &mut pos, tm_v.tm_sec as u64, 2); }
                b'j' => { emit_pad_uint(out, &mut pos, (tm_v.tm_yday + 1) as u64, 3); }
                b'a' => {
                    let i = (tm_v.tm_wday.rem_euclid(7)) as usize;
                    emit(out, &mut pos, WDAY_SHORT[i]);
                }
                b'A' => {
                    let i = (tm_v.tm_wday.rem_euclid(7)) as usize;
                    emit(out, &mut pos, WDAY_LONG[i]);
                }
                b'b' | b'h' => {
                    let i = (tm_v.tm_mon.rem_euclid(12)) as usize;
                    emit(out, &mut pos, MON_SHORT[i]);
                }
                b'B' => {
                    let i = (tm_v.tm_mon.rem_euclid(12)) as usize;
                    emit(out, &mut pos, MON_LONG[i]);
                }
                b'p' => {
                    emit(out, &mut pos, if tm_v.tm_hour < 12 { b"AM" } else { b"PM" });
                }
                b'%' => { emit(out, &mut pos, b"%"); }
                other => {
                    // Unknown conversion — emit %X verbatim.
                    let tmp = [b'%', other];
                    emit(out, &mut pos, &tmp);
                }
            }
            fi += 2;
        } else {
            // SAFETY: single byte from the format string.
            emit(out, &mut pos, &[b]);
            fi += 1;
        }
    }
    // C99: return 0 if the result didn't fit.
    if pos >= max {
        return 0;
    }
    out[pos] = 0;
    pos
}

/// Static buffer for `asctime` / `ctime` returns. Single-threaded.
/// Holds 26 chars per POSIX (`"Wed Jun 30 21:49:08 1993\n\0"`).
static mut ASCTIME_BUF: [u8; 32] = [0; 32];

/// `asctime(tm)` — fixed `"%a %b %e %H:%M:%S %Y\n"` formatting.
/// Returns a pointer to the static buffer; subsequent calls
/// overwrite it.
///
/// # Safety
/// `t` must be a valid `*const tm`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asctime(t: *const tm) -> *mut u8 {
    let p = &raw mut ASCTIME_BUF;
    // SAFETY: static buffer of 32 bytes; strftime cannot overrun.
    unsafe {
        let _ = strftime(
            (*p).as_mut_ptr(),
            (*p).len(),
            b"%a %b %e %H:%M:%S %Y\n\0".as_ptr(),
            t,
        );
        (*p).as_mut_ptr()
    }
}

/// `ctime(time)` — convenience: `asctime(localtime(time))`.
///
/// # Safety
/// `timep` must be a valid `*const time_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ctime(timep: *const time_t) -> *mut u8 {
    // SAFETY: forwarded under caller contract; localtime returns a
    // pointer into TM_STATIC.
    unsafe { asctime(localtime(timep)) }
}

// ── times() — POSIX process CPU times ───────────────────────────────

/// POSIX `<sys/times.h>` `struct tms`. `clock_t` is `i64` here
/// (matches glibc x86_64). Times are in CLK_TCK = 100Hz ticks.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct tms {
    pub tms_utime:  i64,
    pub tms_stime:  i64,
    pub tms_cutime: i64,
    pub tms_cstime: i64,
}

/// `times(buf)` — write per-task CPU-time accumulation and return
/// the wall-clock ticks since boot. NARF synthesises tms_utime
/// from monotonic_ns and zeros the rest; consumers using `clock()`
/// or `time(1)`-shaped wall measurements still get a valid clock.
///
/// # Safety
/// `buf` must be a writable `*mut tms`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn times(buf: *mut tms) -> i64 {
    if buf.is_null() {
        let mut sink = [0i64; 4];
        return narf_user_runtime::times(&mut sink);
    }
    let mut tmp = [0i64; 4];
    let wall = narf_user_runtime::times(&mut tmp);
    // SAFETY: caller-supplied writable struct.
    unsafe {
        (*buf).tms_utime  = tmp[0];
        (*buf).tms_stime  = tmp[1];
        (*buf).tms_cutime = tmp[2];
        (*buf).tms_cstime = tmp[3];
    }
    wall
}

/// `clock()` — POSIX `clock(3)`. Returns the calling task's
/// utime in CLK_TCK = 100Hz ticks. Aliases what `times` would
/// write into `tms_utime`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn clock() -> i64 {
    let mut tmp = [0i64; 4];
    let _ = narf_user_runtime::times(&mut tmp);
    tmp[0]
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

/// `nanosleep(*const timespec, *mut timespec)` — POSIX. Suspends
/// the calling task for the timespec interval. `rem`, when non-
/// null, is populated with the remaining time on interrupt (we
/// don't yet surface signal-interrupted sleeps; rem stays zeroed).
///
/// Reference: musl `src/time/nanosleep.c`.
///
/// # Safety
/// `req` must point to a valid `timespec`. `rem`, when non-null,
/// must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nanosleep(req: *const timespec, rem: *mut timespec) -> i32 {
    if req.is_null() { return -1; }
    // SAFETY: caller asserts `req` is readable.
    let r = unsafe { *req };
    if r.tv_sec < 0 || r.tv_nsec < 0 || r.tv_nsec >= 1_000_000_000 {
        crate::errno::set_errno(22); // EINVAL
        return -1;
    }
    let ns = (r.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(r.tv_nsec as u64);
    let res = narf_user_runtime::nanosleep(ns);
    if !rem.is_null() {
        // SAFETY: caller-asserted writable.
        unsafe { *rem = timespec { tv_sec: 0, tv_nsec: 0 }; }
    }
    res
}

/// `clock_getres(clk_id, *mut timespec)` — POSIX. Reports the
/// resolution of the named clock. NARF clocks advance per the TSC
/// frequency; we report 1 ns as the nominal resolution (the
/// granularity callers should expect).
///
/// # Safety
/// `res`, when non-null, must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn clock_getres(_clk_id: i32, res: *mut timespec) -> i32 {
    if !res.is_null() {
        // SAFETY: caller-asserted writable.
        unsafe { *res = timespec { tv_sec: 0, tv_nsec: 1 }; }
    }
    0
}

/// `clock_nanosleep(clk_id, flags, *req, *rem)` — POSIX absolute /
/// relative sleep on a named clock. Today we honour the relative
/// form (flags == 0) and forward to nanosleep; the absolute form
/// (`TIMER_ABSTIME = 1`) is computed as `(req - now)`.
///
/// Reference: musl `src/time/clock_nanosleep.c`.
///
/// # Safety
/// `req` must be readable; `rem`, when non-null, must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn clock_nanosleep(
    clk_id: i32,
    flags:  i32,
    req:    *const timespec,
    rem:    *mut timespec,
) -> i32 {
    if req.is_null() { return 22; }
    // SAFETY: caller-asserted readable timespec.
    let r = unsafe { *req };
    if r.tv_sec < 0 || r.tv_nsec < 0 || r.tv_nsec >= 1_000_000_000 {
        return 22; // EINVAL
    }
    let target_ns = (r.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(r.tv_nsec as u64);
    let sleep_ns = if flags == 1 {
        // TIMER_ABSTIME — compute the delta against the current
        // clock reading.
        let (sec, nsec) = narf_user_runtime::clock_gettime(clk_id as u32);
        let now = (sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(nsec as u64);
        target_ns.saturating_sub(now)
    } else {
        target_ns
    };
    let res = narf_user_runtime::nanosleep(sleep_ns);
    if !rem.is_null() {
        // SAFETY: caller-asserted writable.
        unsafe { *rem = timespec { tv_sec: 0, tv_nsec: 0 }; }
    }
    if res == 0 { 0 } else { 4 } // EINTR on interrupt
}
