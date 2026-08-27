//! `/dev/rtc0` (+ `/dev/rtc` symlink) — Linux real-time-clock char device.
//!
//! Linux ref: `drivers/rtc/rtc-cmos.c` + `drivers/rtc/dev.c` (the RTC
//! chardev ioctl surface) and `include/uapi/linux/rtc.h` (`struct
//! rtc_time` + `RTC_RD_TIME`/`RTC_SET_TIME`/`RTC_UIE_ON`/`RTC_UIE_OFF`).
//!
//! Consumers: `hwclock` / `busybox hwclock` (`RTC_RD_TIME` for
//! `--show`), systemd-timesyncd, util-linux. `hwclock --show` opens
//! `/dev/rtc0`, issues `ioctl(fd, RTC_RD_TIME, &rtc_time)`, and prints
//! the broken-down UTC time; that is the critical path here.
//!
//! ## `struct rtc_time` ABI
//!
//! `struct rtc_time` is nine `int`s laid out identically to `struct tm`
//! but with fixed-width `int` fields — 36 bytes total. The `RTC_RD_TIME`
//! / `RTC_SET_TIME` ioctls exchange exactly this 36-byte image; we copy
//! precisely [`RTC_TIME_LEN`] bytes to/from user memory, mirroring the
//! termios kernel-vs-libc size trap fixed for TCGETS/TCSETS (writing a
//! larger struct than the kernel ABI overran the caller's buffer).
//!
//! ## Time source
//!
//! `RTC_RD_TIME` reports NARF's current wall-clock time
//! ([`narf_time::wall::now_wall`], UNIX seconds) converted to
//! broken-down **UTC** via the Howard Hinnant civil-from-days algorithm
//! (RTC is conventionally UTC). `RTC_SET_TIME` is accepted and ignored
//! (returns 0) — NARF treats the RTC as read-mostly, like most VMs.
//!
//! ## Device number
//!
//! Char major 254 / minor 0 — the conventional dynamic RTC misc number,
//! matching the `dev` attr this module publishes under
//! `/sys/class/rtc/rtc0/`.

use alloc::boxed::Box;

use crate::{FileOps, FileType, FsError, FsFuture, Mode, Stat};

/// Conventional RTC char device numbers (`/dev/rtc0`).
/// Linux ref: `Documentation/admin-guide/devices.txt` (misc RTC).
pub const RTC_MAJOR: u32 = 254;
/// Minor number for `rtc0`.
pub const RTC_MINOR: u32 = 0;

// ── `struct rtc_time` (uapi/linux/rtc.h) ──────────────────────────────
//
// struct rtc_time {
//     int tm_sec;   int tm_min;  int tm_hour;
//     int tm_mday;  int tm_mon;  int tm_year;
//     int tm_wday;  int tm_yday; int tm_isdst;
// };
//
// Same layout as `struct tm` but with `int` (i32) fields. `tm_mon` is
// 0..=11 and `tm_year` is years-since-1900, exactly like `struct tm`.

/// Wire size of `struct rtc_time`: nine `c_int` = 36 bytes. The
/// `RTC_RD_TIME`/`RTC_SET_TIME` ioctls exchange exactly this many bytes.
pub const RTC_TIME_LEN: usize = 36;

/// In-kernel image of `struct rtc_time`. `#[repr(C)]` with nine `i32`
/// fields ⇒ exactly [`RTC_TIME_LEN`] (36) bytes, no padding.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RtcTime {
    pub tm_sec: i32,
    pub tm_min: i32,
    pub tm_hour: i32,
    /// Day of month, 1..=31.
    pub tm_mday: i32,
    /// Month, **0..=11** (January = 0).
    pub tm_mon: i32,
    /// Year **since 1900** (2026 ⇒ 126).
    pub tm_year: i32,
    /// Day of week, 0..=6 (Sunday = 0).
    pub tm_wday: i32,
    /// Day of year, 0..=365.
    pub tm_yday: i32,
    pub tm_isdst: i32,
}

// Compile-time proof the wire size matches the ABI.
const _: () = assert!(core::mem::size_of::<RtcTime>() == RTC_TIME_LEN);

// ── ioctl request codes (uapi/linux/rtc.h) ────────────────────────────
//
// Encoded via _IOR('p', N, struct rtc_time) / _IO('p', N):
//   RTC_RD_TIME  = _IOR('p', 0x09, struct rtc_time) = 0x80247009
//   RTC_SET_TIME = _IOW('p', 0x0a, struct rtc_time) = 0x4024700a
//   RTC_UIE_ON   = _IO('p', 0x03)                    = 0x00007003
//   RTC_UIE_OFF  = _IO('p', 0x04)                    = 0x00007004

/// `ioctl(fd, RTC_RD_TIME, &rtc_time)` — read current RTC time. Kernel
/// writes a `struct rtc_time`. This is the `hwclock --show` path.
pub const RTC_RD_TIME: u32 = 0x8024_7009;
/// `ioctl(fd, RTC_SET_TIME, &rtc_time)` — set RTC time. Kernel reads a
/// `struct rtc_time`. Accepted and ignored (returns 0).
pub const RTC_SET_TIME: u32 = 0x4024_700a;
/// `ioctl(fd, RTC_UIE_ON, 0)` — enable update interrupt. Returns 0.
pub const RTC_UIE_ON: u32 = 0x0000_7003;
/// `ioctl(fd, RTC_UIE_OFF, 0)` — disable update interrupt. Returns 0.
pub const RTC_UIE_OFF: u32 = 0x0000_7004;

// ── epoch → broken-down UTC ───────────────────────────────────────────
//
// Howard Hinnant's civil-from-days algorithm
// (https://howardhinnant.github.io/date_algorithms.html) — the
// canonical table-free conversion between days-since-epoch and
// (year, month, day). Mirrors `narf-libc`'s `gmtime_r`
// (narf-libc/src/time.rs); reproduced here so the FS layer has no
// dependency on the libc crate. Proven correct for the whole signed
// day range.

/// Inverse civil calendar: days-since-Unix-epoch → `(year, month 1..=12,
/// day 1..=31)`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (y + i64::from(m <= 2), m as u32, d as u32)
}

/// Days from civil `(y, m, d)` to the Unix epoch. Used only to compute
/// `tm_yday`. Hinnant's algorithm.
fn days_from_civil(mut y: i64, m: u32, d: u32) -> i64 {
    y -= i64::from(m <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) as u64 + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

/// Convert a UNIX timestamp (seconds since 1970-01-01 UTC) to a
/// broken-down [`RtcTime`] in UTC, with `tm_mon` 0-based and `tm_year`
/// years-since-1900 (matching the Linux RTC ABI). `div_euclid`/
/// `rem_euclid` keep pre-epoch (negative) timestamps correct.
pub fn rtc_time_from_unix(secs: i64) -> RtcTime {
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    // tm_wday: 1970-01-01 was a Thursday (= 4). Euclid remainder gives a
    // non-negative 0..=6 with Sunday = 0.
    let wday = (((days % 7) + 4).rem_euclid(7)) as i32;
    // tm_yday: whole days since Jan 1 of this year.
    let jan1 = days_from_civil(y, 1, 1);
    let yday = (days - jan1) as i32;
    RtcTime {
        tm_sec: (tod % 60) as i32,
        tm_min: ((tod % 3600) / 60) as i32,
        tm_hour: (tod / 3600) as i32,
        tm_mday: d as i32,
        tm_mon: m as i32 - 1,
        tm_year: (y - 1900) as i32,
        tm_wday: wday,
        tm_yday: yday,
        tm_isdst: 0,
    }
}

/// Current wall-clock time as broken-down UTC. Reads
/// [`narf_time::wall::now_wall`] (UNIX seconds since epoch).
fn now_rtc_time() -> RtcTime {
    let w = narf_time::wall::now_wall();
    rtc_time_from_unix(w.secs)
}

// ── user-pointer copy (matches devfs_pty's SMAP-bracketed helpers) ────

/// Copy a [`RtcTime`] out to user memory for `RTC_RD_TIME` — exactly
/// [`RTC_TIME_LEN`] bytes. The SMAP window mirrors the pty ioctl
/// helpers; a bare store to a user-only PTE at CPL=0 #PFs once
/// CR4.SMAP = 1 (true on every CPU NARF boots).
#[cfg(target_arch = "x86_64")]
unsafe fn write_user_rtc_time(uptr: usize, v: &RtcTime) -> Result<(), FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    let v = *v;
    // SAFETY: caller guarantees `uptr` is a valid user pointer sized for
    // a `struct rtc_time` (36 bytes); `with_user_access` enables SMAP
    // and `write_unaligned` handles any alignment.
    unsafe {
        narf_arch::x86_64::smap::with_user_access(|| {
            core::ptr::write_unaligned(uptr as *mut RtcTime, v);
        });
    }
    Ok(())
}

/// Read a [`RtcTime`] in from user memory for `RTC_SET_TIME`. Validates
/// the pointer even though the value is accepted-and-ignored, so a bogus
/// pointer still faults cleanly rather than silently succeeding.
#[cfg(target_arch = "x86_64")]
unsafe fn read_user_rtc_time(uptr: usize) -> Result<RtcTime, FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    // SAFETY: caller guarantees `uptr` is a valid user pointer sized for
    // a `struct rtc_time`; `with_user_access` enables SMAP and
    // `read_unaligned` handles any alignment.
    let v = unsafe {
        narf_arch::x86_64::smap::with_user_access(|| {
            core::ptr::read_unaligned(uptr as *const RtcTime)
        })
    };
    Ok(v)
}

// Non-x86_64 fallback — no SMAP; raw pointer ops (the FS ioctl layer is
// x86_64-only in practice, but keep the surface buildable everywhere).
#[cfg(not(target_arch = "x86_64"))]
unsafe fn write_user_rtc_time(uptr: usize, v: &RtcTime) -> Result<(), FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    let v = *v;
    // SAFETY: caller-supplied valid user pointer (its contract); non-null
    // per the check above; `write_unaligned` writes exactly one 36-byte
    // `RtcTime` regardless of alignment.
    unsafe { core::ptr::write_unaligned(uptr as *mut RtcTime, v) };
    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn read_user_rtc_time(uptr: usize) -> Result<RtcTime, FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    // SAFETY: caller-supplied valid user pointer (its contract); non-null
    // per the check above; `read_unaligned` reads exactly one 36-byte
    // `RtcTime` regardless of alignment.
    Ok(unsafe { core::ptr::read_unaligned(uptr as *const RtcTime) })
}

// ── /dev/rtc0 device node ─────────────────────────────────────────────

/// `/dev/rtc0` — the RTC char device. All state lives in the global
/// wall clock, so this is a zero-sized handle.
///
/// Linux ref: `drivers/rtc/dev.c::rtc_dev_ioctl`.
#[derive(Debug)]
pub struct DevRtc;

impl FileOps for DevRtc {
    /// `read()` on an RTC chardev is not the interface programs use
    /// (`hwclock` uses ioctls). Linux returns update-interrupt event
    /// longs here; we return EOF (0 bytes) so a stray `read()` doesn't
    /// hang or error out.
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Ok(0) })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o644,
            },
            mtime_cycles: 0,
        }
    }

    fn rdev(&self) -> u64 {
        crate::devfs::linux_makedev(254, 0)
    }

    fn ino(&self) -> u64 {
        0xd001_0000_0000_0000 | self.rdev().wrapping_add(1)
    }

    /// RTC ioctls. Unknown requests return `Unsupported` → `-ENOTTY`,
    /// the Linux convention (`rtc_dev_ioctl` default). `hwclock` probes
    /// `RTC_UIE_ON`/`OFF` and tolerates failure, but returning 0 is
    /// safest.
    fn ioctl(&self, cmd: u32, arg: usize) -> Result<u64, FsError> {
        match cmd {
            RTC_RD_TIME => {
                let t = now_rtc_time();
                // SAFETY: `arg` is a validated user pointer from the
                // ioctl syscall path, sized for `struct rtc_time`.
                unsafe { write_user_rtc_time(arg, &t)? };
                Ok(0)
            }
            RTC_SET_TIME => {
                // Accept-and-ignore: NARF's RTC is read-mostly. Still
                // read the struct so a bad pointer faults cleanly and
                // the caller's buffer is validated.
                // SAFETY: `arg` is a validated user pointer from the
                // ioctl syscall path, sized for `struct rtc_time`.
                let _ = unsafe { read_user_rtc_time(arg)? };
                Ok(0)
            }
            // Update-interrupt enable/disable: no periodic IRQ backing,
            // so treat as a successful no-op (hwclock tolerates either).
            RTC_UIE_ON | RTC_UIE_OFF => Ok(0),
            // Everything else → -ENOTTY, matching Linux.
            _ => Err(FsError::Unsupported),
        }
    }
}

/// Format the current wall-clock as `YYYY-MM-DD` for the sysfs `date`
/// attr. Public so `sysfs::populate_rtc_class` can render it.
/// Linux ref: `drivers/rtc/sysfs.c::date_show`.
pub fn sysfs_date_string() -> alloc::string::String {
    let t = now_rtc_time();
    alloc::format!(
        "{:04}-{:02}-{:02}\n",
        t.tm_year + 1900,
        t.tm_mon + 1,
        t.tm_mday
    )
}

/// Format the current wall-clock as `HH:MM:SS` for the sysfs `time`
/// attr. Linux ref: `drivers/rtc/sysfs.c::time_show`.
pub fn sysfs_time_string() -> alloc::string::String {
    let t = now_rtc_time();
    alloc::format!("{:02}:{:02}:{:02}\n", t.tm_hour, t.tm_min, t.tm_sec)
}

/// UNIX-seconds string for the sysfs `since_epoch` attr.
/// Linux ref: `drivers/rtc/sysfs.c::since_epoch_show`.
pub fn sysfs_since_epoch_string() -> alloc::string::String {
    let w = narf_time::wall::now_wall();
    alloc::format!("{}\n", w.secs)
}

// ── Tests ─────────────────────────────────────────────────────────────

mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// 2026-07-19 12:34:56 UTC = 1_784_464_496. Exercises the 0-based
    /// month, since-1900 year, and a Sunday wday.
    fn rtc_civil_known_2026() -> TestResult {
        let t = rtc_time_from_unix(1_784_464_496);
        if t.tm_year != 126 {
            return TestResult::Fail("tm_year (since 1900) mismatch");
        }
        if t.tm_mon != 6 {
            return TestResult::Fail("tm_mon (0-based July=6) mismatch");
        }
        if t.tm_mday != 19 {
            return TestResult::Fail("tm_mday mismatch");
        }
        if t.tm_hour != 12 || t.tm_min != 34 || t.tm_sec != 56 {
            return TestResult::Fail("HH:MM:SS mismatch");
        }
        // 2026-07-19 is a Sunday (tm_wday 0).
        if t.tm_wday != 0 {
            return TestResult::Fail("tm_wday (Sunday=0) mismatch");
        }
        TestResult::Pass
    }

    kernel_test_in!("filesystem", rtc_civil_known_2026);

    /// The Unix epoch itself: 1970-01-01 00:00:00 UTC = Thursday.
    fn rtc_civil_epoch() -> TestResult {
        let t = rtc_time_from_unix(0);
        if t.tm_year != 70
            || t.tm_mon != 0
            || t.tm_mday != 1
            || t.tm_hour != 0
            || t.tm_min != 0
            || t.tm_sec != 0
        {
            return TestResult::Fail("epoch broken-down fields mismatch");
        }
        // 1970-01-01 was a Thursday (tm_wday 4), yday 0.
        if t.tm_wday != 4 {
            return TestResult::Fail("epoch tm_wday (Thursday=4) mismatch");
        }
        if t.tm_yday != 0 {
            return TestResult::Fail("epoch tm_yday mismatch");
        }
        TestResult::Pass
    }

    kernel_test_in!("filesystem", rtc_civil_epoch);

    /// A leap-year boundary: 2000-02-29 00:00:00 UTC = 951_782_400.
    /// Catches an off-by-one in the century leap-day handling.
    fn rtc_civil_leap_day_2000() -> TestResult {
        let t = rtc_time_from_unix(951_782_400);
        if t.tm_year != 100 {
            return TestResult::Fail("leap-day tm_year mismatch");
        }
        if t.tm_mon != 1 {
            return TestResult::Fail("leap-day tm_mon (Feb=1) mismatch");
        }
        if t.tm_mday != 29 {
            return TestResult::Fail("leap-day tm_mday (29) mismatch");
        }
        TestResult::Pass
    }

    kernel_test_in!("filesystem", rtc_civil_leap_day_2000);

    /// `struct rtc_time` must be exactly 36 bytes (nine `c_int`), the
    /// wire size the ioctls copy. A regression here is the termios-style
    /// buffer-overrun trap.
    fn rtc_time_wire_size() -> TestResult {
        if core::mem::size_of::<RtcTime>() != RTC_TIME_LEN || RTC_TIME_LEN != 36 {
            return TestResult::Fail("RtcTime size != 36 bytes");
        }
        TestResult::Pass
    }

    kernel_test_in!("filesystem", rtc_time_wire_size);
}
