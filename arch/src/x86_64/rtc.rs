//! CMOS RTC (MC146818-compatible) — clean-room.
//!
//! Reference: **Motorola "MC146818 Real-Time Clock plus RAM"**
//! datasheet (free, semantic-scholar.org / many mirrors). The
//! IBM PC RTC at IO ports `0x70` (index) / `0x71` (data) is
//! 100% compatible.
//!
//! ## Registers
//!
//! | index | content                         |
//! |-------|---------------------------------|
//! | 0x00  | Seconds                         |
//! | 0x02  | Minutes                         |
//! | 0x04  | Hours                           |
//! | 0x06  | Day of week                     |
//! | 0x07  | Day of month                    |
//! | 0x08  | Month                           |
//! | 0x09  | Year (0..99)                    |
//! | 0x0A  | Status A (UIP bit 7 = update-in-progress) |
//! | 0x0B  | Status B (bit 1 = 24-hour mode, bit 2 = data mode: 1=binary, 0=BCD) |
//! | 0x32  | Century (when ACPI FADT century_index = 0x32) |
//!
//! ## Read-coherency
//!
//! The MC146818 increments fields once per second. To read a
//! coherent set, poll until `Status A.UIP = 0`, then read all
//! fields. This stage cut does the read in one go after a single
//! UIP poll — sufficient for boot wall-clock seeding, where the
//! caller doesn't care if it loses 1 second.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::io_port::{inb, outb};

const RTC_INDEX: u16 = 0x70;
const RTC_DATA: u16 = 0x71;

const REG_SECONDS: u8 = 0x00;
const REG_MINUTES: u8 = 0x02;
const REG_HOURS: u8 = 0x04;
const REG_DAY: u8 = 0x07;
const REG_MONTH: u8 = 0x08;
const REG_YEAR: u8 = 0x09;
const REG_STATUS_A: u8 = 0x0A;
const REG_STATUS_B: u8 = 0x0B;
const REG_CENTURY: u8 = 0x32;

const STATUS_A_UIP: u8 = 1 << 7;
const STATUS_B_24H: u8 = 1 << 1;
const STATUS_B_BIN: u8 = 1 << 2;

/// Wall-clock snapshot returned by `read_now`. Year is the full
/// 4-digit year (century resolution depends on whether the
/// platform exposes the 0x32 century byte).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct WallTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

unsafe fn read_index(idx: u8) -> u8 {
    // SAFETY: caller-asserted CPL=0 + CMOS RTC IO window owned.
    unsafe {
        outb(RTC_INDEX, idx);
        inb(RTC_DATA)
    }
}

fn from_bcd(v: u8) -> u8 {
    (v >> 4) * 10 + (v & 0x0F)
}

/// Read the current wall-clock time from CMOS. Polls Status A
/// until UIP clears, reads the field set, returns a decoded
/// `WallTime`.
///
/// # Safety
/// CPL = 0; the CMOS IO ports `0x70/0x71` must be owned by the
/// caller (boot context, no SMP races).
pub unsafe fn read_now() -> WallTime {
    // Wait for UIP to clear so the field set is coherent.
    for _ in 0..1_000_000u32 {
        // SAFETY: caller-asserted.
        let s = unsafe { read_index(REG_STATUS_A) };
        if s & STATUS_A_UIP == 0 {
            break;
        }
        core::hint::spin_loop();
    }
    // SAFETY: caller-asserted.
    let status_b = unsafe { read_index(REG_STATUS_B) };
    let binary = status_b & STATUS_B_BIN != 0;
    let h24 = status_b & STATUS_B_24H != 0;
    let conv = |v: u8| -> u8 {
        if binary {
            v
        } else {
            from_bcd(v)
        }
    };

    // SAFETY: same.
    let mut sec = unsafe { read_index(REG_SECONDS) };
    // SAFETY: same.
    let mut min = unsafe { read_index(REG_MINUTES) };
    // SAFETY: same.
    let mut hr = unsafe { read_index(REG_HOURS) };
    // SAFETY: same.
    let mut dom = unsafe { read_index(REG_DAY) };
    // SAFETY: same.
    let mut mon = unsafe { read_index(REG_MONTH) };
    // SAFETY: same.
    let mut yr = unsafe { read_index(REG_YEAR) };
    // SAFETY: same — century may not be wired (returns junk on
    // some chipsets; FADT century_index disambiguates).
    let cent = unsafe { read_index(REG_CENTURY) };

    // 12-hour format: bit 7 = PM. Convert before BCD decode.
    let pm = !h24 && (hr & 0x80 != 0);
    hr &= 0x7F;

    sec = conv(sec);
    min = conv(min);
    hr = conv(hr);
    dom = conv(dom);
    mon = conv(mon);
    yr = conv(yr);

    if pm && hr < 12 {
        hr += 12;
    }
    if !pm && !h24 && hr == 12 {
        hr = 0;
    }

    let cent = conv(cent);
    let full_year: u16 = if cent >= 19 && cent <= 21 {
        // Plausible century byte (19xx / 20xx / 21xx).
        (cent as u16) * 100 + yr as u16
    } else {
        // Fall back to "20xx assumed" — wrong for embedded
        // devices stuck in 19xx, but right for any modern host.
        2000u16 + yr as u16
    };
    WallTime {
        year: full_year,
        month: mon,
        day: dom,
        hour: hr,
        minute: min,
        second: sec,
    }
}

/// Convert a `WallTime` to seconds since the Unix epoch (1970-01-01
/// 00:00:00 UTC). No leap-second / timezone awareness — caller
/// supplies a UTC `WallTime`.
pub fn to_unix_seconds(t: WallTime) -> i64 {
    fn is_leap(y: u16) -> bool {
        (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
    }
    const DAYS_BEFORE_MONTH: [u32; 13] =
        [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365];
    let y = t.year as i64;
    // Days from epoch to start of year `y`.
    let mut days: i64 = 0;
    for yy in 1970..t.year {
        days += if is_leap(yy) { 366 } else { 365 };
    }
    let mut mon_days = DAYS_BEFORE_MONTH[(t.month - 1).min(12) as usize] as i64;
    if t.month > 2 && is_leap(t.year) {
        mon_days += 1;
    }
    days += mon_days + (t.day as i64 - 1);
    let _ = y;
    days * 86_400 + t.hour as i64 * 3600 + t.minute as i64 * 60 + t.second as i64
}
