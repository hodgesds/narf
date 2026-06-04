//! Real-Time Clock backstops — clean-room.
//!
//! Three register-layout codecs covering the RTC variants every
//! consumer device exposes:
//!
//! - [`cmos`] — MC146818-compatible CMOS RTC on x86 (I/O ports
//!   0x70/0x71).
//! - [`pl031`] — ARM PrimeCell PL031 RTC (memory-mapped, 24 KiB
//!   register window).
//! - [`pmic`] — Qualcomm PMIC peripheral type 0x6000 RTC (SPMI-
//!   addressed, 32-bit second counter).
//!
//! The three formats look completely different on the wire but
//! produce the same logical "year / month / day / hour / minute /
//! second" tuple, exposed as [`RtcDateTime`]. Higher-level code
//! converts to [`crate::Instant`] / Unix epoch.

extern crate alloc;

/// Decoded date/time. Year is the full 4-digit form (2026, not 26).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RtcDateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

impl RtcDateTime {
    /// Convert to seconds since the Unix epoch (1970-01-01 00:00:00 UTC).
    /// The conversion uses a Howard Hinnant-style algorithm which is
    /// accurate for any year ≥ 1.
    pub fn to_unix_seconds(self) -> i64 {
        let y = self.year as i64;
        let m = self.month as i64;
        let d = self.day as i64;
        let yp = if m <= 2 { y - 1 } else { y };
        let era = yp.div_euclid(400);
        let yoe = yp - era * 400;
        let mp = if m > 2 { m - 3 } else { m + 9 };
        let doy = (153 * mp + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146097 + doe - 719468;
        days * 86400 + self.hour as i64 * 3600 + self.minute as i64 * 60 + self.second as i64
    }
}

// ── MC146818 CMOS RTC (x86) ──────────────────────────────────────

/// MC146818-compatible CMOS RTC.
///
/// ## Reference (public only)
///
/// - **Motorola MC146818 Real-Time Clock Plus RAM** datasheet
///   (1980s — Motorola; the IC the IBM PC AT and every clone since
///   uses for its CMOS RTC). The full datasheet is widely
///   mirrored, e.g.:
///   <https://www.nxp.com/docs/en/data-sheet/MC146818.pdf>
/// - **OSDev wiki "RTC"** entry — re-derives the same register
///   table from the Motorola datasheet:
///   <https://wiki.osdev.org/RTC>
pub mod cmos {
    use super::RtcDateTime;

    /// I/O port addresses (x86 only).
    pub const ADDR_PORT: u16 = 0x70;
    pub const DATA_PORT: u16 = 0x71;

    /// Register indices accessed via address-port writes.
    pub const REG_SECONDS: u8 = 0x00;
    pub const REG_MINUTES: u8 = 0x02;
    pub const REG_HOURS: u8 = 0x04;
    pub const REG_DAY_OF_WEEK: u8 = 0x06;
    pub const REG_DAY_OF_MONTH: u8 = 0x07;
    pub const REG_MONTH: u8 = 0x08;
    pub const REG_YEAR: u8 = 0x09;
    pub const REG_STATUS_A: u8 = 0x0A;
    pub const REG_STATUS_B: u8 = 0x0B;
    /// Century byte — added by ACPI's Fixed ACPI Description Table
    /// `Century` field (offset varies; common is 0x32). When zero
    /// in the FADT, the byte isn't valid and the kernel should
    /// assume the year is post-2000.
    pub const REG_CENTURY: u8 = 0x32;

    /// Status A bit 7 — Update In Progress (UIP). Reads must be
    /// retried until this clears for a coherent snapshot.
    pub const STATUS_A_UIP: u8 = 1 << 7;
    /// Status B bit 1 — 24-hour mode. When clear, hours encode
    /// AM/PM in bit 7.
    pub const STATUS_B_24H: u8 = 1 << 1;
    /// Status B bit 2 — Binary mode. When clear, all numeric
    /// registers are BCD.
    pub const STATUS_B_BIN: u8 = 1 << 2;

    /// Decode one BCD byte. `bcd_to_bin(0x42) == 42`.
    pub fn bcd_to_bin(b: u8) -> u8 {
        ((b >> 4) * 10) + (b & 0x0F)
    }

    pub fn bin_to_bcd(b: u8) -> u8 {
        ((b / 10) << 4) | (b % 10)
    }

    /// Decode a coherent snapshot of the seven date/time registers
    /// taken with UIP clear. `status_b` is the value of REG_STATUS_B
    /// when the snapshot was taken — it determines BCD vs binary
    /// and 12h vs 24h interpretation.
    ///
    /// `century` is the value of the optional Century byte (REG 0x32);
    /// pass 0 if the FADT says no Century byte. Without a century,
    /// we assume 2000 + `year` (kernels currently can't run before
    /// 2000 without other failures).
    pub fn decode_snapshot(
        sec: u8,
        min: u8,
        hour: u8,
        day: u8,
        month: u8,
        year: u8,
        century: u8,
        status_b: u8,
    ) -> RtcDateTime {
        let bcd = status_b & STATUS_B_BIN == 0;
        let h24 = status_b & STATUS_B_24H != 0;

        let conv = |v: u8| if bcd { bcd_to_bin(v) } else { v };
        let mut hour = if h24 {
            conv(hour & 0x7F)
        } else {
            // 12h with PM bit (bit 7) set on the *raw* register, before
            // BCD conversion.
            let pm = hour & 0x80 != 0;
            let h = conv(hour & 0x7F) % 12;
            if pm {
                h + 12
            } else {
                h
            }
        };
        if hour >= 24 {
            hour = 0; // defensive — broken RTCs occasionally stamp 24
        }

        let year_full = if century != 0 {
            (conv(century) as u16) * 100 + (conv(year) as u16)
        } else {
            2000 + (conv(year) as u16)
        };

        RtcDateTime {
            year: year_full,
            month: conv(month),
            day: conv(day),
            hour,
            minute: conv(min),
            second: conv(sec),
        }
    }
}

// ── ARM PL031 RTC (memory-mapped) ────────────────────────────────

/// ARM PrimeCell PL031 Real Time Clock.
///
/// ## Reference (public only)
///
/// - **ARM PrimeCell Real Time Clock (PL031), Technical Reference
///   Manual, Revision r1p3**, ARM. Public.
///   <https://developer.arm.com/documentation/ddi0224/c/>
///
/// PL031 is dead simple: a free-running 32-bit second counter
/// (`RTCDR`), a load register (`RTCLR`), a match/alarm register
/// (`RTCMR`), interrupt status / mask / clear, and a control
/// register that gates the counter.
pub mod pl031 {
    use super::RtcDateTime;

    pub mod regs {
        /// Data Register (read-only) — current 32-bit second count.
        pub const RTCDR: usize = 0x000;
        /// Match Register — alarm fires when RTCDR == RTCMR.
        pub const RTCMR: usize = 0x004;
        /// Load Register — write to set RTCDR.
        pub const RTCLR: usize = 0x008;
        /// Control Register — bit 0 = Start (gate the counter).
        pub const RTCCR: usize = 0x00C;
        /// Interrupt Mask Set/Clear — bit 0 = match-interrupt mask.
        pub const RTCIMSC: usize = 0x010;
        /// Raw Interrupt Status — bit 0 = match.
        pub const RTCRIS: usize = 0x014;
        /// Masked Interrupt Status.
        pub const RTCMIS: usize = 0x018;
        /// Interrupt Clear (write 1 to clear).
        pub const RTCICR: usize = 0x01C;
    }

    pub const RTCCR_START: u32 = 1 << 0;
    pub const RTCIMSC_ALARM: u32 = 1 << 0;
    pub const RTCRIS_ALARM: u32 = 1 << 0;

    /// Convert PL031's 32-bit Unix-epoch-seconds counter to a
    /// [`RtcDateTime`]. Inverse of [`RtcDateTime::to_unix_seconds`]
    /// for non-negative inputs.
    pub fn unix_seconds_to_datetime(s: u32) -> RtcDateTime {
        let total = s as i64;
        let secs_per_day = 86_400i64;
        let mut days = total / secs_per_day;
        let mut tod = total - days * secs_per_day;
        if tod < 0 {
            tod += secs_per_day;
            days -= 1;
        }
        let hour = (tod / 3600) as u8;
        let minute = ((tod % 3600) / 60) as u8;
        let second = (tod % 60) as u8;
        // Howard Hinnant inverse: days since 1970-01-01 → (y, m, d).
        let z = days + 719_468;
        let era = if z >= 0 {
            z / 146_097
        } else {
            (z - 146_096) / 146_097
        };
        let doe = (z - era * 146_097) as u64;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe as i64 + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
        let m = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
        let year = (y + if m <= 2 { 1 } else { 0 }) as u16;
        RtcDateTime {
            year,
            month: m,
            day: d,
            hour,
            minute,
            second,
        }
    }
}

// ── Qualcomm PMIC RTC (peripheral type 0x6000) ──────────────────

/// Qualcomm PMIC RTC peripheral.
///
/// ## Reference (public only)
///
/// - Public Qualcomm devicetree binding documentation describing
///   the hardware-visible register layout:
///   <https://docs.kernel.org/devicetree/bindings/rtc/qcom,pm8xxx-rtc.yaml>
///
/// Register layout (within the PMIC peripheral block, all SPMI-
/// addressed):
///
/// ```text
///   0x46  CTRL  bit 7 = enable, bit 0 = alarm enable
///   0x48  RDATA0..RDATA3  current second-count (LE u32)
///   0x4C  WDATA0..WDATA3  load-second count (LE u32)
///   0x50  ALARM_RDATA0..3 alarm second-count (LE u32)
///   0x58  ALARM_CTRL      bit 7 = alarm match enable
/// ```
///
/// The counter is 32-bit Unix-style seconds since 1970-01-01.
pub mod pmic {
    use super::pl031::unix_seconds_to_datetime;
    use super::RtcDateTime;

    pub const CTRL: usize = 0x46;
    pub const RDATA: usize = 0x48; // 4 bytes
    pub const WDATA: usize = 0x4C;
    pub const ALARM_RDATA: usize = 0x50;
    pub const ALARM_CTRL: usize = 0x58;

    pub const CTRL_ENABLE: u8 = 1 << 7;
    pub const CTRL_ALARM_ENABLE: u8 = 1 << 0;
    pub const ALARM_CTRL_MATCH: u8 = 1 << 7;

    /// Decode a 4-byte snapshot of `RDATA` (LE) into a date/time.
    pub fn decode_snapshot(rdata: [u8; 4]) -> RtcDateTime {
        let s = u32::from_le_bytes(rdata);
        unix_seconds_to_datetime(s)
    }
}
