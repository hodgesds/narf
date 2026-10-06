//! Directory Entry structures.
//!
//! Based on Microsoft FAT Gen1 Specification (v1.03), pages 23-33.
//! URL: https://download.microsoft.com/download/7/0/3/70320475-7281-420b-8594-531a7bc86e42/fatgen103.pdf

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct DirEntry {
    pub name: [u8; 11],
    pub attr: u8,
    pub nt_res: u8,
    pub crt_time_tehnth: u8,
    pub crt_time: u16,
    pub crt_date: u16,
    pub lst_acc_date: u16,
    pub fst_clus_hi: u16,
    pub wrt_time: u16,
    pub wrt_date: u16,
    pub fst_clus_lo: u16,
    pub file_size: u32,
}

pub mod attr {
    pub const READ_ONLY: u8 = 0x01;
    pub const HIDDEN: u8 = 0x02;
    pub const SYSTEM: u8 = 0x04;
    pub const VOLUME_ID: u8 = 0x08;
    pub const DIRECTORY: u8 = 0x10;
    pub const ARCHIVE: u8 = 0x20;
    pub const LONG_NAME: u8 = READ_ONLY | HIDDEN | SYSTEM | VOLUME_ID;
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct LfnEntry {
    pub ord: u8,
    pub name1: [u16; 5],
    pub attr: u8,
    pub type_res: u8,
    pub chksum: u8,
    pub name2: [u16; 6],
    pub fst_clus_lo: u16, // Must be 0
    pub name3: [u16; 2],
}

impl DirEntry {
    pub fn is_free(&self) -> bool {
        self.name[0] == 0xE5
    }

    pub fn is_end(&self) -> bool {
        self.name[0] == 0x00
    }

    pub fn is_directory(&self) -> bool {
        (self.attr & attr::DIRECTORY) != 0
    }

    pub fn is_lfn(&self) -> bool {
        self.attr == attr::LONG_NAME
    }

    pub fn first_cluster(&self) -> u32 {
        ((self.fst_clus_hi as u32) << 16) | (self.fst_clus_lo as u32)
    }
}

pub const LFN_ENTRY_LAST_MASK: u8 = 0x40;

/// Cumulative days before each month (index = month 1..12; 0 and 13..15
/// are 0), Linux `fs/fat/misc.c::days_in_year`.
const DAYS_IN_YEAR: [i64; 16] = [
    0, 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 0, 0, 0,
];
const SECS_PER_MIN: i64 = 60;
const SECS_PER_HOUR: i64 = 60 * 60;
const SECS_PER_DAY: i64 = SECS_PER_HOUR * 24;
/// Days from 1970-01-01 to 1980-01-01 (`DAYS_DELTA`).
const DAYS_DELTA: i64 = 365 * 10 + 2;
/// Year field value of 2100 (`YEAR_2100`), which is not a leap year.
const YEAR_2100: i64 = 120;

/// MS-DOS date (bits 0-4 day, 5-8 month, 9-15 years since 1980) and time
/// (bits 0-4 two-second units, 5-10 minutes, 11-15 hours), plus the
/// optional 10 ms create-time byte, to wall-clock nanoseconds since the
/// epoch. Exactly Linux's `fat_time_fat2unix`: month 0 reads as January,
/// day 0 as the 1st, out-of-range fields are not rejected, and
/// `tz_offset_secs` (`fat_tz_offset`) is ADDED to the local time the
/// fields hold. A result before the epoch (only reachable through a
/// negative offset on 1980-01-01) clamps to 0, the stat layer's floor.
pub fn fat_time_to_unix_ns(time: u16, date: u16, time_cs: u8, tz_offset_secs: i64) -> u64 {
    let year = i64::from(date >> 9);
    let month = core::cmp::max(1, (date >> 5) & 0xf) as usize;
    let day = i64::from(core::cmp::max(1, date & 0x1f)) - 1;

    let mut leap_day = (year + 3) / 4;
    if year > YEAR_2100 {
        // 2100 isn't a leap year.
        leap_day -= 1;
    }
    let is_leap = (year & 3) == 0 && year != YEAR_2100;
    if is_leap && month > 2 {
        leap_day += 1;
    }

    let mut second = i64::from(time & 0x1f) << 1;
    second += i64::from((time >> 5) & 0x3f) * SECS_PER_MIN;
    second += i64::from(time >> 11) * SECS_PER_HOUR;
    second += (year * 365 + leap_day + DAYS_IN_YEAR[month] + day + DAYS_DELTA) * SECS_PER_DAY;
    second += tz_offset_secs;

    let (sec, nsec) = if time_cs != 0 {
        (
            second + i64::from(time_cs / 100),
            u64::from(time_cs % 100) * 10_000_000,
        )
    } else {
        (second, 0)
    };
    if sec < 0 {
        return 0;
    }
    sec as u64 * 1_000_000_000 + nsec
}

/// A FAT inode's times as Linux's `fat_fill_inode` builds them for vfat
/// (NARF's driver always handles long names, so it is vfat): mtime from
/// the write date/time with NO 10 ms field (that byte belongs to the
/// creation time), ctime = mtime (they share one on-disk field), atime =
/// the access DATE at local midnight. Nanoseconds since the epoch.
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct FatTimes {
    pub atime_ns: u64,
    pub mtime_ns: u64,
}

impl FatTimes {
    pub fn from_entry(entry: &DirEntry, tz_offset_secs: i64) -> Self {
        let (wrt_time, wrt_date, acc_date) = (entry.wrt_time, entry.wrt_date, entry.lst_acc_date);
        Self {
            atime_ns: fat_time_to_unix_ns(0, acc_date, 0, tz_offset_secs),
            mtime_ns: fat_time_to_unix_ns(wrt_time, wrt_date, 0, tz_offset_secs),
        }
    }
}

pub fn calculate_checksum(name: &[u8; 11]) -> u8 {
    let mut sum: u8 = 0;
    for &b in name {
        sum = (((sum & 1) << 7) as u16 + (sum >> 1) as u16 + b as u16) as u8;
    }
    sum
}

impl LfnEntry {
    pub fn extract_name(&self, out: &mut [u16]) -> usize {
        let mut count = 0;
        let name1 = self.name1;
        for &c in &name1 {
            if c == 0 || c == 0xFFFF {
                return count;
            }
            out[count] = c;
            count += 1;
        }
        let name2 = self.name2;
        for &c in &name2 {
            if c == 0 || c == 0xFFFF {
                return count;
            }
            out[count] = c;
            count += 1;
        }
        let name3 = self.name3;
        for &c in &name3 {
            if c == 0 || c == 0xFFFF {
                return count;
            }
            out[count] = c;
            count += 1;
        }
        count
    }
}
