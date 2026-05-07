//! `EFI_TIME` + `EFI_TIME_CAPABILITIES` — UEFI 2.10 §8.3.

extern crate alloc;

/// Sentinel TimeZone meaning "use local time" (no UTC offset).
pub const EFI_UNSPECIFIED_TIMEZONE: i16 = 0x07FF;

/// `EFI_TIME` — 16 bytes (UEFI 2.10 §8.3.1).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct EfiTime {
    pub year: u16,         // 1900..=9999
    pub month: u8,         // 1..=12
    pub day: u8,           // 1..=31
    pub hour: u8,          // 0..=23
    pub minute: u8,        // 0..=59
    pub second: u8,        // 0..=59 (no leap-second flag here)
    pub nanosecond: u32,   // 0..=999_999_999
    /// Minutes east of UTC (-1440..=1440), or `EFI_UNSPECIFIED_TIMEZONE`.
    pub time_zone: i16,
    /// Daylight-savings flags (UEFI 2.10 §8.3.1 EFI_TIME_DAYLIGHT_*).
    pub daylight: u8,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TimeError {
    Short,
    OutOfRange,
}

impl EfiTime {
    /// Decode the 16-byte wire form.
    pub fn decode(buf: &[u8]) -> Result<Self, TimeError> {
        if buf.len() < 16 {
            return Err(TimeError::Short);
        }
        let t = Self {
            year: u16::from_le_bytes([buf[0], buf[1]]),
            month: buf[2],
            day: buf[3],
            hour: buf[4],
            minute: buf[5],
            second: buf[6],
            // buf[7] is Pad1.
            nanosecond: u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
            time_zone: i16::from_le_bytes([buf[12], buf[13]]),
            daylight: buf[14],
            // buf[15] is Pad2.
        };
        if !(1900..=9999).contains(&t.year)
            || !(1..=12).contains(&t.month)
            || !(1..=31).contains(&t.day)
            || t.hour > 23
            || t.minute > 59
            || t.second > 59
            || t.nanosecond > 999_999_999
        {
            return Err(TimeError::OutOfRange);
        }
        Ok(t)
    }

    /// Encode to the 16-byte wire form.
    pub fn encode(self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0..2].copy_from_slice(&self.year.to_le_bytes());
        b[2] = self.month;
        b[3] = self.day;
        b[4] = self.hour;
        b[5] = self.minute;
        b[6] = self.second;
        b[8..12].copy_from_slice(&self.nanosecond.to_le_bytes());
        b[12..14].copy_from_slice(&self.time_zone.to_le_bytes());
        b[14] = self.daylight;
        b
    }
}

/// `EFI_TIME_CAPABILITIES` — 12 bytes (UEFI 2.10 §8.3.2).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct EfiTimeCapabilities {
    /// Reporting resolution in clock ticks per second.
    pub resolution: u32,
    /// Worst-case error in parts-per-million.
    pub accuracy: u32,
    /// `true` if `SetTime()` clears the sub-second portion.
    pub sets_to_zero: bool,
}

impl EfiTimeCapabilities {
    pub fn decode(buf: &[u8]) -> Result<Self, TimeError> {
        if buf.len() < 12 {
            return Err(TimeError::Short);
        }
        Ok(Self {
            resolution: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            accuracy: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
            sets_to_zero: buf[8] != 0,
        })
    }
}
