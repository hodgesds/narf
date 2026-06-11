//! NTPv4 packet codec — clean-room.
//!
//! References (public-only):
//! - RFC 5905 — Network Time Protocol Version 4 (D. Mills et al,
//!   June 2010). §7.3 (Packet Header Variables — 48-byte fixed
//!   header). §7.5 (Packet Header Format — bit layout). §6 (NTP
//!   timestamp format: 64-bit field, 32-bit seconds since the NTP
//!   prime epoch + 32-bit fractional second).
//!   <https://datatracker.ietf.org/doc/html/rfc5905>
//! - RFC 868 — Time Protocol — kept in mind for the historical
//!   1900-01-01 NTP prime epoch.
//!   <https://datatracker.ietf.org/doc/html/rfc868>
//!
//! No GPL Linux source consulted.
//!
//! ## Header (RFC 5905 §7.5, figure 8)
//!
//! 48 bytes (the fixed portion; key/digest extension fields aren't
//! decoded here):
//!
//! ```text
//!   byte 0:
//!     bits 7..6  LI   (Leap Indicator: 0=ok, 1=last min has 61s,
//!                       2=last min has 59s, 3=alarm/unsynced)
//!     bits 5..3  VN   (Version Number: 4 for NTPv4)
//!     bits 2..0  Mode (3=client, 4=server, 5=broadcast,
//!                       6=NTP control message)
//!   byte 1     Stratum
//!   byte 2     Poll (signed log2 seconds, typical 4..17)
//!   byte 3     Precision (signed log2 seconds)
//!   bytes 4..7   Root Delay        (NTP short fixed-point: 16.16)
//!   bytes 8..11  Root Dispersion   (NTP short fixed-point: 16.16)
//!   bytes 12..15 Reference ID      (4 bytes — usually a 4-character
//!                                    "kiss code" at stratum 0/1)
//!   bytes 16..23 Reference Timestamp (NTP 64-bit)
//!   bytes 24..31 Origin Timestamp    (T1)
//!   bytes 32..39 Receive Timestamp   (T2)
//!   bytes 40..47 Transmit Timestamp  (T3)
//! ```

extern crate alloc;

/// Header byte length (RFC 5905 §7.5).
pub const NTP_HDR_LEN: usize = 48;

/// NTP prime epoch is 1900-01-01 — Unix epoch (1970-01-01) is this
/// many seconds later.
pub const NTP_UNIX_EPOCH_OFFSET_SECS: u64 = 2_208_988_800;

// ── LI / VN / Mode (RFC 5905 §7.3) ────────────────────────────────

pub const LI_NO_WARNING: u8 = 0;
pub const LI_LAST_MIN_HAS_61_SECONDS: u8 = 1;
pub const LI_LAST_MIN_HAS_59_SECONDS: u8 = 2;
pub const LI_ALARM_UNSYNCED: u8 = 3;

pub const NTP_VERSION_3: u8 = 3;
pub const NTP_VERSION_4: u8 = 4;

pub const MODE_RESERVED: u8 = 0;
pub const MODE_SYMMETRIC_ACTIVE: u8 = 1;
pub const MODE_SYMMETRIC_PASSIVE: u8 = 2;
pub const MODE_CLIENT: u8 = 3;
pub const MODE_SERVER: u8 = 4;
pub const MODE_BROADCAST: u8 = 5;
pub const MODE_NTP_CONTROL: u8 = 6;
pub const MODE_PRIVATE: u8 = 7;

/// Stratum special values (RFC 5905 §3 + §11.2).
pub const STRATUM_UNSPECIFIED: u8 = 0;
pub const STRATUM_PRIMARY: u8 = 1;
pub const STRATUM_UNSYNCED: u8 = 16;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NtpError {
    Short,
}

// ── Timestamp helpers ──────────────────────────────────────────────

/// Convert a Unix epoch (seconds + fractional 2^-32 ticks) to the
/// 64-bit NTP timestamp.
pub fn unix_to_ntp(unix_seconds: u64, fractional_2e32: u32) -> u64 {
    let ntp_seconds = unix_seconds + NTP_UNIX_EPOCH_OFFSET_SECS;
    (ntp_seconds << 32) | (fractional_2e32 as u64)
}

/// Convert an NTP 64-bit timestamp to Unix-epoch seconds + the raw
/// 32-bit fractional field. Returns `None` if the timestamp is below
/// the Unix epoch (rarely meaningful — would mean before 1970).
pub fn ntp_to_unix(ntp: u64) -> Option<(u64, u32)> {
    let ntp_seconds = ntp >> 32;
    if ntp_seconds < NTP_UNIX_EPOCH_OFFSET_SECS {
        return None;
    }
    Some((
        ntp_seconds - NTP_UNIX_EPOCH_OFFSET_SECS,
        (ntp & 0xFFFF_FFFF) as u32,
    ))
}

// ── Header ─────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct NtpHeader {
    pub leap_indicator: u8,
    pub version: u8,
    pub mode: u8,
    pub stratum: u8,
    /// Poll exponent (signed log2 of seconds).
    pub poll: i8,
    /// Precision exponent (signed log2 of seconds).
    pub precision: i8,
    /// NTP short-fixed (16.16): bits 31..16 = seconds, 15..0 = fraction.
    pub root_delay: u32,
    pub root_dispersion: u32,
    pub reference_id: [u8; 4],
    pub reference_timestamp: u64,
    pub origin_timestamp: u64,
    pub receive_timestamp: u64,
    pub transmit_timestamp: u64,
}

impl NtpHeader {
    pub fn encode(&self) -> [u8; NTP_HDR_LEN] {
        let mut out = [0u8; NTP_HDR_LEN];
        out[0] =
            ((self.leap_indicator & 0x03) << 6) | ((self.version & 0x07) << 3) | (self.mode & 0x07);
        out[1] = self.stratum;
        out[2] = self.poll as u8;
        out[3] = self.precision as u8;
        out[4..8].copy_from_slice(&self.root_delay.to_be_bytes());
        out[8..12].copy_from_slice(&self.root_dispersion.to_be_bytes());
        out[12..16].copy_from_slice(&self.reference_id);
        out[16..24].copy_from_slice(&self.reference_timestamp.to_be_bytes());
        out[24..32].copy_from_slice(&self.origin_timestamp.to_be_bytes());
        out[32..40].copy_from_slice(&self.receive_timestamp.to_be_bytes());
        out[40..48].copy_from_slice(&self.transmit_timestamp.to_be_bytes());
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, NtpError> {
        if buf.len() < NTP_HDR_LEN {
            return Err(NtpError::Short);
        }
        let mut reference_id = [0u8; 4];
        reference_id.copy_from_slice(&buf[12..16]);
        Ok(Self {
            leap_indicator: (buf[0] >> 6) & 0x03,
            version: (buf[0] >> 3) & 0x07,
            mode: buf[0] & 0x07,
            stratum: buf[1],
            poll: buf[2] as i8,
            precision: buf[3] as i8,
            root_delay: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            root_dispersion: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
            reference_id,
            reference_timestamp: u64::from_be_bytes([
                buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
            ]),
            origin_timestamp: u64::from_be_bytes([
                buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31],
            ]),
            receive_timestamp: u64::from_be_bytes([
                buf[32], buf[33], buf[34], buf[35], buf[36], buf[37], buf[38], buf[39],
            ]),
            transmit_timestamp: u64::from_be_bytes([
                buf[40], buf[41], buf[42], buf[43], buf[44], buf[45], buf[46], buf[47],
            ]),
        })
    }
}

/// Build a SNTP-style client request (RFC 5905 §14): VN=4, Mode=3,
/// Stratum=0 (per the request convention), all timestamps zero
/// except the Transmit Timestamp the host samples just before the
/// send.
pub fn client_request(transmit_timestamp_ntp: u64) -> NtpHeader {
    NtpHeader {
        leap_indicator: LI_ALARM_UNSYNCED,
        version: NTP_VERSION_4,
        mode: MODE_CLIENT,
        stratum: STRATUM_UNSPECIFIED,
        poll: 0,
        precision: 0,
        root_delay: 0,
        root_dispersion: 0,
        reference_id: [0; 4],
        reference_timestamp: 0,
        origin_timestamp: 0,
        receive_timestamp: 0,
        transmit_timestamp: transmit_timestamp_ntp,
    }
}

/// NTP "short fixed-point" (16.16) — convert to seconds (rounded
/// down) and the 16-bit fractional field.
pub fn short_to_secs_frac(short: u32) -> (u16, u16) {
    (((short >> 16) & 0xFFFF) as u16, (short & 0xFFFF) as u16)
}

/// Build the 16.16 short-fixed-point form from integer seconds + 16-
/// bit fractional units.
pub fn short_from_secs_frac(secs: u16, frac: u16) -> u32 {
    ((secs as u32) << 16) | (frac as u32)
}
