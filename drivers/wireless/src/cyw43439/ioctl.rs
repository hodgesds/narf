//! IOCTL command codec for the CYW43439.
//!
//! IOCTLs are the SET/GET request-response pairs the host issues on
//! SDPCM channel `CHANNEL_CONTROL` (channel 0) using the BCDC
//! framing in [`super::sdpcm`]. The full IOCTL set is documented in
//! Infineon's **AN232689 Wi-Fi Software User Guide** (which lists
//! the high-level commands a host driver issues) and in the wider
//! Broadcom CDC literature; the on-the-wire numbering is the
//! long-standing `WLC_*` set, also reproduced verbatim in the
//! permissively-licensed cross-checks (`soypat/cyw43439` MIT,
//! Embassy `cyw43` Apache-2.0 / MIT). **No GPL `brcmfmac` /
//! `bcmdhd` source consulted.**
//!
//! This module provides:
//!
//! - The numeric `WLC_*` command set (a representative subset; the
//!   full ~300-entry list is intentionally not exhaustive — entries
//!   land here as they're needed by code in `narf-wireless`).
//! - [`build_request`] — compose a complete IOCTL request frame
//!   (HW header + SW header + BCDC header + payload) for emission
//!   on F2.
//! - [`parse_response`] — split a received F2 frame back into its
//!   parts and surface the chip's `status` code.

use alloc::vec::Vec;

use super::sdpcm::{
    bcdc_flag, BcdcHeader, FramingError, HwHeader, SwHeader, BCDC_HEADER_LEN, CHANNEL_CONTROL,
    HW_HEADER_LEN, SW_HEADER_LEN,
};

// ── Representative IOCTL command numbers ──────────────────────────
//
// These are the long-standing Broadcom `WLC_*` IDs (also documented
// in AN232689). Each constant is grouped by what it does so that
// reviewers can audit the public-doc justification without hunting
// for individual entries.

/// `WLC_GET_MAGIC` — read the firmware "magic" value to confirm the
/// IOCTL channel is up and the chip's endianness matches.
pub const WLC_GET_MAGIC: u32 = 1;
/// `WLC_UP` — bring the radio up (associate / scan can follow).
pub const WLC_UP: u32 = 2;
/// `WLC_DOWN` — take the radio back down.
pub const WLC_DOWN: u32 = 3;
/// `WLC_GET_VERSION` — read the host-API version the firmware
/// implements (used to gate IOVAR availability).
pub const WLC_GET_VERSION: u32 = 4;
/// `WLC_GET_INFRA` — read whether infra (managed STA) mode is on.
pub const WLC_GET_INFRA: u32 = 19;
/// `WLC_SET_INFRA` — set infra (managed STA) mode.
pub const WLC_SET_INFRA: u32 = 20;
/// `WLC_GET_AUTH` — read the current auth mode.
pub const WLC_GET_AUTH: u32 = 21;
/// `WLC_SET_AUTH` — set the current auth mode.
pub const WLC_SET_AUTH: u32 = 22;
/// `WLC_GET_BSSID` — read the BSSID we're associated with.
pub const WLC_GET_BSSID: u32 = 23;
/// `WLC_SET_BSSID` — direct-associate to a specified BSSID.
pub const WLC_SET_BSSID: u32 = 26;
/// `WLC_GET_SSID` — read the SSID the firmware reports.
pub const WLC_GET_SSID: u32 = 25;
/// `WLC_SET_SSID` — request association to an SSID.
pub const WLC_SET_SSID: u32 = 26;
/// `WLC_GET_CHANNEL` — read the current channel.
pub const WLC_GET_CHANNEL: u32 = 29;
/// `WLC_SET_CHANNEL` — set the channel for non-association
/// (e.g. monitor / IBSS).
pub const WLC_SET_CHANNEL: u32 = 30;
/// `WLC_SCAN` — issue a scan request. The payload describes the
/// scan parameters; results are read via `WLC_SCAN_RESULTS`.
pub const WLC_SCAN: u32 = 50;
/// `WLC_SCAN_RESULTS` — fetch the most recent scan result list.
pub const WLC_SCAN_RESULTS: u32 = 51;
/// `WLC_DISASSOC` — disassociate from the current AP.
pub const WLC_DISASSOC: u32 = 52;
/// `WLC_REASSOC` — request a re-association.
pub const WLC_REASSOC: u32 = 53;
/// `WLC_SET_RADIO` — set the radio on/off.
pub const WLC_SET_RADIO: u32 = 38;
/// `WLC_SET_PASSIVE_SCAN` — toggle passive-scan mode.
pub const WLC_SET_PASSIVE_SCAN: u32 = 49;
/// `WLC_GET_PASSIVE_SCAN` — read the passive-scan state.
pub const WLC_GET_PASSIVE_SCAN: u32 = 48;
/// `WLC_GET_VAR` — read a string-keyed firmware variable. The
/// payload begins with the NUL-terminated variable name, followed
/// by space for the response.
pub const WLC_GET_VAR: u32 = 262;
/// `WLC_SET_VAR` — write a string-keyed firmware variable. The
/// payload begins with the NUL-terminated variable name followed by
/// the variable's value bytes.
pub const WLC_SET_VAR: u32 = 263;

// ── Request / response builders ────────────────────────────────────

/// Direction of an IOCTL — Set or Get.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Get,
    Set,
}

/// Compose a complete IOCTL request frame on SDPCM channel 0.
///
/// Returns the on-wire byte sequence (HW header + SW header + BCDC
/// header + payload + trailing pad to 4-byte alignment, as the chip
/// requires).
pub fn build_request(
    seq: u8,
    xact_id: u16,
    if_idx: u8,
    direction: Direction,
    cmd: u32,
    payload: &[u8],
) -> Vec<u8> {
    let payload_len = payload.len();
    let header_total = HW_HEADER_LEN + SW_HEADER_LEN + BCDC_HEADER_LEN;
    let unpadded = header_total + payload_len;
    // Pad the whole frame to a 4-byte boundary.
    let padded = (unpadded + 3) & !3;

    let mut buf = Vec::with_capacity(padded);

    let hw = HwHeader {
        length: padded as u16,
    };
    buf.extend_from_slice(&hw.encode());

    let sw = SwHeader {
        seq,
        channel: CHANNEL_CONTROL,
        flags: 0,
        next_len_16: 0,
        data_offset: (HW_HEADER_LEN + SW_HEADER_LEN) as u8,
        fc_mask: 0,
        max_seq: 0,
    };
    buf.extend_from_slice(&sw.encode());

    let mut flags = (u32::from(if_idx) << bcdc_flag::IF_SHIFT) & bcdc_flag::IF_MASK;
    flags |= (u32::from(xact_id) << bcdc_flag::ID_SHIFT) & bcdc_flag::ID_MASK;
    if matches!(direction, Direction::Set) {
        flags |= bcdc_flag::SET;
    }
    let bcdc = BcdcHeader {
        cmd,
        len: payload_len as u32,
        flags,
        status: 0,
    };
    buf.extend_from_slice(&bcdc.encode());
    buf.extend_from_slice(payload);
    while buf.len() < padded {
        buf.push(0);
    }
    buf
}

/// Parsed view of an IOCTL response frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Response<'a> {
    pub hw: HwHeader,
    pub sw: SwHeader,
    pub bcdc: BcdcHeader,
    pub payload: &'a [u8],
}

/// Errors returned from [`parse_response`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    Framing(FramingError),
    /// SDPCM SW header reports a `data_offset` outside the frame.
    BadDataOffset,
    /// HW header length disagrees with the buffer slice.
    LengthMismatch,
    /// SW header reports a non-control channel (caller should
    /// dispatch to the data / event path instead).
    NotControlChannel,
    /// BCDC `status` is non-zero (chip rejected the command).
    /// The numeric status is preserved on the variant.
    ChipError(u32),
}

impl From<FramingError> for ParseError {
    fn from(e: FramingError) -> Self {
        ParseError::Framing(e)
    }
}

/// Decode a full received IOCTL frame.
pub fn parse_response(frame: &[u8]) -> Result<Response<'_>, ParseError> {
    let hw = HwHeader::decode(frame)?;
    if usize::from(hw.length) != frame.len() {
        return Err(ParseError::LengthMismatch);
    }
    let sw = SwHeader::decode(&frame[HW_HEADER_LEN..])?;
    if sw.channel != CHANNEL_CONTROL {
        return Err(ParseError::NotControlChannel);
    }
    let doff = usize::from(sw.data_offset);
    if doff > frame.len() || doff < HW_HEADER_LEN + SW_HEADER_LEN {
        return Err(ParseError::BadDataOffset);
    }
    let bcdc_start = doff;
    if bcdc_start + BCDC_HEADER_LEN > frame.len() {
        return Err(ParseError::Framing(FramingError::ShortHeader));
    }
    let bcdc = BcdcHeader::decode(&frame[bcdc_start..])?;
    if bcdc.status != 0 {
        return Err(ParseError::ChipError(bcdc.status));
    }
    let payload_start = bcdc_start + BCDC_HEADER_LEN;
    let payload_len = bcdc.len as usize;
    let payload_end = payload_start + payload_len;
    if payload_end > frame.len() {
        return Err(ParseError::Framing(FramingError::ShortHeader));
    }
    Ok(Response {
        hw,
        sw,
        bcdc,
        payload: &frame[payload_start..payload_end],
    })
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_request_layout() -> TestResult {
        // SET_VAR with a 12-byte payload should produce a frame with
        //   HW (4) + SW (8) + BCDC (16) + payload (12) = 40 bytes,
        // already 4-byte aligned, no padding.
        let payload: &[u8] = b"country\x00US\x00\x00";
        let frame = build_request(1, 0xBEEF, 0, Direction::Set, WLC_SET_VAR, payload);
        if frame.len() != HW_HEADER_LEN + SW_HEADER_LEN + BCDC_HEADER_LEN + payload.len() {
            return TestResult::Fail("frame length wrong");
        }
        // HW header length must equal the full frame length.
        let hw = match HwHeader::decode(&frame) {
            Ok(h) => h,
            Err(_) => return TestResult::Fail("HW header decode failed"),
        };
        if usize::from(hw.length) != frame.len() {
            return TestResult::Fail("HW length mismatch");
        }
        // SW header must point at the BCDC header start.
        let sw = match SwHeader::decode(&frame[HW_HEADER_LEN..]) {
            Ok(s) => s,
            Err(_) => return TestResult::Fail("SW header decode failed"),
        };
        if usize::from(sw.data_offset) != HW_HEADER_LEN + SW_HEADER_LEN {
            return TestResult::Fail("SW data_offset wrong");
        }
        if sw.channel != CHANNEL_CONTROL {
            return TestResult::Fail("SW channel must be CONTROL");
        }
        // BCDC header.
        let bcdc = match BcdcHeader::decode(&frame[HW_HEADER_LEN + SW_HEADER_LEN..]) {
            Ok(b) => b,
            Err(_) => return TestResult::Fail("BCDC header decode failed"),
        };
        if bcdc.cmd != WLC_SET_VAR {
            return TestResult::Fail("BCDC cmd field wrong");
        }
        if !bcdc.is_set() {
            return TestResult::Fail("BCDC SET flag not asserted");
        }
        if bcdc.xact_id() != 0xBEEF {
            return TestResult::Fail("BCDC xact_id wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/wireless/cyw43439/ioctl", smoke_request_layout);

    fn smoke_request_padding() -> TestResult {
        // 5-byte payload should pad the frame out to 4-byte alignment.
        let payload = [0xAAu8; 5];
        let frame = build_request(2, 1, 0, Direction::Get, WLC_GET_VAR, &payload);
        if frame.len() % 4 != 0 {
            return TestResult::Fail("frame not 4-byte aligned");
        }
        let unpadded = HW_HEADER_LEN + SW_HEADER_LEN + BCDC_HEADER_LEN + payload.len();
        if frame.len() < unpadded {
            return TestResult::Fail("frame shorter than headers + payload");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/wireless/cyw43439/ioctl", smoke_request_padding);

    fn smoke_response_round_trip() -> TestResult {
        // Build a request, swap the BCDC `status` to a fake error,
        // and assert parse_response surfaces it.
        let payload = b"\x00\x00\x00\x00";
        let mut frame = build_request(3, 7, 0, Direction::Get, WLC_GET_MAGIC, payload);
        // Patch BCDC status to non-zero.
        let bcdc_start = HW_HEADER_LEN + SW_HEADER_LEN;
        frame[bcdc_start + 12] = 0xAA;
        frame[bcdc_start + 13] = 0x00;
        frame[bcdc_start + 14] = 0x00;
        frame[bcdc_start + 15] = 0x00;
        match parse_response(&frame) {
            Err(ParseError::ChipError(0xAA)) => {}
            _ => return TestResult::Fail("non-zero BCDC status not surfaced"),
        }
        // Now zero the status and confirm parse succeeds.
        for b in &mut frame[bcdc_start + 12..bcdc_start + 16] {
            *b = 0;
        }
        match parse_response(&frame) {
            Ok(r) => {
                if r.bcdc.cmd != WLC_GET_MAGIC {
                    return TestResult::Fail("BCDC cmd round-trip wrong");
                }
                if r.bcdc.xact_id() != 7 {
                    return TestResult::Fail("BCDC xact_id round-trip wrong");
                }
            }
            Err(_) => return TestResult::Fail("parse failed for clean response"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/wireless/cyw43439/ioctl", smoke_response_round_trip);

    fn smoke_response_rejects_wrong_channel() -> TestResult {
        let payload = [0u8; 4];
        let mut frame = build_request(0, 0, 0, Direction::Get, WLC_GET_MAGIC, &payload);
        // Flip channel field to DATA.
        let chan_byte_index = HW_HEADER_LEN + 1;
        frame[chan_byte_index] =
            (frame[chan_byte_index] & 0xF0) | super::super::sdpcm::CHANNEL_DATA;
        match parse_response(&frame) {
            Err(ParseError::NotControlChannel) => TestResult::Pass,
            _ => TestResult::Fail("data-channel frame must not parse as IOCTL"),
        }
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/ioctl",
        smoke_response_rejects_wrong_channel
    );
}
