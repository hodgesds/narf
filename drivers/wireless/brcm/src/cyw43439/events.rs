// SPDX-License-Identifier: GPL-2.0-or-later
//! Asynchronous-event codec for the CYW43439.
//!
//! The chip pushes *events* (link-up, scan-complete, deauth, etc.)
//! to the host on SDPCM channel `CHANNEL_EVENT` (channel 1). Each
//! event frame carries:
//!
//! - The standard SDPCM HW + SW headers (see [`super::sdpcm`]).
//! - An Ethernet frame (`ether_type = 0x886C`, "Broadcom event") —
//!   the same VTAG layout the chip uses for over-the-air events.
//! - A 10-byte Broadcom vendor envelope (subtype, OUI, user subtype).
//! - A 48-byte **BCM event header** in network byte order.
//! - The event-specific payload (variable-length).
//!
//! Wire layout and validation cross-checked against Linux
//! `drivers/net/wireless/broadcom/brcm80211/brcmfmac/fweh.h`
//! (`brcm_ethhdr`, `brcmf_event_msg_be`, `brcmf_event`) and
//! `fweh.c::brcmf_fweh_process_event`. SDPCM/BCDC transport headers
//! are little-endian; this event envelope is big-endian.

use core::convert::TryInto;

use super::sdpcm::FramingError;

/// EtherType the chip uses for events on channel 1.
pub const ETHERTYPE_BRCM_EVENT: u16 = 0x886C;
/// Length of the Ethernet header preceding a BCM event (dst + src +
/// type = 6 + 6 + 2).
pub const ETH_HEADER_LEN: usize = 14;
/// Length of the Broadcom vendor envelope after the Ethernet header.
pub const BRCM_ETH_HEADER_LEN: usize = 10;
/// Offset of the BCM event message after Ethernet and vendor headers.
pub const EVENT_HEADER_OFFSET: usize = ETH_HEADER_LEN + BRCM_ETH_HEADER_LEN;
/// Length of the BCM event message header.
pub const EVENT_HEADER_LEN: usize = 48;
/// Length of the complete Ethernet + vendor + event message envelope.
pub const EVENT_ENVELOPE_LEN: usize = EVENT_HEADER_OFFSET + EVENT_HEADER_LEN;

const BRCM_SUBTYPE_VENDOR_LONG: u16 = 0x8001;
const BRCM_USER_SUBTYPE_EVENT: u16 = 1;
const BRCM_OUI: [u8; 3] = [0x00, 0x10, 0x18];

// ── Representative event-type IDs (AN232689 + cross-checks) ───────

/// `WLC_E_SET_SSID` — association complete (success or failure).
pub const WLC_E_SET_SSID: u32 = 0;
/// `WLC_E_AUTH` — 802.11 authentication phase result.
pub const WLC_E_AUTH: u32 = 3;
/// `WLC_E_DEAUTH` — peer deauthenticated us.
pub const WLC_E_DEAUTH: u32 = 5;
/// `WLC_E_DEAUTH_IND` — we sent a deauth.
pub const WLC_E_DEAUTH_IND: u32 = 6;
/// `WLC_E_ASSOC` — we issued / received an association request.
pub const WLC_E_ASSOC: u32 = 7;
/// `WLC_E_DISASSOC` — disassociation result.
pub const WLC_E_DISASSOC: u32 = 11;
/// `WLC_E_DISASSOC_IND` — peer initiated disassociation.
pub const WLC_E_DISASSOC_IND: u32 = 12;
/// `WLC_E_LINK` — link came up or went down.
pub const WLC_E_LINK: u32 = 16;
/// `WLC_E_PRUNE` — candidate AP was pruned by the firmware roam
/// state machine.
pub const WLC_E_PRUNE: u32 = 23;
/// `WLC_E_PSK_SUP` — PSK 4-way handshake state changed.
pub const WLC_E_PSK_SUP: u32 = 46;
/// `WLC_E_ESCAN_RESULT` — extended-scan result delivery.
pub const WLC_E_ESCAN_RESULT: u32 = 69;

// ── Event status codes ────────────────────────────────────────────

/// Success status for an event.
pub const EVENT_STATUS_SUCCESS: u32 = 0;
/// Generic failure.
pub const EVENT_STATUS_FAIL: u32 = 1;
/// Operation timed out.
pub const EVENT_STATUS_TIMEOUT: u32 = 2;
/// No matching network was found.
pub const EVENT_STATUS_NO_NETWORKS: u32 = 3;

/// Decoded BCM event header.
///
/// Linux's `brcmf_event_msg_be` is a 48-byte packed structure carrying
/// (in order, multi-byte fields in big-endian / network byte order):
///
/// ```text
///    u16 version           (must be 1 or 2)
///    u16 flags
///    u32 event_type        (WLC_E_*)
///    u32 status            (EVENT_STATUS_*)
///    u32 reason
///    u32 auth_type
///    u32 datalen           (length of payload following this header)
///    u8  addr[6]           (MAC of the source station)
///    u8  ifname[16]        (interface name, e.g. "wl0")
///    u8  ifidx
///    u8  bsscfgidx
/// ```
///
/// Event-specific payload bytes follow this fixed header. Their own
/// encoding is event-dependent and is not converted by this codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventHeader {
    pub version: u16,
    pub flags: u16,
    pub event_type: u32,
    pub status: u32,
    pub reason: u32,
    pub auth_type: u32,
    pub datalen: u32,
    pub source_mac: [u8; 6],
    pub if_name: [u8; 16],
    pub if_idx: u8,
    pub bsscfg_idx: u8,
}

/// Errors produced by [`EventHeader::decode`] and [`parse_event`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventError {
    /// Source slice is shorter than the event header.
    ShortHeader,
    /// `version` field is not in the supported range.
    UnsupportedVersion(u16),
    /// Ethernet header's `ether_type` is not the BCM event type.
    NotBrcmEvent,
    /// Broadcom subtype, OUI or user subtype does not identify an event.
    NotBrcmEventEnvelope,
    /// The declared event data length exceeds the bytes received.
    TruncatedPayload,
    /// Underlying SDPCM framing error.
    Framing(FramingError),
}

impl From<FramingError> for EventError {
    fn from(e: FramingError) -> Self {
        EventError::Framing(e)
    }
}

impl EventHeader {
    pub fn decode(bytes: &[u8]) -> Result<Self, EventError> {
        if bytes.len() < EVENT_HEADER_LEN {
            return Err(EventError::ShortHeader);
        }
        let version = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        if version != 1 && version != 2 {
            return Err(EventError::UnsupportedVersion(version));
        }
        let flags = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
        let event_type = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        let status = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
        let reason = u32::from_be_bytes(bytes[12..16].try_into().unwrap());
        let auth_type = u32::from_be_bytes(bytes[16..20].try_into().unwrap());
        let datalen = u32::from_be_bytes(bytes[20..24].try_into().unwrap());
        let mut source_mac = [0u8; 6];
        source_mac.copy_from_slice(&bytes[24..30]);
        let mut if_name = [0u8; 16];
        if_name.copy_from_slice(&bytes[30..46]);
        let if_idx = bytes[46];
        let bsscfg_idx = bytes[47];
        Ok(Self {
            version,
            flags,
            event_type,
            status,
            reason,
            auth_type,
            datalen,
            source_mac,
            if_name,
            if_idx,
            bsscfg_idx,
        })
    }
}

/// A parsed event frame: the BCM event header plus a borrow of its
/// trailing payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event<'a> {
    pub header: EventHeader,
    pub payload: &'a [u8],
}

/// Parse a BCM event frame after the transport/data headers have been
/// removed: Ethernet → Broadcom vendor envelope → event message → payload.
/// Reject truncated event data; ignore bytes after its declared length
/// (for example Ethernet padding).
pub fn parse_event(frame: &[u8]) -> Result<Event<'_>, EventError> {
    if frame.len() < EVENT_ENVELOPE_LEN {
        return Err(EventError::ShortHeader);
    }
    let ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    if ether_type != ETHERTYPE_BRCM_EVENT {
        return Err(EventError::NotBrcmEvent);
    }
    let vendor = &frame[ETH_HEADER_LEN..EVENT_HEADER_OFFSET];
    if u16::from_be_bytes([vendor[0], vendor[1]]) != BRCM_SUBTYPE_VENDOR_LONG
        || vendor[5..8] != BRCM_OUI
        || u16::from_be_bytes([vendor[8], vendor[9]]) != BRCM_USER_SUBTYPE_EVENT
    {
        return Err(EventError::NotBrcmEventEnvelope);
    }
    let header = EventHeader::decode(&frame[EVENT_HEADER_OFFSET..])?;
    let data = &frame[EVENT_ENVELOPE_LEN..];
    let payload = data
        .get(..header.datalen as usize)
        .ok_or(EventError::TruncatedPayload)?;
    Ok(Event { header, payload })
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn build_test_frame(event_type: u32, payload: &[u8]) -> alloc::vec::Vec<u8> {
        let mut buf = alloc::vec::Vec::new();
        // Ethernet header: dst (6) + src (6) + ethertype (2).
        buf.extend_from_slice(&[0xFF; 6]); // broadcast dst
        buf.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        buf.extend_from_slice(&ETHERTYPE_BRCM_EVENT.to_be_bytes());
        // brcm_ethhdr: vendor-long subtype, length, version, OUI,
        // event user subtype. The length is not used to locate event data.
        buf.extend_from_slice(&[0x80, 0x01, 0, 0, 0, 0x00, 0x10, 0x18, 0x00, 0x01]);
        // Event header: 48 bytes.
        let mut hdr = [0u8; EVENT_HEADER_LEN];
        hdr[0..2].copy_from_slice(&1u16.to_be_bytes()); // version 1
        hdr[2..4].copy_from_slice(&0u16.to_be_bytes()); // flags
        hdr[4..8].copy_from_slice(&event_type.to_be_bytes());
        hdr[8..12].copy_from_slice(&0u32.to_be_bytes()); // status
        hdr[12..16].copy_from_slice(&0u32.to_be_bytes()); // reason
        hdr[16..20].copy_from_slice(&0u32.to_be_bytes()); // auth_type
        hdr[20..24].copy_from_slice(&(payload.len() as u32).to_be_bytes());
        // source mac, if_name, if_idx, bsscfg_idx — already zero.
        buf.extend_from_slice(&hdr);
        buf.extend_from_slice(payload);
        buf
    }

    fn smoke_event_round_trip() -> TestResult {
        let payload = b"hello-event";
        let frame = build_test_frame(WLC_E_LINK, payload);
        match parse_event(&frame) {
            Ok(e) => {
                if e.header.event_type != WLC_E_LINK {
                    return TestResult::Fail("event_type lost in decode");
                }
                if e.payload != payload {
                    return TestResult::Fail("payload mis-aligned");
                }
                if e.header.datalen as usize != payload.len() {
                    return TestResult::Fail("datalen wrong");
                }
            }
            Err(_) => return TestResult::Fail("parse_event failed on clean input"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/wireless/cyw43439/events", smoke_event_round_trip);

    fn smoke_event_rejects_wrong_ethertype() -> TestResult {
        let mut frame = build_test_frame(WLC_E_LINK, b"x");
        // Patch the ethertype to IPv4 (0x0800) — must reject.
        frame[12] = 0x08;
        frame[13] = 0x00;
        match parse_event(&frame) {
            Err(EventError::NotBrcmEvent) => TestResult::Pass,
            _ => TestResult::Fail("non-BRCM ethertype must be rejected"),
        }
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/events",
        smoke_event_rejects_wrong_ethertype
    );

    fn smoke_event_rejects_bad_version() -> TestResult {
        let mut frame = build_test_frame(WLC_E_AUTH, b"x");
        // Patch version to 0 — must reject.
        frame[EVENT_HEADER_OFFSET] = 0;
        frame[EVENT_HEADER_OFFSET + 1] = 0;
        match parse_event(&frame) {
            Err(EventError::UnsupportedVersion(0)) => TestResult::Pass,
            _ => TestResult::Fail("unsupported version not rejected"),
        }
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/events",
        smoke_event_rejects_bad_version
    );

    fn smoke_event_linux_wire_fixture() -> TestResult {
        // Literal Linux fweh.h layout, independent of the test builder:
        // Ethernet (14), brcm_ethhdr (10), brcmf_event_msg_be (48), data (4).
        // Event-specific data remains in its original byte order.
        let frame: [u8; 76] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst
            0x02, 0x11, 0x22, 0x33, 0x44, 0x55, // src
            0x88, 0x6c, // EtherType
            0x80, 0x01, 0x00, 0x3e, 0x00, 0x00, 0x10, 0x18, 0x00, 0x01, // vendor
            0x00, 0x02, // version
            0x00, 0x01, // flags
            0x00, 0x00, 0x00, 0x45, // ESCAN_RESULT
            0x00, 0x00, 0x00, 0x08, // PARTIAL
            0x01, 0x02, 0x03, 0x04, // reason
            0x05, 0x06, 0x07, 0x08, // auth_type
            0x00, 0x00, 0x00, 0x04, // datalen
            0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, // station MAC
            b'w', b'l', b'0', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // ifname
            0x02, 0x03, // ifidx, bsscfgidx
            0x44, 0x33, 0x22, 0x11, // event payload
        ];
        let event = match parse_event(&frame) {
            Ok(event) => event,
            Err(_) => return TestResult::Fail("Linux firmware event envelope rejected"),
        };
        if event.header.version != 2
            || event.header.flags != 1
            || event.header.event_type != WLC_E_ESCAN_RESULT
            || event.header.status != 8
            || event.header.reason != 0x0102_0304
            || event.header.auth_type != 0x0506_0708
            || event.header.datalen != 4
            || event.header.source_mac != [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]
            || &event.header.if_name[..3] != b"wl0"
            || event.header.if_idx != 2
            || event.header.bsscfg_idx != 3
            || event.payload != [0x44, 0x33, 0x22, 0x11]
        {
            return TestResult::Fail("Linux firmware event fields decoded at wrong offset/order");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/events",
        smoke_event_linux_wire_fixture
    );

    fn smoke_event_validates_vendor_envelope() -> TestResult {
        // Subtype, each OUI octet and user subtype are event discriminators.
        for offset in [14, 15, 19, 20, 21, 22, 23] {
            let mut frame = build_test_frame(WLC_E_LINK, &[]);
            frame[offset] ^= 0xff;
            if parse_event(&frame) != Err(EventError::NotBrcmEventEnvelope) {
                return TestResult::Fail("invalid Broadcom event discriminator accepted");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/events",
        smoke_event_validates_vendor_envelope
    );

    fn smoke_event_rejects_truncated_envelope_and_payload() -> TestResult {
        let frame = build_test_frame(WLC_E_LINK, &[1, 2, 3, 4]);
        for len in 0..EVENT_ENVELOPE_LEN {
            if parse_event(&frame[..len]) != Err(EventError::ShortHeader) {
                return TestResult::Fail("truncated event envelope accepted");
            }
        }
        for len in EVENT_ENVELOPE_LEN..frame.len() {
            if parse_event(&frame[..len]) != Err(EventError::TruncatedPayload) {
                return TestResult::Fail("truncated event payload accepted");
            }
        }
        let mut oversized = frame;
        oversized[EVENT_HEADER_OFFSET + 20..EVENT_HEADER_OFFSET + 24]
            .copy_from_slice(&u32::MAX.to_be_bytes());
        if parse_event(&oversized) != Err(EventError::TruncatedPayload) {
            return TestResult::Fail("oversized event data length accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/events",
        smoke_event_rejects_truncated_envelope_and_payload
    );

    fn smoke_event_ignores_transport_padding() -> TestResult {
        let mut frame = build_test_frame(WLC_E_LINK, &[0xaa]);
        frame.extend_from_slice(&[0xbb; 3]);
        if parse_event(&frame).map(|event| event.payload) != Ok(&[0xaa][..]) {
            return TestResult::Fail("padding leaked into event payload");
        }
        let mut empty = build_test_frame(WLC_E_LINK, &[]);
        empty.extend_from_slice(&[0xbb; 3]);
        if parse_event(&empty).map(|event| event.payload) != Ok(&[][..]) {
            return TestResult::Fail("zero-length event included padding");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/events",
        smoke_event_ignores_transport_padding
    );
}
