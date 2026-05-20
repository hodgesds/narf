//! USB CDC Network Control Model (NCM) 1.0 — clean-room.
//!
//! References (public-only):
//! - **USB Network Control Model (NCM) Specification, Revision
//!   1.0 with Errata and Adopters Agreement** (USB-IF, September
//!   2010 / errata March 2014). Public, usb.org. §3.2 (NTB-16
//!   framing — NTH16 + NDP16 + datagrams), §3.3 (NTB-32),
//!   §6.2.1 (`GET_NTB_PARAMETERS`), §7.1 (NCM Functional
//!   Descriptor).
//!   <https://www.usb.org/document-library/class-definitions-communication-devices-12>
//! - **USB CDC 1.2** §5.2.3 (functional descriptor common
//!   header). Public.
//!   <https://www.usb.org/document-library/class-definitions-communication-devices-12>
//! - **USB ECM 1.2** §5.4 (Ethernet Networking Functional
//!   Descriptor — NCM reuses the MAC-address ASCII string slot).
//!   Public.
//!   <https://www.usb.org/document-library/class-definitions-communication-devices-12>
//!
//! No GPL Linux source consulted.
//!
//! ## Why NCM
//!
//! NCM is the modern USB-Ethernet protocol every USB-C dock and
//! tethered-phone uses. It batches multiple Ethernet datagrams
//! into a single bulk transfer (the "NCM Transfer Block", NTB)
//! to amortise USB-2/3 transfer overhead. The host driver:
//!
//! 1. Parses the NCM Functional Descriptor to learn the device's
//!    MAC address (string-descriptor index) + supported features.
//! 2. Issues `GET_NTB_PARAMETERS` to learn max NTB sizes,
//!    alignment, NDP type (NDP16 / NDP32), and datagram counts.
//! 3. RX: reads NTBs from bulk IN, parses the NTH16 header, walks
//!    the NDP16 datagram-pointer table, hands each Ethernet
//!    frame to the network stack.
//! 4. TX: batches Ethernet frames into NTBs, builds an NDP16
//!    pointer table, ships the NTB on bulk OUT.
//!
//! ## NTB-16 layout (§3.2)
//!
//! ```text
//!  ┌──────────────────────────┐
//!  │  NTH16 (12 bytes)        │  signature, length, sequence,
//!  │                          │  total NTB length, NDP offset
//!  ├──────────────────────────┤
//!  │  Datagram 0              │
//!  │  …                       │
//!  │  Datagram N-1            │  (each is a raw Ethernet frame)
//!  ├──────────────────────────┤
//!  │  NDP16 (8 + 4*N bytes)   │  signature, length, next NDP,
//!  │                          │  per-datagram (offset, length)
//!  └──────────────────────────┘
//! ```
//!
//! Datagrams are placed *before* the NDP, but the NTH16 carries
//! the NDP's offset so the receiver can find it without
//! scanning.

use alloc::vec::Vec;
use core::convert::TryInto;

use super::cdc::{check_class_specific, CdcError, FunctionalSubtype};

// ── Class-specific request codes (NCM 1.0 §6.2) ──────────────────

pub const REQ_GET_NTB_PARAMETERS: u8 = 0x80;
pub const REQ_GET_NET_ADDRESS: u8 = 0x81;
pub const REQ_SET_NET_ADDRESS: u8 = 0x82;
pub const REQ_GET_NTB_FORMAT: u8 = 0x83;
pub const REQ_SET_NTB_FORMAT: u8 = 0x84;
pub const REQ_GET_NTB_INPUT_SIZE: u8 = 0x85;
pub const REQ_SET_NTB_INPUT_SIZE: u8 = 0x86;
pub const REQ_GET_MAX_DATAGRAM_SIZE: u8 = 0x87;
pub const REQ_SET_MAX_DATAGRAM_SIZE: u8 = 0x88;
pub const REQ_GET_CRC_MODE: u8 = 0x89;
pub const REQ_SET_CRC_MODE: u8 = 0x8A;

// ── NTB signatures (NCM 1.0 §3.2.1) ──────────────────────────────

/// `NTH16` signature — "NCMH" little-endian.
pub const NTH16_SIGNATURE: u32 = 0x484D_434E;
/// `NTH32` signature — "ncmh" little-endian.
pub const NTH32_SIGNATURE: u32 = 0x686D_636E;
/// `NDP16` signature — "NCM0" (no CRC) or "NCM1" (CRC).
pub const NDP16_SIGNATURE_NO_CRC: u32 = 0x304D_434E;
pub const NDP16_SIGNATURE_CRC: u32 = 0x314D_434E;

// ── NCM Functional Descriptor (NCM 1.0 §7.1) ─────────────────────

/// NCM functional-descriptor `bmNetworkCapabilities` bit set.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct NetworkCapabilities {
    /// Device supports `SET_ETHERNET_PACKET_FILTER`.
    pub packet_filter: bool,
    /// Device supports `GET_NET_ADDRESS` / `SET_NET_ADDRESS`.
    pub net_address: bool,
    /// Device supports `GET/SET_ENCAP_COMMAND`.
    pub encap_command: bool,
    /// Device supports `MAX_DATAGRAM_SIZE` requests.
    pub max_datagram_size: bool,
    /// Device supports `CRC_MODE` requests.
    pub crc_mode: bool,
    /// Device supports the 8-byte NDP word alignment.
    pub ndp_8byte: bool,
}

impl NetworkCapabilities {
    pub fn decode(byte: u8) -> Self {
        Self {
            packet_filter: byte & 0x01 != 0,
            net_address: byte & 0x02 != 0,
            encap_command: byte & 0x04 != 0,
            max_datagram_size: byte & 0x08 != 0,
            crc_mode: byte & 0x10 != 0,
            ndp_8byte: byte & 0x20 != 0,
        }
    }
}

/// Parsed NCM Functional Descriptor.
///
/// ```text
///   u8 bFunctionLength       (6)
///   u8 bDescriptorType       (0x24 CS_INTERFACE)
///   u8 bDescriptorSubtype    (0x1A NCM)
///   u16 bcdNcmVersion        (0x0100 = NCM 1.0)
///   u8 bmNetworkCapabilities
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NcmDescriptor {
    pub bcd_ncm_version: u16,
    pub capabilities: NetworkCapabilities,
}

impl NcmDescriptor {
    pub fn parse(buf: &[u8]) -> Result<Self, CdcError> {
        check_class_specific(buf, FunctionalSubtype::Ncm.to_byte())?;
        if (buf[0] as usize) < 6 || buf.len() < 6 {
            return Err(CdcError::Truncated);
        }
        Ok(Self {
            bcd_ncm_version: u16::from_le_bytes([buf[3], buf[4]]),
            capabilities: NetworkCapabilities::decode(buf[5]),
        })
    }
}

// ── Ethernet Networking Functional Descriptor (ECM 1.2 §5.4) ─────
//
// NCM devices reuse the ECM functional descriptor for the MAC
// address string slot.

/// Parsed Ethernet Networking Functional Descriptor.
///
/// ```text
///   u8  bFunctionLength       (13)
///   u8  bDescriptorType       (0x24 CS_INTERFACE)
///   u8  bDescriptorSubtype    (0x0F EthernetNetworking)
///   u8  iMACAddress           (string-descriptor index)
///   u32 bmEthernetStatistics  (capability bitmap)
///   u16 wMaxSegmentSize       (typically 1514)
///   u16 wNumberMCFilters
///   u8  bNumberPowerFilters
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EthernetNetworkingDescriptor {
    pub mac_string_index: u8,
    pub statistics_bitmap: u32,
    pub max_segment_size: u16,
    pub number_mc_filters: u16,
    pub number_power_filters: u8,
}

impl EthernetNetworkingDescriptor {
    pub fn parse(buf: &[u8]) -> Result<Self, CdcError> {
        check_class_specific(buf, FunctionalSubtype::EthernetNetworking.to_byte())?;
        if (buf[0] as usize) < 13 || buf.len() < 13 {
            return Err(CdcError::Truncated);
        }
        Ok(Self {
            mac_string_index: buf[3],
            statistics_bitmap: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
            max_segment_size: u16::from_le_bytes([buf[8], buf[9]]),
            number_mc_filters: u16::from_le_bytes([buf[10], buf[11]]),
            number_power_filters: buf[12],
        })
    }
}

// ── NTB-16 framing ───────────────────────────────────────────────

/// NTB-16 transfer-header (NTH16) — 12 bytes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Nth16 {
    /// `dwSignature` — must be [`NTH16_SIGNATURE`].
    pub signature: u32,
    /// `wHeaderLength` — must be 12 for NTB-16.
    pub header_length: u16,
    /// `wSequence` — host-monotonic, echoed in responses.
    pub sequence: u16,
    /// `wBlockLength` — total NTB size in bytes (header +
    /// datagrams + NDP).
    pub block_length: u16,
    /// `wNdpIndex` — byte offset of the first NDP16 within this
    /// NTB.
    pub ndp_index: u16,
}

impl Nth16 {
    pub const LEN: usize = 12;

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut b = [0u8; Self::LEN];
        b[0..4].copy_from_slice(&self.signature.to_le_bytes());
        b[4..6].copy_from_slice(&self.header_length.to_le_bytes());
        b[6..8].copy_from_slice(&self.sequence.to_le_bytes());
        b[8..10].copy_from_slice(&self.block_length.to_le_bytes());
        b[10..12].copy_from_slice(&self.ndp_index.to_le_bytes());
        b
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, NcmError> {
        if bytes.len() < Self::LEN {
            return Err(NcmError::Truncated);
        }
        let signature = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        if signature != NTH16_SIGNATURE {
            return Err(NcmError::BadSignature(signature));
        }
        let header_length = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
        if header_length as usize != Self::LEN {
            return Err(NcmError::BadFieldLength);
        }
        Ok(Self {
            signature,
            header_length,
            sequence: u16::from_le_bytes(bytes[6..8].try_into().unwrap()),
            block_length: u16::from_le_bytes(bytes[8..10].try_into().unwrap()),
            ndp_index: u16::from_le_bytes(bytes[10..12].try_into().unwrap()),
        })
    }
}

/// NDP16 datagram-pointer entry — `(offset, length)` pair.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DatagramPtr {
    pub offset: u16,
    pub length: u16,
}

/// NDP16 — 8 bytes of header + N+1 entries (the trailing entry
/// is `{0,0}` as a sentinel).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ndp16 {
    /// `dwSignature` — `NCM0` (no CRC) or `NCM1` (CRC).
    pub signature: u32,
    /// `wLength` — total NDP length including trailing zero
    /// sentinel.
    pub length: u16,
    /// `wNextNdpIndex` — offset of next NDP in this NTB, or 0
    /// if none.
    pub next_ndp_index: u16,
    pub entries: Vec<DatagramPtr>,
}

impl Ndp16 {
    /// Header length (signature + length + nextNdpIndex).
    pub const HEADER_LEN: usize = 8;
    /// Per-entry size (offset + length).
    pub const ENTRY_LEN: usize = 4;

    pub fn encode(&self) -> Vec<u8> {
        let body = Self::HEADER_LEN + (self.entries.len() + 1) * Self::ENTRY_LEN;
        let mut b = alloc::vec![0u8; body];
        b[0..4].copy_from_slice(&self.signature.to_le_bytes());
        b[4..6].copy_from_slice(&(body as u16).to_le_bytes());
        b[6..8].copy_from_slice(&self.next_ndp_index.to_le_bytes());
        for (i, entry) in self.entries.iter().enumerate() {
            let off = Self::HEADER_LEN + i * Self::ENTRY_LEN;
            b[off..off + 2].copy_from_slice(&entry.offset.to_le_bytes());
            b[off + 2..off + 4].copy_from_slice(&entry.length.to_le_bytes());
        }
        // Trailing {0,0} sentinel was zeroed by initial vec
        // allocation; nothing more to do.
        b
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, NcmError> {
        if bytes.len() < Self::HEADER_LEN {
            return Err(NcmError::Truncated);
        }
        let signature = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        if signature != NDP16_SIGNATURE_NO_CRC && signature != NDP16_SIGNATURE_CRC {
            return Err(NcmError::BadSignature(signature));
        }
        let length = u16::from_le_bytes(bytes[4..6].try_into().unwrap()) as usize;
        if length < Self::HEADER_LEN + Self::ENTRY_LEN || length > bytes.len() {
            return Err(NcmError::BadFieldLength);
        }
        let next_ndp_index = u16::from_le_bytes(bytes[6..8].try_into().unwrap());
        let entries_bytes = &bytes[Self::HEADER_LEN..length];
        if entries_bytes.len() % Self::ENTRY_LEN != 0 {
            return Err(NcmError::BadFieldLength);
        }
        let mut entries = Vec::with_capacity(entries_bytes.len() / Self::ENTRY_LEN);
        for chunk in entries_bytes.chunks_exact(Self::ENTRY_LEN) {
            let off = u16::from_le_bytes([chunk[0], chunk[1]]);
            let len = u16::from_le_bytes([chunk[2], chunk[3]]);
            // Stop at the first sentinel — entries past it are
            // padding only.
            if off == 0 && len == 0 {
                break;
            }
            entries.push(DatagramPtr {
                offset: off,
                length: len,
            });
        }
        Ok(Self {
            signature,
            length: length as u16,
            next_ndp_index,
            entries,
        })
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NcmError {
    Truncated,
    BadSignature(u32),
    BadFieldLength,
    /// More datagrams supplied than fit in a single NTB-16
    /// (per-NTB datagram limit, set by the device's NTB
    /// parameters).
    TooManyDatagrams,
    /// One of the supplied datagrams extends past the NTB.
    DatagramOutOfBounds,
    /// Caller asked to encode an NTB longer than 65535 bytes
    /// (the wBlockLength field width).
    NtbTooLarge,
    /// Device's interface descriptors didn't include a CDC-Comm /
    /// NCM (subclass 0x0D) interface — not an NCM device.
    NotNcm,
    /// SET_CONFIGURATION control transfer failed during bind.
    SetConfigFailed,
}

// ── NTB encoder ──────────────────────────────────────────────────

/// Build a complete NTB-16 from `datagrams`. The output layout
/// is:
///
/// ```text
///   NTH16 (12 bytes)
///   datagram 0
///   ...
///   datagram N-1
///   NDP16 (8 bytes header + (N+1) * 4 bytes entries)
/// ```
///
/// `sequence` is the host-monotonic counter the receiver echoes
/// back. `crc` selects the NDP16 signature (NCM0 vs NCM1).
pub fn build_ntb16(
    sequence: u16,
    datagrams: &[&[u8]],
    crc: bool,
) -> Result<Vec<u8>, NcmError> {
    // Datagrams precede the NDP16 in the wire layout. Compute
    // each datagram's offset (which sits in the NDP16 entry).
    let mut datagram_block_size = 0usize;
    for d in datagrams {
        datagram_block_size += d.len();
    }
    let ndp_size = Ndp16::HEADER_LEN + (datagrams.len() + 1) * Ndp16::ENTRY_LEN;
    let total = Nth16::LEN + datagram_block_size + ndp_size;
    if total > u16::MAX as usize {
        return Err(NcmError::NtbTooLarge);
    }
    let ndp_index = (Nth16::LEN + datagram_block_size) as u16;

    let mut buf = alloc::vec![0u8; total];
    let nth = Nth16 {
        signature: NTH16_SIGNATURE,
        header_length: Nth16::LEN as u16,
        sequence,
        block_length: total as u16,
        ndp_index,
    };
    buf[0..Nth16::LEN].copy_from_slice(&nth.encode());

    // Lay out datagrams + record (offset, length) entries.
    let mut entries = Vec::with_capacity(datagrams.len());
    let mut cursor = Nth16::LEN;
    for d in datagrams {
        if d.is_empty() {
            return Err(NcmError::DatagramOutOfBounds);
        }
        buf[cursor..cursor + d.len()].copy_from_slice(d);
        entries.push(DatagramPtr {
            offset: cursor as u16,
            length: d.len() as u16,
        });
        cursor += d.len();
    }
    let ndp = Ndp16 {
        signature: if crc {
            NDP16_SIGNATURE_CRC
        } else {
            NDP16_SIGNATURE_NO_CRC
        },
        length: ndp_size as u16,
        next_ndp_index: 0,
        entries,
    };
    let ndp_bytes = ndp.encode();
    buf[ndp_index as usize..ndp_index as usize + ndp_bytes.len()].copy_from_slice(&ndp_bytes);
    Ok(buf)
}

/// Parsed NTB ready for datagram-by-datagram extraction.
#[derive(Debug)]
pub struct ParsedNtb<'a> {
    pub nth: Nth16,
    pub ndp: Ndp16,
    raw: &'a [u8],
}

impl<'a> ParsedNtb<'a> {
    pub fn parse(ntb: &'a [u8]) -> Result<Self, NcmError> {
        let nth = Nth16::decode(ntb)?;
        if nth.block_length as usize > ntb.len() {
            return Err(NcmError::Truncated);
        }
        if nth.ndp_index as usize >= nth.block_length as usize {
            return Err(NcmError::BadFieldLength);
        }
        let ndp_slice = &ntb[nth.ndp_index as usize..nth.block_length as usize];
        let ndp = Ndp16::decode(ndp_slice)?;
        Ok(Self { nth, ndp, raw: ntb })
    }

    /// Borrow the `i`-th datagram from the NTB. Bounds-checked
    /// against `nth.block_length`.
    pub fn datagram(&self, i: usize) -> Option<&'a [u8]> {
        let entry = self.ndp.entries.get(i)?;
        let off = entry.offset as usize;
        let end = off.checked_add(entry.length as usize)?;
        if end > self.nth.block_length as usize {
            return None;
        }
        self.raw.get(off..end)
    }

    /// Number of datagrams in this NTB.
    pub fn len(&self) -> usize {
        self.ndp.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ndp.entries.is_empty()
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use crate::cdc::CS_INTERFACE;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_ncm_descriptor() -> TestResult {
        // length 6, CS_INTERFACE, subtype 0x1A NCM, bcdNCM=0x0100,
        // capabilities 0x35 (packet_filter | encap_command | max_dgram | ndp_8byte).
        let raw = [6u8, CS_INTERFACE, 0x1A, 0x00, 0x01, 0x35];
        let d = match NcmDescriptor::parse(&raw) {
            Ok(d) => d,
            Err(_) => return TestResult::Fail("clean NCM desc rejected"),
        };
        if d.bcd_ncm_version != 0x0100 {
            return TestResult::Fail("bcdNcmVersion lost");
        }
        if !d.capabilities.packet_filter
            || !d.capabilities.encap_command
            || !d.capabilities.max_datagram_size
            || !d.capabilities.ndp_8byte
        {
            return TestResult::Fail("capability bits lost");
        }
        if d.capabilities.net_address {
            return TestResult::Fail("net_address bit over-set");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_ncm", smoke_ncm_descriptor);

    fn smoke_ethernet_networking_descriptor() -> TestResult {
        let raw = [
            13u8, CS_INTERFACE, 0x0F, // header
            5,    // iMACAddress
            0, 0, 0, 0, // statistics
            0xEA, 0x05, // wMaxSegmentSize = 1514
            0, 0, // wNumberMCFilters
            0,    // bNumberPowerFilters
        ];
        let d = match EthernetNetworkingDescriptor::parse(&raw) {
            Ok(d) => d,
            Err(_) => return TestResult::Fail("clean Ethernet desc rejected"),
        };
        if d.mac_string_index != 5 {
            return TestResult::Fail("mac string index lost");
        }
        if d.max_segment_size != 1514 {
            return TestResult::Fail("max segment size lost");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/cdc_ncm",
        smoke_ethernet_networking_descriptor
    );

    fn smoke_ntb16_round_trip_single_datagram() -> TestResult {
        let dg: &[u8] = b"hello-ethernet-frame";
        let ntb = match build_ntb16(42, &[dg], false) {
            Ok(n) => n,
            Err(_) => return TestResult::Fail("clean inputs rejected"),
        };
        let parsed = match ParsedNtb::parse(&ntb) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("self-built NTB rejected by parser"),
        };
        if parsed.nth.sequence != 42 {
            return TestResult::Fail("sequence lost");
        }
        if parsed.len() != 1 {
            return TestResult::Fail("datagram count lost");
        }
        if parsed.datagram(0) != Some(dg) {
            return TestResult::Fail("datagram payload mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/cdc_ncm",
        smoke_ntb16_round_trip_single_datagram
    );

    fn smoke_ntb16_round_trip_multiple_datagrams() -> TestResult {
        let a: &[u8] = b"frame-a";
        let b: &[u8] = b"frame-b-longer";
        let c: &[u8] = b"c";
        let ntb = match build_ntb16(7, &[a, b, c], false) {
            Ok(n) => n,
            Err(_) => return TestResult::Fail("clean inputs rejected"),
        };
        let parsed = match ParsedNtb::parse(&ntb) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("self-built NTB rejected"),
        };
        if parsed.len() != 3 {
            return TestResult::Fail("expected 3 datagrams");
        }
        if parsed.datagram(0) != Some(a)
            || parsed.datagram(1) != Some(b)
            || parsed.datagram(2) != Some(c)
        {
            return TestResult::Fail("datagram payload(s) mis-ordered");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/cdc_ncm",
        smoke_ntb16_round_trip_multiple_datagrams
    );

    fn smoke_ntb16_rejects_bad_signature() -> TestResult {
        let mut ntb = build_ntb16(1, &[b"abc"], false).expect("clean inputs");
        ntb[0] = 0xFF; // corrupt signature
        match ParsedNtb::parse(&ntb) {
            Err(NcmError::BadSignature(_)) => TestResult::Pass,
            _ => TestResult::Fail("bad signature must be rejected"),
        }
    }
    kernel_test_in!(
        "drivers/usb/cdc_ncm",
        smoke_ntb16_rejects_bad_signature
    );

    fn smoke_ndp16_signature_selects_crc_mode() -> TestResult {
        let ntb_no_crc = build_ntb16(0, &[b"x"], false).expect("clean inputs");
        let ntb_crc = build_ntb16(0, &[b"x"], true).expect("clean inputs");
        let no_crc = ParsedNtb::parse(&ntb_no_crc).expect("clean parse");
        let crc = ParsedNtb::parse(&ntb_crc).expect("clean parse");
        if no_crc.ndp.signature != NDP16_SIGNATURE_NO_CRC {
            return TestResult::Fail("no-CRC NDP signature wrong");
        }
        if crc.ndp.signature != NDP16_SIGNATURE_CRC {
            return TestResult::Fail("CRC NDP signature wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/cdc_ncm",
        smoke_ndp16_signature_selects_crc_mode
    );
}

// ── Class enumeration + bind ───────────────────────────────────────
//
// Minimal "is this an NCM device, and if so claim it" path. The
// full TX/RX surface (NCM Set-Net-Address class request + per-
// endpoint NTB pipelines) is a follow-up.

use narf_lib::sync::IrqSafeSpinLock;

/// One bound CDC-NCM device — slot id + Comm interface number.
#[derive(Copy, Clone, Debug)]
pub struct CdcNcmDevice {
    pub slot_id: u8,
    /// `bInterfaceNumber` of the CDC-Comm/NCM interface.
    pub comm_iface: u8,
    /// `bInterfaceNumber` of the CDC-Data interface (where the
    /// bulk endpoints live). 0xFF means "not yet enumerated".
    pub data_iface: u8,
    /// DCI of the bulk-IN endpoint (host→device commands +
    /// device→host NTBs). 0 = not enumerated.
    pub bulk_in_dci: u8,
    /// DCI of the bulk-OUT endpoint (host→device NTBs).
    pub bulk_out_dci: u8,
    /// Sequence counter for outbound NTBs. Increments per send.
    pub tx_sequence: u16,
}

/// System-wide registry of bound CDC-NCM devices.
pub static CDC_NCM_DEVICES: IrqSafeSpinLock<Vec<CdcNcmDevice>> =
    IrqSafeSpinLock::new(Vec::new());

/// Find the first CDC-Comm interface with subclass NCM in `cfg`.
pub fn find_ncm_comm_interface(cfg: &[u8]) -> Option<u8> {
    let mut i = 0;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        if cfg[i + 1] == 0x04 && len >= 9 {
            let cls = cfg[i + 5];
            let sub = cfg[i + 6];
            if cls == crate::cdc::USB_CLASS_CDC_COMM && sub == crate::cdc::CDC_SUBCLASS_NCM {
                return Some(cfg[i + 2]);
            }
        }
        i += len;
    }
    None
}

/// Bind to an already-addressed CDC-NCM device. SET_CONFIGURATION,
/// then record the slot/interface pair.
pub fn try_bind_ncm_already_addressed(
    xhci_dev: &crate::xhci::Xhci,
    slot_id: u8,
    cfg: &[u8],
) -> Result<usize, NcmError> {
    let comm_iface = find_ncm_comm_interface(cfg).ok_or(NcmError::NotNcm)?;
    let cfg_value = if cfg.len() >= 9 { cfg[5] } else { 1 };
    let mut nothing = [0u8; 0];
    if xhci_dev
        .control_in(
            slot_id,
            0x00,
            crate::hid::STD_REQ_SET_CONFIGURATION,
            cfg_value as u16,
            0,
            &mut nothing,
        )
        .is_err()
    {
        return Err(NcmError::SetConfigFailed);
    }
    // Find the CDC-Data interface + its bulk endpoint pair. Some
    // composite devices interleave multiple interface descriptors;
    // walking the cfg blob with `find_ncm_bulk_endpoints` handles
    // that by accepting the first Data interface after the Comm
    // interface number we resolved above.
    let (data_iface, bulk_in_ep, bulk_out_ep) = match find_ncm_bulk_endpoints(cfg) {
        Some(t) => t,
        None => return Err(NcmError::NotNcm),
    };
    // Configure the bulk pair so the controller wires up its
    // Transfer Rings. Mirrors the MSC bind path.
    if xhci_dev
        .configure_endpoints(slot_id, &[bulk_in_ep, bulk_out_ep])
        .is_err()
    {
        return Err(NcmError::SetConfigFailed);
    }
    let bulk_in_dci = ((bulk_in_ep.ep_addr & 0x0F) * 2) + 1;
    let bulk_out_dci = ((bulk_out_ep.ep_addr & 0x0F) * 2) + 0;
    let idx = {
        let mut g = CDC_NCM_DEVICES.lock();
        let idx = g.len();
        g.push(CdcNcmDevice {
            slot_id,
            comm_iface,
            data_iface,
            bulk_in_dci,
            bulk_out_dci,
            tx_sequence: 0,
        });
        idx
    };
    // Register against the net iface registry as "usb-ncm{idx}".
    // The send_fn is a static trampoline that dispatches to
    // CDC_NCM_DEVICES[0] — sufficient for the single-NIC bring-up
    // arc; multi-NIC routing will swap to per-iface trampolines.
    register_ncm_iface(idx);
    Ok(idx)
}

/// Walk the config blob for the first CDC-Data interface (class
/// 0x0A) and return its (interface_number, bulk_in_ep, bulk_out_ep).
pub fn find_ncm_bulk_endpoints(
    cfg: &[u8],
) -> Option<(u8, crate::xhci::EndpointConfig, crate::xhci::EndpointConfig)> {
    use crate::xhci::{EndpointConfig, EndpointKind};
    let mut i = 0;
    let mut data_iface: Option<u8> = None;
    let mut bulk_in: Option<EndpointConfig> = None;
    let mut bulk_out: Option<EndpointConfig> = None;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        let desc_type = cfg[i + 1];
        if desc_type == 0x04 && len >= 9 {
            // INTERFACE descriptor — look for CDC-Data.
            let cls = cfg[i + 5];
            if cls == crate::cdc::USB_CLASS_CDC_DATA {
                data_iface = Some(cfg[i + 2]);
                // Reset the search so we pick up THIS interface's eps.
                bulk_in = None;
                bulk_out = None;
            }
        } else if desc_type == 0x05 && data_iface.is_some() && len >= 7 {
            // ENDPOINT under the most-recently-seen Data interface.
            let ep_addr = cfg[i + 2];
            let attrs = cfg[i + 3];
            let max_packet = u16::from_le_bytes([cfg[i + 4], cfg[i + 5]]) & 0x07FF;
            let is_in = ep_addr & 0x80 != 0;
            // Bulk = transfer type 2 in attrs[1:0].
            if attrs & 0x03 == 2 {
                let kind = if is_in {
                    EndpointKind::BulkIn
                } else {
                    EndpointKind::BulkOut
                };
                let cfg_ep = EndpointConfig {
                    ep_addr,
                    max_packet,
                    kind,
                };
                if is_in {
                    bulk_in = Some(cfg_ep);
                } else {
                    bulk_out = Some(cfg_ep);
                }
            }
        }
        i += len;
    }
    match (data_iface, bulk_in, bulk_out) {
        (Some(iface), Some(i), Some(o)) => Some((iface, i, o)),
        _ => None,
    }
}

/// Send one Ethernet frame over the bound NCM device at `idx`.
/// Wraps the frame in an NTB-16 (single-datagram NDP) and ships
/// it on the bulk-OUT endpoint.
pub fn send_frame(idx: usize, eth_frame: &[u8]) -> Result<usize, NcmError> {
    let (slot_id, bulk_out_dci, sequence) = {
        let mut g = CDC_NCM_DEVICES.lock();
        let dev = g.get_mut(idx).ok_or(NcmError::NotNcm)?;
        let seq = dev.tx_sequence;
        dev.tx_sequence = dev.tx_sequence.wrapping_add(1);
        (dev.slot_id, dev.bulk_out_dci, seq)
    };
    let ntb = build_ntb16(sequence, &[eth_frame], /*crc*/ false)?;
    let outcome = crate::xhci::with_controller(|c| c.bulk_out(slot_id, bulk_out_dci, &ntb));
    match outcome {
        Some(Ok(n)) => Ok(n),
        Some(Err(_)) | None => Err(NcmError::Truncated),
    }
}

/// Pull one Ethernet frame off the bound NCM device's bulk-IN
/// endpoint. Reads an NTB into `scratch`, parses it, returns the
/// first datagram (if any). Caller polls this periodically; on
/// real silicon the bulk-IN ring continuously holds an NTB-sized
/// read posted so frames stream in.
pub fn recv_frame<'a>(
    idx: usize,
    scratch: &'a mut [u8],
) -> Result<Option<&'a [u8]>, NcmError> {
    let (slot_id, bulk_in_dci) = {
        let g = CDC_NCM_DEVICES.lock();
        let dev = g.get(idx).ok_or(NcmError::NotNcm)?;
        (dev.slot_id, dev.bulk_in_dci)
    };
    let outcome = crate::xhci::with_controller(|c| c.bulk_in(slot_id, bulk_in_dci, scratch));
    let n = match outcome {
        Some(Ok(n)) => n,
        Some(Err(_)) | None => return Err(NcmError::Truncated),
    };
    if n == 0 {
        return Ok(None);
    }
    let ntb = ParsedNtb::parse(&scratch[..n])?;
    if ntb.is_empty() {
        return Ok(None);
    }
    let dg = ntb.datagram(0).ok_or(NcmError::DatagramOutOfBounds)?;
    // Re-borrow against the scratch lifetime — Ntb16 borrows
    // immutably; the lifetime path is straightforward here because
    // dg points into &scratch[..n].
    let off = dg.as_ptr() as usize - scratch.as_ptr() as usize;
    let dlen = dg.len();
    Ok(Some(&scratch[off..off + dlen]))
}

/// Trampoline used by [`narf_net::iface`]'s `SendFn` slot. Sends
/// via NCM device 0 (the bring-up arc binds at most one USB-NCM
/// device). Multi-NIC routing will replace this with a per-iface
/// closure-equivalent dispatch table.
fn ncm_send_static_trampoline(frame: &[u8]) -> Result<(), ()> {
    match send_frame(0, frame) {
        Ok(_) => Ok(()),
        Err(_) => Err(()),
    }
}

/// Register the NCM device at `idx` as a network interface. The
/// MAC address is resolved via GET_DESCRIPTOR(STRING, iMACAddress)
/// in a follow-up; for now we register a placeholder MAC the
/// stack can ARP-reply with — the device will overwrite this once
/// the SET_NET_ADDRESS path lands.
fn register_ncm_iface(idx: usize) {
    let name = alloc::format!("usb-ncm{}", idx);
    // Placeholder locally-administered MAC. Bit 1 of byte 0 = 1
    // (LAA flag), bit 0 = 0 (unicast). Device-specific MAC takes
    // over once GET_NET_ADDRESS lands.
    let mac = [0x02, 0x4E, 0x41, 0x52, 0x46, idx as u8];
    // narf_net's register() interface takes &str — we leak the
    // String so its lifetime spans the kernel.
    let static_name: &'static str = alloc::boxed::Box::leak(name.into_boxed_str());
    narf_net::iface::register(static_name, mac, ncm_send_static_trampoline);
}

pub fn attached_ncm_count() -> usize {
    CDC_NCM_DEVICES.lock().len()
}

#[doc(hidden)]
pub fn __reset_ncm_for_test() {
    CDC_NCM_DEVICES.lock().clear();
}
