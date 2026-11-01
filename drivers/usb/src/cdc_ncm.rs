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

// ── SET_ETHERNET_PACKET_FILTER request code (CDC 1.2 §6.2.4) ──────
/// Request code for `SET_ETHERNET_PACKET_FILTER` (class request,
/// wIndex=interface, wValue=filter bitmap). NCM 1.0 §6.2.
pub const REQ_SET_PACKET_FILTER: u8 = 0x43;

// ── NTB signatures (NCM 1.0 §3.2.1) ──────────────────────────────

/// `NTH16` signature — "NCMH" little-endian.
pub const NTH16_SIGNATURE: u32 = 0x484D_434E;
/// `NTH32` signature — "ncmh" little-endian.
pub const NTH32_SIGNATURE: u32 = 0x686D_636E;
/// `NDP16` signature — "NCM0" (no CRC) or "NCM1" (CRC).
pub const NDP16_SIGNATURE_NO_CRC: u32 = 0x304D_434E;
pub const NDP16_SIGNATURE_CRC: u32 = 0x314D_434E;

// ── GET_NTB_PARAMETERS response (NCM 1.0 §6.2.1) ─────────────────

/// Decoded `GET_NTB_PARAMETERS` response — 28 bytes, little-endian.
///
/// ```text
///   u16 wLength                    (28)
///   u16 bmNtbFormatsSupported      (bit 0 = NTB-16, bit 1 = NTB-32)
///   u32 dwNtbInMaxSize             (max host→device NTB in bytes)
///   u16 wNdpInDivisor
///   u16 wNdpInPayloadRemainder
///   u16 wNdpInAlignment
///   u16 wPadding1
///   u32 dwNtbOutMaxSize            (max device→host NTB in bytes)
///   u16 wNdpOutDivisor
///   u16 wNdpOutPayloadRemainder
///   u16 wNdpOutAlignment
///   u16 wNtbOutMaxDatagrams
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NtbParameters {
    /// `bmNtbFormatsSupported`: bit 0 = NTB-16 supported, bit 1 = NTB-32.
    pub formats_supported: u16,
    /// Maximum size of an IN NTB (host → device). Used to clamp
    /// outbound NTB size — never send more than this.
    pub ntb_in_max_size: u32,
    /// Alignment divisor for datagram payloads in IN NTBs.
    pub ndp_in_divisor: u16,
    /// Payload-remainder for IN NTB alignment.
    pub ndp_in_payload_remainder: u16,
    /// Alignment of the NDP within an IN NTB.
    pub ndp_in_alignment: u16,
    /// Maximum size of an OUT NTB (device → host).
    pub ntb_out_max_size: u32,
    /// Alignment divisor for datagram payloads in OUT NTBs.
    pub ndp_out_divisor: u16,
    /// Payload-remainder for OUT NTB alignment.
    pub ndp_out_payload_remainder: u16,
    /// Alignment of the NDP within an OUT NTB.
    pub ndp_out_alignment: u16,
    /// Maximum number of datagrams in a single OUT NTB (0 = no
    /// device limit — host should apply its own cap).
    pub ntb_out_max_datagrams: u16,
}

impl NtbParameters {
    /// Minimum wire length per spec (NCM 1.0 §6.2.1).
    pub const WIRE_LEN: usize = 28;

    /// Decode from the 28-byte GET_NTB_PARAMETERS response buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, NcmError> {
        if buf.len() < Self::WIRE_LEN {
            return Err(NcmError::Truncated);
        }
        let wlen = u16::from_le_bytes([buf[0], buf[1]]) as usize;
        if wlen < Self::WIRE_LEN {
            return Err(NcmError::BadFieldLength);
        }
        Ok(Self {
            formats_supported: u16::from_le_bytes([buf[2], buf[3]]),
            ntb_in_max_size: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
            ndp_in_divisor: u16::from_le_bytes([buf[8], buf[9]]),
            ndp_in_payload_remainder: u16::from_le_bytes([buf[10], buf[11]]),
            ndp_in_alignment: u16::from_le_bytes([buf[12], buf[13]]),
            // buf[14..15] = wPadding1 — ignored
            ntb_out_max_size: u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]),
            ndp_out_divisor: u16::from_le_bytes([buf[20], buf[21]]),
            ndp_out_payload_remainder: u16::from_le_bytes([buf[22], buf[23]]),
            ndp_out_alignment: u16::from_le_bytes([buf[24], buf[25]]),
            ntb_out_max_datagrams: u16::from_le_bytes([buf[26], buf[27]]),
        })
    }

    /// True if the device supports NTB-32 format (bit 1 of
    /// `bmNtbFormatsSupported`).
    pub fn supports_ntb32(&self) -> bool {
        self.formats_supported & 0x02 != 0
    }
}

// ── SET_ETHERNET_PACKET_FILTER bitmap (CDC 1.2 §6.2.4) ───────────

/// Packet-filter bitmap for `SET_ETHERNET_PACKET_FILTER`.
///
/// Sent as `wValue` in the class-specific control request
/// `SET_ETHERNET_PACKET_FILTER` (request code 0x43). The device
/// uses the bitmap to configure its Ethernet-level receive filter.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PacketFilter {
    /// PROMISCUOUS — receive all packets regardless of destination.
    pub promiscuous: bool,
    /// ALL_MULTICAST — receive all multicast frames without filter.
    pub all_multicast: bool,
    /// DIRECTED — receive unicast frames addressed to this MAC.
    pub directed: bool,
    /// BROADCAST — receive broadcast frames.
    pub broadcast: bool,
    /// MULTICAST — receive multicast frames matching the filter.
    pub multicast: bool,
}

impl PacketFilter {
    /// Typical "normal" filter: directed + broadcast + multicast.
    pub const NORMAL: Self = Self {
        promiscuous: false,
        all_multicast: false,
        directed: true,
        broadcast: true,
        multicast: true,
    };

    /// Encode as the `wValue` u16 for the class control request.
    pub fn encode(&self) -> u16 {
        let mut v: u16 = 0;
        if self.promiscuous {
            v |= 1 << 0;
        }
        if self.all_multicast {
            v |= 1 << 1;
        }
        if self.directed {
            v |= 1 << 2;
        }
        if self.broadcast {
            v |= 1 << 3;
        }
        if self.multicast {
            v |= 1 << 4;
        }
        v
    }

    /// Decode a `wValue` bitmap from the device (or for round-trip
    /// testing).
    pub fn decode(v: u16) -> Self {
        Self {
            promiscuous: v & (1 << 0) != 0,
            all_multicast: v & (1 << 1) != 0,
            directed: v & (1 << 2) != 0,
            broadcast: v & (1 << 3) != 0,
            multicast: v & (1 << 4) != 0,
        }
    }
}

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
    /// Neither GET_NET_ADDRESS nor the iMACAddress string
    /// descriptor yielded a valid station address during bind.
    /// The bind fails rather than inventing an address.
    NoMacAddress,
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
pub fn build_ntb16(sequence: u16, datagrams: &[&[u8]], crc: bool) -> Result<Vec<u8>, NcmError> {
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

    /// True when the NDP signature marks CRC mode (`NCM1`): each
    /// datagram in this NTB carries a trailing CRC-32.
    pub fn uses_crc(&self) -> bool {
        self.ndp.signature == NDP16_SIGNATURE_CRC
    }
}

// ── CRC mode support (NCM 1.0 §3.2) ──────────────────────────────
//
// When CRC mode is negotiated on, the sender appends a CRC-32
// (IEEE 802.3, reflected polynomial 0xEDB88320 — the Ethernet FCS
// polynomial) to each datagram, and the datagram lengths in the
// NDP include those 4 bytes. The receiver verifies and strips
// them; a datagram whose CRC fails is dropped, never delivered.

/// IEEE 802.3 CRC-32 of `data` (init/xorout 0xFFFFFFFF).
pub fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    crc ^ 0xFFFF_FFFF
}

/// `frame` with its CRC-32 appended (little-endian) — the wire
/// form of a datagram under CRC mode.
pub fn append_crc(frame: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(frame.len() + 4);
    out.extend_from_slice(frame);
    out.extend_from_slice(&crc32_ieee(frame).to_le_bytes());
    out
}

/// Walk every frame in a received NTB, invoking `f` on each.
/// Entries are located through the NDP pointer table, so padding
/// between datagrams is skipped. Under CRC mode the trailing
/// CRC-32 is verified and stripped first; CRC-failing datagrams
/// are dropped. Returns `(delivered, dropped)`.
pub fn for_each_frame(ntb: &[u8], f: &mut dyn FnMut(&[u8])) -> Result<(usize, usize), NcmError> {
    let parsed = ParsedNtb::parse(ntb)?;
    let crc = parsed.uses_crc();
    let mut delivered = 0usize;
    let mut dropped = 0usize;
    for i in 0..parsed.len() {
        let Some(dg) = parsed.datagram(i) else {
            continue;
        };
        if crc {
            if dg.len() < 4 {
                dropped += 1;
                continue;
            }
            let (frame, tail) = dg.split_at(dg.len() - 4);
            let want = u32::from_le_bytes(tail.try_into().unwrap());
            if crc32_ieee(frame) != want {
                dropped += 1;
                continue;
            }
            f(frame);
        } else {
            f(dg);
        }
        delivered += 1;
    }
    Ok((delivered, dropped))
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use crate::cdc::CS_INTERFACE;
    use alloc::vec::Vec;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_ncm_descriptor() -> TestResult {
        // length 6, CS_INTERFACE, subtype 0x1A NCM, bcdNCM=0x0100,
        // capabilities 0x2D (packet_filter | encap_command | max_dgram | ndp_8byte).
        let raw = [6u8, CS_INTERFACE, 0x1A, 0x00, 0x01, 0x2D];
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
            13u8,
            CS_INTERFACE,
            0x0F, // header
            5,    // iMACAddress
            0,
            0,
            0,
            0, // statistics
            0xEA,
            0x05, // wMaxSegmentSize = 1514
            0,
            0, // wNumberMCFilters
            0, // bNumberPowerFilters
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
    kernel_test_in!("drivers/usb/cdc_ncm", smoke_ethernet_networking_descriptor);

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
    kernel_test_in!("drivers/usb/cdc_ncm", smoke_ntb16_rejects_bad_signature);

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

    fn smoke_ntb_parameters_decode() -> TestResult {
        // Synthesise a 28-byte GET_NTB_PARAMETERS response.
        // wLength=28, bmNtbFormatsSupported=0x0003 (NTB-16 + NTB-32),
        // dwNtbInMaxSize=65536, wNdpInDivisor=4, wNdpInRemainder=0,
        // wNdpInAlignment=4, wPadding1=0, dwNtbOutMaxSize=16384,
        // wNdpOutDivisor=4, wNdpOutRemainder=0, wNdpOutAlignment=4,
        // wNtbOutMaxDatagrams=40.
        #[rustfmt::skip]
        let raw: [u8; 28] = [
            28, 0,          // wLength = 28
            0x03, 0x00,     // bmNtbFormatsSupported = 0x0003
            0x00, 0x00, 0x01, 0x00, // dwNtbInMaxSize = 65536
            0x04, 0x00,     // wNdpInDivisor = 4
            0x00, 0x00,     // wNdpInPayloadRemainder = 0
            0x04, 0x00,     // wNdpInAlignment = 4
            0x00, 0x00,     // wPadding1 = 0
            0x00, 0x40, 0x00, 0x00, // dwNtbOutMaxSize = 16384
            0x04, 0x00,     // wNdpOutDivisor = 4
            0x00, 0x00,     // wNdpOutPayloadRemainder = 0
            0x04, 0x00,     // wNdpOutAlignment = 4
            0x28, 0x00,     // wNtbOutMaxDatagrams = 40
        ];
        let p = match NtbParameters::decode(&raw) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("clean NTB parameters rejected"),
        };
        if p.ntb_in_max_size != 65536 {
            return TestResult::Fail("ntb_in_max_size wrong");
        }
        if p.ntb_out_max_size != 16384 {
            return TestResult::Fail("ntb_out_max_size wrong");
        }
        if p.ntb_out_max_datagrams != 40 {
            return TestResult::Fail("ntb_out_max_datagrams wrong");
        }
        if !p.supports_ntb32() {
            return TestResult::Fail("NTB-32 support bit not set");
        }
        // Truncated input must be rejected.
        match NtbParameters::decode(&raw[..10]) {
            Err(NcmError::Truncated) => {}
            _ => return TestResult::Fail("truncated input not rejected"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_ncm", smoke_ntb_parameters_decode);

    fn smoke_set_packet_filter_encode() -> TestResult {
        // NORMAL filter = directed | broadcast | multicast = bits 2|3|4
        let normal = PacketFilter::NORMAL;
        let encoded = normal.encode();
        if encoded != 0x001C {
            // 0b0001_1100 = 28
            return TestResult::Fail("NORMAL filter bitmap wrong");
        }
        // Promiscuous only → bit 0.
        let promisc = PacketFilter {
            promiscuous: true,
            ..Default::default()
        };
        if promisc.encode() != 0x0001 {
            return TestResult::Fail("promiscuous-only filter wrong");
        }
        // Round-trip: encode → decode → encode.
        let rt = PacketFilter::decode(encoded);
        if rt.encode() != encoded {
            return TestResult::Fail("round-trip failed");
        }
        if !rt.directed || !rt.broadcast || !rt.multicast {
            return TestResult::Fail("NORMAL bits lost on decode");
        }
        if rt.promiscuous || rt.all_multicast {
            return TestResult::Fail("extra bits set on decode");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_ncm", smoke_set_packet_filter_encode);

    fn smoke_crc32_ieee_check_vector() -> TestResult {
        // The standard CRC-32 check value: CRC32("123456789").
        if crc32_ieee(b"123456789") != 0xCBF4_3926 {
            return TestResult::Fail("CRC-32 check vector mismatch");
        }
        if crc32_ieee(b"") != 0 {
            return TestResult::Fail("CRC-32 of empty input must be 0");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_ncm", smoke_crc32_ieee_check_vector);

    fn smoke_ntb_crc_round_trip_and_drop() -> TestResult {
        // TX shape under CRC mode: each datagram carries its
        // appended CRC; the RX walker verifies + strips.
        let f1: &[u8] = b"crc-frame-one-0123456789";
        let f2: &[u8] = b"second-frame";
        let d1 = append_crc(f1);
        let d2 = append_crc(f2);
        let ntb = match build_ntb16(5, &[&d1, &d2], true) {
            Ok(n) => n,
            Err(_) => return TestResult::Fail("CRC NTB build rejected"),
        };
        let mut got: Vec<Vec<u8>> = Vec::new();
        let r = for_each_frame(&ntb, &mut |f| got.push(f.to_vec()));
        match r {
            Ok((2, 0)) => {}
            _ => return TestResult::Fail("CRC NTB walk counts wrong"),
        }
        if got.len() != 2 || got[0] != f1 || got[1] != f2 {
            return TestResult::Fail("CRC-stripped frames mismatch");
        }
        // Corrupt the first datagram's CRC tail: that datagram
        // must be dropped, the other still delivered.
        let mut bad = ntb.clone();
        let crc_off = Nth16::LEN + f1.len();
        bad[crc_off] ^= 0xFF;
        let mut got2: Vec<Vec<u8>> = Vec::new();
        let r2 = for_each_frame(&bad, &mut |f| got2.push(f.to_vec()));
        match r2 {
            Ok((1, 1)) => {}
            _ => return TestResult::Fail("corrupt-CRC walk counts wrong"),
        }
        if got2.len() != 1 || got2[0] != f2 {
            return TestResult::Fail("wrong datagram survived CRC failure");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_ncm", smoke_ntb_crc_round_trip_and_drop);

    fn smoke_ntb_padded_reassembly() -> TestResult {
        // Hand-built NTB with 2 padding bytes between datagrams:
        // the walker must follow the NDP offsets, not assume
        // datagrams are tightly packed.
        let a: [u8; 20] = [0xAA; 20];
        let b: [u8; 30] = [0xBB; 30];
        let ndp_index = 12 + 20 + 2 + 30; // 64
        let total = ndp_index + 20; // NDP16: 8 + 3 entries * 4
        let mut ntb = alloc::vec![0u8; total];
        ntb[0..4].copy_from_slice(&NTH16_SIGNATURE.to_le_bytes());
        ntb[4..6].copy_from_slice(&12u16.to_le_bytes());
        ntb[6..8].copy_from_slice(&9u16.to_le_bytes()); // sequence
        ntb[8..10].copy_from_slice(&(total as u16).to_le_bytes());
        ntb[10..12].copy_from_slice(&(ndp_index as u16).to_le_bytes());
        ntb[12..32].copy_from_slice(&a);
        // bytes 32..34 are the padding (left zeroed)
        ntb[34..64].copy_from_slice(&b);
        let n = ndp_index;
        ntb[n..n + 4].copy_from_slice(&NDP16_SIGNATURE_NO_CRC.to_le_bytes());
        ntb[n + 4..n + 6].copy_from_slice(&20u16.to_le_bytes());
        ntb[n + 6..n + 8].copy_from_slice(&0u16.to_le_bytes());
        ntb[n + 8..n + 10].copy_from_slice(&12u16.to_le_bytes());
        ntb[n + 10..n + 12].copy_from_slice(&20u16.to_le_bytes());
        ntb[n + 12..n + 14].copy_from_slice(&34u16.to_le_bytes());
        ntb[n + 14..n + 16].copy_from_slice(&30u16.to_le_bytes());
        // n+16..n+20: {0,0} sentinel (zeroed)
        let mut got: Vec<Vec<u8>> = Vec::new();
        let r = for_each_frame(&ntb, &mut |f| got.push(f.to_vec()));
        match r {
            Ok((2, 0)) => {}
            _ => return TestResult::Fail("padded NTB walk counts wrong"),
        }
        if got.len() != 2 || got[0] != a || got[1] != b {
            return TestResult::Fail("padded NTB frames mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_ncm", smoke_ntb_padded_reassembly);

    fn smoke_mac_string_descriptor_parse() -> TestResult {
        // Build a string descriptor for "001A2B3C4D5E" (UTF-16LE).
        let text = b"001A2B3C4D5E";
        let mut desc = alloc::vec![0u8; 2 + text.len() * 2];
        desc[0] = desc.len() as u8;
        desc[1] = 0x03;
        for (i, &ch) in text.iter().enumerate() {
            desc[2 + i * 2] = ch;
            desc[3 + i * 2] = 0;
        }
        if parse_mac_string_descriptor(&desc) != Some([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]) {
            return TestResult::Fail("iMACAddress string not decoded");
        }
        // Non-hex character → reject.
        let mut bad = desc.clone();
        bad[2] = b'Z';
        if parse_mac_string_descriptor(&bad).is_some() {
            return TestResult::Fail("non-hex MAC string accepted");
        }
        // All-zero address in string form → reject (unprogrammed).
        let mut zero = alloc::vec![0u8; 26];
        zero[0] = 26;
        zero[1] = 0x03;
        for i in 0..12 {
            zero[2 + i * 2] = b'0';
        }
        if parse_mac_string_descriptor(&zero).is_some() {
            return TestResult::Fail("all-zero MAC string accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_ncm", smoke_mac_string_descriptor_parse);

    /// Modelled NCM configuration blob shared by the finder
    /// fixtures: Comm iface 0 (NCM), data iface 1 alt 0 (no
    /// endpoints) + alt 1 (bulk pair).
    fn modelled_ncm_cfg() -> Vec<u8> {
        #[rustfmt::skip]
        let cfg: &[u8] = &[
            9, 2, 0, 0, 2, 1, 0, 0x80, 0x32, // config (len patched below)
            // Comm interface 0, subclass NCM, 1 endpoint
            9, 4, 0, 0, 1, 0x02, 0x0D, 0, 0,
            // NCM functional descriptor, caps 0x13
            6, 0x24, 0x1A, 0x00, 0x01, 0x13,
            // Ethernet Networking descriptor, iMACAddress = 5
            13, 0x24, 0x0F, 5, 0, 0, 0, 0, 0xEA, 0x05, 0, 0, 0,
            // interrupt endpoint of the Comm interface
            7, 5, 0x83, 3, 16, 0, 8,
            // Data interface 1, alt 0, no endpoints
            9, 4, 1, 0, 0, 0x0A, 0, 0, 0,
            // Data interface 1, alt 1, bulk pair
            9, 4, 1, 1, 2, 0x0A, 0, 0, 0,
            7, 5, 0x81, 2, 64, 0, 0,
            7, 5, 0x02, 2, 64, 0, 0,
        ];
        let mut v = cfg.to_vec();
        let total = v.len() as u16;
        v[2..4].copy_from_slice(&total.to_le_bytes());
        v
    }

    fn smoke_ncm_functional_descriptor_finder() -> TestResult {
        let cfg = modelled_ncm_cfg();
        let (ncm, eth) = find_ncm_functional_descriptors(&cfg, 0);
        let ncm = match ncm {
            Some(d) => d,
            None => return TestResult::Fail("NCM functional descriptor not found"),
        };
        if !ncm.capabilities.packet_filter
            || !ncm.capabilities.net_address
            || !ncm.capabilities.crc_mode
        {
            return TestResult::Fail("modelled capabilities decoded wrong");
        }
        let eth = match eth {
            Some(d) => d,
            None => return TestResult::Fail("Ethernet descriptor not found"),
        };
        if eth.mac_string_index != 5 {
            return TestResult::Fail("modelled iMACAddress index wrong");
        }
        // Wrong comm interface → nothing found.
        let (n2, e2) = find_ncm_functional_descriptors(&cfg, 9);
        if n2.is_some() || e2.is_some() {
            return TestResult::Fail("descriptors found under wrong interface");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/cdc_ncm",
        smoke_ncm_functional_descriptor_finder
    );

    fn smoke_ncm_data_alt_setting_finder() -> TestResult {
        let cfg = modelled_ncm_cfg();
        // The endpoint-bearing instance is alt 1 of interface 1.
        if find_ncm_data_alt_setting(&cfg) != Some((1, 1)) {
            return TestResult::Fail("data alt setting not resolved to alt 1");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_ncm", smoke_ncm_data_alt_setting_finder);

    fn smoke_ncm_tx_routing_two_devices() -> TestResult {
        // The device-0 routing bug, pinned as fixed: with TWO
        // modelled devices registered, TX state resolution for
        // device 1 must return device 1's slot/endpoint, and its
        // sequence counter must advance independently of device
        // 0's.
        __reset_ncm_for_test();
        let mk = |slot_id: u8, out_dci: u8| CdcNcmDevice {
            slot_id,
            comm_iface: 0,
            data_iface: 1,
            bulk_in_dci: 3,
            bulk_out_dci: out_dci,
            tx_sequence: 0,
            mac: [0x02, 0, 0, 0, 0, slot_id],
            ntb_in_max_size: 4096,
            ntb_out_max_size: 16384,
            crc_enabled: false,
            iface_name: alloc::format!("usb-ncm-model-{}", slot_id),
            pump_running: false,
            detached: false,
        };
        {
            let mut g = CDC_NCM_DEVICES.lock();
            g.push(mk(7, 4));
            g.push(mk(9, 6));
        }
        let t0 = tx_target(0);
        let t1 = tx_target(1);
        let s1a = take_tx_state(1);
        let s1b = take_tx_state(1);
        let s0 = take_tx_state(0);
        __reset_ncm_for_test();
        if t0 != Some((7, 4)) || t1 != Some((9, 6)) {
            return TestResult::Fail("tx_target mis-routed between devices");
        }
        match (s1a, s1b, s0) {
            (
                Some((9, 6, 0, false, 4096)),
                Some((9, 6, 1, false, 4096)),
                Some((7, 4, 0, false, 4096)),
            ) => {}
            _ => return TestResult::Fail("per-device TX state wrong or shared"),
        }
        if tx_target(0).is_some() {
            return TestResult::Fail("tx_target resolved after reset");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_ncm", smoke_ncm_tx_routing_two_devices);

    /// Two modelled NCM devices bind; detaching the first
    /// tombstones exactly its record (TX fail-closes, net iface
    /// unregisters, survivor untouched), detach is idempotent
    /// and a no-op for unknown slots, wholesale detach clears
    /// the rest, and a re-push of the same slot publishes under
    /// a fresh index — never a duplicate iface, never a
    /// retargeted TX cookie.
    /// Masking-defeating cases: the detached record's pump had
    /// already exited (`pump_running` false before detach) yet
    /// detach still tombstones + unregisters; and TX state
    /// taken before detach does not survive it (`take_tx_state`
    /// after detach is `None` even though the sequence had
    /// already advanced).
    fn smoke_ncm_detach_tombstones_and_unregisters() -> TestResult {
        __reset_ncm_for_test();
        let mk = |slot_id: u8, out_dci: u8| CdcNcmDevice {
            slot_id,
            comm_iface: 0,
            data_iface: 1,
            bulk_in_dci: 3,
            bulk_out_dci: out_dci,
            tx_sequence: 0,
            mac: [0x02, 0, 0, 0, 0, slot_id],
            ntb_in_max_size: 4096,
            ntb_out_max_size: 16384,
            crc_enabled: false,
            iface_name: alloc::format!("usb-ncm-detach{}", slot_id),
            pump_running: true,
            detached: false,
        };
        {
            let mut g = CDC_NCM_DEVICES.lock();
            g.push(mk(7, 4));
            g.push(mk(9, 6));
        }
        // Register the net ifaces for real, capturing the
        // assigned names, so the unregister half is asserted
        // against the net registry, not trusted. Names follow
        // the production rule (`usb-ncm{record index}`).
        let (name7, name9) = {
            let mut g = CDC_NCM_DEVICES.lock();
            let n7 = narf_net::iface::register_with_context(
                "usb-ncm0",
                [0x02, 0, 0, 0, 0, 7],
                0,
                ncm_send_ctx,
            );
            let n9 = narf_net::iface::register_with_context(
                "usb-ncm1",
                [0x02, 0, 0, 0, 0, 9],
                1,
                ncm_send_ctx,
            );
            g[0].iface_name = n7.clone();
            g[1].iface_name = n9.clone();
            (n7, n9)
        };
        if narf_net::iface::lookup(&name7).is_none() || narf_net::iface::lookup(&name9).is_none() {
            __reset_ncm_for_test();
            return TestResult::Fail("net ifaces must resolve before detach");
        }
        if attached_ncm_count() != 2 {
            __reset_ncm_for_test();
            return TestResult::Fail("two devices should be bound");
        }
        // Advance device 0's TX sequence, then simulate its
        // pump having already exited before detach lands.
        if take_tx_state(0).is_none() {
            __reset_ncm_for_test();
            return TestResult::Fail("TX state must resolve before detach");
        }
        {
            let mut g = CDC_NCM_DEVICES.lock();
            g[0].pump_running = false;
        }
        if detach_ncm_slot(7).is_err() {
            __reset_ncm_for_test();
            return TestResult::Fail("detach must be infallible");
        }
        let ok = attached_ncm_count() == 1
            && tx_target(0).is_none()
            && take_tx_state(0).is_none()
            && CdcNcmIface::from_idx(0).is_none()
            && narf_net::iface::lookup(&name7).is_none()
            && tx_target(1) == Some((9, 6))
            && CdcNcmIface::from_idx(1).is_some()
            && narf_net::iface::lookup(&name9).is_some();
        if !ok {
            __reset_ncm_for_test();
            return TestResult::Fail("detach must tombstone exactly one binding");
        }
        // Idempotent, and unknown slots are a silent no-op.
        let _ = detach_ncm_slot(7);
        let _ = detach_ncm_slot(99);
        if attached_ncm_count() != 1 || tx_target(1) != Some((9, 6)) {
            __reset_ncm_for_test();
            return TestResult::Fail("repeat/unknown detach must not change the registry");
        }
        detach_all_ncm();
        if attached_ncm_count() != 0
            || tx_target(1).is_some()
            || narf_net::iface::lookup(&name9).is_some()
        {
            __reset_ncm_for_test();
            return TestResult::Fail("wholesale detach must clear every binding");
        }
        // Re-push the same slot: records are never removed, so
        // the new record lands at a fresh index with a fresh
        // iface name — never a duplicate, never a recycled
        // cookie. The re-bound name follows the production
        // rule (`usb-ncm{record index}`), exactly as bind
        // assigns it.
        let idx = {
            let mut g = CDC_NCM_DEVICES.lock();
            let idx = g.len();
            g.push(mk(7, 4));
            g[idx].iface_name = alloc::format!("usb-ncm{}", idx);
            idx
        };
        if idx != 2 {
            __reset_ncm_for_test();
            return TestResult::Fail("re-bind must not reuse a tombstoned index");
        }
        let fresh = {
            let g = CDC_NCM_DEVICES.lock();
            g[idx].iface_name.clone()
        };
        if fresh == name7 {
            __reset_ncm_for_test();
            return TestResult::Fail("re-bind must not recycle the detached iface name");
        }
        let _ = detach_ncm_slot(7);
        if attached_ncm_count() != 0 {
            __reset_ncm_for_test();
            return TestResult::Fail("cleanup detach must leave no live binding");
        }
        __reset_ncm_for_test();
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/cdc_ncm",
        smoke_ncm_detach_tombstones_and_unregisters
    );

    /// The class-registry unbind hook installed by
    /// `cdc_ncm::register_initcalls` must reach `detach_ncm_slot`
    /// through the supervisor's `dispatch_unbind` path — the
    /// wiring the hub-detach path actually uses, not just the
    /// detach function in isolation.
    fn smoke_ncm_dispatch_unbind_reaches_detach() -> TestResult {
        __reset_ncm_for_test();
        {
            let mut g = CDC_NCM_DEVICES.lock();
            g.push(CdcNcmDevice {
                slot_id: 7,
                comm_iface: 0,
                data_iface: 1,
                bulk_in_dci: 3,
                bulk_out_dci: 4,
                tx_sequence: 0,
                mac: [0x02, 0, 0, 0, 0, 7],
                ntb_in_max_size: 4096,
                ntb_out_max_size: 16384,
                crc_enabled: false,
                iface_name: alloc::format!("usb-ncm-detach{}", 7),
                pump_running: true,
                detached: false,
            });
        }
        register_initcalls();
        let report = crate::class_registry::dispatch_unbind(7);
        let live = attached_ncm_count();
        __reset_ncm_for_test();
        if report.invoked == 0 {
            return TestResult::Fail("dispatch_unbind invoked no hooks");
        }
        if live != 0 {
            return TestResult::Fail("unbind hook must tombstone the slot 7 binding");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/cdc_ncm",
        smoke_ncm_dispatch_unbind_reaches_detach
    );

    /// #789 remainder (a): rebind-on-redock proof. Two modelled
    /// NCM devices bind with real net ifaces; the supervisor's
    /// `dispatch_unbind` path detaches the first; a re-push of
    /// the same slot — the shape bind takes on replug, after
    /// the supervisor cleared the port claim — lands at a fresh
    /// index with a fresh iface name, TX state resolves to the
    /// NEW device (with a fresh sequence counter), and the old
    /// cookie fail-closes.
    fn smoke_ncm_redock_rebind_via_dispatch() -> TestResult {
        __reset_ncm_for_test();
        let mk = |slot_id: u8, out_dci: u8| CdcNcmDevice {
            slot_id,
            comm_iface: 0,
            data_iface: 1,
            bulk_in_dci: 3,
            bulk_out_dci: out_dci,
            tx_sequence: 0,
            mac: [0x02, 0, 0, 0, 0, slot_id],
            ntb_in_max_size: 4096,
            ntb_out_max_size: 16384,
            crc_enabled: false,
            iface_name: alloc::format!("usb-ncm-detach{}", slot_id),
            pump_running: true,
            detached: false,
        };
        {
            let mut g = CDC_NCM_DEVICES.lock();
            g.push(mk(7, 4));
            g.push(mk(9, 6));
        }
        let (name7, name9) = {
            let mut g = CDC_NCM_DEVICES.lock();
            let n7 = narf_net::iface::register_with_context(
                "usb-ncm0",
                [0x02, 0, 0, 0, 0, 7],
                0,
                ncm_send_ctx,
            );
            let n9 = narf_net::iface::register_with_context(
                "usb-ncm1",
                [0x02, 0, 0, 0, 0, 9],
                1,
                ncm_send_ctx,
            );
            g[0].iface_name = n7.clone();
            g[1].iface_name = n9.clone();
            (n7, n9)
        };
        if narf_net::iface::lookup(&name7).is_none() || narf_net::iface::lookup(&name9).is_none() {
            __reset_ncm_for_test();
            return TestResult::Fail("net ifaces must resolve before detach");
        }
        register_initcalls();
        let report = crate::class_registry::dispatch_unbind(7);
        if report.invoked == 0 {
            __reset_ncm_for_test();
            return TestResult::Fail("dispatch_unbind invoked no hooks");
        }
        if tx_target(0).is_some()
            || take_tx_state(0).is_some()
            || narf_net::iface::lookup(&name7).is_some()
            || tx_target(1) != Some((9, 6))
        {
            __reset_ncm_for_test();
            return TestResult::Fail("dispatch detach must tombstone exactly one binding");
        }
        // Re-plug: fresh record, published under the production
        // name rule with a real net iface, fresh TX sequence —
        // never a recycled cookie or name.
        let idx = {
            let mut g = CDC_NCM_DEVICES.lock();
            let idx = g.len();
            g.push(mk(7, 4));
            let requested = alloc::format!("usb-ncm{}", idx);
            let assigned = narf_net::iface::register_with_context(
                &requested,
                [0x02, 0, 0, 0, 0, 7],
                idx as u64,
                ncm_send_ctx,
            );
            g[idx].iface_name = assigned;
            idx
        };
        if idx != 2 {
            __reset_ncm_for_test();
            return TestResult::Fail("re-bind must not reuse a tombstoned index");
        }
        let fresh = {
            let g = CDC_NCM_DEVICES.lock();
            g[idx].iface_name.clone()
        };
        // take_tx_state takes the registry lock itself, so it
        // must run with no guard held here. A fresh record
        // means a fresh sequence counter (0), not the detached
        // record's advanced counter.
        let state = take_tx_state(idx);
        if fresh == name7
            || tx_target(idx) != Some((7, 4))
            || tx_target(0).is_some()
            || narf_net::iface::lookup(&fresh).is_none()
            || state != Some((7, 4, 0, false, 4096))
        {
            __reset_ncm_for_test();
            return TestResult::Fail("re-bind must publish fresh and keep the old cookie dead");
        }
        let _ = detach_ncm_slot(7);
        __reset_ncm_for_test();
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_ncm", smoke_ncm_redock_rebind_via_dispatch);
}

// ── Class enumeration + bind ───────────────────────────────────────
//
// Full bind path: SET_CONFIGURATION (+ SET_INTERFACE to the
// endpoint-bearing data alt setting), endpoint configuration,
// NTB parameter negotiation, station-address acquisition from the
// device, netdev publication with per-device TX routing, and a
// supervised RX pump.

use narf_lib::sync::IrqSafeSpinLock;

/// One bound CDC-NCM device — slot id + Comm interface number.
#[derive(Clone, Debug)]
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
    /// Station address read from the device at bind
    /// (GET_NET_ADDRESS, or the iMACAddress string descriptor).
    pub mac: [u8; 6],
    /// Negotiated host→device NTB size cap (`dwNtbInMaxSize`);
    /// 0 = the device never answered GET_NTB_PARAMETERS.
    pub ntb_in_max_size: u32,
    /// Negotiated device→host NTB size (`dwNtbOutMaxSize`);
    /// sizes the RX pump's buffer.
    pub ntb_out_max_size: u32,
    /// CRC mode negotiated on (SET_CRC_MODE accepted): TX
    /// datagrams carry an appended CRC-32 and RX datagrams are
    /// CRC-verified and stripped.
    pub crc_enabled: bool,
    /// Assigned `narf_net::iface` name (`usb-ncm{N}`).
    pub iface_name: alloc::string::String,
    /// RX pump liveness flag (pump clears it on exit).
    pub pump_running: bool,
    /// Detach tombstone: set by `detach_ncm_slot`. The pump exits
    /// when it sees it; TX/RX resolve to `NotNcm`. Records are
    /// never removed, because net-registry TX cookies are record
    /// indices — removing a record would retarget every later
    /// device's cookie at the wrong device (the ECM rule).
    pub detached: bool,
}

/// System-wide registry of bound CDC-NCM devices.
pub static CDC_NCM_DEVICES: IrqSafeSpinLock<Vec<CdcNcmDevice>> = IrqSafeSpinLock::new(Vec::new());

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

/// Locate the NCM + Ethernet Networking functional descriptors
/// in the descriptor set that follows the Comm interface
/// `comm_iface` within `cfg`.
pub fn find_ncm_functional_descriptors(
    cfg: &[u8],
    comm_iface: u8,
) -> (Option<NcmDescriptor>, Option<EthernetNetworkingDescriptor>) {
    let mut in_comm = false;
    let mut ncm = None;
    let mut eth = None;
    let mut i = 0usize;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        let desc_type = cfg[i + 1];
        if desc_type == 0x04 && len >= 9 {
            // INTERFACE descriptor — byte 2 is bInterfaceNumber.
            in_comm = cfg[i + 2] == comm_iface;
        } else if desc_type == 0x24 && in_comm {
            // CS_INTERFACE functional descriptor.
            match cfg[i + 2] {
                0x1A if ncm.is_none() => {
                    ncm = NcmDescriptor::parse(&cfg[i..i + len]).ok();
                }
                0x0F if eth.is_none() => {
                    eth = EthernetNetworkingDescriptor::parse(&cfg[i..i + len]).ok();
                }
                _ => {}
            }
        }
        i += len;
    }
    (ncm, eth)
}

/// Find the CDC-Data interface instance that owns bulk endpoints
/// and report `(interface_number, bAlternateSetting)`. NCM data
/// interfaces commonly ship alt 0 with no endpoints (inactive)
/// and alt 1 with the bulk pair (active); the host must
/// SET_INTERFACE to the endpoint-bearing setting before the data
/// pipe runs.
pub fn find_ncm_data_alt_setting(cfg: &[u8]) -> Option<(u8, u8)> {
    let mut current: Option<(u8, u8, bool)> = None; // (num, alt, is_data)
    let mut i = 0usize;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        let desc_type = cfg[i + 1];
        if desc_type == 0x04 && len >= 9 {
            current = Some((
                cfg[i + 2],
                cfg[i + 3],
                cfg[i + 5] == crate::cdc::USB_CLASS_CDC_DATA,
            ));
        } else if desc_type == 0x05 && len >= 7 {
            if let Some((num, alt, true)) = current {
                // Bulk endpoint under the current Data interface.
                if cfg[i + 3] & 0x03 == 2 {
                    return Some((num, alt));
                }
            }
        }
        i += len;
    }
    None
}

/// A station address is usable when it is neither unprogrammed
/// (all-zero / all-ones) nor a multicast address.
pub fn is_valid_station_address(mac: &[u8; 6]) -> bool {
    !mac.iter().all(|&b| b == 0) && !mac.iter().all(|&b| b == 0xFF) && mac[0] & 1 == 0
}

/// Decode an iMACAddress string descriptor (USB string format:
/// bLength, bDescriptorType 0x03, then UTF-16LE hex digits —
/// "001A2B3C4D5E") into a station address.
pub fn parse_mac_string_descriptor(desc: &[u8]) -> Option<[u8; 6]> {
    if desc.len() < 2 || desc[1] != 0x03 {
        return None;
    }
    let total = (desc[0] as usize).min(desc.len());
    let body = &desc[2..total];
    if body.len() < 24 || body.len() % 2 != 0 {
        return None;
    }
    let mut mac = [0u8; 6];
    for nib in 0..12usize {
        let lo = body[nib * 2];
        let hi = body[nib * 2 + 1];
        if hi != 0 {
            return None;
        }
        let v = match lo {
            b'0'..=b'9' => lo - b'0',
            b'a'..=b'f' => lo - b'a' + 10,
            b'A'..=b'F' => lo - b'A' + 10,
            _ => return None,
        };
        if nib % 2 == 0 {
            mac[nib / 2] = v << 4;
        } else {
            mac[nib / 2] |= v;
        }
    }
    if is_valid_station_address(&mac) {
        Some(mac)
    } else {
        None
    }
}

/// Fetch the iMACAddress string descriptor (`index`) from the
/// device and decode it. The LANGID is read from the string-0
/// table first, falling back to en-US (0x0409).
async fn fetch_mac_string(xhci_dev: &crate::xhci::Xhci, slot_id: u8, index: u8) -> Option<[u8; 6]> {
    if index == 0 {
        return None;
    }
    let mut lang = [0u8; 4];
    let langid = match xhci_dev
        .control_in(slot_id, 0x80, 6, 0x0300, 0, &mut lang)
        .await
    {
        Ok(n) if n >= 4 => u16::from_le_bytes([lang[2], lang[3]]),
        _ => 0x0409,
    };
    let mut buf = [0u8; 64];
    let n = xhci_dev
        .control_in(slot_id, 0x80, 6, 0x0300 | index as u16, langid, &mut buf)
        .await
        .ok()?;
    parse_mac_string_descriptor(&buf[..n])
}

/// Outcome of the bind-time class-request negotiation.
struct Negotiated {
    ntb_in_max_size: u32,
    ntb_out_max_size: u32,
    crc_enabled: bool,
}

/// Run the NCM class-request negotiation against the Comm
/// interface: GET_NTB_PARAMETERS, then — as the parameters and
/// the functional descriptor's capabilities offer — select
/// NTB-16, set the input size, and enable CRC mode. Individual
/// SET failures are tolerated (the device keeps its defaults);
/// only the returned sizes/CRC state reflect what stuck.
async fn negotiate_ncm(
    xhci_dev: &crate::xhci::Xhci,
    slot_id: u8,
    comm_iface: u8,
    caps: &NetworkCapabilities,
) -> Negotiated {
    // Defaults when the device never answers: our TX NTBs stay
    // single-frame sized; the pump posts a 16 KiB buffer.
    let mut out = Negotiated {
        ntb_in_max_size: 0,
        ntb_out_max_size: 16 * 1024,
        crc_enabled: false,
    };
    let mut raw = [0u8; NtbParameters::WIRE_LEN];
    let params = match xhci_dev
        .control_in(
            slot_id,
            0xA1,
            REQ_GET_NTB_PARAMETERS,
            0,
            comm_iface as u16,
            &mut raw,
        )
        .await
    {
        Ok(_) => NtbParameters::decode(&raw).ok(),
        Err(_) => None,
    };
    let Some(params) = params else {
        return out;
    };
    out.ntb_in_max_size = params.ntb_in_max_size;
    if params.ntb_out_max_size > 0 {
        out.ntb_out_max_size = params.ntb_out_max_size;
    }
    // Select NTB-16 (format index 0) when the device offers it.
    if params.formats_supported & 0x01 != 0 {
        let _ = xhci_dev
            .control_out(slot_id, 0x21, REQ_SET_NTB_FORMAT, 0, comm_iface as u16, &[])
            .await;
    }
    // Tell the device the largest NTB we will send: the device's
    // own cap, clamped to what this TX path builds (single-frame
    // NTBs, generous headroom).
    if params.ntb_in_max_size > 0 {
        let input_size = params.ntb_in_max_size.min(4096);
        let _ = xhci_dev
            .control_out(
                slot_id,
                0x21,
                REQ_SET_NTB_INPUT_SIZE,
                0,
                comm_iface as u16,
                &input_size.to_le_bytes(),
            )
            .await;
    }
    // CRC mode when the functional descriptor offers it.
    if caps.crc_mode {
        let crc_on = xhci_dev
            .control_out(slot_id, 0x21, REQ_SET_CRC_MODE, 1, comm_iface as u16, &[])
            .await;
        out.crc_enabled = crc_on.is_ok();
    }
    out
}

/// Bind to an already-addressed CDC-NCM device:
/// SET_CONFIGURATION (+ SET_INTERFACE to the endpoint-bearing
/// data alt setting), endpoint configuration, NTB negotiation,
/// station-address acquisition from the device, netdev
/// publication with per-device TX routing, and the RX pump.
pub async fn try_bind_ncm_already_addressed(
    xhci_dev: &crate::xhci::Xhci,
    slot_id: u8,
    cfg: &[u8],
) -> Result<usize, NcmError> {
    let comm_iface = find_ncm_comm_interface(cfg).ok_or(NcmError::NotNcm)?;
    let cfg_value = if cfg.len() >= 9 { cfg[5] } else { 1 };
    if xhci_dev
        .control_out(
            slot_id,
            0x00,
            crate::hid::STD_REQ_SET_CONFIGURATION,
            cfg_value as u16,
            0,
            &[],
        )
        .await
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
    // Activate the data interface's endpoint-bearing alt setting
    // (commonly alt 1; alt 0 carries no endpoints and leaves the
    // data pipe inert on real firmware).
    if let Some((alt_iface, alt)) = find_ncm_data_alt_setting(cfg) {
        if alt > 0 {
            let _ = xhci_dev
                .control_out(slot_id, 0x01, 0x0B, alt as u16, alt_iface as u16, &[])
                .await;
        }
    }
    // Configure the bulk pair so the controller wires up its
    // Transfer Rings. Mirrors the MSC bind path.
    if xhci_dev
        .configure_endpoints(slot_id, &[bulk_in_ep, bulk_out_ep])
        .await
        .is_err()
    {
        return Err(NcmError::SetConfigFailed);
    }
    let bulk_in_dci = ((bulk_in_ep.ep_addr & 0x0F) * 2) + 1;
    let bulk_out_dci = (bulk_out_ep.ep_addr & 0x0F) * 2;

    // Functional descriptors drive negotiation + MAC acquisition.
    let (ncm_desc, eth_desc) = find_ncm_functional_descriptors(cfg, comm_iface);
    let caps = ncm_desc.map(|d| d.capabilities).unwrap_or_default();
    let negotiated = negotiate_ncm(xhci_dev, slot_id, comm_iface, &caps).await;

    // Station address from the device itself: GET_NET_ADDRESS
    // when offered, else the iMACAddress string descriptor. No
    // valid address → the bind fails; one is never invented.
    let mut mac: Option<[u8; 6]> = None;
    if caps.net_address {
        let mut raw = [0u8; 6];
        if xhci_dev
            .control_in(
                slot_id,
                0xA1,
                REQ_GET_NET_ADDRESS,
                0,
                comm_iface as u16,
                &mut raw,
            )
            .await
            .is_ok()
            && is_valid_station_address(&raw)
        {
            mac = Some(raw);
        }
    }
    if mac.is_none() {
        if let Some(eth) = eth_desc {
            mac = fetch_mac_string(xhci_dev, slot_id, eth.mac_string_index).await;
        }
    }
    let mac = mac.ok_or(NcmError::NoMacAddress)?;

    // Normal receive filtering (directed + broadcast + multicast)
    // when the device offers the request.
    if caps.packet_filter {
        let _ = xhci_dev
            .control_out(
                slot_id,
                0x21,
                REQ_SET_PACKET_FILTER,
                PacketFilter::NORMAL.encode(),
                comm_iface as u16,
                &[],
            )
            .await;
    }

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
            mac,
            ntb_in_max_size: negotiated.ntb_in_max_size,
            ntb_out_max_size: negotiated.ntb_out_max_size,
            crc_enabled: negotiated.crc_enabled,
            iface_name: alloc::format!("usb-ncm{}", idx),
            pump_running: false,
            detached: false,
        });
        idx
    };
    // Publish with per-device TX routing: the registration cookie
    // is this record's index, and the send hook resolves it back
    // to this device — and only this device.
    let assigned = register_ncm_iface(idx, mac);
    {
        let mut g = CDC_NCM_DEVICES.lock();
        g[idx].iface_name = assigned;
        g[idx].pump_running = true;
    }
    narf_scheduler::spawn(async move {
        ncm_rx_pump(idx).await;
    });
    Ok(idx)
}

/// Supervised RX pump for one bound NCM device: post bulk-IN
/// reads sized by the negotiated OUT NTB maximum, walk each NTB
/// with [`for_each_frame`], and hand every datagram to the stack
/// as its own frame. Stops after a bounded run of consecutive
/// transfer errors (a removed device surfaces as persistent
/// errors) or when the record vanishes.
async fn ncm_rx_pump(idx: usize) {
    let (slot_id, bulk_in_dci, name, buf_len) = {
        let g = CDC_NCM_DEVICES.lock();
        let Some(dev) = g.get(idx) else {
            return;
        };
        (
            dev.slot_id,
            dev.bulk_in_dci,
            dev.iface_name.clone(),
            (dev.ntb_out_max_size as usize).clamp(4096, 64 * 1024),
        )
    };
    let Some(c) = crate::xhci::controller() else {
        let mut g = CDC_NCM_DEVICES.lock();
        if let Some(dev) = g.get_mut(idx) {
            dev.pump_running = false;
        }
        return;
    };
    let mut buf = alloc::vec![0u8; buf_len];
    let mut errors = 0u32;
    loop {
        // Detach check first: a tombstoned record exits before
        // posting another transfer or delivering another frame.
        // An NTB already in flight when detach lands may still
        // deliver once (same window as ECM); the loop never
        // iterates past the tombstone.
        {
            let g = CDC_NCM_DEVICES.lock();
            if g.get(idx).map(|d| d.detached).unwrap_or(true) {
                break;
            }
        }
        match c.bulk_in(slot_id, bulk_in_dci, &mut buf).await {
            Ok(n) if n > 0 => {
                errors = 0;
                let _ = for_each_frame(&buf[..n], &mut |frame| {
                    let mut owned = frame.to_vec();
                    narf_net::iface::on_rx_frame_from(&name, &mut owned);
                });
            }
            Ok(_) => narf_scheduler::yield_now().await,
            Err(_) => {
                errors += 1;
                if errors >= 16 {
                    break;
                }
                narf_scheduler::yield_now().await;
            }
        }
    }
    let mut g = CDC_NCM_DEVICES.lock();
    if let Some(dev) = g.get_mut(idx) {
        dev.pump_running = false;
    }
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
                    interval: 0,
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

/// Resolve a device-record index to its TX target
/// `(slot_id, bulk_out_dci)`. A detached record resolves to
/// `None`: a tombstoned index must never retarget a later
/// device, and must never emit on a dead slot.
pub fn tx_target(idx: usize) -> Option<(u8, u8)> {
    let g = CDC_NCM_DEVICES.lock();
    g.get(idx)
        .filter(|d| !d.detached)
        .map(|d| (d.slot_id, d.bulk_out_dci))
}

/// Snapshot + advance the TX bookkeeping for device `idx`:
/// `(slot_id, bulk_out_dci, sequence, crc_enabled,
/// ntb_in_max_size)`. The sequence bump happens here, under the
/// registry lock, so concurrent sends on one device never reuse
/// a sequence number — and never touch another device's counter.
pub fn take_tx_state(idx: usize) -> Option<(u8, u8, u16, bool, u32)> {
    let mut g = CDC_NCM_DEVICES.lock();
    let dev = g.get_mut(idx).filter(|d| !d.detached)?;
    let seq = dev.tx_sequence;
    dev.tx_sequence = dev.tx_sequence.wrapping_add(1);
    Some((
        dev.slot_id,
        dev.bulk_out_dci,
        seq,
        dev.crc_enabled,
        dev.ntb_in_max_size,
    ))
}

/// Send one Ethernet frame over the bound NCM device at `idx` —
/// and only that device: the endpoint comes from the device's
/// own record via [`take_tx_state`]. Wraps the frame in an
/// NTB-16 (single-datagram NDP; CRC appended when CRC mode was
/// negotiated) and ships it on the bulk-OUT endpoint.
pub fn send_frame(idx: usize, eth_frame: &[u8]) -> Result<usize, NcmError> {
    let (slot_id, bulk_out_dci, sequence, crc, in_max) =
        take_tx_state(idx).ok_or(NcmError::NotNcm)?;
    let with_crc;
    let datagram: &[u8] = if crc {
        with_crc = append_crc(eth_frame);
        &with_crc
    } else {
        eth_frame
    };
    let ntb = build_ntb16(sequence, &[datagram], crc)?;
    if in_max > 0 && ntb.len() > in_max as usize {
        return Err(NcmError::NtbTooLarge);
    }
    // The net stack's `SendFn` is sync — bridge to the now-async
    // bulk_out via block_on. Safe here because the trampoline is
    // called from netstack TX paths that are not themselves inside
    // an executor poll.
    let c = match crate::xhci::controller() {
        Some(c) => c,
        None => return Err(NcmError::Truncated),
    };
    let outcome =
        narf_scheduler::block_on(async move { c.bulk_out(slot_id, bulk_out_dci, &ntb).await });
    match outcome {
        Ok(n) => Ok(n),
        Err(_) => Err(NcmError::Truncated),
    }
}

/// Pull one Ethernet frame off the bound NCM device's bulk-IN
/// endpoint. Reads an NTB into `scratch`, parses it, returns the
/// first deliverable datagram (if any). CRC handling matches the
/// production pump path ([`for_each_frame`]): under CRC mode each
/// datagram's trailing CRC-32 is verified and stripped, and a
/// CRC-failing datagram is skipped in favour of the next one
/// rather than delivered with the FCS still attached. Caller
/// polls this periodically; on real silicon the bulk-IN ring
/// continuously holds an NTB-sized read posted so frames stream
/// in.
pub fn recv_frame(idx: usize, scratch: &mut [u8]) -> Result<Option<&[u8]>, NcmError> {
    let (slot_id, bulk_in_dci) = {
        let g = CDC_NCM_DEVICES.lock();
        let dev = g.get(idx).filter(|d| !d.detached).ok_or(NcmError::NotNcm)?;
        (dev.slot_id, dev.bulk_in_dci)
    };
    // Sync entry-point on the net RX path; bridge to async bulk_in
    // via block_on. Called from non-executor contexts.
    let c = match crate::xhci::controller() {
        Some(c) => c,
        None => return Err(NcmError::Truncated),
    };
    let outcome =
        narf_scheduler::block_on(async { c.bulk_in(slot_id, bulk_in_dci, scratch).await });
    let n = match outcome {
        Ok(n) => n,
        Err(_) => return Err(NcmError::Truncated),
    };
    if n == 0 {
        return Ok(None);
    }
    let ntb = ParsedNtb::parse(&scratch[..n])?;
    // Walk the datagrams with the pump path's semantics
    // (for_each_frame): out-of-bounds entries are skipped, and
    // under CRC mode the trailing CRC-32 is verified and stripped
    // — a too-short or CRC-failing datagram is skipped, never
    // delivered with the FCS still attached.
    for i in 0..ntb.len() {
        let Some(dg) = ntb.datagram(i) else {
            continue;
        };
        let frame: &[u8] = if ntb.uses_crc() {
            if dg.len() < 4 {
                continue;
            }
            let (frame, tail) = dg.split_at(dg.len() - 4);
            let want = u32::from_le_bytes(tail.try_into().unwrap());
            if crc32_ieee(frame) != want {
                continue;
            }
            frame
        } else {
            dg
        };
        // Re-borrow against the scratch lifetime — Ntb16 borrows
        // immutably; the lifetime path is straightforward here
        // because frame points into &scratch[..n].
        let off = frame.as_ptr() as usize - scratch.as_ptr() as usize;
        return Ok(Some(&scratch[off..off + frame.len()]));
    }
    Ok(None)
}

/// `SendCtxFn` trampoline for [`narf_net::iface`]: the cookie is
/// the device-record index captured at registration, so a frame
/// submitted on interface N is emitted by device N — the previous
/// device-0-hardwired trampoline is gone.
fn ncm_send_ctx(cookie: u64, frame: &[u8], _meta: narf_net::TxMeta) -> Result<(), ()> {
    match send_frame(cookie as usize, frame) {
        Ok(_) => Ok(()),
        Err(_) => Err(()),
    }
}

/// Detach hook for a slot: tombstone every NCM record bound to
/// it and unregister its net iface. The pump exits on the
/// tombstone at its next loop-top check; TX/RX resolve to
/// `NotNcm` instead of retargeting a later device (records are
/// never removed — the ECM rule: net-registry TX cookies are
/// record indices). Unknown slots no-op; repeat detach is a
/// silent no-op (unregister is idempotent).
///
/// RX-mirror obligation (#789, from the #872-review note):
/// RESOLVED as not owed here — same verdict as ECM/r8152:
/// this family's pumps deliver via
/// `narf_net::iface::on_rx_frame_from` directly and never call
/// `publish::note_rx_mirror_attached`, and its `usb-ncm{N}`
/// names cannot collide with the `eth%d` keys the mirror
/// registry can ever hold. No clear call is owed; if this
/// family ever dual-publishes, its detach paths must call
/// `publish::clear_rx_mirror_attached` alongside unregister.
///
/// Panic-free and idempotent by the #893 hook contract: no
/// indexing and no fallible unwraps on any path. Tombstones are
/// set under the registry lock and iface names collected there,
/// but the net unregister runs after the lock is released —
/// the net registry lock must never be taken while the NCM
/// registry lock is held (UVC collect-then-unregister pattern).
/// A TX already past `take_tx_state` when detach lands may
/// still hit the wire; every later TX fail-closes.
///
/// Infallible bookkeeping, adapted to the [`UsbUnbindFn`]
/// contract with an unconditional `Ok(())` (#893: a hook
/// reports failure with `Err(())`, never by panicking).
pub fn detach_ncm_slot(slot_id: u8) -> Result<(), ()> {
    let ifaces: Vec<alloc::string::String> = {
        let mut g = CDC_NCM_DEVICES.lock();
        let mut names = Vec::new();
        for dev in g.iter_mut().filter(|d| d.slot_id == slot_id && !d.detached) {
            dev.detached = true;
            dev.pump_running = false;
            names.push(dev.iface_name.clone());
        }
        names
    };
    for name in ifaces {
        let _ = narf_net::iface::unregister(&name);
    }
    Ok(())
}

/// Wholesale variant of [`detach_ncm_slot`] for controller
/// recovery (`attach::detach_all_bindings`): tombstone every
/// NCM binding and unregister every net iface, regardless of
/// slot. Infallible and idempotent, same pump-exit and
/// never-remove reasoning as [`detach_ncm_slot`], and the same
/// #789 mirror verdict (no clear call owed).
pub fn detach_all_ncm() {
    let ifaces: Vec<alloc::string::String> = {
        let mut g = CDC_NCM_DEVICES.lock();
        let mut names = Vec::new();
        for dev in g.iter_mut().filter(|d| !d.detached) {
            dev.detached = true;
            dev.pump_running = false;
            names.push(dev.iface_name.clone());
        }
        names
    };
    for name in ifaces {
        let _ = narf_net::iface::unregister(&name);
    }
}

/// Register the NCM device at `idx` as a network interface under
/// `usb-ncm{idx}`, publishing the device-supplied station
/// address `mac`. Returns the assigned interface name.
fn register_ncm_iface(idx: usize, mac: [u8; 6]) -> alloc::string::String {
    let name = alloc::format!("usb-ncm{}", idx);
    narf_net::iface::register_with_context(&name, mac, idx as u64, ncm_send_ctx)
}

/// Number of live (non-detached) NCM devices. Tombstoned
/// records still occupy their index (TX cookies are indices),
/// so the raw registry length is not the live count.
pub fn attached_ncm_count() -> usize {
    CDC_NCM_DEVICES
        .lock()
        .iter()
        .filter(|d| !d.detached)
        .count()
}

#[doc(hidden)]
pub fn __reset_ncm_for_test() {
    CDC_NCM_DEVICES.lock().clear();
}

// ── Public API alias (spec §"Public API") ────────────────────────

/// Public-facing bind entry point — alias to
/// [`try_bind_ncm_already_addressed`] using the spec-mandated name.
///
/// Accepts an already-addressed `slot_id` and a full configuration
/// descriptor blob `cfg`. If the device has a CDC-Comm/NCM interface
/// (class 0x02 / subclass 0x0D) the driver claims it, issues
/// `SET_CONFIGURATION`, wires up the bulk-IN/OUT pair, and registers
/// the device with the net-iface registry under `usb-ncmN`.
///
/// Returns the index into [`CDC_NCM_DEVICES`] on success, or
/// [`NcmError`] if the device is not NCM or configuration fails.
#[inline]
pub async fn try_bind_cdc_ncm_already_addressed(
    xhci_dev: &crate::xhci::Xhci,
    slot_id: u8,
    cfg: &[u8],
) -> Result<usize, NcmError> {
    try_bind_ncm_already_addressed(xhci_dev, slot_id, cfg).await
}

// ── CdcNcmIface — logical per-device interface handle ────────────

/// Logical handle to a bound CDC-NCM device exposed to the rest of
/// the kernel as a narf-net `NetIfaceEntry`-compatible face.
///
/// After [`try_bind_cdc_ncm_already_addressed`] succeeds, callers
/// can borrow a `CdcNcmIface` via [`CdcNcmIface::from_idx`] to send
/// or receive Ethernet frames without going through the static
/// trampoline used during bring-up.
#[derive(Copy, Clone, Debug)]
pub struct CdcNcmIface {
    /// Index into [`CDC_NCM_DEVICES`].
    pub idx: usize,
    /// Station address read from the device at bind.
    pub mac: [u8; 6],
}

impl CdcNcmIface {
    /// Construct from a bound-device index. Returns `None` if `idx`
    /// is out of range or the record is detached.
    pub fn from_idx(idx: usize) -> Option<Self> {
        let g = CDC_NCM_DEVICES.lock();
        let dev = g.get(idx).filter(|d| !d.detached)?;
        Some(Self { idx, mac: dev.mac })
    }

    /// Send `eth_frame` via the bound NCM device. Wraps the frame
    /// in a single-datagram NTB-16 and ships it on bulk-OUT.
    pub fn send(&self, eth_frame: &[u8]) -> Result<usize, NcmError> {
        send_frame(self.idx, eth_frame)
    }

    /// Receive the next Ethernet frame off the bulk-IN endpoint.
    /// `scratch` must be at least as large as the device's max IN-NTB
    /// size (typically 16 KiB; see [`NtbParameters::ntb_in_max_size`]).
    /// Returns the datagram slice (borrowed from `scratch`) or `None`
    /// if the transfer was empty.
    pub fn recv<'a>(&self, scratch: &'a mut [u8]) -> Result<Option<&'a [u8]>, NcmError> {
        recv_frame(self.idx, scratch)
    }
}

pub static CDC_NCM_MATCH: [crate::class_registry::UsbClassMatch; 1] = [
    // Class 2 (Comm), Subclass 13 (NCM)
    crate::class_registry::UsbClassMatch {
        vendor_id: 0,
        product_id: 0,
        class: Some(2),
        subclass: Some(13),
        protocol: None,
    },
];

pub fn probe(
    _device: alloc::sync::Arc<crate::device::USBDevice>,
) -> Result<(), crate::class_registry::UsbProbeError> {
    use core::fmt::Write;
    let _ = writeln!(narf_console::Writer, "  usb: CDC-NCM device bound!");
    Ok(())
}

pub fn register_initcalls() {
    // Mirror ECM's hook registration: the probe always declines
    // (NCM binding stays in the attach cascade), and the unbind
    // hook adapts infallible `detach_ncm_slot` to the fallible
    // `UsbUnbindFn` contract with an unconditional `Ok(())`
    // (#893: a hook reports failure with `Err(())`, never by
    // panicking).
    let _ = crate::class_registry::register_class_driver_with_unbind(
        "cdc-ncm",
        &CDC_NCM_MATCH,
        probe,
        detach_ncm_slot,
    );
}
