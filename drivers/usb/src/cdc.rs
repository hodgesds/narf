//! USB CDC (Communications Device Class) common descriptor parser
//! — clean-room.
//!
//! References (public-only):
//! - **USB Class Definitions for Communications Devices, Revision
//!   1.2, Errata 1** (USB-IF, November 2010 / errata July 2012).
//!   Public document, usb.org. §3 architecture, §5.2 functional
//!   descriptors, §5.3 interface descriptors.
//!   <https://www.usb.org/document-library/class-definitions-communication-devices-12>
//! - **USB Specification 2.0** §9 (standard descriptors). Public.
//!
//! No GPL Linux source consulted.
//!
//! ## Class triples
//!
//! CDC devices expose **two** interfaces:
//!
//! - The **CDC Communication interface** (class `0x02`,
//!   "Communications and CDC Control") carries the class-specific
//!   functional descriptors + the management endpoint
//!   (notification IN endpoint).
//! - The **CDC Data interface** (class `0x0A`, "CDC-Data")
//!   carries the bulk IN/OUT endpoints with the actual payload.
//!
//! The CDC-Comm interface's *subclass* discriminates the model:
//!
//! | Subclass | Model                                     |
//! | -------- | ----------------------------------------- |
//! |   0x01   | DLCM — Direct Line Control Model          |
//! |   0x02   | ACM  — Abstract Control Model (serial)    |
//! |   0x06   | ENCM — Ethernet Networking Control Model  |
//! |   0x0D   | NCM  — Network Control Model              |
//! |   0x0E   | MBIM — Mobile Broadband Interface Model   |
//!
//! ## Functional descriptors (§5.2.3)
//!
//! Every CDC class-specific descriptor begins with:
//!
//! ```text
//!   bLength            u8   total length in bytes
//!   bDescriptorType    u8   0x24 = CS_INTERFACE
//!   bDescriptorSubtype u8   identifies the variant
//! ```
//!
//! followed by a subtype-specific payload. The shared subtype
//! values land here; each per-subclass module decodes its own
//! payload.

use core::convert::TryFrom;

// ── Class triple ─────────────────────────────────────────────────

/// CDC-Comm interface class — CDC management surface.
pub const USB_CLASS_CDC_COMM: u8 = 0x02;
/// CDC-Data interface class — bulk payload pipe.
pub const USB_CLASS_CDC_DATA: u8 = 0x0A;

/// `bDescriptorType = 0x24` — CS_INTERFACE (class-specific
/// interface descriptor). USB 2.0 §9.6.6.
pub const CS_INTERFACE: u8 = 0x24;
/// `bDescriptorType = 0x25` — CS_ENDPOINT.
pub const CS_ENDPOINT: u8 = 0x25;

// ── CDC-Comm subclasses (CDC 1.2 §4.3) ───────────────────────────

pub const CDC_SUBCLASS_DLCM: u8 = 0x01;
pub const CDC_SUBCLASS_ACM: u8 = 0x02;
pub const CDC_SUBCLASS_TCM: u8 = 0x03;
pub const CDC_SUBCLASS_MCCM: u8 = 0x04;
pub const CDC_SUBCLASS_CCM: u8 = 0x05;
pub const CDC_SUBCLASS_ENCM: u8 = 0x06;
pub const CDC_SUBCLASS_ATMNCM: u8 = 0x07;
pub const CDC_SUBCLASS_WHCM: u8 = 0x08;
pub const CDC_SUBCLASS_DMM: u8 = 0x09;
pub const CDC_SUBCLASS_MDLM: u8 = 0x0A;
pub const CDC_SUBCLASS_OBEX: u8 = 0x0B;
pub const CDC_SUBCLASS_EEM: u8 = 0x0C;
pub const CDC_SUBCLASS_NCM: u8 = 0x0D;
pub const CDC_SUBCLASS_MBIM: u8 = 0x0E;

// ── Functional-descriptor subtypes (CDC 1.2 §5.2.3 + subclass specs) ─

/// Functional-descriptor subtype.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FunctionalSubtype {
    /// `Header` — required first functional descriptor (CDC §5.2.3.1).
    Header,
    /// `Call Management` — PSTN-1.2 §5.3.1.
    CallManagement,
    /// `Abstract Control Management` — PSTN-1.2 §5.3.2.
    Acm,
    /// `Direct Line Management` — PSTN-1.2 §5.3.3.
    DirectLine,
    /// `Telephone Ringer` — PSTN-1.2 §5.3.4.
    TelephoneRinger,
    /// `Telephone Call and Line State Reporting Capabilities`.
    TelephoneCallStateReporting,
    /// `Union` — groups Comm + Data interfaces (CDC §5.2.3.2).
    Union,
    /// `Country Selection`.
    CountrySelection,
    /// `Telephone Operational Modes`.
    TelephoneOperationalModes,
    /// `USB Terminal`.
    UsbTerminal,
    /// `Network Channel Terminal`.
    NetworkChannelTerminal,
    /// `Protocol Unit`.
    ProtocolUnit,
    /// `Extension Unit`.
    ExtensionUnit,
    /// `Multi-Channel Management`.
    MultiChannelManagement,
    /// `CAPI Control Management`.
    CapiControlManagement,
    /// `Ethernet Networking` — ECM 1.2 §5.4.
    EthernetNetworking,
    /// `ATM Networking`.
    AtmNetworking,
    /// `Wireless Handset Control Model`.
    WirelessHandsetControlModel,
    /// `Mobile Direct Line Model`.
    MobileDirectLineModel,
    /// `MDLM Detail`.
    MdlmDetail,
    /// `Device Management Model`.
    DeviceManagementModel,
    /// `OBEX`.
    Obex,
    /// `Command Set`.
    CommandSet,
    /// `Command Set Detail`.
    CommandSetDetail,
    /// `Telephone Control Model`.
    TelephoneControlModel,
    /// `OBEX Service Identifier`.
    ObexServiceIdentifier,
    /// `NCM` — NCM 1.0 §5.2.2.2.
    Ncm,
    /// `MBIM` — MBIM 1.0 §6.4.
    Mbim,
    /// `MBIM Extended` — MBIM 1.0 §6.5.
    MbimExtended,
    /// Subtype the parser doesn't recognise. Carries the raw byte.
    Unknown(u8),
}

impl FunctionalSubtype {
    pub fn decode(b: u8) -> Self {
        match b {
            0x00 => FunctionalSubtype::Header,
            0x01 => FunctionalSubtype::CallManagement,
            0x02 => FunctionalSubtype::Acm,
            0x03 => FunctionalSubtype::DirectLine,
            0x04 => FunctionalSubtype::TelephoneRinger,
            0x05 => FunctionalSubtype::TelephoneCallStateReporting,
            0x06 => FunctionalSubtype::Union,
            0x07 => FunctionalSubtype::CountrySelection,
            0x08 => FunctionalSubtype::TelephoneOperationalModes,
            0x09 => FunctionalSubtype::UsbTerminal,
            0x0A => FunctionalSubtype::NetworkChannelTerminal,
            0x0B => FunctionalSubtype::ProtocolUnit,
            0x0C => FunctionalSubtype::ExtensionUnit,
            0x0D => FunctionalSubtype::MultiChannelManagement,
            0x0E => FunctionalSubtype::CapiControlManagement,
            0x0F => FunctionalSubtype::EthernetNetworking,
            0x10 => FunctionalSubtype::AtmNetworking,
            0x11 => FunctionalSubtype::WirelessHandsetControlModel,
            0x12 => FunctionalSubtype::MobileDirectLineModel,
            0x13 => FunctionalSubtype::MdlmDetail,
            0x14 => FunctionalSubtype::DeviceManagementModel,
            0x15 => FunctionalSubtype::Obex,
            0x16 => FunctionalSubtype::CommandSet,
            0x17 => FunctionalSubtype::CommandSetDetail,
            0x18 => FunctionalSubtype::TelephoneControlModel,
            0x19 => FunctionalSubtype::ObexServiceIdentifier,
            0x1A => FunctionalSubtype::Ncm,
            0x1B => FunctionalSubtype::Mbim,
            0x1C => FunctionalSubtype::MbimExtended,
            other => FunctionalSubtype::Unknown(other),
        }
    }

    /// Wire-byte representation. Inverse of [`decode`].
    pub fn to_byte(self) -> u8 {
        match self {
            FunctionalSubtype::Header => 0x00,
            FunctionalSubtype::CallManagement => 0x01,
            FunctionalSubtype::Acm => 0x02,
            FunctionalSubtype::DirectLine => 0x03,
            FunctionalSubtype::TelephoneRinger => 0x04,
            FunctionalSubtype::TelephoneCallStateReporting => 0x05,
            FunctionalSubtype::Union => 0x06,
            FunctionalSubtype::CountrySelection => 0x07,
            FunctionalSubtype::TelephoneOperationalModes => 0x08,
            FunctionalSubtype::UsbTerminal => 0x09,
            FunctionalSubtype::NetworkChannelTerminal => 0x0A,
            FunctionalSubtype::ProtocolUnit => 0x0B,
            FunctionalSubtype::ExtensionUnit => 0x0C,
            FunctionalSubtype::MultiChannelManagement => 0x0D,
            FunctionalSubtype::CapiControlManagement => 0x0E,
            FunctionalSubtype::EthernetNetworking => 0x0F,
            FunctionalSubtype::AtmNetworking => 0x10,
            FunctionalSubtype::WirelessHandsetControlModel => 0x11,
            FunctionalSubtype::MobileDirectLineModel => 0x12,
            FunctionalSubtype::MdlmDetail => 0x13,
            FunctionalSubtype::DeviceManagementModel => 0x14,
            FunctionalSubtype::Obex => 0x15,
            FunctionalSubtype::CommandSet => 0x16,
            FunctionalSubtype::CommandSetDetail => 0x17,
            FunctionalSubtype::TelephoneControlModel => 0x18,
            FunctionalSubtype::ObexServiceIdentifier => 0x19,
            FunctionalSubtype::Ncm => 0x1A,
            FunctionalSubtype::Mbim => 0x1B,
            FunctionalSubtype::MbimExtended => 0x1C,
            FunctionalSubtype::Unknown(b) => b,
        }
    }
}

// ── Errors ───────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CdcError {
    /// Buffer too short to even read `bLength`.
    Short,
    /// `bLength` larger than the supplied buffer.
    Truncated,
    /// `bDescriptorType` isn't `CS_INTERFACE` (0x24).
    NotClassSpecific,
    /// Subtype byte isn't the one this decoder expected.
    BadSubtype(u8),
    /// Field-specific malformation (e.g. version BCD out of range).
    MalformedField,
}

// ── Header functional descriptor (CDC 1.2 §5.2.3.1) ──────────────

/// CDC `Header` functional descriptor.
///
/// ```text
///   u8  bFunctionLength       (5)
///   u8  bDescriptorType       (0x24 CS_INTERFACE)
///   u8  bDescriptorSubtype    (0x00 Header)
///   u16 bcdCDC                (BCD release; 0x0120 = CDC 1.2)
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HeaderDescriptor {
    pub bcd_cdc: u16,
}

impl HeaderDescriptor {
    pub fn parse(buf: &[u8]) -> Result<Self, CdcError> {
        check_class_specific(buf, FunctionalSubtype::Header.to_byte())?;
        if (buf[0] as usize) < 5 || buf.len() < 5 {
            return Err(CdcError::Truncated);
        }
        let bcd_cdc = u16::from_le_bytes([buf[3], buf[4]]);
        Ok(Self { bcd_cdc })
    }
}

// ── Union functional descriptor (CDC 1.2 §5.2.3.2) ───────────────

/// CDC `Union` functional descriptor — groups one CDC-Comm
/// "control" interface with one or more CDC-Data "subordinate"
/// interfaces.
///
/// ```text
///   u8 bFunctionLength
///   u8 bDescriptorType        (0x24 CS_INTERFACE)
///   u8 bDescriptorSubtype     (0x06 Union)
///   u8 bControlInterface
///   u8 bSubordinateInterface0
///   ... up to bFunctionLength
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnionDescriptor {
    pub control_interface: u8,
    pub subordinate_interfaces: alloc::vec::Vec<u8>,
}

impl UnionDescriptor {
    pub fn parse(buf: &[u8]) -> Result<Self, CdcError> {
        check_class_specific(buf, FunctionalSubtype::Union.to_byte())?;
        if (buf[0] as usize) < 4 || buf.len() < 4 {
            return Err(CdcError::Truncated);
        }
        let length = buf[0] as usize;
        let control_interface = buf[3];
        let mut subordinate_interfaces = alloc::vec::Vec::with_capacity(length.saturating_sub(4));
        for &b in &buf[4..length] {
            subordinate_interfaces.push(b);
        }
        Ok(Self {
            control_interface,
            subordinate_interfaces,
        })
    }
}

// ── Borrow-iterator over CS_INTERFACE blocks ─────────────────────

/// Iterate the class-specific functional descriptors in
/// `interface_payload`. The argument is the raw byte slice from
/// the standard interface descriptor's tail (i.e. the bytes
/// between `bInterfaceDescriptor` and the first endpoint
/// descriptor).
///
/// Yields `(subtype, slice)` for each well-formed CS_INTERFACE
/// block. Stops on the first malformed block.
pub fn iter_functional_descriptors(
    interface_payload: &[u8],
) -> impl Iterator<Item = (FunctionalSubtype, &[u8])> {
    FunctionalIter {
        rest: interface_payload,
    }
}

struct FunctionalIter<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for FunctionalIter<'a> {
    type Item = (FunctionalSubtype, &'a [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.rest.len() < 3 {
                return None;
            }
            let length = self.rest[0] as usize;
            if length < 3 || length > self.rest.len() {
                return None;
            }
            let dtype = self.rest[1];
            let chunk = &self.rest[..length];
            self.rest = &self.rest[length..];
            if dtype != CS_INTERFACE {
                // Non-class-specific descriptor — skip it but
                // keep iterating. Endpoint / interface descriptors
                // intermixed are common.
                continue;
            }
            let sub = FunctionalSubtype::decode(chunk[2]);
            return Some((sub, chunk));
        }
    }
}

// ── Internal helper ──────────────────────────────────────────────

pub(crate) fn check_class_specific(buf: &[u8], expect_subtype: u8) -> Result<(), CdcError> {
    if buf.len() < 3 {
        return Err(CdcError::Short);
    }
    let length = buf[0] as usize;
    if length < 3 || length > buf.len() {
        return Err(CdcError::Truncated);
    }
    if buf[1] != CS_INTERFACE {
        return Err(CdcError::NotClassSpecific);
    }
    if buf[2] != expect_subtype {
        return Err(CdcError::BadSubtype(buf[2]));
    }
    Ok(())
}

impl TryFrom<u8> for FunctionalSubtype {
    type Error = ();
    fn try_from(b: u8) -> Result<Self, Self::Error> {
        Ok(FunctionalSubtype::decode(b))
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_header_round_trip() -> TestResult {
        // CDC 1.2 header descriptor: length=5, CS_INTERFACE (0x24),
        // subtype Header (0x00), bcdCDC = 0x0120 (CDC 1.2).
        let raw = [5u8, CS_INTERFACE, 0x00, 0x20, 0x01];
        let h = match HeaderDescriptor::parse(&raw) {
            Ok(h) => h,
            Err(_) => return TestResult::Fail("clean header rejected"),
        };
        if h.bcd_cdc != 0x0120 {
            return TestResult::Fail("bcdCDC mis-decoded");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc", smoke_header_round_trip);

    fn smoke_union_round_trip() -> TestResult {
        // Union { ctrl=0, sub0=1, sub1=2 } → length 6.
        let raw = [6u8, CS_INTERFACE, 0x06, 0, 1, 2];
        let u = match UnionDescriptor::parse(&raw) {
            Ok(u) => u,
            Err(_) => return TestResult::Fail("clean union rejected"),
        };
        if u.control_interface != 0 {
            return TestResult::Fail("control interface lost");
        }
        if u.subordinate_interfaces != alloc::vec![1, 2] {
            return TestResult::Fail("subordinates lost");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc", smoke_union_round_trip);

    fn smoke_iter_skips_non_cs_interface() -> TestResult {
        // A standard endpoint descriptor (length=7, type=0x05)
        // mixed in among two CS_INTERFACEs should be skipped.
        let mut buf = alloc::vec::Vec::new();
        buf.extend_from_slice(&[5u8, CS_INTERFACE, 0x00, 0x20, 0x01]); // header
        buf.extend_from_slice(&[7u8, 0x05, 0x81, 0x03, 0x08, 0x00, 0x10]); // endpoint
        buf.extend_from_slice(&[6u8, CS_INTERFACE, 0x06, 0, 1, 2]); // union
        let subtypes: alloc::vec::Vec<_> =
            iter_functional_descriptors(&buf).map(|(s, _)| s).collect();
        if subtypes != alloc::vec![FunctionalSubtype::Header, FunctionalSubtype::Union] {
            return TestResult::Fail("iter yielded wrong subtypes");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc", smoke_iter_skips_non_cs_interface);

    fn smoke_iter_stops_on_truncation() -> TestResult {
        // Length=20 but only 5 bytes supplied.
        let buf = [20u8, CS_INTERFACE, 0x00, 0x20, 0x01];
        let n = iter_functional_descriptors(&buf).count();
        if n != 0 {
            return TestResult::Fail("truncated descriptor must terminate iter");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc", smoke_iter_stops_on_truncation);

    fn smoke_subtype_round_trip() -> TestResult {
        if FunctionalSubtype::decode(0x00) != FunctionalSubtype::Header {
            return TestResult::Fail("header subtype");
        }
        if FunctionalSubtype::decode(0x02) != FunctionalSubtype::Acm {
            return TestResult::Fail("acm subtype");
        }
        if FunctionalSubtype::decode(0x1A) != FunctionalSubtype::Ncm {
            return TestResult::Fail("ncm subtype");
        }
        if FunctionalSubtype::decode(0xFE) != FunctionalSubtype::Unknown(0xFE) {
            return TestResult::Fail("unknown subtype must preserve raw");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc", smoke_subtype_round_trip);
}
