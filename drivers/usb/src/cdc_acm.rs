//! USB CDC Abstract Control Model (ACM) — clean-room.
//!
//! References (public-only):
//! - **USB CDC Subclass Specification for PSTN Devices, Revision
//!   1.2** (USB-IF, February 2007). Public, usb.org. §3.6.2.1
//!   (ACM Functional Descriptor + bmCapabilities), §6.3.10
//!   (`SET_LINE_CODING`), §6.3.11 (`GET_LINE_CODING`), §6.3.12
//!   (`SET_CONTROL_LINE_STATE`), §6.5.4 (`SerialState`
//!   notification).
//!   <https://www.usb.org/document-library/class-definitions-communication-devices-12>
//! - **USB Specification 2.0** §9.3 (USB device requests; SETUP
//!   packet layout). Public.
//!
//! No GPL Linux source consulted.
//!
//! ## Why ACM
//!
//! ACM is the modern USB serial profile — every USB-to-UART dock,
//! USB CDC console (FX2-based dev boards, modern microcontrollers
//! like RP2040 / STM32 in CDC mode), and modem speaks ACM. The
//! host driver:
//!
//! 1. Walks the descriptors, finds an interface with class/subclass
//!    (CDC-Comm 0x02, ACM 0x02), parses its ACM Functional
//!    Descriptor + Union to learn which Data interface to bind.
//! 2. Programs the data path with `SET_LINE_CODING` (baud /
//!    parity / data bits / stop bits) + `SET_CONTROL_LINE_STATE`
//!    (DTR / RTS).
//! 3. Sends/receives bytes over the bound CDC-Data bulk IN/OUT.
//! 4. Watches the notification IN endpoint for `SerialState`
//!    events (carrier detect, DSR, parity-error, etc.).
//!
//! Stage-2 ships the **codec layer** — descriptor parser + setup-
//! packet builders + notification decoder. The actual xHCI
//! transfer-ring scheduling lives in the per-controller driver.

use core::convert::TryFrom;

use super::cdc::{check_class_specific, CdcError, FunctionalSubtype};

// ── CDC-ACM class-specific request codes (PSTN 1.2 §6.3) ─────────

pub const REQ_SEND_ENCAPSULATED_COMMAND: u8 = 0x00;
pub const REQ_GET_ENCAPSULATED_RESPONSE: u8 = 0x01;
pub const REQ_SET_COMM_FEATURE: u8 = 0x02;
pub const REQ_GET_COMM_FEATURE: u8 = 0x03;
pub const REQ_CLEAR_COMM_FEATURE: u8 = 0x04;
pub const REQ_SET_LINE_CODING: u8 = 0x20;
pub const REQ_GET_LINE_CODING: u8 = 0x21;
pub const REQ_SET_CONTROL_LINE_STATE: u8 = 0x22;
pub const REQ_SEND_BREAK: u8 = 0x23;

// ── CDC-ACM notification codes (PSTN 1.2 §6.5) ───────────────────

pub const NOTIFICATION_NETWORK_CONNECTION: u8 = 0x00;
pub const NOTIFICATION_RESPONSE_AVAILABLE: u8 = 0x01;
pub const NOTIFICATION_SERIAL_STATE: u8 = 0x20;

// ── ACM Functional Descriptor (PSTN 1.2 §3.6.2.1) ────────────────

/// `bmCapabilities` bit definitions in the ACM functional
/// descriptor.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AcmCapabilities {
    /// Device supports `SET_COMM_FEATURE` / `CLEAR_COMM_FEATURE`.
    pub comm_feature: bool,
    /// Device supports `SET_LINE_CODING` / `GET_LINE_CODING` /
    /// `SET_CONTROL_LINE_STATE` + the SerialState notification.
    pub line_coding_state: bool,
    /// Device supports `SEND_BREAK`.
    pub send_break: bool,
    /// Device supports the network-connection notification.
    pub network_connection: bool,
}

impl AcmCapabilities {
    pub fn decode(byte: u8) -> Self {
        Self {
            comm_feature: byte & 0x01 != 0,
            line_coding_state: byte & 0x02 != 0,
            send_break: byte & 0x04 != 0,
            network_connection: byte & 0x08 != 0,
        }
    }
}

/// Parsed ACM functional descriptor.
///
/// ```text
///   u8 bFunctionLength       (4)
///   u8 bDescriptorType       (0x24 CS_INTERFACE)
///   u8 bDescriptorSubtype    (0x02 ACM)
///   u8 bmCapabilities
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AcmDescriptor {
    pub capabilities: AcmCapabilities,
}

impl AcmDescriptor {
    pub fn parse(buf: &[u8]) -> Result<Self, CdcError> {
        check_class_specific(buf, FunctionalSubtype::Acm.to_byte())?;
        if (buf[0] as usize) < 4 || buf.len() < 4 {
            return Err(CdcError::Truncated);
        }
        Ok(Self {
            capabilities: AcmCapabilities::decode(buf[3]),
        })
    }
}

// ── Line coding (PSTN 1.2 §6.3.10 / Table 17) ────────────────────

/// Stop-bit count.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum StopBits {
    /// 1 stop bit.
    One = 0,
    /// 1.5 stop bits.
    OnePointFive = 1,
    /// 2 stop bits.
    Two = 2,
}

/// Parity setting.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Parity {
    None = 0,
    Odd = 1,
    Even = 2,
    Mark = 3,
    Space = 4,
}

/// `LineCoding` payload — the 7-byte data structure exchanged
/// with `SET_LINE_CODING` / `GET_LINE_CODING`.
///
/// ```text
///   u32 dwDTERate           (bits per second)
///   u8  bCharFormat         (StopBits)
///   u8  bParityType         (Parity)
///   u8  bDataBits           (5, 6, 7, 8, or 16)
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LineCoding {
    pub baud_rate: u32,
    pub stop_bits: StopBits,
    pub parity: Parity,
    pub data_bits: u8,
}

impl LineCoding {
    /// 115200 8-N-1 — the common dev-board default.
    pub const N_115200_8N1: Self = Self {
        baud_rate: 115_200,
        stop_bits: StopBits::One,
        parity: Parity::None,
        data_bits: 8,
    };
    /// 9600 8-N-1 — the historical default for serial consoles.
    pub const N_9600_8N1: Self = Self {
        baud_rate: 9_600,
        stop_bits: StopBits::One,
        parity: Parity::None,
        data_bits: 8,
    };

    pub fn encode(&self) -> [u8; 7] {
        [
            self.baud_rate as u8,
            (self.baud_rate >> 8) as u8,
            (self.baud_rate >> 16) as u8,
            (self.baud_rate >> 24) as u8,
            self.stop_bits as u8,
            self.parity as u8,
            self.data_bits,
        ]
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CdcError> {
        if bytes.len() < 7 {
            return Err(CdcError::Truncated);
        }
        let baud = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let stop = match bytes[4] {
            0 => StopBits::One,
            1 => StopBits::OnePointFive,
            2 => StopBits::Two,
            _ => return Err(CdcError::MalformedField),
        };
        let parity = match bytes[5] {
            0 => Parity::None,
            1 => Parity::Odd,
            2 => Parity::Even,
            3 => Parity::Mark,
            4 => Parity::Space,
            _ => return Err(CdcError::MalformedField),
        };
        let data = bytes[6];
        if !matches!(data, 5 | 6 | 7 | 8 | 16) {
            return Err(CdcError::MalformedField);
        }
        Ok(Self {
            baud_rate: baud,
            stop_bits: stop,
            parity,
            data_bits: data,
        })
    }
}

// ── Control line state (PSTN 1.2 §6.3.12) ────────────────────────

/// Bit 0 of `wValue` for `SET_CONTROL_LINE_STATE` — DTR.
pub const CTRL_DTR: u16 = 1 << 0;
/// Bit 1 — RTS.
pub const CTRL_RTS: u16 = 1 << 1;

// ── SETUP-packet builders ────────────────────────────────────────

/// USB setup packet — 8 bytes per USB 2.0 §9.3.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SetupPacket {
    pub bm_request_type: u8,
    pub b_request: u8,
    pub w_value: u16,
    pub w_index: u16,
    pub w_length: u16,
}

impl SetupPacket {
    pub fn encode(&self) -> [u8; 8] {
        [
            self.bm_request_type,
            self.b_request,
            self.w_value as u8,
            (self.w_value >> 8) as u8,
            self.w_index as u8,
            (self.w_index >> 8) as u8,
            self.w_length as u8,
            (self.w_length >> 8) as u8,
        ]
    }
}

/// `bmRequestType = Class | Interface | Out` — class-specific
/// SET request directed at an interface.
const RT_CLASS_INTERFACE_OUT: u8 = 0x21;
/// `bmRequestType = Class | Interface | In` — class-specific GET.
const RT_CLASS_INTERFACE_IN: u8 = 0xA1;

/// Build the SETUP packet for `SET_LINE_CODING` directed at the
/// CDC-Comm interface number `iface`. The 7-byte data-stage
/// payload is `LineCoding::encode()`.
pub fn build_set_line_coding(iface: u8) -> SetupPacket {
    SetupPacket {
        bm_request_type: RT_CLASS_INTERFACE_OUT,
        b_request: REQ_SET_LINE_CODING,
        w_value: 0,
        w_index: iface as u16,
        w_length: 7,
    }
}

/// Build the SETUP packet for `GET_LINE_CODING`.
pub fn build_get_line_coding(iface: u8) -> SetupPacket {
    SetupPacket {
        bm_request_type: RT_CLASS_INTERFACE_IN,
        b_request: REQ_GET_LINE_CODING,
        w_value: 0,
        w_index: iface as u16,
        w_length: 7,
    }
}

/// Build the SETUP packet for `SET_CONTROL_LINE_STATE`.
/// `state` is a bitmask of [`CTRL_DTR`] / [`CTRL_RTS`].
pub fn build_set_control_line_state(iface: u8, state: u16) -> SetupPacket {
    SetupPacket {
        bm_request_type: RT_CLASS_INTERFACE_OUT,
        b_request: REQ_SET_CONTROL_LINE_STATE,
        w_value: state,
        w_index: iface as u16,
        w_length: 0,
    }
}

/// Build the SETUP packet for `SEND_BREAK`. `duration_ms` is the
/// requested break duration in milliseconds; `0xFFFF` means
/// "send break until next request"; `0` means "stop break".
pub fn build_send_break(iface: u8, duration_ms: u16) -> SetupPacket {
    SetupPacket {
        bm_request_type: RT_CLASS_INTERFACE_OUT,
        b_request: REQ_SEND_BREAK,
        w_value: duration_ms,
        w_index: iface as u16,
        w_length: 0,
    }
}

// ── SerialState notification (PSTN 1.2 §6.5.4) ───────────────────

/// SerialState bits — 16-bit payload of the notification.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct SerialState {
    /// `bRxCarrier` — DCD asserted.
    pub rx_carrier: bool,
    /// `bTxCarrier` — DSR asserted.
    pub tx_carrier: bool,
    /// `bBreak` — break received.
    pub break_received: bool,
    /// `bRingSignal` — RI asserted.
    pub ring_signal: bool,
    /// `bFraming` — framing error.
    pub framing_error: bool,
    /// `bParity` — parity error.
    pub parity_error: bool,
    /// `bOverRun` — receiver overrun.
    pub overrun: bool,
}

impl SerialState {
    pub fn decode(payload_lo: u8) -> Self {
        Self {
            rx_carrier: payload_lo & 0x01 != 0,
            tx_carrier: payload_lo & 0x02 != 0,
            break_received: payload_lo & 0x04 != 0,
            ring_signal: payload_lo & 0x08 != 0,
            framing_error: payload_lo & 0x10 != 0,
            parity_error: payload_lo & 0x20 != 0,
            overrun: payload_lo & 0x40 != 0,
        }
    }
}

/// Decoded notification packet from the CDC-Comm notification IN
/// endpoint. The wire format is exactly the 8-byte SETUP packet
/// header followed by `wLength` data bytes; the device acts as
/// "host" on this pipe.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Notification {
    /// `NETWORK_CONNECTION` — `wValue` bit 0 set ↔ link up.
    NetworkConnection { up: bool },
    /// `RESPONSE_AVAILABLE`.
    ResponseAvailable,
    /// `SERIAL_STATE` — 2-byte payload.
    SerialState(SerialState),
    /// Notification code the parser doesn't decode further.
    Unknown { code: u8, value: u16, index: u16 },
}

impl Notification {
    pub fn decode(packet: &[u8]) -> Result<Self, CdcError> {
        if packet.len() < 8 {
            return Err(CdcError::Short);
        }
        let bm_rt = packet[0];
        let _ = bm_rt; // unused after type filter; could enforce 0xA1.
        let code = packet[1];
        let value = u16::from_le_bytes([packet[2], packet[3]]);
        let index = u16::from_le_bytes([packet[4], packet[5]]);
        let length = u16::from_le_bytes([packet[6], packet[7]]) as usize;
        if packet.len() < 8 + length {
            return Err(CdcError::Truncated);
        }
        Ok(match code {
            NOTIFICATION_NETWORK_CONNECTION => Notification::NetworkConnection {
                up: value & 1 != 0,
            },
            NOTIFICATION_RESPONSE_AVAILABLE => Notification::ResponseAvailable,
            NOTIFICATION_SERIAL_STATE => {
                if length < 2 {
                    return Err(CdcError::Truncated);
                }
                Notification::SerialState(SerialState::decode(packet[8]))
            }
            other => Notification::Unknown {
                code: other,
                value,
                index,
            },
        })
    }
}

impl TryFrom<u8> for StopBits {
    type Error = CdcError;
    fn try_from(b: u8) -> Result<Self, Self::Error> {
        Ok(match b {
            0 => StopBits::One,
            1 => StopBits::OnePointFive,
            2 => StopBits::Two,
            _ => return Err(CdcError::MalformedField),
        })
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_acm_descriptor_caps() -> TestResult {
        let raw = [4u8, CS_INTERFACE, 0x02, 0x06]; // line_coding_state + send_break
        let d = match AcmDescriptor::parse(&raw) {
            Ok(d) => d,
            Err(_) => return TestResult::Fail("clean ACM desc rejected"),
        };
        if !d.capabilities.line_coding_state || !d.capabilities.send_break {
            return TestResult::Fail("capability bits lost");
        }
        if d.capabilities.comm_feature || d.capabilities.network_connection {
            return TestResult::Fail("capability bits over-set");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_acm", smoke_acm_descriptor_caps);

    fn smoke_line_coding_round_trip() -> TestResult {
        let coding = LineCoding::N_115200_8N1;
        let bytes = coding.encode();
        let back = match LineCoding::decode(&bytes) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("self-built line coding rejected"),
        };
        if back != coding {
            return TestResult::Fail("line coding round-trip");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_acm", smoke_line_coding_round_trip);

    fn smoke_line_coding_rejects_bad_data_bits() -> TestResult {
        let bytes = [0x00, 0xC2, 0x01, 0x00, 0, 0, 9]; // 9 data bits invalid
        match LineCoding::decode(&bytes) {
            Err(CdcError::MalformedField) => TestResult::Pass,
            _ => TestResult::Fail("9 data bits must be rejected"),
        }
    }
    kernel_test_in!(
        "drivers/usb/cdc_acm",
        smoke_line_coding_rejects_bad_data_bits
    );

    fn smoke_set_line_coding_setup_layout() -> TestResult {
        let s = build_set_line_coding(2);
        let bytes = s.encode();
        if bytes[0] != 0x21 {
            return TestResult::Fail("bmRequestType wrong");
        }
        if bytes[1] != REQ_SET_LINE_CODING {
            return TestResult::Fail("bRequest wrong");
        }
        if u16::from_le_bytes([bytes[4], bytes[5]]) != 2 {
            return TestResult::Fail("wIndex (interface) wrong");
        }
        if u16::from_le_bytes([bytes[6], bytes[7]]) != 7 {
            return TestResult::Fail("wLength must be 7");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/cdc_acm",
        smoke_set_line_coding_setup_layout
    );

    fn smoke_control_line_state_setup() -> TestResult {
        let s = build_set_control_line_state(0, CTRL_DTR | CTRL_RTS);
        let bytes = s.encode();
        if u16::from_le_bytes([bytes[2], bytes[3]]) != (CTRL_DTR | CTRL_RTS) {
            return TestResult::Fail("wValue lost DTR|RTS");
        }
        if u16::from_le_bytes([bytes[6], bytes[7]]) != 0 {
            return TestResult::Fail("wLength should be 0");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_acm", smoke_control_line_state_setup);

    fn smoke_serial_state_notification() -> TestResult {
        // 8-byte header: bmRequestType=0xA1, code=0x20, value=0,
        // index=0, length=2. Payload byte 0 = 0x03 (DCD + DSR).
        let pkt = [0xA1, 0x20, 0, 0, 0, 0, 2, 0, 0x03, 0];
        let n = match Notification::decode(&pkt) {
            Ok(n) => n,
            Err(_) => return TestResult::Fail("clean notification rejected"),
        };
        match n {
            Notification::SerialState(s) => {
                if !s.rx_carrier || !s.tx_carrier {
                    return TestResult::Fail("DCD/DSR lost in decode");
                }
            }
            _ => return TestResult::Fail("not classified as SerialState"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_acm", smoke_serial_state_notification);

    fn smoke_network_connection_notification() -> TestResult {
        // value=1 → link up.
        let pkt = [0xA1, 0x00, 1, 0, 0, 0, 0, 0];
        match Notification::decode(&pkt) {
            Ok(Notification::NetworkConnection { up: true }) => TestResult::Pass,
            _ => TestResult::Fail("link-up notification not classified"),
        }
    }
    kernel_test_in!(
        "drivers/usb/cdc_acm",
        smoke_network_connection_notification
    );
}
