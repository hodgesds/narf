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

// ── Live driver: discovery + bind + bulk-IN pump ──────────────────

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

use crate::cdc::{USB_CLASS_CDC_COMM, USB_CLASS_CDC_DATA, CDC_SUBCLASS_ACM};
use crate::xhci::{EndpointConfig, EndpointKind, PortSpeed, Xhci, XhciError};

/// `bmRequestType` for ACM class requests (Host-to-Device, Class,
/// Interface recipient — USB 2.0 §9.3).
pub const RT_HOST_TO_DEV_CLASS_IFACE: u8 = 0x21;

/// One bound CDC-ACM device. Held in the global [`ACM_DEVICES`]
/// registry; the supervisor drains its bulk-IN endpoint each cycle
/// and pushes received bytes onto `narf_input`'s AsciiByte ring so
/// `/dev/console` reads them just like UART input.
#[derive(Debug)]
pub struct AcmDevice {
    pub slot_id: u8,
    /// Data interface number (USB 2.0 §9.3 — needed for class
    /// requests + SET_INTERFACE).
    pub data_iface: u8,
    /// Comm interface number — used for SET_LINE_CODING /
    /// SET_CONTROL_LINE_STATE class requests (recipient = Interface).
    pub comm_iface: u8,
    /// DCI of the bulk-IN endpoint (incoming bytes from device).
    pub bulk_in_dci: u8,
    /// DCI of the bulk-OUT endpoint (host-to-device bytes).
    pub bulk_out_dci: u8,
    /// Cached negotiated line coding for diagnostics + GET retries.
    pub line_coding: LineCoding,
}

/// Global registry of bound CDC-ACM devices. Populated by
/// [`try_bind_acm_already_addressed`]; drained by [`pump_all`].
static ACM_DEVICES: IrqSafeSpinLock<Vec<Arc<AcmDevice>>> =
    IrqSafeSpinLock::new(Vec::new());

/// Walk a configuration descriptor looking for a CDC-ACM Comm +
/// Data interface pair. Returns:
///   `(comm_iface, data_iface, bulk_in_ep, bulk_out_ep)`
///
/// Topology (CDC PSTN §3.6 + USB 2.0 §9.6.5):
///   - Interface descriptor with class=0x02 (Comm) subclass=0x02
///     (ACM) — that's the Comm interface; usually carries one
///     interrupt-IN notification endpoint.
///   - Interface descriptor with class=0x0A (Data) — that's the
///     Data interface; carries the bulk-IN + bulk-OUT pair we
///     drain for terminal bytes.
pub fn find_acm_interfaces(
    cfg: &[u8],
) -> Option<(u8, u8, EndpointConfig, EndpointConfig)> {
    let mut i = 0usize;
    let mut comm_iface: Option<u8> = None;
    let mut data_iface: Option<u8> = None;
    let mut bulk_in: Option<EndpointConfig> = None;
    let mut bulk_out: Option<EndpointConfig> = None;
    let mut current_class: u8 = 0;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        let dtype = cfg[i + 1];
        match dtype {
            // Interface Descriptor (USB 2.0 §9.6.5).
            4 if len >= 9 => {
                let cls = cfg[i + 5];
                let sub = cfg[i + 6];
                current_class = cls;
                if cls == USB_CLASS_CDC_COMM && sub == CDC_SUBCLASS_ACM {
                    comm_iface = Some(cfg[i + 2]);
                } else if cls == USB_CLASS_CDC_DATA {
                    data_iface = Some(cfg[i + 2]);
                }
            }
            // Endpoint Descriptor (USB 2.0 §9.6.6). Only the bulk
            // pair on the Data interface matters for the terminal
            // pipeline; the Comm interface's interrupt-IN
            // notification endpoint we ignore for now.
            5 if len >= 7 && current_class == USB_CLASS_CDC_DATA => {
                let ep_addr = cfg[i + 2];
                let attr = cfg[i + 3];
                let mps = u16::from_le_bytes([cfg[i + 4], cfg[i + 5]]);
                let xfer_t = attr & 0x03;
                if xfer_t == 2 {
                    // Bulk
                    let cfg = EndpointConfig {
                        ep_addr,
                        max_packet: mps,
                        kind: if ep_addr & 0x80 != 0 {
                            EndpointKind::BulkIn
                        } else {
                            EndpointKind::BulkOut
                        },
                    };
                    if ep_addr & 0x80 != 0 && bulk_in.is_none() {
                        bulk_in = Some(cfg);
                    } else if ep_addr & 0x80 == 0 && bulk_out.is_none() {
                        bulk_out = Some(cfg);
                    }
                }
            }
            _ => {}
        }
        i += len;
    }
    Some((comm_iface?, data_iface?, bulk_in?, bulk_out?))
}

/// Post-address ACM bind: caller has already issued port_reset +
/// enable_slot + address_device. We pull the config descriptor,
/// match the Comm + Data interface pair, configure the bulk
/// endpoints, then issue `SET_CONFIGURATION` →
/// `SET_LINE_CODING(115200 8N1)` →
/// `SET_CONTROL_LINE_STATE(DTR | RTS)` so the device knows the host
/// is ready to receive bytes. Failure on any step returns Err and
/// the caller's cleanup_guard frees the slot.
pub async fn try_bind_acm_already_addressed(
    xhci_dev: &Xhci,
    slot_id: u8,
    cfg: &[u8],
    speed: PortSpeed,
) -> Result<(), CdcError> {
    let _ = speed; // reserved for future MaxPacketSize-aware setup
    let (comm_iface, data_iface, bulk_in, bulk_out) =
        find_acm_interfaces(cfg).ok_or(CdcError::Truncated)?;

    // Configure xHC-side endpoint contexts for the bulk pair.
    xhci_dev
        .configure_endpoints(slot_id, &[bulk_in, bulk_out])
        .await
        .map_err(|_| CdcError::Truncated)?;

    // SET_CONFIGURATION before any class request (USB 2.0 §9.4.7).
    if cfg.len() < 9 || cfg[1] != 2 {
        return Err(CdcError::Truncated);
    }
    let cfg_value = cfg[5];
    let mut nothing = [0u8; 0];
    xhci_dev
        .control_in(
            slot_id,
            0x00,
            crate::hid::STD_REQ_SET_CONFIGURATION,
            cfg_value as u16,
            0,
            &mut nothing,
        )
        .await
        .map_err(|_| CdcError::Truncated)?;

    // SET_LINE_CODING(115200 8N1) — the dev-board default. PSTN 1.2
    // §6.3.10. Failure here is non-fatal for some chips that ignore
    // line coding (Arduino-style sketches just sample any baud).
    let coding = LineCoding::N_115200_8N1;
    let coding_bytes = coding.encode();
    let _ = xhci_dev.control_out(
        slot_id,
        RT_HOST_TO_DEV_CLASS_IFACE,
        REQ_SET_LINE_CODING,
        0,
        comm_iface as u16,
        &coding_bytes,
    ).await;

    // SET_CONTROL_LINE_STATE(DTR | RTS) — tells the device the host
    // is present + ready to receive (PSTN 1.2 §6.3.12). On many
    // USB-to-serial dongles this gates whether the chip drives RXD.
    let _ = xhci_dev.control_out(
        slot_id,
        RT_HOST_TO_DEV_CLASS_IFACE,
        REQ_SET_CONTROL_LINE_STATE,
        CTRL_DTR | CTRL_RTS,
        comm_iface as u16,
        &[],
    ).await;

    // Pre-arm the bulk-IN endpoint so the controller starts polling
    // the device for bytes. Same pattern as the persistent-arm
    // interrupt-IN we use for HID kbd / mouse.
    let bulk_in_ep = bulk_in.ep_addr & 0x0F;
    let bulk_in_dci = (bulk_in_ep * 2) + 1;
    let bulk_out_ep = bulk_out.ep_addr & 0x0F;
    let bulk_out_dci = bulk_out_ep * 2;
    xhci_dev
        .arm_interrupt_in(slot_id, bulk_in_dci, bulk_in.max_packet.min(64) as u32)
        .map_err(|_| CdcError::Truncated)?;

    let dev = Arc::new(AcmDevice {
        slot_id,
        data_iface,
        comm_iface,
        bulk_in_dci,
        bulk_out_dci,
        line_coding: coding,
    });
    {
        use core::fmt::Write as _;
        use core::sync::atomic::{AtomicU64, Ordering};
        static ATTACHED: AtomicU64 = AtomicU64::new(0);
        let bit = 1u64 << (slot_id as u32 & 63);
        let prev = ATTACHED.fetch_or(bit, Ordering::AcqRel);
        if prev & bit == 0 {
            let _ = writeln!(
                narf_console::Writer,
                "  cdc-acm: serial attached on slot {} ({} bps)",
                slot_id, coding.baud_rate
            );
        }
    }
    ACM_DEVICES.lock().push(dev);
    Ok(())
}

/// Drain one report from each bound ACM device's bulk-IN endpoint
/// and forward the bytes to the global input ring as
/// [`narf_input::InputEvent::AsciiByte`] events. `/dev/console` reads
/// pop these the same way it consumes UART input — so a USB serial
/// adaptor wired to a debug header becomes a kernel console source.
pub fn pump_all(xhci_dev: &Xhci) -> usize {
    let devs: Vec<Arc<AcmDevice>> = {
        let g = ACM_DEVICES.lock();
        g.clone()
    };
    let mut total = 0usize;
    for d in &devs {
        let mut buf = [0u8; 64];
        loop {
            match xhci_dev.poll_interrupt_in(d.slot_id, d.bulk_in_dci, &mut buf) {
                Ok(Some(n)) => {
                    for &b in &buf[..n.min(buf.len())] {
                        narf_input::push_global(narf_input::InputEvent::AsciiByte(b));
                        total += 1;
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
    }
    total
}

/// Send bytes to a bound ACM device's bulk-OUT endpoint. Returns
/// the number of bytes the controller acknowledged delivering.
/// First device only for now; multi-device routing follows when a
/// `/dev/ttyUSB0` namespace lands.
pub async fn send(xhci_dev: &Xhci, data: &[u8]) -> Result<usize, XhciError> {
    let devs: Vec<Arc<AcmDevice>> = {
        let g = ACM_DEVICES.lock();
        g.clone()
    };
    let dev = devs.first().ok_or(XhciError::CmdFailed(0xFC))?;
    xhci_dev.bulk_out(dev.slot_id, dev.bulk_out_dci, data).await
}

/// Number of bound ACM devices. Test + diagnostics helper.
pub fn attached_count() -> usize {
    ACM_DEVICES.lock().len()
}

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
    use crate::cdc::CS_INTERFACE;
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
