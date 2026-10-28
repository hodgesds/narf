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
//!   packet layout), §9.6.4 (Interface Association Descriptor).
//!   Public.
//! - **USB ECN: Interface Association Descriptor**, USB-IF, May
//!   2003. IAD `bDescriptorType = 0x0B`, 8-byte layout:
//!   bFirstInterface, bInterfaceCount, bFunctionClass,
//!   bFunctionSubClass, bFunctionProtocol, iFunction. Public.
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
//!    Composite devices present an Interface Association Descriptor
//!    (IAD, type 0x0B) before the Comm interface grouping the
//!    pair; the scanner accepts both IAD-led and bare interface
//!    layouts.
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

// ── Interface Association Descriptor (IAD) — USB ECN May 2003 ────

/// `bDescriptorType = 0x0B` — Interface Association Descriptor.
/// Appears before the first interface of a CDC function in
/// composite devices (e.g. `bDeviceClass = 0xEF, bDeviceProtocol
/// = 0x01`). 8-byte layout:
/// ```text
///   u8 bLength            (8)
///   u8 bDescriptorType    (0x0B)
///   u8 bFirstInterface
///   u8 bInterfaceCount
///   u8 bFunctionClass     (0x02 for CDC)
///   u8 bFunctionSubClass  (0x02 for ACM)
///   u8 bFunctionProtocol
///   u8 iFunction
/// ```
pub const USB_DT_INTERFACE_ASSOCIATION: u8 = 0x0B;

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
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use narf_lib::sync::IrqSafeSpinLock;

use crate::cdc::{CDC_SUBCLASS_ACM, USB_CLASS_CDC_COMM, USB_CLASS_CDC_DATA};
use crate::serial::port::{apply_plan, ControlTransport, ControlXfer};
use crate::xhci::{EndpointConfig, EndpointKind, PortSpeed, Xhci, XhciError};

/// `bmRequestType` for ACM class requests (Host-to-Device, Class,
/// Interface recipient — USB 2.0 §9.3).
pub const RT_HOST_TO_DEV_CLASS_IFACE: u8 = 0x21;

/// One bound CDC-ACM device. Held in the global [`ACM_DEVICES`]
/// registry; the supervisor drains its bulk-IN endpoint each cycle
/// and pushes received bytes onto `narf_input`'s AsciiByte ring so
/// `/dev/console` reads them just like UART input. The same bytes
/// also land in the device's `/dev/ttyACM<N>` RX ring, and the
/// pump drains that node's TX ring onto bulk-OUT and decodes
/// notification-endpoint reports into the node's modem state
/// (`cdc_acm_bridge`).
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
    /// DCI of the Comm interface's interrupt-IN notification
    /// endpoint (PSTN 1.2 §6.5), when the device carries one.
    /// Armed at bind; SerialState reports decoded from it drive
    /// the ttyACM modem state (#757).
    pub notify_dci: Option<u8>,
    /// ACM functional-descriptor capabilities the device declares
    /// (PSTN 1.2 §3.6.2.1); all-clear when it omits the
    /// descriptor. Gates `SEND_BREAK`.
    pub capabilities: AcmCapabilities,
    /// The `/dev/ttyACM<N>` index this device is published as
    /// (#753), assigned by the bind path's bridge registration.
    pub tty_index: Option<usize>,
    /// Live line coding: the bind default, updated by every
    /// successful `CdcAcmPort::set_line_coding`. This is the
    /// state the suspend/resume replay replays (#763), so it
    /// tracks actuations, not just the bind. Updated ONLY after
    /// a `SET_LINE_CODING` the device accepted, so the cache
    /// always describes the state the device is actually in (#759).
    pub line_coding: IrqSafeSpinLock<LineCoding>,
    /// Last control-line bitmask (`CTRL_DTR` / `CTRL_RTS`)
    /// successfully driven via `SET_CONTROL_LINE_STATE`;
    /// replayed with the line coding on resume (#763).
    pub control_lines: AtomicU16,
    /// (hub registry index, downstream port) this device sits
    /// behind, when bound through a hub — the wake target for
    /// runtime hub-port resume (#763, mirroring #840 for HID).
    /// `None` for root-hub devices.
    pub hub_port: Option<(usize, u8)>,
}

/// Global registry of bound CDC-ACM devices. Populated by
/// [`try_bind_acm_already_addressed`]; drained by [`pump_all`].
static ACM_DEVICES: IrqSafeSpinLock<Vec<Arc<AcmDevice>>> = IrqSafeSpinLock::new(Vec::new());

/// The result of scanning a configuration blob for a CDC-ACM
/// function: the Comm + Data interface pair, the bulk endpoints
/// that carry terminal bytes, the Comm interface's notification
/// endpoint (when present), and the capabilities the ACM
/// functional descriptor declares.
#[derive(Clone, Debug)]
pub struct AcmInterfaces {
    pub comm_iface: u8,
    pub data_iface: u8,
    pub bulk_in: EndpointConfig,
    pub bulk_out: EndpointConfig,
    /// Interrupt-IN notification endpoint on the Comm interface
    /// (PSTN 1.2 §6.5), when the device carries one.
    pub notify: Option<EndpointConfig>,
    /// ACM functional-descriptor capabilities (PSTN 1.2
    /// §3.6.2.1); all-clear when the device omits the descriptor.
    pub capabilities: AcmCapabilities,
}

/// Walk a configuration descriptor looking for a CDC-ACM Comm +
/// Data interface pair.
///
/// Topology (CDC PSTN §3.6 + USB 2.0 §9.6.5 + IAD ECN):
///   - Optional Interface Association Descriptor (type 0x0B)
///     grouping the function — present on composite devices
///     where `bDeviceClass=0xEF`. Recognised but not required;
///     the scanner accepts both IAD-led and bare interface layouts.
///   - Interface descriptor with class=0x02 (Comm) subclass=0x02
///     (ACM) — that's the Comm interface; carries the
///     class-specific functional descriptors and (usually) one
///     interrupt-IN notification endpoint.
///   - Interface descriptor with class=0x0A (Data) — that's the
///     Data interface; carries the bulk-IN + bulk-OUT pair we
///     drain for terminal bytes.
///
/// Pairing rule: when the Comm interface carries a Union
/// functional descriptor (CDC 1.2 §5.2.3.2) naming this Comm
/// interface as its control interface, the Union's subordinate
/// list governs — the Data interface is the first subordinate
/// that presents a bulk pair, and if no subordinate does, the
/// scan fails closed rather than binding some other function's
/// pair. Without a Union, the first Data interface with a bulk
/// pair wins (the historical class/position scan).
pub fn find_acm_interfaces(cfg: &[u8]) -> Option<AcmInterfaces> {
    use crate::cdc::{UnionDescriptor, CS_INTERFACE};

    let mut i = 0usize;
    let mut comm_iface: Option<u8> = None;
    let mut notify: Option<EndpointConfig> = None;
    let mut capabilities = AcmCapabilities::decode(0);
    let mut union_subordinates: Option<Vec<u8>> = None;
    // Completed Data-interface bulk pairs, in walk order:
    // (interface number, bulk-IN, bulk-OUT).
    let mut data_pairs: Vec<(u8, EndpointConfig, EndpointConfig)> = Vec::new();
    // The Data interface currently being walked, with its
    // partially-collected bulk pair.
    let mut cur_data: Option<(u8, Option<EndpointConfig>, Option<EndpointConfig>)> = None;
    let mut current_iface: Option<u8> = None;
    let mut current_class: u8 = 0;

    // Close out the Data interface being walked, if it completed
    // a bulk pair.
    macro_rules! finish_data {
        () => {
            if let Some((num, Some(bi), Some(bo))) = cur_data.take() {
                data_pairs.push((num, bi, bo));
            } else {
                cur_data = None;
            }
        };
    }

    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        let dtype = cfg[i + 1];
        match dtype {
            // Interface Association Descriptor (USB IAD ECN,
            // USB_DT_INTERFACE_ASSOCIATION = 0x0B). 8-byte layout:
            // bFirstInterface at +2, bInterfaceCount at +3,
            // bFunctionClass at +4, bFunctionSubClass at +5.
            // We recognise an IAD with FunctionClass=0x02
            // (CDC-Comm) + FunctionSubClass=0x02 (ACM) as
            // confirmation that an ACM function follows; the
            // subsequent interface descriptors will be parsed by
            // the cases below. IAD without class/subclass match
            // is silently skipped.
            USB_DT_INTERFACE_ASSOCIATION if len >= 8 => {
                let fc = cfg[i + 4];
                let fsc = cfg[i + 5];
                // If this IAD declares an ACM function, reset
                // any previously-accumulated partial state so
                // we bind to this function rather than a stale
                // partial match from earlier in the blob.
                if fc == USB_CLASS_CDC_COMM && fsc == CDC_SUBCLASS_ACM {
                    finish_data!();
                    comm_iface = None;
                    notify = None;
                    capabilities = AcmCapabilities::decode(0);
                    union_subordinates = None;
                    data_pairs.clear();
                    current_iface = None;
                    current_class = 0;
                }
            }
            // Interface Descriptor (USB 2.0 §9.6.5).
            4 if len >= 9 => {
                finish_data!();
                let num = cfg[i + 2];
                let cls = cfg[i + 5];
                let sub = cfg[i + 6];
                current_iface = Some(num);
                current_class = cls;
                if cls == USB_CLASS_CDC_COMM && sub == CDC_SUBCLASS_ACM {
                    if comm_iface.is_none() {
                        comm_iface = Some(num);
                    }
                } else if cls == USB_CLASS_CDC_DATA {
                    cur_data = Some((num, None, None));
                }
            }
            // Class-specific functional descriptor (CDC 1.2
            // §5.2.3) attached to the Comm interface: the ACM
            // descriptor declares capabilities; the Union
            // descriptor names the Data interface(s) this Comm
            // interface controls.
            CS_INTERFACE if len >= 3 => {
                if current_iface == comm_iface && comm_iface.is_some() {
                    match cfg[i + 2] {
                        subtype if subtype == FunctionalSubtype::Acm.to_byte() => {
                            if let Ok(d) = AcmDescriptor::parse(&cfg[i..i + len]) {
                                capabilities = d.capabilities;
                            }
                        }
                        subtype if subtype == FunctionalSubtype::Union.to_byte() => {
                            if let Ok(u) = UnionDescriptor::parse(&cfg[i..i + len]) {
                                if Some(u.control_interface) == comm_iface {
                                    union_subordinates = Some(u.subordinate_interfaces);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            // Endpoint Descriptor (USB 2.0 §9.6.6). On the Data
            // interface only the bulk pair matters for the
            // terminal pipeline; on the Comm interface the
            // interrupt-IN endpoint is the notification pipe
            // (PSTN 1.2 §6.5).
            5 if len >= 7 => {
                let ep_addr = cfg[i + 2];
                let attr = cfg[i + 3];
                let mps = u16::from_le_bytes([cfg[i + 4], cfg[i + 5]]);
                let interval = cfg[i + 6];
                let xfer_t = attr & 0x03;
                let is_in = ep_addr & 0x80 != 0;
                if current_class == USB_CLASS_CDC_DATA {
                    if xfer_t == 2 {
                        // Bulk
                        let ep_cfg = EndpointConfig {
                            ep_addr,
                            max_packet: mps,
                            kind: if is_in {
                                EndpointKind::BulkIn
                            } else {
                                EndpointKind::BulkOut
                            },
                            interval: 0,
                        };
                        if let Some((_, bi, bo)) = &mut cur_data {
                            if is_in && bi.is_none() {
                                *bi = Some(ep_cfg);
                            } else if !is_in && bo.is_none() {
                                *bo = Some(ep_cfg);
                            }
                        }
                    }
                } else if current_iface == comm_iface && comm_iface.is_some() {
                    if xfer_t == 3 && is_in && notify.is_none() {
                        // Interrupt-IN — notification endpoint.
                        notify = Some(EndpointConfig {
                            ep_addr,
                            max_packet: mps,
                            kind: EndpointKind::InterruptIn,
                            interval,
                        });
                    }
                }
            }
            _ => {}
        }
        i += len;
    }
    finish_data!();

    let comm_iface = comm_iface?;
    let (data_iface, bulk_in, bulk_out) = match &union_subordinates {
        Some(subs) => {
            let mut found = None;
            for sub in subs {
                if let Some(p) = data_pairs.iter().find(|(num, _, _)| num == sub) {
                    found = Some(*p);
                    break;
                }
            }
            found?
        }
        None => *data_pairs.first()?,
    };
    Some(AcmInterfaces {
        comm_iface,
        data_iface,
        bulk_in,
        bulk_out,
        notify,
        capabilities,
    })
}

// ── CdcAcmPort — public per-port API ─────────────────────────────

/// A bound CDC-ACM virtual serial port.  Wraps the shared
/// [`AcmDevice`] registry entry and the xHCI controller reference
/// to provide a typed, `async`-friendly API.
///
/// Obtained from the global [`ACM_DEVICES`] registry after a
/// successful [`try_bind_cdc_acm_already_addressed`] call.  A
/// caller that just wants the first available port can use
/// [`CdcAcmPort::first`].
#[derive(Debug)]
pub struct CdcAcmPort {
    dev: Arc<AcmDevice>,
    xhci: Arc<Xhci>,
}

impl CdcAcmPort {
    /// Grab the first bound CDC-ACM device, if any.
    pub fn first(xhci: Arc<Xhci>) -> Option<Self> {
        let dev = ACM_DEVICES.lock().first().cloned()?;
        Some(Self { dev, xhci })
    }

    /// Grab the bound CDC-ACM device on `slot_id`, if any.
    pub fn for_slot(xhci: Arc<Xhci>, slot_id: u8) -> Option<Self> {
        let dev = ACM_DEVICES
            .lock()
            .iter()
            .find(|d| d.slot_id == slot_id)
            .cloned()?;
        Some(Self { dev, xhci })
    }

    /// The line coding the device last accepted (the bind
    /// default, or the most recent successful
    /// [`CdcAcmPort::set_line_coding`]).
    pub fn line_coding(&self) -> LineCoding {
        *self.dev.line_coding.lock()
    }

    /// Send `SET_LINE_CODING` (PSTN 1.2 §6.3.10) with the
    /// supplied parameters.
    ///
    /// The transfer's result is propagated honestly: a STALLed
    /// or failed request returns [`CdcError::Transfer`] and the
    /// cached line coding is left describing the state the
    /// device is actually in; the cache updates only after the
    /// device accepts the new coding (#759).
    pub fn set_line_coding(&self, coding: LineCoding) -> Result<(), CdcError> {
        if !matches!(coding.data_bits, 5 | 6 | 7 | 8 | 16) {
            return Err(CdcError::MalformedField);
        }
        let coding_bytes = coding.encode();
        // The control transfer is issued synchronously by
        // parking on the xHCI command ring via `block_on`. No
        // lock is held across the bridge (the cache update below
        // takes the lock only after the transfer completes).
        let res = narf_scheduler::block_on(async {
            self.xhci
                .control_out(
                    self.dev.slot_id,
                    RT_HOST_TO_DEV_CLASS_IFACE,
                    REQ_SET_LINE_CODING,
                    0,
                    self.dev.comm_iface as u16,
                    &coding_bytes,
                )
                .await
        });
        res.map_err(|_| CdcError::Transfer)?;
        *self.dev.line_coding.lock() = coding;
        Ok(())
    }

    /// Send `SET_CONTROL_LINE_STATE` — sets DTR (`bit 0`) and RTS
    /// (`bit 1`) in the `wValue` field per PSTN 1.2 §6.3.12.
    ///
    /// A STALLed or failed request returns [`CdcError::Transfer`]
    /// — the caller is never told the lines moved when the
    /// device did not accept the request (#759).
    pub fn set_control_lines(&self, dtr: bool, rts: bool) -> Result<(), CdcError> {
        let state: u16 = if dtr { CTRL_DTR } else { 0 } | if rts { CTRL_RTS } else { 0 };
        let res = narf_scheduler::block_on(async {
            self.xhci
                .control_out(
                    self.dev.slot_id,
                    RT_HOST_TO_DEV_CLASS_IFACE,
                    REQ_SET_CONTROL_LINE_STATE,
                    state,
                    self.dev.comm_iface as u16,
                    &[],
                )
                .await
        });
        res.map_err(|_| CdcError::Transfer)
    }

    /// Send `SEND_BREAK` (PSTN 1.2 §6.3, request `0x23`):
    /// `duration_ms` is the break duration carried in `wValue` —
    /// a millisecond count, `0` to stop an ongoing break, or
    /// `0xFFFF` to break until the next request.
    ///
    /// Refused with [`CdcError::Unsupported`] when the device
    /// did not declare the send-break capability in its ACM
    /// functional descriptor (PSTN 1.2 §3.6.2.1) — the request
    /// is never issued to a device that did not opt in.
    pub fn send_break(&self, duration_ms: u16) -> Result<(), CdcError> {
        if !self.dev.capabilities.send_break {
            return Err(CdcError::Unsupported);
        }
        let setup = build_send_break(self.dev.comm_iface, duration_ms);
        let res = narf_scheduler::block_on(async {
            self.xhci
                .control_out(
                    self.dev.slot_id,
                    setup.bm_request_type,
                    setup.b_request,
                    setup.w_value,
                    setup.w_index,
                    &[],
                )
                .await
        });
        res.map_err(|_| CdcError::Transfer)
    }

    /// Receive up to `buf.len()` bytes from the device's bulk-IN
    /// endpoint.  Returns the number of bytes copied.
    pub async fn read(&self, buf: &mut [u8]) -> Result<usize, XhciError> {
        self.xhci
            .bulk_in(self.dev.slot_id, self.dev.bulk_in_dci, buf)
            .await
    }

    /// Transmit `buf` to the device's bulk-OUT endpoint.  Returns
    /// the number of bytes the controller acknowledged delivering.
    pub async fn write(&self, buf: &[u8]) -> Result<usize, XhciError> {
        self.xhci
            .bulk_out(self.dev.slot_id, self.dev.bulk_out_dci, buf)
            .await
    }
}

/// Post-address ACM bind: caller has already issued port_reset +
/// enable_slot + address_device. We pull the config descriptor,
/// match the Comm + Data interface pair, configure the bulk
/// endpoints, then issue `SET_CONFIGURATION` →
/// `SET_LINE_CODING(115200 8N1)` →
/// `SET_CONTROL_LINE_STATE(DTR | RTS)` so the device knows the host
/// is ready to receive bytes. Failure on any step returns Err and
/// the caller's cleanup_guard frees the slot.
pub async fn try_bind_cdc_acm_already_addressed(
    xhci_dev: &Xhci,
    slot_id: u8,
    cfg: &[u8],
    speed: PortSpeed,
    hub_port: Option<(usize, u8)>,
) -> Result<(), CdcError> {
    let _ = speed; // reserved for future MaxPacketSize-aware setup
    let ifaces = find_acm_interfaces(cfg).ok_or(CdcError::Truncated)?;
    let comm_iface = ifaces.comm_iface;
    let data_iface = ifaces.data_iface;
    let bulk_in = ifaces.bulk_in;
    let bulk_out = ifaces.bulk_out;

    // Configure xHC-side endpoint contexts for the bulk pair,
    // plus the notification endpoint when the device carries
    // one — without a configured endpoint context the
    // notification pipe can never be armed (#757).
    let mut ep_list: Vec<EndpointConfig> = alloc::vec![bulk_in, bulk_out];
    if let Some(notify) = ifaces.notify {
        ep_list.push(notify);
    }
    xhci_dev
        .configure_endpoints(slot_id, &ep_list)
        .await
        .map_err(|_| CdcError::Truncated)?;

    // SET_CONFIGURATION before any class request (USB 2.0 §9.4.7).
    if cfg.len() < 9 || cfg[1] != 2 {
        return Err(CdcError::Truncated);
    }
    let cfg_value = cfg[5];
    xhci_dev
        .control_out(
            slot_id,
            0x00,
            crate::hid::STD_REQ_SET_CONFIGURATION,
            cfg_value as u16,
            0,
            &[],
        )
        .await
        .map_err(|_| CdcError::Truncated)?;

    // SET_LINE_CODING(115200 8N1) — the dev-board default. PSTN 1.2
    // §6.3.10. Failure here is non-fatal for some chips that ignore
    // line coding (Arduino-style sketches just sample any baud).
    let coding = LineCoding::N_115200_8N1;
    let coding_bytes = coding.encode();
    let _ = xhci_dev
        .control_out(
            slot_id,
            RT_HOST_TO_DEV_CLASS_IFACE,
            REQ_SET_LINE_CODING,
            0,
            comm_iface as u16,
            &coding_bytes,
        )
        .await;

    // SET_CONTROL_LINE_STATE(DTR | RTS) — tells the device the host
    // is present + ready to receive (PSTN 1.2 §6.3.12). On many
    // USB-to-serial dongles this gates whether the chip drives RXD.
    let _ = xhci_dev
        .control_out(
            slot_id,
            RT_HOST_TO_DEV_CLASS_IFACE,
            REQ_SET_CONTROL_LINE_STATE,
            CTRL_DTR | CTRL_RTS,
            comm_iface as u16,
            &[],
        )
        .await;

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

    // Arm the notification endpoint the same way (#757): the
    // device can now raise SerialState reports, which the pump
    // decodes into the ttyACM node's modem state.
    let notify_dci = match ifaces.notify {
        Some(notify) => {
            let dci = ((notify.ep_addr & 0x0F) * 2) + 1;
            xhci_dev
                .arm_interrupt_in(slot_id, dci, notify.max_packet.min(64) as u32)
                .map_err(|_| CdcError::Truncated)?;
            Some(dci)
        }
        None => None,
    };

    // Publish the per-device /dev/ttyACM<N> node (#753). The
    // transport resolves the device lazily through this registry
    // on each ioctl, so registering just before the registry
    // push is safe: an ioctl landing in between is answered
    // ENODEV, the honest state of a half-bound device.
    let tty_index = crate::cdc_acm_bridge::register_tty_acm(Arc::new(
        crate::cdc_acm_bridge::XhciAcmTransport::new(slot_id, ifaces.capabilities),
    ));

    let dev = Arc::new(AcmDevice {
        slot_id,
        data_iface,
        comm_iface,
        bulk_in_dci,
        bulk_out_dci,
        notify_dci,
        capabilities: ifaces.capabilities,
        tty_index: Some(tty_index),
        line_coding: IrqSafeSpinLock::new(coding),
        control_lines: AtomicU16::new(CTRL_DTR | CTRL_RTS),
        hub_port,
    });
    if should_announce_attach(slot_id) {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "  cdc-acm: serial attached on slot {} ({} bps)",
            slot_id,
            coding.baud_rate
        );
    }
    ACM_DEVICES.lock().push(dev);
    Ok(())
}

/// Detach the ACM device bound to `slot_id` (unplugged or torn
/// down by the supervisor): drop the binding so `pump_all` stops
/// polling the dead slot, and withdraw its `/dev/ttyACM<N>`
/// publication. Returns true when a binding was removed.
pub fn detach_acm(slot_id: u8) -> bool {
    let (removed, indices) = {
        let mut g = ACM_DEVICES.lock();
        let indices: Vec<usize> = g
            .iter()
            .filter(|d| d.slot_id == slot_id)
            .filter_map(|d| d.tty_index)
            .collect();
        let before = g.len();
        g.retain(|d| d.slot_id != slot_id);
        (g.len() != before, indices)
    };
    for idx in indices {
        crate::cdc_acm_bridge::unregister_tty_acm(idx);
    }
    removed
}

/// Drop every ACM binding and ttyACM publication. Called on a
/// controller recovery epoch change.
pub fn clear_acm() {
    let indices: Vec<usize> = {
        let mut g = ACM_DEVICES.lock();
        let v: Vec<usize> = g.iter().filter_map(|d| d.tty_index).collect();
        g.clear();
        v
    };
    for idx in indices {
        crate::cdc_acm_bridge::unregister_tty_acm(idx);
    }
}

// ── Suspend / resume (system PM) ──────────────────────────────────
//
// #763: before this lane nothing replayed ACM state after S3 —
// the bind-time SET_LINE_CODING / SET_CONTROL_LINE_STATE ran
// once, ever, so a dongle that lost power in S3 came back with
// its UART unconfigured and DTR dropped (modems lose carrier,
// dev-board consoles die, no error anywhere). The class
// registers an async system-PM hook (`narf_power::system_pm`):
// prepare latches the pump quiesced before the synchronous
// device fan-out gates the controller; resume (which runs after
// the fan-out restored xHCI) replays each bound device's saved
// line coding + control lines in bind order. State is saved
// continuously — the `CdcAcmPort` setters commit to the device
// record only on transfer success — so prepare has nothing to
// snapshot.

/// Pump quiesce latch: set by the PM prepare hook, cleared when
/// the resume replay settles. While set, `pump_all` leaves every
/// endpoint alone.
static ACM_PM_SUSPENDED: AtomicBool = AtomicBool::new(false);

/// True while the class is quiesced for system suspend.
pub fn pm_quiesced() -> bool {
    ACM_PM_SUSPENDED.load(Ordering::SeqCst)
}

fn pm_prepare() {
    ACM_PM_SUSPENDED.store(true, Ordering::SeqCst);
}

fn pm_finish_resume() {
    ACM_PM_SUSPENDED.store(false, Ordering::SeqCst);
}

/// The bind-time control sequence for one device, rebuilt from
/// its saved state: `SET_LINE_CODING` then
/// `SET_CONTROL_LINE_STATE`, the order bind issues them (PSTN
/// 1.2 §6.3.10 / §6.3.12). Pure — the fixtures pin it
/// byte-for-byte.
pub fn resume_plan(dev: &AcmDevice) -> Vec<ControlXfer> {
    let coding = *dev.line_coding.lock();
    let state = dev.control_lines.load(Ordering::SeqCst);
    alloc::vec![
        ControlXfer::with_data(
            RT_HOST_TO_DEV_CLASS_IFACE,
            REQ_SET_LINE_CODING,
            0,
            dev.comm_iface as u16,
            &coding.encode(),
        ),
        ControlXfer::new(
            RT_HOST_TO_DEV_CLASS_IFACE,
            REQ_SET_CONTROL_LINE_STATE,
            state,
            dev.comm_iface as u16,
        ),
    ]
}

/// Replay every bound device's saved state over `transport`.
/// A device that detached while suspended is absent from the
/// registry and gets no replay; a device whose slot refuses the
/// transfers fails typed (`DriverError`) without stopping the
/// remaining devices' replays.
pub async fn resume_replay<T: ControlTransport + ?Sized>(
    transport: &T,
) -> Result<(), narf_power::device_pm::DeviceSuspendError> {
    let devs: Vec<Arc<AcmDevice>> = ACM_DEVICES.lock().clone();
    let mut failed = false;
    for dev in &devs {
        if apply_plan(transport, dev.slot_id, &resume_plan(dev))
            .await
            .is_err()
        {
            failed = true;
        }
    }
    if failed {
        Err(narf_power::device_pm::DeviceSuspendError::DriverError)
    } else {
        Ok(())
    }
}

struct AcmSystemPm;

impl narf_power::system_pm::AsyncSystemPm for AcmSystemPm {
    fn prepare_suspend<'a>(&'a self) -> narf_power::system_pm::SystemPmFuture<'a> {
        Box::pin(async {
            pm_prepare();
            Ok(())
        })
    }

    fn resume_from_suspend<'a>(&'a self) -> narf_power::system_pm::SystemPmFuture<'a> {
        Box::pin(async {
            let result = match crate::xhci::controller() {
                Some(xhci) => resume_replay(xhci.as_ref()).await,
                None => {
                    if attached_count() == 0 {
                        Ok(())
                    } else {
                        Err(narf_power::device_pm::DeviceSuspendError::DriverError)
                    }
                }
            };
            pm_finish_resume();
            result
        })
    }
}

/// Register the class's async system-PM hook. Called once from
/// the USB crate's Stage::Subsys initcalls; registration is
/// idempotent on the hook name.
pub fn register_pm() {
    narf_power::system_pm::register_async_system_pm("cdc-acm", Arc::new(AcmSystemPm));
}

/// (hub index, port) pairs with a live ACM binding — the
/// pure-filter input for the supervisor's hub-port wake step.
pub fn hub_ports() -> Vec<(usize, u8)> {
    let mut v: Vec<(usize, u8)> = {
        let g = ACM_DEVICES.lock();
        g.iter().filter_map(|d| d.hub_port).collect()
    };
    v.sort_unstable();
    v.dedup();
    v
}

/// Supervisor wake step for hub-attached ACM, run immediately
/// before `pump_all` each cycle (#763; the #840 HID pattern). A
/// suspended hub port gates the device's endpoints, so an ACM
/// console behind an autosuspended port would stay dead even
/// though it is bound and pumped every cycle. The wake opens a
/// fresh idle window, so a silent device re-suspends after a
/// full idle window rather than being held awake.
pub async fn resume_suspended_hub_ports(xhci_dev: &Xhci) {
    // Collect binding contexts first, then snapshot the hub
    // registry — never hold HUBS across the ACM registry lock
    // (the pumps nest the other way via `mark_port_activity`).
    let ports = hub_ports();
    let targets = {
        let g = crate::attach::HUBS.lock();
        crate::attach::suspended_ports_among(&g[..], &ports)
    };
    for (hub_idx, port) in targets {
        crate::attach::resume_port(xhci_dev, hub_idx, port).await;
        if !crate::attach::hub_port_is_suspended(hub_idx, port) {
            crate::attach::mark_port_activity(hub_idx, port);
        }
    }
}

/// Drain one report from each bound ACM device's bulk-IN endpoint
/// and forward the bytes to the global input ring as
/// [`narf_input::InputEvent::AsciiByte`] events. `/dev/console` reads
/// pop these the same way it consumes UART input — so a USB serial
/// adaptor wired to a debug header becomes a kernel console source.
/// The same bytes also land in the device's `/dev/ttyACM<N>` RX
/// ring (#753), the pump drains that node's TX ring onto bulk-OUT,
/// and notification-endpoint reports are decoded into the node's
/// modem state (#757). All controller calls here are non-blocking
/// polls; no lock is held across any of them.
pub fn pump_all(xhci_dev: &Xhci) -> usize {
    // Quiesced for system suspend (#763): the PM prepare hook
    // latches this before the controller fan-out; leave every
    // endpoint alone until the resume replay settles.
    if pm_quiesced() {
        return 0;
    }
    let devs: Vec<Arc<AcmDevice>> = {
        let g = ACM_DEVICES.lock();
        g.clone()
    };
    let mut total = 0usize;
    for d in &devs {
        // ── RX: bulk-IN → console input ring + ttyACM RX ring ──
        let mut buf = [0u8; 64];
        loop {
            match xhci_dev.poll_interrupt_in(d.slot_id, d.bulk_in_dci, &mut buf) {
                Ok(Some(n)) => {
                    let n = n.min(buf.len());
                    for &b in &buf[..n] {
                        narf_input::push_global(narf_input::InputEvent::AsciiByte(b));
                        total += 1;
                    }
                    if let Some(idx) = d.tty_index {
                        crate::cdc_acm_bridge::feed_rx(idx, &buf[..n]);
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        if let Some(idx) = d.tty_index {
            // ── Notifications: SerialState → ttyACM modem state ──
            if let Some(dci) = d.notify_dci {
                let mut nbuf = [0u8; 64];
                while let Ok(Some(n)) = xhci_dev.poll_interrupt_in(d.slot_id, dci, &mut nbuf) {
                    let n = n.min(nbuf.len());
                    match Notification::decode(&nbuf[..n]) {
                        Ok(Notification::SerialState(s)) => {
                            crate::cdc_acm_bridge::note_serial_state(idx, s);
                        }
                        Ok(Notification::NetworkConnection { up }) => {
                            crate::cdc_acm_bridge::note_network_connection(idx, up);
                        }
                        _ => {}
                    }
                }
            }
            // ── TX: ttyACM TX ring → bulk-OUT ──
            // Peek/skip discipline (the vendor-serial pump's):
            // bytes leave the ring only once the controller
            // reports the transfer complete. A TCXONC-stopped
            // port peeks as empty, so its bytes simply wait.
            let mut chunk = [0u8; 64];
            let pending = crate::cdc_acm_bridge::tx_peek(idx, &mut chunk);
            if pending > 0 {
                if let Some(generation) = xhci_dev.device_generation(d.slot_id) {
                    if let Ok(token) = xhci_dev.begin_bulk_out(
                        d.slot_id,
                        d.bulk_out_dci,
                        generation,
                        &chunk[..pending],
                    ) {
                        for _ in 0..512 {
                            match xhci_dev.poll_bulk_out(&token) {
                                Ok(Some(sent)) => {
                                    crate::cdc_acm_bridge::tx_skip(idx, sent.min(pending));
                                    total += sent;
                                    break;
                                }
                                Ok(None) => continue,
                                Err(_) => break,
                            }
                        }
                    }
                }
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

/// Whether binding `slot_id` should print the "serial attached"
/// banner: yes iff no live binding for the slot exists yet.
/// Membership in [`ACM_DEVICES`] is the latch — `detach_acm`
/// removes the entry on unplug, so a replugged adapter on the same
/// slot announces again. (This replaces a function-local `ATTACHED`
/// bitmask in the bind path that was never cleared on detach and
/// permanently suppressed the banner after the first bind.)
fn should_announce_attach(slot_id: u8) -> bool {
    !ACM_DEVICES.lock().iter().any(|d| d.slot_id == slot_id)
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
            NOTIFICATION_NETWORK_CONNECTION => {
                Notification::NetworkConnection { up: value & 1 != 0 }
            }
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

    /// Detach/replug latch: the "serial attached" announce
    /// predicate tracks ACM_DEVICES membership — latched while a
    /// binding for the slot lives, re-armed once `detach_acm`
    /// removes it, so a replugged adapter announces again.
    fn smoke_acm_announce_latch_replug() -> TestResult {
        const SLOT: u8 = 201; // no real enumeration reaches this slot in tests
        let baseline = attached_count();
        if !should_announce_attach(SLOT) {
            return TestResult::Fail("announce should be armed with no binding");
        }
        ACM_DEVICES.lock().push(Arc::new(AcmDevice {
            slot_id: SLOT,
            data_iface: 1,
            comm_iface: 0,
            bulk_in_dci: 3,
            bulk_out_dci: 2,
            notify_dci: None,
            capabilities: AcmCapabilities::decode(0),
            tty_index: None,
            line_coding: IrqSafeSpinLock::new(LineCoding::N_115200_8N1),
            control_lines: AtomicU16::new(CTRL_DTR | CTRL_RTS),
            hub_port: None,
        }));
        if attached_count() != baseline + 1 {
            return TestResult::Fail("fabricated binding not registered");
        }
        if should_announce_attach(SLOT) {
            return TestResult::Fail("announce should be latched while bound");
        }
        if !detach_acm(SLOT) {
            return TestResult::Fail("detach_acm should report the removal");
        }
        if attached_count() != baseline {
            return TestResult::Fail("binding should be gone after detach_acm");
        }
        if !should_announce_attach(SLOT) {
            return TestResult::Fail("announce should re-arm after detach");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_acm", smoke_acm_announce_latch_replug);

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
    kernel_test_in!("drivers/usb/cdc_acm", smoke_set_line_coding_setup_layout);

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
    kernel_test_in!("drivers/usb/cdc_acm", smoke_network_connection_notification);

    /// Synthesize a configuration descriptor that presents an IAD-led
    /// CDC-ACM + CDC-Data pair (the "composite device" layout used by
    /// modern microcontrollers that set `bDeviceClass = 0xEF`). Verify
    /// that [`find_acm_interfaces`] correctly identifies the Comm + Data
    /// interface pair and bulk endpoint pair.
    ///
    /// Blob layout (all little-endian, lengths in bytes):
    ///
    /// ```text
    ///   9  Configuration Descriptor  (bNumInterfaces=2, bConfigurationValue=1)
    ///   8  IAD                       (bFirstInterface=0, bInterfaceCount=2,
    ///                                 bFunctionClass=0x02, bFunctionSubClass=0x02)
    ///   9  Interface 0               (class=0x02 CDC-Comm, subclass=0x02 ACM)
    ///   5  Header functional desc    (bcdCDC 0x0120)
    ///   4  ACM functional desc       (bmCapabilities=0x07)
    ///   5  Union functional desc     (control=0, subordinate=1)
    ///   7  Endpoint 0x83             (Interrupt-IN — notification ep)
    ///   9  Interface 1               (class=0x0A CDC-Data, subclass=0x00)
    ///   7  Endpoint 0x81             (Bulk-IN)
    ///   7  Endpoint 0x02             (Bulk-OUT)
    ///
    /// Total = 9+8+9+5+4+5+7+9+7+7 = 70 bytes
    /// ```
    fn smoke_iad_acm_data_bind_detect() -> TestResult {
        use crate::xhci::EndpointKind;

        // Configuration Descriptor (9 bytes):
        //   bLength=9, bDescriptorType=2 (Configuration),
        //   wTotalLength=70, bNumInterfaces=2, bConfigurationValue=1,
        //   iConfiguration=0, bmAttributes=0xC0, bMaxPower=50
        let cfg: [u8; 70] = [
            9,
            2,
            70,
            0,
            2,
            1,
            0,
            0xC0,
            50,
            // IAD (8 bytes): bFirstInterface=0, bInterfaceCount=2,
            // bFunctionClass=0x02 (CDC-Comm), bFunctionSubClass=0x02 (ACM),
            // bFunctionProtocol=0x00, iFunction=0
            8,
            USB_DT_INTERFACE_ASSOCIATION,
            0,
            2,
            0x02,
            0x02,
            0x00,
            0,
            // Interface 0 (9 bytes): CDC-Comm / ACM
            // bInterfaceNumber=0, bAlternateSetting=0, bNumEndpoints=1,
            // bInterfaceClass=0x02, bInterfaceSubClass=0x02 (ACM),
            // bInterfaceProtocol=0x01, iInterface=0
            9,
            4,
            0,
            0,
            1,
            0x02,
            0x02,
            0x01,
            0,
            // Header functional descriptor (5 bytes):
            // bFunctionLength=5, CS_INTERFACE (0x24), subtype 0x00,
            // bcdCDC=0x0120 (CDC 1.2).
            5,
            CS_INTERFACE,
            0x00,
            0x20,
            0x01,
            // ACM functional descriptor (4 bytes):
            // bFunctionLength=4, CS_INTERFACE, subtype 0x02 (ACM),
            // bmCapabilities=0x07 (comm feature + line coding/state
            // + send break; no network-connection notification).
            4,
            CS_INTERFACE,
            0x02,
            0x07,
            // Union functional descriptor (5 bytes):
            // bFunctionLength=5, CS_INTERFACE, subtype 0x06 (Union),
            // bControlInterface=0, bSubordinateInterface0=1.
            5,
            CS_INTERFACE,
            0x06,
            0,
            1,
            // Endpoint 0x83 (7 bytes): Interrupt-IN (notification)
            // ep_addr=0x83, bmAttributes=0x03 (Interrupt), wMaxPacketSize=16, bInterval=255
            7,
            5,
            0x83,
            0x03,
            16,
            0,
            255,
            // Interface 1 (9 bytes): CDC-Data
            // bInterfaceNumber=1, bAlternateSetting=0, bNumEndpoints=2,
            // bInterfaceClass=0x0A (CDC-Data), bInterfaceSubClass=0x00,
            // bInterfaceProtocol=0x00, iInterface=0
            9,
            4,
            1,
            0,
            2,
            0x0A,
            0x00,
            0x00,
            0,
            // Endpoint 0x81 (7 bytes): Bulk-IN
            // ep_addr=0x81, bmAttributes=0x02 (Bulk), wMaxPacketSize=64
            7,
            5,
            0x81,
            0x02,
            64,
            0,
            0,
            // Endpoint 0x02 (7 bytes): Bulk-OUT
            // ep_addr=0x02, bmAttributes=0x02 (Bulk), wMaxPacketSize=64
            7,
            5,
            0x02,
            0x02,
            64,
            0,
            0,
        ];

        let r = match find_acm_interfaces(&cfg) {
            Some(r) => r,
            None => return TestResult::Fail("IAD-led ACM+Data not detected"),
        };

        if r.comm_iface != 0 {
            return TestResult::Fail("comm iface should be 0");
        }
        if r.data_iface != 1 {
            return TestResult::Fail("data iface should be 1");
        }
        if r.bulk_in.ep_addr != 0x81 || r.bulk_in.kind != EndpointKind::BulkIn {
            return TestResult::Fail("bulk-IN mis-identified");
        }
        if r.bulk_out.ep_addr != 0x02 || r.bulk_out.kind != EndpointKind::BulkOut {
            return TestResult::Fail("bulk-OUT mis-identified");
        }
        if r.bulk_in.max_packet != 64 || r.bulk_out.max_packet != 64 {
            return TestResult::Fail("max_packet mis-decoded");
        }
        // The Comm interface's interrupt-IN endpoint is captured
        // as the notification pipe (#757) — not dropped.
        match r.notify {
            Some(n) if n.ep_addr == 0x83 && n.kind == EndpointKind::InterruptIn => {}
            _ => return TestResult::Fail("notification endpoint not captured"),
        }
        if n_max_packet(&r) != 16 {
            return TestResult::Fail("notification max_packet mis-decoded");
        }
        // ACM functional descriptor bmCapabilities=0x07 decoded.
        let caps = r.capabilities;
        if !caps.comm_feature || !caps.line_coding_state || !caps.send_break {
            return TestResult::Fail("ACM capabilities lost in scan");
        }
        if caps.network_connection {
            return TestResult::Fail("capability bits over-set");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_acm", smoke_iad_acm_data_bind_detect);

    // ── Suspend / resume replay (#763) ───────────────────────

    use crate::serial::port::PortError;

    /// Recording `ControlTransport` fake (the serial layer's
    /// seam): logs every transfer as (slot, xfer) and refuses
    /// transfers for scripted dead slots.
    struct FakeTransport {
        log: IrqSafeSpinLock<Vec<(u8, ControlXfer)>>,
        dead: Vec<u8>,
    }

    impl FakeTransport {
        fn new(dead: Vec<u8>) -> Self {
            FakeTransport {
                log: IrqSafeSpinLock::new(Vec::new()),
                dead,
            }
        }
    }

    impl ControlTransport for FakeTransport {
        async fn control_out(
            &self,
            slot_id: u8,
            bm_request_type: u8,
            b_request: u8,
            w_value: u16,
            w_index: u16,
            data: &[u8],
        ) -> Result<(), PortError> {
            if self.dead.contains(&slot_id) {
                return Err(PortError::Transfer);
            }
            let mut x = ControlXfer::new(bm_request_type, b_request, w_value, w_index);
            x.data.extend_from_slice(data);
            self.log.lock().push((slot_id, x));
            Ok(())
        }
    }

    fn fabricate_acm(
        slot_id: u8,
        comm_iface: u8,
        coding: LineCoding,
        control_lines: u16,
    ) -> Arc<AcmDevice> {
        let dev = Arc::new(AcmDevice {
            slot_id,
            data_iface: comm_iface + 1,
            comm_iface,
            bulk_in_dci: 3,
            bulk_out_dci: 2,
            notify_dci: None,
            capabilities: AcmCapabilities::decode(0),
            tty_index: None,
            line_coding: IrqSafeSpinLock::new(coding),
            control_lines: AtomicU16::new(control_lines),
            hub_port: None,
        });
        ACM_DEVICES.lock().push(dev.clone());
        dev
    }

    fn smoke_acm_resume_plan_byte_exact() -> TestResult {
        // Saved state deliberately NOT the bind default: 9600
        // 7E2 (PSTN Table 17 encoding: dwDTERate 9600 LE =
        // 80 25 00 00, bCharFormat 2 = 2 stop bits, bParityType
        // 2 = Even, bDataBits 7) and DTR only on iface 2.
        let dev = fabricate_acm(
            231,
            2,
            LineCoding {
                baud_rate: 9_600,
                stop_bits: StopBits::Two,
                parity: Parity::Even,
                data_bits: 7,
            },
            CTRL_DTR,
        );
        let plan = resume_plan(&dev);
        detach_acm(231);
        if plan.len() != 2 {
            return TestResult::Fail("resume plan must be the two bind transfers");
        }
        let lc = &plan[0];
        if lc.bm_request_type != RT_HOST_TO_DEV_CLASS_IFACE
            || lc.b_request != REQ_SET_LINE_CODING
            || lc.w_value != 0
            || lc.w_index != 2
            || lc.data != [0x80, 0x25, 0x00, 0x00, 2, 2, 7]
        {
            return TestResult::Fail("resume SET_LINE_CODING step is not byte-exact");
        }
        let cls = &plan[1];
        if cls.bm_request_type != RT_HOST_TO_DEV_CLASS_IFACE
            || cls.b_request != REQ_SET_CONTROL_LINE_STATE
            || cls.w_value != CTRL_DTR
            || cls.w_index != 2
            || !cls.data.is_empty()
        {
            return TestResult::Fail("resume SET_CONTROL_LINE_STATE step is not byte-exact");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_acm", smoke_acm_resume_plan_byte_exact);

    fn smoke_acm_resume_plan_devices_do_not_cross() -> TestResult {
        // Masking-defeating: two devices whose saved states
        // differ in every field. Each plan must carry its own
        // device's iface, coding bytes and control lines — a
        // replay that mixed them would still "succeed" on the
        // wire, so the plans themselves are asserted.
        let a = fabricate_acm(231, 0, LineCoding::N_115200_8N1, CTRL_DTR | CTRL_RTS);
        let b = fabricate_acm(
            232,
            3,
            LineCoding {
                baud_rate: 9_600,
                stop_bits: StopBits::Two,
                parity: Parity::Even,
                data_bits: 7,
            },
            CTRL_DTR,
        );
        let pa = resume_plan(&a);
        let pb = resume_plan(&b);
        detach_acm(231);
        detach_acm(232);
        if pa[0].w_index != 0
            || pa[0].data != [0x00, 0xC2, 0x01, 0x00, 0, 0, 8]
            || pa[1].w_value != 3
        {
            return TestResult::Fail("device A plan lost its own state");
        }
        if pb[0].w_index != 3
            || pb[0].data != [0x80, 0x25, 0x00, 0x00, 2, 2, 7]
            || pb[1].w_value != 1
        {
            return TestResult::Fail("device B plan lost its own state");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/cdc_acm",
        smoke_acm_resume_plan_devices_do_not_cross
    );

    fn smoke_acm_resume_replay_fake_conversation() -> TestResult {
        let a = fabricate_acm(231, 0, LineCoding::N_115200_8N1, CTRL_DTR | CTRL_RTS);
        let b = fabricate_acm(
            232,
            3,
            LineCoding {
                baud_rate: 9_600,
                stop_bits: StopBits::Two,
                parity: Parity::Even,
                data_bits: 7,
            },
            CTRL_DTR,
        );
        let plan_a = resume_plan(&a);
        let plan_b = resume_plan(&b);
        let fake = FakeTransport::new(Vec::new());
        let result = narf_scheduler::block_on_spin(resume_replay(&fake));
        detach_acm(231);
        detach_acm(232);
        if result.is_err() {
            return TestResult::Fail("resume replay over a healthy fake must succeed");
        }
        // Transcript: device A's two transfers (slot 231) then
        // device B's (slot 232) — registry order, bind order
        // within each device.
        let log = fake.log.lock();
        let mut expected: Vec<(u8, &ControlXfer)> = Vec::new();
        for x in &plan_a {
            expected.push((231, x));
        }
        for x in &plan_b {
            expected.push((232, x));
        }
        if log.len() != expected.len()
            || !log
                .iter()
                .zip(expected.iter())
                .all(|((slot, got), (want_slot, want))| slot == want_slot && got == *want)
        {
            return TestResult::Fail("resume transcript is not the two plans in order");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/cdc_acm",
        smoke_acm_resume_replay_fake_conversation
    );

    fn smoke_acm_resume_replay_dead_and_detached() -> TestResult {
        let a = fabricate_acm(231, 0, LineCoding::N_115200_8N1, CTRL_DTR | CTRL_RTS);
        let _b = fabricate_acm(232, 3, LineCoding::N_9600_8N1, CTRL_DTR | CTRL_RTS);
        let plan_a = resume_plan(&a);
        // Dead slot: 232's device vanished across the sleep
        // without a detach (slot refuses every transfer). The
        // replay must fail typed, deliver 231's plan in full,
        // and put nothing on the dead slot.
        let fake = FakeTransport::new(alloc::vec![232]);
        let result = narf_scheduler::block_on_spin(resume_replay(&fake));
        match result {
            Err(narf_power::device_pm::DeviceSuspendError::DriverError) => {}
            _ => return TestResult::Fail("dead slot must fail the replay typed DriverError"),
        }
        {
            let log = fake.log.lock();
            if log.iter().any(|(slot, _)| *slot == 232) {
                return TestResult::Fail("dead slot must receive no transfers");
            }
            if log.len() != plan_a.len()
                || !log
                    .iter()
                    .zip(plan_a.iter())
                    .all(|((slot, got), want)| *slot == 231 && got == want)
            {
                return TestResult::Fail("surviving device's plan must replay in full");
            }
        }
        // Detached while suspended: 232 leaves the registry, so
        // the next replay has nothing to replay into the void —
        // it succeeds with only 231's transfers.
        detach_acm(232);
        let fake2 = FakeTransport::new(Vec::new());
        let result2 = narf_scheduler::block_on_spin(resume_replay(&fake2));
        detach_acm(231);
        if result2.is_err() {
            return TestResult::Fail("replay after detach must succeed");
        }
        let log2 = fake2.log.lock();
        if log2.len() != plan_a.len()
            || !log2
                .iter()
                .zip(plan_a.iter())
                .all(|((slot, got), want)| *slot == 231 && got == want)
        {
            return TestResult::Fail("detached device must get no replay");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/cdc_acm",
        smoke_acm_resume_replay_dead_and_detached
    );

    fn smoke_acm_pm_latch() -> TestResult {
        // The latch the prepare/resume hooks drive: the pump
        // consults `pm_quiesced` before touching any endpoint.
        if pm_quiesced() {
            return TestResult::Fail("pm latch must start clear");
        }
        pm_prepare();
        if !pm_quiesced() {
            return TestResult::Fail("pm_prepare must latch the quiesce");
        }
        pm_finish_resume();
        if pm_quiesced() {
            return TestResult::Fail("pm_finish_resume must clear the quiesce");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_acm", smoke_acm_pm_latch);

    fn n_max_packet(r: &AcmInterfaces) -> u16 {
        r.notify.map(|n| n.max_packet).unwrap_or(0)
    }

    // ── Descriptor blob builders for the Union tests ─────────

    fn cfg_header(total: u16) -> alloc::vec::Vec<u8> {
        alloc::vec![9, 2, total as u8, (total >> 8) as u8, 2, 1, 0, 0xC0, 50]
    }

    fn iface(num: u8, class: u8, sub: u8, n_eps: u8) -> alloc::vec::Vec<u8> {
        alloc::vec![9, 4, num, 0, n_eps, class, sub, 0, 0]
    }

    fn ep(addr: u8, attr: u8, mps: u16) -> alloc::vec::Vec<u8> {
        alloc::vec![7, 5, addr, attr, mps as u8, (mps >> 8) as u8, 1]
    }

    fn join(parts: &[alloc::vec::Vec<u8>]) -> alloc::vec::Vec<u8> {
        let total: usize = parts.iter().map(|p| p.len()).sum::<usize>() + 9;
        let mut out = cfg_header(total as u16);
        for p in parts {
            out.extend_from_slice(p);
        }
        out
    }

    /// Masking-defeating: TWO CDC-Data interfaces carry bulk
    /// pairs. The first (interface 1) is not in the Comm
    /// interface's Union; the Union names interface 2. The scan
    /// must bind interface 2's pair — the class/position scan
    /// alone would have taken interface 1's.
    fn smoke_union_selects_named_data_interface() -> TestResult {
        let cfg = join(&[
            iface(0, 0x02, 0x02, 1),
            // Union: control=0, subordinate=2 (5 bytes).
            alloc::vec![5, CS_INTERFACE, 0x06, 0, 2],
            ep(0x83, 0x03, 16),
            iface(1, 0x0A, 0x00, 2),
            ep(0x82, 0x02, 64),
            ep(0x03, 0x02, 64),
            iface(2, 0x0A, 0x00, 2),
            ep(0x84, 0x02, 64),
            ep(0x04, 0x02, 64),
        ]);
        let r = match find_acm_interfaces(&cfg) {
            Some(r) => r,
            None => return TestResult::Fail("union-led ACM not detected"),
        };
        if r.data_iface != 2 {
            return TestResult::Fail("Union-named data interface must win");
        }
        if r.bulk_in.ep_addr != 0x84 || r.bulk_out.ep_addr != 0x04 {
            return TestResult::Fail("bound the wrong function's bulk pair");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/cdc_acm",
        smoke_union_selects_named_data_interface
    );

    /// A Union naming a subordinate that does not exist fails
    /// closed — the scan must not fall back to an unrelated
    /// Data interface's pair the Union did not name.
    fn smoke_union_dangling_fails_closed() -> TestResult {
        let cfg = join(&[
            iface(0, 0x02, 0x02, 1),
            // Union: control=0, subordinate=3 (does not exist).
            alloc::vec![5, CS_INTERFACE, 0x06, 0, 3],
            ep(0x83, 0x03, 16),
            iface(1, 0x0A, 0x00, 2),
            ep(0x81, 0x02, 64),
            ep(0x02, 0x02, 64),
        ]);
        if find_acm_interfaces(&cfg).is_some() {
            return TestResult::Fail("dangling Union must fail closed");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_acm", smoke_union_dangling_fails_closed);

    /// SEND_BREAK setup packet, pinned byte-for-byte against
    /// PSTN 1.2 §6.3 (request 0x23): bmRequestType 0x21
    /// (class/interface/host-to-device), wValue = duration in
    /// milliseconds, wIndex = Comm interface, wLength 0.
    fn smoke_send_break_setup_layout() -> TestResult {
        let s = build_send_break(1, 250);
        let bytes = s.encode();
        let expect = [0x21u8, 0x23, 250, 0, 1, 0, 0, 0];
        if bytes != expect {
            return TestResult::Fail("SEND_BREAK setup layout wrong");
        }
        // 0xFFFF = break until stopped; 0 = stop break.
        if build_send_break(0, 0xFFFF).w_value != 0xFFFF {
            return TestResult::Fail("continuous-break wValue lost");
        }
        if build_send_break(0, 0).w_value != 0 {
            return TestResult::Fail("stop-break wValue lost");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_acm", smoke_send_break_setup_layout);
}
