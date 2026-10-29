//! Bind + transfer layer for vendor USB-to-serial adapters (#754).
//!
//! The four chip-family modules (`ftdi`, `cp210x`, `pl2303`,
//! `ch341`) are codecs: they encode baud/line/modem settings but,
//! until this module, issued no USB transfer and had no production
//! caller — a dongle enumerated to `UnknownClass` and its slot was
//! disabled. This module is the missing layer:
//!
//! 1. **Plans.** For each family, the ordered control transfers
//!    that open and configure a port are built as pure data
//!    ([`ControlXfer`] lists) from the family codec encoders.
//!    Keeping the plans pure is what lets the fixture tests pin the
//!    exact wire bytes per family without a controller.
//! 2. **Bind.** [`try_bind_serial_already_addressed`] is the
//!    attach-cascade step: VID/PID dispatch via [`super::identify`],
//!    vendor-interface endpoint discovery, endpoint configuration,
//!    `SET_CONFIGURATION`, plan execution, bulk-IN arming, and
//!    publication as `/dev/ttyUSB<N>` through the existing
//!    [`super::devfs_bridge`].
//! 3. **Datapath.** [`pump_all`] is the supervisor pump: bulk-IN
//!    bytes move into the tty RX ring (FTDI's per-packet 2-byte
//!    status header is stripped and decoded into the modem cache),
//!    and tty TX ring bytes move out over bulk-OUT. Reconfiguration
//!    ([`set_line_settings`]) replays the family's configure plan
//!    against the live device, so baud/line/modem settings actually
//!    reach the hardware after bind.
//!
//! ## Family wire facts (from the vendor documents)
//!
//! - **FTDI** (AN120 / AN232B): control requests on
//!   `bmRequestType 0x40`; the baud divisor is computed against the
//!   3 MHz effective base (48 MHz ÷ 16) for BM/R parts and the
//!   12 MHz effective base (120 MHz ÷ 10) for H parts. Bulk-IN
//!   packets carry a 2-byte status prefix (modem status, line
//!   status) that is not payload.
//! - **CP210x** (Silicon Labs AN571): requests on `0x41` with
//!   `wIndex` = interface; `SET_BAUDRATE` (0x1E) takes the rate as
//!   a 4-byte little-endian data stage; the UART must be enabled
//!   with `IFC_ENABLE` before use.
//! - **PL2303** (Prolific datasheet / CDC PSTN): line format is the
//!   7-byte CDC line-coding structure via `SET_LINE_CODING`;
//!   DTR/RTS ride `SET_CONTROL_LINE_STATE`; two vendor writes to
//!   register 0x0404 release the chip from reset at startup.
//! - **CH341** (WCH datasheet): `SERIAL_INIT` (0xA1, wValue 0,
//!   wIndex 0 — the Linux `ch341_configure` form) followed by
//!   register writes for baud divisor and LCR via `WRITE_REG`.
//!
//! ## Scope notes
//!
//! - One port per device: multi-port chips (FT2232H, CP2105,
//!   CP2108) bind their first interface (FTDI channel A). Further
//!   channels are a follow-on, not silently claimed here.
//! - Flow control reaches the device for FTDI (its `SET_FLOW_CTRL`
//!   encoding is fully modelled in the codec). For CP210x the
//!   AN571 `SET_FLOW` 16-byte structure and for PL2303/CH341 their
//!   vendor flow paths are not modelled yet, so requesting a
//!   non-`None` flow mode on those families returns
//!   [`PortError::Unsupported`] instead of the codec states'
//!   historical silent no-op.
//! - The termios ioctl surface is #756 and suspend/resume
//!   line-state replay is #763; this module is the datapath those
//!   follow-ons compose with. The replay lives in the
//!   suspend/resume section below: an async system-PM hook whose
//!   resume rebuilds every bound port's open plan from its
//!   retained [`LineSettings`].

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::xhci::{EndpointConfig, EndpointKind, Xhci};

use super::devfs_bridge;
use super::{ch341, cp210x, ftdi, pl2303};
use super::{ChipFamily, DataBits, FlowControl, ModemStatus, Parity, StopBits};

// ── Errors ────────────────────────────────────────────────────────

/// Failure modes of the bind / transfer layer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PortError {
    /// VID/PID is not in the serial dispatch table.
    UnknownDevice,
    /// The configuration has no vendor interface with a bulk pair.
    NoSerialInterface,
    /// The family cannot express this setting on the wire yet
    /// (named so callers can distinguish it from a transfer fault).
    Unsupported(&'static str),
    /// Baud rate the family's divisor model cannot represent.
    UnsupportedBaud(u32),
    /// A USB transfer (control or endpoint configuration) failed.
    Transfer,
}

// ── Line settings ─────────────────────────────────────────────────

/// A complete line configuration — the termios-shaped surface the
/// transfer layer programs onto the device.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LineSettings {
    pub baud: u32,
    pub data_bits: DataBits,
    pub parity: Parity,
    pub stop_bits: StopBits,
    pub flow: FlowControl,
    /// Assert DTR after configuration.
    pub dtr: bool,
    /// Assert RTS after configuration.
    pub rts: bool,
}

impl Default for LineSettings {
    /// 115200 8N1, no flow control, DTR + RTS asserted — the
    /// dev-board default the CDC-ACM binder also uses.
    fn default() -> Self {
        LineSettings {
            baud: 115_200,
            data_bits: DataBits::Eight,
            parity: Parity::None,
            stop_bits: StopBits::One,
            flow: FlowControl::None,
            dtr: true,
            rts: true,
        }
    }
}

// ── Control-transfer plans ────────────────────────────────────────

/// One host-to-device control transfer with its data stage
/// (possibly empty). Plans are ordered lists of these; executing a
/// plan means issuing the transfers in order and stopping at the
/// first failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlXfer {
    pub bm_request_type: u8,
    pub b_request: u8,
    pub w_value: u16,
    pub w_index: u16,
    pub data: Vec<u8>,
}

impl ControlXfer {
    pub fn new(bm_request_type: u8, b_request: u8, w_value: u16, w_index: u16) -> Self {
        ControlXfer {
            bm_request_type,
            b_request,
            w_value,
            w_index,
            data: Vec::new(),
        }
    }

    pub fn with_data(
        bm_request_type: u8,
        b_request: u8,
        w_value: u16,
        w_index: u16,
        data: &[u8],
    ) -> Self {
        let mut x = Self::new(bm_request_type, b_request, w_value, w_index);
        x.data.extend_from_slice(data);
        x
    }
}

/// FTDI chip generation for a product ID. The H parts are the
/// multi-port / high-speed ones; everything else in the dispatch
/// table is a BM/R-generation part.
fn ftdi_chip_for_pid(pid: u16) -> ftdi::ChipType {
    match pid {
        // FT2232H, FT4232H, FT232H, FT4233HP — 120 MHz H generation.
        0x6010 | 0x6011 | 0x6014 | 0x6048 => ftdi::ChipType::H,
        _ => ftdi::ChipType::Bm,
    }
}

/// The transfers that initialise a family before configuration:
/// FTDI port reset, CP210x UART enable, PL2303 reset release,
/// CH341 serial init.
fn init_prefix(family: ChipFamily) -> Vec<ControlXfer> {
    match family {
        // FTDI AN232B: RESET request, wValue 0 = reset the port.
        ChipFamily::Ftdi => alloc::vec![ControlXfer::new(
            ftdi::RT_HOST_TO_DEV,
            ftdi::REQ_RESET,
            0,
            0,
        )],
        // AN571: IFC_ENABLE with UART_ENABLE before any other
        // configuration takes effect. wIndex = interface (patched
        // in by configure_plan's caller via open_plan).
        ChipFamily::Cp210x => alloc::vec![ControlXfer::new(
            cp210x::REQTYPE_HOST_TO_INTERFACE,
            cp210x::IFC_ENABLE,
            cp210x::UART_ENABLE,
            0,
        )],
        // PL2303 startup: vendor-write register 0x0404 = 0 then 1
        // to release the power-on-reset state.
        ChipFamily::Pl2303 => {
            let (rt, req, reg, val0, _) = pl2303::setup_vendor_write(pl2303::INIT_REG, 0);
            let (_, _, _, val1, _) = pl2303::setup_vendor_write(pl2303::INIT_REG, 1);
            alloc::vec![
                ControlXfer::new(rt, req, reg, val0),
                ControlXfer::new(rt, req, reg, val1),
            ]
        }
        // CH341: SERIAL_INIT with wValue = wIndex = 0 (the Linux
        // ch341_configure form), priming the register interface.
        ChipFamily::Ch341 => alloc::vec![ControlXfer::new(
            ch341::RT_HOST_TO_DEV_VENDOR,
            ch341::REQ_SERIAL_INIT,
            0,
            0,
        )],
    }
}

/// The ordered control transfers that make a device match
/// `settings` (baud, line format, modem lines, flow). Pure: the
/// same function feeds the binder, the reconfiguration path, and
/// the fixture tests. `pid` selects the FTDI divisor generation;
/// `iface` is the USB interface number the family protocols index
/// by (FTDI channel 0 = first port in this layer).
pub fn configure_plan(
    family: ChipFamily,
    pid: u16,
    iface: u8,
    settings: &LineSettings,
) -> Result<Vec<ControlXfer>, PortError> {
    let mut plan = Vec::new();
    match family {
        ChipFamily::Ftdi => {
            if settings.baud == 0 {
                return Err(PortError::UnsupportedBaud(0));
            }
            let chip = ftdi_chip_for_pid(pid);
            let packed = match chip {
                ftdi::ChipType::H => ftdi::calc_divisor_h(settings.baud),
                _ => ftdi::calc_divisor_bm(settings.baud),
            };
            let (wv, wi) = ftdi::divisor_to_wvalue_windex(packed, 0);
            plan.push(ControlXfer::new(
                ftdi::RT_HOST_TO_DEV,
                ftdi::REQ_SET_BAUD_RATE,
                wv,
                wi,
            ));
            plan.push(ControlXfer::new(
                ftdi::RT_HOST_TO_DEV,
                ftdi::REQ_SET_DATA,
                ftdi::encode_data_format(settings.data_bits, settings.parity, settings.stop_bits),
                0,
            ));
            plan.push(ControlXfer::new(
                ftdi::RT_HOST_TO_DEV,
                ftdi::REQ_MODEM_CTRL,
                ftdi::encode_modem_ctrl(settings.dtr, settings.rts),
                0,
            ));
            let flow_bits = match settings.flow {
                FlowControl::None => ftdi::FLOW_DISABLE,
                FlowControl::RtsCts => ftdi::FLOW_RTS_CTS,
                FlowControl::XonXoff => ftdi::FLOW_XON_XOFF,
            };
            plan.push(ControlXfer::new(
                ftdi::RT_HOST_TO_DEV,
                ftdi::REQ_SET_FLOW_CTRL,
                0,
                flow_bits,
            ));
        }
        ChipFamily::Cp210x => {
            if settings.flow != FlowControl::None {
                // AN571 SET_FLOW (0x13) writes a 16-byte flow
                // structure that is not modelled yet; refuse rather
                // than silently dropping the request.
                return Err(PortError::Unsupported("cp210x set-flow (AN571 SET_FLOW)"));
            }
            let (rt, req, wv, wi, data) = cp210x::build_set_baudrate(settings.baud, iface);
            plan.push(ControlXfer::with_data(rt, req, wv, wi, &data));
            let (rt, req, wv, wi, _) = cp210x::build_set_line_ctl(
                settings.data_bits,
                settings.parity,
                settings.stop_bits,
                iface,
            );
            plan.push(ControlXfer::new(rt, req, wv, wi));
            plan.push(ControlXfer::new(
                cp210x::REQTYPE_HOST_TO_INTERFACE,
                cp210x::SET_MHS,
                cp210x::encode_modem_ctrl(settings.dtr, settings.rts),
                iface as u16,
            ));
        }
        ChipFamily::Pl2303 => {
            if settings.flow != FlowControl::None {
                return Err(PortError::Unsupported("pl2303 set-flow"));
            }
            let (rt, req, wv, wi, _) = pl2303::setup_set_line_coding();
            let coding = pl2303::build_line_coding(
                settings.baud,
                settings.data_bits,
                settings.parity,
                settings.stop_bits,
            );
            plan.push(ControlXfer::with_data(rt, req, wv, wi, &coding));
            // SET_CONTROL_LINE_STATE (CDC PSTN §6.3.12, the form
            // pl2303 uses): wValue bit 0 = DTR, bit 1 = RTS.
            let mut lines: u16 = 0;
            if settings.dtr {
                lines |= 0x0001;
            }
            if settings.rts {
                lines |= 0x0002;
            }
            plan.push(ControlXfer::new(0x21, 0x22, lines, iface as u16));
        }
        ChipFamily::Ch341 => {
            if settings.baud == 0 || ch341::calc_divisor(settings.baud).is_none() {
                return Err(PortError::UnsupportedBaud(settings.baud));
            }
            if settings.flow != FlowControl::None {
                return Err(PortError::Unsupported("ch341 set-flow"));
            }
            let words = ch341::baud_control_words(settings.baud)
                .ok_or(PortError::UnsupportedBaud(settings.baud))?;
            for (reg, word) in words {
                plan.push(ControlXfer::new(
                    ch341::RT_HOST_TO_DEV_VENDOR,
                    ch341::REQ_WRITE_REG,
                    reg,
                    word,
                ));
            }
            let (reg, word) =
                ch341::lcr_control_word(settings.data_bits, settings.parity, settings.stop_bits);
            plan.push(ControlXfer::new(
                ch341::RT_HOST_TO_DEV_VENDOR,
                ch341::REQ_WRITE_REG,
                reg,
                word,
            ));
            plan.push(ControlXfer::new(
                ch341::RT_HOST_TO_DEV_VENDOR,
                ch341::REQ_MODEM_CTRL,
                ch341::encode_modem_ctrl(settings.dtr, settings.rts),
                0,
            ));
        }
    }
    Ok(plan)
}

/// The full open sequence: family init prefix followed by the
/// configure plan for `settings`.
pub fn open_plan(
    family: ChipFamily,
    pid: u16,
    iface: u8,
    settings: &LineSettings,
) -> Result<Vec<ControlXfer>, PortError> {
    let mut plan = init_prefix(family);
    // CP210x IFC_ENABLE is indexed by interface; the prefix is
    // built with wIndex 0, so patch it for the bound interface.
    if family == ChipFamily::Cp210x {
        for x in plan.iter_mut() {
            x.w_index = iface as u16;
        }
    }
    plan.extend(configure_plan(family, pid, iface, settings)?);
    Ok(plan)
}

/// The control-IN request that reads the modem status byte(s) for
/// families that poll it: `(bmRequestType, bRequest, wValue,
/// wIndex, wLength)`. FTDI and CP210x poll; PL2303 and CH341
/// deliver status on their interrupt-IN endpoints instead, so they
/// return `None`.
pub fn modem_status_request(family: ChipFamily, iface: u8) -> Option<(u8, u8, u16, u16, u16)> {
    match family {
        ChipFamily::Ftdi => Some((ftdi::RT_DEV_TO_HOST, ftdi::REQ_GET_MODEM_STATUS, 0, 0, 2)),
        ChipFamily::Cp210x => Some((
            cp210x::REQTYPE_INTERFACE_TO_HOST,
            cp210x::GET_MDMSTS,
            0,
            iface as u16,
            1,
        )),
        ChipFamily::Pl2303 | ChipFamily::Ch341 => None,
    }
}

/// Decode a modem-status byte with the family's codec. For FTDI
/// this is byte 0 of the GET_MODEM_STATUS response — the same
/// RS0 layout as the bulk-IN status prefix.
pub fn decode_modem_byte(family: ChipFamily, byte: u8) -> ModemStatus {
    match family {
        ChipFamily::Ftdi => ftdi::decode_modem_status(byte),
        ChipFamily::Cp210x => cp210x::decode_modem_status(byte),
        ChipFamily::Pl2303 => pl2303::decode_modem_status(byte),
        ChipFamily::Ch341 => ch341::decode_modem_status(byte),
    }
}

/// Split one received bulk-IN packet into its payload range,
/// updating `modem` from any status prefix the family carries.
/// FTDI prefixes every packet with 2 status bytes (AN232B); the
/// other families' bulk streams are raw payload. A short FTDI
/// packet (< 2 bytes) is framing garbage: the returned range is
/// empty.
pub fn ingest_rx(family: ChipFamily, packet: &[u8], modem: &mut ModemStatus) -> (usize, usize) {
    match family {
        ChipFamily::Ftdi => {
            if packet.len() < 2 {
                return (0, 0);
            }
            *modem = ftdi::decode_modem_status(packet[0]);
            (2, packet.len())
        }
        _ => (0, packet.len()),
    }
}

// ── Endpoint discovery ────────────────────────────────────────────

/// The endpoints of the first vendor-serial interface in a
/// configuration: one bulk-IN / bulk-OUT pair plus an optional
/// interrupt-IN (modem-status notifications on PL2303 / CP210x /
/// CH341; FTDI carries status in its bulk stream instead).
#[derive(Copy, Clone, Debug)]
pub struct SerialEndpoints {
    pub iface: u8,
    pub bulk_in: EndpointConfig,
    pub bulk_out: EndpointConfig,
    pub intr_in: Option<EndpointConfig>,
}

/// Walk a configuration-descriptor blob for the first interface
/// with `bInterfaceClass == 0xFF` (vendor-specific) that carries a
/// bulk pair, and return its endpoints. Interfaces of any other
/// class are walked past without their endpoints being considered
/// — a composite device's CDC data interface must never be claimed
/// as the serial port. Malformed or truncated blobs yield `None`.
pub fn find_serial_endpoints(cfg: &[u8]) -> Option<SerialEndpoints> {
    let mut i = 0usize;
    let mut cur_iface: Option<u8> = None;
    let mut cur_is_vendor = false;
    let mut bulk_in: Option<EndpointConfig> = None;
    let mut bulk_out: Option<EndpointConfig> = None;
    let mut intr_in: Option<EndpointConfig> = None;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            return None;
        }
        let dtype = cfg[i + 1];
        match dtype {
            // Interface descriptor (USB 2.0 §9.6.5): bLength 9,
            // bInterfaceNumber at +2, bInterfaceClass at +5.
            0x04 if len >= 9 => {
                // A new interface closes the previous one: if it
                // completed a vendor bulk pair, it wins (first
                // complete vendor interface is the bound port).
                if cur_is_vendor && bulk_in.is_some() && bulk_out.is_some() {
                    return Some(SerialEndpoints {
                        iface: cur_iface?,
                        bulk_in: bulk_in?,
                        bulk_out: bulk_out?,
                        intr_in,
                    });
                }
                cur_iface = Some(cfg[i + 2]);
                cur_is_vendor = cfg[i + 5] == 0xFF;
                bulk_in = None;
                bulk_out = None;
                intr_in = None;
            }
            // Endpoint descriptor (USB 2.0 §9.6.6): bLength 7,
            // bEndpointAddress at +2, bmAttributes at +3
            // (bits 1:0 transfer type: 2 = bulk, 3 = interrupt),
            // wMaxPacketSize at +4.
            0x05 if len >= 7 && cur_is_vendor => {
                let addr = cfg[i + 2];
                let xfer = cfg[i + 3] & 0x03;
                let max_packet = u16::from_le_bytes([cfg[i + 4], cfg[i + 5]]);
                let is_in = addr & 0x80 != 0;
                let interval = if len >= 9 { cfg[i + 6] } else { 0 };
                match (xfer, is_in) {
                    (2, true) => {
                        if bulk_in.is_none() {
                            bulk_in = Some(EndpointConfig {
                                ep_addr: addr,
                                max_packet,
                                kind: EndpointKind::BulkIn,
                                interval,
                            });
                        }
                    }
                    (2, false) => {
                        if bulk_out.is_none() {
                            bulk_out = Some(EndpointConfig {
                                ep_addr: addr,
                                max_packet,
                                kind: EndpointKind::BulkOut,
                                interval,
                            });
                        }
                    }
                    (3, true) => {
                        if intr_in.is_none() {
                            intr_in = Some(EndpointConfig {
                                ep_addr: addr,
                                max_packet,
                                kind: EndpointKind::InterruptIn,
                                interval,
                            });
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        i += len;
    }
    if cur_is_vendor && bulk_in.is_some() && bulk_out.is_some() {
        return Some(SerialEndpoints {
            iface: cur_iface?,
            bulk_in: bulk_in?,
            bulk_out: bulk_out?,
            intr_in,
        });
    }
    None
}

// ── Bound ports ───────────────────────────────────────────────────

/// One bound vendor-serial device. Held in [`SERIAL_PORTS`];
/// `tty_index` keys the shared devfs [`devfs_bridge::SerialPort`]
/// whose rings the pump drains and fills.
#[derive(Debug)]
pub struct BoundPort {
    pub slot_id: u8,
    pub family: ChipFamily,
    pub pid: u16,
    pub tty_index: usize,
    pub iface: u8,
    pub bulk_in_dci: u8,
    pub bulk_out_dci: u8,
    /// Last line configuration programmed onto the device.
    pub settings: LineSettings,
    /// Latest modem-status snapshot (FTDI: from the bulk-IN
    /// status prefix; polled families: via GET_MDMSTS).
    pub modem: ModemStatus,
    /// (hub registry index, downstream port) this device sits
    /// behind, when bound through a hub — the wake target for
    /// runtime hub-port resume (#763, mirroring #840 for HID).
    /// `None` for root-hub devices, which have no downstream
    /// port to suspend.
    pub hub_port: Option<(u8, u8)>,
}

/// Global registry of bound vendor-serial ports, mirroring
/// `cdc_acm::ACM_DEVICES`.
static SERIAL_PORTS: IrqSafeSpinLock<Vec<BoundPort>> = IrqSafeSpinLock::new(Vec::new());

/// Number of currently bound vendor-serial ports.
pub fn bound_count() -> usize {
    SERIAL_PORTS.lock().len()
}

/// Transport seam for executing control plans: anything that can
/// issue a host-to-device control transfer on a bound slot. The
/// production implementation is the xHCI controller; fixtures
/// implement it with a recording fake so plan execution (order,
/// stop-at-first-failure, per-slot routing) is testable without
/// silicon. Same async-trait shape as the thunderbolt `Config`
/// seam (which carries the same allow).
#[allow(async_fn_in_trait)]
pub trait ControlTransport {
    /// Issue one control-OUT transfer. `Err(PortError::Transfer)`
    /// is the typed failure — a dead or refusing slot is an error
    /// value, never a panic.
    async fn control_out(
        &self,
        slot_id: u8,
        bm_request_type: u8,
        b_request: u8,
        w_value: u16,
        w_index: u16,
        data: &[u8],
    ) -> Result<(), PortError>;
}

impl ControlTransport for Xhci {
    async fn control_out(
        &self,
        slot_id: u8,
        bm_request_type: u8,
        b_request: u8,
        w_value: u16,
        w_index: u16,
        data: &[u8],
    ) -> Result<(), PortError> {
        Xhci::control_out(
            self,
            slot_id,
            bm_request_type,
            b_request,
            w_value,
            w_index,
            data,
        )
        .await
        .map(|_| ())
        .map_err(|_| PortError::Transfer)
    }
}

/// Execute a control plan against a live device, in order,
/// stopping at the first failed transfer.
pub async fn apply_plan<T: ControlTransport + ?Sized>(
    transport: &T,
    slot_id: u8,
    plan: &[ControlXfer],
) -> Result<(), PortError> {
    for x in plan {
        transport
            .control_out(
                slot_id,
                x.bm_request_type,
                x.b_request,
                x.w_value,
                x.w_index,
                &x.data,
            )
            .await?;
    }
    Ok(())
}

/// Attach-cascade step for vendor USB-serial adapters. The caller
/// has already addressed the device; on success the port is
/// configured at the [`LineSettings::default`] line format,
/// published as `/dev/ttyUSB<N>`, and registered for the
/// supervisor pump. Returns the ttyUSB index. On failure the
/// caller keeps slot-lifecycle ownership (the dispatcher disables
/// the slot), matching the other class binders.
pub async fn try_bind_serial_already_addressed(
    xhci_dev: &Xhci,
    slot_id: u8,
    vid: u16,
    pid: u16,
    cfg: &[u8],
    hub_port: Option<(u8, u8)>,
) -> Result<usize, PortError> {
    let family = super::identify(vid, pid).ok_or(PortError::UnknownDevice)?;
    let eps = find_serial_endpoints(cfg).ok_or(PortError::NoSerialInterface)?;

    let mut ep_list: Vec<EndpointConfig> = alloc::vec![eps.bulk_in, eps.bulk_out];
    if let Some(intr) = eps.intr_in {
        ep_list.push(intr);
    }
    xhci_dev
        .configure_endpoints(slot_id, &ep_list)
        .await
        .map_err(|_| PortError::Transfer)?;

    // SET_CONFIGURATION before any class/vendor request (USB 2.0
    // §9.4.7) — the configuration value is byte 5 of the
    // configuration descriptor header.
    if cfg.len() < 9 || cfg[1] != 0x02 {
        return Err(PortError::NoSerialInterface);
    }
    xhci_dev
        .control_out(
            slot_id,
            0x00,
            crate::hid::STD_REQ_SET_CONFIGURATION,
            cfg[5] as u16,
            0,
            &[],
        )
        .await
        .map_err(|_| PortError::Transfer)?;

    let settings = LineSettings::default();
    let plan = open_plan(family, pid, eps.iface, &settings)?;
    apply_plan(xhci_dev, slot_id, &plan).await?;

    let bulk_in_dci = crate::bulk::dci_for(eps.bulk_in.ep_addr);
    let bulk_out_dci = crate::bulk::dci_for(eps.bulk_out.ep_addr);
    // Pre-arm the bulk-IN endpoint so the controller polls the
    // device for bytes — the same persistent-arm pattern the
    // CDC-ACM binder uses for its bulk-IN.
    xhci_dev
        .arm_interrupt_in(slot_id, bulk_in_dci, eps.bulk_in.max_packet.min(64) as u32)
        .map_err(|_| PortError::Transfer)?;

    let tty_index = devfs_bridge::register_tty_usb(family);
    // No lock is held across any .await above; the registry lock
    // is taken only for this final synchronous push.
    SERIAL_PORTS.lock().push(BoundPort {
        slot_id,
        family,
        pid,
        tty_index,
        iface: eps.iface,
        bulk_in_dci,
        bulk_out_dci,
        settings,
        modem: ModemStatus::default(),
        hub_port,
    });
    Ok(tty_index)
}

/// Reprogram a bound port's line configuration on the live
/// device (the production path behind future termios ioctls,
/// #756). The plan is computed from the family's codec encoders
/// and replayed in full; the cached settings update only after
/// every transfer succeeds, so a failed reconfiguration leaves
/// the cache describing the state the device is actually in.
pub async fn set_line_settings(
    xhci_dev: &Xhci,
    slot_id: u8,
    settings: LineSettings,
) -> Result<(), PortError> {
    let (family, pid, iface) = {
        let g = SERIAL_PORTS.lock();
        let p = g
            .iter()
            .find(|p| p.slot_id == slot_id)
            .ok_or(PortError::UnknownDevice)?;
        (p.family, p.pid, p.iface)
    };
    let plan = configure_plan(family, pid, iface, &settings)?;
    apply_plan(xhci_dev, slot_id, &plan).await?;
    let mut g = SERIAL_PORTS.lock();
    if let Some(p) = g.iter_mut().find(|p| p.slot_id == slot_id) {
        p.settings = settings;
    }
    Ok(())
}

/// Poll a bound port's modem status over the control pipe
/// (FTDI / CP210x) and refresh the cache. Returns the fresh
/// snapshot, or `None` for families that report status on their
/// interrupt-IN endpoint instead.
pub async fn refresh_modem_status(xhci_dev: &Xhci, slot_id: u8) -> Option<ModemStatus> {
    let (family, iface) = {
        let g = SERIAL_PORTS.lock();
        let p = g.iter().find(|p| p.slot_id == slot_id)?;
        (p.family, p.iface)
    };
    let (rt, req, wv, wi, len) = modem_status_request(family, iface)?;
    let mut buf = [0u8; 2];
    let n = xhci_dev
        .control_in(slot_id, rt, req, wv, wi, &mut buf[..len as usize])
        .await
        .ok()?;
    if n == 0 {
        return None;
    }
    let status = decode_modem_byte(family, buf[0]);
    let mut g = SERIAL_PORTS.lock();
    if let Some(p) = g.iter_mut().find(|p| p.slot_id == slot_id) {
        p.modem = status;
    }
    Some(status)
}

/// Detach the vendor-serial port bound to `slot_id`: drop the
/// binding (so the pump stops polling the dead slot) and withdraw
/// the `/dev/ttyUSB<N>` publication. Returns true when a binding
/// was removed.
pub fn detach_serial(slot_id: u8) -> bool {
    let removed = {
        let mut g = SERIAL_PORTS.lock();
        let before = g.len();
        let mut indices = Vec::new();
        g.retain(|p| {
            if p.slot_id == slot_id {
                indices.push(p.tty_index);
                false
            } else {
                true
            }
        });
        if g.len() != before {
            Some(indices)
        } else {
            None
        }
    };
    match removed {
        Some(indices) => {
            for idx in indices {
                devfs_bridge::unregister_tty_usb(idx);
            }
            true
        }
        None => false,
    }
}

/// Drop every vendor-serial binding and publication. Called on a
/// controller recovery epoch change, mirroring
/// `cdc_acm::clear_acm`.
pub fn clear_serial() {
    let indices: Vec<usize> = {
        let mut g = SERIAL_PORTS.lock();
        let v: Vec<usize> = g.iter().map(|p| p.tty_index).collect();
        g.clear();
        v
    };
    for idx in indices {
        devfs_bridge::unregister_tty_usb(idx);
    }
}

// ── Suspend / resume (system PM) ──────────────────────────────────
//
// #763: before this lane nothing replayed vendor-serial state
// after S3 — the bind-time open plan ran once, ever, so a dongle
// that lost power in S3 came back with its UART at power-on
// defaults and DTR dropped. The class registers an async
// system-PM hook (`narf_power::system_pm`): prepare latches the
// pump quiesced before the synchronous device fan-out gates the
// controller; resume (which runs after the fan-out restored
// xHCI) replays every bound port's open plan rebuilt from its
// retained `settings`. State is saved continuously —
// `set_line_settings` commits the cache only after the plan
// fully applies — so prepare has nothing to snapshot.

/// Pump quiesce latch: set by the PM prepare hook, cleared when
/// the resume replay settles. While set, `pump_all` leaves every
/// endpoint alone.
static PM_SUSPENDED: AtomicBool = AtomicBool::new(false);

/// True while the class is quiesced for system suspend.
pub fn pm_quiesced() -> bool {
    PM_SUSPENDED.load(Ordering::SeqCst)
}

fn pm_prepare() {
    PM_SUSPENDED.store(true, Ordering::SeqCst);
}

fn pm_finish_resume() {
    PM_SUSPENDED.store(false, Ordering::SeqCst);
}

/// The resume work list: for every bound port, its bind-time
/// open plan rebuilt from the retained settings — the exact
/// sequence bind issued (family init prefix + configure plan,
/// modem lines included), in registry order. Pure: built under
/// the registry lock, executed after it is dropped.
pub fn resume_snapshot() -> Vec<(u8, Result<Vec<ControlXfer>, PortError>)> {
    let g = SERIAL_PORTS.lock();
    g.iter()
        .map(|p| (p.slot_id, open_plan(p.family, p.pid, p.iface, &p.settings)))
        .collect()
}

/// Replay every bound port's saved state over `transport`. A
/// port that detached while suspended is absent from the
/// snapshot and gets no replay; a port whose slot refuses the
/// transfers fails typed (`DriverError`) without stopping the
/// remaining ports' replays.
pub async fn resume_replay<T: ControlTransport + ?Sized>(
    transport: &T,
) -> Result<(), narf_power::device_pm::DeviceSuspendError> {
    let mut failed = false;
    for (slot_id, plan) in resume_snapshot() {
        match plan {
            Ok(plan) => {
                if apply_plan(transport, slot_id, &plan).await.is_err() {
                    failed = true;
                }
            }
            Err(_) => failed = true,
        }
    }
    if failed {
        Err(narf_power::device_pm::DeviceSuspendError::DriverError)
    } else {
        Ok(())
    }
}

struct UsbSerialPm;

impl narf_power::system_pm::AsyncSystemPm for UsbSerialPm {
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
                    if bound_count() == 0 {
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
    narf_power::system_pm::register_async_system_pm("usb-serial", Arc::new(UsbSerialPm));
}

/// (hub index, port) pairs with a live vendor-serial binding —
/// the pure-filter input for the supervisor's hub-port wake
/// step.
pub fn hub_ports() -> Vec<(u8, u8)> {
    let mut v: Vec<(u8, u8)> = {
        let g = SERIAL_PORTS.lock();
        g.iter().filter_map(|p| p.hub_port).collect()
    };
    v.sort_unstable();
    v.dedup();
    v
}

/// Supervisor wake step for hub-attached vendor serial, run
/// immediately before `pump_all` each cycle (#763; the #840 HID
/// pattern). A suspended hub port gates the device's endpoints,
/// so a serial dongle behind an autosuspended port would stay
/// dead even though it is bound and pumped every cycle. The
/// wake opens a fresh idle window, so a silent device
/// re-suspends after a full idle window rather than being held
/// awake.
pub async fn resume_suspended_hub_ports(xhci_dev: &Xhci) {
    // Collect binding contexts first, then snapshot the hub
    // registry — never hold HUBS across the serial registry lock
    // (the pumps nest the other way via `mark_port_activity`).
    let ports = hub_ports();
    let targets = {
        let g = crate::attach::HUBS.lock();
        crate::attach::suspended_ports_among(&g[..], &ports)
    };
    for (hub_slot, port) in targets {
        crate::attach::resume_port(xhci_dev, hub_slot, port).await;
        if !crate::attach::hub_port_is_suspended(hub_slot, port) {
            crate::attach::mark_port_activity(hub_slot, port);
        }
    }
}

// ── Supervisor pump ───────────────────────────────────────────────

/// Drain and fill every bound port once. Called from the USB
/// supervisor cycle alongside `cdc_acm::pump_all`.
///
/// RX: completed bulk-IN packets are polled (persistent-arm,
/// non-blocking); FTDI packets have their 2-byte status prefix
/// stripped into the modem cache before the payload lands in the
/// tty RX ring. TX: up to one 64-byte chunk per port is peeked
/// from the tty TX ring and submitted as a bulk-OUT; the bytes
/// are only removed from the ring once the controller reports
/// the transfer complete, so a chunk that has not finished is
/// retried next cycle rather than dropped. All controller calls
/// here are non-blocking polls — no lock in this module is ever
/// held across an `.await` (there are none in this function).
pub fn pump_all(xhci_dev: &Xhci) -> usize {
    // Quiesced for system suspend (#763): the PM prepare hook
    // latches this before the controller fan-out; leave every
    // endpoint alone until the resume replay settles.
    if pm_quiesced() {
        return 0;
    }
    let mut moved = 0usize;
    let mut ports = SERIAL_PORTS.lock();
    for port in ports.iter_mut() {
        let tty = match devfs_bridge::get_port(port.tty_index) {
            Some(t) => t,
            None => continue,
        };
        // ── RX ──
        let mut buf = [0u8; 64];
        while let Ok(Some(n)) = xhci_dev.poll_interrupt_in(port.slot_id, port.bulk_in_dci, &mut buf)
        {
            let n = n.min(buf.len());
            let (lo, hi) = ingest_rx(port.family, &buf[..n], &mut port.modem);
            if hi > lo {
                moved += tty.lock().rx.push(&buf[lo..hi]);
            }
        }
        // ── TX ──
        let mut chunk = [0u8; 64];
        let pending = tty.lock().tx.peek(&mut chunk);
        if pending > 0 {
            if let Some(generation) = xhci_dev.device_generation(port.slot_id) {
                if let Ok(token) = xhci_dev.begin_bulk_out(
                    port.slot_id,
                    port.bulk_out_dci,
                    generation,
                    &chunk[..pending],
                ) {
                    // Bounded non-blocking completion poll; an
                    // unfinished chunk stays queued for next cycle.
                    for _ in 0..512 {
                        match xhci_dev.poll_bulk_out(&token) {
                            Ok(Some(sent)) => {
                                tty.lock().tx.skip(sent.min(pending));
                                moved += sent;
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
    moved
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // ── Descriptor blob builders (USB 2.0 §9.6 layouts) ──────

    fn cfg_header(total: u16, num_ifaces: u8) -> Vec<u8> {
        let mut v = alloc::vec![9u8, 0x02];
        v.extend_from_slice(&total.to_le_bytes());
        v.push(num_ifaces);
        v.push(1); // bConfigurationValue
        v.push(0); // iConfiguration
        v.push(0x80); // bmAttributes
        v.push(50); // bMaxPower
        v
    }

    fn iface_desc(num: u8, class: u8, num_eps: u8) -> Vec<u8> {
        alloc::vec![9, 0x04, num, 0, num_eps, class, 0, 0, 0]
    }

    fn ep_desc(addr: u8, xfer: u8, max_packet: u16) -> Vec<u8> {
        let mut v = alloc::vec![7, 0x05, addr, xfer];
        v.extend_from_slice(&max_packet.to_le_bytes());
        v.push(0);
        v
    }

    fn blob(parts: &[Vec<u8>]) -> Vec<u8> {
        let total: usize = parts.iter().map(|p| p.len()).sum();
        let mut out = cfg_header(total as u16, 0);
        // num_ifaces byte is cosmetic for the walker; leave as built.
        for p in parts {
            out.extend_from_slice(p);
        }
        out
    }

    /// FT232R-shaped blob: one vendor interface, bulk IN 0x81 /
    /// bulk OUT 0x02 (the FT232R's real endpoint addresses).
    fn ftdi_blob() -> Vec<u8> {
        blob(&[
            iface_desc(0, 0xFF, 2),
            ep_desc(0x81, 2, 64),
            ep_desc(0x02, 2, 64),
        ])
    }

    // ── Plan pinning: FTDI ───────────────────────────────────

    fn smoke_ftdi_open_plan_byte_exact() -> TestResult {
        // FT232R (0403:6001), default settings 115200 8N1, DTR+RTS.
        // Baud: AN120 divisor for 115200 against the 3 MHz
        // effective base is 26.04 → divisor3 208 → packed 0x001A
        // (the value Linux ftdi_sio programs; wValue 0x001A,
        // wIndex 0x0000 on channel 0).
        let plan = match open_plan(ChipFamily::Ftdi, 0x6001, 0, &LineSettings::default()) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("FTDI open plan should build"),
        };
        let expect: [(u8, u8, u16, u16); 5] = [
            (0x40, ftdi::REQ_RESET, 0x0000, 0x0000),
            (0x40, ftdi::REQ_SET_BAUD_RATE, 0x001A, 0x0000),
            (0x40, ftdi::REQ_SET_DATA, 0x0008, 0x0000),
            (0x40, ftdi::REQ_MODEM_CTRL, 0x0303, 0x0000),
            (0x40, ftdi::REQ_SET_FLOW_CTRL, 0x0000, 0x0000),
        ];
        if plan.len() != expect.len() {
            return TestResult::Fail("FTDI open plan length wrong");
        }
        for (got, want) in plan.iter().zip(expect.iter()) {
            if got.bm_request_type != want.0
                || got.b_request != want.1
                || got.w_value != want.2
                || got.w_index != want.3
                || !got.data.is_empty()
            {
                return TestResult::Fail("FTDI open plan transfer mismatch");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/serial/port", smoke_ftdi_open_plan_byte_exact);

    fn smoke_ftdi_h_series_baud_pinned() -> TestResult {
        // FT2232H (0403:6010) at 115200: H divisor against the
        // 12 MHz effective base is 104.17 → divisor3 833 → packed
        // 0xC068 with the 120 MHz clock-select bit 0x20000 →
        // wValue 0xC068, wIndex 0x0002.
        let plan = match configure_plan(ChipFamily::Ftdi, 0x6010, 0, &LineSettings::default()) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("FTDI H configure plan should build"),
        };
        let baud = &plan[0];
        if baud.b_request != ftdi::REQ_SET_BAUD_RATE
            || baud.w_value != 0xC068
            || baud.w_index != 0x0002
        {
            return TestResult::Fail("FTDI H baud wValue/wIndex mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/serial/port", smoke_ftdi_h_series_baud_pinned);

    // ── Plan pinning: CP210x ─────────────────────────────────

    fn smoke_cp210x_open_plan_byte_exact() -> TestResult {
        // CP2102 (10C4:EA60) on interface 0, default settings.
        // AN571: IFC_ENABLE(UART_ENABLE) → SET_BAUDRATE with the
        // rate as a 4-byte LE data stage (115200 = 00 C2 01 00) →
        // SET_LINE_CTL wValue 0x0800 (8N1) → SET_MHS 0x0303
        // (WRITE_DTR|WRITE_RTS|DTR|RTS).
        let plan = match open_plan(ChipFamily::Cp210x, 0xEA60, 0, &LineSettings::default()) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("CP210x open plan should build"),
        };
        if plan.len() != 4 {
            return TestResult::Fail("CP210x open plan length wrong");
        }
        let ifc = &plan[0];
        if ifc.bm_request_type != 0x41
            || ifc.b_request != cp210x::IFC_ENABLE
            || ifc.w_value != cp210x::UART_ENABLE
            || ifc.w_index != 0
        {
            return TestResult::Fail("CP210x IFC_ENABLE mismatch");
        }
        let baud = &plan[1];
        if baud.bm_request_type != 0x41
            || baud.b_request != cp210x::SET_BAUDRATE
            || baud.w_value != 0
            || baud.w_index != 0
            || baud.data != alloc::vec![0x00, 0xC2, 0x01, 0x00]
        {
            return TestResult::Fail("CP210x SET_BAUDRATE mismatch (divisor bytes)");
        }
        let line = &plan[2];
        if line.b_request != cp210x::SET_LINE_CTL || line.w_value != 0x0800 {
            return TestResult::Fail("CP210x SET_LINE_CTL 8N1 mismatch");
        }
        let mhs = &plan[3];
        if mhs.b_request != cp210x::SET_MHS || mhs.w_value != 0x0303 {
            return TestResult::Fail("CP210x SET_MHS mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/serial/port", smoke_cp210x_open_plan_byte_exact);

    fn smoke_cp210x_line_plan_7e2_and_baud_57600() -> TestResult {
        // The two families' framing must not share assumptions:
        // CP210x line format is one packed wValue (7E2 = 0x0722)
        // and its baud is a raw Hz data stage (57600 = 00 E1 00
        // 00), where FTDI splits a divisor across wValue/wIndex.
        let settings = LineSettings {
            baud: 57_600,
            data_bits: DataBits::Seven,
            parity: Parity::Even,
            stop_bits: StopBits::Two,
            flow: FlowControl::None,
            dtr: false,
            rts: true,
        };
        let plan = match configure_plan(ChipFamily::Cp210x, 0xEA60, 0, &settings) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("CP210x configure plan should build"),
        };
        if plan[0].data != alloc::vec![0x00, 0xE1, 0x00, 0x00] {
            return TestResult::Fail("CP210x 57600 baud data stage mismatch");
        }
        if plan[1].w_value != 0x0722 {
            return TestResult::Fail("CP210x 7E2 line-control word mismatch");
        }
        // DTR low / RTS high: WRITE bits set, only RTS value set.
        if plan[2].w_value != 0x0302 {
            return TestResult::Fail("CP210x SET_MHS DTR-low/RTS-high mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/serial/port",
        smoke_cp210x_line_plan_7e2_and_baud_57600
    );

    // ── Endpoint discovery ───────────────────────────────────

    fn smoke_serial_endpoints_ftdi_blob() -> TestResult {
        let eps = match find_serial_endpoints(&ftdi_blob()) {
            Some(e) => e,
            None => return TestResult::Fail("FTDI blob should yield endpoints"),
        };
        if eps.iface != 0 || eps.bulk_in.ep_addr != 0x81 || eps.bulk_out.ep_addr != 0x02 {
            return TestResult::Fail("FTDI endpoint selection wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/serial/port", smoke_serial_endpoints_ftdi_blob);

    fn smoke_serial_endpoints_first_of_two_vendor_interfaces() -> TestResult {
        // Masking-defeating: a dual-port CP2105-shaped blob has
        // TWO vendor interfaces with bulk pairs. The binder takes
        // the first interface's pair — and must not merge the
        // second interface's endpoints into it.
        let b = blob(&[
            iface_desc(0, 0xFF, 2),
            ep_desc(0x81, 2, 64),
            ep_desc(0x01, 2, 64),
            iface_desc(1, 0xFF, 2),
            ep_desc(0x83, 2, 64),
            ep_desc(0x03, 2, 64),
        ]);
        let eps = match find_serial_endpoints(&b) {
            Some(e) => e,
            None => return TestResult::Fail("dual-interface blob should yield endpoints"),
        };
        if eps.iface != 0 || eps.bulk_in.ep_addr != 0x81 || eps.bulk_out.ep_addr != 0x01 {
            return TestResult::Fail("first vendor interface must win");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/serial/port",
        smoke_serial_endpoints_first_of_two_vendor_interfaces
    );

    fn smoke_serial_endpoints_skips_cdc_data_pair() -> TestResult {
        // Masking-defeating: a composite blob whose FIRST bulk
        // pair belongs to a CDC Data interface (class 0x0A). The
        // vendor interface (class 0xFF) comes later; only its
        // endpoints may be selected.
        let b = blob(&[
            iface_desc(0, 0x02, 1),
            ep_desc(0x83, 3, 16),
            iface_desc(1, 0x0A, 2),
            ep_desc(0x82, 2, 64),
            ep_desc(0x03, 2, 64),
            iface_desc(2, 0xFF, 2),
            ep_desc(0x84, 2, 64),
            ep_desc(0x04, 2, 64),
        ]);
        let eps = match find_serial_endpoints(&b) {
            Some(e) => e,
            None => return TestResult::Fail("composite blob should yield vendor endpoints"),
        };
        if eps.iface != 2 || eps.bulk_in.ep_addr != 0x84 || eps.bulk_out.ep_addr != 0x04 {
            return TestResult::Fail("CDC data pair must not be claimed as serial");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/serial/port",
        smoke_serial_endpoints_skips_cdc_data_pair
    );

    fn smoke_serial_endpoints_malformed() -> TestResult {
        // Tampered/truncated variants must fail closed.
        let mut truncated = ftdi_blob();
        truncated.truncate(20); // cut mid endpoint descriptor
        if find_serial_endpoints(&truncated).is_some() {
            return TestResult::Fail("truncated blob must yield None");
        }
        // Vendor interface with bulk IN only (no pair).
        let half = blob(&[iface_desc(0, 0xFF, 1), ep_desc(0x81, 2, 64)]);
        if find_serial_endpoints(&half).is_some() {
            return TestResult::Fail("bulk-IN-only interface must yield None");
        }
        // Zero-length descriptor would loop a naive walker.
        let mut zero_len = ftdi_blob();
        zero_len[9] = 0;
        if find_serial_endpoints(&zero_len).is_some() {
            return TestResult::Fail("zero-length descriptor must yield None");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/serial/port", smoke_serial_endpoints_malformed);

    // ── RX framing ───────────────────────────────────────────

    fn smoke_ftdi_rx_ingest_strips_status_header() -> TestResult {
        // FTDI bulk-IN packet: [modem status 0x10 (CTS), line
        // status 0x00, 'O', 'K']. Payload is bytes 2..; the
        // status byte decodes into the modem cache.
        let mut modem = ModemStatus::default();
        let pkt = [0x10u8, 0x00, b'O', b'K'];
        let (lo, hi) = ingest_rx(ChipFamily::Ftdi, &pkt, &mut modem);
        if (lo, hi) != (2, 4) || &pkt[lo..hi] != b"OK" {
            return TestResult::Fail("FTDI payload range wrong");
        }
        if !modem.cts || modem.dsr || modem.ri || modem.dcd {
            return TestResult::Fail("FTDI status byte 0x10 must decode as CTS only");
        }
        // A 1-byte packet is framing garbage → empty range.
        let (lo, hi) = ingest_rx(ChipFamily::Ftdi, &[0x10], &mut modem);
        if lo != hi {
            return TestResult::Fail("short FTDI packet must yield empty payload");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/serial/port",
        smoke_ftdi_rx_ingest_strips_status_header
    );

    fn smoke_cp210x_rx_ingest_is_raw() -> TestResult {
        // CP210x bulk-IN has no status prefix — the same first
        // byte that FTDI would eat as status is payload here.
        let mut modem = ModemStatus::default();
        let pkt = [0x10u8, b'A'];
        let (lo, hi) = ingest_rx(ChipFamily::Cp210x, &pkt, &mut modem);
        if (lo, hi) != (0, 2) {
            return TestResult::Fail("CP210x payload must be the raw packet");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/serial/port", smoke_cp210x_rx_ingest_is_raw);

    // ── End-to-end conversation over a fake device ───────────

    /// A recording fake device: executes a plan into a transcript
    /// and hands back one scripted bulk-IN packet — the fixture
    /// half of the bind conversation.
    struct FakeDevice {
        transcript: Vec<ControlXfer>,
        rx_packet: Vec<u8>,
    }

    fn smoke_serial_bind_conversation_ftdi_end_to_end() -> TestResult {
        // Stage 1 — dispatch: the dongle's IDs select FTDI.
        let family = match super::super::identify(0x0403, 0x6001) {
            Some(f) => f,
            None => return TestResult::Fail("FT232R IDs must dispatch to FTDI"),
        };
        // Stage 2 — endpoint discovery on its config blob.
        let eps = match find_serial_endpoints(&ftdi_blob()) {
            Some(e) => e,
            None => return TestResult::Fail("conversation: endpoints missing"),
        };
        if eps.bulk_in.ep_addr != 0x81 || eps.bulk_out.ep_addr != 0x02 {
            return TestResult::Fail("conversation: endpoint pair wrong");
        }
        // Stage 3 — the open plan executes against the fake; the
        // transcript must be the spec-pinned sequence.
        let plan = match open_plan(family, 0x6001, eps.iface, &LineSettings::default()) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("conversation: open plan failed"),
        };
        let mut fake = FakeDevice {
            transcript: Vec::new(),
            rx_packet: alloc::vec![0x10, 0x00, b'O', b'K'],
        };
        for x in &plan {
            fake.transcript.push(x.clone());
        }
        if fake.transcript.len() != 5 || fake.transcript[1].w_value != 0x001A {
            return TestResult::Fail("conversation: transcript is not the pinned plan");
        }
        // Stage 4 — RX: the fake's packet is ingested (FTDI
        // header stripped) into a published ttyUSB port's ring,
        // and reading the ring returns exactly the payload.
        devfs_bridge::__reset_for_test();
        clear_serial();
        let idx = devfs_bridge::register_tty_usb(family);
        let tty = match devfs_bridge::get_port(idx) {
            Some(t) => t,
            None => return TestResult::Fail("conversation: tty port not published"),
        };
        let mut modem = ModemStatus::default();
        let (lo, hi) = ingest_rx(family, &fake.rx_packet, &mut modem);
        tty.lock().rx.push(&fake.rx_packet[lo..hi]);
        let mut out = [0u8; 4];
        let n = tty.lock().rx.pop(&mut out);
        if &out[..n] != b"OK" {
            return TestResult::Fail("conversation: RX payload mismatch");
        }
        // Stage 5 — TX: bytes written to the tty TX ring are what
        // the pump would submit on bulk-OUT 0x02.
        tty.lock().tx.push(b"AT\r");
        let mut chunk = [0u8; 64];
        let pending = tty.lock().tx.peek(&mut chunk);
        if &chunk[..pending] != b"AT\r" {
            return TestResult::Fail("conversation: TX peek mismatch");
        }
        devfs_bridge::unregister_tty_usb(idx);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/serial/port",
        smoke_serial_bind_conversation_ftdi_end_to_end
    );

    // ── Registry / detach ────────────────────────────────────

    fn smoke_serial_detach_unregisters_publication() -> TestResult {
        devfs_bridge::__reset_for_test();
        clear_serial();
        let idx = devfs_bridge::register_tty_usb(ChipFamily::Cp210x);
        SERIAL_PORTS.lock().push(BoundPort {
            slot_id: 42,
            family: ChipFamily::Cp210x,
            pid: 0xEA60,
            tty_index: idx,
            iface: 0,
            bulk_in_dci: 3,
            bulk_out_dci: 2,
            settings: LineSettings::default(),
            modem: ModemStatus::default(),
            hub_port: None,
        });
        if bound_count() != 1 || devfs_bridge::port_count() != 1 {
            return TestResult::Fail("bound port should be registered + published");
        }
        if !detach_serial(42) {
            return TestResult::Fail("detach should report a removal");
        }
        if bound_count() != 0 || devfs_bridge::port_count() != 0 {
            return TestResult::Fail("detach must drop binding and publication");
        }
        if detach_serial(42) {
            return TestResult::Fail("second detach should report no removal");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/serial/port",
        smoke_serial_detach_unregisters_publication
    );

    // ── Typed refusals (no silent no-ops) ────────────────────

    fn smoke_serial_refusals_are_typed() -> TestResult {
        // CP210x hardware flow control is refused with a typed
        // error until AN571 SET_FLOW is modelled — never the old
        // codec-state silent no-op.
        let s = LineSettings {
            flow: FlowControl::RtsCts,
            ..LineSettings::default()
        };
        match configure_plan(ChipFamily::Cp210x, 0xEA60, 0, &s) {
            Err(PortError::Unsupported(_)) => {}
            _ => return TestResult::Fail("CP210x RtsCts must be a typed refusal"),
        }
        // Baud 0 is unrepresentable in every family's model.
        let z = LineSettings {
            baud: 0,
            ..LineSettings::default()
        };
        match configure_plan(ChipFamily::Ftdi, 0x6001, 0, &z) {
            Err(PortError::UnsupportedBaud(0)) => {}
            _ => return TestResult::Fail("FTDI baud 0 must be UnsupportedBaud"),
        }
        match configure_plan(ChipFamily::Ch341, 0x7523, 0, &z) {
            Err(PortError::UnsupportedBaud(0)) => {}
            _ => return TestResult::Fail("CH341 baud 0 must be UnsupportedBaud"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/serial/port", smoke_serial_refusals_are_typed);

    // ── Suspend / resume replay (#763) ───────────────────────

    /// Recording `ControlTransport` fake: logs every transfer as
    /// (slot, xfer) and refuses transfers for scripted dead
    /// slots, so the replay executor runs against a fake
    /// conversation with no silicon.
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

    /// Fabricate a bound port with the given retained state and
    /// return its tty index (mirror of the detach fixture's
    /// fabrication).
    fn fabricate_port(
        slot_id: u8,
        family: ChipFamily,
        pid: u16,
        settings: LineSettings,
        hub_port: Option<(u8, u8)>,
    ) -> usize {
        let idx = devfs_bridge::register_tty_usb(family);
        SERIAL_PORTS.lock().push(BoundPort {
            slot_id,
            family,
            pid,
            tty_index: idx,
            iface: 0,
            bulk_in_dci: 3,
            bulk_out_dci: 2,
            settings,
            modem: ModemStatus::default(),
            hub_port,
        });
        idx
    }

    fn smoke_serial_resume_snapshot_rebuilds_open_plan() -> TestResult {
        devfs_bridge::__reset_for_test();
        clear_serial();
        // Non-default retained state: 9600 baud, DTR only (RTS
        // dropped) — a replay that fell back to defaults or to
        // the bind-time DTR|RTS would be visible here.
        let settings = LineSettings {
            baud: 9_600,
            dtr: true,
            rts: false,
            ..LineSettings::default()
        };
        fabricate_port(207, ChipFamily::Ftdi, 0x6001, settings, None);
        let snapshot = resume_snapshot();
        let expected = match open_plan(ChipFamily::Ftdi, 0x6001, 0, &settings) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("resume: open plan must build"),
        };
        if snapshot.len() != 1 || snapshot[0].0 != 207 {
            return TestResult::Fail("resume: snapshot must hold the one bound port");
        }
        match &snapshot[0].1 {
            Ok(plan) if *plan == expected => {}
            _ => return TestResult::Fail("resume: snapshot plan is not the open plan"),
        }
        // Byte-exact pin of the modem step: FTDI MODEM_CTRL
        // (AN232B) wValue packs the line values in the low byte
        // and their enable masks in the high byte — DTR asserted
        // (0x0101) + RTS deasserted (0x0200) = 0x0301. A replay
        // that re-asserted RTS would read 0x0303 here.
        let modem_step = expected
            .iter()
            .find(|x| x.b_request == ftdi::REQ_MODEM_CTRL)
            .expect("FTDI plan carries a modem step");
        if modem_step.w_value != 0x0301 {
            return TestResult::Fail("resume: modem step lost the DTR-only state");
        }
        clear_serial();
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/serial/port",
        smoke_serial_resume_snapshot_rebuilds_open_plan
    );

    fn smoke_serial_resume_replay_fake_conversation() -> TestResult {
        devfs_bridge::__reset_for_test();
        clear_serial();
        fabricate_port(207, ChipFamily::Ftdi, 0x6001, LineSettings::default(), None);
        let cp_settings = LineSettings {
            baud: 9_600,
            ..LineSettings::default()
        };
        fabricate_port(208, ChipFamily::Cp210x, 0xEA60, cp_settings, None);
        let fake = FakeTransport::new(Vec::new());
        let result = narf_scheduler::block_on_spin(resume_replay(&fake));
        if result.is_err() {
            return TestResult::Fail("resume: replay over a healthy fake must succeed");
        }
        // The transcript must be port 207's full open plan
        // followed by port 208's, each transfer tagged with its
        // own slot — the masking-defeating property is that the
        // two ports' different bauds/ifaces never cross (FTDI
        // carries its divisor in wValue, CP210x its baud in a
        // data stage; a crossed replay would still "succeed"
        // against the fake but mismatch the expected sequence).
        let mut expected: Vec<(u8, ControlXfer)> = Vec::new();
        for (slot, family, pid, settings) in [
            (207u8, ChipFamily::Ftdi, 0x6001u16, LineSettings::default()),
            (208u8, ChipFamily::Cp210x, 0xEA60u16, cp_settings),
        ] {
            let plan = match open_plan(family, pid, 0, &settings) {
                Ok(p) => p,
                Err(_) => return TestResult::Fail("resume: open plan must build"),
            };
            for x in plan {
                expected.push((slot, x));
            }
        }
        let log = fake.log.lock();
        if *log != expected {
            return TestResult::Fail("resume: transcript is not the two open plans in order");
        }
        drop(log);
        clear_serial();
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/serial/port",
        smoke_serial_resume_replay_fake_conversation
    );

    fn smoke_serial_resume_replay_dead_slot_typed() -> TestResult {
        devfs_bridge::__reset_for_test();
        clear_serial();
        fabricate_port(207, ChipFamily::Ftdi, 0x6001, LineSettings::default(), None);
        fabricate_port(
            208,
            ChipFamily::Cp210x,
            0xEA60,
            LineSettings::default(),
            None,
        );
        // Slot 208's device vanished across the sleep: every
        // transfer to it fails. The replay must surface a typed
        // DriverError, still deliver 207's full plan, and never
        // panic or half-program 208.
        let fake = FakeTransport::new(alloc::vec![208]);
        let result = narf_scheduler::block_on_spin(resume_replay(&fake));
        match result {
            Err(narf_power::device_pm::DeviceSuspendError::DriverError) => {}
            _ => return TestResult::Fail("resume: dead slot must fail typed DriverError"),
        }
        let log = fake.log.lock();
        if log.iter().any(|(slot, _)| *slot == 208) {
            return TestResult::Fail("resume: dead slot must receive no transfers");
        }
        let plan207 = match open_plan(ChipFamily::Ftdi, 0x6001, 0, &LineSettings::default()) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("resume: open plan must build"),
        };
        if log.len() != plan207.len()
            || !log
                .iter()
                .zip(plan207.iter())
                .all(|((slot, got), want)| *slot == 207 && got == want)
        {
            return TestResult::Fail("resume: surviving port's plan must replay in full");
        }
        drop(log);
        clear_serial();
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/serial/port",
        smoke_serial_resume_replay_dead_slot_typed
    );

    fn smoke_serial_hub_ports_filter_and_pm_latch() -> TestResult {
        devfs_bridge::__reset_for_test();
        clear_serial();
        fabricate_port(
            207,
            ChipFamily::Ftdi,
            0x6001,
            LineSettings::default(),
            Some((1, 3)),
        );
        fabricate_port(
            208,
            ChipFamily::Cp210x,
            0xEA60,
            LineSettings::default(),
            None,
        );
        fabricate_port(
            209,
            ChipFamily::Pl2303,
            0x2303,
            LineSettings::default(),
            Some((1, 4)),
        );
        if hub_ports() != alloc::vec![(1u8, 3u8), (1u8, 4u8)] {
            return TestResult::Fail("hub_ports must list only hub-bound ports, sorted");
        }
        clear_serial();
        // The PM latch the prepare/resume hooks drive: the pump
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
    kernel_test_in!(
        "drivers/usb/serial/port",
        smoke_serial_hub_ports_filter_and_pm_latch
    );
}
