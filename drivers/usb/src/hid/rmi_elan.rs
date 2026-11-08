//! USB-HID RMI4 / Elan touchpad bind — clean-room (issue #1681).
//!
//! Bridges the vendor touchpad libraries in `narf_input_driver`
//! (`hid_rmi`, `hid_elan`) onto USB HID over xHCI, so a
//! USB-attached Synaptics RMI4 or Elan touchpad binds the same way
//! the I2C-HID ones do. The libraries already existed on main with
//! no USB caller: this module is the missing `HidIo` / `ElanHidIo`
//! backend plus the attach-cascade bind and the interrupt-IN pump.
//!
//! References (public, non-GPL only except where the NARF
//! libraries already cite Linux line numbers):
//! - **HID Class Specification 1.11** (USB-IF, June 2001) §7.2.1
//!   GET_REPORT, §7.2.2 SET_REPORT — the control-transfer encoding
//!   for Feature / Output reports (`wValue = (type << 8) | id`,
//!   report-id byte stripped from the data stage).
//! - **Linux `drivers/hid/hid-rmi.c`** — report-ID assignments
//!   (0x09 write, 0x0A read-addr, 0x0B read-data, 0x0C attn, 0x0F
//!   set-mode), the `RMI_DEVICE_OUTPUT_SET_REPORT` quirk, and the
//!   `rmi_id[]` device table. Constants are re-exported from
//!   `narf_input_driver::hid_rmi`; nothing is re-derived here.
//! - **Linux `drivers/hid/hid-elan.c`** (verified against
//!   torvalds/linux master 2026-11-06) — `ELAN_TP_USB_INTF = 1`
//!   (the touchpad lives on USB interface 1 on composite devices),
//!   the SET+GET Feature 0x0D parameter cycle, the
//!   `[0x0D, 0x00, 0x03, 0x21, 0x00]` absolute-mode magic, and the
//!   USB report intake: 0x81 single-finger, 0x82 first-finger half
//!   stashed until the 0x83 second-finger half completes the frame
//!   (first present finger from the stashed report's record at
//!   `+3`, second present finger from the 0x83 record at `+1`).
//! - **xHCI 1.2 §4.8.1** — DCI numbering (`IN = num*2 + 1`,
//!   `OUT = num*2`), as already used by `ctap.rs`.
//!
//! ## Wire model
//!
//! 1. `attach.rs` classifies the device by VID/PID against the
//!    existing `RMI_DEVICE_TABLE` / `ELAN_DEVICE_TABLE` and hands
//!    the config blob here. Elan entries whose table bus is
//!    `I2cHid` never match on USB.
//! 2. The HID interface is located (Elan prefers interface 1, per
//!    Linux; anything else takes the first HID interface with an
//!    interrupt-IN endpoint), the Report Descriptor is fetched, and
//!    the RMI output-report size is derived from its Output items
//!    (falling back to the endpoint MPS — both device-derived, never
//!    invented).
//! 3. Endpoints are configured, SET_CONFIGURATION +
//!    SET_PROTOCOL(Report) + SET_IDLE run, and the interrupt-IN
//!    endpoint is armed — the same sequence as `hid::touchpad`.
//! 4. The vendor probe runs synchronously through
//!    [`UsbHidIo`]: RMI sets ATTN-report mode and walks the PDT
//!    (F$01 + F$11/F$12 required); Elan reads max-X / max-Y /
//!    resolution and enables absolute mode.
//! 5. On probe success the binding is registered with MT evdev caps
//!    and the supervisor's pump cycle drains ATTN / Elan reports
//!    into `TouchEvent`s. On probe failure the binder falls back to
//!    generic HID (`hid::generic`) for the same interface — the
//!    device is never dropped by this branch.
//!
//! ## Sync → async bridge
//!
//! [`HidIo`] / [`ElanHidIo`] are synchronous traits, but the xHCI
//! control path is async. The backend bridges with
//! `narf_scheduler::block_on_spin` — the same bridge `btusb`'s
//! `UsbHciTransport` uses for its sync trait methods, and the only
//! correct one here: the bind runs inside the supervisor's executor
//! poll (`CURRENT_TASK != 0`), where the halting `block_on` would
//! panic, and the awaited futures are IRQ-driven xHCI control
//! transfers that complete without any other task's help. No
//! `IrqSafeSpinLock` is held across a bridged call (the registry
//! lock is taken only when pushing the finished binding; the
//! per-binding transport lock is taken by the pump around
//! register re-reads, which is exactly the lock-held case
//! `block_on_spin` exists for). The probe is a one-shot bind-time
//! operation — a handful of short transfers — so the spin cost is
//! bounded and never on a hot path.
//!
//! ## Remainders (filed as issues, not guessed)
//!
//! - The Linux `HID_GROUP_RMI` catch-all ("any HID device on the
//!   RMI bus group") is not implemented: the group-assignment rule
//!   could not be verified in-session, so only the explicit
//!   VID/PID tables match. Group-route devices fall through to the
//!   PTP / generic binders below, never dropped.
//! - F$12 multi-source ATTN reads use a 5-object register read,
//!   mirroring the I2C-HID sibling lane; the true object count from
//!   the F$12 query registers is a follow-up.
//! - The Elan mute LED (`HAS_LED`) is recorded in the binding and
//!   drivable via [`set_mute_led_for_slot`]; Linux only registers
//!   it as a led-class device and never writes it at bind time, so
//!   no LED write happens during probe.

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use narf_hid::descriptor::{FieldKind, ReportDescriptor};
use narf_input::rmi4::{PdtEntry, TouchpadReport};
use narf_input::{
    abs,
    evdev::{
        key as evkey, prop, DeviceCaps, DeviceId, DeviceNode, MtContactUpdate, MtEvdevState, ROUTER,
    },
    push_global, AxisInfo, InputEvent, PointerButtons, PointerEvent, TouchEvent, TouchState,
};
use narf_input_driver::{
    hid_elan::{
        self as elan, ElanBus, ElanDeviceParams, ElanFinger, ElanHidIo, ElanQuirks, ElanReport,
    },
    hid_rmi::{self as rmi, clickpad_btn_left, AttnReport, DeviceQuirks, HidIo, HidRmiTransport},
    rmi4_core::{
        decode_f12_data1, decode_f30_buttons, find_function, walk_pdt_page, F01ProductInfo,
        F30Query, Rmi4Transport, TransportError, F01_DEVICE_CONTROL, F11_2D_TOUCHPAD,
        F12_2D_TOUCHPAD_NEXT, F12_OBJECT_SIZE, F30_GPIO_LED,
    },
};
use narf_lib::sync::IrqSafeSpinLock;

use crate::attach::{mark_port_activity, AttachOutcome};
use crate::hid::{
    generic,
    identity::{apply_identity, resolve_usb_identity, BindTopology},
    touchpad, HidError, HID_REPORT_PROTOCOL, HID_REQ_SET_IDLE, HID_REQ_SET_PROTOCOL,
    STD_REQ_SET_CONFIGURATION,
};
use crate::xhci::{controller_by_id, EndpointConfig, EndpointKind, Xhci};

/// GET_REPORT class request (HID 1.11 §7.2.1).
pub const HID_REQ_GET_REPORT: u8 = 0x01;
/// `bmRequestType` for a Device-to-Host Class request to an
/// interface (USB 2.0 §9.3 table 9-2: 0xA1).
pub const RT_DEV_TO_HOST_CLASS_IFACE: u8 = 0xA1;

/// Elan USB touchpad interface number (Linux `ELAN_TP_USB_INTF`,
/// `hid-elan.c:49`). On composite Elan devices the touchpad lives
/// on interface 1; the finder prefers it but falls back to the
/// first HID interface when no interface 1 exists, so
/// single-interface devices still bind.
pub const ELAN_TP_USB_INTF: u8 = 1;

/// Per-poll buffer size for interrupt-IN reads. RMI ATTN /
/// read-data reports and Elan 8-byte reports are all far smaller;
/// 128 matches the PTP pump's headroom for vendor-extended
/// reports.
pub const RMI_ELAN_IN_BUF_BYTES: usize = 128;

/// Upper bound on a derived RMI output-report size. Real silicon
/// uses 19 or 24 bytes; 256 is a safety cap on the per-write
/// allocation if a malformed descriptor claims a huge Output item.
pub const MAX_OUTPUT_REPORT_SIZE: usize = 256;

/// Bounded wait for one interrupt-IN report inside
/// [`UsbHidIo::poll_input_report`]. A full-speed HID device
/// answers a read-data request within ~2 bus intervals (typically
/// 10 ms each), so 50 ms covers the round trip with margin; the
/// wait is wall-clocked via `monotonic_ns`, not an iteration
/// guess, and `sleep_pumps` ticks through it so the cursor / FB /
/// serial console keep moving.
pub const POLL_INPUT_DEADLINE_NS: u64 = 50_000_000;

/// Maximum simultaneously tracked contacts per binding. Matches
/// `TouchPumpState::MAX_TOUCH_SLOTS` (10) in the I2C-HID touch
/// driver.
pub const MAX_PUMP_SLOTS: usize = 10;

// ── Vendor classification ────────────────────────────────────────────

/// Which vendor protocol a USB VID/PID matched.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VendorKind {
    /// Synaptics RMI4-over-HID (`hid_rmi::RMI_DEVICE_TABLE`).
    Rmi { quirks: DeviceQuirks },
    /// Elan HID (`hid_elan::ELAN_DEVICE_TABLE`, USB-bus rows only).
    Elan { quirks: ElanQuirks },
}

/// Classify a USB device by VID/PID. Returns `None` when neither
/// vendor table claims it — the attach cascade then continues to
/// the PTP / consumer / mouse binders. Elan rows whose table bus
/// is `I2cHid` (e.g. the Toshiba Click L9W) never match on USB.
pub fn classify(vendor: u16, product: u16) -> Option<VendorKind> {
    if let Some(m) = rmi::match_device(vendor, product) {
        return Some(VendorKind::Rmi { quirks: m.quirks });
    }
    if let Some(m) = elan::match_device(vendor, product) {
        if m.bus == ElanBus::Usb {
            return Some(VendorKind::Elan { quirks: m.quirks });
        }
    }
    None
}

// ── Config-blob endpoint finder ──────────────────────────────────────

/// The HID interface + endpoints a bind needs.
#[derive(Copy, Clone, Debug)]
pub struct HidEndpoints {
    pub interface_num: u8,
    pub hid_desc_off: usize,
    pub interrupt_in: EndpointConfig,
    pub interrupt_out: Option<EndpointConfig>,
}

/// Walk a configuration descriptor for HID interfaces with an
/// interrupt-IN endpoint (and an interrupt-OUT endpoint when the
/// interface offers one). When `prefer_interface` is `Some(n)`,
/// the interface numbered `n` wins if it qualifies (the Elan
/// interface-1 rule); otherwise the first qualifying interface
/// wins. Returns `None` when no HID interface has interrupt-IN.
pub fn find_rmi_elan_interface(cfg: &[u8], prefer_interface: Option<u8>) -> Option<HidEndpoints> {
    let mut candidates: Vec<HidEndpoints> = Vec::new();
    let mut iface_num: Option<u8> = None;
    let mut hid_off: Option<usize> = None;
    let mut in_ep: Option<EndpointConfig> = None;
    let mut out_ep: Option<EndpointConfig> = None;
    // Flush the interface currently being walked into the
    // candidate list (only when it has an interrupt-IN endpoint).
    let flush = |iface_num: &mut Option<u8>,
                 hid_off: &mut Option<usize>,
                 in_ep: &mut Option<EndpointConfig>,
                 out_ep: &mut Option<EndpointConfig>,
                 candidates: &mut Vec<HidEndpoints>| {
        if let (Some(num), Some(off), Some(in_)) = (*iface_num, *hid_off, *in_ep) {
            candidates.push(HidEndpoints {
                interface_num: num,
                hid_desc_off: off,
                interrupt_in: in_,
                interrupt_out: *out_ep,
            });
        }
        *iface_num = None;
        *hid_off = None;
        *in_ep = None;
        *out_ep = None;
    };
    let mut i = 0usize;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        let dtype = cfg[i + 1];
        match dtype {
            // Interface Descriptor (USB 2.0 §9.6.5).
            4 if len >= 9 => {
                flush(
                    &mut iface_num,
                    &mut hid_off,
                    &mut in_ep,
                    &mut out_ep,
                    &mut candidates,
                );
                if cfg[i + 5] == touchpad::HID_INTERFACE_CLASS {
                    iface_num = Some(cfg[i + 2]);
                }
            }
            touchpad::HID_DESC_TYPE_HID if iface_num.is_some() => {
                hid_off = Some(i);
            }
            // Endpoint Descriptor (USB 2.0 §9.6.6).
            5 if len >= 7 && iface_num.is_some() => {
                let ep_addr = cfg[i + 2];
                let attr = cfg[i + 3];
                let mps = u16::from_le_bytes([cfg[i + 4], cfg[i + 5]]);
                let xfer_t = attr & 0x03;
                if xfer_t == 3 {
                    if ep_addr & 0x80 != 0 && in_ep.is_none() {
                        in_ep = Some(EndpointConfig {
                            ep_addr,
                            max_packet: mps,
                            kind: EndpointKind::InterruptIn,
                            interval: cfg[i + 6],
                        });
                    } else if ep_addr & 0x80 == 0 && out_ep.is_none() {
                        out_ep = Some(EndpointConfig {
                            ep_addr,
                            max_packet: mps,
                            kind: EndpointKind::InterruptOut,
                            interval: cfg[i + 6],
                        });
                    }
                }
            }
            _ => {}
        }
        i += len;
    }
    flush(
        &mut iface_num,
        &mut hid_off,
        &mut in_ep,
        &mut out_ep,
        &mut candidates,
    );
    if let Some(want) = prefer_interface {
        if let Some(found) = candidates.iter().find(|c| c.interface_num == want) {
            return Some(*found);
        }
    }
    candidates.into_iter().next()
}

/// Derive the RMI output-report size (the `output_report_size`
/// `HidRmiTransport` pads its encoders to) from the parsed Report
/// Descriptor: the largest Output item declared for any RMI
/// output report ID (0x09 write, 0x0A read-addr, 0x0F set-mode),
/// plus the 1-byte report-id prefix. Falls back to the
/// interrupt-OUT endpoint's MPS when the descriptor declares no
/// Output item for those IDs, and to the interrupt-IN MPS when
/// there is no OUT endpoint at all. Every source is
/// device-derived; the only invented number is the safety cap.
pub fn output_report_size(
    parsed: &ReportDescriptor,
    out_ep: Option<&EndpointConfig>,
    in_ep: &EndpointConfig,
) -> usize {
    let mut bits = 0u32;
    for id in [
        rmi::RMI_WRITE_REPORT_ID,
        rmi::RMI_READ_ADDR_REPORT_ID,
        rmi::RMI_SET_RMI_MODE_REPORT_ID,
    ] {
        bits = bits.max(parsed.report_body_bits(id, FieldKind::Output));
    }
    if bits > 0 {
        return ((bits.div_ceil(8) as usize) + 1).min(MAX_OUTPUT_REPORT_SIZE);
    }
    if let Some(out) = out_ep {
        return (out.max_packet as usize).min(MAX_OUTPUT_REPORT_SIZE);
    }
    (in_ep.max_packet as usize).min(MAX_OUTPUT_REPORT_SIZE)
}

// ── UsbHidIo: HidIo + ElanHidIo over xHCI ───────────────────────────

/// Synchronous HID transport over xHCI: interrupt-OUT for output
/// reports, control SET_REPORT for Feature reports, control
/// GET_REPORT for Feature reads, and a bounded wall-clocked wait
/// on the interrupt-IN endpoint for input reports.
///
/// See the module docs for the `block_on_spin` safety argument.
/// The backend holds ids only (no `&Xhci` borrow) so the
/// `HidRmiTransport` that owns it can live in the binding registry.
#[derive(Copy, Clone, Debug)]
pub struct UsbHidIo {
    controller: u8,
    slot_id: u8,
    interface: u8,
    in_dci: u8,
    out_dci: Option<u8>,
    quirks: DeviceQuirks,
}

impl UsbHidIo {
    pub fn new(
        controller: u8,
        slot_id: u8,
        interface: u8,
        in_dci: u8,
        out_dci: Option<u8>,
        quirks: DeviceQuirks,
    ) -> Self {
        Self {
            controller,
            slot_id,
            interface,
            in_dci,
            out_dci,
            quirks,
        }
    }

    fn xhci(&self) -> Option<Arc<Xhci>> {
        controller_by_id(self.controller)
    }

    /// Issue one SET_REPORT control transfer (HID 1.11 §7.2.2).
    /// `report_type`: 1 = Output, 3 = Feature. `report[0]` is the
    /// report ID: it rides in `wValue` and is stripped from the
    /// data stage, mirroring the touchpad Mode-Feature-Report
    /// write. Empty reports are a caller bug, not a STALL.
    fn set_report(&mut self, report_type: u16, report: &[u8]) -> Result<(), TransportError> {
        if report.is_empty() {
            return Err(TransportError::Short);
        }
        let xhci = self.xhci().ok_or(TransportError::NotReady)?;
        let report_id = report[0] as u16;
        narf_scheduler::block_on_spin(xhci.control_out(
            self.slot_id,
            touchpad::RT_HOST_TO_DEV_CLASS_IFACE,
            touchpad::HID_REQ_SET_REPORT,
            (report_type << 8) | report_id,
            self.interface as u16,
            &report[1..],
        ))
        .map_err(|_| TransportError::Short)?;
        Ok(())
    }

    /// Issue one GET_REPORT(Feature) control transfer (HID 1.11
    /// §7.2.1). The device returns the report with its ID byte
    /// intact, which is what the Elan param decoder expects.
    fn get_report(&mut self, report_id: u8, dst: &mut [u8]) -> Result<usize, TransportError> {
        if dst.is_empty() {
            return Err(TransportError::Short);
        }
        let xhci = self.xhci().ok_or(TransportError::NotReady)?;
        narf_scheduler::block_on_spin(xhci.control_in(
            self.slot_id,
            RT_DEV_TO_HOST_CLASS_IFACE,
            HID_REQ_GET_REPORT,
            (3u16 << 8) | report_id as u16,
            self.interface as u16,
            dst,
        ))
        .map_err(|_| TransportError::Short)
    }
}

impl HidIo for UsbHidIo {
    /// Send a fully-built output report. Prefers the interrupt-OUT
    /// endpoint (the Linux `hid_hw_output_report` path); the
    /// `OUTPUT_SET_REPORT` quirk (Acer Switch 5) and the
    /// no-OUT-endpoint case both route through SET_REPORT(Output)
    /// instead, matching Linux `hid-rmi.c`'s quirk branch. The
    /// staged TRB is fire-and-forget: ordering with the later
    /// read-data response is enforced by the device, and the
    /// completion event is drained opportunistically so the
    /// transfer-event queue cannot grow across probe writes.
    fn output_report(&mut self, report: &[u8]) -> Result<(), TransportError> {
        if report.is_empty() {
            return Err(TransportError::Short);
        }
        if self.quirks.contains(DeviceQuirks::OUTPUT_SET_REPORT) || self.out_dci.is_none() {
            return self.set_report(1, report);
        }
        let xhci = self.xhci().ok_or(TransportError::NotReady)?;
        let dci = self.out_dci.unwrap_or(0);
        xhci.arm_interrupt_out(self.slot_id, dci, report)
            .map_err(|_| TransportError::Short)?;
        let _ = xhci.poll_interrupt_out(self.slot_id, dci, report.len() as u32);
        Ok(())
    }

    /// Send a Feature report via `SET_REPORT(HID_FEATURE_REPORT)`.
    fn set_feature_report(&mut self, report: &[u8]) -> Result<(), TransportError> {
        self.set_report(3, report)
    }

    /// Read one pending input report, waiting up to
    /// [`POLL_INPUT_DEADLINE_NS`] for the device to answer. Each
    /// iteration drains the xHCI event ring (via
    /// `poll_interrupt_in`), so the response is observed as soon
    /// as the controller posts it — no executor involvement is
    /// needed. `sleep_pumps` ticks keep the console alive across
    /// the wait. Timeout is the caller's retry signal
    /// (`HidRmiTransport::read_block` retries up to 16 times
    /// before giving up).
    fn poll_input_report(&mut self, dst: &mut [u8]) -> Result<usize, TransportError> {
        let xhci = self.xhci().ok_or(TransportError::NotReady)?;
        let deadline = narf_time::monotonic_ns().saturating_add(POLL_INPUT_DEADLINE_NS);
        let mut i = 0u32;
        loop {
            match xhci.poll_interrupt_in(self.slot_id, self.in_dci, dst) {
                Ok(Some(n)) => return Ok(n),
                Ok(None) => {}
                Err(_) => return Err(TransportError::Short),
            }
            if narf_time::monotonic_ns() >= deadline {
                return Err(TransportError::Timeout);
            }
            i += 1;
            if i % 1024 == 0 {
                narf_scheduler::sleep_pumps::run();
            }
        }
    }
}

impl ElanHidIo for UsbHidIo {
    /// Issue `SET_REPORT(HID_FEATURE_REPORT)` with the given body.
    fn set_feature(&mut self, report: &[u8]) -> Result<(), TransportError> {
        self.set_report(3, report)
    }

    /// Issue `GET_REPORT(HID_FEATURE_REPORT)` of `len` bytes into
    /// `dst`. Returns the number of bytes received.
    fn get_feature(&mut self, report_id: u8, dst: &mut [u8]) -> Result<usize, TransportError> {
        self.get_report(report_id, dst)
    }
}

// ── RMI probe ────────────────────────────────────────────────────────
//
// Mirrors the I2C-HID sibling lane's `probe_device` semantics
// (PR #1686, unmerged at authoring time) against the synchronous
// `Rmi4Transport` surface, so the two transports agree on what
// "probed" means without either depending on the other's branch:
// walk PDT page 0, require F$01 plus a 2D sensor (F$11 or F$12),
// read the F$01 product info (which also proves the register
// round-trip works end to end), and learn the F$30 GPIO count.

/// Interrupt-source map: `(function_number, source_mask)` in PDT
/// order. Linux `rmi_scan_pdt` assigns interrupt sources
/// sequentially down the table; the mask is what an ATTN report's
/// source byte is tested against.
pub fn build_interrupt_map(table: &[PdtEntry]) -> Vec<(u8, u8)> {
    let mut out = Vec::new();
    let mut bit: u32 = 0;
    for e in table {
        let mut mask = 0u8;
        for _ in 0..e.interrupt_source_count {
            if bit < 8 {
                mask |= 1 << bit;
            }
            bit += 1;
        }
        out.push((e.function_number, mask));
    }
    out
}

/// Probed RMI4 device: the PDT table plus the functions the pump
/// needs, the F$30 GPIO count, and the interrupt-source map.
#[derive(Debug)]
pub struct RmiProbe {
    pub table: Vec<PdtEntry>,
    pub product: F01ProductInfo,
    pub f01: PdtEntry,
    pub f11: Option<PdtEntry>,
    pub f12: Option<PdtEntry>,
    pub f30: Option<PdtEntry>,
    pub f30_gpio_count: u8,
    pub interrupt_map: Vec<(u8, u8)>,
}

impl RmiProbe {
    /// Walk the PDT and verify the silicon is a usable RMI4
    /// touchpad. Fails with `TransportError::Protocol` when F$01
    /// is missing or no 2D sensor exists; bus errors from the
    /// transport propagate unchanged (the caller treats any error
    /// as "fall back to generic HID").
    pub fn probe(transport: &mut dyn Rmi4Transport) -> Result<Self, TransportError> {
        let table = walk_pdt_page(transport, 0)?;
        let f01 = find_function(&table, F01_DEVICE_CONTROL)
            .copied()
            .ok_or(TransportError::Protocol)?;
        let mut query = [0u8; 11];
        transport.read_block(f01.query_base as u16, &mut query)?;
        let product = F01ProductInfo::decode(&query).map_err(|_| TransportError::Short)?;
        let f11 = find_function(&table, F11_2D_TOUCHPAD).copied();
        let f12 = find_function(&table, F12_2D_TOUCHPAD_NEXT).copied();
        let f30 = find_function(&table, F30_GPIO_LED).copied();
        if f11.is_none() && f12.is_none() {
            return Err(TransportError::Protocol);
        }
        // F$30 GPIO/LED line count from its query registers (2
        // bytes at the query base). Defaults to 8 (one button byte)
        // when the function exists but the query read fails, and 0
        // when there is no F$30 function at all.
        let mut f30_gpio_count = if f30.is_some() { 8 } else { 0 };
        if let Some(f30e) = &f30 {
            let mut qbuf = [0u8; 2];
            if transport
                .read_block(f30e.query_base as u16, &mut qbuf)
                .is_ok()
            {
                if let Ok(q) = F30Query::decode(&qbuf) {
                    f30_gpio_count = q.gpio_led_count;
                }
            }
        }
        let interrupt_map = build_interrupt_map(&table);
        Ok(Self {
            table,
            product,
            f01,
            f11,
            f12,
            f30,
            f30_gpio_count,
            interrupt_map,
        })
    }

    /// Interrupt-source mask for `function_number` (0 when the
    /// function is absent or owns no sources).
    pub fn source_mask_for(&self, function_number: u8) -> u8 {
        self.interrupt_map
            .iter()
            .find(|(f, _)| *f == function_number)
            .map(|(_, m)| *m)
            .unwrap_or(0)
    }
}

/// Read the F$30 button bitmap when its interrupt source fired.
/// Returns `Some(btn_left)` on a clean read, `None` when F$30 is
/// absent, silent, or the register read fails (the caller keeps
/// the previous button state). One bit per GPIO, active-low —
/// `decode_f30_buttons` inverts to "true = pressed" and the
/// clickpad collapses bit 0 into BTN_LEFT.
fn read_rmi_buttons(
    transport: &mut dyn Rmi4Transport,
    probe: &RmiProbe,
    sources: u8,
) -> Option<bool> {
    let f30 = probe.f30.as_ref()?;
    if sources & probe.source_mask_for(F30_GPIO_LED) == 0 {
        return None;
    }
    let nbytes = (probe.f30_gpio_count.min(32) as usize).div_ceil(8).max(1);
    let mut buf = alloc::vec![0u8; nbytes];
    if transport
        .read_block(f30.data_base as u16, &mut buf)
        .is_err()
    {
        return None;
    }
    match decode_f30_buttons(&buf, probe.f30_gpio_count) {
        Ok(bitmap) => Some(clickpad_btn_left(bitmap)),
        Err(_) => None,
    }
}

// ── Shared pump state ────────────────────────────────────────────────
//
// One slot table + evdev emitter drives both vendors' contact
// streams. Semantics mirror the I2C-HID sibling's `Rmi4PumpState`
// (PR #1686): per-slot Down/Move/Up `TouchEvent`s on the global
// ring, a slot-protocol-B frame on the evdev node, and a
// first-contact relative-pointer feed (the PTP pump's shape) for
// consumers that only speak relative motion.

/// One contact in a pump frame.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PumpContact {
    pub present: bool,
    pub x: i32,
    pub y: i32,
    pub pressure: i32,
}

impl PumpContact {
    pub const fn absent() -> Self {
        Self {
            present: false,
            x: 0,
            y: 0,
            pressure: 0,
        }
    }
}

/// Mutable per-binding pump state, carried between reports.
#[derive(Debug)]
pub struct PumpState {
    slots: [bool; MAX_PUMP_SLOTS],
    last_pos: [(i32, i32); MAX_PUMP_SLOTS],
    evdev: MtEvdevState,
    last_pointer: Option<(i32, i32)>,
    last_button: bool,
    /// Stashed Elan 0x82 first-finger half, completed by the next
    /// 0x83 second-finger half (Linux `elan_usb_report_input`).
    elan_prev_first: Option<[u8; elan::ELAN_INPUT_REPORT_SIZE]>,
}

impl PumpState {
    pub fn new() -> Self {
        Self {
            slots: [false; MAX_PUMP_SLOTS],
            last_pos: [(0, 0); MAX_PUMP_SLOTS],
            evdev: MtEvdevState::new(MAX_PUMP_SLOTS),
            last_pointer: None,
            last_button: false,
            elan_prev_first: None,
        }
    }

    /// Emit one frame of contacts: `TouchEvent`s on the global ring
    /// plus a slot-protocol-B evdev frame, then the first-contact
    /// relative-pointer feed. `btn_left` of `None` keeps the
    /// previous button state (a frame that carries no button
    /// information). Coordinates are normalised into the shared
    /// 0..=65535 touch space against `x_range` / `y_range`. Returns
    /// the number of events pushed.
    pub fn emit_contacts(
        &mut self,
        contacts: &[PumpContact],
        btn_left: Option<bool>,
        x_range: (i32, i32),
        y_range: (i32, i32),
        node: &DeviceNode,
    ) -> usize {
        let mut pushed = 0usize;
        let mut updates: Vec<MtContactUpdate> = Vec::new();
        let mut first: Option<(i32, i32)> = None;
        for (i, c) in contacts.iter().enumerate().take(MAX_PUMP_SLOTS) {
            let slot = i as u8;
            if c.present {
                if first.is_none() {
                    first = Some((c.x, c.y));
                }
                let state = if self.slots[i] {
                    TouchState::Move
                } else {
                    TouchState::Down
                };
                let _ = push_global(InputEvent::Touch(TouchEvent {
                    slot,
                    tracking_id: Some(i as i32),
                    id: i as u16,
                    x: TouchEvent::normalise_axis(c.x, x_range.0, x_range.1) as i32,
                    y: TouchEvent::normalise_axis(c.y, y_range.0, y_range.1) as i32,
                    pressure: c.pressure,
                    state,
                }));
                updates.push(MtContactUpdate {
                    slot: i,
                    active: true,
                    tracking_id: i as i32,
                    x: c.x,
                    y: c.y,
                    pressure: Some(c.pressure),
                });
                self.slots[i] = true;
                self.last_pos[i] = (c.x, c.y);
                pushed += 1;
            } else if self.slots[i] {
                let (lx, ly) = self.last_pos[i];
                let _ = push_global(InputEvent::Touch(TouchEvent {
                    slot,
                    tracking_id: Some(i as i32),
                    id: i as u16,
                    x: TouchEvent::normalise_axis(lx, x_range.0, x_range.1) as i32,
                    y: TouchEvent::normalise_axis(ly, y_range.0, y_range.1) as i32,
                    pressure: 0,
                    state: TouchState::Up,
                }));
                updates.push(MtContactUpdate {
                    slot: i,
                    active: false,
                    tracking_id: i as i32,
                    x: lx,
                    y: ly,
                    pressure: None,
                });
                self.slots[i] = false;
                pushed += 1;
            }
        }
        // `None` holds the previous button state.
        let btn = btn_left.unwrap_or(self.last_button);
        self.evdev.dispatch_frame(node, &updates, btn, false);
        // Relative-pointer feed off the first contact, mirroring
        // the PTP pump's first-contact semantics.
        let (dx, dy) = match (first, self.last_pointer) {
            (Some((x, y)), Some((px, py))) => (x - px, y - py),
            (Some(_), None) => (0, 0),
            (None, _) => (0, 0),
        };
        self.last_pointer = first;
        let button_changed = btn != self.last_button;
        self.last_button = btn;
        if dx != 0 || dy != 0 || button_changed {
            let buttons = if btn {
                PointerButtons::LEFT
            } else {
                PointerButtons::from_bits_truncate(0)
            };
            let _ = push_global(InputEvent::Pointer(PointerEvent { dx, dy, buttons }));
            narf_input::evdev::dispatch_rel_to_node(node, dx, dy);
            pushed += 1;
        }
        pushed
    }
}

impl Default for PumpState {
    fn default() -> Self {
        Self::new()
    }
}

// ── RMI ATTN pump ────────────────────────────────────────────────────
//
// F$12 (modern 2D sensor) takes precedence — a device never
// exposes both F$11 and F$12 as its touch sensor. Single-source
// ATTN reports carry the packed data inline; multi-source ATTN
// reports re-read the function's Data registers through the
// transport (the packed layout across functions is not
// self-describing).

/// Decode one RMI ATTN report into contacts + button state, then
/// emit. Register re-reads (multi-source ATTN, F$30 buttons) run
/// under the transport lock; emission happens after the lock is
/// dropped. Returns the number of events pushed.
fn pump_rmi_report(
    binding: &RmiElanBinding,
    probe: &RmiProbe,
    transport: &IrqSafeSpinLock<Box<dyn Rmi4Transport + Send + Sync>>,
    report: &[u8],
) -> usize {
    let Some(attn) = AttnReport::decode(report) else {
        return 0;
    };
    let sources = attn.interrupt_sources;
    let (contacts, btn) = {
        let mut t = transport.lock();
        let t: &mut dyn Rmi4Transport = &mut **t;
        let f12_mask = probe.source_mask_for(F12_2D_TOUCHPAD_NEXT);
        let f11_mask = probe.source_mask_for(F11_2D_TOUCHPAD);
        let mut contacts: Vec<PumpContact> = Vec::new();
        if f12_mask != 0 && sources & f12_mask != 0 {
            if let Some(f12) = &probe.f12 {
                let single_source = sources == f12_mask;
                let nobj = attn.data.len() / F12_OBJECT_SIZE;
                let decoded = if single_source && nobj > 0 {
                    decode_f12_data1(attn.data, nobj).ok()
                } else {
                    // Multi-source ATTN: read Data 1 back from the
                    // register (5 objects; the true object count
                    // comes from the F$12 query at probe time —
                    // remainder).
                    let mut buf = alloc::vec![0u8; 5 * F12_OBJECT_SIZE];
                    match t.read_block(f12.data_base as u16, &mut buf) {
                        Ok(()) => decode_f12_data1(&buf, 5).ok(),
                        Err(_) => None,
                    }
                };
                if let Some(objs) = decoded {
                    contacts = objs
                        .iter()
                        .map(|o| PumpContact {
                            present: o.present && o.is_touching_finger(),
                            x: o.x as i32,
                            y: o.y as i32,
                            pressure: o.z as i32,
                        })
                        .collect();
                }
            }
        } else if f11_mask != 0 && sources & f11_mask != 0 {
            if let Some(f11) = &probe.f11 {
                let single_source = sources == f11_mask;
                // F$11 frame: 1 finger-state byte + 5 bytes per
                // finger (5 fingers max, matching the sibling lane).
                let decoded = if single_source {
                    TouchpadReport::parse(attn.data, 5).ok()
                } else {
                    let mut buf = alloc::vec![0u8; 1 + 5 * 5];
                    match t.read_block(f11.data_base as u16, &mut buf) {
                        Ok(()) => TouchpadReport::parse(&buf, 5).ok(),
                        Err(_) => None,
                    }
                };
                if let Some(rep) = decoded {
                    contacts = rep
                        .fingers
                        .iter()
                        .map(|f| PumpContact {
                            present: f.present,
                            x: f.x as i32,
                            y: f.y as i32,
                            pressure: 0,
                        })
                        .collect();
                }
            }
        }
        let btn = read_rmi_buttons(t, probe, sources);
        (contacts, btn)
    };
    // F$12 coordinates are full-range u16 (0..=0xFFFF); F$11
    // coordinates are 12-bit (0..=0x0FFF). Normalise against the
    // range of the sensor that actually produced this frame.
    let ranges = if probe.f12.is_some() {
        (0, 0xFFFF)
    } else {
        (0, 0x0FFF)
    };
    binding
        .pump
        .lock()
        .emit_contacts(&contacts, btn, ranges, ranges, &binding.evdev_node)
}

// ── Elan USB pump ────────────────────────────────────────────────────
//
// 0x81 single-finger: the on-main `ElanReport` decoder (faithful
// to Linux — every present finger decodes the same record at
// `+3`; single-finger mode reports one finger). 0x82 stashes the
// first-finger half; 0x83 completes the pair (first present finger
// from the stashed record at `+3`, second present finger from the
// 0x83 record at `+1`), exactly as Linux `elan_usb_report_input`.

/// Decode one Elan USB input report into contacts + button state,
/// then emit. Returns the number of events pushed.
fn pump_elan_report(binding: &RmiElanBinding, max_y: u16, report: &[u8]) -> usize {
    if report.is_empty() {
        return 0;
    }
    match report[0] {
        elan::ELAN_SINGLE_FINGER => {
            let Some(rep) = ElanReport::decode_usb_single_finger(report, max_y) else {
                return 0;
            };
            let contacts: Vec<PumpContact> = rep
                .fingers
                .iter()
                .map(|f| PumpContact {
                    present: f.present,
                    x: f.x as i32,
                    y: f.y as i32,
                    pressure: f.pressure as i32,
                })
                .collect();
            binding.pump.lock().emit_contacts(
                &contacts,
                Some(rep.btn_left),
                binding.x_range,
                binding.y_range,
                &binding.evdev_node,
            )
        }
        elan::ELAN_MT_FIRST_FINGER => {
            if report.len() == elan::ELAN_INPUT_REPORT_SIZE {
                let mut state = binding.pump.lock();
                let mut prev = [0u8; elan::ELAN_INPUT_REPORT_SIZE];
                prev.copy_from_slice(&report[..elan::ELAN_INPUT_REPORT_SIZE]);
                state.elan_prev_first = Some(prev);
            }
            0
        }
        elan::ELAN_MT_SECOND_FINGER => {
            if report.len() != elan::ELAN_INPUT_REPORT_SIZE {
                return 0;
            }
            let prev = {
                let mut state = binding.pump.lock();
                state.elan_prev_first.take()
            };
            let Some(prev) = prev else {
                return 0;
            };
            if prev[0] != elan::ELAN_MT_FIRST_FINGER {
                return 0;
            }
            let mut contacts: Vec<PumpContact> = Vec::new();
            let mut seen_first = false;
            for i in 0..elan::ELAN_MAX_FINGERS {
                if prev[2] & (1 << (i + 3)) != 0 {
                    if !seen_first {
                        seen_first = true;
                        let f = ElanFinger::decode(&prev[3..8], max_y).unwrap_or_default();
                        contacts.push(PumpContact {
                            present: true,
                            x: f.x as i32,
                            y: f.y as i32,
                            pressure: f.pressure as i32,
                        });
                    } else {
                        let f = ElanFinger::decode(&report[1..6], max_y).unwrap_or_default();
                        contacts.push(PumpContact {
                            present: true,
                            x: f.x as i32,
                            y: f.y as i32,
                            pressure: f.pressure as i32,
                        });
                    }
                } else {
                    contacts.push(PumpContact::absent());
                }
            }
            binding.pump.lock().emit_contacts(
                &contacts,
                Some(prev[2] & 0x01 != 0),
                binding.x_range,
                binding.y_range,
                &binding.evdev_node,
            )
        }
        _ => 0,
    }
}

// ── Binding ──────────────────────────────────────────────────────────

/// The vendor half of a bound touchpad.
pub enum RmiElanKind {
    /// Synaptics RMI4-over-HID: probed PDT + the transport the
    /// pump re-reads registers through (multi-source ATTN, F$30
    /// buttons). The transport is boxed behind the trait so the
    /// binding type stays concrete across backends.
    Rmi {
        probe: RmiProbe,
        transport: IrqSafeSpinLock<Box<dyn Rmi4Transport + Send + Sync>>,
    },
    /// Elan HID: probe-time parameters + the backend (kept for
    /// the mute-LED control path; the pump itself is pure decode
    /// and never touches it).
    Elan {
        params: ElanDeviceParams,
        io: IrqSafeSpinLock<Box<dyn ElanHidIo + Send + Sync>>,
        quirks: ElanQuirks,
    },
}

// Manual `Debug`: the boxed trait objects (`dyn Rmi4Transport` /
// `dyn ElanHidIo`) are not `Debug`, and `Debug` is not an auto
// trait so it cannot be added to the `dyn` bounds (E0225) — a
// derived impl would fail. The transport / io fields are omitted.
impl fmt::Debug for RmiElanKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rmi { probe, .. } => f
                .debug_struct("Rmi")
                .field("probe", probe)
                .finish_non_exhaustive(),
            Self::Elan { params, quirks, .. } => f
                .debug_struct("Elan")
                .field("params", params)
                .field("quirks", quirks)
                .finish_non_exhaustive(),
        }
    }
}

/// One bound USB-HID RMI4 / Elan touchpad. Held in the global
/// [`RMI_ELAN_DEVICES`] registry; the supervisor's pump cycle
/// drains reports off each.
pub struct RmiElanBinding {
    pub slot_id: u8,
    pub in_dci: u8,
    pub interface_num: u8,
    /// Hub context — (parent hub slot id, downstream port) — when
    /// the touchpad sits behind a hub; `None` on a root port. The
    /// pump feeds `attach::mark_port_activity` with it whenever a
    /// report completes, so an in-use touchpad's port never
    /// idle-suspends mid-gesture (#840).
    pub hub_port: Option<(u8, u8)>,
    pub kind: RmiElanKind,
    pub pump: IrqSafeSpinLock<PumpState>,
    /// Normalisation ranges for the global-ring TouchEvents:
    /// RMI F$12 is full-range u16, F$11 is 12-bit; Elan uses the
    /// probed max-X / max-Y.
    pub x_range: (i32, i32),
    pub y_range: (i32, i32),
    /// evdev ROUTER device id — for unregister on detach.
    pub(crate) evdev_id: DeviceId,
    /// evdev DeviceNode — MT frames dispatched here.
    pub(crate) evdev_node: Arc<DeviceNode>,
}

impl fmt::Debug for RmiElanBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RmiElanBinding")
            .field("slot_id", &self.slot_id)
            .field("in_dci", &self.in_dci)
            .field("interface_num", &self.interface_num)
            .field("hub_port", &self.hub_port)
            .field("kind", &self.kind)
            .field("pump", &self.pump)
            .field("x_range", &self.x_range)
            .field("y_range", &self.y_range)
            .field("evdev_id", &self.evdev_id)
            .field("evdev_node", &self.evdev_node)
            .finish()
    }
}

/// Bound RMI/Elan touchpads, one registry per xHCI controller.
/// Populated by [`try_bind_rmi_elan_already_addressed`]; consumed
/// by [`pump_all`].
static RMI_ELAN_DEVICES: crate::xhci::PerController<Vec<Arc<RmiElanBinding>>> =
    crate::per_controller_vec!();

/// Lock-free atomic count of bound RMI/Elan touchpads.
/// Diagnostics (fb::status::paint, panel counters) read this
/// WITHOUT taking the registry lock.
pub static ATTACHED_RMI_ELAN_COUNT: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Number of bound RMI/Elan touchpads. Test + diagnostics helper.
pub fn attached_rmi_elan_count() -> usize {
    ATTACHED_RMI_ELAN_COUNT.load(core::sync::atomic::Ordering::Acquire) as usize
}

// ── evdev caps ───────────────────────────────────────────────────────

fn axis(min: i32, max: i32) -> AxisInfo {
    AxisInfo {
        min,
        max,
        fuzz: 0,
        flat: 0,
        res: 0,
    }
}

fn add_mt_axes(caps: &mut DeviceCaps, max_slots: usize, x: AxisInfo, y: AxisInfo) {
    caps.add_abs_info(abs::ABS_X, x);
    caps.add_abs_info(abs::ABS_Y, y);
    caps.add_abs_info(
        abs::ABS_MT_SLOT,
        axis(0, max_slots.saturating_sub(1) as i32),
    );
    caps.add_abs_info(abs::ABS_MT_TRACKING_ID, axis(0, 0xFFFF));
    caps.add_abs_info(abs::ABS_MT_POSITION_X, x);
    caps.add_abs_info(abs::ABS_MT_POSITION_Y, y);
}

/// Caps for an RMI4 touchpad: slot-protocol-B axes over the full
/// sensor range, clickpad button, `INPUT_PROP_POINTER |
/// INPUT_PROP_BUTTONPAD` (the same property bits the I2C-HID PTP
/// caps carry — libinput classifies BUTTONPAD devices as
/// touchpads).
fn rmi_caps() -> DeviceCaps {
    let mut caps = DeviceCaps::new();
    add_mt_axes(&mut caps, MAX_PUMP_SLOTS, axis(0, 0xFFFF), axis(0, 0xFFFF));
    caps.add_abs_info(abs::ABS_PRESSURE, axis(0, 255));
    caps.add_abs_info(abs::ABS_MT_PRESSURE, axis(0, 255));
    caps.add_key(evkey::BTN_TOUCH);
    caps.add_key(evkey::BTN_LEFT);
    caps.add_prop(prop::POINTER);
    caps.add_prop(prop::BUTTONPAD);
    caps
}

/// Caps for an Elan touchpad: slot-protocol-B axes over the probed
/// max-X / max-Y (with the probed resolution, as Linux sets
/// `input_abs_set_res`), clickpad button, `INPUT_PROP_POINTER |
/// INPUT_PROP_BUTTONPAD`.
fn elan_caps(params: &ElanDeviceParams) -> DeviceCaps {
    let mut caps = DeviceCaps::new();
    let x = AxisInfo {
        min: 0,
        max: params.max_x as i32,
        fuzz: 0,
        flat: 0,
        res: params.res_x_dots_per_mm as i32,
    };
    let y = AxisInfo {
        min: 0,
        max: params.max_y as i32,
        fuzz: 0,
        flat: 0,
        res: params.res_y_dots_per_mm as i32,
    };
    add_mt_axes(&mut caps, elan::ELAN_MAX_FINGERS, x, y);
    caps.add_abs_info(abs::ABS_PRESSURE, axis(0, elan::ELAN_MAX_PRESSURE as i32));
    caps.add_abs_info(
        abs::ABS_MT_PRESSURE,
        axis(0, elan::ELAN_MAX_PRESSURE as i32),
    );
    caps.add_key(evkey::BTN_TOUCH);
    caps.add_key(evkey::BTN_LEFT);
    caps.add_prop(prop::POINTER);
    caps.add_prop(prop::BUTTONPAD);
    caps
}

// ── Bind ─────────────────────────────────────────────────────────────

/// Caller-side post-address RMI/Elan bind: VID/PID classify →
/// HID interface + endpoints → Report Descriptor fetch → endpoint
/// config → SET_CONFIGURATION → SET_PROTOCOL(Report) → SET_IDLE →
/// arm interrupt-IN → vendor probe → evdev register.
///
/// Returns `Err(HidError::NotBootKeyboard)` when the VID/PID is
/// not in either vendor table, when no HID interface qualifies,
/// or when the vendor probe fails — the attach dispatcher treats
/// any error as "try the next binder". A probe failure is NOT
/// returned to the dispatcher directly: this function falls back
/// to generic HID for the same interface first, so the device
/// stays bound (possibly in RMI mode if the mode-set already
/// landed — the generic dispatcher then sees vendor reports it
/// cannot decode, which is still strictly better than a freed
/// slot; a device that answers nothing is broken either way).
pub async fn try_bind_rmi_elan_already_addressed(
    xhci_dev: &Xhci,
    slot_id: u8,
    vendor: u16,
    product: u16,
    cfg: &[u8],
    topo: BindTopology,
) -> Result<AttachOutcome, HidError> {
    let kind = classify(vendor, product).ok_or(HidError::NotBootKeyboard)?;
    let prefer = match kind {
        VendorKind::Elan { .. } => Some(ELAN_TP_USB_INTF),
        VendorKind::Rmi { .. } => None,
    };
    let eps = find_rmi_elan_interface(cfg, prefer).ok_or(HidError::NoInterruptIn)?;
    let report_len =
        touchpad::report_descriptor_length(cfg, eps.hid_desc_off).ok_or(HidError::NoInterruptIn)?;
    if report_len == 0 || report_len > 4096 {
        return Err(HidError::NoInterruptIn);
    }
    let mut blob = alloc::vec![0u8; report_len as usize];
    let _ = xhci_dev
        .control_in(
            slot_id,
            touchpad::RT_DEV_TO_HOST_STD_IFACE,
            crate::xhci::USB_REQ_GET_DESCRIPTOR,
            (touchpad::HID_DESC_TYPE_REPORT as u16) << 8,
            eps.interface_num as u16,
            &mut blob,
        )
        .await
        .map_err(HidError::Xhci)?;
    let parsed = narf_hid::descriptor::parse(&blob).map_err(|_| HidError::NoInterruptIn)?;

    // Configure xHC-side endpoint contexts (IN + OUT when the
    // interface offers one).
    let mut ep_list = alloc::vec![eps.interrupt_in];
    if let Some(out) = eps.interrupt_out {
        ep_list.push(out);
    }
    xhci_dev
        .configure_endpoints(slot_id, &ep_list)
        .await
        .map_err(HidError::Xhci)?;

    // SET_CONFIGURATION before any class request (USB 2.0 §9.4.7)
    // — a HID touchpad held in Address state will STALL
    // SET_REPORT. bConfigurationValue at offset +5 of the 9-byte
    // cfg-descriptor header.
    if cfg.len() < 9 || cfg[1] != 2 {
        return Err(HidError::NoInterruptIn);
    }
    let cfg_value = cfg[5];
    xhci_dev
        .control_out(
            slot_id,
            0x00,
            STD_REQ_SET_CONFIGURATION,
            cfg_value as u16,
            0,
            &[],
        )
        .await
        .map_err(HidError::Xhci)?;

    // SET_PROTOCOL(Report) — HID §7.2.6. Synaptics / Elan
    // touchpads advertise the Boot interface for BIOS compat AND
    // ship powered-up in Boot Mouse protocol; without this the
    // device keeps emitting 3-byte boot-mouse reports instead of
    // vendor reports. Mirrors `hid::touchpad`.
    xhci_dev
        .control_out(
            slot_id,
            touchpad::RT_HOST_TO_DEV_CLASS_IFACE,
            HID_REQ_SET_PROTOCOL,
            HID_REPORT_PROTOCOL,
            eps.interface_num as u16,
            &[],
        )
        .await
        .map_err(HidError::Xhci)?;

    // SET_IDLE(0, 0) — "report on state change only". Non-fatal:
    // devices that don't implement it STALL; SET_PROTOCOL above
    // was the load-bearing call. Mirrors `BootKeyboard::attach`.
    let _ = xhci_dev
        .control_out(
            slot_id,
            touchpad::RT_HOST_TO_DEV_CLASS_IFACE,
            HID_REQ_SET_IDLE,
            0,
            eps.interface_num as u16,
            &[],
        )
        .await;

    // Arm one Normal TRB so the controller starts polling the
    // device — same pattern as `BootKeyboard::attach`. The probe's
    // `poll_input_report` and the pump both drain this endpoint.
    let in_dci = ((eps.interrupt_in.ep_addr & 0x0F) * 2) + 1;
    let in_len = (eps.interrupt_in.max_packet as usize).max(64) as u32;
    xhci_dev
        .arm_interrupt_in(slot_id, in_dci, in_len)
        .map_err(HidError::Xhci)?;
    let out_dci = eps.interrupt_out.map(|e| (e.ep_addr & 0x0F) * 2);
    let out_size = output_report_size(&parsed, eps.interrupt_out.as_ref(), &eps.interrupt_in);

    // Vendor probe. Any failure falls back to generic HID for the
    // same (already configured + armed) interface.
    match probe_and_register(
        xhci_dev,
        slot_id,
        kind,
        VendorProbeParams {
            interface_num: eps.interface_num,
            in_dci,
            out_dci,
            out_size,
        },
        topo,
    )
    .await
    {
        Ok(outcome) => Ok(outcome),
        Err(e) => {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "  usb-hid: rmi-elan slot={} vendor probe failed ({:?}); falling back to generic HID",
                slot_id, e
            );
            generic::try_bind_generic_already_armed(
                xhci_dev,
                slot_id,
                eps.interface_num,
                in_dci,
                &blob,
                topo.port,
                topo.hub_port,
            )
            .await
            .map(|()| AttachOutcome::GenericHid)
            .map_err(|_| HidError::NotBootKeyboard)
        }
    }
}

/// Endpoint parameters for the vendor probe: the interface and
/// interrupt endpoints the probe binds to, plus the output report
/// size the transport needs.
#[derive(Copy, Clone, Debug)]
struct VendorProbeParams {
    interface_num: u8,
    in_dci: u8,
    out_dci: Option<u8>,
    out_size: usize,
}

/// Run the vendor probe and register the binding. Every error is
/// mapped to `HidError::NotBootKeyboard` — the value is only a
/// "not bound" signal for the generic-HID fallback in the caller.
#[allow(clippy::too_many_arguments)]
async fn probe_and_register(
    xhci_dev: &Xhci,
    slot_id: u8,
    kind: VendorKind,
    params: VendorProbeParams,
    topo: BindTopology,
) -> Result<AttachOutcome, HidError> {
    const NOT_BOUND: HidError = HidError::NotBootKeyboard;
    let VendorProbeParams {
        interface_num,
        in_dci,
        out_dci,
        out_size,
    } = params;
    match kind {
        VendorKind::Rmi { quirks } => {
            let io = UsbHidIo::new(
                xhci_dev.id(),
                slot_id,
                interface_num,
                in_dci,
                out_dci,
                quirks,
            );
            let mut transport = HidRmiTransport::new(io, out_size, quirks);
            transport
                .set_mode(rmi::RMI_MODE_ATTN_REPORTS)
                .map_err(|_| NOT_BOUND)?;
            let probe = RmiProbe::probe(&mut transport).map_err(|_| NOT_BOUND)?;
            let mut caps = rmi_caps();
            if let Some(id) = resolve_usb_identity(
                xhci_dev,
                slot_id,
                topo.port,
                topo.hub_port,
                "USB RMI4 Touchpad",
            )
            .await
            {
                apply_identity(&mut caps, &id);
            }
            let (evdev_id, evdev_node) = ROUTER.register_device(caps);
            let binding = Arc::new(RmiElanBinding {
                slot_id,
                in_dci,
                interface_num,
                hub_port: topo.hub_port,
                kind: RmiElanKind::Rmi {
                    probe,
                    transport: IrqSafeSpinLock::new(Box::new(transport)),
                },
                pump: IrqSafeSpinLock::new(PumpState::new()),
                x_range: (0, 0xFFFF),
                y_range: (0, 0xFFFF),
                evdev_id,
                evdev_node,
            });
            RMI_ELAN_DEVICES.of(xhci_dev.id()).lock().push(binding);
            ATTACHED_RMI_ELAN_COUNT.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
            {
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "  usb-hid: rmi slot={} iface={} dci={} bound (RMI4-over-HID)",
                    slot_id,
                    interface_num,
                    in_dci
                );
            }
            Ok(AttachOutcome::RmiElanTouchpad)
        }
        VendorKind::Elan { quirks } => {
            // Elan never uses interrupt-OUT: every host→device
            // transfer is a Feature SET_REPORT.
            let mut io = UsbHidIo::new(
                xhci_dev.id(),
                slot_id,
                interface_num,
                in_dci,
                None,
                DeviceQuirks::empty(),
            );
            // Params first (Linux reads them in
            // `elan_input_configured`), then absolute mode (Linux
            // `elan_probe` → `elan_start_multitouch`).
            let params = elan::read_device_params(&mut io).map_err(|_| NOT_BOUND)?;
            elan::enable_absolute_mode(&mut io).map_err(|_| NOT_BOUND)?;
            let mut caps = elan_caps(&params);
            if let Some(id) = resolve_usb_identity(
                xhci_dev,
                slot_id,
                topo.port,
                topo.hub_port,
                "USB Elan Touchpad",
            )
            .await
            {
                apply_identity(&mut caps, &id);
            }
            let (evdev_id, evdev_node) = ROUTER.register_device(caps);
            let binding = Arc::new(RmiElanBinding {
                slot_id,
                in_dci,
                interface_num,
                hub_port: topo.hub_port,
                kind: RmiElanKind::Elan {
                    params,
                    io: IrqSafeSpinLock::new(Box::new(io) as Box<dyn ElanHidIo + Send + Sync>),
                    quirks,
                },
                pump: IrqSafeSpinLock::new(PumpState::new()),
                x_range: (0, params.max_x as i32),
                y_range: (0, params.max_y as i32),
                evdev_id,
                evdev_node,
            });
            RMI_ELAN_DEVICES.of(xhci_dev.id()).lock().push(binding);
            ATTACHED_RMI_ELAN_COUNT.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
            {
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "  usb-hid: elan slot={} iface={} dci={} bound (max {}x{})",
                    slot_id,
                    interface_num,
                    in_dci,
                    params.max_x,
                    params.max_y
                );
            }
            Ok(AttachOutcome::RmiElanTouchpad)
        }
    }
}

// ── Pump + registry ──────────────────────────────────────────────────

/// Dispatch one raw interrupt-IN report to the vendor pump.
fn pump_report(binding: &RmiElanBinding, report: &[u8]) -> usize {
    if report.is_empty() {
        return 0;
    }
    match &binding.kind {
        RmiElanKind::Rmi { probe, transport } => pump_rmi_report(binding, probe, transport, report),
        RmiElanKind::Elan { params, .. } => pump_elan_report(binding, params.max_y, report),
    }
}

/// Drain reports from every bound RMI/Elan touchpad. Returns the
/// total events emitted across all bindings. Called from the
/// supervisor's pump cycle alongside the PTP / consumer pumps.
pub fn pump_all(xhci_dev: &Xhci) -> usize {
    let bindings: Vec<Arc<RmiElanBinding>> = {
        let g = RMI_ELAN_DEVICES.of(xhci_dev.id()).lock();
        g.clone()
    };
    let mut total = 0usize;
    for binding in &bindings {
        let mut buf = [0u8; RMI_ELAN_IN_BUF_BYTES];
        let mut reports = 0usize;
        loop {
            match xhci_dev.poll_interrupt_in(binding.slot_id, binding.in_dci, &mut buf) {
                Ok(Some(n)) => {
                    reports += 1;
                    total += pump_report(binding, &buf[..n.min(RMI_ELAN_IN_BUF_BYTES)]);
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        // Completed interrupt-IN transfers are activity on the
        // binding's hub port (#840) — feed even when a report
        // decoded to zero emitted events. No-op when
        // root-attached.
        if reports > 0 {
            if let Some((hub_slot, port)) = binding.hub_port {
                mark_port_activity(xhci_dev.id(), hub_slot, port);
            }
        }
    }
    total
}

/// Hub contexts of all live RMI/Elan bindings (root-attached
/// bindings omitted). Aggregated by `hid::hub_ports` for the
/// supervisor's HID wake step.
pub fn hub_ports(controller: u8) -> Vec<(u8, u8)> {
    let g = RMI_ELAN_DEVICES.of(controller).lock();
    g.iter().filter_map(|b| b.hub_port).collect()
}

/// Unregister an RMI/Elan touchpad's evdev DeviceNode from the
/// ROUTER. Call when the device is detached / unplugged.
pub fn unregister_rmi_elan_evdev(controller: u8, slot_id: u8) {
    let mut g = RMI_ELAN_DEVICES.of(controller).lock();
    if let Some(pos) = g.iter().position(|b| b.slot_id == slot_id) {
        let binding = g.remove(pos);
        ROUTER.unregister_device(binding.evdev_id);
        crate::hid::saturating_sub(&ATTACHED_RMI_ELAN_COUNT, 1);
    }
}

/// Unregister every RMI/Elan touchpad bound on `controller`.
/// Called on a controller recovery epoch change.
pub fn unregister_all_rmi_elan(controller: u8) {
    let slots: Vec<u8> = RMI_ELAN_DEVICES
        .of(controller)
        .lock()
        .iter()
        .map(|b| b.slot_id)
        .collect();
    for slot in slots {
        unregister_rmi_elan_evdev(controller, slot);
    }
}

/// Drive the mute-status LED on a bound Elan touchpad
/// (`HAS_LED` devices only; Linux `elan_mute_led_set_brigtness`).
/// Returns `false` when no Elan binding owns `slot_id`, the
/// device has no LED, or the Feature write fails. Best-effort:
/// the LED is a userspace led-class concern, never load-bearing
/// for the touch path.
pub fn set_mute_led_for_slot(controller: u8, slot_id: u8, on: bool) -> bool {
    let binding = {
        let g = RMI_ELAN_DEVICES.of(controller).lock();
        match g.iter().find(|b| b.slot_id == slot_id) {
            Some(b) => Arc::clone(b),
            None => return false,
        }
    };
    let RmiElanKind::Elan { io, quirks, .. } = &binding.kind else {
        return false;
    };
    if !quirks.contains(ElanQuirks::HAS_LED) {
        return false;
    }
    let mut g = io.lock();
    // `elan::set_mute_led` is generic over `T: ElanHidIo` (implicitly
    // `Sized`), so it cannot take `&mut dyn ElanHidIo` here; call the
    // trait method directly — identical body (encode + `set_feature`).
    g.set_feature(&elan::encode_mute_led(on)).is_ok()
}

#[doc(hidden)]
pub fn __reset_rmi_elan_for_test() {
    for (_, bindings) in RMI_ELAN_DEVICES.each() {
        bindings.lock().clear();
    }
    ATTACHED_RMI_ELAN_COUNT.store(0, core::sync::atomic::Ordering::Release);
}

// ── Tests ────────────────────────────────────────────────────────────
//
// Fixtures are built from the spec itself (spec-fixture
// discipline): `FakeUsbHidIo` answers RMI register reads from a
// synthetic PDT + register image through the real HID framing
// (output-report write / read-addr request → read-data input
// report), and answers Elan Feature GETs from staged responses,
// so the probe + pump under test run the production encode /
// decode paths with no hardware.

#[cfg(target_arch = "x86_64")]
pub(crate) mod tests {
    use super::*;
    use alloc::collections::VecDeque;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use narf_input::{__reset_global_ring_for_test, init_global_ring, pop_touch, TouchState};
    use narf_input_driver::rmi4_core::{PDT_ENTRY_SIZE, PDT_LAST_SLOT_OFFSET};
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Fake HID transport: a 256-byte page-0 RMI register image
    /// plus staged input reports and staged Feature GET responses.
    /// Output reports are interpreted (page-select writes,
    /// read-addr requests synthesise read-data input reports);
    /// Feature SETs are captured for assertion.
    struct FakeUsbHidIo {
        page: [u8; 256],
        cur_page: u8,
        staged_in: VecDeque<Vec<u8>>,
        out_reports: Vec<Vec<u8>>,
        feature_sets: Vec<Vec<u8>>,
        feature_gets: VecDeque<Vec<u8>>,
    }

    impl FakeUsbHidIo {
        fn new(page: [u8; 256]) -> Self {
            Self {
                page,
                cur_page: 0,
                staged_in: VecDeque::new(),
                out_reports: Vec::new(),
                feature_sets: Vec::new(),
                feature_gets: VecDeque::new(),
            }
        }

        fn stage_input(&mut self, report: Vec<u8>) {
            self.staged_in.push_back(report);
        }

        fn stage_feature_get(&mut self, response: Vec<u8>) {
            self.feature_gets.push_back(response);
        }
    }

    impl HidIo for FakeUsbHidIo {
        fn output_report(&mut self, report: &[u8]) -> Result<(), TransportError> {
            if report.is_empty() {
                return Err(TransportError::Short);
            }
            self.out_reports.push(report.to_vec());
            match report[0] {
                rmi::RMI_WRITE_REPORT_ID => {
                    if report.len() < 5 {
                        return Err(TransportError::Short);
                    }
                    let addr = u16::from_le_bytes([report[2], report[3]]);
                    let count = report[1] as usize;
                    if addr == 0x00FF {
                        // Page-select write (rmi_set_page).
                        self.cur_page = report[4];
                    } else if self.cur_page == 0 {
                        let lo = (addr & 0xFF) as usize;
                        let take = count
                            .min(report.len().saturating_sub(4))
                            .min(self.page.len().saturating_sub(lo));
                        self.page[lo..lo + take].copy_from_slice(&report[4..4 + take]);
                    }
                    Ok(())
                }
                rmi::RMI_READ_ADDR_REPORT_ID => {
                    if report.len() < 6 {
                        return Err(TransportError::Short);
                    }
                    let addr = u16::from_le_bytes([report[2], report[3]]);
                    let len = u16::from_le_bytes([report[4], report[5]]) as usize;
                    // The transport stages read-data responses for
                    // page 0 only (the fixture image is page 0).
                    let lo = (addr & 0xFF) as usize;
                    let take = len.min(self.page.len().saturating_sub(lo)).min(62);
                    let mut resp = alloc::vec![rmi::RMI_READ_DATA_REPORT_ID, take as u8];
                    resp.extend_from_slice(&self.page[lo..lo + take]);
                    self.staged_in.push_back(resp);
                    Ok(())
                }
                _ => Ok(()),
            }
        }

        fn set_feature_report(&mut self, report: &[u8]) -> Result<(), TransportError> {
            if report.is_empty() {
                return Err(TransportError::Short);
            }
            self.feature_sets.push(report.to_vec());
            Ok(())
        }

        fn poll_input_report(&mut self, dst: &mut [u8]) -> Result<usize, TransportError> {
            match self.staged_in.pop_front() {
                Some(rep) => {
                    let n = rep.len().min(dst.len());
                    dst[..n].copy_from_slice(&rep[..n]);
                    Ok(n)
                }
                None => Err(TransportError::Timeout),
            }
        }
    }

    impl ElanHidIo for FakeUsbHidIo {
        fn set_feature(&mut self, report: &[u8]) -> Result<(), TransportError> {
            if report.is_empty() {
                return Err(TransportError::Short);
            }
            self.feature_sets.push(report.to_vec());
            Ok(())
        }

        fn get_feature(&mut self, report_id: u8, dst: &mut [u8]) -> Result<usize, TransportError> {
            let _ = report_id;
            match self.feature_gets.pop_front() {
                Some(rep) => {
                    let n = rep.len().min(dst.len());
                    dst[..n].copy_from_slice(&rep[..n]);
                    Ok(n)
                }
                None => Err(TransportError::Short),
            }
        }
    }

    /// Page-0 register image with a three-function PDT (F$01, F$12,
    /// F$30) + terminator, an F$01 product-info block at 0x10, and
    /// an F$30 query block at its query base 0x90. Same layout as the
    /// `smoke_rmi4_pdt_three_function_walk` fixture in
    /// `drivers/input/src/tests.rs`, with F$12 in place of F$11.
    fn rmi_page_image() -> [u8; 256] {
        let mut page = [0u8; 256];
        let last = PDT_LAST_SLOT_OFFSET as usize;
        // F$01 entry at PDT_LAST_SLOT_OFFSET.
        page[last] = 0x10; // query base
        page[last + 1] = 0x20; // command base
        page[last + 2] = 0x30; // control base
        page[last + 3] = 0x40; // data base
        page[last + 4] = 0x01; // 1 IRQ source, version 0
        page[last + 5] = F01_DEVICE_CONTROL;
        // F$12 entry at PDT_LAST_SLOT_OFFSET - 6.
        let s2 = last - PDT_ENTRY_SIZE;
        page[s2] = 0x50;
        page[s2 + 1] = 0x60;
        page[s2 + 2] = 0x70;
        page[s2 + 3] = 0x80;
        page[s2 + 4] = 0x02; // 2 IRQ sources
        page[s2 + 5] = F12_2D_TOUCHPAD_NEXT;
        // F$30 entry at PDT_LAST_SLOT_OFFSET - 12.
        let s3 = last - 2 * PDT_ENTRY_SIZE;
        page[s3] = 0x90;
        page[s3 + 1] = 0xA0;
        page[s3 + 2] = 0xB0;
        page[s3 + 3] = 0xC0;
        page[s3 + 4] = 0x01; // 1 IRQ source
        page[s3 + 5] = F30_GPIO_LED;
        // Terminator (function_number = 0) at the next slot.
        page[s3 - PDT_ENTRY_SIZE + 5] = 0x00;
        // F$01 product info at query base 0x10: manuf=1, props,
        // firmware 0x1234, date, tester, serial.
        page[0x10..0x10 + 11]
            .copy_from_slice(&[0x01, 0x10, 0x34, 0x12, 24, 5, 29, 0x42, 0x42, 0xCA, 0xFE]);
        // F$30 query at its query base 0x90 (the PDT entry's
        // query base — 0xB0 is the control base, not the query
        // base): HAS_GPIO + 8 lines.
        page[0x90] = 0x08;
        page[0x90 + 1] = 0x08;
        page
    }

    /// Build a standalone (unregistered) RMI binding from a probed
    /// transport, for pump tests that need no xHCI.
    fn rmi_binding_for_test(
        probe: RmiProbe,
        transport: HidRmiTransport<FakeUsbHidIo>,
    ) -> Arc<RmiElanBinding> {
        let caps = rmi_caps();
        let (evdev_id, evdev_node) = ROUTER.register_device(caps);
        Arc::new(RmiElanBinding {
            slot_id: 7,
            in_dci: 3,
            interface_num: 0,
            hub_port: None,
            kind: RmiElanKind::Rmi {
                probe,
                transport: IrqSafeSpinLock::new(Box::new(transport)),
            },
            pump: IrqSafeSpinLock::new(PumpState::new()),
            x_range: (0, 0xFFFF),
            y_range: (0, 0xFFFF),
            evdev_id,
            evdev_node,
        })
    }

    /// Build a standalone Elan binding for pump tests.
    fn elan_binding_for_test(params: ElanDeviceParams) -> Arc<RmiElanBinding> {
        let caps = elan_caps(&params);
        let (evdev_id, evdev_node) = ROUTER.register_device(caps);
        let io = UsbHidIo::new(0, 7, 0, 3, None, DeviceQuirks::empty());
        Arc::new(RmiElanBinding {
            slot_id: 7,
            in_dci: 3,
            interface_num: 0,
            hub_port: None,
            kind: RmiElanKind::Elan {
                params,
                io: IrqSafeSpinLock::new(Box::new(io) as Box<dyn ElanHidIo + Send + Sync>),
                quirks: ElanQuirks::empty(),
            },
            pump: IrqSafeSpinLock::new(PumpState::new()),
            x_range: (0, params.max_x as i32),
            y_range: (0, params.max_y as i32),
            evdev_id,
            evdev_node,
        })
    }

    fn smoke_classify_rmi_elan_tables() -> TestResult {
        use narf_input_driver::hid_elan::USB_VENDOR_ID_ELAN;
        use narf_input_driver::hid_rmi::{
            USB_DEVICE_ID_RAZER_BLADE_14, USB_VENDOR_ID_RAZER, USB_VENDOR_ID_SYNAPTICS,
        };
        // RMI: Razer Blade 14 binds with the phys-buttons quirk.
        match classify(USB_VENDOR_ID_RAZER, USB_DEVICE_ID_RAZER_BLADE_14) {
            Some(VendorKind::Rmi { quirks }) => {
                if !quirks.contains(DeviceQuirks::HAS_PHYS_BUTTONS) {
                    return TestResult::Fail("Razer Blade 14 missing HAS_PHYS_BUTTONS");
                }
            }
            _ => return TestResult::Fail("Razer Blade 14 must classify as RMI"),
        }
        // RMI: Synaptics Acer Switch 5 binds with OUTPUT_SET_REPORT.
        match classify(
            USB_VENDOR_ID_SYNAPTICS,
            narf_input_driver::hid_rmi::USB_DEVICE_ID_SYNAPTICS_ACER_SWITCH5,
        ) {
            Some(VendorKind::Rmi { quirks }) => {
                if !quirks.contains(DeviceQuirks::OUTPUT_SET_REPORT) {
                    return TestResult::Fail("Acer Switch 5 missing OUTPUT_SET_REPORT");
                }
            }
            _ => return TestResult::Fail("Acer Switch 5 must classify as RMI"),
        }
        // Elan: HP Pavilion X2 (USB row) binds with the LED quirk.
        match classify(USB_VENDOR_ID_ELAN, 0x074D) {
            Some(VendorKind::Elan { quirks }) => {
                if !quirks.contains(ElanQuirks::HAS_LED) {
                    return TestResult::Fail("HP X2 missing HAS_LED");
                }
            }
            _ => return TestResult::Fail("HP X2 must classify as Elan"),
        }
        // Elan I2C-HID rows must NOT match on USB: the Toshiba
        // Click L9W (0x0401) and Lenovo ThinkBook (0x301A) are
        // i2c-HID devices and would be misbound here.
        if classify(USB_VENDOR_ID_ELAN, 0x0401).is_some() {
            return TestResult::Fail("Toshiba Click L9W (I2cHid) must not classify on USB");
        }
        if classify(USB_VENDOR_ID_ELAN, 0x301A).is_some() {
            return TestResult::Fail("Lenovo ThinkBook (I2cHid) must not classify on USB");
        }
        // Unknown VID/PID falls through to the PTP / generic
        // binders below.
        if classify(0xFFFF, 0xFFFF).is_some() {
            return TestResult::Fail("unknown VID/PID must not classify");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/hid/rmi-elan", smoke_classify_rmi_elan_tables);

    fn smoke_find_rmi_elan_interface() -> TestResult {
        // Config blob: iface 0 (HID, 1 IN ep) + iface 1 (HID, IN +
        // OUT eps). Total length 0x30 = 48 bytes... recomputed
        // below from the actual blob length.
        let mut cfg: Vec<u8> = alloc::vec![
            0x09, 0x02, 0x00, 0x00, 0x02, 0x01, 0x00, 0x80,
            0x32, // config (total patched below)
            0x09, 0x04, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, // iface 0, HID
            0x09, 0x21, 0x11, 0x01, 0x00, 0x01, 0x22, 0x40, 0x00, // HID desc
            0x07, 0x05, 0x81, 0x03, 0x40, 0x00, 0x0A, // ep IN 0x81, mps 64
            0x09, 0x04, 0x01, 0x00, 0x02, 0x03, 0x00, 0x00, 0x00, // iface 1, HID
            0x09, 0x21, 0x11, 0x01, 0x00, 0x01, 0x22, 0x40, 0x00, // HID desc
            0x07, 0x05, 0x82, 0x03, 0x40, 0x00, 0x0A, // ep IN 0x82, mps 64
            0x07, 0x05, 0x02, 0x03, 0x40, 0x00, 0x0A, // ep OUT 0x02, mps 64
        ];
        let total = cfg.len() as u16;
        cfg[2..4].copy_from_slice(&total.to_le_bytes());
        // No preference: first HID interface wins.
        let first = match find_rmi_elan_interface(&cfg, None) {
            Some(e) => e,
            None => return TestResult::Fail("no interface found without preference"),
        };
        if first.interface_num != 0 || first.interrupt_in.ep_addr != 0x81 {
            return TestResult::Fail("first interface must be iface 0 / ep 0x81");
        }
        if first.interrupt_out.is_some() {
            return TestResult::Fail("iface 0 has no OUT endpoint");
        }
        // Prefer interface 1 (the Elan rule): iface 1 with both
        // endpoints wins.
        let pref = match find_rmi_elan_interface(&cfg, Some(1)) {
            Some(e) => e,
            None => return TestResult::Fail("no interface found with preference 1"),
        };
        if pref.interface_num != 1 || pref.interrupt_in.ep_addr != 0x82 {
            return TestResult::Fail("preferred interface must be iface 1 / ep 0x82");
        }
        match pref.interrupt_out {
            Some(out) if out.ep_addr == 0x02 => {}
            _ => return TestResult::Fail("iface 1 must expose OUT ep 0x02"),
        }
        // No HID interface at all: a bare config blob.
        let bare: Vec<u8> = alloc::vec![0x09, 0x02, 0x09, 0x00, 0x00, 0x01, 0x00, 0x80, 0x32];
        if find_rmi_elan_interface(&bare, None).is_some() {
            return TestResult::Fail("bare config must yield no interface");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/hid/rmi-elan", smoke_find_rmi_elan_interface);

    fn smoke_output_report_size_from_descriptor() -> TestResult {
        use narf_hid::descriptor::parse;
        // Descriptor declaring a 19-byte Output report for ID 0x09
        // (Report Size 8 x Count 19): size must be 19 + 1 ID byte.
        let desc: &[u8] = &[
            0x05, 0x01, // Usage Page (Generic Desktop)
            0x09, 0x02, // Usage (Mouse)
            0xA1, 0x01, // Collection (Application)
            0x85, 0x09, //   Report ID (9)
            0x75, 0x08, //   Report Size (8)
            0x95, 0x13, //   Report Count (19)
            0x91, 0x02, //   Output (Data, Variable, Absolute)
            0xC0, // End Collection
        ];
        let parsed = match parse(desc) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("descriptor parse failed"),
        };
        let in_ep = EndpointConfig {
            ep_addr: 0x81,
            max_packet: 64,
            kind: EndpointKind::InterruptIn,
            interval: 10,
        };
        let out_ep = EndpointConfig {
            ep_addr: 0x02,
            max_packet: 64,
            kind: EndpointKind::InterruptOut,
            interval: 10,
        };
        if output_report_size(&parsed, Some(&out_ep), &in_ep) != 20 {
            return TestResult::Fail("Output-item size must be 19 body + 1 ID byte");
        }
        // Descriptor with no Output items: falls back to the OUT
        // endpoint MPS, then to the IN MPS.
        let input_only: &[u8] = &[
            0x05, 0x01, 0x09, 0x02, 0xA1, 0x01, 0x85, 0x01, 0x75, 0x08, 0x95, 0x01, 0x81, 0x02,
            0xC0,
        ];
        let parsed2 = match parse(input_only) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("input-only descriptor parse failed"),
        };
        if output_report_size(&parsed2, Some(&out_ep), &in_ep) != 64 {
            return TestResult::Fail("no Output items must fall back to OUT MPS");
        }
        if output_report_size(&parsed2, None, &in_ep) != 64 {
            return TestResult::Fail("no OUT endpoint must fall back to IN MPS");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/hid/rmi-elan",
        smoke_output_report_size_from_descriptor
    );

    fn smoke_rmi_probe_end_to_end_over_fake_hid() -> TestResult {
        // 1. The mode-set encoding lands verbatim as a Feature
        // report through the fake transport.
        let mut direct = FakeUsbHidIo::new(rmi_page_image());
        if direct
            .set_feature_report(&rmi::encode_set_rmi_mode(rmi::RMI_MODE_ATTN_REPORTS))
            .is_err()
        {
            return TestResult::Fail("direct set_feature_report failed");
        }
        if direct.feature_sets.first().map(|b| b.as_slice()) != Some([0x0F, 0x01].as_slice()) {
            return TestResult::Fail("mode-set Feature report must be [0x0F, 0x01]");
        }
        // 2. Full probe over the fake HID framing: set mode, walk
        // the PDT, read F$01 product info + F$30 query.
        let fake = FakeUsbHidIo::new(rmi_page_image());
        let mut transport = HidRmiTransport::new(fake, 19, DeviceQuirks::empty());
        if transport.set_mode(rmi::RMI_MODE_ATTN_REPORTS).is_err() {
            return TestResult::Fail("set_mode failed over fake HID");
        }
        let probe = match RmiProbe::probe(&mut transport) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("RMI probe failed over fake HID"),
        };
        if !probe.product.is_synaptics() {
            return TestResult::Fail("F01 product info must decode as Synaptics");
        }
        if probe.f12.is_none() {
            return TestResult::Fail("F12 must be present in the fixture PDT");
        }
        if probe.f11.is_some() {
            return TestResult::Fail("F11 must be absent from the fixture PDT");
        }
        if probe.f30.is_none() || probe.f30_gpio_count != 8 {
            return TestResult::Fail("F30 must be present with 8 GPIO lines");
        }
        // Interrupt map: F01 owns bit 0, F12 owns bits 1-2, F30
        // owns bit 3 (sequential assignment down the PDT).
        if probe.source_mask_for(F01_DEVICE_CONTROL) != 0x01 {
            return TestResult::Fail("F01 must own source bit 0");
        }
        if probe.source_mask_for(F12_2D_TOUCHPAD_NEXT) != 0x06 {
            return TestResult::Fail("F12 must own source bits 1-2");
        }
        if probe.source_mask_for(F30_GPIO_LED) != 0x08 {
            return TestResult::Fail("F30 must own source bit 3");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/hid/rmi-elan",
        smoke_rmi_probe_end_to_end_over_fake_hid
    );

    fn smoke_rmi_attn_pump_emits_touch_events() -> TestResult {
        let fake = FakeUsbHidIo::new(rmi_page_image());
        let mut transport = HidRmiTransport::new(fake, 19, DeviceQuirks::empty());
        if transport.set_mode(rmi::RMI_MODE_ATTN_REPORTS).is_err() {
            return TestResult::Fail("set_mode failed over fake HID");
        }
        let probe = match RmiProbe::probe(&mut transport) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("RMI probe failed over fake HID"),
        };
        let binding = rmi_binding_for_test(probe, transport);
        init_global_ring(16);
        __reset_global_ring_for_test();
        // ATTN report: F12 sources (bits 1-2 = 0x06) + one F12
        // finger object at (0x0100, 0x0200), pressure 0x40.
        let attn: Vec<u8> = alloc::vec![
            rmi::RMI_ATTN_REPORT_ID,
            0x06,
            0x01, // object type: FINGER
            0x00,
            0x01, // X = 0x0100
            0x00,
            0x02, // Y = 0x0200
            0x40, // Z
            0x05, // Wx
            0x06, // Wy
        ];
        let pushed = pump_report(&binding, &attn);
        if pushed < 1 {
            return TestResult::Fail("ATTN pump pushed 0 events");
        }
        match pop_touch() {
            Some(t) if t.state == TouchState::Down => {
                if t.x == 0 || t.y == 0 {
                    return TestResult::Fail("ATTN contact coordinates must be non-zero");
                }
            }
            Some(_) => return TestResult::Fail("expected Down on first ATTN contact"),
            None => return TestResult::Fail("no TouchEvent in ring after ATTN pump"),
        }
        // A second identical ATTN report moves the same slot.
        let pushed2 = pump_report(&binding, &attn);
        if pushed2 < 1 {
            return TestResult::Fail("second ATTN pump pushed 0 events");
        }
        match pop_touch() {
            Some(t) if t.state == TouchState::Move => {}
            Some(_) => return TestResult::Fail("expected Move on repeated ATTN contact"),
            None => return TestResult::Fail("no TouchEvent for repeated ATTN"),
        }
        // An all-absent ATTN (F12 sources set, object type NONE)
        // releases the slot.
        let release: Vec<u8> = alloc::vec![
            rmi::RMI_ATTN_REPORT_ID,
            0x06,
            0x00, // object type: NONE
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ];
        let pushed3 = pump_report(&binding, &release);
        if pushed3 < 1 {
            return TestResult::Fail("release ATTN pump pushed 0 events");
        }
        match pop_touch() {
            Some(t) if t.state == TouchState::Up => {}
            Some(_) => return TestResult::Fail("expected Up on release ATTN"),
            None => return TestResult::Fail("no TouchEvent for release ATTN"),
        }
        ROUTER.unregister_device(binding.evdev_id);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/hid/rmi-elan",
        smoke_rmi_attn_pump_emits_touch_events
    );

    fn smoke_fake_hid_io_records_and_replays() -> TestResult {
        let mut fake = FakeUsbHidIo::new([0u8; 256]);
        // A staged input report replays verbatim through
        // poll_input_report, and the queue then reports Timeout.
        fake.stage_input(alloc::vec![0x0C, 0x01, 0xAA]);
        let mut buf = [0u8; 8];
        match fake.poll_input_report(&mut buf) {
            Ok(3) if buf[..3] == [0x0C, 0x01, 0xAA] => {}
            _ => return TestResult::Fail("staged input report must replay verbatim"),
        }
        if fake.poll_input_report(&mut buf).is_ok() {
            return TestResult::Fail("empty input queue must report Timeout");
        }
        // An output report is captured for assertion, and a
        // page-select write updates the fake's current page.
        let page1 = rmi::encode_set_page(1, 19);
        if fake.output_report(&page1).is_err() {
            return TestResult::Fail("page-select output report failed");
        }
        if fake.out_reports.first().map(|b| b.as_slice()) != Some(page1.as_slice()) {
            return TestResult::Fail("output report must be captured verbatim");
        }
        if fake.cur_page != 1 {
            return TestResult::Fail("page-select write must update the fake page");
        }
        // An empty output report is a Short, not a capture.
        if fake.output_report(&[]).is_ok() {
            return TestResult::Fail("empty output report must fail");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/hid/rmi-elan",
        smoke_fake_hid_io_records_and_replays
    );

    fn smoke_rmi_probe_failure_is_protocol() -> TestResult {
        // An empty register image: no PDT entries, no F01 — the
        // probe must fail, which is the signal the bind's
        // generic-HID fallback keys on.
        let fake = FakeUsbHidIo::new([0u8; 256]);
        let mut transport = HidRmiTransport::new(fake, 19, DeviceQuirks::empty());
        if RmiProbe::probe(&mut transport).is_ok() {
            return TestResult::Fail("probe must fail on an empty PDT");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/hid/rmi-elan",
        smoke_rmi_probe_failure_is_protocol
    );

    fn smoke_elan_param_and_absolute_mode_over_fake_hid() -> TestResult {
        use narf_input_driver::hid_elan::{convert_resolution, decode_param_response_le16, param};
        let mut fake = FakeUsbHidIo::new([0u8; 256]);
        // Staged GET responses, in call order: max_x = 0x1234,
        // max_y = 0x5678, res bytes (0x20, 0x10).
        fake.stage_feature_get(alloc::vec![0x0D, 0x05, 0x03, 0x34, 0x12]);
        fake.stage_feature_get(alloc::vec![0x0D, 0x05, 0x03, 0x78, 0x56]);
        fake.stage_feature_get(alloc::vec![0x0D, 0x05, 0x03, 0x20, 0x10]);
        let params = match elan::read_device_params(&mut fake) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("read_device_params failed over fake HID"),
        };
        if params.max_x != 0x1234 || params.max_y != 0x5678 {
            return TestResult::Fail("Elan params mis-decoded");
        }
        if params.res_x_dots_per_mm != convert_resolution(0x20)
            || params.res_y_dots_per_mm != convert_resolution(0x10)
        {
            return TestResult::Fail("Elan resolution mis-decoded");
        }
        // The three SET phases must carry the param codes in order.
        if fake.feature_sets.len() < 3 {
            return TestResult::Fail("expected 3 param-query SETs");
        }
        if fake.feature_sets[0] != elan::encode_param_query(param::MAX_X) {
            return TestResult::Fail("first SET must query MAX_X");
        }
        if fake.feature_sets[1] != elan::encode_param_query(param::MAX_Y) {
            return TestResult::Fail("second SET must query MAX_Y");
        }
        if fake.feature_sets[2] != elan::encode_param_query(param::RES) {
            return TestResult::Fail("third SET must query RES");
        }
        // Absolute mode: the 5 magic bytes, verbatim.
        if elan::enable_absolute_mode(&mut fake).is_err() {
            return TestResult::Fail("enable_absolute_mode failed over fake HID");
        }
        if fake.feature_sets.last().map(|b| b.as_slice())
            != Some([0x0D, 0x00, 0x03, 0x21, 0x00].as_slice())
        {
            return TestResult::Fail("absolute-mode Feature report wrong");
        }
        // The GET-response decoder itself (unit check).
        if decode_param_response_le16(&[0x0D, 0x05, 0x03, 0x34, 0x12]) != Some(0x1234) {
            return TestResult::Fail("param response LE16 decode wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/hid/rmi-elan",
        smoke_elan_param_and_absolute_mode_over_fake_hid
    );

    fn smoke_elan_usb_single_finger_pump() -> TestResult {
        let params = ElanDeviceParams {
            max_x: 0x1234,
            max_y: 0x5678,
            res_x_dots_per_mm: 43,
            res_y_dots_per_mm: 22,
        };
        let binding = elan_binding_for_test(params);
        init_global_ring(16);
        __reset_global_ring_for_test();
        // 0x81 single-finger report: finger 0 present (bit 3) +
        // button (bit 0); record at [3..8] decodes x=0x0100,
        // raw_y=0x5478 → y = max_y - raw_y = 0x0200.
        let report: Vec<u8> = alloc::vec![0x81, 0x00, 0x09, 0x14, 0x00, 0x78, 0x00, 0x80];
        let pushed = pump_report(&binding, &report);
        if pushed < 1 {
            return TestResult::Fail("Elan 0x81 pump pushed 0 events");
        }
        match pop_touch() {
            Some(t) if t.state == TouchState::Down => {
                if t.x == 0 || t.y == 0 {
                    return TestResult::Fail("Elan contact coordinates must be non-zero");
                }
                if t.pressure != 0x80 {
                    return TestResult::Fail("Elan contact pressure must be 0x80");
                }
            }
            Some(_) => return TestResult::Fail("expected Down on first Elan contact"),
            None => return TestResult::Fail("no TouchEvent in ring after Elan pump"),
        }
        // Finger lift: same report with no presence bits and no
        // button → Up.
        let lift: Vec<u8> = alloc::vec![0x81, 0x00, 0x00, 0x14, 0x00, 0x78, 0x00, 0x80];
        if pump_report(&binding, &lift) < 1 {
            return TestResult::Fail("Elan lift pump pushed 0 events");
        }
        match pop_touch() {
            Some(t) if t.state == TouchState::Up => {}
            Some(_) => return TestResult::Fail("expected Up on Elan lift"),
            None => return TestResult::Fail("no TouchEvent for Elan lift"),
        }
        ROUTER.unregister_device(binding.evdev_id);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/hid/rmi-elan",
        smoke_elan_usb_single_finger_pump
    );

    fn smoke_elan_mt_pair_pump() -> TestResult {
        let params = ElanDeviceParams {
            max_x: 0x1234,
            max_y: 0x5678,
            res_x_dots_per_mm: 43,
            res_y_dots_per_mm: 22,
        };
        let binding = elan_binding_for_test(params);
        init_global_ring(16);
        __reset_global_ring_for_test();
        // 0x82 first-finger half: fingers 0+1 present (bits 3,4);
        // record at [3..8] is finger 0's (x=0x0100, y=0x0200).
        let first: Vec<u8> = alloc::vec![0x82, 0x00, 0x18, 0x14, 0x00, 0x78, 0x00, 0x80];
        if pump_report(&binding, &first) != 0 {
            return TestResult::Fail("0x82 half must stash without emitting");
        }
        // 0x83 second-finger half: record at [1..6] is finger 1's
        // (x=0x0200, y=0x0300).
        let second: Vec<u8> = alloc::vec![0x83, 0x24, 0x00, 0x68, 0x00, 0x70, 0x00, 0x00];
        let pushed = pump_report(&binding, &second);
        if pushed < 2 {
            return TestResult::Fail("0x82+0x83 pair must emit 2 contacts");
        }
        let mut downs = 0;
        while let Some(t) = pop_touch() {
            if t.state == TouchState::Down {
                downs += 1;
            }
        }
        if downs != 2 {
            return TestResult::Fail("expected 2 Down TouchEvents from the MT pair");
        }
        // A lone 0x83 with no stashed 0x82 must not emit.
        if pump_report(&binding, &second) != 0 {
            return TestResult::Fail("lone 0x83 must not emit");
        }
        ROUTER.unregister_device(binding.evdev_id);
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/hid/rmi-elan", smoke_elan_mt_pair_pump);
}
