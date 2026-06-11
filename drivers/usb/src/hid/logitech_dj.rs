//! Logitech Unifying / Bolt / Nano Receiver (DJ protocol) — clean-room.
//!
//! ## References
//!
//! - `drivers/hid/hid-logitech-dj.c` (Linux, GPL-2.0-or-later) —
//!   receiver enumeration, DJ wire format, pair / unpair / connection
//!   status notifications.
//! - `drivers/hid/hid-ids.h` — receiver VID/PID list.
//!
//! ## Shape
//!
//! A Logitech Unifying / Bolt / Lightspeed / Nano receiver presents
//! itself as a single USB HID device that multiplexes up to 7 paired
//! sub-devices (keyboards, mice, presenters, ...) over a 2.4 GHz RF
//! link. Each input report carries a 1-byte device index (1..7)
//! identifying which sub-device produced it, followed by a payload
//! whose shape depends on the report type byte.
//!
//! Wire framing (per `hid-logitech-dj.c:126`):
//!
//! ```text
//!   byte 0 : report ID    — 0x20 (DJ short), 0x21 (DJ long),
//!                            0x10 (HID++ short), 0x11 (HID++ long),
//!                            0x12 (HID++ very long)
//!   byte 1 : device index — 0 = receiver itself, 1..7 = paired slot,
//!                            0xFF = HID++ receiver-side message
//!   byte 2 : report type  — 0x01..0x1F = RF-forwarded input
//!                            (keyboard / mouse / consumer / etc),
//!                            0x40..0x7F = receiver notifications
//!                            (pair / unpair / link-loss / errors),
//!                            0x80..0xFF = host-to-receiver commands
//!   byte 3.. : payload    — N bytes; size depends on report ID
//! ```
//!
//! On probe the host issues `REPORT_TYPE_CMD_GET_PAIRED_DEVICES`
//! (`0x81`) on the receiver index (0xFF for HID++, 0x00 for DJ) and
//! the receiver replies with a series of `REPORT_TYPE_NOTIF_DEVICE_PAIRED`
//! (`0x41`) notifications, one per occupied slot. Each notification
//! carries the sub-device's name, RF-report capabilities bitmask, and
//! eQuad-ID.
//!
//! Subsequent input reports tagged with a device index in 1..7 are
//! demultiplexed back to per-slot input streams that re-enter the
//! standard HID stack (keyboard / mouse / consumer / digitizer).

#![allow(dead_code)]

use core::sync::atomic::{AtomicU8, Ordering};

// ── Vendor / Device IDs (mirrors hid-ids.h:929..941) ───────────────

/// USB Vendor ID — Logitech Inc. (`hid-ids.h:880`).
pub const USB_VENDOR_ID_LOGITECH: u16 = 0x046d;

pub const USB_DEVICE_ID_LOGITECH_27MHZ_MOUSE_RECEIVER: u16 = 0xc51b;
pub const USB_DEVICE_ID_LOGITECH_UNIFYING_RECEIVER: u16 = 0xc52b;
pub const USB_DEVICE_ID_LOGITECH_NANO_RECEIVER: u16 = 0xc52f;
pub const USB_DEVICE_ID_LOGITECH_G700_RECEIVER: u16 = 0xc531;
pub const USB_DEVICE_ID_LOGITECH_UNIFYING_RECEIVER_2: u16 = 0xc532;
pub const USB_DEVICE_ID_LOGITECH_NANO_RECEIVER_2: u16 = 0xc534;
pub const USB_DEVICE_ID_LOGITECH_NANO_RECEIVER_LIGHTSPEED_1: u16 = 0xc539;
pub const USB_DEVICE_ID_LOGITECH_NANO_RECEIVER_LIGHTSPEED_1_1: u16 = 0xc53f;
pub const USB_DEVICE_ID_LOGITECH_NANO_RECEIVER_LIGHTSPEED_1_2: u16 = 0xc543;
pub const USB_DEVICE_ID_LOGITECH_NANO_RECEIVER_LIGHTSPEED_1_3: u16 = 0xc547;
pub const USB_DEVICE_ID_LOGITECH_NANO_RECEIVER_LIGHTSPEED_1_4: u16 = 0xc54d;
pub const USB_DEVICE_ID_LOGITECH_NANO_RECEIVER_POWERPLAY: u16 = 0xc53a;
pub const USB_DEVICE_ID_LOGITECH_BOLT_RECEIVER: u16 = 0xc548;

/// Receiver match table — VID/PID of every Logitech receiver
/// `hid-logitech-dj.c` claims (see `logi_dj_receivers` at the
/// bottom of that file). Mirrors `hid-ids.h:929..941`.
pub const LOGITECH_RECEIVERS: &[(u16, u16)] = &[
    (
        USB_VENDOR_ID_LOGITECH,
        USB_DEVICE_ID_LOGITECH_27MHZ_MOUSE_RECEIVER,
    ),
    (
        USB_VENDOR_ID_LOGITECH,
        USB_DEVICE_ID_LOGITECH_UNIFYING_RECEIVER,
    ),
    (USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_LOGITECH_NANO_RECEIVER),
    (USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_LOGITECH_G700_RECEIVER),
    (
        USB_VENDOR_ID_LOGITECH,
        USB_DEVICE_ID_LOGITECH_UNIFYING_RECEIVER_2,
    ),
    (
        USB_VENDOR_ID_LOGITECH,
        USB_DEVICE_ID_LOGITECH_NANO_RECEIVER_2,
    ),
    (
        USB_VENDOR_ID_LOGITECH,
        USB_DEVICE_ID_LOGITECH_NANO_RECEIVER_LIGHTSPEED_1,
    ),
    (
        USB_VENDOR_ID_LOGITECH,
        USB_DEVICE_ID_LOGITECH_NANO_RECEIVER_LIGHTSPEED_1_1,
    ),
    (
        USB_VENDOR_ID_LOGITECH,
        USB_DEVICE_ID_LOGITECH_NANO_RECEIVER_LIGHTSPEED_1_2,
    ),
    (
        USB_VENDOR_ID_LOGITECH,
        USB_DEVICE_ID_LOGITECH_NANO_RECEIVER_LIGHTSPEED_1_3,
    ),
    (
        USB_VENDOR_ID_LOGITECH,
        USB_DEVICE_ID_LOGITECH_NANO_RECEIVER_LIGHTSPEED_1_4,
    ),
    (
        USB_VENDOR_ID_LOGITECH,
        USB_DEVICE_ID_LOGITECH_NANO_RECEIVER_POWERPLAY,
    ),
    (USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_LOGITECH_BOLT_RECEIVER),
];

/// `true` when (vid, pid) is one of the receivers we claim.
pub fn is_receiver(vid: u16, pid: u16) -> bool {
    LOGITECH_RECEIVERS
        .iter()
        .any(|&(v, p)| v == vid && p == pid)
}

// ── DJ protocol constants (mirrors hid-logitech-dj.c:19..113) ─────

/// Maximum number of paired sub-devices behind a single receiver.
pub const DJ_MAX_PAIRED_DEVICES: u8 = 7;
/// Device index used when addressing the receiver itself.
pub const DJ_RECEIVER_INDEX: u8 = 0;
/// Lowest sub-device index (1..7 are paired slots).
pub const DJ_DEVICE_INDEX_MIN: u8 = 1;
/// Highest sub-device index.
pub const DJ_DEVICE_INDEX_MAX: u8 = 7;

/// Total slot table size — receiver + 7 sub-devices (slot 0 = receiver,
/// slots 1..7 = paired devices).
pub const DJ_TOTAL_SLOTS: usize = (DJ_MAX_PAIRED_DEVICES + 1) as usize;

/// On-wire length of a short DJ report.
pub const DJREPORT_SHORT_LENGTH: usize = 15;
/// On-wire length of a long DJ report.
pub const DJREPORT_LONG_LENGTH: usize = 32;

/// Report IDs at the front of every DJ report.
pub const REPORT_ID_DJ_SHORT: u8 = 0x20;
pub const REPORT_ID_DJ_LONG: u8 = 0x21;
pub const REPORT_ID_HIDPP_SHORT: u8 = 0x10;
pub const REPORT_ID_HIDPP_LONG: u8 = 0x11;
pub const REPORT_ID_HIDPP_VERY_LONG: u8 = 0x12;

/// HID++ messages target the receiver (not a paired slot) with this
/// pseudo device-index.
pub const HIDPP_RECEIVER_INDEX: u8 = 0xff;

/// Report-type ranges (the third wire byte).
pub const REPORT_TYPE_RFREPORT_FIRST: u8 = 0x01;
pub const REPORT_TYPE_RFREPORT_LAST: u8 = 0x1F;

/// Command — switch the receiver into DJ mode.
pub const REPORT_TYPE_CMD_SWITCH: u8 = 0x80;
/// Command — enumerate paired devices.
pub const REPORT_TYPE_CMD_GET_PAIRED_DEVICES: u8 = 0x81;

/// Notification — a sub-device paired in.
pub const REPORT_TYPE_NOTIF_DEVICE_PAIRED: u8 = 0x41;
/// Notification — a sub-device un-paired (slot freed).
pub const REPORT_TYPE_NOTIF_DEVICE_UNPAIRED: u8 = 0x40;
/// Notification — link status changed (e.g. powered off).
pub const REPORT_TYPE_NOTIF_CONNECTION_STATUS: u8 = 0x42;
/// Notification — generic error (keepalive timeout etc).
pub const REPORT_TYPE_NOTIF_ERROR: u8 = 0x7F;

/// RF-forwarded report-type bytes (`hid-logitech-dj.c:75..80`).
pub const REPORT_TYPE_KEYBOARD: u8 = 0x01;
pub const REPORT_TYPE_MOUSE: u8 = 0x02;
pub const REPORT_TYPE_CONSUMER_CONTROL: u8 = 0x03;
pub const REPORT_TYPE_SYSTEM_CONTROL: u8 = 0x04;
pub const REPORT_TYPE_MEDIA_CENTER: u8 = 0x08;
pub const REPORT_TYPE_LEDS: u8 = 0x0E;

// ── Encode helpers ─────────────────────────────────────────────────

/// Encode the GET_PAIRED_DEVICES command into a 15-byte DJ short
/// report buffer. The receiver replies with up to 7 paired-device
/// notifications.
///
/// Reference: `logi_dj_recv_query_paired_devices` at
/// `hid-logitech-dj.c:1334`.
pub fn encode_get_paired_devices(out: &mut [u8]) -> Result<usize, DjError> {
    if out.len() < DJREPORT_SHORT_LENGTH {
        return Err(DjError::BufferTooSmall);
    }
    out[..DJREPORT_SHORT_LENGTH].fill(0);
    out[0] = REPORT_ID_DJ_SHORT;
    out[1] = HIDPP_RECEIVER_INDEX; // 0xff — addresses the receiver
    out[2] = REPORT_TYPE_CMD_GET_PAIRED_DEVICES;
    Ok(DJREPORT_SHORT_LENGTH)
}

/// Encode the CMD_SWITCH report (turn DJ-mode on for the receiver +
/// enable all 7 device slots with no keepalive timeout). Linux uses
/// this in `logi_dj_recv_switch_to_dj_mode` at
/// `hid-logitech-dj.c:1284`.
pub fn encode_switch_to_dj_mode(out: &mut [u8]) -> Result<usize, DjError> {
    if out.len() < DJREPORT_SHORT_LENGTH {
        return Err(DjError::BufferTooSmall);
    }
    out[..DJREPORT_SHORT_LENGTH].fill(0);
    out[0] = REPORT_ID_DJ_SHORT;
    out[1] = HIDPP_RECEIVER_INDEX;
    out[2] = REPORT_TYPE_CMD_SWITCH;
    // payload byte 0 = device bitfield (all 7 slots), byte 1 = timeout
    // (0 = no keepalive).
    out[3] = 0x3F | 0x40; // bits 0..6 set; bit 6 = enable keepalive disable
    out[4] = 0x00;
    Ok(DJREPORT_SHORT_LENGTH)
}

// ── Decode helpers ─────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DjError {
    BufferTooSmall,
    ShortReport,
    UnknownReportId(u8),
    BadDeviceIndex(u8),
}

/// A decoded DJ frame header — common 3-byte prefix on every DJ /
/// HID++ message.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DjFrame<'a> {
    pub report_id: u8,
    pub device_index: u8,
    pub report_type: u8,
    pub payload: &'a [u8],
}

/// Parse the 3-byte DJ wire header. Returns `BadDeviceIndex` if the
/// device index lies outside the legal {0, 1..7, 0xFF} set.
pub fn decode_frame(report: &[u8]) -> Result<DjFrame<'_>, DjError> {
    if report.len() < 4 {
        return Err(DjError::ShortReport);
    }
    let report_id = report[0];
    let device_index = report[1];
    let report_type = report[2];
    // Validate device_index against the allowed set.
    let legal = device_index == DJ_RECEIVER_INDEX
        || device_index == HIDPP_RECEIVER_INDEX
        || (DJ_DEVICE_INDEX_MIN..=DJ_DEVICE_INDEX_MAX).contains(&device_index);
    if !legal {
        return Err(DjError::BadDeviceIndex(device_index));
    }
    Ok(DjFrame {
        report_id,
        device_index,
        report_type,
        payload: &report[3..],
    })
}

/// One row of the in-driver paired-device table — slot index, link
/// state, and the device's reported RF capability bitmask.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PairedSlot {
    /// 1..7. `0` means empty.
    pub device_index: u8,
    /// `true` once a pair notification has been seen on this slot.
    pub linked: bool,
    /// 16-bit `reports_supported` low-half from the pair notification.
    /// (Linux uses a 64-bit field; the low 16 bits cover the bits we
    /// need for keyboard / mouse / consumer / power / media.)
    pub reports_supported: u16,
}

/// A decoded pair / unpair notification.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PairEvent {
    pub device_index: u8,
    pub event: PairKind,
    pub equad_id_lsb: u8,
    pub equad_id_msb: u8,
    pub rf_report_type: u8,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PairKind {
    Paired,
    Unpaired,
    ConnectionStatus,
}

/// Decode a pair-notification short report.
/// Layout per `logi_dj_recv_queue_notification` at
/// `hid-logitech-dj.c:967`:
///
/// ```text
///   byte 0 : 0x20 (DJ short)
///   byte 1 : device index (1..7)
///   byte 2 : 0x40 (unpair) | 0x41 (pair) | 0x42 (connection-status)
///   payload (12 bytes):
///     +0 SPFUNCTION flags
///     +1 eQuad-ID LSB
///     +2 eQuad-ID MSB
///     +3 RF report type
/// ```
pub fn decode_pair_notification(report: &[u8]) -> Result<PairEvent, DjError> {
    let f = decode_frame(report)?;
    if f.payload.len() < 4 {
        return Err(DjError::ShortReport);
    }
    let event = match f.report_type {
        REPORT_TYPE_NOTIF_DEVICE_PAIRED => PairKind::Paired,
        REPORT_TYPE_NOTIF_DEVICE_UNPAIRED => PairKind::Unpaired,
        REPORT_TYPE_NOTIF_CONNECTION_STATUS => PairKind::ConnectionStatus,
        other => return Err(DjError::UnknownReportId(other)),
    };
    if !(DJ_DEVICE_INDEX_MIN..=DJ_DEVICE_INDEX_MAX).contains(&f.device_index) {
        return Err(DjError::BadDeviceIndex(f.device_index));
    }
    Ok(PairEvent {
        device_index: f.device_index,
        event,
        equad_id_lsb: f.payload[1],
        equad_id_msb: f.payload[2],
        rf_report_type: f.payload[3],
    })
}

// ── Sub-device demultiplexer ──────────────────────────────────────

/// Per-receiver slot table. Maintained by the driver, populated from
/// pair / unpair notifications, queried during demux.
#[derive(Debug)]
pub struct DjReceiver {
    /// One byte per slot (0 = receiver itself, 1..7 = paired
    /// sub-devices). `0` = empty / unlinked, non-zero = linked +
    /// stored value encodes the RF report-type the slot expects.
    /// Atomic so a slow pump can read while a notif handler updates.
    slots: [AtomicU8; DJ_TOTAL_SLOTS],
}

impl Default for DjReceiver {
    fn default() -> Self {
        Self::new()
    }
}

impl DjReceiver {
    pub const fn new() -> Self {
        Self {
            slots: [const { AtomicU8::new(0) }; DJ_TOTAL_SLOTS],
        }
    }

    /// Number of slots currently marked linked.
    pub fn linked_count(&self) -> usize {
        self.slots
            .iter()
            .skip(1) // slot 0 = receiver itself
            .filter(|s| s.load(Ordering::Acquire) != 0)
            .count()
    }

    /// Mark slot `idx` as linked / unlinked. `idx` must be in 1..=7.
    /// `rf_report_type` 0 means empty.
    pub fn set_slot(&self, idx: u8, rf_report_type: u8) -> Result<(), DjError> {
        if !(DJ_DEVICE_INDEX_MIN..=DJ_DEVICE_INDEX_MAX).contains(&idx) {
            return Err(DjError::BadDeviceIndex(idx));
        }
        self.slots[idx as usize].store(rf_report_type, Ordering::Release);
        Ok(())
    }

    /// Read the slot's current RF report-type. `0` = empty.
    pub fn slot(&self, idx: u8) -> Option<u8> {
        if !(DJ_DEVICE_INDEX_MIN..=DJ_DEVICE_INDEX_MAX).contains(&idx) {
            return None;
        }
        let v = self.slots[idx as usize].load(Ordering::Acquire);
        if v == 0 {
            None
        } else {
            Some(v)
        }
    }

    /// Apply a pair / unpair event to the slot table.
    pub fn apply_pair_event(&self, ev: PairEvent) {
        let val = match ev.event {
            PairKind::Paired => ev.rf_report_type.max(1), // can't be 0 — that means empty
            PairKind::Unpaired => 0,
            PairKind::ConnectionStatus => {
                // Don't touch the slot — link drop, not unpair.
                return;
            }
        };
        // Ignore errors — apply_pair_event is best-effort; the caller
        // already checked the index range when decoding.
        let _ = self.set_slot(ev.device_index, val);
    }

    /// Demultiplex an incoming input report to the slot identified by
    /// its device-index byte. Returns the sub-device's payload slice
    /// for forwarding to the appropriate per-class HID stack.
    /// Returns `None` if the report targets the receiver (slot 0 /
    /// 0xFF) or an unlinked slot.
    pub fn demux<'a>(&self, report: &'a [u8]) -> Option<DjFrame<'a>> {
        let f = decode_frame(report).ok()?;
        if f.device_index == DJ_RECEIVER_INDEX || f.device_index == HIDPP_RECEIVER_INDEX {
            return None;
        }
        self.slot(f.device_index)?;
        Some(f)
    }
}

// ── Smokes ─────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // ── Smoke 1: receiver match table ──

    fn smoke_dj_receiver_match() -> TestResult {
        if !is_receiver(
            USB_VENDOR_ID_LOGITECH,
            USB_DEVICE_ID_LOGITECH_UNIFYING_RECEIVER,
        ) {
            return TestResult::Fail("Unifying receiver should match");
        }
        if !is_receiver(USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_LOGITECH_BOLT_RECEIVER) {
            return TestResult::Fail("Bolt receiver should match");
        }
        // Wrong VID.
        if is_receiver(0x1234, USB_DEVICE_ID_LOGITECH_UNIFYING_RECEIVER) {
            return TestResult::Fail("Non-Logitech VID should not match");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/hid/logitech_dj", smoke_dj_receiver_match);

    // ── Smoke 2: encode GET_PAIRED_DEVICES ──

    fn smoke_dj_encode_get_paired() -> TestResult {
        let mut buf = [0xAAu8; 16];
        let n = match encode_get_paired_devices(&mut buf) {
            Ok(n) => n,
            Err(_) => return TestResult::Fail("encode failed on big-enough buffer"),
        };
        if n != DJREPORT_SHORT_LENGTH {
            return TestResult::Fail("encoded length mismatch");
        }
        if buf[0] != REPORT_ID_DJ_SHORT {
            return TestResult::Fail("report ID byte wrong");
        }
        if buf[1] != HIDPP_RECEIVER_INDEX {
            return TestResult::Fail("device index should target receiver");
        }
        if buf[2] != REPORT_TYPE_CMD_GET_PAIRED_DEVICES {
            return TestResult::Fail("report type wrong");
        }
        // Payload should be zeroed.
        for &b in &buf[3..DJREPORT_SHORT_LENGTH] {
            if b != 0 {
                return TestResult::Fail("payload not zeroed");
            }
        }
        // Trailing buffer byte beyond the report length stays untouched.
        if buf[15] != 0xAA {
            return TestResult::Fail("encoder wrote past report length");
        }
        // Small buffer: error.
        let mut small = [0u8; 4];
        if encode_get_paired_devices(&mut small).is_ok() {
            return TestResult::Fail("encoder should reject too-small buffer");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/hid/logitech_dj", smoke_dj_encode_get_paired);

    // ── Smoke 3: 7-slot demux dispatch ──

    fn smoke_dj_demux_7_slots() -> TestResult {
        let recv = DjReceiver::new();
        // Link slots 1, 3, 7 with keyboard / mouse / consumer report types.
        recv.set_slot(1, REPORT_TYPE_KEYBOARD).unwrap();
        recv.set_slot(3, REPORT_TYPE_MOUSE).unwrap();
        recv.set_slot(7, REPORT_TYPE_CONSUMER_CONTROL).unwrap();
        if recv.linked_count() != 3 {
            return TestResult::Fail("expected 3 linked slots");
        }
        if recv.slot(1) != Some(REPORT_TYPE_KEYBOARD) {
            return TestResult::Fail("slot 1 should hold KEYBOARD");
        }
        if recv.slot(2).is_some() {
            return TestResult::Fail("slot 2 should be empty");
        }
        // Bad index rejected.
        if recv.set_slot(0, 1).is_ok() {
            return TestResult::Fail("slot 0 should be rejected (receiver index)");
        }
        if recv.set_slot(8, 1).is_ok() {
            return TestResult::Fail("slot 8 should be rejected");
        }
        // Demux a report targeting slot 3 (linked).
        let report: &[u8] = &[REPORT_ID_DJ_SHORT, 3, REPORT_TYPE_MOUSE, 0xDE, 0xAD];
        let f = match recv.demux(report) {
            Some(f) => f,
            None => return TestResult::Fail("demux of linked slot should succeed"),
        };
        if f.device_index != 3 {
            return TestResult::Fail("demux device_index wrong");
        }
        if f.payload != &[0xDE, 0xAD][..] {
            return TestResult::Fail("demux payload mismatch");
        }
        // Demux of unlinked slot 5 returns None.
        let report2: &[u8] = &[REPORT_ID_DJ_SHORT, 5, REPORT_TYPE_KEYBOARD, 0];
        if recv.demux(report2).is_some() {
            return TestResult::Fail("unlinked slot demux should return None");
        }
        // Demux of receiver index returns None (it's a notification,
        // not a forwarded input report).
        let recv_report: &[u8] = &[
            REPORT_ID_DJ_SHORT,
            DJ_RECEIVER_INDEX,
            REPORT_TYPE_NOTIF_DEVICE_PAIRED,
            0,
        ];
        if recv.demux(recv_report).is_some() {
            return TestResult::Fail("receiver-targeted report should not demux");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/hid/logitech_dj", smoke_dj_demux_7_slots);

    // ── Smoke 4: pair notification decode ──

    fn smoke_dj_pair_notif_decode() -> TestResult {
        // Build a paired-notification short report: slot 5, paired,
        // eQuad 0xAB12, RF type = KEYBOARD.
        let report: &[u8] = &[
            REPORT_ID_DJ_SHORT,
            5, // device index
            REPORT_TYPE_NOTIF_DEVICE_PAIRED,
            // payload: SPFUNCTION, eQuad LSB/MSB, RF type
            0x00,
            0x12,
            0xAB,
            REPORT_TYPE_KEYBOARD,
        ];
        let ev = match decode_pair_notification(report) {
            Ok(e) => e,
            Err(e) => {
                let _ = e;
                return TestResult::Fail("decode_pair_notification failed");
            }
        };
        if ev.device_index != 5 {
            return TestResult::Fail("device_index wrong");
        }
        if ev.event != PairKind::Paired {
            return TestResult::Fail("event should be Paired");
        }
        if ev.equad_id_lsb != 0x12 || ev.equad_id_msb != 0xAB {
            return TestResult::Fail("eQuad-ID bytes wrong");
        }
        if ev.rf_report_type != REPORT_TYPE_KEYBOARD {
            return TestResult::Fail("rf_report_type wrong");
        }
        // Unpair event on the same slot.
        let mut report2 = report.to_vec();
        report2[2] = REPORT_TYPE_NOTIF_DEVICE_UNPAIRED;
        let ev2 = decode_pair_notification(&report2).unwrap();
        if ev2.event != PairKind::Unpaired {
            return TestResult::Fail("event should be Unpaired");
        }
        // Apply to a receiver — should clear the slot.
        let recv = DjReceiver::new();
        recv.set_slot(5, REPORT_TYPE_KEYBOARD).unwrap();
        recv.apply_pair_event(ev2);
        if recv.slot(5).is_some() {
            return TestResult::Fail("unpair should clear slot");
        }
        // Apply Paired to the receiver.
        recv.apply_pair_event(ev);
        if recv.slot(5) != Some(REPORT_TYPE_KEYBOARD) {
            return TestResult::Fail("pair should populate slot");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/hid/logitech_dj", smoke_dj_pair_notif_decode);
}
