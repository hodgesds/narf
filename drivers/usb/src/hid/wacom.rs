// SPDX-License-Identifier: GPL-2.0-or-later
//! Wacom tablet HID driver — clean-room implementation.
//!
//! ## References
//!
//! - Linux `drivers/hid/wacom_wac.c` — packet decode logic.
//! - Linux `drivers/hid/wacom_sys.c` — enumeration and mode-select.
//! - Linux `drivers/hid/wacom_wac.h` — type definitions.
//!
//! ## Scope
//!
//! Handles Wacom VID=0x056A USB tablets:
//!   - Intuos Pro S/M/L (PTH-460/660/860)
//!   - Intuos S/M consumer (CTL-4100/6100)
//!   - Bamboo Pen (CTL-471/671)
//!   - One by Wacom (CTL-472/672)
//!   - Cintiq 13/16/22 pen displays
//!   - Cintiq Pro 24/32
//!   - Legacy Intuos1-4, Intuos5, BAMBOO_PT
//!
//! ## Protocol overview
//!
//! 1. Device powers on in mouse-emulation mode.
//! 2. Host sends HID SET_REPORT(Feature, ID=2, value=0x02) to switch to pen mode.
//! 3. Interrupt-IN reports arrive. Report ID byte selects packet type:
//!    - 0x02 (WACOM_REPORT_PENABLED)  — pen data
//!    - 0x0C (WACOM_REPORT_INTUOSPAD) — pad/ExpressKey data
//!    - 0x03 (WACOM_REPORT_INTUOS5PAD) — Intuos5/Pro pad
//!    - 0x10 (WACOM_REPORT_CINTIQ)    — Cintiq pen
//!    - 0x11 (WACOM_REPORT_CINTIQPAD) — Cintiq pad
//!
//! ## Pen packet (PENABLED / Intuos/Cintiq) wire layout
//!
//! ```text
//! Byte  0    : report ID
//! Byte  1    : status flags
//!              bit7   : proximity (Intuos)
//!              bit6   : RDY (Cintiq)
//!              bits5-4: tool class 0b11 = enter, 0b10 = exit, 0b00 = data
//!              bit3   : barrel button 2 (upper)
//!              bit2   : barrel button 1 (lower)
//!              bit1   : BTN_TOUCH (stylus on surface, for Bamboo)
//!              bit0   : tool index (Intuos dual-pen, 0 or 1)
//! Bytes 2-3  : X coordinate (big-endian)
//! Bytes 4-5  : Y coordinate (big-endian)
//! Bytes 6-7  : pressure high/low
//! Byte  8    : tilt/distance
//! Byte  9    : extra bits (LSBs for 17-bit X/Y, distance)
//! ```
//!
//! Linux ref: wacom_intuos_general(), wacom_wac.c:849.

use super::wacom_features::{
    lookup, needs_pen_mode, WacomFeatures, WacomType,
    WACOM_FEATURE_REPORT_ID, WACOM_PEN_MODE_VALUE,
};
use narf_input::{
    abs, btn, push_global, AbsoluteEvent, ButtonEvent, InputEvent, TouchEvent, TouchState,
};

// ── Report IDs ───────────────────────────────────────────────────────
// Linux wacom_wac.h lines 41-67.

/// Pen report (Intuos / Cintiq / Bamboo pen-only devices).
/// Linux: WACOM_REPORT_PENABLED = 2.
pub const REPORT_PENABLED: u8 = 0x02;
/// Intuos pad / Express Keys report.
/// Linux: WACOM_REPORT_INTUOSPAD = 12.
pub const REPORT_INTUOSPAD: u8 = 0x0C;
/// Intuos5 / Intuos Pro pad report.
/// Linux: WACOM_REPORT_INTUOS5PAD = 3.
pub const REPORT_INTUOS5PAD: u8 = 0x03;
/// Cintiq pen report.
/// Linux: WACOM_REPORT_CINTIQ = 16.
pub const REPORT_CINTIQ: u8 = 0x10;
/// Cintiq pad report.
/// Linux: WACOM_REPORT_CINTIQPAD = 17.
pub const REPORT_CINTIQPAD: u8 = 0x11;
/// Intuos pen report on newer firmware.
/// Linux: WACOM_REPORT_INTUOS_PEN = 16.
pub const REPORT_INTUOS_PEN: u8 = 0x10;
/// Intuos identity report 1 (enter-prox, contains tool serial).
/// Linux: WACOM_REPORT_INTUOS_ID1 = 5.
pub const REPORT_INTUOS_ID1: u8 = 0x05;
/// Intuos identity report 2.
/// Linux: WACOM_REPORT_INTUOS_ID2 = 6.
pub const REPORT_INTUOS_ID2: u8 = 0x06;

// ── Device IDs emitted as ABS_MISC ───────────────────────────────────
// Linux wacom_wac.h lines 34-39.
pub const STYLUS_DEVICE_ID: u32 = 0x02;
pub const ERASER_DEVICE_ID: u32 = 0x0A;
pub const PAD_DEVICE_ID: u32 = 0x0F;

// ── Tool-type sentinel for BTN codes ─────────────────────────────────
// We reuse the Linux evdev BTN_ codes directly via narf_input::btn.
// BTN_TOUCH (0x14A) is emitted as a ButtonEvent with code = 0x14A.
pub const BTN_TOUCH: u16 = 0x14A;

/// Linux evdev ABS_MISC (0x28) — used by Wacom to report the tool device ID.
/// Not yet in narf_input::abs, defined locally here.
/// Linux: include/uapi/linux/input-event-codes.h ABS_MISC = 0x28.
pub const ABS_MISC: u16 = 0x28;

// ── MT constants ──────────────────────────────────────────────────────
/// Maximum simultaneous MT contacts we track for Intuos Pro touch.
pub const MAX_MT_CONTACTS: usize = 10;

/// State for one live pen tool (Intuos supports dual-pen: two tools
/// simultaneously on the tablet surface).
#[derive(Copy, Clone, Debug, Default)]
pub struct PenState {
    /// Currently active tool BTN code (BTN_TOOL_PEN, BTN_TOOL_RUBBER, etc.).
    pub tool: u16,
    /// Device-specific tool ID reported via ABS_MISC.
    pub id: u32,
    /// Lower 48 bits of tool serial number (for MSC_SERIAL / multi-pen).
    pub serial: u64,
    /// True while the pen is within proximity range.
    pub in_prox: bool,
    /// True when we have successfully decoded a tool identity report.
    /// Until set we suppress data reports (Linux: guard in wacom_intuos_general).
    pub id_known: bool,
}

/// Per-contact MT slot state (Intuos Pro touch).
#[derive(Copy, Clone, Debug, Default)]
pub struct MtSlot {
    /// Tracking ID: None = slot is idle.
    pub tracking_id: Option<i32>,
    pub x: i32,
    pub y: i32,
}

/// Per-device runtime state for a bound Wacom tablet.
#[derive(Debug)]
pub struct WacomState {
    /// Features for this particular device.
    pub features: &'static WacomFeatures,
    /// Pen tool states (index 0 = primary, index 1 = secondary for dual-pen).
    pub pen: [PenState; 2],
    /// MT slot state for Intuos Pro touch (up to MAX_MT_CONTACTS contacts).
    pub mt: [MtSlot; MAX_MT_CONTACTS],
    /// True if mode-select has been sent and acknowledged.
    pub mode_selected: bool,
}

impl WacomState {
    /// Create a new state record for the device with the given PID.
    /// Returns `None` if the PID is not in the device table.
    pub fn new(pid: u16) -> Option<Self> {
        let features = lookup(pid)?;
        Some(Self {
            features,
            pen: [PenState::default(); 2],
            mt: [MtSlot::default(); MAX_MT_CONTACTS],
            mode_selected: false,
        })
    }

    /// Build the 2-byte feature report buffer for pen-mode selection.
    ///
    /// Returns `(report_id, value)` — caller sends these as a
    /// SET_REPORT(Feature, report_id, value) control transfer.
    ///
    /// Linux: wacom_set_device_mode(), wacom_sys.c:604-606.
    pub fn pen_mode_report() -> (u8, u8) {
        (WACOM_FEATURE_REPORT_ID, WACOM_PEN_MODE_VALUE)
    }

    /// True if this device type should receive the pen-mode feature report.
    pub fn needs_mode_select(&self) -> bool {
        needs_pen_mode(self.features)
    }

    /// Dispatch one interrupt-IN report packet to the appropriate decoder.
    /// Returns the number of events pushed onto the global input ring.
    ///
    /// `data` must include the leading report-ID byte.
    pub fn handle_report(&mut self, data: &[u8]) -> usize {
        if data.is_empty() {
            return 0;
        }
        match self.features.device_type {
            WacomType::Intuos | WacomType::Intuos5S | WacomType::Intuos5 | WacomType::Intuos5L
            | WacomType::IntuosProS | WacomType::IntuosProM | WacomType::IntuosProL => {
                self.handle_intuos(data)
            }
            WacomType::BambooPen | WacomType::BambooPT => self.handle_bamboo_pen(data),
            WacomType::IntuosHT | WacomType::IntuosHT2 => self.handle_bamboo_pen(data),
            WacomType::Cintiq
            | WacomType::Cintiq13HD
            | WacomType::Cintiq21UX2
            | WacomType::Cintiq22HD
            | WacomType::Dtk
            | WacomType::Cintiq24HD => self.handle_intuos(data),
            WacomType::PenPartner => self.handle_penpartner(data),
        }
    }

    // ── Intuos / Cintiq common decoder ───────────────────────────────

    /// Handle a report from an Intuos or Cintiq device.
    /// Dispatches to pad, in/out-prox, and general data sub-handlers.
    ///
    /// Linux: wacom_intuos_irq(), wacom_wac.c:1022.
    fn handle_intuos(&mut self, data: &[u8]) -> usize {
        if data.is_empty() { return 0; }
        let rid = data[0];

        // Pad / ExpressKey report.
        if rid == REPORT_INTUOSPAD || rid == REPORT_INTUOS5PAD || rid == REPORT_CINTIQPAD {
            return self.decode_intuos_pad(data);
        }

        // Pen / proximity reports.
        if rid == REPORT_PENABLED || rid == REPORT_CINTIQ || rid == REPORT_INTUOS_PEN
            || rid == REPORT_INTUOS_ID1 || rid == REPORT_INTUOS_ID2
        {
            // Tool identity report (enter-prox).
            if let Some(n) = self.decode_intuos_inout(data) {
                return n;
            }
            // General data report.
            return self.decode_intuos_general(data);
        }

        0
    }

    /// Decode Intuos in-proximity / out-of-proximity events.
    ///
    /// Linux: wacom_intuos_inout(), wacom_wac.c:773.
    ///
    /// Returns `Some(events_emitted)` if this was a prox event,
    /// `None` if it's a data report.
    fn decode_intuos_inout(&mut self, data: &[u8]) -> Option<usize> {
        if data.len() < 2 { return None; }
        let status = data[1];

        // Dual-pen index: bit 0 of status selects pen slot 0 or 1.
        let idx = if self.features.device_type == WacomType::Intuos {
            (status & 0x01) as usize
        } else {
            0
        };

        // Enter proximity: bits 7:2 of status == 0b110000 (0xC0 mask).
        // Linux: wacom_wac.c:786 — (data[1] & 0xfc) == 0xc0.
        if (status & 0xFC) == 0xC0 {
            if data.len() < 9 { return Some(0); }
            // Extract serial: wacom_wac.c:788-790.
            let serial = ((data[3] as u64 & 0x0F) << 28)
                | ((data[4] as u64) << 20)
                | ((data[5] as u64) << 12)
                | ((data[6] as u64) << 4)
                | (data[7] as u64 >> 4);
            // Tool ID: wacom_wac.c:792-793.
            let tool_id = ((data[2] as u32) << 4)
                | ((data[3] as u32) >> 4)
                | (((data[7] as u32) & 0x0F) << 16)
                | (((data[8] as u32) & 0xF0) << 8);

            let pen = &mut self.pen[idx];
            pen.serial = serial;
            pen.id = tool_id;
            pen.tool = intuos_tool_type(tool_id);
            pen.in_prox = true;
            pen.id_known = true;

            let n = push_btn(pen.tool, true)
                + push_abs(ABS_MISC, STYLUS_DEVICE_ID as i32);
            return Some(n);
        }

        // In-range (hover) report: bits 7:1 == 0b0010000 (0xFE mask == 0x20).
        // Linux: wacom_wac.c:802.
        if (status & 0xFE) == 0x20 {
            let pen = &mut self.pen[idx];
            pen.in_prox = true;
            // Emit BTN_TOUCH=0, pressure=0, distance=max while exiting.
            let n = push_btn(BTN_TOUCH, false)
                + push_abs(abs::ABS_PRESSURE, 0)
                + push_abs(abs::ABS_DISTANCE, self.features.distance_max as i32);
            return Some(n);
        }

        // Out-of-proximity: bits 7:1 == 0b1000000 (0xFE mask == 0x80).
        // Linux: wacom_wac.c:817.
        if (status & 0xFE) == 0x80 {
            let pen = &mut self.pen[idx];
            pen.in_prox = false;
            let tool = pen.tool;
            let serial = pen.serial;
            pen.id = 0;
            pen.id_known = false;

            let mut n = 0;
            n += push_abs(abs::ABS_X, 0);
            n += push_abs(abs::ABS_Y, 0);
            n += push_abs(abs::ABS_DISTANCE, 0);
            n += push_abs(abs::ABS_TILT_X, 0);
            n += push_abs(abs::ABS_TILT_Y, 0);
            n += push_abs(abs::ABS_PRESSURE, 0);
            n += push_btn(BTN_TOUCH, false);
            n += push_btn(btn::BTN_STYLUS, false);
            n += push_btn(btn::BTN_STYLUS2, false);
            n += push_btn(tool, false);
            n += push_abs(ABS_MISC, 0);
            // MSC_SERIAL — emit as ABS_MISC serial (simplified; a
            // dedicated MscEvent would be cleaner but is not in narf_input).
            let _ = serial; // tracked; full MSC_SERIAL routing is deferred
            return Some(n);
        }

        // Not a prox event — fall through to data decode.
        None
    }

    /// Decode a general Intuos pen data report.
    ///
    /// Linux: wacom_intuos_general(), wacom_wac.c:849.
    fn decode_intuos_general(&mut self, data: &[u8]) -> usize {
        if data.len() < 10 { return 0; }
        let status = data[1];

        let idx = if self.features.device_type == WacomType::Intuos {
            (status & 0x01) as usize
        } else {
            0
        };

        let pen = &self.pen[idx];
        if !pen.id_known { return 0; }
        // Cintiq guard: bit6 must be set (RDY) for CINTIQ type.
        if matches!(self.features.device_type, WacomType::Cintiq | WacomType::Cintiq13HD
                    | WacomType::Cintiq21UX2 | WacomType::Cintiq22HD | WacomType::Dtk
                    | WacomType::Cintiq24HD)
            && (status & 0x40 == 0)
        {
            return 0;
        }

        // X/Y: big-endian 16-bit shifted left 1, then OR in bit from byte 9.
        // Linux: wacom_wac.c:892-894.
        let x_raw = ((data[2] as u32) << 9) | ((data[3] as u32) << 1) | ((data[9] as u32 >> 1) & 1);
        let y_raw = ((data[4] as u32) << 9) | ((data[5] as u32) << 1) | ((data[9] as u32) & 1);
        let dist_raw = data[9] >> 2;

        // For older Intuos (type < INTUOS3S) the data was half-resolution.
        // We cover that by not shifting back here — the x_max is correspondingly
        // smaller for those devices in the feature table.
        let x = x_raw as i32;
        let y = y_raw as i32;
        let distance = dist_raw as i32;

        let type_nibble = (status >> 1) & 0x0F;
        let mut n = 0;
        n += push_abs(abs::ABS_X, x);
        n += push_abs(abs::ABS_Y, y);
        n += push_abs(abs::ABS_DISTANCE, distance);

        match type_nibble {
            0x00 | 0x01 | 0x02 | 0x03 => {
                // General pen packet.
                // Pressure: wacom_wac.c:912-914 —
                //   t = (data[6] << 3) | ((data[7] & 0xC0) >> 5) | (data[1] & 1)
                //   if pressure_max < 2047 { t >>= 1 }
                let t_raw = ((data[6] as u32) << 3)
                    | (((data[7] as u32) & 0xC0) >> 5)
                    | (status as u32 & 1);
                let pressure = if self.features.pressure_max < 2047 {
                    t_raw >> 1
                } else {
                    t_raw
                } as i32;

                // Tilt: wacom_wac.c:917-919.
                // INTUOSHT2 doesn't report tilt.
                let tilt_x = (((data[7] as i32) << 1) & 0x7E | (data[8] as i32 >> 7)) - 64;
                let tilt_y = (data[8] as i32 & 0x7F) - 64;

                n += push_abs(abs::ABS_PRESSURE, pressure);
                n += push_abs(abs::ABS_TILT_X, tilt_x);
                n += push_abs(abs::ABS_TILT_Y, tilt_y);
                n += push_btn(btn::BTN_STYLUS, status & 2 != 0);
                n += push_btn(btn::BTN_STYLUS2, status & 4 != 0);
                // BTN_TOUCH fires when pressure exceeds a minimal threshold.
                n += push_btn(BTN_TOUCH, pressure > 10);
                // Tool in-range.
                let tool = self.pen[idx].tool;
                n += push_btn(tool, true);
            }
            0x0A => {
                // Airbrush second packet — finger wheel.
                // wacom_wac.c:927.
                let wheel = ((data[6] as u32) << 2) | ((data[7] as u32 >> 6) & 3);
                n += push_abs(abs::ABS_WHEEL, wheel as i32);
                n += push_abs(abs::ABS_TILT_X, (data[7] as i32 & 0x3F) - 32);
                n += push_abs(abs::ABS_TILT_Y, (data[8] as i32 & 0x7F) - 64);
            }
            _ => {}
        }
        n
    }

    /// Decode Intuos5 / Intuos Pro / Cintiq pad (ExpressKeys + touch ring).
    ///
    /// Linux: wacom_intuos_pad(), wacom_wac.c:513.
    fn decode_intuos_pad(&mut self, data: &[u8]) -> usize {
        if data.len() < 4 { return 0; }
        let n_buttons = self.features.num_buttons as usize;
        let mut buttons: u32;
        let mut ring1: u8 = 0;

        match self.features.device_type {
            WacomType::Cintiq24HD | WacomType::Cintiq21UX2 | WacomType::Cintiq22HD => {
                // Cintiq 21UX2 / 22HD: wacom_wac.c:619-638.
                if data.len() < 10 { return 0; }
                buttons = ((data[8] as u32) << 10)
                    | ((data[7] as u32 & 0x01) << 9)
                    | ((data[6] as u32) << 1)
                    | (data[5] as u32 & 0x01);
                // Touch strips (no ring on these models).
                let _strip1 = ((data[1] as u32 & 0x1F) << 8) | data[2] as u32;
                let _strip2 = ((data[3] as u32 & 0x1F) << 8) | data[4] as u32;
                // For Cintiq 24HD, ring data is in bytes 1 and 2.
                if self.features.device_type == WacomType::Cintiq24HD && data.len() >= 9 {
                    ring1 = data[1];
                    buttons = ((data[8] as u32) << 8) | data[6] as u32;
                }
            }
            WacomType::Cintiq13HD => {
                // Cintiq 13HD: wacom_wac.c:537-538.
                if data.len() < 5 { return 0; }
                buttons = ((data[4] as u32) << 1) | (data[3] as u32 & 0x01);
            }
            WacomType::Dtk => {
                // DTK: wacom_wac.c:535-536.
                if data.len() < 7 { return 0; }
                buttons = data[6] as u32;
            }
            WacomType::Intuos5S | WacomType::IntuosProS => {
                // Intuos5S / Pro S: 7 buttons + ring. wacom_wac.c:608-617.
                if data.len() < 5 { return 0; }
                buttons = ((data[4] as u32) << 1) | (data[3] as u32 & 0x01);
                ring1 = data[2];
            }
            WacomType::Intuos5 | WacomType::Intuos5L
            | WacomType::IntuosProM | WacomType::IntuosProL => {
                // Intuos5 M/L / Pro M/L: 9 buttons + ring.
                if data.len() < 5 { return 0; }
                buttons = ((data[4] as u32) << 1) | (data[3] as u32 & 0x01);
                ring1 = data[2];
            }
            _ => {
                // Classic Intuos3 / Intuos4 layout. wacom_wac.c:631-637.
                if data.len() < 7 { return 0; }
                buttons = ((data[6] as u32 & 0x10) << 5)
                    | ((data[5] as u32 & 0x10) << 4)
                    | ((data[6] as u32 & 0x0F) << 4)
                    | (data[5] as u32 & 0x0F);
            }
        }

        let mut n = 0;
        // Emit up to num_buttons ButtonEvents for BTN_0..BTN_N.
        for i in 0..n_buttons.min(16) {
            let pressed = (buttons >> i) & 1 != 0;
            n += push_global(InputEvent::Button(ButtonEvent {
                code: 0x100 + i as u16, // BTN_0 = 0x100
                pressed,
            })) as usize;
        }

        // Touch ring (ABS_WHEEL). Bit 7 = ring active, bits 0-6 = position.
        // Linux: wacom_wac.c:663.
        if ring1 & 0x80 != 0 {
            n += push_abs(abs::ABS_WHEEL, (ring1 & 0x7F) as i32);
        } else {
            n += push_abs(abs::ABS_WHEEL, 0);
        }

        // Pad in-prox indicator.
        let pad_active = buttons != 0 || ring1 & 0x80 != 0;
        n += push_abs(ABS_MISC, if pad_active { PAD_DEVICE_ID as i32 } else { 0 });
        n
    }

    // ── Bamboo Pen / One by Wacom / IntuosHT decoder ────────────────

    /// Decode a report from a Bamboo Pen, Bamboo PT, or Intuos HT/HT2
    /// device. These use a simpler 10-byte report format.
    ///
    /// Linux: wacom_intuos_irq() for INTUOSHT2; the BAMBOO_PEN type
    /// uses the same pen report as INTUOSHT devices.
    /// wacom_wac.c:849 (wacom_intuos_general) handles the pen part.
    fn handle_bamboo_pen(&mut self, data: &[u8]) -> usize {
        if data.len() < 2 { return 0; }
        let rid = data[0];

        // Bamboo Pen pad report (INTUOSPAD / INTUOS5PAD).
        if rid == REPORT_INTUOSPAD || rid == REPORT_INTUOS5PAD {
            // These tablets have no ExpressKeys beyond a possible mode
            // button. Emit nothing for now — pad absent on pen-only models.
            return 0;
        }

        if rid != REPORT_PENABLED { return 0; }
        if data.len() < 10 { return 0; }

        let status = data[1];
        let in_prox = status & 0x20 != 0; // bit 5

        if !self.pen[0].id_known && in_prox {
            // Detect eraser vs. pen from status bits.
            // Linux: wacom_pl_irq / wacom_intuos_inout patterns.
            if status & 0x08 != 0 {
                self.pen[0].tool = btn::BTN_TOOL_RUBBER;
                self.pen[0].id = ERASER_DEVICE_ID;
            } else {
                self.pen[0].tool = btn::BTN_TOOL_PEN;
                self.pen[0].id = STYLUS_DEVICE_ID;
            }
            self.pen[0].id_known = true;
        }

        let mut n = 0;

        if in_prox {
            // X/Y — little-endian 16-bit for Bamboo/IntuosHT.
            let x = u16::from_le_bytes([data[2], data[3]]) as i32;
            let y = u16::from_le_bytes([data[4], data[5]]) as i32;
            // Pressure — 10-bit or 11-bit depending on pressure_max.
            let pressure_raw = ((data[6] as u16) | ((data[7] as u16 & 0x07) << 8)) as i32;
            let pressure = if self.features.pressure_max <= 1023 {
                pressure_raw & 0x3FF
            } else {
                pressure_raw
            };

            let in_range = status & 0x40 != 0; // proximity/hover
            let tip = status & 0x01 != 0;      // tip switch
            let barrel1 = status & 0x02 != 0;
            let barrel2 = status & 0x04 != 0;

            n += push_abs(abs::ABS_X, x);
            n += push_abs(abs::ABS_Y, y);
            n += push_abs(abs::ABS_PRESSURE, pressure);
            n += push_btn(BTN_TOUCH, tip || pressure > 10);
            n += push_btn(btn::BTN_STYLUS, barrel1);
            n += push_btn(btn::BTN_STYLUS2, barrel2);
            let tool = self.pen[0].tool;
            n += push_btn(tool, in_range || tip);
        } else {
            // Out of proximity — reset state.
            let tool = self.pen[0].tool;
            self.pen[0].id_known = false;
            self.pen[0].id = 0;
            n += push_abs(abs::ABS_PRESSURE, 0);
            n += push_abs(abs::ABS_X, 0);
            n += push_abs(abs::ABS_Y, 0);
            n += push_btn(BTN_TOUCH, false);
            n += push_btn(btn::BTN_STYLUS, false);
            n += push_btn(btn::BTN_STYLUS2, false);
            n += push_btn(tool, false);
            n += push_abs(ABS_MISC, 0);
        }

        n
    }

    // ── PenPartner (legacy) ──────────────────────────────────────────

    /// Minimal PenPartner decode (pen-only, 7-byte reports).
    ///
    /// Linux: wacom_penpartner_irq(), wacom_wac.c:118.
    fn handle_penpartner(&mut self, data: &[u8]) -> usize {
        if data.len() < 7 { return 0; }
        let in_prox = data[0] & 0x80 != 0;

        if in_prox && !self.pen[0].id_known {
            self.pen[0].tool = if data[0] & 0x40 != 0 { btn::BTN_TOOL_RUBBER } else { btn::BTN_TOOL_PEN };
            self.pen[0].id = if self.pen[0].tool == btn::BTN_TOOL_RUBBER {
                ERASER_DEVICE_ID
            } else {
                STYLUS_DEVICE_ID
            };
            self.pen[0].id_known = true;
        }

        let mut n = 0;
        if in_prox {
            let x = i16::from_le_bytes([data[1], data[2]]) as i32;
            let y = i16::from_le_bytes([data[3], data[4]]) as i32;
            let pressure = data[6] as i32;
            let tool = self.pen[0].tool;
            n += push_abs(abs::ABS_X, x);
            n += push_abs(abs::ABS_Y, y);
            n += push_abs(abs::ABS_PRESSURE, pressure);
            n += push_btn(BTN_TOUCH, pressure > 0);
            n += push_btn(tool, true);
        } else {
            let tool = self.pen[0].tool;
            self.pen[0].id_known = false;
            n += push_abs(abs::ABS_PRESSURE, 0);
            n += push_btn(BTN_TOUCH, false);
            n += push_btn(tool, false);
        }
        n
    }

    // ── Multi-touch decode (Intuos Pro touch) ─────────────────────────

    /// Decode a multi-touch report from an Intuos Pro (or Cintiq 24HDT).
    /// Uses protocol-B (slot-based) MT.
    ///
    /// Wacom MT packets for Intuos Pro are described in Linux
    /// `wacom_mt_touch()`, wacom_wac.c:1185 area.
    ///
    /// `data` is the raw interrupt-IN payload for a touch-controller
    /// interface (separate USB interface from the pen interface on
    /// dual-interface Intuos Pro tablets).
    ///
    /// Each contact occupies `WACOM_BYTES_PER_MT_PACKET` = 11 bytes.
    pub fn handle_mt_report(&mut self, data: &[u8]) -> usize {
        if data.len() < 2 { return 0; }
        let num_contacts = self.features.touch_max as usize;
        if num_contacts == 0 { return 0; }

        // Byte 0 = report ID, byte 1 = contact count for this frame.
        let contacts_in_frame = data[1] as usize;
        let contacts = contacts_in_frame.min(num_contacts).min(MAX_MT_CONTACTS);

        const BYTES_PER: usize = 11; // WACOM_BYTES_PER_MT_PACKET
        let mut n = 0;

        for i in 0..contacts {
            let off = 2 + i * BYTES_PER;
            if off + BYTES_PER > data.len() { break; }
            let c = &data[off..off + BYTES_PER];

            let contact_id = c[0] as usize;
            if contact_id >= MAX_MT_CONTACTS { continue; }

            let tip = c[1] & 0x01 != 0;
            let x = (c[2] as i32) | ((c[3] as i32) << 8);
            let y = (c[4] as i32) | ((c[5] as i32) << 8);

            let slot = &mut self.mt[contact_id];
            let state = if tip {
                if slot.tracking_id.is_none() {
                    slot.tracking_id = Some(contact_id as i32);
                    slot.x = x;
                    slot.y = y;
                    TouchState::Down
                } else {
                    slot.x = x;
                    slot.y = y;
                    TouchState::Move
                }
            } else {
                let had_contact = slot.tracking_id.is_some();
                slot.tracking_id = None;
                if had_contact { TouchState::Up } else { continue; }
            };

            n += push_global(InputEvent::Touch(TouchEvent {
                slot: contact_id as u8,
                tracking_id: slot.tracking_id,
                id: contact_id as u16,
                x,
                y,
                pressure: 0,
                state,
            })) as usize;
        }
        n
    }
}

// ── Inline helpers ───────────────────────────────────────────────────

/// Push an absolute-axis event. Returns 1 if pushed, 0 if ring not initialised.
#[inline]
fn push_abs(axis: u16, value: i32) -> usize {
    push_global(InputEvent::Absolute(AbsoluteEvent { axis, value })) as usize
}

/// Push a button event. Returns 1 if pushed.
#[inline]
fn push_btn(code: u16, pressed: bool) -> usize {
    push_global(InputEvent::Button(ButtonEvent { code, pressed })) as usize
}

/// Map an Intuos tool ID to the appropriate Linux BTN_TOOL_* code.
///
/// Linux: wacom_intuos_get_tool_type(), wacom_wac.c:694.
fn intuos_tool_type(id: u32) -> u16 {
    match id {
        0x812 | 0x801 | 0x12802 | 0x012 => btn::BTN_TOOL_PENCIL,
        0x832 | 0x032 => btn::BTN_TOOL_BRUSH,
        0x007 | 0x09C | 0x094 | 0x017 | 0x806 => btn::BTN_TOOL_MOUSE,
        0x096 | 0x097 | 0x006 => btn::BTN_TOOL_LENS,
        0xD12 | 0x912 | 0x112 | 0x913 | 0x902 | 0x10902 => btn::BTN_TOOL_AIRBRUSH,
        // Eraser: bit 3 set in tool ID.
        id if id & 0x0008 != 0 => btn::BTN_TOOL_RUBBER,
        _ => btn::BTN_TOOL_PEN,
    }
}

// ── Smoke tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use narf_input::{init_global_ring, pop_absolute, pop_button};

    fn setup() {
        init_global_ring(256);
    }

    fn pop_abs_drain() -> alloc::vec::Vec<AbsoluteEvent> {
        let mut v = alloc::vec::Vec::new();
        while let Some(e) = pop_absolute() { v.push(e); }
        v
    }

    fn pop_btn_drain() -> alloc::vec::Vec<ButtonEvent> {
        let mut v = alloc::vec::Vec::new();
        while let Some(e) = pop_button() { v.push(e); }
        v
    }

    // ── Device table smoke ───────────────────────────────────────────

    #[test]
    fn device_table_has_intuos_pro_pth460() {
        use crate::hid::wacom_features::lookup;
        assert!(lookup(0x0314).is_some(), "PTH-460 / Intuos Pro S missing");
        assert!(lookup(0x0315).is_some(), "PTH-660 / Intuos Pro M missing");
        assert!(lookup(0x0317).is_some(), "PTH-860 / Intuos Pro L missing");
    }

    #[test]
    fn device_table_has_bamboo_and_one_by_wacom() {
        use crate::hid::wacom_features::lookup;
        assert!(lookup(0x00D4).is_some(), "Bamboo Pen S missing");
        assert!(lookup(0x037A).is_some(), "One by Wacom S (CTL-472) missing");
        assert!(lookup(0x037B).is_some(), "One by Wacom M (CTL-672) missing");
    }

    #[test]
    fn device_table_has_cintiq() {
        use crate::hid::wacom_features::lookup;
        assert!(lookup(0x00FA).is_some(), "Cintiq 22HD missing");
        assert!(lookup(0x0304).is_some(), "Cintiq 13HD missing");
        assert!(lookup(0x00F4).is_some(), "Cintiq 24HD missing");
        assert!(lookup(0x00CC).is_some(), "Cintiq 21UX2 missing");
    }

    // ── Mode-select feature report ───────────────────────────────────

    #[test]
    fn mode_select_report_encodes_correctly() {
        use crate::hid::wacom_features::encode_pen_mode_report;
        let mut buf = [0u8; 8];
        let n = encode_pen_mode_report(&mut buf);
        assert_eq!(n, 2, "encoded length should be 2");
        assert_eq!(buf[0], 2, "report ID must be 2");
        assert_eq!(buf[1], 2, "mode value must be 2 (pen mode)");
    }

    #[test]
    fn pen_mode_report_from_state() {
        let (rid, val) = WacomState::pen_mode_report();
        assert_eq!(rid, WACOM_FEATURE_REPORT_ID);
        assert_eq!(val, WACOM_PEN_MODE_VALUE);
    }

    // ── Intuos Pro pen packet decode ─────────────────────────────────

    /// Construct a minimal 10-byte Intuos5/Pro enter-proximity report.
    fn intuos_enter_prox(tool_id_bytes: [u8; 3], serial_nibbles: u8) -> [u8; 10] {
        // Status byte for enter-prox: bits 7:2 = 0b110000 → 0xC0.
        // wacom_wac.c:786: (data[1] & 0xFC) == 0xC0
        let mut pkt = [0u8; 10];
        pkt[0] = REPORT_PENABLED;
        pkt[1] = 0xC0; // enter-prox
        pkt[2] = tool_id_bytes[0]; // upper nibbles of tool ID
        pkt[3] = tool_id_bytes[1];
        pkt[4] = 0x00; // serial
        pkt[5] = 0x00;
        pkt[6] = 0x00;
        pkt[7] = serial_nibbles << 4; // high nibble of byte[7] → part of tool ID
        pkt[8] = tool_id_bytes[2];    // part of tool ID
        pkt[9] = 0x00;
        pkt
    }

    /// Construct a 10-byte Intuos5/Pro pen-data report.
    fn intuos_pen_data(x: u16, y: u16, pressure_raw: u16, tilt_x: i8, tilt_y: i8,
                        barrel1: bool, barrel2: bool, tip: bool) -> [u8; 10] {
        let mut pkt = [0u8; 10];
        pkt[0] = REPORT_PENABLED;
        // status: general pen packet type 0x00; barrel bits; no prox-enter/exit.
        // bit1 = barrel1, bit2 = barrel2.
        pkt[1] = (if barrel1 { 0x02 } else { 0 })
               | (if barrel2 { 0x04 } else { 0 })
               | (if tip { 0x01 } else { 0 });

        // X/Y: big-endian, right-shifted (upper 15 bits of a 17-bit coord).
        // The 17th bit is in data[9].
        // wacom_wac.c:892: x = (be16(&data[2]) << 1) | ((data[9] >> 1) & 1)
        let x17 = (x as u32) << 1; // leave LSB as 0 (in byte[9])
        pkt[2] = (x17 >> 9) as u8;
        pkt[3] = (x17 >> 1) as u8;
        let y17 = (y as u32) << 1;
        pkt[4] = (y17 >> 9) as u8;
        pkt[5] = (y17 >> 1) as u8;

        // Pressure: wacom_wac.c:912
        // t = (data[6] << 3) | ((data[7] & 0xC0) >> 5) | (data[1] & 1)
        // Pack pressure_raw into data[6] and data[7] upper bits.
        let p = pressure_raw as u32;
        pkt[6] = (p >> 3) as u8;
        pkt[7] = (((p & 0x07) << 5) as u8)
               | (((tilt_x as u8 & 0x3F) << 1) & 0x7E);

        // Tilt Y in byte[8].
        pkt[8] = ((tilt_y as u8).wrapping_add(64)) & 0x7F;

        // Byte[9]: distance (upper 6 bits) + X LSB (bit1) + Y LSB (bit0).
        pkt[9] = 0x00;
        pkt
    }

    #[test]
    fn intuos_pro_pen_enter_and_data_8192_pressure() {
        setup();
        let mut state = WacomState::new(0x0315).expect("Intuos Pro M not in table");

        // Enter proximity — standard stylus tool ID bytes.
        let enter = intuos_enter_prox([0x00, 0x00, 0x00], 0x00);
        state.handle_report(&enter);

        // Now send a data report: pressure = 8191 (max for 13-bit... but our
        // table uses 2047 for USB Intuos Pro, so use 2047 as our full-scale).
        // Pressure raw = 2047 (all 11 bits set).
        let p_raw: u16 = 2047;
        let data_pkt = intuos_pen_data(1000, 2000, p_raw, 10, -15, false, false, true);
        let n = state.handle_report(&data_pkt);
        assert!(n > 0, "pen data report produced no events");

        let abs_evts = pop_abs_drain();
        let pressures: alloc::vec::Vec<i32> = abs_evts.iter()
            .filter(|e| e.axis == abs::ABS_PRESSURE)
            .map(|e| e.value)
            .collect();
        assert!(!pressures.is_empty(), "no ABS_PRESSURE event found");
        // Verify pressure is in the expected range (decode divides by 2 when
        // pressure_max < 2047; for 2047 it does not, so expect ~p_raw).
        let p = pressures[0];
        assert!(p > 1000, "pressure {} too low for near-full-scale input", p);
    }

    #[test]
    fn intuos_pro_barrel_buttons() {
        setup();
        let mut state = WacomState::new(0x0315).expect("Intuos Pro M");

        let enter = intuos_enter_prox([0x00, 0x00, 0x00], 0x00);
        state.handle_report(&enter);

        // barrel1 only.
        let pkt = intuos_pen_data(100, 100, 100, 0, 0, true, false, false);
        state.handle_report(&pkt);

        let btns = pop_btn_drain();
        let barrel1_pressed = btns.iter().any(|e| e.code == btn::BTN_STYLUS && e.pressed);
        assert!(barrel1_pressed, "BTN_STYLUS (barrel1) not seen in button events");
    }

    #[test]
    fn intuos_pro_eraser_end_in_range() {
        setup();
        let mut state = WacomState::new(0x0315).expect("Intuos Pro M");

        // Eraser tool ID: any ID with bit3 set → BTN_TOOL_RUBBER.
        // e.g. tool_id = 0x008 — data[3] = 0x00, data[7] = 0x80 (bit3 of id field).
        // Simpler: use ID 0x00A (bit3 set in low nibble).
        // wacom_wac.c:728-729: if (tool_id & 0x0008) → BTN_TOOL_RUBBER.
        // Build enter-prox with tool byte that results in bit3:
        // tool_id = (data[2]<<4)|(data[3]>>4)|...
        // Use data[2]=0, data[3]=0x80 → tool_id lower bits = 0x08.
        let mut enter = [0u8; 10];
        enter[0] = REPORT_PENABLED;
        enter[1] = 0xC0;
        enter[2] = 0x00;
        enter[3] = 0x80; // tool_id bits = (0x00<<4)|(0x80>>4) = 0x08 → eraser
        state.handle_report(&enter);

        assert_eq!(state.pen[0].tool, btn::BTN_TOOL_RUBBER, "expected BTN_TOOL_RUBBER for eraser ID");
    }

    #[test]
    fn intuos_pro_tilt_signed_range() {
        setup();
        let mut state = WacomState::new(0x0315).expect("Intuos Pro M");

        let enter = intuos_enter_prox([0x00, 0x00, 0x00], 0x00);
        state.handle_report(&enter);

        // Tilt X = +45, Tilt Y = -30.
        let pkt = intuos_pen_data(500, 500, 500, 45, -30, false, false, true);
        state.handle_report(&pkt);

        let abs_evts = pop_abs_drain();
        let tx = abs_evts.iter().find(|e| e.axis == abs::ABS_TILT_X).map(|e| e.value);
        let ty = abs_evts.iter().find(|e| e.axis == abs::ABS_TILT_Y).map(|e| e.value);

        // Tilt X should be positive for +45.
        if let Some(v) = tx {
            assert!(v > 0, "ABS_TILT_X should be positive for +45 tilt, got {}", v);
        }
        // Tilt Y should be negative for -30.
        if let Some(v) = ty {
            assert!(v < 0, "ABS_TILT_Y should be negative for -30 tilt, got {}", v);
        }
    }

    // ── Bamboo / One by Wacom decoder ────────────────────────────────

    /// Build a Bamboo pen report (10 bytes, little-endian X/Y).
    fn bamboo_pen_report(x: u16, y: u16, pressure: u16, in_prox: bool, tip: bool) -> [u8; 10] {
        let mut pkt = [0u8; 10];
        pkt[0] = REPORT_PENABLED;
        // bit5 = in_proximity, bit0 = tip
        pkt[1] = (if in_prox { 0x20 } else { 0 }) | (if tip { 0x01 } else { 0 });
        pkt[2] = x as u8;
        pkt[3] = (x >> 8) as u8;
        pkt[4] = y as u8;
        pkt[5] = (y >> 8) as u8;
        pkt[6] = pressure as u8;
        pkt[7] = (pressure >> 8) as u8 & 0x07;
        pkt
    }

    #[test]
    fn bamboo_pen_decode_basic() {
        setup();
        let mut state = WacomState::new(0x037A).expect("One by Wacom S");

        let pkt = bamboo_pen_report(1234, 5678, 512, true, true);
        let n = state.handle_report(&pkt);
        assert!(n > 0, "bamboo pen report produced no events");

        let abs_evts = pop_abs_drain();
        let has_x = abs_evts.iter().any(|e| e.axis == abs::ABS_X);
        let has_y = abs_evts.iter().any(|e| e.axis == abs::ABS_Y);
        assert!(has_x, "no ABS_X event from Bamboo pen report");
        assert!(has_y, "no ABS_Y event from Bamboo pen report");
    }

    #[test]
    fn bamboo_pen_lower_pressure_resolution() {
        setup();
        let mut state = WacomState::new(0x00D4).expect("Bamboo Pen (classic)");
        // Bamboo Pen classic has pressure_max = 1023 (10-bit).
        assert_eq!(state.features.pressure_max, 1023);

        let pkt = bamboo_pen_report(100, 100, 1023, true, true);
        state.handle_report(&pkt);

        let abs_evts = pop_abs_drain();
        let p = abs_evts.iter().find(|e| e.axis == abs::ABS_PRESSURE).map(|e| e.value);
        assert!(p.is_some(), "no ABS_PRESSURE from Bamboo pen");
        // Should be within 10-bit range.
        let pv = p.unwrap();
        assert!(pv <= 1023, "pressure {} exceeded 10-bit maximum", pv);
    }

    // ── Cintiq pad ExpressKey decode ─────────────────────────────────

    #[test]
    fn cintiq_pad_expresskey_bitmap() {
        setup();
        // Use Cintiq 22HD (WACOM_22HD type, 18 ExpressKeys).
        let mut state = WacomState::new(0x00FA).expect("Cintiq 22HD");
        assert_eq!(state.features.num_buttons, 18);

        // Build a pad report with buttons 0 and 2 pressed.
        // Cintiq 22HD uses WACOM_21UX2 layout: wacom_wac.c:619-621.
        // buttons = (data[8]<<10) | (data[7]&0x01)<<9 | data[6]<<1 | data[5]&0x01
        // Set button 0 (bit0): data[5] |= 0x01.
        // Set button 2 (bit2): data[6] |= 0x01 → (data[6]<<1) bit1 set.
        let mut pkt = [0u8; 16];
        pkt[0] = REPORT_INTUOSPAD;
        pkt[5] = 0x01; // button 0
        pkt[6] = 0x01; // contributes bits 1..8 via <<1; bit 0 here → bit1 in buttons
        // So buttons = 0 | 0 | (0x01 << 1) | 0x01 = 0x03 — buttons 0 and 1 pressed.

        let n = state.handle_report(&pkt);
        assert!(n > 0, "Cintiq pad report produced no events");

        let btn_evts = pop_btn_drain();
        let btn0 = btn_evts.iter().any(|e| e.code == 0x100 && e.pressed); // BTN_0
        assert!(btn0, "BTN_0 not pressed in Cintiq ExpressKey report");
    }
}

extern crate alloc;
