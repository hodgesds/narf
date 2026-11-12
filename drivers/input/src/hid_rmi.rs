//! Synaptics RMI4-over-HID transport driver.
//!
//! Wraps the [`crate::rmi4_core`] register protocol around the HID
//! Feature / Output report transport used by USB-attached Synaptics
//! touchpads (and a handful of cover-keyboard accessories). The
//! protocol is "RMI4 register R/W tunneled via HID reports" — five
//! reserved report IDs carry mode-select, address+length read
//! requests, read data responses, blind writes, and ATTN reports.
//!
//! Linux reference (cited per the post-2026-05-20 GPL relicense
//! window): `linux/drivers/hid/hid-rmi.c`. Specifically:
//!
//! - L23-28: report-id assignments (0x01 mouse, 0x09 write,
//!   0x0A read-addr, 0x0B read-data, 0x0C attn, 0x0F set-mode).
//! - L121-141: `rmi_set_page()` — switch RMI4 page via output
//!   report with addr 0xFF.
//! - L143-163: `rmi_set_mode()` — `HID_REQ_SET_REPORT` of the
//!   1-byte Set_RMI_Mode feature report.
//! - L188-257: `rmi_hid_read_block()` — output report carries the
//!   address+length read request; wait for `RMI_READ_DATA_REPORT`
//!   to come back via raw-event.
//! - L753-762: device id table (`rmi_id[]` — USB Razer Blade 14,
//!   Lenovo X1 Cover, Primax Rezel, Synaptics Acer Switch 5, and
//!   any HID device on the `HID_GROUP_RMI` bus group).
//!
//! The driver doesn't drive USB silicon directly — we expose a
//! [`HidIo`] callback the USB-HID transport implements. That lets
//! the same code work over future i2c-HID Synaptics ports without
//! a rewrite.
//!
//! ## Mode select
//!
//! On probe we write a 2-byte Set_RMI_Mode Feature report:
//!
//! ```text
//!   [0x0F]            ← report id (RMI_SET_RMI_MODE_REPORT_ID)
//!   [mode]            ← 0x01 = ATTN_REPORTS, 0x02 = no packed attn
//! ```
//!
//! With ATTN reports enabled, the device sends report ID 0x0C
//! whenever a touch frame is ready. The driver consumes those via
//! [`HidRmiDriver::on_input_report`] and chains them through the
//! F$11 / F$12 decoders.

extern crate alloc;

use alloc::vec::Vec;

use crate::i2c_hid::{I2cHidDriver, I2cHidError};
use crate::rmi4_core::{
    build_interrupt_map, decode_f12_sensor_tuning, find_function, parse_register_descriptor,
    register_descriptor_header, F01ProductInfo, F11SensorInfo, F12SensorInfo, F30Query, PdtEntry,
    Rmi4DeviceProbe, Rmi4Transport, RmiRegDescriptor, TransportError, F01_DEVICE_CONTROL,
    F11_2D_TOUCHPAD, F11_CTRL_SENSOR_MAX_X_POS_OFFSET, F12_2D_TOUCHPAD_NEXT,
    F12_CTRL_SENSOR_TUNING, F12_DATA_OBJECT_DATA, F12_QUERY_HAS_DESCRIPTORS, F30_GPIO_LED,
    PDT_ENTRY_SIZE, PDT_FIRST_SLOT_OFFSET, PDT_LAST_SLOT_OFFSET, RMI4_FALLBACK_F11_MAX,
    RMI4_FALLBACK_F12_MAX, RMI4_FALLBACK_MAX_COUNT, RMI4_PUMP_MAX_SLOTS, RMI_REG_DESC_PRESENCE_MAX,
    RMI_REG_DESC_STRUCT_MAX,
};

// ── Device ID table ────────────────────────────────────────────────
//
// Mirror of Linux `rmi_id[]` in `hid-rmi.c:753`. Only the
// numeric IDs are kept — the "any device on HID_GROUP_RMI bus
// group" catch-all is NOT implemented (issue #1718), so modern
// Synaptics OEM touchpads (ThinkPad, Yoga, Surface, MSI
// laptops) that bind through the HID-group route on Linux fall
// through to the PTP / generic binders here instead.

/// USB vendor ID for Synaptics (Linux `USB_VENDOR_ID_SYNAPTICS`,
/// `hid-ids.h:1350`).
pub const USB_VENDOR_ID_SYNAPTICS: u16 = 0x06CB;
/// USB vendor ID for Razer (`hid-ids.h:1189`).
pub const USB_VENDOR_ID_RAZER: u16 = 0x1532;
/// USB vendor ID for Lenovo (`hid-ids.h:840`).
pub const USB_VENDOR_ID_LENOVO: u16 = 0x17EF;
/// USB vendor ID for Primax (`hid-ids.h:1546`).
pub const USB_VENDOR_ID_PRIMAX: u16 = 0x0461;

/// Razer Blade 14 (Synaptics force touchpad) — RMI device with
/// distinct physical left/right buttons.
pub const USB_DEVICE_ID_RAZER_BLADE_14: u16 = 0x011D;
/// Lenovo ThinkPad X1 cover keyboard.
pub const USB_DEVICE_ID_LENOVO_X1_COVER: u16 = 0x6085;
/// Primax Rezel reference keyboard (early Win8 keyboard cover).
pub const USB_DEVICE_ID_PRIMAX_REZEL: u16 = 0x4E72;
/// Synaptics Acer Switch 5 cover (RMI device that needs the
/// `RMI_DEVICE_OUTPUT_SET_REPORT` quirk).
pub const USB_DEVICE_ID_SYNAPTICS_ACER_SWITCH5: u16 = 0x81A7;

/// Quirk flags — packed identically to Linux `RMI_DEVICE_*` in
/// `hid-rmi.c:35-38`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceQuirks(pub u32);
impl DeviceQuirks {
    /// Device exposes physical (mechanical) left + right buttons
    /// separate from the touch surface — *not* a clickpad. The
    /// driver leaves BTN_LEFT/RIGHT to the OS HID input layer
    /// rather than synthesising them out of F$30.
    pub const HAS_PHYS_BUTTONS: Self = Self(1 << 0);
    /// Some quirky firmwares require all output-report writes go
    /// through `SET_REPORT` instead of the standard
    /// `HID_OUTPUT_REPORT` interrupt OUT endpoint.
    pub const OUTPUT_SET_REPORT: Self = Self(1 << 1);

    pub const fn empty() -> Self {
        Self(0)
    }
    pub fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

/// One row of the hid-rmi USB device id table.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DeviceMatch {
    pub vendor: u16,
    pub product: u16,
    pub quirks: DeviceQuirks,
}

/// The explicit device list (Linux `rmi_id[]:754-759`). The
/// "any device in HID_GROUP_RMI" catch-all is NOT implemented
/// (issue #1718): only this explicit table matches, and the
/// USB-HID glue falls through to the PTP / generic binders for
/// group-route devices.
pub const RMI_DEVICE_TABLE: &[DeviceMatch] = &[
    DeviceMatch {
        vendor: USB_VENDOR_ID_RAZER,
        product: USB_DEVICE_ID_RAZER_BLADE_14,
        quirks: DeviceQuirks(DeviceQuirks::HAS_PHYS_BUTTONS.0),
    },
    DeviceMatch {
        vendor: USB_VENDOR_ID_LENOVO,
        product: USB_DEVICE_ID_LENOVO_X1_COVER,
        quirks: DeviceQuirks::empty(),
    },
    DeviceMatch {
        vendor: USB_VENDOR_ID_PRIMAX,
        product: USB_DEVICE_ID_PRIMAX_REZEL,
        quirks: DeviceQuirks::empty(),
    },
    DeviceMatch {
        vendor: USB_VENDOR_ID_SYNAPTICS,
        product: USB_DEVICE_ID_SYNAPTICS_ACER_SWITCH5,
        quirks: DeviceQuirks(DeviceQuirks::OUTPUT_SET_REPORT.0),
    },
];

/// Lookup by `(vendor, product)`. Returns `Some(match)` when the
/// device is in the explicit table; the USB-HID layer should fall
/// back to checking the HID Usage group when this returns `None`.
pub fn match_device(vendor: u16, product: u16) -> Option<&'static DeviceMatch> {
    RMI_DEVICE_TABLE
        .iter()
        .find(|m| m.vendor == vendor && m.product == product)
}

/// Classify a HID device as an RMI4 touchpad for the bind layers.
///
/// A table hit returns that row's quirks. Failing that, a
/// Synaptics VID (`0x06CB`) or an ACPI `_HID` with the `SYNA`
/// vendor prefix also classifies as RMI4 with no quirks — modern
/// Synaptics OEM touchpads (ThinkPad, Yoga, Surface, MSI laptops)
/// bind through the HID-group route on the wire, not specific USB
/// VIDs, and their ACPI nodes carry `SYNAxxxx` `_HID`s. Returns
/// `None` for anything else, so a non-matching device is rejected
/// by the bind layer instead of being claimed as RMI4.
pub fn classify_device(acpi_hid: &str, vendor: u16, product: u16) -> Option<DeviceQuirks> {
    if let Some(m) = match_device(vendor, product) {
        return Some(m.quirks);
    }
    if vendor == USB_VENDOR_ID_SYNAPTICS || acpi_hid.starts_with("SYNA") {
        return Some(DeviceQuirks::empty());
    }
    None
}

// ── HID Report IDs ─────────────────────────────────────────────────
//
// Direct from `hid-rmi.c:23-28`.

pub const RMI_MOUSE_REPORT_ID: u8 = 0x01;
pub const RMI_WRITE_REPORT_ID: u8 = 0x09;
pub const RMI_READ_ADDR_REPORT_ID: u8 = 0x0A;
pub const RMI_READ_DATA_REPORT_ID: u8 = 0x0B;
pub const RMI_ATTN_REPORT_ID: u8 = 0x0C;
pub const RMI_SET_RMI_MODE_REPORT_ID: u8 = 0x0F;

// ── Set_RMI_Mode values ────────────────────────────────────────────

/// `RMI_MODE_OFF` — disable RMI mode, revert to mouse-emulation.
pub const RMI_MODE_OFF: u8 = 0x00;
/// `RMI_MODE_ATTN_REPORTS` — wake up RMI mode + emit ATTN reports
/// for touch frames (Linux `RMI_MODE_ATTN_REPORTS` value 1).
pub const RMI_MODE_ATTN_REPORTS: u8 = 0x01;
/// `RMI_MODE_NO_PACKED_ATTN_REPORTS` — same as ATTN reports but
/// don't pack PDT data into the ATTN report (Linux value 2).
pub const RMI_MODE_NO_PACKED_ATTN_REPORTS: u8 = 0x02;

/// Encode the 2-byte Set_RMI_Mode Feature report (Linux
/// `rmi_set_mode()` in `hid-rmi.c:143-163`).
///
/// Returns the body the transport will hand to
/// `HID_REQ_SET_REPORT(HID_FEATURE_REPORT)`. The leading byte is
/// the report ID; transports that put the ID in `wValue` strip it.
pub fn encode_set_rmi_mode(mode: u8) -> [u8; 2] {
    [RMI_SET_RMI_MODE_REPORT_ID, mode]
}

// ── RMI4 read / write transport encoding ───────────────────────────
//
// Output reports carry the address + length for register R/W. The
// device echoes data back via the input-report path
// (RMI_READ_DATA_REPORT_ID).

/// Encode the output report for `RMI_WRITE_REPORT_ID` — direct
/// register write. Mirrors `rmi_hid_write_block()` (`hid-rmi.c:259`).
///
/// `addr` is the full 16-bit RMI4 register address. `data` is the
/// write payload; the device's output-report size includes the
/// 4-byte header + payload + padding to report length.
///
/// Buffer layout:
///
/// ```text
///   [0] RMI_WRITE_REPORT_ID
///   [1] data.len() as u8 (the device's write count field)
///   [2] addr_lo
///   [3] addr_hi
///   [4..4+data.len()] payload
///   [..output_report_size] zero-padded by the transport
/// ```
pub fn encode_write_block(addr: u16, data: &[u8], output_report_size: usize) -> Vec<u8> {
    let mut buf = alloc::vec![0u8; output_report_size];
    if buf.len() >= 4 {
        buf[0] = RMI_WRITE_REPORT_ID;
        buf[1] = data.len() as u8;
        buf[2] = (addr & 0xFF) as u8;
        buf[3] = (addr >> 8) as u8;
        let copy_len = data.len().min(buf.len().saturating_sub(4));
        buf[4..4 + copy_len].copy_from_slice(&data[..copy_len]);
    }
    buf
}

/// Encode the output report for `RMI_READ_ADDR_REPORT_ID` —
/// read request. Mirrors `rmi_hid_read_block()` (`hid-rmi.c:188`).
///
/// Buffer layout:
///
/// ```text
///   [0] RMI_READ_ADDR_REPORT_ID
///   [1] 0  (legacy 1-byte length count; modern silicon ignores)
///   [2] addr_lo
///   [3] addr_hi
///   [4] len_lo
///   [5] len_hi
///   [..output_report_size] zero-padded by the transport
/// ```
pub fn encode_read_addr(addr: u16, len: u16, output_report_size: usize) -> Vec<u8> {
    let mut buf = alloc::vec![0u8; output_report_size];
    if buf.len() >= 6 {
        buf[0] = RMI_READ_ADDR_REPORT_ID;
        buf[1] = 0;
        buf[2] = (addr & 0xFF) as u8;
        buf[3] = (addr >> 8) as u8;
        buf[4] = (len & 0xFF) as u8;
        buf[5] = (len >> 8) as u8;
    }
    buf
}

/// Encode the output report for `rmi_set_page()` (`hid-rmi.c:121`)
/// — page switch is a 4-byte write to register `0xFF`.
///
/// ```text
///   [0] RMI_WRITE_REPORT_ID
///   [1] 1                ← write count
///   [2] 0xFF             ← RMI4 page-select register (low byte)
///   [3] 0                ← upper byte of that register
///   [4] page             ← page number
///   [..output_report_size] zero-padded
/// ```
pub fn encode_set_page(page: u8, output_report_size: usize) -> Vec<u8> {
    let mut buf = alloc::vec![0u8; output_report_size];
    if buf.len() >= 5 {
        buf[0] = RMI_WRITE_REPORT_ID;
        buf[1] = 1;
        buf[2] = 0xFF;
        buf[3] = 0;
        buf[4] = page;
    }
    buf
}

/// Extract the page byte from an RMI4 16-bit register address.
pub const fn rmi_page(addr: u16) -> u8 {
    (addr >> 8) as u8
}

// ── HidIo callback the USB-HID layer wires up ──────────────────────
//
// The driver doesn't know how to talk to USB. The USB-HID transport
// implements this trait when it binds to a Synaptics device, and
// the driver consumes / drives it.

/// Synchronous HID transport surface every concrete RMI4 driver
/// instance needs. Backed by either USB HID interrupt-OUT or the
/// I2C-HID interrupt-out channel.
pub trait HidIo {
    /// Send a fully-built output report.
    fn output_report(&mut self, report: &[u8]) -> Result<(), TransportError>;
    /// Send a Feature report via `HID_REQ_SET_REPORT(HID_FEATURE_REPORT)`.
    fn set_feature_report(&mut self, report: &[u8]) -> Result<(), TransportError>;
    /// Read pending input report into `dst`, blocking until one
    /// arrives or the bus times out. Used by the driver to wait
    /// for a `RMI_READ_DATA_REPORT_ID` response. Returns the
    /// number of bytes written into `dst`.
    fn poll_input_report(&mut self, dst: &mut [u8]) -> Result<usize, TransportError>;
}

/// Wraps a [`HidIo`] backend with the RMI4-over-HID
/// page-and-transport state. Implements [`Rmi4Transport`] so the
/// PDT walker + F$01 / F$12 decoders in [`crate::rmi4_core`] all
/// work against it unchanged.
#[derive(Debug)]
pub struct HidRmiTransport<H: HidIo> {
    io: H,
    output_report_size: usize,
    /// Last page we wrote — `Some(page)` only after `rmi_set_page`
    /// succeeded. Lazy page-switch elides redundant writes when
    /// the caller reads two adjacent registers in the same page.
    current_page: Option<u8>,
    quirks: DeviceQuirks,
}

impl<H: HidIo> HidRmiTransport<H> {
    /// Construct a transport. `output_report_size` comes from the
    /// HID descriptor — typically 19 or 24 bytes on Synaptics
    /// touchpads (one byte report-id + 3-byte header + payload).
    pub fn new(io: H, output_report_size: usize, quirks: DeviceQuirks) -> Self {
        Self {
            io,
            output_report_size,
            current_page: None,
            quirks,
        }
    }

    pub fn quirks(&self) -> DeviceQuirks {
        self.quirks
    }

    /// Switch into RMI mode by writing the Set_RMI_Mode Feature
    /// report. Idempotent — the device echoes its current mode in
    /// the next ATTN report.
    pub fn set_mode(&mut self, mode: u8) -> Result<(), TransportError> {
        let buf = encode_set_rmi_mode(mode);
        self.io.set_feature_report(&buf)
    }

    /// Switch RMI page; cached so repeated reads in the same page
    /// don't re-issue. Returns `Ok(())` even when the cache hit
    /// short-circuits.
    pub fn set_page(&mut self, page: u8) -> Result<(), TransportError> {
        if self.current_page == Some(page) {
            return Ok(());
        }
        let buf = encode_set_page(page, self.output_report_size);
        self.io.output_report(&buf)?;
        self.current_page = Some(page);
        Ok(())
    }
}

impl<H: HidIo> Rmi4Transport for HidRmiTransport<H> {
    fn read_block(&mut self, addr: u16, dst: &mut [u8]) -> Result<(), TransportError> {
        let page = rmi_page(addr);
        self.set_page(page)?;
        let req = encode_read_addr(addr, dst.len() as u16, self.output_report_size);
        self.io.output_report(&req)?;
        // Drain the input-report stream until we've collected the
        // requested length. Synaptics silicon chunks reads at the
        // input-report size; the body starts at byte 2 of each
        // RMI_READ_DATA_REPORT (byte 0 = report id, byte 1 =
        // chunk length). Mirrors the loop in
        // `rmi_hid_read_block()` (`hid-rmi.c:226-245`).
        let mut buf = [0u8; 64];
        let mut written = 0usize;
        for _retry in 0..16 {
            let n = self.io.poll_input_report(&mut buf)?;
            if n < 2 {
                return Err(TransportError::Short);
            }
            if buf[0] != RMI_READ_DATA_REPORT_ID {
                // Ignore — likely an ATTN report; the transport
                // layer or caller will drive on_input_report.
                continue;
            }
            let chunk_len = buf[1] as usize;
            let body_end = (2 + chunk_len).min(n);
            let body = &buf[2..body_end];
            let want = dst.len() - written;
            let take = body.len().min(want);
            dst[written..written + take].copy_from_slice(&body[..take]);
            written += take;
            if written >= dst.len() {
                return Ok(());
            }
        }
        Err(TransportError::Timeout)
    }

    fn write_block(&mut self, addr: u16, src: &[u8]) -> Result<(), TransportError> {
        let page = rmi_page(addr);
        self.set_page(page)?;
        let buf = encode_write_block(addr, src, self.output_report_size);
        self.io.output_report(&buf)
    }
}

// ── ATTN report intake ─────────────────────────────────────────────
//
// When the device is in `RMI_MODE_ATTN_REPORTS`, touch frames come
// in as a `RMI_ATTN_REPORT_ID` input report. The first byte after
// the report id is an interrupt-source bitmap (which F$ generated
// the ATTN), the rest is per-function packed data.

/// One decoded ATTN report header. Linux equivalent: the bytes
/// `data[1]` (intr) and `&data[2..]` (packed data) pulled out of
/// `rmi_input_event()` (`hid-rmi.c:320`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AttnReport<'a> {
    pub interrupt_sources: u8,
    pub data: &'a [u8],
}

impl<'a> AttnReport<'a> {
    /// Decode a raw HID input report. `buf` is the full report
    /// (including the leading byte). Returns `None` if the report
    /// isn't an ATTN report or is too short to carry a header.
    pub fn decode(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < 2 || buf[0] != RMI_ATTN_REPORT_ID {
            return None;
        }
        Some(Self {
            interrupt_sources: buf[1],
            data: &buf[2..],
        })
    }
}

// ── Clickpad detection ─────────────────────────────────────────────
//
// On clickpads, the mechanical click is a single GPIO into F$30
// (bit 0 = press), but the device fires only one button event. The
// kernel needs to surface BTN_LEFT exclusively, suppressing the
// left/right area split that the F$11 / F$12 X-position normally
// uses to fake button zones. Linux turns this on via
// `INPUT_PROP_BUTTONPAD` in `rmi_2d_sensor.c` (and indirectly when
// `rmi_hid_pdata.gpio_data.disable = true` is set on the
// `HAS_PHYS_BUTTONS` quirk in `hid-rmi.c:720-721`).

/// Classify a device as a clickpad based on F$30 query + quirks.
/// Returns `true` when the silicon reports a single mechanical
/// mouse button and the driver hasn't flagged phys-buttons.
pub fn is_clickpad(has_phys_buttons_quirk: bool, mech_mouse_btns: u8) -> bool {
    !has_phys_buttons_quirk && mech_mouse_btns <= 1
}

/// On a clickpad, the F$30 button bitmap collapses into a single
/// BTN_LEFT (bit 0 of bitmap → pressed). Returns the BTN_LEFT
/// state directly.
pub fn clickpad_btn_left(f30_bitmap: u32) -> bool {
    (f30_bitmap & 1) != 0
}

// ── Async RMI4-over-HID session (I2C-HID bind path) ────────────────
//
// The synchronous [`HidRmiTransport`] covers transports whose
// `HidIo` is sync (a future USB-HID backend). I2C-HID is async,
// so this session re-drives the same pure encoders
// (`encode_set_rmi_mode`, `encode_set_page`, `encode_read_addr`,
// `encode_write_block`) against the async [`I2cHidDriver`]
// instead of duplicating the wire format. The bind pump owns the
// session: it probes once (mode-set + PDT walk + F$01 query),
// then routes ATTN reports through the F$11 / F$12 decoders.
//
// Read-drain note: while waiting for a `RMI_READ_DATA_REPORT`
// the session polls the input register; ATTN reports that arrive
// interleaved are skipped — and therefore dropped — rather than
// buffered. That loses at most one touch frame on a concurrent
// button transition (the next ATTN carries current state); the
// probe path never races the pump loop, so no frame is lost
// there.

/// Map an [`I2cHidError`] onto the transport error the RMI4 core
/// reports. Bus timeouts stay timeouts; short / undersized
/// reports stay `Short`; everything else is a protocol error,
/// and an uninitialised driver is `NotReady`.
fn map_hid_error(e: I2cHidError) -> TransportError {
    use narf_drivers_i2c::I2cError;
    match e {
        I2cHidError::Bus(I2cError::Timeout) => TransportError::Timeout,
        I2cHidError::Bus(_) => TransportError::Protocol,
        I2cHidError::ShortReport | I2cHidError::BufferTooSmall => TransportError::Short,
        I2cHidError::NotInitialised => TransportError::NotReady,
        I2cHidError::BadDescriptor | I2cHidError::BadPowerState => TransportError::Protocol,
    }
}

/// Async RMI4-over-HID session bound to one [`I2cHidDriver`].
/// Holds only a shared reference — the bind pump keeps calling
/// `driver.read_input_report` directly for its report loop, which
/// is fine because every driver method takes `&self`.
#[derive(Debug)]
pub struct HidRmiSession<'d> {
    driver: &'d I2cHidDriver,
    output_report_size: usize,
    /// Last page we wrote — `Some(page)` only after `set_page`
    /// succeeded. Mirrors the [`HidRmiTransport`] cache.
    current_page: Option<u8>,
    quirks: DeviceQuirks,
}

impl<'d> HidRmiSession<'d> {
    /// Construct a session. `output_report_size` comes from the
    /// HID descriptor's `wMaxOutputLength`; a zero value falls
    /// back to 19 (one report-id byte + 3-byte header + payload,
    /// the typical Synaptics size).
    pub fn new(driver: &'d I2cHidDriver, output_report_size: usize, quirks: DeviceQuirks) -> Self {
        Self {
            driver,
            output_report_size: if output_report_size == 0 {
                19
            } else {
                output_report_size
            },
            current_page: None,
            quirks,
        }
    }

    pub fn quirks(&self) -> DeviceQuirks {
        self.quirks
    }

    /// Switch into RMI mode by writing the Set_RMI_Mode Feature
    /// report (Linux `rmi_set_mode()`, `hid-rmi.c:143-163`).
    pub async fn set_mode(&mut self, mode: u8) -> Result<(), TransportError> {
        self.driver
            .set_feature_report(RMI_SET_RMI_MODE_REPORT_ID, &[mode])
            .await
            .map_err(map_hid_error)
    }

    /// Switch RMI page; cached so repeated reads in the same page
    /// don't re-issue (Linux `rmi_set_page()`, `hid-rmi.c:121`).
    pub async fn set_page(&mut self, page: u8) -> Result<(), TransportError> {
        if self.current_page == Some(page) {
            return Ok(());
        }
        let buf = encode_set_page(page, self.output_report_size);
        self.driver
            .set_output_report(RMI_WRITE_REPORT_ID, &buf[1..])
            .await
            .map_err(map_hid_error)?;
        self.current_page = Some(page);
        Ok(())
    }

    /// Read `dst.len()` bytes from RMI4 register `addr`.
    /// Mirrors `rmi_hid_read_block()` (`hid-rmi.c:188-257`): the
    /// output report carries the address+length request; the
    /// device echoes data back via `RMI_READ_DATA_REPORT` input
    /// reports, chunked at the input-report size (body starts at
    /// byte 2 of each report: byte 0 = report id, byte 1 = chunk
    /// length).
    pub async fn read_block(&mut self, addr: u16, dst: &mut [u8]) -> Result<(), TransportError> {
        let page = rmi_page(addr);
        self.set_page(page).await?;
        let req = encode_read_addr(addr, dst.len() as u16, self.output_report_size);
        self.driver
            .set_output_report(RMI_READ_ADDR_REPORT_ID, &req[1..])
            .await
            .map_err(map_hid_error)?;
        let max_input = self.driver.max_input_length().max(2);
        let mut buf = alloc::vec![0u8; max_input];
        let mut written = 0usize;
        for _retry in 0..16 {
            let n = self
                .driver
                .read_input_report(&mut buf)
                .await
                .map_err(map_hid_error)?;
            if n == 0 {
                narf_scheduler::yield_now().await;
                continue;
            }
            if n < 2 || buf[0] != RMI_READ_DATA_REPORT_ID {
                // Not our read data — likely an ATTN report that
                // arrived interleaved (see the drain note above).
                narf_scheduler::yield_now().await;
                continue;
            }
            let chunk_len = buf[1] as usize;
            let body_end = (2 + chunk_len).min(n);
            let body = &buf[2..body_end];
            let want = dst.len() - written;
            let take = body.len().min(want);
            dst[written..written + take].copy_from_slice(&body[..take]);
            written += take;
            if written >= dst.len() {
                return Ok(());
            }
        }
        Err(TransportError::Timeout)
    }

    /// Write `src` bytes to RMI4 register `addr`. Mirrors
    /// `rmi_hid_write_block()` (`hid-rmi.c:259`).
    pub async fn write_block(&mut self, addr: u16, src: &[u8]) -> Result<(), TransportError> {
        let page = rmi_page(addr);
        self.set_page(page).await?;
        let buf = encode_write_block(addr, src, self.output_report_size);
        self.driver
            .set_output_report(RMI_WRITE_REPORT_ID, &buf[1..])
            .await
            .map_err(map_hid_error)
    }

    /// Decode the F$11 sensor limits over this session (see
    /// `crate::rmi4_core::decode_f11_sensor` for the layout).
    async fn decode_f11_sensor(&mut self, f11: &PdtEntry) -> Option<F11SensorInfo> {
        let mut query1 = [0u8; 1];
        self.read_block(f11.query_base as u16 + 1, &mut query1)
            .await
            .ok()?;
        let mut info = F11SensorInfo {
            max_x: RMI4_FALLBACK_F11_MAX,
            max_y: RMI4_FALLBACK_F11_MAX,
            max_fingers: F11SensorInfo::fingers_from_query1(query1[0]),
        };
        let mut ctrl = [0u8; 4];
        if self
            .read_block(
                f11.control_base as u16 + F11_CTRL_SENSOR_MAX_X_POS_OFFSET,
                &mut ctrl,
            )
            .await
            .is_ok()
        {
            let max_x = u16::from_le_bytes([ctrl[0], ctrl[1]]);
            let max_y = u16::from_le_bytes([ctrl[2], ctrl[3]]);
            if max_x > 0 {
                info.max_x = max_x;
            }
            if max_y > 0 {
                info.max_y = max_y;
            }
        }
        Some(info)
    }

    /// Read one register descriptor over this session (see
    /// `crate::rmi4_core::read_register_descriptor`).
    async fn read_register_descriptor(
        &mut self,
        addr: u16,
    ) -> Result<RmiRegDescriptor, TransportError> {
        let mut size = [0u8; 1];
        self.read_block(addr, &mut size).await?;
        let presence_len = size[0] as usize;
        if presence_len > RMI_REG_DESC_PRESENCE_MAX {
            return Err(TransportError::Protocol);
        }
        if presence_len == 0 {
            return Ok(RmiRegDescriptor::default());
        }
        let mut presence = alloc::vec![0u8; presence_len];
        self.read_block(addr + 1, &mut presence).await?;
        let (struct_size, _) =
            register_descriptor_header(&presence).map_err(|_| TransportError::Protocol)?;
        if struct_size > RMI_REG_DESC_STRUCT_MAX {
            return Err(TransportError::Protocol);
        }
        let mut structure = alloc::vec![0u8; struct_size];
        self.read_block(addr + 2, &mut structure).await?;
        parse_register_descriptor(&presence, &structure).map_err(|_| TransportError::Protocol)
    }

    /// Decode the F$12 sensor limits over this session (see
    /// `crate::rmi4_core::decode_f12_sensor` for the layout).
    async fn decode_f12_sensor(&mut self, f12: &PdtEntry) -> Option<F12SensorInfo> {
        let mut query0 = [0u8; 1];
        self.read_block(f12.query_base as u16, &mut query0)
            .await
            .ok()?;
        if (query0[0] & F12_QUERY_HAS_DESCRIPTORS) == 0 {
            return None;
        }
        // Descriptors live at query_base + 1 (query), + 4
        // (control), + 7 (data), three RMI addresses apart
        // (Linux `rmi_f12_probe`). The query descriptor itself
        // is never consumed after parsing — Linux reads it, we
        // skip it.
        let ctrl_desc = self
            .read_register_descriptor(f12.query_base as u16 + 4)
            .await
            .ok();
        let data_desc = self
            .read_register_descriptor(f12.query_base as u16 + 7)
            .await
            .ok();
        if ctrl_desc.is_none() && data_desc.is_none() {
            return None;
        }
        let mut info = F12SensorInfo {
            max_x: RMI4_FALLBACK_F12_MAX,
            max_y: RMI4_FALLBACK_F12_MAX,
            max_objects: RMI4_FALLBACK_MAX_COUNT,
        };
        if let Some(desc) = &ctrl_desc {
            if let Some(item) = desc.item(F12_CTRL_SENSOR_TUNING) {
                // Linux caps the tuning read at its 15-byte buffer.
                if item.reg_size <= 15 {
                    if let Some(offset) = desc.reg_offset(F12_CTRL_SENSOR_TUNING) {
                        let mut buf = [0u8; 15];
                        if self
                            .read_block(
                                f12.control_base as u16 + offset as u16,
                                &mut buf[..item.reg_size],
                            )
                            .await
                            .is_ok()
                        {
                            if let Some((max_x, max_y)) =
                                decode_f12_sensor_tuning(item, &buf[..item.reg_size])
                            {
                                if max_x > 0 {
                                    info.max_x = max_x;
                                }
                                if max_y > 0 {
                                    info.max_y = max_y;
                                }
                            }
                        }
                    }
                }
            }
        }
        if let Some(desc) = &data_desc {
            if let Some(data1) = desc.item(F12_DATA_OBJECT_DATA) {
                if data1.num_subpackets > 0 {
                    // Clamped to the pump's fixed slot table (Linux
                    // allocates `nbr_fingers` slots dynamically; our
                    // `Rmi4PumpState` holds `RMI4_PUMP_MAX_SLOTS`).
                    info.max_objects = (data1.num_subpackets as usize).min(RMI4_PUMP_MAX_SLOTS);
                }
            }
        }
        Some(info)
    }

    /// Probe the device: set RMI mode with ATTN reports, walk the
    /// page-0 PDT, read the F$01 product-info query block, and
    /// decode the F$11/F$12 sensor-maximum queries (best-effort —
    /// a failed sensor read leaves the probe field `None` and
    /// the consumers fall back to the placeholders).
    /// Returns the shared [`Rmi4DeviceProbe`] the bind pump and
    /// the SMBus transport both consume. Fails when the device
    /// does not answer in RMI mode or has no F$01 function — the
    /// caller then falls back to generic HID routing.
    pub async fn probe(&mut self) -> Result<Rmi4DeviceProbe, TransportError> {
        self.set_mode(RMI_MODE_ATTN_REPORTS).await?;
        // PDT walk, page 0 — same high-to-low scan and
        // termination rules as `walk_pdt_page` in rmi4_core.
        let mut table = Vec::new();
        let mut offset = PDT_LAST_SLOT_OFFSET;
        let mut buf = [0u8; PDT_ENTRY_SIZE];
        while offset >= PDT_FIRST_SLOT_OFFSET {
            self.read_block(offset, &mut buf).await?;
            if buf[5] == 0x00 {
                break;
            }
            match PdtEntry::decode(&buf) {
                Ok(Some(entry)) => table.push(entry),
                Ok(None) => {} // 0xFF empty slot — skip and continue.
                Err(_) => break,
            }
            if offset < PDT_FIRST_SLOT_OFFSET + PDT_ENTRY_SIZE as u16 {
                break;
            }
            offset -= PDT_ENTRY_SIZE as u16;
        }
        let f01 = find_function(&table, F01_DEVICE_CONTROL)
            .copied()
            .ok_or(TransportError::Protocol)?;
        let mut query = [0u8; 11];
        self.read_block(f01.query_base as u16, &mut query).await?;
        let product = F01ProductInfo::decode(&query).map_err(|_| TransportError::Short)?;
        let f11 = find_function(&table, F11_2D_TOUCHPAD).copied();
        let f12 = find_function(&table, F12_2D_TOUCHPAD_NEXT).copied();
        let f30 = find_function(&table, F30_GPIO_LED).copied();
        if f11.is_none() && f12.is_none() {
            return Err(TransportError::Protocol);
        }
        // F$30 GPIO/LED line count from its query registers;
        // defaults to 8 (one button byte) when the function
        // exists but the query read fails, 0 with no F$30.
        let mut f30_gpio_count = if f30.is_some() { 8 } else { 0 };
        if let Some(f30e) = &f30 {
            let mut qbuf = [0u8; 2];
            if self
                .read_block(f30e.query_base as u16, &mut qbuf)
                .await
                .is_ok()
            {
                if let Ok(q) = F30Query::decode(&qbuf) {
                    f30_gpio_count = q.gpio_led_count;
                }
            }
        }
        let interrupt_map = build_interrupt_map(&table);
        // F$11 / F$12 sensor maxima (best-effort — see the
        // doc comment on `probe`).
        let mut f11_sensor = None;
        if let Some(f) = &f11 {
            f11_sensor = self.decode_f11_sensor(f).await;
        }
        let mut f12_sensor = None;
        if let Some(f) = &f12 {
            f12_sensor = self.decode_f12_sensor(f).await;
        }
        Ok(Rmi4DeviceProbe {
            table,
            product,
            f11,
            f12,
            f30,
            f30_gpio_count,
            f11_sensor,
            f12_sensor,
            interrupt_map,
        })
    }
}

// ── Initcall registration ──────────────────────────────────────────

/// Stage::Device banner — at present the hid-rmi driver is a
/// library: it doesn't probe USB or i2c-HID on its own (the
/// transport layer owns probing). This initcall prints the "loaded"
/// banner so the FB panel + boot smoke can confirm the driver is
/// linked, mirroring how Linux logs `module_hid_driver(rmi_driver)`.
/// The HID_GROUP_RMI catch-all is not implemented (issue #1718),
/// so the banner counts explicit table rows only.
pub fn register_initcalls() {
    use core::fmt::Write as _;
    let _ = writeln!(
        narf_console::Writer,
        "  hid-rmi: loaded ({} explicit USB IDs)",
        RMI_DEVICE_TABLE.len(),
    );
}
