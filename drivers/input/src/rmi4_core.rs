//! RMI4 core protocol — driver-side helpers built atop the
//! transport-neutral `narf_input::rmi4` module.
//!
//! The protocol primitives in `narf_input::rmi4` (PDT entry layout,
//! F$01 device control, F$11 finger record) live in the public
//! event-types crate so they're reusable from the verification
//! harness. This module adds:
//!
//!   * F$12 modern 2D-sensor object decode (Win8+ "Synaptics modern"
//!     touchpads — used by every ThinkPad / Yoga / Surface touchpad
//!     since ~2014).
//!   * F$30 GPIO/LED button bitmap decode (clickpad mechanical
//!     buttons land here on Synaptics force / soft touchpads).
//!   * A `TransportError` shape every concrete transport (USB-HID,
//!     I2C-HID, SMBus) returns.
//!   * Walking the Page Description Table by chaining the existing
//!     `rmi4::PdtEntry::decode` against a transport callback —
//!     factored so both `hid_rmi` and a future `smbus_rmi` driver
//!     reuse it.
//!
//! Linux references (informational — code remains clean-room of
//! Linux):
//!   * `drivers/input/rmi4/rmi_driver.c` — bus driver, PDT walk.
//!   * `drivers/input/rmi4/rmi_f01.c` — F01 Device Control.
//!   * `drivers/input/rmi4/rmi_f11.c` — F11 legacy 2D sensor.
//!   * `drivers/input/rmi4/rmi_f12.c` — F12 modern 2D sensor.
//!   * `drivers/input/rmi4/rmi_f30.c` — F30 GPIO/LED buttons.
//!
//! Synaptics public application notes "511-000405-01" describe the
//! same register layout; our decoders here cite those notes.

extern crate alloc;

use alloc::vec::Vec;

use narf_input::{
    evdev::{DeviceNode, MtContactUpdate, MtEvdevState},
    push_global, InputEvent, PointerButtons, PointerEvent, TouchEvent, TouchState,
};

pub use narf_input::rmi4::{
    F01DeviceStatus, Finger, PdtEntry, Rmi4Error, TouchpadReport, F01_CONFIGURED,
    F01_DEVICE_CONTROL, F01_NOSLEEP, F01_REPORT_RATE_HIGH, F01_SLEEP_NORMAL, F01_SLEEP_RESERVED,
    F01_SLEEP_SENSOR_SLEEP, F01_SLEEP_SLEEP_NO_RECAL, F11_2D_TOUCHPAD, F12_2D_TOUCHPAD_NEXT,
    F30_GPIO_LED, F34_FLASH_REFLASH, F54_TEST_AND_REPORTING, PDT_ENTRY_SIZE, PDT_LAST_SLOT_OFFSET,
};

// ── F$01 Product info ──────────────────────────────────────────────
//
// Linux: `drivers/input/rmi4/rmi_f01.c` `rmi_f01_initialize()`
// reads 11 query bytes starting at F01.query_base. We surface the
// fields touchpad userland cares about (manufacturer/product/fw
// id) so the panel + a future "lsinput" syscall can report which
// silicon shipped on this machine.

/// Manufacturer-ID values declared in §4.5.6 of the public
/// Synaptics app notes. Userland looks up vendor-name strings
/// off this code; we keep the enum sparse and only name the IDs
/// we expect to actually see in laptop hardware.
pub const RMI_MANUFACTURER_SYNAPTICS: u8 = 1;

/// F$01 product-info block — decoded from the first 11 query
/// registers (`Query 0` … `Query 10`).
///
/// ```text
///   Q0  Manufacturer ID
///   Q1  Properties (bit 5 = HAS_SENSOR_ID, bit 4 = HAS_PRODUCT_PROPERTIES2,
///                   bit 3 = HAS_LTS, etc.)
///   Q2  Product Info byte 0 (firmware revision low)
///   Q3  Product Info byte 1 (firmware revision high)
///   Q4-Q6  Date code (year, month, day)
///   Q7-Q8  Tester ID
///   Q9-Q10 Serial number low / high
/// ```
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct F01ProductInfo {
    pub manufacturer_id: u8,
    pub properties: u8,
    pub firmware_id: u16,
    pub year: u8,
    pub month: u8,
    pub day: u8,
    pub tester_id: u16,
    pub serial: u16,
}

impl F01ProductInfo {
    /// Decode the 11-byte query block returned from
    /// `F01.query_base` (registers Q0..Q10). Shorter buffers
    /// produce `Err(Rmi4Error::Short)`.
    pub fn decode(buf: &[u8]) -> Result<Self, Rmi4Error> {
        if buf.len() < 11 {
            return Err(Rmi4Error::Short);
        }
        Ok(Self {
            manufacturer_id: buf[0],
            properties: buf[1],
            firmware_id: u16::from_le_bytes([buf[2], buf[3]]),
            year: buf[4],
            month: buf[5],
            day: buf[6],
            tester_id: u16::from_be_bytes([buf[7], buf[8]]),
            serial: u16::from_be_bytes([buf[9], buf[10]]),
        })
    }

    /// True if the silicon advertises itself as a Synaptics part.
    pub fn is_synaptics(&self) -> bool {
        self.manufacturer_id == RMI_MANUFACTURER_SYNAPTICS
    }
}

// ── F$12 Modern 2D sensor objects ──────────────────────────────────
//
// Linux: `drivers/input/rmi4/rmi_f12.c` lines 11-26.
//
// F$12 replaces F$11 on every Synaptics touchpad shipped after the
// Win8 transition. Object records are 8 bytes each (vs. F$11's 5)
// and carry an explicit "object type" field — finger vs. palm vs.
// stylus vs. eraser — so the driver doesn't have to infer "is this
// a finger" from width thresholds the way F$11 did.

/// F$12 object-type field values (Linux `enum
/// rmi_f12_object_type` in `rmi_f12.c:11`). Subset of the codes
/// the public Synaptics docs assign; we name the ones a touchpad
/// driver actually has to dispatch on.
pub mod f12_object {
    pub const NONE: u8 = 0x00;
    pub const FINGER: u8 = 0x01;
    pub const STYLUS: u8 = 0x02;
    pub const PALM: u8 = 0x03;
    pub const UNCLASSIFIED: u8 = 0x04;
    pub const GLOVED_FINGER: u8 = 0x06;
    pub const NARROW_OBJECT: u8 = 0x07;
    pub const HAND_EDGE: u8 = 0x08;
    pub const COVER: u8 = 0x0A;
    pub const STYLUS_2: u8 = 0x0B;
    pub const ERASER: u8 = 0x0C;
    pub const SMALL_OBJECT: u8 = 0x0D;
}

/// Bytes per F$12 "Data 1" object record (Linux
/// `F12_DATA1_BYTES_PER_OBJ` in `rmi_f12.c:26`).
pub const F12_OBJECT_SIZE: usize = 8;

/// One decoded F$12 object. Layout per Synaptics public app
/// notes "DS4/2017 Touch Modular Architecture":
///
/// ```text
///   byte 0  Object type (see `f12_object`)
///   byte 1  X position low
///   byte 2  X position high
///   byte 3  Y position low
///   byte 4  Y position high
///   byte 5  Z (contact pressure / amplitude, 0..=255)
///   byte 6  Wx (contact width X)
///   byte 7  Wy (contact width Y)
/// ```
///
/// `present` is false when `object_type == 0` (no object in this
/// slot) so consumers can iterate the data block uniformly.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct F12Object {
    pub object_type: u8,
    pub present: bool,
    pub x: u16,
    pub y: u16,
    pub z: u8,
    pub w_x: u8,
    pub w_y: u8,
}

impl F12Object {
    /// Decode one 8-byte object record. Returns a default-
    /// initialised (present = false) record when the leading
    /// object-type byte is `NONE`.
    pub fn decode(buf: &[u8]) -> Result<Self, Rmi4Error> {
        if buf.len() < F12_OBJECT_SIZE {
            return Err(Rmi4Error::Short);
        }
        let object_type = buf[0];
        if object_type == f12_object::NONE {
            return Ok(Self::default());
        }
        Ok(Self {
            object_type,
            present: true,
            x: u16::from_le_bytes([buf[1], buf[2]]),
            y: u16::from_le_bytes([buf[3], buf[4]]),
            z: buf[5],
            w_x: buf[6],
            w_y: buf[7],
        })
    }

    /// True if the decoded object represents a real touching
    /// finger the host should track as a contact slot — palms,
    /// covers, and small-object debris are *present* but a
    /// touchpad driver must not surface them as touches.
    pub fn is_touching_finger(&self) -> bool {
        matches!(
            self.object_type,
            f12_object::FINGER | f12_object::GLOVED_FINGER | f12_object::UNCLASSIFIED
        )
    }
}

/// Decode the F$12 "Data 1" multi-object block. `max_objects`
/// caps the number of object records the caller is willing to
/// decode (typically 5 or 10 — the value comes from F$12's Query
/// 1 register at probe time).
pub fn decode_f12_data1(buf: &[u8], max_objects: usize) -> Result<Vec<F12Object>, Rmi4Error> {
    if max_objects == 0 {
        return Err(Rmi4Error::BadEntry);
    }
    let need = max_objects * F12_OBJECT_SIZE;
    if buf.len() < need {
        return Err(Rmi4Error::Short);
    }
    let mut out = Vec::with_capacity(max_objects);
    for i in 0..max_objects {
        let off = i * F12_OBJECT_SIZE;
        out.push(F12Object::decode(&buf[off..off + F12_OBJECT_SIZE])?);
    }
    Ok(out)
}

// ── F$30 GPIO/LED — button bitmap ──────────────────────────────────
//
// Linux: `drivers/input/rmi4/rmi_f30.c` lines 24-47, 101-120.
//
// F$30 owns the physical buttons + LEDs the silicon exposes as
// GPIO. On clickpad touchpads the mechanical click is wired
// through F$30 GPIO 0/1/2 (left/right/middle). Data registers
// are *one bit per GPIO* with the polarity inverted (line low =
// button pressed).

/// F$30 Query 0 capability bits (Linux `RMI_F30_HAS_*` in
/// `rmi_f30.c:14`).
pub mod f30_query {
    pub const EXTENDED_PATTERNS: u8 = 1 << 0;
    pub const HAS_MAPPABLE_BUTTONS: u8 = 1 << 1;
    pub const HAS_LED: u8 = 1 << 2;
    pub const HAS_GPIO: u8 = 1 << 3;
    pub const HAS_HAPTIC: u8 = 1 << 4;
    pub const HAS_GPIO_DRV_CTL: u8 = 1 << 5;
    pub const HAS_MECH_MOUSE_BTNS: u8 = 1 << 6;
}

/// Decoded F$30 query header. Q0 + Q1 give us the capability
/// bits + the GPIO/LED line count (low 5 bits of Q1).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct F30Query {
    pub query_byte_0: u8,
    pub gpio_led_count: u8,
}

impl F30Query {
    pub fn decode(buf: &[u8]) -> Result<Self, Rmi4Error> {
        if buf.len() < 2 {
            return Err(Rmi4Error::Short);
        }
        Ok(Self {
            query_byte_0: buf[0],
            gpio_led_count: buf[1] & 0x1F,
        })
    }

    pub fn has_gpio(&self) -> bool {
        (self.query_byte_0 & f30_query::HAS_GPIO) != 0
    }
    pub fn has_led(&self) -> bool {
        (self.query_byte_0 & f30_query::HAS_LED) != 0
    }
    pub fn has_mech_mouse_btns(&self) -> bool {
        (self.query_byte_0 & f30_query::HAS_MECH_MOUSE_BTNS) != 0
    }
}

/// Decode the F$30 data register into a per-button bitset, with
/// the active-low polarity inverted to "true = pressed".
///
/// `gpio_count` is the GPIO/LED line count from `F30Query`
/// (capped at 32). Returns a `u32` bitmap with bit i = button i
/// pressed. Linux's `rmi_f30_report_button` (`rmi_f30.c:101`)
/// keys each bit off its `gpioled_key_map[i]` entry; we leave
/// that map to the consumer driver since it's per-device.
pub fn decode_f30_buttons(data_regs: &[u8], gpio_count: u8) -> Result<u32, Rmi4Error> {
    let count = gpio_count.min(32) as usize;
    let bytes_needed = count.div_ceil(8);
    if data_regs.len() < bytes_needed {
        return Err(Rmi4Error::Short);
    }
    let mut out = 0u32;
    for i in 0..count {
        let byte = data_regs[i / 8];
        // Polarity: line *low* = button pressed (Linux
        // `rmi_f30.c:107` — `bool key_down = !(data_regs[reg_num]
        // & BIT(bit_num));`). We invert here so callers see
        // "true means pressed" semantics.
        let pressed = (byte & (1 << (i % 8))) == 0;
        if pressed {
            out |= 1 << i;
        }
    }
    Ok(out)
}

/// Convenience: clickpad-style two-button layout. F$30 bit 0 →
/// BTN_LEFT, bit 1 → BTN_RIGHT, bit 2 → BTN_MIDDLE. Returns
/// `(left, right, middle)` booleans.
pub fn classic_clickpad_buttons(bitmap: u32) -> (bool, bool, bool) {
    ((bitmap & 1) != 0, (bitmap & 2) != 0, (bitmap & 4) != 0)
}

// ── Transport abstraction ──────────────────────────────────────────
//
// Every concrete RMI4 driver (hid-rmi, smbus-rmi, future i2c-rmi)
// boils down to "I can read N bytes from RMI4 register address
// A" and "I can write N bytes to register address A" plus a
// notification path for ATTN reports. We model the synchronous
// register-side as a trait.

/// Errors that bubble out of any RMI4 transport.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TransportError {
    /// Underlying bus reported a short transfer (USB STALL, I2C
    /// NAK before all bytes arrived, etc.).
    Short,
    /// Bus timeout — for HID, the read-data report never came
    /// back. Retried by the transport before bubbling up.
    Timeout,
    /// Bus-level protocol error — checksum bad, framing bad,
    /// state machine wedged.
    Protocol,
    /// The transport hasn't been brought up yet (probe didn't
    /// run, or the device was unplugged).
    NotReady,
}

/// One-shot register-window API. Implementors page-switch as
/// needed under the hood — the RMI4 address space is 16-bit but
/// some buses (SMBus, classic HID) tunnel through 8-bit pages.
pub trait Rmi4Transport {
    /// Read `dst.len()` bytes from RMI4 register `addr`.
    fn read_block(&mut self, addr: u16, dst: &mut [u8]) -> Result<(), TransportError>;
    /// Write `src` bytes to RMI4 register `addr`.
    fn write_block(&mut self, addr: u16, src: &[u8]) -> Result<(), TransportError>;
}

// ── Page Description Table walk ────────────────────────────────────
//
// Linux: `drivers/input/rmi4/rmi_driver.c` `rmi_scan_pdt_page()`
// (around line 990 in the version we shipped — exact line moves
// across LTS branches). Walks `0x00E9` down to `0x0010` in
// `PDT_ENTRY_SIZE`-byte chunks.

/// Lowest PDT slot offset (Synaptics public app notes §4.4).
pub const PDT_FIRST_SLOT_OFFSET: u16 = 0x0010;

/// Walk the Page Description Table on the given page, returning
/// every non-empty function entry it finds. Walks high-to-low
/// the way the silicon orders entries.
///
/// `transport.read_block` handles paging — the caller is
/// responsible for ensuring `page` is what the transport's
/// page-tracking state expects.
pub fn walk_pdt_page(
    transport: &mut dyn Rmi4Transport,
    page: u8,
) -> Result<Vec<PdtEntry>, TransportError> {
    let mut out = Vec::new();
    let mut offset = PDT_LAST_SLOT_OFFSET;
    let mut buf = [0u8; PDT_ENTRY_SIZE];
    let base = (page as u16) << 8;
    while offset >= PDT_FIRST_SLOT_OFFSET {
        transport.read_block(base + offset, &mut buf)?;
        // `PdtEntry::decode` returns Ok(None) for an empty slot
        // (function_number == 0x00 or 0xFF). We stop on 0x00
        // (end-of-table marker) per §4.4; 0xFF means "no
        // function this slot" and we keep walking.
        if buf[5] == 0x00 {
            break;
        }
        match PdtEntry::decode(&buf) {
            Ok(Some(entry)) => out.push(entry),
            Ok(None) => {} // 0xFF empty slot — skip and continue.
            Err(_) => break,
        }
        // Step to the next slot. Underflow protection — the
        // walk terminates at 0x0010.
        if offset < PDT_FIRST_SLOT_OFFSET + PDT_ENTRY_SIZE as u16 {
            break;
        }
        offset -= PDT_ENTRY_SIZE as u16;
    }
    Ok(out)
}

/// Look up the first PDT entry matching `function_number` in a
/// previously walked table. Returns `None` when the silicon
/// doesn't expose that function.
pub fn find_function(table: &[PdtEntry], function_number: u8) -> Option<&PdtEntry> {
    table.iter().find(|e| e.function_number == function_number)
}

// ── Shared device probe (HID + SMBus) ─────────────────────────────
//
// Both transports run the same probe — PDT walk on page 0, F$01
// product-info query, locate the 2D sensor (F$11 or F$12) and the
// F$30 buttons — and both need the same interrupt-source map, so
// it lives here once instead of once per transport.

/// One probed RMI4 device: the page-0 PDT plus the functions the
/// pump needs, resolved once at bind time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rmi4DeviceProbe {
    pub table: Vec<PdtEntry>,
    pub product: F01ProductInfo,
    pub f11: Option<PdtEntry>,
    pub f12: Option<PdtEntry>,
    pub f30: Option<PdtEntry>,
    /// GPIO/LED line count from the F$30 query (0 when the device
    /// has no F$30 function or the query read failed — the button
    /// reader then defaults to a 1-byte bitmap).
    pub f30_gpio_count: u8,
    /// `(function_number, interrupt-source bitmask)` in PDT scan
    /// order — see [`build_interrupt_map`].
    pub interrupt_map: Vec<(u8, u8)>,
}

impl Rmi4DeviceProbe {
    /// Interrupt-source bitmask owned by `function_number`
    /// (0 when the function is absent or owns no sources).
    pub fn source_mask_for(&self, function_number: u8) -> u8 {
        self.interrupt_map
            .iter()
            .find(|(f, _)| *f == function_number)
            .map(|(_, m)| *m)
            .unwrap_or(0)
    }

    /// Function owning interrupt-source bit `bit`, if any.
    pub fn function_for_source(&self, bit: u8) -> Option<u8> {
        self.interrupt_map
            .iter()
            .find(|(_, m)| m & (1 << bit) != 0)
            .map(|(f, _)| *f)
    }
}

/// Assign interrupt-source bits to PDT entries in scan order:
/// the first entry's sources take the lowest bits, the next
/// entry follows, and so on (Linux `rmi_driver.c` assigns
/// sources in the same scan order). Only the first 8 sources are
/// mapped — the F$01 interrupt-status registers beyond the first
/// byte belong to functions no laptop touchpad exposes, and the
/// ATTN bitmap the HID transport decodes is one byte.
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

/// Probe a device over a synchronous transport: walk the page-0
/// PDT, read the F$01 product-info query block, and resolve the
/// 2D sensor + F$30 entries. Fails when the device has no F$01
/// or no 2D sensor — the caller then falls back to generic HID
/// routing (or, for SMBus, declines the device).
pub fn probe_device(transport: &mut dyn Rmi4Transport) -> Result<Rmi4DeviceProbe, TransportError> {
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
    // F$30 GPIO/LED line count from its query registers (2 bytes
    // at the query base). Defaults to 8 (one button byte) when
    // the function exists but the query read fails, and 0 when
    // there is no F$30 function at all.
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
    Ok(Rmi4DeviceProbe {
        table,
        product,
        f11,
        f12,
        f30,
        f30_gpio_count,
        interrupt_map,
    })
}

// ── Shared contact pump (HID + SMBus + Elan) ───────────────────────
//
// Every vendor transport ends the same way: a positional array of
// contacts (slot = index) plus a clickpad button state, published
// as `TouchEvent`s on the global ring, a relative-pointer feed
// off the first contact, and a slot-protocol-B frame on the
// device's evdev node. One implementation keeps the three
// transports' event streams identical.

/// Maximum simultaneously tracked contacts in the shared RMI4
/// pump. Matches the F$11/F$12 five-finger panels with room for
/// the ten-object F$12 parts.
pub const RMI4_PUMP_MAX_SLOTS: usize = 10;

/// One normalised 2D contact for the shared pump. Coordinates
/// are raw device units; the pump normalises them against the
/// caller's axis ranges for the global ring and passes them raw
/// to the evdev frame (libinput maps them through the caps'
/// `EVIOCGABS` ranges, as the PTP path does).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Rmi4Contact {
    pub present: bool,
    pub x: i32,
    pub y: i32,
    pub pressure: i32,
}

/// Axis ranges the shared pump normalises contacts against.
/// One bound per axis; the pump maps raw device units into the
/// global ring through [`TouchEvent::normalise_axis`].
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Rmi4PumpBounds {
    pub x_min: i32,
    pub x_max: i32,
    pub y_min: i32,
    pub y_max: i32,
}

/// Per-device pump state shared by the HID, SMBus, and Elan
/// transports.
#[derive(Debug)]
pub struct Rmi4PumpState {
    slots: [bool; RMI4_PUMP_MAX_SLOTS],
    last_pos: [(i32, i32); RMI4_PUMP_MAX_SLOTS],
    evdev: MtEvdevState,
    last_pointer: Option<(i32, i32)>,
    last_button: bool,
}

impl Rmi4PumpState {
    pub fn new() -> Self {
        Self {
            slots: [false; RMI4_PUMP_MAX_SLOTS],
            last_pos: [(0, 0); RMI4_PUMP_MAX_SLOTS],
            evdev: MtEvdevState::new(RMI4_PUMP_MAX_SLOTS),
            last_pointer: None,
            last_button: false,
        }
    }

    /// Pump one frame. `contacts` is positional (index = slot);
    /// entries past [`RMI4_PUMP_MAX_SLOTS`] are dropped.
    /// `btn_left` is `None` when the button state is unknown this
    /// frame (no F$30 source fired) — the pump then holds the
    /// previous button state instead of synthesising a release.
    /// Returns the number of `TouchEvent`s pushed to the global ring.
    pub fn pump_contacts(
        &mut self,
        node: Option<&DeviceNode>,
        contacts: &[Rmi4Contact],
        btn_left: Option<bool>,
        bounds: Rmi4PumpBounds,
    ) -> usize {
        let mut pushed = 0usize;
        let mut updates: Vec<MtContactUpdate> = Vec::new();
        let mut first: Option<(i32, i32)> = None;
        for (i, c) in contacts.iter().enumerate().take(RMI4_PUMP_MAX_SLOTS) {
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
                    x: TouchEvent::normalise_axis(c.x, bounds.x_min, bounds.x_max) as i32,
                    y: TouchEvent::normalise_axis(c.y, bounds.y_min, bounds.y_max) as i32,
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
                    x: TouchEvent::normalise_axis(lx, bounds.x_min, bounds.x_max) as i32,
                    y: TouchEvent::normalise_axis(ly, bounds.y_min, bounds.y_max) as i32,
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
        // `None` holds the previous button state (see above).
        let btn = btn_left.unwrap_or(self.last_button);
        if let Some(node) = node {
            self.evdev.dispatch_frame(node, &updates, btn, false);
        }
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
                PointerButtons::EMPTY
            };
            let _ = push_global(InputEvent::Pointer(PointerEvent { dx, dy, buttons }));
        }
        pushed
    }
}

impl Default for Rmi4PumpState {
    fn default() -> Self {
        Self::new()
    }
}
