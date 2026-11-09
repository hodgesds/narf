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

// ── F$11 / F$12 sensor-maximum queries ─────────────────────────────
//
// Linux references:
//   * `drivers/input/rmi4/rmi_f11.c` — Query 1 finger count
//     (`rmi_f11_get_query_parameters`, `f11_2d_construct_data`)
//     and the control-register sensor maxima
//     (`F11_CTRL_SENSOR_MAX_X_POS_OFFSET` 6 /
//     `F11_CTRL_SENSOR_MAX_Y_POS_OFFSET` 8, read in
//     `rmi_f11_initialize`).
//   * `drivers/input/rmi4/rmi_f12.c` — Query 0 descriptor flag,
//     the three register descriptors (`rmi_f12_probe`), the
//     Control-8 sensor tuning (`rmi_f12_read_sensor_tuning`)
//     and the Data-1 object count (`sensor->nbr_fingers =
//     item->num_subpackets`).
//   * `drivers/input/rmi4/rmi_driver.c` — the register-descriptor
//     wire format (`rmi_read_register_desc`): one size byte, a
//     presence packet register (all bytes at one RMI address),
//     then the structure packet at the next address. The
//     presence register is a *packet* register — its bytes share
//     a single RMI address and the structure follows at
//     presence_address + 1 (upstream revert of the incorrect
//     `presence_address + presence_size` calculation, June 2026).
//
// One deliberate divergence from Linux: a descriptor/query
// failure here never fails the probe. Linux returns -ENODEV
// when F$12 has no register descriptors; we fall back to the
// previous placeholder values (5 objects/fingers, field-width
// axis ranges) so a descriptor quirk on one touchpad cannot
// brick the device. The probe fields stay `None` and every
// consumer uses the same defaults the pumps used before.
//
// Object-type enable bits: Linux exposes no F$12
// object-type-enable register — object types arrive per object
// in F$12 Data 1 byte 0 and are dispatched on by
// `F12Object::is_touching_finger` (see `f12_object`). The
// issue's "object-type enable bits" sub-item is therefore not
// decoded: there is no grounded layout for it in `rmi_f12.c`
// or the S3402 product spec, and inventing one would be a
// fabrication. If the RMI4 specification names such a register,
// it can be added against that passage.

/// F$11 Query 1 finger-count field mask (Linux
/// `RMI_F11_NR_FINGERS_MASK` in `rmi_f11.c`).
pub const F11_QUERY_NR_FINGERS_MASK: u8 = 0x07;

/// F$11 control-register offsets of the sensor-maximum
/// positions (Linux `F11_CTRL_SENSOR_MAX_X_POS_OFFSET` /
/// `F11_CTRL_SENSOR_MAX_Y_POS_OFFSET` in `rmi_f11.c`). Each
/// maximum is a little-endian u16 at `control_base + offset`.
pub const F11_CTRL_SENSOR_MAX_X_POS_OFFSET: u16 = 6;
pub const F11_CTRL_SENSOR_MAX_Y_POS_OFFSET: u16 = 8;

/// F$12 Query 0 bit: the device carries register descriptors
/// (Linux `rmi_f12_probe`: `!(buf & BIT(0))` → -ENODEV).
pub const F12_QUERY_HAS_DESCRIPTORS: u8 = 1 << 0;

/// F$12 Control register 8: sensor tuning — subpacket 0 is the
/// sensor maximum X/Y (Linux `rmi_f12_read_sensor_tuning`).
pub const F12_CTRL_SENSOR_TUNING: u8 = 8;

/// F$12 Data register 1: sensed objects — `num_subpackets` is
/// the maximum reported object count (Linux `rmi_f12_probe`:
/// `sensor->nbr_fingers = item->num_subpackets`).
pub const F12_DATA_OBJECT_DATA: u8 = 1;

/// Largest presence register a descriptor may carry (Linux
/// `rmi_read_register_desc`: `size_presence_reg > 35` → -EIO).
pub const RMI_REG_DESC_PRESENCE_MAX: usize = 35;

/// Largest register-descriptor structure this parser reads.
/// Linux imposes no cap (it `kzalloc`s `struct_size`); real
/// F$12 descriptors are tens of bytes, so 512 is generous
/// headroom and bounds a lying `struct_size` from allocating
/// an unbounded buffer.
pub const RMI_REG_DESC_STRUCT_MAX: usize = 512;

/// Subpacket-map width in bits (Linux
/// `RMI_REG_DESC_SUBPACKET_BITS` = 37 bytes × 8).
pub const RMI_REG_DESC_SUBPACKET_BITS: usize = 296;

/// Fallback sensor values, used when the query/control reads
/// fail: the placeholders the pumps used before this decode
/// existed (5 objects/fingers; field-width axis ranges).
pub const RMI4_FALLBACK_MAX_COUNT: usize = 5;
pub const RMI4_FALLBACK_F11_MAX: u16 = 0x0FFF;
pub const RMI4_FALLBACK_F12_MAX: u16 = 0xFFFF;

/// Decoded F$11 sensor limits: the sensor-maximum X/Y from
/// Control registers 6/8 and the finger count from Query 1.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct F11SensorInfo {
    pub max_x: u16,
    pub max_y: u16,
    pub max_fingers: usize,
}

impl F11SensorInfo {
    /// Finger count from F$11 Query 1 (Linux
    /// `rmi_f11_get_query_parameters`: `nr_fingers = query_buf[0]
    /// & RMI_F11_NR_FINGERS_MASK`; `f11_2d_construct_data`:
    /// `nbr_fingers = nr_fingers == 5 ? 10 : nr_fingers + 1`).
    pub fn fingers_from_query1(query1: u8) -> usize {
        let nr = query1 & F11_QUERY_NR_FINGERS_MASK;
        if nr == 5 {
            10
        } else {
            nr as usize + 1
        }
    }
}

/// Decoded F$12 sensor limits: the sensor-maximum X/Y from
/// Control 8 and the maximum reported object count from the
/// Data-1 descriptor.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct F12SensorInfo {
    pub max_x: u16,
    pub max_y: u16,
    pub max_objects: usize,
}

/// One packet register from an RMI4 register descriptor
/// (Linux `struct rmi_register_desc_item` in `rmi_driver.h`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RmiRegDescItem {
    /// Register number within its block (query / control /
    /// data).
    pub reg: u8,
    /// Register size in bytes.
    pub reg_size: usize,
    /// Number of subpackets the register carries
    /// (`num_subpackets` — for F$12 Data 1, the maximum
    /// reported object count).
    pub num_subpackets: u16,
    /// Subpacket presence map, bit `n` = subpacket `n` present
    /// (Linux `subpacket_map`, 296 bits).
    subpacket_map: [u64; 5],
}

impl RmiRegDescItem {
    /// Whether subpacket `n` is present in this register
    /// (Linux `rmi_register_desc_has_subpacket`).
    pub fn has_subpacket(&self, subpacket: u8) -> bool {
        let bit = subpacket as usize;
        if bit >= RMI_REG_DESC_SUBPACKET_BITS {
            return false;
        }
        (self.subpacket_map[bit / 64] >> (bit % 64)) & 1 != 0
    }
}

/// A parsed RMI4 register descriptor: the packet registers of
/// one kind (query / control / data) present on the device, in
/// ascending register order (Linux `struct
/// rmi_register_descriptor`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RmiRegDescriptor {
    pub items: Vec<RmiRegDescItem>,
}

impl RmiRegDescriptor {
    /// The descriptor item for register `reg`, if present.
    pub fn item(&self, reg: u8) -> Option<&RmiRegDescItem> {
        self.items.iter().find(|i| i.reg == reg)
    }

    /// Byte offset of register `reg` within its register block:
    /// the sum of the sizes of the registers before it (Linux
    /// `rmi_register_desc_calc_reg_offset`). `None` when the
    /// register is absent.
    pub fn reg_offset(&self, reg: u8) -> Option<usize> {
        let mut offset = 0usize;
        for item in &self.items {
            if item.reg == reg {
                return Some(offset);
            }
            offset += item.reg_size;
        }
        None
    }
}

/// Split a descriptor presence block into the structure size
/// and the presence-bitmap start (Linux
/// `rmi_read_register_desc`: `buf[0] == 0` means the structure
/// size is the little-endian u16 in `buf[1..3]` and the bitmap
/// starts at `buf[3]`; otherwise the size is `buf[0]` and the
/// bitmap starts at `buf[1]`).
pub fn register_descriptor_header(presence: &[u8]) -> Result<(usize, usize), Rmi4Error> {
    if presence.is_empty() {
        return Err(Rmi4Error::Short);
    }
    if presence[0] == 0 {
        if presence.len() < 3 {
            return Err(Rmi4Error::Short);
        }
        Ok((u16::from_le_bytes([presence[1], presence[2]]) as usize, 3))
    } else {
        Ok((presence[0] as usize, 1))
    }
}

/// Parse a register descriptor from its presence block and its
/// structure bytes (Linux `rmi_read_register_desc`, structure
/// half). The presence bitmap lists the registers present, in
/// ascending order; each structure entry is a register size
/// (one byte, or `0` + little-endian u16, or `0` + `0x0000` +
/// little-endian u32) followed by subpacket-map bytes of 7 bits
/// each, bit 7 set = another map byte follows.
///
/// Short-structure tolerance (upstream, June 2026 — some
/// touchpads report a structure size too small for the number
/// of registers claimed): an entry that runs past the end of
/// the structure is dropped, along with the entries after it,
/// instead of failing the whole parse.
pub fn parse_register_descriptor(
    presence: &[u8],
    structure: &[u8],
) -> Result<RmiRegDescriptor, Rmi4Error> {
    let (_struct_size, bitmap_start) = register_descriptor_header(presence)?;
    // Registers present, ascending: bit `b` of bitmap byte `i`
    // is register `(i - bitmap_start) * 8 + b`.
    let mut regs: Vec<u8> = Vec::new();
    for (i, byte) in presence.iter().enumerate().skip(bitmap_start) {
        for b in 0..8 {
            if byte & (1 << b) != 0 {
                let reg = (i - bitmap_start) * 8 + b;
                if reg < 256 {
                    regs.push(reg as u8);
                }
            }
        }
    }
    let mut items = Vec::with_capacity(regs.len());
    let mut offset = 0usize;
    for reg in regs {
        // Register size: 1 byte, or 0 + LE16, or 0 + 0x0000 +
        // LE32 (Linux `rmi_read_register_desc`).
        if offset >= structure.len() {
            break;
        }
        let mut reg_size = structure[offset] as usize;
        offset += 1;
        if reg_size == 0 {
            if offset + 2 > structure.len() {
                break;
            }
            reg_size = u16::from_le_bytes([structure[offset], structure[offset + 1]]) as usize;
            offset += 2;
        }
        if reg_size == 0 {
            if offset + 4 > structure.len() {
                break;
            }
            reg_size = u32::from_le_bytes([
                structure[offset],
                structure[offset + 1],
                structure[offset + 2],
                structure[offset + 3],
            ]) as usize;
            offset += 4;
        }
        if reg_size == 0 {
            // A zero-size register is unparseable — stop here,
            // as with a short structure.
            break;
        }
        // Subpacket map: 7 bits per byte, bit 7 = continue.
        let mut map = [0u64; 5];
        let mut map_offset = 0usize;
        let mut complete = false;
        while offset < structure.len() {
            let byte = structure[offset];
            offset += 1;
            for b in 0..7 {
                if byte & (1 << b) != 0 && map_offset < RMI_REG_DESC_SUBPACKET_BITS {
                    map[map_offset / 64] |= 1 << (map_offset % 64);
                }
                map_offset += 1;
            }
            if byte & 0x80 == 0 {
                complete = true;
                break;
            }
        }
        if !complete {
            break;
        }
        let num_subpackets = map.iter().map(|w| w.count_ones() as u16).sum::<u16>();
        items.push(RmiRegDescItem {
            reg,
            reg_size,
            num_subpackets,
            subpacket_map: map,
        });
    }
    Ok(RmiRegDescriptor { items })
}

/// Read one register descriptor from the device at RMI address
/// `addr` (Linux `rmi_read_register_desc`): 1 size byte at
/// `addr`, the presence packet (`size` bytes, all at the single
/// packet address `addr + 1`), then the structure packet at
/// `addr + 2`. Each F$12 descriptor occupies three RMI
/// addresses this way, which is why Linux advances
/// `query_addr` by 3 between the query/control/data
/// descriptors in `rmi_f12_probe`.
pub fn read_register_descriptor(
    transport: &mut dyn Rmi4Transport,
    addr: u16,
) -> Result<RmiRegDescriptor, TransportError> {
    let mut size = [0u8; 1];
    transport.read_block(addr, &mut size)?;
    let presence_len = size[0] as usize;
    if presence_len > RMI_REG_DESC_PRESENCE_MAX {
        return Err(TransportError::Protocol);
    }
    if presence_len == 0 {
        return Ok(RmiRegDescriptor::default());
    }
    let mut presence = alloc::vec![0u8; presence_len];
    transport.read_block(addr + 1, &mut presence)?;
    let (struct_size, _) =
        register_descriptor_header(&presence).map_err(|_| TransportError::Protocol)?;
    if struct_size > RMI_REG_DESC_STRUCT_MAX {
        return Err(TransportError::Protocol);
    }
    let mut structure = alloc::vec![0u8; struct_size];
    transport.read_block(addr + 2, &mut structure)?;
    parse_register_descriptor(&presence, &structure).map_err(|_| TransportError::Protocol)
}

/// Decode the F$12 Control-8 sensor-tuning subpacket 0: the
/// sensor maximum X/Y as two little-endian u16s (Linux
/// `rmi_f12_read_sensor_tuning`: `sensor->max_x =
/// (buf[offset + 1] << 8) | buf[offset]`, same for Y).
/// Returns `None` when subpacket 0 is absent or the block is
/// shorter than the 4 maximum bytes.
pub fn decode_f12_sensor_tuning(item: &RmiRegDescItem, ctrl8: &[u8]) -> Option<(u16, u16)> {
    if !item.has_subpacket(0) || ctrl8.len() < 4 {
        return None;
    }
    Some((
        u16::from_le_bytes([ctrl8[0], ctrl8[1]]),
        u16::from_le_bytes([ctrl8[2], ctrl8[3]]),
    ))
}

/// Decode the F$11 sensor limits over a synchronous transport:
/// Query 1 (finger count) plus the control-register sensor
/// maxima. Any failed read leaves that piece at its fallback
/// value; a failed Query 1 read returns `None` (no finger
/// count, no maxima — the caller keeps the placeholders).
pub fn decode_f11_sensor(
    transport: &mut dyn Rmi4Transport,
    f11: &PdtEntry,
) -> Option<F11SensorInfo> {
    let mut query1 = [0u8; 1];
    transport
        .read_block(f11.query_base as u16 + 1, &mut query1)
        .ok()?;
    let mut info = F11SensorInfo {
        max_x: RMI4_FALLBACK_F11_MAX,
        max_y: RMI4_FALLBACK_F11_MAX,
        max_fingers: F11SensorInfo::fingers_from_query1(query1[0]),
    };
    // Control registers 6..9 hold the maxima (two LE u16s in
    // one 4-byte read at control_base + 6).
    let mut ctrl = [0u8; 4];
    if transport
        .read_block(
            f11.control_base as u16 + F11_CTRL_SENSOR_MAX_X_POS_OFFSET,
            &mut ctrl,
        )
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

/// Decode the F$12 sensor limits over a synchronous transport:
/// the Query-0 descriptor flag, the control + data register
/// descriptors, the Control-8 sensor tuning (maxima) and the
/// Data-1 object count. Any failed step leaves that piece at
/// its fallback value; `None` only when no descriptor parsed
/// at all (Linux would fail the probe here — see the section
/// docs — we fall back to the placeholders instead).
pub fn decode_f12_sensor(
    transport: &mut dyn Rmi4Transport,
    f12: &PdtEntry,
) -> Option<F12SensorInfo> {
    let mut query0 = [0u8; 1];
    transport
        .read_block(f12.query_base as u16, &mut query0)
        .ok()?;
    if (query0[0] & F12_QUERY_HAS_DESCRIPTORS) == 0 {
        return None;
    }
    // Descriptors live at query_base + 1 (query), + 4
    // (control), + 7 (data), three RMI addresses apart (Linux
    // `rmi_f12_probe`). The query descriptor itself is never
    // consumed after parsing — Linux reads it, we skip it.
    let ctrl_desc = read_register_descriptor(transport, f12.query_base as u16 + 4).ok();
    let data_desc = read_register_descriptor(transport, f12.query_base as u16 + 7).ok();
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
                    if transport
                        .read_block(
                            f12.control_base as u16 + offset as u16,
                            &mut buf[..item.reg_size],
                        )
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
    /// Decoded F$11 sensor limits (`None` when the device has
    /// no F$11 function or the query/control reads failed —
    /// consumers use the fallback values then).
    pub f11_sensor: Option<F11SensorInfo>,
    /// Decoded F$12 sensor limits (`None` when the device has
    /// no F$12 function or no register descriptor parsed).
    pub f12_sensor: Option<F12SensorInfo>,
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

    /// Maximum F$11 fingers the sensor reports (fallback 5,
    /// the placeholder the pumps used before the F$11 query
    /// was decoded).
    pub fn f11_max_fingers(&self) -> usize {
        self.f11_sensor
            .map(|s| s.max_fingers)
            .unwrap_or(RMI4_FALLBACK_MAX_COUNT)
    }

    /// Maximum F$12 objects the sensor reports (fallback 5).
    pub fn f12_max_objects(&self) -> usize {
        self.f12_sensor
            .map(|s| s.max_objects)
            .unwrap_or(RMI4_FALLBACK_MAX_COUNT)
    }

    /// Sensor-maximum X/Y: F$12 preferred (a device never
    /// exposes both as its touch sensor); field-width fallbacks
    /// when nothing decoded.
    pub fn sensor_axis_maxima(&self) -> (u16, u16) {
        if let Some(f12) = self.f12_sensor {
            return (f12.max_x, f12.max_y);
        }
        if let Some(f11) = self.f11_sensor {
            return (f11.max_x, f11.max_y);
        }
        if self.f12.is_some() {
            (RMI4_FALLBACK_F12_MAX, RMI4_FALLBACK_F12_MAX)
        } else {
            (RMI4_FALLBACK_F11_MAX, RMI4_FALLBACK_F11_MAX)
        }
    }

    /// Simultaneous-contact slots for the caps: the decoded
    /// object/finger count of whichever sensor is present.
    pub fn sensor_slots(&self) -> usize {
        if self.f12.is_some() {
            self.f12_max_objects()
        } else {
            self.f11_max_fingers()
        }
    }

    /// Axis ranges the shared pump normalises contacts against.
    pub fn sensor_bounds(&self) -> Rmi4PumpBounds {
        let (max_x, max_y) = self.sensor_axis_maxima();
        Rmi4PumpBounds {
            x_min: 0,
            x_max: max_x as i32,
            y_min: 0,
            y_max: max_y as i32,
        }
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
    // F$11 / F$12 sensor maxima (best-effort — a failed read
    // leaves the probe field `None` and the consumers fall
    // back to the placeholders).
    let f11_sensor = f11.as_ref().and_then(|f| decode_f11_sensor(transport, f));
    let f12_sensor = f12.as_ref().and_then(|f| decode_f12_sensor(transport, f));
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
