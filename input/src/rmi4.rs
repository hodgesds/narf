//! Synaptics RMI4 — Register Mapping Interface, version 4 (clean-room).
//!
//! References (public-only):
//! - "Synaptics PS/2 ↔ SMBus + RMI4 Specification" (Synaptics
//!   public application notes, "511-000405-01" — the document
//!   describing the RMI4 transport layer that ClickPad / Force
//!   touchpads expose). Public PDF.
//! - MIPI Touch and Display Interface — clean-room references to
//!   Page Description Table layout and per-function register
//!   conventions are derived from Synaptics public datasheets and
//!   training collateral (no GPL Linux source consulted).
//! - "Synaptics SMBus Touchpad Communication Application Note"
//!   (rev D, 2008) — public; describes the SMBus mode the modern
//!   Linux laptop touchpads (Lenovo / Dell / HP) expose.
//!
//! No GPL Linux source consulted.
//!
//! ## Page Description Table walk
//!
//! RMI4 partitions the device's register space into 8-bit *pages*.
//! On each page the last 6 bytes (offsets 0xFA..0xFF on classic
//! 256-byte pages) contain a **Page Description Table** entry
//! describing one *Function* implemented on that page. Walking
//! consists of:
//!
//!   1. Set page = 0.
//!   2. Read PDT entries from `0xE9` downwards in 6-byte chunks
//!      until you hit one whose Function Number is 0 (terminator).
//!   3. For each entry, the Function Number identifies the
//!      register block (e.g. F$01 = Device Control, F$11 = 2D
//!      Touchpad Sensor, F$30 = GPIO/LED, F$34 = Flash Reflash).
//!
//! ## PDT entry layout (6 bytes)
//!
//! ```text
//!   byte 0  Query Base
//!   byte 1  Command Base
//!   byte 2  Control Base
//!   byte 3  Data Base
//!   byte 4  Interrupt Source Count + Function Version
//!           bits[2..0]  source count (number of IRQ sources owned by this fn)
//!           bits[6..5]  function version (0..3)
//!   byte 5  Function Number (0xFF = "no function on this page slot",
//!                            0x00 = end of table)
//! ```

use alloc::vec::Vec;

/// PDT entry size (§4.4 of the public Synaptics RMI4 application notes).
pub const PDT_ENTRY_SIZE: usize = 6;

/// Highest PDT slot offset on classic 256-byte pages.
pub const PDT_LAST_SLOT_OFFSET: u16 = 0x00E9;

// ── Function Numbers (a representative subset) ─────────────────────

pub const F01_DEVICE_CONTROL: u8 = 0x01;
pub const F11_2D_TOUCHPAD: u8 = 0x11;
pub const F12_2D_TOUCHPAD_NEXT: u8 = 0x12;
pub const F30_GPIO_LED: u8 = 0x30;
pub const F34_FLASH_REFLASH: u8 = 0x34;
pub const F54_TEST_AND_REPORTING: u8 = 0x54;

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Rmi4Error {
    Short,
    BadEntry,
}

/// One Page Description Table entry.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PdtEntry {
    pub function_number: u8,
    pub function_version: u8,
    pub interrupt_source_count: u8,
    pub query_base: u8,
    pub command_base: u8,
    pub control_base: u8,
    pub data_base: u8,
}

impl PdtEntry {
    /// Decode one 6-byte PDT entry. Returns `None` for an empty slot
    /// (function number == 0x00 marks end-of-table).
    pub fn decode(buf: &[u8]) -> Result<Option<Self>, Rmi4Error> {
        if buf.len() < PDT_ENTRY_SIZE {
            return Err(Rmi4Error::Short);
        }
        let function_number = buf[5];
        if function_number == 0 {
            return Ok(None);
        }
        if function_number == 0xFF {
            // Empty slot but more entries may follow.
            return Ok(None);
        }
        let interrupt_source_count = buf[4] & 0x07;
        let function_version = (buf[4] >> 5) & 0x03;
        Ok(Some(Self {
            function_number,
            function_version,
            interrupt_source_count,
            query_base: buf[0],
            command_base: buf[1],
            control_base: buf[2],
            data_base: buf[3],
        }))
    }
}

// ── F$01 Device Control ────────────────────────────────────────────

/// Device-state encoded in F$01 control register byte 0 (§4.5.4 of
/// the Synaptics RMI4 public app notes — table "Sleep Mode bits").
pub const F01_SLEEP_NORMAL: u8 = 0x00;
pub const F01_SLEEP_SENSOR_SLEEP: u8 = 0x01;
pub const F01_SLEEP_RESERVED: u8 = 0x02;
pub const F01_SLEEP_SLEEP_NO_RECAL: u8 = 0x03;
pub const F01_NOSLEEP: u8 = 1 << 2;
pub const F01_REPORT_RATE_HIGH: u8 = 1 << 6;
pub const F01_CONFIGURED: u8 = 1 << 7;

/// Build the F$01 control register byte 0 (Device Control).
pub fn f01_device_control_byte(sleep_mode: u8, configured: bool, report_rate_high: bool) -> u8 {
    let mut v = sleep_mode & 0x03;
    if report_rate_high {
        v |= F01_REPORT_RATE_HIGH;
    }
    if configured {
        v |= F01_CONFIGURED;
    }
    v
}

/// Decoded F$01 status byte 0 (Device Status, §4.5.5):
///
/// ```text
///   bits[3..0] = Status Code (0=OK, 1=Reset Occurred, 2=Invalid Config,
///                4=Device Failure, 5=Configuration CRC Failure,
///                6=Firmware CRC Failure, 7=Firmware Integrity Failure)
///   bit 6      = Flash Programming Mode
///   bit 7      = Unconfigured (1 = needs configuration)
/// ```
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct F01DeviceStatus {
    pub status_code: u8,
    pub flash_programming_mode: bool,
    pub unconfigured: bool,
}

impl F01DeviceStatus {
    pub fn decode(b: u8) -> Self {
        Self {
            status_code: b & 0x0F,
            flash_programming_mode: (b & (1 << 6)) != 0,
            unconfigured: (b & (1 << 7)) != 0,
        }
    }
}

// ── F$11 2D Touchpad Finger Reports ────────────────────────────────

/// One finger as reported by F$11 data register (§4.6.3 of the public
/// app notes). Each finger occupies 5 bytes:
///
/// ```text
///   byte 0  X position high byte
///   byte 1  Y position high byte
///   byte 2  bits[7..4] = X position low 4 bits, bits[3..0] = Y position low 4 bits
///   byte 3  Wx (touch width X)
///   byte 4  Wy (touch width Y)
/// ```
///
/// A finger is *present* if any of its 5 report bytes are non-zero.
/// Position values are packed low/high to give 12-bit X/Y.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Finger {
    pub present: bool,
    pub x: u16,
    pub y: u16,
    pub w_x: u8,
    pub w_y: u8,
}

impl Finger {
    pub const REPORT_SIZE: usize = 5;

    pub fn parse(buf: &[u8]) -> Self {
        let any = buf.iter().any(|b| *b != 0);
        let x = ((buf[0] as u16) << 4) | ((buf[2] >> 4) as u16);
        let y = ((buf[1] as u16) << 4) | ((buf[2] & 0x0F) as u16);
        Self {
            present: any,
            x,
            y,
            w_x: buf[3],
            w_y: buf[4],
        }
    }
}

/// Decode an F$11 multitouch report. The first byte is a *finger
/// state* nibble pair: every two bits encode one finger's state
/// (00=no finger, 01=finger present accurate, 10=finger present
/// inaccurate, 11=reserved). The finger-state byte is followed by
/// up to 5 × N report blocks.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TouchpadReport {
    pub fingers: Vec<Finger>,
}

impl TouchpadReport {
    /// Parse an F$11 data block. `max_fingers` clamps how many finger
    /// states the caller is willing to allocate (e.g. 2 for early
    /// ClickPads, 5 for modern devices).
    pub fn parse(buf: &[u8], max_fingers: usize) -> Result<Self, Rmi4Error> {
        if max_fingers == 0 {
            return Err(Rmi4Error::BadEntry);
        }
        let state_bytes = (max_fingers + 3) / 4; // 2 bits per finger
        let total = state_bytes + max_fingers * Finger::REPORT_SIZE;
        if buf.len() < total {
            return Err(Rmi4Error::Short);
        }
        let mut fingers = Vec::with_capacity(max_fingers);
        let mut report_off = state_bytes;
        for f in 0..max_fingers {
            let state_byte = buf[f / 4];
            let state = (state_byte >> ((f % 4) * 2)) & 0x03;
            if state == 0 || state == 3 {
                fingers.push(Finger::default());
            } else {
                let report = &buf[report_off..report_off + Finger::REPORT_SIZE];
                let mut finger = Finger::parse(report);
                finger.present = true;
                fingers.push(finger);
            }
            report_off += Finger::REPORT_SIZE;
        }
        Ok(Self { fingers })
    }
}

// ── F$34 Flash Reflash ─────────────────────────────────────────────

/// F$34 command codes (§4.10.4 of the public Synaptics RMI4 docs).
pub const F34_CMD_WRITE_BLOCK: u8 = 0x02;
pub const F34_CMD_ERASE_ALL: u8 = 0x03;
pub const F34_CMD_READ_CONFIG_BLOCK: u8 = 0x05;
pub const F34_CMD_WRITE_CONFIG_BLOCK: u8 = 0x06;
pub const F34_CMD_ERASE_CONFIG: u8 = 0x07;
pub const F34_CMD_DISABLE_FLASH_PROG: u8 = 0x08;
pub const F34_CMD_ENABLE_FLASH_PROG: u8 = 0x0F;
