#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum I3cError {
    NoDevice,
    BusBusy,
    Timeout,
    Nack,
    CrcError,
    Denied,
    InvalidArgs,
    HardwareError,
}

pub enum I3cOp<'a> {
    Read(&'a mut [u8]),
    Write(&'a [u8]),
}

pub struct IbiPayload {
    pub addr: u8,
    pub data: alloc::vec::Vec<u8>,
}

// ── Common Command Codes (CCCs) ────────────────────────────────────
//
// Opcodes follow the I3C Basic Spec rev 1.1, Table 11 and the Linux
// kernel's <linux/i3c/ccc.h> macro scheme.  Broadcast CCCs use the
// raw opcode; directed CCCs set bit 7 (0x80) as per the spec.
//
// Linux refs:
//   include/linux/i3c/ccc.h — I3C_CCC_ID() macro and all opcode values
//   drivers/i3c/master/dw-i3c-master.c — dw_i3c_master_send_ccc_cmd(),
//       dw_i3c_master_daa()

/// The 7-bit CCC opcode carried on the I3C bus.
///
/// Bit 7 is always 0 for broadcast CCCs and 1 for directed CCCs as
/// per I3C spec rev 1.1 §5.1.9.3.  The variant values here match
/// Linux's I3C_CCC_ID() convention.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CommonCommandCode {
    // ── Broadcast CCCs (bit 7 = 0) ──────────────────────────
    /// Enable Events Command — broadcast (0x00)
    EnecBc = 0x00,
    /// Disable Events Command — broadcast (0x01)
    DisecBc = 0x01,
    /// Reset Dynamic Address Assignment — broadcast (0x06)
    RstdaaBc = 0x06,
    /// Enter Dynamic Address Assignment (0x07, broadcast-only)
    Entdaa = 0x07,
    /// Set Max Write Length — broadcast (0x09)
    SetmwlBc = 0x09,
    /// Set Max Read Length — broadcast (0x0A)
    SetmrlBc = 0x0A,

    // ── Directed CCCs (bit 7 = 1) ───────────────────────────
    /// Enable Events Command — directed (0x80)
    EnecDir = 0x80,
    /// Disable Events Command — directed (0x81)
    DisecDir = 0x81,
    /// Set Dynamic Address from Static Address (0x87, directed)
    Setdasa = 0x87,
    /// Set New Dynamic Address (0x88, directed)
    Setnewda = 0x88,
    /// Get Max Write Length (0x8B, directed)
    Getmwl = 0x8B,
    /// Get Max Read Length (0x8C, directed)
    Getmrl = 0x8C,
    /// Get Provisioned ID (0x8D, directed)
    Getpid = 0x8D,
    /// Get Bus Characteristics Register (0x8E, directed)
    Getbcr = 0x8E,
    /// Get Device Characteristics Register (0x8F, directed)
    Getdcr = 0x8F,
    /// Get Device Status (0x90, directed)
    Getstatus = 0x90,
}

impl CommonCommandCode {
    /// Returns `true` if this CCC is directed (bit 7 set).
    #[inline]
    pub fn is_directed(self) -> bool {
        (self as u8) & 0x80 != 0
    }

    /// Wire encoding: the raw byte transmitted after START+0x7E.
    #[inline]
    pub fn opcode(self) -> u8 {
        self as u8
    }
}

/// Destination selector for a directed CCC.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CccDest {
    /// Broadcast to all devices on the bus.
    Broadcast,
    /// Directed to a single 7-bit dynamic address.
    Address(u8),
}

/// A discovered I3C device, populated during ENTDAA.
///
/// Decoded from the 8-byte DAA response: 6 bytes PID (MSB first),
/// 1 byte BCR, 1 byte DCR — spec rev 1.1 §5.1.9.3 Table 86.
///
/// Linux ref: drivers/i3c/master/dw-i3c-master.c dw_i3c_master_daa()
/// and include/linux/i3c/device.h i3c_device_info.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct I3cDevice {
    /// 48-bit Provisioned ID (unique per silicon).  Stored as u64,
    /// upper 16 bits are zero.
    pub pid: u64,
    /// Bus Characteristics Register.
    pub bcr: u8,
    /// Device Characteristics Register.
    pub dcr: u8,
    /// Dynamic address assigned during ENTDAA.
    pub dynamic_addr: u8,
}

impl I3cDevice {
    /// Decode one DAA response slot.
    ///
    /// `daa_bytes` must be exactly 8 bytes:
    ///   [PID5, PID4, PID3, PID2, PID1, PID0, BCR, DCR]
    /// The dynamic address is provided separately (written into the
    /// Device Address Table by the master before issuing ENTDAA, then
    /// the device acknowledges it).
    pub fn from_daa_response(daa_bytes: &[u8; 8], dynamic_addr: u8) -> Self {
        // PID is big-endian 6 bytes at [0..6].  Spec rev 1.1 §5.1.9.3.
        let pid = ((daa_bytes[0] as u64) << 40)
            | ((daa_bytes[1] as u64) << 32)
            | ((daa_bytes[2] as u64) << 24)
            | ((daa_bytes[3] as u64) << 16)
            | ((daa_bytes[4] as u64) << 8)
            | (daa_bytes[5] as u64);
        I3cDevice {
            pid,
            bcr: daa_bytes[6],
            dcr: daa_bytes[7],
            dynamic_addr,
        }
    }
}
