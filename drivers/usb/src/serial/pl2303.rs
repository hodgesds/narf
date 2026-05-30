//! Prolific PL2303HX/HXA/HXD/X/EA USB-to-serial adapter driver — clean-room.
//!
//! ## Hardware overview
//!
//! The PL2303 from Prolific Technology exposes a serial port via USB.
//! It uses a mix of standard CDC class requests (GET_LINE_CODING /
//! SET_LINE_CODING in the CDC PSTN format) and proprietary vendor
//! requests for internal register access.
//!
//! The 7-byte line-coding payload layout is identical to CDC-ACM:
//! ```text
//!   bytes 0–3:  baud rate (u32 little-endian)
//!   byte  4:    stop bits (0=1, 1=1.5, 2=2)
//!   byte  5:    parity    (0=none, 1=odd, 2=even, 3=mark, 4=space)
//!   byte  6:    data bits (5, 6, 7, 8)
//! ```
//!
//! ## Baud-rate encoding
//!
//! Two strategies:
//!
//! **Direct** (`no_divisors` or supported standard rate): write the
//! baud rate as a 32-bit little-endian integer directly into bytes
//! 0–3 of the line-coding payload.
//!
//! **Divisor** (unsupported rate, legacy chips): encode via the
//! formula `baud = 12_000_000 * 32 / (mantissa * 4^exponent)`
//! where `mantissa ∈ [1,511]` and `exponent ∈ [0,7]`.  Bytes 0–3
//! are packed as:
//! ```text
//!   buf[3] = 0x80            (flag: divisor encoding)
//!   buf[2] = 0               (reserved)
//!   buf[1] = exponent<<1 | mantissa>>8
//!   buf[0] = mantissa & 0xFF
//! ```
//!
//! ## Vendor register access
//!
//! Vendor read/write control transfers allow the host to read or
//! write internal PL2303 registers:
//!
//! - Read:  `bmRequestType=0xC0, bRequest=0x01, wValue=reg_addr, wIndex=0`
//! - Write: `bmRequestType=0x40, bRequest=0x01, wValue=reg_addr, wIndex=value`
//!
//! Register 0x0404 is written during init (values 0 then 1) to
//! release the chip from its power-on-reset state.
//!
//! ## Linux references
//!
//! `drivers/usb/serial/pl2303.c` — GPL-2.0-or-later.
//!
//! Key symbols cited:
//! - `SET_LINE_REQUEST` / `GET_LINE_REQUEST` constants: pl2303.c l.128–142
//! - `VENDOR_WRITE_*` / `VENDOR_READ_*`: pl2303.c l.144–150
//! - `pl2303_encode_baud_rate_direct`: pl2303.c l.627
//! - `pl2303_encode_baud_rate_divisor`: pl2303.c l.635
//! - Init sequence: pl2303.c l.527–532 (`pl2303_startup`)
//! - `pl2303_set_line_request` / `pl2303_get_line_request`: pl2303.c l.532/752

use super::{DataBits, FlowControl, ModemStatus, Parity, StopBits, UsbSerial};

// ── Request codes ─────────────────────────────────────────────────

/// `bRequest` for SET_LINE_CODING (identical to CDC-ACM).
/// Linux: pl2303.c l.129 `SET_LINE_REQUEST`
pub const SET_LINE_REQUEST: u8 = 0x20;

/// `bmRequestType` for SET_LINE_CODING (host → device, class, iface).
/// Linux: pl2303.c l.128 `SET_LINE_REQUEST_TYPE`
pub const SET_LINE_REQUEST_TYPE: u8 = 0x21;

/// `bRequest` for GET_LINE_CODING.
/// Linux: pl2303.c l.142 `GET_LINE_REQUEST`
pub const GET_LINE_REQUEST: u8 = 0x21;

/// `bmRequestType` for GET_LINE_CODING (device → host, class, iface).
/// Linux: pl2303.c l.141 `GET_LINE_REQUEST_TYPE`
pub const GET_LINE_REQUEST_TYPE: u8 = 0xA1;

/// `bRequest` for vendor write to internal register.
/// Linux: pl2303.c l.145 `VENDOR_WRITE_REQUEST`
pub const VENDOR_WRITE_REQUEST: u8 = 0x01;

/// `bmRequestType` for vendor write (host → device, vendor, device).
/// Linux: pl2303.c l.144 `VENDOR_WRITE_REQUEST_TYPE`
pub const VENDOR_WRITE_REQUEST_TYPE: u8 = 0x40;

/// `bRequest` for vendor read from internal register.
/// Linux: pl2303.c l.149 `VENDOR_READ_REQUEST`
pub const VENDOR_READ_REQUEST: u8 = 0x01;

/// `bmRequestType` for vendor read (device → host, vendor, device).
/// Linux: pl2303.c l.148 `VENDOR_READ_REQUEST_TYPE`
pub const VENDOR_READ_REQUEST_TYPE: u8 = 0xC0;

// ── Init sequence register values ────────────────────────────────

/// Register address written twice during init.
/// Linux: pl2303.c l.527/531 `pl2303_startup` — `pl2303_vendor_write(serial, 0x0404, 0/1)`
pub const INIT_REG: u16 = 0x0404;

// ── Baud rate encoding ────────────────────────────────────────────

/// Encode baud rate using the direct method (raw 32-bit LE integer).
///
/// Used for standard supported rates and newer chip types that do
/// not support divisor encoding.
///
/// Linux: pl2303.c `pl2303_encode_baud_rate_direct` (l.627)
pub fn encode_baud_direct(baud: u32) -> [u8; 4] {
    baud.to_le_bytes()
}

/// Encode baud rate using the divisor method.
///
/// Formula: `baud = 12_000_000 * 32 / (mantissa * 4^exponent)`.
///
/// Returns the 4-byte encoding and the actual achieved baud rate.
///
/// Linux: pl2303.c `pl2303_encode_baud_rate_divisor` (l.635)
pub fn encode_baud_divisor(baud: u32) -> ([u8; 4], u32) {
    let baseline: u32 = 12_000_000 * 32;
    let mut mantissa = baseline / baud.max(1);
    if mantissa == 0 {
        mantissa = 1;
    }
    let mut exponent: u32 = 0;
    while mantissa >= 512 {
        if exponent < 7 {
            mantissa >>= 2; // divide by 4
            exponent += 1;
        } else {
            mantissa = 511;
            break;
        }
    }
    let mut buf = [0u8; 4];
    buf[3] = 0x80;
    buf[2] = 0;
    buf[1] = ((exponent << 1) | (mantissa >> 8)) as u8;
    buf[0] = (mantissa & 0xFF) as u8;

    let actual = baseline / (mantissa << (exponent * 2));
    (buf, actual)
}

// ── Line-coding payload builders ──────────────────────────────────

/// Build the 7-byte line-coding payload for SET_LINE_CODING.
///
/// The layout is identical to CDC-ACM (PSTN spec §6.3.10).
/// Baud bytes 0–3 use the direct encoding; callers can overwrite
/// bytes 0–3 with `encode_baud_divisor` output if needed.
///
/// Linux: pl2303.c `pl2303_set_termios` l.855–895
pub fn build_line_coding(baud: u32, data_bits: DataBits, parity: Parity, stop_bits: StopBits) -> [u8; 7] {
    let baud_bytes = encode_baud_direct(baud);
    let stop = match stop_bits {
        StopBits::One => 0u8,
        StopBits::OnePointFive => 1u8,
        StopBits::Two => 2u8,
    };
    let par = match parity {
        Parity::None => 0u8,
        Parity::Odd => 1u8,
        Parity::Even => 2u8,
        Parity::Mark => 3u8,
        Parity::Space => 4u8,
    };
    let db = match data_bits {
        DataBits::Five => 5u8,
        DataBits::Six => 6u8,
        DataBits::Seven => 7u8,
        DataBits::Eight => 8u8,
    };
    [baud_bytes[0], baud_bytes[1], baud_bytes[2], baud_bytes[3], stop, par, db]
}

/// Build the SETUP packet fields for SET_LINE_CODING.
///
/// Returns `(bmRequestType, bRequest, wValue, wIndex, wLength)`.
/// The 7-byte payload must be sent in the data stage.
pub fn setup_set_line_coding() -> (u8, u8, u16, u16, u16) {
    (SET_LINE_REQUEST_TYPE, SET_LINE_REQUEST, 0, 0, 7)
}

/// Build the SETUP packet fields for GET_LINE_CODING.
///
/// Returns `(bmRequestType, bRequest, wValue, wIndex, wLength)`.
pub fn setup_get_line_coding() -> (u8, u8, u16, u16, u16) {
    (GET_LINE_REQUEST_TYPE, GET_LINE_REQUEST, 0, 0, 7)
}

/// Build the SETUP packet fields for a vendor register write.
///
/// `reg` is written to `wValue`; `val` is written to `wIndex`.
///
/// Linux: pl2303.c `pl2303_vendor_write` (l.274), which calls
/// `usb_control_msg(..., VENDOR_WRITE_REQUEST, VENDOR_WRITE_REQUEST_TYPE,
///   value, index, NULL, 0, 100)`.
pub fn setup_vendor_write(reg: u16, val: u16) -> (u8, u8, u16, u16, u16) {
    (VENDOR_WRITE_REQUEST_TYPE, VENDOR_WRITE_REQUEST, reg, val, 0)
}

/// Build the SETUP packet fields for a vendor register read.
///
/// Linux: pl2303.c `pl2303_vendor_read` (l.244)
pub fn setup_vendor_read(reg: u16) -> (u8, u8, u16, u16, u16) {
    (VENDOR_READ_REQUEST_TYPE, VENDOR_READ_REQUEST, reg, 0, 1)
}

// ── Modem status decode ───────────────────────────────────────────

/// Decode the modem status byte from a PL2303 interrupt-IN report.
///
/// The PL2303 delivers an 8-byte status packet on the interrupt-IN
/// endpoint.  Byte 0 (or byte 8 for older quirks — not handled here)
/// encodes modem status:
/// - bit 4: CTS
/// - bit 5: DSR
/// - bit 6: RI
/// - bit 7: DCD
///
/// This matches the standard UART status register layout, which
/// pl2303.c re-uses in its `uart_state` field.
pub fn decode_modem_status(byte: u8) -> ModemStatus {
    ModemStatus {
        cts: byte & 0x10 != 0,
        dsr: byte & 0x20 != 0,
        ri: byte & 0x40 != 0,
        dcd: byte & 0x80 != 0,
    }
}

// ── Concrete driver state ─────────────────────────────────────────

/// Error type for PL2303 operations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Pl2303Error {
    /// A control transfer failed.
    ControlTransferFailed,
}

/// Per-port state for a bound PL2303 device.
#[derive(Debug)]
pub struct Pl2303State {
    /// USB slot ID.
    pub slot_id: u8,
    /// Current line-coding payload (7 bytes, CDC-ACM format).
    pub line_coding: [u8; 7],
    /// Last modem status snapshot.
    pub modem: ModemStatus,
    /// DTR state.
    pub dtr: bool,
    /// RTS state.
    pub rts: bool,
}

impl Pl2303State {
    /// Create a new state block defaulting to 9600 8N1.
    pub fn new(slot_id: u8) -> Self {
        Self {
            slot_id,
            line_coding: build_line_coding(
                9600,
                DataBits::Eight,
                Parity::None,
                StopBits::One,
            ),
            modem: ModemStatus::default(),
            dtr: false,
            rts: false,
        }
    }
}

impl UsbSerial for Pl2303State {
    type Error = Pl2303Error;

    fn set_baud(&mut self, rate: u32) -> Result<(), Pl2303Error> {
        let baud_bytes = encode_baud_direct(rate);
        self.line_coding[0..4].copy_from_slice(&baud_bytes);
        Ok(())
    }

    fn set_line(
        &mut self,
        data_bits: DataBits,
        parity: Parity,
        stop_bits: StopBits,
    ) -> Result<(), Pl2303Error> {
        // Rebuild keeping the current baud bytes (bytes 0–3).
        let new_lc = build_line_coding(
            u32::from_le_bytes([
                self.line_coding[0],
                self.line_coding[1],
                self.line_coding[2],
                self.line_coding[3],
            ]),
            data_bits,
            parity,
            stop_bits,
        );
        self.line_coding = new_lc;
        Ok(())
    }

    fn set_flow(&mut self, _flow: FlowControl) -> Result<(), Pl2303Error> {
        // PL2303 flow control is managed via internal register writes
        // (reg 0x0a for HXN, or via SET_CONTROL_LINE_STATE for older
        // models).  Codec deferred; physical transfer layer handles it.
        Ok(())
    }

    fn set_modem(&mut self, dtr: bool, rts: bool) -> Result<(), Pl2303Error> {
        self.dtr = dtr;
        self.rts = rts;
        Ok(())
    }

    fn get_modem(&self) -> Result<ModemStatus, Pl2303Error> {
        Ok(self.modem)
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_pl2303_vendor_read_encode() -> TestResult {
        let (bm_rt, b_req, w_val, w_idx, w_len) = setup_vendor_read(0x8484);
        if bm_rt != VENDOR_READ_REQUEST_TYPE {
            return TestResult::Fail("vendor read bmRequestType wrong");
        }
        if b_req != VENDOR_READ_REQUEST {
            return TestResult::Fail("vendor read bRequest wrong");
        }
        if w_val != 0x8484 {
            return TestResult::Fail("vendor read wValue (register) wrong");
        }
        if w_idx != 0 {
            return TestResult::Fail("vendor read wIndex should be 0");
        }
        if w_len != 1 {
            return TestResult::Fail("vendor read wLength should be 1");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/serial/pl2303", smoke_pl2303_vendor_read_encode);

    fn smoke_pl2303_vendor_write_encode() -> TestResult {
        // Init sequence: write 0 to register 0x0404
        let (bm_rt, b_req, w_val, w_idx, w_len) = setup_vendor_write(INIT_REG, 0);
        if bm_rt != VENDOR_WRITE_REQUEST_TYPE {
            return TestResult::Fail("vendor write bmRequestType wrong");
        }
        if b_req != VENDOR_WRITE_REQUEST {
            return TestResult::Fail("vendor write bRequest wrong");
        }
        if w_val != INIT_REG {
            return TestResult::Fail("vendor write wValue (register) wrong");
        }
        if w_idx != 0 {
            return TestResult::Fail("vendor write wIndex (value) wrong");
        }
        if w_len != 0 {
            return TestResult::Fail("vendor write wLength must be 0 (no data stage)");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/serial/pl2303", smoke_pl2303_vendor_write_encode);

    fn smoke_pl2303_set_baud_9600_direct() -> TestResult {
        let buf = encode_baud_direct(9600);
        let back = u32::from_le_bytes(buf);
        if back != 9600 {
            return TestResult::Fail("direct baud encode/decode round-trip failed");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/serial/pl2303", smoke_pl2303_set_baud_9600_direct);

    fn smoke_pl2303_baud_divisor_flag() -> TestResult {
        // Divisor encoding must have buf[3] = 0x80 as the flag byte.
        let (buf, _actual) = encode_baud_divisor(9600);
        if buf[3] != 0x80 {
            return TestResult::Fail("divisor encoding flag byte (buf[3]) must be 0x80");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/serial/pl2303", smoke_pl2303_baud_divisor_flag);

    fn smoke_pl2303_set_line_coding_setup() -> TestResult {
        let (bm_rt, b_req, w_val, w_idx, w_len) = setup_set_line_coding();
        if bm_rt != SET_LINE_REQUEST_TYPE {
            return TestResult::Fail("SET_LINE_CODING bmRequestType wrong");
        }
        if b_req != SET_LINE_REQUEST {
            return TestResult::Fail("SET_LINE_CODING bRequest wrong");
        }
        if w_val != 0 || w_idx != 0 {
            return TestResult::Fail("wValue/wIndex must be 0 for SET_LINE_CODING");
        }
        if w_len != 7 {
            return TestResult::Fail("SET_LINE_CODING wLength must be 7");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/serial/pl2303", smoke_pl2303_set_line_coding_setup);

    fn smoke_pl2303_line_coding_8n1() -> TestResult {
        let lc = build_line_coding(9600, DataBits::Eight, Parity::None, StopBits::One);
        let baud_back = u32::from_le_bytes([lc[0], lc[1], lc[2], lc[3]]);
        if baud_back != 9600 {
            return TestResult::Fail("baud round-trip failed in line coding");
        }
        if lc[4] != 0 {
            return TestResult::Fail("stop bits byte must be 0 for 1 stop bit");
        }
        if lc[5] != 0 {
            return TestResult::Fail("parity byte must be 0 for None parity");
        }
        if lc[6] != 8 {
            return TestResult::Fail("data bits byte must be 8");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/serial/pl2303", smoke_pl2303_line_coding_8n1);

    fn smoke_pl2303_modem_status_decode() -> TestResult {
        // CTS=bit4 + DCD=bit7 → 0x90
        let ms = decode_modem_status(0x90);
        if !ms.cts {
            return TestResult::Fail("CTS should be set for byte=0x90");
        }
        if !ms.dcd {
            return TestResult::Fail("DCD should be set for byte=0x90");
        }
        if ms.dsr || ms.ri {
            return TestResult::Fail("DSR/RI should not be set for byte=0x90");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/serial/pl2303", smoke_pl2303_modem_status_decode);
}
