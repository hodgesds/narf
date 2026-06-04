//! Silicon Labs CP210x USB-to-serial adapter driver — clean-room.
//!
//! ## Hardware overview
//!
//! The CP210x family (CP2101 / CP2102 / CP2103 / CP2104 / CP2105)
//! from Silicon Labs is a low-cost USB-to-serial bridge found in
//! many embedded development boards.  The USB interface presents
//! bulk-OUT (TX) and bulk-IN (RX) endpoints for data, and an
//! interrupt-IN endpoint for modem status notifications.
//!
//! Configuration is via vendor-specific control transfers using
//! `bmRequestType = 0x41` (host-to-interface, vendor class).
//!
//! ## Control interface
//!
//! All configuration requests use `wIndex` = interface number.
//! Notable requests:
//!
//! - `IFC_ENABLE` (0x00):  enable/disable the UART interface
//! - `SET_BAUDDIV` (0x01): set baud clock divisor (legacy)
//! - `SET_LINE_CTL` (0x03): data bits / parity / stop bits
//! - `SET_MHS` (0x07): modem control (DTR / RTS)
//! - `GET_MDMSTS` (0x08): read modem status byte
//! - `SET_BAUDRATE` (0x1E): set baud rate directly (in Hz)
//!
//! ## Line control encoding
//!
//! `SET_LINE_CTL` takes a 16-bit word packed as:
//! ```text
//! bits 11:8   = data bits (5 → 0x500, 6 → 0x600, 7 → 0x700, 8 → 0x800)
//! bits  7:4   = parity (0=none, 1=odd, 2=even, 3=mark, 4=space)
//! bits  3:0   = stop bits (0=1, 1=1.5, 2=2)
//! ```
//!
//! ## Modem control encoding
//!
//! `SET_MHS` uses a mask-plus-value 16-bit word:
//! ```text
//! bit 0: DTR value     bit 8: write DTR (must be 1 to update DTR)
//! bit 1: RTS value     bit 9: write RTS (must be 1 to update RTS)
//! ```
//!
//! ## Linux references
//!
//! `drivers/usb/serial/cp210x.c` — GPL-2.0-or-later.
//!
//! Key symbols cited:
//! - `REQTYPE_*`: cp210x.c l.333–336
//! - `CP210X_IFC_ENABLE`, `CP210X_SET_BAUDDIV`, `CP210X_SET_LINE_CTL`,
//!   `CP210X_SET_MHS`, `CP210X_GET_MDMSTS`, `CP210X_SET_BAUDRATE`:
//!   cp210x.c l.339–364
//! - `UART_ENABLE` / `UART_DISABLE`: cp210x.c l.368–369
//! - `BITS_DATA_*`, `BITS_PARITY_*`, `BITS_STOP_*`: cp210x.c l.375–392
//! - `CONTROL_DTR`, `CONTROL_RTS`, `CONTROL_CTS`, `CONTROL_DSR`,
//!   `CONTROL_RING`, `CONTROL_DCD`, `CONTROL_WRITE_DTR`,
//!   `CONTROL_WRITE_RTS`: cp210x.c l.399–406
//! - `cp210x_tiocmset_port` SET_MHS encoding: cp210x.c l.1336–1403
//! - `cp210x_tiocmget` modem status decode: cp210x.c l.1421–1436
//! - `cp210x_change_speed` SET_BAUDRATE direct: cp210x.c l.1074

use super::{DataBits, FlowControl, ModemStatus, Parity, StopBits, UsbSerial};

// ── bmRequestType values ──────────────────────────────────────────

/// Host-to-device, vendor class, interface recipient.
/// Linux: cp210x.c l.333 `REQTYPE_HOST_TO_INTERFACE`
pub const REQTYPE_HOST_TO_INTERFACE: u8 = 0x41;

/// Device-to-host, vendor class, interface recipient.
/// Linux: cp210x.c l.334 `REQTYPE_INTERFACE_TO_HOST`
pub const REQTYPE_INTERFACE_TO_HOST: u8 = 0xC1;

// ── bRequest values ───────────────────────────────────────────────

/// Enable / disable the UART.  wValue = UART_ENABLE / UART_DISABLE.
/// Linux: cp210x.c l.339 `CP210X_IFC_ENABLE`
pub const IFC_ENABLE: u8 = 0x00;

/// Set baud-rate divisor (legacy path, pre-CP2102).
/// Linux: cp210x.c l.340 `CP210X_SET_BAUDDIV`
pub const SET_BAUDDIV: u8 = 0x01;

/// Set line characteristics (data bits / parity / stop bits).
/// Linux: cp210x.c l.342 `CP210X_SET_LINE_CTL`
pub const SET_LINE_CTL: u8 = 0x03;

/// Set modem handshake lines (DTR / RTS, with write-enable masks).
/// Linux: cp210x.c l.346 `CP210X_SET_MHS`
pub const SET_MHS: u8 = 0x07;

/// Get modem status byte (CTS / DSR / RI / DCD).
/// Linux: cp210x.c l.347 `CP210X_GET_MDMSTS`
pub const GET_MDMSTS: u8 = 0x08;

/// Set baud rate directly (full 32-bit Hz value).
/// Linux: cp210x.c l.364 `CP210X_SET_BAUDRATE`
pub const SET_BAUDRATE: u8 = 0x1E;

// ── IFC_ENABLE wValue constants ───────────────────────────────────

/// Enable the UART (`wValue` for `IFC_ENABLE`).
/// Linux: cp210x.c l.368 `UART_ENABLE`
pub const UART_ENABLE: u16 = 0x0001;

/// Disable the UART.
/// Linux: cp210x.c l.369 `UART_DISABLE`
pub const UART_DISABLE: u16 = 0x0000;

// ── SET_LINE_CTL bit fields ───────────────────────────────────────

// Data bits — bits 11:8
// Linux: cp210x.c l.375–380
pub const BITS_DATA_MASK: u16 = 0x0F00;
pub const BITS_DATA_5: u16 = 0x0500;
pub const BITS_DATA_6: u16 = 0x0600;
pub const BITS_DATA_7: u16 = 0x0700;
pub const BITS_DATA_8: u16 = 0x0800;

// Parity — bits 7:4
// Linux: cp210x.c l.382–387
pub const BITS_PARITY_NONE: u16 = 0x0000;
pub const BITS_PARITY_ODD: u16 = 0x0010;
pub const BITS_PARITY_EVEN: u16 = 0x0020;
pub const BITS_PARITY_MARK: u16 = 0x0030;
pub const BITS_PARITY_SPACE: u16 = 0x0040;

// Stop bits — bits 3:0
// Linux: cp210x.c l.389–392
pub const BITS_STOP_1: u16 = 0x0000;
pub const BITS_STOP_1_5: u16 = 0x0001;
pub const BITS_STOP_2: u16 = 0x0002;

// ── SET_MHS and GET_MDMSTS bit fields ─────────────────────────────

// SET_MHS wValue bits — Linux: cp210x.c l.399–406
pub const CONTROL_DTR: u16 = 0x0001;
pub const CONTROL_RTS: u16 = 0x0002;
pub const CONTROL_CTS: u16 = 0x0010;
pub const CONTROL_DSR: u16 = 0x0020;
pub const CONTROL_RING: u16 = 0x0040;
pub const CONTROL_DCD: u16 = 0x0080;
/// Write-enable bit for DTR: must be set to actually change DTR.
pub const CONTROL_WRITE_DTR: u16 = 0x0100;
/// Write-enable bit for RTS: must be set to actually change RTS.
pub const CONTROL_WRITE_RTS: u16 = 0x0200;

// ── Line-control encoding ─────────────────────────────────────────

/// Encode data bits / parity / stop bits into the `wValue` word
/// for `SET_LINE_CTL`.
///
/// Linux: cp210x.c `cp210x_set_termios` l.1272–1313.
pub fn encode_line_ctl(data_bits: DataBits, parity: Parity, stop_bits: StopBits) -> u16 {
    let db = match data_bits {
        DataBits::Five => BITS_DATA_5,
        DataBits::Six => BITS_DATA_6,
        DataBits::Seven => BITS_DATA_7,
        DataBits::Eight => BITS_DATA_8,
    };
    let par = match parity {
        Parity::None => BITS_PARITY_NONE,
        Parity::Odd => BITS_PARITY_ODD,
        Parity::Even => BITS_PARITY_EVEN,
        Parity::Mark => BITS_PARITY_MARK,
        Parity::Space => BITS_PARITY_SPACE,
    };
    let stop = match stop_bits {
        StopBits::One => BITS_STOP_1,
        StopBits::OnePointFive => BITS_STOP_1_5,
        StopBits::Two => BITS_STOP_2,
    };
    db | par | stop
}

// ── Baud rate control transfer builder ───────────────────────────

/// Build the control transfer parameters for `SET_BAUDRATE`.
///
/// `SET_BAUDRATE` takes the baud rate directly as a 32-bit
/// little-endian value in the data stage.
///
/// Returns `(bmRequestType, bRequest, wValue, wIndex, data[4])` for
/// a control-out transfer.  `iface` is the USB interface number.
///
/// Linux: cp210x.c `cp210x_change_speed` l.1074
/// `cp210x_write_u32_reg(port, CP210X_SET_BAUDRATE, baud)`
pub fn build_set_baudrate(baud: u32, iface: u8) -> (u8, u8, u16, u16, [u8; 4]) {
    (
        REQTYPE_HOST_TO_INTERFACE,
        SET_BAUDRATE,
        0,
        iface as u16,
        baud.to_le_bytes(),
    )
}

/// Build the control transfer parameters for `SET_LINE_CTL`.
///
/// Returns `(bmRequestType, bRequest, wValue, wIndex, wLength)`.
/// `wValue` encodes the line format; wIndex = interface number.
///
/// Linux: cp210x.c l.1313
/// `cp210x_write_u16_reg(port, CP210X_SET_LINE_CTL, bits)`
pub fn build_set_line_ctl(
    data_bits: DataBits,
    parity: Parity,
    stop_bits: StopBits,
    iface: u8,
) -> (u8, u8, u16, u16, u16) {
    let bits = encode_line_ctl(data_bits, parity, stop_bits);
    (
        REQTYPE_HOST_TO_INTERFACE,
        SET_LINE_CTL,
        bits,
        iface as u16,
        0,
    )
}

/// Build the control transfer parameters for `IFC_ENABLE`.
///
/// Pass `UART_ENABLE` to enable or `UART_DISABLE` to disable.
///
/// Linux: cp210x.c `cp210x_open` l.781 /
/// `cp210x_close` l.797
pub fn build_ifc_enable(enable: bool, iface: u8) -> (u8, u8, u16, u16, u16) {
    let v = if enable { UART_ENABLE } else { UART_DISABLE };
    (REQTYPE_HOST_TO_INTERFACE, IFC_ENABLE, v, iface as u16, 0)
}

// ── Modem control encoding ────────────────────────────────────────

/// Encode DTR / RTS state into the `wValue` for `SET_MHS`.
///
/// CONTROL_WRITE_DTR and CONTROL_WRITE_RTS must be set alongside the
/// value bits so the chip actually updates the corresponding signal.
///
/// Linux: cp210x.c `cp210x_tiocmset_port` l.1336–1403.
pub fn encode_modem_ctrl(dtr: bool, rts: bool) -> u16 {
    let mut v: u16 = 0;
    v |= CONTROL_WRITE_DTR | CONTROL_WRITE_RTS;
    if dtr {
        v |= CONTROL_DTR;
    }
    if rts {
        v |= CONTROL_RTS;
    }
    v
}

// ── Modem status decode ───────────────────────────────────────────

/// Decode the modem status byte returned by `GET_MDMSTS`.
///
/// Linux: cp210x.c `cp210x_tiocmget` l.1421–1436.
pub fn decode_modem_status(byte: u8) -> ModemStatus {
    let w = byte as u16;
    ModemStatus {
        cts: w & CONTROL_CTS != 0,
        dsr: w & CONTROL_DSR != 0,
        ri: w & CONTROL_RING != 0,
        dcd: w & CONTROL_DCD != 0,
    }
}

// ── Concrete driver state ─────────────────────────────────────────

/// Error type for CP210x operations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Cp210xError {
    /// A control transfer failed.
    ControlTransferFailed,
}

/// Per-port state for a bound CP210x device.
#[derive(Debug)]
pub struct Cp210xState {
    /// USB slot ID.
    pub slot_id: u8,
    /// USB interface number.
    pub iface: u8,
    /// Current baud rate (Hz).
    pub baud: u32,
    /// Current line control word.
    pub line_ctl: u16,
    /// Last modem status snapshot.
    pub modem: ModemStatus,
    /// DTR state.
    pub dtr: bool,
    /// RTS state.
    pub rts: bool,
}

impl Cp210xState {
    /// Create a new state block defaulting to 9600 8N1.
    pub fn new(slot_id: u8, iface: u8) -> Self {
        Self {
            slot_id,
            iface,
            baud: 9600,
            line_ctl: encode_line_ctl(DataBits::Eight, Parity::None, StopBits::One),
            modem: ModemStatus::default(),
            dtr: false,
            rts: false,
        }
    }
}

impl UsbSerial for Cp210xState {
    type Error = Cp210xError;

    fn set_baud(&mut self, rate: u32) -> Result<(), Cp210xError> {
        self.baud = rate;
        Ok(())
    }

    fn set_line(
        &mut self,
        data_bits: DataBits,
        parity: Parity,
        stop_bits: StopBits,
    ) -> Result<(), Cp210xError> {
        self.line_ctl = encode_line_ctl(data_bits, parity, stop_bits);
        Ok(())
    }

    fn set_flow(&mut self, _flow: FlowControl) -> Result<(), Cp210xError> {
        // CP210x flow control is configured via the SET_FLOW request
        // (0x13) which writes a 16-byte `cp210x_flow_ctl` structure.
        // Deferred to the physical transfer layer.
        Ok(())
    }

    fn set_modem(&mut self, dtr: bool, rts: bool) -> Result<(), Cp210xError> {
        self.dtr = dtr;
        self.rts = rts;
        Ok(())
    }

    fn get_modem(&self) -> Result<ModemStatus, Cp210xError> {
        Ok(self.modem)
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_cp210x_set_baudrate_control_transfer() -> TestResult {
        // SET_BAUDRATE for 115200 on interface 0.
        let (bm_rt, b_req, w_val, w_idx, data) = build_set_baudrate(115200, 0);
        if bm_rt != REQTYPE_HOST_TO_INTERFACE {
            return TestResult::Fail("SET_BAUDRATE bmRequestType wrong");
        }
        if b_req != SET_BAUDRATE {
            return TestResult::Fail("SET_BAUDRATE bRequest wrong");
        }
        if w_val != 0 {
            return TestResult::Fail("SET_BAUDRATE wValue must be 0");
        }
        if w_idx != 0 {
            return TestResult::Fail("SET_BAUDRATE wIndex (iface) wrong");
        }
        let baud_back = u32::from_le_bytes(data);
        if baud_back != 115200 {
            return TestResult::Fail("SET_BAUDRATE data payload wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/serial/cp210x",
        smoke_cp210x_set_baudrate_control_transfer
    );

    fn smoke_cp210x_set_line_ctl_8n1() -> TestResult {
        let word = encode_line_ctl(DataBits::Eight, Parity::None, StopBits::One);
        // Data bits 8 → 0x0800
        if word & BITS_DATA_MASK != BITS_DATA_8 {
            return TestResult::Fail("data-bits field not 0x0800 for 8 bits");
        }
        // No parity → 0x0000
        if word & 0x00F0 != BITS_PARITY_NONE {
            return TestResult::Fail("parity field not 0 for None");
        }
        // 1 stop bit → 0x0000
        if word & 0x000F != BITS_STOP_1 {
            return TestResult::Fail("stop-bits field not 0 for 1 stop bit");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/serial/cp210x", smoke_cp210x_set_line_ctl_8n1);

    fn smoke_cp210x_set_line_ctl_7e15() -> TestResult {
        // 7 data bits, even parity, 1.5 stop bits
        let word = encode_line_ctl(DataBits::Seven, Parity::Even, StopBits::OnePointFive);
        if word & BITS_DATA_MASK != BITS_DATA_7 {
            return TestResult::Fail("data-bits field not 0x0700");
        }
        if word & 0x00F0 != BITS_PARITY_EVEN {
            return TestResult::Fail("parity field not even");
        }
        if word & 0x000F != BITS_STOP_1_5 {
            return TestResult::Fail("stop-bits field not 1.5");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/serial/cp210x", smoke_cp210x_set_line_ctl_7e15);

    fn smoke_cp210x_modem_ctrl_both_set() -> TestResult {
        let v = encode_modem_ctrl(true, true);
        // Both WRITE bits must be present.
        if v & CONTROL_WRITE_DTR == 0 {
            return TestResult::Fail("CONTROL_WRITE_DTR missing");
        }
        if v & CONTROL_WRITE_RTS == 0 {
            return TestResult::Fail("CONTROL_WRITE_RTS missing");
        }
        // Both value bits asserted.
        if v & CONTROL_DTR == 0 {
            return TestResult::Fail("CONTROL_DTR missing");
        }
        if v & CONTROL_RTS == 0 {
            return TestResult::Fail("CONTROL_RTS missing");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/serial/cp210x",
        smoke_cp210x_modem_ctrl_both_set
    );

    fn smoke_cp210x_modem_ctrl_dtr_only() -> TestResult {
        let v = encode_modem_ctrl(true, false);
        // WRITE_RTS must still be set (to tell chip to update RTS).
        if v & CONTROL_WRITE_RTS == 0 {
            return TestResult::Fail("CONTROL_WRITE_RTS missing even when RTS=false");
        }
        // RTS value bit must be clear.
        if v & CONTROL_RTS != 0 {
            return TestResult::Fail("CONTROL_RTS should be clear");
        }
        // DTR bits must be set.
        if v & (CONTROL_WRITE_DTR | CONTROL_DTR) != (CONTROL_WRITE_DTR | CONTROL_DTR) {
            return TestResult::Fail("DTR write+value bits missing");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/serial/cp210x",
        smoke_cp210x_modem_ctrl_dtr_only
    );

    fn smoke_cp210x_modem_status_decode() -> TestResult {
        // CTS=0x10, DSR=0x20, RI=0x40, DCD=0x80
        let ms = decode_modem_status(0xF0);
        if !ms.cts || !ms.dsr || !ms.ri || !ms.dcd {
            return TestResult::Fail("0xF0 should assert all modem signals");
        }
        let ms2 = decode_modem_status(0x10);
        if !ms2.cts || ms2.dsr || ms2.ri || ms2.dcd {
            return TestResult::Fail("0x10 should assert only CTS");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/serial/cp210x",
        smoke_cp210x_modem_status_decode
    );

    fn smoke_cp210x_ifc_enable_setup() -> TestResult {
        let (bm_rt, b_req, w_val, _w_idx, _w_len) = build_ifc_enable(true, 0);
        if bm_rt != REQTYPE_HOST_TO_INTERFACE {
            return TestResult::Fail("IFC_ENABLE bmRequestType wrong");
        }
        if b_req != IFC_ENABLE {
            return TestResult::Fail("IFC_ENABLE bRequest wrong");
        }
        if w_val != UART_ENABLE {
            return TestResult::Fail("IFC_ENABLE wValue should be UART_ENABLE");
        }
        let (_, _, w_val2, _, _) = build_ifc_enable(false, 0);
        if w_val2 != UART_DISABLE {
            return TestResult::Fail("IFC_ENABLE false should give UART_DISABLE");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/serial/cp210x", smoke_cp210x_ifc_enable_setup);
}
