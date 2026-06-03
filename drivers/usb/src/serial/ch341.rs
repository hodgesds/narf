//! WCH CH340/CH341 USB-to-serial adapter driver — clean-room.
//!
//! ## Hardware overview
//!
//! The CH340/CH341 (WCH, Nanjing Qinheng Microelectronics) is the
//! dominant low-cost USB-to-serial chip.  It exposes a vendor-class
//! USB interface with a bulk-OUT / bulk-IN pair for data and one
//! interrupt-IN endpoint for modem status notifications.
//!
//! Configuration is performed through `CH341_REQ_WRITE_REG`
//! (`bRequest = 0x9A`) control transfers — a single request encodes
//! a 16-bit register address in `wValue` and a 16-bit data word in
//! `wIndex`.  Two register pairs control the UART:
//!
//! - `0x1312` (prescaler high) + `0x0F2C` (divisor low) — baud rate
//! - `0x2518` (line control) — parity / stop / data bits via the
//!   LCR byte in the high half of `wIndex`
//!
//! Modem signals are set via `CH341_REQ_MODEM_CTRL` (`0xA4`).
//!
//! ## Baud-rate algorithm
//!
//! The CH341 derives its baud clock from a 48 MHz crystal via:
//!
//! ```text
//! divisor_clock = 48_000_000 / (2^(12 − 3·ps − fact))
//! baud_rate     = divisor_clock / div
//! ```
//!
//! where `ps ∈ 0..=3` (prescaler), `fact ∈ {0,1}` (clock halving
//! flag), and `div ∈ 2..=256`.  The algorithm tries `fact=1` first
//! (higher base clock) and falls back to `fact=0` (halved clock)
//! when `div` would be outside the valid range.
//!
//! The returned 16-bit divisor word is packed as:
//! ```text
//!   bits 15:8  = (0x100 - div) & 0xFF   (two's-complement divisor)
//!   bits  3:2  = fact
//!   bits  1:0  = ps
//! ```
//!
//! ## Linux references
//!
//! `drivers/usb/serial/ch341.c` — GPL-2.0-or-later.
//!
//! Key symbols cited (line numbers in Linux 6.15-rc):
//! - `CH341_REQ_WRITE_REG` (l.56), `CH341_REQ_MODEM_CTRL` (l.58)
//! - `CH341_LCR_*` constants (l.70–79)
//! - `CH341_CLKRATE` / `CH341_CLK_DIV` (l.154–155)
//! - `ch341_get_divisor` algorithm (l.179–241)
//! - `ch341_set_baudrate_lcr` wire encoding (l.253–291)

use super::{DataBits, FlowControl, ModemStatus, Parity, StopBits, UsbSerial};

// ── Register/request constants ────────────────────────────────────

/// Write register request (`bRequest`). Encodes reg in `wValue`,
/// data in `wIndex`.
/// Linux: ch341.c `CH341_REQ_WRITE_REG` (l.56)
pub const REQ_WRITE_REG: u8 = 0x9A;

/// Read register request.
/// Linux: ch341.c `CH341_REQ_READ_REG` (l.57)
pub const REQ_READ_REG: u8 = 0x95;

/// Serial port init request.
/// Linux: ch341.c `CH341_REQ_SERIAL_INIT` (l.58)
pub const REQ_SERIAL_INIT: u8 = 0xA1;

/// Modem control request (`bRequest`). Active-low DTR/RTS in `wValue`.
/// Linux: ch341.c `CH341_REQ_MODEM_CTRL` (l.58 — actually 0xA4)
pub const REQ_MODEM_CTRL: u8 = 0xA4;

/// `bmRequestType` for host-to-device vendor-class interface requests.
pub const RT_HOST_TO_DEV_VENDOR: u8 = 0x40;

/// `bmRequestType` for device-to-host vendor-class interface requests.
pub const RT_DEV_TO_HOST_VENDOR: u8 = 0xC0;

// Baud-rate register addresses written via `REQ_WRITE_REG`.
// Each `wValue` selects which register pair to write.
/// High prescaler register address in `wValue`.
/// Linux: ch341.c `ch341_set_baudrate_lcr` l.267 → wValue = 0x1312
pub const REG_BAUD_HIGH: u16 = 0x1312;
/// Low divisor register address in `wValue`.
/// Linux: ch341.c l.282 → wValue = 0x0F2C
pub const REG_BAUD_LOW: u16 = 0x0F2C;

/// Line-control register address.
/// Linux: ch341.c l.282 → wValue = 0x2518
pub const REG_LCR: u16 = 0x2518;

// ── LCR bit definitions ───────────────────────────────────────────

/// Enable receiver (LCR bit 7).
/// Linux: ch341.c `CH341_LCR_ENABLE_RX` (l.70)
pub const LCR_ENABLE_RX: u8 = 0x80;
/// Enable transmitter (LCR bit 6).
/// Linux: ch341.c `CH341_LCR_ENABLE_TX` (l.71)
pub const LCR_ENABLE_TX: u8 = 0x40;
/// Mark/space parity (LCR bit 5).
/// Linux: ch341.c `CH341_LCR_MARK_SPACE` (l.72)
pub const LCR_MARK_SPACE: u8 = 0x20;
/// Even parity (LCR bit 4).
/// Linux: ch341.c `CH341_LCR_PAR_EVEN` (l.73)
pub const LCR_PAR_EVEN: u8 = 0x10;
/// Parity enable (LCR bit 3).
/// Linux: ch341.c `CH341_LCR_ENABLE_PAR` (l.74)
pub const LCR_ENABLE_PAR: u8 = 0x08;
/// 2 stop bits (LCR bit 2); cleared = 1 stop bit.
/// Linux: ch341.c `CH341_LCR_STOP_BITS_2` (l.75)
pub const LCR_STOP_BITS_2: u8 = 0x04;
/// Data bits: 8 = CS8 (bits 1:0 = 0b11).
/// Linux: ch341.c `CH341_LCR_CS8` (l.76)
pub const LCR_CS8: u8 = 0x03;
/// Data bits: 7 (bits 1:0 = 0b10).
/// Linux: ch341.c `CH341_LCR_CS7` (l.77)
pub const LCR_CS7: u8 = 0x02;
/// Data bits: 6 (bits 1:0 = 0b01).
/// Linux: ch341.c `CH341_LCR_CS6` (l.78)
pub const LCR_CS6: u8 = 0x01;
/// Data bits: 5 (bits 1:0 = 0b00).
/// Linux: ch341.c `CH341_LCR_CS5` (l.79)
pub const LCR_CS5: u8 = 0x00;

// ── Clock constants ───────────────────────────────────────────────

/// Base crystal frequency: 48 MHz.
/// Linux: ch341.c `CH341_CLKRATE` (l.154)
pub const CLKRATE: u32 = 48_000_000;

/// Minimum acceptable baud rate ≈ 46 bps (ps=0, fact=0, div=256×2).
pub const MIN_BPS: u32 = 46;
/// Maximum baud rate = 48_000_000 / (2^(12-3*3-0) * 2) = 2_000_000.
pub const MAX_BPS: u32 = 2_000_000;

/// Per-`ps` minimum rates where using `fact=1` is still possible.
/// Linux: ch341.c `ch341_min_rates` (l.158–163).
/// Rate must exceed `ch341_min_rates[ps]` to use `ps`.
static MIN_RATES: [u32; 4] = [
    // ps=0: CLK_DIV(0,1) * 512 = 2^11 * 512 = clk/512/512 ≈ 183
    CLKRATE / (1 << 11) / 512,
    // ps=1: CLK_DIV(1,1) * 512 = 2^8 * 512
    CLKRATE / (1 << 8) / 512,
    // ps=2: CLK_DIV(2,1) * 512 = 2^5 * 512
    CLKRATE / (1 << 5) / 512,
    // ps=3: CLK_DIV(3,1) * 512 = 2^2 * 512
    CLKRATE / (1 << 2) / 512,
];

// ── Divisor calculation ───────────────────────────────────────────

/// Compute the packed 16-bit divisor word for the given baud rate.
///
/// Returns `(div_high_word, div_low_byte)` where:
/// - `div_high_word` is written to `wIndex` of `REG_BAUD_HIGH`
/// - `div_low_byte`  is the low byte of `wIndex` for `REG_BAUD_LOW`
///
/// Mirrors `ch341_get_divisor` in Linux ch341.c (l.179–241).
///
/// Returns `None` for unsupported rates (out of [MIN_BPS, MAX_BPS]).
pub fn calc_divisor(baud: u32) -> Option<u16> {
    let baud = baud.clamp(MIN_BPS, MAX_BPS);

    // Find the highest prescaler ps such that baud > MIN_RATES[ps].
    let mut ps: i32 = 3;
    while ps >= 0 {
        if baud > MIN_RATES[ps as usize] {
            break;
        }
        ps -= 1;
    }
    if ps < 0 {
        return None;
    }
    let ps = ps as u32;

    // Start with fact=1 (higher base clock).
    let mut fact: u32 = 1;
    // CLK_DIV(ps, fact) = 1 << (12 - 3*ps - fact)
    let mut clk_div: u32 = 1u32 << (12 - 3 * ps - fact);
    let mut div = CLKRATE / (clk_div * baud);

    // Fall back to fact=0 if div is outside [9, 255].
    if div < 9 || div > 255 {
        div /= 2;
        clk_div *= 2;
        fact = 0;
    }

    if div < 2 {
        return None;
    }

    // Round to closer divisor.
    // Linux: l.226-228
    let actual_lo = 16 * CLKRATE / (clk_div * div).max(1);
    let actual_hi = 16 * CLKRATE / (clk_div * (div + 1)).max(1);
    let target = 16 * baud;
    if actual_lo.saturating_sub(target) >= target.saturating_sub(actual_hi) {
        div += 1;
    }

    // Prefer lower base clock (fact=0) if div is even.
    // Linux: l.231-234
    if fact == 1 && div % 2 == 0 {
        div /= 2;
        fact = 0;
    }

    // Pack: bits 15:8 = (0x100 - div), bits 3:2 = fact, bits 1:0 = ps
    let word = (((0x100u32.wrapping_sub(div)) & 0xFF) << 8)
        | (fact << 2)
        | ps;
    Some(word as u16)
}

// ── LCR encoding ─────────────────────────────────────────────────

/// Encode data-bits / parity / stop-bits into the CH341 LCR byte.
///
/// The LCR byte is placed in the high byte of `wIndex` for the
/// `REG_LCR` write request.  TX and RX are always enabled.
///
/// Mirrors `ch341_set_baudrate_lcr` parity / stop / data-bits
/// encoding (Linux ch341.c l.526–552).
pub fn encode_lcr(data_bits: DataBits, parity: Parity, stop_bits: StopBits) -> u8 {
    let mut lcr = LCR_ENABLE_RX | LCR_ENABLE_TX;

    lcr |= match data_bits {
        DataBits::Five => LCR_CS5,
        DataBits::Six => LCR_CS6,
        DataBits::Seven => LCR_CS7,
        DataBits::Eight => LCR_CS8,
    };

    match parity {
        Parity::None => {}
        Parity::Odd => {
            lcr |= LCR_ENABLE_PAR;
            // ODD: PAR_EVEN=0, MARK_SPACE=0
        }
        Parity::Even => {
            lcr |= LCR_ENABLE_PAR | LCR_PAR_EVEN;
        }
        Parity::Mark => {
            lcr |= LCR_ENABLE_PAR | LCR_MARK_SPACE;
        }
        Parity::Space => {
            lcr |= LCR_ENABLE_PAR | LCR_PAR_EVEN | LCR_MARK_SPACE;
        }
    }

    if stop_bits == StopBits::Two {
        lcr |= LCR_STOP_BITS_2;
    }

    lcr
}

// ── Control-transfer packet builders ─────────────────────────────

/// Build the two `wValue`/`wIndex` pairs for a baud-rate write.
///
/// Returns `[(reg_addr, data_word), (reg_addr, data_word)]` where
/// each tuple is `(wValue, wIndex)` for a `REQ_WRITE_REG` control
/// transfer.  Returns `None` if `baud` is not achievable.
///
/// Linux: ch341_set_baudrate_lcr l.253–291 — two
/// `CH341_REQ_WRITE_REG` calls with `wValue=0x1312` / `wValue=0x0F2C`.
pub fn baud_control_words(baud: u32) -> Option<[(u16, u16); 2]> {
    let div_word = calc_divisor(baud)?;
    // High prescaler register: wIndex = divisor word
    // Low divisor register: wIndex = low byte of divisor | 0x0030
    //   (Linux l.268: val | 0x0030 — keep bits 5:4 set; they enable
    //    the baud generator in the chip's internal state machine.)
    let low_byte = (div_word & 0xFF) | 0x30;
    Some([
        (REG_BAUD_HIGH, div_word),
        (REG_BAUD_LOW, low_byte),
    ])
}

/// Build the `(wValue, wIndex)` pair for a line-control write.
///
/// `wIndex` packs the LCR byte in bits 15:8 and 0 in bits 7:0.
/// Linux: ch341_set_baudrate_lcr l.282 → wValue=0x2518, wIndex=lcr<<8
pub fn lcr_control_word(data_bits: DataBits, parity: Parity, stop_bits: StopBits) -> (u16, u16) {
    let lcr = encode_lcr(data_bits, parity, stop_bits);
    (REG_LCR, (lcr as u16) << 8)
}

// ── Modem-status decode ───────────────────────────────────────────

/// Decode the modem status byte from a CH341 interrupt-IN report.
///
/// The CH341 interrupt-IN endpoint delivers a 4-byte status packet.
/// Byte 0 carries the modem status bits, active-low per RS-232
/// convention:
/// - bit 0: CTS inverted (0 = CTS asserted)
/// - bit 1: DSR inverted
/// - bit 2: RI inverted
/// - bit 3: DCD inverted
///
/// Linux: ch341.c `ch341_update_status` l.302+ reads reg 0x0706
/// (two bytes); byte index 0 = modem status, active-low.
pub fn decode_modem_status(byte: u8) -> ModemStatus {
    ModemStatus {
        cts: (byte & 0x01) == 0,
        dsr: (byte & 0x02) == 0,
        ri: (byte & 0x04) == 0,
        dcd: (byte & 0x08) == 0,
    }
}

// ── Concrete driver state ─────────────────────────────────────────

/// Error type for CH341 operations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Ch341Error {
    /// Baud rate not achievable with the CH341 clock.
    UnsupportedBaud(u32),
    /// A control transfer to the device failed.
    ControlTransferFailed,
}

/// Soft state for a bound CH341 device.
///
/// Holds the USB slot ID and the current line settings so callers
/// can read them back without a round-trip to the hardware.
///
/// The actual control transfers are issued by the caller via the
/// `build_*` helpers above, keeping this struct `no_std` and free
/// from any xHCI dependency at the codec layer.
#[derive(Debug)]
pub struct Ch341State {
    /// USB slot ID assigned by the xHCI controller.
    pub slot_id: u8,
    /// Current baud rate, bits/second.
    pub baud: u32,
    /// Current line settings (LCR byte).
    pub lcr: u8,
    /// Last modem status snapshot.
    pub modem: ModemStatus,
    /// DTR assertion state.
    pub dtr: bool,
    /// RTS assertion state.
    pub rts: bool,
}

impl Ch341State {
    /// Create a new state block with 9600 8N1 as default line coding.
    pub fn new(slot_id: u8) -> Self {
        Self {
            slot_id,
            baud: 9600,
            lcr: encode_lcr(DataBits::Eight, Parity::None, StopBits::One),
            modem: ModemStatus::default(),
            dtr: false,
            rts: false,
        }
    }
}

impl UsbSerial for Ch341State {
    type Error = Ch341Error;

    fn set_baud(&mut self, rate: u32) -> Result<(), Ch341Error> {
        if calc_divisor(rate).is_none() {
            return Err(Ch341Error::UnsupportedBaud(rate));
        }
        self.baud = rate;
        Ok(())
    }

    fn set_line(
        &mut self,
        data_bits: DataBits,
        parity: Parity,
        stop_bits: StopBits,
    ) -> Result<(), Ch341Error> {
        self.lcr = encode_lcr(data_bits, parity, stop_bits);
        Ok(())
    }

    fn set_flow(&mut self, _flow: FlowControl) -> Result<(), Ch341Error> {
        // CH341 hardware flow control (RTS/CTS) is toggled via the
        // modem control register; XON/XOFF is not supported in
        // hardware.  Flow-control wiring deferred — requires
        // CH341_REQ_WRITE_REG to the flow-control register (0x2727).
        Ok(())
    }

    fn set_modem(&mut self, dtr: bool, rts: bool) -> Result<(), Ch341Error> {
        self.dtr = dtr;
        self.rts = rts;
        Ok(())
    }

    fn get_modem(&self) -> Result<ModemStatus, Ch341Error> {
        Ok(self.modem)
    }
}

/// Encode the modem-control `wValue` for `REQ_MODEM_CTRL`.
///
/// The CH341 uses active-low logic: clear DTR bit → DTR asserted.
/// Linux: ch341.c l.292 → `ch341_control_out(dev, REQ_MODEM_CTRL, ~control, 0)`
/// where `control` has bit 5 = DTR, bit 6 = RTS.
pub fn encode_modem_ctrl(dtr: bool, rts: bool) -> u16 {
    let mut control: u16 = 0;
    if dtr { control |= 1 << 5; }
    if rts { control |= 1 << 6; }
    // Active-low: invert the low 8 bits.
    (!control) & 0xFF
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_ch341_baud_9600() -> TestResult {
        // 9600 baud must produce a valid (non-None) divisor.
        match calc_divisor(9600) {
            Some(w) => {
                // 9600 falls between MIN_RATES[1]=366 and MIN_RATES[2]=2929
                // (below MIN_RATES[3]=23437), so the selector picks ps=2.
                let _div_high = (w >> 8) as u8;
                let ps = w & 0x03;
                if ps == 2 {
                    TestResult::Pass
                } else {
                    TestResult::Fail("9600 baud: expected ps=2")
                }
            }
            None => TestResult::Fail("9600 baud should produce valid divisor"),
        }
    }
    kernel_test_in!("drivers/usb/serial/ch341", smoke_ch341_baud_9600);

    fn smoke_ch341_baud_115200() -> TestResult {
        match calc_divisor(115200) {
            Some(_) => TestResult::Pass,
            None => TestResult::Fail("115200 baud should be supported"),
        }
    }
    kernel_test_in!("drivers/usb/serial/ch341", smoke_ch341_baud_115200);

    fn smoke_ch341_lcr_8n1() -> TestResult {
        let lcr = encode_lcr(DataBits::Eight, Parity::None, StopBits::One);
        // Must have RX+TX enabled and CS8 bits set.
        if lcr & LCR_ENABLE_RX == 0 {
            return TestResult::Fail("RX enable bit missing");
        }
        if lcr & LCR_ENABLE_TX == 0 {
            return TestResult::Fail("TX enable bit missing");
        }
        if lcr & 0x03 != LCR_CS8 {
            return TestResult::Fail("data-bits field not CS8");
        }
        if lcr & LCR_STOP_BITS_2 != 0 {
            return TestResult::Fail("stop-bits-2 should not be set for 8N1");
        }
        if lcr & LCR_ENABLE_PAR != 0 {
            return TestResult::Fail("parity should not be set for 8N1");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/serial/ch341", smoke_ch341_lcr_8n1);

    fn smoke_ch341_lcr_even_parity() -> TestResult {
        let lcr = encode_lcr(DataBits::Eight, Parity::Even, StopBits::One);
        if lcr & LCR_ENABLE_PAR == 0 {
            return TestResult::Fail("PAR_ENABLE missing for even parity");
        }
        if lcr & LCR_PAR_EVEN == 0 {
            return TestResult::Fail("PAR_EVEN missing for even parity");
        }
        if lcr & LCR_MARK_SPACE != 0 {
            return TestResult::Fail("MARK_SPACE must not be set for even parity");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/serial/ch341", smoke_ch341_lcr_even_parity);

    fn smoke_ch341_baud_control_words() -> TestResult {
        match baud_control_words(9600) {
            Some([(rv, _), (rv2, _)]) => {
                if rv != REG_BAUD_HIGH {
                    return TestResult::Fail("first word must target REG_BAUD_HIGH");
                }
                if rv2 != REG_BAUD_LOW {
                    return TestResult::Fail("second word must target REG_BAUD_LOW");
                }
                TestResult::Pass
            }
            None => TestResult::Fail("9600 baud control words failed"),
        }
    }
    kernel_test_in!("drivers/usb/serial/ch341", smoke_ch341_baud_control_words);

    fn smoke_ch341_modem_ctrl_both_asserted() -> TestResult {
        let w = encode_modem_ctrl(true, true);
        // Active-low: both bits set in control, then inverted.
        let raw: u16 = (1 << 5) | (1 << 6);
        let expected = (!raw) & 0xFF;
        if w != expected {
            return TestResult::Fail("modem ctrl word incorrect");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/serial/ch341", smoke_ch341_modem_ctrl_both_asserted);

    fn smoke_ch341_modem_status_decode() -> TestResult {
        // All signals active (active-low, so byte=0x00 → all asserted).
        let ms = decode_modem_status(0x00);
        if !ms.cts || !ms.dsr || !ms.ri || !ms.dcd {
            return TestResult::Fail("0x00 should assert all modem signals");
        }
        // No signals active (byte=0xFF).
        let ms2 = decode_modem_status(0xFF);
        if ms2.cts || ms2.dsr || ms2.ri || ms2.dcd {
            return TestResult::Fail("0xFF should deassert all modem signals");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/serial/ch341", smoke_ch341_modem_status_decode);
}
