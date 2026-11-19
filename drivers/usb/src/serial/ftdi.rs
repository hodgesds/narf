//! FTDI FT232R/FT2232H/FT4232H USB-to-serial adapter driver — clean-room.
//!
//! ## Hardware overview
//!
//! FTDI chips expose one or more virtual serial ports over USB.
//! Each port has a bulk-OUT (TX) and bulk-IN (RX) endpoint.
//! Configuration is via vendor-specific control transfers
//! (`bmRequestType = 0x40`, device → host direction for GET ops).
//!
//! Multi-port chips (FT2232H = 2 ports, FT4232H = 4 ports) identify
//! their channel in the high byte of `wIndex` for all control
//! transfers: channel A = 1, B = 2, C = 3, D = 4.  Single-port
//! chips (FT232R) use `wIndex = 0` (or channel 1 — both are
//! accepted by the hardware).
//!
//! ## Baud-rate algorithms
//!
//! Three algorithms exist depending on the chip generation:
//!
//! **BM/R series (FT232R / FTX / FT2232C)** — 48 MHz base clock:
//! ```text
//! divisor3 = round(48_000_000 / (2 * baud))
//! integer  = divisor3 >> 3
//! fraction = DIVFRAC[divisor3 & 0x7]   (sub-integer remap table)
//! packed   = integer | (fraction << 14)
//! ```
//!
//! **H series (FT2232H / FT4232H / FT232H)** — 120 MHz base clock,
//! 10-bit oversampling:
//! ```text
//! divisor3 = round(8 * 120_000_000 / (10 * baud))
//! packed   = same | 0x0002_0000   (120 MHz clock-select bit)
//! ```
//!
//! ## Linux references
//!
//! `drivers/usb/serial/ftdi_sio.c` — GPL-2.0-or-later.
//! `drivers/usb/serial/ftdi_sio.h` — GPL-2.0-or-later.
//!
//! Key symbols cited:
//! - Request codes: `ftdi_sio.h` l.27–38 (`FTDI_SIO_*`)
//! - Modem bits: `ftdi_sio.h` l.551–554 (`FTDI_RS0_*`)
//! - Data format bits: `ftdi_sio.h` l.175–183
//! - Flow-control bits: `ftdi_sio.h` l.261–264
//! - BM divisor: `ftdi_sio.c` l.1162 `ftdi_232bm_baud_base_to_divisor`
//! - H-series divisor: `ftdi_sio.c` l.1192 `ftdi_2232h_baud_base_to_divisor`
//! - DTR/RTS encoding: `ftdi_sio.c` l.1207–1232 `update_mctrl`
//! - GET_MODEM_STATUS: `ftdi_sio.h` l.397–402

use super::{DataBits, FlowControl, ModemStatus, Parity, StopBits, UsbSerial};

// Wire constants, chip generations and the baud-divisor / modem-control
// encoders live in the shared codec crate so the loadable `.ko` uses the
// same values; re-exported here so existing paths keep resolving.
pub use narf_drivers_usb_ftdi::codec::{
    calc_divisor_bm, calc_divisor_h, divisor_to_wvalue_windex, encode_modem_ctrl, ChipType,
    DATA_BREAK, DATA_PARITY_EVEN, DATA_PARITY_MARK, DATA_PARITY_NONE, DATA_PARITY_ODD,
    DATA_PARITY_SPACE, DATA_STOP_BITS_1, DATA_STOP_BITS_15, DATA_STOP_BITS_2, FLOW_DISABLE,
    FLOW_DTR_DSR, FLOW_RTS_CTS, FLOW_XON_XOFF, REQ_GET_MODEM_STATUS, REQ_MODEM_CTRL, REQ_RESET,
    REQ_SET_BAUD_RATE, REQ_SET_DATA, REQ_SET_FLOW_CTRL, RS0_CTS, RS0_DSR, RS0_RI, RS0_RLSD,
    RT_DEV_TO_HOST, RT_HOST_TO_DEV, SET_DTR_HIGH, SET_DTR_LOW, SET_DTR_MASK, SET_RTS_HIGH,
    SET_RTS_LOW, SET_RTS_MASK,
};

// ── Data format encoding ──────────────────────────────────────────

/// Encode data bits / parity / stop bits into the `wValue` for
/// `REQ_SET_DATA`.
///
/// Layout (USB spec / FTDI AN232R-01):
/// ```text
/// bits  7:0  = data-bit count (5, 6, 7, or 8)
/// bits 10:8  = parity (0=none, 1=odd, 2=even, 3=mark, 4=space)
/// bits 12:11 = stop bits (0=1, 1=1.5, 2=2)
/// ```
///
/// Linux: `ftdi_sio.c` l.2620–2680 `ftdi_set_termios`.
pub fn encode_data_format(data_bits: DataBits, parity: Parity, stop_bits: StopBits) -> u16 {
    let db: u16 = match data_bits {
        DataBits::Five => 5,
        DataBits::Six => 6,
        DataBits::Seven => 7,
        DataBits::Eight => 8,
    };
    let par: u16 = match parity {
        Parity::None => DATA_PARITY_NONE,
        Parity::Odd => DATA_PARITY_ODD,
        Parity::Even => DATA_PARITY_EVEN,
        Parity::Mark => DATA_PARITY_MARK,
        Parity::Space => DATA_PARITY_SPACE,
    };
    let stop: u16 = match stop_bits {
        StopBits::One => DATA_STOP_BITS_1,
        StopBits::OnePointFive => DATA_STOP_BITS_15,
        StopBits::Two => DATA_STOP_BITS_2,
    };
    db | par | stop
}

// ── Modem status decode ───────────────────────────────────────────

/// Decode the modem status byte (byte 0 of GET_MODEM_STATUS
/// response).
///
/// Linux: `ftdi_sio.h` l.551–554 (`FTDI_RS0_*`) and
/// `ftdi_sio.c` `ftdi_process_packet` modem-status path.
pub fn decode_modem_status(byte0: u8) -> ModemStatus {
    ModemStatus {
        cts: byte0 & RS0_CTS != 0,
        dsr: byte0 & RS0_DSR != 0,
        ri: byte0 & RS0_RI != 0,
        dcd: byte0 & RS0_RLSD != 0,
    }
}

// ── Concrete driver state ─────────────────────────────────────────

/// Error type for FTDI operations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FtdiError {
    /// The control transfer failed.
    ControlTransferFailed,
}

/// Per-port state for a bound FTDI device.
#[derive(Debug)]
pub struct FtdiState {
    /// USB slot ID.
    pub slot_id: u8,
    /// Chip generation — selects the baud divisor algorithm.
    pub chip: ChipType,
    /// Port channel (0 for single-port FT232R; 1–4 for multi-port).
    pub channel: u8,
    /// Current baud rate.
    pub baud: u32,
    /// Current data format word.
    pub data_format: u16,
    /// Last modem status snapshot.
    pub modem: ModemStatus,
    /// DTR state.
    pub dtr: bool,
    /// RTS state.
    pub rts: bool,
}

impl FtdiState {
    /// Create a new state block defaulting to 9600 8N1.
    pub fn new(slot_id: u8, chip: ChipType, channel: u8) -> Self {
        Self {
            slot_id,
            chip,
            channel,
            baud: 9600,
            data_format: encode_data_format(DataBits::Eight, Parity::None, StopBits::One),
            modem: ModemStatus::default(),
            dtr: false,
            rts: false,
        }
    }

    /// Compute the `(wValue, wIndex)` pair for the current baud rate.
    pub fn baud_wvalue_windex(&self) -> (u16, u16) {
        let packed = match self.chip {
            ChipType::Am | ChipType::Bm => calc_divisor_bm(self.baud),
            ChipType::H => calc_divisor_h(self.baud),
        };
        divisor_to_wvalue_windex(packed, self.channel)
    }
}

impl UsbSerial for FtdiState {
    type Error = FtdiError;

    fn set_baud(&mut self, rate: u32) -> Result<(), FtdiError> {
        self.baud = rate;
        Ok(())
    }

    fn set_line(
        &mut self,
        data_bits: DataBits,
        parity: Parity,
        stop_bits: StopBits,
    ) -> Result<(), FtdiError> {
        self.data_format = encode_data_format(data_bits, parity, stop_bits);
        Ok(())
    }

    fn set_flow(&mut self, _flow: FlowControl) -> Result<(), FtdiError> {
        // Flow control is set via REQ_SET_FLOW_CTRL; encoded with
        // FLOW_* constants.  Wired through the concrete transfer
        // layer; deferred from this codec struct.
        Ok(())
    }

    fn set_modem(&mut self, dtr: bool, rts: bool) -> Result<(), FtdiError> {
        self.dtr = dtr;
        self.rts = rts;
        Ok(())
    }

    fn get_modem(&self) -> Result<ModemStatus, FtdiError> {
        Ok(self.modem)
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_ftdi_baud_divisor_bm_115200() -> TestResult {
        // FT232R @ 115200 baud, pinned byte-for-byte against
        // AN120: the effective divisor base is 3 MHz (48 MHz ÷ 16
        // prescaler), so divisor = 3000000/115200 = 26.04 →
        // divisor3 = round(48M / (2 × 115200)) = 208
        // packed_int = 208 >> 3 = 26 = 0x1A
        // frac idx = 208 & 7 = 0 → DIVFRAC[0] = 0
        // packed = 0x001A — the value Linux
        // ftdi_232bm_baud_to_divisor(115200) returns. (An earlier
        // in-tree formula computed against the unprescaled clock
        // and produced 0xC068, which programs ≈4× the requested
        // rate on real hardware; this assertion now pins the
        // document value exactly.)
        let d = calc_divisor_bm(115200);
        if d != 0x001A {
            return TestResult::Fail("115200 BM divisor must be exactly 0x001A (AN120)");
        }
        // 9600 baud exercises a fractional code: 3000000/9600 =
        // 312.5 → divisor3 = 2500 → int 312, DIVFRAC[4] = 1.
        let d9 = calc_divisor_bm(9600);
        if d9 != 0x4138 {
            return TestResult::Fail("9600 BM divisor must be 0x4138 (312 + 1/8 frac)");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/serial/ftdi", smoke_ftdi_baud_divisor_bm_115200);

    fn smoke_ftdi_baud_divisor_h_115200() -> TestResult {
        // FT2232H @ 120 MHz, 115200 baud.
        // H-series divisor must have the clock-select bit set.
        let d = calc_divisor_h(115200);
        if d & 0x0002_0000 == 0 {
            return TestResult::Fail("H-series divisor missing clock-select bit 17");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/serial/ftdi", smoke_ftdi_baud_divisor_h_115200);

    fn smoke_ftdi_data_format_8e1() -> TestResult {
        let w = encode_data_format(DataBits::Eight, Parity::Even, StopBits::One);
        // Data bits = 8 → low byte = 8.
        if w & 0xFF != 8 {
            return TestResult::Fail("data-bits field not 8");
        }
        // Parity even → bits 10:8 = 0b010 = 2.
        let par = (w >> 8) & 0x07;
        if par != 2 {
            return TestResult::Fail("parity field not even (2)");
        }
        // Stop bits = 1 → bits 12:11 = 0b00.
        let stop = (w >> 11) & 0x03;
        if stop != 0 {
            return TestResult::Fail("stop-bits field not 1");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/serial/ftdi", smoke_ftdi_data_format_8e1);

    fn smoke_ftdi_data_format_8n2() -> TestResult {
        let w = encode_data_format(DataBits::Eight, Parity::None, StopBits::Two);
        let stop = (w >> 11) & 0x03;
        if stop != 2 {
            return TestResult::Fail("stop-bits field not 2 for StopBits::Two");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/serial/ftdi", smoke_ftdi_data_format_8n2);

    fn smoke_ftdi_modem_ctrl_dtr_only() -> TestResult {
        let v = encode_modem_ctrl(true, false);
        // DTR high: SET_DTR_HIGH = (0x01 << 8) | 1 = 0x0101
        // RTS low:  SET_RTS_LOW  = (0x02 << 8) | 0 = 0x0200
        // Combined = 0x0301
        if v & 0x0101 != 0x0101 {
            return TestResult::Fail("DTR_HIGH bits not set");
        }
        // RTS mask bit must be set (to tell chip: update RTS).
        if v & 0x0200 == 0 {
            return TestResult::Fail("RTS mask bit missing");
        }
        // RTS value bit must be clear.
        if v & 0x0002 != 0 {
            return TestResult::Fail("RTS value bit must be clear");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/serial/ftdi", smoke_ftdi_modem_ctrl_dtr_only);

    fn smoke_ftdi_modem_status_decode() -> TestResult {
        // byte0 = CTS | DSR = 0x30
        let ms = decode_modem_status(0x30);
        if !ms.cts || !ms.dsr {
            return TestResult::Fail("CTS/DSR should be set for byte0=0x30");
        }
        if ms.ri || ms.dcd {
            return TestResult::Fail("RI/DCD should not be set for byte0=0x30");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/serial/ftdi", smoke_ftdi_modem_status_decode);

    fn smoke_ftdi_bm_9600_wvalue_windex_channel0() -> TestResult {
        let packed = calc_divisor_bm(9600);
        let (wv, wi) = divisor_to_wvalue_windex(packed, 0);
        // Channel 0: wIndex should just be the high 16 bits of packed.
        let expected_wi = (packed >> 16) as u16;
        if wi != expected_wi {
            return TestResult::Fail("wIndex mismatch for channel 0");
        }
        let _ = wv;
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/serial/ftdi",
        smoke_ftdi_bm_9600_wvalue_windex_channel0
    );

    /// The shared codec is what the loadable `.ko` uses: its compile-time
    /// 115200 divisors must equal the run-time values the built-in driver
    /// computes, and bulk-IN framing must strip exactly the two status bytes.
    fn smoke_ftdi_shared_codec_matches_module_use() -> TestResult {
        use narf_drivers_usb_ftdi::codec::split_rx_packet;
        const BM: u32 = calc_divisor_bm(115_200);
        const H: u32 = calc_divisor_h(115_200);
        let baud = 115_200u32;
        if BM != calc_divisor_bm(baud) || H != calc_divisor_h(baud) {
            return TestResult::Fail("const and run-time divisors disagree");
        }
        // AN232B-05: 115200 on the BM 3 MHz base is divisor 26 exactly.
        if BM != 26 {
            return TestResult::Fail("BM 115200 divisor is not 26");
        }
        if split_rx_packet(&[0x01, 0x60, b'h', b'i']) != Some((0x01, 0x60, &b"hi"[..]))
            || split_rx_packet(&[0x01, 0x60]) != Some((0x01, 0x60, &[][..]))
            || split_rx_packet(&[0x01]).is_some()
        {
            return TestResult::Fail("bulk-IN status framing mis-split");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/serial/ftdi",
        smoke_ftdi_shared_codec_matches_module_use
    );
}
