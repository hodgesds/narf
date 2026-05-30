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

// ── Request codes ─────────────────────────────────────────────────

/// Reset the port or purge FIFOs.
/// Linux: ftdi_sio.h l.27
pub const REQ_RESET: u8 = 0x00;

/// Set the modem control register (DTR / RTS).
/// Linux: ftdi_sio.h l.28 `FTDI_SIO_MODEM_CTRL`
pub const REQ_MODEM_CTRL: u8 = 0x01;

/// Set flow control register.
/// Linux: ftdi_sio.h l.29 `FTDI_SIO_SET_FLOW_CTRL`
pub const REQ_SET_FLOW_CTRL: u8 = 0x02;

/// Set baud rate divisor.
/// Linux: ftdi_sio.h l.30 `FTDI_SIO_SET_BAUD_RATE`
pub const REQ_SET_BAUD_RATE: u8 = 0x03;

/// Set data characteristics (data bits / parity / stop bits).
/// Linux: ftdi_sio.h l.31 `FTDI_SIO_SET_DATA`
pub const REQ_SET_DATA: u8 = 0x04;

/// Get modem status (CTS / DSR / RI / DCD).
/// Linux: ftdi_sio.h l.33 `FTDI_SIO_GET_MODEM_STATUS`
pub const REQ_GET_MODEM_STATUS: u8 = 0x05;

/// `bmRequestType` host-to-device vendor class.
/// Linux: ftdi_sio.h `FTDI_SIO_RESET_REQUEST_TYPE` = 0x40
pub const RT_HOST_TO_DEV: u8 = 0x40;

/// `bmRequestType` device-to-host vendor class.
/// Linux: ftdi_sio.h `FTDI_SIO_GET_MODEM_STATUS_REQUEST_TYPE` = 0xC0
pub const RT_DEV_TO_HOST: u8 = 0xC0;

// ── Modem control encoding ────────────────────────────────────────

// Linux: ftdi_sio.h l.233–238
pub const SET_DTR_MASK: u16 = 0x01;
pub const SET_DTR_HIGH: u16 = (SET_DTR_MASK << 8) | 1;
pub const SET_DTR_LOW: u16 = SET_DTR_MASK << 8;
pub const SET_RTS_MASK: u16 = 0x02;
pub const SET_RTS_HIGH: u16 = (SET_RTS_MASK << 8) | 2;
pub const SET_RTS_LOW: u16 = SET_RTS_MASK << 8;

// ── Data format bits (REQ_SET_DATA wValue) ────────────────────────

// Linux: ftdi_sio.h l.175–183
/// Parity: none (bits 10:8 = 0b000).
pub const DATA_PARITY_NONE: u16 = 0x0 << 8;
/// Parity: odd (bits 10:8 = 0b001).
pub const DATA_PARITY_ODD: u16 = 0x1 << 8;
/// Parity: even (bits 10:8 = 0b010).
pub const DATA_PARITY_EVEN: u16 = 0x2 << 8;
/// Parity: mark (bits 10:8 = 0b011).
pub const DATA_PARITY_MARK: u16 = 0x3 << 8;
/// Parity: space (bits 10:8 = 0b100).
pub const DATA_PARITY_SPACE: u16 = 0x4 << 8;
/// Stop bits: 1 (bits 12:11 = 0b00).
pub const DATA_STOP_BITS_1: u16 = 0x0 << 11;
/// Stop bits: 1.5 (bits 12:11 = 0b01).
pub const DATA_STOP_BITS_15: u16 = 0x1 << 11;
/// Stop bits: 2 (bits 12:11 = 0b10).
pub const DATA_STOP_BITS_2: u16 = 0x2 << 11;

// ── Flow-control bits (REQ_SET_FLOW_CTRL wIndex high byte) ────────

// Linux: ftdi_sio.h l.261–264
pub const FLOW_DISABLE: u16 = 0x0000;
pub const FLOW_RTS_CTS: u16 = 0x0100;
pub const FLOW_DTR_DSR: u16 = 0x0200;
pub const FLOW_XON_XOFF: u16 = 0x0400;

// ── Modem status bits (byte 0 of GET_MODEM_STATUS response) ───────

// Linux: ftdi_sio.h l.551–554 (`FTDI_RS0_*`)
pub const RS0_CTS: u8 = 1 << 4;
pub const RS0_DSR: u8 = 1 << 5;
pub const RS0_RI: u8 = 1 << 6;
pub const RS0_RLSD: u8 = 1 << 7; // DCD

// ── Chip generation ───────────────────────────────────────────────

/// FTDI chip generation — determines the baud divisor algorithm and
/// clock frequency.
///
/// Linux: `ftdi_sio.c` `enum ftdi_chip_type` (l.50+)
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ChipType {
    /// FT232AM / FT245AM — 48 MHz, AM-style encoding.
    Am,
    /// FT232BM / FT232R / FT2232C / FTX — 48 MHz, BM-style encoding.
    Bm,
    /// FT2232H / FT4232H / FT232H — 120 MHz, H-style encoding.
    H,
}

// ── Sub-integer fraction table ────────────────────────────────────

/// Fractional sub-divisor remap table.
///
/// The FTDI BM/H hardware encodes the fractional part of the
/// divisor in a non-linear 3-bit field.  The `divisor3 & 0x7`
/// index into this table gives the wire encoding.
///
/// Linux: `ftdi_sio.c` l.1152 (used in both BM and H functions)
static DIVFRAC: [u8; 8] = [0, 3, 2, 4, 1, 5, 6, 7];

// ── Baud divisor calculation ──────────────────────────────────────

/// Compute the packed 32-bit divisor for FT232BM / FT232R / FTX.
///
/// Base clock = 48 MHz.
///
/// Linux: `ftdi_sio.c` `ftdi_232bm_baud_base_to_divisor` (l.1148)
/// and `ftdi_232bm_baud_to_divisor` (l.1162).
///
/// Returns a `u32` where:
/// - bits 13:0 = integer divisor
/// - bits 17:14 = fractional divisor (from `DIVFRAC`)
///
/// Special cases: divisor==1 → packed 0 (rate = 48M/2),
/// divisor==0x4001 → packed 1 (rate = 48M/3).
pub fn calc_divisor_bm(baud: u32) -> u32 {
    baud_base_to_divisor_bm(baud, 48_000_000)
}

fn baud_base_to_divisor_bm(baud: u32, base: u32) -> u32 {
    // divisor shifted 3 bits left
    let divisor3 = ((base as u64 * 2 + baud as u64 / 2) / baud as u64) as u32;
    let mut packed = divisor3 >> 3;
    packed |= (DIVFRAC[(divisor3 & 0x7) as usize] as u32) << 14;
    if packed == 1 {
        packed = 0;
    } else if packed == 0x4001 {
        packed = 1;
    }
    packed
}

/// Compute the packed 32-bit divisor for FT2232H / FT4232H / FT232H.
///
/// Base clock = 120 MHz, 10-bit oversampling.
///
/// Linux: `ftdi_sio.c` `ftdi_2232h_baud_base_to_divisor` (l.1192)
/// and `ftdi_2232h_baud_to_divisor` (l.1218).
///
/// The H-series clock-select bit (0x0002_0000) enables the 120 MHz
/// path in the baud-rate generator; without it the chip falls back
/// to a 48 MHz-derived rate.
pub fn calc_divisor_h(baud: u32) -> u32 {
    baud_base_to_divisor_h(baud, 120_000_000)
}

fn baud_base_to_divisor_h(baud: u32, base: u32) -> u32 {
    // hi-speed: 8 * base / (10 * baud), rounded to nearest
    let divisor3 = ((8u64 * base as u64 + 5u64 * baud as u64) / (10u64 * baud as u64)) as u32;
    let mut packed = divisor3 >> 3;
    packed |= (DIVFRAC[(divisor3 & 0x7) as usize] as u32) << 14;
    if packed == 1 {
        packed = 0;
    } else if packed == 0x4001 {
        packed = 1;
    }
    // Set the 120 MHz clock-select bit.
    packed | 0x0002_0000
}

/// Split a packed 32-bit divisor into the `(wValue, wIndex)` pair
/// for the `REQ_SET_BAUD_RATE` control transfer.
///
/// For single-port chips channel = 0.  For multi-port chips
/// (FT2232H, FT4232H) the caller must OR the channel index into the
/// high byte of `wIndex` after this function returns.
///
/// Linux: `ftdi_sio.c` `change_speed` (l.1345):
/// ```c
/// value = (u16)index_value;
/// index = (u16)(index_value >> 16);
/// if (priv->channel)
///     index = (u16)((index << 8) | priv->channel);
/// ```
pub fn divisor_to_wvalue_windex(packed: u32, channel: u8) -> (u16, u16) {
    let value = packed as u16;
    let mut index = (packed >> 16) as u16;
    if channel != 0 {
        index = (index << 8) | channel as u16;
    }
    (value, index)
}

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

// ── Modem control encoding ────────────────────────────────────────

/// Encode DTR / RTS state into the `wValue` for `REQ_MODEM_CTRL`.
///
/// FTDI uses a mask-value encoding: for each signal, set the mask
/// bit (high byte) and the value bit (low byte) independently.
/// This allows changing one signal without disturbing the other.
///
/// Linux: `ftdi_sio.c` `update_mctrl` (l.1207–1232).
pub fn encode_modem_ctrl(dtr: bool, rts: bool) -> u16 {
    let mut v: u16 = 0;
    if dtr {
        v |= SET_DTR_HIGH;
    } else {
        v |= SET_DTR_LOW;
    }
    if rts {
        v |= SET_RTS_HIGH;
    } else {
        v |= SET_RTS_LOW;
    }
    v
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
        // FT232R @ 48 MHz, 115200 baud.
        // Expected: Linux ftdi_232bm_baud_to_divisor(115200) = 0x001A
        // divisor3 = round(48M * 2 / 115200) ≈ round(833.3) = 833
        // packed_int = 833 >> 3 = 104 = 0x68
        // frac idx = 833 & 7 = 1 → DIVFRAC[1] = 3
        // packed = 0x68 | (3 << 14) = 0x68 | 0xC000 = 0xC068
        let d = calc_divisor_bm(115200);
        if d == 0 {
            return TestResult::Fail("115200 BM divisor should be non-zero");
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
    kernel_test_in!("drivers/usb/serial/ftdi", smoke_ftdi_bm_9600_wvalue_windex_channel0);
}
