//! FTDI FT232/FT2232/FT4232 wire codec, shared by both builds.
//!
//! Pure constants and arithmetic, no I/O and no allocation: the built-in
//! driver (`narf-drivers-usb`'s `serial::ftdi`, which re-exports this
//! module) and the loadable `.ko` (`crate::module_probe`) program the chip
//! with exactly the same values. Moved verbatim from the built-in driver;
//! the Linux references below are `drivers/usb/serial/ftdi_sio.{c,h}`,
//! GPL-2.0-or-later, consulted under NARF's GPL-2.0-or-later licensing.

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
/// Break condition (bit 14 of the SET_DATA wValue): 1 = TX held in
/// the break (spacing) state, 0 = normal transmission. Linux
/// `ftdi_sio.h`: `FTDI_SIO_SET_BREAK (0x1 << 14)`; `ftdi_break_ctl`
/// raises a break by OR-ing this bit into the last programmed
/// SET_DATA word and clears it by rewriting the plain word.
pub const DATA_BREAK: u16 = 0x1 << 14;

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
const DIVFRAC: [u8; 8] = [0, 3, 2, 4, 1, 5, 6, 7];

// ── Baud divisor calculation ──────────────────────────────────────

/// Compute the packed 32-bit divisor for FT232BM / FT232R / FTX.
///
/// Input clock = 48 MHz, but the BM/R baud generator prescales it
/// by 16: the effective divisor base is 3 MHz (FTDI AN120:
/// "the baud rate is calculated as 3000000 / divisor"). The
/// divisor is carried ×8 (`divisor3`) so the three fractional
/// bits ride along.
///
/// Linux: `ftdi_sio.c` `ftdi_232bm_baud_base_to_divisor` (l.1148)
/// and `ftdi_232bm_baud_to_divisor` (l.1162), which compute
/// `divisor3 = DIV_ROUND_CLOSEST(base, 2 * baud)` with
/// `base = 48 MHz` — i.e. 48 MHz / (2·baud) = 8 × 3 MHz / baud.
///
/// Returns a `u32` where:
/// - bits 13:0 = integer divisor
/// - bits 17:14 = fractional divisor (from `DIVFRAC`)
///
/// Special cases (AN120): packed 0 encodes divisor 1 (3 Mbaud);
/// packed 1 encodes the 2 Mbaud rate whose raw divisor3 would
/// otherwise collide with the fractional encoding.
pub const fn calc_divisor_bm(baud: u32) -> u32 {
    baud_base_to_divisor_bm(baud, 48_000_000)
}

const fn baud_base_to_divisor_bm(baud: u32, base: u32) -> u32 {
    // divisor3 = DIV_ROUND_CLOSEST(base, 2 * baud)
    let divisor3 = ((base as u64 + baud as u64) / (2 * baud as u64)) as u32;
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
pub const fn calc_divisor_h(baud: u32) -> u32 {
    baud_base_to_divisor_h(baud, 120_000_000)
}

const fn baud_base_to_divisor_h(baud: u32, base: u32) -> u32 {
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
pub const fn divisor_to_wvalue_windex(packed: u32, channel: u8) -> (u16, u16) {
    let value = packed as u16;
    let mut index = (packed >> 16) as u16;
    if channel != 0 {
        index = (index << 8) | channel as u16;
    }
    (value, index)
}

// ── Modem control encoding ────────────────────────────────────────

/// Encode DTR / RTS state into the `wValue` for `REQ_MODEM_CTRL`.
///
/// FTDI uses a mask-value encoding: for each signal, set the mask
/// bit (high byte) and the value bit (low byte) independently.
/// This allows changing one signal without disturbing the other.
///
/// Linux: `ftdi_sio.c` `update_mctrl` (l.1207–1232).
pub const fn encode_modem_ctrl(dtr: bool, rts: bool) -> u16 {
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

// ── Bulk-IN packet framing ────────────────────────────────────────

/// Status bytes FTDI prefixes to every bulk-IN packet (one per
/// `wMaxPacketSize` chunk): modem status, then line status.
/// Linux: `ftdi_sio.c` `ftdi_process_packet`.
pub const RX_STATUS_LEN: usize = 2;

/// Split one bulk-IN packet (at most `wMaxPacketSize` bytes) into its
/// `(modem_status, line_status, payload)`. A packet shorter than the two
/// status bytes carries nothing and yields `None`.
pub fn split_rx_packet(packet: &[u8]) -> Option<(u8, u8, &[u8])> {
    // `split_at_checked`, not indexing: this runs in the `.ko`, which must
    // stay free of out-of-line `core` panic paths.
    let (status, payload) = packet.split_at_checked(RX_STATUS_LEN)?;
    match status {
        [modem, line] => Some((*modem, *line, payload)),
        _ => None,
    }
}
