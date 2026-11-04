// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8723AE firmware-event mailbox (C2H commands over MMIO).
//!
//! This is the 8723AE-only route in the spec's C2H event inventory: Linux
//! `rtlwifi/pci.c` gates the firmware-event work queue on
//! `HARDWARE_TYPE_RTL8723AE` alone — on `IMR_C2HCMD` it schedules
//! `fwevt_wq`, whose callback calls the chip's `c2h_command_handle`.
//! For 8723AE that is `rtl_8723e_c2h_command_handle`
//! (`rtl8723ae/hal_btc.c:1690`, wired as `.c2h_command_handle` in
//! `rtl8723ae/sw.c:227`). The in-tree ISR side already exists as
//! `irq::IsrStatus::c2h_pending`; this module is the deferred-work half.
//! It has no production caller yet: the future AE packet owner schedules
//! [`drain`] when `c2h_pending` is set, mirroring the `pci.c` gate (which
//! is 8723AE-only — no other rtlwifi chip takes this path).
//!
//! ## Protocol (`hal_btc.c:1690`, `hal_btc.h:49-50,118-122`,
//! `rtl8723ae/reg.h:86-87`)
//!
//! - Header byte at [`REG_C2HEVT_MSG_NORMAL`] (`0x01A0`): `cmd_id` is the
//!   low nibble, `cmd_len` the high nibble; the sequence byte follows at
//!   `0x01A1`. The body (when any) starts at `0x01A2`.
//! - Close byte at [`REG_C2HEVT_CLOSE`] (`0x01AF` — the same address the
//!   88EE profile uses as its `REG_C2HEVT_CLEAR`; on 8723AE it is the
//!   mailbox close handshake, not a clear):
//!   - already [`C2H_EVT_HOST_CLOSE`] (`0x00`) → the host already closed
//!     this event; return [`Outcome::AlreadyClosed`] without reading the
//!     body or writing anything.
//!   - anything other than [`C2H_EVT_FW_CLOSE`] (`0xFF`) → the firmware
//!     has not finished writing; write `0x00` and return
//!     [`Outcome::NotReady`] without reading the body.
//!   - [`C2H_EVT_FW_CLOSE`] → read `cmd_len` body bytes, dispatch, then
//!     write [`C2H_EVT_HOST_CLOSE`] to close the event. The final close
//!     write happens for every dispatched id, including ignored ones.
//! - Dispatch: [`C2H_V0_BT_RSSI`] (4) and [`C2H_V0_BT_OP_MODE`] (5) are
//!   consumed without effect; [`C2H_V0_BT_INFO`] (12) parses the BT info
//!   body ([`parse_bt_info`]); every other id is consumed without effect.
//!
//! ## BT info (`rtl8723e_dm_bt_parse_bt_info`, `hal_btc.c:1645`)
//!
//! Linux first clears `c2h_bt_info_req_sent` and `bt_retry_cnt`, then
//! takes the original info byte from body byte 0 and the retry count from
//! body byte 1 (only when the body is at least 2 bytes — a shorter body
//! leaves the count at 0). Bit 2 of the original is the inquiry/page
//! flag; bit 0 ([`BTINFO_CONNECTION`]) is the connection flag, which
//! Linux turns into `bt_busy` and the `BT_COEX_STATE_BT_IDLE` clear/set.
//! This module returns those four fields as [`BtInfo`]; updating
//! coexistence state from them (and the `btc_periodical` call Linux makes
//! when `get_btc_status()` is true) belongs to the future AE coexistence
//! owner, which does not exist yet. The sequence byte is read (Linux logs
//! it) but carries no dispatch meaning here.

use crate::rtlwifi::firmware_transport::{Error, Io};
use alloc::vec::Vec;

/// C2H event message box (`rtl8723ae/reg.h:86`).
pub const REG_C2HEVT_MSG_NORMAL: u16 = 0x01A0;
/// Mailbox close byte (`rtl8723ae/reg.h` via `hal_btc.c:1690`: `0x01AF`).
/// Same address as the 88EE profile's `REG_C2HEVT_CLEAR`; on 8723AE it is
/// the close handshake, not a clear.
pub const REG_C2HEVT_CLOSE: u16 = 0x01AF;
/// Host-closed close value (`hal_btc.h:49`).
pub const C2H_EVT_HOST_CLOSE: u8 = 0x00;
/// Firmware-closed close value (`hal_btc.h:50`).
pub const C2H_EVT_FW_CLOSE: u8 = 0xFF;
/// BT RSSI event id, consumed without effect (`hal_btc.h:118`).
pub const C2H_V0_BT_RSSI: u8 = 4;
/// BT operation-mode event id, consumed without effect (`hal_btc.h:119`).
pub const C2H_V0_BT_OP_MODE: u8 = 5;
/// BT info event id (`hal_btc.h:122`).
pub const C2H_V0_BT_INFO: u8 = 12;
/// Inquiry/page flag in the BT info original byte (`hal_btc.c:1674`,
/// `BIT(2)`).
pub const BTINFO_INQUIRY_PAGE: u8 = 1 << 2;
/// Connection flag in the BT info original byte (`hal_bt_coexist.h:109`,
/// `BTINFO_B_CONNECTION`, `BIT(0)`).
pub const BTINFO_CONNECTION: u8 = 1 << 0;

/// Parsed BT info body (`rtl8723e_dm_bt_parse_bt_info`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BtInfo {
    /// Body byte 0 (`c2h_bt_info_original`); 0 for an empty body.
    pub original: u8,
    /// Body byte 1 (`bt_retry_cnt`); 0 unless the body is at least
    /// 2 bytes.
    pub retry_cnt: u8,
    /// `original` bit 2 (`c2h_bt_inquiry_page`).
    pub inquiry_page: bool,
    /// `original` bit 0 (`BTINFO_B_CONNECTION` → `bt_busy`).
    pub connected: bool,
}

/// One drained mailbox event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// `C2H_V0_BT_INFO` body, parsed.
    BtInfo(BtInfo),
    /// RSSI, operation-mode, and unknown ids: consumed without effect.
    /// The id is carried so a caller can log it; Linux drops it.
    Ignored {
        /// Low nibble of the header byte.
        id: u8,
    },
}

/// Result of one [`drain`] call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Close byte already [`C2H_EVT_HOST_CLOSE`]: nothing read, nothing
    /// written.
    AlreadyClosed,
    /// Close byte neither host- nor firmware-closed: `0x00` written to
    /// the close byte, body not read.
    NotReady,
    /// Firmware-closed event read, dispatched, and closed with
    /// [`C2H_EVT_HOST_CLOSE`].
    Dispatched(Event),
}

/// Parse a BT info body (`rtl8723e_dm_bt_parse_bt_info`).
///
/// Linux zeroes the retry count first and only overwrites it from body
/// byte 1 when the body is at least 2 bytes; an empty body yields an
/// all-zero [`BtInfo`]. The `c2h_bt_info_req_sent` clear and the
/// `bt_busy` / idle-state updates are coexistence-owner state, not part
/// of this parse.
pub fn parse_bt_info(body: &[u8]) -> BtInfo {
    let original = body.first().copied().unwrap_or(0);
    let retry_cnt = if body.len() >= 2 { body[1] } else { 0 };
    BtInfo {
        original,
        retry_cnt,
        inquiry_page: original & BTINFO_INQUIRY_PAGE != 0,
        connected: original & BTINFO_CONNECTION != 0,
    }
}

/// Drain one firmware-event mailbox entry
/// (`rtl_8723e_c2h_command_handle`).
///
/// Reads the header and sequence bytes, then the close byte, in Linux's
/// order. On [`Outcome::NotReady`] exactly one write is issued (close
/// byte `0x00`); on [`Outcome::Dispatched`] the body is read byte by
/// byte from [`REG_C2HEVT_MSG_NORMAL`] + 2 and the close byte is written
/// [`C2H_EVT_HOST_CLOSE`] after dispatch. [`Outcome::AlreadyClosed`]
/// issues no writes. Any [`Io`] error aborts the drain with no close
/// write, so the firmware event is not lost to a failed read.
pub fn drain<I: Io>(io: &I) -> Result<Outcome, Error> {
    let header = io.read8(REG_C2HEVT_MSG_NORMAL)?;
    let id = header & 0x0f;
    let len = header >> 4;
    let _seq = io.read8(REG_C2HEVT_MSG_NORMAL + 1)?;
    let close = io.read8(REG_C2HEVT_CLOSE)?;
    if close == C2H_EVT_HOST_CLOSE {
        return Ok(Outcome::AlreadyClosed);
    }
    if close != C2H_EVT_FW_CLOSE {
        io.write8(REG_C2HEVT_CLOSE, C2H_EVT_HOST_CLOSE)?;
        return Ok(Outcome::NotReady);
    }
    let mut body = Vec::with_capacity(usize::from(len));
    for index in 0..len {
        body.push(io.read8(REG_C2HEVT_MSG_NORMAL + 2 + u16::from(index))?);
    }
    let event = match id {
        C2H_V0_BT_INFO => Event::BtInfo(parse_bt_info(&body)),
        other => Event::Ignored { id: other },
    };
    io.write8(REG_C2HEVT_CLOSE, C2H_EVT_HOST_CLOSE)?;
    Ok(Outcome::Dispatched(event))
}
