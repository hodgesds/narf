// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192EE firmware-to-host (C2H) packets and the RA-report handler.
//!
//! An RX status with `rpt_sel == 0` is a normal frame; any other value is
//! `C2H_PACKET` (`rtl92ee_rx_query_desc`), queued by `pci.c` to
//! `rtl_c2hcmd_enqueue` → `base.c::rtl_c2h_content_parsing`. The id/body
//! layout and the V1 TX report (8192EE's `spec_ver` lacks
//! `RTL_SPEC_EXT_C2H`) are the core ones shared with RTL8821AE
//! ([`super::super::rtl8821ae::c2h::parse`]). `C2H_RA_RPT` goes to
//! `rtl92ee_c2h_ra_report_handler` → `rtl92ee_dm_dynamic_arfb_select`
//! (`dm.c`), which rewrites the `REG_DARFRC` fallback table for the rate the
//! firmware RA reports. BT info/MP reports are ignored: BT boards are not
//! admitted.

pub use super::super::rtl8821ae::c2h::{
    parse as parse_core, Error, TxReportState, C2H_DATA_OFFSET, C2H_RA_RPT, C2H_TX_REPORT,
};

/// `REG_DARFRC` (`rtl8192ee/reg.h`).
pub const REG_DARFRC: u16 = 0x0430;

/// `DESC92C_RATEMCS8..=15` (`rtl8192ee/def.h`).
pub const DESC_RATEMCS8: u8 = 0x14;
pub const DESC_RATEMCS9: u8 = 0x15;
pub const DESC_RATEMCS10: u8 = 0x16;
pub const DESC_RATEMCS11: u8 = 0x17;
pub const DESC_RATEMCS12: u8 = 0x18;
pub const DESC_RATEMCS13: u8 = 0x19;
pub const DESC_RATEMCS14: u8 = 0x1a;
pub const DESC_RATEMCS15: u8 = 0x1b;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event<'a> {
    /// `rtl_tx_report_handler` (V1): `st == 0` means acknowledged.
    TxReport { sn: u16, st: u8, retry: u8 },
    /// `rtl92ee_c2h_ra_report_handler`: `cmd_buf[0] & 0x3f` rate and
    /// `cmd_buf[3] & BIT(0)` collision state.
    RaReport { rate: u8, collision: bool },
    /// Debug, TXBF, BT and unknown ids: consumed without effect.
    Other(&'a [u8]),
}

/// Parse one C2H packet (from the RX status payload offset, the status
/// length). Linux reads `cmd_buf[3]` of an RA report unconditionally; a
/// body shorter than four bytes is refused as truncated here.
pub fn parse(packet: &[u8]) -> Result<Event<'_>, Error> {
    use super::super::rtl8821ae::c2h::Event as Core;
    Ok(match parse_core(packet)? {
        Core::TxReport { sn, st, retry } => Event::TxReport { sn, st, retry },
        Core::RaReport { .. } => {
            let body = &packet[C2H_DATA_OFFSET..];
            if body.len() < 4 {
                return Err(Error::Truncated);
            }
            Event::RaReport {
                rate: body[0] & 0x3f,
                collision: body[3] & 1 != 0,
            }
        }
        Core::Debug(b) | Core::TxBf(b) | Core::BtInfo(b) | Core::BtMp(b) => Event::Other(b),
        Core::Unknown { body, .. } => Event::Other(body),
    })
}

/// `rtl92ee_dm_dynamic_arfb_select`: the `REG_DARFRC` / `REG_DARFRC + 4`
/// dwords for a reported rate. The MCS8..=12 table applies to those rates;
/// every other rate (MCS13-15, 1SS, legacy) uses the second table.
pub const fn dynamic_arfb(rate: u8, collision: bool) -> (u32, u32) {
    if rate >= DESC_RATEMCS8 && rate <= DESC_RATEMCS12 {
        if collision {
            match rate {
                DESC_RATEMCS12 => (0, 0x0706_0501),
                DESC_RATEMCS11 => (0, 0x0707_0605),
                DESC_RATEMCS10 => (0, 0x0808_0706),
                DESC_RATEMCS9 => (0, 0x0808_0707),
                _ => (0, 0x0909_0808),
            }
        } else {
            match rate {
                DESC_RATEMCS12 => (0x0501_0000, 0x0908_0706),
                DESC_RATEMCS11 => (0x0605_0000, 0x0908_0807),
                DESC_RATEMCS10 => (0x0706_0000, 0x0a09_0908),
                DESC_RATEMCS9 => (0x0707_0000, 0x0a09_0808),
                _ => (0x0808_0000, 0x0b0a_0909),
            }
        }
    } else if collision {
        match rate {
            DESC_RATEMCS15 => (0, 0x0504_0302),
            DESC_RATEMCS14 => (0, 0x0605_0302),
            DESC_RATEMCS13 => (0, 0x0706_0502),
            _ => (0, 0x0605_0402),
        }
    } else {
        match rate {
            DESC_RATEMCS15 => (0x0302_0000, 0x0706_0504),
            DESC_RATEMCS14 => (0x0302_0000, 0x0807_0605),
            DESC_RATEMCS13 => (0x0502_0000, 0x0908_0706),
            _ => (0x0402_0000, 0x0807_0605),
        }
    }
}

/// Apply [`dynamic_arfb`] (`rtl_write_dword` low then high, as Linux).
pub fn apply_dynamic_arfb(
    io: &impl crate::rtlwifi::firmware_transport::Io,
    rate: u8,
    collision: bool,
) -> Result<(), crate::rtlwifi::firmware_transport::Error> {
    let (low, high) = dynamic_arfb(rate, collision);
    io.write32(REG_DARFRC, low)?;
    io.write32(REG_DARFRC + 4, high)
}
