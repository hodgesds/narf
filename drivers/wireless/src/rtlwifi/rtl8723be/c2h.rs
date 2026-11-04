// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8723BE firmware-to-host (C2H) packets.
//!
//! An RX status with `rpt_sel != 0` is `C2H_PACKET`
//! (`rtl8723be_rx_query_desc`), queued by `pci.c` to `rtl_c2hcmd_enqueue`
//! → `base.c::rtl_c2h_content_parsing`. The id/body layout and the V1 TX
//! report (the 8723BE `rtl_hal_cfg` has no `spec_ver`) are the core ones
//! shared with RTL8821AE ([`super::super::rtl8821ae::c2h::parse`]).
//!
//! - `C2H_BT_INFO` → `btc_btinfo_notify` and `C2H_BT_MP` →
//!   `btc_btmpinfo_notify`: `get_btc_status()` is always true on this chip,
//!   so both bodies are handed to the coexistence owner unchanged
//!   (`rtl_c2h_fast_cmd` also takes `C2H_BT_MP` inline rather than through
//!   the C2H work queue).
//! - `C2H_RA_RPT`: the 8723BE `rtl_hal_ops` has no
//!   `c2h_ra_report_handler`, so the report is consumed without effect and
//!   its body is not read.
//! - Debug, TXBF and unknown ids are consumed without effect.

pub use super::super::rtl8821ae::c2h::{
    parse as parse_core, Error, TxReportState, C2H_BT_INFO, C2H_BT_MP, C2H_DATA_OFFSET, C2H_RA_RPT,
    C2H_TX_REPORT,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event<'a> {
    /// `rtl_tx_report_handler` (V1): `st == 0` means acknowledged.
    TxReport { sn: u16, st: u8, retry: u8 },
    /// `btc_btinfo_notify(cmd_buf, cmd_len)`.
    BtInfo(&'a [u8]),
    /// `btc_btmpinfo_notify(cmd_buf, cmd_len)`.
    BtMp(&'a [u8]),
    /// RA report, debug, TXBF and unknown ids: consumed without effect.
    Other(&'a [u8]),
}

/// Parse one C2H packet (from the RX status payload offset, the status
/// length).
pub fn parse(packet: &[u8]) -> Result<Event<'_>, Error> {
    use super::super::rtl8821ae::c2h::Event as Core;
    if packet.len() < C2H_DATA_OFFSET {
        return Err(Error::Truncated);
    }
    if packet[0] == C2H_RA_RPT {
        return Ok(Event::Other(&packet[C2H_DATA_OFFSET..]));
    }
    Ok(match parse_core(packet)? {
        Core::TxReport { sn, st, retry } => Event::TxReport { sn, st, retry },
        Core::BtInfo(b) => Event::BtInfo(b),
        Core::BtMp(b) => Event::BtMp(b),
        Core::RaReport { .. } => Event::Other(&packet[C2H_DATA_OFFSET..]),
        Core::Debug(b) | Core::TxBf(b) => Event::Other(b),
        Core::Unknown { body, .. } => Event::Other(body),
    })
}
