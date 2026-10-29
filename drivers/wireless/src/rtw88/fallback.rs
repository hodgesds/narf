// SPDX-License-Identifier: GPL-2.0-or-later
//! Separately qualified DATA rate fallback (`N2xF`).
//!
//! Linux v7.2 sources:
//! - `tx.c::rtw_tx_pkt_info_update`/`rtw_tx_data_pkt_info_update`: a
//!   station DATA frame leaves `use_rate` and `dis_rate_fallback` false
//!   (only `dm_info->fix_rate` forces both), so firmware RA picks and
//!   falls back from the highest rate. Management frames keep the fixed
//!   CCK1/OFDM6 rate with both bits set (`rtw_tx_mgmt_pkt_info_update`).
//! - `tx.c::rtw_tx_fill_tx_desc`: `RTW_TX_DESC_W3_USE_RATE` (bit 8) and
//!   `RTW_TX_DESC_W3_DISDATAFB` (bit 10).
//! - `fw.c::rtw_fw_send_ra_info`: the RA mask (`SET_RA_INFO_RA_MASK0..3`)
//!   with `DIS_RA` clear, which `wmm.rs::ra_info` already sends.
//!
//! The base programs transmit every DATA frame at one fixed rate.
//! Allowing the firmware to step down changes the emitted rate set over
//! time, so it is a separate continuation over the exact base. Payload
//! byte0 is 1; every other byte is zero.
use super::qualification::{Kind, PAYLOAD};

pub(super) static KIND: Kind = Kind {
    tag: b'F',
    stem: "fallback",
    source: b"source tx.c rtw_tx_pkt_info_update station DATA use_rate=false dis_rate_fallback=false unless dm fix_rate; mgmt use_rate dis_rate_fallback fixed; rtw_tx_fill_tx_desc W3_USE_RATE bit8 W3_DISDATAFB bit10; fw.c rtw_fw_send_ra_info RA_MASK0..3 with DIS_RA clear; firmware RA falls back within the bound rate mask; payload byte0 1, others zero",
    admit,
};

fn admit(did: u16, p: &[u8; PAYLOAD]) -> bool {
    matches!(did, 0xc821 | 0xc822) && bounds(p)
}

/// Whether the payload is the one admissible N2xF record body.
pub(super) fn bounds(p: &[u8; PAYLOAD]) -> bool {
    p[0] == 1 && p[1..].iter().all(|b| *b == 0)
}
