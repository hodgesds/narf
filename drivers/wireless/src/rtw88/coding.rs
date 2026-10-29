// SPDX-License-Identifier: GPL-2.0-or-later
//! Separately qualified HT TX coding (`N2xC`): LDPC and STBC.
//!
//! Linux v6.12 sources:
//! - `main.c::rtw_init_ht_cap` advertises one-stream RX STBC on every chip,
//!   HT `LDPC_CODING` only with `chip->rx_ldpc` (8822B/8822C) and HT
//!   `TX_STBC` only with `chip->tx_stbc` (8822C).
//! - `main.c::rtw_update_sta_info` sets `si->ldpc_en` from the peer's HT
//!   `LDPC_CODING` and `si->stbc_en` from the peer's nonzero HT `RX_STBC`.
//! - `tx.c::rtw_tx_pkt_info_update` copies them into the data descriptor,
//!   forcing STBC off while `hal.txrx_1ss`; `tx.c::rtw_tx_fill_tx_desc`
//!   encodes `W5_DATA_LDPC` (bit7) and `W5_DATA_STBC` (bits9:8).
//! - `fw.c::rtw_fw_send_ra_info` carries `SET_RA_INFO_LDPC` (bit26).
//!
//! RX advertisement is a local decode promise and stays with the base HT
//! station. Emitting coded PPDUs changes the transmitted waveform, so it is
//! a separate continuation over the exact base. Payload byte0 holds the
//! requested TX coding (bit0 LDPC, bit1 STBC); every other byte is zero.
//! TX STBC needs two transmit paths, so RTL8821CE may request LDPC only.
use super::packet_format::DataProfile;
use super::qualification::{Kind, PAYLOAD};

pub(super) const LDPC: u8 = 1 << 0;
pub(super) const STBC: u8 = 1 << 1;

pub(super) static KIND: Kind = Kind {
    tag: b'C',
    stem: "coding",
    source: b"source main.c rtw_init_ht_cap RX_STBC1 all chips, LDPC_CODING rx_ldpc 8822B/8822C, TX_STBC tx_stbc 8822C; rtw_update_sta_info ldpc_en from peer HT LDPC_CODING, stbc_en from peer HT RX_STBC; tx.c rtw_tx_pkt_info_update stbc off when txrx_1ss; rtw_tx_fill_tx_desc W5_DATA_LDPC bit7 W5_DATA_STBC bits9:8; fw.c rtw_fw_send_ra_info RA_INFO_LDPC bit26; HT20 one stream only; payload byte0 bit0 LDPC bit1 STBC, others zero",
    admit,
};

fn admit(did: u16, p: &[u8; PAYLOAD]) -> bool {
    bounds(did, p).is_some()
}

/// Requested TX coding for `did`, or `None` if the payload is inadmissible.
pub(super) fn bounds(did: u16, p: &[u8; PAYLOAD]) -> Option<u8> {
    let flags = p[0];
    let allowed = match did {
        0xc822 => LDPC | STBC,
        0xc821 => LDPC,
        _ => return None,
    };
    (flags != 0 && flags & !allowed == 0 && p[1..].iter().all(|b| *b == 0)).then_some(flags)
}

/// Whether the qualified `flags` permit `p`'s TX coding.
pub(super) fn permits(flags: u8, p: DataProfile) -> bool {
    (!p.ldpc || flags & LDPC != 0) && (!p.stbc || flags & STBC != 0)
}

/// Locally advertised RX coding: LDPC only with source `rx_ldpc`.
pub(super) fn rx_ldpc(did: u16) -> bool {
    did == 0xc822
}

/// Source `tx.c`: coding follows the negotiated peer capability and the
/// qualified flags; `txrx_1ss` is never set because coexistence-driven
/// SMPS is not implemented, so STBC is not forced off here.
pub(super) fn apply(flags: u8, profile: DataProfile, tx_ldpc: bool, tx_stbc: bool) -> DataProfile {
    DataProfile {
        ldpc: profile.mcs != 0 && flags & LDPC != 0 && tx_ldpc,
        stbc: profile.mcs != 0 && flags & STBC != 0 && tx_stbc,
        ..profile
    }
}
