// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821AE VHT80 station profile (1T1R, 5 GHz only).
//!
//! - `base.c::_rtl_init_hw_vht_capab` (`HARDWARE_TYPE_RTL8821AE`, applied to
//!   the 5 GHz sband only): RX/TX MCS map 1SS MCS0-9 (`0xfffe`),
//!   `SHORT_GI_80`, `TXSTBC`, `RXSTBC_1`, A-MPDU length exponent 7
//!   (`MAX_A_MPDU_LENGTH_EXPONENT_MASK`). No LDPC (`sw.c` clears
//!   `vht_ldpc_cap`; `_rtl8821ae_get_ra_ldpc` never opens it). TX STBC is
//!   advertised exactly as Linux; `rtl8821ae_tx_fill_desc` never sets the
//!   descriptor STBC field, so every PPDU is sent without STBC (always
//!   permitted). RX STBC is decoded by the baseband with no driver state.
//! - Deliberate omissions, each a promise this owner does not implement:
//!   `SU_BEAMFORMER/BEAMFORMEE_CAPABLE` (no NDPA/NDP sounding or steering
//!   code exists for this chip, in Linux or here), `HTC_VHT` (no HT-control
//!   handling), `RX/TX_ANTENNA_PATTERN`, `MAX_MPDU_LENGTH_11454` (the
//!   9100-byte `prepare::RX_BUFFER` cannot hold one; 3895 is advertised) and
//!   the `rx_highest`/`tx_highest` long-GI rates (0 = "not specified").
//! - TX mapping (`rtl8821ae/trx.c::rtl8821ae_bw_mapping`/`_sc_mapping`,
//!   `base.c::_rtl_query_bandwidth_mode`, `_rtl_get_vht_highest_n_rate`).
use super::channel::data_sc80;
use super::envelope::{Operating, Permission, Width};
use narf_wireless::association::phy::{LocalPhy, LocalVht};

/// `DESC_RATEVHT1SS_MCS0` / `DESC_RATEVHT1SS_MCS9` (`wifi.h`).
pub const DESC_RATEVHT1SS_MCS0: u8 = 0x2c;
pub const DESC_RATEVHT1SS_MCS9: u8 = 0x35;
/// `DESC_RATEMCS15`: `_rtl_query_bandwidth_mode` gives an 80 MHz packet
/// only above it.
pub const DESC_RATEMCS15: u8 = 0x1b;
/// Full-order (`txpower`) bits of VHT 1SS MCS0-9.
pub const VHT1SS_ORDER: u64 = 0x3ff << 28;
/// `IEEE80211_VHT_MCS_SUPPORT_0_9` for 1SS, others not supported.
pub const MCS_MAP: u16 = 0xfffe;

/// `_rtl_init_hw_vht_capab` for the 1T1R 8821AE (see the module note).
pub fn capability() -> LocalVht {
    LocalVht::new(MCS_MAP, MCS_MAP, true, true, 7)
        .expect("fixed 8821AE 1T1R VHT capability")
        .with_tx_stbc(true)
        .with_rx_stbc(true)
}

/// The VHT80 local PHY: the HT20/40 profile plus [`capability`].
pub fn local() -> LocalPhy {
    LocalPhy::vht80(super::ht::capability(true), capability()).expect("fixed 8821AE VHT80")
}

/// The full-order TXAGC bit of a descriptor rate (`DESC_RATE1M` ..
/// `DESC_RATEMCS15` map to themselves, `DESC_RATEVHT1SS_MCS0..9` to
/// 28..=37); `None` for a rate this 1T1R station never puts on air.
pub fn order(rate: u8) -> Option<u8> {
    match rate {
        0..=DESC_RATEMCS15 => Some(rate),
        DESC_RATEVHT1SS_MCS0..=DESC_RATEVHT1SS_MCS9 => Some(rate - DESC_RATEVHT1SS_MCS0 + 28),
        _ => None,
    }
}

/// [`Permission::admits`] for a descriptor rate.
pub fn admits(permission: &Permission, rate: u8) -> bool {
    order(rate).is_some_and(|bit| permission.admits(bit))
}

/// VHT80 is admitted only on an 80 MHz 5 GHz permission that holds a
/// measured index for every rate an AC_5G RA mask can name (6 Mb/s and
/// VHT 1SS MCS0-9 at 80 MHz) and for the HT MCS0-7 of the HT fallback, so
/// the installed mask is always a subset of the admitted set.
pub fn admitted(permission: &Permission) -> bool {
    let op = permission.operating();
    op.width == Width::W80
        && permission.admitted_rates() & VHT1SS_ORDER == VHT1SS_ORDER
        && super::ht::admitted(permission)
}

/// `_rtl_get_vht_highest_n_rate` (1T1R branch) on mac80211's intersected
/// `vht_mcs.tx_mcs_map` (the peer's TX map within our RX map).
pub fn highest_rate(sta_tx_map: u16) -> u8 {
    match sta_tx_map & 3 {
        0 => DESC_RATEVHT1SS_MCS0 + 7,
        1 => DESC_RATEVHT1SS_MCS0 + 8,
        _ => DESC_RATEVHT1SS_MCS9,
    }
}

/// mac80211's per-NSS minimum of two VHT MCS maps
/// (`ieee80211_vht_cap_ie_to_sta_vht_cap`).
pub fn intersect(own: u16, peer: u16) -> u16 {
    let mut map = 0;
    for nss in 0..8 {
        let (a, b) = ((own >> (2 * nss)) & 3, (peer >> (2 * nss)) & 3);
        let v = if a == 3 || b == 3 { 3 } else { a.min(b) };
        map |= v << (2 * nss);
    }
    map
}

/// Packet bandwidth on an 80 MHz channel (`_rtl_query_bandwidth_mode` then
/// `rtl8821ae_bw_mapping`, `current_chan_bw` 80): 2 for unicast above
/// MCS15, 1 for unicast above 54M, 0 otherwise.
pub fn data_bw(hw_rate: u8, multicast: bool) -> u8 {
    if multicast || hw_rate <= super::trx::DESC_RATE54M {
        0
    } else if hw_rate > DESC_RATEMCS15 {
        2
    } else {
        1
    }
}

/// `rtl8821ae_sc_mapping` at `current_chan_bw` 80 for `data_bw`: 80 MHz
/// don't-care, 40 MHz the primary 40 of the 80 (`cur_80_prime_sc`), 20
/// MHz the primary 20 (`cur_40_prime_sc` x `cur_80_prime_sc`); the same
/// nibbles `channel::data_sc80` programs into `REG_DATA_SC`.
pub fn sub_carrier(op: &Operating, data_bw: u8) -> Option<u8> {
    let wide = op.wide_channel()?;
    let sc = data_sc80((op.channel + 6).checked_sub(wide)? / 4)?;
    Some(match data_bw {
        2 => 0,
        1 => sc >> 4,
        _ => sc & 0xf,
    })
}
