// SPDX-License-Identifier: GPL-2.0-or-later
//! Separately qualified 5GHz VHT80 record (`N2xV`) and its 80MHz program.
//!
//! Record format, factory/regulatory admission, the Linux
//! `rtw_set_channel(center, BW80, sc)` program with the record's VHT TX
//! power, and the station-side pieces (`rtw_init_vht_cap` narrowed to the
//! record, VHT Operation parsing). The station binds it over the HT program
//! for an 80MHz BSS (`station.rs::associate`); VHT DATA then uses
//! `DataProfile::vht` (RA VHT rate ids/mask, BW_MODE 2, descriptor BW 2).
//!
//! Linux 7.3-rc4 sources:
//! - `main.c::rtw_update_channel`: 80MHz `primary_channel_idx`
//!   `RTW_SC_20_UPPER` (1) / `UPMOST` (3) above the center, `LOWER` (2) /
//!   `LOWEST` (4) below (`band5::sc80`).
//! - `rtw8822c.c::rtw8822c_set_channel_bb` BW80 (TXBWCTL 0xa / sc, SBD 6,
//!   PT_OPT 1), `_rf` RF18 BW80 bit12 RXBB 0x8; `rtw8821c.c` BW80 `set_bw`
//!   (ADCCLK `&0xfcffcf00 | 0x40040000 | sc<<2 | 2`), `_rf` BW80 bit10,
//!   `_rxdfir` BW80; `mac.c::rtw_set_channel_mac` DATA_SC with
//!   `RTW_SC_40_UPPER`/`LOWER` and RFMOD_80M.
//! - `phy.c::rtw_phy_get_5g_tx_power_index` at BW80: the average of
//!   `bw40_base[group]` and `[group + 1]` of the center's group plus
//!   `vht_1s_diff.bw80` (+ `vht_2s_diff.bw80`) times `txgi_factor`
//!   (`band5::Power5g::bw80`).
//! - `rtw8822c.c::rtw8822c_set_tx_power_diff` (0x3a00 + rate, 7-bit signed
//!   difference from the MCS7 reference); `rtw8821c.c::
//!   rtw8821c_set_tx_power_index_by_rate` (0x1d00 + rate, four indices per
//!   word; VHT1SS MCS0..9 at 0x1d2c..0x1d35).
//!
//! Payload (bytes 56..120 of the generic 128-byte continuation):
//!
//! | Bytes | Field |
//! |---|---|
//! | 0 | primary (5GHz 20MHz primary inside an 80MHz block) |
//! | 1 | center = `band5::center80(primary)` |
//! | 2 | width 80 (MHz) |
//! | 3 | flags: bit0 SGI80 |
//! | 4..6 | antenna gain, quarter dBi |
//! | 6..8 | qualified EIRP ceiling, quarter dBm |
//! | 8..14 | measured 80MHz peaks (IQK/calibration, response, data), quarter dBm |
//! | 14 | spatial streams 1 or 2 (C21 1) |
//! | 15 | highest VHT MCS 7, 8 or 9 (`IEEE80211_VHT_MCS_SUPPORT_0_{7,8,9}`) |
//! | 16..26 | VHT80 TXAGC index for 1SS MCS0..9 (zero above the highest) |
//! | 26..36 | VHT80 TXAGC index for 2SS MCS0..9 (zero for one stream; B22 path A) |
//! | 36..46 | B22 only: path-B VHT80 2SS MCS0..9 (zero for one stream) |
//! | 46..64 | zero (36..64 on C21/C22) |
//!
//! RTL8822BE (`N2BV`): `rtw8822b_set_channel(center80, BW80, sc)`
//! (`radio8822b::set_channel`), `rtw8822b_set_tx_power_index_by_rate`
//! absolute per-path words 0x1d00/0x1d80 (legacy12 at the bound 5GHz `N2BO`
//! indices, HT words zero as on C22, path-A VHT1SS MCS0..9 at 0x2c..0x35,
//! both paths' VHT2SS at 0x36..0x3f; path-B VHT1SS zero, 1SS transmits on A
//! under `config_trx_mode(AB, AB, false)`), then `rtw8822b_do_iqk`.
//! Ceilings are both paths' `band5::Power5g::bw80` at `txgi_factor` 1.
use super::{
    band5::{self, Width},
    firmware_transport::{Error, Io},
    power_policy::Gate,
    qualification::{Kind, PAYLOAD},
};
use narf_wireless::reg::RegulatoryDomain;

pub(super) static KIND: Kind = Kind {
    tag: b'V',
    stem: "vht80",
    source: b"Linux 7.3-rc4 rtw88 5GHz VHT80: main.c rtw_update_channel 80MHz sc UPPER1/LOWER2/UPMOST3/LOWEST4; rtw8822c.c rtw8822c_set_channel_bb 5G head of the center80 BW80 TXBWCTL0x9b0 0xa/c0=0/ff00=sc|sc<<4 SBD0x88c 6 PT_OPT0xcbc[21]1, rtw8822c_set_channel_rf RF18 BW80 bit12 rxbb0x8, rtw8822c_toggle_igi; rtw8821c.c rtw8821c_set_channel_bb 5G head of the center80 BW80 ADCCLK0x8ac fcffcf00|40040000|sc<<2|2 ADC160[30]1, _bb_swing 5G, _rf WLA LUTDBG0 RF18 BW80 bit10 XTALX2 toggle, _rxdfir BW80 ACBBRXFIR1 TXDFIR0 CHFIR1; mac.c rtw_set_channel_mac DATA_SC txsc20|txsc40(9/10)<<4 RFMOD_80M; phy.c rtw_phy_get_5g_tx_power_index BW80 avg(bw40_base[g],bw40_base[g+1]) + vht_1s_diff.bw80 (+ vht_2s_diff.bw80) * factor; rtw8822c_set_tx_power_diff 0x3a00+rate VHT 0x2c..0x3f relative to MCS7 reference, OFDM at the N2xO 5GHz selection; rtw8821c_set_tx_power_index_by_rate 0x1d2c..0x1d34; RRSR_INIT_5G OFDM6 0x10; all four 20MHz constituents admitted; DFS/NO_IR span passive on every constituent with every constituent beacon-witnessed; record 80MHz envelope",
    admit,
};

/// RTL8822BE `N2BV` program contract, hashed into every B22 N2xV request in
/// addition to the shared kind source.
pub(super) const SOURCE8822B: &[u8] = b"RTL8822BE N2BV: rtw8822b.c rtw8822b_set_channel(center80, BW80, sc) = _bb 5G BW80 ADCCLK0x8ac fcefcf00|sc<<2|2 ADC160[30]1 rfe2/3 0x840[15:12]6 0x8c8[10]1, rtw_set_channel_mac DATA_SC0x483 txsc20|txsc40<<4 RFMOD_80M 0x668[8], _rf RF18 A+B BW80 bit10 RFSI, _rxdfir BW80, toggle_igi, _cca, _rfe; rtw8822b_set_tx_power_index_by_rate 1d00/1d80 absolute: legacy12 at the bound 5GHz N2BO indices (CCK zero), HT words zero, path-A VHT1SS MCS0..9 0x2c..0x35, path-A/B VHT2SS 0x36..0x3f, path-B VHT1SS zero; rtw8822b_do_iqk clear0 segment0; ceilings both paths avg(bw40_base[g],[g+1]) + vht_1s_diff.bw80 (+ vht_2s_diff.bw80), txgi 1, max 0x3f; RRSR_INIT_5G OFDM6 0x10; readback RF18 A+B 8ac 483 668 RRSR TXAGC";

/// Decoded N2xV payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Record {
    pub(super) primary: u8,
    pub(super) center: u8,
    pub(super) sgi: bool,
    pub(super) antenna: i16,
    pub(super) ceiling: i16,
    pub(super) peaks: [i16; 3],
    pub(super) streams: u8,
    pub(super) max_mcs: u8,
    /// 1SS MCS0..9 then 2SS MCS0..9.
    pub(super) indices: [u8; 20],
    /// B22 path-B 2SS MCS0..9 (zero on C21/C22).
    pub(super) indices_b: [u8; 10],
}

impl Record {
    pub(super) fn decode(did: u16, p: &[u8; PAYLOAD]) -> Option<Self> {
        let signed = |at: usize| i16::from_le_bytes([p[at], p[at + 1]]);
        let record = Self {
            primary: p[0],
            center: p[1],
            sgi: p[3] & 1 != 0,
            antenna: signed(4),
            ceiling: signed(6),
            peaks: [signed(8), signed(10), signed(12)],
            streams: p[14],
            max_mcs: p[15],
            indices: p[16..36].try_into().ok()?,
            indices_b: p[36..46].try_into().ok()?,
        };
        let (max, streams, tail) = match did {
            0xc822 => (127, 2, 36),
            0xc821 => (63, 1, 36),
            // rtw8822b_hw_spec.max_power_index 0x3f, absolute per-path index.
            0xb822 => (63, 2, 46),
            _ => return None,
        };
        let used =
            |i: usize| i % 10 <= usize::from(record.max_mcs) && i / 10 < record.streams.into();
        let unused_zero = (0..20).all(|i| used(i) || record.indices[i] == 0)
            && (0..10).all(|i| used(10 + i) || record.indices_b[i] == 0);
        // rtw8822c_set_tx_power_diff: 7-bit signed difference from the
        // reference (VHT1SS MCS7 here).
        let reference = i16::from(record.indices[7]);
        let c22_reference = did != 0xc822
            || record.indices[7] <= 64
                && (0..20).all(|i| {
                    !used(i) || (-64..=63).contains(&(i16::from(record.indices[i]) - reference))
                });
        (band5::center80(record.primary) == Some(record.center)
            && p[2] == 80
            && p[3] & !1 == 0
            && (1..=streams).contains(&record.streams)
            && (7..=9).contains(&record.max_mcs)
            && (0..=128).contains(&record.antenna)
            && (-512..=256).contains(&record.ceiling)
            && record.peaks.iter().all(|v| (-512..=256).contains(v))
            && record
                .indices
                .iter()
                .chain(&record.indices_b)
                .all(|i| *i <= max)
            && unused_zero
            && c22_reference
            && p[tail..].iter().all(|b| *b == 0))
        .then_some(record)
    }
    /// `rtw_update_channel` 80MHz sub-channel index.
    pub(super) fn sc(&self) -> u8 {
        band5::sc80(self.primary, self.center)
    }
    pub(super) fn width(&self) -> Width {
        Width::Eighty(self.sc())
    }
    /// The record's VHT TX selection in the `get_vht_ra_mask` layout
    /// (`VhtRates::tx`): MCS0..`max_mcs` on each qualified stream.
    pub(super) fn tx_mask(&self) -> u32 {
        let group = 0x3ff >> (9 - self.max_mcs);
        (0..u32::from(self.streams)).fold(0, |m, s| m | group << (10 * s))
    }
    /// The VHT TX MCS map advertised for the record (`rtw_init_vht_cap`
    /// narrowed to the qualified streams and highest MCS).
    pub(super) fn tx_map(&self) -> u16 {
        mcs_map(self.streams, self.max_mcs - 7)
    }
    /// The four 20MHz constituents' center frequencies.
    pub(super) fn constituents(&self) -> Option<[u16; 4]> {
        let c = band5::constituents80(self.center);
        Some([
            band5::frequency(c[0])?,
            band5::frequency(c[1])?,
            band5::frequency(c[2])?,
            band5::frequency(c[3])?,
        ])
    }
}

/// A VHT MCS map with `streams` streams at support code `code`
/// (0: MCS0..7, 1: 0..8, 2: 0..9) and the rest `NOT_SUPPORTED`.
fn mcs_map(streams: u8, code: u8) -> u16 {
    (0..8).fold(0, |m, s| {
        m | (if s < streams { u16::from(code) } else { 3 }) << (2 * s)
    })
}

/// `rtw_init_vht_cap` RX MCS map: MCS0..9 on each of `streams` streams.
pub(super) fn rx_map(streams: u8) -> u16 {
    mcs_map(streams, 2)
}

/// `rtw_init_vht_cap` for the bound N2xV association: SGI80 (RX always,
/// TX per the record), RX STBC, RX LDPC per chip (`rtw_chip_has_rx_ldpc`),
/// A-MPDU exponent 0 like the HT capability, maximum MPDU 3895, MCS0..9 RX
/// on the HT program's streams and the record's TX selection, and SU and MU
/// beamformee with `hal.bfee_sts_cap` (`bf.rs`, including VHT Group ID
/// Management -> `rtw_bf_set_gid_table`). TX STBC, TX LDPC and HTC-VHT are
/// not advertised (no separately qualified VHT coding program).
pub(super) fn local(
    did: u16,
    streams: u8,
    record: &Record,
) -> Option<narf_wireless::association::phy::LocalVht> {
    narf_wireless::association::phy::LocalVht::new(
        rx_map(streams),
        record.tx_map(),
        true,
        record.sgi,
        0,
    )
    .ok()
    .and_then(|v| {
        v.with_rx_stbc(true)
            .with_ldpc(super::coding::rx_ldpc(did), false)
            .with_beamforming(narf_wireless::association::phy::VhtBeamforming {
                su_beamformee_sts: Some(super::bf::BFEE_STS),
                su_beamformer_sounding: None,
                mu_beamformee: true,
            })
            .ok()
    })
}

/// Wiphy 5GHz (HT Capabilities, optional VHT Capabilities) bodies.
pub(super) type Band5Capability = ([u8; 26], Option<[u8; 12]>);

/// Wiphy 5GHz capability bodies (`firmware_transport::Io::
/// station_band5_capability`) the station offers on admitted 5GHz primary
/// `channel` over the current station gate `current`. `grant` is the
/// backend's `station_channel_grant` (signed N2xO admission per primary).
///
/// Mirrors `Station::associate` exactly: the gate `retune` installs on the
/// primary (`Gate::with_channel` over the base-only gate), the band-5 N2xL
/// extension of exactly this primary with WMM, its N2xH HT program, and
/// VHT80 only when the firmware bandwidth `hardware_allows` 80MHz, the
/// primary's Annex E block has every other constituent admitted and a
/// loadable N2xV record names this primary and block. Linux main.c
/// `rtw_init_ht_cap`/`rtw_init_vht_cap` advertise the same elements on the
/// 5GHz sband; NARF narrows them to the qualified station offer.
pub(super) fn band5_capability(
    current: &Gate,
    channel: u8,
    mut grant: impl FnMut(u8) -> Result<Option<alloc::sync::Arc<super::qualification::Grant>>, Error>,
) -> Result<Option<Band5Capability>, Error> {
    if !band5::primary(channel) {
        return Ok(None);
    }
    let Some(record) = grant(channel)? else {
        return Ok(None);
    };
    let gate = current.without_channel().with_channel(record)?;
    let Some(extension) = gate
        .extension_request()
        .and_then(|_| {
            super::station_profile::Source::Registered
                .load(gate.clone())
                .ok()
        })
        .filter(|g| g.band5() && g.channel() == channel && g.wmm())
    else {
        return Ok(None);
    };
    let Some(ht) = super::ht::Source::Registered.load(extension).ok() else {
        return Ok(None);
    };
    let vht = match (
        gate.ht_facts()
            .is_some_and(|f| hardware_allows(f.hardware.bandwidth)),
        band5::center80(channel),
    ) {
        (true, Some(center)) => {
            let mut admitted = true;
            for c in band5::constituents80(center) {
                if c != channel && grant(c)?.is_none() {
                    admitted = false;
                    break;
                }
            }
            if admitted {
                super::qualification::Source::Registered
                    .load(&KIND, &gate)
                    .ok()
                    .and_then(|g| {
                        let r = Record::decode(gate.did(), g.payload())?;
                        (g.matches(&gate) && r.primary == channel && r.center == center)
                            .then_some(r)
                    })
                    .and_then(|r| ht.vht80_capability(&r))
            } else {
                None
            }
        }
        _ => None,
    };
    Ok(match vht {
        Some((ht, vht)) => Some((ht, Some(vht))),
        None => ht.ht20_capability().map(|ht| (ht, None)),
    })
}

/// VHT Operation element (192) in `ies`: `(channel width, CCFS0, CCFS1)`.
/// Channel width 1 with CCFS0 the 80MHz center is an 80MHz (or wider,
/// CCFS1 nonzero) BSS. `None` if absent or malformed.
pub(super) fn vht_operation(ies: &[u8]) -> Option<(u8, u8, u8)> {
    let mut at = 0;
    while at + 2 <= ies.len() {
        let len = usize::from(ies[at + 1]);
        let body = ies.get(at + 2..at + 2 + len)?;
        if ies[at] == 192 && len == 5 {
            return Some((body[0], body[1], body[2]));
        }
        at += 2 + len;
    }
    None
}

/// Live check of a bound N2xV record under the installed regulatory domain.
pub(super) fn current(g: &super::qualification::Grant, gate: &Gate) -> Result<(), Error> {
    let domain = narf_wireless::reg::db::get_domain().ok_or(Error::Prerequisite)?;
    current_in(g, gate, &domain)
}

fn admit(did: u16, p: &[u8; PAYLOAD]) -> bool {
    Record::decode(did, p).is_some()
}

/// `main.c::hw_bw_cap_to_bitamp`: only `EFUSE_HW_CAP_IGNORE` (0) and
/// `SUPP_BW80` (7) include 80MHz.
pub(super) fn hardware_allows(bandwidth: u8) -> bool {
    matches!(bandwidth, 0 | 7)
}

/// Factory BW80 VHT ceilings `(1S, 2S)` of the center's 5GHz group
/// (`Gate::vht80_limits`) must enclose every qualified index. On C22 the
/// gate's 5GHz N2xO OFDM selection must also stay within the signed 7-bit
/// difference of the reference.
pub(super) fn within_factory(gate: &Gate, record: &Record) -> bool {
    if gate.channel() != record.primary {
        return false;
    }
    let Some((one, two)) = gate.vht80_limits(record.center) else {
        return false;
    };
    if gate.did() == 0xc822 {
        let Some(ofdm) = gate.ofdm5_indices() else {
            return false;
        };
        let reference = i16::from(record.indices[7]);
        if ofdm
            .iter()
            .any(|v| !(-64..=63).contains(&(i16::from(*v) - reference)))
        {
            return false;
        }
    }
    record.indices.iter().enumerate().all(|(i, v)| {
        if i < 10 {
            *v <= one
        } else {
            *v == 0 || two.is_some_and(|two| *v <= two)
        }
    }) && record
        .indices_b
        .iter()
        .all(|v| *v == 0 || two.is_some_and(|two| *v <= two))
}

/// B22 per-path DESC_RATE 0x00..0x3f table at BW80 (`rtw8822b_set_tx_power_index_by_rate`):
/// `legacy` (the 5GHz primary's legacy12, CCK zero), HT zero, path-A VHT1SS
/// MCS0..9 and, for two streams, VHT2SS per path. HT3S/HT4S (words 7..10)
/// are never written ([`super::radio8822b::write_txagc`]).
pub(super) fn b22_tables(legacy: [[u8; 12]; 2], record: &Record) -> [[u8; 64]; 2] {
    core::array::from_fn(|path| {
        let mut rates = [0u8; 64];
        rates[..12].copy_from_slice(&legacy[path]);
        if path == 0 {
            rates[0x2c..0x36].copy_from_slice(&record.indices[..10]);
            rates[0x36..].copy_from_slice(&record.indices[10..]);
        } else {
            rates[0x36..].copy_from_slice(&record.indices_b);
        }
        rates
    })
}

/// B22 [`program`]: `rtw_set_channel(center80, BW80, sc)`, the VHT80 TX
/// power level over both paths, `rtw8822b_do_iqk`, then the RF18/BB/MAC,
/// TXAGC and RRSR 0x10 readbacks.
async fn program8822b(io: &mut impl Io, gate: &Gate, record: &Record) -> Result<(), Error> {
    let phy = gate.b22_phy().ok_or(Error::State)?;
    let legacy = gate.b22_indices().ok_or(Error::State)?;
    if legacy.iter().any(|path| path[..4] != [0; 4]) {
        return Err(Error::State);
    }
    let tables = b22_tables(legacy, record);
    super::radio8822b::set_channel(io, phy, record.center, record.width()).await?;
    for (path, table) in tables.iter().enumerate() {
        super::radio8822b::write_txagc(io, path as u8, table).await?;
    }
    super::channel_policy::iqk8822b(io).await?;
    super::radio8822b::verify_channel(io, record.center, record.width()).await?;
    super::radio8822b::verify_txagc(io, tables).await?;
    if super::radio::read(io, 0x440).await? != super::radio::RRSR_OFDM6_5G {
        return Err(Error::Prerequisite);
    }
    Ok(())
}

/// Regulatory admission of the 80MHz span (`center +/- 40MHz`): every
/// overlapping rule is plain or passive (`channel_policy::passive_rule` at
/// 80MHz), one rule covers the span, every measured peak plus antenna gain
/// fits the minimum ceiling; a passive span needs all four 20MHz
/// constituents passive-only (no mixed span). Returns `(ceiling, passive)`.
pub(super) fn admission(record: &Record, domain: &RegulatoryDomain) -> Result<(i16, bool), Error> {
    let center = u32::from(band5::frequency(record.center).ok_or(Error::Unsupported)?);
    let (low, high) = (center - 40, center + 40);
    if !domain.country_code.iter().all(u8::is_ascii_uppercase) {
        return Err(Error::Prerequisite);
    }
    let mut limit = record.ceiling.min(80);
    let mut covering = false;
    let mut passive = false;
    for (i, r) in domain.rules.iter().enumerate() {
        if r.freq_start_mhz >= high || r.freq_end_mhz <= low {
            continue;
        }
        passive |= super::channel_policy::passive_rule(domain, i, 80).ok_or(Error::Prerequisite)?;
        covering |= r.freq_start_mhz <= low && r.freq_end_mhz >= high;
        limit = limit.min(i16::from(r.max_power_dbm) * 4);
    }
    if passive
        && !record
            .constituents()
            .ok_or(Error::Unsupported)?
            .iter()
            .all(|c| narf_wireless::reg::witness::passive_only(domain, *c))
    {
        return Err(Error::Prerequisite);
    }
    if !covering
        || record
            .peaks
            .iter()
            .any(|p| i32::from(*p) + i32::from(record.antenna) > i32::from(limit))
    {
        return Err(Error::Prerequisite);
    }
    Ok((limit, passive))
}

/// Live check of a bound N2xV record against `domain` under its own
/// capability and the current base gate.
pub(super) fn current_in(
    g: &super::qualification::Grant,
    gate: &Gate,
    domain: &RegulatoryDomain,
) -> Result<(), Error> {
    g.invoke_source(|| {
        let record = Record::decode(gate.did(), g.payload()).ok_or(Error::State)?;
        if !g.is(&KIND) || !within_factory(gate, &record) {
            return Err(Error::State);
        }
        admission(&record, domain).map(|_| ())
    })
}

/// C22 difference words 0x3a00..0x3a3c: CCK zero, OFDM at the N2xO 5GHz
/// selection, HT unused (index 0) and VHT1SS/2SS (rates 0x2c..0x3f) from
/// the record, all relative to the reference.
fn words(record: &Record, ofdm: [u8; 8]) -> [u32; 16] {
    let mut bytes = [0u8; 64];
    let reference = i16::from(record.indices[7]);
    for (rate, b) in bytes.iter_mut().enumerate() {
        let index = match rate {
            4..=11 => i16::from(ofdm[rate - 4]),
            0x2c..=0x3f => i16::from(record.indices[rate - 0x2c]),
            _ => 0,
        };
        *b = if rate < 4 {
            0
        } else {
            ((index - reference) as i8 as u8) & 127
        };
    }
    core::array::from_fn(|i| u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap()))
}

/// C21 VHT words 0x1d2c, 0x1d30, 0x1d34 (rates 0x2c..0x37; the two 2SS
/// bytes stay zero on the one-stream chip).
fn words8821c(record: &Record) -> [u32; 3] {
    let mut bytes = [0u8; 12];
    bytes[..10].copy_from_slice(&record.indices[..10]);
    core::array::from_fn(|i| u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap()))
}

/// Program the record's VHT80 TXAGC (`rtw_phy_set_tx_power_level` at BW80).
pub(super) async fn write_power(
    io: &mut impl Io,
    did: u16,
    record: &Record,
    ofdm: Option<[u8; 8]>,
) -> Result<(), Error> {
    match did {
        0xc822 => {
            let ofdm = ofdm.ok_or(Error::State)?;
            for r in [0x18e8, 0x41e8] {
                super::radio::mask(io, 0x1c90, 1 << 15, 0).await?;
                super::radio::mask(io, r, 0x1fc00, u32::from(record.indices[7])).await?;
            }
            for (i, v) in words(record, ofdm).into_iter().enumerate() {
                super::radio::mask(io, 0x1c90, 1 << 15, 0).await?;
                io.write32(0x3a00 + i as u16 * 4, v).await?;
            }
            Ok(())
        }
        0xc821 => {
            for (i, v) in words8821c(record).into_iter().enumerate() {
                io.write32(0x1d2c + i as u16 * 4, v).await?;
            }
            Ok(())
        }
        _ => Err(Error::Unsupported),
    }
}

/// Readback of [`write_power`] over any register view.
pub(super) async fn check_power(
    read: &mut impl super::firmware_transport::Read32,
    did: u16,
    record: &Record,
    ofdm: Option<[u8; 8]>,
) -> Result<(), Error> {
    match did {
        0xc822 => {
            let ofdm = ofdm.ok_or(Error::State)?;
            for r in [0x18e8, 0x41e8] {
                if read.read32(r).await? & 0x1fc00 != u32::from(record.indices[7]) << 10 {
                    return Err(Error::Prerequisite);
                }
            }
            for (i, v) in words(record, ofdm).into_iter().enumerate() {
                if read.read32(0x3a00 + i as u16 * 4).await? != v {
                    return Err(Error::Prerequisite);
                }
            }
            Ok(())
        }
        0xc821 => {
            for (i, v) in words8821c(record).into_iter().enumerate() {
                if read.read32(0x1d2c + i as u16 * 4).await? != v {
                    return Err(Error::Prerequisite);
                }
            }
            Ok(())
        }
        _ => Err(Error::Unsupported),
    }
}

/// `rtw_set_channel(center80, BW80, sc)` + IQK + VHT80 TX power on a
/// quiet, drained gate bound to the record's primary (5GHz N2xO).
pub(super) async fn program(io: &mut impl Io, gate: &Gate, record: &Record) -> Result<(), Error> {
    if gate.did() == 0xb822 {
        return program8822b(io, gate, record).await;
    }
    let (did, center, width) = (gate.did(), record.center, record.width());
    let rrsr = super::radio::RRSR_OFDM6_5G;
    match did {
        0xc822 => {
            let (ofdm, diffs) = gate.ofdm5().ok_or(Error::State)?;
            let indices = gate.ofdm5_indices().ok_or(Error::State)?;
            super::radio::wide5_to(io, center, width).await?;
            super::radio::ofdm5(io, ofdm, diffs).await?;
            super::channel_policy::iqk8822c_run(io).await?;
            super::radio::ofdm5(io, ofdm, diffs).await?;
            write_power(io, did, record, Some(indices)).await?;
            super::radio::verify_wide5(io, center, width).await?;
            check_power(
                &mut super::firmware_transport::RadioRead32(io),
                did,
                record,
                Some(indices),
            )
            .await?;
        }
        0xc821 => {
            let facts = gate.band_facts().ok_or(Error::State)?;
            super::radio8821c::wide5(io, center, width, &facts).await?;
            super::channel_policy::iqk8821c(io).await?;
            write_power(io, did, record, None).await?;
            super::radio8821c::verify_wide5(io, center, width, &facts).await?;
            check_power(
                &mut super::firmware_transport::RadioRead32(io),
                did,
                record,
                None,
            )
            .await?;
        }
        _ => return Err(Error::Unsupported),
    }
    if super::radio::read(io, 0x440).await? != rrsr {
        return Err(Error::Prerequisite);
    }
    Ok(())
}
