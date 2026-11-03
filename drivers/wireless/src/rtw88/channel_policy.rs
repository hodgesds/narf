// SPDX-License-Identifier: GPL-2.0-or-later
//! Noninitial 2.4GHz/20MHz operating channels for the retained C21/C22
//! station: per-channel Linux programs, a separately signed per-channel
//! N2xO record over the exact base qualification, and the retune sequence.
//!
//! Linux 7.3-rc4 `rtw88/main.c::rtw_set_channel` runs the chip
//! `set_channel` (`rtw8822c.c::rtw8822c_set_channel` = `_bb`, `rtw_set_channel_mac`,
//! `_rf`, `rtw8822c_toggle_igi`; `rtw8821c.c::rtw8821c_set_channel` = `_bb`,
//! `rtw_set_channel_mac`, `_rf`, `_rxdfir`, `_bb_swing`), then
//! `phy.c::rtw_phy_set_tx_power_level` for the new channel's
//! `rtw_get_channel_group`. RF calibration is deferred while scanning and run
//! from `mac80211.c::rtw_ops_mgd_prepare_tx` (`rtw_chip_prepare_tx` ->
//! `phy_calibration`, i.e. `rtw8822c_do_iqk` / `rtw8821c_do_iqk`) before
//! association.
//!
//! Channel 1 remains the base program and its N22Cv2/N21S qualification.
//! A noninitial channel N (2..=13) is admitted only by an optional signed
//! `rtw88/rtw882{1,2}ce-channelNN-v1-<mac>.bin` record (tag `O`; an RTL8821CU
//! board's own `rtw88/rtw8821cu-...` record keyed by its USB VID/PID) whose
//! identity binds the exact base. The record supplies the measured envelope
//! (antenna gain, qualified ceiling and peaks) and the TX power selection for
//! that channel: C22 per-path CCK references, C21 twelve CCK/OFDM TXAGC
//! indices. Selections are bounded by the factory `rtw_get_channel_group`
//! base for that channel; nothing is derived from another channel's
//! measurement. Without a provisioned record only channel 1 is admitted.
//! Every continuation program (WMM/HT/BA/RTS/coding/QoS/fallback/dm/N21W/
//! LPS) on a noninitial primary is a distinct record qualified over the
//! channel-scoped base ([`scope_request`]); without one the channel carries
//! the base legacy CCK1 profile only.
//! Channel 14 (CCK-only, Japan) is not admitted.
use super::{
    firmware_transport::{Error, Io},
    power_policy::Gate,
    qualification::{Grant, Kind, PAYLOAD},
};
use alloc::{format, string::String};
use narf_wireless::reg::{RegFlags, RegulatoryDomain};

/// Highest admitted noninitial primary.
pub(super) const LAST: u8 = 13;

/// Flags a plain rule may carry: `NO_P2P` and cfg80211's bandwidth-shaping
/// `AUTO_BW` / `NO_160MHZ`, whose effect is read through
/// [`RegulatoryDomain::max_bandwidth`] (`reg.c::reg_get_max_bandwidth`).
/// Every other bit (DFS, NO_IR, indoor, unknown) refuses the rule.
const PLAIN: RegFlags = RegFlags::NO_P2P
    .union(RegFlags::AUTO_BW)
    .union(RegFlags::NO_160MHZ);

/// Rule `index` of `domain` is a well-formed plain rule allowing `width` MHz.
pub(super) fn plain_rule(domain: &RegulatoryDomain, index: usize, width: u32) -> bool {
    domain.rules.get(index).is_some_and(|r| {
        r.freq_start_mhz < r.freq_end_mhz
            && r.flags.bits() & !PLAIN.bits() == 0
            && domain.max_bandwidth(index) >= width
    })
}

/// Flags that make a 5GHz span passive-only for the station: cfg80211
/// `IEEE80211_CHAN_RADAR` (reg.c `handle_channel_single_rule`: `NL80211_RRF_DFS`)
/// and `IEEE80211_CHAN_NO_IR` (`NL80211_RRF_NO_IR`).
const PASSIVE: RegFlags = RegFlags::DFS.union(RegFlags::NO_IR);

/// The passive-only variant of [`plain_rule`] for a 5GHz span: `Some(false)`
/// for a plain rule, `Some(true)` for a rule that additionally carries DFS
/// and/or NO_IR (RX, passive scan and witness-gated station TX only, see
/// `narf_wireless::reg::witness`), `None` when the rule refuses (indoor,
/// unknown bits, malformed, or too narrow for `width`). Never used on
/// 2.4GHz, where DFS / NO_IR still refuse through [`plain_rule`].
pub(super) fn passive_rule(domain: &RegulatoryDomain, index: usize, width: u32) -> Option<bool> {
    let r = domain.rules.get(index)?;
    (r.freq_start_mhz < r.freq_end_mhz
        && r.flags.bits() & !(PLAIN.bits() | PASSIVE.bits()) == 0
        && domain.max_bandwidth(index) >= width)
        .then(|| r.flags.intersects(PASSIVE))
}

/// Linux `phy.c::rtw_get_channel_group` for 2.4GHz channels 1..=13.
pub(super) const fn group(channel: u8) -> Option<usize> {
    match channel {
        1 | 2 => Some(0),
        3..=5 => Some(1),
        6..=8 => Some(2),
        9..=11 => Some(3),
        12 | 13 => Some(4),
        _ => None,
    }
}

/// `ieee80211_channel_to_frequency` for 2.4GHz channels 1..=13.
pub(super) const fn frequency(channel: u8) -> Option<u16> {
    match channel {
        1..=13 => Some(2407 + 5 * channel as u16),
        _ => None,
    }
}

/// Center frequency of an admissible 20MHz primary on either band
/// (2.4GHz 1..=13 or a 5GHz `band5::primary`).
pub(super) fn any_frequency(channel: u8) -> Option<u16> {
    frequency(channel).or_else(|| {
        super::band5::primary(channel)
            .then(|| super::band5::frequency(channel))
            .flatten()
    })
}

/// A 20MHz primary this owner can retune to (2.4GHz 1..=13 or 5GHz).
pub(super) fn tunable(channel: u8) -> bool {
    any_frequency(channel).is_some()
}

/// Base-rate admission of a BSS on `channel`: the band's lowest mandatory
/// rate (CCK1 on 2.4GHz, OFDM6 on 5GHz with no CCK) is a basic rate, since
/// management frames go out at that fixed rate (`rtw_tx_pkt_info_update_rate`).
pub(super) fn base_rate_ok(channel: u8, basic: u16) -> bool {
    if super::band5::primary(channel) {
        basic & 15 == 0 && basic & (1 << 4) != 0
    } else {
        basic & 1 != 0
    }
}

/// `rtw8822c_set_channel_bb` REG_SCOTRK (0xc30[11:0]) for a 2.4GHz primary.
pub(super) const fn scotrk(channel: u8) -> u32 {
    match channel {
        13 | 14 => 0x969,
        11 | 12 => 0x96a,
        _ => 0x9aa,
    }
}

/// `rtw8822c_set_channel_bb` REG_TXDFIR0 (0x808[6:4]) for a 2.4GHz primary.
pub(super) const fn txdfir(channel: u8) -> u32 {
    if channel == 13 {
        3
    } else {
        1
    }
}

/// Decoded N2xO payload (bytes 56..120 of the signed record):
///
/// | Bytes | Field |
/// |---|---|
/// | 0 | primary channel 2..=13, or a 5GHz primary (`band5::primary`) |
/// | 1 | width 20 (MHz) |
/// | 2..4 | antenna gain, quarter dBi |
/// | 4..6 | qualified EIRP ceiling, quarter dBm |
/// | 6..12 | measured peaks (IQK/calibration, response, data), quarter dBm |
/// | 12..14 | C22 per-path CCK references (2.4GHz only; else zero) |
/// | 14..26 | C21 TXAGC indices CCK1..11, OFDM6..54 (C22: zero; 5GHz: CCK zero) |
/// | 26..28 | C22 5GHz per-path OFDM references (REG_TX_PWR_REF_OFDM) |
/// | 28..36 | C22 5GHz OFDM difference words 0x3a04 (6/9/12/18M), 0x3a08 (24..54M) |
/// | 36..64 | zero |
///
/// The C22 5GHz selection mirrors `rtw8822c_set_tx_power_index`: a per-path
/// OFDM reference plus one 7-bit signed difference per OFDM rate
/// (`rtw8822c_set_tx_power_diff`), so OFDM rate r on path p transmits at
/// index `ofdm[p] + diff(r)`. CCK is not transmitted on 5GHz
/// (`rtw_phy_set_tx_power_level_by_path` skips the CCK section); its
/// reference and differences stay zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Record {
    pub(super) channel: u8,
    pub(super) antenna: i16,
    pub(super) ceiling: i16,
    pub(super) peaks: [i16; 3],
    pub(super) gains: [u8; 2],
    pub(super) indices: [u8; 12],
    pub(super) ofdm: [u8; 2],
    pub(super) diffs: [u32; 2],
}

impl Record {
    pub(super) fn decode(did: u16, p: &[u8; PAYLOAD]) -> Option<Self> {
        let signed = |at: usize| i16::from_le_bytes([p[at], p[at + 1]]);
        let record = Self {
            channel: p[0],
            antenna: signed(2),
            ceiling: signed(4),
            peaks: [signed(6), signed(8), signed(10)],
            gains: [p[12], p[13]],
            indices: p[14..26].try_into().ok()?,
            ofdm: [p[26], p[27]],
            diffs: [
                u32::from_le_bytes(p[28..32].try_into().ok()?),
                u32::from_le_bytes(p[32..36].try_into().ok()?),
            ],
        };
        let five = record.band5();
        let chip = match did {
            0xc822 if five => {
                record.indices == [0; 12]
                    && record.gains == [0; 2]
                    && record.ofdm.iter().all(|r| *r <= 127)
                    && record.diffs.iter().all(|w| w & 0x8080_8080 == 0)
            }
            0xc822 => {
                record.indices == [0; 12]
                    && record.gains.iter().all(|g| *g <= 127)
                    && record.ofdm == [0; 2]
                    && record.diffs == [0; 2]
            }
            0xc821 => {
                record.gains == [0; 2]
                    && record.ofdm == [0; 2]
                    && record.diffs == [0; 2]
                    && record.indices.iter().all(|i| *i <= 63)
                    && (!five || record.indices[..4] == [0; 4])
            }
            _ => false,
        };
        (chip
            && ((2..=LAST).contains(&record.channel) || five)
            && p[1] == 20
            && (0..=128).contains(&record.antenna)
            && (-512..=256).contains(&record.ceiling)
            && record.peaks.iter().all(|v| (-512..=256).contains(v))
            && p[36..] == [0; PAYLOAD - 36])
            .then_some(record)
    }
    /// A 5GHz primary record.
    pub(super) fn band5(&self) -> bool {
        super::band5::primary(self.channel)
    }
    /// C22 signed OFDM difference for OFDM rate `rate` (0 = 6M .. 7 = 54M).
    pub(super) fn diff(&self, rate: usize) -> i8 {
        let byte = (self.diffs[rate / 4] >> (8 * (rate % 4))) as u8;
        ((byte << 1) as i8) >> 1
    }
    /// C22 5GHz OFDM6..54 indices as one both-path selection:
    /// `min(ofdm[A] + diff(r), ofdm[B] + diff(r))` per rate
    /// (`rtw8822c_set_tx_power_index` writes the per-rate minimum of the two
    /// paths' differences). None for a 2.4GHz record or an index outside
    /// 0..=127.
    pub(super) fn ofdm5_indices(&self) -> Option<[u8; 8]> {
        if !self.band5() || self.indices != [0; 12] {
            return None;
        }
        let mut out = [0; 8];
        for (rate, slot) in out.iter_mut().enumerate() {
            let index = self
                .ofdm
                .iter()
                .map(|o| i16::from(*o) + i16::from(self.diff(rate)))
                .min()?;
            *slot = u8::try_from(index).ok().filter(|v| *v <= 127)?;
        }
        Some(out)
    }
    /// Center frequency of the 20MHz primary on either band.
    pub(super) fn frequency(&self) -> Option<u16> {
        frequency(self.channel).or(super::band5::frequency(self.channel))
    }
}

fn admit(did: u16, payload: &[u8; PAYLOAD], channel: u8) -> bool {
    Record::decode(did, payload).is_some_and(|r| r.channel == channel)
}

macro_rules! channel_kind {
    ($channel:literal, $stem:literal) => {
        Kind {
            tag: b'O',
            stem: $stem,
            source: concat!(
                "Linux 7.3-rc4 rtw88 main.c rtw_set_channel; rtw8822c.c rtw8822c_set_channel_bb/",
                "rtw_set_channel_mac/rtw8822c_set_channel_rf/rtw8822c_toggle_igi; rtw8821c.c ",
                "rtw8821c_set_channel_bb/_rf/_rxdfir/_bb_swing non-SRRC; phy.c ",
                "rtw_get_channel_group rtw_phy_set_tx_power_level; mac80211.c ",
                "rtw_ops_mgd_prepare_tx rtw8822c_do_iqk clear1 / rtw8821c_do_iqk segment0; ",
                "native TXPAUSE drain, legacy CCK1 base only, 2.4GHz 20MHz ",
                $stem
            )
            .as_bytes(),
            admit: |did, payload| admit(did, payload, $channel),
        }
    };
}

macro_rules! channel5_kind {
    ($channel:literal, $stem:literal) => {
        Kind {
            tag: b'O',
            stem: $stem,
            source: concat!(
                "Linux 7.3-rc4 rtw88 main.c rtw_set_channel; rtw8822c.c rtw8822c_set_channel_bb ",
                "5G head/rtw_set_channel_mac/rtw8822c_set_channel_rf/rtw8822c_toggle_igi; ",
                "rtw8821c.c rtw8821c_set_channel 20MHz incl. rtw8821c_switch_rf_set WLA; phy.c ",
                "rtw_get_channel_group rtw_phy_get_5g_tx_power_index OFDM; rtw8822c_set_tx_power_index ",
                "OFDM reference + rtw8822c_set_tx_power_diff / C21 OFDM TXAGC; no CCK; ",
                "native TXPAUSE drain, legacy OFDM6 base only, 5GHz 20MHz non-DFS ",
                $stem
            )
            .as_bytes(),
            admit: |did, payload| admit(did, payload, $channel),
        }
    };
}

/// One static continuation kind per 5GHz 20MHz primary, in channel order.
pub(super) static KINDS5: [Kind; 28] = [
    channel5_kind!(36, "channel36"),
    channel5_kind!(40, "channel40"),
    channel5_kind!(44, "channel44"),
    channel5_kind!(48, "channel48"),
    channel5_kind!(52, "channel52"),
    channel5_kind!(56, "channel56"),
    channel5_kind!(60, "channel60"),
    channel5_kind!(64, "channel64"),
    channel5_kind!(100, "channel100"),
    channel5_kind!(104, "channel104"),
    channel5_kind!(108, "channel108"),
    channel5_kind!(112, "channel112"),
    channel5_kind!(116, "channel116"),
    channel5_kind!(120, "channel120"),
    channel5_kind!(124, "channel124"),
    channel5_kind!(128, "channel128"),
    channel5_kind!(132, "channel132"),
    channel5_kind!(136, "channel136"),
    channel5_kind!(140, "channel140"),
    channel5_kind!(144, "channel144"),
    channel5_kind!(149, "channel149"),
    channel5_kind!(153, "channel153"),
    channel5_kind!(157, "channel157"),
    channel5_kind!(161, "channel161"),
    channel5_kind!(165, "channel165"),
    channel5_kind!(169, "channel169"),
    channel5_kind!(173, "channel173"),
    channel5_kind!(177, "channel177"),
];

/// 5GHz primaries in [`KINDS5`] order.
pub(super) const PRIMARIES5: [u8; 28] = [
    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165, 169, 173, 177,
];

/// One static continuation kind per noninitial primary, index `channel - 2`.
pub(super) static KINDS: [Kind; 12] = [
    channel_kind!(2, "channel02"),
    channel_kind!(3, "channel03"),
    channel_kind!(4, "channel04"),
    channel_kind!(5, "channel05"),
    channel_kind!(6, "channel06"),
    channel_kind!(7, "channel07"),
    channel_kind!(8, "channel08"),
    channel_kind!(9, "channel09"),
    channel_kind!(10, "channel10"),
    channel_kind!(11, "channel11"),
    channel_kind!(12, "channel12"),
    channel_kind!(13, "channel13"),
];

pub(super) fn kind(channel: u8) -> Option<&'static Kind> {
    if (2..=LAST).contains(&channel) {
        return Some(&KINDS[usize::from(channel - 2)]);
    }
    PRIMARIES5
        .iter()
        .position(|c| *c == channel)
        .map(|i| &KINDS5[i])
}

/// The record's TX power selection never exceeds the factory base of the
/// channel's own group (C22: per-path CCK reference incl. RFE response
/// adjustment; C21: CCK and 1S OFDM indices). On 5GHz the bound is the
/// `rtw_phy_get_5g_tx_power_index` OFDM base of the channel's 5GHz group:
/// C22 every per-path `reference + difference` lies in `0..=limit`, C21
/// every OFDM index is at most the path-A limit.
pub(super) fn within_factory(gate: &Gate, record: &Record) -> bool {
    if record.band5() {
        let Some(limits) = super::band5::group(record.channel).and_then(|g| gate.band5_limits(g))
        else {
            return false;
        };
        return match gate.did() {
            0xc822 => (0..2).all(|path| {
                (0..8).all(|rate| {
                    let v = i16::from(record.ofdm[path]) + i16::from(record.diff(rate));
                    (0..=i16::from(limits[path])).contains(&v)
                })
            }),
            0xc821 => record.indices[4..].iter().all(|i| *i <= limits[0]),
            _ => false,
        };
    }
    let Some(limits) = group(record.channel).and_then(|g| gate.group_limits(g)) else {
        return false;
    };
    match gate.did() {
        0xc822 => record.gains[0] <= limits[0] && record.gains[1] <= limits[1],
        0xc821 => {
            record.indices[..4].iter().all(|i| *i <= limits[0])
                && record.indices[4..].iter().all(|i| *i <= limits[1])
        }
        _ => false,
    }
}

/// Regulatory admission of one record: every rule overlapping the primary's
/// 20MHz occupied span is a plain rule (on 5GHz also a passive-only one,
/// [`passive_rule`]), the span is covered, and every measured peak plus
/// antenna gain fits the minimum ceiling. Returns the admitted EIRP ceiling
/// (quarter dBm).
pub(super) fn policy(record: &Record, domain: &RegulatoryDomain) -> Result<i16, Error> {
    admission(record, domain).map(|(limit, _)| limit)
}

/// [`policy`] plus whether the admitted span is passive-only (a 5GHz rule
/// over it carries DFS / NO_IR). A passive-only primary is admitted for
/// RX, monitor and passive scan; frame TX on it additionally needs the
/// station's beacon-witness grant (`Native::passive_tx_allowed`).
pub(super) fn admission(record: &Record, domain: &RegulatoryDomain) -> Result<(i16, bool), Error> {
    let center = u32::from(record.frequency().ok_or(Error::Unsupported)?);
    let (low, high) = (center - 10, center + 10);
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
        if record.band5() {
            passive |= passive_rule(domain, i, 20).ok_or(Error::Prerequisite)?;
        } else if !plain_rule(domain, i, 20) {
            return Err(Error::Prerequisite);
        }
        covering |= r.freq_start_mhz <= low && r.freq_end_mhz >= high;
        limit = limit.min(i16::from(r.max_power_dbm) * 4);
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

/// Live check of a bound record against the installed regulatory domain,
/// under the record's own current capability.
pub(super) fn current(g: &Grant, did: u16) -> Result<(), Error> {
    let domain = narf_wireless::reg::db::get_domain().ok_or(Error::Prerequisite)?;
    current_in(g, did, &domain)
}

pub(super) fn current_in(g: &Grant, did: u16, domain: &RegulatoryDomain) -> Result<(), Error> {
    limit_in(g, did, domain).map(|_| ())
}

/// [`current_in`] returning the record's admitted EIRP ceiling, which
/// bounds every program qualified over the channel-scoped base.
pub(super) fn limit_in(g: &Grant, did: u16, domain: &RegulatoryDomain) -> Result<i16, Error> {
    g.invoke_source(|| {
        let record = Record::decode(did, g.payload()).ok_or(Error::State)?;
        if kind(record.channel).is_none_or(|k| !g.is(k)) {
            return Err(Error::State);
        }
        policy(&record, domain)
    })
}

/// Whether the bound record's admitted span is passive-only under `domain`
/// (live, under the record's own current capability, like [`limit_in`]).
pub(super) fn passive_in(g: &Grant, did: u16, domain: &RegulatoryDomain) -> Result<bool, Error> {
    g.invoke_source(|| {
        let record = Record::decode(did, g.payload()).ok_or(Error::State)?;
        if kind(record.channel).is_none_or(|k| !g.is(k)) {
            return Err(Error::State);
        }
        admission(&record, domain).map(|(_, passive)| passive)
    })
}

/// Per-channel filename of a program qualified over a channel-scoped base:
/// `rtw88/<family>-<stem>...` becomes `rtw88/<family>-chNN-<stem>...`
/// (`phy8821c::Host::family`: `rtw882Xce` or `rtw8821cu`). Channel 1 keeps
/// the original name.
pub(super) fn scoped_filename(name: &str, channel: u8) -> String {
    match name.find('-') {
        Some(at) if channel != 1 => {
            format!("{}-ch{:02}-{}", &name[..at], channel, &name[at + 1..])
        }
        _ => name.into(),
    }
}

/// Channel-scoped extension base: every WMM/HT/BA/RTS/coding/QoS/fallback/
/// dm/N21W/LPS program on a noninitial primary binds this identity, so it is
/// a distinct per-channel record measured on that channel, bounded by that
/// channel's factory group and checked against that channel's regulatory
/// span. A channel-1 record can never authorize channel N.
pub(super) fn scope_request(
    base: &super::station_profile::Request,
    did: u16,
    g: &Grant,
) -> Option<super::station_profile::Request> {
    let record = Record::decode(did, g.payload())?;
    kind(record.channel).filter(|k| g.is(k))?;
    let (identity, digest) = g.source_identity();
    let mut h = narf_crypto::sha256::Sha256::new();
    h.update(b"NARF RTW88 N2xO channel-scoped operating base v1");
    h.update(&did.to_le_bytes());
    h.update(&[record.channel, 20]);
    h.update(&base.identity);
    h.update(&identity);
    h.update(&digest);
    h.update(b"Linux 7.3-rc4 rtw_set_channel + rtw_phy_set_tx_power_level for this primary; rtw_get_channel_group factory ceilings of this primary only; N2xO CCK references (C22) / TXAGC indices (C21) as the program base; record regulatory span and EIRP ceiling enclose every continuation; no channel-1 measurement reused");
    if record.band5() {
        // The 5GHz variant replaces the base text's CCK references,
        // mgmt/EAPOL 1M, rate ids B8/BG6 and SIFS10 terms.
        h.update(b"5GHz band variant: OFDM-only legacy8 intersection with OFDM6 mandatory (CCK1..11 refused); rateID G7 (get_rate_id WIRELESS_OFDM); mgmt/EAPOL 6M RATEID_G (rtw_tx_pkt_info_update_rate); RRSR_INIT_5G 0x150; N2xO OFDM references + 0x3a04/0x3a08 differences (C22) / OFDM TXAGC with CCK zero (C21) as the program base; WMM AIFS SIFS16 (rtw_aifsn_to_aifs RTW_BAND_5G) with the short slot forced (ieee80211_handle_bss_capability)");
    }
    Some(super::station_profile::Request {
        identity: h.finalize(),
        mac: base.mac,
        filename: scoped_filename(&base.filename, record.channel),
    })
}

/// Accepted associated channel switch: the target primary and its N2xO
/// record (none for channel 1), the countdown deadline (ms) and whether TX is
/// blocked (CSA mode 1).
pub(super) struct Switch {
    pub(super) channel: u8,
    pub(super) grant: Option<alloc::sync::Arc<Grant>>,
    pub(super) due: u64,
    pub(super) block: bool,
}

/// Parsed Channel Switch Announcement for a 20MHz BSS. `channel` is None
/// when the ECSA operating class is not a non-DFS 20MHz class this owner
/// follows (81: 2.4GHz 1..=13; 115: 36..=48; 118: 52..=64; 121: 100..=144;
/// 124: 149..=161; 125: 149..=177, IEEE 802.11 Annex E Table E-4), or the channel is not in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SwitchIe {
    pub(super) block: bool,
    pub(super) channel: Option<u8>,
    pub(super) count: u8,
}

/// `util.c::ieee80211_parse_ch_switch_ie` subset over Beacon/Probe Response
/// elements: ECSA (60: mode, operating class, channel, count) takes
/// precedence over CSA (37: mode, channel, count).
pub(super) fn switch_ie(ies: &[u8]) -> Option<SwitchIe> {
    let (mut csa, mut ecsa) = (None, None);
    let mut at = 0;
    while at + 2 <= ies.len() {
        let len = usize::from(ies[at + 1]);
        let body = ies.get(at + 2..at + 2 + len)?;
        match (ies[at], body) {
            (37, [mode, channel, count]) => {
                csa = Some(SwitchIe {
                    block: *mode != 0,
                    channel: Some(*channel),
                    count: *count,
                })
            }
            (60, [mode, class, channel, count]) => {
                ecsa = Some(SwitchIe {
                    block: *mode != 0,
                    channel: class_channel(*class, *channel),
                    count: *count,
                })
            }
            _ => {}
        }
        at += 2 + len;
    }
    ecsa.or(csa)
}

/// Primary `channel` of a 20MHz global operating class this owner follows.
fn class_channel(class: u8, channel: u8) -> Option<u8> {
    let ok = match class {
        81 => (1..=13).contains(&channel),
        115 => matches!(channel, 36 | 40 | 44 | 48),
        124 => matches!(channel, 149 | 153 | 157 | 161),
        // Annex E Table E-4 20MHz DFS classes (U-NII-2A / U-NII-2C).
        118 => matches!(channel, 52 | 56 | 60 | 64),
        121 => (100..=144).contains(&channel) && channel % 4 == 0,
        125 => matches!(channel, 149 | 153 | 157 | 161 | 165 | 169 | 173 | 177),
        _ => false,
    };
    ok.then_some(channel)
}

/// mac80211 `ieee80211_put_srates_elem` for the 5GHz band in a preq: the
/// eight OFDM rates, no basic flags, no Extended Supported Rates.
const RATES5: [u8; 8] = [0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c];

/// Rewrite one software-scan Probe Request for `channel`
/// (`ieee80211_put_preq_ies_band` builds it for the scanned band): on
/// 2.4GHz the DS Parameter Set names the channel; on 5GHz the Supported
/// Rates are the OFDM set, and Extended Supported Rates and the DS
/// Parameter Set (2.4GHz only) are dropped. Other elements keep their order.
pub(super) fn probe_for(probe: &[u8], channel: u8) -> Option<alloc::vec::Vec<u8>> {
    if super::band5::primary(channel) {
        let mut out = probe.get(..24)?.to_vec();
        let mut at = 24;
        let mut rates = false;
        while at < probe.len() {
            let len = usize::from(*probe.get(at + 1)?);
            let element = probe.get(at..at + 2 + len)?;
            match element[0] {
                1 => {
                    out.extend_from_slice(&[1, RATES5.len() as u8]);
                    out.extend_from_slice(&RATES5);
                    rates = true;
                }
                3 | 50 => {}
                _ => out.extend_from_slice(element),
            }
            at += 2 + len;
        }
        return rates.then_some(out);
    }
    frequency(channel)?;
    let mut out = probe.to_vec();
    let mut at = 24;
    while at + 2 <= out.len() {
        let len = usize::from(out[at + 1]);
        if at + 2 + len > out.len() {
            return None;
        }
        if out[at] == 3 && len == 1 {
            out[at + 2] = channel;
            return Some(out);
        }
        at += 2 + len;
    }
    None
}

async fn wait_h2c(io: &mut impl Io) -> Result<(), Error> {
    for _ in 0..1000 {
        if io.poll_h2c().await? {
            return Ok(());
        }
        io.delay_us(10).await;
    }
    Err(Error::Timeout)
}

/// Program the gate's current channel after `station_retune_begin` (which
/// installed the target gate and paused/drained TX). `rfk` runs the chip's
/// Linux IQK as `rtw_ops_mgd_prepare_tx` does before association; scan
/// retunes skip it like `RTW_FLAG_SCANNING`.
pub(super) async fn program(io: &mut impl Io, gate: &Gate, rfk: bool) -> Result<(), Error> {
    let channel = gate.channel();
    if super::band5::primary(channel) {
        return program5(io, gate, channel, rfk).await;
    }
    group(channel).ok_or(Error::Unsupported)?;
    match gate.did() {
        0xc822 => {
            let gains = gate.cck_gains().ok_or(Error::State)?;
            super::radio::channel_to(io, channel).await?;
            super::radio::gains(io, gains).await?;
            if rfk {
                iqk8822c(io, gains).await?;
            }
            verify8822c(io, channel, gains).await
        }
        0xc821 => {
            let indices = gate.c21_indices().ok_or(Error::State)?;
            // `rtw_set_channel_mac` sets CCK_CHECK bit7 only on 5GHz: coming
            // back from a 5GHz primary needs the full cross-band program and
            // the 2.4GHz RRSR; within 2.4GHz only `_rf` changes.
            let cross = io.read8(0x454).await? & 0x80 != 0;
            if cross {
                let facts = gate.band_facts().ok_or(Error::State)?;
                super::radio8821c::set_channel20(io, channel, &facts).await?;
                super::radio8821c::verify_channel20(io, channel, &facts).await?;
                io.write32(0x440, 0x1f).await?;
            } else {
                super::radio8821c::retune_channel(io, channel).await?;
            }
            super::radio8821c::write_txagc(io, indices).await?;
            if rfk {
                iqk8821c(io).await?;
            }
            super::radio8821c::verify_retune(io, channel, indices).await
        }
        _ => Err(Error::Unsupported),
    }
}

/// 5GHz/20MHz primary of a bound 5GHz N2xO record. C22:
/// `rtw8822c_set_channel` 5GHz (`radio::channel5_to`) then the record's
/// OFDM references/differences (`radio::ofdm5`); C21: `rtw8821c_set_channel`
/// 20MHz over the gate's [`super::radio8821c::BandFacts`] then the record's
/// OFDM TXAGC (CCK zero) and REG_RRSR `RRSR_INIT_5G & mask(6M)`. RF
/// calibration is the same firmware IQK as on 2.4GHz.
async fn program5(io: &mut impl Io, gate: &Gate, channel: u8, rfk: bool) -> Result<(), Error> {
    match gate.did() {
        0xc822 => {
            let (ofdm, diffs) = gate.ofdm5().ok_or(Error::State)?;
            super::radio::channel5_to(io, channel).await?;
            super::radio::ofdm5(io, ofdm, diffs).await?;
            if rfk {
                iqk8822c_run(io).await?;
                super::radio::ofdm5(io, ofdm, diffs).await?;
            }
            super::radio::verify_channel5(io, channel).await?;
            super::radio::verify_ofdm5(io, ofdm, diffs).await
        }
        0xc821 => {
            let facts = gate.band_facts().ok_or(Error::State)?;
            let indices = gate.c21_indices().ok_or(Error::State)?;
            if indices[..4] != [0; 4] {
                return Err(Error::State);
            }
            super::radio8821c::set_channel20(io, channel, &facts).await?;
            super::radio8821c::write_txagc(io, indices).await?;
            io.write32(0x440, super::radio::RRSR_OFDM6_5G).await?;
            if rfk {
                iqk8821c(io).await?;
            }
            super::radio8821c::verify_channel20(io, channel, &facts).await?;
            super::radio8821c::verify_txagc(io, indices, super::radio::RRSR_OFDM6_5G).await
        }
        _ => Err(Error::Unsupported),
    }
}

async fn dpd_off(io: &mut impl Io) -> Result<(), Error> {
    for path in 0..2 {
        super::radio::mask(io, 0x1b00, 6, path).await?;
        super::radio::mask(io, 0x1b08, 1 << 31, 0).await?;
    }
    super::radio::mask(io, 0xa70, 0x3ff, 0x3ff).await
}

/// `rtw8822c_do_iqk` (clear=1) on the retained channel, matching Linux:
/// after the H2C is consumed, poll REG_RPT_CIP (0x2d9c) for the IQK_DONE
/// level 0xaa every 20ms for at most 300ms (`read_poll_timeout(...,
/// iqk_chk == IQK_DONE_8822C, 20000, 300000, ...)`), then clear
/// REG_IQKSTAT. Linux only warns on timeout; this owner fails the retune
/// instead (TX stays closed). A stricter "observe non-0xaa first" rule was
/// dropped: no source shows the firmware leaving IQK_DONE at IQK start, so
/// it could time out on silicon. The stale-level risk is bounded by the
/// RF18/SCOTRK/TXDFIR/gain/RRSR readbacks that follow.
pub(super) async fn iqk8822c(io: &mut impl Io, gains: [u8; 2]) -> Result<(), Error> {
    iqk8822c_run(io).await?;
    super::radio::gains(io, gains).await
}

/// [`iqk8822c`] without the TX power restore; the caller reprograms its
/// band's references.
pub(super) async fn iqk8822c_run(io: &mut impl Io) -> Result<(), Error> {
    dpd_off(io).await?;
    super::radio::rfk_power(io, true).await?;
    io.station_retune_iqk().await?;
    wait_h2c(io).await?;
    let mut complete = false;
    for attempt in 0..=15 {
        let value = io.read8(0x2d9c).await?;
        if value == 255 {
            return Err(Error::Gone);
        }
        if value == 0xaa {
            complete = true;
            break;
        }
        if attempt < 15 {
            io.delay_us(20000).await;
        }
    }
    if !complete {
        return Err(Error::Timeout);
    }
    io.write8(0x1b10, 0).await?;
    super::radio::rfk_power(io, false).await?;
    dpd_off(io).await
}

async fn verify8822c(io: &mut impl Io, channel: u8, gains: [u8; 2]) -> Result<(), Error> {
    for (path, gain) in gains.into_iter().enumerate() {
        if super::radio::rf_read(io, path as u8, 0x18).await? & 0x733ff
            != 0x3000 | u32::from(channel)
            || (super::radio::read(io, if path == 0 { 0x18a0 } else { 0x41a0 }).await? >> 16) & 127
                != u32::from(gain)
        {
            return Err(Error::Prerequisite);
        }
    }
    if super::radio::read(io, 0xc30).await? & 0xfff != scotrk(channel)
        || (super::radio::read(io, 0x808).await? >> 4) & 7 != txdfir(channel)
        || super::radio::read(io, 0x440).await? != 0x1f
    {
        return Err(Error::Prerequisite);
    }
    Ok(())
}

/// `rtw8821c_do_iqk` before association (clear=0, segment=0). RF_DTXLOK is
/// host-cleared after each run, so a stale done marker is refused.
pub(super) async fn iqk8821c(io: &mut impl Io) -> Result<(), Error> {
    if super::radio8821c::rf_read(io, 8).await? == 0xabcde {
        return Err(Error::Prerequisite);
    }
    io.station_retune_iqk().await?;
    wait_h2c(io).await?;
    let mut complete = false;
    for attempt in 0..300 {
        if super::radio8821c::rf_read(io, 8).await? == 0xabcde {
            complete = true;
            break;
        }
        if attempt < 299 {
            io.delay_us(20000).await;
        }
    }
    if !complete {
        return Err(Error::Timeout);
    }
    super::radio8821c::rf(io, 8, 0xfffff, 0).await?;
    if super::radio::read(io, 0x1bf0).await? & 0x100ff != 0 {
        return Err(Error::Prerequisite);
    }
    Ok(())
}
