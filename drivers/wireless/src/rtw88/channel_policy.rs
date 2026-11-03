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
//! `rtw88/rtw882{1,2}ce-channelNN-v1-<mac>.bin` record (tag `O`) whose
//! identity binds the exact base. The record supplies the measured envelope
//! (antenna gain, qualified ceiling and peaks) and the TX power selection for
//! that channel: C22 per-path CCK references, C21 twelve CCK/OFDM TXAGC
//! indices. Selections are bounded by the factory `rtw_get_channel_group`
//! base for that channel; nothing is derived from another channel's
//! measurement. Without a provisioned record only channel 1 is admitted.
//! Noninitial channels carry the base legacy CCK1 profile only: no WMM/HT,
//! BA, protection, coding/QoS/fallback, dm or power-tracking continuation.
//! Channel 14 (CCK-only, Japan) is not admitted.
use super::{
    firmware_transport::{Error, Io},
    power_policy::Gate,
    qualification::{Grant, Kind, PAYLOAD},
};
use narf_wireless::reg::{RegFlags, RegulatoryDomain};

/// Highest admitted noninitial primary.
pub(super) const LAST: u8 = 13;

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
/// | 0 | primary channel 2..=13 |
/// | 1 | width 20 (MHz) |
/// | 2..4 | antenna gain, quarter dBi |
/// | 4..6 | qualified EIRP ceiling, quarter dBm |
/// | 6..12 | measured peaks (IQK/calibration, response, data), quarter dBm |
/// | 12..14 | C22 per-path CCK references (C21: zero) |
/// | 14..26 | C21 TXAGC indices CCK1..11, OFDM6..54 (C22: zero) |
/// | 26..64 | zero |
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Record {
    pub(super) channel: u8,
    pub(super) antenna: i16,
    pub(super) ceiling: i16,
    pub(super) peaks: [i16; 3],
    pub(super) gains: [u8; 2],
    pub(super) indices: [u8; 12],
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
        };
        let chip = match did {
            0xc822 => record.indices == [0; 12] && record.gains.iter().all(|g| *g <= 127),
            0xc821 => record.gains == [0; 2] && record.indices.iter().all(|i| *i <= 63),
            _ => false,
        };
        (chip
            && (2..=LAST).contains(&record.channel)
            && p[1] == 20
            && (0..=128).contains(&record.antenna)
            && (-512..=256).contains(&record.ceiling)
            && record.peaks.iter().all(|v| (-512..=256).contains(v))
            && p[26..] == [0; PAYLOAD - 26])
            .then_some(record)
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
    (2..=LAST)
        .contains(&channel)
        .then(|| &KINDS[usize::from(channel - 2)])
}

/// The record's TX power selection never exceeds the factory base of the
/// channel's own group (C22: per-path CCK reference incl. RFE response
/// adjustment; C21: CCK and 1S OFDM indices).
pub(super) fn within_factory(gate: &Gate, record: &Record) -> bool {
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
/// 20MHz occupied span is a plain rule, the span is covered, and every
/// measured peak plus antenna gain fits the minimum ceiling. Returns the
/// admitted EIRP ceiling (quarter dBm).
pub(super) fn policy(record: &Record, domain: &RegulatoryDomain) -> Result<i16, Error> {
    let center = u32::from(frequency(record.channel).ok_or(Error::Unsupported)?);
    let (low, high) = (center - 10, center + 10);
    if !domain.country_code.iter().all(u8::is_ascii_uppercase) {
        return Err(Error::Prerequisite);
    }
    let mut limit = record.ceiling.min(80);
    let mut covering = false;
    for r in &domain.rules {
        if r.freq_start_mhz >= high || r.freq_end_mhz <= low {
            continue;
        }
        if r.freq_start_mhz >= r.freq_end_mhz
            || r.max_bandwidth_mhz < 20
            || r.flags.bits() & !RegFlags::NO_P2P.bits() != 0
        {
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
    Ok(limit)
}

/// Live check of a bound record against the installed regulatory domain,
/// under the record's own current capability.
pub(super) fn current(g: &Grant, did: u16) -> Result<(), Error> {
    let domain = narf_wireless::reg::db::get_domain().ok_or(Error::Prerequisite)?;
    current_in(g, did, &domain)
}

pub(super) fn current_in(g: &Grant, did: u16, domain: &RegulatoryDomain) -> Result<(), Error> {
    g.invoke_source(|| {
        let record = Record::decode(did, g.payload()).ok_or(Error::State)?;
        if kind(record.channel).is_none_or(|k| !g.is(k)) {
            return Err(Error::State);
        }
        policy(&record, domain).map(|_| ())
    })
}

/// Rewrite the DS Parameter Set of one software-scan Probe Request for
/// `channel` (`ieee80211_build_preq_ies` uses the scanned channel).
pub(super) fn probe_for(probe: &[u8], channel: u8) -> Option<alloc::vec::Vec<u8>> {
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
        if io.poll_h2c()? {
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
    group(channel).ok_or(Error::Unsupported)?;
    match gate.did() {
        0xc822 => {
            let gains = gate.cck_gains().ok_or(Error::State)?;
            super::radio::channel_to(io, channel).await?;
            super::radio::gains(io, gains)?;
            if rfk {
                iqk8822c(io, gains).await?;
            }
            verify8822c(io, channel, gains)
        }
        0xc821 => {
            let indices = gate.c21_indices().ok_or(Error::State)?;
            super::radio8821c::retune_channel(io, channel).await?;
            super::radio8821c::write_txagc(io, indices)?;
            if rfk {
                iqk8821c(io).await?;
            }
            super::radio8821c::verify_retune(io, channel, indices)
        }
        _ => Err(Error::Unsupported),
    }
}

fn dpd_off(io: &mut impl Io) -> Result<(), Error> {
    for path in 0..2 {
        super::radio::mask(io, 0x1b00, 6, path)?;
        super::radio::mask(io, 0x1b08, 1 << 31, 0)?;
    }
    super::radio::mask(io, 0xa70, 0x3ff, 0x3ff)
}

/// `rtw8822c_do_iqk` (clear=1) on the retained channel. REG_RPT_CIP has no
/// host reset, so a completion is accepted only after a post-submission
/// transition into IQK_DONE: a value other than 0xaa must be observed after
/// the H2C is consumed (or before submission) and then 0xaa again.
async fn iqk8822c(io: &mut impl Io, gains: [u8; 2]) -> Result<(), Error> {
    dpd_off(io)?;
    let before = io.read8(0x2d9c)?;
    if before == 255 {
        return Err(Error::Gone);
    }
    super::radio::rfk_power(io, true)?;
    io.station_retune_iqk()?;
    wait_h2c(io).await?;
    let mut armed = before != 0xaa;
    let mut complete = false;
    for _ in 0..300 {
        let value = io.read8(0x2d9c)?;
        if value == 255 {
            return Err(Error::Gone);
        }
        if value != 0xaa {
            armed = true;
        } else if armed {
            complete = true;
            break;
        }
        io.delay_us(1000).await;
    }
    if !complete {
        return Err(Error::Timeout);
    }
    io.write8(0x1b10, 0)?;
    super::radio::rfk_power(io, false)?;
    dpd_off(io)?;
    super::radio::gains(io, gains)
}

fn verify8822c(io: &mut impl Io, channel: u8, gains: [u8; 2]) -> Result<(), Error> {
    for (path, gain) in gains.into_iter().enumerate() {
        if super::radio::rf_read(io, path as u8, 0x18)? & 0x733ff != 0x3000 | u32::from(channel)
            || (super::radio::read(io, if path == 0 { 0x18a0 } else { 0x41a0 })? >> 16) & 127
                != u32::from(gain)
        {
            return Err(Error::Prerequisite);
        }
    }
    if super::radio::read(io, 0xc30)? & 0xfff != scotrk(channel)
        || (super::radio::read(io, 0x808)? >> 4) & 7 != txdfir(channel)
        || super::radio::read(io, 0x440)? != 0x1f
    {
        return Err(Error::Prerequisite);
    }
    Ok(())
}

/// `rtw8821c_do_iqk` before association (clear=0, segment=0). RF_DTXLOK is
/// host-cleared after each run, so a stale done marker is refused.
async fn iqk8821c(io: &mut impl Io) -> Result<(), Error> {
    if super::radio8821c::rf_read(io, 8)? == 0xabcde {
        return Err(Error::Prerequisite);
    }
    io.station_retune_iqk()?;
    wait_h2c(io).await?;
    let mut complete = false;
    for attempt in 0..300 {
        if super::radio8821c::rf_read(io, 8)? == 0xabcde {
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
    if super::radio::read(io, 0x1bf0)? & 0x100ff != 0 {
        return Err(Error::Prerequisite);
    }
    Ok(())
}
