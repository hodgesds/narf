// SPDX-License-Identifier: GPL-2.0-or-later
//! Separately qualified 2.4GHz HT40 operation (`N2xB`) over the bound HT
//! program.
//!
//! Linux 7.3-rc4 sources:
//! - `main.c::rtw_init_ht_cap`: `SUP_WIDTH_20_40 | SGI_40` only when the
//!   firmware-reported `hw_cap.bw` has `RTW_CHANNEL_WIDTH_40`.
//! - `main.c::rtw_update_channel`: center channel, `primary_channel_idx`
//!   `RTW_SC_20_UPPER` (1) when the primary is above the center, else
//!   `RTW_SC_20_LOWER` (2).
//! - `main.c::rtw_set_channel` -> chip `set_channel(center, BW40, idx)`:
//!   `rtw8822c.c::rtw8822c_set_channel_bb` 2.4GHz BW40 branch (RXAGC CCK 4 /
//!   OFDM 0, CCKSB, TXBWCTL 5/sideband, NBI on, SBD 1, PT_OPT 1),
//!   `rtw_set_channel_mac` (DATA_SC, RFMOD_40M), `rtw8822c_set_channel_rf`
//!   (RF18 BW40, RXBB 0x10), `rtw8822c_toggle_igi`;
//!   `rtw8821c.c::rtw8821c_set_channel_bb` BW40 (RXSB, ADCCLK, ADC160),
//!   `rtw_set_channel_mac`, `_rf` (RF18 BW40, XTALX2 toggle), `_rxdfir` BW40.
//! - `phy.c::rtw_phy_get_2g_tx_power_index`: HT rates at BW40 use
//!   `bw40_base[group]` of the center channel's `rtw_get_channel_group`
//!   (one stream), plus `ht_2s_diff.bw40 * txgi_factor` (two streams).
//! - `main.c::rtw_update_sta_info`: `bw_mode` 40, SGI from the peer's
//!   `SGI_40`, `get_rate_id` BGN_40M_1SS (1) / BGN_40M_2SS (0);
//!   `fw.c::rtw_fw_send_ra_info` `SET_RA_INFO_BW_MODE` bits 25:24;
//!   `tx.c::rtw_tx_fill_tx_desc` `RTW_TX_DESC_W5_DATA_BW` bits 6:5.
//! - `rtw8822c.c::query_phy_status_page1`: RXSC 0 reports the current band
//!   width, 9..=12 a 40MHz PPDU.
//!
//! The record is channel-scoped (`rtw882Xce[-chNN]-ht40-v1-<mac>.bin` over
//! `channel_policy::scope_request`), binds only over a bound HT program with
//! the same MCS set, and carries its own measured 40MHz envelope (antenna
//! gain, qualified ceiling, peaks) and HT40 TXAGC indices, which must not
//! exceed the factory BW40 base of the center channel's group. Nothing is
//! inferred from the 20MHz programs. Both 20MHz halves must be admitted
//! channels (channel 1 or a loadable N2xO record), and the installed
//! regulatory domain must cover the whole 40MHz span with a rule allowing
//! 40MHz (cfg80211 `reg_process_ht_flags_channel` / `NO_HT40*`).
//!
//! Payload (bytes 56..120 of the generic 128-byte continuation):
//!
//! | Bytes | Field |
//! |---|---|
//! | 0 | primary 1..=13 |
//! | 1 | secondary = primary +/- 4, 1..=13 |
//! | 2 | width 40 (MHz) |
//! | 3 | flags: bit0 SGI40 |
//! | 4..6 | antenna gain, quarter dBi |
//! | 6..8 | qualified EIRP ceiling, quarter dBm |
//! | 8..14 | measured 40MHz peaks (IQK/calibration, response, data), quarter dBm |
//! | 14..16 | qualified TX MCS mask (equal to the bound HT program's) |
//! | 16..32 | HT40 TXAGC index for MCS0..15 (zero outside the mask; C21 1S) |
//! | 32..64 | zero |
use super::{
    firmware_transport::{Error, Io},
    power_policy::Gate,
    qualification::{Kind, PAYLOAD},
};
use narf_wireless::reg::{RegFlags, RegulatoryDomain};

pub(super) static KIND: Kind = Kind {
    tag: b'B',
    stem: "ht40",
    source: b"Linux 7.3-rc4 rtw88 main.c rtw_init_ht_cap SUP_WIDTH_20_40|SGI_40 hw_cap.bw; rtw_update_channel center/RTW_SC_20_UPPER1/LOWER2; rtw_set_channel; rtw8822c.c rtw8822c_set_channel_bb 2G BW40 RXAGC cck4 ofdm0 CCKSB0x1a00[4] TXBWCTL0x9b0 5/c0=0/ff00=sc|sc<<4 NBI0x1abc[30]1 SBD0x88c 1 PT_OPT0xcbc[21]1, rtw8822c_set_channel_rf RF18 BW40 bit13 rxbb0x10, rtw8822c_toggle_igi; rtw8821c.c rtw8821c_set_channel_bb BW40 RXSB0xa00[4] ADCCLK0x8ac ff3ff300|20020000|sc<<2|1 ADC160[30]1, _rf RF18 BW40 bit11 XTALX2 toggle, _rxdfir BW40; mac.c rtw_set_channel_mac DATA_SC0x483 RFMOD_40M 0x668[7] MAC clk80M USTIME80 CCK_CHECK; phy.c rtw_phy_get_2g_tx_power_index BW40 bw40_base[group(center)] + ht_2s_diff.bw40*factor; rtw_update_sta_info bw_mode40 SGI_40 get_rate_id BGN_40M_1SS1/2SS0; fw.c RA_INFO_BW_MODE 25:24; tx.c W5_DATA_BW 6:5; query_phy_status_page1 RXSC0=current bw; IQK at 40MHz before association; both 20MHz halves admitted; record 40MHz envelope; HT program MCS set unchanged",
    admit,
};

/// Decoded N2xB payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Record {
    pub(super) primary: u8,
    pub(super) secondary: u8,
    pub(super) sgi: bool,
    pub(super) antenna: i16,
    pub(super) ceiling: i16,
    pub(super) peaks: [i16; 3],
    pub(super) mcs: u16,
    pub(super) indices: [u8; 16],
}

impl Record {
    pub(super) fn decode(did: u16, p: &[u8; PAYLOAD]) -> Option<Self> {
        let signed = |at: usize| i16::from_le_bytes([p[at], p[at + 1]]);
        let record = Self {
            primary: p[0],
            secondary: p[1],
            sgi: p[3] & 1 != 0,
            antenna: signed(4),
            ceiling: signed(6),
            peaks: [signed(8), signed(10), signed(12)],
            mcs: u16::from_le_bytes([p[14], p[15]]),
            indices: p[16..32].try_into().ok()?,
        };
        let (max, streams) = match did {
            0xc822 => (127, 0xffff),
            0xc821 => (63, 0xff),
            _ => return None,
        };
        let unused_zero = (0..16).all(|i| record.mcs & (1 << i) != 0 || record.indices[i] == 0);
        // rtw8822c_set_tx_power_index: per-rate TXAGC is a signed 7-bit
        // difference from the MCS7 reference (as for the HT20 program).
        let c22_reference = did != 0xc822
            || record.mcs & 0x80 != 0
                && record.indices[7] <= 64
                && record.indices.iter().enumerate().all(|(i, v)| {
                    record.mcs & (1 << i) == 0
                        || (-64..=63).contains(&(i16::from(*v) - i16::from(record.indices[7])))
                });
        (center(record.primary, record.secondary).is_some()
            && p[2] == 40
            && p[3] & !1 == 0
            && record.mcs & 0xff != 0
            && record.mcs & !streams == 0
            && (0..=128).contains(&record.antenna)
            && (-512..=256).contains(&record.ceiling)
            && record.peaks.iter().all(|v| (-512..=256).contains(v))
            && record.indices.iter().all(|i| *i <= max)
            && unused_zero
            && c22_reference
            && p[32..] == [0; PAYLOAD - 32])
            .then_some(record)
    }
    pub(super) fn center(&self) -> u8 {
        center(self.primary, self.secondary).expect("validated HT40 pair")
    }
    /// `rtw_update_channel` primary sub-channel index.
    pub(super) fn sc(&self) -> u8 {
        if self.primary > self.secondary {
            1
        } else {
            2
        }
    }
    fn two_streams(&self) -> bool {
        self.mcs & 0xff00 != 0
    }
}

fn admit(did: u16, p: &[u8; PAYLOAD]) -> bool {
    Record::decode(did, p).is_some()
}

/// `main.c::hw_bw_cap_to_bitamp`: `EFUSE_HW_CAP_IGNORE` (0),
/// `SUPP_BW80` (7) and `SUPP_BW40` (6) include 40MHz.
pub(super) fn hardware_allows(bandwidth: u8) -> bool {
    matches!(bandwidth, 0 | 6 | 7)
}

/// Center channel of a 2.4GHz 40MHz pair: both halves in 1..=13 (channel
/// 14 is CCK-only) and the secondary exactly 4 channels away.
pub(super) fn center(primary: u8, secondary: u8) -> Option<u8> {
    ((1..=13).contains(&primary)
        && (1..=13).contains(&secondary)
        && primary.abs_diff(secondary) == 4)
        .then(|| primary.min(secondary) + 2)
}

/// Factory BW40 HT ceilings `(1S, 2S)` of the center channel's group must
/// enclose every qualified index.
pub(super) fn within_factory(gate: &Gate, record: &Record) -> bool {
    let Some((one, two)) =
        super::channel_policy::group(record.center()).and_then(|g| gate.ht40_limits(g))
    else {
        return false;
    };
    (0..16).all(|i| {
        let v = record.indices[i];
        if record.mcs & (1 << i) == 0 {
            true
        } else if i < 8 {
            v <= one
        } else {
            two.is_some_and(|two| v <= two)
        }
    })
}

/// Regulatory admission of the 40MHz span (`center +/- 20MHz`): every
/// overlapping rule is plain and allows 40MHz, one rule covers the span,
/// and every measured peak plus antenna gain fits the minimum ceiling.
/// Returns the admitted EIRP ceiling (quarter dBm).
pub(super) fn policy(record: &Record, domain: &RegulatoryDomain) -> Result<i16, Error> {
    let center =
        u32::from(super::channel_policy::frequency(record.center()).ok_or(Error::Unsupported)?);
    let (low, high) = (center - 20, center + 20);
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
            || r.max_bandwidth_mhz < 40
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

/// Live check of a bound N2xB record against the installed regulatory
/// domain, under its own capability and the current base gate.
pub(super) fn current(g: &super::qualification::Grant, gate: &Gate) -> Result<(), Error> {
    let domain = narf_wireless::reg::db::get_domain().ok_or(Error::Prerequisite)?;
    current_in(g, gate, &domain)
}

pub(super) fn current_in(
    g: &super::qualification::Grant,
    gate: &Gate,
    domain: &RegulatoryDomain,
) -> Result<(), Error> {
    g.invoke_source(|| {
        let record = Record::decode(gate.did(), g.payload()).ok_or(Error::State)?;
        if !g.is(&KIND) || record.primary != gate.channel() || !within_factory(gate, &record) {
            return Err(Error::State);
        }
        policy(&record, domain).map(|_| ())
    })
}

/// Secondary channel offset from an HT Operation element (61) in `ies`:
/// `(primary, Some(secondary))` for a 40MHz BSS (SCO 1/3 with STA channel
/// width set), `(primary, None)` for 20MHz. `None` if absent/malformed.
pub(super) fn ht_operation(ies: &[u8]) -> Option<(u8, Option<u8>)> {
    let mut at = 0;
    while at + 2 <= ies.len() {
        let len = usize::from(ies[at + 1]);
        let body = ies.get(at + 2..at + 2 + len)?;
        if ies[at] == 61 && len == 22 {
            let primary = body[0];
            let secondary = match (body[1] & 3, body[1] & 4 != 0) {
                (1, true) => Some(primary.checked_add(4)?),
                (3, true) => Some(primary.checked_sub(4)?),
                _ => None,
            };
            return Some((primary, secondary));
        }
        at += 2 + len;
    }
    None
}

fn words(record: &Record) -> [u32; 16] {
    let mut bytes = [0; 64];
    let reference = i16::from(record.indices[7]);
    let last = if record.two_streams() { 28 } else { 20 };
    for (rate, b) in bytes.iter_mut().enumerate() {
        let index = if (12..last).contains(&rate) {
            i16::from(record.indices[rate - 12])
        } else {
            0
        };
        *b = if rate < 4 {
            0
        } else {
            ((index - reference) as i8 as u8) & 127
        };
    }
    core::array::from_fn(|i| u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap()))
}

/// Program the record's HT40 TXAGC (`rtw_phy_set_tx_power_level` at BW40).
/// C22: per-path OFDM reference (MCS7) and the per-rate difference words,
/// laid out as the HT20 program does; C21: the HT MCS0..7 words.
pub(super) fn write_power(io: &mut impl Io, did: u16, record: &Record) -> Result<(), Error> {
    match did {
        0xc822 => {
            for r in [0x18e8, 0x41e8] {
                super::radio::mask(io, 0x1c90, 1 << 15, 0)?;
                super::radio::mask(io, r, 0x1fc00, u32::from(record.indices[7]))?;
            }
            for (i, v) in words(record).into_iter().enumerate() {
                super::radio::mask(io, 0x1c90, 1 << 15, 0)?;
                io.write32(0x3a00 + i as u16 * 4, v)?;
            }
            Ok(())
        }
        0xc821 => {
            for (i, chunk) in record.indices[..8].chunks_exact(4).enumerate() {
                io.write32(
                    0x1d0c + i as u16 * 4,
                    u32::from_le_bytes(chunk.try_into().unwrap()),
                )?;
            }
            Ok(())
        }
        _ => Err(Error::Unsupported),
    }
}

pub(super) fn verify_power(io: &mut impl Io, did: u16, record: &Record) -> Result<(), Error> {
    check_power(&mut |r| super::radio::read(io, r), did, record)
}

/// Readback of [`write_power`] over any register view.
pub(super) fn check_power(
    read: &mut impl FnMut(u16) -> Result<u32, Error>,
    did: u16,
    record: &Record,
) -> Result<(), Error> {
    match did {
        0xc822 => {
            for r in [0x18e8, 0x41e8] {
                if read(r)? & 0x1fc00 != u32::from(record.indices[7]) << 10 {
                    return Err(Error::Prerequisite);
                }
            }
            for (i, v) in words(record).into_iter().enumerate() {
                if read(0x3a00 + i as u16 * 4)? != v {
                    return Err(Error::Prerequisite);
                }
            }
            Ok(())
        }
        0xc821 => {
            for (i, chunk) in record.indices[..8].chunks_exact(4).enumerate() {
                if read(0x1d0c + i as u16 * 4)? != u32::from_le_bytes(chunk.try_into().unwrap()) {
                    return Err(Error::Prerequisite);
                }
            }
            Ok(())
        }
        _ => Err(Error::Unsupported),
    }
}

/// `rtw_set_channel(center, BW40, sc)` + IQK + HT40 TX power after
/// `station_width_begin` paused and drained TX on the HT-bound gate.
pub(super) async fn program(io: &mut impl Io, gate: &Gate, record: &Record) -> Result<(), Error> {
    let (did, center, sc) = (gate.did(), record.center(), record.sc());
    match did {
        0xc822 => {
            let gains = gate.cck_gains().ok_or(Error::State)?;
            super::radio::width40(io, center, sc).await?;
            super::radio::gains(io, gains)?;
            super::channel_policy::iqk8822c(io, gains).await?;
            write_power(io, did, record)?;
            super::radio::verify_width40(io, center, sc, gains)?;
        }
        0xc821 => {
            super::radio8821c::width40(io, center, sc).await?;
            super::channel_policy::iqk8821c(io).await?;
            write_power(io, did, record)?;
            super::radio8821c::verify_width40(io, center, sc)?;
        }
        _ => return Err(Error::Unsupported),
    }
    verify_power(io, did, record)
}
