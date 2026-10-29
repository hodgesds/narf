// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2008-2011 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
//! AR9285 non-EDMA complete RAW legacy/HT20 descriptors (Linux ar9002_mac.c).
//! Words are host-order values; the retained DMA owner publishes little endian.
use super::rates::{Feedback, Series};
use alloc::vec::Vec;

pub(super) const WORDS: usize = 24;
pub(super) const BYTES: usize = WORDS * 4;
pub(super) const MAX_MPDU: usize = 2304;
pub(super) const RX_BYTES: usize = 4092;
pub(super) const RX_DONE: usize = 12;
pub(super) const TX_DONE: usize = 23;
const RATES: [(u16, u8); 12] = [
    (10, 0x1b),
    (20, 0x1a),
    (55, 0x19),
    (110, 0x18),
    (60, 0x0b),
    (90, 0x0f),
    (120, 0x0a),
    (180, 0x0e),
    (240, 0x09),
    (360, 0x0d),
    (480, 0x08),
    (540, 0x0c),
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Length,
    Address,
    Profile,
    Status,
}

/// Legacy management/data continuation. HT QoS has a distinct bounded encoder;
/// neither enables aggregation, key-cache lookup or automatic sequence update.
pub(super) fn transmit(
    frame: &[u8],
    local: [u8; 6],
    address: u64,
    rate: usize,
) -> Result<[u32; WORDS], Error> {
    let series =
        Series::single(rate, frame.get(4).is_some_and(|b| b & 1 != 0)).ok_or(Error::Profile)?;
    transmit_series(frame, local, address, series)
}
pub(super) fn transmit_series(
    frame: &[u8],
    local: [u8; 6],
    address: u64,
    series: Series,
) -> Result<[u32; WORDS], Error> {
    transmit_series_inner(frame, local, address, series, false)
}
pub(super) fn transmit_ba_response(
    frame: &[u8],
    local: [u8; 6],
    address: u64,
    rate: usize,
) -> Result<[u32; WORDS], Error> {
    if frame.len() != 33
        || frame[..2] != [0xd0, 0]
        || frame[4] & 1 != 0
        || frame[24..26] != [3, 1]
        || frame[27..29] != [0, 0]
    {
        return Err(Error::Profile);
    }
    transmit_series_inner(
        frame,
        local,
        address,
        Series::single(rate, false).ok_or(Error::Profile)?,
        true,
    )
}
pub(super) fn transmit_delba(
    frame: &[u8],
    local: [u8; 6],
    address: u64,
    rate: usize,
) -> Result<[u32; WORDS], Error> {
    if frame.len() != 30
        || frame[..2] != [0xd0, 0]
        || frame[4] & 1 != 0
        || frame[24..26] != [3, 2]
        || u16::from_le_bytes([frame[26], frame[27]]) & 0xfff != 0
        || frame[28..30] != 39u16.to_le_bytes()
    {
        return Err(Error::Profile);
    }
    transmit_series_inner(
        frame,
        local,
        address,
        Series::single(rate, false).ok_or(Error::Profile)?,
        true,
    )
}
fn transmit_series_inner(
    frame: &[u8],
    local: [u8; 6],
    address: u64,
    series: Series,
    recipient_ba: bool,
) -> Result<[u32; WORDS], Error> {
    if !(24..=MAX_MPDU).contains(&frame.len()) {
        return Err(Error::Length);
    }
    if local[0] & 1 != 0 || local == [0; 6] || frame[10..16] != local || frame[22] & 15 != 0 {
        return Err(Error::Profile);
    }
    let fc = u16::from_le_bytes([frame[0], frame[1]]);
    if fc & 0x9403 != 0 {
        return Err(Error::Profile);
    }
    let admitted = match (fc >> 2) & 3 {
        0 => fc & 0x4300 == 0 && matches!((fc >> 4) & 15, 0 | 4 | 10 | 11 | 12 | 13),
        2 => fc & 0x03f0 == 0x0100,
        _ => false,
    };
    if !admitted {
        return Err(Error::Profile);
    }
    if fc & 0xfc == 0xd0
        && !(recipient_ba
            && frame.len() == 30
            && frame[24..26] == [3, 2]
            && u16::from_le_bytes([frame[26], frame[27]]) & 0xfff == 0
            && frame[28..30] == 39u16.to_le_bytes())
        && (frame.len() != 33
            || frame[24..26] != [3, 1]
            || if recipient_ba {
                frame[27..29] != [0, 0] || {
                    let p = u16::from_le_bytes([frame[29], frame[30]]);
                    p & 2 != 2 || !(1..=64).contains(&(p >> 6))
                }
            } else {
                frame[27..29] != [37, 0] || u16::from_le_bytes([frame[29], frame[30]]) & !0x3c != 2
            }
            || !recipient_ba && frame[31..33] != [0, 0])
    {
        return Err(Error::Profile);
    }
    encode_series(frame.len(), address, series, frame[4] & 1 != 0, false)
}
pub(super) fn transmit_ht(
    frame: &[u8],
    local: [u8; 6],
    address: u64,
    mcs: u8,
    basic: usize,
    profile: super::ht::Profile,
) -> Result<[u32; WORDS], Error> {
    transmit_ht_tid(frame, local, address, mcs, basic, profile, 0)
}
/// HT QoS DATA whose QoS control names TID `0..=max_tid`, normal ACK, no
/// EOSP/A-MSDU. `max_tid` exceeds zero only under the N85Q program.
pub(super) fn transmit_ht_tid(
    frame: &[u8],
    local: [u8; 6],
    address: u64,
    mcs: u8,
    basic: usize,
    profile: super::ht::Profile,
    max_tid: u8,
) -> Result<[u32; WORDS], Error> {
    if !(26..=MAX_MPDU).contains(&frame.len())
        || frame[0] != 0x88
        || frame[1] & !8 != if frame[1] & 0x40 != 0 { 0x41 } else { 1 }
        || frame[10..16] != local
        || local[0] & 1 != 0
        || local == [0; 6]
        || frame[22] & 15 != 0
        || frame[24] > max_tid.min(7)
        || frame[25] != 0
        || mcs > 7
        || profile.mcs() & (1 << mcs) == 0
        || basic >= 12
        || profile.rts() && basic >= 4
    {
        return Err(Error::Profile);
    }
    let group = frame[4] & 1 != 0;
    let mut words = encode_series(
        frame.len(),
        address,
        Series {
            rates: [12 + mcs, 0, 0, 0],
            tries: [if group { 1 } else { 4 }, 0, 0, 0],
            basic: basic as u8,
        },
        group,
        true,
    )?;
    if profile.rts() && !group {
        // Linux ath_buf_set_rate + set11nPktDurRTSCTS: native packet duration
        // remains the DATA duration; hardware forms RTS/CTS NAV itself.
        words[2] |= 1 << 22; // AR_RTSEnable, never AR_CTSEnable as well.
        words[6] |= 1 << 15; // AR_RTSCTSQual0 for the only enabled series.
    }
    Ok(words)
}
pub(super) fn transmit_sender_action(
    frame: &[u8],
    local: [u8; 6],
    address: u64,
    rate: usize,
) -> Result<[u32; WORDS], Error> {
    if !(30..=33).contains(&frame.len())
        || frame[..2] != [0xd0, 0]
        || frame[4] & 1 != 0
        || frame[10..16] != local
        || local[0] & 1 != 0
        || local == [0; 6]
        || frame[22] & 15 != 0
        || !(frame.len() == 33
            && frame[24..26] == [3, 0]
            && frame[26] != 0
            && u16::from_le_bytes([frame[27], frame[28]]) & 0x3f == 2
            && (4..=64).contains(&(u16::from_le_bytes([frame[27], frame[28]]) >> 6))
            && frame[29..31] == [0, 0]
            && frame[31] & 15 == 0
            || frame.len() == 30
                && frame[24..26] == [3, 2]
                && frame[26..28] == [0, 8]
                && matches!(u16::from_le_bytes([frame[28], frame[29]]), 37 | 39))
    {
        return Err(Error::Profile);
    }
    encode_series(
        frame.len(),
        address,
        Series::single(rate, false).ok_or(Error::Profile)?,
        false,
        false,
    )
}
pub(super) fn transmit_bar(
    frame: &[u8],
    local: [u8; 6],
    address: u64,
    rate: usize,
) -> Result<[u32; WORDS], Error> {
    if frame.len() != 20
        || frame[..2] != [0x84, 0]
        || frame[4] & 1 != 0
        || frame[10..16] != local
        || local[0] & 1 != 0
        || local == [0; 6]
        || frame[16..18] != [4, 0]
        || frame[18] & 15 != 0
    {
        return Err(Error::Profile);
    }
    encode_series(
        20,
        address,
        Series::single(rate, false).ok_or(Error::Profile)?,
        false,
        false,
    )
}
pub(super) struct PairAddresses {
    pub payloads: [u64; 2],
    pub tail: u64,
}
pub(super) fn transmit_pair(
    frames: [&[u8]; 2],
    local: [u8; 6],
    addresses: PairAddresses,
    mcs: u8,
    basic: usize,
    profile: super::ht::Profile,
    permit: super::tx_ba::PairPermit,
) -> Result<[[u32; WORDS]; 2], Error> {
    if addresses.tail == 0 || addresses.tail & 3 != 0 || addresses.tail > u64::from(u32::MAX) {
        return Err(Error::Address);
    }
    let mut first = transmit_ht(frames[0], local, addresses.payloads[0], mcs, basic, profile)?;
    let encoded_last = transmit_ht(frames[1], local, addresses.payloads[1], mcs, basic, profile)?;
    if frames
        .iter()
        .enumerate()
        .any(|(i, f)| u16::from_le_bytes([f[22], f[23]]) >> 4 != permit.seq[i])
    {
        return Err(Error::Profile);
    }
    first[0] = addresses.tail as u32;
    first[3] |= 0x6000_0000;
    first[8] = permit.air as u32 | (u32::from(permit.delims) << 18);
    first[6] = (36
        + 4 * (8 * permit.air as u32 + 22)
            .div_ceil([26, 52, 78, 104, 156, 208, 234, 260][usize::from(mcs)]))
        | if profile.rts() { 0x8000 } else { 0 };
    let mut last = [0; WORDS];
    last[1] = encoded_last[1];
    last[2] = encoded_last[2];
    last[3] = encoded_last[3] | 0x4000_0000;
    Ok([first, last])
}
pub(super) fn pair_status(
    first: &[u32; WORDS],
    tail: &[u32; WORDS],
    seq: [u16; 2],
) -> Result<([bool; 2], Feedback), Error> {
    let mut status = *first;
    status[14..].copy_from_slice(&tail[14..]);
    let feedback = transmit_feedback(&status)?;
    if tail[TX_DONE] & 1 == 0 {
        return Err(Error::Status);
    }
    let txok = transmit_status(&status, false)? == TxStatus::Delivered;
    let ba = tail[14] & (1 << 30) != 0;
    if txok && !ba {
        return Err(Error::Status);
    } // Source STA deaf/mute/reset case.
    if !txok || tail[TX_DONE] >> 28 != 0 {
        return Ok(([false; 2], feedback));
    }
    let start = ((tail[TX_DONE] >> 1) & 4095) as u16;
    let bitmap = u64::from(tail[17]) | (u64::from(tail[18]) << 32);
    Ok((
        seq.map(|s| {
            let i = s.wrapping_sub(start) & 4095;
            i < 64 && bitmap & (1u64 << i) != 0
        }),
        feedback,
    ))
}
pub(super) fn bar_status(words: &[u32; WORDS], frame: &[u8]) -> Result<TxStatus, Error> {
    let status = transmit_status(words, false)?;
    if status == TxStatus::Delivered
        && (frame.len() != 20
            || words[14] & (1 << 30) == 0
            || words[TX_DONE] >> 28 != 0
            || ((words[TX_DONE] >> 1) & 4095)
                != u32::from(u16::from_le_bytes([frame[18], frame[19]]) >> 4))
    {
        return Err(Error::Status);
    }
    Ok(status)
}
/// Native pad is transport-only: authenticate original bytes before this call.
pub(super) fn dma_bytes(frame: &[u8]) -> Result<Vec<u8>, Error> {
    let qos = frame.first().is_some_and(|b| *b == 0x88);
    let mut dma = Vec::new();
    dma.try_reserve_exact(frame.len() + if qos { 2 } else { 0 })
        .map_err(|_| Error::Length)?;
    if qos {
        if frame.len() < 26 {
            return Err(Error::Length);
        }
        dma.extend_from_slice(&frame[..26]);
        dma.extend_from_slice(&[0, 0]);
        dma.extend_from_slice(&frame[26..]);
    } else {
        dma.extend_from_slice(frame);
    }
    Ok(dma)
}
fn encode_series(
    length: usize,
    address: u64,
    series: Series,
    group: bool,
    ht: bool,
) -> Result<[u32; WORDS], Error> {
    if !(20..=MAX_MPDU).contains(&length) {
        return Err(Error::Length);
    }
    if address == 0
        || address & 3 != 0
        || address
            .checked_add((length + if ht { 2 } else { 0 }) as u64 - 1)
            .is_none_or(|end| end > u64::from(u32::MAX))
    {
        return Err(Error::Address);
    }
    if !ht && !series.valid(group)
        || ht
            && (series.basic >= 12
                || !(12..20).contains(&series.rates[0])
                || series.tries[1..] != [0; 3])
    {
        return Err(Error::Profile);
    }
    let packet_length = (length + 4) as u32; // hardware adds the FCS.
    let mut words = [0; WORDS];
    words[1] = address as u32;
    // AR_ClrDestMask and MAX_RATE_POWER with TPC disabled: actual factory/
    // CTL/host-limited power is already programmed in the per-rate registers.
    words[2] = packet_length | (63 << 16) | (1 << 24);
    words[3] = (length + if ht { 2 } else { 0 }) as u32 | if group { 1 << 24 } else { 0 };
    // Linux enables native duration/L-SIG update for every supported frame;
    // the excluded PS-Poll profile is the sole upstream exception.
    words[4] = 0x8000;
    words[9] = u32::from(RATES[usize::from(series.basic)].1) << 20;
    for slot in 0..4 {
        let tries = series.tries[slot];
        if tries == 0 {
            break;
        }
        let rate = usize::from(series.rates[slot]);
        let (bitrate, code) = if ht {
            (0, 0x80 + (rate - 12) as u8)
        } else {
            RATES[rate]
        };
        let duration = if ht {
            36 + (packet_length * 8 + 22).div_ceil([26, 52, 78, 104, 156, 208, 234, 260][rate - 12])
                * 4
        } else if rate < 4 {
            10 + 192 + (packet_length * 8 * 1000) / (u32::from(bitrate) * 100)
        } else {
            16 + 20 + (22 + packet_length * 8).div_ceil(u32::from(bitrate) * 100 * 4 / 1000) * 4
        };
        if duration > 0x7fff {
            return Err(Error::Profile);
        }
        words[4] |= u32::from(tries) << (16 + slot * 4);
        words[5] |= u32::from(code) << (slot * 8);
        words[6 + slot / 2] |= duration << ((slot % 2) * 16);
        words[9] |= 1 << (2 + slot * 5); // One calibrated chain for every series.
        if slot != 0 {
            words[10 + slot] = 63 << 24;
        }
    }
    Ok(words)
}

pub(super) fn receive_descriptor(address: u64, next: u64) -> Result<[u32; WORDS], Error> {
    if address == 0
        || address & 3 != 0
        || next & 3 != 0
        || next > u64::from(u32::MAX)
        || address
            .checked_add(RX_BYTES as u64 - 1)
            .is_none_or(|end| end > u64::from(u32::MAX))
    {
        return Err(Error::Address);
    }
    let mut words = [0; WORDS];
    words[0] = next as u32;
    words[1] = address as u32;
    words[3] = RX_BYTES as u32;
    Ok(words)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TxStatus {
    Pending,
    Delivered,
    Failed,
}
pub(super) fn transmit_status(words: &[u32; WORDS], group: bool) -> Result<TxStatus, Error> {
    let done = words[TX_DONE];
    if done == u32::MAX {
        return Err(Error::Status);
    }
    if done & 1 == 0 {
        return Ok(TxStatus::Pending);
    }
    let status = words[15];
    transmit_feedback(words)?;
    if done & (1 << 17) != 0 || status & 0xf000e != 0 || (!group && status & 1 == 0) {
        return Ok(TxStatus::Failed);
    }
    Ok(TxStatus::Delivered)
}
/// FinalTxIdx names a programmed rate series, not a hardware error. A foreign
/// or disabled series is malformed and cannot retire this native owner.
pub(super) fn transmit_feedback(words: &[u32; WORDS]) -> Result<Feedback, Error> {
    let index = ((words[TX_DONE] >> 21) & 3) as usize;
    if words[4] >> (16 + index * 4) & 15 == 0 {
        return Err(Error::Status);
    }
    let code = (words[5] >> (index * 8)) as u8;
    let rate = RATES
        .iter()
        .position(|&(_, codeword)| codeword == code)
        .or_else(|| {
            (0x80..=0x87)
                .contains(&code)
                .then_some(12 + usize::from(code & 7))
        })
        .ok_or(Error::Status)?;
    Ok(Feedback {
        rate: rate as u8,
        retried: index != 0 || words[15] & 0xff0 != 0,
        radio: words[15] & 0xf000c == 0 && words[TX_DONE] & (1 << 17) == 0,
    })
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Mpdu {
    bytes: Vec<u8>,
    pub rate: usize,
    pub rssi: i8,
    pub stbc: bool,
    aggregation: Aggregation,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Aggregation {
    pub aggregate: bool,
    pub first: bool,
    pub more: bool,
}
impl Mpdu {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(super) fn aggregation(&self) -> Aggregation {
        self.aggregation
    }
}
impl narf_wireless::station_security::RawFrame for Mpdu {
    fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    fn unmodified(&self) -> bool {
        true
    }
}
/// Caller first observed RxDone with acquire/device ordering and owns the
/// exact payload extent. KeyMiss is normal for protected host-CCMP frames;
/// the MAC owner must have cleared the complete hardware key cache.
pub(super) fn receive(words: &[u32; WORDS], payload: &[u8]) -> Result<Option<Mpdu>, Error> {
    receive_inner(words, payload, None, false)
}
pub(super) fn receive_profile(
    words: &[u32; WORDS],
    payload: &[u8],
    profile: super::ht::Profile,
) -> Result<Option<Mpdu>, Error> {
    receive_inner(words, payload, Some(profile), false)
}
pub(super) fn receive_ba(
    words: &[u32; WORDS],
    payload: &[u8],
    profile: super::ht::Profile,
) -> Result<Option<Mpdu>, Error> {
    receive_inner(words, payload, Some(profile), true)
}
fn receive_inner(
    words: &[u32; WORDS],
    payload: &[u8],
    profile: Option<super::ht::Profile>,
    ba: bool,
) -> Result<Option<Mpdu>, Error> {
    let ht = profile.is_some();
    let status = words[RX_DONE];
    if status & 1 == 0 {
        return Ok(None);
    }
    let length = (words[5] & 0xfff) as usize;
    if length > payload.len() || length > RX_BYTES {
        return Err(Error::Length);
    }
    if status & !(0x8000_0003 | if ba { 0x2003_0000 } else { 0 }) != 0
        || words[5] & 0x1000 != 0
        || words[7] & 7 != 0
        || !(if ba { 24 } else { 28 }..=if ht { 3887 } else { MAX_MPDU + 4 }).contains(&length)
    {
        return Ok(None);
    }
    let code = (words[4] >> 24) as u8;
    let rate = RATES
        .iter()
        .position(|&(_, value)| value == code)
        .or_else(|| {
            if matches!(code, 0x1c..=0x1e) {
                RATES.iter().position(|&(_, value)| value == code & !4)
            } else {
                None
            }
        })
        .or_else(|| (ht && (0x80..=0x87).contains(&code)).then_some(12 + usize::from(code & 7)));
    let Some(rate) = rate else {
        return Ok(None);
    };
    // AR9002 status3 reports one-spatial-stream STBC in bit3. Admission is
    // directional: our source-bound RX capability plus the actual AP's
    // association-response TX_STBC, never the AP's RX capability alone.
    let stbc = words[7] & 8 != 0;
    if stbc && (rate < 12 || !profile.is_some_and(super::ht::Profile::rx_stbc)) {
        return Ok(None);
    }
    let bytes = &payload[..length - 4];
    let aggregation = Aggregation {
        aggregate: status & (1 << 17) != 0,
        more: status & (1 << 16) != 0,
        first: status & (1 << 29) != 0,
    };
    if ba
        && bytes.len() == 20
        && bytes[..2] == [0x84, 0]
        && rate < 12
        && status & 2 != 0
        && aggregation == Aggregation::default()
    {
        let mut copy = Vec::new();
        copy.try_reserve_exact(bytes.len())
            .map_err(|_| Error::Length)?;
        copy.extend_from_slice(bytes);
        return Ok(Some(Mpdu {
            bytes: copy,
            rate,
            rssi: (words[8] >> 24) as i8,
            stbc,
            aggregation,
        }));
    }
    if length < 28 {
        return Ok(None);
    }
    let fc = u16::from_le_bytes([bytes[0], bytes[1]]);
    // Native key miss can clear FrameOK while preserving complete CCMP
    // ciphertext. With the entire key cache invalid, only protected key-miss
    // frames may take this path; software authentication still gates delivery.
    if status & 2 == 0 && (status & 0x8000_0000 == 0 || fc & 0x4000 == 0) {
        return Ok(None);
    }
    if fc & 0x8403 != 0 || bytes[22] & 15 != 0 {
        return Ok(None);
    }
    let qos = ht
        && (fc >> 2) & 3 == 2
        && fc & 0x03f0 == 0x0280
        && bytes.len() >= 28
        && (bytes[24] & 0x70 == 0 || ba && bytes[24] & 0x70 == 0x60)
        && bytes[25] == 0;
    let legacy = match (fc >> 2) & 3 {
        0 => fc & 0x4300 == 0,
        2 => fc & 0x03f0 == 0x0200 || qos,
        _ => false,
    };
    if !legacy || !qos && length > MAX_MPDU + 4 || rate >= 12 && (!ht || (fc >> 2) & 3 != 2) {
        return Ok(None);
    }
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len())
        .map_err(|_| Error::Length)?;
    if qos {
        copy.extend_from_slice(&bytes[..26]);
        copy.extend_from_slice(&bytes[28..]);
    } else {
        copy.extend_from_slice(bytes);
    }
    Ok(Some(Mpdu {
        bytes: copy,
        rate,
        rssi: (words[8] >> 24) as i8,
        stbc,
        aggregation,
    }))
}

#[cfg(feature = "kernel-test")]
#[path = "descriptor/tests.rs"]
mod tests;
