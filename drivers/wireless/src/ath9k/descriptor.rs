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
//! AR9285 non-EDMA, single-buffer legacy descriptors (Linux ar9002_mac.c).
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

/// No HT, aggregation, key-cache lookup, automatic sequence replacement,
/// padding, RTS/CTS or rate fallback is admitted by this initial profile.
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
        0 => fc & 0x4300 == 0 && matches!((fc >> 4) & 15, 0 | 4 | 10 | 11 | 12),
        2 => fc & 0x03f0 == 0x0100,
        _ => false,
    };
    if !admitted {
        return Err(Error::Profile);
    }
    encode_series(frame.len(), address, series, frame[4] & 1 != 0)
}
fn encode_series(
    length: usize,
    address: u64,
    series: Series,
    group: bool,
) -> Result<[u32; WORDS], Error> {
    if !(24..=MAX_MPDU).contains(&length) {
        return Err(Error::Length);
    }
    if address == 0
        || address & 3 != 0
        || address
            .checked_add(length as u64 - 1)
            .is_none_or(|end| end > u64::from(u32::MAX))
    {
        return Err(Error::Address);
    }
    if !series.valid(group) {
        return Err(Error::Profile);
    }
    let packet_length = (length + 4) as u32; // hardware adds the FCS.
    let mut words = [0; WORDS];
    words[1] = address as u32;
    // AR_ClrDestMask and MAX_RATE_POWER with TPC disabled: actual factory/
    // CTL/host-limited power is already programmed in the per-rate registers.
    words[2] = packet_length | (63 << 16) | (1 << 24);
    words[3] = length as u32 | if group { 1 << 24 } else { 0 };
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
        let (bitrate, code) = RATES[rate];
        let duration = if rate < 4 {
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
}
impl Mpdu {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
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
    let status = words[RX_DONE];
    if status & 1 == 0 {
        return Ok(None);
    }
    let length = (words[5] & 0xfff) as usize;
    if length > payload.len() || length > RX_BYTES {
        return Err(Error::Length);
    }
    if status & !0x8000_0003 != 0
        || words[5] & 0x1000 != 0
        || words[7] & 15 != 0
        || !(28..=MAX_MPDU + 4).contains(&length)
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
        });
    let Some(rate) = rate else {
        return Ok(None);
    };
    let bytes = &payload[..length - 4];
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
    let legacy = match (fc >> 2) & 3 {
        0 => fc & 0x4300 == 0,
        2 => fc & 0x03f0 == 0x0200,
        _ => false,
    };
    if !legacy {
        return Ok(None);
    }
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len())
        .map_err(|_| Error::Length)?;
    copy.extend_from_slice(bytes);
    Ok(Some(Mpdu {
        bytes: copy,
        rate,
        rssi: (words[8] >> 24) as i8,
    }))
}

#[cfg(feature = "kernel-test")]
#[path = "descriptor/tests.rs"]
mod tests;
