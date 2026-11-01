// SPDX-License-Identifier: GPL-2.0-or-later
//! Explicit S-source-only control and mutable-PM descriptor admission.
use super::*;
pub(in crate::ath9k) fn transmit_ps(
    frame: &[u8],
    local: [u8; 6],
    ap: [u8; 6],
    aid: u16,
    address: u64,
    basic: usize,
    source: &crate::ath9k::ps::Grant,
) -> Result<[u32; WORDS], Error> {
    source.check().map_err(|_| Error::Profile)?;
    if basic >= 12
        || local == [0; 6]
        || local[0] & 1 != 0
        || ap == [0; 6]
        || ap[0] & 1 != 0
        || frame.get(4..10) != Some(&ap)
        || frame.get(10..16) != Some(&local)
    {
        return Err(Error::Profile);
    }
    let poll = frame.len() == 16
        && frame[..2] == [0xa4, 0x10]
        && (1..=2007).contains(&aid)
        && frame[2..4] == (aid | 0xc000).to_le_bytes();
    let null = frame.len() == 24
        && frame[0] == 0x48
        && matches!(frame[1], 1 | 0x11)
        && frame[2..4] == [0, 0]
        && frame[16..22] == ap
        && frame[22] & 15 == 0;
    if !poll && !null {
        return Err(Error::Profile);
    }
    let mut words = encode_series(
        frame.len(),
        address,
        Series::single(basic, false).ok_or(Error::Profile)?,
        false,
        false,
    )?;
    if poll {
        words[3] |= 2 << 20;
        words[4] &= !0x8000;
    } //PSPOLL preserves Duration/AID.
    Ok(words)
}
pub(in crate::ath9k) fn unmark(
    frame: &[u8],
    source: &crate::ath9k::ps::Grant,
) -> Result<Vec<u8>, Error> {
    source.check().map_err(|_| Error::Profile)?;
    if frame.len() < 24 || frame[0] & 0x0c != 8 {
        return Err(Error::Profile);
    }
    let mut copy = frame.to_vec();
    copy[1] &= !0x10;
    Ok(copy)
}

/// The original unqualified RX entry points keep rejecting Null subtypes.
/// This separate parser receives an actual S-bound native descriptor only.
pub(in crate::ath9k) fn receive_ps(
    words: &[u32; WORDS],
    payload: &[u8],
    profile: crate::ath9k::ht::Profile,
    ba: bool,
    source: &crate::ath9k::ps::Grant,
) -> Result<Option<Mpdu>, Error> {
    source.check().map_err(|_| Error::Profile)?;
    receive_inner(words, payload, Some(profile), ba, true)
}
