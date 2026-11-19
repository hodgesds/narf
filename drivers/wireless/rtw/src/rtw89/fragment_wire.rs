// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Pure source software-fragment metadata. No RF/key/native/queue authority.
//! Linux7.3-rc4 mac80211 tx.c split-before-encrypt and final duration rules.
use alloc::{vec, vec::Vec};
pub(super) const DISABLED: u32 = u32::MAX;
pub(super) const MAX_FRAGMENTS: usize = 16;
pub(super) fn threshold(value: u32) -> Option<u32> {
    if value == DISABLED {
        Some(value)
    } else if (256..=2346).contains(&value) {
        Some(value & !1)
    } else {
        None
    }
}
/// Original three-address native host header length. Fragment ownership is
/// separately bound to the one current peer/association/key/native epoch.
pub(super) fn header(frame: &[u8]) -> Option<usize> {
    if frame.len() < 24 || frame[0] & 3 != 0 || frame[1] & 0xb0 != 0 {
        return None;
    }
    match frame[0] {
        8 if matches!(frame[1] & 3, 1 | 2) => Some(24),
        0x88 if matches!(frame[1] & 3, 1 | 2)
            && frame.len() >= 26
            && frame[24] & 0xf0 == 0
            && frame[25] == 0 =>
        {
            Some(26)
        }
        0x00 | 0x10 | 0x40 | 0x50 | 0xa0 | 0xb0 | 0xc0 | 0xd0 if frame[1] & 3 == 0 => Some(24),
        _ => None,
    }
}
/// Plaintext split for Open DATA/unprotected management; secure trains use
/// the shared key owner BEFORE encryption. The caller supplied one host SN.
pub(super) fn split(frame: &[u8], limit: u32) -> Option<Vec<Vec<u8>>> {
    let limit = threshold(limit)?;
    let length = header(frame)?;
    if limit == DISABLED || frame[1] & 0x44 != 0 || frame[22] & 15 != 0 || frame[4] & 1 != 0 {
        return None;
    }
    if frame.len() + 4 <= limit as usize {
        return Some(vec![frame.to_vec()]);
    }
    let per = limit as usize - length - 4;
    let count = (frame.len() - length).div_ceil(per);
    if count > MAX_FRAGMENTS {
        return None;
    }
    let mut frames = Vec::new();
    frames.try_reserve_exact(count).ok()?;
    for (number, body) in frame[length..].chunks(per).enumerate() {
        let mut next = frame[..length].to_vec();
        next[22] = (next[22] & 0xf0) | number as u8;
        if number + 1 < count {
            next[1] |= 4;
        }
        next.extend_from_slice(body);
        frames.push(next);
    }
    Some(frames)
}
/// Source fixed CCK1 long preamble: ACK+SIFS=192+112+10 microseconds.
/// Earlier fragments reserve the next COMPLETE protected MPDU+FCS plus
/// twoACK+threeSIFS. Duration is excluded by CCMP AAD and is set AFTER seal.
pub(super) fn duration(next_mpdu: Option<usize>) -> Option<u16> {
    let duration = match next_mpdu {
        None => 314,
        Some(length) => 628u32
            .checked_add(202)?
            .checked_add(u32::try_from(length.checked_add(4)?).ok()?.checked_mul(8)?)?,
    };
    u16::try_from(duration).ok()
}
pub(super) fn durations(frames: &mut [Vec<u8>]) -> Option<()> {
    for index in 0..frames.len() {
        let next = frames.get(index + 1).map(Vec::len);
        let value = duration(next)?;
        if frames[index].len() < 24 {
            return None;
        }
        frames[index][2..4].copy_from_slice(&value.to_le_bytes());
    }
    Some(())
}
pub(super) fn recipe() -> [u8; 32] {
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(b"RTL8852B MACID0 ch1/20 TXA1 RXAB software fragmentation v1; threshold256..2346 even plaintext hdr+body+FCS; crypto overhead after split; max16 complete original fragments sameoneSN frag0..15/MF originalAAD; no groupRA/AMSDU/AMPDU/+HTC/MLD");
    hash.update(b"fixed CCK1 long-preamble data/management wholetrain no firmwareRA/multirate fallback; final314us ACK+SIFS, earlier2ACK+3SIFS+nextprotectedMPDU+FCS; hostSW_SEQ+originalfragno, no management HWSSN rewrite; no host hardware crypto");
    hash.update(b"retained wholetrain before issue; prePN original source/peer/port/prefix/BA/size/nativequeue; exact immutable bytes/key identity no PN/SN on Busy; one original terminal DMA+RPQ radio-success MPDU at a time; actual original cap/full joint program/current key and final RX prefix at descriptor/doorbell; cancel/loss retains issuedDMA and denies futureparts");
    hash.update(b"RX everyoriginal native descriptor/profile/peer/current association proof before optional fourentry2s/4096reassembly; eachCCMP MIC then same originalkeycolor/PN+1, no plain/protected/key epoch mixing; original EAPOL/PMF owner and terminal installs, openplainMSDU separate original peer cache; no premature Ethernet/key/port; pending train/cache blocks LPS, source RFtracking current and awake restore receipt unchanged");
    hash.finalize()
}
/// RTL8852A fragment recipe: the same bounded plaintext split as B, over
/// the A v0 TXWD path (MACID0 ch1/20, TX-A, RX-AB).
pub(super) fn recipe_a() -> [u8; 32] {
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(b"RTL8852A MACID0 ch1/20 TX-A RX-AB software fragmentation v1; threshold256..2346 even plaintext hdr+body+FCS; crypto overhead after split; max16 complete original fragments sameoneSN frag0..15/MF originalAAD; no groupRA/AMSDU/AMPDU/+HTC/MLD");
    hash.update(b"fixed CCK1 long-preamble data/management wholetrain no firmwareRA/multirate fallback; final314us ACK+SIFS, earlier2ACK+3SIFS+nextprotectedMPDU+FCS; hostSW_SEQ+originalfragno, no management HWSSN rewrite; no host hardware crypto");
    hash.update(b"retained wholetrain before issue; prePN original source/peer/port/prefix/BA/size/nativequeue; exact immutable bytes/key identity no PN/SN on Busy; one original terminal DMA+RPQ radio-success MPDU at a time; actual original cap/full joint program/current key and final RX prefix at descriptor/doorbell; cancel/loss retains issuedDMA and denies futureparts");
    hash.update(b"RX everyoriginal native descriptor/profile/peer/current association proof before optional fourentry2s/4096reassembly; eachCCMP MIC then same originalkeycolor/PN+1, no plain/protected/key epoch mixing; original EAPOL/PMF owner and terminal installs, openplainMSDU separate original peer cache; no premature Ethernet/key/port; pending train/cache blocks LPS, source RFtracking current and awake restore receipt unchanged");
    hash.finalize()
}
