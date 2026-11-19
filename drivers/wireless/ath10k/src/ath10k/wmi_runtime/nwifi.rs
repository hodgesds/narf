// SPDX-License-Identifier: GPL-2.0-or-later
//! Native-WiFi decap (`ATH10K_HW_TXRX_NATIVE_WIFI`, Linux's default
//! `rawmode=0`) for TLV station firmware without `RAW_MODE_SUPPORT`.
//!
//! TX mirrors mac.c `ath10k_tx_h_nwifi`: the 802.11 header leaves without QoS
//! Control (the TID travels in the HTT descriptor and firmware rebuilds QoS).
//! RX mirrors htt_rx.c `ath10k_htt_rx_h_mpdu`/`ath10k_htt_rx_h_undecap_nwifi`
//! with `fill_crypt_header`: each MSDU arrives as `[nwifi header][LLC...]`
//! while the first MSDU's descriptor holds the original 802.11 header and,
//! for a frame the firmware decrypted, its CCMP header (`rx_hdr_status`).
//! `undecap` rebuilds the RAW-equivalent original MPDU from those parts (an
//! A-MSDU as one aggregate with its subframe headers, the CCMP header kept,
//! MIC/FCS space appended) so the unchanged RAW descriptor, BA and shared
//! PN/replay admission run over it.
use super::htt::rx::Msdu;
use alloc::vec::Vec;

/// `RX_HTT_HDR_STATUS_LEN` bytes immediately before the MSDU payload.
const HDR_STATUS: usize = 64;
/// `IEEE80211_CCMP_HDR_LEN` (`ath10k_htt_rx_crypto_param_len`, AES-CCM).
const CCMP_HEADER: usize = 8;
/// `IEEE80211_CCMP_MIC_LEN`, re-added only so the RAW trim stays exact.
const CCMP_MIC: usize = 8;
/// `hw_params.decap_align_bytes` (4 on every TLV PCI chip).
const ALIGN: usize = 4;

fn word(descriptor: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(descriptor[at..at + 4].try_into().unwrap())
}
fn set_word(descriptor: &mut [u8], at: usize, value: u32) {
    descriptor[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

/// `RX_MSDU_START_INFO1_DECAP_FORMAT` of `rx_msdu_start_common.info1`
/// (descriptor byte 32): 0 RAW, 1 native WiFi, 2 Ethernet II, 3 802.3.
pub(super) fn decap_format(descriptor: &[u8]) -> u32 {
    (word(descriptor, 32) >> 8) & 3
}
/// `RX_MSDU_END_INFO0_LAST_MSDU` (`rx_msdu_end_common.info0`, byte 56).
pub(super) fn last_msdu(descriptor: &[u8]) -> bool {
    word(descriptor, 56) & (1 << 15) != 0
}
fn first_msdu(descriptor: &[u8]) -> bool {
    word(descriptor, 56) & (1 << 14) != 0
}

/// mac.c `ath10k_tx_h_nwifi`: remove QoS Control and the QoS subtype from
/// an 802.11 data frame. The caller passes the TID in the HTT descriptor.
pub(super) fn transmit(mut frame: Vec<u8>) -> Option<Vec<u8>> {
    if frame.len() < 24 || frame[0] & 0x0c != 0x08 || frame[1] & 0x83 != 0x01 {
        return None;
    }
    if frame[0] & 0x80 != 0 {
        if frame.len() < 26 {
            return None;
        }
        frame.drain(24..26);
        frame[0] &= !0x80;
    }
    Some(frame)
}

/// `ieee80211_get_DA`/`ieee80211_get_SA` of a three-address nwifi header.
fn addresses(header: &[u8]) -> ([u8; 6], [u8; 6]) {
    let at = |o: usize| -> [u8; 6] { header[o..o + 6].try_into().unwrap() };
    let to_ds = header[1] & 1 != 0;
    let from_ds = header[1] & 2 != 0;
    (
        if to_ds { at(16) } else { at(4) },
        if from_ds { at(16) } else { at(10) },
    )
}

/// Rebuild one original MPDU from the native-WiFi MSDUs of one A-MSDU
/// (first..last). `None` for anything that is not exactly that shape: a
/// frame the firmware could not decrypt is delivered RAW (htt_rx.c "it will
/// report the frame as raw") and never reaches this function.
pub(super) fn undecap(group: &[Msdu]) -> Option<Msdu> {
    let first = group.first()?;
    let count = group.len();
    for (index, msdu) in group.iter().enumerate() {
        if msdu.offload.is_some()
            || decap_format(&msdu.descriptor) != 1
            || first_msdu(&msdu.descriptor) != (index == 0)
            || last_msdu(&msdu.descriptor) != (index + 1 == count)
        {
            return None;
        }
    }
    let descriptor = &first.descriptor;
    let status = &descriptor[descriptor.len() - HDR_STATUS..];
    // Station receive is three-address data without +HTC (the RAW
    // admission refuses Order and four-address frames alike).
    if !matches!(status[0], 0x08 | 0x88) || status[1] & 0x83 != 0x02 {
        return None;
    }
    let qos = status[0] == 0x88;
    let length = if qos { 26 } else { 24 };
    let protected = status[1] & 0x40 != 0;
    let amsdu = qos && status[24] & 0x80 != 0;
    if !amsdu && count != 1 {
        return None;
    }
    let mut out = Vec::new();
    out.try_reserve(length + CCMP_HEADER + 2048 * count + CCMP_MIC + 4)
        .ok()?;
    out.extend_from_slice(&status[..length]);
    if protected {
        // AES-CCM only (`enctype` 6); the CCMP header follows the header
        // at its decap alignment and must carry ExtIV.
        if word(descriptor, 12) >> 28 != 6 {
            return None;
        }
        let at = length.next_multiple_of(ALIGN);
        let crypto = status.get(at..at + CCMP_HEADER)?;
        if crypto[3] & 0x20 == 0 {
            return None;
        }
        out.extend_from_slice(crypto);
    }
    let mut attention = 0;
    for (index, msdu) in group.iter().enumerate() {
        attention |= word(&msdu.descriptor, 4);
        let nwifi = &msdu.payload;
        // `ath10k_htt_rx_nwifi_hdrlen`: a three-address non-QoS header.
        if nwifi.len() < 24 || nwifi[0] & 0x8c != 0x08 || nwifi[1] & 3 == 3 || nwifi[1] & 0x80 != 0
        {
            return None;
        }
        let (da, sa) = addresses(nwifi);
        let body = &nwifi[24..];
        if amsdu {
            let subframe = 14 + body.len();
            if subframe > 2304 || u16::try_from(body.len()).is_err() {
                return None;
            }
            out.extend_from_slice(&da);
            out.extend_from_slice(&sa);
            out.extend_from_slice(&(body.len() as u16).to_be_bytes());
            out.extend_from_slice(body);
            if index + 1 != count {
                out.resize(out.len() + (ALIGN - subframe % ALIGN) % ALIGN, 0);
            }
        } else {
            // The original header has a different DA (and SA): copy the
            // decapped ones back (FromDS: DA = Address1, SA = Address3).
            out[4..10].copy_from_slice(&da);
            out[16..22].copy_from_slice(&sa);
            out.extend_from_slice(body);
        }
    }
    if protected {
        out.resize(out.len() + CCMP_MIC, 0);
    }
    out.resize(out.len() + 4, 0); // RAW carries FCS
    if out.len() > 0x3fff {
        return None;
    }
    let mut rebuilt = first.descriptor;
    let length = (word(&rebuilt, 24) & !0x3fff) | out.len() as u32;
    let info1 = word(&rebuilt, 32) & !0x300;
    let end = word(&rebuilt, 56) | 0xc000;
    set_word(&mut rebuilt, 4, attention);
    set_word(&mut rebuilt, 24, length);
    set_word(&mut rebuilt, 32, info1);
    set_word(&mut rebuilt, 56, end);
    Some(Msdu {
        descriptor: rebuilt,
        payload: out,
        offload: None,
    })
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "nwifi_tests.rs"]
mod tests;
