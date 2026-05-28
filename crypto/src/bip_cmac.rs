//! BIP-CMAC-128 — 802.11w Management Frame Protection (MFP).
//!
//! BIP (Broadcast/Multicast Integrity Protocol) is the keyed-MAC
//! discipline that protects group-addressed and (for unicast)
//! certain management frames once Robust Management Frames are in
//! play. The CMAC-128 variant — the only mandatory one — uses
//! AES-128-CMAC keyed by the IGTK (Integrity Group Temporal Key)
//! and produces a 16-byte MIC.
//!
//! Frame-level wiring lives in `narf_wireless::mfp`; this module
//! is the pure-crypto surface: install an IGTK, compute or verify
//! a MIC from an `(AAD, body)` pair and an IPN.
//!
//! ## References
//!
//! - IEEE 802.11-2020 §12.5.4.1 (BIP), §11.4.3 (MFP).
//!   <https://standards.ieee.org/ieee/802.11/7028/>
//! - 802.11-2020 §9.4.2.55 (MMIE element layout).
//! - NIST SP 800-38B — CMAC primitive (we go through
//!   `crate::cmac_aes128`).
//! - Linux `net/mac80211/wpa.c::ieee80211_crypto_aes_cmac_*` for
//!   the AAD/IPN handling shape (GPL-2.0-or-later; cited under
//!   NARF's post-relicense policy).
//!
//! ## BIP AAD (§12.5.4.4)
//!
//! ```text
//!     AAD = FC_masked || A1 || A2 || A3
//! ```
//!
//! where `FC_masked` is the Frame Control field with the Retry,
//! PwrMgmt, and MoreData bits zeroed (so the MIC survives those
//! transit-only mutations). `A1`/`A2`/`A3` are the management
//! frame's addresses; AAD is 2 + 18 = 20 bytes.
//!
//! ## MMIE layout (§9.4.2.55)
//!
//! ```text
//!     Element ID (1, 0x4C)
//!     Length     (1)
//!     KeyID      (2 LE)
//!     IPN        (6, LE wire / BE in PN comparisons)
//!     MIC        (16 for CMAC-128, 8 for CMAC-64 deprecated)
//! ```
//!
//! ## Replay handling
//!
//! Per §12.5.4.5, the receiver maintains a 48-bit "rx_pn" per IGTK
//! key index; an incoming IPN must compare strictly greater than
//! the stored value (no sliding window for BIP — broadcast frames
//! are linearly ordered by the AP).
//!
//! No GPL Linux source consulted beyond the AAD-construction shape
//! and replay-counter discipline, both of which are explicitly in
//! IEEE 802.11-2020.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

use crate::cmac_aes128;

/// 802.11 Element ID for the Management MIC Element (§9.4.2.55).
pub const ELEMENT_ID_MMIE: u8 = 0x4C;

/// MMIE length when MIC is 16 bytes (CMAC-128): 2 (KeyID) + 6 (IPN) + 16.
pub const MMIE_LEN_CMAC_128: usize = 2 + 6 + 16;

/// BIP-CMAC-128 MIC length.
pub const BIP_MIC_LEN: usize = 16;

/// IPN (IGTK Packet Number) length on the wire.
pub const BIP_IPN_LEN: usize = 6;

/// IGTK and MMIE-protected key indices per §11.4.3 — the AP allocates
/// IGTKs into key index 4 or 5 (key indices 0..3 are CCMP PTK/GTK slots).
pub const IGTK_KEY_INDEX_MIN: u16 = 4;
pub const IGTK_KEY_INDEX_MAX: u16 = 5;

/// FC bitmask of the Retry / PwrMgmt / MoreData transit bits that BIP
/// AAD zeroes (§12.5.4.4).
const FC_MASK_TRANSIT_BITS: u16 = (1 << 11) | (1 << 12) | (1 << 13);

/// Errors surfaced by the BIP MIC engine.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BipError {
    /// MIC bytes did not match the recomputed value.
    MicFailed,
    /// Incoming IPN ≤ stored IPN — replay (§12.5.4.5).
    Replay,
    /// MMIE element layout was invalid (wrong ID, length, etc.).
    BadMmie,
    /// Frame too short for a 24-byte 802.11 header.
    Truncated,
    /// IGTK key index outside the IGTK range (4 or 5).
    BadKeyIndex,
}

/// Installed IGTK — key bytes + key index + per-key receive PN.
#[derive(Clone, Debug)]
pub struct Igtk {
    pub key: [u8; 16],
    pub key_id: u16,
    pub rx_pn: u64,
    pub tx_pn: u64,
}

impl Igtk {
    /// Install an IGTK per §11.4.3. Key index must be 4 or 5.
    pub fn install(key: [u8; 16], key_id: u16) -> Result<Self, BipError> {
        if !(IGTK_KEY_INDEX_MIN..=IGTK_KEY_INDEX_MAX).contains(&key_id) {
            return Err(BipError::BadKeyIndex);
        }
        Ok(Self {
            key,
            key_id,
            rx_pn: 0,
            tx_pn: 0,
        })
    }
}

/// Build the BIP AAD from a 24-byte management-frame header. AAD is
/// `FC_masked || A1 || A2 || A3` per §12.5.4.4. Result is exactly 20
/// bytes.
pub fn build_bip_aad(hdr: &[u8]) -> Result<[u8; 20], BipError> {
    if hdr.len() < 24 {
        return Err(BipError::Truncated);
    }
    let mut aad = [0u8; 20];
    // Mask FC[10..14] (Retry/PwrMgmt/MoreData) — wire FC is little-endian.
    let fc = u16::from_le_bytes([hdr[0], hdr[1]]);
    let fc_masked = fc & !FC_MASK_TRANSIT_BITS;
    aad[0..2].copy_from_slice(&fc_masked.to_le_bytes());
    // A1 || A2 || A3 — 6 bytes each, at offsets 4, 10, 16 in the 802.11 header.
    aad[2..8].copy_from_slice(&hdr[4..10]);
    aad[8..14].copy_from_slice(&hdr[10..16]);
    aad[14..20].copy_from_slice(&hdr[16..22]);
    Ok(aad)
}

/// Encode IPN as 6 little-endian bytes (the wire order in MMIE).
pub fn encode_ipn(ipn: u64) -> [u8; BIP_IPN_LEN] {
    let mut out = [0u8; BIP_IPN_LEN];
    for (i, b) in out.iter_mut().enumerate() {
        *b = (ipn >> (8 * i)) as u8;
    }
    out
}

/// Decode 6 little-endian IPN bytes into a u64.
pub fn decode_ipn(bytes: &[u8]) -> u64 {
    let mut v: u64 = 0;
    for (i, &b) in bytes.iter().take(BIP_IPN_LEN).enumerate() {
        v |= (b as u64) << (8 * i);
    }
    v
}

/// Build an MMIE blob (KeyID(2) || IPN(6) || MIC(16)) — the element
/// ID + length bytes are added by the frame-encoder layer in
/// `narf_wireless::mfp`. Length = 24 bytes for CMAC-128.
pub fn build_mmie_body(key_id: u16, ipn: u64, mic: &[u8; BIP_MIC_LEN]) -> [u8; MMIE_LEN_CMAC_128] {
    let mut out = [0u8; MMIE_LEN_CMAC_128];
    out[0..2].copy_from_slice(&key_id.to_le_bytes());
    out[2..8].copy_from_slice(&encode_ipn(ipn));
    out[8..24].copy_from_slice(mic);
    out
}

/// Parse an MMIE body (just the KeyID/IPN/MIC region — caller has
/// already validated the leading element-id + length bytes).
pub fn parse_mmie_body(buf: &[u8]) -> Result<(u16, u64, [u8; BIP_MIC_LEN]), BipError> {
    if buf.len() != MMIE_LEN_CMAC_128 {
        return Err(BipError::BadMmie);
    }
    let key_id = u16::from_le_bytes([buf[0], buf[1]]);
    let ipn = decode_ipn(&buf[2..8]);
    let mut mic = [0u8; BIP_MIC_LEN];
    mic.copy_from_slice(&buf[8..24]);
    Ok((key_id, ipn, mic))
}

/// Compute the BIP-CMAC-128 MIC over `(AAD || body)`. `body` is the
/// management-frame body *without* the trailing MMIE (the spec says
/// "frame body minus the MIC field"; the MMIE element-id + length
/// bytes are included since they are present on the wire prior to
/// the MIC, but the MIC itself is set to zero or absent during the
/// computation). Callers that need to MIC an outbound frame should
/// pass a body buffer where the MIC bytes inside the MMIE are zeros.
pub fn compute_mic(igtk: &Igtk, aad: &[u8; 20], body: &[u8]) -> [u8; BIP_MIC_LEN] {
    let mut buf = Vec::with_capacity(aad.len() + body.len());
    buf.extend_from_slice(aad);
    buf.extend_from_slice(body);
    cmac_aes128::cmac_aes128(&igtk.key, &buf)
}

/// Verify a BIP-CMAC-128 MIC. On success the caller is responsible for
/// committing the new rx_pn; this function does not mutate the IGTK
/// so callers can serialize replay-window updates.
pub fn verify_mic(
    igtk: &Igtk,
    aad: &[u8; 20],
    body_without_mic: &[u8],
    presented_mic: &[u8; BIP_MIC_LEN],
) -> Result<(), BipError> {
    let expected = compute_mic(igtk, aad, body_without_mic);
    // Constant-time compare (RFC 4493 §3 discipline).
    let mut diff = 0u8;
    for i in 0..BIP_MIC_LEN {
        diff |= expected[i] ^ presented_mic[i];
    }
    if diff != 0 {
        return Err(BipError::MicFailed);
    }
    Ok(())
}

/// Check + commit an inbound IPN per §12.5.4.5: must be strictly
/// greater than the stored rx_pn. Caller calls this after successful
/// MIC verify.
pub fn ipn_check_and_update(igtk: &mut Igtk, incoming_ipn: u64) -> Result<(), BipError> {
    if incoming_ipn <= igtk.rx_pn {
        return Err(BipError::Replay);
    }
    igtk.rx_pn = incoming_ipn;
    Ok(())
}

// ── Tests ───────────────────────────────────────────────────────────

pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_bip_install_rejects_wrong_index() -> TestResult {
        // Key indices 0..3 are CCMP slots; IGTK lives at 4 or 5.
        if Igtk::install([0u8; 16], 0).is_ok() {
            return TestResult::Fail("KeyID 0 should be rejected for IGTK");
        }
        if Igtk::install([0u8; 16], 3).is_ok() {
            return TestResult::Fail("KeyID 3 should be rejected for IGTK");
        }
        if Igtk::install([0u8; 16], 4).is_err() {
            return TestResult::Fail("KeyID 4 should be accepted");
        }
        if Igtk::install([0u8; 16], 5).is_err() {
            return TestResult::Fail("KeyID 5 should be accepted");
        }
        if Igtk::install([0u8; 16], 6).is_ok() {
            return TestResult::Fail("KeyID 6 should be rejected");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/bip", smoke_bip_install_rejects_wrong_index);

    fn smoke_bip_aad_masks_transit_bits() -> TestResult {
        // Build a 24-byte mgmt header with Retry/PwrMgmt/MoreData set.
        let mut hdr = [0u8; 24];
        hdr[0] = 0xD0; // subtype Action
        hdr[1] = 0x38; // Retry|PwrMgmt|MoreData
        // A1 / A2 / A3
        hdr[4..10].copy_from_slice(&[0x11; 6]);
        hdr[10..16].copy_from_slice(&[0x22; 6]);
        hdr[16..22].copy_from_slice(&[0x33; 6]);

        let aad = build_bip_aad(&hdr).expect("aad");
        if aad[1] & 0x38 != 0 {
            return TestResult::Fail("Retry/PwrMgmt/MoreData must be zeroed in AAD");
        }
        if aad[2..8] != [0x11u8; 6] || aad[8..14] != [0x22u8; 6] || aad[14..20] != [0x33u8; 6] {
            return TestResult::Fail("A1/A2/A3 not laid out correctly in AAD");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/bip", smoke_bip_aad_masks_transit_bits);

    fn smoke_bip_mic_round_trip() -> TestResult {
        let key = [0xAAu8; 16];
        let igtk = Igtk::install(key, 4).expect("install");
        let aad = [0xBBu8; 20];
        let body = [0xCCu8; 32];
        let mic = compute_mic(&igtk, &aad, &body);
        if mic.iter().all(|&b| b == 0) {
            return TestResult::Fail("MIC should not be all-zero");
        }
        verify_mic(&igtk, &aad, &body, &mic).expect("verify");
        // Tamper with body — verify must fail.
        let mut bad_body = body;
        bad_body[0] ^= 0x01;
        match verify_mic(&igtk, &aad, &bad_body, &mic) {
            Err(BipError::MicFailed) => {}
            _ => return TestResult::Fail("tampered body must reject"),
        }
        // Tamper with MIC.
        let mut bad_mic = mic;
        bad_mic[15] ^= 0x80;
        match verify_mic(&igtk, &aad, &body, &bad_mic) {
            Err(BipError::MicFailed) => {}
            _ => return TestResult::Fail("tampered MIC must reject"),
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/bip", smoke_bip_mic_round_trip);

    fn smoke_bip_ipn_replay_window_strictly_increasing() -> TestResult {
        let mut igtk = Igtk::install([0u8; 16], 4).expect("install");
        ipn_check_and_update(&mut igtk, 1).expect("first ipn");
        ipn_check_and_update(&mut igtk, 2).expect("ipn 2");
        // Equal → replay.
        match ipn_check_and_update(&mut igtk, 2) {
            Err(BipError::Replay) => {}
            _ => return TestResult::Fail("equal IPN should be rejected"),
        }
        // Regression → replay.
        match ipn_check_and_update(&mut igtk, 1) {
            Err(BipError::Replay) => {}
            _ => return TestResult::Fail("regression IPN should be rejected"),
        }
        // Jump forward is allowed (the AP may broadcast fewer than every PN).
        ipn_check_and_update(&mut igtk, 100).expect("jump");
        if igtk.rx_pn != 100 {
            return TestResult::Fail("rx_pn should advance to 100");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/bip", smoke_bip_ipn_replay_window_strictly_increasing);

    fn smoke_bip_mmie_body_round_trip() -> TestResult {
        let mic = [0xDEu8; 16];
        let body = build_mmie_body(4, 0x010203040506, &mic);
        if body.len() != MMIE_LEN_CMAC_128 {
            return TestResult::Fail("MMIE body length wrong");
        }
        let (kid, ipn, back_mic) = parse_mmie_body(&body).expect("parse");
        if kid != 4 {
            return TestResult::Fail("KeyID round-trip lost");
        }
        if ipn != 0x010203040506 {
            return TestResult::Fail("IPN round-trip lost");
        }
        if back_mic != mic {
            return TestResult::Fail("MIC round-trip lost");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/bip", smoke_bip_mmie_body_round_trip);
}
