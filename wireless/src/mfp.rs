//! 802.11w Management Frame Protection (MFP) — frame-layer wrapper.
//!
//! Wires the BIP-CMAC-128 primitives from `narf_crypto::bip_cmac` into
//! the management-frame transmit / receive paths: emit an MMIE on
//! outbound protected group / Action frames, validate the MMIE on
//! inbound, and surface IGTK lifecycle to the supplicant.
//!
//! ## Spec references
//!
//! - IEEE 802.11-2020 §11.4.3 — Robust Management Frames + key install
//!   semantics. <https://standards.ieee.org/ieee/802.11/7028/>
//! - IEEE 802.11-2020 §12.5.4 — BIP construction.
//! - IEEE 802.11-2020 §9.4.2.55 — MMIE element layout.
//!
//! The actual MIC math lives in `narf-crypto`; this module is the
//! 802.11-frame glue that decides which frames need MMIE, where to
//! splice the MMIE bytes, and how to authenticate keys + replay.
//!
//! Cross-referenced against Linux `net/mac80211/wpa.c` (BIP AAD,
//! `ieee80211_crypto_aes_cmac_*`) for the field-by-field MIC compute
//! order — both citations are within the post-relicense policy.

use alloc::vec::Vec;

use narf_crypto::bip_cmac::{
    self, build_bip_aad, build_mmie_body, parse_mmie_body, BipError, Igtk, BIP_MIC_LEN,
    ELEMENT_ID_MMIE, MMIE_LEN_CMAC_128,
};

/// Errors surfaced to the MLME / supplicant layer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MfpError {
    /// IGTK key index outside the 4..=5 range.
    BadKeyIndex,
    /// MIC compare failed.
    MicFailed,
    /// IPN ≤ stored rx_pn.
    Replay,
    /// MMIE element missing, wrong ID, or wrong length.
    NoMmie,
    /// Frame too short for a 24-byte mgmt header + MMIE.
    Truncated,
}

impl From<BipError> for MfpError {
    fn from(e: BipError) -> Self {
        match e {
            BipError::MicFailed => MfpError::MicFailed,
            BipError::Replay => MfpError::Replay,
            BipError::BadMmie => MfpError::NoMmie,
            BipError::Truncated => MfpError::Truncated,
            BipError::BadKeyIndex => MfpError::BadKeyIndex,
        }
    }
}

/// IGTK slot pair — §11.4.3 says the AP advertises two IGTKs (active +
/// next) so STAs can roll over smoothly. Active key index lives in
/// 4..=5; the unused slot may be `None`.
#[derive(Default, Debug)]
pub struct MfpKeyStore {
    pub active: Option<Igtk>,
    pub next: Option<Igtk>,
}

impl MfpKeyStore {
    pub const fn new() -> Self {
        Self {
            active: None,
            next: None,
        }
    }

    /// Install an IGTK as the active key. Per §11.4.3 the new key may
    /// arrive in either slot 4 or 5; if a different IGTK was active,
    /// it's demoted to `next` so already-in-flight frames signed under
    /// the previous key can still verify until the rollover window
    /// closes.
    pub fn install_active(&mut self, key: [u8; 16], key_id: u16) -> Result<(), MfpError> {
        let new = Igtk::install(key, key_id).map_err(MfpError::from)?;
        if let Some(prev) = self.active.take() {
            self.next = Some(prev);
        }
        self.active = Some(new);
        Ok(())
    }

    /// Look up an IGTK by key index — either the active slot or the
    /// fallback `next` slot.
    pub fn find_by_key_id(&self, key_id: u16) -> Option<&Igtk> {
        if let Some(a) = &self.active {
            if a.key_id == key_id {
                return Some(a);
            }
        }
        if let Some(n) = &self.next {
            if n.key_id == key_id {
                return Some(n);
            }
        }
        None
    }

    pub fn find_by_key_id_mut(&mut self, key_id: u16) -> Option<&mut Igtk> {
        if let Some(a) = &mut self.active {
            if a.key_id == key_id {
                return Some(a);
            }
        }
        if let Some(n) = &mut self.next {
            if n.key_id == key_id {
                return Some(n);
            }
        }
        None
    }
}

/// Append an MMIE element to an outbound management-frame body and
/// fill in the BIP-CMAC-128 MIC.
///
/// `hdr_24` is the 24-byte 802.11 management header; `body` is the
/// mutable frame body the caller is building up — on entry the body
/// holds the unsigned fixed fields + IEs; on success the MMIE has been
/// appended with the correctly-computed MIC. Returns the IPN that was
/// stamped into the MMIE so callers can persist it for replay debugging.
pub fn protect_outbound(
    igtk: &mut Igtk,
    hdr_24: &[u8],
    body: &mut Vec<u8>,
) -> Result<u64, MfpError> {
    if hdr_24.len() < 24 {
        return Err(MfpError::Truncated);
    }
    // §12.5.4.5: tx_pn is monotonically incremented and stamped into the
    // outgoing MMIE.
    igtk.tx_pn = igtk.tx_pn.wrapping_add(1);
    let ipn = igtk.tx_pn;
    let aad = build_bip_aad(hdr_24).map_err(MfpError::from)?;

    // Reserve the MMIE bytes: ElementID (1) || Length (1) || body (24).
    let mmie_header_len = 2;
    let start_of_mmie = body.len();
    body.extend_from_slice(&[ELEMENT_ID_MMIE, (MMIE_LEN_CMAC_128) as u8]);
    // Zero the MMIE body region; we'll fill it in after MIC computation.
    body.extend(core::iter::repeat(0u8).take(MMIE_LEN_CMAC_128));

    // Per §12.5.4.4, the MIC is computed over (AAD || frame body) with
    // the MIC field inside the MMIE set to zero — which is what we just
    // staged. We've already pre-filled KeyID(2) || IPN(6) || zeros(16),
    // but the prepass needs the right KeyID/IPN bytes — write them now.
    let mmie_body_off = start_of_mmie + mmie_header_len;
    body[mmie_body_off..mmie_body_off + 2].copy_from_slice(&igtk.key_id.to_le_bytes());
    body[mmie_body_off + 2..mmie_body_off + 8]
        .copy_from_slice(&bip_cmac::encode_ipn(ipn));
    // MIC bytes already zero.

    let mic = bip_cmac::compute_mic(igtk, &aad, body);
    // Splice MIC into MMIE.
    body[mmie_body_off + 8..mmie_body_off + 24].copy_from_slice(&mic);

    // Sanity: cross-check by recomputing the MMIE body via build helper.
    let mmie_block = build_mmie_body(igtk.key_id, ipn, &mic);
    debug_assert_eq!(&body[mmie_body_off..mmie_body_off + 24], &mmie_block);

    Ok(ipn)
}

/// Verify an inbound management-frame body that should carry an MMIE
/// trailer and commit the new IPN on success.
///
/// `body` is the *full* management-frame body, MMIE included. On
/// success returns the slice of `body` *without* the MMIE so callers
/// can decode the remaining fixed fields + IEs. On failure the IGTK
/// rx_pn is untouched.
pub fn verify_inbound<'a>(
    store: &mut MfpKeyStore,
    hdr_24: &[u8],
    body: &'a [u8],
) -> Result<&'a [u8], MfpError> {
    if hdr_24.len() < 24 {
        return Err(MfpError::Truncated);
    }
    // MMIE is the last (2 + MMIE_LEN_CMAC_128) bytes of the body.
    let mmie_total = 2 + MMIE_LEN_CMAC_128;
    if body.len() < mmie_total {
        return Err(MfpError::Truncated);
    }
    let split = body.len() - mmie_total;
    let mmie_bytes = &body[split..];
    if mmie_bytes[0] != ELEMENT_ID_MMIE || mmie_bytes[1] as usize != MMIE_LEN_CMAC_128 {
        return Err(MfpError::NoMmie);
    }
    let (key_id, ipn, mic) = parse_mmie_body(&mmie_bytes[2..]).map_err(MfpError::from)?;

    // Recreate the body-with-zero-MIC view for the MIC compute.
    let mut probe = Vec::with_capacity(body.len());
    probe.extend_from_slice(&body[..split]);
    probe.extend_from_slice(&mmie_bytes[..2]);
    probe.extend_from_slice(&mmie_bytes[2..2 + 8]); // KeyID + IPN
    probe.extend(core::iter::repeat(0u8).take(BIP_MIC_LEN)); // MIC zeroed

    let aad = build_bip_aad(hdr_24).map_err(MfpError::from)?;
    let igtk = store
        .find_by_key_id_mut(key_id)
        .ok_or(MfpError::NoMmie)?;
    bip_cmac::verify_mic(igtk, &aad, &probe, &mic).map_err(MfpError::from)?;
    bip_cmac::ipn_check_and_update(igtk, ipn).map_err(MfpError::from)?;
    Ok(&body[..split])
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn make_hdr() -> [u8; 24] {
        let mut hdr = [0u8; 24];
        // Frame Control: Type=Mgmt (0), Subtype=Action (0xD).
        hdr[0] = 0xD0;
        hdr[1] = 0x00;
        // A1/A2/A3 — distinct addresses.
        hdr[4..10].copy_from_slice(&[0x11; 6]);
        hdr[10..16].copy_from_slice(&[0x22; 6]);
        hdr[16..22].copy_from_slice(&[0x33; 6]);
        hdr
    }

    fn smoke_mfp_install_promotes_active_to_next() -> TestResult {
        let mut store = MfpKeyStore::new();
        store.install_active([0xAA; 16], 4).expect("install");
        store.install_active([0xBB; 16], 5).expect("rotate");
        // Both keys should now be reachable.
        if store.active.as_ref().map(|k| k.key_id) != Some(5) {
            return TestResult::Fail("active should be key 5 after rotate");
        }
        if store.next.as_ref().map(|k| k.key_id) != Some(4) {
            return TestResult::Fail("previous active should drop into next");
        }
        if store.find_by_key_id(4).is_none() {
            return TestResult::Fail("old key 4 should still be findable in fallback");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/mfp", smoke_mfp_install_promotes_active_to_next);

    fn smoke_mfp_protect_and_verify_round_trip() -> TestResult {
        let hdr = make_hdr();
        let mut tx_igtk = Igtk::install([0x42; 16], 4).expect("install");
        // Some plausible Action-frame body — Category(1) + Action(1) +
        // a chunk of dialog/parameters.
        let mut body: Vec<u8> = alloc::vec![0x07, 0x01, 0xDE, 0xAD, 0xBE, 0xEF];
        let _ipn = protect_outbound(&mut tx_igtk, &hdr, &mut body).expect("protect");

        // Build a receive-side store with the same IGTK.
        let mut store = MfpKeyStore::new();
        store.install_active([0x42; 16], 4).expect("install rx");

        let original = verify_inbound(&mut store, &hdr, &body).expect("verify");
        if original != [0x07, 0x01, 0xDE, 0xAD, 0xBE, 0xEF] {
            return TestResult::Fail("verify_inbound should strip the MMIE");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/mfp", smoke_mfp_protect_and_verify_round_trip);

    fn smoke_mfp_verify_rejects_tampered_body() -> TestResult {
        let hdr = make_hdr();
        let mut tx_igtk = Igtk::install([0x42; 16], 4).expect("install");
        let mut body: Vec<u8> = alloc::vec![0x07, 0x01, 0xDE, 0xAD, 0xBE, 0xEF];
        protect_outbound(&mut tx_igtk, &hdr, &mut body).expect("protect");
        // Tamper with the Action body before the MMIE.
        body[3] ^= 0x01;

        let mut store = MfpKeyStore::new();
        store.install_active([0x42; 16], 4).expect("install rx");
        match verify_inbound(&mut store, &hdr, &body) {
            Err(MfpError::MicFailed) => TestResult::Pass,
            other => TestResult::Fail(match other {
                Ok(_) => "verify accepted tampered body",
                Err(_) => "verify failed with wrong error",
            }),
        }
    }
    kernel_test_in!("wireless/mfp", smoke_mfp_verify_rejects_tampered_body);

    fn smoke_mfp_verify_rejects_replay() -> TestResult {
        let hdr = make_hdr();
        let mut tx_igtk = Igtk::install([0x42; 16], 4).expect("install");
        let mut body1: Vec<u8> = alloc::vec![0x07, 0x01, 0xAA];
        let mut body2: Vec<u8> = alloc::vec![0x07, 0x01, 0xBB];
        protect_outbound(&mut tx_igtk, &hdr, &mut body1).expect("protect1");
        protect_outbound(&mut tx_igtk, &hdr, &mut body2).expect("protect2");

        let mut store = MfpKeyStore::new();
        store.install_active([0x42; 16], 4).expect("install rx");

        verify_inbound(&mut store, &hdr, &body2).expect("body2 first");
        // body1 has IPN=1, store rx_pn=2 → replay.
        match verify_inbound(&mut store, &hdr, &body1) {
            Err(MfpError::Replay) => TestResult::Pass,
            other => TestResult::Fail(match other {
                Ok(_) => "verify accepted replayed frame",
                Err(_) => "verify failed with wrong error",
            }),
        }
    }
    kernel_test_in!("wireless/mfp", smoke_mfp_verify_rejects_replay);

    // End-to-end: PSK → PMK → 4-way → install MFP IGTK.
    //
    // Threads the full WPA2-Personal path:
    //   1. PBKDF2-SHA1(passphrase, SSID, 4096, 32) ⇒ PMK
    //   2. PRF(PMK, ANonce, SNonce, AA, SA) ⇒ PTK (KCK/KEK/TK)
    //   3. Use the KEK conceptually to wrap an IGTK, then install it
    //      into the MFP key store; verify a round-trip MMIE protection.
    //
    // Steps 1 & 2 already have dedicated smokes covering the spec
    // vectors; this test stitches them with step 3 to assert the
    // wiring is consistent at the surface level.
    fn smoke_mfp_e2e_psk_pmk_4way_install_igtk() -> TestResult {
        use crate::eapol::derive_ptk;
        use narf_crypto::pbkdf2_sha1::wpa2_pmk;

        // (1) PSK → PMK.
        let pmk = wpa2_pmk(b"narfwifi-passphrase", b"NarfNet");
        if pmk.iter().all(|&b| b == 0) {
            return TestResult::Fail("PMK is all-zero");
        }
        // (2) PTK from PMK + nonces + addresses. Use the cleanroom
        // HMAC-SHA1 from iwlwifi/wpa.rs by going through the same
        // primitive — here we register a stub so the test doesn't
        // need the driver crate. Production wires the HMAC-SHA1
        // from iwlwifi/wpa::HmacSha1.
        struct LocalHmacSha1;
        impl crate::eapol::HmacPrimitive for LocalHmacSha1 {
            fn out_len(&self) -> usize {
                20
            }
            fn mac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
                narf_crypto::pbkdf2_sha1::hmac_sha1(key, data).to_vec()
            }
        }
        let aa = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let sa = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let anonce = [0x11u8; 32];
        let snonce = [0x22u8; 32];
        let ptk = derive_ptk(&LocalHmacSha1, &pmk, &aa, &sa, &anonce, &snonce, 16);
        if ptk.tk.len() != 16 || ptk.kek.iter().all(|&b| b == 0) {
            return TestResult::Fail("PTK derivation produced empty TK/KEK");
        }

        // (3) Install an IGTK and run a protect/verify cycle. (KEK is
        // conceptually used to unwrap the IGTK from M3's Key Data; here
        // we treat it as already-unwrapped IGTK bytes.)
        let mut igtk_key = [0u8; 16];
        igtk_key.copy_from_slice(&ptk.tk);
        let mut store = MfpKeyStore::new();
        store.install_active(igtk_key, 4).expect("install IGTK");

        // Mirror tx-side IGTK for the round-trip.
        let mut tx_igtk = Igtk::install(igtk_key, 4).expect("tx igtk");
        let hdr = make_hdr();
        let mut body: Vec<u8> = alloc::vec![0x07, 0x01, 0xCA, 0xFE];
        protect_outbound(&mut tx_igtk, &hdr, &mut body).expect("protect");
        let original = verify_inbound(&mut store, &hdr, &body).expect("verify");
        if original != [0x07, 0x01, 0xCA, 0xFE] {
            return TestResult::Fail("E2E MMIE verify lost original body");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/mfp", smoke_mfp_e2e_psk_pmk_4way_install_igtk);
}
