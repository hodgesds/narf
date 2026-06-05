//! iwlwifi WPA2-PSK 4-way handshake driver.
//!
//! Glues together the PMK derivation (PBKDF2-HMAC-SHA1 from
//! `narf_crypto::pbkdf2_sha1::wpa2_pmk`), the supplicant state machine
//! (`narf_wireless::eapol::Supplicant`), the HMAC-SHA1 PRF primitive
//! (`wpa::HmacSha1`), and the MIC computation needed to authenticate
//! M2 / M4 back to the AP.
//!
//! ## Reference
//! IEEE Std 802.11-2020 §12.7.6 (4-way handshake).
//! IEEE Std 802.11-2020 §12.7.1.3 (PTK derivation).
//! IEEE Std 802.11-2020 §12.7.2 (EAPOL-Key MIC).
//!
//! ## Flow
//!
//! 1. Caller produces PMK from passphrase+SSID via
//!    `derive_pmk(passphrase, ssid)`.
//! 2. Caller constructs `Wpa2Handshake::new(pmk, aa, sa, snonce)` once
//!    the assoc-response arrives.
//! 3. On each incoming EAPOL-Key frame from the AP the caller invokes
//!    `process` and forwards the returned response frame (with MIC
//!    installed) to the TX path.
//! 4. After M3 → M4 the supplicant is `done()`. The caller installs
//!    the PTK via `super::sta::AddStaKeyParams::ccmp_ptk` and the GTK
//!    via `super::sta::AddStaKeyParams::ccmp_gtk` (extracted from M3
//!    Key Data — KDE parsing remains caller-side for now).

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;
use narf_wireless::eapol::{KeyFrame, Ptk, Supplicant, FourWayError, FourWayState};

use super::wpa::HmacSha1;

/// CCMP-128 TK length.
pub const CCMP_TK_LEN: usize = 16;
/// AKM-1 / AKM-2 (HMAC-SHA1) MIC length.
pub const AKM_SHA1_MIC_LEN: usize = 16;

/// Derive the WPA2-Personal PMK from passphrase + SSID. Returns a
/// 32-byte PMK (PBKDF2-HMAC-SHA1, 4096 iterations).
pub fn derive_pmk(passphrase: &[u8], ssid: &[u8]) -> [u8; 32] {
    narf_crypto::pbkdf2_sha1::wpa2_pmk(passphrase, ssid)
}

/// Compute the EAPOL-Key MIC for an outgoing frame. The KCK is the
/// first 16 bytes of the PTK. The MIC field of `frame` must be zeroed
/// before calling — the caller takes the returned MIC and writes it
/// back into the frame's MIC slot.
///
/// Reference: 802.11-2020 §12.7.2 (Key MIC), AKM-1/2 uses
/// HMAC-SHA1-128 (first 16 bytes of the SHA-1 output).
pub fn compute_mic(kck: &[u8], eapol_bytes_with_zero_mic: &[u8]) -> [u8; AKM_SHA1_MIC_LEN] {
    let full = super::wpa::hmac_sha1(kck, eapol_bytes_with_zero_mic);
    let mut mic = [0u8; AKM_SHA1_MIC_LEN];
    mic.copy_from_slice(&full[..AKM_SHA1_MIC_LEN]);
    mic
}

/// Serialise an EAPOL frame, install the MIC, and re-serialise.
///
/// The Key MIC field sits at fixed offsets inside the EAPOL-Key body
/// (after the 4-byte EAPOL header); per §12.7.2:
///   EAPOL hdr [0..4]
///   Key body  [4..4+95+mic_len+...]
///   MIC slot offset within body: 1+2+2+8+32+16+8+8 = 77
///   so absolute offset = 4 + 77 = 81.
pub fn install_mic(frame: &mut KeyFrame, kck: &[u8]) {
    // Zero the MIC, then compute over the full EAPOL PDU bytes.
    for b in frame.key_mic.iter_mut() {
        *b = 0;
    }
    let pdu = frame.clone().into_eapol();
    let mic = compute_mic(kck, &pdu);
    frame.key_mic = mic.to_vec();
}

// ── Driver wrapper ──────────────────────────────────────────────────

/// Per-association handshake state.
pub struct Wpa2Handshake {
    /// Derived PMK (32 bytes).
    pub pmk: [u8; 32],
    /// Supplicant state machine driving M1→M2→M3→M4.
    pub supplicant: Supplicant,
}

impl Wpa2Handshake {
    /// Create a new handshake driver. `aa` is the AP BSSID; `sa` is
    /// our station MAC; `snonce` is a freshly-generated 32-byte random
    /// nonce.
    pub fn new(pmk: [u8; 32], aa: [u8; 6], sa: [u8; 6], snonce: [u8; 32]) -> Self {
        Self {
            pmk,
            supplicant: Supplicant::new(aa, sa, snonce),
        }
    }

    /// Process an incoming EAPOL-Key frame from the AP and return the
    /// fully-MIC'd response frame to TX (M2 after M1, M4 after M3),
    /// or `None` if the supplicant is idle / done.
    pub fn process(&mut self, rx: &KeyFrame) -> Result<Option<KeyFrame>, FourWayError> {
        let prev_state = self.supplicant.state;
        let maybe_reply = self.supplicant.handle(&HmacSha1, &self.pmk, CCMP_TK_LEN, rx)?;

        // If the supplicant emitted M2 or M4, MIC it.
        let mut out = maybe_reply;
        if let Some(ref mut frame) = out {
            // M2 (state advanced WaitM1→WaitM3): MIC bit is set; we
            // need the MIC computed against the KCK we just derived.
            // M4 (state advanced WaitM3→PtkDone): same.
            let need_mic = frame.has_mic();
            if need_mic {
                if let Some(ref ptk) = self.supplicant.ptk {
                    install_mic(frame, &ptk.kck);
                }
            }
            let _ = prev_state;
        }

        Ok(out)
    }

    /// True once M4 has been emitted and the PTK is ready to install.
    pub fn done(&self) -> bool {
        self.supplicant.state == FourWayState::PtkDone
    }

    /// Pull out the derived PTK once `done()` is true.
    pub fn ptk(&self) -> Option<&Ptk> {
        self.supplicant.ptk.as_ref()
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_wireless::eapol::{
        KeyFrame, KEY_DESCRIPTOR_RSN, KI_INSTALL, KI_KEY_ACK, KI_KEY_MIC, KI_KEY_TYPE_PAIRWISE,
        KI_SECURE,
    };

    // ── PBKDF2-SHA1 PMK derivation matches the canonical IEEE
    // 802.11i Annex J.4.2 test vector for SSID="IEEE", pass="password".
    //
    // The vector value comes from the standard; both Linux wpa_supplicant
    // and the iperf3 WPA2 test suites reproduce it.
    fn smoke_iwlwifi_wpa2_pmk_ieee_annex_j_vector() -> TestResult {
        let pmk = derive_pmk(b"password", b"IEEE");
        // Expected PMK from IEEE 802.11i-2004 Annex J.4.2 (PSK from
        // passphrase) — first 8 bytes are 0xF42C6FC52DF0EBEF.
        let expected_prefix: [u8; 8] = [0xF4, 0x2C, 0x6F, 0xC5, 0x2D, 0xF0, 0xEB, 0xEF];
        if pmk[..8] != expected_prefix {
            return TestResult::Fail("PMK prefix mismatch vs IEEE 802.11i Annex J.4.2");
        }
        TestResult::Pass
    }

    // ── PMK is deterministic across two calls with same inputs.
    fn smoke_iwlwifi_wpa2_pmk_deterministic() -> TestResult {
        let a = derive_pmk(b"narfwifi", b"NarfNet");
        let b = derive_pmk(b"narfwifi", b"NarfNet");
        if a != b {
            return TestResult::Fail("PMK derivation not deterministic");
        }
        // Different passphrase → different PMK.
        let c = derive_pmk(b"different", b"NarfNet");
        if a == c {
            return TestResult::Fail("different passphrase produced same PMK");
        }
        TestResult::Pass
    }

    // ── compute_mic returns a stable HMAC-SHA1-128.
    fn smoke_iwlwifi_compute_mic_known_vector() -> TestResult {
        // KCK = 0x0b * 20 (RFC 2104 case 1 key). Body = "Hi There".
        // HMAC-SHA1 = B617318655057264E28BC0B6FB378C8EF146BE00; first 16 bytes:
        let kck = [0x0bu8; 20];
        let body = b"Hi There";
        let mic = compute_mic(&kck, body);
        let expected: [u8; 16] = [
            0xB6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64,
            0xE2, 0x8B, 0xC0, 0xB6, 0xFB, 0x37, 0x8C, 0x8E,
        ];
        if mic != expected {
            return TestResult::Fail("compute_mic vector mismatch");
        }
        TestResult::Pass
    }

    // ── Full M1→M2→M3→M4 handshake produces PtkDone and a non-zero
    //    PTK with deterministic KCK/KEK/TK lengths.
    fn smoke_iwlwifi_handshake_full_round_trip() -> TestResult {
        let pmk = [0x42u8; 32];
        let aa = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let sa = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let snonce = [0x11u8; 32];

        let mut h = Wpa2Handshake::new(pmk, aa, sa, snonce);

        // Build M1.
        let mut m1 = KeyFrame::empty(AKM_SHA1_MIC_LEN);
        m1.descriptor_type = KEY_DESCRIPTOR_RSN;
        m1.key_information = KI_KEY_TYPE_PAIRWISE | KI_KEY_ACK;
        m1.replay_counter = 1;
        m1.key_nonce = [0xAAu8; 32];

        let m2 = match h.process(&m1) {
            Ok(Some(m2)) => m2,
            _ => return TestResult::Fail("expected M2"),
        };
        if !m2.has_mic() {
            return TestResult::Fail("M2 must have MIC bit");
        }
        // MIC must be non-zero now.
        if m2.key_mic.iter().all(|&b| b == 0) {
            return TestResult::Fail("M2 MIC was not installed");
        }

        // Build M3 — Install + ACK + MIC + Pairwise; nonce = ANonce
        // (must match what we recorded in M1).
        let mut m3 = KeyFrame::empty(AKM_SHA1_MIC_LEN);
        m3.descriptor_type = KEY_DESCRIPTOR_RSN;
        m3.key_information = KI_KEY_TYPE_PAIRWISE | KI_KEY_ACK | KI_KEY_MIC | KI_INSTALL | KI_SECURE;
        m3.replay_counter = 2;
        m3.key_nonce = [0xAAu8; 32]; // same as M1 ANonce
        // (MIC bytes themselves not validated by handshake driver.)

        let m4 = match h.process(&m3) {
            Ok(Some(m4)) => m4,
            _ => return TestResult::Fail("expected M4"),
        };
        if !m4.has_mic() {
            return TestResult::Fail("M4 must have MIC");
        }
        if !h.done() {
            return TestResult::Fail("handshake should be done after M4");
        }
        let ptk = match h.ptk() {
            Some(p) => p,
            None => return TestResult::Fail("PTK absent after handshake"),
        };
        if ptk.tk.len() != CCMP_TK_LEN {
            return TestResult::Fail("TK wrong length");
        }
        if ptk.kck.iter().all(|&b| b == 0) {
            return TestResult::Fail("KCK all-zero");
        }
        TestResult::Pass
    }

    kernel_test_in!(
        "drivers/wireless/iwlwifi/handshake",
        smoke_iwlwifi_wpa2_pmk_ieee_annex_j_vector
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/handshake",
        smoke_iwlwifi_wpa2_pmk_deterministic
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/handshake",
        smoke_iwlwifi_compute_mic_known_vector
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/handshake",
        smoke_iwlwifi_handshake_full_round_trip
    );
}
