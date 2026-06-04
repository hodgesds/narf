//! HDCP 2.x key derivation + message MICs.
//!
//! Cleanroom Rust impl of the host-side HDCP 2.3 cryptography surface
//! the way SEC2 (NVIDIA) / PSP (AMD) / ME (Intel) firmware previously
//! owned. NARF puts it in-kernel so the open driver path doesn't depend
//! on vendor-signed firmware just to talk HDCP 2.x to a display.
//!
//! ## References
//!
//! - **HDCP 2.3 specification** (DCP LLC, public), §2.7 — Key
//!   Derivation Function. §2.2 — protocol messages H' / L' / V / M.
//!   <https://www.digital-cp.com/sites/default/files/specifications/HDCP%20on%20DisplayPort%20Specification%20Rev2_3.pdf>
//! - **`/home/daniel/git/linux/include/drm/display/drm_hdcp.h`** —
//!   canonical wire-format field sizes (`HDCP_2_2_*_LEN` constants);
//!   we mirror those names where they line up.
//! - **HDCP 2.3 errata** (2019) — RxCaps endianness clarification.
//! - **FIPS 198-1** — HMAC. <https://csrc.nist.gov/publications/detail/fips/198/1/final>
//!
//! ## KDF surface
//!
//! Per the host's KDF formulation (task input):
//!
//! ```text
//!     dkey(km, rn, ctr) = AES-128-CBC(km, ctr ‖ (rn ⊕ ctr)) with IV = 0
//!     kd  = dkey(km, rn, 0) ‖ dkey(km, rn, 1)         (32 B)
//!     kh  = HMAC-SHA256(kd, "kh")[0..16]              (16 B)
//!     ks  = caller-chosen 16-byte session key
//! ```
//!
//! The plaintext block `ctr ‖ (rn ⊕ ctr)` is a single 128-bit AES block
//! formed by concatenating the 8-byte counter and `(rn ⊕ ctr)`. Since
//! IV is all-zero and we encrypt one block, AES-128-CBC degenerates to
//! AES-128 of that block under key `km`.
//!
//! The H' / L' / V / M MIC inputs are HMAC-SHA256 outputs over the
//! per-message byte sequences specified by HDCP 2.3 §2.2.
//!
//! No GPL Linux source consulted for the crypto layer — the actual KDF
//! lives in vendor firmware (Intel MEI HDCP, NVIDIA SEC2, AMD PSP) and
//! the public Linux helpers are pure I/O glue.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

use crate::aes_ctr;
use crate::cmac_aes128::AES_BLOCK_LEN;
use crate::hkdf::hmac_sha256;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;

/// HDCP 2.x master-key length (§2.3.1).
pub const HDCP_KM_LEN: usize = 16;
/// HDCP 2.x session-key length.
pub const HDCP_KS_LEN: usize = 16;
/// HDCP rtx (host nonce) length.
pub const HDCP_RTX_LEN: usize = 8;
/// HDCP rrx (sink nonce) length.
pub const HDCP_RRX_LEN: usize = 8;
/// HDCP rn (locality-check round nonce) length.
pub const HDCP_RN_LEN: usize = 8;
/// HDCP riv (CTR riv for ks wrap) length.
pub const HDCP_RIV_LEN: usize = 8;
/// HDCP TxCaps wire length.
pub const HDCP_TX_CAPS_LEN: usize = 3;
/// HDCP RxCaps wire length.
pub const HDCP_RX_CAPS_LEN: usize = 3;
/// HMAC-SHA256 output length used for H' / L' / V / M.
pub const HDCP_MIC_LEN: usize = 32;

// ── Key derivation ───────────────────────────────────────────────────

/// `dkey(km, rn, ctr)` — one 128-bit AES output under km.
///
/// Plaintext block = `ctr ‖ (rn ⊕ ctr)` where both halves are 8 bytes.
/// `ctr` arrives as a single 64-bit counter index (0 or 1 in HDCP 2.x);
/// we expand to 8 bytes big-endian.
///
/// With CBC's IV = 0 and a single-block input, CBC degenerates to ECB
/// of the input block under km.
pub fn dkey(km: &[u8; HDCP_KM_LEN], rn: &[u8; HDCP_RN_LEN], ctr: u64) -> [u8; AES_BLOCK_LEN] {
    let mut block = [0u8; AES_BLOCK_LEN];
    // Lower half = ctr (8 bytes big-endian).
    block[0..8].copy_from_slice(&ctr.to_be_bytes());
    // Upper half = rn XOR ctr (treating rn as 8 bytes big-endian).
    let ctr_be = ctr.to_be_bytes();
    for i in 0..8 {
        block[8 + i] = rn[i] ^ ctr_be[i];
    }

    let cipher = Aes128::new(GenericArray::from_slice(km));
    let mut ga = GenericArray::clone_from_slice(&block);
    cipher.encrypt_block(&mut ga);
    let mut out = [0u8; AES_BLOCK_LEN];
    out.copy_from_slice(ga.as_slice());
    out
}

/// `kd = dkey(km, rn, 0) ‖ dkey(km, rn, 1)` — the 256-bit derived key
/// that keys H', L', V, and M.
pub fn derive_kd(km: &[u8; HDCP_KM_LEN], rn: &[u8; HDCP_RN_LEN]) -> [u8; 32] {
    let d0 = dkey(km, rn, 0);
    let d1 = dkey(km, rn, 1);
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&d0);
    out[16..].copy_from_slice(&d1);
    out
}

/// `kh = HMAC-SHA256(kd, "kh")[0..16]` — the 128-bit key that wraps
/// km in the AKE_Send_Pairing_Info / AKE_Stored_km messages.
pub fn derive_kh(kd: &[u8; 32]) -> [u8; 16] {
    let mac = hmac_sha256(kd, b"kh");
    let mut out = [0u8; 16];
    out.copy_from_slice(&mac[..16]);
    out
}

/// Wrap a 128-bit session key `ks` with AES-128 CTR under kd, starting
/// the counter at `riv ‖ 0` (the riv is the 64-bit IV the host sends
/// in SKE_Send_Eks; the lower 64 bits are zero per §2.2.5).
pub fn wrap_ks_ctr(
    kd_low16: &[u8; 16],
    riv: &[u8; HDCP_RIV_LEN],
    ks: &[u8; HDCP_KS_LEN],
) -> [u8; HDCP_KS_LEN] {
    let mut iv = [0u8; AES_BLOCK_LEN];
    iv[..8].copy_from_slice(riv);
    // Lower half = 0; CTR keystream output is XOR'd into ks → ciphertext.
    let mut buf = *ks;
    aes_ctr::ctr_apply(kd_low16, iv, &mut buf);
    buf
}

/// Encrypt `km` with `kh` (AES-128 ECB, single block) for the
/// AKE_Send_Pairing_Info exchange (E_kh_km).
pub fn wrap_km_with_kh(
    kh: &[u8; 16],
    km: &[u8; HDCP_KM_LEN],
    m_xor: Option<&[u8; HDCP_KM_LEN]>,
) -> [u8; HDCP_KM_LEN] {
    // E_kh(km XOR m) where m = rtx || rrx (per §2.2.4 stored_km variant);
    // when m is None (initial pairing), m XOR = 0 → just E_kh(km).
    let mut block = *km;
    if let Some(m) = m_xor {
        for i in 0..HDCP_KM_LEN {
            block[i] ^= m[i];
        }
    }
    let cipher = Aes128::new(GenericArray::from_slice(kh));
    let mut ga = GenericArray::clone_from_slice(&block);
    cipher.encrypt_block(&mut ga);
    let mut out = [0u8; HDCP_KM_LEN];
    out.copy_from_slice(ga.as_slice());
    out
}

// ── Message MICs (H', L', V, M) ──────────────────────────────────────

/// Compute H' = HMAC-SHA256(rtx ‖ RxCaps ‖ TxCaps, kd).
///
/// Per HDCP 2.3 §2.2.3, the receiver computes this and the host
/// verifies it against its own re-computed value. Returns the 32-byte
/// HMAC tag.
pub fn compute_h_prime(
    kd: &[u8; 32],
    rtx: &[u8; HDCP_RTX_LEN],
    rx_caps: &[u8; HDCP_RX_CAPS_LEN],
    tx_caps: &[u8; HDCP_TX_CAPS_LEN],
) -> [u8; HDCP_MIC_LEN] {
    let mut msg = [0u8; HDCP_RTX_LEN + HDCP_RX_CAPS_LEN + HDCP_TX_CAPS_LEN];
    msg[..HDCP_RTX_LEN].copy_from_slice(rtx);
    msg[HDCP_RTX_LEN..HDCP_RTX_LEN + HDCP_RX_CAPS_LEN].copy_from_slice(rx_caps);
    msg[HDCP_RTX_LEN + HDCP_RX_CAPS_LEN..].copy_from_slice(tx_caps);
    hmac_sha256(kd, &msg)
}

/// Verify a presented H' — constant-time compare against the recomputed
/// value. Returns `true` on match.
pub fn verify_h_prime(
    kd: &[u8; 32],
    rtx: &[u8; HDCP_RTX_LEN],
    rx_caps: &[u8; HDCP_RX_CAPS_LEN],
    tx_caps: &[u8; HDCP_TX_CAPS_LEN],
    presented: &[u8; HDCP_MIC_LEN],
) -> bool {
    let expected = compute_h_prime(kd, rtx, rx_caps, tx_caps);
    ct_eq(&expected, presented)
}

/// Compute L' = HMAC-SHA256(rn, kd_xor_rrx).
///
/// HDCP 2.3 §2.3 locality-check: the receiver replies with L' within
/// 7 ms (DP) or 20 ms (HDMI). The key is `kd` with its lower 64 bits
/// XOR'd with rrx (per §2.7 — only the lower 8 bytes of kd are XOR'd).
pub fn compute_l_prime(
    kd: &[u8; 32],
    rrx: &[u8; HDCP_RRX_LEN],
    rn: &[u8; HDCP_RN_LEN],
) -> [u8; HDCP_MIC_LEN] {
    let mut keyed = *kd;
    // Lower 8 bytes (per spec — XOR rrx into the least-significant
    // 64 bits of kd before HMAC).
    for i in 0..HDCP_RRX_LEN {
        keyed[24 + i] ^= rrx[i];
    }
    hmac_sha256(&keyed, rn)
}

/// Verify a presented L' against the recomputed value.
pub fn verify_l_prime(
    kd: &[u8; 32],
    rrx: &[u8; HDCP_RRX_LEN],
    rn: &[u8; HDCP_RN_LEN],
    presented: &[u8; HDCP_MIC_LEN],
) -> bool {
    let expected = compute_l_prime(kd, rrx, rn);
    ct_eq(&expected, presented)
}

/// Compute V = HMAC-SHA256(ReceiverIDList ‖ RxInfo ‖ seq_num_V, kd) —
/// the repeater authentication MIC over the downstream topology.
/// HDCP 2.3 §2.3.5.
pub fn compute_v(
    kd: &[u8; 32],
    receiver_id_list: &[u8],
    rx_info: &[u8; 2],
    seq_num_v: &[u8; 3],
) -> [u8; HDCP_MIC_LEN] {
    let mut msg: Vec<u8> = Vec::with_capacity(receiver_id_list.len() + 2 + 3);
    msg.extend_from_slice(receiver_id_list);
    msg.extend_from_slice(rx_info);
    msg.extend_from_slice(seq_num_v);
    hmac_sha256(kd, &msg)
}

/// Compute M = HMAC-SHA256(StreamID_Type ‖ seq_num_M, k=kh).
/// HDCP 2.3 §2.3.6 stream management.
pub fn compute_m(kh: &[u8; 16], stream_id_type: &[u8], seq_num_m: &[u8; 3]) -> [u8; HDCP_MIC_LEN] {
    let mut msg: Vec<u8> = Vec::with_capacity(stream_id_type.len() + 3);
    msg.extend_from_slice(stream_id_type);
    msg.extend_from_slice(seq_num_m);
    hmac_sha256(kh, &msg)
}

// ── Constant-time helpers ────────────────────────────────────────────

/// Constant-time equality for two 32-byte arrays.
fn ct_eq(a: &[u8; HDCP_MIC_LEN], b: &[u8; HDCP_MIC_LEN]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..HDCP_MIC_LEN {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ── Tests ───────────────────────────────────────────────────────────

pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_hdcp_dkey_deterministic() -> TestResult {
        // dkey is deterministic and depends on all three inputs.
        let km = [0xAAu8; HDCP_KM_LEN];
        let rn = [0xBBu8; HDCP_RN_LEN];
        let d0 = dkey(&km, &rn, 0);
        let d1 = dkey(&km, &rn, 1);
        if d0 == d1 {
            return TestResult::Fail("dkey(km, rn, 0) must differ from dkey(km, rn, 1)");
        }
        // Re-derivation matches.
        let d0_again = dkey(&km, &rn, 0);
        if d0_again != d0 {
            return TestResult::Fail("dkey is non-deterministic");
        }
        // Different rn produces different output.
        let rn2 = [0xCCu8; HDCP_RN_LEN];
        let d_diff = dkey(&km, &rn2, 0);
        if d_diff == d0 {
            return TestResult::Fail("dkey ignores rn");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/hdcp", smoke_hdcp_dkey_deterministic);

    fn smoke_hdcp_dkey_block_layout() -> TestResult {
        // Reproduce dkey(km, rn, 0) by hand and verify the wiring.
        // Block layout = ctr (8 BE bytes) || (rn XOR ctr).
        // For ctr = 0, block = [0..0, rn[0]^0, rn[1]^0, ...]
        let km = [0u8; HDCP_KM_LEN];
        let rn = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let d0 = dkey(&km, &rn, 0);

        // Hand-compute AES(0, [0,0,0,0,0,0,0,0,0x01,0x02,...]).
        let mut expected = [0u8; 16];
        expected[8..].copy_from_slice(&rn);
        let cipher = Aes128::new(GenericArray::from_slice(&km));
        let mut ga = GenericArray::clone_from_slice(&expected);
        cipher.encrypt_block(&mut ga);
        let mut hand = [0u8; 16];
        hand.copy_from_slice(ga.as_slice());

        if d0 != hand {
            return TestResult::Fail("dkey block layout mis-wired");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/hdcp", smoke_hdcp_dkey_block_layout);

    fn smoke_hdcp_kd_is_two_dkeys_concatenated() -> TestResult {
        let km = [0x42u8; HDCP_KM_LEN];
        let rn = [0x33u8; HDCP_RN_LEN];
        let kd = derive_kd(&km, &rn);
        let d0 = dkey(&km, &rn, 0);
        let d1 = dkey(&km, &rn, 1);
        if kd[..16] != d0 || kd[16..] != d1 {
            return TestResult::Fail("kd != dkey0 || dkey1");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/hdcp", smoke_hdcp_kd_is_two_dkeys_concatenated);

    fn smoke_hdcp_kh_derivation() -> TestResult {
        // kh is HMAC-SHA256(kd, "kh") truncated to 16 bytes. Tampering
        // with kd must change kh.
        let kd_a = [0xAAu8; 32];
        let kd_b = [0xBBu8; 32];
        let kh_a = derive_kh(&kd_a);
        let kh_b = derive_kh(&kd_b);
        if kh_a == kh_b {
            return TestResult::Fail("kh ignores kd");
        }
        // Match against the raw HMAC truncation.
        let raw = hmac_sha256(&kd_a, b"kh");
        if kh_a[..] != raw[..16] {
            return TestResult::Fail("kh != HMAC(kd, 'kh')[0..16]");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/hdcp", smoke_hdcp_kh_derivation);

    fn smoke_hdcp_h_prime_inputs_all_matter() -> TestResult {
        let kd = [0x11u8; 32];
        let rtx = [0x22u8; HDCP_RTX_LEN];
        let rx_caps = [0x02, 0, 0];
        let tx_caps = [0x02, 0, 0];
        let h = compute_h_prime(&kd, &rtx, &rx_caps, &tx_caps);

        // Verify it.
        if !verify_h_prime(&kd, &rtx, &rx_caps, &tx_caps, &h) {
            return TestResult::Fail("verify_h_prime rejected its own output");
        }

        // Tamper with rtx → reject.
        let mut rtx2 = rtx;
        rtx2[0] ^= 1;
        if verify_h_prime(&kd, &rtx2, &rx_caps, &tx_caps, &h) {
            return TestResult::Fail("verify accepted modified rtx");
        }
        // Tamper with rx_caps.
        let rx2 = [0x02, 0, 0x01];
        if verify_h_prime(&kd, &rtx, &rx2, &tx_caps, &h) {
            return TestResult::Fail("verify accepted modified rx_caps");
        }
        // Tamper with tx_caps.
        let tx2 = [0x02, 0x01, 0];
        if verify_h_prime(&kd, &rtx, &rx_caps, &tx2, &h) {
            return TestResult::Fail("verify accepted modified tx_caps");
        }
        // Tamper with H' itself.
        let mut bad_h = h;
        bad_h[31] ^= 0x80;
        if verify_h_prime(&kd, &rtx, &rx_caps, &tx_caps, &bad_h) {
            return TestResult::Fail("verify accepted bit-flipped H'");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/hdcp", smoke_hdcp_h_prime_inputs_all_matter);

    fn smoke_hdcp_l_prime_key_xor_with_rrx() -> TestResult {
        let kd = [0x55u8; 32];
        let rrx = [0x99u8; HDCP_RRX_LEN];
        let rn = [0x77u8; HDCP_RN_LEN];
        let lp = compute_l_prime(&kd, &rrx, &rn);

        // Recompute by hand with the rrx XOR'd into bytes 24..32.
        let mut keyed = kd;
        for i in 0..HDCP_RRX_LEN {
            keyed[24 + i] ^= rrx[i];
        }
        let hand = hmac_sha256(&keyed, &rn);
        if lp != hand {
            return TestResult::Fail("L' != HMAC(kd_xor_rrx, rn)");
        }
        // Verify path.
        if !verify_l_prime(&kd, &rrx, &rn, &lp) {
            return TestResult::Fail("verify_l_prime rejected its own output");
        }
        // Tamper with rrx → reject.
        let mut bad_rrx = rrx;
        bad_rrx[0] ^= 1;
        if verify_l_prime(&kd, &bad_rrx, &rn, &lp) {
            return TestResult::Fail("L' verify accepted modified rrx");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/hdcp", smoke_hdcp_l_prime_key_xor_with_rrx);

    fn smoke_hdcp_wrap_ks_ctr_round_trip() -> TestResult {
        // Wrap ks under (kd_low16, riv); the receiver unwraps with the
        // same key+iv → recovers ks. Since CTR is self-inverse, our
        // round-trip applies wrap twice.
        let kd_low16 = [0x44u8; 16];
        let riv = [0x66u8; HDCP_RIV_LEN];
        let ks = [0x88u8; HDCP_KS_LEN];
        let wrapped = wrap_ks_ctr(&kd_low16, &riv, &ks);
        if wrapped == ks {
            return TestResult::Fail("CTR wrap produced identity");
        }
        let unwrapped = wrap_ks_ctr(&kd_low16, &riv, &wrapped);
        if unwrapped != ks {
            return TestResult::Fail("CTR wrap round-trip lost ks");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/hdcp", smoke_hdcp_wrap_ks_ctr_round_trip);

    fn smoke_hdcp_kh_wraps_km_round_trip() -> TestResult {
        // wrap_km_with_kh with m=None is straight AES; same key, decrypt
        // recovers km. We don't expose decrypt, but we can verify the
        // wrap is deterministic + reversible by hand-decrypting.
        use aes::cipher::BlockDecrypt;
        let kh = [0x33u8; 16];
        let km = [0x77u8; HDCP_KM_LEN];
        let wrapped = wrap_km_with_kh(&kh, &km, None);
        if wrapped == km {
            return TestResult::Fail("wrap_km_with_kh produced identity");
        }
        // Hand-decrypt.
        let cipher = Aes128::new(GenericArray::from_slice(&kh));
        let mut ga = GenericArray::clone_from_slice(&wrapped);
        cipher.decrypt_block(&mut ga);
        let mut recovered = [0u8; HDCP_KM_LEN];
        recovered.copy_from_slice(ga.as_slice());
        if recovered != km {
            return TestResult::Fail("hand-decrypt didn't recover km");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/hdcp", smoke_hdcp_kh_wraps_km_round_trip);

    fn smoke_hdcp_v_repeater_topology_mic() -> TestResult {
        let kd = [0x12u8; 32];
        let receiver_ids = [0xABu8; 10]; // 2 RIDs of 5 bytes each
        let rx_info = [0x00, 0x00];
        let seq = [0x00, 0x00, 0x01];
        let v = compute_v(&kd, &receiver_ids, &rx_info, &seq);
        if v.iter().all(|&b| b == 0) {
            return TestResult::Fail("V should not be all zero");
        }
        // Tampering with the receiver-ID list changes V.
        let mut bad = receiver_ids;
        bad[0] ^= 1;
        let v2 = compute_v(&kd, &bad, &rx_info, &seq);
        if v == v2 {
            return TestResult::Fail("V ignored receiver-ID list");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/hdcp", smoke_hdcp_v_repeater_topology_mic);

    fn smoke_hdcp_m_stream_management_mic() -> TestResult {
        let kh = [0x21u8; 16];
        let stream = [0x00, 0x01, 0x00, 0x01]; // 2 (stream_id, type) pairs
        let seq = [0x00, 0x00, 0x02];
        let m = compute_m(&kh, &stream, &seq);
        if m.iter().all(|&b| b == 0) {
            return TestResult::Fail("M should not be all zero");
        }
        // Tamper with the stream-type → M changes.
        let bad = [0x00, 0x00, 0x00, 0x01];
        let m2 = compute_m(&kh, &bad, &seq);
        if m == m2 {
            return TestResult::Fail("M ignored stream-id-type");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/hdcp", smoke_hdcp_m_stream_management_mic);

    fn smoke_hdcp_kd_changes_with_km() -> TestResult {
        // kd must depend on km; same rn but different km → different kd.
        let rn = [0x10u8; HDCP_RN_LEN];
        let km1 = [0x01u8; HDCP_KM_LEN];
        let km2 = [0x02u8; HDCP_KM_LEN];
        let kd1 = derive_kd(&km1, &rn);
        let kd2 = derive_kd(&km2, &rn);
        if kd1 == kd2 {
            return TestResult::Fail("kd should change when km changes");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/hdcp", smoke_hdcp_kd_changes_with_km);
}
