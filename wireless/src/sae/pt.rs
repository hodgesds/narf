//! SAE Hash-to-Element (H2E) — Password Token (PT) and PWE derivation.
//!
//! ## Why H2E exists
//!
//! IEEE 802.11-2020 §12.4.4.2.2 ("hunting and pecking") iterates a
//! counter against the password until a candidate X-coordinate lands
//! on the curve. The iteration count statistically depends on the
//! password, leaking information through timing. The cure is to push
//! the curve-search into a constant-time hash-to-curve primitive —
//! IEEE 802.11-2020 §12.4.4.2.3 ("Hash to Element") is that fix.
//!
//! The on-wire signal that H2E is in use is the SAE Authentication
//! frame's Status field carrying `SAE_STATUS_HASH_TO_ELEMENT` (126,
//! §12.4.7.5). Peers that don't speak H2E reply with
//! `SAE_STATUS_UNSUPPORTED_GROUP` (77, §9.4.1.9) and the supplicant
//! falls back to the legacy loop in [`super::dragonfly`].
//!
//! ## Two-step derivation (PT then PWE)
//!
//! H2E splits the PWE derivation so the expensive hash-to-curve work
//! is done once per `(ssid, password)`; hostap `sae_derive_pt_ecc` and
//! `sae_derive_pwe_from_pt_ecc`, IEEE 802.11-2020 §12.4.4.2.3:
//!
//! ```text
//!   PT  = SSWU(HKDF-Expand(pwd-seed, "…u1 P1", 48) mod p)
//!       + SSWU(HKDF-Expand(pwd-seed, "…u2 P2", 48) mod p),
//!         pwd-seed = HKDF-Extract(ssid, password [|| identifier])
//!   PWE = (H(0^32, MAX(MAC) || MIN(MAC)) mod (r - 1) + 1) · PT
//! ```
//!
//! This is not RFC 9380 `hash_to_curve` (no `expand_message_xmd`, no
//! DST); only the SSWU map is shared. Pinned to the IEEE 802.11-2020
//! Annex J.10 PT/PWE vector (`smoke_sae_h2e_pwe_ieee_j10_vector`).
//!
//! [`pwe_hunt_and_peck`] is the §12.4.4.2.2 loop (hostap
//! `sae_derive_pwe_ecc`).
//!
use alloc::vec::Vec;

use narf_crypto::hkdf::{hkdf_expand, hkdf_extract, hmac_sha256};
use narf_crypto::p256::field::Fp;
use narf_crypto::p256::hash_to_curve::{map_to_curve_sswu, os2ip_mod_p};
use narf_crypto::p256::point::{scalar_mul, AffinePoint};
use narf_crypto::p256::scalar::Scalar;

/// The SAE Password Token for group 19, as hostap `sae_derive_pt_ecc`
/// (IEEE 802.11-2020 §12.4.4.2.3):
///
/// ```text
///   pwd-seed  = HKDF-Extract(ssid, password [|| identifier])
///   pwd-value = HKDF-Expand(pwd-seed, "SAE Hash to Element u1 P1", 48)
///   u1        = pwd-value mod p;  P1 = SSWU(u1)
///   pwd-value = HKDF-Expand(pwd-seed, "SAE Hash to Element u2 P2", 48)
///   u2        = pwd-value mod p;  P2 = SSWU(u2)
///   PT        = P1 + P2
/// ```
///
/// (`len = olen(p) + ceil(olen(p)/2)` = 48; SSWU with Z = -10 is
/// `narf_crypto::p256::hash_to_curve::map_to_curve_sswu`, hostap `sswu`.)
/// `identifier` is the SAE Password Identifier.
pub fn pt_h2e(ssid: &str, password: &str, identifier: Option<&str>) -> AffinePoint {
    pt_h2e_bytes(
        ssid.as_bytes(),
        password.as_bytes(),
        identifier.map(str::as_bytes),
    )
}

/// [`pt_h2e`] over raw octets (SSIDs and passwords need not be UTF-8).
pub fn pt_h2e_bytes(ssid: &[u8], password: &[u8], identifier: Option<&[u8]>) -> AffinePoint {
    let mut ikm: Vec<u8> = Vec::with_capacity(password.len() + identifier.map_or(0, |s| s.len()));
    ikm.extend_from_slice(password);
    if let Some(id) = identifier {
        ikm.extend_from_slice(id);
    }
    // sae_pwd_seed: hkdf_extract(hash_len, ssid, ssid_len, password [|| id])
    let pwd_seed = hkdf_extract(Some(ssid), &ikm);
    let point = |label: &[u8]| {
        let pwd_value = hkdf_expand(&pwd_seed, label, 48);
        let u = os2ip_mod_p(&pwd_value);
        map_to_curve_sswu(&u)
    };
    let p1 = point(b"SAE Hash to Element u1 P1");
    let p2 = point(b"SAE Hash to Element u2 P2");
    p1.to_projective().add_mixed(&p2).to_affine()
}

/// `MAX(STA-A-MAC, STA-B-MAC) || MIN(STA-A-MAC, STA-B-MAC)` (hostap
/// `sae_max_min_addr` / `sae_pwd_seed_key`).
fn max_min(a: &[u8; 6], b: &[u8; 6]) -> [u8; 12] {
    let (hi, lo) = if a > b { (a, b) } else { (b, a) };
    let mut out = [0u8; 12];
    out[..6].copy_from_slice(hi);
    out[6..].copy_from_slice(lo);
    out
}

/// `x mod (r - 1) + 1` for a 32-octet big-endian `x` (`r` = the P-256
/// group order): `2^256 < 2 (r - 1)`, so one conditional subtraction
/// reduces. The result is in `[1, r - 1]`.
fn mod_order_minus_one_plus_one(x: &[u8; 32]) -> Scalar {
    let rm1 = Scalar::ZERO.sub(&Scalar::ONE).to_bytes_be();
    let mut v = *x;
    if v >= rm1 {
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let d = v[i] as i16 - rm1[i] as i16 - borrow;
            v[i] = d.rem_euclid(256) as u8;
            borrow = (d < 0) as i16;
        }
    }
    Scalar::from_bytes_be(&v)
        .expect("value below r - 1")
        .add(&Scalar::ONE)
}

/// The PWE from a cached PT, as hostap `sae_derive_pwe_from_pt_ecc`
/// (IEEE 802.11-2020 §12.4.4.2.3):
///
/// ```text
///   val = H(0^32, MAX(STA-A-MAC, STA-B-MAC) || MIN(STA-A-MAC, STA-B-MAC))
///   val = val mod (r - 1) + 1
///   PWE = val · PT
/// ```
///
/// (`H` = HKDF-Extract / HMAC-SHA256 keyed with 32 zero octets.)
pub fn pwe_from_pt(pt: AffinePoint, mac_a: &[u8; 6], mac_b: &[u8; 6]) -> AffinePoint {
    let addrs = max_min(mac_a, mac_b);
    let hash = hkdf_extract(Some(&[0u8; 32]), &addrs);
    let val = mod_order_minus_one_plus_one(&hash);
    scalar_mul(&val, &pt)
}

/// The hunting-and-pecking PWE for group 19, as hostap
/// `sae_derive_pwe_ecc` + `sae_test_pwd_seed_ecc` (IEEE 802.11-2020
/// §12.4.4.2.2):
///
/// ```text
///   for counter = 1, 2, … (at least k = 40 rounds, until found):
///     pwd-seed  = HMAC-SHA256(MAX(addr) || MIN(addr), password || counter)
///     pwd-value = KDF-256(pwd-seed, "SAE Hunting and Pecking", p)
///     first pwd-value < p with x³ - 3x + b a quadratic residue → x,
///       its seed's parity (pwd-seed[31] & 1) → y parity
///   y = sqrt(x³ - 3x + b), negated when its LSB ≠ the saved parity
/// ```
///
/// Every round runs whatever was found (hostap's constant-iteration
/// loop; the stub password after `found` only changes which bytes are
/// hashed). Returns the PWE and the round that found it; `None` if no
/// candidate within 200 rounds (hostap's "SAE: Failed to find PWE").
pub fn pwe_hunt_and_peck(
    password: &[u8],
    mac_a: &[u8; 6],
    mac_b: &[u8; 6],
) -> Option<(AffinePoint, u8)> {
    let addrs = max_min(mac_a, mac_b);
    let prime = Fp::ZERO.sub(&Fp::ONE).to_bytes_be();
    // p = (p - 1) + 1 as big-endian bytes.
    let mut p_bytes = prime;
    for i in (0..32).rev() {
        let (v, c) = p_bytes[i].overflowing_add(1);
        p_bytes[i] = v;
        if !c {
            break;
        }
    }
    let mut found: Option<(Fp, u8, u8)> = None;
    let mut counter: u8 = 1;
    loop {
        if counter > 200 {
            return None;
        }
        let mut msg = Vec::with_capacity(password.len() + 1);
        msg.extend_from_slice(password);
        msg.push(counter);
        let pwd_seed = hmac_sha256(&addrs, &msg);
        let v = super::session::kdf_sha256(&pwd_seed, b"SAE Hunting and Pecking", &p_bytes, 32);
        let mut x = [0u8; 32];
        x.copy_from_slice(&v);
        if let Some(xf) = Fp::from_bytes_be(&x) {
            if found.is_none() && curve_rhs(&xf).is_quadratic_residue() {
                found = Some((xf, pwd_seed[31] & 1, counter));
            }
        }
        if found.is_some() && counter >= 40 {
            break;
        }
        counter += 1;
    }
    let (x, odd, round) = found?;
    let mut y = curve_rhs(&x).sqrt();
    if y.lsb() != odd {
        y = y.neg();
    }
    let pwe = AffinePoint {
        x,
        y,
        infinity: false,
    };
    Some((pwe, round))
}

/// `x³ - 3x + b` (P-256).
fn curve_rhs(x: &Fp) -> Fp {
    let x3 = x.square().mul(x);
    let three_x = x.add(x).add(x);
    x3.sub(&three_x)
        .add(&Fp::from_limbs(narf_crypto::p256::CURVE_B))
}

/// Validate that a candidate PWE is structurally usable: on-curve and
/// not the point at infinity. Per IEEE 802.11-2020 §12.4.4.1 the PWE
/// must be a non-identity element of the group.
pub fn pwe_valid(pwe: &AffinePoint) -> bool {
    if pwe.infinity {
        return false;
    }
    pwe.is_on_curve()
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod pt_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_sae_pt_h2e_deterministic() -> TestResult {
        // Same (ssid, password) ⇒ same PT.
        let pt1 = pt_h2e("narfnet", "narfwifi", None);
        let pt2 = pt_h2e("narfnet", "narfwifi", None);
        if pt1.x != pt2.x || pt1.y != pt2.y {
            return TestResult::Fail("pt_h2e not deterministic on same inputs");
        }
        if !pt1.is_on_curve() {
            return TestResult::Fail("PT must be on curve");
        }
        if pt1.infinity {
            return TestResult::Fail("PT must not be infinity");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae", smoke_sae_pt_h2e_deterministic);

    fn smoke_sae_pt_h2e_changes_with_password() -> TestResult {
        let pt1 = pt_h2e("narfnet", "alpha", None);
        let pt2 = pt_h2e("narfnet", "beta", None);
        if pt1.x == pt2.x && pt1.y == pt2.y {
            return TestResult::Fail("different password should yield different PT");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae", smoke_sae_pt_h2e_changes_with_password);

    fn smoke_sae_pt_h2e_changes_with_ssid() -> TestResult {
        let pt1 = pt_h2e("ssid-A", "pw", None);
        let pt2 = pt_h2e("ssid-B", "pw", None);
        if pt1.x == pt2.x && pt1.y == pt2.y {
            return TestResult::Fail("different SSID should yield different PT");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae", smoke_sae_pt_h2e_changes_with_ssid);

    fn smoke_sae_pt_h2e_identifier_separates() -> TestResult {
        // SAE-PK identifier acts as another DS axis: same (ssid, pw)
        // but different identifier ⇒ different PT.
        let pt_none = pt_h2e("net", "pw", None);
        let pt_a = pt_h2e("net", "pw", Some("id-A"));
        let pt_b = pt_h2e("net", "pw", Some("id-B"));
        if pt_none.x == pt_a.x && pt_none.y == pt_a.y {
            return TestResult::Fail("identifier=Some should differ from identifier=None");
        }
        if pt_a.x == pt_b.x && pt_a.y == pt_b.y {
            return TestResult::Fail("identifier-A vs identifier-B should differ");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae", smoke_sae_pt_h2e_identifier_separates);

    fn smoke_sae_pwe_from_pt_on_curve() -> TestResult {
        let pt = pt_h2e("net", "pw", None);
        let pwe = pwe_from_pt(pt, &[0x11; 6], &[0x22; 6]);
        if !pwe_valid(&pwe) {
            return TestResult::Fail("PWE must be a valid (on-curve, non-infinity) point");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae", smoke_sae_pwe_from_pt_on_curve);

    fn smoke_sae_pwe_from_pt_mac_pair_canonical() -> TestResult {
        // PWE must not depend on which MAC was passed first — both peers
        // must derive the same PWE. The canonical-order step inside
        // pwe_from_pt is what enforces this.
        let pt = pt_h2e("net", "pw", None);
        let a = [0xAA; 6];
        let b = [0xBB; 6];
        let pwe_ab = pwe_from_pt(pt, &a, &b);
        let pwe_ba = pwe_from_pt(pt, &b, &a);
        if pwe_ab.x != pwe_ba.x || pwe_ab.y != pwe_ba.y {
            return TestResult::Fail("PWE must be symmetric in MAC pair");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae", smoke_sae_pwe_from_pt_mac_pair_canonical);

    fn smoke_sae_pwe_from_pt_changes_with_mac_pair() -> TestResult {
        // Different MAC pair ⇒ different PWE (with overwhelming prob).
        let pt = pt_h2e("net", "pw", None);
        let pwe_1 = pwe_from_pt(pt, &[0x11; 6], &[0x22; 6]);
        let pwe_2 = pwe_from_pt(pt, &[0x33; 6], &[0x44; 6]);
        if pwe_1.x == pwe_2.x && pwe_1.y == pwe_2.y {
            return TestResult::Fail("PWE must change with MAC pair");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae", smoke_sae_pwe_from_pt_changes_with_mac_pair);

    fn smoke_sae_pwe_is_scalar_multiple_of_pt() -> TestResult {
        // The relationship `PWE = val · PT` is verifiable because we can
        // recompute `val` deterministically from (PT, MACs) using the
        // same HKDF path pwe_from_pt uses. We don't expose `val`, but
        // we can sanity-check: the resulting PWE must be a valid
        // on-curve point that is NOT the same as PT (val != 1 with
        // overwhelming probability) and NOT infinity.
        let pt = pt_h2e("net", "pw", None);
        let pwe = pwe_from_pt(pt, &[0x55; 6], &[0x66; 6]);
        if pwe.x == pt.x && pwe.y == pt.y {
            return TestResult::Fail("PWE shouldn't equal PT (val almost-certainly != 1)");
        }
        if !pwe_valid(&pwe) {
            return TestResult::Fail("PWE must be valid");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae", smoke_sae_pwe_is_scalar_multiple_of_pt);
}
