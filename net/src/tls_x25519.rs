//! X25519 Diffie-Hellman (RFC 7748 §5) over the in-tree Curve25519 field.
//!
//! The Montgomery ladder runs on `narf_crypto::curve25519::FieldElement`
//! (5×51-bit limbs, `mul` fully reduces, `sub` weak-reduces), so the
//! ladder needs no local field code. Conditional swaps are done with
//! field-arithmetic masks — no branch on a secret bit — and the scalar is
//! clamped per RFC 7748 §5 (`k[0] &= 248; k[31] &= 127; k[31] |= 64`).
//!
//! References (public-only):
//! - RFC 7748 §5 — the X25519 function, ladder pseudocode, `A = 486662`,
//!   base point `u = 9`, `a24 = (A - 2) / 4 = 121665`.
//!   <https://datatracker.ietf.org/doc/html/rfc7748#section-5>
//! - RFC 7748 §5.2 — Alice/Bob test vectors (used by the unit test below).
//! - RFC 8446 §4.2.7 — TLS 1.3 key_share: the client offers the X25519
//!   public key; the shared secret feeds the handshake key schedule.
//!
//! An all-zero shared secret is rejected (RFC 7748 §6.1: the check "MAY"
//! be performed; we fail closed — a zero output means the peer sent a
//! small-order point and contributed nothing).

use narf_crypto::curve25519::FieldElement;

/// `a24 = (A - 2) / 4 = 121665` for Curve25519 (`A = 486662`, RFC 7748
/// §4.1), little-endian.
const A24: FieldElement = FieldElement::from_bytes(&[
    0x41, 0xdb, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0,
]);

/// The X25519 base point, `u = 9` (RFC 7748 §4.1), little-endian.
const BASE_POINT: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Constant-time conditional swap of two field elements, `swap ∈ {0, 1}`.
///
/// Implemented with a field-arithmetic mask (`mask` is the field element
/// 0 or 1, built without branching on `swap`): `t = mask * (a - b)`,
/// `a' = a - t`, `b' = b + t`. When `swap == 1`, `t = a - b` and the pair
/// exchanges; when `swap == 0`, `t = 0` and the pair is unchanged.
fn cswap(swap: u8, a: &mut FieldElement, b: &mut FieldElement) {
    let mut mask_bytes = [0u8; 32];
    mask_bytes[0] = swap & 1;
    let mask = FieldElement::from_bytes(&mask_bytes);
    let diff = a.sub(b);
    let t = mask.mul(&diff);
    *a = a.sub(&t);
    *b = b.add(&t);
}

/// X25519 scalar multiplication, RFC 7748 §5.
///
/// `scalar` is clamped in place per the spec. Returns `None` when the
/// shared secret is all zero (small-order peer point — fail closed).
pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> Option<[u8; 32]> {
    let mut k = *scalar;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;

    let x1 = FieldElement::from_bytes(point);
    let mut x2 = FieldElement::ONE;
    let mut z2 = FieldElement::ZERO;
    let mut x3 = x1;
    let mut z3 = FieldElement::ONE;
    let mut swap: u8 = 0;

    // RFC 7748 §5 ladder, bits 254 down to 0.
    for t in (0..=254).rev() {
        let k_t = (k[t >> 3] >> (t & 7)) & 1;
        swap ^= k_t;
        cswap(swap, &mut x2, &mut x3);
        cswap(swap, &mut z2, &mut z3);
        swap = k_t;

        let a = x2.add(&z2);
        let aa = a.square();
        let b = x2.sub(&z2);
        let bb = b.square();
        let e = aa.sub(&bb);
        let c = x3.add(&z3);
        let d = x3.sub(&z3);
        let da = d.mul(&a);
        let cb = c.mul(&b);
        x3 = da.add(&cb).square();
        z3 = x1.mul(&da.sub(&cb).square());
        x2 = aa.mul(&bb);
        z2 = e.mul(&aa.add(&A24.mul(&e)));
    }
    cswap(swap, &mut x2, &mut x3);
    cswap(swap, &mut z2, &mut z3);

    let out = x2.mul(&z2.invert()).to_bytes();
    if out.iter().all(|&b| b == 0) {
        return None;
    }
    Some(out)
}

/// X25519 public key for a private scalar: `X25519(scalar, 9)`.
pub fn x25519_public(scalar: &[u8; 32]) -> Option<[u8; 32]> {
    x25519(scalar, &BASE_POINT)
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use narf_kernel_test::{kernel_test_in, kt_assert_eq, TestResult};

    /// Hex decoder for the test vectors (test-only; the crate has no hex
    /// dependency).
    fn hex(s: &str) -> Vec<u8> {
        let s = s.as_bytes();
        let mut out = Vec::with_capacity(s.len() / 2);
        for pair in s.chunks(2) {
            // A malformed fixture literal must fail the test at its
            // assertion, not panic the guest: fall back to 0 and let the
            // vector check fail.
            let hi = (pair[0] as char).to_digit(16).unwrap_or(0) as u8;
            let lo = (pair[1] as char).to_digit(16).unwrap_or(0) as u8;
            out.push((hi << 4) | lo);
        }
        out
    }

    fn arr32(hex_str: &str) -> [u8; 32] {
        hex(hex_str).try_into().unwrap_or([0; 32])
    }

    /// RFC 7748 §5.2 / §6.1 Alice-Bob vectors.
    fn x25519_matches_rfc7748_vectors() -> TestResult {
        let alice_priv = arr32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_pub = arr32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let bob_priv = arr32("5dab087e624a8a4b79e17f8b83800ee66df3cb12973937ecf3c9ad771c5feaa5");
        let bob_pub = arr32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let shared = arr32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        kt_assert_eq!(x25519_public(&alice_priv), Some(alice_pub));
        kt_assert_eq!(x25519_public(&bob_priv), Some(bob_pub));
        kt_assert_eq!(x25519(&alice_priv, &bob_pub), Some(shared));
        kt_assert_eq!(x25519(&bob_priv, &alice_pub), Some(shared));
        TestResult::Pass
    }

    kernel_test_in!("net/tls", x25519_matches_rfc7748_vectors);

    /// RFC 8448 §3 ephemeral keys: the client's private key must yield
    /// the trace's public key, and the DH with the server's public key
    /// must yield the trace's handshake IKM.
    fn x25519_matches_rfc8448_ephemeral() -> TestResult {
        let client_priv = arr32("49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005");
        let client_pub = arr32("99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c");
        let server_pub = arr32("c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f");
        let shared = arr32("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
        kt_assert_eq!(x25519_public(&client_priv), Some(client_pub));
        kt_assert_eq!(x25519(&client_priv, &server_pub), Some(shared));
        TestResult::Pass
    }

    kernel_test_in!("net/tls", x25519_matches_rfc8448_ephemeral);
}
