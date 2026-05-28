//! NIST P-256 (secp256r1, prime256v1) clean-room implementation.
//!
//! Spec references (all consulted as public documents):
//!
//! - NIST FIPS 186-4 §D.1.2.3 — curve parameters
//!   <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf>
//! - NIST SP 800-186 §3.2.1.3 — republished parameters and
//!   informative reduction annex
//!   <https://csrc.nist.gov/publications/sp/800-186/final>
//! - RFC 5903 §8.1 — ECDH test vectors
//!   <https://datatracker.ietf.org/doc/html/rfc5903>
//! - RFC 7664 §3.2 — SAE hunting-and-pecking
//!   <https://datatracker.ietf.org/doc/html/rfc7664>
//! - IEEE 802.11-2020 §12.4 — SAE state machine + constant-time
//!   discipline (NOTE in §12.4.4.2.2)
//! - Renes-Costello-Batina 2016: "Complete addition formulas for
//!   prime order elliptic curves" — used for the affine fall-back;
//!   the Jacobian doubling here follows the textbook formulas in
//!   Cohen-Frey "Handbook of EHCC" §13.2.
//!
//! Reference (clean-room, not copied): `crypto/ecc.c` in the Linux
//! tree implements the same primitives. NARF is GPL-2.0-or-later
//! after the 2026-05-20 relicense, so the reference is in scope.
//!
//! ## Module layout
//!
//! - [`field`]  — GF(p) arithmetic on 4 × u64 limbs.
//! - [`point`]  — group operations (add, double, scalar-mul) using
//!   Jacobian projective coordinates.
//! - [`scalar`] — Z/n arithmetic for the scalar field.
//!
//! ## Wire format
//!
//! Affine points are encoded as `X || Y`, each 32 bytes big-endian —
//! 64 bytes total, matching what 802.11-2020 §12.4.7.4 puts on the
//! wire for SAE Commit elements. The point-at-infinity is rejected
//! at the wire boundary; callers must never serialise it.

#![allow(dead_code)]

pub mod field;
pub mod point;
pub mod scalar;

pub use field::Fp;
pub use point::{AffinePoint, ProjectivePoint};
pub use scalar::Scalar;

/// P-256 curve parameter `b` (FIPS 186-4 §D.1.2.3).
/// b = 0x5AC635D8AA3A93E7 B3EBBD55769886BC 651D06B0CC53B0F6 3BCE3C3E27D2604B
pub const CURVE_B: [u64; 4] = [
    0x3BCE_3C3E_27D2_604B,
    0x651D_06B0_CC53_B0F6,
    0xB3EB_BD55_7698_86BC,
    0x5AC6_35D8_AA3A_93E7,
];

/// P-256 generator G_x (FIPS 186-4 §D.1.2.3).
/// G.x = 6B17D1F2E12C4247 F8BCE6E563A440F2 77037D812DEB33A0 F4A13945D898C296
pub const GENERATOR_X: [u64; 4] = [
    0xF4A1_3945_D898_C296,
    0x7703_7D81_2DEB_33A0,
    0xF8BC_E6E5_63A4_40F2,
    0x6B17_D1F2_E12C_4247,
];

/// P-256 generator G_y (FIPS 186-4 §D.1.2.3).
/// G.y = 4FE342E2FE1A7F9B 8EE7EB4A7C0F9E16 2BCE33576B315ECE CBB6406837BF51F5
pub const GENERATOR_Y: [u64; 4] = [
    0xCBB6_4068_37BF_51F5,
    0x2BCE_3357_6B31_5ECE,
    0x8EE7_EB4A_7C0F_9E16,
    0x4FE3_42E2_FE1A_7F9B,
];

/// P-256 group order n (FIPS 186-4 §D.1.2.3).
/// n = FFFFFFFF00000000 FFFFFFFFFFFFFFFF BCE6FAADA7179E84 F3B9CAC2FC632551
pub const ORDER_N: [u64; 4] = [
    0xF3B9_CAC2_FC63_2551,
    0xBCE6_FAAD_A717_9E84,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_0000_0000,
];

/// Encoded affine size: X (32 bytes BE) || Y (32 bytes BE).
pub const ENCODED_POINT_SIZE: usize = 64;

/// Encoded scalar size: 32 bytes big-endian.
pub const ENCODED_SCALAR_SIZE: usize = 32;
