//! # Cleanroom Ed25519 Implementation
//!
//! Implementation of the Ed25519 digital signature algorithm according to RFC 8032.
//! Reference: <https://datatracker.ietf.org/doc/html/rfc8032>

use crate::curve25519::Point;
use crate::sha512::Sha512;

/// Ed25519 signature (64 bytes).
pub type Signature = [u8; 64];

/// Ed25519 public key (32 bytes).
pub type PublicKey = [u8; 32];

/// Ed25519 secret key (32 bytes).
pub type SecretKey = [u8; 32];

/// Derive the public key from a 32-byte secret key.
pub fn ed25519_public_key(sk: &SecretKey) -> PublicKey {
    let mut hasher = Sha512::new();
    hasher.update(sk);
    let h = hasher.finalize();

    let mut a = [0u8; 32];
    a.copy_from_slice(&h[0..32]);
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;

    Point::BASE.mul(&a).to_bytes()
}

/// Sign a message using a secret key.
pub fn ed25519_sign(sk: &SecretKey, msg: &[u8]) -> Signature {
    let mut hasher = Sha512::new();
    hasher.update(sk);
    let h = hasher.finalize();

    let mut a = [0u8; 32];
    a.copy_from_slice(&h[0..32]);
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;

    let prefix = &h[32..64];

    // r = H(prefix || msg) mod L
    let mut hasher = Sha512::new();
    hasher.update(prefix);
    hasher.update(msg);
    let hr = hasher.finalize();
    let r = reduce_mod_l(&hr);

    let r_point_bytes = Point::BASE.mul(&r).to_bytes();

    // k = H(R || A || msg) mod L
    let pk_bytes = Point::BASE.mul(&a).to_bytes();

    let mut hasher = Sha512::new();
    hasher.update(&r_point_bytes);
    hasher.update(&pk_bytes);
    hasher.update(msg);
    let hk = hasher.finalize();
    let k = reduce_mod_l(&hk);

    // s = (r + k * a) mod L
    let s = mul_add_mod_l(&k, &a, &r);

    let mut sig = [0u8; 64];
    sig[0..32].copy_from_slice(&r_point_bytes);
    sig[32..64].copy_from_slice(&s);
    sig
}

/// Verify an Ed25519 signature.
pub fn ed25519_verify(pk: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
    let r_bytes: [u8; 32] = sig[0..32].try_into().unwrap();
    let s_bytes: [u8; 32] = sig[32..64].try_into().unwrap();

    // 1. S < L check
    let s_limbs = [
        u64::from_le_bytes(s_bytes[0..8].try_into().unwrap()),
        u64::from_le_bytes(s_bytes[8..16].try_into().unwrap()),
        u64::from_le_bytes(s_bytes[16..24].try_into().unwrap()),
        u64::from_le_bytes(s_bytes[24..32].try_into().unwrap()),
    ];
    if is_ge_l(&s_limbs) {
        return false;
    }

    // 2. Decode points
    let a = match Point::from_bytes_checked(pk) {
        Some(p) => p,
        None => return false,
    };
    let r = match Point::from_bytes_checked(&r_bytes) {
        Some(p) => p,
        None => return false,
    };

    // 3. k = H(R || A || msg) mod L
    let mut hasher = Sha512::new();
    hasher.update(&r_bytes);
    hasher.update(pk);
    hasher.update(msg);
    let hk = hasher.finalize();
    let k = reduce_mod_l(&hk);

    // 4. [8][S]B = [8]R + [8][k]A
    let sb = Point::BASE.mul(&s_bytes);
    let ka = a.mul(&k);
    let r_plus_ka = r.add(&ka);

    // Clear cofactor
    sb.double().double().double() == r_plus_ka.double().double().double()
}

/// Curve order L = 2^252 + 27742317777372353535851937790883648493
const L: [u64; 4] = [
    0x5812631a5cf5d3ed,
    0x14def9dea2f79cd6,
    0x0000000000000000,
    0x1000000000000000,
];

/// Helper to check if a 256-bit number is >= L
fn is_ge_l(val: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if val[i] > L[i] {
            return true;
        }
        if val[i] < L[i] {
            return false;
        }
    }
    true
}

/// Reduction modulo L.
pub fn reduce_mod_l(h: &[u8; 64]) -> [u8; 32] {
    // Treat h as a 512-bit little-endian integer.
    // We want to calculate h mod L.
    // L = 2^252 + 27742317777372353535851937790883648493

    let mut r = [0u64; 9]; // 512 bits + extra for shift
    for i in 0..8 {
        r[i] = u64::from_le_bytes(h[i * 8..i * 8 + 8].try_into().unwrap());
    }

    // We use a simpler approach: process from top down.
    // But since it's 512 bits and L is ~252 bits, we can do it more traditionally.
    let mut rem = [0u64; 8];
    for i in (0..512).rev() {
        // rem = rem << 1
        let mut carry = 0u64;
        for limb in &mut rem {
            let next_carry = *limb >> 63;
            *limb = (*limb << 1) | carry;
            carry = next_carry;
        }

        // bit = h[i]
        let bit = (r[i / 64] >> (i % 64)) & 1;
        rem[0] |= bit;

        // if rem >= L, rem -= L
        // Note: rem is 512 bits, L is 256 bits.
        while is_ge_l_large(&rem) {
            sub_l_large(&mut rem);
        }
    }

    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&rem[i].to_le_bytes());
    }
    out
}

fn is_ge_l_large(val: &[u64; 8]) -> bool {
    for i in (4..8).rev() {
        if val[i] > 0 {
            return true;
        }
    }
    for i in (0..4).rev() {
        if val[i] > L[i] {
            return true;
        }
        if val[i] < L[i] {
            return false;
        }
    }
    true
}

fn sub_l_large(val: &mut [u64; 8]) {
    let mut borrow = 0u64;
    for i in 0..4 {
        let (res, b) = val[i].overflowing_sub(L[i]);
        let (res2, b2) = res.overflowing_sub(borrow);
        val[i] = res2;
        borrow = if b || b2 { 1 } else { 0 };
    }
    for limb in val.iter_mut().skip(4) {
        let (res, b) = limb.overflowing_sub(borrow);
        *limb = res;
        borrow = if b { 1 } else { 0 };
    }
}

/// Calculate (k * a + r) mod L
pub(crate) fn mul_add_mod_l(k: &[u8; 32], a: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut prod = [0u64; 8];
    let k_limbs = [
        u64::from_le_bytes(k[0..8].try_into().unwrap()),
        u64::from_le_bytes(k[8..16].try_into().unwrap()),
        u64::from_le_bytes(k[16..24].try_into().unwrap()),
        u64::from_le_bytes(k[24..32].try_into().unwrap()),
    ];
    let a_limbs = [
        u64::from_le_bytes(a[0..8].try_into().unwrap()),
        u64::from_le_bytes(a[8..16].try_into().unwrap()),
        u64::from_le_bytes(a[16..24].try_into().unwrap()),
        u64::from_le_bytes(a[24..32].try_into().unwrap()),
    ];

    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let val = prod[i + j] as u128 + (k_limbs[i] as u128 * a_limbs[j] as u128) + carry;
            prod[i + j] = (val & 0xffffffffffffffff) as u64;
            carry = val >> 64;
        }
        prod[i + 4] = carry as u64;
    }

    let r_limbs = [
        u64::from_le_bytes(r[0..8].try_into().unwrap()),
        u64::from_le_bytes(r[8..16].try_into().unwrap()),
        u64::from_le_bytes(r[16..24].try_into().unwrap()),
        u64::from_le_bytes(r[24..32].try_into().unwrap()),
    ];
    let mut carry = 0u64;
    for i in 0..4 {
        let (res, b) = prod[i].overflowing_add(r_limbs[i]);
        let (res2, b2) = res.overflowing_add(carry);
        prod[i] = res2;
        carry = if b || b2 { 1 } else { 0 };
    }
    for limb in prod.iter_mut().skip(4) {
        let (res, b) = limb.overflowing_add(carry);
        *limb = res;
        carry = if b { 1 } else { 0 };
    }

    let mut h = [0u8; 64];
    for i in 0..8 {
        h[i * 8..i * 8 + 8].copy_from_slice(&prod[i].to_le_bytes());
    }
    reduce_mod_l(&h)
}
