//! PBKDF2 (RFC 8018 §5.2) with HMAC-SHA-1, HMAC-SHA-256 and HMAC-SHA-512.
//!
//! ```text
//!     T_i = U_1 ^ U_2 ^ ... ^ U_c
//!     U_1 = HMAC(P, S || INT(i)),  U_j = HMAC(P, U_{j-1})
//!     HMAC(K, m) = H((K0 ^ opad) || H((K0 ^ ipad) || m))      (RFC 2104 §2)
//! ```
//!
//! The HMAC key is the password for the whole derivation, so the hash
//! states after the `K0 ^ ipad` and `K0 ^ opad` blocks are computed once.
//! For U_2..U_c the message is the previous U, one digest long, so each
//! HMAC is exactly two compressions of one padded block whose padding never
//! changes. That is half the compressions of a plain HMAC per iteration,
//! with no buffering in the loop.
//!
//! On x86_64 with SHA-NI, HMAC-SHA-256 runs those compressions on
//! `SHA256RNDS2` ([`crate::sha256::Sha256::compress_ni`]) in short sections
//! ([`crate::simd::section`]). This is the LUKS keyslot KDF: cryptsetup
//! sizes iteration counts to 2 s of its own accelerated PBKDF2, about 10.9
//! million iterations on a Ryzen 7 PRO 8840HS.

use zeroize::{Zeroize, Zeroizing};

use crate::pbkdf2_sha1::Sha1;
use crate::sha256::Sha256;
use crate::sha512::Sha512;

/// Iterations per SIMD section. At about 400 cycles per iteration this keeps
/// interrupts masked for roughly 25 µs at a time.
#[cfg(all(target_arch = "x86_64", any(test, feature = "kernel")))]
const NI_CHUNK: u32 = 256;

/// A Merkle-Damgård hash, as PBKDF2 needs it.
trait Md {
    /// Compression block size in bytes.
    const BLOCK: usize;
    /// Digest size in bytes.
    const OUT: usize;
    /// Size of the big-endian message bit length that ends the padding.
    const LEN_BYTES: usize;
    /// The chaining state.
    type State: Copy + Zeroize;
    /// The initial hash value.
    fn iv() -> Self::State;
    /// One compression; `block.len() == Self::BLOCK`.
    fn compress(state: &mut Self::State, block: &[u8]);
    /// The state's words, big-endian, into `out[..Self::OUT]`.
    fn store(state: &Self::State, out: &mut [u8]);

    /// `count` iterations of `u = HMAC(u)`, `t ^= u`. `inner` and `outer`
    /// are padded one-block messages whose first `OUT` bytes are the
    /// message: `inner` holds the current U on entry and the last U on
    /// return.
    fn iterate(
        istate: &Self::State,
        ostate: &Self::State,
        inner: &mut [u8],
        outer: &mut [u8],
        t: &mut [u8],
        count: u32,
    ) {
        iterate_portable::<Self>(istate, ostate, inner, outer, t, count);
    }
}

/// [`Md::iterate`] in portable code.
fn iterate_portable<M: Md + ?Sized>(
    istate: &M::State,
    ostate: &M::State,
    inner: &mut [u8],
    outer: &mut [u8],
    t: &mut [u8],
    count: u32,
) {
    let mut st = Zeroizing::new(*istate);
    for _ in 0..count {
        *st = *istate;
        M::compress(&mut st, inner);
        M::store(&st, &mut outer[..M::OUT]);
        *st = *ostate;
        M::compress(&mut st, outer);
        M::store(&st, &mut inner[..M::OUT]);
        for (t, u) in t.iter_mut().zip(&inner[..M::OUT]) {
            *t ^= u;
        }
    }
}

struct Sha1Md;
struct Sha256Md;
struct Sha512Md;

impl Md for Sha1Md {
    const BLOCK: usize = 64;
    const OUT: usize = 20;
    const LEN_BYTES: usize = 8;
    type State = [u32; 5];
    fn iv() -> [u32; 5] {
        [
            0x6745_2301,
            0xEFCD_AB89,
            0x98BA_DCFE,
            0x1032_5476,
            0xC3D2_E1F0,
        ]
    }
    fn compress(state: &mut [u32; 5], block: &[u8]) {
        Sha1::compress_block(state, block.try_into().expect("SHA-1 block"));
    }
    fn store(state: &[u32; 5], out: &mut [u8]) {
        for (o, w) in out.chunks_exact_mut(4).zip(state) {
            o.copy_from_slice(&w.to_be_bytes());
        }
    }
}

impl Md for Sha256Md {
    const BLOCK: usize = 64;
    const OUT: usize = 32;
    const LEN_BYTES: usize = 8;
    type State = [u32; 8];
    fn iv() -> [u32; 8] {
        [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ]
    }
    fn compress(state: &mut [u32; 8], block: &[u8]) {
        Sha256::compress_portable(state, block.try_into().expect("SHA-256 block"));
    }
    fn store(state: &[u32; 8], out: &mut [u8]) {
        for (o, w) in out.chunks_exact_mut(4).zip(state) {
            o.copy_from_slice(&w.to_be_bytes());
        }
    }

    fn iterate(
        istate: &[u32; 8],
        ostate: &[u32; 8],
        inner: &mut [u8],
        outer: &mut [u8],
        t: &mut [u8],
        count: u32,
    ) {
        #[cfg(all(target_arch = "x86_64", any(test, feature = "kernel")))]
        {
            if crate::simd::caps().sha256 {
                iterate_sha256_ni(istate, ostate, inner, outer, t, count);
                return;
            }
        }
        iterate_portable::<Self>(istate, ostate, inner, outer, t, count);
    }
}

/// [`Md::iterate`] for HMAC-SHA-256 on SHA-NI, [`NI_CHUNK`] iterations per
/// section.
#[cfg(all(target_arch = "x86_64", any(test, feature = "kernel")))]
fn iterate_sha256_ni(
    istate: &[u32; 8],
    ostate: &[u32; 8],
    inner: &mut [u8],
    outer: &mut [u8],
    t: &mut [u8],
    mut count: u32,
) {
    let mut iblock = Zeroizing::new([[0u8; 64]; 1]);
    let mut oblock = Zeroizing::new([[0u8; 64]; 1]);
    iblock[0].copy_from_slice(inner);
    oblock[0].copy_from_slice(outer);
    let mut st = Zeroizing::new(*istate);
    while count > 0 {
        let n = count.min(NI_CHUNK);
        crate::simd::section(|| {
            for _ in 0..n {
                *st = *istate;
                // SAFETY: inside a section, and caps() reported SHA-NI.
                unsafe { Sha256::compress_ni(&mut st, &iblock[..]) };
                Sha256Md::store(&st, &mut oblock[0][..32]);
                *st = *ostate;
                // SAFETY: as above.
                unsafe { Sha256::compress_ni(&mut st, &oblock[..]) };
                Sha256Md::store(&st, &mut iblock[0][..32]);
                for (t, u) in t.iter_mut().zip(&iblock[0][..32]) {
                    *t ^= u;
                }
            }
        });
        count -= n;
    }
    inner.copy_from_slice(&iblock[0]);
    outer.copy_from_slice(&oblock[0]);
}

impl Md for Sha512Md {
    const BLOCK: usize = 128;
    const OUT: usize = 64;
    const LEN_BYTES: usize = 16;
    type State = [u64; 8];
    fn iv() -> [u64; 8] {
        [
            0x6a09e667f3bcc908,
            0xbb67ae8584caa73b,
            0x3c6ef372fe94f82b,
            0xa54ff53a5f1d36f1,
            0x510e527fade682d1,
            0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b,
            0x5be0cd19137e2179,
        ]
    }
    fn compress(state: &mut [u64; 8], block: &[u8]) {
        Sha512::compress_block(state, block.try_into().expect("SHA-512 block"));
    }
    fn store(state: &[u64; 8], out: &mut [u8]) {
        for (o, w) in out.chunks_exact_mut(8).zip(state) {
            o.copy_from_slice(&w.to_be_bytes());
        }
    }
}

/// `H(state || parts...)` where `state` already absorbed `absorbed` bytes:
/// the rest of the message, the padding and the length (FIPS 180-4 §5.1).
fn finish<M: Md>(state: &M::State, absorbed: usize, parts: &[&[u8]], out: &mut [u8]) {
    let mut st = Zeroizing::new(*state);
    let mut buf = Zeroizing::new([0u8; 128]);
    let mut fill = 0usize;
    let mut total = absorbed;
    for part in parts {
        total += part.len();
        for &byte in *part {
            buf[fill] = byte;
            fill += 1;
            if fill == M::BLOCK {
                M::compress(&mut st, &buf[..M::BLOCK]);
                fill = 0;
            }
        }
    }
    buf[fill] = 0x80;
    fill += 1;
    if fill > M::BLOCK - M::LEN_BYTES {
        buf[fill..M::BLOCK].fill(0);
        M::compress(&mut st, &buf[..M::BLOCK]);
        fill = 0;
    }
    buf[fill..M::BLOCK].fill(0);
    let bits = (total as u128) * 8;
    buf[M::BLOCK - M::LEN_BYTES..M::BLOCK]
        .copy_from_slice(&bits.to_be_bytes()[16 - M::LEN_BYTES..]);
    M::compress(&mut st, &buf[..M::BLOCK]);
    M::store(&st, out);
}

fn pbkdf2<M: Md>(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    assert!(iterations >= 1, "PBKDF2 iteration count must be at least 1");
    // RFC 2104 §2: a key longer than the block is hashed first.
    let mut k0 = Zeroizing::new([0u8; 128]);
    if password.len() > M::BLOCK {
        finish::<M>(&M::iv(), 0, &[password], &mut k0[..M::OUT]);
    } else {
        k0[..password.len()].copy_from_slice(password);
    }
    let mut pad = Zeroizing::new([0u8; 128]);
    let mut istate = Zeroizing::new(M::iv());
    let mut ostate = Zeroizing::new(M::iv());
    for (p, k) in pad[..M::BLOCK].iter_mut().zip(&k0[..M::BLOCK]) {
        *p = k ^ 0x36;
    }
    M::compress(&mut istate, &pad[..M::BLOCK]);
    for (p, k) in pad[..M::BLOCK].iter_mut().zip(&k0[..M::BLOCK]) {
        *p = k ^ 0x5c;
    }
    M::compress(&mut ostate, &pad[..M::BLOCK]);

    // The one-block HMAC messages of U_2..U_c: U, 0x80, zeros, and the bit
    // length of one key block plus one digest.
    let mut inner = Zeroizing::new([0u8; 128]);
    let mut outer = Zeroizing::new([0u8; 128]);
    let bits = ((M::BLOCK + M::OUT) as u128) * 8;
    for block in [&mut inner, &mut outer] {
        block[M::OUT] = 0x80;
        block[M::BLOCK - M::LEN_BYTES..M::BLOCK]
            .copy_from_slice(&bits.to_be_bytes()[16 - M::LEN_BYTES..]);
    }

    let mut t = Zeroizing::new([0u8; 64]);
    let mut mid = Zeroizing::new([0u8; 64]);
    for (index, chunk) in out.chunks_mut(M::OUT).enumerate() {
        let block_index = u32::try_from(index + 1).expect("PBKDF2 output exceeds 2^32-1 blocks");
        // U_1 = HMAC(P, S || INT(i)).
        finish::<M>(
            &istate,
            M::BLOCK,
            &[salt, &block_index.to_be_bytes()],
            &mut mid[..M::OUT],
        );
        finish::<M>(&ostate, M::BLOCK, &[&mid[..M::OUT]], &mut inner[..M::OUT]);
        t[..M::OUT].copy_from_slice(&inner[..M::OUT]);
        M::iterate(
            &istate,
            &ostate,
            &mut inner[..M::BLOCK],
            &mut outer[..M::BLOCK],
            &mut t[..M::OUT],
            iterations - 1,
        );
        chunk.copy_from_slice(&t[..chunk.len()]);
    }
}

/// PBKDF2-HMAC-SHA-1 into `out` (any length up to (2^32 - 1) * 20 bytes).
///
/// # Panics
/// If `iterations` is 0.
pub fn pbkdf2_hmac_sha1(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    pbkdf2::<Sha1Md>(password, salt, iterations, out);
}

/// PBKDF2-HMAC-SHA-256 into `out` (any length up to (2^32 - 1) * 32 bytes).
///
/// # Panics
/// If `iterations` is 0.
pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    pbkdf2::<Sha256Md>(password, salt, iterations, out);
}

/// PBKDF2-HMAC-SHA-512 into `out` (any length up to (2^32 - 1) * 64 bytes).
///
/// # Panics
/// If `iterations` is 0.
pub fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    pbkdf2::<Sha512Md>(password, salt, iterations, out);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::vec::Vec;

    /// HMAC-SHA-256 that never takes the SHA-NI path.
    struct Sha256Portable;
    impl Md for Sha256Portable {
        const BLOCK: usize = 64;
        const OUT: usize = 32;
        const LEN_BYTES: usize = 8;
        type State = [u32; 8];
        fn iv() -> [u32; 8] {
            Sha256Md::iv()
        }
        fn compress(state: &mut [u32; 8], block: &[u8]) {
            Sha256Md::compress(state, block);
        }
        fn store(state: &[u32; 8], out: &mut [u8]) {
            Sha256Md::store(state, out);
        }
    }

    fn hex(s: &str) -> Vec<u8> {
        let s: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        s.chunks(2)
            .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }

    /// Plain RFC 2104 HMAC-SHA-512 over the streaming hasher: the reference
    /// the pad-precomputing derivation must agree with.
    fn hmac_sha512_plain(key: &[u8], msg: &[u8]) -> [u8; 64] {
        let mut k0 = [0u8; 128];
        if key.len() > 128 {
            let mut h = Sha512::new();
            h.update(key);
            k0[..64].copy_from_slice(&h.finalize());
        } else {
            k0[..key.len()].copy_from_slice(key);
        }
        let mut inner = Sha512::new();
        inner.update(&k0.map(|b| b ^ 0x36));
        inner.update(msg);
        let digest = inner.finalize();
        let mut outer = Sha512::new();
        outer.update(&k0.map(|b| b ^ 0x5c));
        outer.update(&digest);
        outer.finalize()
    }

    fn pbkdf2_sha512_plain(p: &[u8], s: &[u8], c: u32, out: &mut [u8]) {
        for (i, chunk) in out.chunks_mut(64).enumerate() {
            let mut msg = s.to_vec();
            msg.extend_from_slice(&(i as u32 + 1).to_be_bytes());
            let mut u = hmac_sha512_plain(p, &msg);
            let mut t = u;
            for _ in 1..c {
                u = hmac_sha512_plain(p, &u);
                for (t, u) in t.iter_mut().zip(&u) {
                    *t ^= u;
                }
            }
            chunk.copy_from_slice(&t[..chunk.len()]);
        }
    }

    // RFC 6070 §2.
    #[test]
    fn pbkdf2_sha1_rfc6070() {
        let cases: [(&[u8], &[u8], u32, &str); 4] = [
            (
                b"password",
                b"salt",
                1,
                "0c60c80f961f0e71f3a9b524af6012062fe037a6",
            ),
            (
                b"password",
                b"salt",
                2,
                "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957",
            ),
            (
                b"password",
                b"salt",
                4096,
                "4b007901b765489abead49d926f721d065a429c1",
            ),
            (
                b"passwordPASSWORDpassword",
                b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
                4096,
                "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038",
            ),
        ];
        for (p, s, c, want) in cases {
            let want = hex(want);
            let mut out = alloc::vec![0u8; want.len()];
            pbkdf2_hmac_sha1(p, s, c, &mut out);
            assert_eq!(out, want, "c={c}");
        }
    }

    // RFC 7914 §11.
    #[test]
    fn pbkdf2_sha256_rfc7914() {
        let cases: [(&[u8], &[u8], u32, &str); 2] = [
            (
                b"passwd",
                b"salt",
                1,
                "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc
                 49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
            ),
            (
                b"Password",
                b"NaCl",
                80000,
                "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56
                 a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d",
            ),
        ];
        for (p, s, c, want) in cases {
            let want = hex(want);
            let mut out = alloc::vec![0u8; want.len()];
            pbkdf2_hmac_sha256(p, s, c, &mut out);
            assert_eq!(out, want, "c={c}");
        }
    }

    #[test]
    fn pbkdf2_sha512_matches_plain_hmac() {
        let long_key = [0xa5u8; 200];
        let cases: [(&[u8], &[u8], u32, usize); 4] = [
            (b"password", b"salt", 1, 64),
            (b"password", b"salt", 2, 64),
            (b"passphrase with spaces", &[7u8; 32], 1000, 100),
            (&long_key, b"long key is hashed first", 3, 64),
        ];
        for (p, s, c, len) in cases {
            let mut fast = alloc::vec![0u8; len];
            let mut plain = alloc::vec![0u8; len];
            pbkdf2_hmac_sha512(p, s, c, &mut fast);
            pbkdf2_sha512_plain(p, s, c, &mut plain);
            assert_eq!(fast, plain, "c={c} len={len}");
        }
        let mut out = [0u8; 64];
        pbkdf2_hmac_sha512(b"password", b"salt", 1, &mut out);
        assert_eq!(
            out.to_vec(),
            hex(
                "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252
                 c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce"
            )
        );
    }

    /// The SHA-NI iteration and the portable one agree from the same state.
    #[test]
    fn pbkdf2_sha256_ni_matches_portable() {
        if !crate::simd::caps().sha256 {
            std::eprintln!("no SHA-NI on this CPU; skipped");
            return;
        }
        let istate = [1u32, 2, 3, 4, 5, 6, 7, 8];
        let ostate = [0xdead_beefu32, 9, 8, 7, 6, 5, 4, 3];
        for count in [
            1u32,
            2,
            NI_CHUNK - 1,
            NI_CHUNK,
            NI_CHUNK + 1,
            3 * NI_CHUNK + 7,
        ] {
            let mut inner = [0u8; 64];
            let mut outer = [0u8; 64];
            inner[..32].copy_from_slice(&[0x5a; 32]);
            inner[32] = 0x80;
            outer[32] = 0x80;
            inner[62] = 0x03;
            outer[62] = 0x03;
            let (mut i2, mut o2) = (inner, outer);
            let mut t1 = [0x11u8; 32];
            let mut t2 = t1;
            iterate_portable::<Sha256Md>(&istate, &ostate, &mut inner, &mut outer, &mut t1, count);
            iterate_sha256_ni(&istate, &ostate, &mut i2, &mut o2, &mut t2, count);
            assert_eq!(t1, t2, "count={count}");
            assert_eq!(inner, i2, "count={count}");
        }
    }

    /// The LUKS1 header shape: 32-byte salt, 64-byte key, a long run.
    #[test]
    fn pbkdf2_sha256_luks_shape_matches_portable() {
        let salt = [0x3cu8; 32];
        let mut fast = [0u8; 64];
        pbkdf2_hmac_sha256(b"correct horse battery staple", &salt, 20_000, &mut fast);
        let mut slow = [0u8; 64];
        pbkdf2::<Sha256Portable>(b"correct horse battery staple", &salt, 20_000, &mut slow);
        assert_eq!(fast, slow);
    }
}
