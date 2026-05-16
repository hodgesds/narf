//! Subsystem smokes for `narf-crypto`.
//!
//! Migrated from `narf-verification`. Tests register under the
//! `crypto` subsystem.

extern crate alloc;

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_crypto_ed25519_verify() -> TestResult {
    // RFC 8032 §7.1 Test 1: empty message, well-known key + signature.
    use crate::{ed25519_verify, Ed25519Verify, Key};
    use narf_capabilities::{Cap, Read};

    let public: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];
    let sig: [u8; 64] = [
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82,
        0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49,
        0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c,
        0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43,
        0x8e, 0x7a, 0x10, 0x0b,
    ];

    let cap: Cap<Key<Ed25519Verify>, Read> = Cap::<Key<Ed25519Verify>, Read>::bootstrap();
    if ed25519_verify(&cap, &public, b"", &sig).is_err() {
        return TestResult::Fail("ed25519 verify rejected RFC 8032 vector");
    }

    let mut bad_sig = sig;
    bad_sig[0] ^= 0x01;
    if ed25519_verify(&cap, &public, b"", &bad_sig).is_ok() {
        return TestResult::Fail("ed25519 verify accepted tampered signature");
    }

    TestResult::Pass
}
kernel_test_in!("crypto", smoke_crypto_ed25519_verify);

fn smoke_crypto_chacha20_roundtrip() -> TestResult {
    use crate::{chacha20_open, chacha20_seal, ChaCha20Poly1305Alg, Key};
    use alloc::vec::Vec;
    use narf_capabilities::{Cap, Grant};

    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let aad: &[u8] = b"narf-crypto-aad";
    let original: Vec<u8> = b"the quick brown fox jumps over the lazy dog".to_vec();

    let cap: Cap<Key<ChaCha20Poly1305Alg>, Grant> =
        Cap::<Key<ChaCha20Poly1305Alg>, Grant>::bootstrap();

    let mut buf = original.clone();
    if chacha20_seal(&cap, &key, &nonce, &mut buf, aad).is_err() {
        return TestResult::Fail("chacha20 seal returned AeadFailure");
    }
    if buf.len() != original.len() + 16 {
        return TestResult::Fail("chacha20 seal didn't append 16-byte tag");
    }
    if buf[..original.len()] == original[..] {
        return TestResult::Fail("chacha20 seal left plaintext unencrypted");
    }
    if chacha20_open(&cap, &key, &nonce, &mut buf, aad).is_err() {
        return TestResult::Fail("chacha20 open rejected our own ciphertext");
    }
    if buf != original {
        return TestResult::Fail("chacha20 open didn't recover plaintext");
    }

    let mut buf2 = original.clone();
    let _ = chacha20_seal(&cap, &key, &nonce, &mut buf2, aad);
    if chacha20_open(&cap, &key, &nonce, &mut buf2, b"different-aad").is_ok() {
        return TestResult::Fail("chacha20 open accepted mismatched AAD");
    }

    TestResult::Pass
}
kernel_test_in!("crypto", smoke_crypto_chacha20_roundtrip);

fn smoke_crypto_hkdf_test_vector() -> TestResult {
    // RFC 5869 Test Case 1 — HKDF-SHA-256.
    use crate::{hkdf_expand, Hkdf, Key};
    use narf_capabilities::{Cap, Read};

    let ikm: [u8; 22] = [0x0b; 22];
    let salt: [u8; 13] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];
    let info: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
    let expected: [u8; 42] = [
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f,
        0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4,
        0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
    ];

    let cap: Cap<Key<Hkdf>, Read> = Cap::<Key<Hkdf>, Read>::bootstrap();
    let okm = match hkdf_expand(&cap, &salt, &ikm, &info, 42) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("hkdf_expand returned an error"),
    };
    if okm.len() != 42 || okm[..] != expected[..] {
        return TestResult::Fail("hkdf_expand output mismatched RFC 5869 vector");
    }
    TestResult::Pass
}
kernel_test_in!("crypto", smoke_crypto_hkdf_test_vector);

fn smoke_crypto_blake3_known_answer() -> TestResult {
    use crate::blake3_hash;

    let expected: [u8; 32] = [
        0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc, 0xc9,
        0x49, 0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca, 0xe4, 0x1f,
        0x32, 0x62,
    ];
    let got = blake3_hash(b"");
    if got != expected {
        return TestResult::Fail("blake3 empty-input hash drifted from KAT");
    }
    TestResult::Pass
}
kernel_test_in!("crypto", smoke_crypto_blake3_known_answer);

fn smoke_crypto_tpm_command_shapes() -> TestResult {
    use crate::tpm::{submit, Tpm2Command, Tpm2Status, TpmAlgHash, TpmCc};

    if TpmCc::PcrExtend as u32 != 0x0000_0182 {
        return TestResult::Fail("PcrExtend CC drifted from TCG value");
    }
    if TpmCc::GetRandom as u32 != 0x0000_017B {
        return TestResult::Fail("GetRandom CC drifted from TCG value");
    }
    if TpmAlgHash::Sha256 as u16 != 0x000B {
        return TestResult::Fail("Sha256 alg id drifted from TCG value");
    }

    let cmd = Tpm2Command::GetRandom { bytes: 16 };
    if submit(&cmd) != Tpm2Status::NotImplemented {
        return TestResult::Fail("TPM submit should return NotImplemented");
    }
    TestResult::Pass
}
kernel_test_in!("crypto", smoke_crypto_tpm_command_shapes);

fn smoke_crypto_pq_fips_gate() -> TestResult {
    use crate::pq::{fips_allowed, fips_mode, HybridMode, PqAlg};

    if fips_mode() {
        return TestResult::Fail("FIPS mode should be false until primitives are validated");
    }
    if !fips_allowed(PqAlg::MlKem768) || !fips_allowed(PqAlg::MlDsa65) {
        return TestResult::Fail("non-FIPS posture should permit every PQ algorithm");
    }
    if HybridMode::Hybrid == HybridMode::PqOnly {
        return TestResult::Fail("HybridMode variant comparison broken");
    }
    TestResult::Pass
}
kernel_test_in!("crypto", smoke_crypto_pq_fips_gate);

// ── Hardware-accelerated crypto ───────────────────────────────────

fn smoke_crypto_accel_features_probe_runs() -> TestResult {
    use crate::accel::Features;

    let _ = Features::probe();

    // Boolean values; we don't assert specific results — varies by host.

    TestResult::Pass
}

kernel_test_in!("crypto/accel", smoke_crypto_accel_features_probe_runs);

fn smoke_crypto_accel_features_struct_default() -> TestResult {
    use crate::accel::Features;
    // Default is "no acceleration"; on a real probe at least one
    // bit will usually flip true on x86_64 / aarch64 production
    // hardware. We can't assert that without environment
    // dependence, so just check the default + Copy/Eq surface.
    let d = Features::default();
    if d.aes || d.sha2 || d.sha1 || d.pmull || d.crc32 {
        return TestResult::Fail("default Features should be all-false");
    }
    let p = Features::probe();
    let _ = (p == d, p.aes, p.sha2);
    TestResult::Pass
}
kernel_test_in!("crypto/accel", smoke_crypto_accel_features_struct_default);
// Live `aes_round_forward` execution requires CR4.OSFXSR /
// OSXMMEXCPT to be set so AESENC's XMM access doesn't trap. The
// kernel boot path doesn't always get there before tests run,
// and a smoke test that toggles CR4 would mask real CR4 bugs.
// Vector validation against a software reference lives in the
// future `crypto::aes` module that owns the key schedule + has
// tested SSE-state setup.

// ── Primitive smokes ───────────────────────────────────────────────
//
// The `#[test]` blocks in `primitive_tests.rs` validate the raw
// FIPS / RFC vectors against a host build. They never run in the
// kernel test harness — the `kernel_test_in!` runs do. These smokes
// duplicate the most important vectors at the kernel-runtime layer
// so a regression in the cleanroom primitive (e.g. an arch-specific
// codegen bug, an alloc/heap interaction at runtime, or a future
// hardware-accelerated path that diverges from the software one)
// gets caught on every boot rather than only on `cargo test`.

fn smoke_crypto_sha256_abc() -> TestResult {
    // FIPS 180-4 SHA-256 example.
    use crate::sha256::Sha256;
    let mut h = Sha256::new();
    h.update(b"abc");
    let got = h.finalize();
    let want: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
        0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
        0xf2, 0x00, 0x15, 0xad,
    ];
    if got == want { TestResult::Pass } else { TestResult::Fail("sha256(\"abc\") drift") }
}
kernel_test_in!("crypto", smoke_crypto_sha256_abc);

fn smoke_crypto_sha256_empty() -> TestResult {
    // Edge case: zero-length input.
    use crate::sha256::Sha256;
    let h = Sha256::new();
    let got = h.finalize();
    let want: [u8; 32] = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
        0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
        0x78, 0x52, 0xb8, 0x55,
    ];
    if got == want { TestResult::Pass } else { TestResult::Fail("sha256(\"\") drift") }
}
kernel_test_in!("crypto", smoke_crypto_sha256_empty);

fn smoke_crypto_sha256_streaming_matches_one_shot() -> TestResult {
    // Updating in two chunks must produce the same digest as one
    // update of the concatenation — guards a block-buffer flush bug.
    use crate::sha256::Sha256;
    let mut a = Sha256::new();
    a.update(b"the quick brown fox jumps over ");
    a.update(b"the lazy dog");
    let mut b = Sha256::new();
    b.update(b"the quick brown fox jumps over the lazy dog");
    if a.finalize() == b.finalize() {
        TestResult::Pass
    } else {
        TestResult::Fail("sha256 streaming mismatched one-shot")
    }
}
kernel_test_in!("crypto", smoke_crypto_sha256_streaming_matches_one_shot);

fn smoke_crypto_sha512_abc() -> TestResult {
    use crate::sha512::Sha512;
    let mut h = Sha512::new();
    h.update(b"abc");
    let got = h.finalize();
    let want: [u8; 64] = [
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20,
        0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6,
        0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba,
        0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
        0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
    ];
    if got == want { TestResult::Pass } else { TestResult::Fail("sha512(\"abc\") drift") }
}
kernel_test_in!("crypto", smoke_crypto_sha512_abc);

fn smoke_crypto_sha512_streaming_matches_one_shot() -> TestResult {
    use crate::sha512::Sha512;
    let mut a = Sha512::new();
    for chunk in [&b"123"[..], b"456", b"789"] {
        a.update(chunk);
    }
    let mut b = Sha512::new();
    b.update(b"123456789");
    if a.finalize() == b.finalize() {
        TestResult::Pass
    } else {
        TestResult::Fail("sha512 streaming mismatched one-shot")
    }
}
kernel_test_in!("crypto", smoke_crypto_sha512_streaming_matches_one_shot);

fn smoke_crypto_chacha20_block_rfc8439() -> TestResult {
    // RFC 8439 §2.3.2: key/nonce/counter with known block output.
    use crate::chacha20::{chacha20_block, chacha20_init};
    let key: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f,
    ];
    let nonce: [u8; 12] = [
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
    ];
    let state = chacha20_init(&key, &nonce, 1);
    let mut out = [0u8; 64];
    chacha20_block(&state, &mut out);
    let want: [u8; 64] = [
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
        0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a,
        0xc3, 0xd4, 0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2,
        0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
        0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
    ];
    if out == want { TestResult::Pass } else { TestResult::Fail("chacha20 block drift") }
}
kernel_test_in!("crypto", smoke_crypto_chacha20_block_rfc8439);

fn smoke_crypto_chacha20_xor_is_self_inverse() -> TestResult {
    // XOR cipher property: encrypt(encrypt(p)) == p with the same
    // (key, nonce, counter). Useful regression for any keystream
    // tracking bug.
    use crate::chacha20::chacha20_xor;
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let mut buf: alloc::vec::Vec<u8> =
        b"the quick brown fox jumps over the lazy dog".to_vec();
    let original = buf.clone();
    chacha20_xor(&key, &nonce, 1, &mut buf);
    if buf == original {
        return TestResult::Fail("first chacha20_xor left data unchanged");
    }
    chacha20_xor(&key, &nonce, 1, &mut buf);
    if buf == original {
        TestResult::Pass
    } else {
        TestResult::Fail("chacha20_xor is not its own inverse")
    }
}
kernel_test_in!("crypto", smoke_crypto_chacha20_xor_is_self_inverse);

fn smoke_crypto_poly1305_rfc8439() -> TestResult {
    use crate::poly1305::Poly1305;
    let key: [u8; 32] = [
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
        0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
        0x41, 0x49, 0xf5, 0x1b,
    ];
    let mut mac = Poly1305::new(&key);
    mac.update(b"Cryptographic Forum Research Group");
    let tag = mac.finalize();
    let want = [
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
        0x27, 0xa9,
    ];
    if tag == want { TestResult::Pass } else { TestResult::Fail("poly1305 tag drift") }
}
kernel_test_in!("crypto", smoke_crypto_poly1305_rfc8439);

fn smoke_crypto_aead_seal_open_roundtrip_raw() -> TestResult {
    // Raw `aead::chacha20_poly1305_{seal,open}` (no cap gate). The
    // `crypto::chacha20_seal/open` smokes cover the cap layer; this
    // exercises the algorithm directly so a regression in the raw
    // path is caught even if the cap surface temporarily diverges.
    use crate::aead::{chacha20_poly1305_open, chacha20_poly1305_seal};
    let key = [0x42u8; 32];
    let nonce = [0x11u8; 12];
    let aad = b"narf-test-aad";
    let plaintext = b"chacha20-poly1305 raw round trip";
    let mut buf = plaintext.to_vec();
    let tag = chacha20_poly1305_seal(&key, &nonce, aad, &mut buf);
    if buf == plaintext[..] {
        return TestResult::Fail("seal left plaintext unencrypted");
    }
    if !chacha20_poly1305_open(&key, &nonce, aad, &mut buf, &tag) {
        return TestResult::Fail("open rejected its own seal");
    }
    if buf != plaintext[..] {
        return TestResult::Fail("open didn't recover plaintext");
    }
    TestResult::Pass
}
kernel_test_in!("crypto", smoke_crypto_aead_seal_open_roundtrip_raw);

fn smoke_crypto_aead_rejects_tampered_ciphertext() -> TestResult {
    // Flip a byte of ciphertext → open must reject (auth tag fails).
    use crate::aead::{chacha20_poly1305_open, chacha20_poly1305_seal};
    let key = [0x42u8; 32];
    let nonce = [0x11u8; 12];
    let aad: &[u8] = b"";
    let mut buf = b"ciphertext-tamper-detect".to_vec();
    let tag = chacha20_poly1305_seal(&key, &nonce, aad, &mut buf);
    buf[5] ^= 0x01;
    if chacha20_poly1305_open(&key, &nonce, aad, &mut buf, &tag) {
        TestResult::Fail("open accepted tampered ciphertext")
    } else {
        TestResult::Pass
    }
}
kernel_test_in!("crypto", smoke_crypto_aead_rejects_tampered_ciphertext);

fn smoke_crypto_aead_rejects_tampered_tag() -> TestResult {
    // Flip a tag byte → open must reject.
    use crate::aead::{chacha20_poly1305_open, chacha20_poly1305_seal};
    let key = [0x42u8; 32];
    let nonce = [0x11u8; 12];
    let aad: &[u8] = b"aad";
    let mut buf = b"tag-tamper".to_vec();
    let mut tag = chacha20_poly1305_seal(&key, &nonce, aad, &mut buf);
    tag[0] ^= 0x80;
    if chacha20_poly1305_open(&key, &nonce, aad, &mut buf, &tag) {
        TestResult::Fail("open accepted tampered tag")
    } else {
        TestResult::Pass
    }
}
kernel_test_in!("crypto", smoke_crypto_aead_rejects_tampered_tag);

fn smoke_crypto_ed25519_sign_verify_roundtrip_raw() -> TestResult {
    // Raw ed25519 sign + verify (no cap gate). RFC 8032 §7.1 Test 1.
    use crate::ed25519::{ed25519_public_key, ed25519_sign, ed25519_verify};
    let sk = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
        0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
        0x1c, 0xae, 0x7f, 0x60,
    ];
    let pk = ed25519_public_key(&sk);
    let want_pk: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
        0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
        0xf7, 0x07, 0x51, 0x1a,
    ];
    if pk != want_pk {
        return TestResult::Fail("ed25519_public_key drift from RFC 8032");
    }
    let msg = b"";
    let sig = ed25519_sign(&sk, msg);
    if !ed25519_verify(&pk, msg, &sig) {
        return TestResult::Fail("verify rejected our own sign");
    }
    let mut bad = sig;
    bad[5] ^= 0x10;
    if ed25519_verify(&pk, msg, &bad) {
        return TestResult::Fail("verify accepted tampered sig");
    }
    TestResult::Pass
}
kernel_test_in!("crypto", smoke_crypto_ed25519_sign_verify_roundtrip_raw);

fn smoke_crypto_ed25519_rejects_tampered_message() -> TestResult {
    // Sign one message, verify a different message under the same
    // (pk, sig) — must fail.
    use crate::ed25519::{ed25519_public_key, ed25519_sign, ed25519_verify};
    let sk = [0x77u8; 32];
    let pk = ed25519_public_key(&sk);
    let sig = ed25519_sign(&sk, b"original");
    if ed25519_verify(&pk, b"different", &sig) {
        TestResult::Fail("verify accepted message substitution")
    } else if !ed25519_verify(&pk, b"original", &sig) {
        TestResult::Fail("verify rejected honest message")
    } else {
        TestResult::Pass
    }
}
kernel_test_in!("crypto", smoke_crypto_ed25519_rejects_tampered_message);

fn smoke_crypto_curve25519_base_times_one() -> TestResult {
    // B*1 = B. The scalar bit-set in Point::mul has historically
    // had off-by-one bugs in Montgomery-ladder ports; this catches
    // the simplest case.
    use crate::curve25519::Point;
    let mut scalar = [0u8; 32];
    scalar[0] = 1;
    if Point::BASE.mul(&scalar).to_bytes() == Point::BASE.to_bytes() {
        TestResult::Pass
    } else {
        TestResult::Fail("B*1 ≠ B — Montgomery ladder bug")
    }
}
kernel_test_in!("crypto", smoke_crypto_curve25519_base_times_one);

fn smoke_crypto_curve25519_base_doubled() -> TestResult {
    // B*2 produces the well-known doubled-base compressed point
    // (RFC 8032 §6 reference value).
    use crate::curve25519::Point;
    let want: [u8; 32] = [
        0xc9, 0xa3, 0xf8, 0x6a, 0xae, 0x46, 0x5f, 0x0e, 0x56, 0x51, 0x38, 0x64, 0x51, 0x0f,
        0x39, 0x97, 0x56, 0x1f, 0xa2, 0xc9, 0xe8, 0x5e, 0xa2, 0x1d, 0xc2, 0x29, 0x23, 0x09,
        0xf3, 0xcd, 0x60, 0x22,
    ];
    if Point::BASE.double().to_bytes() == want {
        TestResult::Pass
    } else {
        TestResult::Fail("B*2 drifted from RFC 8032 reference")
    }
}
kernel_test_in!("crypto", smoke_crypto_curve25519_base_doubled);

fn smoke_crypto_hkdf_extract_expand_rfc5869() -> TestResult {
    // RFC 5869 Test Case 1 — extract then expand against the raw
    // `hkdf::*` API (cap-free) to catch primitive-level regressions.
    use crate::hkdf::{hkdf_expand, hkdf_extract};
    let ikm = [0x0bu8; 22];
    let salt = [
        0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];
    let info = [0xf0u8, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
    let prk = hkdf_extract(Some(&salt), &ikm);
    let want_prk: [u8; 32] = [
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
        0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
        0xd7, 0xc2, 0xb3, 0xe5,
    ];
    if prk != want_prk {
        return TestResult::Fail("hkdf_extract drift");
    }
    let okm = hkdf_expand(&prk, &info, 42);
    let want_okm: [u8; 42] = [
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
        0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
        0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
    ];
    if okm.as_slice() == &want_okm[..] {
        TestResult::Pass
    } else {
        TestResult::Fail("hkdf_expand drift")
    }
}
kernel_test_in!("crypto", smoke_crypto_hkdf_extract_expand_rfc5869);

fn smoke_crypto_hmac_sha256_matches_rfc4231() -> TestResult {
    // RFC 4231 §4.2 Test Case 1 — HMAC-SHA-256 with the canonical
    // "Hi There" payload. Our `hmac_sha256` is the lower layer
    // under HKDF-extract; if HKDF-extract regressed silently we'd
    // see a mismatch here first.
    use crate::hkdf::hmac_sha256;
    let key = [0x0bu8; 20];
    let mac = hmac_sha256(&key, b"Hi There");
    let want: [u8; 32] = [
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
        0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
        0x2e, 0x32, 0xcf, 0xf7,
    ];
    if mac == want {
        TestResult::Pass
    } else {
        TestResult::Fail("hmac_sha256 drift from RFC 4231 case 1")
    }
}
kernel_test_in!("crypto", smoke_crypto_hmac_sha256_matches_rfc4231);

fn smoke_crypto_blake3_known_message() -> TestResult {
    // The existing smoke covers the empty-input KAT. Add a
    // non-trivial-input KAT (BLAKE3 official test vectors) so a
    // chunk-boundary regression in the cleanroom port shows up.
    use crate::blake3_hash;
    let got = blake3_hash(b"abc");
    let want: [u8; 32] = [
        0x64, 0x37, 0xb3, 0xac, 0x38, 0x46, 0x51, 0x33, 0xff, 0xb6, 0x3b, 0x75, 0x27, 0x3a,
        0x8d, 0xb5, 0x48, 0xc5, 0x58, 0x46, 0x5d, 0x79, 0xdb, 0x03, 0xfd, 0x35, 0x9c, 0x6c,
        0xd5, 0xbd, 0x9d, 0x85,
    ];
    if got == want {
        TestResult::Pass
    } else {
        TestResult::Fail("blake3(\"abc\") drift")
    }
}
kernel_test_in!("crypto", smoke_crypto_blake3_known_message);
