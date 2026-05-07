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
