use super::*;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

fn decode<const N: usize>(hex: &str) -> [u8; N] {
    let mut result = [0; N];
    for (byte, pair) in result.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        let digit = |v: u8| if v <= b'9' { v - b'0' } else { v - b'a' + 10 };
        *byte = digit(pair[0]) << 4 | digit(pair[1]);
    }
    result
}
// RFC 3610 §8 Packet Vector #1: 8 octets cleartext AAD, 23 message,
// 13-byte nonce, detached 8-octet authentication tag.
fn smoke_aes_ccm_rfc3610_vector_one() -> TestResult {
    let key = decode::<16>("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
    let nonce = decode::<13>("00000003020100a0a1a2a3a4a5");
    let aad = decode::<8>("0001020304050607");
    let plain = decode::<23>("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e");
    let encrypted = decode::<23>("588c979a61c663d2f066d0c2c0f989806d5f6b61dac384");
    let expected = decode::<8>("17e8d12cfdf926e0");
    let mut body = plain;
    if seal(&key, &nonce, &aad, &mut body) != Ok(expected) || body != encrypted {
        return TestResult::Fail("RFC3610 CCM ciphertext/tag differ");
    }
    if open(&key, &nonce, &aad, &mut body, &expected) != Ok(()) || body != plain {
        return TestResult::Fail("RFC3610 CCM known ciphertext did not authenticate");
    }
    TestResult::Pass
}
kernel_test_in!("crypto/aes_ccm", smoke_aes_ccm_rfc3610_vector_one);

fn smoke_aes_ccm_auth_failure_never_exposes_plaintext() -> TestResult {
    let key = decode::<16>("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
    let nonce = decode::<13>("00000003020100a0a1a2a3a4a5");
    let aad = decode::<8>("0001020304050607");
    let encrypted = decode::<23>("588c979a61c663d2f066d0c2c0f989806d5f6b61dac384");
    let tag = decode::<8>("17e8d12cfdf926e0");
    for field in 0..5 {
        let (mut key, mut nonce, mut aad, mut body, mut tag) = (key, nonce, aad, encrypted, tag);
        match field {
            0 => key[7] ^= 1,
            1 => nonce[3] ^= 1,
            2 => aad[4] ^= 1,
            3 => body[11] ^= 1,
            _ => tag[5] ^= 1,
        }
        let before = body;
        if open(&key, &nonce, &aad, &mut body, &tag) != Err(Error::Authentication) || body != before
        {
            return TestResult::Fail("CCM auth failure modified caller ciphertext");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "crypto/aes_ccm",
    smoke_aes_ccm_auth_failure_never_exposes_plaintext
);

fn smoke_aes_ccm_message_length_rejects_before_mutation() -> TestResult {
    let mut body = vec![0xa5; MAX_MESSAGE_LEN + 1];
    if seal(&[0; 16], &[0; 13], &[], &mut body) != Err(Error::Length)
        || open(&[0; 16], &[0; 13], &[], &mut body, &[0; 8]) != Err(Error::Length)
        || body.iter().any(|byte| *byte != 0xa5)
    {
        return TestResult::Fail("L=2 overflow mutated plaintext/ciphertext");
    }
    TestResult::Pass
}
kernel_test_in!(
    "crypto/aes_ccm",
    smoke_aes_ccm_message_length_rejects_before_mutation
);

fn smoke_aes_ccm_rfc3610_additional_vectors() -> TestResult {
    let key = decode::<16>("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
    // RFC3610 §8 Packet Vector #2 (24-byte message).
    let nonce = decode::<13>("00000004030201a0a1a2a3a4a5");
    let aad = decode::<8>("0001020304050607");
    let mut body = decode::<24>("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    if seal(&key, &nonce, &aad, &mut body) != Ok(decode::<8>("a091d56e10400916"))
        || body != decode::<24>("72c91a36e135f8cf291ca894085c87e3cc15c439c9e43a3b")
    {
        return TestResult::Fail("RFC3610 vector2 differs");
    }
    // RFC3610 §8 Packet Vector #4 (12-byte AAD, 19-byte message).
    let nonce = decode::<13>("00000006050403a0a1a2a3a4a5");
    let aad = decode::<12>("000102030405060708090a0b");
    let mut body = decode::<19>("0c0d0e0f101112131415161718191a1b1c1d1e");
    if seal(&key, &nonce, &aad, &mut body) != Ok(decode::<8>("96c861b9c9e61ef1"))
        || body != decode::<19>("a28c6865939a9a79faaa5c4c2a9d4a91cdac8c")
    {
        return TestResult::Fail("RFC3610 vector4 differs");
    }
    TestResult::Pass
}
kernel_test_in!("crypto/aes_ccm", smoke_aes_ccm_rfc3610_additional_vectors);

// Independent OpenSSL AES-CCM oracle, via Python cryptography AESCCM with
// key=00..0f, nonce=00..0c, body[i]=i%256, aad[i]=i%256, tag_length=8.
// Includes independent AAD/message pad boundaries and RFC's 0xff00 AAD
// length-encoding transition; expected tags are frozen, not self-roundtrips.
fn smoke_aes_ccm_independent_boundary_vectors() -> TestResult {
    let key = decode::<16>("000102030405060708090a0b0c0d0e0f");
    let nonce = decode::<13>("000102030405060708090a0b0c");
    for (message_len, aad_len, tag) in [
        (0, 0, "9fbef26dcc34fce5"),
        (0, 16, "9e936fa265330a0f"),
        (16, 0, "7033fd7b5f2ad5b2"),
        (16, 14, "5aab3bef9f50a108"),
        (17, 30, "f4df8342d1842642"),
        (1, 65279, "3ae00a8cbc3a0b13"),
        (1, 65280, "9890bc270fad2a72"),
        (65535, 0, "87c00f421b8120ba"),
    ] {
        let plain: Vec<u8> = (0..message_len).map(|n| n as u8).collect();
        let aad: Vec<u8> = (0..aad_len).map(|n| n as u8).collect();
        let mut body = plain.clone();
        let expected = decode::<8>(tag);
        if seal(&key, &nonce, &aad, &mut body) != Ok(expected) {
            return TestResult::Fail("independent AES-CCM boundary tag differs");
        }
        if !body.is_empty() && body[0] != 0x16 {
            return TestResult::Fail("independent AES-CCM counter start differs");
        }
        if open(&key, &nonce, &aad, &mut body, &expected) != Ok(()) || body != plain {
            return TestResult::Fail("independent AES-CCM boundary open failed");
        }
    }
    TestResult::Pass
}
kernel_test_in!("crypto/aes_ccm", smoke_aes_ccm_independent_boundary_vectors);
