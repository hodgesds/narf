//! CMAC-AES256 (NIST SP 800-38B).
//!
//! This is the AES-256 instantiation of the CMAC construction used by
//! BIP-CMAC-256.  It deliberately keeps the same small, allocation-free
//! core as `cmac_aes128`: only the AES key schedule changes.

#![allow(dead_code)]

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;

/// AES block and CMAC tag length, in octets.
pub const CMAC_TAG_LEN: usize = 16;

/// GF(2^128) reduction constant from NIST SP 800-38B §6.1.
const RB: u8 = 0x87;

/// Derive CMAC's K1 and K2 subkeys for an AES-256 key.
pub fn derive_subkeys(aes_key: &[u8; 32]) -> ([u8; 16], [u8; 16]) {
    let cipher = Aes256::new(GenericArray::from_slice(aes_key));
    let mut block = GenericArray::clone_from_slice(&[0u8; 16]);
    cipher.encrypt_block(&mut block);
    let mut l = [0u8; 16];
    l.copy_from_slice(block.as_slice());
    let k1 = gf128_double(&l);
    let k2 = gf128_double(&k1);
    (k1, k2)
}

fn gf128_double(block: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut carry = 0u8;
    for i in (0..16).rev() {
        let next_carry = block[i] >> 7;
        out[i] = (block[i] << 1) | carry;
        carry = next_carry;
    }
    if block[0] >> 7 != 0 {
        out[15] ^= RB;
    }
    out
}

/// Compute the full 128-bit AES-256-CMAC tag over `data`.
pub fn cmac_aes256(aes_key: &[u8; 32], data: &[u8]) -> [u8; CMAC_TAG_LEN] {
    let (k1, k2) = derive_subkeys(aes_key);
    cmac_aes256_with_subkeys(aes_key, &k1, &k2, data)
}

/// AES-256-CMAC with caller-provided subkeys, for repeated operations under
/// one IGTK.
pub fn cmac_aes256_with_subkeys(
    aes_key: &[u8; 32],
    k1: &[u8; 16],
    k2: &[u8; 16],
    data: &[u8],
) -> [u8; CMAC_TAG_LEN] {
    let cipher = Aes256::new(GenericArray::from_slice(aes_key));
    let block_count = data.len().div_ceil(16);
    let complete_last = block_count != 0 && data.len() % 16 == 0;
    let preceding = block_count.saturating_sub(1);
    let mut x = [0u8; 16];

    for i in 0..preceding {
        let input = &data[i * 16..(i + 1) * 16];
        for j in 0..16 {
            x[j] ^= input[j];
        }
        let mut block = GenericArray::clone_from_slice(&x);
        cipher.encrypt_block(&mut block);
        x.copy_from_slice(block.as_slice());
    }

    let mut last = [0u8; 16];
    let subkey = if block_count == 0 {
        last[0] = 0x80;
        k2
    } else if complete_last {
        let offset = preceding * 16;
        last.copy_from_slice(&data[offset..offset + 16]);
        k1
    } else {
        let offset = preceding * 16;
        let tail = &data[offset..];
        last[..tail.len()].copy_from_slice(tail);
        last[tail.len()] = 0x80;
        k2
    };
    for j in 0..16 {
        x[j] ^= last[j] ^ subkey[j];
    }
    let mut block = GenericArray::clone_from_slice(&x);
    cipher.encrypt_block(&mut block);
    let mut tag = [0u8; CMAC_TAG_LEN];
    tag.copy_from_slice(block.as_slice());
    tag
}

pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // NIST SP 800-38B, Appendix D.3, AES-256 Example 1.
    fn smoke_cmac_aes256_nist_empty() -> TestResult {
        let key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let expected = [
            0x02, 0x89, 0x62, 0xf6, 0x1b, 0x7b, 0xf8, 0x9e, 0xfc, 0x6b, 0x55, 0x1f, 0x46, 0x67,
            0xd9, 0x83,
        ];
        if cmac_aes256(&key, &[]) != expected {
            return TestResult::Fail("NIST AES-256-CMAC empty-vector mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/cmac", smoke_cmac_aes256_nist_empty);

    // NIST SP 800-38B, Appendix D.3, AES-256 Example 3 (40 octets).
    fn smoke_cmac_aes256_nist_partial_block() -> TestResult {
        let key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let message = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac,
            0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        ];
        let expected = [
            0xaa, 0xf3, 0xd8, 0xf1, 0xde, 0x56, 0x40, 0xc2, 0x32, 0xf5, 0xb1, 0x69, 0xb9, 0xc9,
            0x11, 0xe6,
        ];
        if cmac_aes256(&key, &message) != expected {
            return TestResult::Fail("NIST AES-256-CMAC partial-vector mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/cmac", smoke_cmac_aes256_nist_partial_block);
}
