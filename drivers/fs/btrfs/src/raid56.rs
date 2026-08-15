//! RAID5/6 parity arithmetic.
//!
//! Btrfs uses ordinary XOR for P and the Linux RAID6 convention for Q: data
//! stripe `i` is multiplied by `2^i` in GF(2^8), whose reduction polynomial is
//! `x^8 + x^4 + x^3 + x^2 + 1` (`0x1d` after the high bit is shifted out).

use alloc::vec;
use alloc::vec::Vec;

use narf_filesystem::FsError;

/// Build P and, when requested, Q for equal-length data stripes.
pub(crate) fn syndromes(data: &[&[u8]], with_q: bool) -> Result<(Vec<u8>, Vec<u8>), FsError> {
    let len = data.first().map_or(0, |stripe| stripe.len());
    if data.is_empty() || data.iter().any(|stripe| stripe.len() != len) {
        return Err(FsError::InvalidData);
    }
    let mut p = vec![0u8; len];
    let mut q = vec![0u8; if with_q { len } else { 0 }];
    let mut coefficient = 1u8;
    for stripe in data {
        for (at, byte) in stripe.iter().copied().enumerate() {
            p[at] ^= byte;
            if with_q {
                q[at] ^= gf_mul(byte, coefficient);
            }
        }
        coefficient = gf_mul2(coefficient);
    }
    Ok((p, q))
}

/// Recover one or two absent data stripes from available P/Q syndromes.
///
/// `data` is in btrfs's logical data-stripe order. `None` entries are rebuilt
/// in place. A missing parity slice is represented by `None` as well.
pub(crate) fn recover(
    data: &mut [Option<Vec<u8>>],
    p: Option<&[u8]>,
    q: Option<&[u8]>,
    len: usize,
) -> Result<(), FsError> {
    if data.is_empty()
        || data.iter().flatten().any(|stripe| stripe.len() != len)
        || p.is_some_and(|stripe| stripe.len() != len)
        || q.is_some_and(|stripe| stripe.len() != len)
    {
        return Err(FsError::InvalidData);
    }

    let missing: Vec<usize> = data
        .iter()
        .enumerate()
        .filter_map(|(index, stripe)| stripe.is_none().then_some(index))
        .collect();
    match missing.as_slice() {
        [] => Ok(()),
        &[target] => {
            let mut rebuilt = vec![0u8; len];
            if let Some(parity) = p {
                rebuilt.copy_from_slice(parity);
                for stripe in data.iter().flatten() {
                    xor_into(&mut rebuilt, stripe);
                }
            } else if let Some(syndrome) = q {
                rebuilt.copy_from_slice(syndrome);
                let mut coefficient = 1u8;
                for (index, stripe) in data.iter().enumerate() {
                    if let Some(stripe) = stripe {
                        mul_xor_into(&mut rebuilt, stripe, coefficient);
                    }
                    if index != data.len() - 1 {
                        coefficient = gf_mul2(coefficient);
                    }
                }
                let inverse = gf_inv(gf_pow2(target)).ok_or(FsError::InvalidData)?;
                for byte in &mut rebuilt {
                    *byte = gf_mul(*byte, inverse);
                }
            } else {
                return Err(FsError::InvalidData);
            }
            data[target] = Some(rebuilt);
            Ok(())
        }
        &[first, second] => {
            let (p, q) = p.zip(q).ok_or(FsError::InvalidData)?;
            let mut p_missing = p.to_vec();
            let mut q_missing = q.to_vec();
            let mut coefficient = 1u8;
            for stripe in data.iter() {
                if let Some(stripe) = stripe {
                    xor_into(&mut p_missing, stripe);
                    mul_xor_into(&mut q_missing, stripe, coefficient);
                }
                coefficient = gf_mul2(coefficient);
            }

            // P' = Da ^ Db; Q' = ca*Da ^ cb*Db.
            // Db = (Q' ^ ca*P') / (ca ^ cb), then Da = P' ^ Db.
            let ca = gf_pow2(first);
            let cb = gf_pow2(second);
            let inverse = gf_inv(ca ^ cb).ok_or(FsError::InvalidData)?;
            let mut second_data = vec![0u8; len];
            let mut first_data = vec![0u8; len];
            for at in 0..len {
                second_data[at] = gf_mul(q_missing[at] ^ gf_mul(ca, p_missing[at]), inverse);
                first_data[at] = p_missing[at] ^ second_data[at];
            }
            data[first] = Some(first_data);
            data[second] = Some(second_data);
            Ok(())
        }
        _ => Err(FsError::InvalidData),
    }
}

fn xor_into(dst: &mut [u8], src: &[u8]) {
    for (dst, src) in dst.iter_mut().zip(src.iter().copied()) {
        *dst ^= src;
    }
}

fn mul_xor_into(dst: &mut [u8], src: &[u8], coefficient: u8) {
    for (dst, src) in dst.iter_mut().zip(src.iter().copied()) {
        *dst ^= gf_mul(src, coefficient);
    }
}

fn gf_pow2(power: usize) -> u8 {
    let mut value = 1u8;
    for _ in 0..power {
        value = gf_mul2(value);
    }
    value
}

fn gf_mul2(value: u8) -> u8 {
    (value << 1) ^ if value & 0x80 != 0 { 0x1d } else { 0 }
}

fn gf_mul(mut left: u8, mut right: u8) -> u8 {
    let mut product = 0u8;
    while right != 0 {
        if right & 1 != 0 {
            product ^= left;
        }
        left = gf_mul2(left);
        right >>= 1;
    }
    product
}

fn gf_inv(value: u8) -> Option<u8> {
    if value == 0 {
        return None;
    }
    // Every non-zero GF(2^8) element satisfies x^255 = 1.
    let mut result = 1u8;
    let mut base = value;
    let mut exponent = 254u8;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exponent >>= 1;
    }
    Some(result)
}
