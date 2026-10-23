// SPDX-License-Identifier: GPL-2.0-or-later
//! AR9285 EEPROM-derived detector calibration. This programs no transmit
//! permission: CTL/rate power, analog calibration and active PHY are separate.
use crate::ath9k::{
    identity::{BringUpError, RegisterIo},
    EEPROM_4K_BYTES,
};
#[derive(Debug)]
struct Plan {
    gains: [u16; 2],
    count: usize,
    bounds: [u16; 4],
    values: [u8; 128],
    overlap: u8,
}
fn indices(target: u8, list: &[u8]) -> (usize, usize) {
    if target <= list[0] {
        return (0, 0);
    }
    if target >= list[list.len() - 1] {
        return (list.len() - 1, list.len() - 1);
    }
    for i in 0..list.len() - 1 {
        if target == list[i] {
            return (i, i);
        }
        if target < list[i + 1] {
            return (i, i + 1);
        }
    }
    unreachable!()
}
fn interpolate(target: u16, left: u16, right: u16, a: u8, b: u8) -> u8 {
    if left == right {
        return a;
    }
    (((i32::from(target) - i32::from(left)) * i32::from(b)
        + (i32::from(right) - i32::from(target)) * i32::from(a))
        / (i32::from(right) - i32::from(left))) as u8
}
fn vpd(minimum: u8, maximum: u8, power: &[u8], detector: &[u8]) -> [u8; 64] {
    let mut out = [0; 64];
    for (i, at) in out
        .iter_mut()
        .take(usize::from((maximum - minimum) / 2) + 1)
        .enumerate()
    {
        let value = minimum + 2 * i as u8;
        let (mut left, mut right) = indices(value, power);
        if right < 1 {
            right = 1;
        }
        if left == power.len() - 1 {
            left = power.len() - 2;
        }
        *at = interpolate(
            u16::from(value),
            u16::from(power[left]),
            u16::from(power[right]),
            detector[left],
            detector[right],
        );
    }
    out
}
fn plan(image: &[u8; EEPROM_4K_BYTES], frequency: u16, overlap: u8) -> Result<Plan, BringUpError> {
    if !(2300..2555).contains(&frequency)
        || overlap > 15
        || image[72] & 15 == 0
        || image[72] & !15 != 0
    {
        return Err(BringUpError::BadCalibration);
    }
    let mut gains = [0; 2];
    let mut count = 0;
    for bit in (0..4).rev() {
        if image[72] & (1 << bit) != 0 && count < 2 {
            gains[count] = bit as u16;
            count += 1;
        }
    }
    let piers = &image[120..123];
    let piers = &piers[..piers.iter().position(|b| *b == 255).unwrap_or(3)];
    if piers.is_empty() || piers.windows(2).any(|w| w[0] >= w[1]) {
        return Err(BringUpError::BadCalibration);
    }
    let target = (frequency - 2300) as u8;
    let (left, right) = indices(target, piers);
    let mut minimum = [0u8; 2];
    let mut maximum = [0u8; 2];
    let mut tables = [[0u8; 64]; 2];
    for gain in 0..count {
        let mut parts = [([0u8; 5], [0u8; 5]); 2];
        for (slot, pier) in [left, right].into_iter().enumerate() {
            let at = 123 + pier * 20 + gain * 5;
            parts[slot].0.copy_from_slice(&image[at..at + 5]);
            parts[slot].1.copy_from_slice(&image[at + 10..at + 15]);
            if parts[slot].0.windows(2).any(|w| w[0] > w[1])
                || parts[slot].1.windows(2).any(|w| w[0] > w[1])
            {
                return Err(BringUpError::BadCalibration);
            }
        }
        minimum[gain] = parts[0].0[0].max(parts[1].0[0]);
        maximum[gain] = parts[0].0[4].min(parts[1].0[4]);
        let range = maximum[gain]
            .checked_sub(minimum[gain])
            .filter(|r| (2..=126).contains(r))
            .ok_or(BringUpError::BadCalibration)?;
        let a = vpd(minimum[gain], maximum[gain], &parts[0].0, &parts[0].1);
        let b = vpd(minimum[gain], maximum[gain], &parts[1].0, &parts[1].1);
        for i in 0..=usize::from(range / 2) {
            tables[gain][i] = interpolate(
                u16::from(target),
                u16::from(piers[left]),
                u16::from(piers[right]),
                a[i],
                b[i],
            );
        }
    }
    let mut bounds = [58; 4];
    let mut values = [0u8; 128];
    let mut k = 0;
    for gain in 0..count {
        bounds[gain] = (if gain == count - 1 {
            u16::from(maximum[gain]) / 2
        } else {
            (u16::from(maximum[gain]) + u16::from(minimum[gain + 1])) / 4
        })
        .min(63);
        let mut offset = if gain == 0 {
            -(i16::from(minimum[gain]) / 2)
        } else {
            bounds[gain - 1] as i16 - i16::from(minimum[gain]) / 2 - i16::from(overlap) + 1
        };
        let first = tables[gain][0];
        let step = (i16::from(tables[gain][1]) - i16::from(first)).max(1);
        while offset < 0 && k < 127 {
            values[k] = (i16::from(first) + offset * step).max(0) as u8;
            k += 1;
            offset += 1;
        }
        let size = usize::from((maximum[gain] - minimum[gain]) / 2) + 1;
        // Linux explicitly narrows tgtIndex to u8 before selecting its cap.
        let target =
            (bounds[gain] as i16 + i16::from(overlap) - i16::from(minimum[gain]) / 2) as u8;
        let limit = usize::from(target).min(size) as i16;
        while offset < limit && k < 127 {
            values[k] = tables[gain][offset as usize];
            k += 1;
            offset += 1;
        }
        let last = tables[gain][size - 1];
        let step = (i16::from(last) - i16::from(tables[gain][size - 2])).max(1);
        if i16::from(target) >= limit {
            while offset <= i16::from(target) && k < 127 {
                values[k] = (i16::from(last) + (offset - limit + 1) * step).min(255) as u8;
                k += 1;
                offset += 1;
            }
        }
    }
    if k == 0 {
        return Err(BringUpError::BadCalibration);
    }
    while k < 128 {
        values[k] = values[k - 1];
        k += 1;
    }
    Ok(Plan {
        gains,
        count,
        bounds,
        values,
        overlap,
    })
}
pub(super) fn program(
    io: &mut impl RegisterIo,
    image: &[u8; EEPROM_4K_BYTES],
    frequency: u16,
) -> Result<(), BringUpError> {
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    let minor = u16::from_le_bytes(image[4..6].try_into().unwrap()) & 0xfff;
    let overlap = if minor >= 2 {
        image[76]
    } else {
        let value = io.read32(0xa26c);
        if value == u32::MAX {
            return Err(BringUpError::DeviceGone);
        }
        (value & 15) as u8
    };
    // Validate the complete calibration before any detector register update.
    let p = plan(image, frequency, overlap)?;
    for (mask, shift, value) in [
        (0xc000, 14, (p.count - 1) as u16),
        (0x30000, 16, p.gains[0]),
        (0xc0000, 18, p.gains[1]),
        (0x300000, 20, 0),
    ] {
        super::rmw(io, 0xa258, mask, (u32::from(value) << shift) & mask)?;
    }
    let mut boundaries = u32::from(p.overlap);
    for (i, b) in p.bounds.iter().enumerate() {
        boundaries |= u32::from(*b) << (4 + 6 * i);
    }
    io.write32(0xa26c, boundaries);
    for (i, bytes) in p.values.chunks_exact(4).enumerate() {
        io.write32(
            0xa280 + i as u64 * 4,
            u32::from_le_bytes(bytes.try_into().unwrap()),
        );
    }
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    Ok(())
}
#[cfg(any(test, feature = "kernel-test"))]
#[path = "power/tests.rs"]
mod tests;
