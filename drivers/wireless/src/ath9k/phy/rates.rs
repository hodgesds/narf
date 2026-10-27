// SPDX-License-Identifier: GPL-2.0-or-later
//! AR9285 legacy20 target-power interpolation and factory CTL limiting.
//! The inactive probe supplies a zero-dBm ceiling; this grants no TX rights.
use crate::{
    ath9k::{
        identity::{BringUpError, RegisterIo},
        EEPROM_4K_BYTES,
    },
    qualcomm_regulatory::Factory,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct Plan {
    pub(in crate::ath9k) registers: [(u64, u32); 7],
}
fn target<const N: usize>(
    image: &[u8; EEPROM_4K_BYTES],
    at: usize,
    frequency: u16,
) -> Result<[u8; N], BringUpError> {
    let rows = &image[at..at + 3 * (N + 1)];
    let count = rows
        .chunks_exact(N + 1)
        .position(|r| r[0] == 255)
        .unwrap_or(3);
    if count == 0 {
        return Err(BringUpError::BadCalibration);
    }
    for (i, row) in rows.chunks_exact(N + 1).take(count).enumerate() {
        if row[1..].iter().any(|p| *p > 63) || (i > 0 && rows[(i - 1) * (N + 1)] >= row[0]) {
            return Err(BringUpError::BadCalibration);
        }
    }
    let mut left = 0;
    let mut right = 0;
    if frequency >= 2300 + u16::from(rows[(count - 1) * (N + 1)]) {
        left = count - 1;
        right = left;
    } else if frequency > 2300 + u16::from(rows[0]) {
        for i in 1..count {
            let f = 2300 + u16::from(rows[i * (N + 1)]);
            if frequency == f {
                left = i;
                right = i;
                break;
            }
            if frequency < f {
                left = i - 1;
                right = i;
                break;
            }
        }
    }
    let a = &rows[left * (N + 1)..(left + 1) * (N + 1)];
    let b = &rows[right * (N + 1)..(right + 1) * (N + 1)];
    Ok(core::array::from_fn(|i| {
        if left == right {
            a[i + 1]
        } else {
            let x = i32::from(frequency) - 2300;
            (((x - i32::from(a[0])) * i32::from(b[i + 1])
                + (i32::from(b[0]) - x) * i32::from(a[i + 1]))
                / (i32::from(b[0]) - i32::from(a[0]))) as u8
        }
    }))
}
fn edge(image: &[u8; EEPROM_4K_BYTES], index: usize, frequency: u16) -> Result<u8, BringUpError> {
    let edges = &image[279 + index * 8..279 + (index + 1) * 8];
    let count = edges.chunks_exact(2).position(|r| r[0] == 255).unwrap_or(4);
    for i in 1..count {
        if edges[(i - 1) * 2] >= edges[i * 2] {
            return Err(BringUpError::BadCalibration);
        }
    }
    for i in 0..count {
        let f = 2300 + u16::from(edges[i * 2]);
        if frequency == f {
            return Ok(edges[i * 2 + 1] & 63);
        }
        if frequency < f {
            if i > 0 && edges[(i - 1) * 2 + 1] >> 6 != 0 {
                return Ok(edges[(i - 1) * 2 + 1] & 63);
            }
            break;
        }
    }
    Ok(63)
}
fn limit(
    image: &[u8; EEPROM_4K_BYTES],
    frequency: u16,
    cfg_ctl: u16,
    mode: u16,
    ceiling: u8,
) -> Result<u8, BringUpError> {
    let mut power = 63;
    let wanted = (cfg_ctl & !15) | (mode & 15);
    for (i, index) in image[267..279]
        .iter()
        .copied()
        .take_while(|n| *n != 0)
        .enumerate()
    {
        if wanted != u16::from(index) && wanted != (u16::from(index) & 15) | 0xe0 {
            continue;
        }
        let p = edge(image, i, frequency)?;
        if cfg_ctl & !15 == 0xe0 {
            power = power.min(p);
        } else {
            power = p;
            break;
        }
    }
    Ok(power.min(ceiling))
}
fn plan(
    image: &[u8; EEPROM_4K_BYTES],
    frequency: u16,
    cfg_ctl: u16,
    ceiling: u8,
) -> Result<Plan, BringUpError> {
    if !(2300..2555).contains(&frequency) || ceiling > 40 {
        return Err(BringUpError::BadCalibration);
    }
    // EEPROM antenna gain is already in half-dBm. Saturation prevents an
    // unsigned subtraction from raising power when a ceiling is below gain.
    let ceiling = ceiling.saturating_sub(image[60]);
    let mut cck = target::<4>(image, 183, frequency)?;
    let mut ofdm = target::<4>(image, 198, frequency)?;
    let mut ht20 = target::<8>(image, 213, frequency)?;
    for (mode, powers) in [(1, &mut cck[..]), (2, &mut ofdm[..]), (5, &mut ht20[..])] {
        let allowed = limit(image, frequency, cfg_ctl, mode, ceiling)?;
        for power in powers {
            *power = (*power).min(allowed);
        }
    }
    // AR5416_PWR_TABLE_OFFSET_DB=-5; subtracting twice that offset adds10.
    // The conservative20-dBm ceiling keeps every six-bit encoded level valid.
    let pack = |powers: [u8; 4]| -> u32 {
        powers
            .into_iter()
            .enumerate()
            .fold(0, |v, (i, p)| v | (u32::from(p + 10) << (8 * i)))
    };
    Ok(Plan {
        registers: [
            (0x9934, pack([ofdm[0]; 4])),
            (0x9938, pack(ofdm)),
            (0xa234, pack([cck[0], ofdm[0], cck[1], cck[1]])),
            (0xa238, pack([cck[2], cck[2], cck[3], cck[3]])),
            (0xa38c, pack(ht20[..4].try_into().unwrap())),
            (0xa390, pack(ht20[4..].try_into().unwrap())),
            (0x993c, 63), // TPC disabled until the retained TX descriptor owner exists.
        ],
    })
}
fn initial_ctl(factory: Factory) -> u16 {
    // ath_regd_get_band_ctl, initial DFS region unset. World SKUs take the
    // minimum across matching EEPROM regulatory groups rather than NO_CTL.
    let rd = factory.eeprom & !0x4000;
    let world = rd & 0x8000 == 0 && (rd & 0xf0 == 0x60 || rd == 0x199);
    (if factory.country == 0 && world {
        0xe0
    } else {
        factory.ctl_2ghz
    }) | 2
}
pub(in crate::ath9k) fn checked_plan(
    image: &[u8; EEPROM_4K_BYTES],
    ceiling: u8,
) -> Result<Plan, BringUpError> {
    let factory = Factory::from_eeprom(u32::from(u16::from_le_bytes(
        image[8..10].try_into().unwrap(),
    )))
    .map_err(|_| BringUpError::BadCalibration)?;
    plan(image, 2412, initial_ctl(factory), ceiling)
}
pub(super) fn program(
    io: &mut impl RegisterIo,
    image: &[u8; EEPROM_4K_BYTES],
    frequency: u16,
    ceiling: u8,
) -> Result<(), BringUpError> {
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    let factory = Factory::from_eeprom(u32::from(u16::from_le_bytes(
        image[8..10].try_into().unwrap(),
    )))
    .map_err(|_| BringUpError::BadCalibration)?;
    let p = plan(image, frequency, initial_ctl(factory), ceiling)?;
    for (register, value) in p.registers {
        if !io.authorized() {
            return Err(BringUpError::DeviceGone);
        }
        io.write32(register, value);
    }
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    Ok(())
}
#[cfg(any(test, feature = "kernel-test"))]
mod tests;
