// SPDX-License-Identifier: GPL-2.0-or-later
//! Linux eeprom_4k.c full HT40 power tables. Primary target/CTL, extension
//! legacy target/CTL and center HT40 target/CTL have distinct lookup centers.
use super::*;
use crate::ath9k::channel_width::Geometry;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct WidePlan {
    pub(in crate::ath9k) geometry: Geometry,
    pub(in crate::ath9k) increment: u8,
    pub(in crate::ath9k) registers: [(u64, u32); 10],
}
pub(in crate::ath9k) fn wide_plan(
    image: &[u8; EEPROM_4K_BYTES],
    geometry: Geometry,
    ceiling: u8,
) -> Result<WidePlan, BringUpError> {
    if !geometry.is_wide() || ceiling > 40 || ceiling < image[60] {
        return Err(BringUpError::Policy);
    }
    let factory = Factory::from_eeprom(u32::from(crate::ath9k::identity::eeprom_word(image, 8)))
        .map_err(|_| BringUpError::BadCalibration)?;
    let ctl = initial_ctl(factory);
    let primary = plan(image, geometry.control(), ctl, ceiling)?;
    let conducted = ceiling - image[60];
    let mut ht40 = target::<8>(image, 240, geometry.center())?;
    let allowed = limit(image, geometry.center(), ctl, 7, conducted)?;
    for power in &mut ht40 {
        *power = (*power).min(allowed);
    }
    let ext_cck = target::<4>(image, 183, geometry.extension())?[0].min(limit(
        image,
        geometry.extension(),
        ctl,
        1,
        conducted,
    )?);
    let ext_ofdm = target::<4>(image, 198, geometry.extension())?[0].min(limit(
        image,
        geometry.extension(),
        ctl,
        2,
        conducted,
    )?);
    let minor = crate::ath9k::identity::eeprom_word(image, 4) & 0xfff;
    let increment = if minor >= 2 { image[82] } else { 2 };
    let pack = |power: [u8; 4], increment: u8| -> Result<u32, BringUpError> {
        let mut word = 0;
        for (index, power) in power.into_iter().enumerate() {
            // ATH9K_POW_SM is6 bits. Refuse an unrepresentable board gain
            // instead of wrapping the native PDADC compensation downward.
            let encoded = u16::from(power) + 10 + u16::from(increment);
            if encoded > 63 {
                return Err(BringUpError::BadCalibration);
            }
            word |= u32::from(encoded) << (index * 8);
        }
        Ok(word)
    };
    Ok(WidePlan {
        geometry,
        increment,
        registers: [
            primary.registers[0],
            primary.registers[1],
            primary.registers[2],
            primary.registers[3],
            primary.registers[4],
            primary.registers[5],
            (0xa3cc, pack(ht40[..4].try_into().unwrap(), increment)?),
            (0xa3d0, pack(ht40[4..].try_into().unwrap(), increment)?),
            // Native duplicate CCK/OFDM use HT40 MCS0 power without the
            // HT40 PDADC increment; extension legacy powers are separate.
            (0xa3d4, pack([ht40[0], ht40[0], ext_cck, ext_ofdm], 0)?),
            primary.registers[6],
        ],
    })
}
pub(in crate::ath9k) fn program_wide(
    io: &mut impl RegisterIo,
    image: &[u8; EEPROM_4K_BYTES],
    geometry: Geometry,
    ceiling: u8,
) -> Result<WidePlan, BringUpError> {
    let plan = wide_plan(image, geometry, ceiling)?;
    for (register, value) in plan.registers {
        if !io.authorized() {
            return Err(BringUpError::DeviceGone);
        }
        io.write32(register, value);
        if !io.authorized() || io.read32(register) != value {
            return Err(BringUpError::DeviceGone);
        }
    }
    Ok(plan)
}
