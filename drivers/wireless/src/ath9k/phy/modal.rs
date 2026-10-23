// SPDX-License-Identifier: GPL-2.0-or-later
//! AR9285 modal/RF board values from Linux ath9k/eeprom_4k.c. The
//! caller supplies normalized, checksum-verified EEPROM and inactive PHY.
use super::rmw;
use crate::ath9k::{
    identity::{BringUpError, RegisterIo},
    EEPROM_4K_BYTES,
};
fn field(
    io: &mut impl RegisterIo,
    reg: u64,
    mask: u32,
    shift: u32,
    value: u8,
) -> Result<(), BringUpError> {
    rmw(io, reg, mask, (u32::from(value) << shift) & mask)
}
fn readback(io: &mut impl RegisterIo, reg: u64) -> Result<(), BringUpError> {
    if io.read32(reg) == u32::MAX {
        Err(BringUpError::DeviceGone)
    } else {
        Ok(())
    }
}
fn analog(io: &mut impl RegisterIo, reg: u64, shift: u32, value: u8) -> Result<(), BringUpError> {
    field(io, reg, 7 << shift, shift, value)?;
    io.delay_us(100);
    Ok(())
}
pub(super) fn prepare(
    io: &mut impl RegisterIo,
    image: &[u8; EEPROM_4K_BYTES],
    ht40: bool,
    combining: bool,
) -> Result<(), BringUpError> {
    let m = &image[52..120];
    let minor = u16::from_le_bytes(image[4..6].try_into().unwrap()) & 0xfff;
    let chain = u32::from_le_bytes(m[..4].try_into().unwrap());
    let common = u32::from_le_bytes(m[4..8].try_into().unwrap());
    io.write32(0x9964, common);
    rmw(io, 0x9960, 0, chain)?;
    rmw(
        io,
        0x9920,
        0x7ff,
        (u32::from(m[22]) << 5) & 0x7e0 | u32::from(m[23]) & 31,
    )?;
    let atten = if minor >= 3 { m[10] } else { 23 };
    if minor >= 3 {
        for base in [0xa20c, 0xb20c] {
            for (mask, shift, value) in [
                (0x1f000, 12, m[32]),
                (0x3f, 0, m[31]),
                (0x3e0000, 17, m[35]),
                (0xfc0, 6, m[34]),
            ] {
                field(io, base, mask, shift, value)?;
            }
        }
    }
    for base in [0x9848, 0xa848] {
        field(io, base, 0x3f80, 7, atten)?;
        field(io, base, 0x1fc000, 14, m[11])?;
    }
    if m[37] >= 3 {
        let control1 = m[39] >> 4;
        let control2 = m[41] >> 4;
        let value = (u32::from(control1) << 24) & 0x01000000
            | (u32::from(control2) << 25) & 0x06000000
            | (u32::from(control2 >> 2) << 27) & 0x18000000
            | (u32::from(control1 >> 1) << 29) & 0x20000000
            | (u32::from(control1 >> 2) << 30) & 0x40000000;
        rmw(io, 0x99ac, 0x7f000000, value)?;
        readback(io, 0x99ac)?;
        field(io, 0xa208, 0x2000, 13, control1 >> 3)?;
        readback(io, 0xa208)?;
        if combining {
            rmw(io, 0x99ac, 0x1e000000 | 0x7e00, (2 << 27) | (1 << 25))?;
        }
    }
    let mut ob = [m[25] & 15, m[25] >> 4, m[38] & 15, m[38] >> 4, m[39] & 15];
    let mut db1 = [m[26] & 15, m[26] >> 4, m[40] & 15, m[40] >> 4, m[41] & 15];
    let mut db2 = [m[36] & 15, m[36] >> 4, m[42] & 15, m[42] >> 4, m[43] & 15];
    if m[37] == 1 {
        for i in 1..5 {
            ob[i] = ob[1];
            db1[i] = db1[1];
            db2[i] = db2[1];
        }
    } else if m[37] == 0 {
        let (first_ob, first_db) = (ob[0], db1[0]);
        ob.fill(first_ob);
        db1.fill(first_db);
        db2.fill(first_db);
    }
    for (i, shift) in [21, 18, 15, 12, 9].into_iter().enumerate() {
        analog(io, 0x7828, shift, ob[i])?;
    }
    for (i, shift) in [6, 3, 0].into_iter().enumerate() {
        analog(io, 0x7828, shift, db1[i])?;
    }
    for (i, shift) in [29, 26].into_iter().enumerate() {
        analog(io, 0x782c, shift, db1[i + 3])?;
    }
    for (i, shift) in [23, 20, 17, 14, 11].into_iter().enumerate() {
        analog(io, 0x782c, shift, db2[i])?;
    }
    field(io, 0x9844, 0x3f80, 7, m[9])?;
    field(io, 0x9850, 0xff, 0, m[12])?;
    rmw(
        io,
        0x9834,
        0,
        (u32::from(m[15]) << 24)
            | (u32::from(m[15]) << 16)
            | (u32::from(m[17]) << 8)
            | u32::from(m[17]),
    )?;
    field(io, 0x9828, 0xff0000, 16, m[16])?;
    field(io, 0x9864, 0xff000, 12, m[18])?;
    field(io, 0x99b8, 0xff, 0, m[18])?;
    if minor >= 2 {
        field(io, 0x9824, 0xff, 0, m[28])?;
        field(io, 0x9824, 0xff00, 8, m[29])?;
    }
    if minor >= 3 && ht40 {
        field(io, 0x9844, 0x3f80, 7, m[33])?;
    }
    let scale = u32::from(m[46] & 31);
    if image[31] == 0 && scale != 0 {
        let mask = (1 << 0) | (1 << 5) | (1 << 10) | (1 << 15) | (1 << 20) | (1 << 25);
        for reg in [0xa278, 0xa394, 0xa3dc] {
            rmw(io, reg, mask * 31, mask * scale)?;
        }
        let mask = (1 << 0) | (1 << 5) | (1 << 15);
        rmw(io, 0xa27c, mask * 31, mask * scale)?;
        let mask = (1 << 0) | (1 << 5);
        for reg in [0xa398, 0xa3e0] {
            rmw(io, reg, mask * 31, mask * scale)?;
        }
    }
    Ok(())
}
#[cfg(any(test, feature = "kernel-test"))]
mod tests;
