// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2009-2013 Realtek Corporation.
//! RTL8188EE-only MAC/BB/RF and 1T IQK/LCK continuation. Ported from Linux
//! rtl8188ee/{phy,rf,hw,table}.c. Packet DMA and interrupts stay parked.
use super::firmware_transport::{Error as AccessError, Io};

#[path = "radio/tables.rs"]
mod tables;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Access(AccessError),
    Profile,
    Gate,
    Calibration,
}
impl From<AccessError> for Error {
    fn from(error: AccessError) -> Self {
        Self::Access(error)
    }
}

/// Factory-qualified single-path EE board. Constructed from the retained
/// sparse EFUSE map, never from the shared firmware signature alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Profile {
    hp: bool,
}
impl Profile {
    pub fn from_factory(factory: &super::efuse::Factory) -> Result<Self, Error> {
        let map = &factory.logical;
        let word = |at| u16::from_le_bytes([map[at], map[at + 1]]);
        if word(0) != 0x8129 || word(0xd6) != 0x10ec || word(0xd8) != 0x8179 {
            return Err(Error::Profile);
        }
        Ok(Self {
            hp: matches!(map[0xc5], 0 | 255) && word(0xda) == 0x103c && word(0xdc) == 0x197d,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub iqk: [u16; 4],
    pub recovery: [u32; 9],
    pub channel_rf: u32,
    pub cck_high_power: bool,
}
/// Read-only per-rate PG offsets are kept for the later EFUSE/channel power
/// owner; these are NOT hardware-register writes and grant no TX authority.
pub fn power_groups() -> &'static [[u32; 3]] {
    tables::POWER_GROUPS
}

const ADDA: [u16; 16] = [
    0x85c, 0xe6c, 0xe70, 0xe74, 0xe78, 0xe7c, 0xe80, 0xe84, 0xe88, 0xe8c, 0xed0, 0xed4, 0xed8,
    0xedc, 0xee0, 0xeec,
];
const BB_BACKUP: [u16; 9] = [
    0xc04, 0xc08, 0x874, 0xb68, 0xb6c, 0x870, 0x860, 0x864, 0x800,
];
const RECOVERY: [u16; 9] = [
    0xc14, 0xc1c, 0xc4c, 0xc78, 0xc80, 0xc88, 0xc94, 0xc9c, 0xca0,
];

fn read(io: &impl Io, reg: u16) -> Result<u32, Error> {
    let value = io.read32(reg)?;
    if value == u32::MAX {
        Err(Error::Access(AccessError::Gone))
    } else {
        Ok(value)
    }
}
async fn bb(io: &impl Io, reg: u16, mask: u32, value: u32) -> Result<(), Error> {
    if mask == 0 {
        return Err(Error::Profile);
    }
    let value = if mask == u32::MAX {
        value
    } else {
        (read(io, reg)? & !mask) | (value << mask.trailing_zeros())
    };
    io.write32(reg, value)?;
    Ok(())
}
async fn rf_write(io: &impl Io, reg: u8, value: u32) -> Result<(), Error> {
    // Eight address bits, twenty data bits. The older unused scaffold's
    // four-bit-address/twelve-bit-value encoding is not this device's LSSI.
    io.write32(0x840, (u32::from(reg) << 20) | (value & 0xfffff))?;
    Ok(())
}
async fn rf_read(io: &impl Io, reg: u8) -> Result<u32, Error> {
    let original = read(io, 0x824)?;
    let request = (original & !0x7f800000) | (u32::from(reg) << 23) | (1 << 31);
    io.write32(0x824, original & !(1 << 31))?;
    io.delay_us(10).await;
    io.write32(0x824, request)?;
    io.delay_us(120).await;
    Ok(read(
        io,
        if read(io, 0x820)? & (1 << 8) != 0 {
            0x8b8
        } else {
            0x8a0
        },
    )? & 0xfffff)
}
async fn rf_mask(io: &impl Io, reg: u8, mask: u32, value: u32) -> Result<(), Error> {
    let original = rf_read(io, reg).await?;
    rf_write(
        io,
        reg,
        (original & !mask) | (value << mask.trailing_zeros()),
    )
    .await
}
async fn writes(io: &impl Io, rows: &[[u32; 2]]) -> Result<(), Error> {
    for &[reg, value] in rows {
        io.write32(reg as u16, value)?;
    }
    Ok(())
}
pub(super) fn parked(io: &impl Io) -> Result<(), Error> {
    if io.read8(0x301)? != 0xff
        || io.read8(0x100)? & 0xcf != 0
        || read(io, 0xb0)? != 0
        || read(io, 0xb8)? != 0
    {
        return Err(Error::Gate);
    }
    Ok(())
}

pub(super) async fn configure(io: &impl Io, profile: Profile) -> Result<Report, Error> {
    parked(io)?;
    for &[reg, value] in tables::MAC {
        io.write8(reg as u16, value as u8)?;
    }
    io.write8(0x4ca, 0x0b)?;
    let rcr = read(io, 0x608)?;
    io.write32(0x608, rcr & !0x300)?; // reject CRC/ICV errors, Linux hw_init
    let low = io.read8(2)?;
    let high = io.read8(3)?;
    io.write8(2, low | 3)?;
    io.write8(3, high | 0x20)?;
    io.write8(0x1f, 7)?;
    io.write8(2, 0x27)?;
    let value = read(io, 0x4c)?;
    io.write32(0x4c, value | (1 << 23))?;
    for table in [tables::BB, tables::AGC] {
        for &[reg, value] in table {
            io.write32(reg as u16, value)?;
            io.delay_us(1).await;
        }
    }
    let cck_high_power = read(io, 0x824)? & 0x200 != 0;
    bb(io, 0x800, 1 << 24, 1).await?;
    bb(io, 0x800, 1 << 25, 1).await?;
    let environment = (read(io, 0x870)? >> 4) & 1;
    bb(io, 0x860, 1 << 20, 1).await?;
    io.delay_us(1).await;
    bb(io, 0x860, 1 << 4, 1).await?;
    io.delay_us(1).await;
    for mask in [0x400, 0x800] {
        bb(io, 0x824, mask, 0).await?;
        io.delay_us(1).await;
    }
    for &[reg, value] in tables::RF {
        match reg {
            0xffe => io.delay_us(50_000).await,
            0xfd => io.delay_us(5_000).await,
            0xfc => io.delay_us(1_000).await,
            0xfb => io.delay_us(50).await,
            0xfa => io.delay_us(5).await,
            0xf9 => io.delay_us(1).await,
            0..=255 => {
                rf_write(io, reg as u8, value).await?;
                io.delay_us(1).await;
            }
            _ => return Err(Error::Profile),
        }
    }
    if profile.hp {
        rf_write(io, 0x52, 0x7e4bd).await?;
        io.delay_us(1).await;
    }
    bb(io, 0x870, 1 << 4, environment).await?;
    let channel_rf = rf_read(io, 0x18).await? & 0xfff00fff;
    let (iqk, recovery) = calibrate(io).await?;
    lck(io).await?;
    parked(io)?;
    Ok(Report {
        iqk,
        recovery,
        channel_rf,
        cck_high_power,
    })
}

async fn trigger(io: &impl Io) -> Result<(), Error> {
    io.write32(0xe48, 0xf9000000)?;
    io.write32(0xe48, 0xf8000000)?;
    io.delay_us(10_000).await;
    Ok(())
}
async fn tx_iqk(io: &impl Io) -> Result<bool, Error> {
    writes(
        io,
        &[
            [0xe30, 0x10008c1c],
            [0xe34, 0x30008c1c],
            [0xe38, 0x8214032a],
            [0xe3c, 0x28160000],
            [0xe4c, 0x00462911],
        ],
    )
    .await?;
    trigger(io).await?;
    let status = read(io, 0xeac)?;
    let before = read(io, 0xe94)?;
    let after = read(io, 0xe9c)?;
    let _ = read(io, 0xea4)?;
    Ok(status & (1 << 28) == 0 && (before >> 16) & 1023 != 0x142 && (after >> 16) & 1023 != 0x42)
}
async fn rx_iqk(io: &impl Io) -> Result<bool, Error> {
    for second in [false, true] {
        io.write32(0xe28, 0)?;
        for (reg, value) in [
            (0xef, 0x800a0),
            (0x30, 0x30000),
            (0x31, 0x0000f),
            (0x32, if second { 0xf7ffa } else { 0xf117b }),
        ] {
            rf_write(io, reg, value).await?;
        }
        io.write32(0xe28, 0x80800000)?;
        if second {
            writes(
                io,
                &[
                    [0xe44, 0x01004800],
                    [0xe30, 0x30008c1c],
                    [0xe34, 0x10008c1c],
                    [0xe38, 0x82160c05],
                    [0xe3c, 0x28160c05],
                ],
            )
            .await?;
        } else {
            writes(
                io,
                &[
                    [0xe40, 0x01007c00],
                    [0xe44, 0x81004800],
                    [0xe30, 0x10008c1c],
                    [0xe34, 0x30008c1c],
                    [0xe38, 0x82160804],
                    [0xe3c, 0x28160000],
                ],
            )
            .await?;
        }
        io.write32(0xe4c, 0x0046a911)?;
        trigger(io).await?;
        let status = read(io, 0xeac)?;
        let before = read(io, 0xe94)?;
        let after = read(io, 0xe9c)?;
        if !second {
            if status & (1 << 28) != 0
                || (before >> 16) & 1023 == 0x142
                || (after >> 16) & 1023 == 0x42
            {
                return Ok(false);
            }
            io.write32(
                0xe40,
                0x80007c00 | (before & 0x3ff0000) | ((after & 0x3ff0000) >> 16),
            )?;
        } else {
            let rx = read(io, 0xea4)?;
            return Ok(status & (1 << 27) == 0
                && (rx >> 16) & 1023 != 0x132
                && (status >> 16) & 1023 != 0x36);
        }
    }
    Ok(false)
}

struct Backup {
    adda: [u32; 16],
    mac: [u32; 4],
    bb: [u32; 9],
    pi: bool,
}
fn backup(io: &impl Io) -> Result<Backup, Error> {
    let mut result = Backup {
        adda: [0; 16],
        mac: [0; 4],
        bb: [0; 9],
        pi: read(io, 0x820)? & 0x100 != 0,
    };
    for (reg, value) in ADDA.iter().zip(&mut result.adda) {
        *value = read(io, *reg)?;
    }
    for (reg, value) in [0x522, 0x550, 0x551].iter().zip(&mut result.mac[..3]) {
        *value = u32::from(io.read8(*reg)?);
    }
    result.mac[3] = read(io, 0x40)?;
    for (reg, value) in BB_BACKUP.iter().zip(&mut result.bb) {
        *value = read(io, *reg)?;
    }
    Ok(result)
}
async fn pass(io: &impl Io, saved: &Backup, attempt: usize) -> Result<[u16; 4], Error> {
    for (index, reg) in ADDA.iter().enumerate() {
        io.write32(*reg, if index == 0 { 0x0b1b25a0 } else { 0x0bdb25a0 })?;
    }
    if !saved.pi {
        io.write32(0x820, 0x01000100)?;
        io.write32(0x828, 0x01000100)?;
    }
    bb(io, 0x800, 1 << 24, 0).await?;
    writes(
        io,
        &[
            [0xc04, 0x03a05600],
            [0xc08, 0x000800e4],
            [0x874, 0x22204000],
        ],
    )
    .await?;
    bb(io, 0x870, 1 << 10, 1).await?;
    bb(io, 0x870, 1 << 26, 1).await?;
    bb(io, 0x860, 1 << 10, 0).await?;
    bb(io, 0x864, 1 << 10, 0).await?;
    io.write8(0x522, 0x3f)?;
    io.write8(0x550, saved.mac[1] as u8 & !8)?;
    io.write8(0x551, saved.mac[2] as u8 & !8)?;
    io.write8(0x40, saved.mac[3] as u8 & !32)?;
    writes(
        io,
        &[
            [0xb68, 0x0f600000],
            [0xe28, 0x80800000],
            [0xe40, 0x01007c00],
            [0xe44, 0x81004800],
        ],
    )
    .await?;
    let mut result = [0; 4];
    for _ in 0..2 {
        if tx_iqk(io).await? {
            result[0] = ((read(io, 0xe94)? >> 16) & 1023) as u16;
            result[1] = ((read(io, 0xe9c)? >> 16) & 1023) as u16;
            break;
        }
    }
    for _ in 0..2 {
        if rx_iqk(io).await? {
            result[2] = ((read(io, 0xea4)? >> 16) & 1023) as u16;
            result[3] = ((read(io, 0xeac)? >> 16) & 1023) as u16;
            break;
        }
    }
    io.write32(0xe28, 0)?;
    if attempt != 0 {
        if !saved.pi {
            io.write32(0x820, 0x01000000)?;
            io.write32(0x828, 0x01000000)?;
        }
        for (reg, value) in ADDA.iter().zip(saved.adda) {
            io.write32(*reg, value)?;
        }
        for (reg, value) in [0x522, 0x550, 0x551].iter().zip(saved.mac) {
            io.write8(*reg, value as u8)?;
        }
        io.write32(0x40, saved.mac[3])?;
        for (reg, value) in BB_BACKUP.iter().zip(saved.bb) {
            io.write32(*reg, value)?;
        }
        writes(
            io,
            &[
                [0x840, 0x00032ed3],
                [0xe30, 0x01008c00],
                [0xe34, 0x01008c00],
            ],
        )
        .await?;
    }
    Ok(result)
}
fn similar(samples: &mut [[u16; 4]; 4], a: usize, b: usize) -> bool {
    let mut bitmap = 0u8;
    let mut candidate = None;
    for i in 0..4 {
        if samples[a][i].abs_diff(samples[b][i]) > 5 {
            if i == 2 && bitmap == 0 {
                if u32::from(samples[a][2]) + u32::from(samples[a][3]) == 0 {
                    candidate = Some(b);
                } else if u32::from(samples[b][2]) + u32::from(samples[b][3]) == 0 {
                    candidate = Some(a);
                } else {
                    bitmap |= 1 << i;
                }
            } else {
                bitmap |= 1 << i;
            }
        }
    }
    if bitmap == 0 {
        if let Some(candidate) = candidate {
            let tx = [samples[candidate][0], samples[candidate][1]];
            samples[3][..2].copy_from_slice(&tx);
            false
        } else {
            true
        }
    } else {
        false
    }
}
async fn calibrate(io: &impl Io) -> Result<([u16; 4], [u32; 9]), Error> {
    let saved = backup(io)?;
    let mut samples = [[0; 4]; 4];
    let mut selected = None;
    for i in 0..3 {
        samples[i] = pass(io, &saved, i).await?;
        if i == 1 && similar(&mut samples, 0, 1) {
            selected = Some(0);
            break;
        }
        if i == 2 {
            selected = if similar(&mut samples, 0, 2) {
                Some(0)
            } else if similar(&mut samples, 1, 2) {
                Some(1)
            } else if samples[3].iter().any(|value| *value != 0) {
                Some(3)
            } else {
                None
            };
        }
    }
    let result = samples[selected.ok_or(Error::Calibration)?];
    // Linux may use TX-only/default fallback; native station admission stays
    // closed unless this first-boot profile has measured both TX and RX.
    if result[0] == 0 || result[2] == 0 {
        return Err(Error::Calibration);
    }
    matrix(io, result).await?;
    let mut recovery = [0; 9];
    for (reg, value) in RECOVERY.iter().zip(&mut recovery) {
        *value = read(io, *reg)?;
    }
    Ok((result, recovery))
}
async fn matrix(io: &impl Io, values: [u16; 4]) -> Result<(), Error> {
    let old = (read(io, 0xc80)? >> 22) & 1023;
    let sign = |value: u16| {
        if value & 0x200 != 0 {
            i32::from(value) - 1024
        } else {
            i32::from(value)
        }
    };
    let x = (sign(values[0]) as u32).wrapping_mul(old);
    let y = sign(values[1]) * old as i32;
    bb(io, 0xc80, 0x3ff, x >> 8).await?;
    bb(io, 0xc4c, 1 << 31, (x >> 7) & 1).await?;
    bb(io, 0xc94, 0xf0000000, ((y >> 8) as u32 & 0x3c0) >> 6).await?;
    bb(io, 0xc80, 0x003f0000, (y >> 8) as u32 & 0x3f).await?;
    bb(io, 0xc4c, 1 << 29, ((y >> 7) & 1) as u32).await?;
    bb(io, 0xc14, 0x3ff, u32::from(values[2])).await?;
    bb(io, 0xc14, 0xfc00, u32::from(values[3] & 0x3f)).await?;
    bb(io, 0xca0, 0xf0000000, u32::from(values[3] >> 6) & 15).await
}
async fn lck(io: &impl Io) -> Result<(), Error> {
    let mode = io.read8(0xd03)?;
    let continuous = mode & 0x70 != 0;
    let old = if continuous {
        io.write8(0xd03, mode & 0x8f)?;
        let old = rf_read(io, 0).await? & 0xfff;
        rf_mask(io, 0, 0xfff, (old & 0x8ffff) | 0x10000).await?;
        old
    } else {
        io.write8(0x522, 255)?;
        0
    };
    let channel = rf_read(io, 0x18).await? & 0xfff;
    rf_mask(io, 0x18, 0xfff, channel | 0x8000).await?;
    io.delay_us(100_000).await;
    if continuous {
        io.write8(0xd03, mode)?;
        rf_mask(io, 0, 0xfff, old).await?;
    } else {
        io.write8(0x522, 0)?;
    }
    Ok(())
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "radio_tests.rs"]
mod tests;
