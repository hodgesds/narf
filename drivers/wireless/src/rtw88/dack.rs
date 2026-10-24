// SPDX-License-Identifier: GPL-2.0-or-later
//! One-shot fresh RTL8822C ADC/DAC DC calibration, Linux rtw8822c.c.
//! No cached vector restore/recovery is claimed. Failed sampling, hardware
//! writes or convergence are terminal rather than Linux's log-and-continue.
use super::{
    firmware_transport::{Error, Io},
    radio::{mask, read, rf, rf_read},
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Info {
    pub adc: [u32; 2],
    pub residual: [[u16; 2]; 2],
}
const BACKUP: [u16; 16] = [
    0x180c, 0x1810, 0x410c, 0x4110, 0x1c3c, 0x1c24, 0x1d70, 0x9b4, 0x1a00, 0x1a14, 0x1d58, 0x1c38,
    0x1e24, 0x1e28, 0x1860, 0x4160,
];
fn bases(path: u8) -> (u16, u16) {
    if path == 0 {
        (0x1800, 0x2800)
    } else {
        (0x4100, 0x4500)
    }
}
fn signed(v: u16) -> i16 {
    if v >= 512 {
        v as i16 - 1024
    } else {
        v as i16
    }
}
fn magnitude(v: u16) -> u16 {
    signed(v).unsigned_abs()
}
fn valid(v: u16) -> bool {
    magnitude(v) <= 100
}
fn measurement(io: &mut impl Io) -> Result<[u16; 2], Error> {
    let v = read(io, 0x2dbc)? & 0x3fffff;
    Ok([((v >> 12) & 0x3ff) as u16, (v & 0x3ff) as u16])
}
async fn sample(io: &mut impl Io) -> Result<[u16; 2], Error> {
    let mut data = [[0u16; 100]; 2];
    let mut count = 0;
    for attempt in 0..10000 {
        let v = measurement(io)?;
        let accepted = v.into_iter().all(valid);
        if accepted {
            data[0][count] = v[0];
            data[1][count] = v[1];
            count += 1;
        }
        if count == 100 {
            break;
        }
        if !accepted && attempt % 32 == 31 {
            io.delay_us(1).await;
        }
    }
    if count != 100 {
        return Err(Error::Prerequisite);
    }
    for attempt in 0..=100 {
        for values in &mut data {
            values.sort_unstable_by_key(|v| signed(*v));
        }
        if data.iter().all(|v| signed(v[99]) - signed(v[0]) <= 5) {
            return Ok(core::array::from_fn(|path| {
                // Source trims ten samples at either edge and rounds toward0.
                let sum: i32 = data[path][10..90]
                    .iter()
                    .map(|v| i32::from(signed(*v)))
                    .sum();
                ((sum / 80) as i16 as u16) & 0x3ff
            }));
        }
        if attempt == 100 {
            return Err(Error::Prerequisite);
        }
        for index in [0, 99] {
            let v = measurement(io)?;
            if !v.into_iter().all(valid) {
                return Err(Error::Prerequisite);
            }
            data[0][index] = v[0];
            data[1][index] = v[1];
        }
        io.delay_us(1).await;
    }
    Err(Error::Prerequisite)
}
async fn ready(io: &mut impl Io, reg: u16, bits: u32, wanted: u32) -> Result<(), Error> {
    for _ in 0..1000 {
        if (read(io, reg)? & bits) >> bits.trailing_zeros() == wanted {
            return Ok(());
        }
        io.delay_us(10).await;
    }
    Err(Error::Timeout)
}
async fn adc(io: &mut impl Io, path: u8) -> Result<(u32, [u16; 2]), Error> {
    let (base, _) = bases(path);
    let selection = if path == 0 { 0xa0000 } else { 0x80000 };
    mask(io, base + 0x30, 1 << 30, 0)?;
    if path == 1 {
        io.write32(base + 0x30, 0x30db8041)?;
    }
    for (off, v) in [
        (0x60, 0xf0040ff0),
        (0x0c, 0xdff00220),
        (0x10, 0x02dd08c4),
        (0x0c, 0x10000260),
    ] {
        io.write32(base + off, v)?;
    }
    for p in 0..2 {
        rf(io, p, 0, 0xfffff, 0x10000).await?;
    }
    for p in 0..2 {
        if rf_read(io, p, 0)? >> 16 != 1 {
            return Err(Error::Prerequisite);
        }
    }
    let mut compensation = [0; 2];
    let mut converged = false;
    let mut code = 0;
    for _ in 0..10 {
        io.write32(0x1c3c, selection + 0x8003)?;
        io.write32(0x1c24, 0x10002)?;
        let before = sample(io).await?;
        // Source preserves a previous nonzero compensation when a later
        // before sample happens to be zero, but writes the actual new pair.
        let next = before.map(|v| if v == 0 { 0 } else { 1024 - v });
        for i in 0..2 {
            if before[i] != 0 {
                compensation[i] = next[i];
            }
        }
        code = u32::from(next[0]) | u32::from(next[1]) << 10;
        io.write32(base + 0x68, code)?;
        io.write32(0x1c3c, selection + 0x8103)?;
        let after = sample(io).await?;
        if after.into_iter().all(|v| magnitude(v) < 5) {
            converged = true;
            break;
        }
    }
    if !converged {
        return Err(Error::Prerequisite);
    }
    io.write32(0x1c3c, 3)?;
    io.write32(base + 0x0c, 0x10000260)?;
    io.write32(base + 0x10, 0x02d508c4)?;
    rf(io, path, 0x8f, 1 << 13, 1).await?;
    Ok((code, compensation))
}
async fn step1(io: &mut impl Io, path: u8, adc: u32) -> Result<(), Error> {
    let (base, result) = bases(path);
    io.write32(base + 0x68, adc)?;
    io.write32(base + 0x0c, 0xdff00220)?;
    if path == 0 {
        io.write32(base + 0x60, 0xf0040ff0)?;
        io.write32(0x1c38, u32::MAX)?;
    }
    for (reg, v) in [
        (base + 0x10, 0x02d508c5),
        (0x9b4, 0xdb66db00),
        (base + 0xb0, 0x0a11fb88),
        (base + 0xbc, 0x0008ff81),
        (base + 0xc0, 0x0003d208),
        (base + 0xcc, 0x0a11fb88),
        (base + 0xd8, 0x0008ff81),
        (base + 0xdc, 0x0003d208),
        (base + 0xb8, 0x60000000),
    ] {
        io.write32(reg, v)?;
    }
    io.delay_us(2000).await;
    io.write32(base + 0xbc, 0x000aff8d)?;
    io.delay_us(2000).await;
    io.write32(base + 0xb0, 0x0a11fb89)?;
    io.write32(base + 0xcc, 0x0a11fb89)?;
    io.delay_us(1000).await;
    io.write32(base + 0xb8, 0x62000000)?;
    io.write32(base + 0xd4, 0x62000000)?;
    io.delay_us(20000).await;
    ready(io, result + 8, 0x7fff80, 0xffff).await?;
    ready(io, result + 0x34, 0x7fff80, 0xffff).await?;
    io.write32(base + 0xb8, 0x02000000)?;
    io.delay_us(1000).await;
    for (reg, v) in [
        (base + 0xbc, 0x0008ff87),
        (0x9b4, 0xdb6db600),
        (base + 0x10, 0x02d508c5),
        (base + 0xbc, 0x0008ff87),
        (base + 0x60, 0xf0000000),
    ] {
        io.write32(reg, v)?;
    }
    Ok(())
}
fn compensation(v: u16) -> Result<u32, Error> {
    let value = if v == 0 { 0 } else { 1024 - v };
    let result = if value < 0x300 {
        i32::from(value) * 12 / 5 + 0x80
    } else {
        0x7f - i32::from(1024 - value) * 12 / 5
    };
    if !(0..=255).contains(&result) {
        return Err(Error::Prerequisite);
    }
    Ok(result as u32)
}
async fn step2(io: &mut impl Io, path: u8) -> Result<[u32; 2], Error> {
    let (base, _) = bases(path);
    for (off, bits, v) in [
        (0xbc, 0xf0000000, 0),
        (0xc0, 15, 8),
        (0xd8, 0xf0000000, 0),
        (0xdc, 15, 8),
    ] {
        mask(io, base + off, bits, v)?;
    }
    io.write32(0x1b00, 8)?;
    io.write8(0x1bcc, 0x3f)?;
    io.write32(base + 0x0c, 0xdff00220)?;
    io.write32(base + 0x10, 0x02d508c5)?;
    io.write32(0x1c3c, 0x88103)?;
    let v = sample(io).await?;
    Ok([compensation(v[0])?, compensation(v[1])?])
}
async fn step3(
    io: &mut impl Io,
    path: u8,
    adc: [u16; 2],
    offset: [u32; 2],
) -> Result<[u16; 2], Error> {
    let (base, result) = bases(path);
    let [ic, qc] = offset;
    for (reg, v) in [
        (base + 0x0c, 0xdff00220),
        (base + 0x10, 0x02d508c5),
        (0x9b4, 0xdb66db00),
        (base + 0xb0, 0x0a11fb88),
        (base + 0xbc, 0xc008ff81),
        (base + 0xc0, 0x0003d208),
    ] {
        io.write32(reg, v)?;
    }
    mask(io, base + 0xbc, 0xf0000000, ic & 15)?;
    mask(io, base + 0xc0, 15, (ic >> 4) & 15)?;
    io.write32(base + 0xcc, 0x0a11fb88)?;
    io.write32(base + 0xd8, 0xe008ff81)?;
    io.write32(base + 0xdc, 0x0003d208)?;
    mask(io, base + 0xd8, 0xf0000000, qc & 15)?;
    mask(io, base + 0xdc, 15, (qc >> 4) & 15)?;
    io.write32(base + 0xb8, 0x60000000)?;
    io.delay_us(2000).await;
    mask(io, base + 0xbc, 14, 6)?;
    io.delay_us(2000).await;
    io.write32(base + 0xb0, 0x0a11fb89)?;
    io.write32(base + 0xcc, 0x0a11fb89)?;
    io.delay_us(1000).await;
    io.write32(base + 0xb8, 0x62000000)?;
    io.write32(base + 0xd4, 0x62000000)?;
    io.delay_us(20000).await;
    ready(io, result + 0x24, 0x07f80000, ic).await?;
    ready(io, result + 0x50, 0x07f80000, qc).await?;
    io.write32(base + 0xb8, 0x02000000)?;
    io.delay_us(1000).await;
    mask(io, base + 0xbc, 14, 3)?;
    io.write32(0x9b4, 0xdb6db600)?;
    io.write32(
        base + 0x68,
        u32::from((adc[0] + 16) & 0x3ff) | u32::from((adc[1] + 16) & 0x3ff) << 10,
    )?;
    io.write32(base + 0x10, 0x02d508c5)?;
    io.write32(base + 0x60, 0xf0000000)?;
    Ok(sample(io).await?.map(|v| v.wrapping_sub(16) & 0x3ff))
}
pub(super) async fn calibrate(io: &mut impl Io) -> Result<Info, Error> {
    let mut backup = [0; 16];
    for (slot, reg) in backup.iter_mut().zip(BACKUP) {
        *slot = read(io, reg)?;
    }
    // Linux path*i+i aliases RF0x8f when DACK_RF==1. Retain both originals
    // independently; path-B's value must never overwrite path-A's backup.
    let rf_backup = [rf_read(io, 0, 0x8f)?, rf_read(io, 1, 0x8f)?];
    for (reg, bits, v) in [(0x1d58, 0xff8, 0x1ff), (0x1a00, 3, 2), (0x1a14, 0x300, 3)] {
        mask(io, reg, bits, v)?;
    }
    io.write32(0x1d70, 0x7e7e7e7e)?;
    mask(io, 0x180c, 3, 0)?;
    mask(io, 0x410c, 3, 0)?;
    io.write32(0x1b00, 8)?;
    io.write8(0x1bcc, 0x3f)?;
    io.write32(0x1b00, 10)?;
    io.write8(0x1bcc, 0x3f)?;
    mask(io, 0x1e24, 1 << 31, 0)?;
    mask(io, 0x1e28, 15, 3)?;
    let mut info = Info {
        adc: [0; 2],
        residual: [[0; 2]; 2],
    };
    for path in 0..2 {
        let (code, correction) = adc(io, path).await?;
        info.adc[usize::from(path)] = code;
        let mut converged = false;
        for _ in 0..10 {
            step1(io, path, code).await?;
            let offset = step2(io, path).await?;
            let residual = step3(io, path, correction, offset).await?;
            info.residual[usize::from(path)] = residual;
            if residual.into_iter().all(|v| magnitude(v) < 5) {
                converged = true;
                break;
            }
        }
        if !converged {
            return Err(Error::Prerequisite);
        }
        let (base, _) = bases(path);
        io.write32(base + 0x68, 0)?;
        io.write32(base + 0x10, 0x02d508c4)?;
        mask(io, base + 0xbc, 1, 0)?;
        mask(io, base + 0x30, 1 << 30, 1)?;
    }
    io.write32(0x1b00, 8)?;
    mask(io, 0x4130, 1 << 30, 1)?;
    io.write8(0x1bcc, 0)?;
    io.write32(0x1b00, 10)?;
    io.write8(0x1bcc, 0)?;
    for (reg, v) in BACKUP.into_iter().zip(backup) {
        io.write32(reg, v)?;
    }
    for path in 0..2 {
        rf(io, path, 0x8f, 0xfffff, rf_backup[usize::from(path)]).await?;
    }
    // One-shot owner deliberately omits Linux's later-reset vector cache.
    Ok(info)
}
