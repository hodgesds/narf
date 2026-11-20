// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 2009-2012 Realtek Corporation.
//! RTL8723AE 1T1R IQK source program and recovery image.
//!
//! `rtl8723ae/phy.c::rtl8723e_phy_iq_calibrate` always passes is2t=false.
//! The ADDA/PI/MAC and matrix operations are the RTL8723AE branches of
//! `rtl8723com/phy_common.c`, including the unbraced result[t][1] update.
//! This preparation owner grants no emission or station permission and
//! is not called by firmware-only startup. A future native radio caller
//! must establish the required factory/calibration authority first.
use super::phy::{get_bb, set_bb, MASKDWORD};
use crate::rtlwifi::{firmware_transport::Io, prepare::Error};

pub const ADDA_REGS: [u16; 16] = [
    0x85c, 0xe6c, 0xe70, 0xe74, 0xe78, 0xe7c, 0xe80, 0xe84, 0xe88, 0xe8c, 0xed0, 0xed4, 0xed8,
    0xedc, 0xee0, 0xeec,
];
pub const MAC_REGS: [u16; 4] = [0x522, 0x550, 0x551, 0x040];
pub const BB_REGS: [u16; 10] = [
    0xc14, 0xc1c, 0xc4c, 0xc78, 0xc80, 0xc88, 0xc90, 0xc94, 0xc9c, 0xca0,
];
const TOLERANCE: u32 = 5;

#[derive(Clone, Copy, Debug, Default)]
struct Backup {
    adda: [u32; 16],
    mac: [u32; 4],
    c04: u32,
    c08: u32,
    r874: u32,
    rfpi: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    pub result: [[i64; 8]; 4],
    /// 0xff means no selected candidate; completion alone admits no radio.
    pub candidate: u8,
    pub e94: i64,
    pub e9c: i64,
    pub eb4: i64,
    pub ebc: i64,
    pub bb_backup: [u32; 10],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    New,
    Complete,
    Failed,
}

#[derive(Debug)]
pub struct Owner {
    phase: Phase,
    report: Option<Report>,
}
impl Default for Owner {
    fn default() -> Self {
        Self::new()
    }
}
impl Owner {
    pub const fn new() -> Self {
        Self {
            phase: Phase::New,
            report: None,
        }
    }
    pub const fn phase(&self) -> Phase {
        self.phase
    }
    pub fn report(&self) -> Option<&Report> {
        self.report.as_ref()
    }
    pub async fn run(&mut self, io: &impl Io) -> Result<(), Error> {
        if self.phase != Phase::New {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        self.report = Some(calibrate(io).await?);
        self.phase = Phase::Complete;
        Ok(())
    }
    /// b_recovery=true: restore exactly the ten saved BB registers.
    pub fn recover(&mut self, io: &impl Io) -> Result<(), Error> {
        if self.phase != Phase::Complete {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        let report = self.report.as_ref().ok_or(Error::State)?;
        for (reg, value) in BB_REGS.into_iter().zip(report.bb_backup) {
            set_bb(io, reg, MASKDWORD, value)?;
        }
        self.phase = Phase::Complete;
        Ok(())
    }
}

fn field(io: &impl Io, reg: u16) -> Result<i64, Error> {
    Ok(i64::from((get_bb(io, reg, MASKDWORD)? & 0x03ff_0000) >> 16))
}

async fn path_a(io: &impl Io) -> Result<u8, Error> {
    for (reg, value) in [
        (0xe30, 0x1000_8c1f),
        (0xe34, 0x1000_8c1f),
        (0xe38, 0x8214_0102),
        (0xe3c, 0x2816_0502),
        (0xe4c, 0x0010_28d1),
        (0xe48, 0xf900_0000),
        (0xe48, 0xf800_0000),
    ] {
        set_bb(io, reg, MASKDWORD, value)?;
    }
    io.delay_us(1_000).await;
    let eac = get_bb(io, 0xeac, MASKDWORD)?;
    let e94 = get_bb(io, 0xe94, MASKDWORD)?;
    let e9c = get_bb(io, 0xe9c, MASKDWORD)?;
    let ea4 = get_bb(io, 0xea4, MASKDWORD)?;
    let f = |v: u32| (v & 0x03ff_0000) >> 16;
    if eac & (1 << 28) != 0 || f(e94) == 0x142 || f(e9c) == 0x42 {
        return Ok(0);
    }
    Ok(
        if eac & (1 << 27) == 0 && f(ea4) != 0x132 && f(eac) != 0x36 {
            3
        } else {
            1
        },
    )
}

fn pi_mode(io: &impl Io, on: bool) -> Result<(), Error> {
    let value = if on { 0x0100_0100 } else { 0x0100_0000 };
    set_bb(io, 0x820, MASKDWORD, value)?;
    set_bb(io, 0x828, MASKDWORD, value)
}

async fn trial(
    io: &impl Io,
    result: &mut [[i64; 8]; 4],
    t: usize,
    backup: &mut Backup,
) -> Result<(), Error> {
    if t == 0 {
        get_bb(io, 0x800, MASKDWORD)?;
        for (b, r) in backup.adda.iter_mut().zip(ADDA_REGS) {
            *b = get_bb(io, r, MASKDWORD)?;
        }
        for (i, (b, r)) in backup.mac.iter_mut().zip(MAC_REGS).enumerate() {
            *b = if i < 3 {
                u32::from(io.read8(r)?)
            } else {
                io.read32(r)?
            };
        }
    }
    set_bb(io, ADDA_REGS[0], MASKDWORD, 0x0b1b_25a0)?;
    for reg in &ADDA_REGS[1..] {
        set_bb(io, *reg, MASKDWORD, 0x0bdb_25a0)?;
    }
    if t == 0 {
        backup.rfpi = get_bb(io, 0x820, 1 << 8)? != 0;
    }
    if !backup.rfpi {
        pi_mode(io, true)?;
    }
    if t == 0 {
        backup.c04 = get_bb(io, 0xc04, MASKDWORD)?;
        backup.c08 = get_bb(io, 0xc08, MASKDWORD)?;
        backup.r874 = get_bb(io, 0x874, MASKDWORD)?;
    }
    set_bb(io, 0xc04, MASKDWORD, 0x03a0_5600)?;
    set_bb(io, 0xc08, MASKDWORD, 0x0008_00e4)?;
    set_bb(io, 0x874, MASKDWORD, 0x2220_4000)?;
    io.write8(0x522, 0x3f)?;
    io.write8(0x550, (backup.mac[1] & !8) as u8)?;
    io.write8(0x551, (backup.mac[2] & !8) as u8)?;
    io.write8(0x040, (backup.mac[3] & !0x20) as u8)?;
    set_bb(io, 0xb68, MASKDWORD, 0x0008_0000)?;
    set_bb(io, 0xe28, MASKDWORD, 0x8080_0000)?;
    set_bb(io, 0xe40, MASKDWORD, 0x0100_7c00)?;
    set_bb(io, 0xe44, MASKDWORD, 0x0100_4800)?;
    for attempt in 0..2 {
        let ok = path_a(io).await?;
        if ok == 3 {
            result[t][0] = field(io, 0xe94)?;
            result[t][1] = field(io, 0xe9c)?;
            result[t][2] = field(io, 0xea4)?;
            result[t][3] = field(io, 0xeac)?;
            break;
        } else if attempt == 1 && ok == 1 {
            result[t][0] = field(io, 0xe94)?;
        }
        // Outside the source's unbraced else-if, including a failed TX.
        result[t][1] = field(io, 0xe9c)?;
    }
    set_bb(io, 0xc04, MASKDWORD, backup.c04)?;
    set_bb(io, 0x874, MASKDWORD, backup.r874)?;
    set_bb(io, 0xc08, MASKDWORD, backup.c08)?;
    set_bb(io, 0xe28, MASKDWORD, 0)?;
    set_bb(io, 0x840, MASKDWORD, 0x0003_2ed3)?;
    if t != 0 {
        if !backup.rfpi {
            pi_mode(io, false)?;
        }
        for (r, v) in ADDA_REGS.into_iter().zip(backup.adda) {
            set_bb(io, r, MASKDWORD, v)?;
        }
        for (r, v) in MAC_REGS[..3].iter().zip(&backup.mac[..3]) {
            io.write8(*r, *v as u8)?;
        }
        io.write32(0x040, backup.mac[3])?;
    }
    Ok(())
}

/// The AE comparison has bound=4 even though the matrix has eight slots.
pub(super) fn simularity_compare(result: &mut [[i64; 8]; 4], c1: usize, c2: usize) -> bool {
    if c1 >= 4 || c2 >= 4 {
        return false;
    }
    let mut candidate = 0xff;
    let mut bitmap = 0;
    for i in 0..4 {
        if result[c1][i].abs_diff(result[c2][i]) as u32 > TOLERANCE {
            if i == 2 && bitmap == 0 {
                if result[c1][i] + result[c1][i + 1] == 0 {
                    candidate = c2 as u8;
                } else if result[c2][i] + result[c2][i + 1] == 0 {
                    candidate = c1 as u8;
                } else {
                    bitmap |= 1 << i;
                }
            } else {
                bitmap |= 1 << i;
            }
        }
    }
    if bitmap == 0 {
        if candidate != 0xff {
            let picked = result[usize::from(candidate)];
            result[3][..2].copy_from_slice(&picked[..2]);
            return false;
        }
        true
    } else if bitmap & 0xf == 0 {
        let picked = result[c1];
        result[3][..4].copy_from_slice(&picked[..4]);
        false
    } else {
        false
    }
}

fn fill(io: &impl Io, r: &[i64; 8], tx_only: bool) -> Result<(), Error> {
    let oldval = (get_bb(io, 0xc80, MASKDWORD)? >> 22) & 0x3ff;
    let mut x = r[0] as u32;
    if x & 0x200 != 0 {
        x |= 0xffff_fc00;
    }
    set_bb(io, 0xc80, 0x3ff, x.wrapping_mul(oldval) >> 8)?;
    set_bb(io, 0xc4c, 1 << 31, (x.wrapping_mul(oldval) >> 7) & 1)?;
    let mut y = r[1];
    if y & 0x200 != 0 {
        y |= 0xffff_fc00;
    }
    let c = y.wrapping_mul(i64::from(oldval)) >> 8;
    set_bb(io, 0xc94, 0xf000_0000, ((c & 0x3c0) >> 6) as u32)?;
    set_bb(io, 0xc80, 0x003f_0000, (c & 0x3f) as u32)?;
    set_bb(
        io,
        0xc4c,
        1 << 29,
        ((y.wrapping_mul(i64::from(oldval)) >> 7) & 1) as u32,
    )?;
    if !tx_only {
        set_bb(io, 0xc14, 0x3ff, r[2] as u32)?;
        set_bb(io, 0xc14, 0xfc00, (r[3] & 0x3f) as u32)?;
        set_bb(io, 0xca0, 0xf000_0000, ((r[3] >> 6) & 0xf) as u32)?;
    }
    Ok(())
}

async fn calibrate(io: &impl Io) -> Result<Report, Error> {
    let mut result = [[0i64; 8]; 4];
    let mut backup = Backup::default();
    let mut candidate = 0xff;
    for t in 0..3 {
        trial(io, &mut result, t, &mut backup).await?;
        if t == 1 && simularity_compare(&mut result, 0, 1) {
            candidate = 0;
            break;
        }
        if t == 2 {
            if simularity_compare(&mut result, 0, 2) {
                candidate = 0;
                break;
            }
            if simularity_compare(&mut result, 1, 2) {
                candidate = 1;
            } else {
                candidate = if result[3].iter().sum::<i64>() != 0 {
                    3
                } else {
                    0xff
                };
            }
        }
    }
    let picked = result[usize::from(candidate.min(3))];
    let (e94, e9c, eb4, ebc) = if candidate == 0xff {
        (0x100, 0, 0x100, 0)
    } else {
        (picked[0], picked[1], picked[4], picked[5])
    };
    if candidate != 0xff && picked[0] != 0 {
        fill(io, &picked, picked[2] == 0)?;
    }
    let mut bb_backup = [0; 10];
    for (saved, reg) in bb_backup.iter_mut().zip(BB_REGS) {
        *saved = get_bb(io, reg, MASKDWORD)?;
    }
    Ok(Report {
        result,
        candidate,
        e94,
        e9c,
        eb4,
        ebc,
        bb_backup,
    })
}
