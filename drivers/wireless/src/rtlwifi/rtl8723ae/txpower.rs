// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 2009-2012 Realtek Corporation.
//! RTL8723AE factory/RF6052 TX-power source math and register plans.
//!
//! `hw.c::_rtl8723e_read_txpower_info_from_hwpg` (qualified, provisioned
//! maps only), `phy.c::_rtl8723e_get_txpower_index` and `rf.c` CCK/OFDM
//! writers. These preparation APIs mint no signed grant and have no native
//! station caller. A source register plan is not emission authority.
//! Unlike 92C, AE uses its PG origoffset table and decodes only path A's
//! CCK/HT40 base areas. Observed 0xff fields are not replaced by guessed
//! defaults. Auxiliary path-B register effects are preserved, although AE
//! has only one RF transmit chain.
use super::{
    adapter::Adapter,
    phy::{set_bb, PgStore, MASKDWORD},
};
use crate::rtlwifi::{firmware_transport::Io, prepare::Error};

const MAX_TX_PWR: u8 = 0x3f;
const REG_A: [u16; 6] = [0xe00, 0xe04, 0xe10, 0xe14, 0xe18, 0xe1c];
const REG_B: [u16; 6] = [0x830, 0x834, 0x83c, 0x848, 0x84c, 0x868];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Efuse {
    pub cck: [[u8; 14]; 2],
    pub ht40_1s: [[u8; 14]; 2],
    pub ht40_2s: [[u8; 14]; 2],
    pub ht20_diff: [[u8; 14]; 2],
    pub legacy_ht_diff: [[u8; 14]; 2],
    pub pwrgroup_ht20: [[u8; 14]; 2],
    pub pwrgroup_ht40: [[u8; 14]; 2],
    pub legacy_ht_txpowerdiff: u8,
    pub regulatory: u8,
    pub tssi: [u8; 2],
    pub thermal: u8,
    pub apk_thermalmeterignore: bool,
}

const fn group(index: u8) -> usize {
    if index < 3 {
        0
    } else if index < 9 {
        1
    } else {
        2
    }
}

impl Efuse {
    /// Uses only the qualified Adapter's retained 256-byte map. The
    /// source's autoload-failure defaults are unreachable on that type.
    pub fn from_adapter(adapter: &Adapter) -> Self {
        let hw = &adapter.hwinfo;
        let mut out = Self {
            cck: [[0; 14]; 2],
            ht40_1s: [[0; 14]; 2],
            ht40_2s: [[0; 14]; 2],
            ht20_diff: [[0; 14]; 2],
            legacy_ht_diff: [[0; 14]; 2],
            pwrgroup_ht20: [[0; 14]; 2],
            pwrgroup_ht40: [[0; 14]; 2],
            legacy_ht_txpowerdiff: 0,
            regulatory: hw[0x2b] & 7,
            tssi: [hw[0x29], 0],
            thermal: hw[0x2a] & 0x1f,
            apk_thermalmeterignore: hw[0x2a] & 0x1f == 0x1f,
        };
        for c in 0..14u8 {
            let g = group(c);
            let i = usize::from(c);
            // Only rf_path<1 populates these base areas in the AE source.
            out.cck[0][i] = hw[0x10 + g];
            out.ht40_1s[0][i] = hw[0x16 + g];
            for (rf, shift) in [(0, 0), (1, 4)] {
                let two_diff = (hw[0x66 + g] >> shift) & 0xf;
                out.ht40_2s[rf][i] = out.ht40_1s[rf][i].saturating_sub(two_diff);
                out.pwrgroup_ht40[rf][i] = (hw[0x22 + g] >> shift) & 0xf;
                out.pwrgroup_ht20[rf][i] = (hw[0x25 + g] >> shift) & 0xf;
                let diff = (hw[0x1c + g] >> shift) & 0xf;
                out.ht20_diff[rf][i] = if diff & 8 != 0 { diff | 0xf0 } else { diff };
                out.legacy_ht_diff[rf][i] = (hw[0x1f + g] >> shift) & 0xf;
            }
        }
        out.legacy_ht_txpowerdiff = out.legacy_ht_diff[0][7];
        out
    }
}

/// Only the explicit BT1/BT2 RF6052 cases alter the source words. Other
/// dynamic-power levels use the Normal branch in this source program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DynamicPower {
    Normal,
    Bt1,
    Bt2,
}

fn replicate(v: u32) -> u32 {
    v | v << 8 | v << 16 | v << 24
}
fn clamp_cck(v: u32) -> u32 {
    u32::from_le_bytes(v.to_le_bytes().map(|b| b.min(MAX_TX_PWR)))
}
fn clamp_ofdm(v: u32) -> u32 {
    u32::from_le_bytes(v.to_le_bytes().map(|b| (b & 0x7f).min(MAX_TX_PWR)))
}

fn cck_words(efuse: &Efuse, pg: &PgStore, level: [u8; 2], scanning: bool) -> [u32; 2] {
    let mut out = level.map(|v| replicate(u32::from(v)));
    if scanning {
        if efuse.regulatory == 0 {
            out = [0x3f3f_3f3f; 2];
        }
    } else if efuse.regulatory == 0 {
        out[0] = out[0].wrapping_add(pg.origoffset[0][6].wrapping_add(pg.origoffset[0][7] << 8));
        out[1] = out[1].wrapping_add(pg.origoffset[0][14].wrapping_add(pg.origoffset[0][15] << 24));
    }
    out.map(clamp_cck)
}

fn bases(efuse: &Efuse, level: [u8; 2], channel: u8, forty: bool) -> ([u32; 2], [u32; 2]) {
    let c = usize::from(channel - 1);
    let ofdm = core::array::from_fn(|rf| {
        replicate(u32::from(level[rf]) + u32::from(efuse.legacy_ht_diff[rf][c]))
    });
    let mcs = core::array::from_fn(|rf| {
        let v = if forty {
            level[rf]
        } else {
            level[rf].wrapping_add(efuse.ht20_diff[rf][c])
        };
        replicate(u32::from(v))
    });
    (ofdm, mcs)
}

#[allow(clippy::too_many_arguments)]
fn ofdm_word(
    efuse: &Efuse,
    pg: &PgStore,
    channel: u8,
    forty: bool,
    index: usize,
    rf: usize,
    base: ([u32; 2], [u32; 2]),
    dynamic: DynamicPower,
) -> Result<u32, Error> {
    let c = usize::from(channel - 1);
    let b = if index < 2 { base.0[rf] } else { base.1[rf] };
    let col = index + rf * 8;
    let word = match efuse.regulatory {
        1 if forty => b,
        1 => {
            // AE adds one for every >=3-group HT20 PG store; the CE
            // four-group special case is not this chip's algorithm.
            let g = if pg.pwrgroup_cnt >= 3 {
                group(channel - 1) + 1
            } else {
                0
            };
            pg.origoffset.get(g).ok_or(Error::State)?[col].wrapping_add(b)
        }
        2 => b,
        3 => {
            let limit = if forty {
                efuse.pwrgroup_ht40[rf][c]
            } else {
                efuse.pwrgroup_ht20[rf][c]
            };
            let customer = u32::from_le_bytes(
                pg.origoffset[0][col]
                    .to_le_bytes()
                    .map(|v| (v & 0x7f).min(limit)),
            );
            customer.wrapping_add(b)
        }
        _ => pg.origoffset[0][col].wrapping_add(b),
    };
    let word = match dynamic {
        DynamicPower::Normal => word,
        DynamicPower::Bt1 => word.wrapping_sub(0x0606_0606),
        DynamicPower::Bt2 => word.wrapping_sub(0x0c0c_0c0c),
    };
    Ok(clamp_ofdm(word))
}

/// Exact source words after clamps. This records source register math;
/// it does not carry a calibration capability or authorize transmission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    cck: [u32; 2],
    ofdm: [[u32; 2]; 6],
    pub channel: u8,
    pub forty: bool,
    pub current_cck: u8,
    pub current_ofdm24: u8,
}
impl Plan {
    pub fn for_channel(
        efuse: &Efuse,
        pg: &PgStore,
        channel: u8,
        forty: bool,
        scanning: bool,
        dynamic: DynamicPower,
    ) -> Result<Self, Error> {
        if !(1..=14).contains(&channel) {
            return Err(Error::State);
        }
        let c = usize::from(channel - 1);
        let levels = [efuse.ht40_1s[0][c], efuse.ht40_1s[1][c]];
        let base = bases(efuse, levels, channel, forty);
        let mut ofdm = [[0; 2]; 6];
        for (index, row) in ofdm.iter_mut().enumerate() {
            for (rf, word) in row.iter_mut().enumerate() {
                *word = ofdm_word(efuse, pg, channel, forty, index, rf, base, dynamic)?;
            }
        }
        Ok(Self {
            cck: cck_words(efuse, pg, [efuse.cck[0][c], efuse.cck[1][c]], scanning),
            ofdm,
            channel,
            forty,
            current_cck: efuse.cck[0][c],
            current_ofdm24: levels[0],
        })
    }
    pub fn cck_words(&self) -> [u32; 2] {
        self.cck
    }
    pub fn ofdm_words(&self) -> &[[u32; 2]; 6] {
        &self.ofdm
    }
    /// Actual per-path register indices, including auxiliary MCS8-15
    /// fields. Only path A rates 0..20 can ever belong to an AE station.
    pub fn indices(&self) -> [[u8; 28]; 2] {
        let mut out = [[0; 28]; 2];
        let a = self.cck[0].to_le_bytes();
        out[0][..4].copy_from_slice(&[a[0], a[1], a[2], 0]);
        out[1][..4].copy_from_slice(&self.cck[1].to_le_bytes());
        for (index, row) in self.ofdm.iter().enumerate() {
            for (rf, target) in out.iter_mut().enumerate() {
                target[4 + index * 4..8 + index * 4].copy_from_slice(&row[rf].to_le_bytes());
            }
        }
        out
    }
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
}
impl Default for Owner {
    fn default() -> Self {
        Self::new()
    }
}
impl Owner {
    pub const fn new() -> Self {
        Self { phase: Phase::New }
    }
    pub const fn phase(&self) -> Phase {
        self.phase
    }
    /// Programs one source plan under caller-held authority. Failure
    /// cannot retry a partially written set of TXAGC registers.
    pub fn program(&mut self, io: &impl Io, plan: &Plan) -> Result<(), Error> {
        if self.phase != Phase::New {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        let agc = plan.cck;
        set_bb(io, 0xe08, 0xff00, agc[0] & 0xff)?;
        set_bb(io, 0x86c, 0xffff_ff00, (agc[0] >> 8) & 0xff00_ffff)?;
        set_bb(io, 0x86c, 0xff, agc[1] >> 24)?;
        set_bb(io, 0x838, 0xffff_ff00, agc[1] & 0x00ff_ffff)?;
        for (index, row) in plan.ofdm.iter().enumerate() {
            for (rf, word) in row.iter().enumerate() {
                set_bb(
                    io,
                    if rf == 0 { REG_A[index] } else { REG_B[index] },
                    MASKDWORD,
                    *word,
                )?;
                if index == 3 {
                    let base = if rf == 0 { 0xc90 } else { 0xc98 };
                    let mut value = word.to_le_bytes()[3];
                    for offset in 0..3 {
                        value = value.saturating_sub(6);
                        io.write8(base + offset, value)?;
                    }
                }
            }
        }
        self.phase = Phase::Complete;
        Ok(())
    }
}
