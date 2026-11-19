// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! BE gain table decoder: phy_be.c::rtw89_phy_config_bb_gain_be.
//! Twelve source bands, two BW classes and byte-packed signed entries. The
//! AX table's byte-wide path and sparse RXSC layouts are not reused here.
use super::operating_channel_c::{Band, Profile, Width};
use super::radio_table::Pair;
use alloc::vec::Vec;
struct GainRegister {
    g: [u32; 2],
    a: [u32; 2],
    gm: u32,
    am: u32,
}
#[path = "radio_gain_be_registers.rs"]
mod registers;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Profile,
    Type,
    Memory,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Gain {
    pub(super) lna: [[[[i8; 7]; 2]; 2]; 12],
    pub(super) tia: [[[[i8; 2]; 2]; 2]; 12],
    pub(super) lna_op1db: [[[[i8; 7]; 2]; 2]; 12],
    pub(super) tia_op1db: [[[[i8; 8]; 2]; 2]; 12],
    pub(super) rpl20: [[[i8; 1]; 2]; 12],
    pub(super) rpl40: [[[i8; 2]; 2]; 12],
    pub(super) rpl80: [[[i8; 4]; 2]; 12],
    pub(super) rpl160: [[[i8; 8]; 2]; 12],
    direct: Vec<(u32, u32, u32)>,
}
fn put(dst: &mut [i8], value: u32) {
    for (d, s) in dst.iter_mut().zip(value.to_le_bytes()) {
        *d = s as i8;
    }
}
impl Gain {
    pub(super) fn decode(pairs: &[Pair], rfe: u8) -> Result<Self, Error> {
        let mut gain = Self::default();
        for &Pair(address, data) in pairs {
            let kind = address >> 24;
            let band = ((address >> 16) & 255) as usize;
            let path = ((address >> 8) & 15) as usize;
            let bw = ((address >> 12) & 15) as usize;
            let subtype = (address & 255) as usize;
            if band >= 12 || path >= 2 || bw >= 2 || (0xf9..=0xfe).contains(&address) {
                return Err(Error::Profile);
            }
            match kind {
                0 => match subtype {
                    0 => put(&mut gain.lna[band][bw][path][..4], data),
                    1 => put(&mut gain.lna[band][bw][path][4..], data),
                    2 => put(&mut gain.tia[band][bw][path], data),
                    _ => return Err(Error::Type),
                },
                1 => match subtype >> 4 {
                    0 => gain.rpl20[band][path][0] = data as i8,
                    1 => put(&mut gain.rpl40[band][path], data),
                    2 => put(&mut gain.rpl80[band][path], data),
                    3 => {
                        let start = if subtype & 15 == 0 { 0 } else { 4 };
                        put(&mut gain.rpl160[band][path][start..start + 4], data)
                    }
                    _ => return Err(Error::Type),
                },
                2 => {} // Source ignores BB gain bypass on BE.
                3 => match subtype {
                    0 => put(&mut gain.lna_op1db[band][bw][path][..4], data),
                    1 => put(&mut gain.lna_op1db[band][bw][path][4..], data),
                    2 => put(&mut gain.tia_op1db[band][bw][path][..4], data),
                    3 => put(&mut gain.tia_op1db[band][bw][path][4..], data),
                    _ => return Err(Error::Type),
                },
                4 if rfe < 50 => {}
                15 => {
                    let reg = address & 0xfffff;
                    if reg & 3 != 0 {
                        return Err(Error::Profile);
                    }
                    gain.direct.try_reserve(1).map_err(|_| Error::Memory)?;
                    gain.direct.push((reg, 0xffff_0000, data));
                }
                _ => return Err(Error::Profile),
            }
        }
        Ok(gain)
    }
    pub(super) fn direct(&self) -> &[(u32, u32, u32)] {
        &self.direct
    }
    /// Source rtw8922a_set_gain, per path: LNA/TIA, OP1dB, then dense
    /// 160/80/40/20 subchannel compensation. Pure PHY-relative field program;
    /// caller still needs current qualified BE radio/channel ownership.
    pub(super) fn channel_program(&self, profile: Profile) -> Result<Vec<(u32, u32, u32)>, Error> {
        let band = match profile.subband() {
            0 => 0,
            1 => 1,
            3 => 2,
            4 => 3,
            s => usize::from(s - 1),
        };
        if band >= 12 || profile.width() == Width::Mhz320 {
            return Err(Error::Profile);
        }
        let bw = usize::from(profile.width() > Width::Mhz40);
        let mut program = Vec::new();
        program.try_reserve_exact(78).map_err(|_| Error::Memory)?;
        for path in 0..2 {
            for (table, values) in [
                (registers::BB_GAIN_LNA, self.lna[band][bw][path].as_slice()),
                (registers::BB_GAIN_TIA, self.tia[band][bw][path].as_slice()),
                (
                    registers::BB_OP1DB_LNA,
                    self.lna_op1db[band][bw][path].as_slice(),
                ),
                (
                    registers::BB_OP1DB_TIA_LNA,
                    self.tia_op1db[band][bw][path].as_slice(),
                ),
            ] {
                for (reg, value) in table.iter().zip(values) {
                    let (a, m) = if profile.band() == Band::Ghz2 {
                        (reg.g[path], reg.gm)
                    } else {
                        (reg.a[path], reg.am)
                    };
                    program.push((a, m, i32::from(*value) as u32));
                }
            }
            for (table, values) in [
                (
                    registers::RPL_COMP_BW160,
                    self.rpl160[band][path].as_slice(),
                ),
                (registers::RPL_COMP_BW80, self.rpl80[band][path].as_slice()),
                (registers::RPL_COMP_BW40, self.rpl40[band][path].as_slice()),
                (registers::RPL_COMP_BW20, self.rpl20[band][path].as_slice()),
            ] {
                let offset = if path == 1 { 0x400 } else { 0 };
                for (&(a, m), value) in table.iter().zip(values) {
                    program.push((a | offset, m, i32::from(*value) as u32));
                }
            }
        }
        Ok(program)
    }
}
#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};
    fn smoke_rtw8922a_gain_uses_be_band_bw_path_and_dense_subchannels() -> TestResult {
        let g = Gain::decode(
            &[
                Pair(0x000b_1100, 0x807f_01ff),
                Pair(0x000b_1101, 0x0000_fe02),
                Pair(0x000b_1102, 0x0000_fdfc),
                Pair(0x010b_1110, 0x4433_2211),
                Pair(0x010b_1120, 0x8877_6655),
                Pair(0x010b_1130, 0xccbb_aa99),
                Pair(0x010b_113f, 0x00ff_eedd),
                Pair(0x030b_1103, 0xf4f3_f2f1),
                Pair(0x020b_1100, 0x0102_0304),
                Pair(0x0f00_0100, 0x1234),
            ],
            1,
        )
        .unwrap();
        kt_assert_eq!(g.lna[11][1][1], [-1, 1, 127, -128, 2, -2, 0]);
        kt_assert_eq!(g.tia[11][1][1], [-4, -3]);
        kt_assert_eq!(g.rpl40[11][1], [0x11, 0x22]);
        kt_assert_eq!(g.rpl80[11][1], [0x55, 0x66, 0x77, -120]);
        kt_assert_eq!(g.rpl160[11][1], [-103, -86, -69, -52, -35, -18, -1, 0]);
        kt_assert_eq!(g.tia_op1db[11][1][1][4..], [-15, -14, -13, -12]);
        kt_assert_eq!(g.direct(), &[(0x100, 0xffff_0000, 0x1234)]);
        for address in [
            0x000c_0000,
            0x0000_2000,
            0x0000_0200,
            0x0000_0003,
            0x0100_0040,
        ] {
            kt_assert!(Gain::decode(&[Pair(address, 0)], 1).is_err());
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtw89/8922a",
        smoke_rtw8922a_gain_uses_be_band_bw_path_and_dense_subchannels
    );
}
