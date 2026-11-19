// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! B's retained AX BB-gain state, decoded before any PHY table publication.
use super::radio_table::Pair;
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Gain {
    pub lna: [[[i8; 7]; 2]; 8],
    pub tia: [[[i8; 2]; 2]; 8],
    pub bypass: [[[i8; 7]; 2]; 8],
    pub lna_op1db: [[[i8; 7]; 2]; 8],
    pub tia_op1db: [[[i8; 8]; 2]; 8],
    pub rpl20: [[i8; 2]; 8],
    pub rpl40: [[[i8; 9]; 2]; 8],
    pub rpl80: [[[i8; 13]; 2]; 8],
    pub rpl160: [[[i8; 15]; 2]; 8],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Profile,
    Type,
}
fn put(destination: &mut [i8], data: u32) {
    for (d, s) in destination.iter_mut().zip(data.to_le_bytes()) {
        *d = s as i8;
    }
}
impl Gain {
    pub fn decode(pairs: &[Pair], rfe: u8) -> Result<Self, Error> {
        let mut gain = Self::default();
        for &Pair(address, data) in pairs {
            let kind = address >> 24;
            let band = ((address >> 16) & 255) as usize;
            let path = ((address >> 8) & 255) as usize;
            let subtype = (address & 255) as usize;
            if band >= 8 || path >= 2 {
                return Err(Error::Profile);
            }
            match kind {
                0 => match subtype {
                    0 => put(&mut gain.lna[band][path][..4], data),
                    1 => put(&mut gain.lna[band][path][4..], data),
                    2 => put(&mut gain.tia[band][path], data),
                    _ => return Err(Error::Type),
                },
                1 => {
                    let start = subtype & 15;
                    let width = subtype >> 4;
                    match (width, start) {
                        (0, _) => gain.rpl20[band][path] = data as i8,
                        (1, 0) => gain.rpl40[band][path][0] = data as i8,
                        (1, 1) => put(&mut gain.rpl40[band][path][1..3], data),
                        (2, 0) => gain.rpl80[band][path][0] = data as i8,
                        (2, 1) => put(&mut gain.rpl80[band][path][1..5], data),
                        (2, 9) => put(&mut gain.rpl80[band][path][9..11], data),
                        (3, 0) => gain.rpl160[band][path][0] = data as i8,
                        (3, 1 | 5 | 9) => put(&mut gain.rpl160[band][path][start..start + 4], data),
                        (3, 13) => put(&mut gain.rpl160[band][path][13..15], data),
                        _ => return Err(Error::Type),
                    }
                }
                2 => match subtype {
                    0 => put(&mut gain.bypass[band][path][..4], data),
                    1 => put(&mut gain.bypass[band][path][4..], data),
                    _ => return Err(Error::Type),
                },
                3 => match subtype {
                    0 => put(&mut gain.lna_op1db[band][path][..4], data),
                    1 => put(&mut gain.lna_op1db[band][path][4..], data),
                    2 => put(&mut gain.tia_op1db[band][path][..4], data),
                    3 => put(&mut gain.tia_op1db[band][path][4..], data),
                    _ => return Err(Error::Type),
                },
                4 if rfe < 50 => {}
                _ => return Err(Error::Profile),
            }
        }
        Ok(gain)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "radio_gain/tests.rs"]
mod tests;
