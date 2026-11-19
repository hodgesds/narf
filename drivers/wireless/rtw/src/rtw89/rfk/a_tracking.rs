// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! fw.c `rtw89_build_txpwr_trk_tbl_from_elm` for A support_bands2G/5G.
//! Optional 6G rows consume their actual bytes when present; none invented.
use crate::rtw89::{mac::ChipId, radio_assets::Assets, rfk::Error};
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::rtw89) struct Tracking {
    delta: [[[i8; 30]; 4]; 16],
}
impl Tracking {
    pub fn from_assets(assets: &Assets) -> Result<Self, Error> {
        if assets.chip() != ChipId::Rtl8852A {
            return Err(Error::Table);
        }
        Self::parse(
            &assets
                .elements()
                .iter()
                .find(|e| e.id == 18)
                .ok_or(Error::Table)?
                .bytes,
        )
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let bitmap = u32::from_le_bytes(
            bytes
                .get(..4)
                .ok_or(Error::Table)?
                .try_into()
                .map_err(|_| Error::Table)?,
        );
        if bitmap & 0xfff0 != 0xfff0 {
            return Err(Error::Table);
        }
        let data = bytes.get(8..).ok_or(Error::Table)?;
        let mut delta = [[[0; 30]; 4]; 16];
        let mut offset = 0;
        for (kind, rows) in delta.iter_mut().enumerate() {
            if bitmap & (1 << kind) == 0 {
                continue;
            }
            let count = match kind {
                0..=3 => 4,
                4..=7 => 3,
                _ => 1,
            };
            for row in rows.iter_mut().take(count) {
                let actual = data.get(offset..offset + 30).ok_or(Error::Table)?;
                for (out, &v) in row.iter_mut().zip(actual) {
                    *out = v as i8;
                }
                offset += 30;
            }
        }
        Ok(Self { delta })
    }
    pub fn rows(&self, subband: u8, path: u8) -> (&[i8; 30], &[i8; 30]) {
        let (types, row) = match subband {
            1 => ([(7, 6), (5, 4)], 0),
            3 => ([(7, 6), (5, 4)], 1),
            4 => ([(7, 6), (5, 4)], 2),
            _ => ([(11, 10), (9, 8)], 0),
        };
        let (up, down) = types[usize::from(path)];
        (&self.delta[up][row], &self.delta[down][row])
    }
}
