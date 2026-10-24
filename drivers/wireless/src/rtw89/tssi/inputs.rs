//! The first matching signed-container tracking element or Linux's explicit
//! static B fallback. Partial/malformed present data never selects defaults.
use super::{tables, Error};
use crate::rtw89::radio_assets::Assets;
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::rtw89) struct Tracking {
    pub(super) up: [[i8; 30]; 2],
    pub(super) down: [[i8; 30]; 2],
}
impl Tracking {
    pub(in crate::rtw89) fn from_assets(assets: &Assets) -> Result<Self, Error> {
        match assets.elements().iter().find(|element| element.id == 18) {
            None => Ok(Self {
                up: [tables::A_P, tables::B_P],
                down: [tables::A_N, tables::B_N],
            }),
            Some(element) => Self::parse(&element.bytes),
        }
    }
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let bitmap = u32::from_le_bytes(
            bytes
                .get(..4)
                .ok_or(Error::Table)?
                .try_into()
                .map_err(|_| Error::Table)?,
        );
        // B supports2G+5G; Linux demands all of their tracking types even
        // when this initial station uses only2G. Type0..3 are optional6G rows.
        if bitmap & 0xfff0 != 0xfff0 || bitmap & !0xffff != 0 || bytes.len() < 8 {
            return Err(Error::Table);
        }
        let mut result = Self {
            up: [[0; 30]; 2],
            down: [[0; 30]; 2],
        };
        let mut offset: usize = 8;
        for kind in 0..16 {
            if bitmap & (1 << kind) == 0 {
                continue;
            }
            let subbands = if kind < 4 {
                4
            } else if kind < 8 {
                3
            } else {
                1
            };
            let end = offset.checked_add(subbands * 30).ok_or(Error::Table)?;
            let data = bytes.get(offset..end).ok_or(Error::Table)?;
            let destination = match kind {
                8 => Some(&mut result.down[1]),
                9 => Some(&mut result.up[1]),
                10 => Some(&mut result.down[0]),
                11 => Some(&mut result.up[0]),
                _ => None,
            };
            if let Some(destination) = destination {
                for (out, input) in destination.iter_mut().zip(data) {
                    *out = *input as i8;
                }
            }
            offset = end;
        }
        if offset != bytes.len() {
            return Err(Error::Table);
        }
        Ok(result)
    }
}
