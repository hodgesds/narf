// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Exact B fixed WW/ch1/20 power *configuration*, never a dBm authorization.
//! Final measured peaks and current host policy independently gate emission.
use super::{
    radio_assets::{Assets, Element},
    rfk::{Error, Interface},
};
#[path = "radio_power/defaults.rs"]
mod defaults;
#[path = "radio_power/recipe.rs"]
mod recipe;
pub(super) const RECIPE: [u8; 32] = recipe::RECIPE;
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Plan {
    byrate: [i8; 44],
    offset: [i8; 5],
    limits: [[i8; 8]; 2],
    ru: [[i8; 3]; 2],
    shape: [u8; 2],
}
fn selected(elements: &[Element], id: u32, rfe: u8) -> Result<Option<&[u8]>, Error> {
    let mut out: Option<(u8, &[u8])> = None;
    for elm in elements.iter().filter(|e| e.id == id) {
        let h = elm.bytes.get(..8).ok_or(Error::Table)?;
        let n = u32::from_le_bytes(h[4..8].try_into().unwrap()) as usize;
        let size = usize::from(h[3]);
        if h[..2] != [0, 0]
            || size == 0
            || n == 0
            || n.checked_mul(size).and_then(|v| v.checked_add(8)) != Some(elm.bytes.len())
        {
            return Err(Error::Table);
        }
        if h[2] == rfe || (h[2] == 0 && out.is_none_or(|(old, _)| old == 0)) {
            out = Some((h[2], &elm.bytes));
        }
    }
    Ok(out.map(|(_, b)| b))
}
fn entries(
    bytes: &[u8],
    known: usize,
    minimum: usize,
) -> Result<impl Iterator<Item = [u8; 16]> + '_, Error> {
    let size = usize::from(bytes[3]);
    if size < minimum || size > 255 || known > 16 {
        return Err(Error::Table);
    }
    for e in bytes[8..].chunks_exact(size) {
        if e.get(known..)
            .is_some_and(|ext| ext.iter().any(|&v| v != 0))
        {
            return Err(Error::Table);
        }
    }
    Ok(bytes[8..].chunks_exact(size).map(move |e| {
        let mut x = [0; 16];
        let n = e.len().min(known);
        x[..n].copy_from_slice(&e[..n]);
        x
    }))
}
impl Plan {
    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::rtw89) fn fixture_defaults() -> Result<Self, Error> {
        Self::from_elements(&[], 1)
    }

    pub fn from_assets(assets: &Assets, rfe: u8) -> Result<Self, Error> {
        Self::from_elements(assets.elements(), rfe)
    }
    fn from_elements(elements: &[Element], rfe: u8) -> Result<Self, Error> {
        if rfe == 255 {
            return Err(Error::Policy);
        }
        let mut plan = defaults::DEFAULT;
        if let Some(bytes) = selected(elements, 9, rfe)? {
            plan.byrate = [0; 44];
            plan.offset = [0; 5];
            for e in entries(bytes, 11, 9)? {
                let (band, nss, rs, start, len, bw, ofdma) = (
                    e[0],
                    e[1],
                    e[2],
                    usize::from(e[3]),
                    usize::from(e[4]),
                    e[9],
                    e[10],
                );
                let bound = match rs {
                    0 => 4,
                    1 => 8,
                    2 => 16,
                    3 => 4,
                    4 => 8,
                    _ => return Err(Error::Table),
                };
                if band >= 3
                    || bw >= 5
                    || start + len > bound
                    || ((rs == 2 || rs == 3)
                        && (nss >= (if rs == 3 { 2 } else { 4 }) || ofdma >= 2))
                {
                    return Err(Error::Table);
                }
                if band != 0 || bw != 0 || ((rs == 2 || rs == 3) && ofdma != 0) {
                    continue;
                }
                let base = match (rs, nss) {
                    (0, _) => Some((0, 4)),
                    (1, _) => Some((4, 8)),
                    (2, 0) => Some((12, 12)),
                    (2, 1) => Some((28, 12)),
                    (3, 0) => Some((24, 4)),
                    (3, 1) => Some((40, 4)),
                    (4, _) => None,
                    _ => continue,
                };
                for i in 0..len {
                    let v = if i < 4 { e[5 + i] as i8 } else { 0 };
                    if let Some((base, used)) = base {
                        if start + i < used {
                            plan.byrate[base + start + i] = v;
                        }
                    } else if start + i < 5 {
                        plan.offset[start + i] = v;
                    }
                }
            }
        }
        if let Some(bytes) = selected(elements, 10, rfe)? {
            plan.limits = [[0; 8]; 2];
            for e in entries(bytes, 7, 7)? {
                if e[0] >= 2 || e[1] >= 2 || e[2] >= 3 || e[3] >= 2 || e[4] >= 16 || e[5] >= 14 {
                    return Err(Error::Table);
                }
                if e[4] != 0 || e[5] != 0 {
                    continue;
                }
                let base = match (e[0], e[2]) {
                    (0, 0) => 0,
                    (1, 0) => 2,
                    (0, 1) => 4,
                    (0, 2) => 6,
                    _ => continue,
                };
                plan.limits[e[1] as usize][base + e[3] as usize] = e[6] as i8;
            }
        }
        if let Some(bytes) = selected(elements, 13, rfe)? {
            plan.ru = [[0; 3]; 2];
            for e in entries(bytes, 5, 5)? {
                if e[0] >= 8 || e[1] >= 2 || e[2] >= 16 || e[3] >= 14 {
                    return Err(Error::Table);
                }
                if e[0] < 3 && e[2] == 0 && e[3] == 0 {
                    plan.ru[e[1] as usize][e[0] as usize] = e[4] as i8;
                }
            }
        }
        if let Some(bytes) = selected(elements, 16, rfe)? {
            plan.shape = [0; 2];
            for e in entries(bytes, 5, 4)? {
                if e[0] >= 8 || e[1] >= 2 || e[2] >= 16 || e[4] >= 3 {
                    return Err(Error::Table);
                }
                if e[0] == 0 && e[2] == 0 && e[4] == 0 {
                    plan.shape[e[1] as usize] = e[3];
                }
            }
        }
        Ok(plan)
    }
    /// Bind signed source units and the exact fixed power/response profile. These
    /// bytes make no physical power claim; measured conducted maxima are separate.
    pub fn bind(&self, hash: &mut narf_crypto::sha256::Sha256) {
        hash.update(b"B WW0 ch1 20 source RF2 MAC1 BB3;equal A/B ref0;CCK+OFDM autoresponse;no SAR/antenna offset curves");
        for row in [
            &self.byrate[..],
            &self.offset[..],
            &self.limits[0][..],
            &self.limits[1][..],
            &self.ru[0][..],
            &self.ru[1][..],
        ] {
            for &v in row {
                hash.update(&v.to_le_bytes());
            }
        }
        hash.update(&self.shape);
    }
    fn visit(&self, mut emit: impl FnMut(u32, u32, u32) -> Result<(), Error>) -> Result<(), Error> {
        for (i, bytes) in self.byrate.chunks_exact(4).enumerate() {
            let mut v = [0; 4];
            for (k, b) in bytes.iter().enumerate() {
                v[k] = (*b >> 1) as u8;
            }
            emit(0xd2c0 + i as u32 * 4, u32::MAX, u32::from_le_bytes(v))?;
        }
        let mut offset = 0;
        for (i, v) in self.offset.iter().enumerate() {
            offset |= ((i32::from(*v >> 1) as u32) & 15) << (4 * i);
        }
        emit(0xd204, 0xfffff, offset)?;
        let fir = if self.shape[0] == 0 {
            [
                0x023d23ff, 0x0029b354, 0x000fc1c8, 0x00fdb053, 0x00f86f9a, 0x06faef92, 0x00fe5fcc,
                0x00ffdff5,
            ]
        } else {
            [
                0x023d83ff, 0x002c636a, 0x0013f204, 0x00008090, 0x00f87fb0, 0x06f99f83, 0x00fdbfba,
                0x00003ff5,
            ]
        };
        for (i, v) in fir.into_iter().enumerate() {
            emit(0x10000 + 0x2300 + i as u32 * 4, u32::MAX, v)?;
        }
        emit(0x14494, 0x3000000, u32::from(self.shape[1]))?;
        for p in 0..2 {
            let mut page = [0u8; 40];
            for (i, v) in self.limits[p].iter().enumerate() {
                page[i] = (*v >> 1) as u8;
            }
            for (i, b) in page.chunks_exact(4).enumerate() {
                emit(
                    0xd2ec + p as u32 * 40 + i as u32 * 4,
                    u32::MAX,
                    u32::from_le_bytes(b.try_into().unwrap()),
                )?;
            }
        }
        for p in 0..2 {
            let mut page = [0u8; 24];
            for (i, v) in self.ru[p].iter().enumerate() {
                page[i * 8] = (*v >> 1) as u8;
            }
            for (i, b) in page.chunks_exact(4).enumerate() {
                emit(
                    0xd33c + p as u32 * 24 + i as u32 * 4,
                    u32::MAX,
                    u32::from_le_bytes(b.try_into().unwrap()),
                )?;
            }
        }
        reference(emit)
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum State {
    #[default]
    New,
    Preparing,
    Configured,
}
#[derive(Default)]
pub(super) struct Power {
    state: State,
}
fn reference(mut emit: impl FnMut(u32, u32, u32) -> Result<(), Error>) -> Result<(), Error> {
    emit(0xd200, 0xffffc00, 0)?;
    for a in [0x15804, 0x17804, 0x15808, 0x17808] {
        emit(a, 0x7ffffff, (172 << 18) | (312 << 9))?;
    }
    Ok(())
}
fn apply(io: &mut impl Interface, a: u32, m: u32, v: u32) -> Result<(), Error> {
    io.admit()?;
    let expected = if m == u32::MAX {
        v
    } else {
        let old = io.read32(a)?;
        if old == u32::MAX {
            return Err(super::power::Error::Gone.into());
        }
        (old & !m) | ((v << m.trailing_zeros()) & m)
    };
    io.admit()?;
    io.write32(a, expected)?;
    io.admit()?;
    let actual = io.read32(a)?;
    if actual == u32::MAX || actual & m != expected & m {
        return Err(super::power::Error::Access.into());
    }
    Ok(())
}
/// # Safety
/// Same exclusive current measured B preparation as Power::prepare; only the
/// source initial reference-control prefix, no emission authorization.
pub(super) unsafe fn initial_reference(io: &mut impl Interface) -> Result<(), Error> {
    reference(|a, m, v| apply(io, a, m, v))
}
impl Power {
    pub fn state(&self) -> State {
        self.state
    }
    /// # Safety
    /// Exclusive actual B/PHY0 awake initial owner, CMAC TX/ordinary DMA closed,
    /// current signed full recipe and measured all-path response envelope. This
    /// writes only source controls; caller owns actual RFK and terminal cleanup.
    pub unsafe fn prepare(&mut self, io: &mut impl Interface, plan: &Plan) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        self.state = State::Preparing;
        plan.visit(|a, m, v| apply(io, a, m, v))?;
        self.state = State::Configured;
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "radio_power/tests.rs"]
mod tests;
