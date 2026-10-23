// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! AX physical fuse interpretation and checked hardware-signature selection.
//! References: Linux rtw89/efuse.c recognizers and fw.c MSS pool selectors.

use super::{fwdl::SignaturePool, mac::ChipId};
use core::ops::Range;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    UnsupportedChip,
    UnknownFuses,
    MissingSignature,
    UnknownBlacklist,
    NewerBlacklist,
    Blacklisted,
    Bounds,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Modern {
    device: u8,
    customer: u8,
    key: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fuses {
    chip: ChipId,
    enabled: bool,
    legacy: Option<u8>,
    modern: Option<Modern>,
}

/// Host policy, independent of the firmware-supplied blacklist version/bit.
/// External lists must come from the authenticated board policy owner.
#[derive(Clone, Copy, Debug)]
pub struct Blacklist {
    version: u8,
    bits: [u8; 32],
}
impl Blacklist {
    /// Linux supplies version0/all-clear lists only for these AX profiles.
    pub fn upstream(chip: ChipId) -> Option<Self> {
        matches!(chip, ChipId::Rtl8852B | ChipId::Rtl8852C).then_some(Self {
            version: 0,
            bits: [0; 32],
        })
    }
    pub fn authenticated(version: u8, bits: [u8; 32]) -> Self {
        Self { version, bits }
    }
    fn check(self, content: &[u8]) -> Result<(), Error> {
        let bit = usize::from(*content.get(32).ok_or(Error::Bounds)?);
        let version = *content.get(33).ok_or(Error::Bounds)?;
        if version > self.version {
            return Err(Error::NewerBlacklist);
        }
        if self.bits[bit / 8] & (1 << (bit & 7)) != 0 {
            return Err(Error::Blacklisted);
        }
        Ok(())
    }
}
impl Fuses {
    /// Native callers must read BOTH bytes at DDV0x5ec successfully. A failed
    /// read must never be replaced with erased bytes. Unknown programmed fuses
    /// are an error rather than an insecure-boot fallback.
    pub fn decode(chip: ChipId, b1: u8, b2: u8) -> Result<Self, Error> {
        if chip == ChipId::Rtl8922A {
            return Err(Error::UnsupportedChip);
        }
        if (b1, b2) == (255, 255) {
            return Ok(Self {
                chip,
                enabled: false,
                legacy: None,
                modern: None,
            });
        }
        let legacy = match (255 - b1, 15 - (b2 & 15), 7 - ((b2 >> 4) & 7)) {
            (0, 0, 0) => Some(0),
            (0, 1, 1) => Some(1),
            _ => None,
        };
        let modern = if chip == ChipId::Rtl8852B && (b1, b2) == (255, 0x6e) {
            Some(Modern {
                device: 1,
                customer: 0,
                key: 0,
            })
        } else {
            let device = match b1 & 15 {
                12 => Some(0),
                10 => Some(1),
                9 => Some(2),
                6 => Some(3),
                15 => Some(15),
                _ => None,
            };
            device.map(|device| Modern {
                device,
                customer: 31 - ((b1 >> 4) | ((b2 & 0x40) >> 2)),
                key: 15 - (b2 & 15),
            })
        };
        if legacy.is_none() && modern.is_none() {
            return Err(Error::UnknownFuses);
        }
        Ok(Self {
            chip,
            enabled: true,
            legacy,
            modern,
        })
    }
    pub fn chip(self) -> ChipId {
        self.chip
    }
    pub fn enabled(self) -> bool {
        self.enabled
    }
    pub fn check_blacklist(self, policy: Option<Blacklist>, content: &[u8]) -> Result<(), Error> {
        if self.enabled {
            policy.ok_or(Error::UnknownBlacklist)?.check(content)?;
        }
        Ok(())
    }
    /// None means this formatted section doesn't match the physical selection.
    pub fn signature(
        self,
        image: &[u8],
        pool: SignaturePool,
        content: &[u8],
    ) -> Result<Option<Range<usize>>, Error> {
        if !self.enabled {
            return Ok(None);
        }
        let (index, stride, length) = if pool.bitmap {
            // AX sb_sel_mgn is zero. This field overlaps key_sign_len: an
            // explicit incompatible selector must not be silently truncated.
            if u32at(content, 58)? != 0 {
                return Ok(None);
            }
            let Some(selection) = self.modern else {
                return Ok(None);
            };
            let header = image
                .get(pool.offset..pool.offset.checked_add(32).ok_or(Error::Bounds)?)
                .ok_or(Error::Bounds)?;
            let keys = u16at(header, 26)?;
            let customers = u16at(header, 24)?;
            if usize::from(selection.key) >= keys || usize::from(selection.customer) >= customers {
                return Ok(None);
            }
            let default = header[16] != 0;
            let bit = if selection.device == 15 {
                if !default {
                    return Ok(None);
                }
                let bit = usize::from(selection.customer) * keys + usize::from(selection.key);
                if bit >= 64 {
                    return Ok(None);
                }
                bit
            } else {
                if selection.device >= header[21] {
                    return Ok(None);
                }
                usize::from(selection.device) * keys * customers
                    + usize::from(selection.customer) * keys
                    + usize::from(selection.key)
                    + if default { 64 } else { 0 }
            };
            let bitmap = image
                .get(pool.offset + 32..pool.signatures_offset)
                .ok_or(Error::Bounds)?;
            let value = *bitmap.get(bit / 8).ok_or(Error::Bounds)?;
            if value & (1 << (bit & 7)) == 0 {
                return Ok(None);
            }
            let rank = bitmap[..bit / 8]
                .iter()
                .map(|byte| byte.count_ones() as usize)
                .sum::<usize>()
                + (value & ((1u8 << (bit & 7)) - 1)).count_ones() as usize;
            (rank, pool.signature_len, pool.signature_len)
        } else {
            // Linux's indexed selector uses512-byte signatures even when v1
            // DSP storage adds eight bytes per entry to the overall pool size.
            (
                usize::from(self.legacy.ok_or(Error::MissingSignature)?),
                512,
                512,
            )
        };
        if index >= pool.signature_count {
            return Err(Error::MissingSignature);
        }
        let start = pool
            .signatures_offset
            .checked_add(index.checked_mul(stride).ok_or(Error::Bounds)?)
            .ok_or(Error::Bounds)?;
        let end = start.checked_add(length).ok_or(Error::Bounds)?;
        if end > pool.offset.checked_add(pool.len).ok_or(Error::Bounds)? || end > image.len() {
            return Err(Error::Bounds);
        }
        Ok(Some(start..end))
    }
}
fn u16at(bytes: &[u8], at: usize) -> Result<usize, Error> {
    Ok(usize::from(u16::from_le_bytes(
        bytes
            .get(at..at + 2)
            .ok_or(Error::Bounds)?
            .try_into()
            .map_err(|_| Error::Bounds)?,
    )))
}
fn u32at(bytes: &[u8], at: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(
        bytes
            .get(at..at + 4)
            .ok_or(Error::Bounds)?
            .try_into()
            .map_err(|_| Error::Bounds)?,
    ))
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "secure_tests.rs"]
mod tests;
