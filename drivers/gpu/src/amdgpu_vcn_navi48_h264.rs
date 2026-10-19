// SPDX-License-Identifier: MIT
// Header inspection adapted from IGT 2.4 tests/amdgpu/amd_vcn.c:
// Copyright 2014 Advanced Micro Devices, Inc.
// Copyright 2023 Advanced Micro Devices, Inc.
// These are upstream notices; see ../VCN-NOTICES for the permission notice.
//! Bounded Annex-B header inspection for the fixed encoder proof. This is not
//! a video decoder or a general bitstream validator. Derived from IGT's test.
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Picture {
    pub width: u32,
    pub height: u32,
    pub profile: u8,
    pub slice_type: u8,
    pub idr: bool,
}
struct Bits<'a> {
    data: &'a [u8],
    at: usize,
}
impl Bits<'_> {
    fn bit(&mut self) -> Option<u32> {
        let value = (self.data.get(self.at / 8)? >> (7 - self.at % 8)) & 1;
        self.at += 1;
        Some(u32::from(value))
    }
    fn bits(&mut self, count: u32) -> Option<u32> {
        if count > 32 {
            return None;
        }
        let mut value = 0;
        for _ in 0..count {
            value = (value << 1) | self.bit()?;
        }
        Some(value)
    }
    fn ue(&mut self, max: u32) -> Option<u32> {
        let mut zeros = 0;
        while self.bit()? == 0 {
            zeros += 1;
            if zeros > 31 {
                return None;
            }
        }
        let value = (1u64 << zeros) - 1 + u64::from(self.bits(zeros)?);
        (value <= u64::from(max)).then_some(value as u32)
    }
    fn se(&mut self) -> Option<i32> {
        let value = self.ue(u32::MAX - 1)?;
        let signed = if value & 1 == 0 {
            -(i64::from(value) / 2)
        } else {
            i64::from(value / 2) + 1
        };
        i32::try_from(signed).ok()
    }
}
fn start_code(data: &[u8], mut at: usize) -> Option<(usize, usize)> {
    while at + 3 <= data.len() {
        if data.get(at..at + 4) == Some(&[0, 0, 0, 1]) {
            return Some((at, at + 4));
        }
        if data[at..at + 3] == [0, 0, 1] {
            return Some((at, at + 3));
        }
        at += 1;
    }
    None
}
fn rbsp(data: &[u8]) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(data.len());
    let mut zeros = 0;
    let mut at = 0;
    while at < data.len() {
        let value = data[at];
        if zeros >= 2 && value == 3 {
            if *data.get(at + 1)? > 3 {
                return None;
            }
            zeros = 0;
        } else {
            bytes.push(value);
            zeros = if value == 0 { zeros + 1 } else { 0 };
        }
        at += 1;
    }
    Some(bytes)
}
fn sps(data: &[u8]) -> Option<(u32, u32, u8, u32)> {
    let mut b = Bits { data, at: 0 };
    let profile = b.bits(8)? as u8;
    if !matches!(profile, 66 | 77 | 100) || b.bits(8)? & 3 != 0 {
        return None;
    }
    b.bits(8)?; // level_idc
    let sps_id = b.ue(31)?;
    if profile == 100 {
        // The proof uses eight-bit 4:2:0 NV12 input only.
        if b.ue(3)? != 1 || b.ue(6)? != 0 || b.ue(6)? != 0 {
            return None;
        }
        b.bit()?;
        if b.bit()? != 0 {
            for size in [16, 16, 16, 16, 16, 16, 64, 64] {
                if b.bit()? == 0 {
                    continue;
                }
                let (mut last, mut next) = (8, 8);
                for _ in 0..size {
                    if next != 0 {
                        let delta = b.se()?;
                        if !(-128..=127).contains(&delta) {
                            return None;
                        }
                        next = (last + delta + 256) % 256;
                    }
                    if next != 0 {
                        last = next;
                    }
                }
            }
        }
    }
    b.ue(12)?;
    match b.ue(2)? {
        0 => {
            b.ue(12)?;
        }
        1 => {
            b.bit()?;
            b.se()?;
            b.se()?;
            let count = b.ue(255)?;
            for _ in 0..count {
                b.se()?;
            }
        }
        _ => {}
    }
    b.ue(16)?;
    b.bit()?;
    let width = (b.ue(4095)? + 1) * 16;
    let map_height = b.ue(4095)? + 1;
    let frame = b.bit()?;
    if frame == 0 {
        b.bit()?;
    }
    b.bit()?;
    let height = map_height * 16 * (2 - frame);
    let (mut crop_x, mut crop_y) = (0, 0);
    if b.bit()? != 0 {
        crop_x = (b.ue(8192)? + b.ue(8192)?) * 2;
        crop_y = (b.ue(8192)? + b.ue(8192)?) * 2 * (2 - frame);
    }
    b.bit()?; // VUI presence; remaining VUI is irrelevant to this inspection.
    let (width, height) = (width.checked_sub(crop_x)?, height.checked_sub(crop_y)?);
    (width > 0 && height > 0).then_some((width, height, profile, sps_id))
}
pub(super) fn inspect(data: &[u8]) -> Option<Picture> {
    if data.len() > 0x1f000 {
        return None;
    }
    let (first, mut head) = start_code(data, 0)?;
    if data[..first].iter().any(|b| *b != 0) {
        return None;
    }
    let (mut format, mut slice) = (None, None);
    let mut pps = None;
    let mut count = 0;
    loop {
        count += 1;
        if count > 64 {
            return None;
        }
        let next = start_code(data, head + 1);
        let end = next.map_or(data.len(), |p| p.0);
        let nal = data.get(head..end)?;
        let header = *nal.first()?;
        if header & 0x80 != 0 {
            return None;
        }
        match header & 31 {
            7 => {
                if header & 0x60 == 0 {
                    return None;
                }
                let value = sps(&rbsp(&nal[1..])?)?;
                if format.is_some_and(|old| old != value) {
                    return None;
                }
                format = Some(value);
            }
            8 => {
                if header & 0x60 == 0 {
                    return None;
                }
                let bytes = rbsp(&nal[1..])?;
                let mut bits = Bits {
                    data: &bytes,
                    at: 0,
                };
                let value = (bits.ue(255)?, bits.ue(31)?);
                if pps.is_some_and(|old| old != value) {
                    return None;
                }
                pps = Some(value);
            }
            1 | 5 => {
                if header & 31 == 5 && header & 0x60 == 0 {
                    return None;
                }
                let bytes = rbsp(&nal[1..])?;
                let mut bits = Bits {
                    data: &bytes,
                    at: 0,
                };
                bits.ue(65535)?;
                let value = ((bits.ue(9)? % 5) as u8, header & 31 == 5, bits.ue(255)?);
                if slice.is_some_and(|old| old != value) {
                    return None;
                }
                slice = Some(value);
            }
            6 | 9 | 12 => {}
            _ => return None,
        }
        match next {
            Some((_, at)) => head = at,
            None => break,
        }
    }
    let (width, height, profile, sps_id) = format?;
    let (slice_type, idr, slice_pps) = slice?;
    let (pps_id, pps_sps) = pps?;
    if pps_sps != sps_id || slice_pps != pps_id {
        return None;
    }
    Some(Picture {
        width,
        height,
        profile,
        slice_type,
        idr,
    })
}
