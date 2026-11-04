// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! BlockAck CAM, version 1 (BE generation) — H2C encoding + slot map.
//!
//! Mirrors Linux `rtw89/fw.c` `rtw89_fw_h2c_ba_cam_v1` and
//! `rtw89/core.c` `rtw89_core_acquire_sta_ba_entry` /
//! `rtw89_core_release_sta_ba_entry` (torvalds/linux @ 05441d6 —
//! the sparse-clone reference; the flat cbbddb6 clone carries
//! `fw.h`'s struct but not `fw.c`, so the builder body is
//! grounded in the 05441d6 tree, same caveat as the WCN6750
//! lane). Struct and bitfields: `fw.h:1942..1957` (identical
//! in both clones).
//!
//! `struct rtw89_h2c_ba_cam_v1` is two little-endian words:
//! w0 = VALID bit 0 | INIT_REQ bit 1 | TID bits 7:4 | MACID
//! bits 15:8 | BMAP_SIZE bits 19:16 | SSN bits 31:20;
//! w1 = UID bits 7:0 (unused here, Linux leaves it zero) |
//! STD_ENTRY_EN bit 8 | BAND_SEL bit 9 | MLD_EN bit 10 |
//! ENTRY_IDX bits 31:24. The entry index Linux writes is the
//! bitmap index PLUS `chip->bacam_dynamic_num` ("std entry
//! right after dynamic ones", `fw.c:2985`); for 8922A the
//! dynamic count is 8 (`rtw8922a.c:3287`, chip-row container).
//!
//! Bitmap-size tiers (`fw.c:2970`): buf_size > 512 → 10,
//! > 256 → 8, > 64 → 4, else 0.
//!
//! Slot map (`core.c:5597,5643`): a bitmap of `bacam_num`
//! entries. Acquire takes the lowest free index; when full,
//! a TID 0 or 5 request evicts the lowest-index entry whose
//! TID is neither 0 nor 5 ("hardware will process the
//! original tid automatically"); any other TID on a full map
//! fails. Release frees the entry for a (station, TID) pair.
//! This module models the bitmap + TID table; the per-station
//! list lookup is the caller's job, so [`BaCam::release`]
//! takes the index directly.
//!
//! Deliberate difference from Linux: field values outside
//! their bitfield width are REJECTED instead of truncated
//! (Linux's `le32_encode_bits` silently drops overflow bits).
//! A TID above 15 or an SSN above 4095 would otherwise corrupt
//! adjacent fields; fail closed instead.

/// H2C BA-CAM v1 payload: two little-endian words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct BaCamH2c {
    /// w0 (see module docs).
    pub w0: u32,
    /// w1 (see module docs).
    pub w1: u32,
}

/// Errors from BA-CAM encoding and allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    /// A field value exceeds its bitfield width.
    BadValue,
    /// No slot free and no evictable entry (see module docs).
    NoSpace,
    /// Release of an index that is not allocated.
    NotFound,
}

/// Bitmap-size tier for an AMPDU buffer size
/// (`fw.c:2970..2977`).
pub(super) fn bmap_size(buf_size: u32) -> u32 {
    if buf_size > 512 {
        10
    } else if buf_size > 256 {
        8
    } else if buf_size > 64 {
        4
    } else {
        0
    }
}

/// Encode the BA-CAM v1 H2C payload.
///
/// * `valid` — allocate (true) or free (false) the entry.
/// * `macid` — station MAC ID, bits 15:8.
/// * `tid` — traffic identifier, bits 7:4.
/// * `bmap_size` — from [`bmap_size`], bits 19:16.
/// * `ssn` — starting sequence number, bits 31:20.
/// * `bitmap_idx` — slot-map index; the written entry index
///   is `bitmap_idx + dynamic_num`.
/// * `dynamic_num` — `chip->bacam_dynamic_num` (8 for 8922A).
/// * `mld` — MLD enable, bit 10.
/// * `band_sel` — `mac_idx != 0`, bit 9.
#[allow(clippy::too_many_arguments)]
pub(super) fn build_h2c(
    valid: bool,
    macid: u32,
    tid: u32,
    bmap_size: u32,
    ssn: u32,
    bitmap_idx: u32,
    dynamic_num: u32,
    mld: bool,
    band_sel: bool,
) -> Result<BaCamH2c, Error> {
    if macid > 0xFF || tid > 0xF || bmap_size > 0xF || ssn > 0xFFF {
        return Err(Error::BadValue);
    }
    let entry_idx = bitmap_idx
        .checked_add(dynamic_num)
        .filter(|idx| *idx <= 0xFF)
        .ok_or(Error::BadValue)?;
    let w0 =
        (valid as u32) | (1 << 1) | (tid << 4) | (macid << 8) | (bmap_size << 16) | (ssn << 20);
    let w1 = (1 << 8) | ((band_sel as u32) << 9) | ((mld as u32) << 10) | (entry_idx << 24);
    Ok(BaCamH2c { w0, w1 })
}

/// BA-CAM slot map: one TID per entry, `None` = free.
/// `num` is `chip->bacam_num` (24 for 8922A).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct BaCam {
    /// TID recorded per slot, or `None` when free.
    slots: [Option<u8>; 24],
    /// Number of usable slots (≤ 24).
    num: usize,
}

impl BaCam {
    /// Empty map with `num` slots. `num` above 24 is rejected
    /// (the backing array is the 8922A maximum).
    pub(super) fn new(num: usize) -> Result<Self, Error> {
        if num == 0 || num > 24 {
            return Err(Error::BadValue);
        }
        Ok(Self {
            slots: [None; 24],
            num,
        })
    }

    /// Acquire a slot for `tid`, following Linux
    /// (`core.c:5597`): lowest free index; on a full map, a
    /// TID 0 or 5 request evicts the lowest-index entry whose
    /// TID is neither 0 nor 5. Returns the bitmap index (the
    /// H2C entry index is this plus `dynamic_num`).
    pub(super) fn acquire(&mut self, tid: u8) -> Result<usize, Error> {
        if tid > 15 {
            return Err(Error::BadValue);
        }
        for idx in 0..self.num {
            if self.slots[idx].is_none() {
                self.slots[idx] = Some(tid);
                return Ok(idx);
            }
        }
        if tid != 0 && tid != 5 {
            return Err(Error::NoSpace);
        }
        for idx in 0..self.num {
            match self.slots[idx] {
                Some(old) if old != 0 && old != 5 => {
                    self.slots[idx] = Some(tid);
                    return Ok(idx);
                }
                _ => {}
            }
        }
        Err(Error::NoSpace)
    }

    /// Release slot `idx`. The caller owns the (station, TID)
    /// lookup; this only frees the bitmap entry.
    pub(super) fn release(&mut self, idx: usize) -> Result<(), Error> {
        if idx >= self.num || self.slots[idx].is_none() {
            return Err(Error::NotFound);
        }
        self.slots[idx] = None;
        Ok(())
    }

    /// TID recorded at `idx`, or `None` when free/out of range.
    pub(super) fn tid_at(&self, idx: usize) -> Option<u8> {
        if idx >= self.num {
            return None;
        }
        self.slots[idx]
    }
}
