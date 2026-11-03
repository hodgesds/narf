//! Display-14.00 DBUF slices, MBUS joining and per-pipe/per-plane DDB.
//!
//! MIT Linux b90c984d `display/skl_watermark.c`, display 14 (not DG2):
//! `adlp_allowed_dbufs`, `adlp_check_mbus_joined`, `compute_dbuf_slices`,
//! `intel_dbuf_enabled_slices` (S1 always on), `skl_ddb_entry_for_slices`,
//! `mbus_ddb_offset`, `intel_crtc_ddb_weight` (hdisplay),
//! `intel_crtc_dbuf_weights`, `skl_crtc_allocate_ddb`,
//! `skl_crtc_allocate_plane_ddb` (cursor at the end, highest satisfiable
//! level, proportional extra by relative data rate, post-allocation level,
//! transition and SAGV checks and `skl_need_wm_copy_wa`),
//! `pipe_mbus_dbox_ctl` (`DISPLAY_VERx100 == 1400`), `mbus_ctl_join_update`,
//! `intel_dbuf_mdclk_cdclk_ratio_update` (MDCLK from CD2XCLK below display
//! 20: ratio 2, doubled when joined) and `skl_ddb_dbuf_slice_mask`.
//! `intel_dbuf_bw.c::intel_dbuf_bw_min_cdclk` supplies the DBUF bandwidth
//! CDCLK floor. `intel_display_device.c` XE_LPDP: 4096 blocks in four slices.
//! Register layout: `skl_watermark_regs.h`, `skl_universal_plane_regs.h`,
//! `intel_cursor_regs.h`.

use crate::intel_gpu_xelpg_wm::{Level, PlaneWm, LEVELS};

pub(crate) const PIPES: usize = 4;
/// Universal planes per pipe on display 14 (PLANE_1..PLANE_5).
pub(crate) const PLANES: usize = 5;
pub(crate) const DBUF_SIZE: u16 = 4096;
pub(crate) const SLICES: usize = 4;
const SLICE_SIZE: u16 = DBUF_SIZE / SLICES as u16;
const S1: u8 = 1 << 0;
const S2: u8 = 1 << 1;
const S3: u8 = 1 << 2;
const S4: u8 = 1 << 3;
const A: u8 = 1 << 0;
const B: u8 = 1 << 1;
const C: u8 = 1 << 2;
const D: u8 = 1 << 3;

/// `DBUF_CTL_S(slice)`.
pub(crate) const DBUF_CTL: [u64; SLICES] = [0x45008, 0x44fe8, 0x44300, 0x44304];
pub(crate) const DBUF_POWER_REQUEST: u32 = 1 << 31;
pub(crate) const DBUF_POWER_STATE: u32 = 1 << 30;
/// `DBUF_TRACKER_STATE_SERVICE_MASK` | `DBUF_MIN_TRACKER_STATE_SERVICE_MASK`.
pub(crate) const DBUF_TRACKER_MASK: u32 = 0x00ff_0000;
/// `MBUS_CTL`.
pub(crate) const MBUS_CTL: u64 = 0x4438c;
/// MBUS_JOIN | MBUS_HASHING_MODE_MASK | MBUS_JOIN_PIPE_SELECT_MASK.
pub(crate) const MBUS_CTL_MASK: u32 = (1 << 31) | (1 << 30) | (7 << 26);
/// `PIPE_MBUS_DBOX_CTL(pipe)`.
pub(crate) const fn dbox_ctl(pipe: usize) -> u64 {
    0x7003c + pipe as u64 * 0x1000
}

struct Conf {
    active: u8,
    mask: [u8; PIPES],
    join: bool,
}

const fn conf(active: u8, mask: [u8; PIPES], join: bool) -> Conf {
    Conf { active, mask, join }
}

const AB: u8 = S1 | S2;
const CD: u8 = S3 | S4;
/// `adlp_allowed_dbufs`, join cases first.
const ALLOWED: [Conf; 17] = [
    conf(A, [AB | CD, 0, 0, 0], true),
    conf(B, [0, AB | CD, 0, 0], true),
    conf(A, [AB, 0, 0, 0], false),
    conf(B, [0, CD, 0, 0], false),
    conf(A | B, [AB, CD, 0, 0], false),
    conf(C, [0, 0, CD, 0], false),
    conf(A | C, [AB, 0, CD, 0], false),
    conf(B | C, [0, CD, CD, 0], false),
    conf(A | B | C, [AB, CD, CD, 0], false),
    conf(D, [0, 0, 0, AB], false),
    conf(A | D, [AB, 0, 0, AB], false),
    conf(B | D, [0, CD, 0, AB], false),
    conf(A | B | D, [AB, CD, 0, AB], false),
    conf(C | D, [0, 0, CD, AB], false),
    conf(A | C | D, [AB, 0, CD, AB], false),
    conf(B | C | D, [0, CD, CD, AB], false),
    conf(A | B | C | D, [AB, CD, CD, AB], false),
];

/// `adlp_check_mbus_joined`.
pub(crate) fn mbus_joined(active_pipes: u8) -> bool {
    ALLOWED
        .iter()
        .find(|c| c.active == active_pipes)
        .is_some_and(|c| c.join)
}

/// `compute_dbuf_slices` over `adlp_allowed_dbufs`.
pub(crate) fn dbuf_slices(pipe: usize, active_pipes: u8, join: bool) -> u8 {
    ALLOWED
        .iter()
        .find(|c| c.active == active_pipes && c.join == join)
        .map_or(0, |c| c.mask[pipe])
}

/// A DDB range `[start, end)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) start: u16,
    pub(crate) end: u16,
}

impl Entry {
    pub(crate) fn size(self) -> u16 {
        self.end - self.start
    }
    /// `skl_plane_ddb_reg_val`: END is inclusive, zero for an empty entry.
    pub(crate) fn reg(self) -> u32 {
        if self.end == 0 {
            0
        } else {
            (u32::from(self.end - 1) << 16) | u32::from(self.start)
        }
    }
    fn overlaps(self, other: Entry) -> bool {
        self.size() != 0 && other.size() != 0 && self.start < other.end && other.start < self.end
    }
}

fn for_slices(mask: u8) -> Entry {
    if mask == 0 {
        return Entry::default();
    }
    Entry {
        start: mask.trailing_zeros() as u16 * SLICE_SIZE,
        end: (8 - mask.leading_zeros()) as u16 * SLICE_SIZE,
    }
}

/// `mbus_ddb_offset`.
fn mbus_offset(mask: u8) -> u16 {
    if mask & (S1 | S2) != 0 {
        for_slices(S1).start
    } else if mask & (S3 | S4) != 0 {
        for_slices(S3).start
    } else {
        0
    }
}

/// `skl_ddb_dbuf_slice_mask` (applied, as in Linux, to the given entry).
pub(crate) fn slice_mask(entry: Entry) -> u8 {
    if entry.size() == 0 {
        return 0;
    }
    let first = entry.start / SLICE_SIZE;
    let last = (entry.end - 1) / SLICE_SIZE;
    (first..=last).fold(0, |m, s| m | (1 << s))
}

/// One universal plane's computed input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PlaneInput {
    pub(crate) wm: PlaneWm,
    /// `skl_plane_relative_data_rate`: width * height * cpp.
    pub(crate) rel_data_rate: u64,
    /// `intel_plane_data_rate`: pixel rate (kHz) * cpp.
    pub(crate) data_rate: u32,
}

/// One active pipe's computed input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PipeInput {
    /// `intel_crtc_ddb_weight`.
    pub(crate) hdisplay: u16,
    pub(crate) planes: [Option<PlaneInput>; PLANES],
    /// `skl_cursor_allocation` result.
    pub(crate) cursor_alloc: u16,
    /// Watermarks of a visible cursor; constrains level selection.
    pub(crate) cursor_wm: PlaneWm,
}

/// One pipe's allocation and final watermarks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PipeAlloc {
    /// MBUS-relative pipe DDB (`dbuf_state->ddb[pipe]`).
    pub(crate) ddb: Entry,
    /// Absolute DDB (`crtc_state->wm.skl.ddb`).
    pub(crate) absolute: Entry,
    pub(crate) planes: [Entry; PLANES],
    pub(crate) cursor: Entry,
    pub(crate) wm: [PlaneWm; PLANES],
    pub(crate) cursor_wm: PlaneWm,
    /// Highest level satisfied for every plane.
    pub(crate) level: usize,
}

/// The global DBUF state (`struct intel_dbuf_state`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Dbuf {
    pub(crate) active_pipes: u8,
    pub(crate) joined: bool,
    pub(crate) slices: [u8; PIPES],
    pub(crate) enabled_slices: u8,
    pub(crate) pipes: [PipeAlloc; PIPES],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DdbError {
    /// No active pipe, or an active pipe without a slice assignment.
    Unsupported,
    /// "Requested display configuration exceeds system DDB limitations".
    Exhausted,
    /// Absolute pipe allocations would overlap.
    Overlap,
}

fn check(level: &mut Level, ddb: Entry) {
    // skl_check_wm_level.
    if level.min_ddb_alloc > ddb.size() {
        *level = Level::default();
    }
}

/// `skl_crtc_allocate_plane_ddb` for one pipe.
fn allocate_planes(input: &PipeInput, alloc_ddb: Entry) -> Result<PipeAlloc, DdbError> {
    let mut out = PipeAlloc {
        ddb: alloc_ddb,
        ..Default::default()
    };
    for (i, p) in input.planes.iter().enumerate() {
        if let Some(p) = p {
            out.wm[i] = p.wm;
        }
    }
    out.cursor_wm = input.cursor_wm;
    let mut start = alloc_ddb.start;
    let mut size = alloc_ddb.size();
    if size == 0 {
        return Err(DdbError::Unsupported);
    }
    let cursor = input.cursor_alloc;
    if cursor > size {
        return Err(DdbError::Exhausted);
    }
    size -= cursor;
    out.cursor = Entry {
        start: alloc_ddb.end - cursor,
        end: alloc_ddb.end,
    };
    let mut data_rate: u64 = input.planes.iter().flatten().map(|p| p.rel_data_rate).sum();
    let mut found = None;
    for level in (0..LEVELS).rev() {
        if out.cursor_wm.levels[level].min_ddb_alloc > out.cursor.size() {
            continue;
        }
        let blocks: u32 = out
            .wm
            .iter()
            .map(|w| u32::from(w.levels[level].min_ddb_alloc))
            .sum();
        if blocks <= u32::from(size) {
            size -= blocks as u16;
            found = Some(level);
            break;
        }
    }
    let level = found.ok_or(DdbError::Exhausted)?;
    out.level = level;
    if data_rate == 0 {
        size = 0;
    }
    for (i, p) in input.planes.iter().enumerate() {
        let rate = p.map_or(0, |p| p.rel_data_rate);
        let mut extra = 0u16;
        if rate != 0 && data_rate != 0 {
            extra = size.min((u64::from(size) * rate).div_ceil(data_rate) as u16);
            size -= extra;
            data_rate -= rate;
        }
        let blocks = out.wm[i].levels[level].min_ddb_alloc + extra;
        if blocks != 0 {
            out.planes[i] = Entry {
                start,
                end: start + blocks,
            };
            start += blocks;
        }
    }
    let cursor = out.cursor;
    let planes = out.planes;
    let all = out
        .wm
        .iter_mut()
        .zip(planes)
        .chain(core::iter::once((&mut out.cursor_wm, cursor)));
    for (wm, ddb) in all {
        // Levels above the selected one: skl_check_wm_level, then
        // skl_need_wm_copy_wa keeps disabled levels' blocks/lines sane.
        for l in level + 1..LEVELS {
            check(&mut wm.levels[l], ddb);
            if !wm.levels[l].enable {
                wm.levels[l].blocks = wm.levels[l - 1].blocks;
                wm.levels[l].lines = wm.levels[l - 1].lines;
            }
        }
        check(&mut wm.trans, ddb);
        check(&mut wm.sagv, ddb);
        check(&mut wm.sagv_trans, ddb);
    }
    Ok(out)
}

/// `skl_compute_ddb` for a complete new pipe set (every pipe is part of
/// the transaction).
pub(crate) fn compute(pipes: &[Option<PipeInput>; PIPES]) -> Result<Dbuf, DdbError> {
    let active_pipes = pipes
        .iter()
        .enumerate()
        .filter(|(_, p)| p.is_some())
        .fold(0u8, |m, (i, _)| m | (1 << i));
    if active_pipes == 0 {
        return Err(DdbError::Unsupported);
    }
    let joined = mbus_joined(active_pipes);
    let mut out = Dbuf {
        active_pipes,
        joined,
        ..Default::default()
    };
    for (pipe, slices) in out.slices.iter_mut().enumerate() {
        *slices = dbuf_slices(pipe, active_pipes, joined);
    }
    out.enabled_slices = out.slices.iter().fold(S1, |m, s| m | s);
    let weight = |p: usize| pipes[p].map_or(0u32, |p| u32::from(p.hdisplay));
    for (pipe, input) in pipes.iter().enumerate() {
        let Some(input) = input else { continue };
        let mask = out.slices[pipe];
        if mask == 0 || input.hdisplay == 0 {
            return Err(DdbError::Unsupported);
        }
        let range = for_slices(mask);
        let offset = mbus_offset(mask);
        let (mut ws, mut we, mut wt) = (0u32, 0u32, 0u32);
        for (other, slices) in out.slices.iter().enumerate() {
            if *slices != mask {
                continue;
            }
            let w = weight(other);
            wt += w;
            if other < pipe {
                ws += w;
                we += w;
            } else if other == pipe {
                we += w;
            }
        }
        let size = u32::from(range.size());
        let ddb = Entry {
            start: range.start - offset + (size * ws / wt) as u16,
            end: range.start - offset + (size * we / wt) as u16,
        };
        let mut alloc = allocate_planes(input, ddb)?;
        alloc.absolute = Entry {
            start: offset + ddb.start,
            end: offset + ddb.end,
        };
        out.pipes[pipe] = alloc;
    }
    for (a, first) in out.pipes.iter().enumerate() {
        if out.pipes[a + 1..]
            .iter()
            .any(|second| first.absolute.overlaps(second.absolute))
        {
            return Err(DdbError::Overlap);
        }
    }
    Ok(out)
}

impl Dbuf {
    /// `mbus_ctl_join_update` with every pipe needing a modeset
    /// (`MBUS_JOIN_PIPE_SELECT_NONE`).
    pub(crate) fn mbus_ctl(&self) -> u32 {
        let base = if self.joined {
            (1 << 31) | (1 << 30)
        } else {
            0
        };
        base | (7 << 26)
    }

    /// `pipe_mbus_dbox_ctl` for display 14.00.
    pub(crate) fn dbox(&self, pipe: usize) -> u32 {
        let mut v = 2 << 5; // I_CREDIT(2)
        v |= (16 << 20) | (1 << 17) | (1 << 16); // B2B max 16, delay 1, regulate
        v |= if self.joined { 12 } else { 8 }; // A_CREDIT
        v |= 0xa << 8; // B_CREDIT
        let bank = match pipe {
            0 | 3 => self.active_pipes & (A | D),
            _ => self.active_pipes & (B | C),
        };
        v |= if bank.is_power_of_two() {
            3 << 14
        } else {
            2 << 14
        };
        v
    }

    /// `DBUF_CTL_S(slice)` value over `old`: request per the enabled mask,
    /// `DBUF_TRACKER_STATE_SERVICE(8)` (`gen12_dbuf_slices_config`) and the
    /// MDCLK/CDCLK minimum tracker (ratio 2, doubled when joined).
    pub(crate) fn dbuf_ctl(&self, slice: usize, old: u32, enabled: u8) -> u32 {
        let ratio = if self.joined { 4 } else { 2 };
        let request = if enabled & (1 << slice) != 0 {
            DBUF_POWER_REQUEST
        } else {
            0
        };
        (old & !(DBUF_POWER_REQUEST | DBUF_POWER_STATE | DBUF_TRACKER_MASK))
            | request
            | (8 << 19)
            | ((ratio - 1) << 16)
    }

    /// `intel_dbuf_bw_min_cdclk` from per-plane data rates.
    pub(crate) fn bw_min_cdclk(&self, pipes: &[Option<PipeInput>; PIPES]) -> u32 {
        let mut max_bw = [0u32; SLICES];
        let mut planes = [0u32; SLICES];
        for (pipe, input) in pipes.iter().enumerate() {
            let Some(input) = input else { continue };
            for (i, plane) in input.planes.iter().enumerate() {
                let Some(plane) = plane else { continue };
                let mask = slice_mask(self.pipes[pipe].planes[i]);
                for (s, (bw, n)) in max_bw.iter_mut().zip(planes.iter_mut()).enumerate() {
                    if mask & (1 << s) != 0 {
                        *bw = (*bw).max(plane.data_rate);
                        *n += 1;
                    }
                }
            }
        }
        let total = max_bw
            .iter()
            .zip(planes.iter())
            .map(|(bw, n)| u64::from(*bw) * u64::from(*n))
            .max()
            .unwrap_or(0);
        total.div_ceil(64).min(u64::from(u32::MAX)) as u32
    }
}
