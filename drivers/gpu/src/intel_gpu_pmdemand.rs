//! Display-14 PM demand requests.
//!
//! MIT Linux b90c984d `display/intel_pmdemand.c`:
//! `intel_pmdemand_atomic_check` (parameter derivation, pre-Xe3 fields),
//! `intel_pmdemand_check_prev_transaction`, `intel_pmdemand_init_pmdemand_params`,
//! `intel_pmdemand_update_params` (serialized: pre-plane max(old, new),
//! post-plane new), `intel_pmdemand_program_params` (write only on change,
//! then `REQ_ENABLE` and completion). Registers from `intel_display_regs.h`
//! (`XELPDP_INITIATE_PMDEMAND_REQUEST`, `GEN12_DCPR_STATUS_1`,
//! `GEN8_DE_MISC_IIR.XELPDP_PMDEMAND_RSPTOUT_ERR`). MTL waits on the
//! response interrupt; this owner polls the same `REQ_ENABLE` completion
//! the LNL path uses and additionally refuses a latched response timeout.
//! `intel_bw.c::mtl_find_qgv_points` supplies `qclk_gv_bw`: `U16_MAX`
//! whenever SAGV is not enabled.
//!
//! Display 30 (Xe3_LPD) uses the [`Layout::Xe3`] field set
//! (`intel_pmdemand_update_params` / `intel_pmdemand_init_pmdemand_params`,
//! `DISPLAY_VER >= 30`): a 4-bit `XE3_PMDEMAND_PIPES_MASK` (7:4) holding
//! `min(active pipes, INTEL_NUM_PIPES)` replaces the 2-bit pipes field and
//! the DBUF slice count, and the scaler count is not tracked; the `_for`
//! entry points take it. Display 14 and 20 keep the pre-Xe3 entry points.

use crate::intel_gpu_aux::MmioWindow;
use narf_filesystem::FsError;

pub(crate) const REQUEST0: u64 = 0x45230;
pub(crate) const REQUEST1: u64 = 0x45234;
/// `GEN12_DCPR_STATUS_1`.
pub(crate) const DCPR_STATUS_1: u64 = 0x46440;
/// `GEN8_DE_MISC_IIR`.
pub(crate) const DE_MISC_IIR: u64 = 0x44468;
pub(crate) const REQ_ENABLE: u32 = 1 << 31;
pub(crate) const INFLIGHT: u32 = 1 << 26;
pub(crate) const RSPTOUT_ERR: u32 = 1 << 27;

/// `struct pmdemand_params` (display 14, pre-Xe3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Params {
    pub(crate) qclk_gv_bw: u16,
    pub(crate) voltage_index: u8,
    pub(crate) qclk_gv_index: u8,
    pub(crate) active_pipes: u8,
    pub(crate) active_dbufs: u8,
    pub(crate) active_phys: u8,
    pub(crate) plls: u8,
    pub(crate) cdclk_freq_mhz: u16,
    pub(crate) ddiclk_max: u16,
    pub(crate) scalers: u8,
}

// (register, shift, mask) per field.
const FIELDS: [(bool, u32, u32); 10] = [
    (false, 16, 0xffff), // QCLK_GV_BW
    (false, 12, 0x7),    // VOLTAGE_INDEX
    (false, 8, 0xf),     // QCLK_GV_INDEX
    (false, 6, 0x3),     // PIPES
    (false, 4, 0x3),     // DBUFS
    (false, 0, 0x7),     // PHYS
    (true, 20, 0x7ff),   // CDCLK_FREQ
    (true, 8, 0x7ff),    // DDICLK_FREQ
    (true, 4, 0x7),      // SCALERS
    (true, 0, 0x7),      // PLLS
];

/// The PM demand field layout of a display IP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Layout {
    /// Display 14 and 20: `XELPDP_PMDEMAND_PIPES_MASK` (7:6),
    /// `XELPDP_PMDEMAND_DBUFS_MASK` (5:4) and `XELPDP_PMDEMAND_SCALERS_MASK`.
    PreXe3,
    /// Display >= 30: `XE3_PMDEMAND_PIPES_MASK` (7:4), no DBUFS or SCALERS.
    Xe3,
}

impl Layout {
    pub(crate) const fn for_ip(ip: crate::intel_gpu_xe2lpd::DisplayIp) -> Self {
        match ip {
            crate::intel_gpu_xe2lpd::DisplayIp::Xe3Lpd => Self::Xe3,
            _ => Self::PreXe3,
        }
    }
}

// (index into Params::values, second register, shift, mask) per Xe3 field.
const XE3_FIELDS: [(usize, bool, u32, u32); 8] = [
    (0, false, 16, 0xffff), // QCLK_GV_BW
    (1, false, 12, 0x7),    // VOLTAGE_INDEX
    (2, false, 8, 0xf),     // QCLK_GV_INDEX
    (3, false, 4, 0xf),     // XE3_PMDEMAND_PIPES
    (5, false, 0, 0x7),     // PHYS
    (6, true, 20, 0x7ff),   // CDCLK_FREQ
    (7, true, 8, 0x7ff),    // DDICLK_FREQ
    (9, true, 0, 0x7),      // PLLS
];

impl Params {
    fn values(&self) -> [u32; 10] {
        [
            u32::from(self.qclk_gv_bw),
            u32::from(self.voltage_index),
            u32::from(self.qclk_gv_index),
            u32::from(self.active_pipes),
            u32::from(self.active_dbufs),
            u32::from(self.active_phys),
            u32::from(self.cdclk_freq_mhz),
            u32::from(self.ddiclk_max),
            u32::from(self.scalers),
            u32::from(self.plls),
        ]
    }

    fn from_values(v: [u32; 10]) -> Self {
        Self {
            qclk_gv_bw: v[0] as u16,
            voltage_index: v[1] as u8,
            qclk_gv_index: v[2] as u8,
            active_pipes: v[3] as u8,
            active_dbufs: v[4] as u8,
            active_phys: v[5] as u8,
            cdclk_freq_mhz: v[6] as u16,
            ddiclk_max: v[7] as u16,
            scalers: v[8] as u8,
            plls: v[9] as u8,
        }
    }

    /// `intel_pmdemand_init_pmdemand_params` field extraction.
    pub(crate) fn decode(reg0: u32, reg1: u32) -> Self {
        let mut v = [0; 10];
        for (i, (second, shift, mask)) in FIELDS.into_iter().enumerate() {
            v[i] = ((if second { reg1 } else { reg0 }) >> shift) & mask;
        }
        Self::from_values(v)
    }

    /// `intel_pmdemand_init_pmdemand_params` field extraction for `layout`
    /// (fields a layout does not carry decode as zero).
    pub(crate) fn decode_for(layout: Layout, reg0: u32, reg1: u32) -> Self {
        match layout {
            Layout::PreXe3 => Self::decode(reg0, reg1),
            Layout::Xe3 => {
                let mut v = [0; 10];
                for (i, second, shift, mask) in XE3_FIELDS {
                    v[i] = ((if second { reg1 } else { reg0 }) >> shift) & mask;
                }
                Self::from_values(v)
            }
        }
    }

    /// [`Params::apply`] for `layout`: only the layout's fields are
    /// updated, every other bit of both registers is kept.
    pub(crate) fn apply_for(&self, layout: Layout, reg0: u32, reg1: u32) -> (u32, u32) {
        match layout {
            Layout::PreXe3 => self.apply(reg0, reg1),
            Layout::Xe3 => {
                let (mut r0, mut r1) = (reg0, reg1);
                let values = self.values();
                for (i, second, shift, mask) in XE3_FIELDS {
                    let reg = if second { &mut r1 } else { &mut r0 };
                    *reg = (*reg & !(mask << shift)) | (values[i].min(mask) << shift);
                }
                (r0, r1)
            }
        }
    }

    /// Field-wise maximum (`max3(old, new, 0)` when serialized).
    pub(crate) fn max(&self, other: &Self) -> Self {
        let (mut v, b) = (self.values(), other.values());
        for (a, b) in v.iter_mut().zip(b) {
            *a = (*a).max(b);
        }
        Self::from_values(v)
    }

    /// `intel_pmdemand_update_params` applied to the current register pair.
    /// Values are clamped to their fields the way `REG_FIELD_PREP` masks.
    pub(crate) fn apply(&self, reg0: u32, reg1: u32) -> (u32, u32) {
        let (mut r0, mut r1) = (reg0, reg1);
        for ((second, shift, mask), value) in FIELDS.into_iter().zip(self.values()) {
            let reg = if second { &mut r1 } else { &mut r0 };
            *reg = (*reg & !(mask << shift)) | ((value.min(mask)) << shift);
        }
        (r0, r1)
    }
}

/// Inputs for `intel_pmdemand_atomic_check`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Demand {
    /// `intel_bw_qgv_point_peakbw`; `None` means SAGV is not enabled.
    pub(crate) qgv_peak_bw: Option<u16>,
    pub(crate) enabled_slices: u8,
    pub(crate) active_pipes: u8,
    /// `intel_cdclk_actual_voltage_level`.
    pub(crate) voltage_level: u8,
    pub(crate) cdclk_khz: u32,
    pub(crate) max_port_clock_khz: u32,
    /// Non-Type-C PHY mask (`active_combo_phys_mask`).
    pub(crate) combo_phys: u16,
}

impl Demand {
    pub(crate) fn params(&self) -> Params {
        let active_phys = (self.combo_phys.count_ones() as u8).min(7);
        Params {
            qclk_gv_bw: self.qgv_peak_bw.unwrap_or(u16::MAX),
            qclk_gv_index: 0,
            active_dbufs: (self.enabled_slices.count_ones() as u8).min(3),
            active_pipes: (self.active_pipes.count_ones() as u8).min(3),
            voltage_index: self.voltage_level,
            cdclk_freq_mhz: self.cdclk_khz.div_ceil(1000) as u16,
            ddiclk_max: self.max_port_clock_khz.div_ceil(1000) as u16,
            active_phys,
            plls: (active_phys + 1).min(7),
            scalers: 7,
        }
    }

    /// `intel_pmdemand_atomic_check` for `layout`. On display >= 30 the
    /// pipe count is `min(active pipes, INTEL_NUM_PIPES)` (four pipes on
    /// `xe2_lpd_display`) and neither the DBUF slices nor the scalers are
    /// tracked: they stay zero, as [`Params::decode_for`] reads them.
    pub(crate) fn params_for(&self, layout: Layout) -> Params {
        let params = self.params();
        match layout {
            Layout::PreXe3 => params,
            Layout::Xe3 => Params {
                active_pipes: (self.active_pipes.count_ones() as u8).min(4),
                active_dbufs: 0,
                scalers: 0,
                ..params
            },
        }
    }
}

fn read(io: &(impl MmioWindow + ?Sized), r: u64) -> Result<u32, FsError> {
    let v = io.read32(r);
    if v == u32::MAX || !io.display_access_ok() {
        Err(FsError::NoDevice)
    } else {
        Ok(v)
    }
}

fn wait_clear(io: &(impl MmioWindow + ?Sized), r: u64, bit: u32) -> Result<(), FsError> {
    let mut lost = false;
    let done = narf_scheduler::responsive_spin_until(
        || {
            let v = io.read32(r);
            lost = v == u32::MAX || !io.display_access_ok();
            lost || v & bit == 0
        },
        narf_time::Deadline::after_ms(10),
    );
    if lost {
        Err(FsError::NoDevice)
    } else if done {
        Ok(())
    } else {
        Err(FsError::TimedOut)
    }
}

/// `intel_pmdemand_check_prev_transaction`.
pub(crate) fn wait_idle(io: &(impl MmioWindow + ?Sized)) -> Result<(), FsError> {
    wait_clear(io, REQUEST1, REQ_ENABLE)?;
    wait_clear(io, DCPR_STATUS_1, INFLIGHT)
}

/// Current parameters after the previous transaction completed.
pub(crate) fn current(io: &(impl MmioWindow + ?Sized)) -> Result<Params, FsError> {
    wait_idle(io)?;
    Ok(Params::decode(read(io, REQUEST0)?, read(io, REQUEST1)?))
}

/// [`current`] decoded with `layout`.
pub(crate) fn current_for(
    io: &(impl MmioWindow + ?Sized),
    layout: Layout,
) -> Result<Params, FsError> {
    wait_idle(io)?;
    Ok(Params::decode_for(
        layout,
        read(io, REQUEST0)?,
        read(io, REQUEST1)?,
    ))
}

/// `intel_pmdemand_program_params(new, old, serialized = true)`: the
/// pre-plane request uses `old = Some`, the post-plane one `None`. Returns
/// whether a request was initiated. The resulting request is proved by
/// readback, completion and the absence of a response timeout.
pub(crate) fn program(
    io: &(impl MmioWindow + ?Sized),
    new: &Params,
    old: Option<&Params>,
) -> Result<bool, FsError> {
    program_for(io, Layout::PreXe3, new, old)
}

/// [`program`] with `layout`'s fields. Display 30 waits for the request
/// the same way (`intel_pmdemand_wait`: only display 20 polls in Linux,
/// every other display waits for the response interrupt on the same
/// `REQ_ENABLE` completion this owner polls).
pub(crate) fn program_for(
    io: &(impl MmioWindow + ?Sized),
    layout: Layout,
    new: &Params,
    old: Option<&Params>,
) -> Result<bool, FsError> {
    wait_idle(io)?;
    let reg0 = read(io, REQUEST0)?;
    let reg1 = read(io, REQUEST1)?;
    let target = old.map_or(*new, |old| old.max(new));
    let (mod0, mod1) = target.apply_for(layout, reg0, reg1);
    if mod0 == reg0 && mod1 == reg1 {
        return Ok(false);
    }
    if mod0 != reg0 {
        io.write32(REQUEST0, mod0);
    }
    if mod1 != reg1 {
        io.write32(REQUEST1, mod1);
    }
    if read(io, REQUEST0)? != mod0 || read(io, REQUEST1)? != mod1 {
        return Err(FsError::NoDevice);
    }
    io.write32(REQUEST1, mod1 | REQ_ENABLE);
    wait_clear(io, REQUEST1, REQ_ENABLE)?;
    wait_clear(io, DCPR_STATUS_1, INFLIGHT)?;
    if read(io, REQUEST0)? != mod0
        || read(io, REQUEST1)? != mod1
        || read(io, DE_MISC_IIR)? & RSPTOUT_ERR != 0
    {
        return Err(FsError::NoDevice);
    }
    Ok(true)
}
