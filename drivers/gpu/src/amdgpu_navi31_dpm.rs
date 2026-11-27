//! Navi31 DPM/fan message builders and DPM-table decoding (SMU 13.0.0).
//!
//! Message ids are Linux smu_v13_0_0_ppsmc.h; the clock map is
//! smu_v13_0_0_ppt.c's `smu_v13_0_0_clk_map`; the frequency argument
//! encoding `(ppclk << 16) | (mhz & 0xffff)` is
//! smu_v13_0_set_soft_freq_limited_range, with 0xffff meaning automatic
//! (Linux `SMU_V13_SOFT_FREQ_ROUND` aside, the round is a no-op for the
//! values this module admits). These are pure request values: the retained
//! SMU owner (lane 2, #2464) sends them through the mailbox, and no code
//! here touches the mailbox or the registers.
//!
//! Fan sequences live in the thermal monitor (`amdgpu_navi31_thermal`),
//! which owns the THM register bank; the only fan item here is the
//! `SetMGpuFanBoostLimitRpm` message.

/// PPSMC message ids, smu_v13_0_0_ppsmc.h.
pub const MSG_SET_SOFT_MIN_BY_FREQ: u32 = 0x19;
pub const MSG_SET_SOFT_MAX_BY_FREQ: u32 = 0x1a;
pub const MSG_SET_HARD_MIN_BY_FREQ: u32 = 0x1b;
pub const MSG_SET_HARD_MAX_BY_FREQ: u32 = 0x1c;
pub const MSG_GET_MIN_DPM_FREQ: u32 = 0x1d;
pub const MSG_GET_MAX_DPM_FREQ: u32 = 0x1e;
pub const MSG_GET_DPM_FREQ_BY_INDEX: u32 = 0x1f;
pub const MSG_SET_WORKLOAD_MASK: u32 = 0x24;
pub const MSG_ALLOW_GFX_OFF: u32 = 0x28;
pub const MSG_DISALLOW_GFX_OFF: u32 = 0x29;
pub const MSG_SET_PPT_LIMIT: u32 = 0x32;
pub const MSG_GET_PPT_LIMIT: u32 = 0x33;
pub const MSG_REENABLE_AC_DC_INTERRUPT: u32 = 0x34;
pub const MSG_SET_TEMPERATURE_INPUT_SELECT: u32 = 0x38;
pub const MSG_SET_MGPU_FAN_BOOST_LIMIT_RPM: u32 = 0x3c;
pub const MSG_COUNT: u32 = 0x52;

/// `PPCLK_e` indices, smu13_driver_if_v13_0_0.h.
pub const PPCLK_GFXCLK: usize = 0;
pub const PPCLK_SOCCLK: usize = 1;
pub const PPCLK_UCLK: usize = 2;
pub const PPCLK_FCLK: usize = 3;
pub const PPCLK_DCLK_0: usize = 4;
pub const PPCLK_VCLK_0: usize = 5;
pub const PPCLK_DCLK_1: usize = 6;
pub const PPCLK_VCLK_1: usize = 7;
pub const PPCLK_DISPCLK: usize = 8;
pub const PPCLK_DPPCLK: usize = 9;
pub const PPCLK_DPREFCLK: usize = 10;
pub const PPCLK_DCFCLK: usize = 11;
pub const PPCLK_DTBCLK: usize = 12;
pub const PPCLK_COUNT: usize = 13;

/// A Linux `smu_clk_type`, as smu_v13_0_0_clk_map names it. `ppclk` is the
/// map itself: SCLK and GFXCLK are both `PPCLK_GFXCLK`, MCLK is `PPCLK_UCLK`,
/// DCEFCLK is `PPCLK_DCFCLK`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Clock {
    Gfxclk,
    Sclk,
    Socclk,
    Fclk,
    Uclk,
    Mclk,
    Vclk,
    Vclk1,
    Dclk,
    Dclk1,
    Dcefclk,
}
impl Clock {
    pub const fn ppclk(self) -> u32 {
        match self {
            Clock::Gfxclk | Clock::Sclk => PPCLK_GFXCLK as u32,
            Clock::Socclk => PPCLK_SOCCLK as u32,
            Clock::Fclk => PPCLK_FCLK as u32,
            Clock::Uclk | Clock::Mclk => PPCLK_UCLK as u32,
            Clock::Vclk => PPCLK_VCLK_0 as u32,
            Clock::Vclk1 => PPCLK_VCLK_1 as u32,
            Clock::Dclk => PPCLK_DCLK_0 as u32,
            Clock::Dclk1 => PPCLK_DCLK_1 as u32,
            Clock::Dcefclk => PPCLK_DCFCLK as u32,
        }
    }
}

/// Workload bits for `SetWorkloadMask`, smu13_driver_if_v13_0_0.h.
pub mod workload {
    pub const DEFAULT: u32 = 1 << 0;
    pub const FULL_SCREEN_3D: u32 = 1 << 1;
    pub const POWER_SAVING: u32 = 1 << 2;
    pub const VIDEO: u32 = 1 << 3;
    pub const VR: u32 = 1 << 4;
    pub const COMPUTE: u32 = 1 << 5;
    pub const CUSTOM: u32 = 1 << 6;
    pub const WINDOW_3D: u32 = 1 << 7;
}

/// One SMU mailbox request: the PPSMC message id and its argument register.
/// The owner sends `msg` with `arg` and reads the response back; a `Get*`
/// request's response is decoded with [`freq_from_response`] or
/// [`count_from_response`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub msg: u32,
    pub arg: u32,
}
/// `(ppclk << 16) | (mhz & 0xffff)`, as smu_v13_0_set_soft_freq_limited_range.
fn by_freq(msg: u32, clock: Clock, mhz: u32) -> Request {
    Request {
        msg,
        arg: (clock.ppclk() << 16) | (mhz & 0xffff),
    }
}
impl Request {
    pub fn set_soft_min(clock: Clock, mhz: u32) -> Self {
        by_freq(MSG_SET_SOFT_MIN_BY_FREQ, clock, mhz)
    }
    pub fn set_soft_max(clock: Clock, mhz: u32) -> Self {
        by_freq(MSG_SET_SOFT_MAX_BY_FREQ, clock, mhz)
    }
    /// Automatic maximum: Linux sends 0xffff as the frequency.
    pub fn set_soft_max_auto(clock: Clock) -> Self {
        by_freq(MSG_SET_SOFT_MAX_BY_FREQ, clock, 0xffff)
    }
    /// Hard bounds use the same encoding as the soft ones; the only Linux
    /// caller pins GFXCLK (`PPCLK_GFXCLK` is 0, so its raw frequency is the
    /// same value), and no other clock has a hard-bound caller to check
    /// against — the shared encoding is the documented one.
    pub fn set_hard_min(clock: Clock, mhz: u32) -> Self {
        by_freq(MSG_SET_HARD_MIN_BY_FREQ, clock, mhz)
    }
    pub fn set_hard_max(clock: Clock, mhz: u32) -> Self {
        by_freq(MSG_SET_HARD_MAX_BY_FREQ, clock, mhz)
    }
    pub fn get_min_dpm_freq(clock: Clock) -> Self {
        by_freq(MSG_GET_MIN_DPM_FREQ, clock, 0)
    }
    pub fn get_max_dpm_freq(clock: Clock) -> Self {
        by_freq(MSG_GET_MAX_DPM_FREQ, clock, 0)
    }
    /// `index` 0xff asks PMFW for the level count (see
    /// [`count_from_response`]); any other index asks for that level.
    pub fn get_dpm_freq_by_index(clock: Clock, index: u32) -> Self {
        by_freq(MSG_GET_DPM_FREQ_BY_INDEX, clock, index)
    }
    /// `mask` is a combination of [`workload`] bits.
    pub fn set_workload_mask(mask: u32) -> Self {
        Request {
            msg: MSG_SET_WORKLOAD_MASK,
            arg: mask,
        }
    }
    pub fn allow_gfx_off() -> Self {
        Request {
            msg: MSG_ALLOW_GFX_OFF,
            arg: 0,
        }
    }
    pub fn disallow_gfx_off() -> Self {
        Request {
            msg: MSG_DISALLOW_GFX_OFF,
            arg: 0,
        }
    }
    /// PPT0 limit in watts, as smu_v13_0_set_ppt_limit.
    pub fn set_ppt_limit(watts: u32) -> Self {
        Request {
            msg: MSG_SET_PPT_LIMIT,
            arg: watts,
        }
    }
    /// Response is the AC PPT0 limit in watts (hwmon `power1_cap`).
    pub fn get_ppt_limit() -> Self {
        Request {
            msg: MSG_GET_PPT_LIMIT,
            arg: 0,
        }
    }
    /// Re-arm the AC/DC interrupt after the `ReenableAcDcInterrupt` context
    /// (smu_v13_0_interrupt_work, sent on every AC/DC switch).
    pub fn reenable_ac_dc_interrupt() -> Self {
        Request {
            msg: MSG_REENABLE_AC_DC_INTERRUPT,
            arg: 0,
        }
    }
    /// `mask` selects which temperature inputs feed the fan controller
    /// (`TempInputSelectMask` in the board table).
    pub fn set_temperature_input_select(mask: u32) -> Self {
        Request {
            msg: MSG_SET_TEMPERATURE_INPUT_SELECT,
            arg: mask,
        }
    }
    pub fn set_fan_boost_limit_rpm(rpm: u32) -> Self {
        Request {
            msg: MSG_SET_MGPU_FAN_BOOST_LIMIT_RPM,
            arg: rpm,
        }
    }
}

/// A `GetDpmFreqByIndex` / `GetMinDpmFreq` / `GetMaxDpmFreq` frequency
/// response, in MHz. `None` for the reserved zero and out-of-range values
/// `amdgpu_info_stats::dpm_mhz` rejects.
pub fn freq_from_response(raw: u32) -> Option<u32> {
    crate::amdgpu_info_stats::dpm_mhz(raw)
}
/// A `GetDpmFreqByIndex(0xff)` count response, as a level count. `None`
/// when PMFW reports no levels.
pub fn count_from_response(raw: u32) -> Option<u32> {
    crate::amdgpu_info_stats::last_dpm_index(raw).map(|last| last + 1)
}

/// `sizeof(DriverInfoTable_t)`; the transfer table is `TABLE_DRIVER_INFO`.
pub const DPM_TABLE_BYTES: usize = 372;

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
fn array<const N: usize>(b: &[u8], at: usize) -> [u16; N] {
    let mut out = [0u16; N];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u16_at(b, at + 2 * i);
    }
    out
}

/// Decoded `DriverInfoTable_t`: the DPM frequency tables PMFW boots from.
/// Offsets are the field order of `DriverInfoTable_t` in
/// smu13_driver_if_v13_0_0.h. The table carries one VCLK and one DCLK table
/// shared by both instances; `DcModeMaxFreq` is `uint16_t` here (it is
/// `uint32_t` in `SkuTable_t`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DpmTables {
    pub gfx: [u16; 16],
    pub vclk: [u16; 8],
    pub dclk: [u16; 8],
    pub socclk: [u16; 8],
    pub uclk: [u16; 4],
    pub dispclk: [u16; 8],
    pub dppclk: [u16; 8],
    pub dprefclk: [u16; 8],
    pub dcfclk: [u16; 8],
    pub dtbclk: [u16; 8],
    pub fclk: [u16; 8],
    pub dc_mode_max: [u16; PPCLK_COUNT],
}
impl DpmTables {
    /// Decode a transferred `DriverInfoTable_t`. `None` for a shorter buffer.
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < DPM_TABLE_BYTES {
            return None;
        }
        let mut dc_mode_max = [0u16; PPCLK_COUNT];
        for (i, slot) in dc_mode_max.iter_mut().enumerate() {
            *slot = u16_at(b, 184 + 2 * i);
        }
        Some(Self {
            gfx: array(b, 0),
            vclk: array(b, 32),
            dclk: array(b, 48),
            socclk: array(b, 64),
            uclk: array(b, 80),
            dispclk: array(b, 88),
            dppclk: array(b, 104),
            dprefclk: array(b, 120),
            dcfclk: array(b, 136),
            dtbclk: array(b, 152),
            fclk: array(b, 168),
            dc_mode_max,
        })
    }
    /// The DPM frequency table for a `PPCLK_e` index. The two VCLK/DCLK
    /// instances share one table each.
    pub fn freq_table(&self, ppclk: usize) -> Option<&[u16]> {
        Some(match ppclk {
            PPCLK_GFXCLK => &self.gfx,
            PPCLK_SOCCLK => &self.socclk,
            PPCLK_UCLK => &self.uclk,
            PPCLK_FCLK => &self.fclk,
            PPCLK_DCLK_0 | PPCLK_DCLK_1 => &self.dclk,
            PPCLK_VCLK_0 | PPCLK_VCLK_1 => &self.vclk,
            PPCLK_DISPCLK => &self.dispclk,
            PPCLK_DPPCLK => &self.dppclk,
            PPCLK_DPREFCLK => &self.dprefclk,
            PPCLK_DCFCLK => &self.dcfclk,
            PPCLK_DTBCLK => &self.dtbclk,
            _ => return None,
        })
    }
    /// `DcModeMaxFreq[ppclk]`, in MHz.
    pub fn dc_mode_max(&self, ppclk: usize) -> Option<u16> {
        self.dc_mode_max.get(ppclk).copied()
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi31_dpm_tests.rs"]
mod tests;
