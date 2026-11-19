// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8852A NHM (noise histogram measurement) noise monitoring.
//!
//! Mirrors Linux `rtw89/phy.c` NHM machinery (torvalds/linux @ 05441d6)
//! for the one chip that supports it: `chip->support_noise` is true only
//! for RTL8852A (`rtw8852a.c:2419`), and 8852A is the only chip with
//! non-NULL `nhm_report`/`nhm_th` tables (`rtw8852a.c:2489..2490`;
//! every other chip wires NULL). The AX CCX register block
//! (`rtw89_ccx_regs_ax`, `phy.c:8954`) supplies the control registers;
//! the 8852A tables below supply the threshold/report register pairs.
//!
//! This module programs nothing on its own: the 8852A station owner now
//! exists (`station_control::Controller` admits RTL8852A, and
//! `supports_noise()` gates every entry point on `SUPPORT_NOISE_8852A`),
//! but no production caller triggers a measurement yet — the trigger /
//! get-result entry points stay fixture-pinned until the radio (BB/RF)
//! owner wires the measurement into the channel plan. Like the
//! negotiated-TTLM engine and the EHT tables, this is
//! implemented-but-not-advertised: the model is fixture-pinned now so the
//! future owner wires up verified values. The future owner gates every
//! entry point on `SUPPORT_NOISE_8852A`, matching Linux's early returns
//! in `rtw89_phy_nhm_trigger`, `rtw89_phy_nhm_get_result`, and
//! `rtw89_phy_nhm_setting_init`.
//!
//! Deliberate narrowings, each a grounded absence, not an oversight:
//! - The IFS-CLM register writes inside Linux's `rtw89_phy_ccx_trigger`
//!   (`ifs_cnt_addr`, `setting_addr`) are NOT modeled: they belong to
//!   the shared CCX/IFS-CLM machinery, whose background run lives in
//!   `track.rs` per the spec. Only the NHM enable toggle of that
//!   trigger is modeled here.
//! - The channel-history recording at the tail of
//!   `__rtw89_phy_nhm_get_result` (mac80211 `sband` lookup, per-channel
//!   `nhm_his` list) is NOT modeled: it is mac80211 survey plumbing,
//!   not measurement. `get_result` returns the noise value; the future
//!   owner decides what consumes it. (In Linux, `!support_noise` also
//!   NULLs the `get_survey` op, `core.c:7679` — the survey consumer.)
//! - The `nhm_set` period/unit writes reproduce Linux's literal calls:
//!   `period` is written into BOTH the period field and the unit field
//!   (`phy.c:6944..6947`). The unit field therefore carries
//!   `period & 0x3`, not `unit_idx`; `unit_idx` is still stored in
//!   state because Linux stores it in `env->ccx_unit_idx`.
//! - Register-field writes use the crate's masked-write convention:
//!   the caller passes a field VALUE, and the write positions it into
//!   the mask (`(old & !mask) | ((value << shift) & mask)`).

use super::irq::Regs;
use super::power;

/// NHM is supported only on RTL8852A. Linux `chip->support_noise`
/// (`rtw8852a.c:2419`); every other chip in the local reference wires
/// `false` and NULL NHM tables.
pub(super) const SUPPORT_NOISE_8852A: bool = true;

/// Number of NHM thresholds (`core.h:5773`).
pub(super) const NHM_TH_NUM: usize = 11;
/// Number of NHM report counters (`core.h:5774`).
pub(super) const NHM_RPT_NUM: usize = 12;
/// Weight offset for the first/last bins (`phy.h:221`).
pub(super) const NHM_WEIGHT_OFFSET: u8 = 2;
/// Threshold shift factor (`phy.h:225`).
pub(super) const NHM_TH_FACTOR: u32 = 1;
/// Workaround threshold for 8852A/B/C (`phy.h:222`: 109 << 1).
pub(super) const NHM_WA_TH: u8 = 218;
/// Default monitor time for a trigger, ms (`phy.h:224`).
pub(super) const NHM_MNTR_TIME_MS: u16 = 40;
/// Trigger racing level (`core.h:7133`).
pub(super) const NHM_RAC_LV_1: u8 = 1;
/// Racing level ceiling (`core.h:7136`).
pub(super) const NHM_RAC_MAX_NUM: u8 = 5;
/// Released racing level (`core.h:7131`).
pub(super) const NHM_RAC_RELEASE: u8 = 0;

/// One (address, mask) register field, as Linux's `struct rtw89_reg_def`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RegDef {
    pub(super) addr: u32,
    pub(super) mask: u32,
}

/// NHM control register (`reg.h:8991`).
pub(super) const R_NHM_CFG: u32 = 0x0C08;
/// Period field of `R_NHM_CFG` (`reg.h:8992`): GENMASK(15, 0).
pub(super) const B_NHM_PERIOD_MSK: u32 = 0xFFFF;
/// Counter-unit field of `R_NHM_CFG` (`reg.h:8993`): GENMASK(17, 16).
pub(super) const B_NHM_COUNTER_MSK: u32 = 0x3 << 16;
/// NHM enable bit of `R_NHM_CFG` (`reg.h:8994`): BIT(18).
pub(super) const B_NHM_EN_MSK: u32 = 1 << 18;
/// Include-CCA bit of `R_NHM_CFG` (`reg.h:8995`): BIT(19).
pub(super) const B_NHM_INCLUDE_CCA_MSK: u32 = 1 << 19;
/// TH0 field of `R_NHM_CFG` (`reg.h:8996`): GENMASK(31, 24).
pub(super) const B_NHM_TH0_MSK: u32 = 0xFF << 24;
/// Threshold registers 1/5/9 (`reg.h:8997, 9002, 9007`).
pub(super) const R_NHM_TH1: u32 = 0x0C0C;
pub(super) const R_NHM_TH5: u32 = 0x0C10;
pub(super) const R_NHM_TH9: u32 = 0x0C14;
/// TH1..TH4 fields of `R_NHM_TH1` (`reg.h:8998..9001`).
pub(super) const B_NHM_TH1_MSK: u32 = 0xFF;
pub(super) const B_NHM_TH2_MSK: u32 = 0xFF << 8;
pub(super) const B_NHM_TH3_MSK: u32 = 0xFF << 16;
pub(super) const B_NHM_TH4_MSK: u32 = 0xFF << 24;
/// TH5..TH8 fields of `R_NHM_TH5` (`reg.h:9003..9006`).
pub(super) const B_NHM_TH5_MSK: u32 = 0xFF;
pub(super) const B_NHM_TH6_MSK: u32 = 0xFF << 8;
pub(super) const B_NHM_TH7_MSK: u32 = 0xFF << 16;
pub(super) const B_NHM_TH8_MSK: u32 = 0xFF << 24;
/// TH9..TH10 fields of `R_NHM_TH9` (`reg.h:9008..9009`).
pub(super) const B_NHM_TH9_MSK: u32 = 0xFF;
pub(super) const B_NHM_TH10_MSK: u32 = 0xFF << 8;
/// Power-DB method field of `R_NHM_TH9` (`reg.h:9010`): GENMASK(17, 16).
pub(super) const B_NHM_PWDB_METHOD_MSK: u32 = 0x3 << 16;
/// NHM status register, AX CCX block (`reg.h:9263`).
pub(super) const R_NHM_AX: u32 = 0x1AA4;
/// Ready bit of `R_NHM_AX` (`reg.h:9264`): BIT(16).
pub(super) const B_NHM_READY_MSK: u32 = 1 << 16;
/// Report counter registers (`reg.h:9245..9262`).
pub(super) const R_NHM_CNT0: u32 = 0x1A88;
pub(super) const R_NHM_CNT2: u32 = 0x1A8C;
pub(super) const R_NHM_CNT4: u32 = 0x1A90;
pub(super) const R_NHM_CNT6: u32 = 0x1A94;
pub(super) const R_NHM_CNT8: u32 = 0x1A98;
pub(super) const R_NHM_CNT10: u32 = 0x1A9C;
/// Report counter fields: low half GENMASK(15, 0), high half GENMASK(31, 16).
pub(super) const B_NHM_CNT_LO_MSK: u32 = 0xFFFF;
pub(super) const B_NHM_CNT_HI_MSK: u32 = 0xFFFF << 16;

/// 8852A threshold table (`rtw8852a.c:484..496`), verbatim.
pub(super) const NHM_TH: [RegDef; NHM_TH_NUM] = [
    RegDef {
        addr: R_NHM_CFG,
        mask: B_NHM_TH0_MSK,
    },
    RegDef {
        addr: R_NHM_TH1,
        mask: B_NHM_TH1_MSK,
    },
    RegDef {
        addr: R_NHM_TH1,
        mask: B_NHM_TH2_MSK,
    },
    RegDef {
        addr: R_NHM_TH1,
        mask: B_NHM_TH3_MSK,
    },
    RegDef {
        addr: R_NHM_TH1,
        mask: B_NHM_TH4_MSK,
    },
    RegDef {
        addr: R_NHM_TH5,
        mask: B_NHM_TH5_MSK,
    },
    RegDef {
        addr: R_NHM_TH5,
        mask: B_NHM_TH6_MSK,
    },
    RegDef {
        addr: R_NHM_TH5,
        mask: B_NHM_TH7_MSK,
    },
    RegDef {
        addr: R_NHM_TH5,
        mask: B_NHM_TH8_MSK,
    },
    RegDef {
        addr: R_NHM_TH9,
        mask: B_NHM_TH9_MSK,
    },
    RegDef {
        addr: R_NHM_TH9,
        mask: B_NHM_TH10_MSK,
    },
];

/// 8852A report table (`rtw8852a.c:498..512`), verbatim.
pub(super) const NHM_RPT: [RegDef; NHM_RPT_NUM] = [
    RegDef {
        addr: R_NHM_CNT0,
        mask: B_NHM_CNT_LO_MSK,
    },
    RegDef {
        addr: R_NHM_CNT0,
        mask: B_NHM_CNT_HI_MSK,
    },
    RegDef {
        addr: R_NHM_CNT2,
        mask: B_NHM_CNT_LO_MSK,
    },
    RegDef {
        addr: R_NHM_CNT2,
        mask: B_NHM_CNT_HI_MSK,
    },
    RegDef {
        addr: R_NHM_CNT4,
        mask: B_NHM_CNT_LO_MSK,
    },
    RegDef {
        addr: R_NHM_CNT4,
        mask: B_NHM_CNT_HI_MSK,
    },
    RegDef {
        addr: R_NHM_CNT6,
        mask: B_NHM_CNT_LO_MSK,
    },
    RegDef {
        addr: R_NHM_CNT6,
        mask: B_NHM_CNT_HI_MSK,
    },
    RegDef {
        addr: R_NHM_CNT8,
        mask: B_NHM_CNT_LO_MSK,
    },
    RegDef {
        addr: R_NHM_CNT8,
        mask: B_NHM_CNT_HI_MSK,
    },
    RegDef {
        addr: R_NHM_CNT10,
        mask: B_NHM_CNT_LO_MSK,
    },
    RegDef {
        addr: R_NHM_CNT10,
        mask: B_NHM_CNT_HI_MSK,
    },
];

/// Mirror of Linux's `struct rtw89_env_monitor_info` NHM fields
/// (`core.h:7219..7220` and the `nhm_*` state in `phy.c`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct NhmState {
    /// Whether CCA is included in the measurement.
    pub(super) include_cca: bool,
    /// Monitor time of the last programmed measurement, ms.
    pub(super) mntr_time_ms: u16,
    /// Sum of the last report counters.
    pub(super) sum: u32,
    /// Thresholds, 12 slots; slot 11 is always 0 in Linux's table.
    pub(super) th: [u8; NHM_RPT_NUM],
    /// Last report counters.
    pub(super) result: [u16; NHM_RPT_NUM],
    /// A CCX measurement is in flight.
    pub(super) ccx_ongoing: bool,
    /// Current racing level (`NHM_RAC_*`).
    pub(super) ccx_rac_lv: u8,
    /// Period computed for the last programmed measurement.
    pub(super) period: u32,
    /// Unit index computed for the last programmed measurement.
    pub(super) unit_idx: u32,
}

impl NhmState {
    /// Fresh state, as after `__rtw89_phy_nhm_setting_init`'s field
    /// assignments (thresholds/results start zeroed; `th_update` fills
    /// thresholds when a measurement is programmed).
    pub(super) const fn new() -> Self {
        Self {
            include_cca: false,
            mntr_time_ms: 0,
            sum: 0,
            th: [0; NHM_RPT_NUM],
            result: [0; NHM_RPT_NUM],
            ccx_ongoing: false,
            ccx_rac_lv: NHM_RAC_RELEASE,
            period: 0,
            unit_idx: 0,
        }
    }
}

/// NHM model errors. `Io` wraps the register-access error; the rest
/// mirror Linux's `-EINVAL` arms in the NHM path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Io(power::Error),
    InvalidMonitorTime,
    RacingConflict,
}

impl From<power::Error> for Error {
    fn from(e: power::Error) -> Self {
        Error::Io(e)
    }
}

/// Write a field value into a masked register field, preserving every
/// bit outside the mask.
fn write_field(io: &mut impl Regs, addr: u32, mask: u32, value: u32) -> Result<(), Error> {
    let old = io.read32(addr)?;
    let shift = mask.trailing_zeros();
    io.write32(addr, (old & !mask) | ((value << shift) & mask))?;
    Ok(())
}

/// Set every bit of a mask.
fn set_bits(io: &mut impl Regs, addr: u32, mask: u32) -> Result<(), Error> {
    let old = io.read32(addr)?;
    io.write32(addr, old | mask)?;
    Ok(())
}

/// Clear every bit of a mask.
fn clear_bits(io: &mut impl Regs, addr: u32, mask: u32) -> Result<(), Error> {
    let old = io.read32(addr)?;
    io.write32(addr, old & !mask)?;
    Ok(())
}

/// 11k threshold defaults (`phy.c:6896..6898`), shifted by
/// `NHM_TH_FACTOR`. With the workaround override (8852A/B/C,
/// `phy.c:6906..6908`), slot 10 becomes `NHM_WA_TH`; slot 11 stays 0.
pub(super) const fn th_values(wa_override: bool) -> [u8; NHM_RPT_NUM] {
    let mut th = [36, 42, 48, 54, 60, 70, 80, 90, 100, 110, 120, 0];
    if wa_override {
        th[10] = NHM_WA_TH;
    }
    th
}

/// Write the 11 threshold fields (`rtw89_phy_nhm_th_update`'s register
/// loop, `phy.c:6910..6916`). The 8852A path always takes the
/// workaround override.
pub(super) fn write_thresholds(io: &mut impl Regs, th: &[u8; NHM_RPT_NUM]) -> Result<(), Error> {
    for i in 0..NHM_TH_NUM {
        write_field(io, NHM_TH[i].addr, NHM_TH[i].mask, u32::from(th[i]))?;
    }
    Ok(())
}

/// Weighted-average noise (`rtw89_nhm_weighted_avg`, `phy.c:6649..6688`),
/// exactly: 0 on an empty sum; first-bin weight clamped from
/// `th[0] - offset`; interior bins average their neighbours; last bin
/// takes `th[10] + offset`; on the 8852A/B/C arm, when `th[10]` equals
/// `NHM_WA_TH`, the last two weights become `th[9] + offset`, and the
/// last counter always folds into the first (`result[0] += result[11]`,
/// `result[11] = 0`). Weights are computed in `u16` and narrowed: every
/// grounded threshold is at most 218 + 2, so no value wraps.
pub(super) fn weighted_avg(state: &mut NhmState) -> u8 {
    if state.sum == 0 {
        return 0;
    }
    let mut weight = [0u8; NHM_RPT_NUM];
    let weight_zero = (u16::from(state.th[0]).saturating_sub(u16::from(NHM_WEIGHT_OFFSET)))
        .min(u16::from(u8::MAX)) as u8;
    for (i, slot) in weight.iter_mut().enumerate() {
        *slot = if i == 0 {
            weight_zero
        } else if i == NHM_RPT_NUM - 1 {
            state.th[i - 1].saturating_add(NHM_WEIGHT_OFFSET)
        } else {
            ((u16::from(state.th[i - 1]) + u16::from(state.th[i])) / 2) as u8
        };
    }
    // 8852A arm (this module IS the 8852A path).
    if state.th[NHM_TH_NUM - 1] == NHM_WA_TH {
        weight[NHM_RPT_NUM - 1] = state.th[NHM_TH_NUM - 2].saturating_add(NHM_WEIGHT_OFFSET);
        weight[NHM_RPT_NUM - 2] = weight[NHM_RPT_NUM - 1];
    }
    state.result[0] = state.result[0].saturating_add(state.result[NHM_RPT_NUM - 1]);
    state.result[NHM_RPT_NUM - 1] = 0;
    let mut weighted_sum: u32 = 0;
    for (counter, w) in state.result.iter().zip(weight.iter()) {
        weighted_sum += u32::from(*counter) * u32::from(*w);
    }
    ((weighted_sum / state.sum) >> NHM_TH_FACTOR) as u8
}

/// Monitor-time to (period, unit index) (`rtw89_phy_ccx_ms_to_period_unit`,
/// `phy.c:6340..6367`). Time clamps to 2097 ms; the quotient buckets
/// select the 4/8/16/32 µs unit; period is `(ms * 250) >> unit_idx`.
pub(super) const fn ms_to_period_unit(time_ms: u16) -> (u32, u32) {
    let ms = if time_ms > 2097 { 2097 } else { time_ms };
    let quotient = 32u32 * (ms as u32) / 2097;
    let idx = if quotient < 4 {
        0
    } else if quotient < 8 {
        1
    } else if quotient < 16 {
        2
    } else {
        3
    };
    (((ms as u32) * 250) >> idx, idx)
}

/// Racing-level arbitration (`rtw89_phy_ccx_racing_ctrl`, `phy.c:6524..6553`).
pub(super) fn racing_ctrl(state: &mut NhmState, level: u8) -> Result<(), Error> {
    if level >= NHM_RAC_MAX_NUM {
        return Err(Error::RacingConflict);
    }
    if state.ccx_ongoing {
        if level <= state.ccx_rac_lv {
            return Err(Error::RacingConflict);
        }
        state.ccx_ongoing = false;
    }
    state.ccx_rac_lv = level;
    Ok(())
}

/// Racing release (`rtw89_phy_ccx_racing_release`, `phy.c:6369..6379`).
/// The IFS-CLM app field is not part of this module's state.
pub(super) fn racing_release(state: &mut NhmState) {
    state.ccx_ongoing = false;
    state.ccx_rac_lv = NHM_RAC_RELEASE;
}

/// Initialize NHM state and control registers
/// (`__rtw89_phy_nhm_setting_init`, `phy.c:6469..6483`): defaults plus
/// the enable bit on `R_NHM_CFG` and the power-DB method bits on
/// `R_NHM_TH9`.
pub(super) fn setting_init(io: &mut impl Regs, state: &mut NhmState) -> Result<(), Error> {
    state.include_cca = false;
    state.mntr_time_ms = 0;
    state.sum = 0;
    set_bits(io, R_NHM_CFG, B_NHM_EN_MSK)?;
    set_bits(io, R_NHM_TH9, B_NHM_PWDB_METHOD_MSK)?;
    Ok(())
}

/// Enable/disable the NHM block (`rtw89_phy_ccx_trigger`'s NHM arms and
/// the env-monitor enable/disable, `phy.c:6562..6580`).
pub(super) fn set_enable(io: &mut impl Regs, enable: bool) -> Result<(), Error> {
    if enable {
        set_bits(io, R_NHM_CFG, B_NHM_EN_MSK)
    } else {
        clear_bits(io, R_NHM_CFG, B_NHM_EN_MSK)
    }
}

/// Program a measurement (`rtw89_phy_nhm_set`, `phy.c:6919..6965`):
/// zero monitor time is rejected; a changed monitor time recomputes the
/// period/unit and programs both fields (Linux passes `period` to both
/// writes — see the module docs); a changed include-CCA flag reprograms
/// it; thresholds are always rewritten with the 8852A workaround
/// override.
pub(super) fn set_params(
    io: &mut impl Regs,
    state: &mut NhmState,
    mntr_time_ms: u16,
    include_cca: bool,
) -> Result<(), Error> {
    if mntr_time_ms == 0 {
        return Err(Error::InvalidMonitorTime);
    }
    if mntr_time_ms != state.mntr_time_ms {
        let (period, unit_idx) = ms_to_period_unit(mntr_time_ms);
        write_field(io, R_NHM_CFG, B_NHM_PERIOD_MSK, period)?;
        write_field(io, R_NHM_CFG, B_NHM_COUNTER_MSK, period)?;
        state.mntr_time_ms = mntr_time_ms;
        state.period = period;
        state.unit_idx = unit_idx;
    }
    if include_cca != state.include_cca {
        if include_cca {
            set_bits(io, R_NHM_CFG, B_NHM_INCLUDE_CCA_MSK)?;
        } else {
            clear_bits(io, R_NHM_CFG, B_NHM_INCLUDE_CCA_MSK)?;
        }
        state.include_cca = include_cca;
    }
    let th = th_values(true);
    state.th = th;
    write_thresholds(io, &th)?;
    Ok(())
}

/// Trigger a measurement (`__rtw89_phy_nhm_trigger`, `phy.c:6967..6979`):
/// racing release, program the default 40 ms / include-CCA parameters,
/// then toggle the enable bit off and on; the measurement is in flight
/// afterwards. The IFS-CLM register writes of Linux's `ccx_trigger` are
/// out of scope (see the module docs).
pub(super) fn trigger(io: &mut impl Regs, state: &mut NhmState) -> Result<(), Error> {
    racing_release(state);
    set_params(io, state, NHM_MNTR_TIME_MS, true)?;
    clear_bits(io, R_NHM_CFG, B_NHM_EN_MSK)?;
    set_bits(io, R_NHM_CFG, B_NHM_EN_MSK)?;
    state.ccx_ongoing = true;
    Ok(())
}

/// Read a measurement (`__rtw89_phy_nhm_get_result`'s register half,
/// `phy.c:6691..6730`): `None` when the ready bit is clear; otherwise
/// the 12 report counters, their sum, and the weighted-average noise.
/// The mac80211 channel-history tail is out of scope (see module docs).
pub(super) fn get_result(io: &mut impl Regs, state: &mut NhmState) -> Result<Option<u8>, Error> {
    let status = io.read32(R_NHM_AX)?;
    if status & B_NHM_READY_MSK == 0 {
        return Ok(None);
    }
    let mut sum: u32 = 0;
    for (slot, rpt) in state.result.iter_mut().zip(NHM_RPT.iter()) {
        let value = io.read32(rpt.addr)? & rpt.mask;
        let shift = rpt.mask.trailing_zeros();
        let counter = (value >> shift) as u16;
        *slot = counter;
        sum += u32::from(counter);
    }
    state.sum = sum;
    Ok(Some(weighted_avg(state)))
}
