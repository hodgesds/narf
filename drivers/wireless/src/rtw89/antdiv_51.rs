// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8851B one-path antenna-diversity owner: phy.c
//! `rtw89_phy_antdiv_init` / `rtw89_phy_antdiv_reg_init` /
//! `rtw89_phy_antdiv_set_ant` / `rtw89_phy_antdiv_parse` /
//! `rtw89_phy_antdiv_track` / `rtw89_phy_antdiv_work` (training +
//! decision states) and rtw8851b.c `rtw8851b_rfe_gpio` /
//! `rtw8851b_set_bb_gpio` / `rtw8851b_set_mac_gpio`, for the
//! `rfe_type % 3 == 2` boards that `radio_51` previously refused.
//!
//! Linux references (torvalds/linux @ 05441d69; the protocols are stable
//! across the gap to the programme's cbbddb6 reference):
//! - mac.c `rtw89_mac_setup_phycap`: on a one-path chip
//!   `hal->ant_diversity = rfe_type % 3 == 2`, with `antenna_tx =
//!   antenna_rx = RF_A`. There is no `<= 50` bound on the flag.
//! - rtw8851b.c `rtw8851b_rfe_gpio`: returns early for `rfe_type > 50`
//!   (the bound lives on the GPIO writes only, not the flag), then
//!   `set_bb_gpio(16, true, RFE_SEL0_SRC_ANTSEL_0)`,
//!   `set_bb_gpio(17, false, RFE_SEL0_SRC_ANTSEL_0)`,
//!   `set_mac_gpio(16)`, `set_mac_gpio(17)`.
//! - phy.c `rtw89_phy_dm_init` order: `antdiv_init` (state reset +
//!   `reg_init` writes), then `chip_rfe_gpio`, then `antdiv_set_ant`.
//!   `radio_51::prepare_controls` applies the three programs in that
//!   order and retains the [`AntDiv`] state for the runtime track.
//!
//! Register model: a [`Field`] is `(address, mask, unshifted value)` in
//! the `radio_51` convention — the applier shifts the value by
//! `mask.trailing_zeros()`, matching Linux `write32_mask` /
//! `write8_mask` (which shift the data by `__ffs(mask)`). PHY_0 BB
//! registers are addressed at `PHY + offset` (`PHY = 0x10000`, as in
//! `radio_init` / `radio_51`); the GPIO function-select register is a
//! plain MAC-space write8. Antenna bitmaps follow core.h
//! `enum rtw89_rf_path_bit`: `RF_A = BIT(0) = 1`, `RF_B = BIT(1) = 2`.
//!
//! The runtime track (`parse` / `track` / `step`) is a pure state
//! machine over already-classified PPDU observations
//! (`super::rx_packet::AntDivObservation`, classified by
//! `super::rx_packet::ppdu_class` from Linux's
//! `rtw89_get_data_rate_mode` + `RTW89_HW_RATE_OFDM6` split).
//! `radio_51::Radio::parse_ppdu` feeds it from the MACID-matched
//! PHYSTS path and `Radio::track` drives `track` / `step` on the 2 s
//! track tick; the 30 ms / 110 ms / immediate re-queue periods Linux's
//! `antdiv_work` uses are recorded as the requested period
//! (`Radio::antdiv_period_ms`), because NARF has no sub-second
//! delayed-work scheduler yet.
use super::rx_packet::PpduClass;
use super::{phy_operating, power, rfk};
use alloc::vec::Vec;

/// PHY_0 BB page base, as in `radio_51` / `radio_init`.
const PHY: u32 = 0x10000;

/// Antenna bitmaps (core.h `enum rtw89_rf_path_bit`).
pub(super) const RF_A: u8 = 1;
pub(super) const RF_B: u8 = 2;

/// ANTSEL field values (phy.c `ANTDIV_MAIN` / `ANTDIV_AUX`).
const ANTDIV_MAIN: u32 = 0;
const ANTDIV_AUX: u32 = 1;

/// phy.h antenna-diversity constants.
const TRAINNING_CNT: u8 = 2;
const TRAINNING_INTVL_MS: u32 = 30;
const DELAY_MS: u32 = 110;
const EVM_DIFF_TH: u32 = 8;
const RSSI_DIFF_TH: u8 = 3;
/// core.h `RTW89_TX_DIV_RSSI_RAW_TH = (2 << RSSI_FACTOR)`, `RSSI_FACTOR = 1`.
const TX_DIV_RSSI_RAW_TH: u32 = 4;

/// One masked register write: `(address, mask, unshifted value)`.
pub(super) type Field = (u32, u32, u32);
/// One masked MAC-space write8: `(address, mask, unshifted value)`.
pub(super) type MacField = (u32, u8, u8);

/// `rtw8851b_rfe_gpio` BB half (`rtw89_phy_write32_mask`, PHY_0):
/// per GPIO, the RFE path-select word (value `RF_PATH_A = 0`), the
/// inversion bit, and the source-select word (`RFE_SEL0_SRC_ANTSEL_0
/// = 8`). Empty unless `rfe_type <= 50` and `rfe_type % 3 == 2` —
/// the early return in `rtw8851b_rfe_gpio` covers the whole function,
/// including the MAC half below.
pub(super) fn rfe_gpio_fields(rfe_type: u8) -> Vec<Field> {
    if rfe_type > 50 || rfe_type % 3 != 2 {
        return Vec::new();
    }
    // R_RFE_SEL0_A2 0x033C, B_RFE_SEL0_MASK GENMASK(1,0):
    // addr = 0x033C + (idx/16)*4, mask = 0x3 << (idx%16)*2, value 0.
    // R_RFE_INV0 0x5890, mask BIT(idx), value inv.
    // R_RFE_SEL0_BASE 0x5880, B_RFE_SEL0_SRC_MASK GENMASK(3,0):
    // addr = 0x5880 + (idx/8)*4, mask = 0xF << (idx%8)*4, value 8.
    alloc::vec![
        (PHY + 0x0340, 0x3, 0),
        (PHY + 0x5890, 1 << 16, 1),
        (PHY + 0x5888, 0xF, 8),
        (PHY + 0x0340, 0xC, 0),
        (PHY + 0x5890, 1 << 17, 0),
        (PHY + 0x5888, 0xF0, 8),
    ]
}

/// `rtw8851b_rfe_gpio` MAC half (`rtw89_write8_mask` on
/// `R_AX_GPIO16_23_FUNC_SEL` 0x02D8): GPIO16 selects function bit 3,
/// GPIO17 selects function bit 7 (stored unshifted as `BIT(7) >> 4`,
/// shifted back by the mask at apply time). Same gate as
/// [`rfe_gpio_fields`].
pub(super) fn rfe_gpio_mac_fields(rfe_type: u8) -> Vec<MacField> {
    if rfe_type > 50 || rfe_type % 3 != 2 {
        return Vec::new();
    }
    // B_AX_PINMUX_GPIO16_FUNC_SEL_MASK GENMASK(3,0), data BIT(3);
    // B_AX_PINMUX_GPIO17_FUNC_SEL_MASK GENMASK(7,4), data BIT(7) >> 4.
    alloc::vec![(0x02D8, 0x0F, 0x08), (0x02D8, 0xF0, 0x08)]
}

/// `rtw89_phy_antdiv_reg_init` (`rtw89_phy_write32_idx`, PHY_0), in
/// Linux order. All values are 0 except the RFSW antenna mapping
/// (0x0100) and the ANTSEL BTG TRX bit (1).
pub(super) fn reg_init_fields() -> [Field; 10] {
    [
        // R_P0_TRSW 0x5868, B_P0_ANT_TRAIN_EN BIT(0).
        (PHY + 0x5868, 1, 0),
        // R_P0_TRSW, B_P0_TX_ANT_SEL BIT(1).
        (PHY + 0x5868, 2, 0),
        // R_P0_ANT_SW 0x0728, B_P0_TRSW_TX_EXTEND GENMASK(3,0).
        (PHY + 0x0728, 0xF, 0),
        // R_P0_ANT_SW, B_P0_HW_ANTSW_DIS_BY_GNT_BT BIT(12).
        (PHY + 0x0728, 1 << 12, 0),
        // R_P0_TRSW, B_P0_BT_FORCE_ANTIDX_EN BIT(12).
        (PHY + 0x5868, 1 << 12, 0),
        // R_RFSW_CTRL_ANT0_BASE 0x5870, B_RFSW_CTRL_ANT_MAPPING
        // GENMASK(15,0).
        (PHY + 0x5870, 0xFFFF, 0x0100),
        // R_P0_ANTSEL 0x586C, B_P0_ANTSEL_BTG_TRX BIT(21).
        (PHY + 0x586C, 1 << 21, 1),
        // R_P0_ANTSEL, B_P0_ANTSEL_HW_CTRL BIT(16).
        (PHY + 0x586C, 1 << 16, 0),
        // R_P0_ANTSEL, B_P0_ANTSEL_SW_2G BIT(23).
        (PHY + 0x586C, 1 << 23, 0),
        // R_P0_ANTSEL, B_P0_ANTSEL_SW_5G BIT(25).
        (PHY + 0x586C, 1 << 25, 0),
    ]
}

/// Apply masked PHY_0 writes over a `phy_operating` interface: admit,
/// read-modify-write with the value shifted by `mask.trailing_zeros()`,
/// `u32::MAX` reads refused as gone — the `phy_operating::Access`
/// semantics, minus the xtal helpers this owner does not use.
pub(super) fn apply_controls(
    io: &mut impl phy_operating::Interface,
    fields: &[Field],
) -> Result<(), rfk::Error> {
    for &(address, mask, value) in fields {
        io.admit()?;
        let old = io.read32(address)?;
        if old == u32::MAX {
            return Err(power::Error::Gone.into());
        }
        io.admit()?;
        io.write32(
            address,
            (old & !mask) | ((value << mask.trailing_zeros()) & mask),
        )?;
    }
    Ok(())
}

/// Apply masked MAC-space write8s over a `phy_operating` interface,
/// with the same shift-and-mask semantics as [`apply_controls`].
pub(super) fn apply_mac8(
    io: &mut impl phy_operating::Interface,
    fields: &[MacField],
) -> Result<(), rfk::Error> {
    for &(address, mask, value) in fields {
        io.admit()?;
        let old = io.read8(address)?;
        io.admit()?;
        let mask = u32::from(mask);
        let shifted = (u32::from(value) << mask.trailing_zeros()) & mask;
        io.write8(address, (old & !(mask as u8)) | (shifted as u8))?;
    }
    Ok(())
}

/// Kernel EWMA for `DECLARE_EWMA(rssi, 10, 16)` (include/linux/
/// average.h, instantiated at rtw89 core.h:4649): `internal` starts 0;
/// the first add stores `val << 10`; later adds store
/// `((internal << 4) - internal + (val << 10)) >> 4`; reads shift back
/// by 10. Counts and sums stay far below u32 overflow for u8 RSSI.
#[derive(Clone, Copy, Debug, Default)]
struct Ewma {
    internal: u32,
}

impl Ewma {
    fn add(&mut self, value: u8) {
        let value = u32::from(value);
        if self.internal == 0 {
            self.internal = value << 10;
        } else {
            self.internal = ((self.internal << 4) - self.internal + (value << 10)) >> 4;
        }
    }

    fn read(self) -> u32 {
        self.internal >> 10
    }
}

/// One `rtw89_antdiv_stats` instance: per-class EWMA RSSI, per-class
/// packet counts, and the accumulated OFDM EVM sum. Counts are u32
/// (Linux widths are not load-bearing here: counts are only compared
/// and summed for the EVM divisor, and every window resets).
#[derive(Clone, Copy, Debug, Default)]
struct Stats {
    cck: Ewma,
    ofdm: Ewma,
    non_legacy: Ewma,
    pkt_cnt_cck: u32,
    pkt_cnt_ofdm: u32,
    pkt_cnt_non_legacy: u32,
    evm: u32,
}

impl Stats {
    fn reset(&mut self) {
        *self = Self::default();
    }

    /// `rtw89_phy_antdiv_sts_instance_add`: CCK accumulates RSSI only;
    /// OFDM and non-legacy accumulate RSSI and `ofdm.evm_min`.
    fn add(&mut self, class: PpduClass, rssi_avg: u8, evm_min: u8) {
        match class {
            PpduClass::Cck => {
                self.cck.add(rssi_avg);
                self.pkt_cnt_cck += 1;
            }
            PpduClass::Ofdm => {
                self.ofdm.add(rssi_avg);
                self.pkt_cnt_ofdm += 1;
                self.evm += u32::from(evm_min);
            }
            PpduClass::NonLegacy => {
                self.non_legacy.add(rssi_avg);
                self.pkt_cnt_non_legacy += 1;
                self.evm += u32::from(evm_min);
            }
        }
    }

    /// `rtw89_phy_antdiv_sts_instance_get_rssi`: the majority packet
    /// class wins; ties favor non-legacy, then OFDM, then CCK (the
    /// comparison chain, not a max).
    fn rssi(&self) -> u8 {
        if self.pkt_cnt_non_legacy >= self.pkt_cnt_cck
            && self.pkt_cnt_non_legacy >= self.pkt_cnt_ofdm
        {
            self.non_legacy.read() as u8
        } else if self.pkt_cnt_ofdm >= self.pkt_cnt_cck
            && self.pkt_cnt_ofdm >= self.pkt_cnt_non_legacy
        {
            self.ofdm.read() as u8
        } else {
            self.cck.read() as u8
        }
    }

    /// `rtw89_phy_antdiv_sts_instance_get_evm`: `phy_div` — truncating
    /// division, 0 on a zero divisor.
    fn evm(&self) -> u8 {
        let denom = self.pkt_cnt_non_legacy + self.pkt_cnt_ofdm;
        if denom == 0 {
            0
        } else {
            (self.evm / denom) as u8
        }
    }
}

/// The `rtw89_antdiv_info` runtime: target/main/aux stats, training
/// count, previous target RSSI, the collect gate, the current antenna
/// bitmaps, and the `ant_diversity_fixed` gate. The `ant_diversity`
/// flag itself is structural — this owner is only composed for
/// diversity RFEs — while `fixed` mirrors Linux's early return in
/// `parse` / `track`.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct AntDiv {
    target: Stats,
    main: Stats,
    aux: Stats,
    training_count: u8,
    rssi_pre: u8,
    get_stats: bool,
    antenna_tx: u8,
    antenna_rx: u8,
    fixed: bool,
}

/// Outcome of [`AntDiv::track`]: the target RSSI moved by less than
/// [`RSSI_DIFF_TH`] (stable, no work) or by at least that much (queue
/// the training work immediately, period 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TrackOutcome {
    Stable,
    StartTraining,
}

/// Outcome of [`AntDiv::step`] (`rtw89_phy_antdiv_work`): a training
/// step, with the re-queue period in milliseconds and the ANTSEL
/// program only on odd (post-swap) steps, or a decision step, whose
/// ANTSEL program always follows the decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Work {
    Training {
        period_ms: u32,
        set_ant: Option<[Field; 4]>,
    },
    Decision {
        set_ant: [Field; 4],
    },
}

impl AntDiv {
    /// `rtw89_phy_antdiv_init` state half: collect gate closed,
    /// previous RSSI 0, all three stats instances reset. The
    /// `reg_init` writes are [`reg_init_fields`], applied by the
    /// composer. Antennas arrive as the one-path `RF_A` pair from
    /// `mac_setup_phycap`.
    pub(super) fn new(antenna_tx: u8, antenna_rx: u8) -> Self {
        Self {
            antenna_tx,
            antenna_rx,
            ..Self::default()
        }
    }

    /// Mirror `ant_diversity_fixed` for the `parse` / `track` gates.
    pub(super) fn set_fixed(&mut self, fixed: bool) {
        self.fixed = fixed;
    }

    pub(super) fn antenna_tx(&self) -> u8 {
        self.antenna_tx
    }

    pub(super) fn antenna_rx(&self) -> u8 {
        self.antenna_rx
    }

    pub(super) fn training_count(&self) -> u8 {
        self.training_count
    }

    pub(super) fn get_stats(&self) -> bool {
        self.get_stats
    }

    pub(super) fn rssi_pre(&self) -> u8 {
        self.rssi_pre
    }

    fn reset_stats(&mut self) {
        self.target.reset();
        self.main.reset();
        self.aux.reset();
    }

    /// `rtw89_phy_antdiv_set_ant` (`R_P0_ANTSEL` 0x586C, PHY_0): when
    /// transmitting on RF_B the default antenna is AUX and the
    /// alternate is MAIN; otherwise the default is MAIN and the
    /// alternate is AUX. (Linux additionally returns early for
    /// `antenna_tx == 0`; a composed owner always carries RF_A/RF_B
    /// from `new`/`swap`, so that gate is unreachable here and the
    /// else branch — default MAIN — is the faithful program.)
    pub(super) fn set_ant_fields(&self) -> [Field; 4] {
        let (default_ant, optional_ant) = if self.antenna_tx == RF_B {
            (ANTDIV_AUX, ANTDIV_MAIN)
        } else {
            (ANTDIV_MAIN, ANTDIV_AUX)
        };
        [
            // B_P0_ANTSEL_CGCS_CTRL BIT(17).
            (PHY + 0x586C, 1 << 17, default_ant),
            // B_P0_ANTSEL_RX_ORI GENMASK(7,4).
            (PHY + 0x586C, 0xF0, default_ant),
            // B_P0_ANTSEL_RX_ALT GENMASK(11,8).
            (PHY + 0x586C, 0xF00, optional_ant),
            // B_P0_ANTSEL_TX_ORI GENMASK(15,12).
            (PHY + 0x586C, 0xF000, default_ant),
        ]
    }

    /// `rtw89_phy_swap_hal_antenna`: receive flips RF_A <-> RF_B
    /// (anything not RF_A becomes RF_A, matching the ternary), then
    /// transmit follows receive.
    fn swap(&mut self) {
        self.antenna_rx = if self.antenna_rx == RF_A { RF_B } else { RF_A };
        self.antenna_tx = self.antenna_rx;
    }

    /// `rtw89_phy_antdiv_parse`: always accumulate into target; when
    /// the collect gate is open, also into main (receive on RF_A) or
    /// aux (receive on RF_B). Returns early when fixed.
    pub(super) fn parse(&mut self, class: PpduClass, rssi_avg: u8, evm_min: u8) {
        if self.fixed {
            return;
        }
        self.target.add(class, rssi_avg, evm_min);
        if !self.get_stats {
            return;
        }
        if self.antenna_rx == RF_A {
            self.main.add(class, rssi_avg, evm_min);
        } else if self.antenna_rx == RF_B {
            self.aux.add(class, rssi_avg, evm_min);
        }
    }

    /// `rtw89_phy_antdiv_track`: the target RSSI becomes the new
    /// previous value and the target instance resets, whether or not
    /// training starts. A move of at least [`RSSI_DIFF_TH`] restarts
    /// training from count 0. Returns early when fixed.
    pub(super) fn track(&mut self) -> TrackOutcome {
        if self.fixed {
            return TrackOutcome::Stable;
        }
        let rssi = self.target.rssi();
        let rssi_pre = self.rssi_pre;
        self.rssi_pre = rssi;
        self.target.reset();
        if rssi.abs_diff(rssi_pre) < RSSI_DIFF_TH {
            TrackOutcome::Stable
        } else {
            self.training_count = 0;
            TrackOutcome::StartTraining
        }
    }

    /// `rtw89_phy_antdiv_decision_state`: collect gate closed,
    /// training count reset, then EVM decides first (a difference over
    /// [`EVM_DIFF_TH`] wins outright), RSSI decides next (a difference
    /// over [`TX_DIV_RSSI_RAW_TH`]), and no decision swaps back from
    /// the training antenna to the original. A decision sets both
    /// transmit and receive to the candidate.
    fn decide(&mut self) {
        self.get_stats = false;
        self.training_count = 0;
        let main_rssi = u32::from(self.main.rssi());
        let aux_rssi = u32::from(self.aux.rssi());
        let main_evm = u32::from(self.main.evm());
        let aux_evm = u32::from(self.aux.evm());
        let candidate = if main_evm > aux_evm + EVM_DIFF_TH {
            Some(RF_A)
        } else if aux_evm > main_evm + EVM_DIFF_TH {
            Some(RF_B)
        } else if main_rssi > aux_rssi + TX_DIV_RSSI_RAW_TH {
            Some(RF_A)
        } else if aux_rssi > main_rssi + TX_DIV_RSSI_RAW_TH {
            Some(RF_B)
        } else {
            None
        };
        match candidate {
            Some(antenna) => {
                self.antenna_tx = antenna;
                self.antenna_rx = antenna;
            }
            // Swap back from the training antenna to the original.
            None => self.swap(),
        }
    }

    /// `rtw89_phy_antdiv_work`: while `training_count <=
    /// TRAINNING_CNT`, run the training state; otherwise decide and
    /// program ANTSEL. Training alternates: even counts open the
    /// collect gate for 30 ms (count 0 also resets all stats); odd
    /// counts close the gate, swap antennas, program ANTSEL, and wait
    /// 110 ms for the switch to settle.
    pub(super) fn step(&mut self) -> Work {
        if self.training_count <= TRAINNING_CNT {
            let (period_ms, set_ant) = if self.training_count % 2 == 0 {
                if self.training_count == 0 {
                    self.reset_stats();
                }
                self.get_stats = true;
                (TRAINNING_INTVL_MS, None)
            } else {
                self.get_stats = false;
                self.swap();
                (DELAY_MS, Some(self.set_ant_fields()))
            };
            self.training_count += 1;
            Work::Training { period_ms, set_ant }
        } else {
            self.decide();
            Work::Decision {
                set_ant: self.set_ant_fields(),
            }
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "antdiv_51/tests.rs"]
mod tests;
