//! Bluetooth coexistence glue (`btcoex.c`): scheme selection, the MCI
//! defaults, the WLAN weight tables, the 2WIRE/3WIRE enable/init paths
//! and the scheme dispatcher.
//!
//! Grounded in Linux `drivers/net/wireless/ath/ath9k/btcoex.c` and
//! `btcoex.h` @ commit `cbbddb6b08cc9900a87cccaa9b22bbe06aa4f50a`
//! (2026-10-31), plus `reg.h` for the weight/mode registers and `hw.h`
//! / `hw.c` for the GPIO request helpers.
//!
//! What this implements:
//! - `init_scheme`: NONE when coexistence is disabled, MCI when the
//!   capability is set, 3WIRE otherwise (every AR9003 part satisfies
//!   `AR_SREV_9300_20_OR_LATER`, so the AR9280 2WIRE branch is
//!   unreachable here).
//! - `init_mci`: the `ath9k_hw_btcoex_init_mci` defaults, including the
//!   `0x2201` (AR9462) / `0xa4c1` (other) config word.
//! - `set_weight` / `bt_stomp`: the WLAN weight tables (`mci_wlan_weights`
//!   for AR9462/AR9565, `ar9003_wlan_weights` otherwise) with the
//!   concurrent-TX priority overlay.
//! - `enable_mci` / `disable_mci`: the MCI weight-register programming.
//! - `init_btcoex_hw`: the `ath9k_hw_init_btcoex_hw` mode/mode2/mode3
//!   computation (slotted mode, the `AR_SREV_9300_20_OR_LATER`
//!   rx-clear-polarity flip, the SOC first-slot/time-extend overrides).
//! - `init_2wire` / `init_3wire`: the baseband input-enable bits, the
//!   BT-active/BT-priority input muxes and the GPIO request-in wiring.
//! - `enable_2wire` / `enable_3wire`: the WLAN-active GPIO request-out
//!   (TX_FRAME / RX_CLEAR_EXTERNAL mux) and, for 3WIRE, the mode/weight
//!   register programming.
//! - `deinit`: the GPIO free — a no-op on AR9003 (Linux's
//!   `ath9k_hw_gpio_free` returns early for non-SoC parts).
//! - `btcoex_enable` / `btcoex_disable`: the scheme dispatcher,
//!   including the BT-active pull-down programming on enable.
//!
//! Not this file: the live-owner integration (the owner holds `Btcoex`
//! and calls `init_btcoex_hw` / `init_2wire` / `init_3wire` /
//! `btcoex_enable` / `btcoex_disable` / `deinit`; see #1931), the
//! driver-layer BT profile list and duty-cycle scheme (#1932 / #2056),
//! and the WoW `mci_enabled` flag integration (#1935).

use super::mci::{
    gpio_request_out, Mci, AR_BTCOEX_WL_WEIGHTS0, AR_BTCOEX_WL_WEIGHTS1, AR_BTCOEX_WL_WEIGHTS2,
    AR_BTCOEX_WL_WEIGHTS3, AR_QUIET1, AR_QUIET1_QUIET_ACK_CTS_ENABLE,
    MCI_GPM_COEX_MAJOR_VERSION_DEFAULT, MCI_GPM_COEX_MINOR_VERSION_DEFAULT,
};
use super::{field, rmw, Chip, HW_CAP_MCI};
use crate::ath9k::identity::{BringUpError, RegisterIo};

/// `btcoex.h::ATH_WLANACTIVE_GPIO_9300`.
const WLANACTIVE_GPIO_9300: u8 = 5;
/// `btcoex.h::ATH_BTACTIVE_GPIO_9300`.
const BTACTIVE_GPIO_9300: u8 = 4;
/// `btcoex.h::ATH_BTPRIORITY_GPIO_9300`.
const BTPRIORITY_GPIO_9300: u8 = 8;

/// `btcoex.h::ATH_BTCOEX_STOMP_MAX`: one TX-priority byte per stomp type.
const STOMP_MAX: usize = 5;

/// `reg.h::AR9300_BT_WGHT`: the BT weight programmed for every slot.
const BT_WGHT: u32 = 0xcccc_4444;

/// `btcoex.c::enum ath_bt_mode`: the coexistence mode field values.
/// The init config below always selects slotted mode.
const BT_COEX_MODE_SLOTTED: u32 = 2;

/// `btcoex.c::ath9k_hw_init_btcoex_hw` (`ath_btcoex_config`): the fixed
/// mode configuration. `bt_time_extend` 0 and `bt_first_slot_time` 5
/// are the non-SoC values; the SoC overrides are
/// `SOC_BT_TIME_EXTEND` (`0xa`) and `SOC_BT_FIRST_SLOT_TIME` (`0x1d`).
const BT_TIME_EXTEND: u32 = 0;
const BT_FIRST_SLOT_TIME: u32 = 5;
const SOC_BT_TIME_EXTEND: u32 = 0xa;
const SOC_BT_FIRST_SLOT_TIME: u32 = 0x1d;
/// `btcoex.c`: the WLAN-active / quiet-collision times for the SoC
/// mode3 image (`wl_active_time` / `wl_qc_time`, both `0x20`).
const BT_WL_ACTIVE_TIME: u32 = 0x20;
const BT_WL_QC_TIME: u32 = 0x20;
/// `btcoex.c`: the BT priority time (`bt_priority_time`, 2).
const BT_PRIORITY_TIME: u32 = 2;
/// `btcoex.h::ATH_BTCOEX_BMISS_THRESH`: the beacon-miss threshold
/// programmed into mode2 (50).
const BMISS_THRESH: u32 = 50;

/// `reg.h::AR_BT_COEX_MODE` / `AR_BT_COEX_MODE2` / `AR_BT_COEX_MODE3`
/// and their fields (`_S` is the shift of the matching mask).
const AR_BT_COEX_MODE: u64 = 0x8170;
const AR_BT_COEX_MODE2: u64 = 0x817c;
const AR_BT_COEX_MODE3: u64 = 0x81d4;
const AR_BT_TIME_EXTEND: u32 = 0x0000_00ff;
const AR_BT_TIME_EXTEND_S: u32 = 0;
const AR_BT_TXSTATE_EXTEND: u32 = 0x0000_0100;
const AR_BT_TXSTATE_EXTEND_S: u32 = 8;
const AR_BT_TX_FRAME_EXTEND: u32 = 0x0000_0200;
const AR_BT_TX_FRAME_EXTEND_S: u32 = 9;
const AR_BT_MODE: u32 = 0x0000_0c00;
const AR_BT_MODE_S: u32 = 10;
const AR_BT_QUIET: u32 = 0x0000_1000;
const AR_BT_QUIET_S: u32 = 12;
const AR_BT_QCU_THRESH: u32 = 0x0001_e000;
const AR_BT_QCU_THRESH_S: u32 = 13;
const AR_BT_RX_CLEAR_POLARITY: u32 = 0x0002_0000;
const AR_BT_RX_CLEAR_POLARITY_S: u32 = 17;
const AR_BT_PRIORITY_TIME: u32 = 0x00fc_0000;
const AR_BT_PRIORITY_TIME_S: u32 = 18;
const AR_BT_FIRST_SLOT_TIME: u32 = 0xff00_0000;
const AR_BT_FIRST_SLOT_TIME_S: u32 = 24;
const AR_BT_BCN_MISS_THRESH: u32 = 0x0000_00ff;
const AR_BT_BCN_MISS_THRESH_S: u32 = 0;
const AR_BT_HOLD_RX_CLEAR: u32 = 0x0001_0000;
const AR_BT_HOLD_RX_CLEAR_S: u32 = 16;
const AR_BT_PROTECT_BT_AFTER_WAKEUP: u32 = 0x0008_0000;
const AR_BT_DISABLE_BT_ANT: u32 = 0x0010_0000;
const AR_BT_PHY_ERR_BT_COLL_ENABLE: u32 = 0x8000_0000;
const AR_BT_WL_ACTIVE_TIME: u32 = 0x0000_00ff;
const AR_BT_WL_ACTIVE_TIME_S: u32 = 0;
const AR_BT_WL_QC_TIME: u32 = 0x0000_ff00;
const AR_BT_WL_QC_TIME_S: u32 = 8;

/// `reg.h::AR_BT_COEX_WL_WEIGHTS0` / `AR_BT_COEX_WL_WEIGHTS1` (the
/// non-MCI WLAN weight registers, `0x8174` / `0x81c4`) and
/// `AR_BT_COEX_BT_WEIGHTS(i)` (`0x83ac + i * 4`). These are distinct
/// from the MCI weight registers (`AR_MCI_COEX_WL_WEIGHTS(i)`,
/// `0x18b0 + i * 4`, imported from `mci.rs` as
/// `AR_BTCOEX_WL_WEIGHTS0..3`).
const AR_BT_COEX_WL_WEIGHTS0: u64 = 0x8174;
const AR_BT_COEX_WL_WEIGHTS1: u64 = 0x81c4;
/// `reg.h::AR_BT_COEX_BT_WEIGHTS(i)`.
const fn ar_bt_coex_bt_weights(i: u32) -> u64 {
    0x83ac + (i as u64) * 4
}

/// `reg.h::AR_GPIO_INPUT_EN_VAL` (AR9300 2.0+, `0x405c`) and the
/// baseband input-enable bits it carries for the 2WIRE/3WIRE init.
const AR_GPIO_INPUT_EN_VAL: u64 = 0x405c;
const AR_GPIO_INPUT_EN_VAL_BT_PRIORITY_DEF: u32 = 0x0000_0004;
const AR_GPIO_INPUT_EN_VAL_BT_FREQUENCY_DEF: u32 = 0x0000_0008;
const AR_GPIO_INPUT_EN_VAL_BT_PRIORITY_BB: u32 = 0x0000_0400;
const AR_GPIO_INPUT_EN_VAL_BT_ACTIVE_BB: u32 = 0x0000_1000;
/// `reg.h::AR_GPIO_INPUT_MUX1` (AR9300 2.0+, `0x4060`) and the
/// BT-active / BT-priority input-mux fields.
const AR_GPIO_INPUT_MUX1: u64 = 0x4060;
const AR_GPIO_INPUT_MUX1_BT_ACTIVE: u32 = 0x000f_0000;
const AR_GPIO_INPUT_MUX1_BT_ACTIVE_S: u32 = 16;
const AR_GPIO_INPUT_MUX1_BT_PRIORITY: u32 = 0x0000_0f00;
const AR_GPIO_INPUT_MUX1_BT_PRIORITY_S: u32 = 8;
/// `reg.h::AR_GPIO_OE_OUT` (AR9300 2.0+, `0x4050`) and
/// `AR_GPIO_OE_OUT_DRV_ALL` (2 bits per pin); the request-in path
/// writes drive NO (`0`) into the pin's field.
const AR_GPIO_OE_OUT: u64 = 0x4050;
const AR_GPIO_OE_OUT_DRV_ALL: u32 = 0x3;
/// `reg.h::AR_GPIO_OUTPUT_MUX1` (AR9300 2.0+, `0x4068`): the output
/// mux for pins 0..5, one 5-bit field per pin at `(gpio % 6) * 5`.
/// Used by the tests to pin the `gpio_request_out` mux writes.
const AR_GPIO_OUTPUT_MUX1: u64 = 0x4068;
/// `reg.h::AR_GPIO_PDPU` (AR9300 2.0+, `0x4090`): the BT-active
/// pull-down programmed on enable (2 bits per pin).
const AR_GPIO_PDPU: u64 = 0x4090;
/// `reg.h::AR_PCU_MISC` and `reg.h::AR_PCU_BT_ANT_PREVENT_RX`
/// (cleared on 3WIRE enable).
const AR_PCU_MISC: u64 = 0x8120;
const AR_PCU_BT_ANT_PREVENT_RX: u32 = 0x0010_0000;
/// `hw.h::AR_GPIO_OUTPUT_MUX_AS_*` values used by the 2WIRE/3WIRE
/// enable/disable paths.
const GPIO_MUX_AS_OUTPUT: u32 = 0;
const GPIO_MUX_AS_TX_FRAME: u32 = 3;
const GPIO_MUX_AS_RX_CLEAR_EXTERNAL: u32 = 4;

/// `hw.h::SM(v, f)`: `((v << f_S) & f)` — the field value for a
/// register image, without touching hardware.
const fn sm(value: u32, mask: u32, shift: u32) -> u32 {
    (value << shift) & mask
}

/// `btcoex.c::ar9003_wlan_weights`: the WLAN weights for non-MCI AR9003
/// parts. Only the first three rows are initialised in Linux; the
/// `LOW_FTP` and `AUDIO` rows are zero-initialised there and are zero
/// here.
const AR9003_WLAN_WEIGHTS: [[u32; 4]; STOMP_MAX] = [
    [0xffff_fff0, 0xffff_fff0, 0xffff_fff0, 0xffff_fff0],
    [0x8888_8880, 0x8888_8880, 0x8888_8880, 0x8888_8880],
    [0x0000_0000, 0x0000_0000, 0x0000_0000, 0x0000_0000],
    [0x0000_0000, 0x0000_0000, 0x0000_0000, 0x0000_0000],
    [0x0000_0000, 0x0000_0000, 0x0000_0000, 0x0000_0000],
];

/// `btcoex.c::mci_wlan_weights`: the WLAN weights for AR9462/AR9565.
const MCI_WLAN_WEIGHTS: [[u32; 4]; STOMP_MAX] = [
    [0x0101_7d01, 0x4141_4101, 0x4141_4101, 0x4141_4141],
    [0x0101_7d01, 0x3b3b_3b01, 0x3b3b_3b01, 0x3b3b_3b3b],
    [0x0101_7d01, 0x0101_0101, 0x0101_0101, 0x0101_0101],
    [0x0101_7d01, 0x013b_0101, 0x3b3b_0101, 0x3b3b_013b],
    [0xffff_ff01, 0xffff_ffff, 0xffff_ff01, 0xffff_ffff],
];

/// `btcoex.c::ath9k_hw_btcoex_set_weight` TX-priority shifts, one per
/// WLAN weight slot after the first.
const TXPRIO_SHIFT: [u32; 4] = [24, 16, 16, 0];

/// `btcoex.h::enum ath_stomp_type`, in Linux order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(in crate::ath9k) enum StompType {
    /// `ATH_BTCOEX_STOMP_ALL`.
    All = 0,
    /// `ATH_BTCOEX_STOMP_LOW`.
    Low = 1,
    /// `ATH_BTCOEX_STOMP_NONE`.
    None = 2,
    /// `ATH_BTCOEX_STOMP_LOW_FTP`.
    LowFtp = 3,
    /// `ATH_BTCOEX_STOMP_AUDIO`.
    Audio = 4,
}

/// `btcoex.h::enum ath_btcoex_scheme`, in Linux order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(in crate::ath9k) enum Scheme {
    /// `ATH_BTCOEX_CFG_NONE`.
    None = 0,
    /// `ATH_BTCOEX_CFG_2WIRE`.
    TwoWire = 1,
    /// `ATH_BTCOEX_CFG_3WIRE`.
    ThreeWire = 2,
    /// `ATH_BTCOEX_CFG_MCI`.
    Mci = 3,
}

/// The Bluetooth coexistence state (`btcoex.h::struct ath_btcoex_hw`),
/// holding the MCI engine plus the scheme, weight and mode-register
/// state the enable paths program. The pre-AR9300 `bt_coex_weights`
/// image is not stored: `set_weight`'s combined-weight branch and the
/// `AR_BT_COEX_WEIGHT` writes in `enable_3wire` / `disable` only feed
/// the unreachable pre-AR9300 path, as with the weight arguments
/// `set_weight` does not take.
pub(in crate::ath9k) struct Btcoex {
    /// The selected coexistence scheme.
    pub(in crate::ath9k) scheme: Scheme,
    /// The MCI engine.
    pub(in crate::ath9k) mci: Mci,
    /// Whether coexistence is enabled (`btcoex_hw.enabled`).
    pub(in crate::ath9k) enabled: bool,
    /// WLAN-active GPIO pin.
    pub(in crate::ath9k) wlanactive_gpio: u8,
    /// BT-active GPIO pin.
    pub(in crate::ath9k) btactive_gpio: u8,
    /// BT-priority GPIO pin.
    pub(in crate::ath9k) btpriority_gpio: u8,
    /// BT weights, one per WLAN weight slot.
    pub(in crate::ath9k) bt_weight: [u32; 4],
    /// WLAN weights, one per slot.
    pub(in crate::ath9k) wlan_weight: [u32; 4],
    /// Concurrent-TX priority per stomp type.
    pub(in crate::ath9k) tx_prio: [u8; STOMP_MAX],
    /// Register image for `AR_BT_COEX_MODE` (`init_btcoex_hw`).
    pub(in crate::ath9k) bt_coex_mode: u32,
    /// Register image for `AR_BT_COEX_MODE2` (`init_btcoex_hw`).
    pub(in crate::ath9k) bt_coex_mode2: u32,
    /// Register image for `AR_BT_COEX_MODE3` (`init_btcoex_hw`, SoC only).
    pub(in crate::ath9k) bt_coex_mode3: u32,
}

impl Btcoex {
    /// A fresh coexistence state for `chip`, scheme unselected.
    pub(in crate::ath9k) fn new(chip: Chip) -> Self {
        Self {
            scheme: Scheme::None,
            mci: Mci::new(chip),
            enabled: false,
            wlanactive_gpio: 0,
            btactive_gpio: 0,
            btpriority_gpio: 0,
            bt_weight: [0; 4],
            wlan_weight: [0; 4],
            tx_prio: [0; STOMP_MAX],
            bt_coex_mode: 0,
            bt_coex_mode2: 0,
            bt_coex_mode3: 0,
        }
    }
}

/// `hw.h::ath9k_hw_mci_is_enabled`: coexistence is globally enabled
/// and the chip carries the MCI capability.
pub(in crate::ath9k) fn mci_is_enabled(btcoex_enabled: bool, hw_caps: u32) -> bool {
    btcoex_enabled && hw_caps & HW_CAP_MCI != 0
}

/// `btcoex.c::ath9k_hw_btcoex_init_scheme`: pick the coexistence
/// scheme. NONE when coexistence is disabled, MCI when the capability
/// is set, 3WIRE otherwise. The AR9280 2WIRE branch is unreachable for
/// AR9003 (every in-tree part satisfies `AR_SREV_9300_20_OR_LATER`).
pub(in crate::ath9k) fn init_scheme(btcoex: &mut Btcoex, btcoex_enabled: bool, hw_caps: u32) {
    if !btcoex_enabled {
        btcoex.scheme = Scheme::None;
        return;
    }
    if hw_caps & HW_CAP_MCI != 0 {
        btcoex.scheme = Scheme::Mci;
    } else {
        btcoex.scheme = Scheme::ThreeWire;
        btcoex.wlanactive_gpio = WLANACTIVE_GPIO_9300;
        btcoex.btactive_gpio = BTACTIVE_GPIO_9300;
        btcoex.btpriority_gpio = BTPRIORITY_GPIO_9300;
    }
}

/// `btcoex.c::ath9k_hw_init_btcoex_hw`: compute the `AR_BT_COEX_MODE`
/// / `MODE2` / `MODE3` register images from the fixed Linux config
/// (slotted mode, TX-state and TX-frame extend on, quiet collision on,
/// priority time 2, first slot 5, hold-RX-clear on, beacon-miss
/// threshold 50). No register is written here; `enable_3wire` programs
/// the images.
///
/// `qnum` is the TX queue number (Linux `gpio.c` passes
/// `txq->axq_qnum`); it lands in the mode's QCU-threshold field.
/// `is_soc` selects the SoC overrides: first-slot time `0x1d`,
/// time-extend `0xa`, the mode3 image (`wl_active_time` /
/// `wl_qc_time`, both `0x20`) and the mode2 protect-after-wakeup /
/// PHY-error-collision bits. No in-tree part is a SoC — the owner
/// passes `false` today; the branch exists so the overrides are
/// ported, not dropped.
///
/// Deviations, kept verbatim from Linux: every in-tree part satisfies
/// `AR_SREV_9300_20_OR_LATER`, so the configured rx-clear polarity
/// (`true`) is always inverted (`false`); the mode image preserves the
/// previous QCU-threshold bits and ORs the new `qnum` in, so a stale
/// threshold survives when `qnum` does not cover it; mode2
/// accumulates (`|=`), so a preset mode2 keeps its stray bits.
pub(in crate::ath9k) fn init_btcoex_hw(btcoex: &mut Btcoex, qnum: u8, is_soc: bool) {
    let mut time_extend = BT_TIME_EXTEND;
    let mut first_slot_time = BT_FIRST_SLOT_TIME;

    if is_soc {
        first_slot_time = SOC_BT_FIRST_SLOT_TIME;
        time_extend = SOC_BT_TIME_EXTEND;

        btcoex.bt_coex_mode3 = sm(
            BT_WL_ACTIVE_TIME,
            AR_BT_WL_ACTIVE_TIME,
            AR_BT_WL_ACTIVE_TIME_S,
        ) | sm(BT_WL_QC_TIME, AR_BT_WL_QC_TIME, AR_BT_WL_QC_TIME_S);

        btcoex.bt_coex_mode2 = AR_BT_PROTECT_BT_AFTER_WAKEUP | AR_BT_PHY_ERR_BT_COLL_ENABLE;
    }

    // The configured polarity is `true`; `AR_SREV_9300_20_OR_LATER`
    // inverts it, and every in-tree part satisfies that revision.
    let rxclear_polarity = false;

    btcoex.bt_coex_mode = (btcoex.bt_coex_mode & AR_BT_QCU_THRESH)
        | sm(time_extend, AR_BT_TIME_EXTEND, AR_BT_TIME_EXTEND_S)
        | sm(1, AR_BT_TXSTATE_EXTEND, AR_BT_TXSTATE_EXTEND_S)
        | sm(1, AR_BT_TX_FRAME_EXTEND, AR_BT_TX_FRAME_EXTEND_S)
        | sm(BT_COEX_MODE_SLOTTED, AR_BT_MODE, AR_BT_MODE_S)
        | sm(1, AR_BT_QUIET, AR_BT_QUIET_S)
        | sm(
            u32::from(rxclear_polarity),
            AR_BT_RX_CLEAR_POLARITY,
            AR_BT_RX_CLEAR_POLARITY_S,
        )
        | sm(BT_PRIORITY_TIME, AR_BT_PRIORITY_TIME, AR_BT_PRIORITY_TIME_S)
        | sm(
            first_slot_time,
            AR_BT_FIRST_SLOT_TIME,
            AR_BT_FIRST_SLOT_TIME_S,
        )
        | sm(u32::from(qnum), AR_BT_QCU_THRESH, AR_BT_QCU_THRESH_S);

    btcoex.bt_coex_mode2 |= sm(1, AR_BT_HOLD_RX_CLEAR, AR_BT_HOLD_RX_CLEAR_S)
        | sm(BMISS_THRESH, AR_BT_BCN_MISS_THRESH, AR_BT_BCN_MISS_THRESH_S)
        | AR_BT_DISABLE_BT_ANT;
}

/// `btcoex.c::ath9k_hw_btcoex_init_mci`: reset the MCI state to the
/// Linux defaults. Only the fields Linux touches are reset; the GPM
/// buffer address/length, the schedule address, the concurrent-TX flag
/// and the FTP-stomp flag keep their values.
pub(in crate::ath9k) fn init_mci(btcoex: &mut Btcoex) {
    let mci = &mut btcoex.mci;
    mci.ready = false;
    mci.bt_state = super::mci::BtState::Sleep;
    mci.bt_ver_major = MCI_GPM_COEX_MAJOR_VERSION_DEFAULT;
    mci.bt_ver_minor = MCI_GPM_COEX_MINOR_VERSION_DEFAULT;
    mci.bt_version_known = false;
    mci.update_2g5g = true;
    mci.is_2g = true;
    mci.wlan_channels_update = false;
    mci.wlan_channels = [0x0000_0000, 0xffff_ffff, 0xffff_ffff, 0x7fff_ffff];
    mci.query_bt = true;
    mci.unhalt_bt_gpm = true;
    mci.halted_bt_gpm = false;
    mci.need_flush_btinfo = false;
    mci.wlan_cal_seq = 0;
    mci.wlan_cal_done = 0;
    mci.config = if mci.chip == Chip::Ar9462 {
        0x2201
    } else {
        0xa4c1
    };
}

/// `hw.c::ath9k_hw_gpio_request_in` on an AR9003 (non-SoC, non-7010):
/// the WMAC path writes drive NO (`0`) into the pin's 2-bit
/// `AR_GPIO_OE_OUT` field. The SoC `gpiod` path does not apply to any
/// in-tree part.
fn gpio_request_in(io: &mut impl RegisterIo, gpio: u8) -> Result<(), BringUpError> {
    rmw(
        io,
        AR_GPIO_OE_OUT,
        AR_GPIO_OE_OUT_DRV_ALL << (u32::from(gpio) * 2),
        0,
    )
}

/// `btcoex.c::ath9k_hw_btcoex_init_2wire`: connect BT-active to the
/// baseband (clear the default BT-priority/BT-frequency input-enable
/// bits, set the BT-active baseband bit), route the BT-active input
/// mux to the configured GPIO pin (non-SoC only) and request the pin
/// as an input. The AR9280 2WIRE branch is unreachable for AR9003, but
/// the path is ported whole so the file's 2WIRE half is not a stub.
pub(in crate::ath9k) fn init_2wire(
    io: &mut impl RegisterIo,
    btcoex: &Btcoex,
    is_soc: bool,
) -> Result<(), BringUpError> {
    rmw(
        io,
        AR_GPIO_INPUT_EN_VAL,
        AR_GPIO_INPUT_EN_VAL_BT_PRIORITY_DEF | AR_GPIO_INPUT_EN_VAL_BT_FREQUENCY_DEF,
        0,
    )?;
    rmw(
        io,
        AR_GPIO_INPUT_EN_VAL,
        0,
        AR_GPIO_INPUT_EN_VAL_BT_ACTIVE_BB,
    )?;
    if !is_soc {
        field(
            io,
            AR_GPIO_INPUT_MUX1,
            AR_GPIO_INPUT_MUX1_BT_ACTIVE,
            AR_GPIO_INPUT_MUX1_BT_ACTIVE_S,
            u32::from(btcoex.btactive_gpio),
        )?;
    }
    gpio_request_in(io, btcoex.btactive_gpio)
}

/// `btcoex.c::ath9k_hw_btcoex_init_3wire`: connect BT-active and
/// BT-priority to the baseband, route both input muxes to the
/// configured GPIO pins (non-SoC only) and request both pins as
/// inputs.
pub(in crate::ath9k) fn init_3wire(
    io: &mut impl RegisterIo,
    btcoex: &Btcoex,
    is_soc: bool,
) -> Result<(), BringUpError> {
    rmw(
        io,
        AR_GPIO_INPUT_EN_VAL,
        0,
        AR_GPIO_INPUT_EN_VAL_BT_PRIORITY_BB | AR_GPIO_INPUT_EN_VAL_BT_ACTIVE_BB,
    )?;
    if !is_soc {
        field(
            io,
            AR_GPIO_INPUT_MUX1,
            AR_GPIO_INPUT_MUX1_BT_ACTIVE,
            AR_GPIO_INPUT_MUX1_BT_ACTIVE_S,
            u32::from(btcoex.btactive_gpio),
        )?;
        field(
            io,
            AR_GPIO_INPUT_MUX1,
            AR_GPIO_INPUT_MUX1_BT_PRIORITY,
            AR_GPIO_INPUT_MUX1_BT_PRIORITY_S,
            u32::from(btcoex.btpriority_gpio),
        )?;
    }
    gpio_request_in(io, btcoex.btactive_gpio)?;
    gpio_request_in(io, btcoex.btpriority_gpio)
}

/// `btcoex.c::ath9k_hw_btcoex_deinit`: free the BT-active,
/// BT-priority and WLAN-active GPIOs. On AR9003 this is a no-op:
/// Linux's `ath9k_hw_gpio_free` returns early for non-SoC parts (only
/// the SoC `gpiod` path releases anything), and no in-tree part is a
/// SoC. Kept as the teardown hook so the owner calls the same shape
/// on every scheme; the pins and mode images are left untouched.
pub(in crate::ath9k) fn deinit(_btcoex: &Btcoex) {}

/// `btcoex.c::ath9k_hw_btcoex_set_weight` for AR9003
/// (`AR_SREV_9300_20_OR_LATER`): pick the WLAN weight table for the
/// stomp type (the MCI table for AR9462/AR9565, promoting `LOW` to
/// `LOW_FTP` when FTP stomping is on) and overlay the concurrent-TX
/// priority. The `bt_weight`/`wlan_weight` arguments of the Linux
/// function only feed the unreachable pre-AR9300 path, so they are not
/// parameters here.
pub(in crate::ath9k) fn set_weight(btcoex: &mut Btcoex, stomp_type: StompType) {
    let chip = btcoex.mci.chip;
    let stype = if stomp_type == StompType::Low && btcoex.mci.stomp_ftp {
        StompType::LowFtp
    } else {
        stomp_type
    };
    let weight = if chip == Chip::Ar9462 || chip == Chip::Ar9565 {
        MCI_WLAN_WEIGHTS[stype as usize]
    } else {
        AR9003_WLAN_WEIGHTS[stomp_type as usize]
    };
    let concur_tx = btcoex.mci.concur_tx && btcoex.tx_prio[stomp_type as usize] != 0;
    for i in 0..4 {
        btcoex.bt_weight[i] = BT_WGHT;
        btcoex.wlan_weight[i] = weight[i];
        if concur_tx && i > 0 {
            btcoex.wlan_weight[i] &= !(0xff << TXPRIO_SHIFT[i - 1]);
            btcoex.wlan_weight[i] |=
                u32::from(btcoex.tx_prio[stomp_type as usize]) << TXPRIO_SHIFT[i - 1];
        }
    }
    // Last WLAN weight has to be adjusted wrt tx priority.
    if concur_tx {
        btcoex.wlan_weight[3] &= !(0xff << TXPRIO_SHIFT[3]);
        btcoex.wlan_weight[3] |= u32::from(btcoex.tx_prio[stomp_type as usize]) << TXPRIO_SHIFT[3];
    }
}

/// `btcoex.c::ath9k_hw_btcoex_bt_stomp` for AR9003: configure the
/// weights for a stomp type.
pub(in crate::ath9k) fn bt_stomp(btcoex: &mut Btcoex, stomp_type: StompType) {
    set_weight(btcoex, stomp_type);
}

/// `btcoex.c::ath9k_hw_btcoex_set_concur_txprio`: record the
/// concurrent-TX priority per stomp type.
pub(in crate::ath9k) fn set_concur_txprio(btcoex: &mut Btcoex, stomp_txprio: [u8; STOMP_MAX]) {
    btcoex.tx_prio = stomp_txprio;
}

/// `btcoex.c::ath9k_hw_btcoex_enable_mci`: program the WLAN weight
/// registers and the quiet-ack CTS enable, then mark coexistence
/// enabled. Call `bt_stomp` first to compute the weights.
pub(in crate::ath9k) fn enable_mci(
    io: &mut impl RegisterIo,
    btcoex: &mut Btcoex,
) -> Result<(), BringUpError> {
    io.write32(AR_BTCOEX_WL_WEIGHTS0, btcoex.wlan_weight[0]);
    io.write32(AR_BTCOEX_WL_WEIGHTS1, btcoex.wlan_weight[1]);
    io.write32(AR_BTCOEX_WL_WEIGHTS2, btcoex.wlan_weight[2]);
    io.write32(AR_BTCOEX_WL_WEIGHTS3, btcoex.wlan_weight[3]);
    rmw(io, AR_QUIET1, 0, AR_QUIET1_QUIET_ACK_CTS_ENABLE)?;
    btcoex.enabled = true;
    Ok(())
}

/// `btcoex.c::ath9k_hw_btcoex_disable_mci`: stomp everything, then
/// re-program the (now zeroed) WLAN weight registers. The caller
/// clears `enabled` first, as `ath9k_hw_btcoex_disable` does.
pub(in crate::ath9k) fn disable_mci(
    io: &mut impl RegisterIo,
    btcoex: &mut Btcoex,
) -> Result<(), BringUpError> {
    bt_stomp(btcoex, StompType::None);
    io.write32(AR_BTCOEX_WL_WEIGHTS0, btcoex.wlan_weight[0]);
    io.write32(AR_BTCOEX_WL_WEIGHTS1, btcoex.wlan_weight[1]);
    io.write32(AR_BTCOEX_WL_WEIGHTS2, btcoex.wlan_weight[2]);
    io.write32(AR_BTCOEX_WL_WEIGHTS3, btcoex.wlan_weight[3]);
    Ok(())
}

/// `btcoex.c::ath9k_hw_btcoex_enable_2wire`: request the WLAN-active
/// GPIO as an output muxed to TX_FRAME. No mode or weight register is
/// programmed for 2WIRE; the dispatcher sets `enabled`.
pub(in crate::ath9k) fn enable_2wire(
    io: &mut impl RegisterIo,
    btcoex: &Btcoex,
) -> Result<(), BringUpError> {
    gpio_request_out(io, u32::from(btcoex.wlanactive_gpio), GPIO_MUX_AS_TX_FRAME)
}

/// `btcoex.c::ath9k_hw_btcoex_enable_3wire`: program the mode and
/// weight registers from the `init_btcoex_hw` / `set_weight` images,
/// set the quiet-ack CTS enable, clear the BT-antenna-prevent-RX bit
/// and request the WLAN-active GPIO as an output muxed to
/// RX_CLEAR_EXTERNAL. Call `init_btcoex_hw` and `bt_stomp` first.
/// The dispatcher sets `enabled`.
///
/// The AR9271 `0x50040` bit-9 clear does not apply to any in-tree
/// part (AR9271 is not an AR9003 chip) and is not ported. The
/// pre-AR9300 `AR_BT_COEX_WEIGHT` write is likewise unreachable.
///
/// Quirk, kept verbatim: on a SoC the PHY-error-collision bit is
/// cleared in the `AR_BT_COEX_MODE2` register first, but the mode2
/// image write that follows re-sets it (the image carries the bit from
/// `init_btcoex_hw`), so the clear has no net effect once init ran.
pub(in crate::ath9k) fn enable_3wire(
    io: &mut impl RegisterIo,
    btcoex: &Btcoex,
    is_soc: bool,
) -> Result<(), BringUpError> {
    if is_soc {
        rmw(io, AR_BT_COEX_MODE2, AR_BT_PHY_ERR_BT_COLL_ENABLE, 0)?;
    }
    io.write32(AR_BT_COEX_MODE, btcoex.bt_coex_mode);
    io.write32(AR_BT_COEX_MODE2, btcoex.bt_coex_mode2);
    if is_soc {
        io.write32(AR_BT_COEX_MODE3, btcoex.bt_coex_mode3);
    }
    io.write32(AR_BT_COEX_WL_WEIGHTS0, btcoex.wlan_weight[0]);
    io.write32(AR_BT_COEX_WL_WEIGHTS1, btcoex.wlan_weight[1]);
    for (i, weight) in btcoex.bt_weight.iter().enumerate() {
        io.write32(ar_bt_coex_bt_weights(i as u32), *weight);
    }
    rmw(io, AR_QUIET1, 0, AR_QUIET1_QUIET_ACK_CTS_ENABLE)?;
    rmw(io, AR_PCU_MISC, AR_PCU_BT_ANT_PREVENT_RX, 0)?;
    gpio_request_out(
        io,
        u32::from(btcoex.wlanactive_gpio),
        GPIO_MUX_AS_RX_CLEAR_EXTERNAL,
    )
}

/// `btcoex.c::ath9k_hw_btcoex_enable`: the scheme dispatcher. NONE
/// returns without touching hardware or `enabled`; 2WIRE, 3WIRE and
/// MCI run their enable path, then (except for MCI, and except on a
/// SoC) the BT-active pin gets its pull-down programmed, and
/// `enabled` is set. `is_soc` is `false` for every in-tree part.
pub(in crate::ath9k) fn btcoex_enable(
    io: &mut impl RegisterIo,
    btcoex: &mut Btcoex,
    is_soc: bool,
) -> Result<(), BringUpError> {
    match btcoex.scheme {
        Scheme::None => return Ok(()),
        Scheme::TwoWire => enable_2wire(io, btcoex)?,
        Scheme::ThreeWire => enable_3wire(io, btcoex, is_soc)?,
        Scheme::Mci => enable_mci(io, btcoex)?,
    }
    if btcoex.scheme != Scheme::Mci && !is_soc {
        rmw(
            io,
            AR_GPIO_PDPU,
            0x3 << (u32::from(btcoex.btactive_gpio) * 2),
            0x2 << (u32::from(btcoex.btactive_gpio) * 2),
        )?;
    }
    btcoex.enabled = true;
    Ok(())
}

/// `btcoex.c::ath9k_hw_btcoex_disable`: clear `enabled` first, then
/// run the MCI disable path and return for MCI, or — for 2WIRE/3WIRE
/// (and, as in Linux, with no early return for NONE) — request the
/// WLAN-active GPIO as a plain output and, for 3WIRE, park the mode
/// registers (mode `AR_BT_QUIET | AR_BT_MODE`, i.e. the mode field set
/// to DISABLED) and zero the weights. The pre-AR9300 `set_gpio`
/// (WLAN-active low) and `AR_BT_COEX_WEIGHT` writes are unreachable
/// for AR9003 and are not ported.
pub(in crate::ath9k) fn btcoex_disable(
    io: &mut impl RegisterIo,
    btcoex: &mut Btcoex,
) -> Result<(), BringUpError> {
    btcoex.enabled = false;
    if btcoex.scheme == Scheme::Mci {
        disable_mci(io, btcoex)?;
        return Ok(());
    }
    gpio_request_out(io, u32::from(btcoex.wlanactive_gpio), GPIO_MUX_AS_OUTPUT)?;
    if btcoex.scheme == Scheme::ThreeWire {
        io.write32(AR_BT_COEX_MODE, AR_BT_QUIET | AR_BT_MODE);
        io.write32(AR_BT_COEX_MODE2, 0);
        io.write32(AR_BT_COEX_WL_WEIGHTS0, 0);
        io.write32(AR_BT_COEX_WL_WEIGHTS1, 0);
        for i in 0..4u32 {
            io.write32(ar_bt_coex_bt_weights(i), 0);
        }
    }
    Ok(())
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests;
