//! Bluetooth coexistence glue (`btcoex.c`): scheme selection, the MCI
//! defaults, the WLAN weight tables and the MCI enable/disable path.
//!
//! Grounded in Linux `drivers/net/wireless/ath/ath9k/btcoex.c` and
//! `btcoex.h` @ commit `cbbddb6b08cc9900a87cccaa9b22bbe06aa4f50a`
//! (2026-10-31), plus `reg.h` for the weight registers.
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
//!
//! Follow-up (not this file): the 2WIRE/3WIRE enable/init paths
//! (`init_btcoex_hw` mode computation, `enable_2wire`/`enable_3wire`,
//! `init_2wire`/`init_3wire`, `deinit`), which need the GPIO
//! request-in/out wiring, and the scheme dispatcher (`btcoex_enable` /
//! `btcoex_disable`), which lives with the owner once those paths land.
//! The `bt_coex_mode`/`mode2`/`mode3`/`bt_coex_weights` register images
//! belong to that follow-up and are not stored here.

use super::mci::{
    Mci, AR_BTCOEX_WL_WEIGHTS0, AR_BTCOEX_WL_WEIGHTS1, AR_BTCOEX_WL_WEIGHTS2,
    AR_BTCOEX_WL_WEIGHTS3, AR_QUIET1, AR_QUIET1_QUIET_ACK_CTS_ENABLE,
    MCI_GPM_COEX_MAJOR_VERSION_DEFAULT, MCI_GPM_COEX_MINOR_VERSION_DEFAULT,
};
use super::{rmw, Chip, HW_CAP_MCI};
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
/// holding the MCI engine plus the scheme and weight state the MCI
/// path programs. The 2WIRE/3WIRE register images (`bt_coex_mode`,
/// `bt_coex_mode2`, `bt_coex_mode3`, `bt_coex_weights`) are a
/// follow-up and are not stored here.
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

#[cfg(any(test, feature = "kernel-test"))]
mod tests;
