// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8723BE HT station profile (RF_1T1R).
//!
//! - `base.c::_rtl_init_hw_ht_capab` (shared by every rtlwifi station):
//!   `SUP_WIDTH_20_40 | SGI_40 | SGI_20 | DSSSCCK40 | MAX_AMSDU`
//!   (`disable_amsdu_8k` is never set for 8723BE), `ampdu_factor`
//!   `IEEE80211_HT_MAX_AMPDU_64K` (3), `ampdu_density`
//!   `IEEE80211_HT_MPDU_DENSITY_16` (7), `tx_params =
//!   IEEE80211_HT_MCS_TX_DEFINED`; RX MCS0-7 only (`get_rf_type` is
//!   `RF_1T1R` on this chip; the 1T2R/2T2R `rx_mask[1]` row never applies).
//!   `sw.c` sets no HT STBC/LDPC. The 20/40 width bit (and with it SGI_40
//!   and DSSSCCK40) is only advertised while the signed `NAPC` envelope
//!   holds a 40 MHz permission for the AP's geometry; without it the narrow
//!   HT20 form is sent.
//! - The local TX MCS set bounds mac80211's intersected
//!   `sta->deflink.ht_cap.mcs.rx_mask` and with it the
//!   `rtl8723be_update_hal_rate_mask` bitmap: MCS0-7 only, on the single
//!   path. Deliberate omissions, both receive-side promises this owner does
//!   not implement: `rx_mask[4] = 0x01` (MCS32) and `rx_highest` (0 here =
//!   "not specified").
//! - `rtl8723be/hw.c` `rtl8723be_set_hw_reg` has all three HT cases —
//!   `HW_VAR_SHORTGI_DENSITY`, `HW_VAR_AMPDU_FACTOR` (`regtoset_normal`
//!   into `REG_AGGLEN_LMT`; the BT `regtoset_bt` row is for BT boards,
//!   never admitted) and `HW_VAR_AMPDU_MIN_SPACE` — with the same
//!   registers and `regtoset_normal` row as RTL8192CE, whose
//!   `rtl8192ce::ht::timing` this mirrors.
use super::envelope::Permission;
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;
use narf_wireless::association::phy::{HtGi, HtWidth, LocalHt, LocalPhy};

/// `rtl8723be/reg.h` `REG_AGGLEN_LMT` / `REG_AMPDU_MIN_SPACE`.
pub const REG_AGGLEN_LMT: u16 = 0x0458;
pub const REG_AMPDU_MIN_SPACE: u16 = 0x045c;
/// Full-order rate bits of MCS0-7.
pub const MCS0_7: u64 = 0xff << 12;

/// HT is admitted when the permission holds a measured index for every
/// one-stream MCS (the legacy rates are always all admitted).
pub fn admitted(permission: &Permission) -> bool {
    permission.admitted_rates() & MCS0_7 == MCS0_7
}

/// `_rtl_init_hw_ht_capab` for RF_1T1R (see the module note).
pub fn capability(forty: bool) -> LocalHt {
    LocalHt::new(
        [255, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [255, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        if forty {
            HtWidth::TwentyForty
        } else {
            HtWidth::Twenty
        },
        HtGi {
            rx20: true,
            tx20: true,
            rx40: forty,
            tx40: forty,
        },
        3,
        7,
    )
    .expect("fixed 8723BE HT capability")
    .with_rx_amsdu_7935(true)
    .with_dsss_cck40(true)
}

/// The local PHY the station associates with.
pub fn local(forty: bool) -> LocalPhy {
    if forty {
        LocalPhy::ht40(capability(true)).expect("fixed 8723BE HT20/40")
    } else {
        LocalPhy::ht20(capability(false)).expect("fixed 8723BE HT20")
    }
}

/// `rtl_op_bss_info_changed(BSS_CHANGED_HT)` from `_rtl_pci_init_struct`
/// state (`current_ampdu_density` 7, raised to the peer's, so it stays 7;
/// `current_ampdu_factor` 3, lowered to the peer's; `max_mss_density` 0):
/// `HW_VAR_SHORTGI_DENSITY` (`min_space_cfg |= 0 << 3`, written),
/// `HW_VAR_AMPDU_FACTOR` (`fac <= 3`: `fac = 1 << (fac + 2)` capped at
/// `0xf`, each `regtoset_normal` nibble lowered to it, four
/// `REG_AGGLEN_LMT` bytes) and `HW_VAR_AMPDU_MIN_SPACE` (`min_space_cfg =
/// (cfg & 0xf8) | density`, written). `min_space_cfg` is the software
/// cache (`mac->min_space_cfg`, 0 at init), kept across associations.
pub fn timing(
    io: &impl Io,
    min_space_cfg: &mut u8,
    peer_factor: u8,
    peer_density: u8,
) -> Result<(), Error> {
    let density = peer_density.max(7);
    let factor = peer_factor.min(3);
    io.write8(REG_AMPDU_MIN_SPACE, *min_space_cfg)?;
    let mut reg = [0x41u8, 0xa8, 0x72, 0xb9];
    let fac = (1u8 << (factor + 2)).min(0xf);
    for (i, value) in reg.iter_mut().enumerate() {
        if (*value & 0xf0) > (fac << 4) {
            *value = (*value & 0x0f) | (fac << 4);
        }
        if (*value & 0x0f) > fac {
            *value = (*value & 0xf0) | fac;
        }
        io.write8(REG_AGGLEN_LMT + i as u16, *value)?;
    }
    if density <= 7 {
        *min_space_cfg = (*min_space_cfg & 0xf8) | density;
        io.write8(REG_AMPDU_MIN_SPACE, *min_space_cfg)?;
    }
    Ok(())
}
