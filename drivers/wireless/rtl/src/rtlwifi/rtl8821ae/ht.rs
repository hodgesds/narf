// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821AE HT station profile.
//!
//! - `base.c::_rtl_init_hw_ht_capab` (1T1R): `SUP_WIDTH_20_40 | SGI_40 |
//!   SGI_20 | DSSSCCK40 | MAX_AMSDU` (`disable_amsdu_8k` is never set for
//!   8821AE), `ampdu_factor` `IEEE80211_HT_MAX_AMPDU_64K` (3),
//!   `ampdu_density` `IEEE80211_HT_MPDU_DENSITY_16` (7), RX MCS0-7,
//!   `tx_params = IEEE80211_HT_MCS_TX_DEFINED`; no HT STBC/LDPC (8821AE
//!   `sw.c` clears `ht_stbc_cap`). The 20/40 width bit (and with it SGI_40
//!   and DSSSCCK40) is only advertised while the signed `NAPC` envelope
//!   holds a 40 MHz permission for the AP's geometry: without it the
//!   station cannot follow a 40 MHz BSS, so the narrow HT20 form is sent.
//!   Deliberate omissions, both receive-side promises this owner does not
//!   implement: `rx_mask[4] = 0x01` (MCS32) and `rx_highest` (150 Mb/s, 0
//!   here = "not specified").
//! - `core.c::rtl_op_bss_info_changed(BSS_CHANGED_HT)` with
//!   `rtl8821ae_set_hw_reg` `HW_VAR_SHORTGI_DENSITY`, `HW_VAR_AMPDU_FACTOR`
//!   (8821AE branch) and `HW_VAR_AMPDU_MIN_SPACE`, starting from the
//!   `pci.c::rtl_pci_init_aspm` / `_rtl_pci_init_struct` values
//!   (`min_space_cfg = 0`, `max_mss_density = 0`, `current_ampdu_density =
//!   7`, `current_ampdu_factor = 3`).
use super::envelope::Permission;
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;
use narf_wireless::association::phy::{HtGi, HtWidth, LocalHt, LocalPhy};

pub const REG_AMPDU_MAX_LENGTH_8812: u16 = 0x0458;
pub const REG_AMPDU_MIN_SPACE: u16 = 0x045c;
/// `DESC_RATEMCS0`..=`DESC_RATEMCS7` full-order bits (the 1T1R HT set).
pub const MCS0_7: u64 = 0xff << 12;
/// `DESC_RATEMCS0` / `DESC_RATEMCS7`.
pub const DESC_RATEMCS0: u8 = 0x0c;
pub const DESC_RATEMCS7: u8 = 0x13;

/// `_rtl_init_hw_ht_capab` for the 1T1R 8821AE; `forty` selects the
/// 20/40 MHz form (see the module note).
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
    .expect("fixed 8821AE 1T1R HT capability")
    .with_rx_amsdu_7935(true)
    .with_dsss_cck40(true)
}

/// The local PHY the station associates with.
pub fn local(forty: bool) -> LocalPhy {
    if forty {
        LocalPhy::ht40(capability(true)).expect("fixed 8821AE HT20/40")
    } else {
        LocalPhy::ht20(capability(false)).expect("fixed 8821AE HT20")
    }
}

/// HT is admitted only when the permission holds a measured index for every
/// rate the Linux association RA mask names (MCS0-7 of a 1T1R station; the
/// legacy rates are already all admitted), so `rtl8821ae_update_hal_rate_mask`
/// stays exact and its mask a subset of the admitted set.
pub fn admitted(permission: &Permission) -> bool {
    permission.admitted_rates() & MCS0_7 == MCS0_7
}

/// `rtl_op_bss_info_changed(BSS_CHANGED_HT)`: `current_ampdu_density` is
/// raised to the peer's (it starts at 7, so stays 7), `current_ampdu_factor`
/// lowered to the peer's (from 3), then `HW_VAR_SHORTGI_DENSITY`
/// (`min_space_cfg |= max_mss_density << 3`, `max_mss_density` 0),
/// `HW_VAR_AMPDU_FACTOR` (8821AE: `(0x2000 << factor) - 1` below
/// `HT_AGG_SIZE_64K`, else `0xffff`, with BIT(31)) and
/// `HW_VAR_AMPDU_MIN_SPACE` (`min_space_cfg = (cfg & 0xf8) | density`).
/// `min_space_cfg` is the software cache, kept across associations.
pub fn timing(
    io: &impl Io,
    min_space_cfg: &mut u8,
    peer_factor: u8,
    peer_density: u8,
) -> Result<(), Error> {
    let density = peer_density.max(7);
    let factor = peer_factor.min(3);
    io.write8(REG_AMPDU_MIN_SPACE, *min_space_cfg)?;
    let length = if factor < 3 {
        (0x2000u32 << factor) - 1
    } else {
        0xffff
    };
    io.write32(REG_AMPDU_MAX_LENGTH_8812, length | (1 << 31))?;
    if density <= 7 {
        *min_space_cfg = (*min_space_cfg & 0xf8) | density;
        io.write8(REG_AMPDU_MIN_SPACE, *min_space_cfg)?;
    }
    Ok(())
}
