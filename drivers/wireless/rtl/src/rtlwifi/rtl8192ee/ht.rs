// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192EE HT station profile.
//!
//! - `base.c::_rtl_init_hw_ht_capab` for `RF_2T2R`: `SUP_WIDTH_20_40 |
//!   SGI_40 | SGI_20 | DSSSCCK40 | MAX_AMSDU` (`disable_amsdu_8k` is never
//!   set for 8192EE), `ampdu_factor` `IEEE80211_HT_MAX_AMPDU_64K` (3),
//!   `ampdu_density` `IEEE80211_HT_MPDU_DENSITY_16` (7), RX MCS0-15,
//!   `tx_params = IEEE80211_HT_MCS_TX_DEFINED`; no HT STBC/LDPC is
//!   advertised (`sw.c` sets neither `stbc_cap` nor `ldpc_cap` for the
//!   station). The 20/40 width bit (and with it SGI_40 and DSSSCCK40) is
//!   only advertised while the signed `N92E` envelope holds a 40 MHz
//!   permission for the AP's geometry; without it the narrow HT20 form is
//!   sent.
//! - The local TX MCS set (`tx_selection`, which bounds mac80211's
//!   intersected `sta->deflink.ht_cap.mcs.rx_mask` and with it the
//!   `rtl92ee_update_hal_rate_mask` bitmap) names MCS8-15 only when the
//!   permission admits every one of them on both paths; otherwise the RA
//!   mask can only name MCS0-7. Deliberate omissions, both receive-side
//!   promises this owner does not implement: `rx_mask[4] = 0x01` (MCS32)
//!   and `rx_highest` (300 Mb/s; 0 here = "not specified").
//! - `core.c::rtl_op_bss_info_changed(BSS_CHANGED_HT)`: of
//!   `HW_VAR_SHORTGI_DENSITY`, `HW_VAR_AMPDU_FACTOR` and
//!   `HW_VAR_AMPDU_MIN_SPACE` only the factor has an 8192EE case
//!   (`regtoset_normal` into `REG_AGGLEN_LMT`).
use super::envelope::Permission;
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;
use narf_wireless::association::phy::{HtGi, HtWidth, LocalHt, LocalPhy};

pub const REG_AGGLEN_LMT: u16 = 0x0458;
/// Full-order rate bits of MCS0-7 / MCS8-15.
pub const MCS0_7: u64 = 0xff << 12;
pub const MCS8_15: u64 = 0xff << 20;

/// HT is admitted when the permission holds a measured index for every
/// one-stream MCS (the legacy rates are always all admitted).
pub fn admitted(permission: &Permission) -> bool {
    permission.admitted_rates() & MCS0_7 == MCS0_7
}

/// Two-stream TX (MCS8-15) is admitted on both paths.
pub fn two_stream(permission: &Permission) -> bool {
    permission.admitted_rates() & MCS8_15 == MCS8_15
}

/// `_rtl_init_hw_ht_capab` for the 2T2R 8192EE (see the module note).
pub fn capability(forty: bool, two_stream: bool) -> LocalHt {
    let tx1 = if two_stream { 255 } else { 0 };
    LocalHt::new(
        [255, 255, 0, 0, 0, 0, 0, 0, 0, 0],
        [255, tx1, 0, 0, 0, 0, 0, 0, 0, 0],
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
    .expect("fixed 8192EE 2T2R HT capability")
    .with_rx_amsdu_7935(true)
    .with_dsss_cck40(true)
}

/// The local PHY the station associates with.
pub fn local(forty: bool, two_stream: bool) -> LocalPhy {
    if forty {
        LocalPhy::ht40(capability(true, two_stream)).expect("fixed 8192EE HT20/40")
    } else {
        LocalPhy::ht20(capability(false, two_stream)).expect("fixed 8192EE HT20")
    }
}

/// `rtl_op_bss_info_changed(BSS_CHANGED_HT)`: `current_ampdu_factor`
/// lowered to the peer's (from 3), then `HW_VAR_AMPDU_FACTOR` (`fac <= 3`:
/// `fac = 1 << (fac + 2)` capped at `0xf`, each `regtoset_normal` nibble
/// lowered to it, four `REG_AGGLEN_LMT` bytes). `rtl92ee_set_hw_reg` has no
/// `HW_VAR_SHORTGI_DENSITY` / `HW_VAR_AMPDU_MIN_SPACE` case (both fall to
/// the default log), so the density writes nothing.
pub fn timing(io: &impl Io, peer_factor: u8) -> Result<(), Error> {
    let factor = peer_factor.min(3);
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
    Ok(())
}

/// Host-capability bits ([`host_capabilities`]).
pub const HOST_HT_2G: u8 = 1 << 0;
pub const HOST_HT40_2G: u8 = 1 << 1;
/// Every HT-admitting operating point also admits MCS8-15 on both paths.
pub const HOST_TX_2SS: u8 = 1 << 2;

/// The 2.4 GHz capability the host API (nl80211 `GET_WIPHY`) publishes.
/// Linux `base.c::_rtl_init_mac80211` runs `_rtl_init_hw_ht_capab` on the
/// sband unconditionally; here it carries HT only while the signed `N92E`
/// envelope admits it under `domain` at some operating point the
/// association path can select: HT on an [`admitted`] 20 MHz point, the
/// 20/40 form on an [`admitted`] 40 MHz point. The TX MCS8-15 selection is
/// published only when every such point admits it ([`two_stream`]), so the
/// host never sees a wider TX set than an association could send.
pub fn host_capabilities(
    base: &super::envelope::Calibration,
    domain: &narf_wireless::reg::RegulatoryDomain,
) -> u8 {
    use super::envelope::Width;
    let mut caps = 0;
    let mut two = true;
    for op in base.operating_points() {
        let Ok(permission) = base.permission_for(domain, op) else {
            continue;
        };
        if !admitted(&permission) {
            continue;
        }
        two &= two_stream(&permission);
        caps |= match op.width {
            Width::W20 => HOST_HT_2G,
            Width::W40Above | Width::W40Below => HOST_HT_2G | HOST_HT40_2G,
        };
    }
    if caps != 0 && two {
        caps |= HOST_TX_2SS;
    }
    caps
}

/// The `PhyCapabilities` of `band` for the [`host_capabilities`] bits: the
/// same HT body ([`capability`]) the association path sends; `None` off
/// 2.4 GHz or without HT.
pub fn host_phy(caps: u8, band: u32) -> Option<narf_wireless::iface::PhyCapabilities> {
    (band == 2400 && caps & HOST_HT_2G != 0).then(|| narf_wireless::iface::PhyCapabilities {
        ht: capability(caps & HOST_HT40_2G != 0, caps & HOST_TX_2SS != 0).capability_body(),
        vht: None,
    })
}
