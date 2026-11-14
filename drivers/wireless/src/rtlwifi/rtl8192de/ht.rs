// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192DE HT station profile.
//!
//! Mirrors `rtl8192ee/ht.rs`: the local TX MCS set names MCS8-15 only
//! when the signed envelope permission admits every two-stream rate —
//! and, for the 8192DE, only on a `RF_2T2R` function. A dual-dual
//! (1T1R) function never transmits two streams, however the board is
//! measured: `mode_info` gives `RfType::OneT1R` there, so
//! [`two_stream`] refuses it. The ARFR rate table
//! (`rate::rate_table_value`) already carries the MCS8-15 bits on
//! 2T2R (`0x0f0f_f005` N-mode mask); this module is the admission
//! gate that decides whether the station may offer them.
//!
//! - `base.c::_rtl_init_hw_ht_capab` (shared by every rtlwifi chip,
//!   including the 92D): `SUP_WIDTH_20_40 | SGI_40 | SGI_20 |
//!   DSSSCCK40 | MAX_AMSDU`, `ampdu_factor` 64K (3), `ampdu_density`
//!   16 (7); RX MCS mask `[255, 255]` (+ MCS32, `rx_highest` 300
//!   Mb/s) for 1T2R/2T2R, `[255, 0]` for 1T1R. The 92D clears
//!   MAX_AMSDU when `disable_amsdu_8k` (`rtl92de_init_sw_vars`,
//!   `sw.c`: the 8K A-MSDU is disabled whenever `macphymode !=
//!   SINGLEMAC_SINGLEPHY` — see [`super::sw_consequences`]).
//!   Deliberate omissions, both receive-side promises this owner
//!   does not implement: `rx_mask[4] = 0x01` (MCS32) and
//!   `rx_highest` (300 Mb/s; 0 here = "not specified").
//! - `core.c::rtl_op_bss_info_changed(BSS_CHANGED_HT)`:
//!   `HW_VAR_SHORTGI_DENSITY` (`max_mss_density`, always 0 —
//!   `pci.c:1184`), `HW_VAR_AMPDU_FACTOR` (`current_ampdu_factor`,
//!   lowered to the peer's from 3) and `HW_VAR_AMPDU_MIN_SPACE`
//!   (`current_ampdu_density`, raised to the peer's from 7), in that
//!   order; all three register cases live in
//!   [`super::station`] and [`timing`] runs them.

use super::envelope::{Calibration, Permission, Width};
use super::station::{ampdu_factor, ampdu_min_space, shortgi_density};
use super::{MacPhyMode, RfType};
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;
use narf_wireless::association::phy::{HtGi, HtWidth, LocalHt, LocalPhy};

/// Full-order rate bits of MCS0-7 / MCS8-15.
pub const MCS0_7: u64 = 0xff << 12;
pub const MCS8_15: u64 = 0xff << 20;

/// Host-capability bits ([`host_capabilities`]).
pub const HOST_HT_2G: u8 = 1 << 0;
pub const HOST_HT40_2G: u8 = 1 << 1;
/// Every HT-admitting operating point also admits MCS8-15 on both paths.
pub const HOST_TX_2SS: u8 = 1 << 2;
pub const HOST_HT_5G: u8 = 1 << 3;
pub const HOST_HT40_5G: u8 = 1 << 4;
/// The dual-MAC `disable_amsdu_8k` consequence (MAX_AMSDU cleared).
pub const HOST_DISABLE_AMSDU_8K: u8 = 1 << 5;
/// The envelope is for an `RF_2T2R` board (RX MCS0-15).
pub const HOST_2T2R: u8 = 1 << 6;

/// HT is admitted when the permission holds a measured index for every
/// one-stream MCS (the legacy rates are always all admitted).
pub fn admitted(permission: &Permission) -> bool {
    permission.admitted_rates() & MCS0_7 == MCS0_7
}

/// Two-stream TX (MCS8-15) is admitted when the permission holds a
/// measured index for every two-stream rate and the function is
/// `RF_2T2R` (single / dual-single mode). Dual-dual functions are
/// 1T1R and never two-stream.
pub fn two_stream(permission: &Permission, rf_type: RfType) -> bool {
    rf_type == RfType::TwoT2R && permission.admitted_rates() & MCS8_15 == MCS8_15
}

/// `_rtl_init_hw_ht_capab` for the 8192DE (see the module note): the
/// RX MCS mask follows the function (`[255, 255]` on 2T2R, `[255, 0]`
/// on 1T1R), the TX mask follows the two-stream admission, SGI_40 is
/// advertised only on a 40 MHz offer, MAX_AMSDU is cleared when
/// `disable_amsdu_8k`.
pub fn capability(
    forty: bool,
    rf_type: RfType,
    two_stream: bool,
    disable_amsdu_8k: bool,
) -> LocalHt {
    let rx1 = if rf_type == RfType::TwoT2R { 255 } else { 0 };
    let tx1 = if two_stream { 255 } else { 0 };
    LocalHt::new(
        [255, rx1, 0, 0, 0, 0, 0, 0, 0, 0],
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
    .expect("fixed 8192DE HT capability")
    .with_rx_amsdu_7935(!disable_amsdu_8k)
    .with_dsss_cck40(true)
}

/// The local PHY the station associates with.
pub fn local(forty: bool, rf_type: RfType, two_stream: bool, disable_amsdu_8k: bool) -> LocalPhy {
    if forty {
        LocalPhy::ht40(capability(true, rf_type, two_stream, disable_amsdu_8k))
            .expect("fixed 8192DE HT20/40")
    } else {
        LocalPhy::ht20(capability(false, rf_type, two_stream, disable_amsdu_8k))
            .expect("fixed 8192DE HT20")
    }
}

/// `MAX_MSS_DENSITY_1T` / `MAX_MSS_DENSITY_2T` (`def.h`): the
/// `SHORTGI_DENSITY` base (`hw.c` `rtl92d_set_hw_reg`
/// `HW_VAR_SHORTGI_DENSITY`), `0x0A` → `0x50` for 1T, `0x13` →
/// `0x98` for 2T.
pub const MAX_MSS_DENSITY_1T: u8 = 0x0a;
pub const MAX_MSS_DENSITY_2T: u8 = 0x13;

/// The `SHORTGI_DENSITY` base for this function's RF type
/// (`hw.c:824/828`): 1T → `0x50`, 2T → `0x98`.
pub const fn minspace_cfg(rf_type: RfType) -> u8 {
    match rf_type {
        RfType::OneT1R => 0x50,
        RfType::TwoT2R => 0x98,
    }
}

/// `rtl_op_bss_info_changed(BSS_CHANGED_HT)` (`core.c:1251` order):
/// `HW_VAR_SHORTGI_DENSITY` with `max_mss_density` (always 0 —
/// `pci.c:1184`), then `HW_VAR_AMPDU_FACTOR` with
/// `current_ampdu_factor` (lowered to the peer's from 3), then
/// `HW_VAR_AMPDU_MIN_SPACE` with `current_ampdu_density` (raised to
/// the peer's from 7). `min_space_cfg` is the `REG_AMPDU_MIN_SPACE`
/// shadow the three cases share.
pub fn timing(
    io: &impl Io,
    mode: MacPhyMode,
    min_space_cfg: &mut u8,
    rf_type: RfType,
    peer_factor: u8,
    peer_density: u8,
) -> Result<(), Error> {
    *min_space_cfg = shortgi_density(io, minspace_cfg(rf_type), 0)?;
    ampdu_factor(io, mode, peer_factor.min(3))?;
    *min_space_cfg = ampdu_min_space(io, *min_space_cfg, peer_density.max(7))?;
    Ok(())
}

/// The HT capability the host API (nl80211 `GET_WIPHY`) publishes.
/// Linux `base.c::_rtl_init_mac80211` runs `_rtl_init_hw_ht_capab` on
/// the sband unconditionally; here it carries HT only while the signed
/// `N92D` envelope admits it under `domain` at some operating point
/// the association path can select: HT on an [`admitted`] 20 MHz
/// point, the 20/40 form on an [`admitted`] 40 MHz point, on 2.4 GHz
/// and 5 GHz alike. The TX MCS8-15 selection is published only when
/// every such point admits it ([`two_stream`]), so the host never
/// sees a wider TX set than an association could send. The dual-MAC
/// `disable_amsdu_8k` consequence and the 2T2R RX mask travel as
/// their own bits.
pub fn host_capabilities(
    base: &Calibration,
    domain: &narf_wireless::reg::RegulatoryDomain,
    rf_type: RfType,
    disable_amsdu_8k: bool,
) -> u8 {
    let mut caps = 0;
    let mut two = true;
    for op in base.operating_points() {
        let Ok(permission) = base.permission_for(domain, op) else {
            continue;
        };
        if !admitted(&permission) {
            continue;
        }
        two &= two_stream(&permission, rf_type);
        caps |= match (op.is_5ghz(), op.width) {
            (false, Width::W20) => HOST_HT_2G,
            (false, _) => HOST_HT_2G | HOST_HT40_2G,
            (true, Width::W20) => HOST_HT_5G,
            (true, _) => HOST_HT_5G | HOST_HT40_5G,
        };
    }
    if caps != 0 && two {
        caps |= HOST_TX_2SS;
    }
    if rf_type == RfType::TwoT2R {
        caps |= HOST_2T2R;
    }
    if disable_amsdu_8k {
        caps |= HOST_DISABLE_AMSDU_8K;
    }
    caps
}

/// The `PhyCapabilities` of `band` for the [`host_capabilities`] bits:
/// the same HT body ([`capability`]) the association path sends;
/// `None` off 2.4/5 GHz or without HT on that band.
pub fn host_phy(caps: u8, band: u32) -> Option<narf_wireless::iface::PhyCapabilities> {
    let (ht, ht40) = match band {
        2400 => (HOST_HT_2G, HOST_HT40_2G),
        5000 => (HOST_HT_5G, HOST_HT40_5G),
        _ => return None,
    };
    if caps & ht == 0 {
        return None;
    }
    let rf_type = if caps & HOST_2T2R != 0 {
        RfType::TwoT2R
    } else {
        RfType::OneT1R
    };
    Some(narf_wireless::iface::PhyCapabilities {
        ht: capability(
            caps & ht40 != 0,
            rf_type,
            caps & HOST_TX_2SS != 0,
            caps & HOST_DISABLE_AMSDU_8K != 0,
        )
        .capability_body(),
        vht: None,
    })
}
