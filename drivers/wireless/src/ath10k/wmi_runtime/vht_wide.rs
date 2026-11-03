// SPDX-License-Identifier: GPL-2.0-or-later
//! Source-qualified 80+80 limits. Linux ath10k/core.c assigns QCA9984 two
//! wide streams and QCA9888 one; only10.4 encodes the native NSS override.
use super::*;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath10k::wmi_runtime) struct Wide {
    /// The other 80 MHz segment center (MHz).
    pub center2: u16,
    /// Contiguous160 (`center2` adjacent to the primary80) rather than
    /// 80+80 (`NL80211_CHAN_WIDTH_160` vs `_80P80`).
    pub contiguous: bool,
    pub nss: u8,
    pub rx_nss: u8,
    pub rx_sgi: bool,
}
/// Linux ath10k mac.c::get_160mhz_nss_from_maxrate. Its TX override
/// conservatively uses one for an unrecognized peer RX hint. An unknown
/// peer TX highest-rate field does not erase a valid advertised receive map.
pub(super) fn maxrate_nss(rate: u16) -> Option<u8> {
    match rate {
        780 => Some(1),
        1560 => Some(2),
        2106 => Some(3),
        3120 => Some(4),
        _ => None,
    }
}
impl Profile {
    /// Discontiguous 80+80 on a chip whose Supported Channel Width Set is
    /// 160+80+80 (`vht_cap_info` & 0xc == 8). An AP operating contiguous
    /// 160 yields a contiguous profile from the same advertisement.
    pub(in crate::ath10k::wmi_runtime) fn offer_80p80(
        caps: &Capabilities,
        cached: &ScanBss,
        own: [u8; 6],
        chains: Chains,
        maximum_nss: u8,
    ) -> Result<Option<Self>, Error> {
        if caps.vht & 12 != 8 {
            return Ok(None);
        }
        Self::offer_wide(caps, cached, own, chains, maximum_nss)
    }
    /// The 160 MHz offer for the chip's own Supported Channel Width Set:
    /// 160+80+80 (8) opts into both shapes, 160-only (4) into contiguous
    /// 160 alone (Linux `ath10k_create_vht_cap` copies `vht_cap_info`).
    pub(in crate::ath10k::wmi_runtime) fn offer_wide(
        caps: &Capabilities,
        cached: &ScanBss,
        own: [u8; 6],
        chains: Chains,
        maximum_nss: u8,
    ) -> Result<Option<Self>, Error> {
        let width_set = caps.vht & 12;
        if cached.frequency < 3000 || !matches!(width_set, 4 | 8) || maximum_nss == 0 {
            return Ok(None);
        }
        let nss = maximum_nss.min(chains.count());
        let map = (0..8).fold(0xffffu16, |map, i| {
            if i < u32::from(nss) {
                (map & !(3 << (i * 2))) | (2 << (i * 2))
            } else {
                map
            }
        });
        // Conservatively expose only the wide stream count at every VHT
        // width in this opt-in profile. Ordinary80 keeps its original maps;
        // no missing local per-width NSS signal is fabricated.
        let vht = LocalVht::new(
            map,
            map,
            caps.vht & 32 != 0,
            caps.vht & 32 != 0,
            ((caps.vht >> 23) & 7) as u8,
        )
        .map_err(plan_error)?
        .with_ldpc(caps.vht & 16 != 0, caps.vht & 16 != 0)
        .with_rx_stbc(chains.multiple() && caps.vht & 0x300 != 0)
        .with_tx_stbc(chains.multiple() && caps.vht & 128 != 0);
        let sgi160 = caps.vht & 64 != 0;
        let vht = if width_set == 8 {
            vht.with_80p80(sgi160, sgi160)
        } else {
            vht.with_160mhz(sgi160, sgi160)
        };
        let ht = local_ht(caps, true, chains).map_err(plan_error)?;
        let local = LocalPhy::vht160(ht, vht).map_err(plan_error)?;
        let profile = Self::offer_local(caps, cached, own, local, chains, width_set)?;
        Ok(profile.filter(|p| p.vht.is_some_and(|v| v.wide.is_some())))
    }
}
#[cfg(any(test, feature = "kernel-test"))]
#[path = "vht160_tests.rs"]
mod tests;
