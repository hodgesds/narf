// SPDX-License-Identifier: GPL-2.0-or-later
//! Typed response-bound SISO HT20/5GHz HT40. Linux mac.c's get_ht_cap
//! advertises20/40 with HT, and each GI from its distinct SERVICE_READY bit.
use super::{station::plan_error, Error, ScanBss};
use crate::ath10k::wmi_boot::Capabilities;
use narf_wireless::association::{
    self,
    phy::{ApElements, HtGi, HtWidth, LocalHt, LocalPhy, Offer, Width},
    Bss, JoinPlan, SecurityMode,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Profile {
    pub(super) capabilities: u16,
    pub(super) ampdu: u8,
    pub(super) mcs: u8,
    pub(super) short_gi: bool,
    receive_sgi20: bool,
    receive_sgi40: bool,
    pub(super) center: u16,
    pub(super) secondary: Option<u16>,
    local: LocalPhy,
    offered: Offer,
}
pub(super) fn supported(caps: &Capabilities) -> bool {
    caps.ht & 1 != 0 && (1..=4).contains(&caps.rf_chains)
}
fn local(caps: &Capabilities, forty: bool) -> Result<LocalPhy, Error> {
    let mask = [255, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let ht = LocalHt::new(
        mask,
        mask,
        if forty {
            HtWidth::TwentyForty
        } else {
            HtWidth::Twenty
        },
        HtGi {
            rx20: caps.ht & 2 != 0,
            tx20: caps.ht & 2 != 0,
            rx40: forty && caps.ht & 0x800 != 0,
            tx40: forty && caps.ht & 0x800 != 0,
        },
        0,
        6,
    )
    .map_err(plan_error)?;
    if forty {
        LocalPhy::ht40(ht)
    } else {
        LocalPhy::ht20(ht)
    }
    .map_err(plan_error)
}
pub(super) fn capability(caps: &Capabilities, forty: bool) -> Option<[u8; 26]> {
    if !supported(caps) {
        return None;
    }
    let mask = [255, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    LocalHt::new(
        mask,
        mask,
        if forty {
            HtWidth::TwentyForty
        } else {
            HtWidth::Twenty
        },
        HtGi {
            rx20: caps.ht & 2 != 0,
            tx20: caps.ht & 2 != 0,
            rx40: forty && caps.ht & 0x800 != 0,
            tx40: forty && caps.ht & 0x800 != 0,
        },
        0,
        6,
    )
    .ok()
    .map(|p| p.capability_body())
}
pub(super) fn bss(cached: &ScanBss) -> Result<Bss, Error> {
    Ok(Bss {
        bssid: cached.bssid,
        ssid: cached.ssid.clone(),
        channel: association::channel::from_frequency(u32::from(cached.frequency))
            .ok_or(Error::Unsupported)?,
        signal_dbm: None,
        capability: cached.capability,
        beacon_interval: cached.beacon_interval,
        information_elements: cached.information_elements.clone(),
    })
}
impl Profile {
    pub(super) fn offer(
        caps: &Capabilities,
        cached: &ScanBss,
        own: [u8; 6],
        forty: bool,
    ) -> Result<Option<Self>, Error> {
        let bss = bss(cached)?;
        ApElements::parse(&bss.information_elements).map_err(plan_error)?;
        let wmm = narf_wireless::wmm::Parameters::parse(&bss.information_elements)
            .map_err(|_| Error::Malformed)?;
        if !supported(caps) || wmm.is_none_or(|p| p.ac[0].admission_control) {
            return Ok(None);
        }
        let local = local(caps, forty)?;
        let mode = if bss.capability & 16 != 0 {
            SecurityMode::Wpa2Psk
        } else {
            SecurityMode::Open
        };
        let plan =
            JoinPlan::prepare_with_phy(&bss, own, &bss.ssid, mode, local).map_err(plan_error)?;
        let Some(offered) = plan.offered_phy().copied() else {
            return Ok(None);
        };
        let h = offered.ht();
        // Center indices38/46/151/159 are not valid20MHz primaries, so
        // channel::frequency (a primary inventory) deliberately rejects them.
        let center = (if cached.frequency < 3000 { 2407 } else { 5000 })
            + 5 * u16::from(offered.center_channel());
        let secondary = if offered.width() == Width::Forty {
            offered
                .occupied_channels()
                .iter()
                .find(|c| **c != bss.channel)
                .and_then(|c| association::channel::frequency(*c))
                .map(|f| f as u16)
        } else {
            None
        };
        if !matches!(offered.width(), Width::Twenty | Width::Forty) {
            return Err(Error::Unsupported);
        }
        Ok(Some(Self {
            capabilities: native_capabilities(h, offered.width()),
            ampdu: h.peer_ampdu_factor() | h.peer_mpdu_density() << 2,
            mcs: h.tx_mcs()[0],
            short_gi: h.tx_sgi20() || offered.width() == Width::Forty && h.tx_sgi40(),
            receive_sgi20: h.rx_sgi20(),
            receive_sgi40: offered.width() == Width::Forty && h.rx_sgi40(),
            center,
            secondary,
            local,
            offered,
        }))
    }
    pub(super) fn local(self) -> LocalPhy {
        self.local
    }
    pub(super) fn protection_required(self) -> bool {
        self.offered.ht().operation().protection() != 0
    }
    pub(super) fn response(mut self, plan: &JoinPlan) -> Result<Self, Error> {
        let n = plan.negotiated_phy().ok_or(Error::Unsupported)?;
        // No unproved live VDEV restart: a response cannot silently change
        // the geometry whose native START and occupied power are retained.
        if n.width() != self.offered.width()
            || n.center_channel() != self.offered.center_channel()
            || n.occupied_channels() != self.offered.occupied_channels()
            || self.secondary.is_some()
                && n.ht().operation().protection() != self.offered.ht().operation().protection()
        {
            return Err(Error::Unsupported);
        }
        self.capabilities = native_capabilities(n.ht(), n.width());
        self.ampdu = n.ht().peer_ampdu_factor() | n.ht().peer_mpdu_density() << 2;
        self.mcs = n.ht().tx_mcs()[0];
        self.short_gi = n.ht().tx_sgi20() || n.width() == Width::Forty && n.ht().tx_sgi40();
        self.receive_sgi20 = n.ht().rx_sgi20();
        self.receive_sgi40 = n.width() == Width::Forty && n.ht().rx_sgi40();
        Ok(self)
    }
    pub(super) fn mode(self, frequency: u16) -> u32 {
        if self.secondary.is_some() {
            6
        } else if frequency < 3000 {
            5
        } else {
            4
        }
    }
    pub(super) fn density(self) -> u32 {
        match (self.ampdu >> 2) & 7 {
            0 => 0,
            1..=3 => 1,
            n => 1 << (n - 3),
        }
    }
    pub(super) fn matches_beacon(self, ies: &[u8]) -> bool {
        ApElements::parse(ies).is_ok_and(|p| {
            p.ht_capability() == Some(self.offered.ht().peer_capability_body())
                && p.ht_operation() == Some(self.offered.ht().operation().body())
        })
    }
    pub(super) fn accepts(self, descriptor: &[u8]) -> bool {
        if descriptor.len() < 116 {
            return false;
        }
        let word = |at| u32::from_le_bytes(descriptor[at..at + 4].try_into().unwrap());
        match word(104) >> 24 {
            4 => true,
            8 | 9 => {
                let sig = word(108);
                descriptor[103] & 1 == 0
                    && sig & 0x7f < 8
                    && (sig & 0x80 == 0 || self.secondary.is_some())
                    && (word(112) & 0x80 == 0
                        || if sig & 0x80 == 0 {
                            self.receive_sgi20
                        } else {
                            self.receive_sgi40
                        })
            }
            _ => false,
        }
    }
}

fn native_capabilities(h: &association::phy::HtNegotiation, width: Width) -> u16 {
    // mac80211/ht.c::ieee80211_ht_cap_ie_to_sta_ht_cap masks peer width/GI
    // by our capability before ath10k_peer_assoc_h_ht programs peer_ht_caps.
    // The single native RC_SGI flag permits both widths: these individual
    // bits must retain original-offer/response/local TX bounds, including
    // SGI40-only hardware falling back to20MHz. Original AP facts remain
    // unmodified in `offered`; local RX GI promises are separate above.
    (h.peer_capability() & !0x62)
        | if width == Width::Forty { 2 } else { 0 }
        | if h.tx_sgi20() { 0x20 } else { 0 }
        | if width == Width::Forty && h.tx_sgi40() {
            0x40
        } else {
            0
        }
}
