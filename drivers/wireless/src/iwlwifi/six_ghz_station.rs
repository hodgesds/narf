//! Explicit-band native HE20 station admission. Wider/active/RNR6GHz
//! ownership remains separate; no numeric legacy-channel fallback exists.
use super::{
    connection::{AuthMethod, Beacon},
    ht_vht::Local,
    native_band::{Band, Channel},
};
use alloc::sync::Arc;
use narf_wireless::{
    association::{
        self,
        six_ghz::{self, He6GhzCapability, SixGhzLocal, SixGhzPlan, SixGhzWidth},
        Bss, JoinOptions, JoinPlan, SecurityMode,
    },
    reg::{PowerType6Ghz, RegFlags, RegRule, RegulatoryDomain},
};

pub(super) struct Profile {
    pub plan: SixGhzPlan,
    pub power: super::six_ghz_power::Constraints,
    pub nvm_flags: u32,
    peer: [u8; 6],
}

fn forbid_legacy(mut ies: &[u8]) -> Result<(), &'static str> {
    while !ies.is_empty() {
        let len = usize::from(*ies.get(1).ok_or("truncated6GHz IE")?);
        ies.get(2..2 + len).ok_or("truncated6GHz IE")?;
        if matches!(ies[0], 45 | 61 | 191 | 192) {
            return Err("6GHz cannot carry HT/VHT PHY elements");
        }
        ies = &ies[2 + len..];
    }
    Ok(())
}

/// Intersect every overlapping host restriction and actual NVM/MCC
/// VLP/AFC client flags. The result is a full20MHz rule, never a point
/// lookup through a permissive rule hiding a narrower prohibition.
pub(super) fn rule(
    domain: &RegulatoryDomain,
    channel: Channel,
    nvm_flags: u32,
    firmware: Option<&super::mld_regulatory::Mcc>,
) -> Option<RegRule> {
    if channel.band != Band::Six || nvm_flags & 1 == 0 {
        return None;
    }
    let flags = match firmware {
        Some(mcc) if mcc.he_allowed => *mcc.channels.get(channel.index()?)?,
        Some(_) => return None,
        None => 5 | (1 << 13) | (1 << 14),
    };
    if flags & 5 != 5 {
        return None;
    }
    let frequency = channel.frequency();
    let (low, high) = (frequency - 10, frequency + 10);
    let mut combined = RegRule {
        freq_start_mhz: low,
        freq_end_mhz: high,
        max_bandwidth_mhz: 20,
        max_power_dbm: i8::MAX,
        flags: RegFlags::empty(),
    };
    let mut covered = false;
    for rule in domain
        .rules
        .iter()
        .filter(|rule| rule.freq_start_mhz < high && rule.freq_end_mhz > low)
    {
        if rule.freq_end_mhz <= rule.freq_start_mhz
            || rule.max_bandwidth_mhz < 20
            || rule.flags.contains(RegFlags::NO_IR)
        {
            return None;
        }
        covered |= rule.freq_start_mhz <= low && rule.freq_end_mhz >= high;
        combined.max_power_dbm = combined.max_power_dbm.min(rule.max_power_dbm);
        combined.flags |= rule.flags;
    }
    if (nvm_flags & flags) & (1 << 13) == 0 {
        combined.flags |= RegFlags::NO_6GHZ_VLP_CLIENT;
    }
    if (nvm_flags & flags) & (1 << 14) == 0 {
        combined.flags |= RegFlags::NO_6GHZ_AFC_CLIENT;
    }
    covered.then_some(combined)
}

#[inline(never)]
pub(super) fn prepare(
    beacon: &Beacon,
    own: [u8; 6],
    auth: &AuthMethod,
    local: Local,
    domain: &RegulatoryDomain,
    firmware: Option<&super::mld_regulatory::Mcc>,
) -> Result<(super::sc_security::Profile, Arc<Profile>), &'static str> {
    forbid_legacy(&beacon.information_elements)?;
    super::rates::Rates::parse_six(&beacon.information_elements, true)?;
    let channel = Channel::six(beacon.channel)
        .filter(|ch| beacon.band == ch.band)
        .ok_or("6GHz association has no explicit native channel")?;
    let bit = 1u64 << (channel.index().unwrap() - 51);
    if !local.he || local.six_channels[0] & bit == 0 || !matches!(local.native_rates, 2 | 3) {
        return Err("6GHz association lacks actual NVM/HE/rate facts");
    }
    let nvm_flags =
        1 | if local.six_channels[1] & bit != 0 {
            1 << 13
        } else {
            0
        } | if local.six_channels[2] & bit != 0 {
            1 << 14
        } else {
            0
        };
    let rule =
        rule(domain, channel, nvm_flags, firmware).ok_or("6GHz host/NVM/MCC channel prohibited")?;
    let local = SixGhzLocal::new(
        super::sc_he::local_six(local)?,
        // Actual shared HE source profile: min spacing4, A-MPDU exp3,
        // MPDU3895, SMPS disabled, no unproved RD/antenna promises.
        He6GhzCapability::new(4 | (3 << 3) | (3 << 9)),
        rule,
    )
    .map_err(|_| "invalid native6GHz local HE profile")?;
    let mode = match auth {
        AuthMethod::Wpa3Sae { .. } => SecurityMode::Wpa3Sae {
            pwe: association::SaePwe::HashToElement,
        },
        _ => return Err("6GHz requires WPA3 SAE-H2E and PMF"),
    };
    let bss = Bss {
        bssid: beacon.bssid,
        ssid: beacon.ssid.clone(),
        channel: beacon.channel,
        band: Some(association::channel::Band::Ghz6),
        signal_dbm: None,
        capability: beacon.capabilities,
        beacon_interval: beacon.interval,
        information_elements: beacon.information_elements.clone(),
    };
    let plan = JoinPlan::prepare_6ghz(
        &bss,
        own,
        &beacon.ssid,
        mode,
        &local,
        JoinOptions::default(),
    )
    .map_err(|_| "unsupported native6GHz security/HE offer")?;
    let selected = *plan.six_ghz().ok_or("shared6GHz plan absent")?;
    let announced = six_ghz::admit(&beacon.information_elements, beacon.channel)
        .map_err(|_| "invalid native6GHz AP operation")?;
    if selected.width() != SixGhzWidth::Twenty
        || announced.channel.width != association::phy::Width::Twenty
        || selected.channel().discontiguous
        || selected.eht().is_some()
    {
        return Err("native6GHz owner currently requires an AP20/STA20 HE span");
    }
    let power = super::six_ghz_power::Constraints::parse(
        selected.power_type(),
        &beacon.information_elements,
    )?;
    Ok((
        super::sc_security::Profile::from_plan(&plan, mode)?,
        Arc::new(Profile {
            plan: selected,
            power,
            nvm_flags,
            peer: beacon.bssid,
        }),
    ))
}

impl Profile {
    pub fn channel(&self) -> Channel {
        Channel::six(self.plan.channel().primary).unwrap()
    }
    pub fn power_type(&self) -> PowerType6Ghz {
        self.plan.power_type()
    }
    pub fn append_capabilities(&self, out: &mut alloc::vec::Vec<u8>) {
        let capability = self.plan.he().local_capability();
        out.extend_from_slice(&[255, capability.len() as u8]);
        out.extend_from_slice(&capability);
        out.extend_from_slice(&self.plan.local_capability().element());
        out.extend_from_slice(&[
            255,
            2,
            six_ghz::EXT_NON_AP_STA_REG_CON,
            self.plan.regulatory_connectivity(),
        ]);
    }
    /// Initial native contract confirms the exact offered AP HE/6GHz
    /// facts. A changed response/live operation requires reassociation.
    #[inline(never)]
    pub fn confirm(&self, ies: &[u8]) -> Result<(), &'static str> {
        forbid_legacy(ies)?;
        super::rates::Rates::parse_six(ies, true)?;
        let actual = six_ghz::admit(ies, self.channel().number)
            .map_err(|_| "6GHz response omitted HE/band/operation facts")?;
        if actual.he_capability != *self.plan.he().peer_capability()
            || actual.he_operation != *self.plan.he().operation()
            || actual.capability != self.plan.peer_capability()
            || actual.operation != *self.plan.operation()
            || super::six_ghz_power::Constraints::parse(self.power_type(), ies)? != self.power
        {
            return Err("6GHz AP changed HE/channel/power facts; reassociation required");
        }
        Ok(())
    }
    pub fn check_pending(&self, hw: &super::runtime::Hardware) -> Result<(), &'static str> {
        for packet in &hw.notifications {
            if packet.receive_queue != 0 || packet.header.group_id != 0 || packet.header.cmd != 0xc1
            {
                continue;
            }
            let Some(mpdu) = super::scan_api::mpdu(&packet.payload) else {
                continue;
            };
            if Channel::received(mpdu.channel, mpdu.raw_band, hw.band_in_rx_supported())
                != Some(self.channel())
                || mpdu.frame.len() < 36
                || mpdu.frame[0] != 0x80
                || mpdu.frame[10..16] != self.peer
                || mpdu.frame[16..22] != self.peer
            {
                continue;
            }
            let ies = mpdu
                .body(24, 0)
                .and_then(|body| body.get(12..))
                .ok_or("invalid6GHz pending beacon")?;
            self.confirm(ies)?;
        }
        Ok(())
    }
}
