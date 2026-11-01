//! Explicit-band native HE/EHT20..320 station admission. Active/RNR6GHz
//! scanning remains separate; no numeric legacy-channel fallback exists.
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
    pub span: super::six_ghz_span::Span,
    ap_span: super::six_ghz_span::Span,
    peer: [u8; 6],
}

fn width(width: SixGhzWidth) -> u8 {
    match width {
        SixGhzWidth::Twenty => 0,
        SixGhzWidth::Forty => 1,
        SixGhzWidth::Eighty => 2,
        SixGhzWidth::OneSixty => 3,
        SixGhzWidth::ThreeTwenty => 4,
    }
}
fn announced_span(ies: &[u8], primary: u8) -> Result<super::six_ghz_span::Span, &'static str> {
    let he = six_ghz::admit(ies, primary).map_err(|_| "invalid6GHz announced HE channel")?;
    if he.channel.discontiguous {
        return Err("native6GHz80+80 owner absent");
    }
    let he_width = match he.channel.width {
        association::phy::Width::Twenty => 0,
        association::phy::Width::Forty => 1,
        association::phy::Width::Eighty => 2,
        association::phy::Width::OneSixty => 3,
    };
    let he_center = if he_width == 3 {
        he.operation.ccfs1
    } else {
        he.operation.ccfs0
    };
    let he_span = super::six_ghz_span::Span::new(primary, he_width, he_center)
        .ok_or("invalid6GHz HE span")?;
    let mut rest = ies;
    while !rest.is_empty() {
        let len = usize::from(*rest.get(1).ok_or("short6GHz EHT channel IE")?);
        let body = rest.get(2..2 + len).ok_or("short6GHz EHT channel extent")?;
        if rest[0] == 255 && body.first() == Some(&106) {
            let operation = association::eht::EhtOperation::parse(&body[1..])
                .map_err(|_| "invalid6GHz EHT operation")?;
            if let Some(info) = operation.information() {
                let width = info[0] & 7;
                let center = if width >= 3 { info[2] } else { info[1] };
                let span = super::six_ghz_span::Span::new(primary, width, center)
                    .ok_or("invalid6GHz EHT span")?;
                if !span.contains(he_span) {
                    return Err("6GHz EHT operation does not contain HE channel");
                }
                return Ok(span);
            }
        }
        rest = &rest[2 + len..];
    }
    Ok(he_span)
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
    // ACTIVE permits ordinary operation; ALLOW_20MHZ_ACTIVITY is only
    // the narrower no-IR relaxation. Neither bit is a wider-span proof.
    if flags & 1 == 0 || flags & (4 | 8) == 0 {
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

fn local_for_width(source: Local, maximum: u8, rule: RegRule) -> Result<SixGhzLocal, &'static str> {
    let he = super::sc_he::local_six_width(source, maximum)?;
    let limit = match maximum {
        0 => SixGhzWidth::Twenty,
        1 => SixGhzWidth::Forty,
        2 => SixGhzWidth::Eighty,
        3 => SixGhzWidth::OneSixty,
        _ => SixGhzWidth::ThreeTwenty,
    };
    let local = SixGhzLocal::new(he, He6GhzCapability::new(4 | (3 << 3) | (3 << 9)), rule)
        .map_err(|_| "invalid native6GHz HE width profile")?
        .with_max_width(limit);
    if source.eht {
        local
            .with_eht(super::sc_eht::local_six_width(source, &he, maximum)?)
            .map_err(|_| "invalid native6GHz EHT width profile")
    } else {
        Ok(local)
    }
}
fn join_plan(
    bss: &Bss,
    own: [u8; 6],
    mode: SecurityMode,
    physical: &SixGhzLocal,
    mld: Option<association::mlo::Local>,
) -> Result<JoinPlan, association::Error> {
    match mld {
        Some(mld) => JoinPlan::prepare_mld_6ghz(
            bss,
            own,
            &bss.ssid,
            mode,
            physical,
            JoinOptions::default(),
            mld,
        ),
        None => JoinPlan::prepare_6ghz(bss, own, &bss.ssid, mode, physical, JoinOptions::default()),
    }
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
    let channel = Channel::six(beacon.channel)
        .filter(|ch| ch.band == beacon.band)
        .ok_or("6GHz association has no explicit native channel")?;
    if !local.he || !matches!(local.native_rates, 2 | 3) {
        return Err("6GHz actual HE/rate facts absent");
    }
    let primary = super::six_ghz_span::Span::new(channel.number, 0, channel.number).unwrap();
    let primary_flags = primary
        .nvm_flags(local)
        .ok_or("6GHz actual primary NVM fact absent")?;
    let primary_rule = primary
        .rule(domain, primary_flags, firmware)
        .ok_or("6GHz primary host/NVM/MCC prohibited")?;
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
    let ap_span = announced_span(&beacon.information_elements, beacon.channel)?;
    let mut source = local;
    source.eht &= firmware.is_none_or(|mcc| mcc.eht_allowed);
    source.eht_320 &= source.eht && firmware.is_none_or(|mcc| mcc.widths.three_twenty);
    let mld = super::sc_mlo::local(source.eht, &beacon.information_elements, own)?;
    let he160 = source.width160_channels != 0 || source.six_widths[2] != 0;
    let maximum = if source.eht_320 && he160 {
        4
    } else if source.six_widths[2] != 0 {
        3
    } else if source.six_widths[1] != 0 {
        2
    } else if source.six_widths[0] != 0 {
        1
    } else {
        0
    };
    for maximum in (0..=maximum).rev() {
        let physical = local_for_width(source, maximum, primary_rule.clone())?;
        let Ok(plan) = join_plan(&bss, own, mode, &physical, mld) else {
            continue;
        };
        let selected = *plan.six_ghz().ok_or("shared6GHz plan absent")?;
        if selected.channel().discontiguous {
            continue;
        }
        let Some(span) = super::six_ghz_span::Span::new(
            beacon.channel,
            width(selected.width()),
            selected.channel().center,
        ) else {
            continue;
        };
        if !ap_span.contains(span) {
            continue;
        }
        let Some(nvm_flags) = span.nvm_flags(source) else {
            continue;
        };
        let Some(rule) = span
            .rule(domain, nvm_flags, firmware)
            .filter(|rule| rule.allows_6ghz_client(selected.power_type()))
        else {
            continue;
        };
        // Rebuild with the full selected span's AP-type restrictions. This
        // keeps transmitted regulatory connectivity truthful too.
        drop(plan);
        let physical = local_for_width(source, maximum, rule)?;
        let Ok(plan) = join_plan(&bss, own, mode, &physical, mld) else {
            continue;
        };
        let selected = *plan.six_ghz().ok_or("shared6GHz full-span plan absent")?;
        if width(selected.width()) != span.width || selected.channel().center != span.center {
            return Err("6GHz regulatory refinement changed native span");
        }
        super::rates::Rates::parse_six_eht(
            &beacon.information_elements,
            true,
            selected.eht().is_some(),
        )?;
        let power = super::six_ghz_power::Constraints::parse_span(
            selected.power_type(),
            &beacon.information_elements,
            ap_span,
            span,
        )?;
        return Ok((
            super::sc_security::Profile::from_plan(&plan, mode)?,
            Arc::new(Profile {
                plan: selected,
                power,
                nvm_flags,
                span,
                ap_span,
                peer: beacon.bssid,
            }),
        ));
    }
    Err("native6GHz has no complete source-qualified HE/EHT channel span")
}

impl Profile {
    pub fn channel(&self) -> Channel {
        self.span.primary
    }
    pub fn rule(
        &self,
        domain: &RegulatoryDomain,
        firmware: Option<&super::mld_regulatory::Mcc>,
    ) -> Option<RegRule> {
        self.span.rule(domain, self.nvm_flags, firmware)
    }
    pub fn power_type(&self) -> PowerType6Ghz {
        self.plan.power_type()
    }
    pub fn append_capabilities(&self, out: &mut alloc::vec::Vec<u8>) {
        let capability = self.plan.he().local_capability();
        out.extend_from_slice(&[255, capability.len() as u8]);
        out.extend_from_slice(&capability);
        if let Some(eht) = self.plan.eht() {
            let capability = eht.local_capability();
            out.extend_from_slice(&[255, capability.len() as u8]);
            out.extend_from_slice(&capability);
        }
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
        super::rates::Rates::parse_six_eht(ies, true, self.plan.eht().is_some())?;
        let actual = six_ghz::admit(ies, self.channel().number)
            .map_err(|_| "6GHz response omitted HE/band/operation facts")?;
        if actual.he_capability != *self.plan.he().peer_capability()
            || actual.he_operation != *self.plan.he().operation()
            || actual.capability != self.plan.peer_capability()
            || actual.operation != *self.plan.operation()
            || announced_span(ies, self.channel().number)? != self.ap_span
            || super::six_ghz_power::Constraints::parse_span(
                self.power_type(),
                ies,
                self.ap_span,
                self.span,
            )? != self.power
            || self
                .plan
                .eht()
                .is_some_and(|eht| !super::sc_eht::matches(eht, ies, &actual.he_capability))
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
