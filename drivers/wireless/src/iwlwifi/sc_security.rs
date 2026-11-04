//! MLD station security negotiation and native key/PMF wire facts.
//! Admission follows the shared supplicant plan; key flags follow Linux
//! `mld/key.c::iwl_mld_get_key_flags`, SEC_KEY_CMD v1 and STA_CONFIG v2.
use super::{
    boot_context::{put32, put64},
    connection::{AuthMethod, Beacon},
    ht_vht::Local,
    scan_api, security,
};
use alloc::vec::Vec;
use narf_wireless::association::{
    phy::{HtGi, HtWidth, LocalHt, LocalPhy, LocalVht},
    AkmSet, Bss, JoinOptions, JoinPlan, Pmf, SaeJoin, SaePwe, SecurityMode,
};
use zeroize::Zeroizing;

pub(super) struct Profile {
    pub akm: Option<security::Akm>,
    pub pmf: bool,
    pub rsne: Option<Vec<u8>>,
    pub sae: Option<SaeJoin>,
    pub offer: Option<narf_wireless::association::phy::Offer>,
    pub mld: Option<alloc::boxed::Box<narf_wireless::association::mlo::Context>>,
    /// A multiple-link request plan (`JoinPlan::prepare_mld_links`) whose
    /// association link equals this profile; `None` for one link.
    pub links: Option<alloc::boxed::Box<JoinPlan>>,
}

/// Retired material cannot return with reset replay/nonce state during this
/// connection owner. Like shared station_security::Security, exhaustion is
/// terminal instead of evicting evidence. Fingerprints retain no raw keys.
#[derive(Default)]
pub(super) struct KeyHistory {
    digests: Vec<[u8; 32]>,
}
impl KeyHistory {
    pub fn reserve(&mut self, candidates: [Option<&[u8; 16]>; 3]) -> Result<(), &'static str> {
        let mut fresh = [[0; 32]; 3];
        let mut count = 0;
        for material in candidates.into_iter().flatten() {
            let mut hash = narf_crypto::sha256::Sha256::new();
            hash.update(material);
            let digest = hash.finalize();
            if self.digests.contains(&digest) || fresh[..count].contains(&digest) {
                return Err("MLD retired/cross-role key material cannot restart packet numbers");
            }
            fresh[count] = digest;
            count += 1;
        }
        if self.digests.len() + count > 16 {
            return Err("MLD connection key history exhausted");
        }
        self.digests
            .try_reserve(count)
            .map_err(|_| "MLD connection key history allocation failed")?;
        // Reserve before any REMOVE/ADD can become device-visible. A failed
        // or cancelled installation must not become a same-owner retry.
        self.digests.extend_from_slice(&fresh[..count]);
        Ok(())
    }
}

fn bss(beacon: &Beacon) -> Bss {
    Bss {
        bssid: beacon.bssid,
        ssid: beacon.ssid.clone(),
        channel: beacon.channel,
        band: None,
        signal_dbm: None,
        capability: beacon.capabilities,
        beacon_interval: beacon.interval,
        information_elements: beacon.information_elements.clone(),
    }
}

fn local_phy(local: Local, channel: u8) -> Result<Option<LocalPhy>, &'static str> {
    if !local.ht {
        return Ok(None);
    }
    if !(1..=2).contains(&local.rx_streams) || !(1..=2).contains(&local.tx_streams) {
        return Err("MLD security plan has no native PHY streams");
    }
    let mut rx = [0; 10];
    let mut tx = [0; 10];
    rx[..usize::from(local.rx_streams)].fill(255);
    tx[..usize::from(local.tx_streams)].fill(255);
    let ht = LocalHt::new(
        rx,
        tx,
        HtWidth::TwentyForty,
        HtGi {
            rx20: true,
            tx20: true,
            rx40: true,
            tx40: true,
        },
        3,
        4,
    )
    .map_err(|_| "MLD local security HT profile invalid")?;
    let phy = if local.vht && channel > 14 {
        let map = |streams| {
            let mut map = u16::MAX;
            for stream in 0..streams {
                map = (map & !(3 << (2 * stream))) | (2 << (2 * stream));
            }
            map
        };
        let vht = LocalVht::new(map(local.rx_streams), map(local.tx_streams), true, true, 3)
            .map_err(|_| "MLD local security VHT profile invalid")?;
        if local.supports160() {
            LocalPhy::vht160(ht, vht.with_160mhz(true, true).with_extended_nss_bw(true))
        } else {
            LocalPhy::vht80(ht, vht)
        }
    } else {
        LocalPhy::ht40(ht)
    };
    let phy = phy.map_err(|_| "MLD local security PHY profile invalid")?;
    let phy = if local.he {
        phy.with_he(super::sc_he::local(local, channel)?)
            .map_err(|_| "MLD local HE security profile invalid")?
    } else {
        phy
    };
    let phy = if local.eht && local.he {
        phy.with_eht(super::sc_eht::local(local, Some(channel))?)
            .map_err(|_| "MLD local EHT security profile invalid")?
    } else {
        phy
    };
    Ok(Some(phy))
}

impl Profile {
    pub fn negotiate(
        beacon: &Beacon,
        own: [u8; 6],
        auth: &AuthMethod,
        mut local: Local,
    ) -> Result<Self, &'static str> {
        let mode = match auth {
            AuthMethod::Open if !local.he && !local.supports160() => {
                if beacon.privacy {
                    return Err("secured AP requested as open");
                }
                return Ok(Self {
                    akm: None,
                    pmf: false,
                    rsne: None,
                    sae: None,
                    offer: None,
                    mld: None,
                    links: None,
                });
            }
            AuthMethod::Open => SecurityMode::Open,
            AuthMethod::Wpa2Psk(_) => SecurityMode::Wpa2Psk,
            AuthMethod::Wpa3Sae { .. } => SecurityMode::Wpa3Sae { pwe: SaePwe::Both },
        };
        let bss = bss(beacon);
        // Preserve the legacy no-PMF offer when the peer cannot negotiate
        // it, like the Gen2 station owner. An MFPC AP enables optional PMF;
        // MFPR is then admitted only with a usable BIP-CMAC-128 profile.
        let peer_mfpc = beacon
            .rsn
            .as_deref()
            .and_then(narf_wireless::rsn::RsnIe::decode_body)
            .is_some_and(|rsn| rsn.rsn_capabilities & narf_wireless::rsn::RSN_CAP_MFP_CAPABLE != 0);
        // Native EHT is admitted only with the actual WPA3/MFP hierarchy.
        // Optional EHT on another security mode retains the genuine HE path.
        local.eht &= local.he && peer_mfpc && matches!(auth, AuthMethod::Wpa3Sae { .. });
        let physical = match local_phy(local, beacon.channel) {
            Ok(physical) => physical,
            Err(_) if local.he => {
                let mut legacy = local;
                legacy.he = false;
                return Self::negotiate(beacon, own, auth, legacy);
            }
            Err(reason) => return Err(reason),
        };
        let mld = super::sc_mlo::local(local.eht, &beacon.information_elements, own)?;
        let options = JoinOptions::default()
            .with_akms(AkmSet::ALL)
            .with_pmf(if peer_mfpc {
                Pmf::Optional
            } else {
                Pmf::Disabled
            });
        let plan = if let Some(mld) = mld {
            JoinPlan::prepare_mld(
                &bss,
                own,
                &beacon.ssid,
                mode,
                physical.ok_or("native MLD physical EHT source absent")?,
                options,
                mld,
            )
        } else {
            JoinPlan::prepare_with_options(&bss, own, &beacon.ssid, mode, physical, options)
        };
        let plan = match plan {
            Ok(plan) => plan,
            Err(_) if local.he && mld.is_none() => {
                // A non-HE-mandatory BSS can retain the native legacy path
                // when its optional HE profile is not implemented. The
                // shared plan still rejects a mandatory HE selector.
                let mut legacy = local;
                legacy.he = false;
                return Self::negotiate(beacon, own, auth, legacy);
            }
            Err(_) => return Err("unsupported MLD station security offer"),
        };
        Self::from_plan(&plan, mode)
    }

    pub(super) fn from_plan(plan: &JoinPlan, mode: SecurityMode) -> Result<Self, &'static str> {
        use narf_wireless::eapol::KeyMgmt;
        let akm = match plan.akm() {
            None if mode == SecurityMode::Open => None,
            Some(KeyMgmt::Psk) => Some(security::Akm::Wpa2Psk),
            Some(KeyMgmt::PskSha256) => Some(security::Akm::Wpa2PskSha256),
            Some(KeyMgmt::Sae) => Some(security::Akm::Wpa3Sae),
            Some(KeyMgmt::SaeExtKey) => Some(security::Akm::Wpa3SaeExtKey),
            _ => return Err("unsupported MLD negotiated key hierarchy"),
        };
        Ok(Self {
            akm,
            pmf: plan.pmf(),
            rsne: plan.rsn_body(),
            sae: plan.sae().cloned(),
            offer: plan.offered_phy().copied(),
            mld: plan.mld().copied().map(alloc::boxed::Box::new),
            links: None,
        })
    }

    /// Request the further affiliated links of the selected AP MLD
    /// (mlme.c ieee80211_mgd_assoc with several `req->links`): each
    /// candidate is prepared from its own actual beacon with the same
    /// native local PHY admission as the association link, and the
    /// resulting multiple-link plan must reproduce this profile's
    /// association-link security and MLD context exactly. Candidates that
    /// cannot be prepared are not requested; if none remain the profile
    /// stays single-link. Returns the requested candidates' indices.
    pub fn negotiate_links(
        &mut self,
        beacon: &Beacon,
        own: [u8; 6],
        local: Local,
        further: &[(&Beacon, [u8; 6], Local)],
    ) -> Result<Vec<usize>, &'static str> {
        use narf_wireless::association::{MldLinkPhy, MldLinkRequest};
        let Some(context) = self.mld.as_deref().copied() else {
            return Ok(Vec::new());
        };
        let mode = SecurityMode::Wpa3Sae { pwe: SaePwe::Both };
        if !self.pmf
            || !matches!(
                self.akm,
                Some(security::Akm::Wpa3Sae | security::Akm::Wpa3SaeExtKey)
            )
        {
            return Err("native MLD multiple-link request requires SAE/PMF");
        }
        // mac80211 copies the station `wiphy_iftype_ext_capab` into every
        // MLD request; iwl mld publishes IWL_MLD_EMLSR_CAPA for an 11be NVM
        // (admitted here: this path requires the native EHT PHY). Its
        // TID-to-link negotiation and link reconfiguration capability bits
        // are not advertised: neither negotiation is implemented.
        let mld = narf_wireless::association::mlo::Local::single_link(context.own_mld())
            .map_err(|_| "native MLD local address invalid")?
            .with_capabilities(
                0,
                narf_wireless::association::mlo::EmlCapabilities::INTEL_MLD_LOCAL,
            );
        let options = JoinOptions::default()
            .with_akms(AkmSet::ALL)
            .with_pmf(Pmf::Optional);
        let assoc_bss = bss(beacon);
        let assoc_phy = local_phy(local, beacon.channel)?.ok_or("native MLD EHT PHY absent")?;
        let assoc = MldLinkRequest {
            bss: &assoc_bss,
            own_link: own,
            phy: MldLinkPhy::Phy(assoc_phy),
        };
        let mut chosen = Vec::new();
        let mut bsses = Vec::new();
        let mut phys = Vec::new();
        for (index, (candidate, own_link, local)) in further.iter().enumerate() {
            let link_bss = bss(candidate);
            let Ok(Some(phy)) = local_phy(*local, candidate.channel) else {
                continue;
            };
            let request = MldLinkRequest {
                bss: &link_bss,
                own_link: *own_link,
                phy: MldLinkPhy::Phy(phy),
            };
            // Each candidate alone must form a valid request with the
            // association link before it joins the combined request.
            if JoinPlan::prepare_mld_links(assoc, &[request], &beacon.ssid, mode, options, mld)
                .is_ok()
            {
                chosen.push(index);
                bsses.push((link_bss, *own_link));
                phys.push(phy);
            }
        }
        if chosen.is_empty() {
            return Ok(chosen);
        }
        let requests: Vec<_> = bsses
            .iter()
            .zip(&phys)
            .map(|((bss, own_link), phy)| MldLinkRequest {
                bss,
                own_link: *own_link,
                phy: MldLinkPhy::Phy(*phy),
            })
            .collect();
        let plan = JoinPlan::prepare_mld_links(assoc, &requests, &beacon.ssid, mode, options, mld)
            .map_err(|_| "native MLD multiple-link request invalid")?;
        let same = Self::from_plan(&plan, mode)?;
        if same.akm != self.akm
            || same.pmf != self.pmf
            || same.rsne != self.rsne
            || same.mld.as_deref() != Some(&context)
        {
            return Err("native MLD multiple-link plan changed the association link");
        }
        self.links = Some(alloc::boxed::Box::new(plan));
        Ok(chosen)
    }

    pub(super) fn rsn_extensions(
        &self,
        mut ies: &[u8],
    ) -> Result<security::RsnExtensions, &'static str> {
        let station = self.sae.as_ref().and_then(SaeJoin::station_rsnxe);
        let mut ap = None;
        while !ies.is_empty() {
            if ies.len() < 2 || ies.len() < 2 + usize::from(ies[1]) {
                return Err("truncated AP RSNXE information elements");
            }
            if ies[0] == 244 {
                if ap.is_some() {
                    return Err("duplicate AP RSNXE");
                }
                ap = Some(ies[2..2 + usize::from(ies[1])].to_vec());
            }
            ies = &ies[2 + usize::from(ies[1])..];
        }
        Ok((station, ap))
    }

    /// Optional response RSNEs cannot silently change the negotiated AKM,
    /// cipher or PMF facts. SAE responses may omit the SAE PMKID.
    pub fn check_response(&self, mut ies: &[u8]) -> Result<(), &'static str> {
        // A multiple-link response carries affiliated profiles; it is
        // validated per link by `JoinPlan::accept_mld_links` instead.
        if let Some(context) = self.mld.as_deref().filter(|_| self.links.is_none()) {
            context
                .response(ies)
                .map_err(|_| "native MLD association response changed selected context")?;
        }
        let mut seen = false;
        while !ies.is_empty() {
            if ies.len() < 2 || usize::from(ies[1]) > ies.len() - 2 {
                return Err("truncated MLD association-response IE");
            }
            let end = 2 + usize::from(ies[1]);
            if ies[0] == 48 {
                if seen {
                    return Err("duplicate MLD association-response RSNE");
                }
                seen = true;
                let got = narf_wireless::rsn::RsnIe::decode_body(&ies[2..end])
                    .ok_or("invalid MLD association-response RSNE")?;
                let expected = self
                    .rsne
                    .as_deref()
                    .and_then(narf_wireless::rsn::RsnIe::decode_body);
                let no_pmkid = self
                    .sae
                    .as_ref()
                    .and_then(|s| narf_wireless::rsn::RsnIe::decode_body(&s.station_rsne(None)));
                if expected.as_ref() != Some(&got) && no_pmkid.as_ref() != Some(&got) {
                    return Err("MLD response changed the negotiated security profile");
                }
            }
            ies = &ies[end..];
        }
        Ok(())
    }
}

/// ADD/REMOVE SEC_KEY_CMD v1. CMAC IGTKs use the CCMP cipher selector;
/// only pairwise PMF keys and IGTKs get MFP, while station group keys get
/// NO_TX. RX sequence is the authenticated KDE replay floor (offset64).
pub(super) fn key_command(
    id: u8,
    group: bool,
    pmf: bool,
    key: Option<&[u8; 16]>,
    rx_pn: u64,
) -> Result<Zeroizing<[u8; 80]>, &'static str> {
    if group && id > 5 {
        return Err("invalid MLD native key identity/PN");
    }
    key_command_for(1, id, group, pmf, key, rx_pn)
}

/// Linux mld/key.c `iwl_mld_get_key_flags` for a station vif: CCMP/CMAC
/// cipher, MCAST|NO_TX for group keys, MFP for IGTK (4/5) and an MFP
/// station's pairwise key. BIGTK (6/7) is neither IGTK nor pairwise.
pub(super) fn key_flags(id: u8, group: bool, pmf: bool) -> u32 {
    let igtk = group && matches!(id, 4 | 5);
    2 | if group { 0x48 } else { 0 } | if igtk || (!group && pmf) { 0x20 } else { 0 }
}

/// SEC_KEY_CMD v1 ADD/REMOVE for an explicit firmware STA mask. Linux
/// `iwl_mld_get_key_sta_mask`: a pairwise key (link_id < 0) spans every
/// link STA of the AP MLD; a station's per-link GTK/IGTK/BIGTK names only
/// that link's STA.
pub(super) fn key_command_for(
    sta_mask: u32,
    id: u8,
    group: bool,
    pmf: bool,
    key: Option<&[u8; 16]>,
    rx_pn: u64,
) -> Result<Zeroizing<[u8; 80]>, &'static str> {
    if (group && id > 7) || (!group && id != 0) || rx_pn >= 1 << 48 || sta_mask == 0 {
        return Err("invalid MLD native key identity/PN");
    }
    let mut body = Zeroizing::new([0; 80]);
    put32(&mut body[..], 0, if key.is_some() { 1 } else { 3 });
    put32(&mut body[..], 4, sta_mask);
    put32(&mut body[..], 8, u32::from(id));
    put32(&mut body[..], 12, key_flags(id, group, pmf));
    if let Some(key) = key {
        body[16..32].copy_from_slice(key);
        put64(&mut body[..], 64, rx_pn);
    }
    Ok(body)
}

/// Validate firmware's unicast CCMP integrity result and the management
/// replay domain before exposing a robust frame's decrypted body. It is
/// separate from all data-TID PN counters (mac80211 NUM_TIDS).
pub(super) fn robust_unicast_body<'a>(
    mpdu: &scan_api::Mpdu<'a>,
    protected_required: bool,
    management_pn: &mut u64,
) -> Option<&'a [u8]> {
    let f = mpdu.frame;
    if f.len() < 24 || f[1] & 0x87 != 0 || f[22] & 15 != 0 || mpdu.amsdu {
        return None;
    }
    if !protected_required {
        return (f[1] & 0x40 == 0).then(|| mpdu.body(24, 0)).flatten();
    }
    // MLD v3 status: CCM=2<<8, MIC_OK=bit6, REPLAY_ERROR=bit7.
    // Linux iwl_mld_rx_crypto uses CCM+MIC rather than DEC_DONE. When
    // firmware supplied a station lookup, it must refer to our station0;
    // otherwise the caller's exact AP MAC binding is the lookup fallback.
    if f[1] & 0x40 == 0
        || mpdu.status & 0x7c0 != 0x240
        || mpdu.status & 4 != 0 && mpdu.status & 0x1f000000 != 0
    {
        return None;
    }
    let iv = f.get(24..32).filter(|iv| iv[3] == 0x20)?;
    let pn = u64::from_le_bytes([iv[0], iv[1], iv[4], iv[5], iv[6], iv[7], 0, 0]);
    if pn <= *management_pn {
        return None;
    }
    let body = mpdu.body(24, 8)?;
    *management_pn = pn;
    Some(body)
}
