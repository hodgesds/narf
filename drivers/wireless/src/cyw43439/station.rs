// SPDX-License-Identifier: GPL-2.0-or-later
//! FullMAC single-station commands over retained BCDC or msgbuf runtimes.
//! References: Linux brcmfmac/{common,cfg80211}.c and fwil_types.h.

use super::{
    channel, events,
    fullmac::{FirmwareVendor, Fullmac},
    ioctl::{self, Direction},
    runtime::Error,
};
#[cfg(any(test, feature = "kernel-test"))]
use super::{runtime::Runtime, PacketTransport};
use alloc::{sync::Arc, vec, vec::Vec};
use narf_wireless::{AssociateRequest, BssInfo, ScanRequest, SecurityConfig};

#[derive(Debug, Clone)]
pub struct Bss {
    pub info: BssInfo,
    pub ies: Vec<u8>,
}

pub struct Station<R: Fullmac> {
    pub runtime: R,
    pub mac: [u8; 6],
    pub channels: Vec<u8>,
    domain: Arc<narf_wireless::reg::RegulatoryDomain>,
    policy: Option<Arc<dyn PolicySource>>,
    connection: Option<policy::TxGrant>,
    pub bssid: Option<[u8; 6]>,
    pub cache: Vec<Bss>,
    scan_id: u16,
    pub supplicant: bool,
    mfp_supported: bool,
    /// Firmware SAE offload: `cap` token `sae` with FWSUP and MFP.
    sae_offload: bool,
    /// `BRCMF_FEAT_PMKID_V3` (`wlc_ver` major >= 13).
    pmkid_v3: bool,
    /// Firmware PMKID list known to be programmed; `None` after a refused
    /// or interrupted `pmkid_info` update until it is rewritten.
    pmksa: Option<pmksa::Cache>,
    mfp_verified: bool,
    phy: Option<phy::Capabilities>,
    ht_verified: bool,
    vht_verified: bool,
    power_save: bool,
    operation: bool,
    /// Probe Request vendor elements currently installed in firmware.
    probe_ies: Vec<u8>,
    /// Negotiated firmware WMM rank map for the authorized peer.
    ac_priority: [u8; 8],
}
impl<R: Fullmac> core::fmt::Debug for Station<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FullmacStation")
            .field("mac", &self.mac)
            .field("bssid", &self.bssid)
            .finish_non_exhaustive()
    }
}

impl<R: Fullmac> Station<R> {
    /// Initialize firmware IOCTLs, CLM, regulatory policy and event delivery.
    /// The caller supplies a completed firmware-loader transport and an
    /// authenticated host policy; no interface may be published before success.
    pub async fn initialize(
        runtime: R,
        clm: &[u8],
        domain: narf_wireless::reg::RegulatoryDomain,
    ) -> Result<Self, Error> {
        Self::initialize_inner(runtime, clm, Arc::new(domain), None).await
    }

    async fn initialize_inner(
        mut runtime: R,
        clm: &[u8],
        domain: Arc<narf_wireless::reg::RegulatoryDomain>,
        policy: Option<Arc<dyn PolicySource>>,
    ) -> Result<Self, Error> {
        if (R::EXTERNAL_CLM && clm.is_empty())
            || clm.len() > 1024 * 1024
            || !domain.country_code.iter().all(u8::is_ascii_uppercase)
        {
            return Err(Error::Malformed);
        }
        let version = runtime
            .command(Direction::Get, ioctl::WLC_GET_VERSION, &[], 4)
            .await?;
        if version.as_slice() != 2u32.to_le_bytes() {
            return Err(Error::Unsupported);
        }
        for (i, chunk) in clm.chunks(1024).enumerate() {
            let mut payload = vec![0; 12 + chunk.len()];
            let flags = 0x1000u16
                | if i == 0 { 2 } else { 0 }
                | if (i + 1) * 1024 >= clm.len() { 4 } else { 0 };
            payload[..2].copy_from_slice(&flags.to_le_bytes());
            payload[2..4].copy_from_slice(&2u16.to_le_bytes());
            payload[4..8].copy_from_slice(&(chunk.len() as u32).to_le_bytes());
            payload[12..].copy_from_slice(chunk);
            set_var(&mut runtime, "clmload", &payload).await?;
        }
        if !clm.is_empty() && get_var(&mut runtime, "clmload_status", 4).await?.as_slice() != [0; 4]
        {
            return Err(Error::Firmware(1));
        }
        let mut country = [0; 12];
        country[..2].copy_from_slice(&domain.country_code);
        country[8..10].copy_from_slice(&domain.country_code);
        set_var(&mut runtime, "country", &country).await?;
        runtime.configure_bus().await?;
        let phy = phy::probe(&mut runtime).await?;
        set_int(&mut runtime, ioctl::WLC_SET_PM, 0).await?;
        set_int(&mut runtime, 20, 1).await?; // Infrastructure station.
        set_int(&mut runtime, 22, 0).await?; // Open-system 802.11 authentication.
                                             // This profile pins the selected BSSID and does not consume ROAM
                                             // events. Firmware must not silently move the authorized peer.
        set_var(&mut runtime, "roam_off", &1u32.to_le_bytes()).await?;
        let address = get_var(&mut runtime, "cur_etheraddr", 6).await?;
        let mac: [u8; 6] = address.try_into().map_err(|_| Error::Malformed)?;
        if mac == [0; 6] || mac[0] & 1 != 0 {
            return Err(Error::Malformed);
        }
        let mut mask = [0; 16];
        for event in [0, 3, 5, 6, 7, 11, 12, 16, 46, 63, 69] {
            mask[event / 8] |= 1 << (event % 8);
        }
        set_var(&mut runtime, "event_msgs", &mask).await?;
        let supplicant = match get_var(&mut runtime, "sup_wpa", 4).await {
            Ok(bytes) => bytes.len() == 4,
            Err(Error::Firmware(code)) if code as i32 == -23 => false,
            Err(error) => return Err(error),
        };
        // Linux feature.c probes this exact native iovar; host RSN flags
        // alone do not establish firmware management-protection support.
        let mfp_supported = match get_var(&mut runtime, "mfp", 4).await {
            Ok(bytes) if bytes.len() == 4 && le32(&bytes, 0)? <= 2 => true,
            Ok(_) => return Err(Error::Malformed),
            Err(Error::Firmware(_)) => false,
            Err(error) => return Err(error),
        };
        // Linux feature.c brcmf_feat_firmware_capabilities: BRCMF_FEAT_SAE
        // is the exact `cap` token "sae " (distinct from "sae_ext"). Linux
        // cfg80211.c only offloads SAE with BRCMF_FEAT_FWSUP; WPA3 also needs
        // native MFP, so all three firmware features are required.
        let sae_offload = supplicant
            && mfp_supported
            && match get_var(&mut runtime, "cap", sae::CAP_LEN).await {
                Ok(caps) => sae::has_capability(&caps, b"sae"),
                Err(Error::Firmware(_)) => false,
                Err(error) => return Err(error),
            };
        let pmkid_v3 = match get_var(&mut runtime, "wlc_ver", pmksa::WLC_VERSION_LEN).await {
            Ok(reply) => pmksa::v3_from_wlc_version(&reply)?,
            Err(Error::Firmware(_)) => false,
            Err(error) => return Err(error),
        };
        policy::check_initial(&mut runtime, &policy, &domain)?;
        policy::enable(&mut runtime, &policy, &domain).await?;
        policy::check_initial(&mut runtime, &policy, &domain)?;
        let reply = runtime
            .command(Direction::Get, 217, &64u32.to_le_bytes(), 260)
            .await?;
        let count = le32(&reply, 0)? as usize;
        if count > 64 || reply.len() < 4 + count * 4 {
            return Err(Error::Malformed);
        }
        let mut channels = Vec::new();
        for index in 0..count {
            let channel = le32(&reply, 4 + index * 4)?;
            let Ok(channel) = u8::try_from(channel) else {
                continue;
            };
            if (channel <= 14 || R::BAND_5GHZ)
                && channel_ceiling(&domain, channel, false).is_some()
                && !channels.contains(&channel)
            {
                channels.push(channel);
            }
        }
        if channels.is_empty() {
            return Err(Error::Unsupported);
        }
        policy::check_initial(&mut runtime, &policy, &domain)?;
        Ok(Self {
            runtime,
            mac,
            channels,
            domain,
            policy,
            connection: None,
            bssid: None,
            cache: Vec::new(),
            scan_id: 0,
            supplicant,
            mfp_supported,
            sae_offload,
            pmkid_v3,
            pmksa: Some(pmksa::Cache::default()),
            mfp_verified: false,
            phy,
            ht_verified: false,
            vht_verified: false,
            power_save: false,
            operation: false,
            probe_ies: Vec::new(),
            ac_priority: wmm::DEFAULT_AC_PRIORITY,
        })
    }

    /// Current negotiated firmware WMM rank map (`wme_ac_sta`) for the
    /// authorized peer; absent without a connection.
    pub fn ac_priority(&self) -> Option<[u8; 8]> {
        self.bssid.map(|_| self.ac_priority)
    }

    fn reset_wmm(&mut self) {
        self.ac_priority = wmm::DEFAULT_AC_PRIORITY;
        self.runtime.set_ac_priority(self.ac_priority);
    }

    /// Last firmware-acknowledged ordinary station power-save policy.
    /// Firmware WPA3-Personal SAE offload (`NL80211_EXT_FEATURE_SAE_OFFLOAD`).
    pub fn supports_sae_offload(&self) -> bool {
        self.sae_offload
    }

    /// Firmware PMKID cache revision (`BRCMF_FEAT_PMKID_V3`).
    pub fn pmkid_v3(&self) -> bool {
        self.pmkid_v3
    }
    /// Firmware PMKID list last programmed, if known.
    pub fn programmed_pmksa(&self) -> Option<&pmksa::Cache> {
        self.pmksa.as_ref()
    }

    /// Reconcile the firmware `pmkid_info` list with `desired`
    /// (Linux `brcmf_update_pmklist` / `brcmf_pmksa_v3_op`). A firmware
    /// refusal leaves the list unknown, so the next call rewrites it.
    pub async fn sync_pmksa(&mut self, desired: &pmksa::Cache) -> Result<(), Error> {
        if self.pmksa.as_ref() == Some(desired) {
            return Ok(());
        }
        self.poll()?;
        self.operation = true;
        self.pmksa = None;
        let result = pmksa::program(&mut self.runtime, self.pmkid_v3, desired).await;
        self.operation = false;
        match result {
            Ok(()) => self.pmksa = Some(desired.clone()),
            Err(Error::Firmware(_)) => {}
            Err(_) => {
                self.bssid = None;
                self.connection = None;
                self.runtime.fail();
                self.runtime.set_link(None);
            }
        }
        result
    }

    pub fn power_save(&self) -> bool {
        self.power_save
    }

    /// Completed firmware-offloaded PMF negotiation/key receipt metadata.
    /// This grants no independent packet or management-frame authority.
    pub fn management_protection(&self) -> bool {
        self.mfp_verified && self.bssid.is_some() && self.connection.is_some()
    }
    /// Actual retained firmware MFP and four-way-offload capability. This is
    /// wiphy metadata, not a completed protected association or key grant.
    pub fn supports_management_protection(&self) -> bool {
        self.mfp_supported && self.supplicant
    }
    /// Actual queried HT capabilities by2GHz/5GHz band. Width40 also requires
    /// exact firmware chanspec inventory; it grants no operating permission.
    pub fn ht_capabilities(&self) -> [Option<[u8; 26]>; 2] {
        [false, true].map(|five| {
            self.phy
                .as_ref()
                .filter(|_| !five || R::BAND_5GHZ)
                .map(|phy| phy.body(five))
        })
    }
    /// Completed native HT association facts for the currently admitted peer.
    pub fn ht_connection(&self) -> bool {
        self.ht_verified && self.bssid.is_some() && self.connection.is_some()
    }
    /// Firmware-probed VHT metadata is restricted to the exact5GHz family.
    pub fn vht_capabilities(&self) -> [Option<[u8; 12]>; 2] {
        [
            None,
            self.phy
                .as_ref()
                .and_then(|p| p.vht_body(R::VHT80 && R::BAND_5GHZ)),
        ]
    }
    pub fn vht_connection(&self) -> bool {
        self.vht_verified && self.bssid.is_some() && self.connection.is_some()
    }
    /// Last native-verified20/40/80MHz occupied width. Metadata
    /// grants no TX authority; the current policy fence still guards service.
    pub fn channel_width_mhz(&self) -> Option<u32> {
        self.bssid.and(self.connection).map(policy::TxGrant::width)
    }

    /// Linux brcmf_cfg80211_set_power_mgmt: PM_FAST / PM_OFF followed by
    /// pm2_sleep_ret with cfg80211's default (maximum) 2000 ms timeout.
    /// This is firmware station PS; the host bus remains awake and polled.
    pub async fn set_power_save(&mut self, enabled: bool) -> Result<(), Error> {
        // Poll first to detect cancelled operations or transport failure, and
        // consume queued peer loss before any control/state publication.
        self.poll()?;
        if self.power_save == enabled {
            return Ok(());
        }
        self.operation = true;
        let connection = self.connection;
        let grants = connection.as_slice();
        let result = async {
            self.checked_command(
                grants,
                &[],
                ioctl::WLC_SET_PM,
                &(if enabled { 2u32 } else { 0 }).to_le_bytes(),
            )
            .await?;
            self.checked_var(grants, &[], "pm2_sleep_ret", &2000u32.to_le_bytes())
                .await
        }
        .await;
        self.operation = false;
        if let Err(error) = result {
            // A partial/ambiguous transition must never be treated as the
            // old applied policy or replayed on the same firmware lifetime.
            self.runtime.fail();
            self.bssid = None;
            self.connection = None;
            self.runtime.set_link(None);
            return Err(error);
        }
        self.power_save = enabled;
        self.poll()
    }

    pub async fn scan(&mut self, request: ScanRequest) -> Result<Vec<BssInfo>, Error> {
        if self.operation {
            self.runtime.fail();
            return Err(Error::Failed);
        }
        self.operation = true;
        let result = self.scan_inner(request).await;
        self.operation = false;
        result
    }

    async fn scan_inner(&mut self, request: ScanRequest) -> Result<Vec<BssInfo>, Error> {
        if self.bssid.is_some() {
            return Err(Error::Busy);
        }
        if request.random_mac.is_some()
            || request.colocated_6ghz
            || request.duration_tu.is_some()
            || request.duration_mandatory
        {
            return Err(Error::Unsupported);
        }
        let probe_ies = probe_ies::parse(&request.extra_ies)?;
        let mut channels = Vec::new();
        for channel in if !request.frequencies_mhz.is_empty() {
            let mut selected = Vec::new();
            for &frequency in &request.frequencies_mhz {
                let channel =
                    u32::from(channel::from_frequency(frequency).ok_or(Error::Unsupported)?);
                if !request.channels.is_empty() && !request.channels.contains(&channel) {
                    return Err(Error::Malformed);
                }
                selected.push(channel);
            }
            selected
        } else if request.channels.is_empty() {
            self.channels.iter().map(|&ch| u32::from(ch)).collect()
        } else {
            request.channels.clone()
        } {
            let channel = u8::try_from(channel).map_err(|_| Error::Malformed)?;
            if !self.channels.contains(&channel) {
                return Err(Error::Malformed);
            }
            if !channels.contains(&channel) {
                channels.push(channel);
            }
        }
        self.check_receive_policy(&channels)?;
        self.scan_id = self.scan_id.wrapping_add(1);
        let id = self.scan_id;
        let command = scan_command(id, &channels, &request.ssids, request.active)?;
        self.runtime.poll()?;
        while self.runtime.pop_event().is_some() {}
        let mut grants = Vec::new();
        if request.active {
            // Every requested active channel must permit TX. Filtering a
            // restricted channel out of the power reduction would still send
            // its probe request in the unchanged firmware channel list.
            let mut power: Option<u8> = None;
            for &channel in &channels {
                let ceiling = channel_power(&self.domain, channel).ok_or(Error::Unsupported)?;
                power = Some(power.map_or(ceiling, |old| old.min(ceiling)));
            }
            let power = power.ok_or(Error::Unsupported)?;
            for &channel in &channels {
                grants.push(self.grant(channel, power)?);
            }
            self.check_grants(&grants)?;
            self.checked_var(
                &grants,
                &channels,
                "qtxpower",
                &(u32::from(power) * 4).to_le_bytes(),
            )
            .await?;
        }
        self.check_receive_policy(&channels)?;
        self.check_grants(&grants)?;
        if let Some(update) = probe_ies::update(&self.probe_ies, &probe_ies) {
            // Firmware applies the del/add records in order; a refused or
            // cancelled update leaves the installed set unknown, so no later
            // Probe Request may be claimed to carry exactly a caller's IEs.
            if let Err(error) = self
                .checked_var(&grants, &channels, "vndr_ie", &update)
                .await
            {
                self.runtime.fail();
                return Err(error);
            }
            self.probe_ies = probe_ies;
            self.check_receive_policy(&channels)?;
            self.check_grants(&grants)?;
        }
        self.cache.clear();
        self.checked_var(&grants, &channels, "escan", &command)
            .await?;
        self.check_receive_policy(&channels)?;
        self.check_grants(&grants)?;
        let deadline = narf_time::Deadline::after_ms(15000);
        let outcome = async {
            loop {
                self.check_receive_policy(&channels)?;
                self.check_grants(&grants)?;
                self.runtime.poll()?;
                self.check_receive_policy(&channels)?;
                self.check_grants(&grants)?;
                while let Some(event) = self.runtime.pop_event() {
                    if event.header.event_type != events::WLC_E_ESCAN_RESULT {
                        continue;
                    }
                    if event.header.status == 8 {
                        // BRCMF_E_STATUS_PARTIAL.
                        let (event_id, bss) = parse_scan_result(&event.payload)?;
                        if event_id != id {
                            continue;
                        }
                        if channels.contains(&(bss.info.channel as u8))
                            && (request.ssids.is_empty()
                                || request
                                    .ssids
                                    .iter()
                                    .any(|s| s.is_empty() || *s == bss.info.ssid))
                        {
                            if let Some(old) = self
                                .cache
                                .iter_mut()
                                .find(|b| b.info.bssid == bss.info.bssid)
                            {
                                *old = bss;
                            } else if self.cache.len() < 64 {
                                self.cache.push(bss);
                            }
                        }
                    } else {
                        // Some firmware sends a headerless terminal event, as
                        // Linux's escan handler permits. When it supplies the
                        // escan header, a stale sync ID cannot complete this scan.
                        if !event.payload.is_empty() {
                            let length = le32(&event.payload, 0)? as usize;
                            if length < 12 || length > event.payload.len() {
                                return Err(Error::Malformed);
                            }
                            let event_id = u16::from_le_bytes(
                                event
                                    .payload
                                    .get(8..10)
                                    .ok_or(Error::Malformed)?
                                    .try_into()
                                    .unwrap(),
                            );
                            if event_id != id {
                                continue;
                            }
                        }
                        if event.header.status == 0 {
                            self.check_receive_policy(&channels)?;
                            self.check_grants(&grants)?;
                            return Ok(self.cache.iter().map(|b| b.info.clone()).collect());
                        }
                        return Err(Error::Firmware(event.header.status));
                    }
                }
                if deadline.expired() {
                    self.runtime.fail();
                    return Err(Error::Timeout);
                }
                wait().await;
            }
        }
        .await;
        // Once firmware accepted escan, any malformed/error outcome needs
        // reset or a confirmed abort. Never let its late completion finish
        // another operation. Cancellation is caught by `operation` on poll.
        if outcome.is_err() {
            self.runtime.fail();
        }
        outcome
    }

    pub async fn associate(&mut self, request: AssociateRequest) -> Result<(), Error> {
        if self.operation {
            self.runtime.fail();
            return Err(Error::Failed);
        }
        self.operation = true;
        let result = self.associate_inner(request).await;
        self.operation = false;
        result
    }

    async fn associate_inner(&mut self, request: AssociateRequest) -> Result<(), Error> {
        if self.bssid.is_some() {
            return Err(Error::Busy);
        }
        if request.ssid.is_empty()
            || request.ssid.len() > 32
            || request.bssid == [0; 6]
            || request.bssid[0] & 1 != 0
        {
            return Err(Error::Malformed);
        }
        let bss = self
            .cache
            .iter()
            .find(|b| {
                b.info.bssid == request.bssid
                    && b.info.ssid == request.ssid
                    && b.info.channel == request.channel
                    && b.info.frequency_mhz == request.frequency_mhz
            })
            .ok_or(Error::Malformed)?
            .clone();
        self.refresh_policy()?;
        let akm = match &request.security {
            SecurityConfig::Open
                if matches!(bss.info.security, narf_wireless::scan::BssSecurity::Open) =>
            {
                None
            }
            SecurityConfig::Wpa2 { .. } if self.supplicant => Some(narf_wireless::rsn::AKM_PSK),
            SecurityConfig::Wpa3 { password } if self.sae_offload => {
                if password.is_empty() || password.len() > sae::PASSWORD_MAX {
                    return Err(Error::Malformed);
                }
                Some(narf_wireless::rsn::AKM_SAE)
            }
            _ => return Err(Error::Unsupported),
        };
        if let Some(akm) = akm {
            let rsn = rsn(&bss.ies).ok_or(Error::Unsupported)?;
            use narf_wireless::rsn::*;
            let ccmp = Suite::standard(CIPHER_CCMP_128);
            if rsn.group_cipher != ccmp
                || !rsn.pairwise_ciphers.contains(&ccmp)
                || !rsn.akms.contains(&Suite::standard(akm))
            {
                return Err(Error::Unsupported);
            }
        }
        let secure = akm.is_some();
        let sae = akm == Some(narf_wireless::rsn::AKM_SAE);
        let protection =
            mfp::Profile::negotiate_akm(&bss.ies, &request.ie, akm, self.mfp_supported)?;
        validate_association_ies(&request.ie, protection.akm(), protection.required())?;
        let mut ht = self
            .phy
            .as_ref()
            .map(|phy| phy.prepare(&bss.ies, bss.info.channel as u8, &self.channels))
            .transpose()?
            .flatten();
        for _ in 0..2 {
            if ht.is_some_and(|profile| {
                profile.channel.width() > 20
                    && occupied_power(&self.domain, profile.channel).is_none()
            }) {
                ht = ht.map(phy::Profile::narrow);
            } else {
                break;
            }
        }
        let occupied = ht.map_or_else(
            || channel::Operating::twenty(bss.info.channel as u8).ok_or(Error::Unsupported),
            |profile| Ok(profile.channel),
        )?;
        let power = occupied_power(&self.domain, occupied).ok_or(Error::Unsupported)?;
        let grant = self.grant_occupied(occupied, power)?;
        self.mfp_verified = false;
        self.ht_verified = false;
        self.vht_verified = false;
        self.tx_var(grant, "qtxpower", &(u32::from(power) * 4).to_le_bytes())
            .await?;
        self.runtime.poll()?;
        while self.runtime.pop_event().is_some() {}
        let result = async {
            if self.phy.is_some() || R::BAND_5GHZ {
                self.configure_width(grant, occupied).await?;
            }
            // brcmf_set_auth_type: NL80211_AUTHTYPE_SAE is 3, Open 0.
            self.tx_int(grant, 22, if sae { 3 } else { 0 }).await?;
            // Linux configures (and clears for Open) the association RSNE
            // before joining. Pin the firmware offload to this driver's
            // single negotiated PSK/CCMP profile even on a mixed-mode AP.
            let mut wpa_ie = Vec::new();
            if secure {
                let body = protection.rsn().encode_body();
                wpa_ie.extend_from_slice(&[48, body.len() as u8]);
                wpa_ie.extend_from_slice(&body);
            }
            self.tx_var(grant, "wpaie", &wpa_ie).await?;
            self.tx_var(
                grant,
                "wpa_auth",
                // WPA2_AUTH_PSK / WPA3_AUTH_SAE_PSK (brcmu_wifi.h).
                &match (secure, sae) {
                    (_, true) => sae::WPA3_AUTH_SAE_PSK,
                    (true, false) => 128u32,
                    _ => 0,
                }
                .to_le_bytes(),
            )
            .await?;
            self.tx_int(grant, 134, if secure { 4 } else { 0 }).await?;
            if self.mfp_supported {
                // WSEC can overwrite MFP state: Linux cfg80211.c places
                // this after cipher configuration, including NONE on Open.
                self.tx_var(grant, "mfp", &protection.mode().to_le_bytes())
                    .await?;
                let applied = self.tx_query(grant, "mfp", 4).await?;
                if applied.as_slice() != protection.mode().to_le_bytes() {
                    return Err(Error::Unsupported);
                }
            }
            if self.supplicant {
                self.tx_var(grant, "sup_wpa", &u32::from(secure).to_le_bytes())
                    .await?;
            }
            if let SecurityConfig::Wpa3 { password } = &request.security {
                // Linux: "clean up user-space RSNE" so firmware builds the
                // SAE RSNE itself, then the fwvid password ABI.
                self.tx_var(grant, "wpaie", &[]).await?;
                match self.runtime.firmware_vendor() {
                    FirmwareVendor::Cyw => {
                        let body = sae::cyw_password(password)?;
                        self.tx_var(grant, "sae_password", &body[..]).await?;
                    }
                    FirmwareVendor::Wcc => {
                        let body = sae::wcc_passphrase(password)?;
                        self.tx_command(grant, ioctl::WLC_SET_WSEC_PMK, &body[..])
                            .await?;
                    }
                }
            }
            if let SecurityConfig::Wpa2 { psk } = &request.security {
                // CYW legacy wsec_pmk: length/flags + 64-byte key buffer.
                let mut pmk = zeroize::Zeroizing::new([0; 68]);
                pmk[..2].copy_from_slice(&32u16.to_le_bytes());
                pmk[4..36].copy_from_slice(psk);
                self.tx_command(grant, 268, &pmk[..]).await?;
            }
            let mut join = [0; 50];
            join[..4].copy_from_slice(&(request.ssid.len() as u32).to_le_bytes());
            join[4..4 + request.ssid.len()].copy_from_slice(&request.ssid);
            join[36..42].copy_from_slice(&request.bssid);
            join[44..48].copy_from_slice(&1u32.to_le_bytes());
            join[48..50].copy_from_slice(&occupied.chanspec().to_le_bytes());
            self.tx_command(grant, 26, &join).await?;
            let deadline = narf_time::Deadline::after_ms(15000);
            let (mut associated, mut keys) = (false, !secure);
            let mut protection_verified = false;
            let mut wmm_verified = false;
            let mut drain_batches = 0;
            loop {
                self.check_grants(core::slice::from_ref(&grant))?;
                let consumed = self.runtime.poll()?;
                self.check_grants(core::slice::from_ref(&grant))?;
                while let Some(event) = self.runtime.pop_event() {
                    if event.header.event_type == 63 && self.ht_verified {
                        return Err(Error::Unsupported);
                    }
                    if event.header.source_mac != request.bssid {
                        continue;
                    }
                    match event.header.event_type {
                        events::WLC_E_LINK => {
                            if event.header.flags & 1 == 0 || event.header.status != 0 {
                                return Err(Error::Firmware(event.header.reason));
                            }
                        }
                        events::WLC_E_PSK_SUP => {
                            if event.header.status != 6 {
                                return Err(Error::Firmware(event.header.status));
                            }
                            keys = true; // BRCMF_E_STATUS_FWSUP_COMPLETED.
                        }
                        events::WLC_E_DEAUTH
                        | events::WLC_E_DEAUTH_IND
                        | events::WLC_E_DISASSOC
                        | events::WLC_E_DISASSOC_IND => {
                            return Err(Error::Firmware(event.header.reason))
                        }
                        events::WLC_E_SET_SSID => {
                            if event.header.status != 0 {
                                return Err(Error::Firmware(event.header.status));
                            }
                            associated = true;
                        }
                        _ => {}
                    }
                }
                // A bounded poll can expose join/key events while older RX
                // remains beyond its packet/completion budget. Retire ALL
                // unauthorized data and process peer loss through an actual
                // current FIFO/ring idle sample before opening the host port.
                while self.runtime.pop_data().is_some() {}
                if associated && keys && consumed == 0 {
                    if let Some(profile) = ht.filter(|_| !self.ht_verified) {
                        self.verify_phy(grant, request.bssid, bss.info.channel as u8, profile)
                            .await?;
                        self.ht_verified = true;
                        self.vht_verified = profile.vht();
                        // Native queries can consume later peer loss/data.
                        // Re-observe a current FIFO/ring idle sample first.
                        continue;
                    }
                    if protection.verify() && !protection_verified {
                        self.mfp_verified = self
                            .verify_management_protection(grant, request.bssid, protection)
                            .await?;
                        protection_verified = true;
                        // Queries can drain new events/data. Require another
                        // genuine idle fence before publishing the host port.
                        continue;
                    }
                    if !wmm_verified {
                        // Linux brcmf_get_assoc_ies ranks the current firmware
                        // EDCA rows; a refused query keeps the default map.
                        self.ac_priority =
                            match self.tx_query(grant, "wme_ac_sta", wmm::ACPARAM_LEN).await {
                                Ok(rows) => wmm::prioritize(&rows)?,
                                Err(Error::Firmware(_)) => wmm::DEFAULT_AC_PRIORITY,
                                Err(error) => return Err(error),
                            };
                        wmm_verified = true;
                        // Another genuine idle fence follows this query.
                        continue;
                    }
                    self.check_grants(core::slice::from_ref(&grant))?;
                    self.connection = Some(grant);
                    self.runtime.set_ac_priority(self.ac_priority);
                    self.runtime.set_link(Some(request.bssid));
                    self.bssid = Some(request.bssid);
                    return Ok(());
                }
                if deadline.expired() {
                    return Err(Error::Timeout);
                }
                if associated && keys {
                    drain_batches += 1;
                    if drain_batches < 4 {
                        continue;
                    }
                    drain_batches = 0;
                }
                wait().await;
            }
        }
        .await;
        if result.is_err() {
            self.mfp_verified = false;
            self.ht_verified = false;
            self.vht_verified = false;
            self.reset_wmm();
            self.bssid = None;
            self.connection = None;
            self.runtime.set_link(None);
            // SET_SSID/PSK events carry no join transaction ID. An ACK to
            // DISASSOC does not prove that old authorization events are
            // drained. Until recovery confirms a fresh firmware lifecycle,
            // a failed join may never be retried against the same BSSID.
            self.runtime.fail();
        }
        result
    }

    pub async fn disconnect(&mut self) -> Result<(), Error> {
        if self.operation {
            self.runtime.fail();
            return Err(Error::Failed);
        }
        self.operation = true;
        let result = self.disconnect_inner().await;
        if result.is_err() {
            self.runtime.fail();
        }
        self.operation = false;
        result
    }

    async fn disconnect_inner(&mut self) -> Result<(), Error> {
        self.check_connection_policy()?;
        let grant = self.connection.take();
        let peer = self.bssid.take();
        self.mfp_verified = false;
        self.ht_verified = false;
        self.vht_verified = false;
        self.reset_wmm();
        self.runtime.set_link(None);
        if let Some(grant) = grant {
            self.tx_command(grant, 52, &[]).await?;
        } else {
            self.checked_command(&[], &[], 52, &[]).await?;
        }
        if let Some(peer) = peer {
            let deadline = narf_time::Deadline::after_ms(2000);
            'complete: loop {
                self.refresh_policy()?;
                if let Some(grant) = grant {
                    self.check_grants(core::slice::from_ref(&grant))?;
                }
                self.runtime.poll()?;
                while let Some(event) = self.runtime.pop_event() {
                    if event.header.source_mac == peer
                        && (matches!(event.header.event_type, 5 | 6 | 11 | 12)
                            || event.header.event_type == 16 && event.header.flags & 1 == 0)
                    {
                        break 'complete;
                    }
                }
                if deadline.expired() {
                    self.runtime.fail();
                    return Err(Error::Timeout);
                }
                wait().await;
            }
        }
        while self.runtime.pop_data().is_some() {}
        Ok(())
    }

    pub fn poll(&mut self) -> Result<(), Error> {
        // Control operations hold the device mutex. Observing this flag in
        // the worker means cancellation happened between completed IOCTLs.
        if self.operation {
            self.runtime.fail();
            self.bssid = None;
            self.connection = None;
            self.runtime.set_link(None);
            return Err(Error::Failed);
        }
        self.check_connection_policy()?;
        if let Err(error) = self.runtime.poll() {
            self.bssid = None;
            self.connection = None;
            self.runtime.set_link(None);
            return Err(error);
        }
        self.check_connection_policy()?;
        while let Some(event) = self.runtime.pop_event() {
            if let Some(peer) = self.bssid {
                // CHANNEL_ADOPTED is a firmware radio transition, not a new
                // occupied grant. Source MAC can be absent for radio events.
                // Retuning/rejoin needs its own lifecycle; close this port.
                if event.header.event_type == 63 {
                    self.bssid = None;
                    self.connection = None;
                    self.ht_verified = false;
                    self.vht_verified = false;
                    self.runtime.fail();
                    self.runtime.set_link(None);
                    return Err(Error::Unsupported);
                }
                if event.header.source_mac == peer
                    && (matches!(event.header.event_type, 5 | 6 | 11 | 12)
                        || event.header.event_type == 16 && event.header.flags & 1 == 0
                        || event.header.event_type == 46 && event.header.status != 6)
                {
                    self.bssid = None;
                    self.connection = None;
                }
            }
        }
        self.check_connection_policy()?;
        self.runtime.set_link(self.bssid);
        Ok(())
    }
}

#[path = "station_policy.rs"]
mod policy;
pub use policy::{GlobalPolicy, PolicySource};

#[path = "station_mfp.rs"]
mod mfp;
#[path = "station_phy.rs"]
mod phy;
#[path = "station_pmksa.rs"]
pub mod pmksa;
#[path = "station_probe_ies.rs"]
mod probe_ies;
#[path = "station_sae.rs"]
pub mod sae;
#[path = "station_wmm.rs"]
pub mod wmm;

const MAX_REPLY: usize = 1502;

/// The firmware offload builds its own association elements. Match the
/// nl80211 PSK-offload contract: validate the requested RSNE, consume a
/// bounded well-formed IE list, and leave firmware-generated capabilities
/// and RSNXE to the firmware. External-key profiles remain unsupported.
fn validate_association_ies(mut ies: &[u8], akm: u8, mfp: bool) -> Result<(), Error> {
    let secure = akm != 0;
    use narf_wireless::rsn::*;
    if ies.len() > 2048 {
        return Err(Error::Malformed);
    }
    let mut seen_rsn = false;
    while !ies.is_empty() {
        let header = ies.get(..2).ok_or(Error::Malformed)?;
        let end = 2 + usize::from(header[1]);
        let body = ies.get(2..end).ok_or(Error::Malformed)?;
        if header[0] == 48 {
            if !secure || seen_rsn {
                return Err(Error::Unsupported);
            }
            let rsn = RsnIe::decode_body(body).ok_or(Error::Malformed)?;
            let ccmp = Suite::standard(CIPHER_CCMP_128);
            if rsn.group_cipher != ccmp
                || rsn.pairwise_ciphers != [ccmp]
                || rsn.akms != [Suite::standard(akm)]
                || rsn.rsn_capabilities & RSN_CAP_MFP_REQUIRED != 0 && !mfp
                || !rsn.pmkids.is_empty()
                || rsn
                    .group_management_cipher
                    .is_some_and(|cipher| cipher != Suite::standard(CIPHER_BIP_CMAC_128))
            {
                return Err(Error::Unsupported);
            }
            seen_rsn = true;
        } else if matches!(header[0], 45 | 61 | 191 | 192)
            || header[0] == 221 && body.starts_with(&[0, 80, 242, 2])
            || header[0] == 244 && !secure
        {
            return Err(Error::Unsupported);
        }
        ies = &ies[end..];
    }
    Ok(())
}
async fn wait() {
    narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
}
async fn set_int<R: Fullmac>(runtime: &mut R, command: u32, value: u32) -> Result<(), Error> {
    runtime
        .command(Direction::Set, command, &value.to_le_bytes(), MAX_REPLY)
        .await
        .map(|_| ())
}
pub(super) async fn set_var<R: Fullmac>(
    runtime: &mut R,
    name: &str,
    value: &[u8],
) -> Result<(), Error> {
    let mut payload = name.as_bytes().to_vec();
    payload.push(0);
    payload.extend_from_slice(value);
    runtime
        .command(Direction::Set, 263, &payload, MAX_REPLY)
        .await
        .map(|_| ())
}
async fn get_var<R: Fullmac>(runtime: &mut R, name: &str, length: usize) -> Result<Vec<u8>, Error> {
    let mut payload = name.as_bytes().to_vec();
    payload.push(0);
    runtime.command(Direction::Get, 262, &payload, length).await
}
fn le32(bytes: &[u8], index: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(
        bytes
            .get(index..index + 4)
            .ok_or(Error::Malformed)?
            .try_into()
            .unwrap(),
    ))
}
fn channel_power(domain: &narf_wireless::reg::RegulatoryDomain, channel: u8) -> Option<u8> {
    occupied_power(domain, channel::Operating::twenty(channel)?)
}
fn occupied_power(
    domain: &narf_wireless::reg::RegulatoryDomain,
    channel: channel::Operating,
) -> Option<u8> {
    u8::try_from(occupied_ceiling(domain, channel, true)?).ok()
}
fn channel_ceiling(
    domain: &narf_wireless::reg::RegulatoryDomain,
    channel: u8,
    transmit: bool,
) -> Option<i8> {
    occupied_ceiling(domain, channel::Operating::twenty(channel)?, transmit)
}
fn occupied_ceiling(
    domain: &narf_wireless::reg::RegulatoryDomain,
    channel: channel::Operating,
    transmit: bool,
) -> Option<i8> {
    use narf_wireless::reg::RegFlags;
    let (low, high) = channel.span();
    let mut covered = false;
    let mut ceiling: Option<i8> = None;
    for rule in &domain.rules {
        if rule.freq_start_mhz >= high || rule.freq_end_mhz <= low {
            continue;
        }
        if rule.freq_start_mhz >= rule.freq_end_mhz
            || rule.max_bandwidth_mhz < channel.width()
            || transmit && rule.flags.bits() & !RegFlags::NO_P2P.bits() != 0
        {
            return None;
        }
        covered |= rule.freq_start_mhz <= low && rule.freq_end_mhz >= high;
        ceiling = Some(ceiling.map_or(rule.max_power_dbm, |old| old.min(rule.max_power_dbm)));
    }
    covered.then_some(ceiling).flatten()
}
fn rsn(ies: &[u8]) -> Option<narf_wireless::rsn::RsnIe> {
    let mut rest = ies;
    while rest.len() >= 2 {
        let len = usize::from(rest[1]);
        let body = rest.get(2..2 + len)?;
        if rest[0] == 48 {
            return narf_wireless::rsn::RsnIe::decode_body(body);
        }
        rest = &rest[2 + len..];
    }
    None
}

fn scan_command(
    id: u16,
    channels: &[u8],
    ssids: &[Vec<u8>],
    active: bool,
) -> Result<Vec<u8>, Error> {
    if channels.is_empty()
        || channels.len() > 64
        || ssids.len() > 16
        || ssids.iter().any(|s| s.len() > 32)
    {
        return Err(Error::Malformed);
    }
    let ssid_start = (72 + channels.len() * 2).next_multiple_of(4);
    let mut out = vec![0; ssid_start + ssids.len() * 36];
    out[..4].copy_from_slice(&1u32.to_le_bytes());
    out[4..6].copy_from_slice(&1u16.to_le_bytes());
    out[6..8].copy_from_slice(&id.to_le_bytes());
    out[44..50].fill(0xff);
    out[50] = 2; // DOT11_BSSTYPE_ANY.
    out[51] = u8::from(!active);
    out[52..68].fill(0xff); // firmware default dwell/probe values.
    out[68..72]
        .copy_from_slice(&((ssids.len() as u32) << 16 | channels.len() as u32).to_le_bytes());
    for (i, &ch) in channels.iter().enumerate() {
        let chanspec = channel::encode20(ch).ok_or(Error::Malformed)?;
        out[72 + i * 2..74 + i * 2].copy_from_slice(&chanspec.to_le_bytes());
    }
    for (i, ssid) in ssids.iter().enumerate() {
        let index = ssid_start + i * 36;
        out[index..index + 4].copy_from_slice(&(ssid.len() as u32).to_le_bytes());
        out[index + 4..index + 4 + ssid.len()].copy_from_slice(ssid);
    }
    Ok(out)
}

fn parse_scan_result(bytes: &[u8]) -> Result<(u16, Bss), Error> {
    if bytes.len() < 12 + 128
        || le32(bytes, 0)? as usize > bytes.len()
        || u16::from_le_bytes(bytes[10..12].try_into().unwrap()) != 1
    {
        return Err(Error::Malformed);
    }
    let id = u16::from_le_bytes(bytes[8..10].try_into().unwrap());
    let b = &bytes[12..];
    let length = le32(b, 4)? as usize;
    if le32(b, 0)? != 109 || length < 128 || length > b.len() {
        return Err(Error::Malformed);
    }
    let b = &b[..length];
    let ssid_len = usize::from(b[18]);
    let offset = usize::from(u16::from_le_bytes(b[116..118].try_into().unwrap()));
    let ie_len = le32(b, 120)? as usize;
    if ssid_len > 32 || offset < 128 || ie_len > 2048 || b[8] & 1 != 0 || b[8..14] == [0; 6] {
        return Err(Error::Malformed);
    }
    let ies = b
        .get(offset..offset.checked_add(ie_len).ok_or(Error::Malformed)?)
        .ok_or(Error::Malformed)?;
    // Verify every IE before preserving an AP's original bytes.
    let mut rest = ies;
    while !rest.is_empty() {
        let len = usize::from(*rest.get(1).ok_or(Error::Malformed)?);
        rest = rest.get(2 + len..).ok_or(Error::Malformed)?;
    }
    let chanspec = u16::from_le_bytes(b[72..74].try_into().unwrap());
    // Legacy APs can leave ctl_ch zero. Never use a wide center as primary.
    let channel = channel::primary(chanspec, b[88]).ok_or(Error::Unsupported)?;
    let capability = u16::from_le_bytes(b[16..18].try_into().unwrap());
    let security = if rsn(ies).is_some() {
        narf_wireless::scan::BssSecurity::Wpa2
    } else if capability & 16 != 0 {
        narf_wireless::scan::BssSecurity::Wep
    } else {
        narf_wireless::scan::BssSecurity::Open
    };
    Ok((
        id,
        Bss {
            info: BssInfo {
                bssid: b[8..14].try_into().unwrap(),
                ssid: b[19..19 + ssid_len].to_vec(),
                frequency_mhz: channel::frequency(channel).ok_or(Error::Unsupported)?,
                channel: u32::from(channel),
                rssi: i16::from_le_bytes(b[78..80].try_into().unwrap()).clamp(-128, 0) as i8,
                security,
            },
            ies: ies.to_vec(),
        },
    ))
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "station_tests.rs"]
pub(in crate::cyw43439) mod tests;
