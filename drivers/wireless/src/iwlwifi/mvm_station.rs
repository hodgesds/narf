//! Composed legacy station lifecycle for the native API77 interface.
use super::{Owner, Phase};
use crate::firmware_asset::Asset;
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::AtomicBool;
use narf_wireless::{
    association::{Bss, SecurityMode},
    reg::RegulatoryDomain,
};
use zeroize::Zeroizing;

/// Station credential of one native join.
pub(in crate::iwlwifi) enum Credential {
    Open,
    /// WPA2-PSK PMK for the native four-way owner.
    Psk(Zeroizing<[u8; 32]>),
    /// WPA3-Personal password for host SAE (sae_pwe 2) plus PMF.
    Sae(Zeroizing<Vec<u8>>),
}
impl Credential {
    pub(in crate::iwlwifi) fn mode(&self) -> SecurityMode {
        match self {
            Credential::Open => SecurityMode::Open,
            Credential::Psk(_) => SecurityMode::Wpa2Psk,
            Credential::Sae(_) => SecurityMode::Wpa3Sae {
                pwe: narf_wireless::association::SaePwe::Both,
            },
        }
    }
}

impl Owner {
    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::iwlwifi) fn model_expire_receive_aggregate(&mut self) {
        let now = narf_time::now_cycles().wrapping_add(narf_time::wall::ns_to_cycles(200_000_000));
        if let Some(d) = self
            .power
            .prepared
            .as_mut()
            .and_then(|p| p.mlme.data.as_mut())
        {
            d.aggregate.pop(now);
        }
    }
    pub(in crate::iwlwifi) fn station_wpa2_supported(&self) -> bool {
        self.security_api().is_ok()
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::iwlwifi) fn model_expire_peer(&mut self) {
        self.power
            .prepared
            .as_mut()
            .unwrap()
            .mlme
            .data
            .as_mut()
            .unwrap()
            .last_peer =
            narf_time::now_cycles().wrapping_sub(narf_time::wall::ns_to_cycles(10_000_000_001));
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::iwlwifi) fn model_after_alive(
        hardware: super::super::runtime::Hardware,
        firmware: &[u8],
    ) -> alloc::boxed::Box<Self> {
        // Precondition shared with mvm_boot_tests: firmware ALIVE/unified init
        // has completed. NVM/defaults below still use actual native commands.
        let parsed = super::super::parse_ucode(firmware).unwrap();
        alloc::boxed::Box::new(Self {
            hardware,
            firmware: firmware.to_vec(),
            profile: super::super::gen2_profile::select(0xa0f0, 0x351, 0x10c000).unwrap(),
            phase: Phase::Starting,
            mac: None,
            nvm: None,
            beacons: Vec::new(),
            scan: super::scan::ScanContext::new(&parsed.api),
            channel: super::channel::ChannelContext::new(&parsed.api),
            peer: None,
            management_queue: None,
            power: super::power::Context::new(&parsed.api),
            security: super::rsna::Context::new(&parsed.api),
        })
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::iwlwifi) async fn model_configure(&mut self) -> Result<(), &'static str> {
        self.configure([2; 6]).await
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::iwlwifi) fn model_retained(&self) -> (usize, usize, usize) {
        super::super::runtime::model::retained(&self.hardware)
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::iwlwifi) unsafe fn model_destroy(self: alloc::boxed::Box<Self>) {
        // SAFETY: only the private model calls this after dropping control work.
        unsafe { super::super::runtime::model::destroy(self.hardware) };
    }
    pub(in crate::iwlwifi) fn bind_station_stop(&mut self, stop: Arc<AtomicBool>) {
        self.hardware.bind_station_stop(stop);
    }
    pub(in crate::iwlwifi) fn station_source(
        &self,
        firmware: narf_capabilities::Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>,
        master: bool,
    ) -> super::super::mvm_publication::Source {
        super::super::mvm_publication::Source {
            firmware,
            pci: self.hardware.authority(master),
        }
    }
    pub(in crate::iwlwifi) fn station_fail(&mut self) {
        self.power.phy.ba.clear_packets();
        self.hardware.fail();
        self.phase = Phase::Failed;
    }
    /// Firmware/transport restart of a failed owner, following Linux
    /// `mvm/ops.c::iwl_mvm_nic_restart` -> `iwl_mvm_restart_cleanup` ->
    /// `ieee80211_restart_hw` -> `iwl_mvm_up`: stop the device (DMA stop
    /// acknowledged, bus mastering cleared, every queue/command allocation
    /// replaced), reload the retained executable, rerun unified NVM and the
    /// awake-runtime defaults, then rebuild station state from scratch.
    ///
    /// Unlike mac80211's in-place reconfiguration, no association is
    /// replayed: firmware objects of the stopped instance (MAC, link, peer,
    /// queues, keys, BA sessions, PHY context) are discarded and the host
    /// station starts from `Configured`, so a new scan/join and RSNA must
    /// follow. Committed key PN floors survive in the retained history. The
    /// restarted device must report the same MAC address and NVM
    /// channels/chains/PHY; any change or failure leaves the owner failed.
    pub(in crate::iwlwifi) async fn recover(&mut self) -> Result<(), &'static str> {
        if !self.station_failed() {
            return Err("MVM recovery requires a failed owner");
        }
        let mac = self.mac.ok_or("MVM recovery before first configuration")?;
        // The pre-failure identity stays the reference for every attempt; a
        // rejected restart never replaces it with what it reported.
        let original = self.nvm.take().ok_or("MVM recovery before NVM")?;
        self.power.phy.ba.clear_packets();
        let result = self.recover_inner(mac, &original).await;
        if result.is_err() {
            self.hardware.fail();
            self.phase = Phase::Failed;
            self.mac = Some(mac);
            self.nvm = Some(original);
        }
        result
    }

    async fn recover_inner(
        &mut self,
        mac: [u8; 6],
        original: &super::super::station_api::Nvm,
    ) -> Result<(), &'static str> {
        self.restart_hardware(mac).await?;
        // DMA stop is acknowledged: retire installed keys into PN history.
        self.retire_security_after_reset()?;
        let parsed = super::super::parse_ucode(&self.firmware)
            .map_err(|_| "invalid retained MVM firmware")?;
        // Every per-association owner named firmware objects or DMA of the
        // stopped instance; the restart already released that DMA.
        self.beacons.clear();
        self.scan = super::scan::ScanContext::new(&parsed.api);
        self.channel = super::channel::ChannelContext::new(&parsed.api);
        self.peer = None;
        self.management_queue = None;
        self.power = super::power::Context::new(&parsed.api);
        self.mac = None;
        self.nvm = None;
        self.phase = Phase::Starting;
        self.configure(mac).await?;
        let nvm = self.nvm.as_ref().ok_or("MVM recovery lost NVM")?;
        if nvm.channels != original.channels
            || nvm.tx_chains != original.tx_chains
            || nvm.rx_chains != original.rx_chains
            || nvm.phy != original.phy
        {
            return Err("MVM recovery changed NVM identity");
        }
        Ok(())
    }

    /// System-suspend stop of an owner without a station (Linux
    /// `iwl_mvm_suspend` without WoWLAN: mac80211 has already quiesced and
    /// disconnected the interface, then `iwl_mvm_mac_stop` ->
    /// `iwl_mvm_stop_device` -> `iwl_trans_stop_device`). The owner is left
    /// failed; [`Self::recover`] performs the resume-time `iwl_mvm_up`.
    pub(in crate::iwlwifi) async fn suspend_transport(&mut self) -> Result<(), &'static str> {
        if self.phase != Phase::Configured && !self.station_failed() {
            return Err("MVM suspend with an active station owner");
        }
        self.power.phy.ba.clear_packets();
        self.phase = Phase::Failed;
        #[cfg(any(test, feature = "kernel-test"))]
        let model = super::super::runtime::model::is_model(&self.hardware);
        #[cfg(not(any(test, feature = "kernel-test")))]
        let model = false;
        if model {
            self.hardware.fail();
        } else {
            self.hardware.stop_for_suspend().await?;
        }
        // DMA stop is acknowledged: no installed key can be used again.
        self.retire_security_after_reset()
    }

    async fn restart_hardware(&mut self, mac: [u8; 6]) -> Result<(), &'static str> {
        #[cfg(any(test, feature = "kernel-test"))]
        if super::super::runtime::model::is_model(&self.hardware) {
            return super::super::runtime::model::restart(&mut self.hardware);
        }
        let parsed = super::super::parse_ucode(&self.firmware)
            .map_err(|_| "invalid retained MVM firmware")?;
        if self.hardware.restart(&parsed).await? != mac {
            return Err("MVM recovery changed hardware MAC");
        }
        Ok(())
    }

    pub(in crate::iwlwifi) fn station_failed(&self) -> bool {
        self.hardware.is_failed() || self.phase == Phase::Failed
    }
    pub(in crate::iwlwifi) fn station_irq(&self) -> Option<u8> {
        self.hardware.irq_vector()
    }
    pub(in crate::iwlwifi) fn station_poll_idle(&mut self) -> Result<(), &'static str> {
        self.hardware.poll()?;
        self.hardware.notifications.clear();
        Ok(())
    }
    pub(in crate::iwlwifi) fn station_expired(&self) -> bool {
        self.power
            .prepared
            .as_ref()
            .and_then(|p| p.mlme.data.as_ref())
            .is_some_and(|d| {
                narf_time::now_cycles().wrapping_sub(d.last_peer)
                    > narf_time::wall::ns_to_cycles(10_000_000_000)
            })
    }
    pub(in crate::iwlwifi) fn station_information(&self, bssid: [u8; 6]) -> Option<Vec<u8>> {
        self.scan_information_elements(bssid).map(<[u8]>::to_vec)
    }
    pub(in crate::iwlwifi) fn station_power_fence(
        &mut self,
        domain: &RegulatoryDomain,
    ) -> Result<super::PowerFence, &'static str> {
        if !self.data_port_using(|| Ok(domain.clone())) {
            return Err("MVM controlled port not ready");
        }
        self.check_link_power(domain)?;
        self.power
            .prepared
            .as_ref()
            .ok_or("MVM power owner absent")?
            .fence()
    }
    pub(in crate::iwlwifi) fn station_needs_security(&self) -> bool {
        self.security.needs_service()
            || !self.power.phy.actions.is_empty()
            || self.power.phy.ba.needs_work()
    }
    pub(in crate::iwlwifi) fn station_defer_packet(&mut self, frame: Vec<u8>) {
        self.power
            .prepared
            .as_mut()
            .unwrap()
            .mlme
            .data
            .as_mut()
            .unwrap()
            .aggregate
            .defer_validated(frame);
    }
    pub(in crate::iwlwifi) async fn station_scan(
        &mut self,
        channels: &[u8],
        domain: &RegulatoryDomain,
    ) -> Result<Vec<narf_wireless::BssInfo>, &'static str> {
        self.passive_scan_in_domain(channels, domain).await
    }
    pub(in crate::iwlwifi) fn station_receive(
        &mut self,
        policy: impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<Option<super::LegacyReceive>, &'static str> {
        self.receive_data_using(policy)
    }
    pub(in crate::iwlwifi) async fn station_send(
        &mut self,
        bytes: &[u8],
        assist: u32,
        policy: impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<(), &'static str> {
        self.transmit_data_assisted(bytes, assist, policy).await
    }
    pub(in crate::iwlwifi) fn station_can_pipeline(&self) -> bool {
        self.ba_qualified()
    }
    pub(in crate::iwlwifi) async fn station_security(
        &mut self,
        nonce: impl FnMut() -> Result<[u8; 32], &'static str>,
        policy: impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<(), &'static str> {
        let mut policy = policy;
        self.service_ba(&mut policy).await?;
        self.service_phy_actions(&mut policy).await?;
        if let Some(frame) = self.receive_data_inner(&mut policy)? {
            match frame {
                super::LegacyReceive::Ethernet(frame) | super::LegacyReceive::Checked(frame, _) => {
                    self.power
                        .prepared
                        .as_mut()
                        .unwrap()
                        .mlme
                        .data
                        .as_mut()
                        .unwrap()
                        .aggregate
                        .defer_validated(frame)
                }
                super::LegacyReceive::Eapol(_) => {
                    return self.data_failed("MVM control lost native RSNA owner")
                }
            }
        }
        if self.security.needs_service() {
            self.service_security_using(nonce, &mut policy).await
        } else {
            Ok(())
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::iwlwifi) async fn station_join(
        &mut self,
        bssid: [u8; 6],
        ssid: &[u8],
        channel: u8,
        elements: &[u8],
        credential: Credential,
        source: Asset,
        binding: [u8; 32],
        stop: Arc<AtomicBool>,
        mut policy: impl FnMut() -> Result<RegulatoryDomain, &'static str>,
        mut nonce: impl FnMut() -> Result<[u8; 32], &'static str>,
    ) -> Result<(), &'static str> {
        if self.phase != Phase::Configured {
            return Err("MVM station requires configured scan owner");
        }
        let mode = credential.mode();
        let beacon = self
            .beacons
            .iter()
            .find(|b| b.bssid == bssid && b.channel == channel && b.ssid == ssid)
            .ok_or("MVM station BSS not observed")?;
        let bss = Bss {
            bssid,
            ssid: beacon.ssid.clone(),
            channel,
            signal_dbm: None,
            capability: beacon.capabilities,
            beacon_interval: beacon.interval,
            information_elements: beacon.information_elements.clone(),
        };
        self.station_plan(&bss, ssid, mode, elements, self.power.phy.offered.is_some())?;
        // Decode and bind the exact signed input BEFORE the first PHY/queue
        // publication. No missing/malformed board asset consumes a lifecycle.
        let probe = Asset {
            bytes: source.bytes.clone(),
            cap: source.cap,
            signer: source.signer,
            digest: source.digest,
        };
        super::power::parse_for(
            probe,
            binding,
            self.mac.unwrap(),
            channel,
            self.power.phy.emission(),
        )?
        .with_span(self.power.phy.span())
        .host_ceiling(&policy()?)?;
        self.prepare_channel_in_domain(channel, &policy()?).await?;
        self.prepare_peer_in_domain(bssid, &policy()?).await?;
        self.prepare_management_queue().await?;
        self.prepare_power_using(source, binding, &mut policy)
            .await?;
        self.power.prepared.as_mut().unwrap().stop = Some(stop);
        self.activate_link_using(&mut policy).await?;
        let authenticated = match &credential {
            Credential::Sae(password) => {
                let ssid_owned = ssid.to_vec();
                self.authenticate_sae_using(
                    ssid,
                    elements,
                    narf_wireless::association::SaePwe::Both,
                    |join, own, peer| {
                        super::pmf::fresh_session(join, &ssid_owned, password, own, peer)
                    },
                    &mut policy,
                )
                .await?
            }
            _ => self.authenticate_open_using(&mut policy).await?,
        };
        if authenticated.status != 0 {
            return Err("MVM AP refused authentication");
        }
        self.associate_elements_using(ssid, mode, elements, &mut policy)
            .await?;
        self.prepare_data_using(&mut policy).await?;
        match credential {
            Credential::Psk(pmk) => self.secure_using(*pmk, &mut nonce, &mut policy).await?,
            Credential::Sae(_) => self.secure_sae_using(&mut nonce, &mut policy).await?,
            Credential::Open => {}
        }
        if !self.data_port_using(&mut policy) {
            return Err("MVM station native controlled port not completed");
        }
        Ok(())
    }

    /// Every transition consumes the preceding native terminal receipt. A
    /// partially pending/failed owner is quarantined, never reconstructed.
    /// A completed association first tells its AP (§3.25 over-air
    /// deauthentication) when current emission authority still exists.
    pub(in crate::iwlwifi) async fn station_close(
        &mut self,
        mut policy: impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<(), &'static str> {
        if self.phase == Phase::DataPrepared {
            self.deauthenticate_using(super::assoc::DEAUTH_LEAVING, &mut policy)
                .await?;
            self.release_legacy_data().await?;
        }
        if self.phase == Phase::Associated {
            self.clear_association().await?;
        }
        if self.phase == Phase::LinkActive {
            self.deactivate_link().await?;
        }
        if self.phase == Phase::TransmitPowerPrepared {
            self.release_transmit_power()?;
        }
        if self.phase == Phase::ManagementQueuePrepared {
            self.release_management_queue().await?;
        }
        if self.phase == Phase::PeerPrepared {
            self.release_ap_peer().await?;
        }
        if self.phase == Phase::ChannelPrepared {
            self.release_inactive_channel().await?;
        }
        if self.phase != Phase::Configured {
            return Err("MVM station close has uncertain native owner");
        }
        Ok(())
    }
}
