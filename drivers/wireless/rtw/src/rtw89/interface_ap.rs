// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852B AP frontend: native terminal-completion AP controls on the one
//! retained owner (`startup_ap.rs`) and the host AP session (`ap_host.rs`).
//!
//! Linux order (mac80211 + rtw89, 7.3-rc4): `rtw89_ops_add_interface`
//! (`rtw89_mac_vif_init`), chanctx assignment (`rtw89_set_channel` +
//! `rtw89_chip_rfk_channel`), `rtw89_ops_start_ap`, beacon via
//! `rtw89_fw_h2c_update_beacon` (`rtw89_ops_bss_info_changed` /
//! `set_tim` -> `update_beacon_work`), `rtw89_ops_sta_state` NOTEXIST->NONE
//! (`rtw89_core_sta_link_add`) and AUTH->ASSOC (`_assoc`), removal on
//! NONE->NOTEXIST, `rtw89_ops_stop_ap`. Keys stay with the host
//! (`rtw89_ops_set_key` is never reached: no security CAM in this profile).
//! A stopped AP closes this generation; the supervisor composes a fresh
//! one (fresh FLR) in the still-selected AP role before the next START_AP.
use super::*;
use crate::rtw89::{
    ap_control::PortConfig,
    ap_crypto::{self, Install},
    ap_host::{self, Inbound, Plan, Registration},
    ap_ps,
    station_control::codec,
};
use core::num::NonZeroU64;
use narf_wireless::ap_control::{ApControlAuthority, ApEmissionAuthority};

/// Bounded wait for a terminal RPQ report of a waited management/control
/// frame (`ieee80211_report_used_skb` arrives from `rtw89_pci_tx_status`).
const REPORT_MS: u64 = 1000;

fn map(error: ap_host::Error) -> WirelessError {
    match error {
        ap_host::Error::Invalid | ap_host::Error::Ps(_) => WirelessError::InvalidArgs,
        ap_host::Error::Unsupported => WirelessError::NotSupported,
        ap_host::Error::Busy => WirelessError::Busy,
        ap_host::Error::Crypto(ap_crypto::Error::Exhausted) => WirelessError::Busy,
        ap_host::Error::Crypto(_) => WirelessError::InvalidArgs,
    }
}
fn native(error: crate::rtw89::power::Error) -> WirelessError {
    match error {
        crate::rtw89::power::Error::Unsupported => WirelessError::NotSupported,
        crate::rtw89::power::Error::Busy => WirelessError::Busy,
        crate::rtw89::power::Error::Timeout => WirelessError::Timeout,
        crate::rtw89::power::Error::Access => WirelessError::Denied,
        _ => WirelessError::HardwareError,
    }
}
fn errno(error: WirelessError) -> i32 {
    match error {
        WirelessError::Denied => 1,
        WirelessError::Busy => 16,
        WirelessError::InvalidArgs => 22,
        WirelessError::NotSupported => 95,
        WirelessError::Timeout => 110,
        WirelessError::HardwareError => 5,
    }
}

impl<I: Io + 'static> Device<I> {
    /// Nonzero AP control generation: the selected AP role of this exact
    /// published, live generation. A new selection or generation never
    /// reuses an older value.
    pub(super) fn ap_generation(&self) -> Option<NonZeroU64> {
        if !self.ap_selected()
            || !self.ap_capable.load(Ordering::Acquire)
            || !self.published.load(Ordering::Acquire)
            || self.retired.load(Ordering::Acquire)
            || self.closed()
            || self.role_changed()
        {
            return None;
        }
        NonZeroU64::new(self.selection.generation)
    }
    fn ap_current(&self, emission: &ApEmissionAuthority) -> Result<(), WirelessError> {
        let generation = self.ap_generation().ok_or(WirelessError::Denied)?;
        if !self.admitted.load(Ordering::Acquire) {
            return Err(WirelessError::Busy);
        }
        if !emission.matches_role(self, 3, generation) {
            return Err(WirelessError::Denied);
        }
        Ok(())
    }
    /// Exact request, its synchronous reservation, UP and this AP role.
    fn ap_authority(
        &self,
        authority: &ApControlAuthority,
    ) -> Result<ApEmissionAuthority, WirelessError> {
        authority.check_for(self)?;
        if !authority.has_reservation() || self.ap_generation().is_none() {
            return Err(WirelessError::Denied);
        }
        let emission = authority.native_emission_for(self)?;
        // Source/registration/admin retirement wakes the AP worker.
        if !emission.watch(&core::task::Waker::from(Arc::new(SleepWake(
            self.line.clone(),
        )))) {
            return Err(WirelessError::Denied);
        }
        self.ap_current(&emission)?;
        Ok(emission)
    }
    fn ap_publish_link(&self, up: bool) {
        let _metadata = self.metadata.lock();
        if self.retired.load(Ordering::Acquire) {
            return;
        }
        let up = up && !self.closed();
        self.port.store(up, Ordering::Release);
        self.up.store(up, Ordering::Release);
        narf_net::iface::set_link_metadata(&self.name, up, None, None);
    }
    /// Republish the beacon (head || current TIM || tail) on the owner.
    async fn ap_beacon(
        &self,
        owner: &mut crate::rtw89::station_lifecycle::Owner<I>,
    ) -> Result<(), WirelessError> {
        let (beacon, tim_at) = self.ap.lock().beacon().map_err(map)?;
        owner
            .io
            .ap_publish_beacon(&beacon, tim_at, &self.admission)
            .await
            .map_err(native)
    }

    pub(super) async fn ap_start(
        &self,
        authority: &ApControlAuthority,
        config: narf_wireless::ApConfig,
        settings: narf_wireless::ApStartSettings,
    ) -> Result<(), WirelessError> {
        let emission = self.ap_authority(authority)?;
        let control = authority.event_authority()?;
        if self.ap.lock().started() {
            return Err(WirelessError::Busy);
        }
        let primary = frequency_primary(config.frequency_mhz).ok_or(WirelessError::InvalidArgs)?;
        if !station::channel_admitted(self.channels.load(Ordering::Acquire), primary) {
            return Err(WirelessError::NotSupported);
        }
        let plan = Plan::new(self.local, &config, &settings, primary).map_err(map)?;
        let port = PortConfig {
            beacon_interval: plan.beacon_interval,
            dtim_period: plan.dtim_period,
        };
        let mut storage = self.lifecycle.retained.lock().await;
        let owner = storage.as_mut().ok_or(WirelessError::HardwareError)?;
        self.ap_current(&emission)?;
        // A refused channel (unsigned, DFS/NO_IR) is proven unpublished.
        owner
            .io
            .ap_channel(primary, &self.admission)
            .await
            .map_err(native)?;
        let mut attempt = Attempt {
            device: self,
            armed: true,
        };
        owner
            .io
            .ap_prepare(self.local, &self.admission)
            .await
            .map_err(native)?;
        owner
            .io
            .ap_start(port, &self.admission)
            .await
            .map_err(native)?;
        {
            let mut host = self.ap.lock();
            host.start(self.local, plan, settings);
            host.control = Some(control);
            host.emission = Some(emission.clone());
        }
        self.ap_beacon(owner).await?;
        drop(storage);
        authority.check_for(self)?;
        authority.require_up()?;
        self.ap_current(&emission)?;
        attempt.armed = false;
        self.ap_publish_link(true);
        self.line.raise();
        Ok(())
    }
    pub(super) async fn ap_stop(
        &self,
        authority: &ApControlAuthority,
    ) -> Result<(), WirelessError> {
        authority.check_for(self)?;
        if self.ap_generation().is_none() {
            return Err(WirelessError::Denied);
        }
        if !self.ap.lock().started() {
            return Err(WirelessError::InvalidArgs);
        }
        self.ap_publish_link(false);
        let result = {
            let mut storage = self.lifecycle.retained.lock().await;
            match storage.as_mut() {
                Some(owner) => owner.io.ap_stop(&self.admission).await.map_err(native),
                None => Err(WirelessError::HardwareError),
            }
        };
        self.ap.lock().stop();
        // The controller is Stopped; only a fresh generation may restart.
        self.close();
        result
    }
    pub(super) async fn ap_set_beacon(
        &self,
        authority: &ApControlAuthority,
        head: Option<Vec<u8>>,
        tail: Option<Vec<u8>>,
    ) -> Result<(), WirelessError> {
        let emission = self.ap_authority(authority)?;
        self.ap.lock().set_beacon(head, tail).map_err(map)?;
        let mut storage = self.lifecycle.retained.lock().await;
        let owner = storage.as_mut().ok_or(WirelessError::HardwareError)?;
        self.ap_current(&emission)?;
        let mut attempt = Attempt {
            device: self,
            armed: true,
        };
        self.ap_beacon(owner).await?;
        attempt.armed = false;
        drop(storage);
        authority.check_for(self)
    }
    /// `rtw89_core_sta_link_assoc`: RA over the peer's legacy rates.
    async fn ap_associate(
        &self,
        owner: &mut crate::rtw89::station_lifecycle::Owner<I>,
        peer: ap_host::Peer,
        aid: u16,
    ) -> Result<(), WirelessError> {
        let rates = if peer.rates == 0 { 1 } else { peer.rates };
        let ra = codec::ra(rates).ok_or(WirelessError::InvalidArgs)?;
        // Host PS state first: a refused AID/WMM combination never reaches
        // firmware; a failed firmware association closes the generation.
        self.ap.lock().associate(peer.addr, aid).map_err(map)?;
        owner
            .io
            .ap_associate_peer(
                peer.addr,
                aid,
                codec::ra_at(peer.macid, ra),
                &self.admission,
            )
            .await
            .map_err(native)
    }
    pub(super) async fn ap_add_station(
        &self,
        authority: &ApControlAuthority,
        config: narf_wireless::StationConfig,
    ) -> Result<(), WirelessError> {
        let emission = self.ap_authority(authority)?;
        self.ap.lock().check_new(&config).map_err(map)?;
        let mut storage = self.lifecycle.retained.lock().await;
        let owner = storage.as_mut().ok_or(WirelessError::HardwareError)?;
        self.ap_current(&emission)?;
        let mut attempt = Attempt {
            device: self,
            armed: true,
        };
        let macid = owner
            .io
            .ap_add_peer(config.mac, &self.admission)
            .await
            .map_err(native)?;
        let peer = self.ap.lock().add_peer(&config, macid).map_err(map)?;
        if config.aid != 0 {
            self.ap_associate(owner, peer, config.aid).await?;
        }
        if config.authorized.is_some() {
            self.ap.lock().update_peer(&config).map_err(map)?;
        }
        attempt.armed = false;
        drop(storage);
        authority.check_for(self)
    }
    pub(super) async fn ap_set_station(
        &self,
        authority: &ApControlAuthority,
        config: narf_wireless::StationConfig,
    ) -> Result<(), WirelessError> {
        let emission = self.ap_authority(authority)?;
        let existing = self
            .ap
            .lock()
            .peer(config.mac)
            .ok_or(WirelessError::InvalidArgs)?;
        let mut storage = self.lifecycle.retained.lock().await;
        let owner = storage.as_mut().ok_or(WirelessError::HardwareError)?;
        self.ap_current(&emission)?;
        let peer = self.ap.lock().update_peer(&config).map_err(map)?;
        if existing.aid == 0 && config.aid != 0 {
            let mut attempt = Attempt {
                device: self,
                armed: true,
            };
            self.ap_associate(owner, peer, config.aid).await?;
            attempt.armed = false;
        }
        drop(storage);
        authority.check_for(self)
    }
    pub(super) async fn ap_del_station(
        &self,
        authority: &ApControlAuthority,
        peer: Option<[u8; 6]>,
    ) -> Result<(), WirelessError> {
        let emission = self.ap_authority(authority)?;
        let targets: Vec<[u8; 6]> = match peer {
            Some(addr) => {
                if self.ap.lock().peer(addr).is_none() {
                    return Err(WirelessError::InvalidArgs);
                }
                vec![addr]
            }
            None => self.ap.lock().peers().iter().map(|p| p.addr).collect(),
        };
        let mut storage = self.lifecycle.retained.lock().await;
        let owner = storage.as_mut().ok_or(WirelessError::HardwareError)?;
        self.ap_current(&emission)?;
        let mut attempt = Attempt {
            device: self,
            armed: true,
        };
        for addr in targets {
            // Host state first: no frame is built for the peer once its
            // packet binding is withdrawn by `ap_remove_peer`.
            self.ap.lock().remove_peer(addr);
            owner
                .io
                .ap_remove_peer(addr, &self.admission)
                .await
                .map_err(native)?;
        }
        if self.ap.lock().beacon_dirty() {
            self.ap_beacon(owner).await?;
        }
        attempt.armed = false;
        drop(storage);
        authority.check_for(self)
    }
    pub(super) async fn ap_add_key(
        &self,
        authority: &ApControlAuthority,
        key: narf_wireless::OwnedKey,
    ) -> Result<(), i32> {
        let emission = self.ap_authority(authority).map_err(errno)?;
        let install = Install::from_params(key.params()).map_err(|_| 22)?;
        self.ap_current(&emission).map_err(errno)?;
        self.ap
            .lock()
            .install_key(&install)
            .map_err(|e| errno(map(e)))?;
        authority.check_for(self).map_err(errno)
    }
    pub(super) async fn ap_del_key(
        &self,
        authority: &ApControlAuthority,
        index: u8,
        pairwise: bool,
        peer: Option<[u8; 6]>,
    ) -> Result<(), i32> {
        let emission = self.ap_authority(authority).map_err(errno)?;
        let target = ap_crypto::target(index, pairwise, peer).map_err(|_| 22)?;
        self.ap_current(&emission).map_err(errno)?;
        self.ap
            .lock()
            .remove_key(target)
            .map_err(|_| 2 /* ENOENT */)?;
        authority.check_for(self).map_err(errno)
    }
    pub(super) async fn ap_default_key(
        &self,
        authority: &ApControlAuthority,
        index: u8,
        unicast: bool,
        multicast: bool,
        management: bool,
        beacon: bool,
    ) -> Result<(), i32> {
        let emission = self.ap_authority(authority).map_err(errno)?;
        // Only the group data key selection exists in this profile; the
        // pairwise key is always index 0 and there is no BIP/BIGTK.
        if management || beacon || index > 3 {
            return Err(95);
        }
        self.ap_current(&emission).map_err(errno)?;
        if multicast {
            self.ap
                .lock()
                .default_group(index)
                .map_err(|e| errno(map(e)))?;
        } else if !unicast {
            return Err(22);
        }
        authority.check_for(self).map_err(errno)
    }
    pub(super) async fn ap_key_sequence(
        &self,
        authority: &ApControlAuthority,
        index: u8,
        pairwise: bool,
        peer: Option<[u8; 6]>,
    ) -> Result<narf_wireless::KeySequence, i32> {
        let emission = self.ap_authority(authority).map_err(errno)?;
        let target = ap_crypto::target(index, pairwise, peer).map_err(|_| 22)?;
        self.ap_current(&emission).map_err(errno)?;
        let seq = self.ap.lock().key_sequence(target).map_err(|_| 2)?;
        authority.check_for(self).map_err(errno)?;
        Ok(narf_wireless::KeySequence {
            cipher: ap_host::CCMP,
            seq,
        })
    }
    /// Submit one finished MPDU now and wait for its terminal report.
    async fn ap_send_waited(
        &self,
        emission: &ApEmissionAuthority,
        mpdu: &[u8],
        wait: bool,
    ) -> Result<bool, WirelessError> {
        let id = {
            let mut storage = self.lifecycle.retained.lock().await;
            let owner = storage.as_mut().ok_or(WirelessError::HardwareError)?;
            self.ap_current(emission)?;
            if !owner.io.ap_packet_ready() {
                return Err(WirelessError::Busy);
            }
            let rate = owner.io.ap_lowest_rate().map_err(native)?;
            let id = owner
                .io
                .packet_submit_ap(mpdu, false, true, rate)
                .map_err(|_| WirelessError::Busy)?;
            self.ap.lock().watch_report(id);
            id
        };
        self.line.raise();
        if !wait {
            return Ok(true);
        }
        let deadline = self.environment.now_ms().saturating_add(REPORT_MS);
        loop {
            if let Some(ack) = self.ap.lock().take_report(id) {
                return Ok(ack);
            }
            if self.closed() || self.environment.now_ms() >= deadline {
                self.ap.lock().forget_report(id);
                return Err(WirelessError::Timeout);
            }
            self.line.raise();
            self.environment.pause().await;
        }
    }
    pub(super) async fn ap_management(
        &self,
        authority: &ApControlAuthority,
        request: narf_wireless::MgmtTxRequest,
    ) -> Result<bool, WirelessError> {
        let emission = self.ap_authority(authority)?;
        let (frequency, ghz5) = {
            let host = self.ap.lock();
            let plan = host.plan().ok_or(WirelessError::Busy)?;
            (plan.frequency, station::ghz5(plan.primary))
        };
        // On-channel only; the 2.4 GHz floor rate is CCK 1 Mb/s.
        if request.frequency_mhz != 0 && request.frequency_mhz != frequency
            || request.no_cck && !ghz5
        {
            return Err(WirelessError::NotSupported);
        }
        let mpdu = self
            .ap
            .lock()
            .management_frame(&request.frame)
            .map_err(map)?;
        // Sweep F3: a bufferable MMPDU to a dozing peer is PS-buffered
        // (TIM set) instead of sent immediately — `ieee80211_tx_h_unicast_ps_buf`.
        // Group and unassociated destinations, awake peers, non-bufferable
        // MMPDUs, and peers the PS table does not track all take the
        // immediate path below. A buffered frame reports not-acked: this
        // synchronous API cannot wait for the peer's wake.
        let mut dest = [0u8; 6];
        dest.copy_from_slice(&mpdu[4..10]);
        let aid = self
            .ap
            .lock()
            .peer(dest)
            .and_then(|peer| (peer.aid != 0).then_some(peer.aid));
        if let Some(aid) = aid {
            match self
                .ap
                .lock()
                .ps_decide(mpdu.clone(), aid, self.environment.now_ms())
            {
                Ok(ap_ps::Transmit::Buffered { .. }) => return Ok(false),
                Ok(ap_ps::Transmit::Send(_)) => {}
                Err(ap_host::Error::Ps(ap_ps::Error::Unknown)) => {}
                Err(error) => return Err(map(error)),
            }
        }
        let ack = self.ap_send_waited(&emission, &mpdu, true).await?;
        authority.check_for(self)?;
        Ok(ack)
    }
    pub(super) async fn ap_control_tx(
        &self,
        authority: &ApControlAuthority,
        request: narf_wireless::ControlPortTxRequest,
    ) -> Result<bool, i32> {
        let emission = self.ap_authority(authority).map_err(errno)?;
        let mpdu = self
            .ap
            .lock()
            .control_frame(
                request.dest,
                request.ethertype,
                request.pdu(),
                request.no_encrypt,
            )
            .map_err(|e| errno(map(e)))?;
        let mpdu = zeroize::Zeroizing::new(mpdu);
        let ack = self
            .ap_send_waited(&emission, &mpdu, request.wait_for_ack)
            .await
            .map_err(errno)?;
        authority.check_for(self).map_err(errno)?;
        Ok(ack)
    }
    pub(super) async fn ap_register_frame(
        &self,
        authority: &ApControlAuthority,
        frame_type: u16,
        prefix: Vec<u8>,
    ) -> Result<(), WirelessError> {
        authority.check_for(self)?;
        if !authority.has_reservation()
            || self.ap_generation().is_none()
            || !matches!(frame_type, 0x00 | 0x20 | 0x40 | 0xa0 | 0xb0 | 0xc0 | 0xd0)
            || prefix.len() > 256
        {
            return Err(WirelessError::NotSupported);
        }
        let event = authority.event_authority()?;
        let mut host = self.ap.lock();
        host.registrations
            .retain(|r| r.event.registration_current().is_ok());
        if host.registrations.len() >= 16 {
            return Err(WirelessError::Busy);
        }
        host.registrations
            .try_reserve(1)
            .map_err(|_| WirelessError::HardwareError)?;
        host.registrations.push(Arc::new(Registration {
            event,
            frame_type,
            prefix,
        }));
        Ok(())
    }

    /// Ordinary stack TX in the AP role: the frame waits in the stack ring
    /// for the AP worker (`ap_drain`), which builds and protects it.
    pub(super) fn ap_enqueue(&self, bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
        if !self.admitted.load(Ordering::Acquire)
            || self.closed()
            || !self.up.load(Ordering::Acquire)
            || !station::admitted(bytes, self.local)
            || !offloads(meta)
            || !self.ap.lock().started()
        {
            return Err(());
        }
        let memory = narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0)
            .map_err(|_| ())?;
        let mut frame = Frame::new(memory, bytes.len() as u32);
        frame.payload_mut().copy_from_slice(bytes);
        frame.set_tx_meta(meta);
        self.tx
            .lock()
            .as_mut()
            .ok_or(())?
            .try_send(frame)
            .map_err(|_| ())?;
        self.line.raise();
        Ok(())
    }
    /// One synchronous AP progress pass under `try_lock` (never waits for
    /// another task): stack TX into the host session, PS releases and
    /// backlog to the native AP queues, RPQ reports, and RX classified by
    /// the hardware MACID. Returns events for delivery after every lock.
    fn ap_progress(&self) -> Option<(Vec<Inbound>, u32)> {
        let mut storage = self.lifecycle.retained.try_lock()?;
        let owner = storage.as_mut()?;
        let mut rings = self.rings.try_lock()?;
        let started = self.ap.lock().started();
        if self.closed() || !self.admitted.load(Ordering::Acquire) || !started {
            rings.clear();
            return None;
        }
        let emission_current = self
            .ap
            .lock()
            .emission
            .as_ref()
            .is_some_and(|emission| emission.current());
        if !emission_current {
            // The START_AP source/registration/admin authority retired.
            rings.clear();
            self.ap.lock().stop();
            self.ap_publish_link(false);
            self.close();
            return None;
        }
        let now = self.environment.now_ms();
        let frequency = self.ap.lock().plan().map_or(0, |plan| plan.frequency);
        let result = (|| -> Result<Vec<Inbound>, crate::rtw89::packet_core::Error> {
            for _ in 0..BACKLOG {
                let Ok(Some(frame)) = rings.tx.try_recv() else {
                    break;
                };
                let _ = self.ap.lock().transmit_ethernet(frame.payload(), now);
            }
            self.ap.lock().expire(now);
            let rate = owner
                .io
                .ap_lowest_rate()
                .map_err(|_| crate::rtw89::packet_core::Error::State)?;
            while owner.io.ap_packet_ready() {
                let next = self.ap.lock().next_outbound().cloned();
                let Some(out) = next else {
                    break;
                };
                match owner.io.packet_submit_ap(
                    &out.mpdu,
                    out.after_dtim,
                    out.release.is_some(),
                    rate,
                ) {
                    Ok(id) => self.ap.lock().consume_outbound(id),
                    Err(crate::rtw89::packet_core::Error::Busy) => break,
                    Err(crate::rtw89::packet_core::Error::Packet) => {
                        // A peer removed meanwhile: drop this one frame.
                        self.ap.lock().drop_outbound();
                    }
                    Err(error) => return Err(error),
                }
            }
            let mut inbound = Vec::new();
            for _ in 0..32 {
                let step = owner.io.packet_poll()?;
                if let Some(receipt) = &step.receipt {
                    self.ap
                        .lock()
                        .report(receipt.id, receipt.radio_acknowledged);
                }
                if let Some(frame) = &step.frame {
                    use narf_wireless::station_security::RawFrame;
                    inbound.extend(self.ap.lock().receive(step.rx_mac_id, frame.bytes(), now));
                }
                if !step.consumed_rx && step.receipt.is_none() && step.c2h.is_none() {
                    break;
                }
            }
            Ok(inbound)
        })();
        match result {
            Ok(inbound) => {
                for event in &inbound {
                    if let Inbound::Ethernet(bytes) = event {
                        if let Ok(memory) =
                            narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0)
                        {
                            let mut frame = Frame::new(memory, bytes.len() as u32);
                            frame.payload_mut().copy_from_slice(bytes);
                            let _ = rings.rx.try_send(frame);
                        }
                    }
                }
                Some((inbound, frequency))
            }
            Err(_) => {
                rings.clear();
                self.ap.lock().stop();
                self.ap_publish_link(false);
                self.close();
                None
            }
        }
    }
    pub(super) fn ap_drain(&self) -> bool {
        let Some((inbound, frequency)) = self.ap_progress() else {
            return false;
        };
        let progressed = !inbound.is_empty();
        let (registrations, control) = {
            let host = self.ap.lock();
            (host.registrations.clone(), host.control.clone())
        };
        // Every native/ring/session guard is gone before callbacks.
        for event in inbound {
            let Some(_delivery) = self.begin_delivery() else {
                break;
            };
            match event {
                Inbound::Ethernet(mut bytes) => {
                    narf_net::iface::on_rx_frame_from(&self.name, &mut bytes);
                }
                Inbound::Management(frame) => {
                    let fc = u16::from_le_bytes([frame[0], frame[1]]) & 0xfc;
                    for registration in &registrations {
                        if fc != registration.frame_type
                            || !frame[24..].starts_with(&registration.prefix)
                        {
                            continue;
                        }
                        if let Ok(prepared) = registration
                            .event
                            .prepare_management_received(frequency, None, &frame)
                        {
                            if !self.closed() && self.ap.lock().started() {
                                let _ = prepared.deliver();
                            }
                        }
                    }
                }
                Inbound::Control {
                    peer,
                    ethertype,
                    pdu,
                    unencrypted,
                } => {
                    if let Some(control) = &control {
                        if let Ok(prepared) =
                            control.prepare_control_received(peer, ethertype, &pdu, unencrypted)
                        {
                            if !self.closed() && self.ap.lock().peer(peer).is_some() {
                                let _ = prepared.deliver();
                            }
                        }
                    }
                }
            }
        }
        progressed
    }
    /// AP worker period: progress, then refresh the firmware beacon when
    /// the TIM changed (`rtw89_ops_set_tim` -> `update_beacon_work`).
    pub(super) async fn ap_service(&self) {
        self.ap_drain();
        if !self.ap.lock().beacon_dirty() || self.closed() {
            return;
        }
        let mut storage = self.lifecycle.retained.lock().await;
        let Some(owner) = storage.as_mut() else {
            return;
        };
        if self.closed() || !self.ap.lock().beacon_dirty() {
            return;
        }
        if self.ap_beacon(owner).await.is_err() {
            drop(storage);
            self.ap.lock().stop();
            self.ap_publish_link(false);
            self.close();
        }
    }
}
