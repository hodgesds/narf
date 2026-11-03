// SPDX-License-Identifier: GPL-2.0-or-later
//! Retained native AP transitions. Source/policy permission is rechecked on
//! every suspension; cancellation leaves this same vdev/peer/DMA owner closed.
use super::{
    ap::{self, Session, Token, Vdev},
    ap_wire, htt, wire, Error, Hif, HostMemory, HttMemory, Radio,
};
use alloc::{boxed::Box, vec::Vec};
use narf_wireless::{ap_control::ApEmissionAuthority, ApConfig, ApStartSettings};

impl<T: Hif + HostMemory + HttMemory> Radio<T> {
    pub(in crate::ath10k) fn ap_supported(&self) -> bool {
        self.wire.dialect == super::Dialect::Tlv
            && self.htt.wmi.htc.transport.nonblocking_wmi()
            && self.htt.ap_protocol()
            && self.htt.wmi.raw_mode()
            && self.htt.wmi.caps.as_ref().is_some_and(|caps| {
                caps.service(self.wire.dialect, 0) && caps.service(self.wire.dialect, 92)
            })
            && self
                .htt
                .wmi
                .ap_resources()
                .is_some_and(|(vdevs, peers)| vdevs >= 1 && peers >= 9)
            && super::management::path(
                self.wire.dialect,
                self.features,
                self.htt.wmi.caps.as_ref().unwrap(),
            )
            .is_ok_and(|path| !matches!(path, super::management::Path::Inline(_)))
    }
    pub(in crate::ath10k) fn ap_uapsd(&self) -> bool {
        self.ap_supported()
            && self
                .htt
                .wmi
                .caps
                .as_ref()
                .is_some_and(|caps| caps.service(self.wire.dialect, 6))
    }
    pub(in crate::ath10k) fn ap_policy(&self) -> Option<ap::Policy> {
        self.ap.as_ref().map(|ap| ap.policy.clone())
    }
    pub(in crate::ath10k) fn ap_abandoned(&self) -> bool {
        self.ap.as_ref().is_some_and(|ap| {
            ap.busy
                || ap.current(ap.policy.domain()).is_err()
                || ap
                    .pending
                    .iter()
                    .any(|pending| pending.control && pending.status.is_none())
        })
    }
    pub(in crate::ath10k) fn ap_data_capture(&self) -> Result<ap::Capture, Error> {
        self.ap.as_ref().ok_or(Error::Failed)?.capture(true, true)
    }
    pub(in crate::ath10k) fn ap_capture(&self) -> Result<ap::Capture, Error> {
        self.ap.as_ref().ok_or(Error::Failed)?.capture(true, true)
    }
    pub(in crate::ath10k) fn ap_clients(&self) -> Result<Vec<[u8; 6]>, Error> {
        let ap = self.ap.as_ref().ok_or(Error::Failed)?;
        ap.current(ap.policy.domain())?;
        let mut macs = Vec::new();
        macs.try_reserve_exact(ap.peers.len())
            .map_err(|_| Error::NoMemory)?;
        macs.extend(
            ap.peers
                .iter()
                .filter(|peer| peer.associated && peer.record.mapped())
                .map(|peer| peer.record.mac),
        );
        Ok(macs)
    }
    pub(in crate::ath10k) fn ap_exists(&self) -> bool {
        self.ap.is_some()
    }
    pub(in crate::ath10k) fn ap_running(&self) -> bool {
        self.ap
            .as_ref()
            .is_some_and(|ap| !ap.failed && !ap.busy && ap.vdev == Vdev::Up && ap.own.mapped())
    }
    pub(in crate::ath10k) fn ap_current(
        &self,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<(), Error> {
        self.ap.as_ref().ok_or(Error::Failed)?.current(domain)
    }
    fn ap_next_echo(&mut self) -> Result<u32, Error> {
        self.ap_sequence = self
            .ap_sequence
            .checked_add(1)
            .filter(|n| *n != u32::MAX)
            .ok_or(Error::Exhausted)?;
        let value = self.ap_sequence;
        self.ap.as_mut().ok_or(Error::Failed)?.echo = value;
        Ok(value)
    }
    pub(super) async fn ap_command(
        &mut self,
        bytes: &[u8],
        validate: &impl Fn() -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.send_scan_command(bytes, validate).await
    }
    /// Consume only the one physical runtime's genuine received events. Every
    /// native copied packet retains its original AP/copy/DATA/source epochs.
    pub(super) fn ap_event(&mut self, event: htt::Event) -> Result<bool, Error> {
        if let htt::Event::Wmi(bytes) = &event {
            if let Some(reports) = self
                .ap
                .as_mut()
                .ok_or(Error::Failed)?
                .management_completions(bytes)?
            {
                let mut ids = Vec::new();
                ids.try_reserve_exact(reports.len())
                    .map_err(|_| Error::NoMemory)?;
                ids.extend(reports.iter().map(|report| report.id));
                self.htt.wmi.htc.transport.complete_wmi_management(&ids)?;
                return Ok(false);
            }
            let id = wire::word(bytes, 0)? & 0xffffff;
            if id == self.wire.management_event {
                let native = self.wire.management(&bytes[4..], self.features)?;
                self.ap.as_mut().ok_or(Error::Failed)?.management(native)?;
            } else if id == 0x5001
                && self
                    .ap
                    .as_ref()
                    .is_some_and(|ap| ap.vdev == Vdev::StartSent)
            {
                if self.wire.start_response(&bytes[4..])? == Some(()) {
                    self.ap.as_mut().unwrap().vdev = Vdev::Started;
                }
            } else {
                self.ap.as_mut().ok_or(Error::Failed)?.wmi_event(bytes)?;
            }
        }
        match event {
            htt::Event::Idle => return Ok(true),
            htt::Event::Message(bytes) => {
                self.ap.as_mut().ok_or(Error::Failed)?.peer_event(&bytes)?
            }
            htt::Event::Rx(batch) => {
                for (status, frame) in batch.frames {
                    self.ap
                        .as_mut()
                        .ok_or(Error::Failed)?
                        .receive(status, batch.peer, batch.tid, frame)?;
                }
            }
            htt::Event::InOrder(indication, frames) => {
                // TLV RX_IN_ORD supplies the same complete RAW descriptor
                // plus an exact owned DMA pointer/peer/vdev/TID receipt.
                // Decapped offload/fragment forms supply no AP RAW authority.
                if !indication.offload
                    && !indication.fragment
                    && u32::from(indication.vdev) == self.primary_vdev()
                {
                    for frame in frames {
                        self.ap.as_mut().ok_or(Error::Failed)?.receive(
                            1,
                            indication.peer,
                            indication.tid,
                            frame,
                        )?;
                    }
                }
            }
            _ => {}
        }
        let (session, htt) = (&mut self.ap, &mut self.htt);
        session
            .as_mut()
            .ok_or(Error::Failed)?
            .htt_completions(htt)?;
        Ok(false)
    }
    pub(super) async fn ap_wait(
        &mut self,
        matched: impl Fn(&Session) -> bool,
        validate: &impl Fn() -> Result<(), Error>,
    ) -> Result<(), Error> {
        let deadline = narf_time::Deadline::after_ms(3000);
        for _ in 0..8192 {
            validate()?;
            if matched(self.ap.as_ref().ok_or(Error::Failed)?) {
                return Ok(());
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            let event = super::checked_policy(
                async { self.htt.poll().await.map_err(Error::from) },
                validate,
            )
            .await?;
            self.ap_event(event)?;
            narf_scheduler::yield_now().await;
        }
        Err(Error::Exhausted)
    }
    pub(super) async fn ap_prefix(
        &mut self,
        validate: &impl Fn() -> Result<(), Error>,
    ) -> Result<(), Error> {
        let deadline = narf_time::Deadline::after_ms(3000);
        for _ in 0..8192 {
            validate()?;
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            let event = super::checked_policy(
                async { self.htt.poll().await.map_err(Error::from) },
                validate,
            )
            .await?;
            let deferred = self.htt.take_idle_deferred();
            if self.ap_event(event)? && !deferred {
                return Ok(());
            }
            narf_scheduler::yield_now().await;
        }
        Err(Error::Exhausted)
    }
    pub(super) async fn ap_barrier(
        &mut self,
        validate: &impl Fn() -> Result<(), Error>,
    ) -> Result<(), Error> {
        let value = self.ap_next_echo()?;
        self.ap_command(&ap_wire::echo(value)?, validate).await?;
        self.ap_wait(|ap| ap.echo_seen == value, validate).await
    }
    /// Open response windows only after the synchronous real CE handoff.
    /// Native input consumed during credit/source waits stays in the OLD
    /// phase; it cannot satisfy a command that has not been published.
    pub(super) async fn ap_publish(
        &mut self,
        command: &[u8],
        publication: ap::Publication,
        validate: &impl Fn() -> Result<(), Error>,
    ) -> Result<(), Error> {
        let deadline = narf_time::Deadline::after_ms(3000);
        for _ in 0..8192 {
            self.ap_prefix(validate).await?;
            validate()?;
            if self
                .htt
                .wmi
                .htc
                .try_begin_wmi_retained(command)
                .map_err(htt::Error::from)?
            {
                let ap = self.ap.as_mut().ok_or(Error::Failed)?;
                match publication {
                    ap::Publication::Vdev(phase) => {
                        ap.vdev = phase;
                        if phase == Vdev::DeleteSent {
                            ap.vdev_deleted = false;
                        }
                        if phase == Vdev::StopSent {
                            ap.native_stopped = false;
                        }
                        if phase == Vdev::Up {
                            ap.beacon_ok = false;
                        }
                    }
                    ap::Publication::CreatePeer(mac) | ap::Publication::DeletePeer(mac) => {
                        let record = if mac == ap.own.mac {
                            &mut ap.own
                        } else {
                            &mut ap
                                .peers
                                .iter_mut()
                                .find(|peer| peer.record.mac == mac)
                                .ok_or(Error::Failed)?
                                .record
                        };
                        if matches!(publication, ap::Publication::CreatePeer(_)) {
                            record.expected = true;
                        } else {
                            record.delete_ack = false;
                            record.deleting = true;
                        }
                    }
                }
                super::checked_policy(
                    async {
                        self.htt
                            .wmi
                            .htc
                            .wait_wmi_source()
                            .await
                            .map_err(htt::Error::from)
                            .map_err(Error::from)
                    },
                    validate,
                )
                .await?;
                return Ok(());
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            narf_scheduler::yield_now().await;
        }
        Err(Error::Exhausted)
    }
    pub(super) async fn ap_create_peer(
        &mut self,
        mac: [u8; 6],
        validate: &impl Fn() -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.ap_publish(
            &self.wire.offchannel_peer(mac)?,
            ap::Publication::CreatePeer(mac),
            validate,
        )
        .await
    }
    pub(super) async fn ap_remove_peer(
        &mut self,
        mac: [u8; 6],
        validate: &impl Fn() -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.ap_publish(
            &self.wire.delete_offchannel_peer(mac)?,
            ap::Publication::DeletePeer(mac),
            validate,
        )
        .await
    }
    pub(super) async fn ap_quiet(
        &mut self,
        validate: &impl Fn() -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.ap_wait(
            |ap| ap.pending.iter().all(|packet| packet.status.is_some()),
            validate,
        )
        .await?;
        if self.htt.wmi.htc.transport.pending_htt_tx()? != 0 {
            return Err(Error::Failed);
        }
        self.ap_prefix(validate).await
    }
    pub(in crate::ath10k) async fn ap_start(
        &mut self,
        config: ApConfig,
        settings: ApStartSettings,
        emission: ApEmissionAuthority,
        policy: ap::Policy,
        validate: &impl Fn() -> Result<(), Error>,
    ) -> Result<(), Error> {
        validate()?;
        let domain = policy.domain();
        if !policy.current()
            || !self.ap_supported()
            || self.failed
            || self.ap.is_some()
            || self.peer.is_some()
            || self.data.is_some()
            || self.roc.is_some()
            || self.scan_pending.is_some()
            || !emission.current()
        {
            return Err(Error::Unsupported);
        }
        let own = self.ready.ok_or(Error::Failed)?.mac;
        let plan = ap_wire::Plan::new(config, settings, own, self.ap_uapsd())?;
        if self.ap_staging.as_ref().is_some_and(|staging| {
            !staging.current() || !plan.config.privacy && !staging.keys.is_empty()
        }) {
            self.ap_staging = None;
            return Err(Error::Unsupported);
        }

        let beacon = ap_wire::beacon(&plan)?;
        let probe = ap_wire::probe(&plan)?;
        if beacon.len().max(probe.len()) > self.htt.wmi.htc.wmi_max_payload() {
            return Err(Error::Unsupported);
        }
        let permission =
            self.hinted_permission(domain, plan.config.frequency_mhz as u16, None, false)?;
        self.htt.wmi.htc.transport.runtime_idle(false);
        if self.ap_history.is_none() {
            self.ap_history = Some(alloc::sync::Arc::new(narf_lib::sync::IrqSafeSpinLock::new(
                super::ap_key::History::default(),
            )));
        }
        self.ap = Some(Box::new(Session::new(
            policy.clone(),
            plan,
            permission.clone(),
            emission.clone(),
            own,
        )));
        // The immutable local proof closes every native await, without a
        // callback to an AP socket or interface while Radio is borrowed.
        let current = || {
            validate()?;
            if !policy.current() || !emission.current() {
                return Err(Error::Failed);
            }
            permission.check(domain)
        };
        self.ap_prefix(&current).await?;
        self.ap_publish(
            &ap_wire::delete(self.primary)?,
            ap::Publication::Vdev(Vdev::DeleteSent),
            &current,
        )
        .await?;
        self.ap_wait(|ap| ap.vdev_deleted, &current).await?;
        self.ap.as_mut().unwrap().vdev = Vdev::Absent;
        self.ap_prefix(&current).await?;
        self.ap.as_mut().unwrap().vdev = Vdev::CreateSent;
        // The AP replaces the station discovery role on the same id.
        self.primary = super::p2p::Vdev::new(self.primary.id(), super::p2p::Role::Ap);
        self.ap_command(&ap_wire::create(self.primary, own)?, &current)
            .await?;
        self.ap_barrier(&current).await?;
        self.ap.as_mut().unwrap().vdev = Vdev::Created;
        self.ap_create_peer(own, &current).await?;
        self.ap_wait(|ap| ap.own.mapped(), &current).await?;
        let own_epoch = self.ap.as_ref().unwrap().own.epoch.clone();
        let own_generation = own_epoch.load(core::sync::atomic::Ordering::Acquire);
        let initial = current;
        let current = || {
            initial()?;
            if own_generation == u64::MAX
                || own_epoch.load(core::sync::atomic::Ordering::Acquire) != own_generation
            {
                return Err(Error::Failed);
            }
            Ok(())
        };

        self.ap_command(&self.wire.domain(&permission)?, &current)
            .await?;
        self.ap_command(&self.wire.power(&permission)?, &current)
            .await?;
        for command in ap_wire::parameters(&self.ap.as_ref().unwrap().plan)? {
            self.ap_command(&command, &current).await?;
        }

        let plan = &self.ap.as_ref().unwrap().plan;
        let contention = plan
            .wmm
            .unwrap_or_else(|| super::wmm::legacy_defaults(permission.frequency, plan.rates));
        self.ap_dirty_wmm = true;
        self.ap_command(
            &super::wmm::command(self.wire.dialect, contention)?,
            &current,
        )
        .await?;
        let plan = &self.ap.as_ref().unwrap().plan;
        let mut start = self.wire.start_station(
            &permission,
            plan.config.beacon_interval as u16,
            plan.config.dtim_period as u8,
        )?;
        // wmi_tlv_vdev_start_cmd: vdev/request/interval/dtim/flags/SSID.
        wire::put(&mut start, 24, u32::from(plan.config.hidden_ssid != 0));
        wire::put(&mut start, 28, plan.config.ssid.len() as u32);
        start[32..32 + plan.config.ssid.len()].copy_from_slice(&plan.config.ssid);
        self.ap_publish(&start, ap::Publication::Vdev(Vdev::StartSent), &current)
            .await?;
        self.ap_wait(|ap| ap.vdev == Vdev::Started, &current)
            .await?;
        self.ap_command(&beacon, &current).await?;
        self.ap_command(&probe, &current).await?;
        let mut up = ap_wire::command(0x5005, 92, &[0, 0, 0, 0])?;
        up[16..22].copy_from_slice(&own);
        self.ap_publish(&up, ap::Publication::Vdev(Vdev::Up), &current)
            .await?;
        self.ap_barrier(&current).await?;
        self.ap_wait(|ap| ap.beacon_ok, &current).await?;
        let ap = self.ap.as_mut().unwrap();
        ap.current(domain)?;
        ap.busy = false;
        // Earlier NEW_KEY/default ACKs were zeroizing metadata only. Promote
        // under each ORIGINAL still-current source after the real self peer,
        // AP/UP/template receipts and actual native DATA quiescence.
        if let Some(staging) = self.ap_staging.take() {
            for (key, source) in staging.keys {
                self.ap_add_key(key, source, domain, &current).await?;
            }
            if let Some((index, source)) = staging.default {
                self.ap_default_key(index, (false, true, false, false), source, domain)?;
            }
        }
        Ok(())
    }
    pub(in crate::ath10k) fn ap_poll_now(
        &mut self,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<Vec<ap::Received>, Error> {
        self.ap_current(domain)?;
        self.htt.wmi.htc.transport.runtime_idle(false);
        for _ in 0..64 {
            let event = self.htt.poll_now()?;
            if self.ap_event(event)? {
                break;
            }
            self.ap_current(domain)?;
        }
        let ap = self.ap.as_mut().ok_or(Error::Failed)?;
        let mut received = Vec::new();
        received
            .try_reserve_exact(ap.received.len())
            .map_err(|_| Error::NoMemory)?;
        received.extend(ap.received.drain(..));
        Ok(received)
    }
    pub(in crate::ath10k) fn ap_begin_ethernet(
        &mut self,
        domain: &narf_wireless::reg::RegulatoryDomain,
        ethernet: &[u8],
        original: &ap::Capture,
    ) -> Result<bool, Error> {
        self.ap_current(domain)?;
        original.current(domain)?;
        // A completed native loss may be arbitrarily far behind diagnostics.
        // No fresh capture after draining may revive this queued original.
        let mut quiet = false;
        for _ in 0..64 {
            let event = self.htt.poll_now()?;
            let deferred = self.htt.take_idle_deferred();
            if self.ap_event(event)? && !deferred {
                quiet = true;
                break;
            }
            original.current(domain)?;
        }
        original.current(domain)?;
        if !quiet {
            return Ok(false);
        }
        if !self.ap_running() || !self.htt.source_ready()? {
            return Ok(false);
        }
        let ap = self.ap.as_mut().ok_or(Error::Failed)?;
        // Preserve two real control/management IDs under ordinary DATA load.
        if ap.pending.len() >= 30 {
            return Ok(false);
        }
        ap.pending.try_reserve(1).map_err(|_| Error::NoMemory)?;
        let Some((bytes, tid)) = ap.ethernet(ethernet, false, false)? else {
            return Ok(true);
        };
        ap.current(domain)?;
        original.current(domain)?;
        let id = self.htt.begin_transmit(
            htt::tx::Parameters {
                kind: htt::tx::Kind::Raw,
                vdev: self.primary.id(),
                tid,
                hardware_crypto: false,
            },
            &bytes,
        )?;
        self.ap.as_mut().unwrap().pending.push(ap::Pending {
            token: Token::Htt(id),
            deadline: narf_time::Deadline::after_ms(3000),
            status: None,
            control: false,
        });
        Ok(true)
    }
}
