//! Retained Sc/Bz/API89 AP device work. Source callbacks and nl80211 events
//! run outside State; only concrete capability/provider fences run inside it.
use super::*;
use alloc::vec;
use narf_wireless::ap_control::ApControlAuthority;

pub(super) use super::super::ap_host::*;

impl Device {
    pub(super) fn prune_ap_early(&self) {
        self.ap_host.prune_early();
    }
    pub(super) fn capture_ap_early(&self) -> Result<early::Prepared, i32> {
        self.ap_host.capture_early(self)
    }
    pub(super) fn ap_early_control(
        &self,
        authority: &ApControlAuthority,
        operation: &mut Option<Operation>,
    ) -> Result<Option<Result<bool, i32>>, i32> {
        if !matches!(
            operation,
            Some(Operation::Key(_) | Operation::DeleteKey(..) | Operation::DefaultKey(..))
        ) {
            return Ok(None);
        }
        {
            let state = self.state.try_lock().ok_or(16)?;
            if state.ap.is_some() {
                return Ok(None);
            }
            if state.connection.is_some() || state.scheduled.is_some() {
                return Err(16);
            }
        }
        {
            let control = self.control.try_lock().ok_or(16)?;
            if control.is_some() {
                return Err(16);
            }
        }
        authority.check_for(self).map_err(|_| 1)?;
        self.source.invoke(|| Ok(())).map_err(|_| 1)?;
        self.ap_host.stage_early(self, authority, operation)
    }
    pub(super) fn ap_set_mode(&self, mode: u32) -> Result<(), WirelessError> {
        if !matches!(mode, 2 | 3) || mode == 3 && !self.ap_capable {
            return Err(WirelessError::NotSupported);
        }
        let _lease = self.radio_control.try_reserve()?;
        // Full metadata/control queries stay outside the native State lock.
        if self.link_up() || narf_net::iface::lookup(self.name()).is_some_and(|link| link.link_up) {
            return Err(WirelessError::Busy);
        }
        let state = self.state.try_lock().ok_or(WirelessError::Busy)?;
        if state.ap.is_some() || state.connection.is_some() || state.scheduled.is_some() {
            return Err(WirelessError::Busy);
        }
        let _admission = self.admission.lock();
        self.source
            .invoke(|| Ok(()))
            .map_err(|_| WirelessError::Denied)?;
        if self.mode.load(Ordering::Acquire) == mode {
            return Ok(());
        }
        let generation = self
            .mode_generation
            .load(Ordering::Acquire)
            .checked_add(1)
            .ok_or(WirelessError::Denied)?;
        let native = {
            let mut role = self.ap_host.role.lock();
            let retired = role.retire();
            *role = narf_net::native_emission::ProviderLifetime::new();
            retired
        };
        self.mode_generation.store(generation, Ordering::Release);
        self.mode.store(mode, Ordering::Release);
        self.ap_host.early.lock().clear();
        self.set_link_locked(false);
        drop(_admission);
        drop(state);
        native.notify();
        Ok(())
    }
    pub(super) fn retire_ap(&self, state: &mut State) {
        if let Some(ap) = state.ap.take() {
            ap.proof.retire();
        }
        if let Some(owner) = self.ap_host.active.lock().take() {
            owner.retire();
        }
        state.ap_probes.clear();
        self.ap_host.early.lock().clear();
    }
    /// Arm the retained pump outside State. The1ms AP pump deadline covers
    /// generic cap-epoch revocation; provider closure additionally wakes it.
    pub(super) fn ap_currentness(&self, waker: Option<&Waker>) -> bool {
        if let Some(waker) = waker {
            let old = self.ap_host.waker.lock().replace(waker.clone());
            drop(old);
        }
        if self.current_iftype() == 3 {
            self.prune_ap_early();
        }
        let owner = self.ap_host.active.lock().clone();
        owner.is_some_and(|owner| {
            owner.check().is_err() || waker.is_some_and(|waker| !owner.watch(waker))
        })
    }
    pub(super) fn ap_publications(
        &self,
        ap: &super::super::ap_session::Session,
        hardware: &Hardware,
        packet: super::super::ap_session::packet::Event,
    ) -> Vec<Publication> {
        let Ok(source) = hardware.source_fence() else {
            return Vec::new();
        };
        let Some(receive) = hardware.receive_publication() else {
            return Vec::new();
        };
        let registrations = match &packet {
            super::super::ap_session::packet::Event::Control { .. } => vec![ap.proof.event()],
            super::super::ap_session::packet::Event::Management { frame, .. } => {
                let kind = u16::from_le_bytes([frame[0], frame[1]]) & 0x00fc;
                self.ap_host
                    .registrations
                    .lock()
                    .iter()
                    .filter(|registration| {
                        registration.frame_type == kind
                            && frame[24..].starts_with(&registration.prefix)
                    })
                    .map(|registration| registration.event.clone())
                    .collect()
            }
        };
        let data = match &packet {
            super::super::ap_session::packet::Event::Control { ethertype, .. }
                if *ethertype != ap.settings.control_port.ethertype =>
            {
                Some(ap.data_publication())
            }
            _ => None,
        };
        let packet = Arc::new(packet);
        registrations
            .into_iter()
            .map(|event| Publication {
                event,
                source: source.clone(),
                receive: receive.clone(),
                data: data.clone(),
                frequency: ap.plan.channel.frequency(),
                packet: packet.clone(),
            })
            .collect()
    }
    pub(super) fn ap_register(
        &self,
        authority: &ApControlAuthority,
        frame_type: u16,
        prefix: Vec<u8>,
    ) -> Result<(), WirelessError> {
        authority.check_for(self)?;
        if self.current_iftype() != 3
            || !authority.has_reservation()
            || frame_type & !0x00f0 != 0
            || prefix.len() > 256
        {
            return Err(WirelessError::InvalidArgs);
        }
        let event = authority.event_authority()?;
        // Prune arbitrary source callbacks outside State and registration lock.
        let old = self.ap_host.registrations.lock().clone();
        let retired: Vec<_> = old
            .iter()
            .filter(|registration| registration.event.registration_current().is_err())
            .cloned()
            .collect();
        let mut registrations = self.ap_host.registrations.lock();
        registrations
            .retain(|registration| !retired.iter().any(|old| Arc::ptr_eq(old, registration)));
        if registrations.len() == 16 {
            return Err(WirelessError::Busy);
        }
        registrations.push(Arc::new(Registration {
            event,
            frame_type,
            prefix,
        }));
        drop(registrations);
        authority.check_for(self)
    }
    pub(super) async fn ap_control(
        &self,
        authority: &ApControlAuthority,
        operation: Operation,
    ) -> Result<bool, i32> {
        authority.check_for(self).map_err(|_| 1)?;
        if self.current_iftype() != 3 || !self.ap_capable || !authority.has_reservation() {
            return Err(95);
        }
        let mut operation = Some(operation);
        if let Some(result) = self.ap_early_control(authority, &mut operation)? {
            return result;
        }
        let operation = operation.unwrap();
        let device = self.me.upgrade().ok_or(19)?;
        let cancel = Arc::new(AtomicBool::new(false));
        let stop = matches!(&operation, Operation::Stop);
        let early = if matches!(&operation, Operation::Start(..)) {
            Some(self.capture_ap_early()?)
        } else {
            None
        };
        let request = if stop {
            None
        } else {
            authority.require_up().map_err(|_| 1)?;
            Some(Arc::new(super::super::ap_owner::Request {
                authority: authority.native_emission_for(self).map_err(|_| 95)?,
                related: early
                    .as_ref()
                    .map_or_else(|| Arc::from([]), |early| early.guards()),
                cancel: cancel.clone(),
            }))
        };
        let start = if let Operation::Start(config, settings) = &operation {
            let plan =
                super::super::ap_wire::Plan::new(config.as_ref().clone(), settings, self.mac)
                    .map_err(|_| 22)?;
            early.as_ref().unwrap().validate(&plan).map_err(|_| 22)?;
            if !self.channels.contains(&plan.channel.number) {
                return Err(22);
            }
            let iface: Arc<dyn WirelessNetIface> = device.clone();
            let emission = request.as_ref().unwrap().authority.clone();
            if !emission.matches_role(self, 3, self.ap_control_generation().ok_or(1)?) {
                return Err(1);
            }
            let proof = super::super::ap_owner::Owner::new(
                Arc::downgrade(&iface),
                authority.identity().map_err(|_| 1)?,
                authority.event_authority().map_err(|_| 1)?,
                emission,
                self.ap_host.role.lock().observe(),
                cancel.clone(),
            )
            .map_err(|_| 1)?;
            Some((Box::new(plan), proof, early.unwrap()))
        } else {
            None
        };
        let mut slot = self.control.try_lock().ok_or(16)?;
        if slot.is_some() {
            return Err(16);
        }
        let reply = Arc::new(IrqSafeSpinLock::new(Reply {
            result: None,
            waker: None,
        }));
        let completion = reply.clone();
        let retained = authority.clone();
        let permit = request.clone();
        let abandoned = cancel.clone();
        *slot = Some(Work::new(async move {
            let mut state = device.state.lock().await;
            let result = device
                .apply_ap(&mut state, operation, start, permit, abandoned)
                .await;
            drop(state);
            let wake = {
                let mut reply = completion.lock();
                reply.result = Some(result);
                reply.waker.take()
            };
            if let Some(waker) = wake {
                waker.wake();
            }
            // Keep the actual admission lease through terminal cleanup.
            // Full virtual/source checks happen after poll_control releases
            // its own work-slot guard, in the borrowed API waiter below.
            drop(retained);
        }));
        drop(slot);
        let mut waiter = Box::pin(Waiter {
            reply,
            cancel,
            consumed: false,
        });
        let result = poll_fn(|cx| {
            if let Some(request) = &request {
                // Watch the retained physical pump, not each short-lived
                // netlink ACK task. One source may issue unbounded controls;
                // only distinct physical native owners consume watch slots.
                let pump = self.ap_host.waker.lock().clone();
                if !request.watch(pump.as_ref().unwrap_or(cx.waker())) {
                    request.cancel.store(true, Ordering::Release);
                }
            }
            let _ = self.poll_control(cx);
            waiter.as_mut().poll(cx)
        })
        .await;
        authority.check_for(self).map_err(|_| 1)?;
        result
    }
    async fn apply_ap(
        &self,
        state: &mut State,
        operation: Operation,
        start: Option<(
            Box<super::super::ap_wire::Plan>,
            Arc<super::super::ap_owner::Owner>,
            early::Prepared,
        )>,
        request: Option<Arc<super::super::ap_owner::Request>>,
        cancel: Arc<AtomicBool>,
    ) -> Result<bool, i32> {
        if matches!(&operation, Operation::Stop) {
            // Never require continuing START RF/admin/socket permission for
            // physical non-emitting cleanup. Hardware retains uncertain DMA.
            self.stop_locked(state).await;
            return if self.quarantined.load(Ordering::Acquire) {
                Err(5)
            } else {
                Ok(true)
            };
        }
        let request = request.ok_or(1)?;
        request.check().map_err(|_| 1)?;
        if let Some((plan, proof, early)) = start {
            if state.connection.is_some() || state.scheduled.is_some() || state.ap.is_some() {
                return Err(16);
            }
            if state.needs_reset || state.hardware.is_failed() {
                self.recover(state).await.map_err(|_| 5)?;
            }
            request.check().map_err(|_| 1)?;
            let settings = match operation {
                Operation::Start(_, settings) => *settings,
                _ => return Err(22),
            };
            let result = Box::pin(super::super::ap_session::Session::prepare(
                &mut state.hardware,
                *plan,
                settings,
                self.mac,
                self.tx_chains,
                &self.policy,
                proof.clone(),
                self.ap_host.history.clone(),
                request.clone(),
            ))
            .await;
            let mut ap = match result {
                Ok(ap) => ap,
                Err(_) => {
                    self.stop_locked(state).await;
                    return Err(5);
                }
            };
            if early.install(&mut ap, &mut state.hardware).await.is_err()
                || ap.enable_beacon(&mut state.hardware).await.is_err()
            {
                self.stop_locked(state).await;
                return Err(5);
            }
            self.ap_host.early.lock().clear();
            let fence = match self.policy.bind(ap.program.clone()) {
                Ok(fence) => fence,
                Err(_) => {
                    self.stop_locked(state).await;
                    return Err(5);
                }
            };
            *self.policy_fence.lock() = Some(fence);
            state.ap = Some(ap);
            state.stop_completed = false;
            *self.ap_host.active.lock() = Some(proof.clone());
            if proof.check().is_err() || request.check().is_err() || cancel.load(Ordering::Acquire)
            {
                self.stop_locked(state).await;
                return Err(1);
            }
            self.up.store(true, Ordering::Release);
            narf_net::iface::set_link_metadata(self.name(), true, None, None);
            if self.refresh_receive_ipc(state).is_err() {
                self.stop_locked(state).await;
                return Err(5);
            }
            let _ = state.hardware.ap_request(None);
            return Ok(true);
        }
        if state.needs_reset || state.hardware.is_failed() {
            return Err(5);
        }
        let before = state.hardware.ap_command_cursor();
        state
            .hardware
            .ap_request(Some(request.clone()))
            .map_err(|_| 1)?;
        let Some(mut ap) = state.ap.take() else {
            let _ = state.hardware.ap_request(None);
            return Err(2);
        };
        let result = async {
            let hw = &mut state.hardware;
            match operation {
                Operation::Beacon(head, tail, probe) => ap.beacon(hw, head, tail, probe).await?,
                Operation::Add(config) => ap.add_peer(hw, config).await?,
                Operation::Set(config) => ap.set_peer(hw, config).await?,
                Operation::Delete(peer) => {
                    if let Some(peer) = peer {
                        ap.remove_peer(hw, peer).await?;
                    } else {
                        while let Some(peer) = ap.peers.first() {
                            let mac = peer.config.mac;
                            ap.remove_peer(hw, mac).await?;
                        }
                    }
                }
                Operation::Key(key) => ap.key(hw, key.params()).await?,
                Operation::DeleteKey(index, pairwise, peer) => {
                    ap.delete_key(hw, index, pairwise, peer).await?
                }
                Operation::DefaultKey(index, unicast, multicast, management, beacon) => {
                    ap.default_key(index, unicast, multicast, management, beacon)?
                }
                Operation::Control(frame) => return ap.control(hw, &frame).await,
                Operation::Management(frame) => return ap.management(hw, &frame).await,
                Operation::Start(..) | Operation::Stop => {
                    return Err("AP invalid retained operation state")
                }
            }
            request.check()?;
            Ok(true)
        }
        .await
        .and_then(|status| {
            request.check()?;
            Ok(status)
        });
        let uncertain = state.hardware.ap_command_cursor() != before
            || state.hardware.receive_publication().is_none()
            || state.hardware.is_failed()
            || request.check().is_err()
            || ap.current().is_err();
        let _ = state.hardware.ap_request(None);
        state.ap = Some(ap);
        if result.is_err() && uncertain {
            self.stop_locked(state).await;
        } else if self.refresh_receive_ipc(state).is_err() {
            self.stop_locked(state).await;
            return Err(5);
        }
        result.map_err(|_| if uncertain { 5 } else { 22 })
    }
}

impl State {
    pub(super) fn progress_ap_transmit(
        &mut self,
        mut cx: Option<&mut Context<'_>>,
    ) -> Result<(), &'static str> {
        self.tx_progress = false;
        let Some(ap) = &mut self.ap else {
            return Ok(());
        };
        ap.current()?;
        while let Some(frame) = self.ap_probes.front() {
            if !ap.try_probe(&mut self.hardware, frame)? {
                break;
            }
            self.ap_probes.pop_front();
            self.tx_progress = true;
        }
        for category in 0..4 {
            if self.pending[category].is_none() {
                self.pending[category] = self.pending_next[category].take();
            }
            if self.pending[category].is_none() {
                if let Some(consumer) = &mut self.tx[category] {
                    let frame = if let Some(cx) = cx.as_deref_mut() {
                        match Pin::new(&mut consumer.recv()).poll(cx) {
                            Poll::Ready(Ok(frame)) => Some(frame),
                            _ => None,
                        }
                    } else {
                        consumer.try_recv().ok().flatten()
                    };
                    self.pending[category] = frame.map(PendingTx::new);
                }
            }
            if let Some(pending) = &self.pending[category] {
                match pending.progress(|frame| {
                    let mut bytes = frame.payload().to_vec();
                    let assist =
                        super::super::csum::prepare_tx(&mut bytes, frame.tx_meta().csum_l4)?;
                    ap.try_enqueue(&mut self.hardware, &bytes, category, assist)
                })? {
                    Transmit::Sent => {
                        self.pending[category] = None;
                        self.tx_progress = true;
                    }
                    Transmit::Busy => {}
                    Transmit::Expired => return Err("AP native TX credit timed out"),
                }
            }
        }
        Ok(())
    }
}
