//! Original API77 netdev uses the common AP role/SME/key/data owner.
//! Socket/provider callbacks execute before native State; terminal Work owns
//! cleanup independently of borrowed nl80211 waiter cancellation.
use super::super::ap_host as host;
use super::*;
use alloc::vec;
pub(super) use host::{error, Operation};
use narf_wireless::ap_control::ApControlAuthority;
type Start = (
    Box<super::super::ap_wire::Plan>,
    Arc<super::super::ap_owner::Owner>,
    host::early::Prepared,
    (Asset, [u8; 32]),
);

impl Device {
    pub(super) fn ap_key_sequence(
        &self,
        authority: &ApControlAuthority,
        index: u8,
        pairwise: bool,
        peer: Option<[u8; 6]>,
    ) -> Result<narf_wireless::KeySequence, i32> {
        authority.check_for(self).map_err(|_| 1)?;
        if self.current_iftype() != 9 || !authority.has_reservation() {
            return Err(95);
        }
        let permit = authority.native_emission_for(self).map_err(|_| 95)?;
        let result = {
            let mut state = self.state.try_lock().ok_or(16)?;
            if !permit.current() {
                return Err(1);
            }
            let State { owner, ap, .. } = &mut *state;
            let session = ap.as_ref().ok_or(2)?;
            let hw = owner.as_mut().ok_or(19)?.ap_hardware();
            hw.source_fence()
                .map_err(|_| 1)?
                .invoke(|| Ok(session.key_sequence(index, pairwise, peer)))
                .map_err(|_| 1)?
        };
        authority.check_for(self).map_err(|_| 1)?;
        result
    }
    pub(super) fn ap_set_mode(&self, mode: u32) -> Result<(), WirelessError> {
        if self.p2p.active() {
            return Err(WirelessError::Busy);
        }
        if !matches!(mode, 2 | 3 | 8 | 9)
            || mode == 3 && !self.ap_capable
            || matches!(mode, 8 | 9) && !self.go_capable
        {
            return Err(WirelessError::NotSupported);
        }
        let _lease = self.radio_control.try_reserve()?;
        if self.link_up() || narf_net::iface::lookup(self.name()).is_some_and(|l| l.link_up) {
            return Err(WirelessError::Busy);
        }
        let state = self.state.try_lock().ok_or(WirelessError::Busy)?;
        let owner = state.owner.as_ref().ok_or(WirelessError::HardwareError)?;
        if state.ap.is_some()
            || state.scheduled.is_some()
            || !self.ap_stopped.load(Ordering::Acquire)
            || owner.phase() != Phase::Configured && !owner.station_failed()
        {
            return Err(WirelessError::Busy);
        }
        owner
            .station_source(self.source.firmware, false)
            .invoke(|| Ok(()))
            .map_err(|_| WirelessError::Denied)?;
        let _admission = self.admission.lock();
        if self.mode.load(Ordering::Acquire) == mode {
            return Ok(());
        }
        let generation = self
            .mode_generation
            .load(Ordering::Acquire)
            .checked_add(1)
            .ok_or(WirelessError::Denied)?;
        let retired = {
            let mut role = self.ap_host.role.lock();
            let old = role.retire();
            *role = narf_net::native_emission::ProviderLifetime::new();
            old
        };
        self.mode_generation.store(generation, Ordering::Release);
        self.mode.store(mode, Ordering::Release);
        self.ap_host.early.lock().clear();
        self.down_locked(false);
        drop(_admission);
        drop(state);
        retired.notify();
        Ok(())
    }
    fn ap_early_control(
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
            if state.scheduled.is_some()
                || state
                    .owner
                    .as_ref()
                    .is_none_or(|o| o.phase() != Phase::Configured)
            {
                return Err(16);
            }
        }
        {
            let control = self.control.try_lock().ok_or(16)?;
            if control.is_some() {
                return Err(16);
            }
        }
        self.source.invoke(|| Ok(())).map_err(|_| 1)?;
        self.ap_host.stage_early(self, authority, operation)
    }
    async fn stop_ap_locked(&self, state: &mut State) -> Result<(), &'static str> {
        if let Some(owner) = self.ap_host.active.lock().take() {
            owner.retire();
        }
        let ap = state.ap.take();
        if let Some(ap) = &ap {
            ap.proof.retire();
        }
        self.ap_host.early.lock().clear();
        state.ap_pending = None;
        state.pending = None;
        state.ap_probes.clear();
        if let Some(tx) = &mut state.transmit {
            for _ in 0..TX_RING_N {
                if !matches!(tx.try_recv(), Ok(Some(_))) {
                    break;
                }
            }
        }
        self.down(true);
        let result = state
            .owner
            .as_mut()
            .ok_or("MVM AP original owner absent")?
            .ap_stop()
            .await;
        self.ap_stopped.store(result.is_ok(), Ordering::Release);
        self.ap_cleanup.store(false, Ordering::Release);
        self.stopping.store(false, Ordering::Release);
        drop(ap);
        result
    }
    pub(super) async fn stop_ap_retained(&self) -> Result<(), &'static str> {
        if self.ap_stopped.load(Ordering::Acquire) && self.ap_host.active.lock().is_none() {
            return Ok(());
        }
        self.ap_request_stop();
        poll_fn(|cx| {
            self.ap_queue_stop();
            if progress::poll_work(&self.control, cx).is_pending() {
                return Poll::Pending;
            }
            if self.ap_stopped.load(Ordering::Acquire) {
                return Poll::Ready(Ok(()));
            }
            if self.terminal.load(Ordering::Acquire) {
                return Poll::Ready(Err("MVM AP DMA stop remains uncertain"));
            }
            cx.waker().wake_by_ref();
            Poll::Pending
        })
        .await
    }
    pub(super) fn ap_request_stop(&self) {
        if let Some(owner) = self.ap_host.active.lock().clone() {
            owner.retire();
        }
        if !self.stopping.swap(true, Ordering::AcqRel) {
            self.down(false);
        }
        self.ap_cleanup.store(true, Ordering::Release);
        self.ap_queue_stop();
    }
    fn ap_queue_stop(&self) {
        if !self.ap_cleanup.load(Ordering::Acquire) {
            return;
        }
        let Some(mut slot) = self.control.try_lock() else {
            return;
        };
        if slot.is_some() {
            return;
        }
        let Some(device) = self.me.upgrade() else {
            return;
        };
        self.ap_cleanup.store(false, Ordering::Release);
        *slot = Some(Work::new(async move {
            let mut state = device.state.lock().await;
            let _ = device.stop_ap_locked(&mut state).await;
        }));
        drop(slot);
        let wake = self.ap_host.waker.lock().clone();
        if let Some(wake) = wake {
            wake.wake();
        }
    }
    fn ap_refresh(&self, state: &mut State) -> Result<Publication, &'static str> {
        let ap = state.ap.as_ref().ok_or("MVM AP session absent")?;
        ap.current()?;
        let data = ap.data_publication();
        let hw = state
            .owner
            .as_mut()
            .ok_or("MVM AP original transport absent")?
            .ap_hardware();
        let source = hw.source_fence()?;
        let receive = hw
            .receive_publication()
            .ok_or("MVM AP receive/key epoch closed")?;
        let _admission = self.admission.lock();
        if !receive.current() || !data.current() {
            return Err("MVM AP receive/key epoch retired before refresh");
        }
        let replace_receive =
            self.fence
                .lock()
                .as_ref()
                .is_none_or(|old| match old.power.as_ref() {
                    super::super::mvm_publication::Power::Ap(old) => {
                        !old.same_epoch(&receive, &data)
                    }
                    _ => true,
                });
        if replace_receive || state.receive.is_none() {
            // Plain IPC frames have no per-entry native epoch. Replace both
            // endpoints so an old authorized/key epoch cannot survive refresh.
            let (producer, consumer) = narf_ipc::channel();
            state.receive = Some(producer);
            *self.rx.lock() = Some(consumer);
        }
        let publication = Publication {
            source: self.source.clone(),
            power: Arc::new(super::super::mvm_publication::Power::Ap(
                super::super::mvm_publication::Ap::new(source, receive, data)?,
            )),
            generation: (
                self.generation.clone(),
                self.generation.load(Ordering::Acquire),
            ),
        };
        *self.fence.lock() = Some(publication.clone());
        Ok(publication)
    }
    pub(super) async fn ap_control(
        &self,
        authority: &ApControlAuthority,
        operation: Operation,
    ) -> Result<bool, i32> {
        authority.check_for(self).map_err(|_| 1)?;
        if !matches!(self.current_iftype(), 3 | 9)
            || !self.ap_capable
            || !authority.has_reservation()
        {
            return Err(95);
        }
        let mut operation = Some(operation);
        if let Some(result) = self.ap_early_control(authority, &mut operation)? {
            return result;
        }
        let operation = operation.unwrap();
        let stop = matches!(operation, Operation::Stop);
        if matches!(operation, Operation::Start(..)) && self.terminal.load(Ordering::Acquire) {
            self.recover_failed().await.map_err(|_| 5)?;
            self.ap_stopped.store(true, Ordering::Release);
            authority.check_for(self).map_err(|_| 1)?;
        }
        if matches!(operation, Operation::Start(..)) {
            let state = self.state.try_lock().ok_or(16)?;
            if state.ap.is_some() || state.scheduled.is_some() {
                return Err(16);
            }
        }
        // The actual provider runs outside State and the retained Work slot.
        // Its returned record is re-bound to original hardware before I/O.
        let power = if matches!(operation, Operation::Start(..)) {
            let request = if self.current_iftype() == 9 {
                let Operation::Start(config, settings) = &operation else {
                    return Err(22);
                };
                let plan = super::super::ap_wire::Plan::new_go(
                    config.as_ref().clone(),
                    settings,
                    self.mac,
                )
                .map_err(|_| 22)?;
                self.go_power_request(plan.go.ok_or(22)?.device, plan.channel.frequency())
                    .await
                    .map_err(|_| 5)?
            } else {
                self.ap_power_request().await.map_err(|_| 5)?
            };
            let source = (self.environment.ap_power)(&request).map_err(|_| 95)?;
            Some((source, request.binding))
        } else {
            None
        };
        let early = if matches!(operation, Operation::Start(..)) {
            Some(self.ap_host.capture_early(self)?)
        } else {
            None
        };
        let cancel = Arc::new(AtomicBool::new(false));
        let request = if stop {
            None
        } else {
            authority.require_up().map_err(|_| 1)?;
            Some(Arc::new(super::super::ap_owner::Request {
                authority: authority.native_emission_for(self).map_err(|_| 95)?,
                related: early.as_ref().map_or_else(|| Arc::from([]), |e| e.guards()),
                cancel: cancel.clone(),
            }))
        };
        let start = if let Operation::Start(config, settings) = &operation {
            let plan = if self.current_iftype() == 9 {
                super::super::ap_wire::Plan::new_go(config.as_ref().clone(), settings, self.mac)
            } else {
                super::super::ap_wire::Plan::new(config.as_ref().clone(), settings, self.mac)
            }
            .map_err(|_| 22)?;
            if !self.channels.contains(&plan.channel.number) {
                return Err(22);
            }
            early.as_ref().unwrap().validate(&plan).map_err(|_| 22)?;
            let device = self.me.upgrade().ok_or(19)?;
            let iface: Arc<dyn WirelessNetIface> = device.clone();
            let proof = super::super::ap_owner::Owner::new(
                Arc::downgrade(&iface),
                authority.identity().map_err(|_| 1)?,
                authority.event_authority().map_err(|_| 1)?,
                request.as_ref().unwrap().authority.clone(),
                self.ap_host.role.lock().observe(),
                cancel.clone(),
            )
            .map_err(|_| 1)?;
            if !request.as_ref().unwrap().authority.matches_role(
                self,
                self.current_iftype(),
                self.ap_control_generation().ok_or(1)?,
            ) {
                return Err(1);
            }
            Some((Box::new(plan), proof, early.unwrap(), power.unwrap()))
        } else {
            None
        };
        let device = self.me.upgrade().ok_or(19)?;
        let mut slot = self.control.try_lock().ok_or(16)?;
        if slot.is_some() {
            return Err(16);
        }
        if let Some((_, proof, _, _)) = &start {
            // Retained source/watch ownership begins before the first native
            // wait. This is not a beacon/key/port readiness observation.
            *self.ap_host.active.lock() = Some(proof.clone());
        }
        let reply = Arc::new(IrqSafeSpinLock::new(host::Reply {
            result: None,
            waker: None,
        }));
        let completion = reply.clone();
        let permit = request.clone();
        let retained = authority.clone();
        *slot = Some(Work::new(async move {
            let mut state = device.state.lock().await;
            let result = device.apply_ap(&mut state, operation, start, permit).await;
            drop(state);
            let wake = {
                let mut reply = completion.lock();
                reply.result = Some(result);
                reply.waker.take()
            };
            if let Some(wake) = wake {
                wake.wake();
            }
            drop(retained);
        }));
        drop(slot);
        let mut waiter = Box::pin(host::Waiter {
            reply,
            cancel,
            consumed: false,
        });
        let result = poll_fn(|cx| {
            if let Some(request) = &request {
                let pump = self.ap_host.waker.lock().clone();
                if !request.watch(pump.as_ref().unwrap_or(cx.waker())) {
                    request.cancel.store(true, Ordering::Release);
                }
            }
            let _ = progress::poll_work(&self.control, cx);
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
        start: Option<Start>,
        request: Option<Arc<super::super::ap_owner::Request>>,
    ) -> Result<bool, i32> {
        if matches!(operation, Operation::Stop) {
            return self
                .stop_ap_locked(state)
                .await
                .map(|()| true)
                .map_err(|_| 5);
        }
        let request = request.ok_or(1)?;
        request.check().map_err(|_| 1)?;
        if let Some((plan, proof, early, (source, binding))) = start {
            if state.ap.is_some() || state.scheduled.is_some() {
                return Err(16);
            }
            let owner = state.owner.as_mut().ok_or(19)?;
            if owner.phase() != Phase::Configured || owner.station_failed() {
                return Err(16);
            }
            let settings = match operation {
                Operation::Start(_, settings) => *settings,
                _ => return Err(22),
            };
            self.ap_stopped.store(false, Ordering::Release);
            let result = Box::pin(owner.ap_prepare(
                *plan,
                settings,
                &self.environment.ap_policy,
                proof.clone(),
                request.clone(),
                self.ap_host.history.clone(),
                source,
                binding,
            ))
            .await;
            let mut ap = match result {
                Ok(ap) => Box::new(ap),
                Err(_) => {
                    let _ = self.stop_ap_locked(state).await;
                    return Err(5);
                }
            };
            let hw = owner.ap_hardware();
            if early.install(&mut ap, hw).await.is_err()
                || ap.enable_beacon(hw).await.is_err()
                || request.check().is_err()
                || ap.current().is_err()
            {
                let _ = self.stop_ap_locked(state).await;
                return Err(5);
            }
            self.ap_host.early.lock().clear();
            state.ap = Some(ap);
            *self.ap_host.active.lock() = Some(proof);
            let published = {
                let _admission = self.admission.lock();
                if let Some(next) = self.generation.load(Ordering::Acquire).checked_add(1) {
                    self.generation.store(next, Ordering::Release);
                    self.up.store(true, Ordering::Release);
                    self.port.store(true, Ordering::Release);
                    narf_net::iface::set_link_metadata(self.name(), true, None, None);
                    true
                } else {
                    false
                }
            };
            if !published || request.check().is_err() || self.ap_refresh(state).is_err() {
                let _ = self.stop_ap_locked(state).await;
                return Err(5);
            }
            if state
                .owner
                .as_mut()
                .unwrap()
                .ap_hardware()
                .ap_request(None)
                .is_err()
            {
                let _ = self.stop_ap_locked(state).await;
                return Err(5);
            }
            return Ok(true);
        }
        let mut ap = state.ap.take().ok_or(2)?;
        let hw = state.owner.as_mut().ok_or(19)?.ap_hardware();
        let before = hw.ap_command_cursor();
        hw.ap_request(Some(request.clone())).map_err(|_| 1)?;
        let result = async {
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
                Operation::DeleteKey(id, pairwise, peer) => {
                    ap.delete_key(hw, id, pairwise, peer).await?
                }
                Operation::DefaultKey(id, unicast, multicast, management, beacon) => {
                    ap.default_key(id, unicast, multicast, management, beacon)?
                }
                Operation::Control(frame) => return ap.control(hw, &frame).await,
                Operation::Management(frame) => return ap.management(hw, &frame).await,
                Operation::Start(..) | Operation::Stop => {
                    return Err("MVM AP invalid native operation state")
                }
            }
            Ok(true)
        }
        .await
        .and_then(|value| {
            request.check()?;
            Ok(value)
        });
        let uncertain = hw.ap_command_cursor() != before
            || hw.is_failed()
            || hw.receive_publication().is_none()
            || request.check().is_err()
            || ap.current().is_err();
        let _ = hw.ap_request(None);
        state.ap = Some(ap);
        if result.is_err() && uncertain {
            let _ = self.stop_ap_locked(state).await;
        } else if self.ap_refresh(state).is_err() {
            let _ = self.stop_ap_locked(state).await;
            return Err(5);
        }
        result.map_err(|_| if uncertain { 5 } else { 22 })
    }
    pub(super) fn ap_step(&self, mut cx: Option<&mut Context<'_>>) -> Vec<(Vec<u8>, Publication)> {
        if let Some(cx) = cx.as_ref() {
            let old = self.ap_host.waker.lock().replace(cx.waker().clone());
            drop(old);
        }
        // Full arbitrary source checks run before State/control acquisition.
        self.ap_host.prune_early();
        let active = self.ap_host.active.lock().clone();
        let lost = active.as_ref().is_some_and(|owner| {
            owner.check().is_err() || cx.as_ref().is_some_and(|cx| !owner.watch(cx.waker()))
        });
        if lost {
            if let Some(owner) = active {
                owner.retire();
            }
        }
        let mut fallback = Context::from_waker(Waker::noop());
        self.ap_queue_stop();
        if progress::poll_work(&self.control, cx.as_deref_mut().unwrap_or(&mut fallback))
            .is_pending()
        {
            return Vec::new();
        }
        if self.terminal.load(Ordering::Acquire) {
            self.ap_queue_stop();
            return Vec::new();
        }
        if lost || self.source.invoke(|| Ok(())).is_err() {
            self.ap_request_stop();
            return Vec::new();
        }
        let Some(mut state) = self.state.try_lock() else {
            return Vec::new();
        };
        if state.ap.is_none() {
            return Vec::new();
        }
        let result = (|| {
            let State {
                owner,
                ap,
                ap_probes,
                ap_pending,
                transmit,
                ..
            } = &mut *state;
            let owner = owner.as_mut().ok_or("MVM AP original transport absent")?;
            let hw = owner.ap_hardware();
            let ap = ap.as_mut().unwrap();
            ap.current()?;
            let data_epoch = ap.data_publication();
            hw.poll()?;
            hw.retire_transmits();
            let mut output = Vec::new();
            let mut events = Vec::new();
            for _ in 0..64 {
                let Some(packet) = hw.notifications.pop_front() else {
                    break;
                };
                let received = ap.receive(&packet, hw)?;
                if let Some(data) = received.data {
                    output.push(data);
                }
                if let Some(event) = received.event {
                    events.extend(self.ap_publications(ap, hw, event));
                }
                if let Some(probe) = received.probe {
                    if ap_probes.len() < 8 {
                        ap_probes.push_back(probe);
                    }
                }
            }
            if !data_epoch.current() {
                // Do not attach the new denial generation to DATA that was
                // accepted before a later peer-loss notification in this poll.
                output.clear();
            }
            while let Some(probe) = ap_probes.front() {
                if !ap.try_probe(hw, probe)? {
                    break;
                }
                ap_probes.pop_front();
            }
            if ap_pending.is_none() {
                if let Some(tx) = transmit {
                    let frame = if let Some(cx) = cx.as_deref_mut() {
                        match Pin::new(&mut tx.recv()).poll(cx) {
                            Poll::Ready(Ok(frame)) => Some(frame),
                            _ => None,
                        }
                    } else {
                        tx.try_recv().ok().flatten()
                    };
                    *ap_pending = frame.map(super::super::progress::PendingTx::new);
                }
            }
            if let Some(pending) = ap_pending.as_ref() {
                match pending.progress(|frame| {
                    let mut bytes = frame.payload().to_vec();
                    let assist =
                        super::super::csum::prepare_tx(&mut bytes, frame.tx_meta().csum_l4)?;
                    let category = super::super::qos::Parameters::default()
                        .classify(&bytes)
                        .ok_or("MVM AP Ethernet priority malformed")?;
                    ap.try_enqueue(hw, &bytes, category, assist)
                })? {
                    super::super::progress::Transmit::Sent => *ap_pending = None,
                    super::super::progress::Transmit::Busy => {}
                    super::super::progress::Transmit::Expired => {
                        return Err("MVM AP native TX credit deadline")
                    }
                }
            }
            Ok::<_, &'static str>((output, events))
        })();
        let (output, events) = match result {
            Ok(value) => value,
            Err(_) => {
                drop(state);
                self.ap_request_stop();
                return Vec::new();
            }
        };
        let publication = match self.ap_refresh(&mut state) {
            Ok(p) => p,
            Err(_) => {
                drop(state);
                self.ap_request_stop();
                return Vec::new();
            }
        };
        let domain = match self.environment.ap_policy.snapshot() {
            Ok(d) => d,
            Err(_) => {
                drop(state);
                self.ap_request_stop();
                return Vec::new();
            }
        };
        for bytes in &output {
            if let (Some(rx), Ok(memory)) = (
                &mut state.receive,
                super::super::runtime::dma_alloc(bytes.len()),
            ) {
                let mut frame = Frame::new(memory, bytes.len() as u32);
                frame.payload_mut().copy_from_slice(bytes);
                if publication
                    .invoke(&domain, || {
                        if !self.port.load(Ordering::Acquire) {
                            return Err("MVM AP IPC publication closed");
                        }
                        let _ = rx.try_send(frame);
                        Ok(())
                    })
                    .is_err()
                {
                    drop(state);
                    self.ap_request_stop();
                    return Vec::new();
                }
            }
        }
        drop(state);
        for event in events {
            event.publish();
        }
        output
            .into_iter()
            .map(|bytes| (bytes, publication.clone()))
            .collect()
    }
    pub(super) fn ap_publications(
        &self,
        ap: &super::super::ap_session::Session,
        hardware: &Hardware,
        packet: super::super::ap_session::packet::Event,
    ) -> Vec<super::super::ap_host::Publication> {
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
            .map(|event| super::super::ap_host::Publication {
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
        if !matches!(self.current_iftype(), 3 | 9)
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
        registrations.push(Arc::new(super::super::ap_host::Registration {
            event,
            frame_type,
            prefix,
        }));
        drop(registrations);
        authority.check_for(self)
    }
}
