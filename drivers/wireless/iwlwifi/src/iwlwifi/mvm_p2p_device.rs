//! The original API77 physical netdev parents the common actual control
//! child. Original capabilities and every arbitrary power/source callback
//! remain outside State; the child retains native work after waiter drop.
use super::super::{
    device::p2p::{Child, Parent},
    native_band::Channel,
    p2p_host::{PowerSource, Request},
    p2p_wire::Activity as RocActivity,
    runtime::p2p::{Event, Kind},
};
use super::*;
use narf_wireless::ap_control::RadioControlAuthority;

impl Device {
    pub(in crate::iwlwifi) async fn p2p_power_request(
        &self,
        own: [u8; 6],
        frequency: u32,
    ) -> Result<super::super::Gen2TransmitPowerRequest, &'static str> {
        let channel = self
            .p2p_channel(frequency)
            .map_err(|_| "MVM P2P qualification channel unavailable")?;
        let mut state = self.state.lock().await;
        self.source.invoke(|| {
            state
                .owner
                .as_mut()
                .ok_or("MVM P2P original native owner absent")?
                .p2p_power_request(own, channel.number)
        })
    }
    pub(in crate::iwlwifi) fn p2p_invoke<T>(
        &self,
        action: impl FnOnce() -> Result<T, &'static str>,
    ) -> Result<T, &'static str> {
        self.source.invoke(action)
    }
    pub(in crate::iwlwifi) fn p2p_waker(&self) -> Waker {
        self.p2p.waker()
    }
    pub(in crate::iwlwifi) fn p2p_quarantined(&self) -> bool {
        self.terminal.load(Ordering::Acquire)
    }
    pub(in crate::iwlwifi) fn p2p_poll_control(&self, cx: &mut Context<'_>) {
        let _ = progress::poll_work(&self.control, cx);
    }
    pub(in crate::iwlwifi) fn p2p_reserve(
        &self,
    ) -> Result<Arc<dyn narf_wireless::ap_control::ApControlReservation>, WirelessError> {
        self.radio_control.try_reserve()
    }
    pub(in crate::iwlwifi) fn p2p_source_current(&self) -> bool {
        self.source.invoke(|| Ok(())).is_ok()
            && self.publication.load(Ordering::Acquire)
            && ACTIVE
                .lock()
                .as_ref()
                .is_some_and(|device| core::ptr::eq(Arc::as_ptr(device), self))
            && self
                .p2p
                .registration()
                .is_some_and(|original| original.current())
    }
    pub(super) async fn new_p2p_control(
        &self,
        authority: &RadioControlAuthority,
        name: &str,
        mode: u32,
        mac: Option<[u8; 6]>,
    ) -> Result<Arc<dyn WirelessNetIface>, WirelessError> {
        authority.check_for(self)?;
        authority.require_mode(2)?;
        if mode != 10 || !self.p2p_capable || !authority.has_reservation() {
            return Err(WirelessError::NotSupported);
        }
        if !self.p2p_source_current() {
            return Err(WirelessError::Denied);
        }
        if name.is_empty()
            || name.len() > 15
            || name
                .bytes()
                .any(|b| b == 0 || b == b'/' || b.is_ascii_whitespace())
        {
            return Err(WirelessError::InvalidArgs);
        }
        if self.p2p.child().is_some() {
            return Err(WirelessError::Busy);
        }
        {
            let state = self.state.try_lock().ok_or(WirelessError::Busy)?;
            let owner = state.owner.as_ref().ok_or(WirelessError::HardwareError)?;
            if state.ap.is_some()
                || state.scheduled.is_some()
                || owner.phase() != Phase::Configured
                || self.stopping.load(Ordering::Acquire)
            {
                return Err(WirelessError::Busy);
            }
        }
        let own = mac.unwrap_or_else(|| {
            let mut own = self.mac;
            own[0] |= 2;
            own[5] ^= 0x80;
            own
        });
        if own == [0; 6]
            || own[0] & 1 != 0
            || own == self.mac
            || narf_wireless::registry::list()
                .iter()
                .any(|iface| iface.name() == name || iface.mac() == own)
            || narf_net::iface::lookup(name).is_some()
        {
            return Err(WirelessError::InvalidArgs);
        }
        let original = self.p2p.registration().ok_or(WirelessError::Denied)?;
        let namespace = narf_net::iface::lookup(self.name())
            .ok_or(WirelessError::Denied)?
            .net_ns_id;
        let parent = self.me.upgrade().ok_or(WirelessError::Denied)?;
        let child = Child::create(
            Parent::Mvm(parent),
            authority,
            original,
            name,
            own,
            namespace,
        )?;
        self.p2p.attach(&child);
        Ok(child)
    }
    async fn p2p_cleanup_error(&self, state: &mut State) -> WirelessError {
        // Non-emitting reset/BME-off keeps the original device owner. Dead
        // START/socket/tag8 authority cannot prohibit this physical closure.
        if let Some(owner) = state.owner.as_mut() {
            owner.station_fail();
            let _ = owner.suspend_transport().await;
        }
        self.down(true);
        WirelessError::HardwareError
    }
    pub(in crate::iwlwifi) async fn p2p_start_request(
        &self,
        request: Arc<Request>,
    ) -> Result<(), WirelessError> {
        request.check().map_err(|_| WirelessError::Denied)?;
        if !self.p2p_source_current() || self.suspended.load(Ordering::Acquire) {
            return Err(WirelessError::Denied);
        }
        self.recover_failed().await.map_err(error)?;
        let mut state = self.state.lock().await;
        if self.current_iftype() != 2
            || state.ap.is_some()
            || state.scheduled.is_some()
            || self.stopping.load(Ordering::Acquire)
        {
            return Err(WirelessError::Busy);
        }
        let owner = state.owner.as_mut().ok_or(WirelessError::HardwareError)?;
        request.check().map_err(|_| WirelessError::Denied)?;
        if owner.p2p_start(request).await.is_err() {
            return Err(self.p2p_cleanup_error(&mut state).await);
        }
        Ok(())
    }
    pub(in crate::iwlwifi) async fn p2p_stop_request(&self) -> Result<Vec<Event>, WirelessError> {
        let mut state = self.state.lock().await;
        let hw = state
            .owner
            .as_mut()
            .ok_or(WirelessError::HardwareError)?
            .p2p_hardware();
        match hw.p2p_retire_native(true).await {
            Ok(events) => Ok(events),
            Err(_) => Err(self.p2p_cleanup_error(&mut state).await),
        }
    }
    fn p2p_channel(&self, frequency: u32) -> Result<Channel, WirelessError> {
        self.channels
            .iter()
            .filter_map(|n| Channel::legacy(*n))
            .find(|channel| channel.frequency() == frequency && channel.number != 14)
            .ok_or(WirelessError::InvalidArgs)
    }
    async fn p2p_load_power(
        &self,
        request: &Request,
        channel: Channel,
    ) -> Result<(Asset, [u8; 32]), WirelessError> {
        request.check().map_err(|_| WirelessError::Denied)?;
        let wanted = {
            let mut state = self.state.lock().await;
            if state.ap.is_some() || state.scheduled.is_some() || self.current_iftype() != 2 {
                return Err(WirelessError::Busy);
            }
            let owner = state.owner.as_mut().ok_or(WirelessError::HardwareError)?;
            if owner.phase() != Phase::Configured || !owner.p2p_hardware().p2p_started() {
                return Err(WirelessError::Busy);
            }
            self.source
                .invoke(|| owner.p2p_power_request(request.own(), channel.number))
                .map_err(error)?
        };
        // This loader may be supplied by an actual platform/fixture. No
        // State, native Work or admission guard survives its callback.
        let source = (self.environment.p2p_power)(&wanted).map_err(error)?;
        request.check().map_err(|_| WirelessError::Denied)?;
        self.source.invoke(|| Ok(())).map_err(error)?;
        Ok((source, wanted.binding))
    }
    pub(in crate::iwlwifi) async fn p2p_prepare_power(
        &self,
        request: Arc<Request>,
        frequency: u32,
        only_if_missing: bool,
    ) -> Result<Option<PowerSource>, WirelessError> {
        request.check().map_err(|_| WirelessError::Denied)?;
        let frequency = {
            let mut state = self.state.lock().await;
            let hw = state
                .owner
                .as_mut()
                .ok_or(WirelessError::HardwareError)?
                .p2p_hardware();
            if !hw.p2p_started() {
                return Err(WirelessError::Busy);
            }
            if only_if_missing && hw.p2p_cookie().is_some() {
                return Ok(None);
            }
            if !only_if_missing && hw.p2p_cookie().is_some() {
                return Err(WirelessError::Busy);
            }
            if frequency == 0 {
                hw.p2p_frequency().ok_or(WirelessError::InvalidArgs)?
            } else {
                frequency
            }
        };
        let channel = self.p2p_channel(frequency)?;
        self.p2p_load_power(&request, channel).await.map(Some)
    }
    #[allow(clippy::too_many_arguments)]
    async fn p2p_begin_locked(
        &self,
        owner: &mut Owner,
        request: Arc<Request>,
        channel: Channel,
        source: (Asset, [u8; 32]),
        cookie: u64,
        duration: u32,
        activity: RocActivity,
        public: bool,
    ) -> Result<(), &'static str> {
        let prepared = owner
            .p2p_prepare(
                request.clone(),
                channel,
                &self.environment.ap_policy,
                source.0,
                source.1,
            )
            .await?;
        let rx = owner
            .identity()
            .ok_or("MVM P2P original NVM disappeared")?
            .1
            .rx_chains;
        let hw = owner.p2p_hardware();
        hw.p2p_begin_native(
            request,
            &self.environment.ap_policy,
            channel,
            &self.channels,
            rx,
            Some(prepared),
            cookie,
            duration,
            activity,
            public,
        )
        .await?;
        let deadline = narf_time::Deadline::after_ms(2000);
        while !hw.p2p_granted(channel.frequency()) {
            let activity = hw.activity();
            hw.poll()?;
            if hw.p2p_needs_retirement() || deadline.expired() {
                return Err("MVM P2P actual SESSION1 START absent or source retired");
            }
            if !hw.p2p_granted(channel.frequency()) {
                activity.await
            }
        }
        Ok(())
    }
    pub(in crate::iwlwifi) async fn p2p_roc_request(
        &self,
        request: Arc<Request>,
        cookie: u64,
        frequency: u32,
        duration: u32,
        activity: RocActivity,
        source: Option<PowerSource>,
    ) -> Result<Vec<Event>, WirelessError> {
        if cookie == 0 || !(10..=5000).contains(&duration) {
            return Err(WirelessError::InvalidArgs);
        }
        let channel = self.p2p_channel(frequency)?;
        let source = source.ok_or(WirelessError::Denied)?;
        let mut state = self.state.lock().await;
        let owner = state.owner.as_mut().ok_or(WirelessError::HardwareError)?;
        if owner.p2p_hardware().p2p_cookie().is_some() {
            return Err(WirelessError::Busy);
        }
        if self
            .p2p_begin_locked(
                owner, request, channel, source, cookie, duration, activity, true,
            )
            .await
            .is_err()
        {
            return Err(self.p2p_cleanup_error(&mut state).await);
        }
        Ok(owner.p2p_hardware().p2p_take_events())
    }
    pub(in crate::iwlwifi) async fn p2p_cancel_request(
        &self,
        request: &Request,
        cookie: u64,
    ) -> Result<Vec<Event>, WirelessError> {
        let mut state = self.state.lock().await;
        request.check().map_err(|_| WirelessError::Denied)?;
        let hw = state
            .owner
            .as_mut()
            .ok_or(WirelessError::HardwareError)?
            .p2p_hardware();
        if !hw.p2p_same_receiver(request) {
            return Err(WirelessError::Denied);
        }
        if hw.p2p_cookie() != Some(cookie) {
            return Err(WirelessError::InvalidArgs);
        }
        match hw.p2p_retire_native(false).await {
            Ok(events) => Ok(events),
            Err(_) => Err(self.p2p_cleanup_error(&mut state).await),
        }
    }
    pub(in crate::iwlwifi) async fn p2p_frame_request(
        &self,
        request: Arc<Request>,
        cookie: u64,
        frame: narf_wireless::MgmtTxRequest,
        source: Option<PowerSource>,
    ) -> Result<(bool, Vec<Event>), WirelessError> {
        request.check().map_err(|_| WirelessError::Denied)?;
        if cookie == 0
            || frame.frame.len() < 24
            || frame.frame.len() > 4095
            || !matches!(frame.frame[0], 0x40 | 0xd0)
            || frame.frame[1] & 0xc7 != 0
            || frame.frame[10..16] != request.own()
            || frame.frame[22] & 15 != 0
            || frame.duration != 0 && !(10..=5000).contains(&frame.duration)
        {
            return Err(WirelessError::InvalidArgs);
        }
        let (frequency, implicit) = {
            let mut state = self.state.lock().await;
            let hw = state
                .owner
                .as_mut()
                .ok_or(WirelessError::HardwareError)?
                .p2p_hardware();
            if !hw.p2p_started() {
                return Err(WirelessError::Busy);
            }
            (
                if frame.frequency_mhz == 0 {
                    hw.p2p_frequency().ok_or(WirelessError::InvalidArgs)?
                } else {
                    frame.frequency_mhz
                },
                hw.p2p_cookie().is_none(),
            )
        };
        let channel = self.p2p_channel(frequency)?;
        let source = if implicit {
            if !frame.offchannel_ok || !(10..=5000).contains(&frame.duration) {
                return Err(WirelessError::InvalidArgs);
            }
            Some(source.ok_or(WirelessError::Denied)?)
        } else {
            None
        };
        let mut state = self.state.lock().await;
        let owner = state.owner.as_mut().ok_or(WirelessError::HardwareError)?;
        if let Some(source) = source {
            if self
                .p2p_begin_locked(
                    owner,
                    request.clone(),
                    channel,
                    source,
                    cookie,
                    frame.duration,
                    RocActivity::Negotiate,
                    false,
                )
                .await
                .is_err()
            {
                return Err(self.p2p_cleanup_error(&mut state).await);
            }
        }
        let tx = owner
            .identity()
            .ok_or(WirelessError::HardwareError)?
            .1
            .tx_chains;
        let hw = owner.p2p_hardware();
        if !hw.p2p_granted(frequency) {
            return Err(WirelessError::Busy);
        }
        match hw
            .p2p_transmit_native(request, frequency, &frame.frame, tx & tx.wrapping_neg())
            .await
        {
            Ok(acked) => Ok((acked, hw.p2p_take_events())),
            Err(_) => Err(self.p2p_cleanup_error(&mut state).await),
        }
    }
    pub(in crate::iwlwifi) async fn p2p_service_native(
        &self,
    ) -> Result<(bool, Vec<Event>), WirelessError> {
        let mut state = self.state.lock().await;
        let hw = state
            .owner
            .as_mut()
            .ok_or(WirelessError::HardwareError)?
            .p2p_hardware();
        if !hw.p2p_started() {
            return Ok((false, Vec::new()));
        }
        if hw.p2p_needs_retirement() {
            let stop = hw.p2p_start_retired();
            return match hw.p2p_retire_native(stop).await {
                Ok(events) => Ok((hw.p2p_started(), events)),
                Err(_) => Err(self.p2p_cleanup_error(&mut state).await),
            };
        }
        if hw.poll().is_err() {
            return Err(self.p2p_cleanup_error(&mut state).await);
        }
        hw.notifications.clear();
        Ok((true, hw.p2p_take_events()))
    }
    pub(in crate::iwlwifi) async fn p2p_finished(&self) -> (bool, Vec<Arc<Request>>) {
        let mut state = self.state.lock().await;
        state.owner.as_mut().map_or_else(
            || (false, Vec::new()),
            |owner| {
                let hw = owner.p2p_hardware();
                (hw.p2p_started(), hw.p2p_take_retired())
            },
        )
    }
    pub(in crate::iwlwifi) fn p2p_result_current(
        &self,
        request: &Request,
        roc: Option<(u64, u32)>,
    ) -> bool {
        if request.check().is_err() || !self.p2p_source_current() {
            return false;
        }
        let Some(mut state) = self.state.try_lock() else {
            return false;
        };
        let Some(owner) = state.owner.as_mut() else {
            return false;
        };
        let hw = owner.p2p_hardware();
        !hw.is_failed()
            && hw.p2p_started()
            && !hw.p2p_start_retired()
            && hw.p2p_same_receiver(request)
            && roc.is_none_or(|(cookie, frequency)| {
                hw.p2p_cookie() == Some(cookie) && hw.p2p_granted(frequency)
            })
    }
    pub(in crate::iwlwifi) fn p2p_event_current(&self, event: &Event) -> bool {
        if !self.p2p_source_current()
            || !event.capture.current()
            || event.receiver.check().is_err()
            || event.origin.check().is_err()
            || !matches!(event.kind, Kind::Expired) && event.start.check().is_err()
            || event
                .policy
                .as_ref()
                .is_some_and(|power| power.check().is_err())
        {
            return false;
        }
        let Some(mut state) = self.state.try_lock() else {
            return false;
        };
        let Some(owner) = state.owner.as_mut() else {
            return false;
        };
        let hw = owner.p2p_hardware();
        !hw.is_failed()
            && match &event.kind {
                Kind::Expired => event.publication.is_none(),
                _ => {
                    event
                        .publication
                        .as_ref()
                        .is_some_and(|grant| grant.current())
                        && hw.p2p_cookie() == Some(event.cookie)
                        && hw.p2p_granted(event.frequency)
                }
            }
    }
}
