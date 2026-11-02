//! Concrete Sc/Bz physical-State adapter. No provider/interface callback may
//! run while State is held. The child retains public work independently.
use super::super::p2p_host::Registration;
use super::super::{
    native_band::Channel,
    p2p_host::Request,
    p2p_wire::{Abi, Activity as RocActivity},
    runtime::p2p::Event,
};
use super::*;
use narf_capabilities::{Cap, Grant as RegisterGrant, Write};
use narf_wireless::ap_control::RadioControlAuthority;

#[path = "p2p_device.rs"]
mod child;
pub(super) use child::Child;

/// Only successful physical registry publication may fill this cell. It
/// retains the actual grant and returned Write receipt, never a name lookup.
pub(super) struct Host {
    registration: IrqSafeSpinLock<Option<Registration>>,
    child: IrqSafeSpinLock<Weak<Child>>,
    signal: Arc<Signal>,
}
struct Signal(IrqSafeSpinLock<Option<Waker>>);
impl alloc::task::Wake for Signal {
    fn wake(self: Arc<Self>) {
        alloc::task::Wake::wake_by_ref(&self);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        let wake = { self.0.lock().clone() };
        if let Some(wake) = wake {
            wake.wake();
        }
    }
}
impl Host {
    pub(super) fn new() -> Self {
        Self {
            registration: IrqSafeSpinLock::new(None),
            child: IrqSafeSpinLock::new(Weak::new()),
            signal: Arc::new(Signal(IrqSafeSpinLock::new(None))),
        }
    }
    pub(super) fn registered(
        &self,
        grant: Cap<narf_net::NetIface, RegisterGrant>,
        parent: Cap<narf_net::NetIface, Write>,
    ) {
        *self.registration.lock() = Some(Registration { grant, parent });
    }
    fn child(&self) -> Option<Arc<Child>> {
        self.child.lock().upgrade()
    }
    fn waker(&self) -> Waker {
        // Every request watches the same retained physical owner, rather
        // than consuming an unbounded provider slot for each netlink task.
        Waker::from(self.signal.clone())
    }
    pub(super) fn active(&self) -> bool {
        self.child().is_some_and(|child| child.active())
    }
    pub(super) fn step(&self, cx: Option<&mut Context<'_>>) -> bool {
        let mut fallback = Context::from_waker(Waker::noop());
        if let Some(cx) = cx.as_ref() {
            let old = self.signal.0.lock().replace(cx.waker().clone());
            drop(old);
        }
        self.child()
            .is_some_and(|child| child.step(cx.unwrap_or(&mut fallback)))
    }
}

impl Device {
    pub(super) async fn new_p2p_control(
        &self,
        authority: &RadioControlAuthority,
        name: &str,
        iftype: u32,
        mac: Option<[u8; 6]>,
    ) -> Result<Arc<dyn WirelessNetIface>, WirelessError> {
        authority.check_for(self)?;
        authority.require_mode(2)?;
        if iftype != 10 || !self.p2p_capable() || !authority.has_reservation() {
            return Err(WirelessError::NotSupported);
        }
        if name.is_empty()
            || name.len() > 15
            || name
                .bytes()
                .any(|byte| byte == 0 || byte == b'/' || byte.is_ascii_whitespace())
        {
            return Err(WirelessError::InvalidArgs);
        }
        let registration = { *self.p2p.registration.lock() }.ok_or(WirelessError::Denied)?;
        let parent = self.me.upgrade().ok_or(WirelessError::Denied)?;
        if self.p2p.child().is_some() {
            return Err(WirelessError::Busy);
        }
        {
            let state = self.state.try_lock().ok_or(WirelessError::Busy)?;
            if state.ap.is_some()
                || state.connection.is_some()
                || state.scheduled.is_some()
                || state.hardware.p2p_started()
                || self.closing.load(Ordering::Acquire)
            {
                return Err(WirelessError::Busy);
            }
        }
        // This new software-local address is used only by the actual MAC1
        // control-device context. It creates no NVM channel/radio permission.
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
        authority.check_for(self)?;
        // NEW may precede parent UP. This namespace observation grants
        // nothing: register_control_child invokes the original parent and
        // retain_control_child checks the creating authority's exact scope.
        let namespace = narf_net::iface::lookup(self.name())
            .map(|metadata| metadata.net_ns_id)
            .ok_or(WirelessError::Denied)?;
        let child = Child::create(parent, authority, registration, name, own, namespace)?;
        *self.p2p.child.lock() = Arc::downgrade(&child);
        Ok(child)
    }
    pub(in crate::iwlwifi) fn p2p_capable(&self) -> bool {
        self.source.invoke(|| Ok(())).is_ok()
            && super::super::parse_ucode(&self.firmware).is_ok_and(|parsed| {
                matches!(Abi::read(&parsed.api), Ok(Abi::Roc6 | Abi::Session2))
                    && parsed.api.api_changes[1] & (1 << 27) != 0
                    && matches!(parsed.api.num_stations, Some(2..=16))
                    && matches!(parsed.api.num_links, Some(2..=4))
            })
    }
    pub(in crate::iwlwifi) fn p2p_source_current(&self) -> bool {
        self.source.invoke(|| Ok(())).is_ok()
            && self.current_owner()
            && self
                .p2p
                .registration
                .lock()
                .is_some_and(|registration| registration.current())
    }
    async fn p2p_cleanup_error(&self, state: &mut State) -> WirelessError {
        // Never replay an ambiguous command/removal to regain eligibility.
        // The actual existing stop owner attempts RF reset/BME-off and
        // retains uncertain DMA. A dead request cannot forbid this cleanup.
        self.stop_locked(state).await;
        state.needs_reset = state.hardware.is_failed();
        WirelessError::HardwareError
    }
    pub(in crate::iwlwifi) async fn p2p_start_request(
        &self,
        request: Arc<Request>,
    ) -> Result<(), WirelessError> {
        request.check().map_err(|_| WirelessError::Denied)?;
        let mut state = self.state.lock().await;
        if !self.p2p_source_current()
            || self.closing.load(Ordering::Acquire)
            || self.suspended.load(Ordering::Acquire)
        {
            return Err(WirelessError::Denied);
        }
        if self.current_iftype() != 2
            || state.connection.is_some()
            || state.ap.is_some()
            || state.scheduled.is_some()
            || state.hardware.p2p_started()
        {
            return Err(WirelessError::Busy);
        }
        if state.needs_reset || state.hardware.is_failed() {
            self.recover(&mut state).await?;
        }
        request.check().map_err(|_| WirelessError::Denied)?;
        let parsed =
            super::super::parse_ucode(&self.firmware).map_err(|_| WirelessError::HardwareError)?;
        if !state.hardware.p2p_supported(&parsed.api) {
            return Err(WirelessError::NotSupported);
        }
        if state
            .hardware
            .p2p_start_native(&parsed.api, request)
            .await
            .is_err()
        {
            return Err(self.p2p_cleanup_error(&mut state).await);
        }
        Ok(())
    }
    pub(in crate::iwlwifi) async fn p2p_stop_request(&self) -> Result<Vec<Event>, WirelessError> {
        let mut state = self.state.lock().await;
        match state.hardware.p2p_retire_native(true).await {
            Ok(events) => Ok(events),
            Err(_) => {
                self.stop_locked(&mut state).await;
                if self.quarantined.load(Ordering::Acquire) {
                    Err(WirelessError::HardwareError)
                } else {
                    Ok(Vec::new())
                }
            }
        }
    }
    pub(in crate::iwlwifi) async fn p2p_roc_request(
        &self,
        request: Arc<Request>,
        cookie: u64,
        frequency: u32,
        duration: u32,
        activity: RocActivity,
    ) -> Result<Vec<Event>, WirelessError> {
        if cookie == 0 || !(10..=5000).contains(&duration) {
            return Err(WirelessError::InvalidArgs);
        }
        request.check().map_err(|_| WirelessError::Denied)?;
        let channel = self
            .channels
            .iter()
            .filter_map(|&number| Channel::legacy(number))
            .find(|channel| channel.frequency() == frequency)
            .ok_or(WirelessError::InvalidArgs)?;
        if channel.number == 14 {
            return Err(WirelessError::InvalidArgs);
        }
        let mut state = self.state.lock().await;
        if state.connection.is_some()
            || state.ap.is_some()
            || state.scheduled.is_some()
            || !state.hardware.p2p_started()
            || state.hardware.p2p_cookie().is_some()
        {
            return Err(WirelessError::Busy);
        }
        request.check().map_err(|_| WirelessError::Denied)?;
        if state
            .hardware
            .p2p_begin_native(
                request,
                &self.policy,
                channel,
                &self.channels,
                self.rx_chains,
                cookie,
                duration,
                activity,
                true,
            )
            .await
            .is_err()
        {
            return Err(self.p2p_cleanup_error(&mut state).await);
        }
        let deadline = narf_time::Deadline::after_ms(2000);
        while !state.hardware.p2p_granted(frequency) {
            let activity = state.hardware.activity();
            if state.hardware.poll().is_err()
                || state.hardware.p2p_needs_retirement()
                || deadline.expired()
            {
                return Err(self.p2p_cleanup_error(&mut state).await);
            }
            if !state.hardware.p2p_granted(frequency) {
                activity.await
            }
        }
        Ok(state.hardware.p2p_take_events())
    }
    pub(in crate::iwlwifi) async fn p2p_cancel_request(
        &self,
        request: &Request,
        cookie: u64,
    ) -> Result<Vec<Event>, WirelessError> {
        let mut state = self.state.lock().await;
        request.check().map_err(|_| WirelessError::Denied)?;
        if !state.hardware.p2p_same_receiver(request) {
            return Err(WirelessError::Denied);
        }
        if state.hardware.p2p_cookie() != Some(cookie) {
            return Err(WirelessError::InvalidArgs);
        }
        match state.hardware.p2p_retire_native(false).await {
            Ok(events) => Ok(events),
            Err(_) => Err(self.p2p_cleanup_error(&mut state).await),
        }
    }
    pub(in crate::iwlwifi) async fn p2p_frame_request(
        &self,
        request: Arc<Request>,
        cookie: u64,
        frame: narf_wireless::MgmtTxRequest,
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
        let mut state = self.state.lock().await;
        let frequency = if frame.frequency_mhz == 0 {
            state
                .hardware
                .p2p_frequency()
                .ok_or(WirelessError::InvalidArgs)?
        } else {
            frame.frequency_mhz
        };
        if !state.hardware.p2p_started() {
            return Err(WirelessError::Busy);
        }
        if state.hardware.p2p_cookie().is_none() {
            if !frame.offchannel_ok || !(10..=5000).contains(&frame.duration) {
                return Err(WirelessError::InvalidArgs);
            }
            let channel = self
                .channels
                .iter()
                .filter_map(|&number| Channel::legacy(number))
                .find(|channel| channel.frequency() == frequency)
                .ok_or(WirelessError::InvalidArgs)?;
            if channel.number == 14 {
                return Err(WirelessError::InvalidArgs);
            }
            if state
                .hardware
                .p2p_begin_native(
                    request.clone(),
                    &self.policy,
                    channel,
                    &self.channels,
                    self.rx_chains,
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
        if state.hardware.p2p_frequency() != Some(frequency) {
            return Err(WirelessError::Busy);
        }
        let deadline = narf_time::Deadline::after_ms(2000);
        while !state.hardware.p2p_granted(frequency) {
            request.check().map_err(|_| WirelessError::Denied)?;
            let activity = state.hardware.activity();
            if state.hardware.poll().is_err()
                || state.hardware.p2p_needs_retirement()
                || deadline.expired()
            {
                return Err(self.p2p_cleanup_error(&mut state).await);
            }
            if !state.hardware.p2p_granted(frequency) {
                activity.await;
            }
        }
        let antenna = self.tx_chains & self.tx_chains.wrapping_neg();
        let result = state
            .hardware
            .p2p_transmit_native(request, frequency, &frame.frame, antenna)
            .await;
        match result {
            Ok(acked) => Ok((acked, state.hardware.p2p_take_events())),
            Err(_) => Err(self.p2p_cleanup_error(&mut state).await),
        }
    }
    pub(in crate::iwlwifi) async fn p2p_service_native(
        &self,
    ) -> Result<(bool, Vec<Event>), WirelessError> {
        let mut state = self.state.lock().await;
        if !state.hardware.p2p_started() {
            return Ok((false, Vec::new()));
        }
        if state.hardware.p2p_needs_retirement() {
            // A retired original START closes the complete device. A live
            // START with a completed/cancelled operation keeps only its MAC.
            let stop = state.hardware.p2p_start_retired();
            return match state.hardware.p2p_retire_native(stop).await {
                Ok(events) => Ok((state.hardware.p2p_started(), events)),
                Err(_) => Err(self.p2p_cleanup_error(&mut state).await),
            };
        }
        if state.hardware.poll().is_err() {
            return Err(self.p2p_cleanup_error(&mut state).await);
        }
        // No station or scan owner is live in this adapter. Unclaimed
        // unsolicited copies cannot be retained for a later station/cache.
        state.hardware.notifications.clear();
        Ok((true, state.hardware.p2p_take_events()))
    }
    pub(super) fn p2p_event_current(&self, event: &Event) -> bool {
        use super::super::runtime::p2p::Kind;
        if !self.p2p_source_current()
            || !event.capture.current()
            || event.receiver.check().is_err()
            || event.origin.check().is_err()
            || !matches!(event.kind, Kind::Expired) && event.start.check().is_err()
            || event
                .policy
                .as_ref()
                .is_some_and(|policy| policy.check().is_err())
        {
            return false;
        }
        let Some(state) = self.state.try_lock() else {
            return false;
        };
        !state.needs_reset
            && !state.hardware.is_failed()
            && match &event.kind {
                Kind::Expired => event.publication.is_none(),
                _ => {
                    event
                        .publication
                        .as_ref()
                        .is_some_and(|grant| grant.current())
                        && state.hardware.p2p_cookie() == Some(event.cookie)
                        && state.hardware.p2p_granted(event.frequency)
                }
            }
    }
    pub(super) fn p2p_result_current(&self, request: &Request, roc: Option<(u64, u32)>) -> bool {
        if request.check().is_err() || !self.p2p_source_current() {
            return false;
        }
        let Some(state) = self.state.try_lock() else {
            return false;
        };
        !state.needs_reset
            && !state.hardware.is_failed()
            && state.hardware.p2p_started()
            && !state.hardware.p2p_start_retired()
            && state.hardware.p2p_same_receiver(request)
            && roc.is_none_or(|(cookie, frequency)| {
                state.hardware.p2p_cookie() == Some(cookie) && state.hardware.p2p_granted(frequency)
            })
    }
}
