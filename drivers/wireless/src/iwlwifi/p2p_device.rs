//! Actual control-only WDEV and retained native worker. No Ethernet entry,
//! IFINDEX, administrative UP, station client or GO role is fabricated here.
use super::*;
use alloc::string::String;
use core::num::NonZeroU64;
use narf_wireless::ap_control::RadioControlRetirement;

pub(in crate::iwlwifi::device) struct Child {
    me: Weak<Self>,
    parent: Arc<Device>,
    name: String,
    own: [u8; 6],
    namespace: u64,
    registration: Registration,
    generation: Arc<AtomicU64>,
    role: IrqSafeSpinLock<narf_net::native_emission::ProviderLifetime>,
    metadata: IrqSafeSpinLock<Option<Metadata>>,
    released: AtomicBool,
    engaged: AtomicBool,
    work: Mutex<Option<Work>>,
    finished: IrqSafeSpinLock<Vec<Finished>>,
    filters: IrqSafeSpinLock<Vec<Arc<Filter>>>,
    rx: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
}
#[derive(Clone, Copy)]
struct Metadata {
    cap: Cap<narf_net::NetIface, Write>,
    wdev: narf_wireless::registry::ControlWdev,
}
struct Filter {
    frame_type: u16,
    prefix: Vec<u8>,
    request: Arc<Request>,
}
enum Operation {
    Start,
    Stop,
    Roc(u64, u32, u32),
    Cancel(u64),
    Frame(u64, narf_wireless::MgmtTxRequest),
    Service,
}
struct Reply {
    result: Option<Result<bool, WirelessError>>,
    waker: Option<Waker>,
}
/// Kept outside the work Future before its terminal poll releases State.
/// Arbitrary source/iface callbacks and final source/lease destruction are
/// deliberately deferred until poll_work has released the work-slot lock.
struct Finished {
    authority: Option<RadioControlAuthority>,
    request: Option<Arc<Request>>,
    reply: Option<Arc<IrqSafeSpinLock<Reply>>>,
    result: Result<bool, WirelessError>,
    events: Vec<Event>,
    _retired: Vec<Arc<Request>>,
}
impl core::fmt::Debug for Child {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IwlP2pControl")
            .field("name", &self.name)
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}
impl Child {
    pub(super) fn create(
        parent: Arc<Device>,
        authority: &RadioControlAuthority,
        registration: Registration,
        name: &str,
        own: [u8; 6],
        namespace: u64,
    ) -> Result<Arc<Self>, WirelessError> {
        let child = Arc::new_cyclic(|me| Self {
            me: me.clone(),
            parent: parent.clone(),
            name: String::from(name),
            own,
            namespace,
            registration,
            generation: Arc::new(AtomicU64::new(1)),
            role: IrqSafeSpinLock::new(narf_net::native_emission::ProviderLifetime::new()),
            metadata: IrqSafeSpinLock::new(None),
            released: AtomicBool::new(false),
            engaged: AtomicBool::new(false),
            work: Mutex::new(None),
            finished: IrqSafeSpinLock::new(Vec::new()),
            filters: IrqSafeSpinLock::new(Vec::new()),
            rx: IrqSafeSpinLock::new(None),
            tx: IrqSafeSpinLock::new(None),
        });
        // Only the actual original grant + parent Write receipt can publish
        // a typed child. Neither a registry/name lookup nor source callback
        // may manufacture or replace either capability.
        let cap = parent
            .source
            .invoke(|| {
                narf_net::registry()
                    .register_control_child(
                        &registration.grant,
                        &registration.parent,
                        Registered(child.clone()),
                    )
                    .map_err(|_| "Intel P2P original parent registration retired")
            })
            .map_err(|_| WirelessError::Denied)?;
        let physical: Arc<dyn WirelessNetIface> = parent.clone();
        let iface: Arc<dyn WirelessNetIface> = child.clone();
        let wdev = match narf_wireless::registry::register_control(&physical, iface.clone()) {
            Ok(wdev) => wdev,
            Err(_) => {
                narf_net::registry().unregister_for_handle(&cap);
                return Err(WirelessError::Busy);
            }
        };
        *child.metadata.lock() = Some(Metadata { cap, wdev });
        // This can call the actual creating socket. All native State/work
        // guards are absent, and callbacks cannot create a START/RF owner.
        if authority.retain_control_child(&iface, &cap).is_err()
            || authority.check_for(parent.as_ref()).is_err()
            || !wdev.current_for(child.as_ref())
            || child.released.load(Ordering::Acquire)
        {
            child.release_control_metadata();
            return Err(WirelessError::Denied);
        }
        Ok(child)
    }
    fn metadata(&self) -> Result<Metadata, WirelessError> {
        self.metadata
            .lock()
            .as_ref()
            .copied()
            .filter(|_| !self.released.load(Ordering::Acquire))
            .ok_or(WirelessError::Denied)
    }
    pub(super) fn active(&self) -> bool {
        self.engaged.load(Ordering::Acquire)
            || self.work.try_lock().is_none_or(|work| work.is_some())
    }
    fn request(&self, authority: &RadioControlAuthority) -> Result<Arc<Request>, WirelessError> {
        if !authority.has_reservation() || !self.parent.p2p_source_current() {
            return Err(WirelessError::Denied);
        }
        authority.check_for(self)?;
        let metadata = self.metadata()?;
        let iface: Arc<dyn WirelessNetIface> = self.me.upgrade().ok_or(WirelessError::Denied)?;
        let role = { self.role.lock().observe() };
        let request = Request::capture(
            authority,
            &iface,
            &metadata.cap,
            self.registration,
            self.generation.clone(),
            role,
            self.parent.p2p.waker(),
        )
        .map_err(|_| WirelessError::Denied)?;
        if !request.watch() {
            return Err(WirelessError::Denied);
        }
        Ok(request)
    }
    fn enqueue(
        self: &Arc<Self>,
        operation: Operation,
        authority: Option<RadioControlAuthority>,
        request: Option<Arc<Request>>,
        reply: Option<Arc<IrqSafeSpinLock<Reply>>>,
    ) -> Result<(), WirelessError> {
        let mut slot = self.work.try_lock().ok_or(WirelessError::Busy)?;
        if slot.is_some() {
            return Err(WirelessError::Busy);
        }
        let child = self.clone();
        *slot = Some(Work::new(async move {
            let (result, events) = match operation {
                Operation::Start => (
                    child
                        .parent
                        .p2p_start_request(request.as_ref().unwrap().clone())
                        .await
                        .map(|_| true),
                    Vec::new(),
                ),
                Operation::Stop => match child.parent.p2p_stop_request().await {
                    Ok(events) => (Ok(true), events),
                    Err(error) => (Err(error), Vec::new()),
                },
                Operation::Roc(cookie, frequency, duration) => match child
                    .parent
                    .p2p_roc_request(
                        request.as_ref().unwrap().clone(),
                        cookie,
                        frequency,
                        duration,
                        RocActivity::Discover,
                    )
                    .await
                {
                    Ok(events) => (Ok(true), events),
                    Err(error) => (Err(error), Vec::new()),
                },
                Operation::Cancel(cookie) => match child
                    .parent
                    .p2p_cancel_request(request.as_ref().unwrap(), cookie)
                    .await
                {
                    Ok(events) => (Ok(true), events),
                    Err(error) => (Err(error), Vec::new()),
                },
                Operation::Frame(cookie, frame) => match child
                    .parent
                    .p2p_frame_request(request.as_ref().unwrap().clone(), cookie, frame)
                    .await
                {
                    Ok((acked, events)) => (Ok(acked), events),
                    Err(error) => (Err(error), Vec::new()),
                },
                Operation::Service => match child.parent.p2p_service_native().await {
                    Ok((_, events)) => (Ok(true), events),
                    Err(error) => (Err(error), Vec::new()),
                },
            };
            let (engaged, retired) = {
                let mut state = child.parent.state.lock().await;
                (
                    state.hardware.p2p_started(),
                    state.hardware.p2p_take_retired(),
                )
            };
            child.engaged.store(engaged, Ordering::Release);
            child.finished.lock().push(Finished {
                authority,
                request,
                reply,
                result,
                events,
                _retired: retired,
            });
        }));
        drop(slot);
        self.parent.p2p.waker().wake();
        Ok(())
    }
    /// One retained physical worker drives every command/retirement, including
    /// when the original borrowed nl80211 Future is dropped. Actual providers
    /// wake this same worker; its 1ms timer also invokes generic cap epochs.
    pub(super) fn step(self: &Arc<Self>, cx: &mut Context<'_>) -> bool {
        let _ = super::super::super::progress::poll_work(&self.work, cx);
        self.complete();
        if self.engaged.load(Ordering::Acquire)
            && !self.parent.quarantined.load(Ordering::Acquire)
            && self.enqueue(Operation::Service, None, None, None).is_ok()
        {
            // Ordinary receive/service leaves the request slot empty. Only
            // an actual awaited cleanup may occupy it, so public controls
            // cannot race an endlessly queued service poll.
            let _ = super::super::super::progress::poll_work(&self.work, cx);
            self.complete();
        }
        self.active()
    }
    fn complete(&self) {
        let completed = { core::mem::take(&mut *self.finished.lock()) };
        for finished in completed {
            for event in finished.events {
                self.publish(event);
            }
            if let Some(reply) = finished.reply {
                let result = if finished
                    .authority
                    .as_ref()
                    .is_some_and(|guard| guard.check_for(self).is_err())
                    || finished
                        .request
                        .as_ref()
                        .is_some_and(|request| request.check().is_err())
                {
                    Err(WirelessError::Denied)
                } else {
                    finished.result
                };
                let wake = {
                    let mut reply = reply.lock();
                    reply.result = Some(result);
                    reply.waker.take()
                };
                if let Some(wake) = wake {
                    wake.wake()
                }
            }
            // Source/lease drops are outside native State AND Work locks.
        }
    }
    async fn control(
        &self,
        authority: &RadioControlAuthority,
        operation: Operation,
    ) -> Result<bool, WirelessError> {
        authority.check_for(self)?;
        authority.require_mode(10)?;
        if !authority.has_reservation() {
            return Err(WirelessError::Denied);
        }
        let request = if matches!(operation, Operation::Stop) {
            None
        } else {
            Some(self.request(authority)?)
        };
        let mut waiter = request
            .as_ref()
            .map(|request| super::super::super::p2p_host::Waiter::new(request.clone()));
        let original = request.clone();
        let roc = match &operation {
            Operation::Roc(cookie, frequency, _) => Some((*cookie, *frequency)),
            _ => None,
        };
        let reply = Arc::new(IrqSafeSpinLock::new(Reply {
            result: None,
            waker: None,
        }));
        let child = self.me.upgrade().ok_or(WirelessError::Denied)?;
        child.enqueue(
            operation,
            Some(authority.clone()),
            request,
            Some(reply.clone()),
        )?;
        let result = poll_fn(|cx| {
            // Service the root's existing native slot first: a station/AP
            // command already holding State must be allowed to finish.
            let _ = self.parent.poll_control(cx);
            child.step(cx);
            let mut reply = reply.lock();
            if let Some(result) = reply.result.take() {
                Poll::Ready(result)
            } else {
                reply.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        })
        .await;
        if let Some(waiter) = &mut waiter {
            waiter.complete()
        }
        authority.check_for(self)?;
        if result.is_ok()
            && original
                .as_ref()
                .is_some_and(|request| !self.parent.p2p_result_current(request, roc))
        {
            return Err(WirelessError::Denied);
        }
        result
    }
    fn publish(&self, event: Event) {
        use super::super::super::runtime::p2p::Kind;
        let Ok(metadata) = self.metadata() else {
            return;
        };
        let sources = match &event.kind {
            Kind::Management { frame, .. } => {
                let old = { self.filters.lock().clone() };
                old.into_iter()
                    .filter(|filter| {
                        filter.frame_type == u16::from_le_bytes([frame[0], frame[1]]) & 0xfc
                            && frame[24..].starts_with(&filter.prefix)
                    })
                    .map(|filter| filter.request.clone())
                    .collect()
            }
            _ => alloc::vec![event.receiver.clone()],
        };
        for receiver in sources {
            if !receiver.same_receiver(&event.receiver) {
                continue;
            }
            let source = receiver.event();
            enum Prepared {
                Roc(narf_wireless::ap_control::PreparedRadioRocEvent),
                Management(narf_wireless::ap_control::PreparedRadioManagementEvent),
            }
            // These calls may invoke an arbitrary socket/interface provider.
            // No native State, Work or filter lock is held here.
            let prepared = match &event.kind {
                Kind::Ready => source
                    .prepare_roc_ready(
                        receiver.emission(),
                        event.cookie,
                        event.frequency,
                        event.duration_ms,
                    )
                    .map(Prepared::Roc),
                Kind::Expired => source
                    .prepare_roc_expired(
                        receiver.emission(),
                        event.cookie,
                        event.frequency,
                        event.duration_ms,
                    )
                    .map(Prepared::Roc),
                Kind::Management { rssi, frame } => source
                    .prepare_control_management_received(
                        &metadata.cap,
                        event.frequency,
                        Some(*rssi),
                        frame,
                    )
                    .map(Prepared::Management),
            };
            let Ok(prepared) = prepared else { continue };
            // Native copy/grant and policy are checked again after provider
            // preparation. The final fixed fence also runs after State is gone.
            if !self.parent.p2p_event_current(&event) || receiver.check().is_err() {
                continue;
            }
            let _ = self.parent.source.invoke(|| {
                if let Some(policy) = &event.policy {
                    policy.check()?
                }
                if !event.capture.current()
                    || event
                        .publication
                        .as_ref()
                        .is_some_and(|grant| !grant.current())
                {
                    return Err("Intel P2P copied native event retired during preparation");
                }
                let fence = event.capture.fence(&receiver, &event.origin);
                match prepared {
                    Prepared::Roc(prepared) => prepared.deliver(fence),
                    Prepared::Management(prepared) => prepared.deliver(fence),
                }
                .map_err(|_| "Intel P2P original event endpoint retired")
            });
        }
    }
}
impl Interface for Child {
    fn name(&self) -> &str {
        &self.name
    }
    fn mac(&self) -> [u8; 6] {
        self.own
    }
    fn mtu(&self) -> u32 {
        0
    }
    fn link_up(&self) -> bool {
        false
    }
    fn control_namespace(&self) -> Option<u64> {
        Some(self.namespace)
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx
    }
}
#[async_trait::async_trait]
impl WirelessNetIface for Child {
    fn wiphy_id(&self) -> u64 {
        self.parent.wiphy_id()
    }
    fn current_iftype(&self) -> u32 {
        10
    }
    fn radio_control_generation(&self) -> Option<NonZeroU64> {
        if self.released.load(Ordering::Acquire) {
            None
        } else {
            NonZeroU64::new(self.generation.load(Ordering::Acquire))
        }
    }
    fn reserve_radio_control(
        &self,
    ) -> Result<Option<Arc<dyn narf_wireless::ap_control::ApControlReservation>>, WirelessError>
    {
        self.parent.radio_control.try_reserve().map(Some)
    }
    fn async_control_interfaces(&self) -> bool {
        true
    }
    fn async_p2p_device_control(&self) -> bool {
        true
    }
    fn async_p2p_management_rx_control(&self) -> bool {
        true
    }
    fn async_p2p_management_tx_control(&self) -> bool {
        true
    }
    fn async_roc_control(&self) -> bool {
        true
    }
    fn supports_offchannel_mgmt_tx(&self) -> bool {
        true
    }
    fn max_remain_on_channel_duration_ms(&self) -> u32 {
        5000
    }
    fn p2p_interface_types(&self) -> Vec<u32> {
        alloc::vec![10]
    }
    async fn start_p2p_device_async(
        &self,
        authority: &RadioControlAuthority,
    ) -> Result<(), WirelessError> {
        self.control(authority, Operation::Start).await.map(|_| ())
    }
    async fn stop_p2p_device_async(
        &self,
        authority: &RadioControlAuthority,
    ) -> Result<(), WirelessError> {
        self.control(authority, Operation::Stop).await.map(|_| ())
    }
    async fn remain_on_channel_async(
        &self,
        authority: &RadioControlAuthority,
        cookie: u64,
        frequency: u32,
        duration: u32,
    ) -> Result<(), WirelessError> {
        self.control(authority, Operation::Roc(cookie, frequency, duration))
            .await
            .map(|_| ())
    }
    async fn cancel_remain_on_channel_async(
        &self,
        authority: &RadioControlAuthority,
        cookie: u64,
    ) -> Result<(), WirelessError> {
        self.control(authority, Operation::Cancel(cookie))
            .await
            .map(|_| ())
    }
    async fn mgmt_tx_radio_async(
        &self,
        authority: &RadioControlAuthority,
        cookie: u64,
        request: narf_wireless::MgmtTxRequest,
    ) -> Result<bool, WirelessError> {
        self.control(authority, Operation::Frame(cookie, request))
            .await
    }
    async fn register_mgmt_frame_radio_async(
        &self,
        authority: &RadioControlAuthority,
        frame_type: u16,
        prefix: &[u8],
    ) -> Result<(), i32> {
        if frame_type & !0xf0 != 0 || prefix.len() > 256 {
            return Err(22);
        }
        let request = self.request(authority).map_err(|_| 1)?;
        let old = { self.filters.lock().clone() };
        let retired: Vec<_> = old
            .into_iter()
            .filter(|filter| filter.request.check().is_err())
            .collect();
        let mut filters = self.filters.lock();
        // The radio lease serializes public registrations. Never silently
        // overwrite a reentrant/current successor from an older snapshot.
        filters.retain(|filter| !retired.iter().any(|old| Arc::ptr_eq(old, filter)));
        if filters.len() == 16 {
            return Err(16);
        }
        filters.push(Arc::new(Filter {
            frame_type,
            prefix: prefix.to_vec(),
            request,
        }));
        drop(filters);
        authority.check_for(self).map_err(|_| 1)
    }
    async fn delete_control_interface_async(
        &self,
        authority: &RadioControlAuthority,
    ) -> Result<RadioControlRetirement, WirelessError> {
        self.control(authority, Operation::Stop).await?;
        let metadata = self.metadata()?;
        // Native STOP and all actual DMA/queue references are terminal before
        // withdrawing the exact original typed registration. Keep generation
        // unchanged through the terminal receipt's final checked ACK.
        authority.retire_control(&metadata.cap)
    }
    fn release_control_metadata(&self) {
        // Only unpublished NEW or a terminal native DEL may call this. If a
        // violated caller reaches it with native work, retain metadata/owner
        // instead of dropping hardware reachability or guessing retirement.
        if self.active() {
            return;
        }
        if self.released.swap(true, Ordering::AcqRel) {
            return;
        }
        let retired = { self.role.lock().retire() };
        let _ = self
            .generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |epoch| {
                epoch.checked_add(1)
            });
        let metadata = { self.metadata.lock().take() };
        if let Some(metadata) = metadata {
            narf_wireless::registry::unregister_control(metadata.wdev, self);
            narf_net::registry().unregister_for_handle(&metadata.cap);
        }
        let filters = { core::mem::take(&mut *self.filters.lock()) };
        drop(filters);
        retired.notify();
    }
    fn get_wireless_info(&self) -> WirelessIfaceInfo {
        let mut info = self.parent.get_wireless_info();
        info.base_name = self.name.clone();
        info.base_mac = self.own;
        info.modes = narf_wireless::iface::WirelessModes::P2P;
        info
    }
    async fn scan(&self, _: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        Err(WirelessError::NotSupported)
    }
    async fn associate(&self, _: AssociateRequest) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }
    async fn disassociate(&self) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }
    async fn set_config(&self, _: WirelessConfig) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }
}
struct Registered(Arc<Child>);
impl Interface for Registered {
    fn name(&self) -> &str {
        self.0.name()
    }
    fn mac(&self) -> [u8; 6] {
        self.0.mac()
    }
    fn mtu(&self) -> u32 {
        0
    }
    fn link_up(&self) -> bool {
        false
    }
    fn control_namespace(&self) -> Option<u64> {
        self.0.control_namespace()
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        self.0.rx_ring()
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        self.0.tx_ring()
    }
}
