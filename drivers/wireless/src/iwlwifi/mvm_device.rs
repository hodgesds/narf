//! Native API77 netdev and driver-retained station/control work. External
//! waiters never own the hardware future or its logical/DMA cancellation.
use super::{
    mvm_boot::{LegacyReceive, Owner, Phase},
    mvm_publication::{Publication, Source},
    progress::{self, Work},
    runtime::Hardware,
};
use crate::firmware_asset::Asset;
use alloc::{
    boxed::Box,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    future::{poll_fn, Future},
    pin::{pin, Pin},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    task::{Context, Poll, Waker},
};
use narf_capabilities::{Cap, Grant};
use narf_ipc::{Consumer, Producer};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};
use narf_net::{Frame, Interface, RX_RING_N, TX_RING_N};
use narf_wireless::{
    reg::RegulatoryDomain, AssociateRequest, BssInfo, ScanRequest, WirelessConfig, WirelessError,
    WirelessIfaceInfo, WirelessNetIface,
};
use zeroize::{Zeroize, Zeroizing};

type Policy = Arc<dyn Fn() -> Result<RegulatoryDomain, &'static str> + Send + Sync>;
type Nonce = Arc<dyn Fn() -> Result<[u8; 32], &'static str> + Send + Sync>;
type Power = Arc<dyn Fn(&mut Owner) -> Result<(Asset, [u8; 32]), &'static str> + Send + Sync>;
#[derive(Clone)]
struct Environment {
    observation_clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    policy: Policy,
    nonce: Nonce,
    power: Power,
}
impl Environment {
    fn native() -> Self {
        Self {
            observation_clock: Arc::new(narf_time::now_cycles),
            policy: Arc::new(|| {
                narf_wireless::reg::db::get_domain().ok_or("MVM authenticated policy unavailable")
            }),
            nonce: Arc::new(super::security::fresh_nonce),
            power: Arc::new(|owner| {
                let request = owner.station_power_request()?;
                let authority = narf_firmware::trusted_loader_authority()
                    .and_then(|c| c.derive().ok())
                    .ok_or("MVM power loader authority unavailable")?;
                let source = crate::firmware_asset::load(&authority, &request.name, 64, true)
                    .map_err(|_| "MVM signed platform power source unavailable")?;
                Ok((source, request.binding))
            }),
        }
    }
}
struct State {
    owner: Option<Box<Owner>>,
    receive: Option<Producer<Frame, RX_RING_N>>,
    transmit: Option<Consumer<Frame, TX_RING_N>>,
    pending: Option<Frame>,
    scan_time: Option<u64>,
}
enum Operation {
    Scan(Vec<u8>, Vec<Vec<u8>>),
    Join(Join),
    Maintain,
    Transmit,
    Close,
}
struct Join {
    bssid: [u8; 6],
    ssid: Vec<u8>,
    channel: u8,
    elements: Vec<u8>,
    pmk: Option<Zeroizing<[u8; 32]>>,
}
enum Outcome {
    Scan(Vec<BssInfo>),
    Joined([u8; 6]),
    Done,
}
struct Completion {
    result: Option<Result<Outcome, &'static str>>,
    waiter: Option<Waker>,
}
type Reply = Arc<IrqSafeSpinLock<Completion>>;

pub(super) struct Device {
    me: Weak<Self>,
    state: Mutex<State>,
    control: Mutex<Option<Work>>,
    source: Source,
    environment: Environment,
    mac: [u8; 6],
    channels: Vec<u8>,
    wpa2: bool,
    ht20: bool,
    irq: Option<u8>,
    publication: AtomicBool,
    terminal: AtomicBool,
    stopping: Arc<AtomicBool>,
    generation: Arc<AtomicU64>,
    up: AtomicBool,
    port: AtomicBool,
    bssid: AtomicU64,
    fence: IrqSafeSpinLock<Option<Publication>>,
    admission: IrqSafeSpinLock<()>,
    rx: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
    #[cfg(any(test, feature = "kernel-test"))]
    test_name: IrqSafeSpinLock<Option<&'static str>>,
}
impl core::fmt::Debug for Device {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IwlMvmDevice")
            .field("mac", &self.mac)
            .field("up", &self.up)
            .finish()
    }
}
impl Device {
    pub(super) async fn power_request(
        &self,
    ) -> Result<super::Gen2TransmitPowerRequest, &'static str> {
        let mut state = self.state.lock().await;
        self.source.invoke(|| {
            state
                .owner
                .as_mut()
                .ok_or("MVM native owner absent")?
                .transmit_power_request()
        })
    }
    pub(super) async fn ht20_power_request(
        &self,
    ) -> Result<super::Gen2TransmitPowerRequest, &'static str> {
        let mut state = self.state.lock().await;
        self.source.invoke(|| {
            let owner = state.owner.as_mut().ok_or("MVM native owner absent")?;
            if !owner.supports_native_ht20() {
                return Err("MVM native HT20 contract unavailable");
            }
            owner.transmit_power_request_for(super::mvm_boot::PowerEmission::Ht20)
        })
    }
    pub(super) async fn initialize(
        hardware: Hardware,
        firmware: Asset,
    ) -> Result<Arc<Self>, &'static str> {
        let mut owner = Box::new(Owner::new(hardware, &firmware.bytes)?);
        let boot = owner.station_source(firmware.cap, false);
        {
            let mut future = pin!(owner.initialize());
            poll_fn(|cx| match boot.invoke(|| Ok(future.as_mut().poll(cx))) {
                Ok(result) => result,
                Err(error) => Poll::Ready(Err(error)),
            })
            .await?;
        }
        let source = owner.station_source(firmware.cap, true);
        source.invoke(|| Ok(()))?;
        Self::configured(owner, source, Environment::native())
    }
    fn configured(
        mut owner: Box<Owner>,
        source: Source,
        environment: Environment,
    ) -> Result<Arc<Self>, &'static str> {
        if owner.phase() != Phase::Configured || owner.station_failed() {
            return Err("MVM native configured owner missing");
        }
        let (mac, nvm) = owner.identity().ok_or("MVM native identity missing")?;
        let channels = nvm.channels.clone();
        let irq = owner.station_irq();
        let wpa2 = owner.station_wpa2_supported();
        let ht20 = owner.supports_native_ht20();
        let stopping = Arc::new(AtomicBool::new(false));
        owner.bind_station_stop(stopping.clone());
        Ok(Arc::new_cyclic(|me| Self {
            me: me.clone(),
            state: Mutex::new(State {
                owner: Some(owner),
                receive: None,
                transmit: None,
                pending: None,
                scan_time: None,
            }),
            control: Mutex::new(None),
            source,
            environment,
            mac,
            channels,
            wpa2,
            ht20,
            irq,
            publication: AtomicBool::new(false),
            terminal: AtomicBool::new(false),
            stopping,
            generation: Arc::new(AtomicU64::new(0)),
            up: AtomicBool::new(false),
            port: AtomicBool::new(false),
            bssid: AtomicU64::new(0),
            fence: IrqSafeSpinLock::new(None),
            admission: IrqSafeSpinLock::new(()),
            rx: IrqSafeSpinLock::new(None),
            tx: IrqSafeSpinLock::new(None),
            #[cfg(any(test, feature = "kernel-test"))]
            test_name: IrqSafeSpinLock::new(None),
        }))
    }
    fn down(&self, terminal: bool) {
        let _publication = self.admission.lock();
        self.down_locked(terminal);
    }
    fn down_current(&self, authority: &Publication) {
        let _publication = self.admission.lock();
        if authority.current() && !self.stopping.load(Ordering::Acquire) {
            self.down_locked(true);
        }
    }
    // Caller holds admission, serializing generation and ring publication.
    fn retire_port_locked(&self) {
        if let Some(next) = self.generation.load(Ordering::Acquire).checked_add(1) {
            self.generation.store(next, Ordering::Release);
        } else {
            self.terminal.store(true, Ordering::Release);
        }
        self.port.store(false, Ordering::Release);
        // The same admission lock serializes native RX publication. Do not
        // leave packets from this port available to a later station owner.
        if let Some(rx) = self.rx.lock().as_mut() {
            for _ in 0..RX_RING_N {
                if !matches!(rx.try_recv(), Ok(Some(_))) {
                    break;
                }
            }
        }
    }
    fn down_locked(&self, terminal: bool) {
        self.retire_port_locked();
        if terminal {
            self.terminal.store(true, Ordering::Release);
        }
        self.bssid.store(0, Ordering::Release);
        *self.fence.lock() = None;
        let was_up = self.up.swap(false, Ordering::AcqRel);
        narf_net::iface::set_link_metadata(self.name(), false, None, None);
        if was_up {
            narf_wireless::nl80211::notify_disconnect(self.name(), 1, false);
        }
    }
    fn admit_port(&self, owner: &mut Owner, bssid: [u8; 6]) -> Result<(), &'static str> {
        let power = owner.station_power_fence(&(self.environment.policy)()?)?;
        let _publication = self.admission.lock();
        if self.terminal.load(Ordering::Acquire) || self.stopping.load(Ordering::Acquire) {
            return Err("MVM station publication cancelled by close");
        }
        let generation = self
            .generation
            .load(Ordering::Acquire)
            .checked_add(1)
            .ok_or("MVM publication generation exhausted")?;
        self.generation.store(generation, Ordering::Release);
        let authority = Publication {
            source: self.source.clone(),
            power,
            generation: (self.generation.clone(), generation),
        };
        authority.invoke(&(self.environment.policy)()?, || {
            *self.fence.lock() = Some(authority.clone());
            self.bssid.store(
                u64::from_le_bytes([
                    bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], 0, 1,
                ]),
                Ordering::Release,
            );
            self.up.store(true, Ordering::Release);
            self.port.store(true, Ordering::Release);
            narf_net::iface::set_link_metadata(self.name(), true, None, None);
            Ok(())
        })
    }
    fn begin(&self, operation: Operation) -> Result<Reply, &'static str> {
        if !self.publication.load(Ordering::Acquire) {
            return Err("MVM native interface is not published");
        }
        if self.terminal.load(Ordering::Acquire) {
            return Err("MVM station is terminal");
        }
        if self.stopping.load(Ordering::Acquire) && !matches!(operation, Operation::Close) {
            return Err("MVM station is closing");
        }
        let mut slot = self.control.try_lock().ok_or("MVM control busy")?;
        if slot.is_some() {
            return Err("MVM control busy");
        }
        {
            let state = self.state.try_lock().ok_or("MVM control busy")?;
            let phase = state
                .owner
                .as_ref()
                .ok_or("MVM native owner absent")?
                .phase();
            if (matches!(operation, Operation::Scan(..) | Operation::Join(_))
                && phase != Phase::Configured)
                || (matches!(operation, Operation::Maintain | Operation::Transmit)
                    && phase != Phase::DataPrepared)
            {
                return Err("MVM control busy");
            }
        }
        let device = self.me.upgrade().ok_or("MVM native owner disappeared")?;
        let reply = Arc::new(IrqSafeSpinLock::new(Completion {
            result: None,
            waiter: None,
        }));
        let result_slot = reply.clone();
        let closing = matches!(operation, Operation::Close);
        let port_commit = matches!(operation, Operation::Join(_) | Operation::Maintain);
        let channels = match &operation {
            Operation::Scan(channels, _) => channels.clone(),
            Operation::Join(request) => alloc::vec![request.channel],
            _ => Vec::new(),
        };
        let transmit_policy = matches!(operation, Operation::Join(_));
        let qualification = if matches!(operation, Operation::Maintain | Operation::Transmit) {
            self.fence.lock().clone()
        } else {
            None
        };
        *slot = Some(Work::new(async move {
            let mut state = device.state.lock().await;
            let result = {
                let mut future = pin!(device.execute(&mut state, operation));
                poll_fn(|cx| {
                    match device.source.invoke(|| {
                        if closing {
                            return Ok(future.as_mut().poll(cx));
                        }
                        let domain = (device.environment.policy)()?;
                        if channels.iter().any(|&channel| {
                            if transmit_policy {
                                super::connection::host_channel_power(&domain, channel, true)
                                    .is_none()
                            } else {
                                !super::mvm_boot::passive_channel(&domain, channel)
                            }
                        }) {
                            return Err("MVM live operation channel policy revoked");
                        }
                        if let Some(qualification) = qualification
                            .as_ref()
                            .filter(|_| !device.stopping.load(Ordering::Acquire))
                        {
                            qualification
                                .power
                                .invoke(&domain, || Ok(future.as_mut().poll(cx)))
                        } else {
                            Ok(future.as_mut().poll(cx))
                        }
                    }) {
                        Ok(result) => result,
                        Err(error) => Poll::Ready(Err(error)),
                    }
                })
                .await
            };
            let owner = state.owner.as_mut().unwrap();
            let result = match result {
                Ok(_) if !closing && device.stopping.load(Ordering::Acquire) => Ok(Outcome::Done),
                Ok(Outcome::Joined(bssid)) => {
                    device.admit_port(owner, bssid).map(|()| Outcome::Done)
                }
                Ok(Outcome::Done)
                    if !closing && port_commit && owner.phase() == Phase::DataPrepared =>
                {
                    let bssid = owner
                        .prepared_legacy_data()
                        .ok_or("MVM terminal data identity missing")
                        .map(|s| s.bssid);
                    bssid
                        .and_then(|bssid| device.admit_port(owner, bssid))
                        .map(|()| Outcome::Done)
                }
                result => result,
            };
            if result.is_err() {
                // Missing board input before I/O remains retryable. Any
                // uncertain native transaction stays quarantined/pinned.
                if owner.phase() != Phase::Configured || device.source.invoke(|| Ok(())).is_err() {
                    owner.station_fail();
                    device.down(true);
                    state.pending = None;
                }
            } else if closing {
                let _publication = device.admission.lock();
                device.stopping.store(false, Ordering::Release);
            }
            let wake = {
                let mut completion = result_slot.lock();
                completion.result = Some(result);
                completion.waiter.take()
            };
            if let Some(wake) = wake {
                wake.wake();
            }
        }));
        Ok(reply)
    }
    async fn wait(&self, reply: Reply) -> Result<Outcome, &'static str> {
        poll_fn(|cx| {
            {
                let mut completion = reply.lock();
                completion.waiter = Some(cx.waker().clone());
            }
            let _ = progress::poll_work(&self.control, cx);
            if let Some(result) = reply.lock().result.take() {
                Poll::Ready(result)
            } else {
                Poll::Pending
            }
        })
        .await
    }
    async fn execute(
        &self,
        state: &mut State,
        operation: Operation,
    ) -> Result<Outcome, &'static str> {
        let State {
            owner,
            pending,
            scan_time,
            ..
        } = state;
        let owner = owner.as_mut().ok_or("MVM native owner absent")?;
        match operation {
            Operation::Scan(channels, ssids) => {
                // A beacon can arrive at any point during this bounded scan.
                // Start time conservatively bounds every retained observation;
                // completion must not refresh an early beacon's age.
                let started = (self.environment.observation_clock)();
                *scan_time = None;
                let mut result = owner
                    .station_scan(&channels, &(self.environment.policy)()?)
                    .await?;
                let current = (self.environment.policy)()?;
                if channels
                    .iter()
                    .any(|&ch| !super::mvm_boot::passive_channel(&current, ch))
                {
                    return Err("MVM scan policy tightened before result publication");
                }
                result.retain(|bss| {
                    ssids.is_empty() || ssids.iter().any(Vec::is_empty) || ssids.contains(&bss.ssid)
                });
                *scan_time = Some(started);
                Ok(Outcome::Scan(result))
            }
            Operation::Join(request) => {
                if scan_time.is_none_or(|time| {
                    (self.environment.observation_clock)().wrapping_sub(time)
                        > narf_time::wall::ns_to_cycles(10_000_000_000)
                }) {
                    return Err("MVM scan observation expired");
                }
                owner.select_station_offer(
                    request.bssid,
                    &request.ssid,
                    request.channel,
                    &request.elements,
                    request.pmk.is_some(),
                )?;
                let (source, binding) = (self.environment.power)(owner)?;
                owner
                    .station_join(
                        request.bssid,
                        &request.ssid,
                        request.channel,
                        &request.elements,
                        request.pmk,
                        source,
                        binding,
                        self.stopping.clone(),
                        || (self.environment.policy)(),
                        || (self.environment.nonce)(),
                    )
                    .await?;
                Ok(Outcome::Joined(request.bssid))
            }
            Operation::Maintain => {
                owner
                    .station_security(
                        || (self.environment.nonce)(),
                        || (self.environment.policy)(),
                    )
                    .await?;
                Ok(Outcome::Done)
            }
            Operation::Transmit => {
                let frame = pending.take().ok_or("MVM pending Ethernet missing")?;
                if self.stopping.load(Ordering::Acquire) {
                    return Err("MVM data stopped before native publication");
                }
                owner
                    .station_send(frame.payload(), || (self.environment.policy)())
                    .await?;
                Ok(Outcome::Done)
            }
            Operation::Close => {
                *pending = None;
                if let Some(tx) = state.transmit.as_mut() {
                    for _ in 0..TX_RING_N {
                        if !matches!(tx.try_recv(), Ok(Some(_))) {
                            break;
                        }
                    }
                }
                owner.station_close().await?;
                Ok(Outcome::Done)
            }
        }
    }
    fn request_close(&self) {
        {
            let _publication = self.admission.lock();
            self.stopping.store(true, Ordering::Release);
        }
        self.down(false);
        let _ = self.begin(Operation::Close);
    }
    fn step(&self, cx: Option<&mut Context<'_>>) -> Vec<(Vec<u8>, Publication)> {
        let mut fallback = Context::from_waker(Waker::noop());
        if progress::poll_work(&self.control, cx.unwrap_or(&mut fallback)).is_pending() {
            return Vec::new();
        }
        if self.terminal.load(Ordering::Acquire) {
            return Vec::new();
        }
        if self.stopping.load(Ordering::Acquire) {
            let _ = self.begin(Operation::Close);
            return Vec::new();
        }
        let Some(mut state) = self.state.try_lock() else {
            return Vec::new();
        };
        let result = (|| {
            let owner = state.owner.as_mut().ok_or("MVM retained owner missing")?;
            self.source.invoke(|| Ok(()))?;
            if owner.phase() != Phase::DataPrepared {
                owner.station_poll_idle()?;
                return Ok((Vec::new(), false, false));
            }
            let mut output = Vec::new();
            for _ in 0..64 {
                match owner.station_receive(|| (self.environment.policy)())? {
                    Some(LegacyReceive::Ethernet(frame)) => output.push(frame),
                    Some(LegacyReceive::Eapol(_)) => {
                        return Err("MVM secured station lost its native RSNA owner")
                    }
                    None => break,
                }
            }
            if owner.station_needs_security() {
                for frame in output.into_iter().rev() {
                    owner.station_defer_packet(frame);
                }
                let _publication = self.admission.lock();
                self.retire_port_locked();
                return Ok((Vec::new(), true, false));
            }
            if owner.station_expired() {
                return Err("MVM current AP beacon/data liveness expired");
            }
            let authority = Publication {
                source: self.source.clone(),
                power: owner.station_power_fence(&(self.environment.policy)()?)?,
                generation: (
                    self.generation.clone(),
                    self.generation.load(Ordering::Acquire),
                ),
            };
            for bytes in &output {
                if let (Some(rx), Ok(memory)) =
                    (&mut state.receive, super::runtime::dma_alloc(bytes.len()))
                {
                    let mut frame = Frame::new(memory, bytes.len() as u32);
                    frame.payload_mut().copy_from_slice(bytes);
                    let _publication = self.admission.lock();
                    authority.invoke(&(self.environment.policy)()?, || {
                        if !self.port.load(Ordering::Acquire)
                            || self.stopping.load(Ordering::Acquire)
                        {
                            return Err("MVM RX publication closed");
                        }
                        let _ = rx.try_send(frame);
                        Ok(())
                    })?;
                }
            }
            if state.pending.is_none() {
                if let Some(tx) = &mut state.transmit {
                    for _ in 0..16 {
                        let Some(frame) =
                            tx.try_recv().map_err(|_| "MVM Ethernet TX ring failed")?
                        else {
                            break;
                        };
                        if admitted(frame.payload(), self.mac, frame.tx_meta()) {
                            state.pending = Some(frame);
                            break;
                        }
                    }
                }
            }
            let send = state.pending.is_some();
            Ok((
                output
                    .into_iter()
                    .map(|frame| (frame, authority.clone()))
                    .collect(),
                false,
                send,
            ))
        })();
        match result {
            Ok((output, maintenance, transmit)) => {
                drop(state);
                if maintenance {
                    let _ = self.begin(Operation::Maintain);
                } else if transmit {
                    let _ = self.begin(Operation::Transmit);
                }
                output
            }
            Err(_) => {
                if self.stopping.load(Ordering::Acquire) {
                    // Close won the publication race. Its retained native
                    // cleanup owns the existing transaction and DMA.
                    drop(state);
                    let _ = self.begin(Operation::Close);
                    return Vec::new();
                }
                state.owner.as_mut().unwrap().station_fail();
                drop(state);
                self.down(true);
                Vec::new()
            }
        }
    }
    fn drain(&self) -> bool {
        self.dispatch(self.step(None))
    }
    fn dispatch(&self, output: Vec<(Vec<u8>, Publication)>) -> bool {
        let progressed = !output.is_empty();
        for (mut bytes, authority) in output {
            if !authority.current() {
                continue;
            }
            let result = (self.environment.policy)().and_then(|domain| {
                authority.invoke(&domain, || {
                    if self.terminal.load(Ordering::Acquire)
                        || self.stopping.load(Ordering::Acquire)
                        || !self.port.load(Ordering::Acquire)
                    {
                        return Err("MVM stack RX closed");
                    }
                    // No owner/ring/admission guard survives this callback.
                    narf_net::iface::on_rx_frame_from(self.name(), &mut bytes);
                    Ok(())
                })
            });
            if result.is_err() {
                self.down_current(&authority);
                break;
            }
        }
        progressed
    }
    fn enqueue(&self, bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
        if !admitted(bytes, self.mac, meta) {
            return Err(());
        }
        let authority = self.fence.lock().clone().ok_or(())?;
        let result = (|| {
            let memory = super::runtime::dma_alloc(bytes.len())?;
            let mut frame = Frame::new(memory, bytes.len() as u32);
            frame.payload_mut().copy_from_slice(bytes);
            let _publication = self.admission.lock();
            authority.invoke(&(self.environment.policy)()?, || {
                if self.terminal.load(Ordering::Acquire)
                    || self.stopping.load(Ordering::Acquire)
                    || !self.port.load(Ordering::Acquire)
                {
                    return Err("MVM TX publication closed");
                }
                Ok(self
                    .tx
                    .lock()
                    .as_mut()
                    .ok_or("MVM TX ring absent")?
                    .try_send(frame)
                    .map_err(|_| ()))
            })
        })();
        match result {
            Ok(result) => result,
            Err(_) => {
                self.down_current(&authority);
                Err(())
            }
        }
    }
    pub(super) fn start_pumps(self: &Arc<Self>) -> Result<(), &'static str> {
        let authority = narf_net::trusted_net_authority()
            .and_then(|c| c.derive().ok())
            .ok_or("MVM network authority unavailable")?;
        self.publish(&authority, true)
    }
    fn publish(
        self: &Arc<Self>,
        authority: &Cap<narf_net::NetIface, Grant>,
        worker: bool,
    ) -> Result<(), &'static str> {
        self.publication
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "MVM publication already attempted")?;
        let mut active = ACTIVE.lock();
        if active.is_some()
            || narf_net::iface::lookup(self.name()).is_some()
            || narf_wireless::registry::list()
                .iter()
                .any(|i| i.name() == self.name())
        {
            return Err("MVM interface name already occupied");
        }
        let mut state = self.state.try_lock().ok_or("MVM unpublished state busy")?;
        let (rxp, rxc) = narf_ipc::channel::<Frame, RX_RING_N>();
        let (txp, txc) = narf_ipc::channel::<Frame, TX_RING_N>();
        self.source.invoke(|| {
            narf_net::registry()
                .register(authority, Registered(self.clone()))
                .map(|_| ())
                .map_err(|_| "MVM net capability registration failed")?;
            state.receive = Some(rxp);
            state.transmit = Some(txc);
            *self.rx.lock() = Some(rxc);
            *self.tx.lock() = Some(txp);
            *active = Some(self.clone());
            drop(state);
            drop(active);
            narf_net::iface::register(self.name(), self.mac, send_frame);
            narf_net::iface::set_link_metadata(self.name(), false, None, None);
            narf_net::iface::set_driver_info(
                self.name(),
                "iwlwifi-mvm",
                None,
                alloc::string::String::new(),
            );
            narf_net::iface::install_rx_drain(drain_network);
            narf_wireless::registry::register(self.clone());
            Ok(())
        })?;
        if worker {
            let device = self.clone();
            narf_scheduler::spawn(async move {
                device.pump().await;
            });
        }
        Ok(())
    }
    async fn pump(self: Arc<Self>) {
        loop {
            let mut activity = super::iwl_msix::Activity::new(self.irq, 20);
            let frames = poll_fn(|cx| {
                let frames = self.step(Some(cx));
                if !frames.is_empty() || Pin::new(&mut activity).poll(cx).is_ready() {
                    Poll::Ready(frames)
                } else {
                    Poll::Pending
                }
            })
            .await;
            self.dispatch(frames);
        }
    }
}
impl Interface for Device {
    fn name(&self) -> &str {
        #[cfg(any(test, feature = "kernel-test"))]
        if let Some(name) = *self.test_name.lock() {
            return name;
        }
        super::iwl_ifname()
    }
    fn mac(&self) -> [u8; 6] {
        self.mac
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        self.up.load(Ordering::Acquire)
            && self.port.load(Ordering::Acquire)
            && !self.terminal.load(Ordering::Acquire)
            && !self.stopping.load(Ordering::Acquire)
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx
    }
}
fn error(error: &'static str) -> WirelessError {
    match error {
        "MVM control busy" | "MVM station is closing" => WirelessError::Busy,
        _ => WirelessError::HardwareError,
    }
}
#[async_trait::async_trait]
impl WirelessNetIface for Device {
    fn supports_handshake_offload(&self) -> bool {
        self.wpa2
    }
    fn reports_disconnect_events(&self) -> bool {
        true
    }
    fn phy_capabilities(&self, band_mhz: u32) -> Option<narf_wireless::iface::PhyCapabilities> {
        (self.ht20 && matches!(band_mhz, 2400 | 5000)).then(|| {
            narf_wireless::iface::PhyCapabilities {
                ht: narf_wireless::association::phy::LocalHt::siso20(true, true).capability_body(),
                vht: None,
            }
        })
    }
    fn get_wireless_info(&self) -> WirelessIfaceInfo {
        use narf_wireless::iface::*;
        WirelessIfaceInfo {
            base_name: self.name().into(),
            base_mac: self.mac,
            bands: [2400, 5000]
                .into_iter()
                .map(|freq_mhz| WirelessBand {
                    freq_mhz,
                    channels: self
                        .channels
                        .iter()
                        .copied()
                        .filter(|&ch| (ch <= 14) == (freq_mhz == 2400))
                        .map(u32::from)
                        .collect(),
                })
                .collect(),
            modes: WirelessModes::STATION,
            hw_caps: HwCaps {
                ht_supported: self.ht20,
                vht_supported: false,
                he_supported: false,
                eht_supported: false,
            },
        }
    }
    fn scan_information_elements(&self, bssid: [u8; 6]) -> Option<Vec<u8>> {
        self.state
            .try_lock()?
            .owner
            .as_ref()?
            .station_information(bssid)
    }
    async fn scan(&self, request: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        if request.active
            || request.random_mac.is_some()
            || request.colocated_6ghz
            || request.duration_mandatory
            || !request.extra_ies.is_empty()
            || request.ssids.len() > 20
            || request.ssids.iter().any(|s| s.len() > 32)
            || request.duration_tu.is_some()
        {
            return Err(WirelessError::NotSupported);
        }
        let channels = if !request.frequencies_mhz.is_empty() {
            let mut channels = Vec::new();
            for frequency in &request.frequencies_mhz {
                let ch = self
                    .channels
                    .iter()
                    .copied()
                    .find(|&ch| channel_frequency(ch) == *frequency)
                    .ok_or(WirelessError::InvalidArgs)?;
                if channels.contains(&ch) {
                    return Err(WirelessError::InvalidArgs);
                }
                channels.push(ch);
            }
            if !request.channels.is_empty()
                && (request.channels.len() != channels.len()
                    || request
                        .channels
                        .iter()
                        .any(|ch| u8::try_from(*ch).map_or(true, |ch| !channels.contains(&ch))))
            {
                return Err(WirelessError::InvalidArgs);
            }
            channels
        } else if request.channels.is_empty() {
            self.channels.clone()
        } else {
            let mut channels = Vec::new();
            for channel in request.channels {
                let ch = u8::try_from(channel).map_err(|_| WirelessError::InvalidArgs)?;
                if !self.channels.contains(&ch) || channels.contains(&ch) {
                    return Err(WirelessError::InvalidArgs);
                }
                channels.push(ch);
            }
            channels
        };
        let reply = self
            .begin(Operation::Scan(channels, request.ssids))
            .map_err(error)?;
        match self.wait(reply).await.map_err(error)? {
            Outcome::Scan(result) => Ok(result),
            _ => Err(WirelessError::HardwareError),
        }
    }
    async fn associate(&self, mut request: AssociateRequest) -> Result<(), WirelessError> {
        let channel = u8::try_from(request.channel).map_err(|_| WirelessError::InvalidArgs)?;
        let frequency = channel_frequency(channel);
        if !self.channels.contains(&channel)
            || request.frequency_mhz != frequency
            || request.ssid.is_empty()
            || request.ssid.len() > 32
            || request.bssid == [0; 6]
            || request.bssid[0] & 1 != 0
        {
            return Err(WirelessError::InvalidArgs);
        }
        if !matches!(
            request.security,
            narf_wireless::SecurityConfig::Open | narf_wireless::SecurityConfig::Wpa2 { .. }
        ) {
            return Err(WirelessError::NotSupported);
        }
        if matches!(request.security, narf_wireless::SecurityConfig::Wpa2 { .. }) && !self.wpa2 {
            return Err(WirelessError::NotSupported);
        }
        let pmk = match &mut request.security {
            narf_wireless::SecurityConfig::Open => None,
            narf_wireless::SecurityConfig::Wpa2 { psk } => {
                let key = Zeroizing::new(*psk);
                psk.zeroize();
                Some(key)
            }
            _ => return Err(WirelessError::NotSupported),
        };
        let join = Join {
            bssid: request.bssid,
            ssid: request.ssid,
            channel,
            elements: request.ie,
            pmk,
        };
        let reply = self.begin(Operation::Join(join)).map_err(error)?;
        self.wait(reply).await.map_err(error).map(|_| ())
    }
    async fn disassociate(&self) -> Result<(), WirelessError> {
        self.request_close();
        poll_fn(|cx| {
            let _ = progress::poll_work(&self.control, cx);
            if self.terminal.load(Ordering::Acquire) {
                return Poll::Ready(Err(WirelessError::HardwareError));
            }
            if !self.stopping.load(Ordering::Acquire) {
                return Poll::Ready(Ok(()));
            }
            let _ = self.begin(Operation::Close);
            cx.waker().wake_by_ref();
            Poll::Pending
        })
        .await
    }
    fn connected_bssid(&self) -> Option<[u8; 6]> {
        let v = self.bssid.load(Ordering::Acquire);
        (v >> 56 != 0).then(|| core::array::from_fn(|i| (v >> (8 * i)) as u8))
    }
    async fn set_config(&self, config: WirelessConfig) -> Result<(), WirelessError> {
        if config.tx_power_dbm.is_some() || config.channel != 0 {
            return Err(WirelessError::NotSupported);
        }
        self.source.invoke(|| Ok(())).map_err(error)
    }
}
struct Registered(Arc<Device>);
fn admitted(bytes: &[u8], mac: [u8; 6], meta: narf_net::TxMeta) -> bool {
    (14..=1514).contains(&bytes.len())
        && bytes[6..12] == mac
        && u16::from_be_bytes([bytes[12], bytes[13]]) >= 0x600
        && !matches!(
            u16::from_be_bytes([bytes[12], bytes[13]]),
            0x888e | 0x80f3 | 0x8137
        )
        && meta.csum_l4.is_none()
        && meta.tso_mss.is_none()
        && meta.vlan_tag.is_none()
}
fn channel_frequency(channel: u8) -> u32 {
    if channel == 14 {
        2484
    } else if channel <= 13 {
        2407 + u32::from(channel) * 5
    } else {
        5000 + u32::from(channel) * 5
    }
}
impl Interface for Registered {
    fn name(&self) -> &str {
        self.0.name()
    }
    fn mac(&self) -> [u8; 6] {
        self.0.mac()
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        self.0.link_up()
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        self.0.rx_ring()
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        self.0.tx_ring()
    }
}
static ACTIVE: IrqSafeSpinLock<Option<Arc<Device>>> = IrqSafeSpinLock::new(None);
fn send_frame(bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    ACTIVE.lock().clone().ok_or(())?.enqueue(bytes, meta)
}
fn drain_network() -> bool {
    let device = ACTIVE.lock().clone();
    device.is_some_and(|d| d.drain())
}
#[cfg(any(test, feature = "kernel-test"))]
#[path = "mvm_device_tests.rs"]
mod tests;
