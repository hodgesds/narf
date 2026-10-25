// SPDX-License-Identifier: GPL-2.0-or-later
//! Common station publication for booted SDIO-BCDC and PCIe-msgbuf owners.
//! SDIO/gSPI discovery supplies a PacketTransport; PCIe supplies its retained runtime.

use super::{
    fullmac::{Family, Fullmac},
    runtime::{Error, Runtime},
    station::Station,
    PacketTransport,
};
#[cfg(any(test, feature = "kernel-test"))]
use alloc::vec;
use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use narf_ipc::{Consumer, Producer};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};
use narf_net::{Frame, Interface, RX_RING_N, TX_RING_N};
use narf_wireless::{
    AssociateRequest, BssInfo, ScanRequest, WirelessConfig, WirelessError, WirelessNetIface,
};

struct State<R: Fullmac> {
    station: Station<R>,
    rx: Producer<Frame, RX_RING_N>,
    tx: Consumer<Frame, TX_RING_N>,
    pending: Option<PendingTx>,
}
struct PendingTx {
    frame: Frame,
    deadline: narf_time::Deadline,
}
impl<R: Fullmac> State<R> {
    fn clear_transmit(&mut self) {
        self.pending = None;
        // A ring has finite capacity. Bound cleanup even if its producer
        // runs concurrently; a disconnected interface admits no new TX.
        for _ in 0..TX_RING_N {
            if !matches!(self.tx.try_recv(), Ok(Some(_))) {
                break;
            }
        }
    }

    /// One synchronous progress step, shared by the timer and kernel
    /// network drains. Waiting for credits never retains the async mutex.
    fn progress(&mut self) -> Result<(), Error> {
        if let Err(error) = self.station.poll() {
            self.clear_transmit();
            return Err(error);
        }
        if self.station.bssid.is_none() {
            self.clear_transmit();
            return Ok(());
        }
        if self.pending.is_none() {
            if let Ok(Some(frame)) = self.tx.try_recv() {
                if transmit_admitted(frame.payload(), self.station.mac) {
                    self.pending = Some(PendingTx {
                        frame,
                        deadline: narf_time::Deadline::after_ms(2000),
                    });
                }
            }
        }
        let Some(pending) = self.pending.as_ref() else {
            return Ok(());
        };
        let result = if pending.deadline.expired() {
            Err(Error::Timeout)
        } else {
            self.station.send_data(pending.frame.payload(), 0)
        };
        match result {
            Ok(()) => self.pending = None,
            Err(Error::Busy) => {}
            Err(error) => {
                self.station.runtime.fail();
                self.station.bssid = None;
                self.clear_transmit();
                return Err(error);
            }
        }
        Ok(())
    }
}
pub struct Device<R: Fullmac> {
    state: Mutex<State<R>>,
    name: String,
    mac: [u8; 6],
    channels: Vec<u32>,
    supplicant: bool,
    up: AtomicBool,
    // Requested PS policy: 0=awake, 1=PM_FAST, 2=terminal failure. The
    // retained worker serializes firmware commands with scan/join/packets.
    power_save: AtomicU8,
    bssid: AtomicU64,
    rx: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
}
impl<R: Fullmac> core::fmt::Debug for Device<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FullmacDevice")
            .field("name", &self.name)
            .field("mac", &self.mac)
            .finish_non_exhaustive()
    }
}

trait Endpoint: Send + Sync {
    fn enqueue(&self, bytes: &[u8]) -> Result<(), ()>;
    fn drain(&self) -> bool;
}
static ACTIVE_SDIO: IrqSafeSpinLock<Option<Arc<dyn Endpoint>>> = IrqSafeSpinLock::new(None);
static ACTIVE_PCIE: IrqSafeSpinLock<Option<Arc<dyn Endpoint>>> = IrqSafeSpinLock::new(None);
fn active_slot(family: Family) -> &'static IrqSafeSpinLock<Option<Arc<dyn Endpoint>>> {
    match family {
        Family::Sdio => &ACTIVE_SDIO,
        Family::Pcie => &ACTIVE_PCIE,
    }
}

/// Attach to a platform-owned, already booted FIFO adapter. All firmware
/// initialization succeeds before any netdev, frame rings or worker appears.
/// There is deliberately no SDIO/gSPI auto-probe without a live host driver.
pub async fn attach<T: PacketTransport + 'static>(
    name: &str,
    transport: T,
    clm: &[u8],
) -> Result<Arc<Device<Runtime<T>>>, Error> {
    attach_runtime(name, Runtime::new(transport), clm).await
}
/// Common station publication for an already booted, retained firmware runtime.
/// All initialization/key capabilities and authenticated policy checks still run.
pub async fn attach_runtime<R: Fullmac + 'static>(
    name: &str,
    runtime: R,
    clm: &[u8],
) -> Result<Arc<Device<R>>, Error> {
    let slot = active_slot(R::FAMILY);
    if name.is_empty()
        || name.len() > 15
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        || slot.lock().is_some()
        || narf_net::iface::lookup(name).is_some()
        || narf_wireless::registry::list()
            .iter()
            .any(|iface| iface.name() == name)
    {
        return Err(Error::Busy);
    }
    let authority = narf_net::trusted_net_authority()
        .and_then(|cap| cap.derive().ok())
        .ok_or(Error::Unsupported)?;
    narf_wireless::reg::db::ensure_snapshot().map_err(|_| Error::Authority)?;
    let station =
        Station::initialize_live(runtime, clm, Arc::new(super::station::GlobalPolicy)).await?;
    let (rx_producer, rx_consumer) = narf_ipc::channel();
    let (tx_producer, tx_consumer) = narf_ipc::channel();
    let device = Arc::new(Device {
        name: name.into(),
        mac: station.mac,
        channels: station.channels.iter().map(|&ch| u32::from(ch)).collect(),
        supplicant: station.supplicant,
        state: Mutex::new(State {
            station,
            rx: rx_producer,
            tx: tx_consumer,
            pending: None,
        }),
        up: AtomicBool::new(false),
        power_save: AtomicU8::new(0),
        bssid: AtomicU64::new(0),
        rx: IrqSafeSpinLock::new(Some(rx_consumer)),
        tx: IrqSafeSpinLock::new(Some(tx_producer)),
    });
    {
        let mut active = slot.lock();
        // Firmware setup awaited bus transactions. Another driver may have
        // claimed this name in that interval; never replace its netdev.
        if active.is_some()
            || narf_net::iface::lookup(name).is_some()
            || narf_wireless::registry::list()
                .iter()
                .any(|iface| iface.name() == name)
        {
            return Err(Error::Busy);
        }
        // Registration may reject a revoked authority or duplicate name.
        // Fail before publishing ACTIVE, a kernel netdev, or any worker.
        narf_net::registry()
            .register(&authority, Registered(device.clone()))
            .map_err(|error| match error {
                narf_net::RegisterError::DuplicateName => Error::Busy,
                narf_net::RegisterError::AuthorityRevoked => Error::Unsupported,
            })?;
        *active = Some(device.clone());
    }
    let send = match R::FAMILY {
        Family::Sdio => send_sdio as fn(&[u8], narf_net::TxMeta) -> Result<(), ()>,
        Family::Pcie => send_pcie,
    };
    narf_net::iface::register(name, device.mac, send);
    narf_net::iface::set_link_state(name, false);
    narf_net::iface::install_rx_drain(drain);
    narf_wireless::registry::register(device.clone());
    let worker = device.clone();
    narf_scheduler::spawn(async move {
        worker.receive_worker().await;
    });
    Ok(device)
}

impl<R: Fullmac + 'static> Device<R> {
    fn link(&self, peer: Option<[u8; 6]>) {
        let mut packed = [0; 8];
        if let Some(peer) = peer {
            packed[..6].copy_from_slice(&peer);
            packed[7] = 1;
        }
        self.bssid
            .store(u64::from_le_bytes(packed), Ordering::Release);
        let up = peer.is_some();
        let was_up = self.up.swap(up, Ordering::AcqRel);
        // Physical carrier preserves operator-controlled IFF_UP and never
        // invokes an administrative open/stop hook under retained locks.
        narf_net::iface::set_link_metadata(&self.name, up, None, None);
        if was_up && !up {
            narf_wireless::nl80211::notify_disconnect(&self.name, 1, false);
        }
    }

    fn step(&self) -> Vec<Vec<u8>> {
        let Some(mut state) = self.state.try_lock() else {
            return Vec::new();
        };
        if state.progress().is_err() {
            self.power_save.store(2, Ordering::Release);
            self.link(None);
            return Vec::new();
        }
        self.link(state.station.bssid);
        let mut output = Vec::new();
        for _ in 0..32 {
            if state.station.check_connection_policy().is_err() {
                state.clear_transmit();
                self.power_save.store(2, Ordering::Release);
                self.link(None);
                return Vec::new();
            }
            let Some(bytes) = state.station.runtime.pop_data() else {
                break;
            };
            if !self.up.load(Ordering::Acquire) || !receive_admitted(&bytes, self.mac) {
                continue;
            }
            if let Ok(buffer) =
                narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0)
            {
                let mut frame = Frame::new(buffer, bytes.len() as u32);
                frame.payload_mut().copy_from_slice(&bytes);
                let _ = state.rx.try_send(frame);
            }
            output.push(bytes);
        }
        output
    }

    async fn apply_power_save(&self) {
        let policy = self.power_save.load(Ordering::Acquire);
        if policy > 1 {
            return;
        }
        let Some(mut state) = self.state.try_lock() else {
            return;
        };
        if state.station.power_save() == (policy == 1) {
            return;
        }
        if let Err(error) = state.station.set_power_save(policy == 1).await {
            self.power_save.store(2, Ordering::Release);
            state.clear_transmit();
            self.link(None);
            narf_console::klog!(
                "{}: FullMAC power-save transition failed: {:?}\n",
                self.name,
                error
            );
        } else if state.station.bssid.is_none() {
            // A concurrent disconnect closes host admission before waiting
            // for this mutex. A PS receipt has no authority to reopen it
            // using the station's earlier peer; it may only publish loss.
            self.link(None);
        }
    }

    async fn receive_worker(self: Arc<Self>) {
        loop {
            for mut frame in self.step() {
                narf_net::iface::on_rx_frame_from(&self.name, &mut frame);
            }
            self.apply_power_save().await;
            narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
        }
    }
}
impl<R: Fullmac + 'static> Endpoint for Device<R> {
    fn enqueue(&self, bytes: &[u8]) -> Result<(), ()> {
        if !self.up.load(Ordering::Acquire) || !transmit_admitted(bytes, self.mac) {
            return Err(());
        }
        let buffer = narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0)
            .map_err(|_| ())?;
        let mut frame = Frame::new(buffer, bytes.len() as u32);
        frame.payload_mut().copy_from_slice(bytes);
        self.tx
            .lock()
            .as_mut()
            .ok_or(())?
            .try_send(frame)
            .map_err(|_| ())
    }
    fn drain(&self) -> bool {
        let frames = self.step();
        let progress = !frames.is_empty();
        for mut frame in frames {
            narf_net::iface::on_rx_frame_from(&self.name, &mut frame);
        }
        progress
    }
}
fn send_sdio(bytes: &[u8], _: narf_net::TxMeta) -> Result<(), ()> {
    let active = ACTIVE_SDIO.lock().clone().ok_or(())?;
    active.enqueue(bytes)
}
fn send_pcie(bytes: &[u8], _: narf_net::TxMeta) -> Result<(), ()> {
    let active = ACTIVE_PCIE.lock().clone().ok_or(())?;
    active.enqueue(bytes)
}
fn drain() -> bool {
    let owners = [ACTIVE_SDIO.lock().clone(), ACTIVE_PCIE.lock().clone()];
    let mut progress = false;
    for owner in owners.into_iter().flatten() {
        progress |= owner.drain();
    }
    progress
}

impl<R: Fullmac + 'static> Interface for Device<R> {
    fn name(&self) -> &str {
        &self.name
    }
    fn mac(&self) -> [u8; 6] {
        self.mac
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        self.up.load(Ordering::Acquire)
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx
    }
}
#[async_trait::async_trait]
impl<R: Fullmac + 'static> WirelessNetIface for Device<R> {
    fn power_save_default(&self) -> Option<bool> {
        Some(false)
    }

    fn set_power_save(&self, enabled: bool) -> Result<(), i32> {
        // The synchronous control plane accepts a desired policy, like the
        // ath11k control worker. Coalesce changes while an IOCTL is in flight;
        // never overwrite terminal failure with a new request.
        self.power_save
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                (old < 2).then_some(u8::from(enabled))
            })
            .map(|_| ())
            .map_err(|_| 19) // ENODEV
    }

    fn max_scan_ssids(&self) -> u8 {
        16
    }

    fn supports_handshake_offload(&self) -> bool {
        self.supplicant
    }
    fn reports_disconnect_events(&self) -> bool {
        true
    }
    fn connected_bssid(&self) -> Option<[u8; 6]> {
        let packed = self.bssid.load(Ordering::Acquire).to_le_bytes();
        (packed[7] != 0).then(|| packed[..6].try_into().unwrap())
    }
    fn scan_information_elements(&self, bssid: [u8; 6]) -> Option<Vec<u8>> {
        self.state
            .try_lock()?
            .station
            .cache
            .iter()
            .find(|b| b.info.bssid == bssid)
            .map(|b| b.ies.clone())
    }
    fn get_wireless_info(&self) -> narf_wireless::WirelessIfaceInfo {
        use narf_wireless::iface::*;
        let mut bands = Vec::new();
        for (freq_mhz, five_ghz) in [(2400, false), (5000, true)] {
            let channels: Vec<u32> = self
                .channels
                .iter()
                .copied()
                .filter(|&channel| (channel > 14) == five_ghz)
                .collect();
            if !channels.is_empty() {
                bands.push(WirelessBand { freq_mhz, channels });
            }
        }
        WirelessIfaceInfo {
            base_name: self.name.clone(),
            base_mac: self.mac,
            bands,
            modes: WirelessModes::STATION,
            hw_caps: HwCaps {
                ht_supported: false,
                vht_supported: false,
                he_supported: false,
                eht_supported: false,
            },
        }
    }
    async fn scan(&self, request: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        self.state
            .lock()
            .await
            .station
            .scan(request)
            .await
            .map_err(wireless_error)
    }
    async fn associate(&self, request: AssociateRequest) -> Result<(), WirelessError> {
        let mut state = self.state.lock().await;
        let result = state.station.associate(request).await;
        self.link(state.station.bssid);
        result.map_err(wireless_error)
    }
    async fn disassociate(&self) -> Result<(), WirelessError> {
        self.link(None);
        let mut state = self.state.lock().await;
        // Close again under the same lock as association/progress publication:
        // an earlier owner may have published up while disconnect waited.
        self.link(None);
        state.clear_transmit();
        state.station.disconnect().await.map_err(wireless_error)
    }
    async fn set_config(&self, _: WirelessConfig) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }
}
fn wireless_error(error: Error) -> WirelessError {
    match error {
        Error::Busy => WirelessError::Busy,
        Error::Timeout => WirelessError::Timeout,
        Error::Unsupported => WirelessError::NotSupported,
        Error::Authority => WirelessError::Denied,
        Error::Malformed => WirelessError::InvalidArgs,
        _ => WirelessError::HardwareError,
    }
}
struct Registered<R: Fullmac>(Arc<Device<R>>);
fn receive_admitted(bytes: &[u8], local: [u8; 6]) -> bool {
    (14..=1514).contains(&bytes.len())
        && u16::from_be_bytes([bytes[12], bytes[13]]) >= 0x600
        && bytes[12..14] != [0x88, 0x8e]
        && (bytes[0] & 1 != 0 || bytes[..6] == local)
        && bytes[6] & 1 == 0
        && bytes[6..12] != [0; 6]
}
fn transmit_admitted(bytes: &[u8], local: [u8; 6]) -> bool {
    (14..=1514).contains(&bytes.len())
        && u16::from_be_bytes([bytes[12], bytes[13]]) >= 0x600
        && bytes[6..12] == local
        && bytes[12..14] != [0x88, 0x8e]
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use crate::cyw43439::{station::tests as station_tests, Function, Transport, TransportError};
    use core::{
        future::Future,
        pin::pin,
        sync::atomic::AtomicUsize,
        task::{Context, Poll, Waker},
    };
    use narf_kernel_test::{kernel_test_in, TestResult};

    #[derive(Clone)]
    struct Bus {
        inner: Arc<IrqSafeSpinLock<station_tests::Bus>>,
        reads: Arc<AtomicUsize>,
    }
    impl Transport for Bus {
        fn read32(&mut self, f: Function, a: u32) -> Result<u32, TransportError> {
            self.inner.lock().read32(f, a)
        }
        fn write32(&mut self, f: Function, a: u32, v: u32) -> Result<(), TransportError> {
            self.inner.lock().write32(f, a, v)
        }
        fn read_burst(
            &mut self,
            f: Function,
            a: u32,
            bytes: &mut [u8],
        ) -> Result<(), TransportError> {
            self.inner.lock().read_burst(f, a, bytes)
        }
        fn write_burst(&mut self, f: Function, a: u32, bytes: &[u8]) -> Result<(), TransportError> {
            self.inner.lock().write_burst(f, a, bytes)
        }
    }
    impl PacketTransport for Bus {
        fn receive_packet(&mut self, bytes: &mut [u8]) -> Result<usize, TransportError> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            self.inner.lock().receive_packet(bytes)
        }
        fn transmit_packet(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
            self.inner.lock().transmit_packet(bytes)
        }
    }

    fn frame(bytes: &[u8]) -> Frame {
        let buffer =
            narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0).unwrap();
        let mut frame = Frame::new(buffer, bytes.len() as u32);
        frame.payload_mut().copy_from_slice(bytes);
        frame
    }

    fn smoke_cyw_sync_credit_wait_allows_rx_and_disconnect_cleanup() -> TestResult {
        let bus = Bus {
            inner: Arc::new(IrqSafeSpinLock::new(station_tests::Bus::new())),
            reads: Arc::new(AtomicUsize::new(0)),
        };
        let mut initialize = pin!(Station::initialize(
            Runtime::new(bus.clone()),
            &[1],
            station_tests::domain()
        ));
        let Poll::Ready(Ok(mut station)) = initialize
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        else {
            return TestResult::Fail("CYW synchronous progress fixture did not initialize");
        };
        let local = station.mac;
        station.bssid = Some([2, 1, 2, 3, 4, 5]);
        let (rx, _rx_consumer) = narf_ipc::channel();
        let (mut producer, tx) = narf_ipc::channel();
        let mut state = State {
            station,
            rx,
            tx,
            pending: None,
        };
        let mut bytes = vec![0; 14];
        bytes[..6].copy_from_slice(&[2, 1, 2, 3, 4, 5]);
        bytes[6..12].copy_from_slice(&local);
        bytes[12..14].copy_from_slice(&[8, 0]);
        producer.try_send(frame(&bytes)).unwrap();
        {
            let mut bus = bus.inner.lock();
            let maximum = bus.credit_window(2); // Only reserved control credits.
            bus.queue(0, maximum, &[]);
            let mut rx = vec![0x20, 0, 0, 0];
            rx.extend_from_slice(&bytes);
            for _ in 0..20 {
                bus.queue(2, maximum, &rx);
            }
        }
        bus.reads.store(0, Ordering::Relaxed);
        if state.progress().is_err()
            || state.pending.is_none()
            || bus.reads.load(Ordering::Relaxed) != 16
            || bus.inner.lock().sent_data() != 0
        {
            return TestResult::Fail(
                "credit wait retained TX owner, transmitted early, or exceeded RX bound",
            );
        }
        let mut received = 0;
        while state.station.runtime.pop_data().is_some() {
            received += 1;
        }
        if received != 15 || state.progress().is_err() {
            return TestResult::Fail("bounded credit-wait step did not deliver first RX batch");
        }
        while state.station.runtime.pop_data().is_some() {
            received += 1;
        }
        if received != 20 || state.pending.is_none() {
            return TestResult::Fail("synchronous credit wait blocked remaining RX progress");
        }
        {
            let mut bus = bus.inner.lock();
            let maximum = bus.credit_window(5);
            bus.queue(0, maximum, &[]);
        }
        producer.try_send(frame(&bytes)).unwrap();
        if state.progress().is_err() || state.pending.is_some() || bus.inner.lock().sent_data() != 1
        {
            return TestResult::Fail("credit update did not release exactly one pending TX");
        }
        {
            let mut bus = bus.inner.lock();
            let maximum = bus.credit_window(2);
            bus.queue(0, maximum, &[]);
        }
        if state.progress().is_err() || state.pending.is_none() {
            return TestResult::Fail("second frame did not retain bounded credit wait");
        }
        producer.try_send(frame(&bytes)).unwrap();
        {
            let mut bus = bus.inner.lock();
            let maximum = bus.credit_window(2);
            bus.event(16, 0, 0, &[], maximum);
        }
        if state.progress().is_err()
            || state.station.bssid.is_some()
            || state.pending.is_some()
            || !matches!(state.tx.try_recv(), Ok(None))
            || bus.inner.lock().sent_data() != 1
        {
            return TestResult::Fail(
                "link loss retained pending/queued TX or released an unauthorized frame",
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/interface",
        smoke_cyw_sync_credit_wait_allows_rx_and_disconnect_cleanup
    );
    fn smoke_cyw_interface_ethernet_address_and_control_port() -> TestResult {
        let local = [2, 1, 2, 3, 4, 5];
        let mut bytes = vec![2, 1, 2, 3, 4, 5, 2, 6, 7, 8, 9, 10, 8, 0];
        if !receive_admitted(&bytes, local) || transmit_admitted(&bytes, local) {
            return TestResult::Fail("valid RX or foreign-source TX admission");
        }
        bytes[..6].copy_from_slice(&[4, 1, 2, 3, 5, 5]);
        if receive_admitted(&bytes, local) {
            return TestResult::Fail("foreign unicast accepted from wrong multicast byte");
        }
        bytes[..6].copy_from_slice(&[1, 1, 2, 3, 4, 5]);
        if !receive_admitted(&bytes, local) {
            return TestResult::Fail("multicast destination rejected");
        }
        bytes[6..12].copy_from_slice(&local);
        if !transmit_admitted(&bytes, local) {
            return TestResult::Fail("own-source multicast TX rejected");
        }
        bytes[12..14].copy_from_slice(&[0x05, 0xff]);
        if transmit_admitted(&bytes, local) || receive_admitted(&bytes, local) {
            return TestResult::Fail("802.3 length escaped Ethernet-II admission");
        }
        bytes[12..14].copy_from_slice(&[0x06, 0]);
        if !transmit_admitted(&bytes, local) || !receive_admitted(&bytes, local) {
            return TestResult::Fail("Ethernet-II minimum type rejected");
        }
        bytes[12..14].copy_from_slice(&[0x88, 0x8e]);
        if transmit_admitted(&bytes, local) || receive_admitted(&bytes, local) {
            return TestResult::Fail("firmware-owned EAPOL escaped controlled port");
        }
        for end in 0..14 {
            if transmit_admitted(&bytes[..end], local) || receive_admitted(&bytes[..end], local) {
                return TestResult::Fail("truncated Ethernet admitted");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/interface",
        smoke_cyw_interface_ethernet_address_and_control_port
    );
}
impl<R: Fullmac + 'static> Interface for Registered<R> {
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

#[cfg(any(test, feature = "kernel-test"))]
#[path = "interface_dhcp_tests.rs"]
mod dhcp_composition_tests;

#[cfg(any(test, feature = "kernel-test"))]
#[path = "../brcmfmac/station_dhcp_tests.rs"]
mod pcie_dhcp_composition_tests;
