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
    telemetry: Arc<super::telemetry::Counters>,
}
struct PendingTx {
    frame: Frame,
    deadline: narf_time::Deadline,
}
struct Received {
    epoch: u64,
    peer: [u8; 6],
    bytes: Vec<u8>,
    /// EAPOL for the host supplicant's control port.
    control: bool,
}
/// Ordered host-supplicant control operations, applied by the worker.
enum ExternalOp {
    Key(narf_wireless::KeyParams),
    DeleteKey(u8),
    Authorize([u8; 6], bool),
}
#[cfg(any(test, feature = "kernel-test"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReceivePoint {
    AfterFrameAllocation,
    BeforeCallback,
}
#[cfg(any(test, feature = "kernel-test"))]
type ReceiveHook = Arc<dyn Fn(ReceivePoint) + Send + Sync>;
impl<R: Fullmac> State<R> {
    fn clear_transmit(&mut self) {
        if let Some(pending) = self.pending.take() {
            self.drop_frame(&pending.frame);
        }
        // A ring has finite capacity. Bound cleanup even if its producer
        // runs concurrently; a disconnected interface admits no new TX.
        for _ in 0..TX_RING_N {
            match self.tx.try_recv() {
                Ok(Some(frame)) => self.drop_frame(&frame),
                _ => break,
            }
        }
    }
    #[cfg(any(test, feature = "kernel-test"))]
    fn tx_queue_for_test(&mut self, bytes: Vec<u8>) {
        let buffer = narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0)
            .expect("test frame");
        let mut frame = Frame::new(buffer, bytes.len() as u32);
        frame.payload_mut().copy_from_slice(&bytes);
        self.pending = Some(PendingTx {
            frame,
            deadline: narf_time::Deadline::after_ms(2000),
        });
    }
    fn drop_frame(&self, frame: &Frame) {
        self.telemetry
            .dropped(crate::ath11k::tx_hdr::classify8021d(frame.payload()));
    }

    /// One synchronous progress step, shared by the timer and kernel
    /// network drains. Waiting for credits never retains the async mutex.
    fn progress(&mut self) -> Result<(), Error> {
        if let Err(error) = self.station.poll() {
            self.clear_transmit();
            return Err(error);
        }
        if self.station.bssid.is_none() || self.station.external_port() == Some(false) {
            // An unauthorized host-supplicant port passes only EAPOL, which
            // uses the control-port path, never the netdev rings.
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
        // Linux brcmf_netdev_start_xmit: cfg80211_classify8021d.
        let priority = crate::ath11k::tx_hdr::classify8021d(pending.frame.payload());
        let length = pending.frame.payload().len();
        let result = if pending.deadline.expired() {
            Err(Error::Timeout)
        } else {
            self.station.send_data(pending.frame.payload(), priority)
        };
        match result {
            Ok(()) => {
                self.pending = None;
                self.telemetry.transmitted(priority, length);
            }
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
    mfp_supported: bool,
    sae_offload: bool,
    telemetry: Arc<super::telemetry::Counters>,
    external_ops: IrqSafeSpinLock<alloc::collections::VecDeque<ExternalOp>>,
    /// Desired firmware PMKID list (nl80211 SET/DEL/FLUSH_PMKSA); the
    /// worker and each association reconcile firmware with it.
    pmksa: IrqSafeSpinLock<super::station::pmksa::Cache>,
    ht_capabilities: [Option<[u8; 26]>; 2],
    vht_capabilities: [Option<[u8; 12]>; 2],
    up: AtomicBool,
    // Requested PS policy: 0=awake, 1=PM_FAST, 2=terminal failure. The
    // retained worker serializes firmware commands with scan/join/packets.
    power_save: AtomicU8,
    bssid: AtomicU64,
    epoch: AtomicU64,
    closing: AtomicBool,
    /// A firmware roam holds the port closed; carrier loss is not reported
    /// as a disconnect unless the roam fails.
    roaming: AtomicBool,
    publication: IrqSafeSpinLock<()>,
    #[cfg(any(test, feature = "kernel-test"))]
    receive_hook: IrqSafeSpinLock<Option<ReceiveHook>>,
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

type PmFuture<'a> = core::pin::Pin<
    alloc::boxed::Box<dyn core::future::Future<Output = Result<(), Error>> + Send + 'a>,
>;
trait Endpoint: Send + Sync {
    fn enqueue(&self, bytes: &[u8]) -> Result<(), ()>;
    fn drain(&self) -> bool;
    fn suspend(&self) -> PmFuture<'_>;
    fn resume(&self) -> PmFuture<'_>;
}
/// System-suspend prepare for the attached PCIe FullMAC owner, if any:
/// Linux `brcmf_cfg80211_suspend` without WoWL (`brcmf_link_down` on a
/// connected station) followed by the bus `suspend` op.
pub async fn suspend_pcie() -> Result<(), Error> {
    let active = ACTIVE_PCIE.lock().clone();
    match active {
        Some(active) => active.suspend().await,
        None => Ok(()),
    }
}
/// Paired resume for [`suspend_pcie`].
pub async fn resume_pcie() -> Result<(), Error> {
    let active = ACTIVE_PCIE.lock().clone();
    match active {
        Some(active) => active.resume().await,
        None => Ok(()),
    }
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
    let telemetry = Arc::new(super::telemetry::Counters::default());
    let (rx_producer, rx_consumer) = narf_ipc::channel();
    let (tx_producer, tx_consumer) = narf_ipc::channel();
    let device = Arc::new(Device {
        name: name.into(),
        mac: station.mac,
        channels: station.channels.iter().map(|&ch| u32::from(ch)).collect(),
        supplicant: station.supplicant,
        mfp_supported: station.supports_management_protection(),
        sae_offload: station.supports_sae_offload(),
        telemetry: telemetry.clone(),
        external_ops: IrqSafeSpinLock::new(Default::default()),
        pmksa: IrqSafeSpinLock::new(Default::default()),
        ht_capabilities: station.ht_capabilities(),
        vht_capabilities: station.vht_capabilities(),
        state: Mutex::new(State {
            station,
            rx: rx_producer,
            tx: tx_consumer,
            pending: None,
            telemetry,
        }),
        up: AtomicBool::new(false),
        power_save: AtomicU8::new(0),
        bssid: AtomicU64::new(0),
        roaming: AtomicBool::new(false),
        epoch: AtomicU64::new(0),
        closing: AtomicBool::new(false),
        publication: IrqSafeSpinLock::new(()),
        #[cfg(any(test, feature = "kernel-test"))]
        receive_hook: IrqSafeSpinLock::new(None),
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
        let _publication = self.publication.lock();
        self.publish_link(peer);
    }
    fn clear_rx(&self) {
        if let Some(rx) = self.rx.lock().as_mut() {
            for _ in 0..RX_RING_N {
                if !matches!(rx.try_recv(), Ok(Some(_))) {
                    break;
                }
            }
        }
    }
    fn advance_epoch(&self) -> bool {
        self.epoch
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |e| e.checked_add(1))
            .is_ok()
    }
    fn close_host(&self) -> u64 {
        let _publication = self.publication.lock();
        self.closing.store(true, Ordering::Release);
        self.advance_epoch();
        self.publish_link(None);
        self.clear_rx();
        self.epoch.load(Ordering::Acquire)
    }
    fn publish_link(&self, peer: Option<[u8; 6]>) {
        let peer = peer.filter(|_| {
            !self.closing.load(Ordering::Acquire) && self.epoch.load(Ordering::Acquire) != u64::MAX
        });
        let mut packed = [0; 8];
        if let Some(peer) = peer {
            packed[..6].copy_from_slice(&peer);
            packed[7] = 1;
        }
        if self
            .bssid
            .swap(u64::from_le_bytes(packed), Ordering::AcqRel)
            != u64::from_le_bytes(packed)
            && !self.advance_epoch()
        {
            self.closing.store(true, Ordering::Release);
            self.bssid.store(0, Ordering::Release);
        }
        let up = peer.is_some() && !self.closing.load(Ordering::Acquire);
        let was_up = self.up.swap(up, Ordering::AcqRel);
        // Physical carrier preserves operator-controlled IFF_UP and never
        // invokes an administrative open/stop hook under retained locks.
        narf_net::iface::set_link_metadata(&self.name, up, None, None);
        if was_up && !up {
            self.clear_rx();
            if !self.roaming.load(Ordering::Acquire) {
                narf_wireless::nl80211::notify_disconnect(&self.name, 1, false);
            }
        }
    }

    fn step(&self) -> Vec<Received> {
        let Some(mut state) = self.state.try_lock() else {
            return Vec::new();
        };
        if self.closing.load(Ordering::Acquire) {
            if state.station.poll().is_err() {
                self.power_save.store(2, Ordering::Release);
            }
            state.clear_transmit();
            for _ in 0..32 {
                if state.station.runtime.pop_data().is_none() {
                    break;
                }
            }
            self.link(None);
            return Vec::new();
        }
        let result = {
            let _publication = self.publication.lock();
            if self.closing.load(Ordering::Acquire) {
                state.clear_transmit();
                state.station.poll()
            } else {
                state.progress()
            }
        };
        let roaming = state.station.roam_pending().is_some();
        if self.roaming.swap(roaming, Ordering::AcqRel) && !roaming && state.station.bssid.is_none()
        {
            // The firmware roam failed after its carrier loss was withheld.
            narf_wireless::nl80211::notify_disconnect(&self.name, 1, false);
        }
        if result.is_err() {
            self.power_save.store(2, Ordering::Release);
            self.link(None);
            return Vec::new();
        }
        self.link(state.station.bssid);
        let Some(peer) = state.station.bssid else {
            return Vec::new();
        };
        let epoch = self.epoch.load(Ordering::Acquire);
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
            if state.station.external_port().is_some() && eapol_admitted(&bytes, self.mac, peer) {
                output.push(Received {
                    epoch,
                    peer,
                    bytes,
                    control: true,
                });
                continue;
            }
            if !self.up.load(Ordering::Acquire)
                || state.station.external_port() == Some(false)
                || !receive_admitted(&bytes, self.mac)
            {
                continue;
            }
            output.push(Received {
                epoch,
                peer,
                bytes,
                control: false,
            });
        }
        output
    }
    fn current_receive(&self, state: &mut State<R>, received: &Received) -> bool {
        if self.closing.load(Ordering::Acquire)
            || !self.up.load(Ordering::Acquire)
            || self.epoch.load(Ordering::Acquire) != received.epoch
            || state.station.bssid != Some(received.peer)
        {
            return false;
        }
        // Reinvoke the retained native source/bus owner and consume current
        // bounded link/key events after allocation and again before callback.
        // A cached policy/peer alone cannot authorize a later publication.
        if state.station.poll().is_err()
            || state.station.bssid != Some(received.peer)
            || state.station.check_connection_policy().is_err()
            || state.station.channel_width_mhz().is_none()
        {
            state.clear_transmit();
            self.power_save.store(2, Ordering::Release);
            self.publish_link(None);
            return false;
        }
        true
    }
    fn publish_received(&self, received: &Received) -> bool {
        let frame = narf_io::alloc_coherent(received.bytes.len(), narf_lib::id::DomainId::DRIVER_0)
            .ok()
            .map(|buffer| {
                let mut frame = Frame::new(buffer, received.bytes.len() as u32);
                frame.payload_mut().copy_from_slice(&received.bytes);
                frame
            });
        #[cfg(any(test, feature = "kernel-test"))]
        self.receive_hook(ReceivePoint::AfterFrameAllocation);
        {
            let Some(mut state) = self.state.try_lock() else {
                return false;
            };
            let _publication = self.publication.lock();
            if !self.current_receive(&mut state, received) {
                return false;
            }
            if let Some(frame) = frame {
                let _ = state.rx.try_send(frame);
            }
        }
        #[cfg(any(test, feature = "kernel-test"))]
        self.receive_hook(ReceivePoint::BeforeCallback);
        let Some(mut state) = self.state.try_lock() else {
            return false;
        };
        let _publication = self.publication.lock();
        self.current_receive(&mut state, received)
    }
    #[cfg(any(test, feature = "kernel-test"))]
    fn receive_hook(&self, point: ReceivePoint) {
        let hook = self.receive_hook.lock().clone();
        if let Some(hook) = hook {
            hook(point);
        }
    }
    fn deliver_received(&self, frames: Vec<Received>) -> bool {
        let mut progress = false;
        for mut frame in frames {
            if frame.control {
                self.deliver_control(&frame);
                progress = true;
                continue;
            }
            if !self.publish_received(&frame) {
                break;
            }
            self.telemetry.received(
                crate::ath11k::tx_hdr::classify8021d(&frame.bytes),
                frame.bytes.len(),
            );
            // No state/publication/ring guard survives the final admission.
            narf_net::iface::on_rx_frame_from(&self.name, &mut frame.bytes);
            progress = true;
        }
        progress
    }

    /// `cfg80211_rx_control_port` for the current host-supplicant peer, or
    /// the netdev when the owner did not request control port over nl80211.
    fn deliver_control(&self, received: &Received) {
        let authorized = {
            let Some(state) = self.state.try_lock() else {
                return;
            };
            if self.epoch.load(Ordering::Acquire) != received.epoch
                || state.station.bssid != Some(received.peer)
            {
                return;
            }
            state.station.external_port() == Some(true)
        };
        if narf_wireless::nl80211::control_port_over_nl80211(&self.name) {
            narf_wireless::nl80211::rx_control_port(
                &self.name,
                received.peer,
                0x888e,
                &received.bytes[14..],
                !authorized,
            );
        } else {
            let mut bytes = received.bytes.clone();
            narf_net::iface::on_rx_frame_from(&self.name, &mut bytes);
        }
    }

    /// Apply queued host-supplicant key/port operations in order.
    async fn apply_external(&self) {
        if self.external_ops.lock().is_empty() {
            return;
        }
        let Some(mut state) = self.state.try_lock() else {
            return;
        };
        loop {
            let Some(op) = self.external_ops.lock().pop_front() else {
                break;
            };
            let result = match op {
                ExternalOp::Key(key) => {
                    state
                        .station
                        .install_key(
                            key.idx,
                            key.pairwise,
                            key.peer,
                            key.cipher,
                            &key.key,
                            &key.seq,
                        )
                        .await
                }
                ExternalOp::DeleteKey(index) => state.station.delete_key(index).await,
                ExternalOp::Authorize(peer, authorized) => {
                    state.station.authorize_port(peer, authorized)
                }
            };
            if let Err(error) = result {
                self.external_ops.lock().clear();
                state.clear_transmit();
                if state.station.bssid.is_none() {
                    self.link(None);
                }
                narf_console::klog!(
                    "{}: FullMAC host-supplicant operation failed: {:?}\n",
                    self.name,
                    error
                );
                break;
            }
        }
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

    async fn apply_pmksa(&self) {
        let desired = self.pmksa.lock().clone();
        let Some(mut state) = self.state.try_lock() else {
            return;
        };
        if state.station.programmed_pmksa() == Some(&desired) {
            return;
        }
        if let Err(error) = state.station.sync_pmksa(&desired).await {
            if state.station.bssid.is_none() {
                self.link(None);
            }
            narf_console::klog!(
                "{}: FullMAC pmkid_info update failed: {:?}\n",
                self.name,
                error
            );
        }
    }

    /// Confirm a pending firmware roam and report `cfg80211_roamed`.
    async fn apply_roam(&self) {
        let Some(mut state) = self.state.try_lock() else {
            return;
        };
        if state.station.roam_pending().is_none() {
            return;
        }
        match state.station.complete_roam().await {
            Ok(Some(roamed)) => {
                state.clear_transmit();
                self.link(state.station.bssid);
                self.roaming.store(false, Ordering::Release);
                narf_wireless::nl80211::notify_roamed(
                    &self.name,
                    roamed.bssid,
                    roamed.frequency_mhz,
                    &roamed.request_ies,
                    &roamed.response_ies,
                );
            }
            Ok(None) => {}
            Err(error) => {
                state.clear_transmit();
                self.power_save.store(2, Ordering::Release);
                self.link(None);
                narf_console::klog!("{}: FullMAC firmware roam failed: {:?}\n", self.name, error);
            }
        }
    }

    /// Per-AC host queue/traffic counters (VO, VI, BE, BK).
    pub fn ac_statistics(&self) -> [super::telemetry::AcStats; 4] {
        self.telemetry.snapshot()
    }

    /// Platform roaming policy (Linux brcmfmac `roamoff`): enable or
    /// disable the firmware roaming engine while disconnected.
    pub async fn set_firmware_roaming(&self, enabled: bool) -> Result<(), WirelessError> {
        let mut state = self.state.lock().await;
        state
            .station
            .set_firmware_roaming(enabled)
            .await
            .map_err(wireless_error)
    }

    async fn receive_worker(self: Arc<Self>) {
        let mut wake = None;
        loop {
            // A transport generation may rebind its vector; re-read the wake
            // source whenever the state is uncontended. The count is sampled
            // before service so a vector raised during service re-runs it.
            if let Some(state) = self.state.try_lock() {
                wake = state.station.runtime.wake_source();
            }
            let seen = wake.as_ref().map(|(signal, _)| signal.count());
            self.deliver_received(self.step());
            self.apply_roam().await;
            self.apply_external().await;
            self.apply_power_save().await;
            self.apply_pmksa().await;
            match (&wake, seen) {
                (Some((signal, delivered)), Some(seen)) => {
                    // brcmf_pcie_isr_thread wakes msgbuf service; the timer
                    // is a missed-edge backstop (or the poll without MSI).
                    let ms = crate::brcmfmac::irq::fallback_ms(*delivered);
                    let fallback = core::pin::pin!(narf_time::sleep_cycles(
                        narf_time::wall::ns_to_cycles(ms * 1_000_000)
                    ));
                    signal.wait(seen, fallback).await;
                }
                _ => {
                    narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
                }
            }
        }
    }
}
impl<R: Fullmac + 'static> Endpoint for Device<R> {
    fn enqueue(&self, bytes: &[u8]) -> Result<(), ()> {
        if !self.up.load(Ordering::Acquire) || !transmit_admitted(bytes, self.mac) {
            return Err(());
        }
        let epoch = self.epoch.load(Ordering::Acquire);
        let buffer = narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0)
            .map_err(|_| ())?;
        let mut frame = Frame::new(buffer, bytes.len() as u32);
        frame.payload_mut().copy_from_slice(bytes);
        let _publication = self.publication.lock();
        if self.closing.load(Ordering::Acquire)
            || !self.up.load(Ordering::Acquire)
            || self.epoch.load(Ordering::Acquire) != epoch
        {
            return Err(());
        }
        self.tx
            .lock()
            .as_mut()
            .ok_or(())?
            .try_send(frame)
            .map_err(|_| ())
    }
    fn drain(&self) -> bool {
        self.deliver_received(self.step())
    }
    fn suspend(&self) -> PmFuture<'_> {
        alloc::boxed::Box::pin(async move {
            let connected = self.state.lock().await.station.bssid.is_some();
            if connected {
                let _ = WirelessNetIface::disassociate(self).await;
            }
            let mut state = self.state.lock().await;
            state.clear_transmit();
            state.station.runtime.suspend_transport().await
        })
    }
    fn resume(&self) -> PmFuture<'_> {
        alloc::boxed::Box::pin(async move {
            let mut state = self.state.lock().await;
            let result = state.station.runtime.resume_transport().await;
            if result.is_err() {
                self.power_save.store(2, Ordering::Release);
                self.link(None);
            }
            result
        })
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
    fn phy_capabilities(&self, band: u32) -> Option<narf_wireless::iface::PhyCapabilities> {
        if !self
            .channels
            .iter()
            .any(|channel| band == 2400 && *channel <= 14 || band == 5000 && *channel > 14)
        {
            return None;
        }
        Some(narf_wireless::iface::PhyCapabilities {
            ht: self.ht_capabilities[usize::from(band == 5000)]?,
            vht: self.vht_capabilities[usize::from(band == 5000)],
        })
    }
    fn cipher_suites(&self) -> &'static [u32] {
        if self.mfp_supported {
            &[
                narf_wireless::CIPHER_SUITE_CCMP,
                narf_wireless::CIPHER_SUITE_AES_CMAC,
            ]
        } else if self.supplicant {
            &[narf_wireless::CIPHER_SUITE_CCMP]
        } else {
            &[]
        }
    }
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
    fn supports_wpa2_mfp_offload(&self) -> bool {
        self.mfp_supported
    }
    fn supports_optional_mfp(&self) -> bool {
        self.mfp_supported
    }
    fn supports_sae_offload(&self) -> bool {
        self.sae_offload
    }
    fn supports_external_supplicant(&self) -> bool {
        true
    }
    fn add_key(&self, key: narf_wireless::KeyParams) -> Result<(), i32> {
        // brcmf_cfg80211_add_key: index < BRCMF_MAX_DEFAULT_KEYS; this
        // profile installs CCMP-128 only.
        if key.idx >= super::station::external::MAX_DEFAULT_KEYS
            || key.cipher != narf_wireless::CIPHER_SUITE_CCMP
            || key.key.len() != 16
            || !(key.seq.is_empty() || key.seq.len() == 6)
        {
            return Err(22);
        }
        let current = self.connected_bssid().ok_or(2)?;
        if key.pairwise && key.peer != Some(current) {
            return Err(2); // ENOENT: not the associated AP.
        }
        self.external_ops.lock().push_back(ExternalOp::Key(key));
        Ok(())
    }
    fn del_key(&self, idx: u8, _pairwise: bool, _peer: Option<[u8; 6]>) -> Result<(), i32> {
        if idx >= super::station::external::MAX_DEFAULT_KEYS {
            return Err(22);
        }
        self.connected_bssid().ok_or(2)?;
        self.external_ops
            .lock()
            .push_back(ExternalOp::DeleteKey(idx));
        Ok(())
    }
    fn set_port_authorized(&self, peer: [u8; 6], authorized: bool) -> Result<(), i32> {
        if self.connected_bssid() != Some(peer) {
            return Err(if authorized { 22 } else { 2 });
        }
        self.external_ops
            .lock()
            .push_back(ExternalOp::Authorize(peer, authorized));
        Ok(())
    }
    fn tx_control_port(
        &self,
        dest: [u8; 6],
        proto: u16,
        frame: Vec<u8>,
        _no_encrypt: bool,
    ) -> Result<(), i32> {
        // EAPOL (and RSN pre-authentication) to the associated AP only.
        if !matches!(proto, 0x888e | 0x88c7) || frame.len() > 1500 {
            return Err(22);
        }
        let peer = self.connected_bssid().ok_or(107)?; // ENOTCONN
        if dest != peer {
            return Err(22);
        }
        let mut state = self.state.try_lock().ok_or(16)?; // EBUSY
        if state.station.external_port().is_none() {
            return Err(95);
        }
        let mut bytes = Vec::with_capacity(14 + frame.len());
        bytes.extend_from_slice(&dest);
        bytes.extend_from_slice(&self.mac);
        bytes.extend_from_slice(&proto.to_be_bytes());
        bytes.extend_from_slice(&frame);
        // mac80211 sends control-port frames as VO (802.1D 7).
        match state.station.send_data(&bytes, 7) {
            Ok(()) => Ok(()),
            Err(Error::Busy) => Err(16),
            Err(_) => Err(5),
        }
    }
    fn station_info(&self) -> Option<narf_wireless::StationInfo> {
        self.connected_bssid()?;
        let (tx, rx, failed) = self.telemetry.totals();
        Some(narf_wireless::StationInfo {
            tx_packets: Some(tx),
            rx_packets: Some(rx),
            tx_failed: Some(failed),
            ..Default::default()
        })
    }
    fn set_pmksa(&self, entry: narf_wireless::PmksaEntry) -> Result<(), i32> {
        // Linux v1 list rows are {bssid, pmkid}; FILS/SSID-only caching is
        // not a profile here. Full list or missing BSSID is -EINVAL.
        let (Some(bssid), Some(pmkid)) = (entry.bssid, entry.pmkid) else {
            return Err(22);
        };
        self.pmksa
            .lock()
            .set(super::station::pmksa::Entry {
                bssid,
                pmkid,
                ssid: entry.ssid.unwrap_or_default(),
            })
            .map_err(|_| 22)
    }
    fn del_pmksa(&self, entry: narf_wireless::PmksaEntry) -> Result<(), i32> {
        let bssid = entry.bssid.ok_or(22)?;
        self.pmksa.lock().delete(bssid).map_err(|_| 22)
    }
    fn flush_pmksa(&self) -> Result<(), i32> {
        self.pmksa.lock().flush();
        Ok(())
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
                ht_supported: self.ht_capabilities.iter().any(Option::is_some),
                vht_supported: self.vht_capabilities.iter().any(Option::is_some),
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
        if state.station.bssid.is_some() {
            return Err(WirelessError::Busy);
        }
        let ticket = self.close_host();
        state.clear_transmit();
        if ticket == u64::MAX {
            return Err(WirelessError::HardwareError);
        }
        // Firmware inserts cached PMKIDs into its (re)association RSNE;
        // the list must be current before the join is issued.
        let desired = self.pmksa.lock().clone();
        let result = match state.station.sync_pmksa(&desired).await {
            Ok(()) => state.station.associate(request).await,
            Err(error) => Err(error),
        };
        {
            let _publication = self.publication.lock();
            if self.epoch.load(Ordering::Acquire) != ticket {
                state.station.runtime.fail();
                state.station.bssid = None;
                self.publish_link(None);
                return Err(WirelessError::Denied);
            }
            if result.is_ok() {
                if let Err(error) = state.station.check_connection_policy() {
                    self.publish_link(None);
                    return Err(wireless_error(error));
                }
                self.closing.store(false, Ordering::Release);
            }
            self.publish_link(state.station.bssid);
        }
        result.map_err(wireless_error)
    }
    async fn disassociate(&self) -> Result<(), WirelessError> {
        self.close_host();
        let mut state = self.state.lock().await;
        // Close again under the same lock as association/progress publication:
        // an earlier owner may have published up while disconnect waited.
        self.close_host();
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
/// EAPOL from the associated AP to this station (host-supplicant mode).
fn eapol_admitted(bytes: &[u8], local: [u8; 6], peer: [u8; 6]) -> bool {
    (18..=1514).contains(&bytes.len())
        && bytes[12..14] == [0x88, 0x8e]
        && bytes[..6] == local
        && bytes[6..12] == peer
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
            telemetry: Default::default(),
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

#[cfg(any(test, feature = "kernel-test"))]
#[path = "optional_mfp_common.rs"]
mod optional_mfp_common;
