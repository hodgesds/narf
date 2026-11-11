//! Live MLD device, serialized with an async mutex. Firmware command
//! waits drain RX themselves and never depend on another executor task.

use super::connection::{Beacon, Connection};
use super::progress::{PendingTx, Transmit, Work};
use super::{runtime::Hardware, scan_api, station_api};
use alloc::{
    boxed::Box,
    collections::VecDeque,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    future::{poll_fn, Future},
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    task::{Context, Poll, Waker},
};
use narf_ipc::{Consumer, Producer};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};
use narf_net::{Frame, Interface, RX_RING_N, TX_RING_N};
use narf_wireless::{
    AssociateRequest, BssInfo, ScanRequest, WirelessConfig, WirelessError, WirelessIfaceInfo,
    WirelessNetIface,
};

pub struct Device {
    #[cfg(any(test, feature = "kernel-test"))]
    test_name: Option<&'static str>,
    me: Weak<Self>,
    radio_control: Arc<narf_wireless::ap_control::ExclusiveControl>,
    scan_generation: Arc<super::scheduled_epoch::Epoch>,
    mode: AtomicU32,
    mode_generation: AtomicU64,
    ap_capable: bool,
    go_capable: bool,
    ap_host: ap::Host,
    p2p: p2p::Host,
    state: Mutex<State>,
    control: Mutex<Option<Work>>,
    publication: AtomicBool,
    source: super::runtime::source::Fence,
    policy: super::mld_policy::Source,
    policy_fence: IrqSafeSpinLock<Option<super::mld_policy::Fence>>,
    generation: Arc<AtomicU64>,
    quarantined: AtomicBool,
    /// A terminal close request survives a dropped state-lock waiter.
    closing: AtomicBool,
    /// A completed system-suspend stop awaiting its resume restart.
    suspended: AtomicBool,
    admission: IrqSafeSpinLock<()>,
    mac: [u8; 6],
    irq_vector: Option<u8>,
    channels: Vec<u8>,
    six_channels: Vec<super::native_band::Channel>,
    tx_chains: u32,
    rx_chains: u32,
    phy: super::ht_vht::Local,
    firmware: Vec<u8>,
    pnvm: Option<Vec<u8>>,
    up: AtomicBool,
    /// Current association BSSID, cached for a lock-free sync read by the
    /// control plane (bit 63 = associated, low 48 bits = BSSID LE). Lets a
    /// CONNECT to a different BSS of the same ESS be routed as a roam.
    bssid: AtomicU64,
    /// The multi-link view of the current association when CONNECT
    /// carried NL80211_ATTR_MLO_SUPPORT (`associate_mlo`); cleared by
    /// every new association or roam attempt.
    mlo_report: IrqSafeSpinLock<Option<narf_wireless::MloConnection>>,
    rx: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx: [IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>; 4],
}

impl core::fmt::Debug for Device {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IwlMldDevice")
            .field("mac", &self.mac)
            .field("up", &self.up)
            .finish()
    }
}

struct State {
    hardware: Hardware,
    scan_uid: u32,
    scheduled: Option<scheduled::Owner>,
    beacons: Vec<Beacon>,
    /// `beacons` entries received by the most recent scan (bssid, band,
    /// channel): the MLO scan freshness further links require.
    scan_seen: Vec<([u8; 6], super::native_band::Band, u8)>,
    connection: Option<Connection>,
    ap: Option<super::ap_session::Session>,
    ap_probes: VecDeque<Vec<u8>>,
    needs_reset: bool,
    stop_completed: bool,
    producer: Option<Producer<Frame, RX_RING_N>>,
    receive_ipc: Option<super::runtime::rx_epoch::Publication>,
    receive_ap_data: Option<super::ap_owner::DataPublication>,
    eapol: VecDeque<Vec<u8>>,
    tx: [Option<Consumer<Frame, TX_RING_N>>; 4],
    pending: [Option<PendingTx<Frame>>; 4],
    pending_next: [Option<PendingTx<Frame>>; 4],
    tx_progress: bool,
}

#[derive(Default)]
struct StepOutcome {
    data: Vec<Delivery>,
    radio: Vec<scheduled::Publication>,
    ap: Vec<ap::Publication>,
}

#[derive(Clone)]
struct Delivery {
    bytes: Vec<u8>,
    source: super::runtime::source::Fence,
    generation: Arc<AtomicU64>,
    epoch: u64,
    receive: super::runtime::rx_epoch::Publication,
    ap_data: Option<super::ap_owner::DataPublication>,
    policy: super::mld_policy::Fence,
}
impl core::ops::Deref for Delivery {
    type Target = Vec<u8>;
    fn deref(&self) -> &Vec<u8> {
        &self.bytes
    }
}
impl Delivery {
    fn current(&self) -> bool {
        self.generation.load(Ordering::Acquire) == self.epoch
            && self.receive.current()
            && self.ap_data.as_ref().is_none_or(|data| data.current())
    }
    fn invoke<T>(
        &self,
        operation: impl FnOnce() -> Result<T, &'static str>,
    ) -> Result<T, &'static str> {
        self.source.invoke(|| {
            self.policy.invoke(|| {
                if !self.current() {
                    return Err("stale Intel station publication generation");
                }
                operation()
            })
        })
    }
}

impl State {
    fn clear_transmit(&mut self) {
        self.pending = core::array::from_fn(|_| None);
        self.pending_next = core::array::from_fn(|_| None);
        self.tx_progress = false;
        for consumer in self.tx.iter_mut().flatten() {
            for _ in 0..TX_RING_N {
                if !matches!(consumer.try_recv(), Ok(Some(_))) {
                    break;
                }
            }
        }
    }

    fn progress_transmit(&mut self, mut cx: Option<&mut Context<'_>>) -> Result<(), &'static str> {
        if self.ap.is_some() {
            return self.progress_ap_transmit(cx);
        }
        self.tx_progress = false;
        let Some(connection) = self.connection.as_mut().filter(|c| c.authorized) else {
            self.clear_transmit();
            return Ok(());
        };
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
            if connection.can_batch(category)
                && self.pending[category].is_some()
                && self.pending_next[category].is_none()
            {
                self.pending_next[category] = self.tx[category]
                    .as_mut()
                    .and_then(|consumer| consumer.try_recv().ok().flatten())
                    .map(PendingTx::new);
            }
            if let (Some(first), Some(second)) =
                (&self.pending[category], &self.pending_next[category])
            {
                if first.expired() || second.expired() {
                    return Err("TX batch queue credit timed out");
                }
                let first = first.frame();
                let second = second.frame();
                // A partial checksum retains the existing single-frame HW
                // offload. Both original IPC frames/deadlines stay owned
                // while an otherwise valid aggregate lacks native credit.
                let result =
                    if first.tx_meta().csum_l4.is_some() || second.tx_meta().csum_l4.is_some() {
                        super::connection::tx_amsdu::Batch::Unsuited
                    } else {
                        connection.try_enqueue_batch(
                            &mut self.hardware,
                            first.payload(),
                            second.payload(),
                            category,
                        )?
                    };
                match result {
                    super::connection::tx_amsdu::Batch::Sent => {
                        self.pending[category] = None;
                        self.pending_next[category] = None;
                        self.tx_progress = true;
                        continue;
                    }
                    super::connection::tx_amsdu::Batch::Busy => continue,
                    super::connection::tx_amsdu::Batch::Unsuited => {}
                }
            }
            if let Some(pending) = &self.pending[category] {
                match pending.progress(|frame| {
                    let mut bytes = frame.payload().to_vec();
                    let assist = super::csum::prepare_tx(&mut bytes, frame.tx_meta().csum_l4)?;
                    connection.try_enqueue_assisted(
                        &mut self.hardware,
                        &bytes,
                        Some(category),
                        assist,
                    )
                })? {
                    Transmit::Sent => {
                        self.pending[category] = self.pending_next[category].take();
                        self.tx_progress = true;
                    }
                    Transmit::Busy => {}
                    Transmit::Expired => return Err("TX queue credit timed out"),
                }
            }
        }
        Ok(())
    }
}

impl Device {
    fn validate_station_profile(hardware: &Hardware) -> Result<(), &'static str> {
        if hardware.is_mvm89() {
            return Ok(());
        }
        for (group, command, version) in [
            (3, 8, 3),
            (3, 9, 8),
            (3, 10, 2),
            (1, 8, 6),
            (5, 0x17, 3),
            (1, 0xc, 5),
        ] {
            if hardware.version(group, command).map(|v| v.0) != Some(version) {
                return Err("unsupported MLD station command version");
            }
        }
        Ok(())
    }

    pub async fn initialize(
        mut hardware: Hardware,
        parsed: &super::ParsedUcode<'_>,
        firmware: &[u8],
    ) -> Result<Arc<Self>, &'static str> {
        hardware.prepare_station_profile(parsed)?;
        Self::validate_station_profile(&hardware)?;
        let mac = hardware.start(parsed).await?;
        let nvm = Self::configure(&mut hardware, mac).await?;
        let irq_vector = hardware.irq_vector();
        let source = hardware.source_fence()?;
        let ap_capable = super::ap_session::supported(&hardware);
        let go_capable = ap_capable
            && matches!(
                hardware.version(3, 0xfc).map(|version| version.1),
                None | Some(1 | 99)
            );
        Ok(Arc::new_cyclic(|me| Self {
            #[cfg(any(test, feature = "kernel-test"))]
            test_name: None,
            me: me.clone(),
            radio_control: Arc::new(narf_wireless::ap_control::ExclusiveControl::new()),
            scan_generation: Arc::new(super::scheduled_epoch::Epoch::new()),
            mode: AtomicU32::new(2),
            mode_generation: AtomicU64::new(1),
            ap_capable,
            go_capable,
            ap_host: ap::Host::new(),
            p2p: p2p::Host::new(),
            state: Mutex::new(State {
                hardware,
                scan_uid: 0,
                scheduled: None,
                beacons: Vec::new(),
                scan_seen: Vec::new(),
                connection: None,
                ap: None,
                ap_probes: VecDeque::new(),
                needs_reset: false,
                stop_completed: false,
                producer: None,
                receive_ipc: None,
                receive_ap_data: None,
                eapol: VecDeque::new(),
                tx: core::array::from_fn(|_| None),
                pending: core::array::from_fn(|_| None),
                pending_next: core::array::from_fn(|_| None),
                tx_progress: false,
            }),
            control: Mutex::new(None),
            publication: AtomicBool::new(false),
            source,
            policy: super::mld_policy::Source::native(),
            policy_fence: IrqSafeSpinLock::new(None),
            generation: Arc::new(AtomicU64::new(0)),
            quarantined: AtomicBool::new(false),
            closing: AtomicBool::new(false),
            suspended: AtomicBool::new(false),
            admission: IrqSafeSpinLock::new(()),
            mac,
            irq_vector,
            channels: nvm.channels,
            six_channels: nvm.six_channels,
            tx_chains: nvm.tx_chains,
            rx_chains: nvm.rx_chains,
            phy: nvm.phy,
            firmware: firmware.to_vec(),
            pnvm: parsed.api.pnvm.map(|bytes| bytes.to_vec()),
            up: AtomicBool::new(false),
            bssid: AtomicU64::new(0),
            mlo_report: IrqSafeSpinLock::new(None),
            rx: IrqSafeSpinLock::new(None),
            tx: core::array::from_fn(|_| IrqSafeSpinLock::new(None)),
        }))
    }

    async fn configure(
        hardware: &mut Hardware,
        mac: [u8; 6],
    ) -> Result<station_api::Nvm, &'static str> {
        let nvm_packet = hardware.command(0xc, 2, &[0; 4]).await?;
        let mut nvm = station_api::Nvm::parse(
            hardware.version(0xc, 2).ok_or("missing NVM version")?.1,
            &nvm_packet.payload,
        )?;
        if nvm.phy.ht {
            hardware.check_aggregation_api()?;
        }
        nvm.phy.he &= super::sc_he::native_supported(hardware);
        nvm.phy.native_rates = super::sc_he::rates_version(hardware).unwrap_or(0);
        nvm.phy.eht = nvm.phy.he && hardware.eht_supported();
        nvm.phy.eht_320 = nvm.phy.eht && hardware.eht_320_supported();
        if !nvm.phy.he || !hardware.band_in_rx_supported() {
            nvm.six_channels.clear();
        }
        let runtime = hardware.runtime_configuration()?;
        hardware
            .command(1, 0x98, &nvm.tx_chains.to_le_bytes())
            .await?;
        hardware.command(1, 0x9b, &runtime.coexistence).await?;
        hardware.command(2, 1, &runtime.soc).await?;
        hardware.station_receive_chains(nvm.rx_chains).await?;
        hardware
            .command(1, 0xc, &station_api::scan_config(&nvm))
            .await?;
        hardware.command(1, 0x77, &runtime.power).await?;
        hardware
            .command(3, 8, &station_api::mac(1, mac, None))
            .await?;
        hardware
            .command(3, 9, &station_api::link(1, mac, false, 1, 0, 1))
            .await?;
        Ok(nvm)
    }

    async fn recover(&self, state: &mut State) -> Result<(), WirelessError> {
        if self.quarantined.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        self.set_link(false);
        *self.policy_fence.lock() = None;
        state.hardware.clear_rf_policy();
        state.needs_reset = true;
        state.stop_completed = false;
        state.connection = None;
        self.retire_ap(state);
        self.abandon_scheduled(state);
        state.clear_transmit();
        state.eapol.clear();
        // RAM fixture: no PCI function or embedded CPU to restart.
        #[cfg(any(test, feature = "kernel-test"))]
        let model = if super::runtime::model::is_model(&state.hardware) {
            super::runtime::model::restart(&mut state.hardware)
                .map_err(|_| WirelessError::HardwareError)?;
            Some(self.mac)
        } else {
            None
        };
        #[cfg(not(any(test, feature = "kernel-test")))]
        let model: Option<[u8; 6]> = None;
        let mac = if let Some(mac) = model {
            mac
        } else {
            let mut parsed =
                super::parse_ucode(&self.firmware).map_err(|_| WirelessError::HardwareError)?;
            parsed.api.pnvm = self.pnvm.as_deref();
            state
                .hardware
                .restart(&parsed)
                .await
                .map_err(|_| WirelessError::HardwareError)?
        };
        if mac != self.mac {
            state.hardware.fail();
            return Err(WirelessError::HardwareError);
        }
        let nvm = Self::configure(&mut state.hardware, mac)
            .await
            .map_err(|_| WirelessError::HardwareError)?;
        if nvm.tx_chains != self.tx_chains
            || nvm.rx_chains != self.rx_chains
            || nvm.channels != self.channels
            || nvm.six_channels != self.six_channels
            || nvm.phy != self.phy
        {
            state.hardware.fail();
            return Err(WirelessError::HardwareError);
        }
        state.needs_reset = false;
        Ok(())
    }

    pub fn start_pumps(self: &Arc<Self>) -> Result<(), &'static str> {
        let authority =
            narf_net::trusted_net_authority().and_then(|authority| authority.derive().ok());
        self.start_pumps_with_authority(authority.as_ref())
    }

    fn start_pumps_with_authority(
        self: &Arc<Self>,
        authority: Option<&narf_capabilities::Cap<narf_net::NetIface, narf_capabilities::Grant>>,
    ) -> Result<(), &'static str> {
        self.publish_with_registration(authority, |authority, interface| {
            narf_net::registry()
                .register(authority, interface)
                .map_err(|_| "iwlwifi capability registry registration failed")
        })
    }

    fn publish_with_registration(
        self: &Arc<Self>,
        authority: Option<&narf_capabilities::Cap<narf_net::NetIface, narf_capabilities::Grant>>,
        register: impl FnOnce(
            &narf_capabilities::Cap<narf_net::NetIface, narf_capabilities::Grant>,
            RegisteredDevice,
        ) -> Result<
            narf_capabilities::Cap<narf_net::NetIface, narf_capabilities::Write>,
            &'static str,
        >,
    ) -> Result<(), &'static str> {
        // Claim before replacing any endpoint, checking global publication, or
        // obtaining a registry entry. A failed attempt requires a fresh owner.
        self.publication
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "iwlwifi publication already attempted")?;
        let authority = authority.ok_or("iwlwifi has no network publication authority")?;
        authority
            .check_live()
            .map_err(|_| "iwlwifi network publication authority revoked")?;
        let mut active = ACTIVE.lock();
        if active.is_some()
            || narf_net::iface::lookup(self.name()).is_some()
            || narf_wireless::registry::list()
                .iter()
                .any(|interface| interface.name() == self.name())
        {
            return Err("iwlwifi interface already registered");
        }
        let mut state = self
            .state
            .try_lock()
            .ok_or("iwlwifi unpublished device busy")?;
        let (rx_producer, rx_consumer) = narf_ipc::channel::<Frame, RX_RING_N>();
        let tx_channels = narf_wireless::AccessCategory::ALL.map(|category| {
            let (producer, consumer) = narf_ipc::channel::<Frame, TX_RING_N>();
            (category, producer, consumer)
        });
        // This is the final fallible publication step. Failure leaves all
        // staged channels private and never exposes ACTIVE/netdev/workers.
        self.source.invoke(|| {
            let parent = register(authority, RegisteredDevice(self.clone()))?;
            self.p2p.registered(*authority, parent);
            state.producer = Some(rx_producer);
            *self.rx.lock() = Some(rx_consumer);
            for (category, producer, consumer) in tx_channels {
                *self.tx[category as usize].lock() = Some(producer);
                state.tx[category as usize] = Some(consumer);
            }
            *active = Some(self.clone());
            Ok(())
        })?;
        drop(state);
        drop(active);
        self.source.invoke(|| {
            if !self.current_owner() {
                return Err("Intel publication owner replaced");
            }
            narf_net::iface::register(self.name(), self.mac, send_frame);
            narf_net::iface::set_link_metadata(self.name(), false, None, None);
            narf_net::iface::set_offloads(self.name(), super::csum::OFFLOADS);
            narf_net::iface::set_link_state(self.name(), false);
            narf_net::iface::install_rx_drain(drain_network);
            Ok(())
        })?;
        narf_power::system_pm::register_async_system_pm(
            "iwlwifi-mld",
            Arc::new(SystemPm(self.clone())),
        );
        let device = self.clone();
        narf_scheduler::spawn(async move {
            device.pump().await;
        });
        Ok(())
    }

    /// Linux non-WoWLAN system suspend (`iwl_mld_suspend` without WoWLAN):
    /// mac80211 quiesces the station with a deauthentication (the ordinary
    /// disconnect), then `iwl_mld_mac80211_stop` stops the transport.
    pub(super) async fn system_suspend(&self) -> Result<(), WirelessError> {
        if self.suspended.load(Ordering::Acquire) {
            return Ok(());
        }
        self.p2p.stop_retained().await?;
        if matches!(self.current_iftype(), 3 | 9) {
            let mut state = self.state.lock().await;
            self.stop_locked(&mut state).await;
            self.suspended.store(true, Ordering::Release);
            return if self.quarantined.load(Ordering::Acquire) {
                Err(WirelessError::HardwareError)
            } else {
                Ok(())
            };
        } else {
            WirelessNetIface::disassociate(self).await?;
        }
        let mut state = self.state.lock().await;
        if state.connection.is_some() || state.scheduled.is_some() {
            return Err(WirelessError::Busy);
        }
        state.needs_reset = true;
        state.clear_transmit();
        state.eapol.clear();
        state.beacons.clear();
        state.scan_seen.clear();
        #[cfg(any(test, feature = "kernel-test"))]
        let model = super::runtime::model::is_model(&state.hardware);
        #[cfg(not(any(test, feature = "kernel-test")))]
        let model = false;
        if model {
            state.hardware.fail();
        } else {
            state
                .hardware
                .stop_for_suspend()
                .await
                .map_err(|_| WirelessError::HardwareError)?;
        }
        self.set_link(false);
        self.suspended.store(true, Ordering::Release);
        Ok(())
    }

    /// Resume: `iwl_mld_mac80211_start` -> firmware restart and runtime
    /// configuration replay through the existing recovery owner. The
    /// station starts unassociated.
    pub(super) async fn system_resume(&self) -> Result<(), WirelessError> {
        if !self.suspended.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut state = self.state.lock().await;
        self.recover(&mut state).await?;
        self.suspended.store(false, Ordering::Release);
        Ok(())
    }

    fn set_link(&self, up: bool) {
        let _admission = self.admission.lock();
        self.set_link_locked(up);
    }
    fn set_link_locked(&self, up: bool) {
        if !up {
            if let Some(next) = self.generation.load(Ordering::Acquire).checked_add(1) {
                self.generation.store(next, Ordering::Release);
            } else {
                self.quarantined.store(true, Ordering::Release);
            }
            if let Some(rx) = self.rx.lock().as_mut() {
                for _ in 0..RX_RING_N {
                    if !matches!(rx.try_recv(), Ok(Some(_))) {
                        break;
                    }
                }
            }
        }
        let was_up = self.up.swap(up, Ordering::AcqRel);
        let current = self.current_owner();
        if current {
            narf_net::iface::set_link_metadata(self.name(), up, None, None);
        }
        // Physical carrier preserves operator-controlled IFF_UP and never
        // invokes an administrative open/stop hook under retained locks.
        if !up {
            self.bssid.store(0, Ordering::Release);
        }
        if was_up && !up && current && self.current_iftype() == 2 {
            narf_wireless::nl80211::notify_disconnect(self.name(), 1, false);
        }
    }
    fn current_owner(&self) -> bool {
        if !self.publication.load(Ordering::Acquire) {
            return true;
        }
        ACTIVE
            .lock()
            .as_ref()
            .is_some_and(|d| core::ptr::eq(Arc::as_ptr(d), self))
    }
    fn policy_current(&self) -> Result<(), &'static str> {
        match self.policy_fence.lock().as_ref() {
            Some(fence) => fence.check(),
            None if !self.up.load(Ordering::Acquire) => Ok(()),
            None => Err("Intel station publication lacks current RF policy"),
        }
    }
    fn install_station_policy(&self, state: &mut State) -> Result<(), &'static str> {
        let program = state
            .connection
            .as_ref()
            .ok_or("Intel station policy lacks association")?
            .regulatory_program();
        let fence = self.policy.bind(program)?;
        let authority = self.station_policy_with_scan(state, fence.clone());
        state.hardware.install_rf_policy(authority)?;
        *self.policy_fence.lock() = Some(fence);
        Ok(())
    }
    /// The retained transport owner stops autonomous firmware emission and
    /// pins uncertain DMA. It does not need continuing RF/source authority.
    async fn stop_locked(&self, state: &mut State) {
        self.retire_ap(state);
        self.set_link(false);
        self.retire_receive_ipc(state);
        state.needs_reset = true;
        self.abandon_scheduled(state);
        state.clear_transmit();
        state.eapol.clear();
        if let Some(connection) = state.connection.as_mut() {
            connection.authorized = false;
        }
        if !state.stop_completed {
            if state.hardware.stop_for_suspend().await.is_err() {
                self.quarantined.store(true, Ordering::Release);
            }
            state.stop_completed = true;
        }
        self.closing.store(false, Ordering::Release);
    }
    fn start_repair(self: &Arc<Self>, state: &mut State) {
        self.retire_ap(state);
        self.set_link(false);
        // Copied scan callbacks leave State before the retained physical
        // stop runs. Close their private owner at repair admission too.
        self.abandon_scheduled(state);
        self.retire_receive_ipc(state);
        state.needs_reset = true;
        state.hardware.fail();
        state.clear_transmit();
        state.eapol.clear();
        if let Some(connection) = state.connection.as_mut() {
            connection.authorized = false;
        }
        if state.stop_completed {
            return;
        }
        let Some(mut slot) = self.control.try_lock() else {
            return;
        };
        if slot.is_some() {
            return;
        }
        let device = self.clone();
        *slot = Some(Work::new(async move {
            let mut state = device.state.lock().await;
            device.stop_locked(&mut state).await;
        }));
    }

    fn healthy_close_pending(&self, state: &State) -> bool {
        self.closing.load(Ordering::Acquire)
            && !self.quarantined.load(Ordering::Acquire)
            && !state.hardware.is_failed()
            && self.current_owner()
            && self.source.invoke(|| Ok(())).is_ok()
            && self.policy_current().is_ok()
    }
    async fn close_locked(&self, state: &mut State) -> Result<(), WirelessError> {
        if state.ap.is_some() {
            self.stop_locked(state).await;
            return if self.quarantined.load(Ordering::Acquire) {
                Err(WirelessError::HardwareError)
            } else {
                Ok(())
            };
        }
        self.retire_scheduled(state)
            .await
            .map_err(|_| WirelessError::HardwareError)?;
        self.set_link(false);
        self.retire_receive_ipc(state);
        state.clear_transmit();
        state.eapol.clear();
        if state.connection.is_none() && (state.needs_reset || state.hardware.is_failed()) {
            self.stop_locked(state).await;
            return if self.quarantined.load(Ordering::Acquire) {
                Err(WirelessError::HardwareError)
            } else {
                Ok(())
            };
        }
        if let Some(connection) = state.connection.take() {
            state.needs_reset = true;
            if connection.disconnect(&mut state.hardware).await.is_err() {
                self.stop_locked(state).await;
                return Err(WirelessError::HardwareError);
            }
            state.hardware.clear_rf_policy();
            *self.policy_fence.lock() = None;
            state.needs_reset = false;
        }
        self.closing.store(false, Ordering::Release);
        Ok(())
    }
    fn start_close(self: &Arc<Self>, state: &mut State) {
        state.clear_transmit();
        state.eapol.clear();
        self.retire_receive_ipc(state);
        if let Some(connection) = state.connection.as_mut() {
            connection.authorized = false;
        }
        let Some(mut slot) = self.control.try_lock() else {
            return;
        };
        if slot.is_some() {
            return;
        }
        let device = self.clone();
        *slot = Some(Work::new(async move {
            let mut state = device.state.lock().await;
            if device.closing.load(Ordering::Acquire) {
                let _ = device.close_locked(&mut state).await;
            }
        }));
    }

    fn publish_link(&self, bssid: [u8; 6], epoch: u64) -> Result<(), &'static str> {
        let _admission = self.admission.lock();
        self.source.invoke(|| {
            self.policy_current()?;
            if self.generation.load(Ordering::Acquire) != epoch
                || self.quarantined.load(Ordering::Acquire)
                || self.closing.load(Ordering::Acquire)
                || !self.current_owner()
            {
                return Err("Intel station publication retired before carrier");
            }
            self.store_bssid(bssid);
            self.up.store(true, Ordering::Release);
            narf_net::iface::set_link_metadata(self.name(), true, None, None);
            Ok(())
        })
    }
    fn source_failed(&self, epoch: u64) {
        let _admission = self.admission.lock();
        if self.generation.load(Ordering::Acquire) != epoch {
            return;
        }
        self.quarantined.store(true, Ordering::Release);
        self.set_link_locked(false);
    }

    fn retire_receive_ipc(&self, state: &mut State) {
        state.receive_ipc = None;
        state.receive_ap_data = None;
        state.producer = None;
        *self.rx.lock() = None;
    }

    /// Called under the native state owner, never a stack callback. Replacing
    /// both endpoints discards queued old-key copies as well as stale outputs.
    fn refresh_receive_ipc(&self, state: &mut State) -> Result<(), &'static str> {
        let _admission = self.admission.lock();
        if state.needs_reset
            || !state.eapol.is_empty()
            || !(state.connection.as_ref().is_some_and(|c| c.authorized)
                || state.ap.as_ref().is_some_and(|ap| ap.current().is_ok()))
            || !self.up.load(Ordering::Acquire)
            || self.quarantined.load(Ordering::Acquire)
            || !self.current_owner()
        {
            self.retire_receive_ipc(state);
            return Ok(());
        }
        let Some(receive) = state.hardware.receive_publication() else {
            self.retire_receive_ipc(state);
            return Ok(());
        };
        let ap_data = state.ap.as_ref().map(|ap| ap.data_publication());
        let source = if state.ap.is_some() {
            state.hardware.source_fence()?
        } else {
            self.source.clone()
        };
        let result = source.invoke(|| {
            self.policy_current()?;
            if !receive.current() || ap_data.as_ref().is_some_and(|data| !data.current()) {
                return Err("Intel RX IPC key epoch closed");
            }
            let ap_changed = match (&state.receive_ap_data, &ap_data) {
                (None, None) => false,
                (Some(old), Some(new)) => !old.same_epoch(new),
                _ => true,
            };
            if state
                .receive_ipc
                .as_ref()
                .is_none_or(|old| !old.same_epoch(&receive))
                || ap_changed
                || state.producer.is_none()
            {
                let (producer, consumer) = narf_ipc::channel();
                state.producer = Some(producer);
                *self.rx.lock() = Some(consumer);
                state.receive_ipc = Some(receive);
                state.receive_ap_data = ap_data;
            }
            Ok(())
        });
        if result.is_err() {
            self.retire_receive_ipc(state);
        }
        result
    }

    /// Cache the associated BSSID for a lock-free `connected_bssid` read.
    fn store_bssid(&self, bssid: [u8; 6]) {
        let mut packed = 1u64 << 63;
        for (i, byte) in bssid.iter().enumerate() {
            packed |= (*byte as u64) << (8 * i);
        }
        self.bssid.store(packed, Ordering::Release);
    }

    fn cached_bssid(&self) -> Option<[u8; 6]> {
        let packed = self.bssid.load(Ordering::Acquire);
        (packed & (1 << 63) != 0).then(|| core::array::from_fn(|i| (packed >> (8 * i)) as u8))
    }

    /// Nonblocking drain used both by the executor and synchronous IP
    /// waits. Dispatch to the network stack only after releasing state:
    /// an ARP/ICMP response can call send_frame synchronously.
    fn step(self: &Arc<Self>, cx: Option<&mut Context<'_>>) -> Vec<Delivery> {
        let outcome = self.step_owned(cx);
        // Every native State/control guard is gone before a source/cache
        // callback can run, including receive/transport error paths.
        for publication in outcome.radio {
            publication.publish();
        }
        for publication in outcome.ap {
            publication.publish();
        }
        for publication in self.client_publications() {
            publication.publish();
        }
        outcome.data
    }

    fn step_owned(self: &Arc<Self>, mut cx: Option<&mut Context<'_>>) -> StepOutcome {
        let mut outcome = StepOutcome::default();
        let mut output = Vec::new();
        let epoch = self.generation.load(Ordering::Acquire);
        if !self.current_owner() {
            return outcome;
        }
        let mut fallback = Context::from_waker(Waker::noop());
        let ap_lost = self.ap_currentness(cx.as_deref_mut().map(|cx| cx.waker()));
        let control_pending = self
            .poll_control(cx.as_deref_mut().unwrap_or(&mut fallback))
            .is_pending();
        // Either retained future may own State while the other awaits it.
        // Drive both slots before returning, including after waiter drops.
        let p2p_busy = self.p2p.step(cx.as_deref_mut());
        if control_pending || p2p_busy {
            return outcome;
        }
        let source_lost = self.source.invoke(|| Ok(())).is_err();
        let policy_lost = self.policy_current().is_err();
        if source_lost {
            self.source_failed(epoch);
        }
        if policy_lost && self.up.load(Ordering::Acquire) {
            self.set_link(false);
        }
        let Some(mut state) = self.state.try_lock() else {
            return outcome;
        };
        if source_lost
            || ap_lost
            || policy_lost
            || state.needs_reset
            || self.quarantined.load(Ordering::Acquire)
        {
            self.start_repair(&mut state);
            return outcome;
        }
        if self.closing.load(Ordering::Acquire) {
            self.start_close(&mut state);
            return outcome;
        }
        if let Some(check) = self.scheduled_currentness(&state) {
            // Source/socket callbacks may consult shared state. Never invoke
            // them under the native owner mutex; revalidate the exact private
            // owner and device generation after reacquiring it.
            drop(state);
            let current = check.current(self.as_ref());
            let Some(reacquired) = self.state.try_lock() else {
                return outcome;
            };
            state = reacquired;
            if self.generation.load(Ordering::Acquire) != epoch || !check.matches(&state) {
                return outcome;
            }
            if !current {
                self.start_scheduled_retirement();
                return outcome;
            }
        }
        let ap_data = state.ap.as_ref().map(|ap| ap.data_publication());
        if state.hardware.poll().is_err() {
            self.start_repair(&mut state);
            return outcome;
        }
        let mut receive_budget = 64;
        if state.scheduled.is_some() {
            let (publications, inspected) = self.scheduled_step_with_budget(&mut state);
            outcome.radio = publications;
            receive_budget = inspected;
            if state.connection.is_none() || state.needs_reset {
                return outcome;
            }
        }
        let mut receive_failed = false;
        let State {
            hardware,
            connection,
            eapol,
            ap,
            ap_probes,
            ..
        } = &mut *state;
        hardware.retire_transmits();
        if let Some(ap) = ap {
            for _ in 0..receive_budget {
                let Some(packet) = hardware.notifications.pop_front() else {
                    break;
                };
                match ap.receive(&packet, hardware) {
                    Ok(received) => {
                        if let Some(data) = received.data {
                            output.push((data, narf_net::RxMeta::default()));
                        }
                        if let Some(event) = received.event {
                            outcome.ap.extend(self.ap_publications(ap, hardware, event));
                        }
                        if let Some(probe) = received.probe {
                            if ap_probes.len() < 8 {
                                ap_probes.push_back(probe);
                            }
                        }
                    }
                    Err(_) => {
                        receive_failed = true;
                        break;
                    }
                }
            }
        } else if let Some(connection) = connection {
            for _ in 0..receive_budget {
                let Some(packet) = hardware.notifications.pop_front() else {
                    break;
                };
                match connection
                    .receive_packet_checked(&packet, hardware.rx_checksum_includes_snap())
                {
                    Ok(frames) => {
                        for (bytes, meta) in frames {
                            queue_ethernet(bytes, meta, connection.authorized, eapol, &mut output);
                        }
                    }
                    Err(_) => {
                        connection.authorized = false;
                        receive_failed = true;
                        break;
                    }
                }
            }
            // link.c iwl_mld_handle_missed_beacon_notif ->
            // ieee80211_cqm_beacon_loss_notify (as set_link_locked emits
            // its nl80211 event under the owner lock).
            if connection.take_cqm_beacon_loss() && self.current_owner() {
                narf_wireless::nl80211::notify_cqm_beacon_loss(self.name());
            }
            match connection.reorder_tick() {
                Ok(frames) => {
                    for bytes in frames {
                        queue_ethernet(
                            bytes,
                            narf_net::RxMeta::default(),
                            connection.authorized,
                            eapol,
                            &mut output,
                        );
                    }
                }
                Err(_) => {
                    connection.authorized = false;
                    receive_failed = true;
                }
            }
            if narf_time::now_cycles().wrapping_sub(connection.last_beacon)
                > narf_time::wall::ns_to_cycles(10_000_000_000)
            {
                connection.authorized = false;
                receive_failed = true;
            }
        } else {
            hardware.notifications.clear();
        }
        if receive_failed {
            // Closing carrier alone leaves firmware's autonomous station
            // and DMA alive. The retained owner must perform the ordinary
            // bounded transport stop, preserving allocations on ambiguity.
            self.start_repair(&mut state);
            return outcome;
        }
        if ap_data.as_ref().is_some_and(|data| !data.current()) {
            // A real peer-loss management notification can follow DATA in the
            // same drain. Preserve its typed event, but never rebind older DATA
            // to the new host authorization generation at final publication.
            output.clear();
        }
        let maintenance = !state.needs_reset
            && !state.hardware.is_failed()
            && state.connection.as_ref().is_some_and(|connection| {
                connection.authorized
                    && (!state.eapol.is_empty() || connection.maintenance_pending())
            });
        if maintenance {
            self.start_control(&mut state);
        } else if !self.link_up() {
            state.clear_transmit();
        } else if state.progress_transmit(cx.as_deref_mut()).is_err() {
            state.hardware.fail();
            state.needs_reset = true;
            state.clear_transmit();
            self.set_link(false);
        }
        if self.refresh_receive_ipc(&mut state).is_err() {
            self.source_failed(epoch);
            return outcome;
        }
        let mut deliveries = Vec::new();
        let receive = state.hardware.receive_publication();
        let policy = self.policy_fence.lock().clone();
        for (bytes, meta) in output {
            let Some(policy) = policy.clone() else {
                break;
            };
            let Some(receive) = receive.clone() else {
                break;
            };
            let delivery = Delivery {
                bytes,
                source: if state.ap.is_some() {
                    match state.hardware.source_fence() {
                        Ok(fence) => fence,
                        Err(_) => break,
                    }
                } else {
                    self.source.clone()
                },
                generation: self.generation.clone(),
                epoch,
                receive,
                ap_data: ap_data.clone(),
                policy,
            };
            let published = {
                let _admission = self.admission.lock();
                delivery.invoke(|| {
                    if !self.link_up()
                        || self.quarantined.load(Ordering::Acquire)
                        || !self.current_owner()
                    {
                        return Err("Intel RX publication closed");
                    }
                    if let (Some(producer), Ok(buffer)) = (
                        &mut state.producer,
                        super::runtime::dma_alloc(delivery.bytes.len()),
                    ) {
                        let mut frame = Frame::new(buffer, delivery.bytes.len() as u32);
                        frame.payload_mut().copy_from_slice(&delivery.bytes);
                        frame.set_rx_meta(meta);
                        let _ = producer.try_send(frame);
                    }
                    Ok(())
                })
            };
            if published.is_ok() {
                deliveries.push(delivery);
            } else if delivery.current() {
                if self.policy_current().is_err() {
                    self.set_link(false);
                } else {
                    self.source_failed(epoch);
                }
                break;
            }
        }
        drop(state);
        if maintenance {
            let _ = self.poll_control(cx.unwrap_or(&mut fallback));
        }
        outcome.data = deliveries;
        outcome
    }
    /// The slot owns the complete future, including its device-state guard.
    /// Polling an external waiter is never required for firmware progress.
    fn poll_control(&self, cx: &mut Context<'_>) -> Poll<()> {
        super::progress::poll_work(&self.control, cx)
    }

    async fn finish_control(&self) {
        poll_fn(|cx| self.poll_control(cx)).await;
    }

    fn start_control(self: &Arc<Self>, state: &mut State) {
        let Some(mut slot) = self.control.try_lock() else {
            return;
        };
        if slot.is_some() {
            return;
        }
        // Close the actual consumer before publishing retained EAPOL work,
        // even if it must wait to acquire state or native M4/key receipts.
        if !state.eapol.is_empty() {
            self.retire_receive_ipc(state);
        }
        let device = self.clone();
        *slot = Some(Work::new(async move {
            let mut state = device.state.lock().await;
            if state.needs_reset || state.hardware.is_failed() {
                return;
            }
            // An unexpected drop of the retained owner also fails closed.
            state.needs_reset = true;
            let result = async {
                let State {
                    hardware,
                    connection,
                    eapol,
                    scheduled,
                    ..
                } = &mut *state;
                if let Some(connection) = connection {
                    connection.set_scheduled_scan_busy(scheduled.is_some());
                    for _ in 0..16 {
                        let Some(frame) = eapol.pop_front() else {
                            break;
                        };
                        connection.handle_eapol(hardware, &frame).await?;
                    }
                    connection.service_aggregation(hardware).await?;
                } else {
                    eapol.clear();
                }
                Ok::<(), &'static str>(())
            }
            .await;
            if result.is_err() {
                state.hardware.fail();
                if let Some(connection) = &mut state.connection {
                    connection.authorized = false;
                }
                state.clear_transmit();
                device.stop_locked(&mut state).await;
            } else {
                state.needs_reset = false;
                if device.refresh_receive_ipc(&mut state).is_err() {
                    state.hardware.fail();
                    state.needs_reset = true;
                    state.clear_transmit();
                    device.stop_locked(&mut state).await;
                }
            }
        }));
    }

    async fn pump(self: Arc<Self>) {
        loop {
            // Provider retirement wakes this owner immediately. The bounded
            // AP timer also re-invokes generic cap epochs, which have no wake
            // callback, and drives physical beacon stop after revocation.
            let mut activity = super::iwl_msix::Activity::new(
                self.irq_vector,
                if matches!(self.current_iftype(), 3 | 9) || self.p2p.active() {
                    1
                } else {
                    100
                },
            );
            // Re-enter step on every wake, including IPC producer and retained
            // control wakes. Awaiting Activity alone would swallow those wakes
            // until the next unrelated radio interrupt or fallback timer.
            let frames = poll_fn(|cx| {
                let frames = self.step(Some(cx));
                let pending = self.state.try_lock().is_some_and(|state| {
                    !state.hardware.is_failed()
                        && (state.hardware.has_pending_rx()
                            || !state.hardware.notifications.is_empty()
                            || state.tx_progress)
                });
                if !frames.is_empty() || pending || Pin::new(&mut activity).poll(cx).is_ready() {
                    Poll::Ready(frames)
                } else {
                    Poll::Pending
                }
            })
            .await;
            self.dispatch(frames);
            narf_scheduler::yield_now().await;
        }
    }
    fn dispatch(&self, deliveries: Vec<Delivery>) -> bool {
        self.dispatch_with(deliveries, |bytes| {
            narf_net::iface::on_rx_frame_from(self.name(), bytes);
        })
    }
    fn dispatch_with(
        &self,
        deliveries: Vec<Delivery>,
        mut callback: impl FnMut(&mut Vec<u8>),
    ) -> bool {
        let progress = !deliveries.is_empty();
        for mut delivery in deliveries {
            let fence = delivery.clone();
            if !fence.current() {
                continue;
            }
            if fence
                .invoke(|| {
                    if !self.link_up()
                        || self.quarantined.load(Ordering::Acquire)
                        || !self.current_owner()
                    {
                        return Err("Intel stack publication closed");
                    }
                    // No owner, admission or ring lock is held by this callback.
                    callback(&mut delivery.bytes);
                    Ok(())
                })
                .is_err()
                && fence.current()
            {
                if self.policy_current().is_err() {
                    self.set_link(false);
                } else {
                    self.source_failed(fence.epoch);
                }
                break;
            }
        }
        progress
    }
}

fn queue_ethernet(
    bytes: Vec<u8>,
    meta: narf_net::RxMeta,
    authorized: bool,
    eapol: &mut VecDeque<Vec<u8>>,
    output: &mut Vec<(Vec<u8>, narf_net::RxMeta)>,
) {
    if bytes[12..14] == [0x88, 0x8e] {
        if eapol.len() < 16 {
            eapol.push_back(bytes);
        }
    } else if authorized {
        output.push((bytes, meta));
    }
}

impl Interface for Device {
    fn name(&self) -> &str {
        #[cfg(any(test, feature = "kernel-test"))]
        if let Some(name) = self.test_name {
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
            && !self.closing.load(Ordering::Acquire)
            && !self.quarantined.load(Ordering::Acquire)
            && self.current_owner()
            && self.source.invoke(|| Ok(())).is_ok()
            && self.policy_current().is_ok()
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx[1]
    }
}

impl Device {
    async fn associate_in_domain(
        &self,
        request: AssociateRequest,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<(), WirelessError> {
        self.associate_links(request, domain, false).await
    }

    /// A fresh station association. `mlo` is cfg80211's
    /// `CONNECT_REQ_MLO_SUPPORT`: only then are further affiliated links
    /// of the AP MLD requested and the connection reported as MLO.
    async fn associate_links(
        &self,
        request: AssociateRequest,
        domain: &narf_wireless::reg::RegulatoryDomain,
        mlo: bool,
    ) -> Result<(), WirelessError> {
        use super::connection::AuthMethod;
        *self.mlo_report.lock() = None;
        let client_role = (self.current_iftype() == 8).then(|| self.ap_host.role.lock().observe());
        let auth = match request.security {
            narf_wireless::SecurityConfig::Open => AuthMethod::Open,
            narf_wireless::SecurityConfig::Wpa2 { psk } => AuthMethod::Wpa2Psk(psk),
            narf_wireless::SecurityConfig::Wpa3 { password } => AuthMethod::Wpa3Sae { password },
            // No external-supplicant mode (the MLD firmware path runs the
            // handshake itself; nl80211 never builds this for it).
            narf_wireless::SecurityConfig::External(_) => return Err(WirelessError::NotSupported),
        };
        if request.ssid.len() > 32 || request.bssid[0] & 1 != 0 {
            return Err(WirelessError::InvalidArgs);
        }
        self.finish_control().await;
        if self.closing.load(Ordering::Acquire) {
            return Err(WirelessError::Busy);
        }
        let mut state = self.state.try_lock().ok_or(WirelessError::Busy)?;
        if state.hardware.p2p_started() {
            return Err(WirelessError::Busy);
        }
        if state.needs_reset
            || state.hardware.is_failed()
            || state
                .connection
                .as_ref()
                .is_some_and(|connection| !connection.authorized)
        {
            self.recover(&mut state).await?;
            if self.closing.load(Ordering::Acquire) {
                return Err(WirelessError::Busy);
            }
        }
        if state.connection.is_some() || state.scheduled.is_some() {
            return Err(WirelessError::Busy);
        }
        let epoch = self.generation.load(Ordering::Acquire);
        self.source
            .invoke(|| Ok(()))
            .map_err(|_| WirelessError::HardwareError)?;
        let beacon = state
            .beacons
            .iter()
            .find(|b| {
                b.bssid == request.bssid
                    && b.ssid == request.ssid
                    && b.channel as u32 == request.channel
                    && super::native_band::Channel::from_frequency(b.channel, request.frequency_mhz)
                        == Some(super::native_band::Channel {
                            band: b.band,
                            number: b.channel,
                        })
            })
            .cloned()
            .ok_or(WirelessError::InvalidArgs)?;
        let client = client_role
            .map(|role| {
                super::p2p_client::Plan::new(self.mac, &beacon, &request.ie)
                    .map(|plan| (plan, role))
            })
            .transpose()
            .map_err(|_| WirelessError::InvalidArgs)?;
        // Cancellation leaves this set. The pump fails closed rather
        // than driving partially configured station/queue state.
        state.needs_reset = true;
        state.stop_completed = false;
        state
            .hardware
            .install_rf_policy(super::mld_policy::Authority::Transaction(
                self.policy
                    .transaction(domain)
                    .map_err(|_| WirelessError::HardwareError)?,
            ))
            .map_err(|_| WirelessError::HardwareError)?;
        // An MLO-permitted station association requests every other
        // affiliated link of the same AP MLD seen in the latest scan; the
        // native owner then admits or drops each one (a P2P client never
        // does MLO). Without CONNECT_REQ_MLO_SUPPORT the driver "shall
        // disable MLO features": no further link is requested.
        let further = if client.is_none() && mlo {
            super::sc_mlo_assoc::scan_candidates(
                &beacon,
                &state.beacons,
                |b| state.scan_seen.contains(&(b.bssid, b.band, b.channel)),
                self.mac,
                || {
                    let bytes = super::security::fresh_nonce()?;
                    let mut address = [0; 6];
                    address.copy_from_slice(&bytes[..6]);
                    Ok(address)
                },
            )
            // Without a link address nothing further is requested.
            .unwrap_or_default()
        } else {
            Vec::new()
        };
        let bssid = request.bssid;
        match Connection::associate_links_in_domain(
            &mut state.hardware,
            self.mac,
            beacon,
            auth,
            self.tx_chains,
            self.phy,
            None,
            domain,
            client,
            further,
        )
        .await
        {
            Ok(connection) => {
                if mlo {
                    *self.mlo_report.lock() = connection.mlo_report();
                }
                state.connection = Some(connection);
                if self.install_station_policy(&mut state).is_err() {
                    self.stop_locked(&mut state).await;
                    return Err(WirelessError::HardwareError);
                }
                state.needs_reset = false;
                let result = self
                    .publish_link(bssid, epoch)
                    .and_then(|()| self.refresh_receive_ipc(&mut state));
                if result.is_err() {
                    if self.healthy_close_pending(&state) {
                        // The terminal M4/key owner is still valid. Close
                        // owns its ordered native retirement; never publish
                        // data while that close waits for this state guard.
                        state.connection.as_mut().unwrap().authorized = false;
                    } else {
                        self.stop_locked(&mut state).await;
                    }
                }
                result.map_err(|_| WirelessError::HardwareError)
            }
            Err(error) => {
                use core::fmt::Write;
                let _ = writeln!(
                    narf_console::Writer,
                    "iwlwifi: association failed: {}",
                    error
                );
                self.stop_locked(&mut state).await;
                Err(WirelessError::HardwareError)
            }
        }
    }
}

#[async_trait::async_trait]
impl WirelessNetIface for Device {
    fn async_control_interfaces(&self) -> bool {
        self.p2p_capable()
    }
    fn supports_virtual_interfaces(&self) -> bool {
        self.p2p_capable()
    }
    fn p2p_interface_types(&self) -> Vec<u32> {
        let mut types = Vec::new();
        if self.go_capable {
            types.push(8);
            types.push(9);
        }
        if self.p2p_capable() {
            types.push(10);
        }
        types
    }
    async fn new_control_interface_async(
        &self,
        authority: &narf_wireless::ap_control::RadioControlAuthority,
        name: &str,
        iftype: u32,
        mac: Option<[u8; 6]>,
    ) -> Result<Arc<dyn WirelessNetIface>, WirelessError> {
        self.new_p2p_control(authority, name, iftype, mac).await
    }
    fn current_iftype(&self) -> u32 {
        self.mode.load(Ordering::Acquire)
    }
    fn set_iftype(&self, mode: u32) -> Result<(), WirelessError> {
        self.ap_set_mode(mode)
    }
    fn supports_ap(&self) -> bool {
        self.ap_capable
    }
    fn supports_ap_uapsd(&self) -> bool {
        self.ap_capable
    }
    fn max_ap_assoc_sta(&self) -> u32 {
        if self.ap_capable {
            super::ap_wire::MAX_PEERS as u32
        } else {
            0
        }
    }
    fn supports_ap_userspace_mlme(&self) -> bool {
        self.ap_capable
    }
    fn supports_ap_authenticator(&self) -> bool {
        self.ap_capable
    }
    fn supports_control_port_tx_status(&self) -> bool {
        self.ap_capable
    }
    fn supports_ap_key_sequence(&self) -> bool {
        self.current_iftype() == 9 && self.go_capable
    }
    async fn key_sequence_ap_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        index: u8,
        pairwise: bool,
        peer: Option<[u8; 6]>,
    ) -> Result<narf_wireless::KeySequence, i32> {
        self.ap_key_sequence(authority, index, pairwise, peer)
    }
    fn supports_control_port_no_preauth(&self) -> bool {
        self.ap_capable
    }
    fn cipher_suites(&self) -> &'static [u32] {
        if self.ap_capable {
            &[
                narf_wireless::CIPHER_SUITE_CCMP,
                narf_wireless::CIPHER_SUITE_AES_CMAC,
            ]
        } else {
            &[narf_wireless::CIPHER_SUITE_CCMP]
        }
    }
    fn ap_control_generation(&self) -> Option<core::num::NonZeroU64> {
        self.ap_capable
            .then(|| core::num::NonZeroU64::new(self.mode_generation.load(Ordering::Acquire)))
            .flatten()
    }
    fn reserve_ap_control(
        &self,
    ) -> Result<Option<Arc<dyn narf_wireless::ap_control::ApControlReservation>>, WirelessError>
    {
        self.radio_control.try_reserve().map(Some)
    }
    async fn start_ap_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        config: narf_wireless::ApConfig,
    ) -> Result<(), WirelessError> {
        self.start_ap_with_settings_async(
            authority,
            config,
            narf_wireless::ApStartSettings::default(),
        )
        .await
    }
    async fn start_ap_with_settings_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        config: narf_wireless::ApConfig,
        settings: narf_wireless::ApStartSettings,
    ) -> Result<(), WirelessError> {
        self.ap_control(
            authority,
            ap::Operation::Start(Box::new(config), Box::new(settings)),
        )
        .await
        .map(|_| ())
        .map_err(ap::error)
    }
    async fn stop_ap_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
    ) -> Result<(), WirelessError> {
        self.ap_control(authority, ap::Operation::Stop)
            .await
            .map(|_| ())
            .map_err(ap::error)
    }
    async fn set_beacon_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        head: Option<Vec<u8>>,
        tail: Option<Vec<u8>>,
        probe: Option<Vec<u8>>,
    ) -> Result<(), WirelessError> {
        self.ap_control(authority, ap::Operation::Beacon(head, tail, probe))
            .await
            .map(|_| ())
            .map_err(ap::error)
    }
    fn supports_p2p_go_power_save(&self) -> bool {
        true
    }
    async fn set_p2p_go_power_save_ap_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        settings: narf_wireless::P2pGoPowerSave,
    ) -> Result<(), WirelessError> {
        authority.check_for(self)?;
        authority.require_up()?;
        settings.validate()?;
        self.ap_control(authority, ap::Operation::SetGoPowerSave(settings))
            .await
            .map(|_| ())
            .map_err(ap::error)
    }
    async fn add_station_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        station: narf_wireless::StationConfig,
    ) -> Result<(), WirelessError> {
        self.ap_control(authority, ap::Operation::Add(station))
            .await
            .map(|_| ())
            .map_err(ap::error)
    }
    async fn set_station_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        station: narf_wireless::StationConfig,
    ) -> Result<(), WirelessError> {
        self.ap_control(authority, ap::Operation::Set(station))
            .await
            .map(|_| ())
            .map_err(ap::error)
    }
    async fn del_station_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        peer: Option<[u8; 6]>,
        _reason: u16,
    ) -> Result<(), WirelessError> {
        self.ap_control(authority, ap::Operation::Delete(peer))
            .await
            .map(|_| ())
            .map_err(ap::error)
    }
    async fn add_key_ap_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        key: narf_wireless::OwnedKey,
    ) -> Result<(), i32> {
        self.ap_control(authority, ap::Operation::Key(key))
            .await
            .map(|_| ())
    }
    async fn del_key_ap_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        index: u8,
        pairwise: bool,
        peer: Option<[u8; 6]>,
    ) -> Result<(), i32> {
        self.ap_control(authority, ap::Operation::DeleteKey(index, pairwise, peer))
            .await
            .map(|_| ())
    }
    async fn default_key_ap_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        index: u8,
        unicast: bool,
        multicast: bool,
        management: bool,
        beacon: bool,
    ) -> Result<(), i32> {
        self.ap_control(
            authority,
            ap::Operation::DefaultKey(index, unicast, multicast, management, beacon),
        )
        .await
        .map(|_| ())
    }
    async fn tx_control_port_ap_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        request: narf_wireless::ControlPortTxRequest,
    ) -> Result<bool, i32> {
        self.ap_control(authority, ap::Operation::Control(request))
            .await
    }
    async fn mgmt_tx_ap_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        _cookie: u64,
        request: narf_wireless::MgmtTxRequest,
    ) -> Result<bool, WirelessError> {
        self.ap_control(authority, ap::Operation::Management(request))
            .await
            .map_err(ap::error)
    }
    async fn register_mgmt_frame_ap_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        frame_type: u16,
        prefix: Vec<u8>,
    ) -> Result<(), WirelessError> {
        self.ap_register(authority, frame_type, prefix)
    }
    fn async_p2p_netdev_management_tx_control(&self) -> bool {
        matches!(self.current_iftype(), 8 | 9) && self.go_capable
    }
    fn async_p2p_netdev_management_rx_control(&self) -> bool {
        matches!(self.current_iftype(), 8 | 9) && self.go_capable
    }
    async fn mgmt_tx_radio_async(
        &self,
        authority: &narf_wireless::ap_control::RadioControlAuthority,
        cookie: u64,
        request: narf_wireless::MgmtTxRequest,
    ) -> Result<bool, WirelessError> {
        if self.current_iftype() == 8 {
            return self.client_frame(authority, cookie, request).await;
        }
        let original = authority.go_ap_control_for(self)?;
        self.mgmt_tx_ap_async(&original, cookie, request).await
    }
    async fn register_mgmt_frame_radio_async(
        &self,
        authority: &narf_wireless::ap_control::RadioControlAuthority,
        frame_type: u16,
        prefix: &[u8],
    ) -> Result<(), i32> {
        if self.current_iftype() == 8 {
            return self.client_register(authority, frame_type, prefix);
        }
        let original = authority.go_ap_control_for(self).map_err(|_| 1)?;
        self.register_mgmt_frame_ap_async(&original, frame_type, prefix.to_vec())
            .await
            .map_err(|error| match error {
                WirelessError::Busy => 16,
                WirelessError::InvalidArgs => 22,
                WirelessError::NotSupported => 95,
                WirelessError::Denied => 1,
                _ => 5,
            })
    }
    fn radio_control_generation(&self) -> Option<core::num::NonZeroU64> {
        if matches!(self.current_iftype(), 3 | 8 | 9) {
            return core::num::NonZeroU64::new(self.mode_generation.load(Ordering::Acquire));
        }
        core::num::NonZeroU64::new(self.generation.load(Ordering::Acquire).checked_add(1)?)
    }
    fn reserve_radio_control(
        &self,
    ) -> Result<Option<Arc<dyn narf_wireless::ap_control::ApControlReservation>>, WirelessError>
    {
        self.radio_control.try_reserve().map(Some)
    }
    fn sched_scan_support(&self) -> Option<narf_wireless::SchedScanSupport> {
        Some(self.scheduled_support())
    }
    fn async_sched_scan_control(&self) -> bool {
        true
    }
    fn sched_scan_pass_all(&self) -> bool {
        true
    }
    async fn start_sched_scan_async(
        &self,
        authority: &narf_wireless::ap_control::RadioControlAuthority,
        request: narf_wireless::SchedScanRequest,
    ) -> Result<(), i32> {
        self.scheduled_control(authority, Some(request)).await
    }
    async fn stop_sched_scan_async(
        &self,
        authority: &narf_wireless::ap_control::RadioControlAuthority,
    ) -> Result<(), i32> {
        self.scheduled_control(authority, None).await
    }
    fn max_scan_ssids(&self) -> u8 {
        20
    }

    fn phy_capabilities(&self, band_mhz: u32) -> Option<narf_wireless::iface::PhyCapabilities> {
        if band_mhz == 6000 || matches!(self.current_iftype(), 3 | 8 | 9) {
            None
        } else {
            self.phy.capabilities(band_mhz)
        }
    }
    fn tx_ring_for_ac(
        &self,
        category: narf_wireless::AccessCategory,
    ) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx[category as usize]
    }

    fn supports_handshake_offload(&self) -> bool {
        true
    }
    fn supports_sae_offload(&self) -> bool {
        // The driver runs the SAE exchange and the AKM-SAE 4-way handshake
        // in-kernel (WPA3-Personal), so nl80211 advertises SAE_OFFLOAD.
        true
    }
    /// mld/mac80211.c `iwl_mac_hw_set_wiphy`: WIPHY_FLAG_SUPPORTS_MLO when
    /// the NVM enables 11be (here: the admitted native EHT PHY, which the
    /// multiple-link request path requires).
    fn supports_mlo(&self) -> bool {
        self.phy.eht
    }
    /// mld/mac80211.c `iwl_mac_hw_set_wiphy` station `ext_capab[0]` on an
    /// 11be NVM: IWL_MLD_EMLSR_CAPA as EML capabilities, exactly what the
    /// native multiple-link request carries. `mld_capa_and_ops` stays 0:
    /// `sc_ttlm_neg` holds the negotiated TID-to-link mapping and link
    /// reconfiguration frame engine (wire values verified #1553), but no
    /// Protected EHT Action RX/TX transport and no `set_ttlm` /
    /// `assoc_ml_reconf` request path reach it yet, so neither the
    /// TTLM-negotiation bits nor `LINK_RECONF_SUPPORT` are claimed (Linux
    /// mac80211 only advertises what `ieee80211_process_neg_ttlm_req` /
    /// `ieee80211_process_ml_reconf_resp` actually service). There is no
    /// UHR ML power management, so `ext_mld_capa_and_ops` stays 0, and no
    /// Extended Capabilities bit (ext_capa_base) is claimed because the
    /// native request carries no Extended Capabilities element.
    fn iftype_extended_capabilities(&self) -> Vec<narf_wireless::IftypeExtendedCapability> {
        if !self.supports_mlo() {
            return Vec::new();
        }
        alloc::vec![narf_wireless::IftypeExtendedCapability {
            iftype: 2, // NL80211_IFTYPE_STATION
            capabilities: Vec::new(),
            mask: Vec::new(),
            eml_capabilities: narf_wireless::association::mlo::EmlCapabilities::INTEL_MLD_LOCAL.0,
            mld_capa_and_ops: 0,
            ext_mld_capa_and_ops: 0,
        }]
    }
    fn reports_disconnect_events(&self) -> bool {
        true
    }

    fn scan_information_elements(&self, bssid: [u8; 6]) -> Option<Vec<u8>> {
        self.state
            .try_lock()?
            .beacons
            .iter()
            .find(|b| b.bssid == bssid)
            .map(|b| b.information_elements.clone())
    }
    fn get_wireless_info(&self) -> WirelessIfaceInfo {
        use narf_wireless::iface::*;
        WirelessIfaceInfo {
            base_name: self.name().into(),
            base_mac: self.mac,
            bands: [2400, 5000, 6000]
                .into_iter()
                .filter(|&band| band != 6000 || !self.six_channels.is_empty())
                .map(|freq_mhz| WirelessBand {
                    freq_mhz,
                    channels: if freq_mhz == 6000 {
                        self.six_channels
                            .iter()
                            .map(|ch| u32::from(ch.number))
                            .collect()
                    } else {
                        self.channels
                            .iter()
                            .copied()
                            .filter(|&ch| (ch <= 14) == (freq_mhz == 2400))
                            .map(u32::from)
                            .collect()
                    },
                })
                .collect(),
            modes: (if self.ap_capable {
                WirelessModes::STATION | WirelessModes::AP
            } else {
                WirelessModes::STATION
            }) | if self.go_capable || self.p2p_capable() {
                WirelessModes::P2P
            } else {
                WirelessModes::empty()
            },
            hw_caps: HwCaps {
                ht_supported: !matches!(self.current_iftype(), 3 | 8 | 9) && self.phy.ht,
                vht_supported: !matches!(self.current_iftype(), 3 | 8 | 9) && self.phy.vht,
                he_supported: !matches!(self.current_iftype(), 3 | 8 | 9) && self.phy.he,
                eht_supported: !matches!(self.current_iftype(), 3 | 8 | 9) && self.phy.eht,
            },
        }
    }

    async fn scan(&self, mut request: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        if !matches!(self.current_iftype(), 2 | 8) {
            return Err(WirelessError::Busy);
        }
        if request.ssids.len() > 20 || request.ssids.iter().any(|ssid| ssid.len() > 32) {
            return Err(WirelessError::InvalidArgs);
        }
        // Frequencies are authoritative; numeric-only selectors retain the
        // legacy2.4/5GHz interpretation. Keep separate bounded native jobs.
        let mut supported: Vec<_> = self
            .channels
            .iter()
            .filter_map(|&ch| super::native_band::Channel::legacy(ch))
            .collect();
        supported.extend_from_slice(&self.six_channels);
        let mut channels = Vec::new();
        if !request.frequencies_mhz.is_empty() {
            for &frequency in &request.frequencies_mhz {
                let channel = supported
                    .iter()
                    .find(|ch| ch.frequency() == frequency)
                    .copied()
                    .ok_or(WirelessError::InvalidArgs)?;
                if !channels.contains(&channel) {
                    channels.push(channel);
                }
            }
        } else if request.channels.is_empty() {
            channels = supported;
        } else {
            for &number in &request.channels {
                let number = u8::try_from(number).map_err(|_| WirelessError::InvalidArgs)?;
                let channel = super::native_band::Channel::legacy(number)
                    .filter(|ch| supported.contains(ch))
                    .ok_or(WirelessError::InvalidArgs)?;
                if !channels.contains(&channel) {
                    channels.push(channel);
                }
            }
        }
        if channels.is_empty() {
            return Err(WirelessError::InvalidArgs);
        }
        // Shared RNR planning consumes canonical frequencies even when the
        // caller selected the complete default native channel set.
        request.frequencies_mhz = channels.iter().map(|ch| ch.frequency()).collect();
        let legacy: Vec<_> = channels
            .iter()
            .copied()
            .filter(|ch| ch.band != super::native_band::Band::Six)
            .collect();
        let six: Vec<_> = channels
            .iter()
            .copied()
            .filter(|ch| ch.band == super::native_band::Band::Six)
            .collect();
        self.finish_control().await;
        if self.closing.load(Ordering::Acquire) {
            return Err(WirelessError::Busy);
        }
        let mut state = self.state.try_lock().ok_or(WirelessError::Busy)?;
        if state.hardware.p2p_started() {
            return Err(WirelessError::Busy);
        }
        if state.needs_reset
            || state.hardware.is_failed()
            || state
                .connection
                .as_ref()
                .is_some_and(|connection| !connection.authorized)
        {
            self.recover(&mut state).await?;
            if self.closing.load(Ordering::Acquire) {
                return Err(WirelessError::Busy);
            }
        }
        if state.connection.is_some() || state.scheduled.is_some() {
            return Err(WirelessError::Busy);
        }
        state.hardware.clear_rf_policy();
        *self.policy_fence.lock() = None;
        state.needs_reset = true;
        state.stop_completed = false;
        // Only one scan runs at a time; firmware scan slot zero.
        state.scan_uid = 0;
        let uid = state.scan_uid;
        let outcome = async {
            let State {
                hardware: hw,
                beacons,
                scan_seen,
                ..
            } = &mut *state;
            scan_seen.clear();
            let version = hw.version(1, 0xd).ok_or(WirelessError::NotSupported)?.0;
            let mut result: Vec<BssInfo> = Vec::new();
            let mut colocated: Vec<narf_wireless::scan::ColocatedAp> = Vec::new();
            for phase in 0..2 {
                let plan = if phase == 1 {
                    Some(narf_wireless::scan::plan_6ghz_scan(
                        &request, &colocated, None,
                    ))
                } else {
                    None
                };
                let channels: Vec<_> = if let Some(plan) = &plan {
                    six.iter()
                        .copied()
                        .filter(|ch| plan.frequencies_mhz.contains(&ch.frequency()))
                        .collect()
                } else {
                    legacy.clone()
                };
                if channels.is_empty() {
                    continue;
                }
                let mut body = scan_api::passive_channels(version, uid, &channels)
                    .map_err(|_| WirelessError::NotSupported)?;
                if channels[0].band == super::native_band::Band::Six
                    && hw.scan_fixed_antenna_supported()
                {
                    body[17] = 1 << 2; // MLD, or MVM's actual capability111.
                }
                if request.active {
                    if let Ok(domain) = self.policy.snapshot() {
                        hw.install_rf_policy(super::mld_policy::Authority::Transaction(
                            self.policy
                                .transaction(&domain)
                                .map_err(|_| WirelessError::HardwareError)?,
                        ))
                        .map_err(|_| WirelessError::HardwareError)?;
                        let permissions =
                            super::connection::regulatory_channels_in_domain(hw, &domain)
                                .await
                                .map_err(|_| WirelessError::HardwareError)?;
                        let powers: Vec<_> = channels
                            .iter()
                            .map(|&channel| {
                                if channel.band == super::native_band::Band::Six {
                                    super::six_ghz_scan::power(
                                        self.phy,
                                        &domain,
                                        channel,
                                        &permissions,
                                    )
                                } else {
                                    super::connection::channel_power(
                                        &domain,
                                        channel.number,
                                        &permissions.channels,
                                        true,
                                    )
                                }
                            })
                            .collect();
                        if let Some(power) = powers.iter().flatten().min() {
                            hw.ensure_platform_power()
                                .await
                                .map_err(|_| WirelessError::HardwareError)?;
                            let mut command = station_api::tx_power(
                                hw.version(1, 0x9f).ok_or(WirelessError::NotSupported)?.0,
                                *power,
                            )
                            .map_err(|_| WirelessError::NotSupported)?;
                            command[0] = 1; // Actual SET_DEVICE ceiling for unbound scan probes.
                            let receipt = hw
                                .command(1, 0x9f, &command)
                                .await
                                .map_err(|_| WirelessError::HardwareError)?;
                            if !receipt.payload.is_empty() {
                                return Err(WirelessError::HardwareError);
                            }
                        }
                        let permitted: Vec<_> = powers.iter().map(Option::is_some).collect();
                        let mut phy = self.phy;
                        phy.he &= permissions.he_allowed;
                        phy.eht &= phy.he && permissions.eht_allowed && hw.eht_supported();
                        if channels[0].band == super::native_band::Band::Six {
                            body = super::six_ghz_scan::request(
                                version,
                                uid,
                                &channels,
                                self.mac,
                                &super::six_ghz_scan::Active {
                                    permitted: &permitted,
                                    ssids: &request.ssids,
                                    targets: plan
                                        .as_ref()
                                        .map_or(&[][..], |p| p.targets.as_slice()),
                                    phy,
                                    hidden: hw.scan_hidden_six_supported(),
                                    tpc: hw.scan_tpc_supported(),
                                    fixed: hw.scan_fixed_antenna_supported(),
                                    extra_ies: &request.extra_ies,
                                },
                            )
                            .map_err(|_| WirelessError::InvalidArgs)?;
                        } else {
                            let numbers: Vec<_> = channels.iter().map(|ch| ch.number).collect();
                            body = scan_api::active(
                                version,
                                uid,
                                &numbers,
                                &permitted,
                                self.mac,
                                &request.ssids,
                            )
                            .map_err(|_| WirelessError::InvalidArgs)?;
                            scan_api::with_phy_capabilities(version, &mut body, phy)
                                .map_err(|_| WirelessError::InvalidArgs)?;
                        }
                    }
                }
                hw.notifications
                    .retain(|p| !(p.header.group_id == 0 && matches!(p.header.cmd, 0xf | 0xc1)));
                hw.command(1, 0xd, &body)
                    .await
                    .map_err(|_| WirelessError::HardwareError)?;
                let deadline = narf_time::Deadline::after_ms(15_000);
                'native_job: loop {
                    let activity = hw.activity();
                    hw.poll().map_err(|_| WirelessError::HardwareError)?;
                    while let Some(packet) = hw.notifications.pop_front() {
                        if packet.header.group_id != 0 {
                            continue;
                        }
                        if packet.header.cmd == 0xf {
                            if packet.payload.len() != 16 {
                                return Err(WirelessError::HardwareError);
                            }
                            if packet.payload[..4] != uid.to_le_bytes() {
                                continue;
                            }
                            if packet.payload[6] != 1 {
                                return Err(WirelessError::HardwareError);
                            }
                            break 'native_job;
                        }
                        if packet.receive_queue != 0 || packet.header.cmd != 0xc1 {
                            continue;
                        }
                        let Some(mpdu) = scan_api::mpdu(&packet.payload) else {
                            continue;
                        };
                        let Some(channel) = super::native_band::Channel::received(
                            mpdu.channel,
                            mpdu.raw_band,
                            hw.band_in_rx_supported(),
                        )
                        .filter(|channel| channels.contains(channel)) else {
                            continue;
                        };
                        if mpdu.frame.len() < 36 || !matches!(mpdu.frame[0], 0x80 | 0x50) {
                            continue;
                        }
                        let bssid = mpdu.frame[16..22].try_into().unwrap();
                        let Some(body) = mpdu.body(24, 0) else {
                            continue;
                        };
                        let Some(beacon) = super::mlme::parse_beacon_to_bss(bssid, body) else {
                            continue;
                        };
                        if phase == 0 && request.colocated_6ghz {
                            for ap in narf_wireless::scan::parse_colocated_aps(&body[12..]) {
                                if colocated.len() < 256
                                    && !colocated.iter().any(|old| {
                                        old.bssid == ap.bssid
                                            && old.frequency_mhz == ap.frequency_mhz
                                    })
                                {
                                    colocated.push(ap);
                                }
                            }
                        }
                        if !request.ssids.is_empty()
                            && !request.ssids.iter().any(Vec::is_empty)
                            && !request.ssids.contains(&beacon.ssid)
                        {
                            continue;
                        }
                        let record = Beacon {
                            bssid,
                            ssid: beacon.ssid.clone(),
                            channel: mpdu.channel,
                            band: channel.band,
                            interval: u16::from_le_bytes([body[8], body[9]]),
                            dtim: super::scan_api::dtim_period(body),
                            rsn: beacon.rsn_ie_body.clone(),
                            privacy: body[10] & 0x10 != 0,
                            capabilities: u16::from_le_bytes([body[10], body[11]]),
                            information_elements: body[12..].to_vec(),
                        };
                        let stored = if let Some(old) = beacons.iter_mut().find(|old| {
                            old.bssid == bssid
                                && old.band == channel.band
                                && old.channel == channel.number
                        }) {
                            *old = record;
                            true
                        } else if beacons.len() < 256 {
                            beacons.push(record);
                            true
                        } else {
                            false
                        };
                        let key = (bssid, channel.band, channel.number);
                        if stored && !scan_seen.contains(&key) {
                            scan_seen.push(key);
                        }
                        let security = if channel.band == super::native_band::Band::Six
                            && beacon
                                .rsn_ie_body
                                .as_deref()
                                .and_then(narf_wireless::rsn::RsnIe::decode_body)
                                .is_some_and(|rsn| {
                                    rsn.akms.iter().any(|suite| {
                                        suite.oui == narf_wireless::rsn::RSN_OUI
                                            && matches!(suite.suite_type, 8 | 24)
                                    })
                                }) {
                            narf_wireless::scan::BssSecurity::Wpa3
                        } else if beacon.rsn_ie_body.is_some() {
                            narf_wireless::scan::BssSecurity::Wpa2
                        } else if u16::from_le_bytes(mpdu.frame[34..36].try_into().unwrap()) & 0x10
                            != 0
                        {
                            narf_wireless::scan::BssSecurity::Wep
                        } else {
                            narf_wireless::scan::BssSecurity::Open
                        };
                        let bss = BssInfo {
                            bssid,
                            ssid: beacon.ssid,
                            frequency_mhz: channel.frequency(),
                            channel: mpdu.channel as u32,
                            rssi: mpdu.rssi,
                            security,
                        };
                        if let Some(old) = result.iter_mut().find(|entry| {
                            entry.bssid == bssid && entry.frequency_mhz == channel.frequency()
                        }) {
                            *old = bss;
                        } else if result.len() < 256 {
                            result.push(bss);
                        }
                    }
                    if deadline.expired() {
                        let mut abort = [0; 8];
                        super::boot_context::put32(&mut abort, 0, uid);
                        hw.command(1, 0xe, &abort)
                            .await
                            .map_err(|_| WirelessError::HardwareError)?;
                        hw.wait_notification(0, 0xf, 2000)
                            .await
                            .map_err(|_| WirelessError::HardwareError)?;
                        return Err(WirelessError::Timeout);
                    }
                    activity.await;
                }
            }
            Ok(result)
        }
        .await;
        state.needs_reset = outcome.is_err();
        if outcome.is_ok() {
            state.hardware.clear_rf_policy();
        } else {
            self.stop_locked(&mut state).await;
        }
        outcome
    }

    async fn associate(&self, request: AssociateRequest) -> Result<(), WirelessError> {
        if !matches!(self.current_iftype(), 2 | 8) {
            return Err(WirelessError::Busy);
        }
        let domain =
            narf_wireless::reg::db::ensure_domain().map_err(|_| WirelessError::HardwareError)?;
        self.associate_in_domain(request, &domain).await
    }

    async fn disassociate(&self) -> Result<(), WirelessError> {
        self.closing.store(true, Ordering::Release);
        self.set_link(false);
        self.finish_control().await;
        // The close request is retained independently of this state-lock
        // waiter. The pump completes it if the public future is dropped.
        let mut state = self.state.lock().await;
        if !self.closing.load(Ordering::Acquire) {
            return Ok(());
        }
        self.close_locked(&mut state).await
    }

    fn connected_bssid(&self) -> Option<[u8; 6]> {
        self.link_up().then(|| self.cached_bssid()).flatten()
    }

    async fn associate_mlo(&self, request: AssociateRequest) -> Result<(), WirelessError> {
        // A P2P client (iftype 8) never does MLO.
        if self.current_iftype() != 2 {
            return self.associate(request).await;
        }
        let domain =
            narf_wireless::reg::db::ensure_domain().map_err(|_| WirelessError::HardwareError)?;
        self.associate_links(request, &domain, true).await
    }

    fn mlo_connection(&self) -> Option<narf_wireless::MloConnection> {
        // Only while the association link it describes is the carrier.
        let current = self.connected_bssid()?;
        self.mlo_report.lock().clone().filter(|mlo| {
            mlo.links
                .iter()
                .any(|link| link.link_id == mlo.assoc_link_id && link.bssid == current)
        })
    }

    fn supports_roam(&self) -> bool {
        true
    }

    async fn roam(&self, request: AssociateRequest) -> Result<(), WirelessError> {
        if self.current_iftype() != 2 {
            return Err(WirelessError::Busy);
        }
        use super::connection::AuthMethod;
        if request.ssid.len() > 32 || request.bssid[0] & 1 != 0 {
            return Err(WirelessError::InvalidArgs);
        }
        let auth = match request.security {
            narf_wireless::SecurityConfig::Open => AuthMethod::Open,
            narf_wireless::SecurityConfig::Wpa2 { psk } => AuthMethod::Wpa2Psk(psk),
            narf_wireless::SecurityConfig::Wpa3 { password } => AuthMethod::Wpa3Sae { password },
            // No external-supplicant mode (the MLD firmware path runs the
            // handshake itself; nl80211 never builds this for it).
            narf_wireless::SecurityConfig::External(_) => return Err(WirelessError::NotSupported),
        };
        self.finish_control().await;
        if self.closing.load(Ordering::Acquire) {
            return Err(WirelessError::Busy);
        }
        let mut state = self.state.try_lock().ok_or(WirelessError::Busy)?;
        // A roam reassociates over one link: no MLO view survives it.
        *self.mlo_report.lock() = None;
        // Roaming requires an existing association to reassociate away from.
        let Some(old) = state.connection.take() else {
            return Err(WirelessError::InvalidArgs);
        };
        let current_ap = old.beacon.bssid;
        if current_ap == request.bssid {
            // Already on the requested BSS — restore and report success.
            state.connection = Some(old);
            return Ok(());
        }
        let beacon = match state.beacons.iter().find(|b| {
            b.bssid == request.bssid
                && b.ssid == request.ssid
                && b.channel as u32 == request.channel
                && super::native_band::Channel::from_frequency(b.channel, request.frequency_mhz)
                    == Some(super::native_band::Channel {
                        band: b.band,
                        number: b.channel,
                    })
        }) {
            Some(beacon) => beacon.clone(),
            None => {
                // Target not in the scan cache: keep the current link.
                state.connection = Some(old);
                return Err(WirelessError::InvalidArgs);
            }
        };
        // Close the carrier before replacing peer/queue/key authority.
        // Reassociation still carries the previous AP address.
        self.set_link(false);
        state.clear_transmit();
        state.eapol.clear();
        state.needs_reset = true;
        if old.disconnect(&mut state.hardware).await.is_err() {
            self.stop_locked(&mut state).await;
            return Err(WirelessError::HardwareError);
        }
        state.hardware.clear_rf_policy();
        *self.policy_fence.lock() = None;
        if self.closing.load(Ordering::Acquire) {
            state.needs_reset = false;
            return Err(WirelessError::Busy);
        }
        let bssid = request.bssid;
        let epoch = self.generation.load(Ordering::Acquire);
        let domain = self
            .policy
            .snapshot()
            .map_err(|_| WirelessError::HardwareError)?;
        state
            .hardware
            .install_rf_policy(super::mld_policy::Authority::Transaction(
                self.policy
                    .transaction(&domain)
                    .map_err(|_| WirelessError::HardwareError)?,
            ))
            .map_err(|_| WirelessError::HardwareError)?;
        match Connection::associate_in_domain(
            &mut state.hardware,
            self.mac,
            beacon,
            auth,
            self.tx_chains,
            self.phy,
            Some(current_ap),
            &domain,
        )
        .await
        {
            Ok(connection) => {
                state.connection = Some(connection);
                if self.install_station_policy(&mut state).is_err() {
                    self.stop_locked(&mut state).await;
                    return Err(WirelessError::HardwareError);
                }
                state.needs_reset = false;
                let result = self
                    .publish_link(bssid, epoch)
                    .and_then(|()| self.refresh_receive_ipc(&mut state));
                if result.is_err() {
                    if self.healthy_close_pending(&state) {
                        // The terminal M4/key owner is still valid. Close
                        // owns its ordered native retirement; never publish
                        // data while that close waits for this state guard.
                        state.connection.as_mut().unwrap().authorized = false;
                    } else {
                        self.stop_locked(&mut state).await;
                    }
                }
                result.map_err(|_| WirelessError::HardwareError)
            }
            Err(error) => {
                use core::fmt::Write;
                let _ = writeln!(narf_console::Writer, "iwlwifi: roam failed: {}", error);
                self.stop_locked(&mut state).await;
                Err(WirelessError::HardwareError)
            }
        }
    }

    async fn set_config(&self, config: WirelessConfig) -> Result<(), WirelessError> {
        if config.tx_power_dbm.is_some() {
            return Err(WirelessError::NotSupported);
        }
        self.finish_control().await;
        if self.closing.load(Ordering::Acquire) {
            return Err(WirelessError::Busy);
        }
        let state = self.state.try_lock().ok_or(WirelessError::Busy)?;
        if state
            .connection
            .as_ref()
            .is_some_and(|c| c.beacon.channel as u32 == config.channel)
        {
            Ok(())
        } else {
            Err(WirelessError::InvalidArgs)
        }
    }
}

// The kernel's routing API uses function pointers. Keep the interface
// owner alive; the PCI function remains bound until kernel shutdown.
static ACTIVE: IrqSafeSpinLock<Option<Arc<Device>>> = IrqSafeSpinLock::new(None);

fn send_frame(bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    let device = ACTIVE.lock().clone().ok_or(())?;
    device.enqueue(bytes, meta)
}
impl Device {
    fn enqueue(&self, bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
        // Refuse offload requests this frame cannot satisfy before queueing;
        // it is never sent with a partial checksum.
        if !super::csum::tx_admissible(bytes, meta) {
            return Err(());
        }
        let epoch = self.generation.load(Ordering::Acquire);
        let result = self.source.invoke(|| {
            let _admission = self.admission.lock();
            if !self.link_up()
                || self.quarantined.load(Ordering::Acquire)
                || !self.current_owner()
                || self.generation.load(Ordering::Acquire) != epoch
            {
                return Ok(Err(()));
            }
            // All ordinary data follows the same bounded queue/credit path. In
            // particular, no direct send may overtake a pending packet or a rekey.
            let Ok(buffer) = super::runtime::dma_alloc(bytes.len()) else {
                return Ok(Err(()));
            };
            let mut frame = Frame::new(buffer, bytes.len() as u32);
            frame.payload_mut().copy_from_slice(bytes);
            frame.set_tx_meta(narf_net::TxMeta {
                more: false,
                ..meta
            });
            let category = super::qos::Parameters::default().classify(bytes).ok_or(());
            let Ok(category) = category else {
                return Ok(Err(()));
            };
            let mut producer = self.tx[category].lock();
            Ok(producer
                .as_mut()
                .ok_or(())
                .and_then(|p| p.try_send(frame).map_err(|_| ())))
        });
        match result {
            Ok(inner) => inner,
            Err(_) => {
                self.source_failed(epoch);
                Err(())
            }
        }
    }
}

fn drain_network() -> bool {
    let Some(device) = ACTIVE.lock().clone() else {
        return false;
    };
    let frames = device.step(None);
    device.dispatch(frames)
}

/// Interrupt-driven half of Linux `iwl_pci_suspend`/`iwl_pci_resume`; it
/// needs the scheduler and device interrupts, so it runs in the
/// asynchronous system-PM phase.
struct SystemPm(Arc<Device>);
fn pm_error(error: WirelessError) -> narf_power::device_pm::DevicePmError {
    if error == WirelessError::Busy {
        narf_power::device_pm::DevicePmError::Busy
    } else {
        narf_power::device_pm::DevicePmError::DriverError
    }
}
impl narf_power::system_pm::AsyncSystemPm for SystemPm {
    fn prepare_suspend<'a>(&'a self) -> narf_power::system_pm::SystemPmFuture<'a> {
        Box::pin(async move { self.0.system_suspend().await.map_err(pm_error) })
    }
    fn resume_from_suspend<'a>(&'a self) -> narf_power::system_pm::SystemPmFuture<'a> {
        Box::pin(async move { self.0.system_resume().await.map_err(pm_error) })
    }
}

struct RegisteredDevice(Arc<Device>);
impl Interface for RegisteredDevice {
    fn name(&self) -> &str {
        self.0.name()
    }
    fn offloads(&self) -> narf_net::OffloadCapabilities {
        super::csum::OFFLOADS
    }
    fn mac(&self) -> [u8; 6] {
        self.0.mac()
    }
    fn mtu(&self) -> u32 {
        self.0.mtu()
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
#[path = "device_tests.rs"]
mod tests;

#[cfg(any(test, feature = "kernel-test"))]
#[path = "dhcp_composition_tests.rs"]
mod dhcp_composition;

#[path = "ap_device.rs"]
mod ap;
#[path = "p2p_parent.rs"]
pub(in crate::iwlwifi) mod p2p;
#[path = "sc_scheduled.rs"]
mod scheduled;

#[path = "client_device.rs"]
mod client_control;
