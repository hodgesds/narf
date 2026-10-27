// SPDX-License-Identifier: GPL-2.0-or-later
//! CYW FullMAC composition against the shared AP-side DHCP fixture (#706 A2).
//!
//! The adapter replaces only the booted F2 transport. Production Station
//! scan/association, Device controlled-port/rings, SDPCM/BDC data framing,
//! stack dispatch and DHCP all run unchanged. WPA2 is explicitly firmware
//! offloaded: SET_SSID and FWSUP_COMPLETED authorize the port; this fixture
//! does not claim to simulate firmware-internal EAPOL or radio crypto.

use super::*;
use crate::cyw43439::{
    sdpcm::{HwHeader, SwHeader, CHANNEL_DATA},
    station::tests as firmware,
    Function, Transport, TransportError,
};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wifi_fixtures::{udp_ipv4, DhcpServer, NetworkPlan};

#[path = "power_save_tests.rs"]
mod power_save_tests;

#[path = "ht40_tests.rs"]
mod ht40_tests;
#[path = "ht_tests.rs"]
mod ht_tests;
#[path = "interface_lifetime_tests.rs"]
mod lifetime_tests;
#[path = "mfp_tests.rs"]
mod mfp_tests;
#[path = "optional_mfp_tests.rs"]
mod optional_mfp_tests;
#[path = "pmksa_tests.rs"]
mod pmksa_tests;
#[path = "probe_ies_tests.rs"]
mod probe_ies_tests;
#[path = "wmm_tests.rs"]
mod wmm_tests;

const OWN: [u8; 6] = [2, 6, 7, 8, 9, 10];
const AP: [u8; 6] = [2, 1, 2, 3, 4, 5];

fn network_plan() -> NetworkPlan {
    NetworkPlan {
        station: OWN,
        bssid: AP,
        server_ip: [10, 77, 0, 1],
        lease_ip: [10, 77, 0, 42],
        netmask: [255, 255, 255, 0],
        lease_seconds: 3600,
    }
}

struct ApState {
    server: DhcpServer,
    uplink: Vec<Vec<u8>>,
}

#[derive(Clone)]
struct Bus {
    firmware: Arc<IrqSafeSpinLock<firmware::Bus>>,
    ap: Arc<IrqSafeSpinLock<ApState>>,
}

impl Bus {
    fn new(secured: bool) -> Self {
        let mut firmware = firmware::Bus::new();
        firmware.set_secured(secured);
        Self {
            firmware: Arc::new(IrqSafeSpinLock::new(firmware)),
            ap: Arc::new(IrqSafeSpinLock::new(ApState {
                server: DhcpServer::new(network_plan()),
                uplink: Vec::new(),
            })),
        }
    }

    fn downlink(&self, ethernet: &[u8]) {
        let mut payload = vec![0x20, 0, 0, 0];
        payload.extend_from_slice(ethernet);
        let mut bus = self.firmware.lock();
        let maximum = bus.credit_window(8);
        bus.queue(CHANNEL_DATA, maximum, &payload);
    }

    fn lose_link(&self) {
        let mut bus = self.firmware.lock();
        let maximum = bus.credit_window(8);
        bus.event(16, 0, 0, &[], maximum); // WLC_E_LINK, link flag cleared.
    }
}

impl Transport for Bus {
    fn read32(&mut self, f: Function, a: u32) -> Result<u32, TransportError> {
        self.firmware.lock().read32(f, a)
    }
    fn write32(&mut self, f: Function, a: u32, v: u32) -> Result<(), TransportError> {
        self.firmware.lock().write32(f, a, v)
    }
    fn read_burst(&mut self, f: Function, a: u32, bytes: &mut [u8]) -> Result<(), TransportError> {
        self.firmware.lock().read_burst(f, a, bytes)
    }
    fn write_burst(&mut self, f: Function, a: u32, bytes: &[u8]) -> Result<(), TransportError> {
        self.firmware.lock().write_burst(f, a, bytes)
    }
}

impl PacketTransport for Bus {
    fn receive_packet(&mut self, bytes: &mut [u8]) -> Result<usize, TransportError> {
        self.firmware.lock().receive_packet(bytes)
    }

    fn transmit_packet(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        self.firmware.lock().transmit_packet(bytes)?;
        let sw = SwHeader::decode(bytes.get(4..).ok_or(TransportError::BadFraming)?)
            .map_err(|_| TransportError::BadFraming)?;
        if sw.channel != CHANNEL_DATA {
            return Ok(());
        }
        let length = usize::from(
            HwHeader::decode(bytes)
                .map_err(|_| TransportError::BadFraming)?
                .length,
        );
        let payload = bytes
            .get(usize::from(sw.data_offset)..length)
            .ok_or(TransportError::BadFraming)?;
        let bdc = payload.get(..4).ok_or(TransportError::BadFraming)?;
        if bdc[0] >> 4 != 2 {
            return Err(TransportError::BadFraming);
        }
        let ethernet = payload
            .get(4 + usize::from(bdc[3]) * 4..)
            .ok_or(TransportError::BadFraming)?;
        let reply = {
            let mut ap = self.ap.lock();
            ap.uplink.push(ethernet.to_vec());
            ap.server.receive(ethernet)
        };
        if let Some(reply) = reply {
            self.downlink(&reply);
        }
        Ok(())
    }
}

type ModelDevice = Device<Runtime<Bus>>;
static ACTIVE_TEST: IrqSafeSpinLock<Option<Arc<ModelDevice>>> = IrqSafeSpinLock::new(None);

fn send(bytes: &[u8], _: narf_net::TxMeta) -> Result<(), ()> {
    let device = ACTIVE_TEST.lock().clone().ok_or(())?;
    device.enqueue(bytes)
}

fn drain() -> bool {
    let device = ACTIVE_TEST.lock().clone();
    device.is_some_and(|device| device.drain())
}

fn ready<F: Future>(future: F) -> Result<F::Output, &'static str> {
    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..256 {
        if let Poll::Ready(result) = future.as_mut().poll(&mut context) {
            return Ok(result);
        }
    }
    Err("CYW fixture firmware conversation did not complete")
}

struct Harness {
    device: Arc<ModelDevice>,
    bus: Bus,
    name: String,
    association_ies: Vec<u8>,
}

impl Harness {
    fn new(secured: bool) -> Result<Self, &'static str> {
        Self::new_policy(secured, None)
    }
    fn new_policy(
        secured: bool,
        database: Option<Arc<narf_wireless::reg::db::Database>>,
    ) -> Result<Self, &'static str> {
        Self::new_config(secured, database, None)
    }
    fn new_config(
        secured: bool,
        database: Option<Arc<narf_wireless::reg::db::Database>>,
        mfp: Option<(bool, bool, u8)>,
    ) -> Result<Self, &'static str> {
        Self::new_features(secured, database, mfp, None)
    }
    fn new_features(
        secured: bool,
        database: Option<Arc<narf_wireless::reg::db::Database>>,
        mfp: Option<(bool, bool, u8)>,
        phy: Option<(u32, u8)>,
    ) -> Result<Self, &'static str> {
        Self::new_details(secured, database, mfp, phy, None)
    }
    fn new_wide(
        secured: bool,
        database: Option<Arc<narf_wireless::reg::db::Database>>,
        mfp: bool,
        wide: crate::cyw43439::phy_fixture::Wide,
    ) -> Result<Self, &'static str> {
        Self::new_details(
            secured,
            database,
            mfp.then_some((true, true, 0)),
            Some((1, 0)),
            Some(wide),
        )
    }
    fn new_details(
        secured: bool,
        database: Option<Arc<narf_wireless::reg::db::Database>>,
        mfp: Option<(bool, bool, u8)>,
        phy: Option<(u32, u8)>,
        wide: Option<crate::cyw43439::phy_fixture::Wide>,
    ) -> Result<Self, &'static str> {
        let bus = Bus::new(secured);
        if let Some((supported, required, fault)) = mfp {
            bus.firmware.lock().mfp_profile(supported, required, fault);
        }
        if let Some((chains, fault)) = phy {
            bus.firmware.lock().phy_profile(chains, fault);
        }
        let mut domain = firmware::domain();
        if let Some(wide) = wide {
            bus.firmware.lock().wide_profile(wide);
            domain.rules[0].max_bandwidth_mhz = 40;
        }
        let station = if let Some(database) = database {
            ready(Station::initialize_live(
                Runtime::new(bus.clone()),
                &[1],
                database,
            ))?
        } else {
            ready(Station::initialize(Runtime::new(bus.clone()), &[1], domain))?
        }
        .map_err(|_| "CYW composition firmware initialization")?;
        if station.mac != OWN {
            return Err("CYW composition firmware identity");
        }
        let channels = station.channels.iter().map(|&ch| u32::from(ch)).collect();
        let supplicant = station.supplicant;
        let mfp_supported = station.supports_management_protection();
        let sae_offload = station.supports_sae_offload();
        let ht_capabilities = station.ht_capabilities();
        let vht_capabilities = station.vht_capabilities();
        let (rx, rx_consumer) = narf_ipc::channel();
        let (tx_producer, tx) = narf_ipc::channel();
        let name = narf_net::iface::register("wlan%d", OWN, send);
        let device = Arc::new(Device {
            state: Mutex::new(State {
                station,
                rx,
                tx,
                pending: None,
            }),
            name: name.clone(),
            mac: OWN,
            channels,
            supplicant,
            mfp_supported,
            sae_offload,
            pmksa: IrqSafeSpinLock::new(Default::default()),
            ht_capabilities,
            vht_capabilities,
            up: AtomicBool::new(false),
            power_save: AtomicU8::new(0),
            bssid: AtomicU64::new(0),
            epoch: AtomicU64::new(0),
            closing: AtomicBool::new(false),
            publication: IrqSafeSpinLock::new(()),
            receive_hook: IrqSafeSpinLock::new(None),
            rx: IrqSafeSpinLock::new(Some(rx_consumer)),
            tx: IrqSafeSpinLock::new(Some(tx_producer)),
        });
        *ACTIVE_TEST.lock() = Some(device.clone());
        narf_net::iface::set_link_state(&name, true); // operator IFF_UP
                                                      // Install the same dispatch pointer as production without re-running
                                                      // stack initialization or registering another netfilter/timer hook.
        narf_net::iface::install_rx_handler(narf_net::tcp_stack::rx_handler);
        narf_net::iface::install_rx_drain(drain);
        Ok(Self {
            device,
            bus,
            name,
            association_ies: Vec::new(),
        })
    }

    fn scan_and_associate(&self, secured: bool) -> Result<(), &'static str> {
        self.scan()?;
        let mut request = Self::request(secured);
        request.ie = self.association_ies.clone();
        ready(self.device.associate(request))?.map_err(|_| "CYW composition association")?;
        if !self.device.link_up()
            || self.device.connected_bssid() != Some(AP)
            || narf_net::iface::lookup(&self.name)
                .is_none_or(|iface| !iface.link_up || !iface.carrier)
        {
            return Err("CYW composition did not authorize the connected port");
        }
        narf_net::iface::set_link_state(&self.name, false);
        self.device.drain();
        if narf_net::iface::lookup(&self.name).is_none_or(|iface| iface.link_up || !iface.carrier) {
            return Err("CYW physical carrier overwrote operator DOWN");
        }
        narf_net::iface::set_link_state(&self.name, true);
        Ok(())
    }
    fn scan(&self) -> Result<(), &'static str> {
        let bss = ready(self.device.scan(ScanRequest {
            ssids: vec![b"test".to_vec()],
            frequencies_mhz: vec![2437],
            channels: vec![6],
            active: false,
            random_mac: None,
            colocated_6ghz: false,
            duration_tu: None,
            duration_mandatory: false,
            extra_ies: Vec::new(),
        }))?
        .map_err(|_| "CYW composition scan")?;
        if bss.len() != 1 || bss[0].bssid != AP || bss[0].frequency_mhz != 2437 {
            return Err("CYW composition scan did not identify the AP");
        }
        Ok(())
    }
    fn request(secured: bool) -> AssociateRequest {
        AssociateRequest {
            bssid: AP,
            ssid: b"test".to_vec(),
            frequency_mhz: 2437,
            channel: 6,
            security: if secured {
                narf_wireless::SecurityConfig::Wpa2 { psk: [0x11; 32] }
            } else {
                narf_wireless::SecurityConfig::Open
            },
            ie: Vec::new(),
        }
    }

    fn received(&self, expected: &[u8]) -> bool {
        let mut rx = self.device.rx.lock();
        let Some(consumer) = rx.as_mut() else {
            return false;
        };
        for _ in 0..RX_RING_N {
            let Ok(Some(frame)) = consumer.try_recv() else {
                break;
            };
            if frame.payload() == expected {
                return true;
            }
        }
        false
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        *ACTIVE_TEST.lock() = None;
        narf_net::iface::set_link_state(&self.name, false);
        narf_net::iface::unregister(&self.name);
    }
}

fn composition(secured: bool) -> Result<(), &'static str> {
    composition_mfp(secured, false)
}
fn composition_mfp(secured: bool, mfp: bool) -> Result<(), &'static str> {
    composition_phy(secured, mfp, None)
}
fn composition_phy(secured: bool, mfp: bool, phy: Option<(u32, u8)>) -> Result<(), &'static str> {
    let harness = Harness::new_features(secured, None, mfp.then_some((true, true, 0)), phy)?;
    composition_native(harness, secured, mfp, phy.is_some())
}
fn composition_native(
    harness: Harness,
    secured: bool,
    mfp: bool,
    ht: bool,
) -> Result<(), &'static str> {
    let plan = network_plan();
    let uplink = udp_ipv4(
        AP,
        OWN,
        plan.lease_ip,
        plan.server_ip,
        49152,
        7,
        b"cyw-a2-uplink",
    );
    if harness.device.link_up()
        || narf_net::iface::lookup(&harness.name)
            .is_none_or(|iface| !iface.link_up || iface.carrier)
        || harness.device.enqueue(&uplink).is_ok()
        || narf_net::dhcp::acquire(&harness.name, 0).is_ok()
        || !harness.bus.ap.lock().uplink.is_empty()
    {
        return Err("CYW admitted data or carrier before association");
    }
    harness.scan_and_associate(secured)?;
    if harness
        .device
        .state
        .try_lock()
        .unwrap()
        .station
        .ht_connection()
        != ht
    {
        return Err("CYW native PHY verification did not match the completed conversation");
    }
    if harness
        .device
        .state
        .try_lock()
        .unwrap()
        .station
        .management_protection()
        != mfp
    {
        return Err("CYW firmware management-protection receipt missing/unrequested");
    }
    // Exercise ordinary station power save through the same native data
    // owner before the real DHCP/IP conversation, for Open and WPA2.
    harness
        .device
        .set_power_save(true)
        .map_err(|_| "CYW power-save request")?;
    ready(harness.device.apply_power_save())?;
    if !harness
        .device
        .state
        .try_lock()
        .unwrap()
        .station
        .power_save()
    {
        return Err("CYW firmware never acknowledged station power save");
    }
    let lease = narf_net::dhcp::dhcp_acquire(&harness.name, 0)
        .map_err(|_| "CYW association did not compose to a DHCP lease")?;
    if !plan.matches_lease(&lease) {
        return Err("CYW composition lease differs from the shared AP offer");
    }
    let observed = harness.bus.ap.lock().server.observations();
    if observed.discovers != 1 || observed.requests != 1 {
        return Err("CYW native data did not carry the DHCP conversation");
    }

    narf_net::iface::send_on(&harness.name, &uplink).map_err(|_| "CYW post-lease netdev TX")?;
    for _ in 0..4 {
        harness.device.drain();
    }
    if !harness.bus.ap.lock().uplink.contains(&uplink) {
        return Err("CYW post-lease uplink changed on the native path");
    }

    let downlink = udp_ipv4(
        OWN,
        AP,
        plan.server_ip,
        plan.lease_ip,
        12345,
        54321,
        b"cyw-a2-downlink",
    );
    let rx_before = narf_net::iface::lookup(&harness.name)
        .ok_or("CYW composition interface disappeared")?
        .stats
        .rx_packets;
    harness.bus.downlink(&downlink);
    for _ in 0..4 {
        harness.device.drain();
    }
    if !harness.received(&downlink)
        || narf_net::iface::lookup(&harness.name)
            .is_none_or(|iface| iface.stats.rx_packets <= rx_before)
    {
        return Err("CYW native downlink did not reach its ring and stack intact");
    }

    // Link loss must discard an already queued TX and an RX captured in the
    // same firmware poll, before either can cross the controlled port.
    let tx_before = harness.bus.ap.lock().uplink.len();
    harness
        .device
        .set_power_save(false)
        .map_err(|_| "CYW awake request")?;
    ready(harness.device.apply_power_save())?;
    if harness
        .device
        .state
        .try_lock()
        .unwrap()
        .station
        .power_save()
    {
        return Err("CYW firmware never acknowledged awake mode");
    }
    let rx_before_loss = narf_net::iface::lookup(&harness.name)
        .ok_or("CYW composition interface disappeared before link loss")?
        .stats
        .rx_packets;
    narf_net::iface::send_on(&harness.name, &uplink)
        .map_err(|_| "CYW queue before terminal link loss")?;
    harness.bus.downlink(&downlink);
    harness.bus.lose_link();
    for _ in 0..4 {
        harness.device.drain();
    }
    if harness.device.link_up()
        || harness.device.connected_bssid().is_some()
        || harness.device.enqueue(&uplink).is_ok()
        || narf_net::iface::send_on(&harness.name, &uplink).is_ok()
        || harness.bus.ap.lock().uplink.len() != tx_before
        || harness.received(&downlink)
        || narf_net::iface::lookup(&harness.name).is_none_or(|iface| {
            !iface.link_up
                || iface.carrier
                || iface.stats.rx_packets != rx_before_loss
                || iface.carrier_changes != 2
                || iface.carrier_up_count != 1
                || iface.carrier_down_count != 1
        })
    {
        return Err("CYW link loss retained data admission or pending frames");
    }
    Ok(())
}

fn smoke_cyw_association_to_dhcp_open() -> TestResult {
    match composition(false) {
        Ok(()) => TestResult::Pass,
        Err(error) => TestResult::Fail(error),
    }
}
kernel_test_in!(
    "drivers/wireless/cyw43439/interface",
    smoke_cyw_association_to_dhcp_open
);

fn smoke_cyw_association_to_dhcp_wpa2_firmware_offload() -> TestResult {
    match composition(true) {
        Ok(()) => TestResult::Pass,
        Err(error) => TestResult::Fail(error),
    }
}
kernel_test_in!(
    "drivers/wireless/cyw43439/interface",
    smoke_cyw_association_to_dhcp_wpa2_firmware_offload
);

fn disconnect_overrides_waiting_old_publisher() -> Result<(), &'static str> {
    let h = Harness::new(false)?;
    h.scan_and_associate(false)?;
    let plan = network_plan();
    let probe = udp_ipv4(
        AP,
        OWN,
        plan.lease_ip,
        plan.server_ip,
        49153,
        7,
        b"cyw-disconnect-publication",
    );
    h.device
        .enqueue(&probe)
        .map_err(|_| "CYW queue before racing disconnect")?;
    let state = h.device.state.try_lock().ok_or("CYW fixture state busy")?;
    let mut disconnect = pin!(h.device.disassociate());
    if disconnect
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_ready()
        || h.device.link_up()
        || h.device.connected_bssid().is_some()
    {
        return Err("CYW disconnect did not close before waiting for state");
    }
    // An earlier step()/associate() still owns state and attempts to publish
    // its original peer. Host close must already suppress that stale grant,
    // even before the native disconnect can acquire state and complete.
    if state.station.bssid != Some(AP) {
        return Err("CYW fixture lacks the previous authorized publisher");
    }
    h.device.link(state.station.bssid);
    if h.device.link_up()
        || h.device.connected_bssid().is_some()
        || h.device.enqueue(&probe).is_ok()
    {
        return Err("CYW previous publisher bypassed the pending host-close fence");
    }
    drop(state);
    ready(disconnect)?.map_err(|_| "CYW interleaved firmware disconnect")?;
    // No step() follows teardown before these cached-state observations.
    if h.device.link_up()
        || h.device.connected_bssid().is_some()
        || h.device.enqueue(&probe).is_ok()
        || narf_net::iface::send_on(&h.name, &probe).is_ok()
        || narf_net::iface::lookup(&h.name).is_none_or(|i| {
            !i.link_up || i.carrier || i.carrier_up_count != 1 || i.carrier_down_count != 1
        })
        || !h.bus.ap.lock().uplink.is_empty()
    {
        return Err("CYW old publisher reopened carrier/BSSID after completed disconnect");
    }
    let mut state = h
        .device
        .state
        .try_lock()
        .ok_or("CYW teardown retained state lock")?;
    if state.station.bssid.is_some()
        || state.pending.is_some()
        || !matches!(state.tx.try_recv(), Ok(None))
    {
        return Err("CYW racing disconnect retained peer or queued data");
    }
    Ok(())
}
fn smoke_cyw_disconnect_overrides_waiting_old_link_publication() -> TestResult {
    match disconnect_overrides_waiting_old_publisher() {
        Ok(()) => TestResult::Pass,
        Err(error) => TestResult::Fail(error),
    }
}
kernel_test_in!(
    "drivers/wireless/cyw43439/interface",
    smoke_cyw_disconnect_overrides_waiting_old_link_publication
);

#[path = "live_policy_tests.rs"]
mod live_policy_tests;
