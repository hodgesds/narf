// SPDX-License-Identifier: GPL-2.0-or-later
//! BCM43602 CR4/msgbuf → FullMAC station → Device → real kernel DHCP/IP.
//! This is compiled as an interface child only for its private test seam;
//! production ACTIVE_PCIE, board registration and firmware trust are untouched.
use super::*;
use crate::brcmfmac::runtime_tests::station_model::{
    self as firmware, Handle, TestAdapter, AP, OWN,
};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wifi_fixtures::udp_ipv4;

#[path = "channel_station_tests.rs"]
mod channel_station_tests;
#[path = "ht40_tests.rs"]
mod ht40_tests;
#[path = "ht_tests.rs"]
mod ht_tests;
#[path = "mfp_tests.rs"]
mod mfp_tests;
#[path = "optional_mfp_tests.rs"]
mod optional_mfp_tests;
#[path = "power_save_tests.rs"]
mod power_save_tests;
#[path = "scan_ies_tests.rs"]
mod scan_ies_tests;
#[path = "vht_tests.rs"]
mod vht_tests;
#[path = "wmm_tests.rs"]
mod wmm_tests;

type ModelDevice = Device<TestAdapter>;
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
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..256 {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return Ok(value);
        }
    }
    Err("PCIe firmware conversation did not complete")
}
type NativeFeatures = (Option<(bool, bool, u8)>, Option<(u32, u8)>);
struct Configuration {
    mfp: Option<(bool, bool, u8)>,
    phy: Option<(u32, u8)>,
    wide: Option<crate::cyw43439::phy_fixture::Wide>,
    vht: Option<crate::cyw43439::phy_fixture::Vht80>,
}
struct Harness {
    device: Arc<ModelDevice>,
    bus: Handle,
    name: String,
    channel: u8,
    association_ies: Vec<u8>,
}
impl Harness {
    fn new(version: u32, secured: bool, keys_first: bool) -> Result<Self, &'static str> {
        Self::new_selected(version, secured, keys_first, false)
    }
    fn new_selected(
        version: u32,
        secured: bool,
        keys_first: bool,
        selected: bool,
    ) -> Result<Self, &'static str> {
        Self::new_channel(version, secured, keys_first, selected, 6)
    }
    fn new_channel(
        version: u32,
        secured: bool,
        keys_first: bool,
        selected: bool,
        channel: u8,
    ) -> Result<Self, &'static str> {
        Self::new_channel_policy(version, secured, keys_first, selected, channel, None)
    }
    fn new_channel_policy(
        version: u32,
        secured: bool,
        keys_first: bool,
        selected: bool,
        channel: u8,
        database: Option<Arc<narf_wireless::reg::db::Database>>,
    ) -> Result<Self, &'static str> {
        Self::new_profile(
            version, secured, keys_first, selected, channel, database, None,
        )
    }
    fn new_profile(
        version: u32,
        secured: bool,
        keys_first: bool,
        selected: bool,
        channel: u8,
        database: Option<Arc<narf_wireless::reg::db::Database>>,
        mfp: Option<(bool, bool, u8)>,
    ) -> Result<Self, &'static str> {
        Self::new_features(
            version,
            secured,
            keys_first,
            selected,
            channel,
            database,
            (mfp, None),
        )
    }
    fn new_features(
        version: u32,
        secured: bool,
        keys_first: bool,
        selected: bool,
        channel: u8,
        database: Option<Arc<narf_wireless::reg::db::Database>>,
        features: NativeFeatures,
    ) -> Result<Self, &'static str> {
        Self::new_details(
            version,
            secured,
            keys_first,
            selected,
            channel,
            database,
            Configuration {
                mfp: features.0,
                phy: features.1,
                wide: None,
                vht: None,
            },
        )
    }
    fn new_wide(
        version: u32,
        secured: bool,
        channel: u8,
        database: Option<Arc<narf_wireless::reg::db::Database>>,
        mfp: bool,
        wide: crate::cyw43439::phy_fixture::Wide,
    ) -> Result<Self, &'static str> {
        Self::new_details(
            version,
            secured,
            secured,
            false,
            channel,
            database,
            Configuration {
                mfp: mfp.then_some((true, true, 0)),
                phy: Some((7, 0)),
                wide: Some(wide),
                vht: None,
            },
        )
    }
    fn new_vht(
        version: u32,
        secured: bool,
        channel: u8,
        database: Option<Arc<narf_wireless::reg::db::Database>>,
        mfp: bool,
        chains: u32,
        vht: crate::cyw43439::phy_fixture::Vht80,
    ) -> Result<Self, &'static str> {
        Self::new_details(
            version,
            secured,
            secured,
            false,
            channel,
            database,
            Configuration {
                mfp: mfp.then_some((true, true, 0)),
                phy: Some((chains, 0)),
                wide: None,
                vht: Some(vht),
            },
        )
    }
    fn new_details(
        version: u32,
        secured: bool,
        keys_first: bool,
        selected: bool,
        channel: u8,
        database: Option<Arc<narf_wireless::reg::db::Database>>,
        features: Configuration,
    ) -> Result<Self, &'static str> {
        let (adapter, bus) = if selected {
            let (selection, assets) = crate::brcmfmac::provision::tests::selected_fixture(
                crate::brcmfmac::provision::Family::Pcie43602,
            )?;
            firmware::create_selected(version, secured, &selection, &assets)
        } else {
            firmware::create(version, secured)
        }
        .map_err(|_| "CR4/common-ring native ownership")?;
        bus.keys_first(keys_first);
        bus.channel(channel);
        if let Some((supported, required, fault)) = features.mfp {
            bus.mfp_profile(supported, required, fault);
        }
        if let Some((chains, fault)) = features.phy {
            bus.phy_profile(chains, fault);
        }
        let mut domain = firmware::domain();
        let wide = features.wide.is_some() || features.vht.is_some();
        let width = if features.vht.is_some() {
            80
        } else if wide {
            40
        } else {
            20
        };
        if let Some(profile) = features.wide {
            bus.wide_profile(profile);
            domain.rules[0].max_bandwidth_mhz = 40;
        }
        if let Some(profile) = features.vht {
            bus.vht_profile(profile);
        }
        if channel > 14 {
            use narf_wireless::reg::{RegFlags, RegRule};
            for (start, end, flags) in [
                (5170, 5250, RegFlags::empty()),
                (5250, 5330, RegFlags::DFS),
                (5735, 5835, RegFlags::empty()),
            ] {
                domain.rules.push(RegRule {
                    freq_start_mhz: start,
                    freq_end_mhz: end,
                    max_bandwidth_mhz: width,
                    max_power_dbm: 17,
                    flags,
                });
            }
        }
        let station = if let Some(database) = database {
            ready(Station::initialize_live(adapter, &[], database))?
        } else {
            ready(Station::initialize(adapter, &[], domain))?
        }
        .map_err(|_| "PCIe station firmware initialization")?;
        let expected: &[u8] = if channel > 14 {
            &[6, 36, 52, 149, 165]
        } else {
            &[1, 6, 11]
        };
        if station.mac != OWN
            || !wide && station.channels != expected
            || !station.channels.contains(&channel)
            || !station.supplicant
        {
            return Err("PCIe firmware identity/channel/key capabilities");
        }
        let channels = station
            .channels
            .iter()
            .map(|&channel| u32::from(channel))
            .collect();
        let supplicant = station.supplicant;
        let mfp_supported = station.supports_management_protection();
        let sae_offload = station.supports_sae_offload();
        let telemetry = Arc::new(crate::cyw43439::telemetry::Counters::default());
        let ht_capabilities = station.ht_capabilities();
        let vht_capabilities = station.vht_capabilities();
        let (rx, consumer) = narf_ipc::channel();
        let (producer, tx) = narf_ipc::channel();
        let name = narf_net::iface::register("wlan%d", OWN, send);
        let device = Arc::new(Device {
            state: Mutex::new(State {
                station,
                rx,
                tx,
                pending: None,
                telemetry: telemetry.clone(),
            }),
            name: name.clone(),
            mac: OWN,
            channels,
            supplicant,
            mfp_supported,
            sae_offload,
            external_ops: narf_lib::sync::IrqSafeSpinLock::new(Default::default()),
            telemetry,
            pmksa: narf_lib::sync::IrqSafeSpinLock::new(Default::default()),
            ht_capabilities,
            vht_capabilities,
            up: AtomicBool::new(false),
            power_save: AtomicU8::new(0),
            bssid: AtomicU64::new(0),
            roaming: AtomicBool::new(false),
            epoch: AtomicU64::new(0),
            closing: AtomicBool::new(false),
            publication: IrqSafeSpinLock::new(()),
            receive_hook: IrqSafeSpinLock::new(None),
            rx: IrqSafeSpinLock::new(Some(consumer)),
            tx: IrqSafeSpinLock::new(Some(producer)),
            lifecycle: Default::default(),
        });
        *ACTIVE_TEST.lock() = Some(device.clone());
        narf_net::iface::set_link_state(&name, true); // operator IFF_UP
        narf_net::iface::install_rx_handler(narf_net::tcp_stack::rx_handler);
        narf_net::iface::install_rx_drain(drain);
        Ok(Self {
            device,
            bus,
            name,
            channel,
            association_ies: Vec::new(),
        })
    }
    fn scan(&self) -> Result<(), &'static str> {
        let bss = ready(self.device.scan(ScanRequest {
            ssids: vec![b"test".to_vec()],
            frequencies_mhz: vec![self.frequency()],
            channels: vec![u32::from(self.channel)],
            active: false,
            random_mac: None,
            colocated_6ghz: false,
            duration_tu: None,
            duration_mandatory: false,
            extra_ies: Vec::new(),
        }))?
        .map_err(|_| "PCIe native escan")?;
        if bss.len() != 1 || bss[0].bssid != AP || bss[0].frequency_mhz != self.frequency() {
            return Err("PCIe scan did not return the native BSS event");
        }
        Ok(())
    }
    fn frequency(&self) -> u32 {
        if self.channel <= 14 {
            2407 + 5 * u32::from(self.channel)
        } else {
            5000 + 5 * u32::from(self.channel)
        }
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
    fn associate(&self, secured: bool) -> Result<(), &'static str> {
        self.scan()?;
        let mut request = Self::request(secured);
        request.channel = u32::from(self.channel);
        request.frequency_mhz = self.frequency();
        request.ie = self.association_ies.clone();
        ready(self.device.associate(request))?.map_err(|_| "PCIe native offloaded association")?;
        if self.device.connected_bssid() != Some(AP)
            || !self.device.link_up()
            || narf_net::iface::lookup(&self.name)
                .is_none_or(|iface| !iface.carrier || !iface.link_up)
        {
            return Err("PCIe association did not open exact peer/carrier");
        }
        narf_net::iface::set_link_state(&self.name, false);
        self.device.drain();
        if narf_net::iface::lookup(&self.name).is_none_or(|iface| iface.link_up || !iface.carrier) {
            return Err("PCIe physical carrier overwrote operator DOWN");
        }
        narf_net::iface::set_link_state(&self.name, true);
        Ok(())
    }
    fn pump(&self) {
        for _ in 0..6 {
            self.device.drain();
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
    fn closed(&self, frame: &[u8]) -> bool {
        !self.device.link_up()
            && self.device.connected_bssid().is_none()
            && self.device.enqueue(frame).is_err()
            && narf_net::iface::send_on(&self.name, frame).is_err()
            && narf_net::iface::lookup(&self.name)
                .is_some_and(|iface| iface.link_up && !iface.carrier)
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        *ACTIVE_TEST.lock() = None;
        narf_net::iface::set_link_state(&self.name, false);
        narf_net::iface::unregister(&self.name);
    }
}
fn packets() -> (Vec<u8>, Vec<u8>) {
    let plan = firmware::network_plan();
    (
        udp_ipv4(
            AP,
            OWN,
            plan.lease_ip,
            plan.server_ip,
            49152,
            7,
            b"bcm43602-native-uplink",
        ),
        udp_ipv4(
            OWN,
            AP,
            plan.server_ip,
            plan.lease_ip,
            12345,
            54321,
            b"bcm43602-native-downlink",
        ),
    )
}
fn composition(version: u32, secured: bool, keys_first: bool) -> Result<(), &'static str> {
    composition_selected(version, secured, keys_first, false)
}
fn composition_selected(
    version: u32,
    secured: bool,
    keys_first: bool,
    selected: bool,
) -> Result<(), &'static str> {
    composition_channel(version, secured, keys_first, selected, 6)
}
fn composition_channel(
    version: u32,
    secured: bool,
    keys_first: bool,
    selected: bool,
    channel: u8,
) -> Result<(), &'static str> {
    composition_mfp(version, secured, keys_first, selected, channel, false)
}
fn composition_mfp(
    version: u32,
    secured: bool,
    keys_first: bool,
    selected: bool,
    channel: u8,
    mfp: bool,
) -> Result<(), &'static str> {
    composition_phy(version, secured, keys_first, selected, channel, mfp, None)
}
fn composition_phy(
    version: u32,
    secured: bool,
    keys_first: bool,
    selected: bool,
    channel: u8,
    mfp: bool,
    phy: Option<(u32, u8)>,
) -> Result<(), &'static str> {
    let harness = Harness::new_features(
        version,
        secured,
        keys_first,
        selected,
        channel,
        None,
        (mfp.then_some((true, true, 0)), phy),
    )?;
    composition_native(harness, secured, mfp, phy.is_some())
}
fn composition_native(
    harness: Harness,
    secured: bool,
    mfp: bool,
    ht: bool,
) -> Result<(), &'static str> {
    let (uplink, downlink) = packets();
    if !harness.closed(&uplink)
        || narf_net::dhcp::acquire(&harness.name, 0).is_ok()
        || harness.bus.sent() != 0
    {
        return Err("PCIe data admitted before station/key authorization");
    }
    harness.bus.downlink(&downlink);
    harness.pump();
    if harness.received(&downlink) {
        return Err("PCIe preauthorization RX escaped controlled port");
    }
    harness.associate(secured)?;
    if harness
        .device
        .state
        .try_lock()
        .unwrap()
        .station
        .ht_connection()
        != ht
    {
        return Err("PCIe PHY proof did not match the completed conversation");
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
        return Err("PCIe firmware PMF offload verification missing/unrequested");
    }
    harness
        .device
        .set_power_save(true)
        .map_err(|_| "PCIe power-save request")?;
    ready(harness.device.apply_power_save())?;
    if !harness
        .device
        .state
        .try_lock()
        .unwrap()
        .station
        .power_save()
    {
        return Err("PCIe firmware never acknowledged station power save");
    }
    let lease = narf_net::dhcp::dhcp_acquire(&harness.name, 0)
        .map_err(|_| "PCIe native station did not obtain a DHCP lease")?;
    if !firmware::network_plan().matches_lease(&lease) || harness.bus.dhcp() != (1, 1) {
        return Err("PCIe DHCP conversation or lease changed");
    }
    narf_net::iface::send_on(&harness.name, &uplink).map_err(|_| "PCIe netdev TX")?;
    harness.pump();
    if !harness.bus.uplink(&uplink) {
        return Err("PCIe ring TX changed the original Ethernet/IP bytes");
    }
    let rx = narf_net::iface::lookup(&harness.name)
        .ok_or("PCIe iface lost")?
        .stats
        .rx_packets;
    harness.bus.downlink(&downlink);
    harness.pump();
    if !harness.received(&downlink)
        || narf_net::iface::lookup(&harness.name).is_none_or(|iface| iface.stats.rx_packets <= rx)
    {
        return Err("PCIe RX DMA/repost did not deliver exact IP to frame ring and stack");
    }
    // Device publication, descriptor consumption and the firmware's copy do
    // not release payload memory. Only the actual TX-status ring can do so.
    harness.bus.hold_transmits(true);
    let statuses = harness.bus.stats().2;
    narf_net::iface::send_on(&harness.name, &uplink).map_err(|_| "PCIe held TX enqueue")?;
    harness.pump();
    if harness.bus.stats().3 != 1
        || harness.bus.stats().2 != statuses
        || !harness.bus.last_tx_alive()
    {
        return Err("PCIe payload retired before matching terminal TX status");
    }
    harness.bus.hold_transmits(false);
    if !harness.bus.last_tx_alive() {
        return Err("firmware status publication freed CPU ownership without polling");
    }
    harness.pump();
    if harness.bus.last_tx_alive()
        || harness.bus.stats().2 != statuses + 1
        || harness.bus.stats().5 != 0
    {
        return Err("PCIe terminal TX status did not retire only its payload safely");
    }
    harness
        .device
        .set_power_save(false)
        .map_err(|_| "PCIe awake request")?;
    ready(harness.device.apply_power_save())?;
    if harness
        .device
        .state
        .try_lock()
        .unwrap()
        .station
        .power_save()
    {
        return Err("PCIe firmware never acknowledged awake mode");
    }
    ready(harness.device.disassociate())?.map_err(|_| "PCIe confirmed disconnect")?;
    harness.pump();
    let (creates, deletes, _, pending, _, unsafe_free) = harness.bus.stats();
    if !harness.closed(&uplink)
        || creates == 0
        || deletes != creates
        || pending != 0
        || unsafe_free != 0
    {
        return Err("PCIe link-down failed to close port and ACK-fence old flow owners");
    }
    Ok(())
}
fn smoke_brcmf_native_open_station_to_dhcp_and_bidirectional_ip() -> TestResult {
    // Shared 7 runs the same conversation over 24/40-byte D2H completions.
    for version in [5, 6, 7] {
        if let Err(error) = composition(version, false, false) {
            return TestResult::Fail(error);
        }
    }
    TestResult::Pass
}
fn smoke_brcmf_signed_board_registry_selection_to_native_open_wpa2_dhcp_ip() -> TestResult {
    for version in [5, 6] {
        for secured in [false, true] {
            if let Err(reason) = composition_selected(version, secured, false, true) {
                return TestResult::Fail(reason);
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/provision",
    smoke_brcmf_signed_board_registry_selection_to_native_open_wpa2_dhcp_ip
);
kernel_test_in!(
    "drivers/wireless/brcmfmac/station",
    smoke_brcmf_native_open_station_to_dhcp_and_bidirectional_ip
);
fn smoke_brcmf_native_wpa2_station_to_dhcp_and_bidirectional_ip() -> TestResult {
    for version in [5, 6, 7] {
        for first in [false, true] {
            if let Err(error) = composition(version, true, first) {
                return TestResult::Fail(error);
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/station",
    smoke_brcmf_native_wpa2_station_to_dhcp_and_bidirectional_ip
);

fn smoke_brcmf_native_missing_offload_keys_and_cancel_keep_port_closed() -> TestResult {
    let harness = match Harness::new(6, true, false) {
        Ok(h) => h,
        Err(e) => return TestResult::Fail(e),
    };
    harness.bus.hold_keys(true);
    if let Err(error) = harness.scan() {
        return TestResult::Fail(error);
    }
    let (uplink, _) = packets();
    {
        let mut association = pin!(harness.device.associate(Harness::request(true)));
        if association
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
            || !harness.closed(&uplink)
            || harness.bus.sent() != 0
        {
            return TestResult::Fail("SET_SSID or LINK authorized WPA2 without FWSUP_COMPLETED");
        }
    }
    harness.pump();
    harness.bus.stale_authorization();
    harness.pump();
    if !harness.closed(&uplink)
        || harness.bus.stats().4
        || harness.bus.sent() != 0
        || harness.bus.stats().5 != 0
    {
        return TestResult::Fail("cancelled firmware-key wait reopened through stale authorization or retained unsafe DMA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/station",
    smoke_brcmf_native_missing_offload_keys_and_cancel_keep_port_closed
);

fn smoke_brcmf_native_link_loss_discards_pending_tx_and_same_poll_rx() -> TestResult {
    let harness = match Harness::new(6, true, true) {
        Ok(h) => h,
        Err(e) => return TestResult::Fail(e),
    };
    if let Err(error) = harness.associate(true) {
        return TestResult::Fail(error);
    }
    let (uplink, downlink) = packets();
    let before = harness.bus.sent();
    if narf_net::iface::send_on(&harness.name, &uplink).is_err() {
        return TestResult::Fail("PCIe pre-loss pending TX");
    }
    harness.bus.downlink(&downlink);
    harness.bus.lose_link();
    harness.pump();
    if !harness.closed(&uplink)
        || harness.bus.sent() != before
        || harness.received(&downlink)
        || harness.bus.stats().5 != 0
    {
        return TestResult::Fail("PCIe link loss allowed pending TX or same-poll RX");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/station",
    smoke_brcmf_native_link_loss_discards_pending_tx_and_same_poll_rx
);

fn smoke_brcmf_native_failed_disconnect_and_late_keys_stay_closed() -> TestResult {
    let harness = match Harness::new(6, true, false) {
        Ok(h) => h,
        Err(e) => return TestResult::Fail(e),
    };
    if let Err(error) = harness.associate(true) {
        return TestResult::Fail(error);
    }
    let (uplink, downlink) = packets();
    harness.bus.hold_transmits(true);
    let before = harness.bus.sent();
    let statuses = harness.bus.stats().2;
    if narf_net::iface::send_on(&harness.name, &uplink).is_err() {
        return TestResult::Fail("PCIe pre-disconnect pending TX");
    }
    harness.pump();
    if harness.bus.sent() != before + 1
        || !harness.bus.uplink(&uplink)
        || harness.bus.stats().3 != 1
        || harness.bus.stats().2 != statuses
        || !harness.bus.last_tx_alive()
    {
        return TestResult::Fail("PCIe failed-disconnect fixture did not publish retained TX DMA");
    }
    // Track every native DMA allocation across the failure, including the
    // already consumed TX descriptor whose terminal status is still withheld.
    let dropped = harness.bus.dropped_addresses();
    let dma_enables = harness.bus.dma_enable_count();
    harness.bus.fail_disconnect();
    harness.bus.downlink(&downlink);
    if !matches!(ready(harness.device.disassociate()), Ok(Err(_))) {
        return TestResult::Fail("firmware refused DISASSOC was accepted");
    }
    harness.bus.stale_authorization();
    harness.pump();
    if !harness.closed(&uplink)
        || harness.bus.sent() != before + 1
        || harness.received(&downlink)
        || harness.bus.stats().4
        || harness.bus.stats().5 != 0
        || harness.bus.stats().3 != 1
        || harness.bus.stats().2 != statuses
        || !harness.bus.last_tx_alive()
        || harness.bus.dropped_addresses() != dropped
        || harness.bus.dma_enable_count() != dma_enables
        || !matches!(
            ready(harness.device.associate(Harness::request(true))),
            Ok(Err(_))
        )
        || !harness.bus.last_tx_alive()
        || harness.bus.dropped_addresses() != dropped
        || harness.bus.dma_enable_count() != dma_enables
        || harness.bus.stats().4
    {
        return TestResult::Fail(
            "refused PCIe disconnect reopened old peer/events or DMA ownership",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/station",
    smoke_brcmf_native_failed_disconnect_and_late_keys_stay_closed
);

#[path = "live_policy_tests.rs"]
mod live_policy_tests;

#[path = "lifecycle_tests.rs"]
mod lifecycle_tests;
