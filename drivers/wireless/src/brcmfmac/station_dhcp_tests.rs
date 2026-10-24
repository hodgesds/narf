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
struct Harness {
    device: Arc<ModelDevice>,
    bus: Handle,
    name: String,
}
impl Harness {
    fn new(version: u32, secured: bool, keys_first: bool) -> Result<Self, &'static str> {
        let (adapter, bus) =
            firmware::create(version, secured).map_err(|_| "CR4/common-ring native ownership")?;
        bus.keys_first(keys_first);
        let station = ready(Station::initialize(adapter, &[], firmware::domain()))?
            .map_err(|_| "PCIe station firmware initialization")?;
        if station.mac != OWN || station.channels != [1, 6, 11] || !station.supplicant {
            return Err("PCIe firmware identity/channel/key capabilities");
        }
        let channels = station
            .channels
            .iter()
            .map(|&channel| u32::from(channel))
            .collect();
        let supplicant = station.supplicant;
        let (rx, consumer) = narf_ipc::channel();
        let (producer, tx) = narf_ipc::channel();
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
            up: AtomicBool::new(false),
            bssid: AtomicU64::new(0),
            rx: IrqSafeSpinLock::new(Some(consumer)),
            tx: IrqSafeSpinLock::new(Some(producer)),
        });
        *ACTIVE_TEST.lock() = Some(device.clone());
        narf_net::iface::set_link_state(&name, false);
        narf_net::iface::install_rx_handler(narf_net::tcp_stack::rx_handler);
        narf_net::iface::install_rx_drain(drain);
        Ok(Self { device, bus, name })
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
        .map_err(|_| "PCIe native escan")?;
        if bss.len() != 1 || bss[0].bssid != AP || bss[0].frequency_mhz != 2437 {
            return Err("PCIe scan did not return the native BSS event");
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
    fn associate(&self, secured: bool) -> Result<(), &'static str> {
        self.scan()?;
        ready(self.device.associate(Self::request(secured)))?
            .map_err(|_| "PCIe native offloaded association")?;
        if self.device.connected_bssid() != Some(AP)
            || !self.device.link_up()
            || narf_net::iface::lookup(&self.name)
                .is_none_or(|iface| !iface.carrier || !iface.link_up)
        {
            return Err("PCIe association did not open exact peer/carrier");
        }
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
                .is_some_and(|iface| !iface.link_up && !iface.carrier)
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
    let harness = Harness::new(version, secured, keys_first)?;
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
    for version in [5, 6] {
        if let Err(error) = composition(version, false, false) {
            return TestResult::Fail(error);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/station",
    smoke_brcmf_native_open_station_to_dhcp_and_bidirectional_ip
);
fn smoke_brcmf_native_wpa2_station_to_dhcp_and_bidirectional_ip() -> TestResult {
    for version in [5, 6] {
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
