//! One real reserved-DMA owner through C21 radio, packet and station admission.
//! Synthetic signed records exist only inside this inert transport fixture.
use super::*;
use crate::rtw88::{
    firmware_transport::station_composition_tests::Peer,
    interface::Device,
    station::Environment,
    station_power8821c::{Request as StationRequest, Source as StationSource},
};
use core::sync::atomic::AtomicU64;
use narf_net::{Interface, TxMeta};
use narf_wireless::reg::db::Database;
use narf_wireless::{AssociateRequest, ScanRequest, SecurityConfig, WirelessNetIface};
const OWN: [u8; 6] = [2, 4, 6, 8, 10, 12];
const AP: [u8; 6] = [2, 0, 0, 0, 0, 1];
const SSID: &[u8] = b"narf-8822ce"; // shared independent AP actor, not a chip identity
#[path = "wmm8821c_tests.rs"]
mod wmm_tests;

type OperatingFixture = (Fixture, Cap<FirmwareBlob, Read>, Cap<FirmwareBlob, Read>);
fn operating() -> Result<OperatingFixture, &'static str> {
    let (f, iqk) = calibrated()?;
    let req = request(&f)?;
    let power = Cap::bootstrap();
    narf_scheduler::block_on(f.lifecycle.prepare_operating8821c_with(
        &f.factory,
        power_source(artifact(&req), power),
        || Ok(domain()),
    ))
    .map_err(|_| "C21 radio fixture parked power failed")?;
    Ok((f, iqk, power))
}
fn station_artifact(request: &StationRequest) -> Vec<u8> {
    let mut b = vec![0; 128];
    b[..4].copy_from_slice(b"N21S");
    b[4..8].copy_from_slice(&[1, 0, 128, 0]);
    b[8..12].copy_from_slice(&128u32.to_le_bytes());
    b[12..16].copy_from_slice(&[0xec, 0x10, 0x21, 0xc8]);
    b[16..48].copy_from_slice(&request.identity);
    b[48..54].copy_from_slice(&request.mac);
    b[54..56].copy_from_slice(&[1, 20]);
    for (at, value) in [(56, 4i16), (58, 76), (60, 44), (62, 48), (64, 52)] {
        b[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    b[66..70].copy_from_slice(&[0, 63, b'U', b'S']);
    b
}
fn policy() -> Arc<Database> {
    let db = Arc::new(Database::new());
    db.install(domain());
    db
}
fn station_source(
    bytes: Vec<u8>,
    cap: Cap<FirmwareBlob, Read>,
    policy: Arc<Database>,
) -> StationSource {
    StationSource::Verified {
        bytes,
        signer: Some([9; 32]),
        cap,
        policy,
    }
}
fn station_request(f: &Fixture) -> Result<StationRequest, &'static str> {
    narf_scheduler::block_on(f.lifecycle.station_request8821c(&f.factory))
        .map_err(|_| "C21 full station request absent after parked power")
}
fn radio_failure(f: &Fixture, error: Error) -> &'static str {
    let m = f.port.0.lock();
    narf_console::klog!("C21 unexpected radio error {:?}, continuation={} calls={} CR={:02x} pause={:02x} dma={:02x} RRSR={:08x} CAM={:08x} RPWM={:02x} CPWM={:02x}\n",error,m.continuation,m.calls,m.bytes[0x100],m.bytes[0x522],m.bytes[0x303],word(&m.bytes,0x440),word(&m.bytes,0x670),m.bytes[0x3d9],m.bytes[0x3da]);
    "C21 native full radio continuation failed; see native receipt diagnostics"
}
fn smoke_rtw8821ce_native_station_radio_retry_receipts_and_retained_reserved_dma() -> TestResult {
    let (f, _, _) = match operating() {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    let req = match station_request(&f) {
        Ok(r) => r,
        Err(e) => return TestResult::Fail(e),
    };
    let baseline = f.port.0.lock().calls;
    for variant in 0..11 {
        let db = policy();
        let mut bytes = station_artifact(&req);
        let cap = Cap::bootstrap();
        match variant {
            0 => {
                bytes = artifact(&match request(&f) {
                    Ok(r) => r,
                    Err(e) => return TestResult::Fail(e),
                });
            }
            1 => bytes[16] ^= 1,
            2 => bytes[48] ^= 1,
            3 => bytes[70] = 1,
            4 => bytes[64..66].copy_from_slice(&80i16.to_le_bytes()),
            5 => db.clear(),
            6 => {
                let mut d = domain();
                d.rules[0].flags = RegFlags::NO_IR;
                db.install(d);
            }
            7 => cap.revoke(),
            8 => bytes[66..68].copy_from_slice(&[20, 30]),
            9 => {
                bytes.pop();
            }
            _ => (),
        }
        let mut source = station_source(bytes, cap, db);
        if let (10, StationSource::Verified { signer, .. }) = (variant, &mut source) {
            *signer = None;
        }
        if narf_scheduler::block_on(f.lifecycle.prepare_station8821c(&f.factory, source)).is_ok()
            || f.lifecycle.status().stage != Stage::Operating8821cPrepared
            || f.port.0.lock().calls != baseline
        {
            return TestResult::Fail(
                "C21 invalid/missing-current station grant wrote or consumed parked owner",
            );
        }
    }
    let result = narf_scheduler::block_on(f.lifecycle.prepare_station8821c(
        &f.factory,
        station_source(station_artifact(&req), Cap::bootstrap(), policy()),
    ));
    let info = match result {
        Ok(i) => i,
        Err(error) => return TestResult::Fail(radio_failure(&f, error)),
    };
    let m = f.port.0.lock();
    if info.identity != req.identity
        || info.thermal != 25
        || info.response_rates != 0x1f
        || m.continuation != 12
        || word(&m.bytes, 0x440) != 0x1f
        || word(&m.bytes, 0x670) & 0x1ffff != 0x100f8
        || m.bytes[0x3d9] != 0xc0
        || m.bytes[0x3da] != 0x80
        || m.bytes[0x100] & 0xcf != 0
        || m.bytes[0x522] != 255
        || m.bytes[0x303] & 0xf7 != 0xf7
        || m.ring.lock().bytes[..16] != [0; 16]
        || m.frame.lock().bytes[..DESC] != [0; DESC]
        || m.station_gate.as_ref().is_none_or(|g| g.did() != 0xc821)
        || m.station_gate.as_ref().is_some_and(|g| {
            g.extension_request().is_none()
                || g.calibrated_base().is_some()
                || g.allows_profile(crate::rtw88::packet_format::DataProfile {
                    rates: 0xfff,
                    qos: false,
                    mcs: 0,
                    sgi: false,
                    ldpc: false,
                    stbc: false,
                    acs: 0,
                })
                || g.allows_profile(crate::rtw88::packet_format::DataProfile {
                    rates: 1,
                    qos: true,
                    mcs: 0,
                    sgi: false,
                    ldpc: false,
                    stbc: false,
                    acs: 0,
                })
        })
        || m.command_ring.pending()
    {
        return TestResult::Fail(
            "C21 actual parked disarm, C21 gains, CAM/wake receipts or sealed chip gate differ",
        );
    }
    drop(m);
    if f.lifecycle.status().stage != Stage::Radio8821cPrepared
        || narf_scheduler::block_on(f.lifecycle.station_radio_info8821c()) != Some(info)
    {
        return TestResult::Fail("C21 native radio receipt not retained");
    }
    let drops = f.drops.clone();
    drop(f);
    if drops.load(Ordering::SeqCst) != 0 {
        return TestResult::Fail("C21 radio completion dropped published firmware DMA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c/station",
    smoke_rtw8821ce_native_station_radio_retry_receipts_and_retained_reserved_dma
);

fn smoke_rtw8821ce_radio_real_receipt_failures_never_admit_station() -> TestResult {
    for failure in 0..7 {
        let (f, _, _) = match operating() {
            Ok(f) => f,
            Err(e) => return TestResult::Fail(e),
        };
        let req = match station_request(&f) {
            Ok(r) => r,
            Err(e) => return TestResult::Fail(e),
        };
        {
            let mut m = f.port.0.lock();
            match failure {
                0 => m.awake_stuck = true,
                1 => m.cam_stuck = true,
                2 => m.bytes[0x2860] ^= 1,
                3 => m.bytes[0x1d00] ^= 1,
                4 => m.thermal_values = Some([31, 31]),
                5 => m.ignore_write = Some(0x440),
                _ => m.bytes[0x303] &= !1,
            }
        }
        if narf_scheduler::block_on(f.lifecycle.prepare_station8821c(
            &f.factory,
            station_source(station_artifact(&req), Cap::bootstrap(), policy()),
        ))
        .is_ok()
            || f.lifecycle.status().stage != Stage::Failed
            || narf_scheduler::block_on(f.lifecycle.station_radio_info8821c()).is_some()
            || f.port.0.lock().station_gate.is_some()
            || f.port.0.lock().bytes[0x100] & 0xcf != 0
        {
            return TestResult::Fail("C21 missing physical/model receipt admitted radio/packets");
        }
        let drops = f.drops.clone();
        drop(f);
        if drops.load(Ordering::SeqCst) != 0 {
            return TestResult::Fail("C21 radio receipt failure released original DMA");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c/station",
    smoke_rtw8821ce_radio_real_receipt_failures_never_admit_station
);

fn smoke_rtw8821ce_radio_pending_thermal_cancel_all_sources_policy_and_dma() -> TestResult {
    for failure in 0..6 {
        let (f, iqk, power) = match operating() {
            Ok(f) => f,
            Err(e) => return TestResult::Fail(e),
        };
        let req = match station_request(&f) {
            Ok(r) => r,
            Err(e) => return TestResult::Fail(e),
        };
        let station = Cap::bootstrap();
        let db = policy();
        f.port.0.lock().hold_delay = Some(2_000_000);
        let mut operation = Box::pin(f.lifecycle.prepare_station8821c(
            &f.factory,
            station_source(station_artifact(&req), station, db.clone()),
        ));
        let mut cx = Context::from_waker(Waker::noop());
        if operation.as_mut().poll(&mut cx).is_ready() || f.port.0.lock().continuation != 11 {
            return TestResult::Fail("C21 radio fixture missed actual pending thermal conversion");
        }
        let baseline = f.port.0.lock().calls;
        match failure {
            0 => (),
            1 => iqk.revoke(),
            2 => power.revoke(),
            3 => station.revoke(),
            4 => db.clear(),
            _ => {
                let mut d = domain();
                d.rules[0].max_power_dbm = 10;
                db.install(d);
            }
        }
        f.port.0.lock().hold_delay = None;
        if failure != 0 && !matches!(operation.as_mut().poll(&mut cx), Poll::Ready(Err(_))) {
            return TestResult::Fail("C21 resumed radio ignored source or live policy denial");
        }
        drop(operation);
        if f.lifecycle.status().stage != Stage::Failed
            || f.port.0.lock().calls != baseline
            || f.port.0.lock().station_gate.is_some()
        {
            return TestResult::Fail(
                "C21 cancelled/revoked radio wrote after retained await or published readiness",
            );
        }
        db.install(domain());
        if narf_scheduler::block_on(f.lifecycle.prepare_station8821c(
            &f.factory,
            station_source(station_artifact(&req), Cap::bootstrap(), db),
        ))
        .is_ok()
        {
            return TestResult::Fail("C21 terminal radio owner resurrected on reinstall");
        }
        let drops = f.drops.clone();
        drop(f);
        if drops.load(Ordering::SeqCst) != 0 {
            return TestResult::Fail("C21 cancelled radio released original DMA");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c/station",
    smoke_rtw8821ce_radio_pending_thermal_cancel_all_sources_policy_and_dma
);

struct Env {
    clock: Arc<AtomicU64>,
}
#[async_trait::async_trait]
impl Environment for Env {
    fn now_ms(&self) -> u64 {
        self.clock.load(Ordering::Acquire)
    }
    fn nonce(&self) -> Option<[u8; 32]> {
        Some([0x33; 32])
    }
    async fn pause(&self) {
        let mut once = true;
        core::future::poll_fn(|cx| {
            if once {
                once = false;
                cx.waker().wake_by_ref();
                Poll::Pending
            } else {
                self.clock.fetch_add(1, Ordering::AcqRel);
                Poll::Ready(())
            }
        })
        .await;
    }
}
type TestDevice = Device<Backend<Port, Block>>;
static ACTIVE: IrqSafeSpinLock<Option<Arc<TestDevice>>> = IrqSafeSpinLock::new(None);
fn send(frame: &[u8], meta: TxMeta) -> Result<(), ()> {
    ACTIVE.lock().clone().ok_or(())?.enqueue(frame, meta)
}
fn drain() -> bool {
    ACTIVE.lock().clone().is_some_and(|d| d.drain())
}
fn complete<T>(future: impl Future<Output = T>) -> Result<T, &'static str> {
    let mut future = Box::pin(future);
    for _ in 0..100_000 {
        if let Poll::Ready(v) = future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            return Ok(v);
        }
    }
    Err("C21 retained native fixture did not complete in bounded polls")
}
struct Harness {
    device: Arc<TestDevice>,
    lifecycle: Arc<Lifecycle<Backend<Port, Block>>>,
    port: Port,
    peer: Arc<IrqSafeSpinLock<Peer>>,
    db: Arc<Database>,
    sources: [Cap<FirmwareBlob, Read>; 3],
    drops: Arc<AtomicUsize>,
}
impl Harness {
    fn new(protected: bool) -> Result<Self, &'static str> {
        if ACTIVE.lock().is_some() {
            return Err("C21 native fixture interface collision");
        }
        let (f, iqk, power) = operating()?;
        let req = station_request(&f)?;
        let station = Cap::bootstrap();
        let db = policy();
        complete(f.lifecycle.prepare_station8821c(
            &f.factory,
            station_source(station_artifact(&req), station, db.clone()),
        ))?
        .map_err(|error| radio_failure(&f, error))?;
        let peer = Arc::new(IrqSafeSpinLock::new(Peer::new(protected)));
        let actor = peer.clone();
        let clock = {
            let mut m = f.port.0.lock();
            m.packet_model.reaction = Some(Arc::new(move |frame| {
                actor.lock().react(frame).map_err(|error| {
                    narf_console::klog!(
                        "C21 native AP rejected {:?}, frame prefix {:?}\n",
                        error,
                        &frame[..frame.len().min(40)]
                    );
                    crate::rtw88::packet_core::Error::Packet
                })
            }));
            m.clock.clone()
        };
        let lifecycle = Arc::new(f.lifecycle);
        let name = narf_net::iface::reserve_name("c21-native%d");
        let device = Arc::new(Device::new(
            name,
            OWN,
            lifecycle.clone(),
            Arc::new(Env { clock }),
        ));
        *ACTIVE.lock() = Some(device.clone());
        narf_net::iface::register(name, OWN, send);
        narf_net::iface::set_link_state(name, true);
        narf_net::iface::set_link_metadata(name, false, None, None);
        narf_net::iface::install_rx_handler(narf_net::tcp_stack::rx_handler);
        narf_net::iface::install_rx_drain(drain);
        device.admit_for_test();
        let h = Self {
            device,
            lifecycle,
            port: f.port,
            peer,
            db,
            sources: [iqk, power, station],
            drops: f.drops,
        };
        complete(h.device.activate())?.map_err(|_| "C21 source port0/packet activation failed")?;
        let beacon = h.peer.lock().ap.beacon();
        h.port.0.lock().packet_model.receive(&beacon, false, false);
        Ok(h)
    }
    fn request(&self) -> AssociateRequest {
        AssociateRequest {
            bssid: AP,
            ssid: SSID.to_vec(),
            frequency_mhz: 2412,
            channel: 1,
            security: if self.peer.lock().ap.protected() {
                SecurityConfig::Wpa2 { psk: [0x55; 32] }
            } else {
                SecurityConfig::Open
            },
            ie: Vec::new(),
        }
    }
    fn scan(&self) -> Result<(), &'static str> {
        let seen = complete(self.device.scan(ScanRequest {
            ssids: vec![SSID.to_vec()],
            frequencies_mhz: vec![2412],
            channels: vec![1],
            active: false,
            random_mac: None,
            colocated_6ghz: false,
            duration_tu: Some(1),
            duration_mandatory: false,
            extra_ies: Vec::new(),
        }))?
        .map_err(|_| "C21 native passive scan failed")?;
        if seen.len() != 1 || seen[0].bssid != AP {
            return Err("C21 native BSS observation mismatch");
        }
        Ok(())
    }
    fn join(&self) -> Result<(), &'static str> {
        self.scan()?;
        complete(self.device.associate(self.request()))?
            .map_err(|_| "C21 actual MLME/RSNA join failed")?;
        if !self.device.link_up() {
            return Err("C21 carrier absent after exact native join");
        }
        Ok(())
    }
    fn pump(&self) {
        for _ in 0..16 {
            self.device.drain();
        }
    }
    fn closed(&self) -> bool {
        !self.device.link_up() && self.device.connected_bssid().is_none()
    }
    fn received(&self) -> Vec<Vec<u8>> {
        let mut result = Vec::new();
        let mut ring = self.device.rx_ring().lock();
        if let Some(ring) = ring.as_mut() {
            while let Ok(Some(frame)) = ring.try_recv() {
                result.push(frame.payload().to_vec());
            }
        }
        result
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        *ACTIVE.lock() = None;
        narf_net::iface::unregister(self.device.name());
    }
}
fn composition(protected: bool) -> TestResult {
    let h = match Harness::new(protected) {
        Ok(h) => h,
        Err(e) => return TestResult::Fail(e),
    };
    if !h.closed() || narf_net::dhcp::acquire(h.device.name(), 100).is_ok() {
        return TestResult::Fail("C21 DHCP/carrier admitted before association");
    }
    if let Err(e) = h.join() {
        return TestResult::Fail(e);
    }
    let plan = h.peer.lock().plan;
    match narf_net::dhcp::dhcp_acquire(h.device.name(), 0) {
        Ok(lease) if plan.matches_lease(&lease) => (),
        _ => return TestResult::Fail("C21 native Open/WPA2 kernel DHCP DORA failed"),
    }
    let uplink = narf_wifi_fixtures::udp_ipv4(
        AP,
        OWN,
        plan.lease_ip,
        plan.server_ip,
        49152,
        7,
        b"c21-native-uplink",
    );
    if narf_net::iface::send_on(h.device.name(), &uplink).is_err() {
        return TestResult::Fail("C21 native IP enqueue failed");
    }
    h.pump();
    if h.peer.lock().uplink.last() != Some(&uplink) {
        return TestResult::Fail("C21 real descriptor/CCMP IP uplink differs");
    }
    let downlink = narf_wifi_fixtures::udp_ipv4(
        OWN,
        AP,
        plan.server_ip,
        plan.lease_ip,
        7,
        49152,
        b"c21-native-downlink",
    );
    let wire = match h.peer.lock().downlink(&downlink) {
        Ok(w) => w,
        Err(e) => return TestResult::Fail(e),
    };
    h.port.0.lock().packet_model.receive(&wire, false, false);
    h.pump();
    if !h.received().contains(&downlink) {
        return TestResult::Fail("C21 actual native RX/CCMP IP differs");
    }
    let m = h.port.0.lock();
    if !m.mailboxes.contains(&[0x20, 0, 0, 1, 0, 0x0c, 0, 0])
        || !m.mailboxes.contains(&[0x40, 0, 0x28, 0x40, 1, 0, 0, 0])
        || word(&m.bytes, 0x500) != 0xa532
        || word(&m.bytes, 0x508) != 0xa532
        || m.packet_model.tx_publications < 5
    {
        return TestResult::Fail("C21 same-source ACTIVE/RA/DCF or native packet chain missing");
    }
    drop(m);
    if !matches!(complete(h.device.disassociate()), Ok(Ok(())))
        || !h.closed()
        || h.port.0.lock().packet_model.active
    {
        return TestResult::Fail("C21 terminal native disconnect did not park");
    }
    if h.device.enqueue(&uplink, TxMeta::default()).is_ok() {
        return TestResult::Fail("C21 closed packet owner reopened");
    }
    let drops = h.drops.clone();
    drop(h);
    // The disconnect's DMA-stop proof released the beacon ring and frame.
    if drops.load(Ordering::SeqCst) != 2 {
        return TestResult::Fail("C21 proven-idle station teardown kept firmware DMA retained");
    }
    TestResult::Pass
}
fn smoke_rtw8821ce_same_owner_native_open_kernel_dhcp_ip() -> TestResult {
    composition(false)
}
fn smoke_rtw8821ce_same_owner_native_wpa2_kernel_dhcp_ip() -> TestResult {
    composition(true)
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c/station",
    smoke_rtw8821ce_same_owner_native_open_kernel_dhcp_ip
);
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c/station",
    smoke_rtw8821ce_same_owner_native_wpa2_kernel_dhcp_ip
);

fn smoke_rtw8821ce_native_m4_cancel_policy_sources_and_late_receipt_terminal() -> TestResult {
    for failure in 0..5 {
        let h = match Harness::new(true) {
            Ok(h) => h,
            Err(e) => return TestResult::Fail(e),
        };
        if let Err(e) = h.scan() {
            return TestResult::Fail(e);
        }
        h.peer.lock().hold_m4 = true;
        let controls = h.port.0.lock().packet_model.controls.clone();
        let request = h.request();
        let mut join = Box::pin(h.device.associate(request));
        let mut cx = Context::from_waker(Waker::noop());
        let mut held = false;
        for _ in 0..100_000 {
            if join.as_mut().poll(&mut cx).is_ready() {
                return TestResult::Fail("C21 held M4 unexpectedly completed join");
            }
            if controls.held.load(Ordering::Acquire) {
                held = true;
                break;
            }
        }
        if !held || !h.closed() {
            return TestResult::Fail(
                "C21 actual native M4 receipt boundary absent/carrier premature",
            );
        }
        let baseline = h.port.0.lock().packet_model.tx_publications;
        match failure {
            0 => (),
            1 => h.sources[0].revoke(),
            2 => h.sources[1].revoke(),
            3 => h.sources[2].revoke(),
            _ => h.db.clear(),
        }
        if failure != 0 && !matches!(join.as_mut().poll(&mut cx), Poll::Ready(Err(_))) {
            return TestResult::Fail("C21 pending M4 ignored actual source/policy denial");
        }
        drop(join);
        controls.release.store(true, Ordering::Release);
        h.db.install(domain());
        h.pump();
        if !h.closed()
            || h.port.0.lock().packet_model.tx_publications != baseline
            || !h.device.closed()
            || h.port.0.lock().packet_model.active
            || !matches!(complete(h.device.associate(h.request())), Ok(Err(_)))
        {
            return TestResult::Fail("C21 late M4/reinstalled policy revived terminal owner");
        }
        let drops = h.drops.clone();
        drop(h);
        if drops.load(Ordering::SeqCst) != 0 {
            return TestResult::Fail("C21 cancelled native M4 released published firmware DMA");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c/station",
    smoke_rtw8821ce_native_m4_cancel_policy_sources_and_late_receipt_terminal
);

fn smoke_rtw8821ce_native_descriptor_publication_rechecks_all_signed_sources() -> TestResult {
    for failure in 0..4 {
        let h = match Harness::new(true) {
            Ok(h) => h,
            Err(e) => return TestResult::Fail(e),
        };
        if let Err(e) = h.join() {
            return TestResult::Fail(e);
        }
        let baseline = h.port.0.lock().packet_model.tx_publications;
        let cap = h.sources[failure.min(2)];
        let db = h.db.clone();
        h.port.0.lock().packet_model.after_descriptor = Some(Arc::new(move || {
            if failure < 3 {
                cap.revoke()
            } else {
                db.clear()
            }
        }));
        let plan = h.peer.lock().plan;
        let packet = narf_wifi_fixtures::udp_ipv4(
            AP,
            OWN,
            plan.lease_ip,
            plan.server_ip,
            49152,
            7,
            b"c21-revoked-at-native-bd",
        );
        if h.device.enqueue(&packet, TxMeta::default()).is_err() {
            return TestResult::Fail(
                "C21 descriptor fault fixture refused initial admitted enqueue",
            );
        }
        h.pump();
        h.db.install(domain());
        h.pump();
        if !h.closed()
            || !h.device.closed()
            || h.port.0.lock().packet_model.tx_publications != baseline
            || h.port.0.lock().packet_model.active
            || h.device.enqueue(&packet, TxMeta::default()).is_ok()
        {
            return TestResult::Fail("C21 signed-source/policy loss after native descriptor allowed doorbell or revived owner");
        }
        let drops = h.drops.clone();
        drop(h);
        if drops.load(Ordering::SeqCst) != 0 {
            return TestResult::Fail("C21 uncertain descriptor publication freed original DMA");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c/station",
    smoke_rtw8821ce_native_descriptor_publication_rechecks_all_signed_sources
);
