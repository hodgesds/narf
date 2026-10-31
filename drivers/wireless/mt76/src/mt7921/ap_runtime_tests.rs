//! Real Session/MCU publication under an actual registered interface grant.
//! The model supplies only the hardware side, never synthetic admin authority.
use super::*;
use alloc::{boxed::Box, string::String};
use core::sync::atomic::{AtomicU32, AtomicU64};
use narf_capabilities::{Cap, Invoke};
use narf_ipc::{Consumer, Producer};
use narf_lib::sync::IrqSafeSpinLock;
use narf_net::netlink_generic::DeferredReplySink;
use narf_net::{AdminHandle, Frame, Interface, RX_RING_N, TX_RING_N};
use narf_wireless::{ap_control::ApControlAuthority, WirelessError, WirelessNetIface};

// Keep the large native model off nested kernel-test stacks on ARM.
type NativeSession = Box<Session<Model>>;
#[path = "ap_iface_tests.rs"]
mod concrete;
#[path = "ap_control_tests.rs"]
mod control;
#[path = "ap_management_tests.rs"]
mod management;
#[path = "p2p_device_tests.rs"]
mod p2p_device;
#[path = "ap_packet_tests.rs"]
mod packets;
#[path = "ap_receive_tests.rs"]
mod receive;
#[path = "ap_update_tests.rs"]
mod update;

#[derive(Debug, Default)]
pub(super) struct Hold {
    pub seen: AtomicBool,
    pub release: AtomicBool,
}
struct Radio {
    name: String,
    mac: [u8; 6],
    mode: AtomicU32,
    generation: AtomicU64,
    serial: Arc<narf_wireless::ap_control::ExclusiveControl>,
    rx: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
}
impl Radio {
    fn new(name: String, mac: [u8; 6], mode: u32) -> Self {
        Self {
            name,
            mac,
            mode: AtomicU32::new(mode),
            generation: AtomicU64::new(1),
            serial: Arc::new(narf_wireless::ap_control::ExclusiveControl::new()),
            rx: IrqSafeSpinLock::new(None),
            tx: IrqSafeSpinLock::new(None),
        }
    }
}
impl Interface for Radio {
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
        true
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx
    }
}
#[async_trait::async_trait]
impl WirelessNetIface for Radio {
    fn get_wireless_info(&self) -> narf_wireless::WirelessIfaceInfo {
        narf_wireless::WirelessIfaceInfo {
            base_name: self.name.clone(),
            base_mac: self.mac(),
            bands: Vec::new(),
            modes: narf_wireless::iface::WirelessModes::AP,
            hw_caps: narf_wireless::iface::HwCaps {
                ht_supported: false,
                vht_supported: false,
                he_supported: false,
                eht_supported: false,
            },
        }
    }
    async fn scan(
        &self,
        _: narf_wireless::ScanRequest,
    ) -> Result<Vec<narf_wireless::BssInfo>, WirelessError> {
        Err(WirelessError::NotSupported)
    }
    async fn associate(&self, _: narf_wireless::AssociateRequest) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }
    async fn disassociate(&self) -> Result<(), WirelessError> {
        Ok(())
    }
    async fn set_config(&self, _: narf_wireless::WirelessConfig) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }
    fn current_iftype(&self) -> u32 {
        self.mode.load(Ordering::Acquire)
    }
    fn supports_ap(&self) -> bool {
        true
    }
    fn ap_control_generation(&self) -> Option<core::num::NonZeroU64> {
        core::num::NonZeroU64::new(self.generation.load(Ordering::Acquire))
    }
    fn reserve_ap_control(
        &self,
    ) -> Result<Option<Arc<dyn narf_wireless::ap_control::ApControlReservation>>, WirelessError>
    {
        self.serial.try_reserve().map(Some)
    }
    fn radio_control_generation(&self) -> Option<core::num::NonZeroU64> {
        core::num::NonZeroU64::new(self.generation.load(Ordering::Acquire))
    }
    fn reserve_radio_control(
        &self,
    ) -> Result<Option<Arc<dyn narf_wireless::ap_control::ApControlReservation>>, WirelessError>
    {
        self.serial.try_reserve().map(Some)
    }
}
struct Registered(Arc<Radio>);
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
        true
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.0.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.0.tx
    }
}
#[derive(Debug)]
struct Source(AtomicBool, IrqSafeSpinLock<Vec<Vec<u8>>>);
impl Source {
    fn new() -> Self {
        Self(AtomicBool::new(true), IrqSafeSpinLock::new(Vec::new()))
    }
}
impl DeferredReplySink for Source {
    fn current(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
    fn deliver(&self, message: Vec<u8>) -> Result<(), i32> {
        if !self.current() {
            return Err(125);
        }
        self.1.lock().push(message);
        Ok(())
    }
}
struct Fixture {
    _binding: Binding,
    ifindex: u32,
    radio: Arc<Radio>,
    iface: Arc<dyn WirelessNetIface>,
    source: Arc<Source>,
    admin: AdminHandle,
    daemon: Cap<narf_net::stack::StackDaemon, Invoke>,
}
struct Binding(String);
impl Drop for Binding {
    fn drop(&mut self) {
        narf_wireless::registry::unregister(&self.0);
        narf_net::registry().unregister(&self.0);
        narf_net::iface::unregister(&self.0);
    }
}
fn reject(_: &[u8], _: narf_net::TxMeta) -> Result<(), ()> {
    Err(())
}
fn fixture(mac: [u8; 6]) -> Result<Fixture, &'static str> {
    fixture_for(mac, 3, true)
}
fn fixture_for(mac: [u8; 6], mode: u32, up: bool) -> Result<Fixture, &'static str> {
    let name = narf_net::iface::register("mt76-ap-native-proof%d", mac, reject);
    let binding = Binding(name.clone());
    let radio = Arc::new(Radio::new(name.clone(), mac, mode));
    let iface: Arc<dyn WirelessNetIface> = radio.clone();
    let authority = narf_net::bootstrap_authority();
    let cap = narf_net::registry()
        .register(&authority, Registered(radio.clone()))
        .map_err(|_| "AP grant fixture driver registration")?;
    let daemon = Cap::<narf_net::stack::StackDaemon, Invoke>::bootstrap();
    let admin =
        narf_net::stack::control_registered(&narf_net::stack::StackAttach { iface: cap, daemon })
            .map_err(|_| "AP grant fixture actual delegated administration")?
            .admin;
    narf_wireless::registry::register(iface.clone());
    if !narf_net::iface::set_link_state(&name, up) {
        return Err("AP fixture administrative UP");
    }
    let ifindex = narf_net::iface::lookup(&name)
        .ok_or("AP fixture ifindex")?
        .ifindex;
    Ok(Fixture {
        _binding: binding,
        ifindex,
        radio,
        iface,
        source: Arc::new(Source::new()),
        admin,
        daemon,
    })
}

fn config(mac: [u8; 6]) -> narf_wireless::ApConfig {
    let mut beacon = vec![0; 36];
    beacon[0] = 0x80;
    beacon[4..10].fill(0xff);
    beacon[10..16].copy_from_slice(&mac);
    beacon[16..22].copy_from_slice(&mac);
    beacon[32..34].copy_from_slice(&100u16.to_le_bytes());
    beacon[34..36].copy_from_slice(&1u16.to_le_bytes());
    beacon.extend_from_slice(&[
        0, 4, b'n', b'a', b'r', b'f', 1, 4, 0x82, 0x84, 0x8b, 0x96, 3, 1, 6,
    ]);
    narf_wireless::ApConfig {
        ssid: b"narf".to_vec(),
        beacon_head: beacon,
        beacon_tail: Vec::new(),
        probe_resp: None,
        beacon_interval: 100,
        dtim_period: 2,
        frequency_mhz: 2437,
        channel_width: 0,
        center_freq1_mhz: None,
        center_freq2_mhz: None,
        hidden_ssid: 0,
        privacy: false,
        mbssid: None,
        mbssid_elems: Vec::new(),
        ema_rnr_elems: Vec::new(),
        fils_discovery: None,
        unsol_bcast_probe_resp: None,
        ftm_responder: None,
        twt_responder: false,
        he_obss_pd: None,
        he_bss_color: None,
    }
}
fn idle() -> Result<(NativeSession, Fixture, Arc<ApControlAuthority>), &'static str> {
    use narf_wireless::reg::{RegFlags, RegRule, RegulatoryDomain};
    let current = Arc::new(CurrentPolicy {
        database: narf_wireless::reg::db::Database::new(),
        hold_bss_ack: AtomicBool::new(false),
    });
    current.database.install(RegulatoryDomain {
        country_code: *b"US",
        rules: vec![RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2472,
            max_bandwidth_mhz: 20,
            max_power_dbm: 17,
            flags: RegFlags::empty(),
        }],
    });
    let mut model = Model::new();
    model.tx_policy = Some(current);
    let mut session = Box::new(Session::new(model, firmware(32)));
    run(session.run()).map_err(|_| "AP actual firmware boot")?;
    let info = run(session.initialize_radio()).map_err(|_| "AP actual radio receipt")?;
    let fixture = fixture(info.capabilities.mac)?;
    let authority = Arc::new(
        ApControlAuthority::bind(
            fixture.admin.clone(),
            &fixture.iface,
            0,
            fixture.ifindex,
            fixture.source.clone(),
        )
        .and_then(ApControlAuthority::reserve)
        .map_err(|_| "AP actual bound administration")?,
    );
    Ok((session, fixture, authority))
}
fn uni(frame: &[u8], id: u16) -> Option<&[u8]> {
    (frame.len() > 48 && frame[43] == 7 && frame[34..36] == id.to_le_bytes()).then(|| &frame[48..])
}
fn bootstrap() -> Result<(), &'static str> {
    let (mut session, fixture, authority) = idle()?;
    let own = fixture.radio.mac();
    let before = session.backend.frames.len();
    let old_epoch = session.receive_epoch;
    run(Box::pin(session.start_ap(authority.clone(), config(own))))
        .map_err(|_| "AP native bootstrap")?;
    if !matches!(
        session.state,
        State::AccessPoint {
            frequency_mhz: 2437,
            ..
        }
    ) || session.receive_epoch == old_epoch
        || session.backend.receive_open
        || session.backend.receive_epoch != session.receive_epoch
        || session.security.is_some()
        || session.receive_current(session.receive_epoch) != Ok(false)
    {
        return Err("AP bootstrap promoted station traffic or stale capture");
    }
    if session.backend.ap_timing != Some((0x003000e7, 0x001c003c, 0x140a0968, 3)) {
        return Err("AP MAC timing did not apply actual 2.4GHz long-slot/SIFS/CFEND profile");
    }
    let frames = &session.backend.frames[before..];
    let bss = frames
        .iter()
        .filter_map(|(_, f)| uni(f, 2))
        .find(|b| b.len() == 44 && b[8] == 1)
        .ok_or("AP active BSS receipt")?;
    if bss[12..16] != [2, 0, 1, 0]
        || bss[18..24] != own
        || bss[24..28] != [19, 0, 100, 0]
        || bss[28] != 2
        || bss[30..32] != [19, 0]
        || bss[40] != 0
    {
        return Err("AP BSS used station connection/AID/WCID or guessed WMM");
    }
    let group = frames
        .iter()
        .filter_map(|(_, f)| uni(f, 3))
        .find(|b| b.get(1) == Some(&19))
        .ok_or("AP BMC WTBL receipt")?;
    if group.len() != 60
        || group[..8] != [0, 19, 1, 0, 1, 14, 0, 0]
        || group[8..16] != [13, 0, 52, 0, 19, 1, 3, 0]
        || group[24..30] != [255; 6]
        || group[45..48] != [1, 1, 1]
        || group[57..59] != [1, 1]
    {
        return Err("AP BMC WTBL native ownership mismatch");
    }
    let beacon = frames
        .iter()
        .filter_map(|(_, f)| uni(f, 2))
        .find(|b| b.len() == 530)
        .ok_or("AP embedded beacon command")?;
    let plan = &session.ap_owner.as_ref().unwrap().plan;
    if beacon[4..8] != [7, 0, 14, 2]
        || beacon[14] != 1
        || beacon[50..50 + plan.beacon.len()] != plan.beacon
        || beacon[8..10] != ((32 + plan.tim_offset) as u16).to_le_bytes()
        || beacon[22..26] != 0x80026000u32.to_le_bytes()
        || beacon[30..34] != 0x1000f801u32.to_le_bytes()
    {
        return Err("AP beacon TXD/TIM wire mismatch");
    }
    if !frames.iter().any(|(_, f)| {
        f.get(36) == Some(&0x16)
            && f.get(64..76) == Some(&[0, 2, 0, 0, 100, 0, 0, 0, 0, 0, 0, 0][..])
    }) || !frames.iter().any(|(_, f)| f.get(36) == Some(&0x17))
    {
        return Err("AP no-response native connection commands missing");
    }
    let trace = session.backend.recovery_trace.len();
    run(Box::pin(session.stop_ap(&authority))).map_err(|_| "AP stop/reset receipt")?;
    if !matches!(session.state, State::RadioReady(_))
        || session.ap_owner.is_some()
        || !session.backend.recovery_trace[trace..]
            .iter()
            .any(|(stage, _)| *stage == "assert")
    {
        return Err("AP stop failed to retire autonomous MAC owner");
    }
    Ok(())
}
fn mt76_ap_native_bss_group_beacon_and_verified_stop() -> TestResult {
    bootstrap().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/ap",
    mt76_ap_native_bss_group_beacon_and_verified_stop
);

fn pending() -> Result<(), &'static str> {
    for revoke in 0..3 {
        let (mut session, fixture, authority) = idle()?;
        let own = fixture.radio.mac();
        let hold = Arc::new(Hold::default());
        session.backend.ap_hold = Some(hold.clone());
        let policy = session.backend.tx_policy.as_ref().unwrap().clone();
        let mut operation = Box::pin(session.start_ap(authority, config(own)));
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        for _ in 0..8192 {
            if operation.as_mut().poll(&mut cx).is_ready() {
                return Err("AP bootstrap completed without native beacon receipt");
            }
            if hold.seen.load(Ordering::Acquire) {
                break;
            }
        }
        if !hold.seen.load(Ordering::Acquire) {
            return Err("AP did not reach held real beacon ACK");
        }
        if revoke != 0 {
            if revoke == 1 {
                fixture.daemon.revoke();
            } else {
                policy.database.clear();
            }
            if run(operation) != Err(Error::Authority) {
                return Err("AP ignored current admin revocation in native wait");
            }
            if session.ap_owner.is_some() || !matches!(session.state, State::RadioReady(_)) {
                return Err("refused AP request left a live autonomous BSS owner");
            }
        } else {
            drop(operation);
            let competing = || {
                ApControlAuthority::bind(
                    fixture.admin.clone(),
                    &fixture.iface,
                    0,
                    fixture.ifindex,
                    fixture.source.clone(),
                )
                .and_then(ApControlAuthority::reserve)
            };
            if competing().err() != Some(WirelessError::Busy) {
                return Err(
                    "dropped native AP waiter released its still-published control reservation",
                );
            }
            if session.state != State::Running(Stage::ApStart)
                || session.ap_owner.is_none()
                || session.backend.receive_open
            {
                return Err("cancelled AP waiter published a terminal host state");
            }
            hold.release.store(true, Ordering::Release);
            run(Box::pin(session.shutdown())).map_err(|_| "AP abandoned native owner shutdown")?;
            if session.ap_owner.is_some() || session.state != State::Stopped {
                return Err("shutdown did not retire abandoned beacon owner");
            }
            if competing().is_err() {
                return Err("verified AP shutdown retained a dead native reservation");
            }
        }
    }
    Ok(())
}
fn mt76_ap_pending_beacon_receipt_revocation_and_cancellation() -> TestResult {
    pending().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/ap",
    mt76_ap_pending_beacon_receipt_revocation_and_cancellation
);

fn prevalidation() -> Result<(), &'static str> {
    let (mut session, fixture, authority) = idle()?;
    let own = fixture.radio.mac();
    let before = session.backend.frames.len();
    let mut invalid = config(own);
    invalid.channel_width = 2;
    if run(Box::pin(session.start_ap(authority.clone(), invalid))) != Err(Error::Bounds)
        || session.backend.frames.len() != before
        || session.ap_owner.is_some()
    {
        return Err("AP silently narrowed requested PHY or published malformed template");
    }
    // An IE may not straddle the TIM insertion boundary even when simply
    // concatenating head/tail would appear valid.
    let mut invalid = config(own);
    let rate = invalid.beacon_head.pop().unwrap();
    invalid.beacon_tail.push(rate);
    if run(Box::pin(session.start_ap(authority, invalid))) != Err(Error::Bounds)
        || session.backend.frames.len() != before
    {
        return Err("AP accepted an IE split across its native TIM insertion");
    }
    Ok(())
}
fn mt76_ap_template_prevalidation_cannot_publish_partial_firmware_state() -> TestResult {
    prevalidation().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/ap",
    mt76_ap_template_prevalidation_cannot_publish_partial_firmware_state
);

fn bound(fixture: &Fixture) -> Result<Arc<ApControlAuthority>, &'static str> {
    ApControlAuthority::bind(
        fixture.admin.clone(),
        &fixture.iface,
        0,
        fixture.ifindex,
        fixture.source.clone(),
    )
    .and_then(ApControlAuthority::reserve)
    .map(Arc::new)
    .map_err(|_| "new actual AP administrative admission")
}
fn peer_config(index: u8) -> narf_wireless::StationConfig {
    narf_wireless::StationConfig {
        mac: [2, 0, 0, 0, 0x76, index],
        aid: u16::from(index),
        listen_interval: 10,
        supported_rates: vec![2, 4, 11, 22],
        wme: Some(false),
        uapsd_queues: None,
        uapsd_max_sp: None,
        mfp: Some(false),
        capability: Some(1),
        ext_capability: None,
        ht_capability: None,
        vht_capability: None,
        he_capability: None,
        he_6ghz_capability: None,
        authorized: Some(false),
        station_tx_power: None,
    }
}
fn native_peers() -> Result<(), &'static str> {
    let (mut session, fixture, authority) = idle()?;
    let own = fixture.radio.mac();
    run(Box::pin(session.start_ap(authority.clone(), config(own))))
        .map_err(|_| "AP peer BSS bootstrap")?;
    session
        .commit_ap_start(&authority)
        .map_err(|_| "AP current interface capture commit")?;
    drop(authority);
    for index in 1..=13 {
        let authority = bound(&fixture)?;
        let config = peer_config(index);
        run(Box::pin(
            session.ap_add_station(authority.clone(), config.clone()),
        ))
        .map_err(|_| "AP actual native peer record")?;
        let peer = session
            .ap_owner
            .as_ref()
            .unwrap()
            .peers
            .get(config.mac)
            .ok_or("native AP peer was not retained")?;
        if peer.wcid != index || !peer.associated || peer.authorized {
            return Err("AP peer WCID/association/closed port ownership");
        }
        let record = session
            .backend
            .frames
            .iter()
            .rev()
            .find_map(|(_, frame)| uni(frame, 3))
            .ok_or("native AP peer UNI record")?;
        if record.len() != 120
            || record[1] != index
            || record[2] != 5
            || record[12..16] != [1, 0, 1, 0]
            || record[16] != 2
            || record[18..20] != u16::from(index).to_le_bytes()
            || record[20..26] != config.mac
            || record[64] != 2
            || record[72..76] != [index, 1, 3, 0]
            || record[84..90] != config.mac
            || record[105..108] != [0, 1, 1]
            || record[117..119] != [1, 1]
        {
            return Err("AP native BASIC/STATE/WTBL directions or host-port separation");
        }
        let before = session.backend.frames.len();
        let epoch = session.receive_epoch;
        session
            .ap_authorize_station(&authority, config.mac, true)
            .map_err(|_| "actual AP host port authorization")?;
        if session.backend.frames.len() != before
            || session.receive_epoch == epoch
            || !session
                .ap_owner
                .as_ref()
                .unwrap()
                .peers
                .get(config.mac)
                .unwrap()
                .authorized
        {
            return Err("AP host port reset native sequence/WTBL or kept old capture epoch");
        }
    }
    let authority = bound(&fixture)?;
    let before = session.backend.frames.len();
    if run(Box::pin(session.ap_add_station(authority, peer_config(14)))) != Err(Error::Busy)
        || session.backend.frames.len() != before
    {
        return Err("AP overran source-native WCID capacity");
    }
    Ok(())
}
fn mt76_ap_native_peer_records_capacity_and_port_transition() -> TestResult {
    native_peers().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/ap",
    mt76_ap_native_peer_records_capacity_and_port_transition
);

fn secure_config(own: [u8; 6]) -> narf_wireless::ApConfig {
    let mut ap = config(own);
    ap.privacy = true;
    ap.beacon_head[34] |= 16;
    ap.beacon_tail.extend_from_slice(&[
        48, 20, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, 0, 0,
    ]);
    ap
}
fn temporal_key(peer: Option<[u8; 6]>, index: u8, material: u8) -> super::ap_crypto::Install {
    super::ap_crypto::Install::prepare(narf_wireless::KeyParams {
        idx: index,
        pairwise: peer.is_some(),
        peer,
        cipher: 0x000fac04,
        key: vec![material; 16],
        seq: vec![0; 6],
        default_mgmt: false,
    })
    .unwrap()
}
fn secure_peer() -> Result<(NativeSession, Fixture, [u8; 6]), &'static str> {
    let (mut session, fixture, authority) = idle()?;
    let own = fixture.radio.mac();
    run(Box::pin(
        session.start_ap(authority.clone(), secure_config(own)),
    ))
    .map_err(|_| "secure AP native BSS")?;
    session
        .commit_ap_start(&authority)
        .map_err(|_| "secure AP current capture")?;
    drop(authority);
    let authority = bound(&fixture)?;
    let cfg = peer_config(1);
    let mac = cfg.mac;
    run(Box::pin(session.ap_add_station(authority, cfg))).map_err(|_| "secure AP native peer")?;
    Ok((session, fixture, mac))
}
fn native_keys() -> Result<(), &'static str> {
    let (mut session, fixture, mac) = secure_peer()?;
    let authority = bound(&fixture)?;
    if session.ap_authorize_station(&authority, mac, true) != Err(Error::Bounds) {
        return Err("AP authorized a secure peer without current PTK");
    }
    let epoch = session.receive_epoch;
    let frames = session.backend.frames.len();
    run(Box::pin(session.ap_install_key(
        authority.clone(),
        temporal_key(Some(mac), 0, 17),
    )))
    .map_err(|_| "native owner PTK installation")?;
    session
        .ap_authorize_station(&authority, mac, true)
        .map_err(|_| "current PTK host authorization")?;
    if session.backend.frames.len() != frames
        || session.receive_epoch == epoch
        || !session.backend.receive_open
    {
        return Err("software AP PTK installed hardware crypto or kept stale capture");
    }
    let own = fixture.radio.mac();
    let mut header = vec![0; 24];
    header[0] = 8;
    header[1] = 0x42;
    header[4..10].copy_from_slice(&mac);
    header[10..16].copy_from_slice(&own);
    header[16..22].copy_from_slice(&own);
    let first = session
        .ap_keys
        .protect(
            own,
            super::ap_crypto::Target::Pairwise(mac),
            &header,
            b"current AP packet",
        )
        .map_err(|_| "real AP software CCMP")?;
    run(Box::pin(session.ap_install_key(
        authority.clone(),
        temporal_key(Some(mac), 0, 17),
    )))
    .map_err(|_| "identical current PTK retry")?;
    let second = session
        .ap_keys
        .protect(
            own,
            super::ap_crypto::Target::Pairwise(mac),
            &header,
            b"current AP packet",
        )
        .map_err(|_| "retained AP PN")?;
    if first[0] != 1 || second[0] != 2 {
        return Err("native key retry restarted software PN");
    }
    run(Box::pin(session.ap_install_key(
        authority.clone(),
        temporal_key(None, 1, 18),
    )))
    .map_err(|_| "AP GTK1 install")?;
    run(Box::pin(session.ap_install_key(
        authority.clone(),
        temporal_key(None, 2, 19),
    )))
    .map_err(|_| "AP GTK2 install")?;
    if session.ap_owner.as_ref().unwrap().default_group.is_some() {
        return Err("install implicitly selected a transmit GTK");
    }
    run(Box::pin(session.ap_default_key(authority.clone(), 2)))
        .map_err(|_| "explicit AP TX GTK selection")?;
    run(Box::pin(session.ap_delete_key(
        authority.clone(),
        2,
        false,
        None,
    )))
    .map_err(|_| "AP selected GTK retirement")?;
    if session.ap_owner.as_ref().unwrap().default_group.is_some() || !session.ap_keys.has_group(1) {
        return Err("GTK delete silently selected a different transmit key");
    }
    run(Box::pin(session.ap_delete_key(
        authority.clone(),
        0,
        true,
        Some(mac),
    )))
    .map_err(|_| "AP PTK retirement")?;
    if session
        .ap_owner
        .as_ref()
        .unwrap()
        .peers
        .get(mac)
        .unwrap()
        .authorized
        || session.ap_keys.has_pair(mac)
    {
        return Err("PTK deletion retained a peer port");
    }
    let before = session.receive_epoch;
    if run(Box::pin(session.ap_install_key(
        authority.clone(),
        temporal_key(Some(mac), 0, 17),
    ))) != Err(Error::Bounds)
        || !matches!(session.state, State::AccessPoint { .. })
        || session.receive_epoch != before
    {
        return Err("retired material reset its nonce or disturbed the live BSS on refusal");
    }
    run(Box::pin(session.ap_delete_station(authority, Some(mac))))
        .map_err(|_| "native AP peer delete receipt")?;
    let record = session
        .backend
        .frames
        .iter()
        .rev()
        .find_map(|(_, f)| uni(f, 3))
        .ok_or("actual native delete record")?;
    if record.len() != 40
        || record[1] != 1
        || record[2] != 2
        || record[16] != 0
        || record[20..26] != mac
        || record[28..32] != [13, 0, 12, 0]
        || record[32..36] != [1, 1, 0, 0]
        || session.ap_owner.as_ref().unwrap().peers.get(mac).is_some()
    {
        return Err("native peer delete skipped BASIC disconnect/WTBL retirement");
    }
    let authority = bound(&fixture)?;
    run(Box::pin(session.ap_add_station(authority, peer_config(1))))
        .map_err(|_| "native WCID reuse after deletion receipt")?;
    if session
        .ap_owner
        .as_ref()
        .unwrap()
        .peers
        .get(mac)
        .unwrap()
        .wcid
        != 1
        || session.ap_keys.has_pair(mac)
    {
        return Err("WCID reuse restored an old software key");
    }
    Ok(())
}
fn mt76_ap_native_key_port_default_gtk_and_peer_retirement() -> TestResult {
    native_keys().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/ap",
    mt76_ap_native_key_port_default_gtk_and_peer_retirement
);

fn abandoned_peer_delete() -> Result<(), &'static str> {
    let (mut session, fixture, mac) = secure_peer()?;
    let authority = bound(&fixture)?;
    run(Box::pin(session.ap_install_key(
        authority.clone(),
        temporal_key(Some(mac), 0, 23),
    )))
    .map_err(|_| "pending-delete PTK")?;
    let hold = Arc::new(Hold::default());
    session.backend.ap_hold = Some(hold.clone());
    let mut operation = Box::pin(session.ap_delete_station(authority, Some(mac)));
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..8192 {
        if operation.as_mut().poll(&mut cx).is_ready() {
            return Err("AP peer delete completed without native receipt");
        }
        if hold.seen.load(Ordering::Acquire) {
            break;
        }
    }
    if !hold.seen.load(Ordering::Acquire) {
        return Err("AP peer did not reach real delete ACK wait");
    }
    drop(operation);
    if session.state != State::Running(Stage::ApPeer)
        || session.backend.receive_open
        || !session.ap_keys.has_pair(mac)
        || session
            .ap_owner
            .as_ref()
            .unwrap()
            .peers
            .get(mac)
            .is_none_or(|p| p.wcid != 1)
    {
        return Err("dropped AP delete released a still-published peer/key owner");
    }
    if bound(&fixture).is_ok() {
        return Err("dropped AP delete returned its active control reservation");
    }
    hold.release.store(true, Ordering::Release);
    run(Box::pin(session.shutdown())).map_err(|_| "abandoned native peer reset")?;
    if session.ap_owner.is_some() || session.ap_keys.has_pair(mac) || bound(&fixture).is_err() {
        return Err("verified reset retained dead peer/control ownership");
    }
    Ok(())
}
fn mt76_ap_dropped_peer_delete_retains_key_wcid_capture_and_control_until_reset() -> TestResult {
    abandoned_peer_delete().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/ap",
    mt76_ap_dropped_peer_delete_retains_key_wcid_capture_and_control_until_reset
);
