// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual CR4/common rings -> msgbuf IOCTL/SCB/flows -> common Device AP
//! frontend. No native host method is replaced, no host key/port bits set by
//! the fixture, and TX terminal receipts come only from real published IDs.
use super::*;
use crate::brcmfmac::runtime_tests::station_model::ap_model::{CLIENT, RATES};
use narf_capabilities::{Cap, Invoke};
use narf_wireless::{ap_control::ApControlAuthority, WirelessNetIface};

// Native flow retirement and watchdog settling really wait on the clock.
// No IrqSafeSpinLock survives this bridge; all driver waits are bounded and
// IRQ-driven/self-waking. Immediate-poll station helper is intentionally not
// used as invented completion credit for these AP lifetime operations.
fn ready<F: Future>(future: F) -> Result<F::Output, &'static str> {
    Ok(narf_scheduler::block_on(future))
}

struct Callback(
    Arc<dyn Fn() -> bool + Send + Sync>,
    Arc<dyn Fn() + Send + Sync>,
);
impl core::fmt::Debug for Callback {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Callback")
    }
}
#[derive(Debug)]
pub(super) struct Source {
    life: narf_net::native_emission::ProviderLifetime,
    messages: IrqSafeSpinLock<Vec<Vec<u8>>>,
    callback: IrqSafeSpinLock<Option<Callback>>,
}
impl Source {
    pub(super) fn new() -> Self {
        Self {
            life: narf_net::native_emission::ProviderLifetime::new(),
            messages: IrqSafeSpinLock::new(Vec::new()),
            callback: IrqSafeSpinLock::new(None),
        }
    }
    pub(super) fn count(&self, command: u8) -> usize {
        self.messages
            .lock()
            .iter()
            .filter(|bytes| bytes.get(16) == Some(&command))
            .count()
    }
}
impl narf_net::netlink_generic::DeferredReplySink for Source {
    fn current(&self) -> bool {
        let callback = self.callback.lock().take();
        if let Some(callback) = callback {
            if (callback.0)() {
                (callback.1)();
            } else {
                *self.callback.lock() = Some(callback);
            }
        }
        self.life.observe().current()
    }
    fn native_source(&self) -> Option<narf_net::native_emission::Lifetime> {
        Some(self.life.observe())
    }
    fn deliver(&self, bytes: Vec<u8>) -> Result<(), i32> {
        if !self.life.observe().current() {
            return Err(125);
        }
        self.messages.lock().push(bytes);
        Ok(())
    }
}
pub(super) fn config(secure: bool) -> (narf_wireless::ApConfig, narf_wireless::ApStartSettings) {
    let mut head = vec![0; 36];
    head[0] = 0x80;
    head[4..10].fill(255);
    head[10..16].copy_from_slice(&OWN);
    head[16..22].copy_from_slice(&OWN);
    head[32..34].copy_from_slice(&100u16.to_le_bytes());
    head[34..36].copy_from_slice(&(if secure { 17u16 } else { 1u16 }).to_le_bytes());
    head.extend_from_slice(&[0, 4, b't', b'e', b's', b't', 1, 4]);
    head.extend_from_slice(&RATES);
    let tail = if secure {
        vec![
            48, 20, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, 0, 0,
        ]
    } else {
        Vec::new()
    };
    (
        narf_wireless::ApConfig {
            ssid: b"test".to_vec(),
            beacon_head: head,
            beacon_tail: tail,
            probe_resp: None,
            beacon_interval: 100,
            dtim_period: 2,
            frequency_mhz: 2437,
            channel_width: 0,
            center_freq1_mhz: None,
            center_freq2_mhz: None,
            hidden_ssid: 0,
            privacy: secure,
            mbssid: None,
            mbssid_elems: Vec::new(),
            ema_rnr_elems: Vec::new(),
            fils_discovery: None,
            unsol_bcast_probe_resp: None,
            ftm_responder: None,
            twt_responder: false,
            he_obss_pd: None,
            he_bss_color: None,
        },
        narf_wireless::ApStartSettings {
            control_port: if secure {
                narf_wireless::ControlPort {
                    enabled: true,
                    over_nl80211: true,
                    ..Default::default()
                }
            } else {
                Default::default()
            },
            ..Default::default()
        },
    )
}
pub(super) fn association(secure: bool) -> Vec<u8> {
    let (config, _) = config(secure);
    let mut ies = config.beacon_head[36..].to_vec();
    ies.extend(config.beacon_tail);
    ies
}
fn key(index: u8, peer: Option<[u8; 6]>, material: u8) -> narf_wireless::OwnedKey {
    narf_wireless::OwnedKey::new(narf_wireless::KeyParams {
        idx: index,
        pairwise: peer.is_some(),
        peer,
        cipher: narf_wireless::CIPHER_SUITE_CCMP,
        key: vec![material; 16],
        seq: Vec::new(),
        default_mgmt: false,
    })
}
fn station(authorized: bool) -> narf_wireless::StationConfig {
    narf_wireless::StationConfig {
        mac: CLIENT,
        aid: 0,
        listen_interval: 0,
        supported_rates: Vec::new(),
        wme: None,
        uapsd_queues: None,
        uapsd_max_sp: None,
        mfp: None,
        capability: None,
        ext_capability: None,
        ht_capability: None,
        vht_capability: None,
        he_capability: None,
        he_6ghz_capability: None,
        authorized: Some(authorized),
        station_tx_power: None,
    }
}
fn ethernet() -> Vec<u8> {
    let mut out = vec![0; 60];
    out[..6].copy_from_slice(&CLIENT);
    out[6..12].copy_from_slice(&OWN);
    out[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    out
}
struct Bound {
    device: Arc<ModelDevice>,
    iface: Arc<dyn WirelessNetIface>,
    bus: Handle,
    admin: narf_net::AdminHandle,
    source: Arc<Source>,
    database: Arc<narf_wireless::reg::db::Database>,
    name: String,
}
impl Bound {
    fn new() -> Result<Self, &'static str> {
        let (adapter, bus) = firmware::create(7, false).map_err(|_| "AP native CR4 attach")?;
        bus.enable_ap();
        let database = Arc::new(narf_wireless::reg::db::Database::new());
        database.install(firmware::domain());
        let station = ready(Station::initialize_live(adapter, &[], database.clone()))?
            .map_err(|_| "AP native initial firmware queries")?;
        let name = narf_net::iface::register("wlan%d", OWN, send);
        let device = shell(name.clone(), station);
        device.ap_fixture_setup(database.clone());
        narf_net::iface::set_link_state(&name, false);
        device
            .set_iftype(3)
            .map_err(|_| "AP mode while native station down")?;
        let cap = narf_net::registry()
            .register(&narf_net::bootstrap_authority(), Registered(device.clone()))
            .map_err(|_| "AP registered netdev")?;
        let daemon = Cap::<narf_net::stack::StackDaemon, Invoke>::bootstrap();
        let admin = narf_net::stack::control_registered(&narf_net::stack::StackAttach {
            iface: cap,
            daemon,
        })
        .map_err(|_| "AP original admin authority")?
        .admin;
        let iface: Arc<dyn WirelessNetIface> = device.clone();
        narf_wireless::registry::register(iface.clone());
        narf_net::iface::set_link_state(&name, true);
        Ok(Self {
            device,
            iface,
            bus,
            admin,
            source: Arc::new(Source::new()),
            database,
            name,
        })
    }
    fn authority_for(&self, source: Arc<Source>) -> ApControlAuthority {
        ApControlAuthority::bind(
            self.admin.clone(),
            &self.iface,
            0,
            narf_net::iface::lookup(&self.name).unwrap().ifindex,
            source,
        )
        .unwrap()
        .reserve()
        .unwrap()
    }
    fn authority(&self) -> ApControlAuthority {
        self.authority_for(self.source.clone())
    }
    fn start(&self, secure: bool) -> Result<(), &'static str> {
        let (config, settings) = config(secure);
        let a = self.authority();
        ready(
            self.device
                .start_ap_with_settings_async(&a, config, settings),
        )?
        .map_err(|_| "AP native START/beacon/rate/DTIM receipt")
    }
    fn peer(&self, secure: bool) -> Result<(), &'static str> {
        let before = self.source.count(19);
        self.bus
            .ap_change(|p| p.associate(CLIENT, association(secure)));
        ready(self.device.ap_worker())?;
        self.device.ap_drain();
        if self.source.count(19) != before + 1 {
            return Err("AP native SCB/NEW_STATION observation");
        }
        Ok(())
    }
    fn install(&self, index: u8, peer: Option<[u8; 6]>, material: u8) -> Result<(), &'static str> {
        let a = self.authority();
        ready(self.device.add_key_ap_async(&a, key(index, peer, material)))?
            .map_err(|_| "AP actual wsec_key terminal")
    }
    fn authorize(&self, value: bool) -> Result<(), &'static str> {
        let a = self.authority();
        ready(self.device.set_station_async(&a, station(value)))?
            .map_err(|_| "AP actual SCB authorization")
    }
    fn enqueue(&self) -> Result<(), &'static str> {
        self.device
            .enqueue(&ethernet())
            .map_err(|_| "AP Ethernet enqueue")?;
        for _ in 0..8 {
            self.device.ap_drain();
        }
        Ok(())
    }
}
impl Drop for Bound {
    fn drop(&mut self) {
        self.bus.d3_ack(true);
        let _ = ready(self.device.teardown());
        *ACTIVE_TEST.lock() = None;
        narf_wireless::registry::unregister(&self.name);
        narf_net::registry().unregister(&self.name);
        narf_net::iface::unregister(&self.name);
    }
}

fn open() -> Result<(), &'static str> {
    let b = Bound::new()?;
    b.start(false)?;
    b.peer(false)?;
    b.enqueue()?;
    if !b.device.link_up()
        || b.device.connected_bssid().is_some()
        || !b
            .bus
            .ap_change(|p| p.packets.iter().any(|bytes| bytes == &ethernet()))
        || b.device.ap_sme_capabilities() != Some(0)
        || b.device.supports_ap_userspace_mlme()
        || b.device.supports_control_port_tx_status()
        || b.device.supports_ap_key_sequence()
    {
        return Err("AP native packet/firmware SME ownership and conservative status");
    }
    let a = b.authority();
    ready(b.device.stop_ap_async(&a))?.map_err(|_| "AP actual STOP/native flow deletion")?;
    if b.device.link_up() || b.bus.ap_change(|p| p.active || !p.peers.is_empty()) {
        return Err("AP native stop/SCB absence");
    }
    drop(a);
    b.start(false)?;
    b.peer(false)?;
    Ok(())
}
fn smoke_brcmf_ap_native_primary_sme_beacon_peer_data_stop_and_successor() -> TestResult {
    match open() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/ap",
    smoke_brcmf_ap_native_primary_sme_beacon_peer_data_stop_and_successor
);

fn secure() -> Result<(), &'static str> {
    let b = Bound::new()?;
    b.install(1, None, 0x42)?;
    if !b.bus.ap_change(|p| p.keys.is_empty()) || b.device.link_up() {
        return Err("AP staged key invented native install");
    }
    {
        let a = b.authority();
        ready(
            b.device
                .default_key_ap_async(&a, 1, false, true, false, false),
        )?
        .map_err(|_| "AP staged default metadata")?;
    }
    b.start(true)?;
    b.peer(true)?;
    if b.bus.ap_change(|p| p.keys.len()) != 1 {
        return Err("AP staged key lacks native promotion");
    }
    if b.authorize(true).is_ok() {
        return Err("AP port opened without native PTK");
    }
    b.install(0, Some(CLIENT), 0x43)?;
    b.authorize(true)?;
    b.enqueue()?;
    let writes = b.bus.ap_change(|p| p.keys.len());
    b.install(0, Some(CLIENT), 0x43)?;
    if b.bus.ap_change(|p| p.keys.len()) != writes {
        return Err("AP identical retry rewrote native PN/RSC");
    }
    let a = b.authority();
    ready(b.device.del_key_ap_async(&a, 0, true, Some(CLIENT)))?
        .map_err(|_| "AP PTK deletion requires native SCB/flow absence")?;
    b.device.ap_drain();
    if b.source.count(20) != 1 || b.bus.ap_change(|p| p.peers.contains_key(&CLIENT)) {
        return Err("AP PTK removal synthesized loss or retained native SCB");
    }
    drop(a);
    b.peer(true)?;
    if b.install(0, Some(CLIENT), 0x43).is_ok() {
        return Err("AP retired key material reinstalled after SCB replacement");
    }
    Ok(())
}
fn smoke_brcmf_ap_native_staged_keys_current_ports_and_scb_delete_never_reinstall() -> TestResult {
    match secure() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/ap",
    smoke_brcmf_ap_native_staged_keys_current_ports_and_scb_delete_never_reinstall
);

fn signed(mut frame: narf_wireless::eapol::KeyFrame, kck: &[u8]) -> Vec<u8> {
    frame.key_mic.fill(0);
    let mut pdu = frame.into_eapol();
    let mic = narf_wireless::eapol::eapol_key_mic(2, kck, &pdu, 16).unwrap();
    pdu[81..97].copy_from_slice(&mic);
    pdu
}
fn control_pdu(source: &Source) -> Option<Vec<u8>> {
    let messages = source.messages.lock();
    let message = messages
        .iter()
        .rev()
        .find(|message| message.get(16) == Some(&129))?;
    let mut rest = message.get(20..)?;
    while rest.len() >= 4 {
        let length = usize::from(u16::from_ne_bytes(rest[..2].try_into().ok()?));
        if length < 4 || length > rest.len() {
            return None;
        }
        if u16::from_ne_bytes(rest[2..4].try_into().ok()?) == 51 {
            return Some(rest[4..length].to_vec());
        }
        rest = rest.get((length + 3) & !3..)?;
    }
    None
}
fn control_frame(pdu: &[u8]) -> Vec<u8> {
    let mut bytes = OWN.to_vec();
    bytes.extend_from_slice(&CLIENT);
    bytes.extend_from_slice(&0x888eu16.to_be_bytes());
    bytes.extend_from_slice(pdu);
    bytes
}
fn rx_control(b: &Bound, pdu: &[u8]) {
    let bytes = control_frame(pdu);
    b.bus.ap_change(|profile| profile.downlink.push_back(bytes));
    b.device.ap_drain();
}
fn tx_control(b: &Bound, pdu: Vec<u8>) -> Result<(), &'static str> {
    let a = b.authority();
    let expected = pdu.clone();
    if ready(b.device.tx_control_port_ap_async(
        &a,
        narf_wireless::ControlPortTxRequest::new(CLIENT, 0x888e, pdu, true, false),
    ))? != Ok(false)
        || !b
            .bus
            .ap_change(|p| p.packets.last().is_some_and(|p| p[14..] == expected))
    {
        return Err("AP EAPOL actual native TX terminal/body; no invented ACK");
    }
    Ok(())
}
fn rsn_exchange() -> Result<(), &'static str> {
    use narf_wireless::eapol::*;
    let b = Bound::new()?;
    b.start(true)?;
    b.bus.ap_change(|profile| {
        profile.associate(CLIENT, association(true));
        profile.downlink.push_back(control_frame(&[2, 1, 0, 0]));
    });
    ready(b.device.ap_worker())?;
    b.device.ap_drain();
    if b.source.count(19) != 1 || control_pdu(&b.source) != Some(vec![2, 1, 0, 0]) {
        return Err(
            "AP same-drain native association/EAPOL did not retain original verification hold",
        );
    }
    let pmk = [0x55; 32];
    let anonce = [0xaa; 32];
    let snonce = [0x77; 32];
    let ptk = wpa_pmk_to_ptk(KeyMgmt::Psk, &pmk, &OWN, &CLIENT, &anonce, &snonce, 16);
    let mut m1 = KeyFrame::empty(16);
    m1.key_information = KI_VERSION_HMAC_SHA1_AES | KI_KEY_TYPE_PAIRWISE | KI_KEY_ACK;
    m1.key_length = 16;
    m1.replay_counter = 1;
    m1.key_nonce = anonce;
    let ie = config(true).0.beacon_tail;
    let mut m2 = KeyFrame::empty(16);
    m2.key_information = KI_VERSION_HMAC_SHA1_AES | KI_KEY_TYPE_PAIRWISE | KI_KEY_MIC;
    m2.replay_counter = 1;
    m2.key_nonce = snonce;
    m2.key_data = ie.clone();
    let m2 = signed(m2, &ptk.kck);
    b.bus
        .ap_change(|profile| profile.response_on_control = Some(control_frame(&m2)));
    tx_control(&b, m1.into_eapol())?;
    b.device.ap_drain();
    let actual = control_pdu(&b.source).ok_or("AP real native M2 delivery")?;
    let mut unsigned = actual.clone();
    unsigned[81..97].fill(0);
    if actual != m2 || eapol_key_mic(2, &ptk.kck, &unsigned, 16).unwrap() != actual[81..97] {
        return Err("AP userspace authenticator rejected M2 MIC/body");
    }
    let mut clear = ie;
    clear.extend_from_slice(&[221, 22, 0, 15, 172, 1, 1, 0]);
    clear.extend_from_slice(&[0x42; 16]);
    if clear.len() % 8 != 0 {
        clear.push(221);
    }
    while clear.len() % 8 != 0 {
        clear.push(0);
    }
    let mut m3 = KeyFrame::empty(16);
    m3.key_information = KI_VERSION_HMAC_SHA1_AES
        | KI_KEY_TYPE_PAIRWISE
        | KI_KEY_ACK
        | KI_KEY_MIC
        | KI_INSTALL
        | KI_SECURE
        | KI_ENCRYPTED_KEY_DATA;
    m3.key_length = 16;
    m3.replay_counter = 2;
    m3.key_nonce = anonce;
    m3.key_data =
        narf_crypto::aes_kw::aes_wrap(ptk.kek.as_slice().try_into().unwrap(), &clear).unwrap();
    let m3 = signed(m3, &ptk.kck);
    let mut m4 = KeyFrame::empty(16);
    m4.key_information = KI_VERSION_HMAC_SHA1_AES | KI_KEY_TYPE_PAIRWISE | KI_KEY_MIC | KI_SECURE;
    m4.replay_counter = 2;
    let m4 = signed(m4, &ptk.kck);
    b.bus
        .ap_change(|profile| profile.response_on_control = Some(control_frame(&m4)));
    tx_control(&b, m3.clone())?;
    let on_wire = b
        .bus
        .ap_change(|p| p.packets.last().unwrap()[14..].to_vec());
    let frame = KeyFrame::decode(&on_wire[4..], 16).ok_or("AP M3 wire key grammar")?;
    if on_wire != m3
        || narf_crypto::aes_kw::aes_unwrap(ptk.kek.as_slice().try_into().unwrap(), &frame.key_data)
            != Some(clear)
    {
        return Err("AP actual native M3 AES-wrapped GTK");
    }
    b.device.ap_drain();
    if control_pdu(&b.source) != Some(m4) {
        return Err("AP actual native M4 before key/port");
    }
    let mut pairwise = key(0, Some(CLIENT), 0).params().clone();
    pairwise.key = ptk.tk;
    {
        let a = b.authority();
        ready(
            b.device
                .add_key_ap_async(&a, narf_wireless::OwnedKey::new(pairwise)),
        )?
        .map_err(|_| "AP actual derived PTK install")?;
    }
    b.install(1, None, 0x42)?;
    b.authorize(true)?;
    b.enqueue()?;
    if b.bus
        .ap_change(|p| p.keys.iter().filter(|k| k[4] == 16).count())
        != 2
    {
        return Err("AP RSN keys not supplied through actual native transactions");
    }
    Ok(())
}
fn smoke_brcmf_ap_native_userspace_rsn_mic_wrapped_gtk_and_real_eapol_terminals() -> TestResult {
    match rsn_exchange() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/ap",
    smoke_brcmf_ap_native_userspace_rsn_mic_wrapped_gtk_and_real_eapol_terminals
);

fn atomic_and_offloads() -> Result<(), &'static str> {
    let b = Bound::new()?;
    let before = b.bus.commands().len();
    for fault in 0..4 {
        let (mut config, mut settings) = config(false);
        match fault {
            0 => config.beacon_tail = vec![221, 30, 1],
            1 => settings.control_port.no_preauth = true,
            2 => settings.p2p_go = Some(Default::default()),
            _ => config.channel_width = 2,
        };
        let a = b.authority();
        if ready(b.device.start_ap_with_settings_async(&a, config, settings))?.is_ok()
            || b.bus.commands().len() != before
            || b.device.link_up()
        {
            return Err("AP malformed/unsupported later field published native prefix");
        }
    }
    drop(b);
    for mode in [1, 2] {
        let b = Bound::new()?;
        b.bus.ap_change(|profile| profile.offload = mode);
        b.start(false)?;
        let a = b.authority();
        ready(b.device.stop_ap_async(&a))?
            .map_err(|_| "AP actual absent/write-only offload restoration")?;
        if b.device.link_up() {
            return Err("AP offload profile stop retained carrier");
        }
    }
    let b = Bound::new()?;
    b.bus.ap_change(|profile| profile.offload = 3);
    if b.start(false).is_ok() || b.device.link_up() {
        return Err("AP ignored actual enabled undisablable offload");
    }
    Ok(())
}
fn smoke_brcmf_ap_native_atomic_admission_and_optional_offload_profiles() -> TestResult {
    match atomic_and_offloads() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/ap",
    smoke_brcmf_ap_native_atomic_admission_and_optional_offload_profiles
);

fn prefix_loss() -> Result<(), &'static str> {
    let b = Bound::new()?;
    b.start(false)?;
    b.peer(false)?;
    b.device
        .enqueue(&ethernet())
        .map_err(|_| "AP enqueue original before native prefix")?;
    let before = b.bus.mappings().0;
    b.bus.ap_change(|p| {
        for _ in 0..200 {
            p.event(23, CLIENT, &[]);
        }
        p.remove(CLIENT);
    });
    for _ in 0..16 {
        b.device.ap_drain();
    }
    if b.bus.ap_change(|p| !p.packets.is_empty())
        || b.bus.mappings().0 != before
        || b.source.count(20) != 1
    {
        return Err("AP >64 actual native events/loss published old DATA or native ID");
    }
    ready(b.device.ap_worker())?;
    b.peer(false)?;
    b.enqueue()?;
    if b.bus.ap_change(|p| p.packets.len()) != 1 {
        return Err("AP fresh successor did not use actual native flow");
    }
    Ok(())
}
fn smoke_brcmf_ap_native_long_completed_prefix_loss_cannot_retarget_queued_data() -> TestResult {
    match prefix_loss() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/ap",
    smoke_brcmf_ap_native_long_completed_prefix_loss_cannot_retarget_queued_data
);

fn copied_peer() -> Result<(), &'static str> {
    let b = Bound::new()?;
    b.start(false)?;
    b.bus.ap_change(|p| p.associate(CLIENT, association(false)));
    ready(b.device.ap_worker())?;
    let bus = b.bus.clone();
    let device = b.device.clone();
    *b.source.callback.lock() = Some(Callback(
        Arc::new(|| true),
        Arc::new(move || {
            bus.ap_change(|p| p.remove(CLIENT));
            let _ = ready(device.ap_worker());
            device.ap_drain();
        }),
    ));
    b.device.ap_drain();
    if b.source.count(19) != 0 || b.source.count(20) != 1 {
        return Err("AP copied NEW survived real native peer loss or genuine DEL suppressed");
    }
    b.peer(false)?;
    if b.source.count(19) != 1 {
        return Err("AP fresh same-MAC successor lost legitimate NEW");
    }
    Ok(())
}
fn smoke_brcmf_ap_native_prepared_sme_copy_keeps_exact_peer_generation() -> TestResult {
    match copied_peer() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/ap",
    smoke_brcmf_ap_native_prepared_sme_copy_keeps_exact_peer_generation
);

fn preauth_actors() -> Result<(), &'static str> {
    for key_actor in [false, true] {
        let b = Bound::new()?;
        b.start(true)?;
        b.peer(true)?;
        let key_source = Arc::new(Source::new());
        let port_source = Arc::new(Source::new());
        {
            let a = b.authority_for(key_source.clone());
            ready(b.device.add_key_ap_async(&a, key(0, Some(CLIENT), 0x65)))?
                .map_err(|_| "AP independent original key actor")?;
        }
        {
            let a = b.authority_for(port_source.clone());
            ready(b.device.set_station_async(&a, station(true)))?
                .map_err(|_| "AP independent original authorization actor")?;
        }
        let actor = if key_actor { key_source } else { port_source };
        *b.source.callback.lock() = Some(Callback(
            Arc::new(|| true),
            Arc::new(move || actor.life.retire().notify()),
        ));
        let mut bytes = OWN.to_vec();
        bytes.extend_from_slice(&CLIENT);
        bytes.extend_from_slice(&0x88c7u16.to_be_bytes());
        bytes.extend_from_slice(&[2, 0, 0, 0]);
        b.bus.ap_change(|p| p.downlink.push_back(bytes));
        b.device.ap_drain();
        if b.source.count(129) != 0 {
            return Err(
                "AP ordinary preauth lost original independent port/key fence after callback",
            );
        }
        rx_control(&b, &[2, 0, 0, 0]);
        if b.source.count(129) != 1 {
            return Err("AP EAPOL bypass incorrectly inherited ordinary preauth DATA requirement");
        }
    }
    Ok(())
}
fn smoke_brcmf_ap_native_preauth_copies_require_original_key_and_port_actors() -> TestResult {
    match preauth_actors() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/ap",
    smoke_brcmf_ap_native_preauth_copies_require_original_key_and_port_actors
);

fn cancel_key() -> Result<(), &'static str> {
    let b = Bound::new()?;
    b.start(true)?;
    b.peer(true)?;
    b.bus.ap_change(|p| p.hold_key = true);
    let a = b.authority();
    let before = b.bus.mappings().1;
    {
        let mut future = pin!(b.device.add_key_ap_async(&a, key(0, Some(CLIENT), 0x66)));
        if !matches!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ) || b.bus.ap_change(|p| p.keys.len()) != 1
        {
            return Err("AP held actual native key transaction not owned before cancellation");
        }
    }
    drop(a);
    ready(b.device.ap_worker())?;
    if b.device.link_up()
        || b.bus.dma_enabled()
        || b.bus.mappings().1 != before
        || b.device.ap_generation().is_some()
    {
        return Err("AP dropped native key waiter released uncertain DMA or left live role");
    }
    Ok(())
}
fn smoke_brcmf_ap_native_cancelled_key_keeps_dma_until_actual_device_stop() -> TestResult {
    match cancel_key() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/ap",
    smoke_brcmf_ap_native_cancelled_key_keeps_dma_until_actual_device_stop
);

fn policy_and_pm() -> Result<(), &'static str> {
    {
        let b = Bound::new()?;
        b.start(false)?;
        b.peer(false)?;
        b.device
            .enqueue(&ethernet())
            .map_err(|_| "AP queued policy original")?;
        // Equal bytes are a replacement authority, not revival of the
        // original Arc captured by the actual native BSS.
        b.database.install(firmware::domain());
        b.device.ap_drain();
        if b.device.link_up() || b.bus.ap_change(|p| !p.packets.is_empty()) {
            return Err("AP equal-byte signed policy replacement revived old queued owner");
        }
        ready(b.device.ap_worker())?;
        if b.bus.ap_change(|p| p.active) {
            return Err("AP revoked-policy cleanup did not use original native stop");
        }
    }
    let b = Bound::new()?;
    b.start(false)?;
    b.peer(false)?;
    let original = {
        let state = b.device.state.try_lock().unwrap();
        state
            .ap
            .as_ref()
            .unwrap()
            .data_capture(&ethernet())
            .map_err(|_| "AP original pre-PM capture")?
    };
    b.bus.d3_ack(true);
    ready(Endpoint::suspend(&*b.device))?
        .map_err(|_| "AP system suspend actual BSS/flow/D3 stop")?;
    // D3 suspend retires the RF link and the AP data/copy owner, but
    // retains DMA by design: Linux `brcmf_pcie_pm_enter_D3` touches
    // neither BME nor the rings (the bus only goes DOWN), and NARF
    // `brcmfmac.md` "System suspend" keeps the rings retained for the
    // hot `leave_d3` resume; BME is cleared only by the confirmed stop
    // (`Runtime::quiesce`, removal/reset). The station D3/D0 smoke
    // asserts the same retention (`dma.len()` unchanged, `dropped == 0`).
    if b.device.link_up() {
        return Err("AP system suspend left RF/link up");
    }
    if original.current().is_ok() {
        return Err("AP system suspend retained data/copy owner");
    }
    if !b.bus.dma_enabled() {
        return Err("AP system suspend freed DMA rings (D3 retains rings/BME)");
    }
    b.bus.d0_alive();
    ready(Endpoint::resume(&*b.device))?.map_err(|_| "AP actual hot D0 receipt")?;
    if b.device.link_up() {
        return Err("AP hot resume re-raised RF/link");
    }
    if original.current().is_ok() {
        return Err("AP hot resume replayed data/copy authority");
    }
    if !b.bus.dma_enabled() {
        return Err("AP hot resume lost DMA rings");
    }
    b.start(false)?;
    b.peer(false)?;
    b.enqueue()?;
    if !b
        .bus
        .ap_change(|p| p.packets.iter().any(|p| p == &ethernet()))
    {
        return Err("AP fresh post-PM owner lacked actual native data");
    }
    Ok(())
}
fn smoke_brcmf_ap_native_policy_replacement_and_system_pm_retire_original_bss() -> TestResult {
    match policy_and_pm() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/ap",
    smoke_brcmf_ap_native_policy_replacement_and_system_pm_retire_original_bss
);

fn program_publication() -> Result<(), &'static str> {
    use crate::cyw43439::{fullmac::Fullmac, ioctl::Direction};
    {
        let b = Bound::new()?;
        b.start(false)?;
        let original = {
            let state = b.device.state.try_lock().ok_or("AP Program capture lock")?;
            state
                .ap
                .as_ref()
                .ok_or("AP Program owner")?
                .publication()
                .map_err(|_| "AP Program original proof")?
        };
        let before = b.bus.commands().len();
        b.bus.ap_program_down_after_setup(b.admin.clone());
        let result = ready(async {
            let mut state = b.device.state.lock().await;
            state
                .station
                .runtime
                .command_ap(&original, Direction::Get, 117, &[], 4)
                .await
        })?;
        if result.is_ok()
            || b.bus.commands().len() != before
            || b.device.transport_failed()
            || b.device.link_up()
        {
            return Err(
                "AP Program retired after setup published IOCTL or poisoned unissued owner",
            );
        }
    }
    {
        let b = Bound::new()?;
        b.start(false)?;
        b.peer(false)?;
        let original = {
            let state = b.device.state.try_lock().ok_or("AP prefix capture lock")?;
            state
                .ap
                .as_ref()
                .ok_or("AP prefix owner")?
                .publication()
                .map_err(|_| "AP prefix original proof")?
        };
        let commands = b.bus.commands().len();
        let lost = b.source.count(20);
        b.bus.ap_program_loss_after_setup(CLIENT);
        let result = ready(async {
            let mut state = b.device.state.lock().await;
            state
                .station
                .runtime
                .command_ap(&original, Direction::Set, 121, &CLIENT, 0)
                .await
        })?;
        if result != Err(crate::cyw43439::runtime::Error::Busy)
            || b.bus.commands().len() != commands
            || b.device.transport_failed()
            || original.current().is_err()
        {
            return Err(
                "AP completed native loss before Program SET published stale authorization",
            );
        }
        // An actual GET can complete while this same native event remains
        // retained, without granting a key/port or discarding its later DEL.
        let query = ready(async {
            let mut state = b.device.state.lock().await;
            state
                .station
                .runtime
                .command_ap(&original, Direction::Get, 117, &[], 4)
                .await
        })?;
        if query != Ok(1u32.to_le_bytes().to_vec()) {
            return Err("AP queued native loss prevented read-only Program query");
        }
        b.device.ap_drain();
        ready(b.device.ap_worker())?;
        b.device.ap_drain();
        if b.source.count(20) != lost + 1
            || b.bus
                .ap_change(|profile| profile.peers.contains_key(&CLIENT))
        {
            return Err("AP Program barrier discarded genuine native loss or its station event");
        }
    }
    {
        let b = Bound::new()?;
        b.start(false)?;
        let original = {
            let state = b.device.state.try_lock().ok_or("AP Program issue lock")?;
            state
                .ap
                .as_ref()
                .ok_or("AP Program issue owner")?
                .publication()
                .map_err(|_| "AP Program issue original proof")?
        };
        let before = b.bus.mappings();
        b.bus.ap_program_fail_index();
        let (result, failed) = ready(async {
            let mut state = b.device.state.lock().await;
            let result = state
                .station
                .runtime
                .command_ap(&original, Direction::Get, 117, &[], 4)
                .await;
            (result, state.station.runtime.transport_failed())
        })?;
        if result.is_ok()
            || !failed
            || b.bus.dma_enabled()
            || b.bus.mappings().1 != before.1
            || original.current().is_ok()
        {
            return Err("AP Program uncertain native index granted credit or released DMA");
        }
    }
    Ok(())
}
fn smoke_brcmf_ap_program_publication_rechecks_original_after_setup_and_pins_uncertain_index(
) -> TestResult {
    match program_publication() {
        Ok(()) => TestResult::Pass,
        Err(error) => TestResult::Fail(error),
    }
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/ap",
    smoke_brcmf_ap_program_publication_rechecks_original_after_setup_and_pins_uncertain_index
);

#[path = "ap_native_sdio_tests.rs"]
mod sdio;
