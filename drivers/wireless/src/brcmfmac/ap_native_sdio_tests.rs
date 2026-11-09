// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual SDHCI Card -> signed AI/CM3 loader -> F1/F2 -> SDPCM/BCDC ->
//! public common Device AP controls. Only inert device bytes are modeled.
use super::*;
use crate::cyw43439::{
    firmware::FirmwareLoader, runtime::Runtime, sdio_ap_model, sdio_bridge::SdioTransport,
};
use alloc::boxed::Box;
use narf_drivers_sdio::{
    card::tests::Model,
    card::{Card, Config},
};
type SdioRuntime = Runtime<SdioTransport<Card<Model>>>;
type SdioDevice = Device<SdioRuntime>;
static ACTIVE_SDIO: IrqSafeSpinLock<Option<Arc<SdioDevice>>> = IrqSafeSpinLock::new(None);
fn sdio_send(bytes: &[u8], _: narf_net::TxMeta) -> Result<(), ()> {
    let device = ACTIVE_SDIO.lock().clone().ok_or(())?;
    device.enqueue(bytes)
}
fn sdio_shell(name: String, station: Station<SdioRuntime>) -> Arc<SdioDevice> {
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
    let device = Arc::new(Device {
        state: Mutex::new(State {
            station,
            rx,
            tx,
            pending: None,
            telemetry: telemetry.clone(),
            ap: None,
            ap_data_generation: 0,
            ap_epoch_changed: false,
            monitor: None,
            vif: None,
            secondaries: Vec::new(),
            p2p: None,
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
        wowl: None,
        wowlan: narf_lib::sync::IrqSafeSpinLock::new(None),
        wakeup: narf_lib::sync::IrqSafeSpinLock::new(None),
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
    *ACTIVE_SDIO.lock() = Some(device.clone());
    device
}
struct SdioBound {
    device: Arc<SdioDevice>,
    iface: Arc<dyn WirelessNetIface>,
    bus: sdio_ap_model::Handle,
    host: Option<Model>,
    proof: Arc<crate::brcmfmac::provision::Proof>,
    admin: narf_net::AdminHandle,
    source: Arc<Source>,
    database: Arc<narf_wireless::reg::db::Database>,
    name: String,
}
/// Surface the inner `Station::initialize_live` failure instead of
/// collapsing every step into the one shared reason string: all 16 SDIO
/// tests build through `SdioBound::build`, so a single string hides which
/// step actually failed in the guest (#1812). One distinct string per
/// `crate::cyw43439::runtime::Error` variant (and per transport cause
/// under `Transport`); the fixture error type stays `&'static str`, so a
/// firmware code is never embedded in the string.
fn station_init_error(error: crate::cyw43439::runtime::Error) -> &'static str {
    use crate::cyw43439::runtime::Error;
    use crate::cyw43439::transport::TransportError;
    match error {
        // `initialize_inner` returns `Transport` from every firmware
        // command (version, CLM chunk load, country, bus configuration,
        // PHY probe, iovar sets/gets, channel list) and from the
        // event/write paths; the transport cause is what the code can
        // distinguish here.
        Error::Transport(TransportError::BadFraming) => {
            "SDIO AP actual BCDC/Station initialization: transport bad framing"
        }
        Error::Transport(TransportError::Busy) => {
            "SDIO AP actual BCDC/Station initialization: transport busy"
        }
        Error::Transport(TransportError::Denied) => {
            "SDIO AP actual BCDC/Station initialization: transport denied"
        }
        Error::Transport(TransportError::ChipFlowError) => {
            "SDIO AP actual BCDC/Station initialization: transport chip flow error"
        }
        Error::Transport(TransportError::LengthOverflow) => {
            "SDIO AP actual BCDC/Station initialization: transport length overflow"
        }
        Error::Transport(TransportError::AddressOverflow) => {
            "SDIO AP actual BCDC/Station initialization: transport address overflow"
        }
        Error::Transport(TransportError::Timeout) => {
            "SDIO AP actual BCDC/Station initialization: transport timeout"
        }
        Error::Transport(TransportError::NotReady) => {
            "SDIO AP actual BCDC/Station initialization: transport not ready"
        }
        Error::Transport(TransportError::Other(_)) => {
            "SDIO AP actual BCDC/Station initialization: transport other"
        }
        // CLM/country validation, the MAC check, the `mfp` reply shape,
        // and the channel-list parse all return `Malformed`; the variant
        // cannot name which of those steps failed.
        Error::Malformed => "SDIO AP actual BCDC/Station initialization: malformed",
        // Firmware version reply other than 2, or no usable channel.
        Error::Unsupported => "SDIO AP actual BCDC/Station initialization: unsupported",
        // Policy authority: snapshot absent at `initialize_live` entry,
        // snapshot gone or country changed across `refresh_policy` /
        // `check_initial` / `enable`, or the channel list emptied by the
        // post-init retain. All three collapse to this one variant, so
        // the string names the class, not the sub-cause.
        Error::Authority => "SDIO AP actual BCDC/Station initialization: authority",
        Error::Busy => "SDIO AP actual BCDC/Station initialization: busy",
        Error::Timeout => "SDIO AP actual BCDC/Station initialization: timeout",
        Error::Failed => "SDIO AP actual BCDC/Station initialization: failed",
        Error::EventOverflow => "SDIO AP actual BCDC/Station initialization: event overflow",
        // Firmware refusals (`clmload_status` nonzero, a refused iovar,
        // a firmware event status/reason). The numeric code cannot be
        // embedded in a `&'static str`.
        Error::Firmware(_) => "SDIO AP actual BCDC/Station initialization: firmware",
    }
}
impl SdioBound {
    fn new() -> Result<Self, &'static str> {
        Self::new_capability(b"ap sta wme\0", true)
    }
    fn new_capability(capability: &[u8], enter_ap: bool) -> Result<Self, &'static str> {
        Self::build(capability, enter_ap, false, None)
    }
    /// Interface 0 answers as the station model, not a primary AP profile.
    fn new_station(capability: &[u8]) -> Result<Self, &'static str> {
        Self::build(capability, false, true, None)
    }
    /// `clm`: retain the production reset authority (`sdio_reset.rs`)
    /// sharing that CLM slot with the generation publisher.
    fn build(
        capability: &[u8],
        enter_ap: bool,
        station_primary: bool,
        clm: Option<crate::cyw43439::sdio_reset::Clm>,
    ) -> Result<Self, &'static str> {
        use crate::brcmfmac::provision::{tests::selected_fixture, Family};
        let (selection, assets) = selected_fixture(Family::Sdio43439)?;
        let (endpoint, bus) = sdio_ap_model::Device::new();
        if station_primary {
            bus.station_primary();
        }
        bus.capability(capability);
        let host = Model::with_endpoint(Box::new(endpoint), Some(selection.host()));
        let card = Card::initialize(host.clone(), Config::default())
            .map_err(|_| "SDIO AP actual CCCR/CIS host init")?;
        let mut transport = SdioTransport::new(card).qualify(assets.proof.clone());
        transport
            .prepare()
            .map_err(|_| "SDIO AP F1/block preparation")?;
        let nvram = crate::brcmfmac::boot::pack_nvram(&assets.nvram)
            .map_err(|_| "SDIO AP selected NVRAM")?;
        let mut loader = FirmwareLoader::new(transport, &assets.firmware, &nvram, 0, false)
            .require_revisions(selection.revisions());
        loader
            .run()
            .map_err(|_| "SDIO AP actual signed AI/CM3/firmware loader")?;
        let core = loader
            .packet_core()
            .ok_or("SDIO AP actual firmware packet core")?;
        let revision = loader
            .packet_core_revision()
            .ok_or("SDIO AP actual core revision")?;
        let mut transport = loader
            .into_transport()
            .map_err(|_| "SDIO AP loader terminal")?;
        transport
            .initialize_packets(core)
            .map_err(|_| "SDIO AP actual F2/mailbox init")?;
        transport
            .initialize_sleep(revision)
            .map_err(|_| "SDIO AP actual sleep source init")?;
        let database = Arc::new(narf_wireless::reg::db::Database::new());
        database.install(firmware::domain());
        let mut runtime = Runtime::new(transport);
        if let Some(clm) = clm {
            *clm.lock() = assets.clm.clone();
            let (_, read) = crate::brcmfmac::provision::tests::registry()?;
            runtime = runtime.with_reboot(Box::new(crate::cyw43439::sdio_reset::Reprovision::new(
                read,
                crate::brcmfmac::provision::tests::TEST_MANIFEST,
                selection.host(),
                (0x2d0, 0xa9af),
                clm,
            )));
        }
        let station = ready(Station::initialize_live(
            runtime,
            &assets.clm,
            database.clone(),
        ))?
        .map_err(station_init_error)?;
        let name = narf_net::iface::register("wlan%d", OWN, sdio_send);
        let device = sdio_shell(name.clone(), station);
        // Production `attach_runtime` registers the netdev capability and
        // the kernel iface first, then records the AP identity/capability.
        // Keep that order so the fixture's original identity is factual.
        let cap = narf_net::registry()
            .register(&narf_net::bootstrap_authority(), Registered(device.clone()))
            .map_err(|_| "SDIO AP original registered netdev")?;
        ready(device.sdio_ap_fixture_setup(database.clone()))?
            .map_err(|_| "SDIO AP actual cap/GET_AP discovery")?;
        narf_net::iface::set_link_state(&name, false);
        if enter_ap {
            device
                .set_iftype(3)
                .map_err(|_| "SDIO AP admitted public mode3")?;
        }
        let daemon = Cap::<narf_net::stack::StackDaemon, Invoke>::bootstrap();
        let admin = narf_net::stack::control_registered(&narf_net::stack::StackAttach {
            iface: cap,
            daemon,
        })
        .map_err(|_| "SDIO AP original admin")?
        .admin;
        let iface: Arc<dyn WirelessNetIface> = device.clone();
        narf_wireless::registry::register(iface.clone());
        narf_net::iface::set_link_state(&name, true);
        Ok(Self {
            device,
            iface,
            bus,
            host: Some(host),
            proof: assets.proof,
            admin,
            source: Arc::new(Source::new()),
            database,
            name,
        })
    }
    fn authority(&self) -> ApControlAuthority {
        ApControlAuthority::bind(
            self.admin.clone(),
            &self.iface,
            0,
            narf_net::iface::lookup(&self.name).unwrap().ifindex,
            self.source.clone(),
        )
        .unwrap()
        .reserve()
        .unwrap()
    }
    fn start(&self, secure: bool) -> Result<(), &'static str> {
        let (config, settings) = config(secure);
        ready(
            self.device
                .start_ap_with_settings_async(&self.authority(), config, settings),
        )?
        .map_err(|_| "SDIO AP actual START/beacon/rate/BSS receipts")
    }
    fn peer(&self, secure: bool) -> Result<(), &'static str> {
        let before = self.source.count(19);
        self.bus
            .change(|profile| profile.associate(CLIENT, association(secure)));
        ready(self.device.ap_worker())?;
        self.device.ap_drain();
        if self.source.count(19) != before + 1 {
            return Err("SDIO AP actual SCB/NEW_STATION");
        }
        Ok(())
    }
    fn enqueue(&self) -> Result<(), &'static str> {
        self.device
            .enqueue(&ethernet())
            .map_err(|_| "SDIO AP original Ethernet enqueue")?;
        for _ in 0..8 {
            self.device.ap_drain();
        }
        Ok(())
    }
    fn install(&self, index: u8, peer: Option<[u8; 6]>, material: u8) -> Result<(), &'static str> {
        ready(
            self.device
                .add_key_ap_async(&self.authority(), key(index, peer, material)),
        )?
        .map_err(|_| "SDIO AP actual wsec_key terminal")
    }
    fn authorize(&self, authorized: bool) -> Result<(), &'static str> {
        ready(
            self.device
                .set_station_async(&self.authority(), station(authorized)),
        )?
        .map_err(|_| "SDIO AP actual SCB authorize terminal")
    }
    fn data_commands(&self) -> usize {
        self.host
            .as_ref()
            .unwrap()
            .native_commands()
            .iter()
            .filter(|(id, arg, _)| *id == 53 && arg >> 31 != 0 && (arg >> 28) & 7 == 2)
            .count()
    }
    /// Drain the original IPC ring and report whether `expected` was copied.
    fn ring(&self, expected: &[u8]) -> bool {
        let mut rx = self.device.rx.lock();
        let Some(consumer) = rx.as_mut() else {
            return false;
        };
        let mut found = false;
        for _ in 0..RX_RING_N {
            let Ok(Some(frame)) = consumer.try_recv() else {
                break;
            };
            found |= frame.payload() == expected;
        }
        found
    }
    fn rx_packets(&self) -> u64 {
        narf_net::iface::lookup(&self.name).map_or(0, |iface| iface.stats.rx_packets)
    }
}
impl Drop for SdioBound {
    fn drop(&mut self) {
        let _ = ready(self.device.teardown());
        self.host.take();
        *ACTIVE_SDIO.lock() = None;
        narf_wireless::registry::unregister(&self.name);
        narf_net::registry().unregister(&self.name);
        narf_net::iface::unregister(&self.name);
    }
}

fn open_and_block() -> Result<(), &'static str> {
    for caps in [b"apextra sta wme\0".as_slice(), b"sta wme\0"] {
        let b = SdioBound::new_capability(caps, false)?;
        b.admin
            .set_link(false)
            .map_err(|_| "SDIO negative capability admin DOWN")?;
        if b.device.ap_capable()
            || b.device.ap_sme_capabilities().is_some()
            || b.device.set_iftype(3).is_ok()
        {
            return Err("SDIO AP absent/non-token native capability became AP authority");
        }
    }
    let b = SdioBound::new()?;
    b.start(false)?;
    b.peer(false)?;
    let mut large = ethernet();
    large.resize(1514, 0x73);
    let before = b.data_commands();
    b.device
        .enqueue(&large)
        .map_err(|_| "SDIO AP maximum actual Ethernet enqueue")?;
    for _ in 0..8 {
        b.device.ap_drain();
    }
    let packets = b.bus.physical_packets();
    let wire = packets
        .iter()
        .rev()
        .find(|p| p[5] == 2)
        .ok_or("SDIO AP actual DATA packet")?;
    if b.data_commands() != before + 1
        || wire.len() != 1536
        || wire[..2] != 1530u16.to_le_bytes()
        || wire[2..4] != (!1530u16).to_le_bytes()
        || wire[5] != 2
        || wire[7] != 12
        || wire[12..16] != [0x20, 0, 0, 0]
        || wire[16..1530] != large
        || wire[1530..].iter().any(|b| *b != 0)
        || !b.bus.change(|profile| profile.packets.contains(&large))
        || !b
            .bus
            .commands()
            .iter()
            .any(|(id, body)| *id == 118 && body == &1u32.to_le_bytes())
        || b.device.ap_sme_capabilities() != Some(0)
        || b.device.supports_ap_userspace_mlme()
        || b.device.supports_control_port_tx_status()
        || b.device.supports_ap_key_sequence()
        || b.device.connected_bssid().is_some()
        || !b.device.link_up()
    {
        return Err("SDIO AP one COMMAND/logical length/zero tail/firmware SME contract");
    }
    ready(b.device.stop_ap_async(&b.authority()))?.map_err(|_| "SDIO AP native STOP")?;
    if b.device.link_up() || b.bus.change(|p| p.active || !p.peers.is_empty()) {
        return Err("SDIO AP native BSS/SCB STOP receipts");
    }
    b.start(false)?;
    b.peer(false)?;
    Ok(())
}
fn smoke_cyw_ap_actual_card_loader_bcdc_sme_and_single_block_packet_stop_successor() -> TestResult {
    match open_and_block() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/wireless/cyw43439/ap",
    smoke_cyw_ap_actual_card_loader_bcdc_sme_and_single_block_packet_stop_successor
);

fn early_control() -> Result<(), &'static str> {
    let b = SdioBound::new()?;
    b.start(true)?;
    let eapol_start = [2, 1, 0, 0];
    b.bus.change(|p| {
        p.associate(CLIENT, association(true));
        p.downlink.push_back(control_frame(&eapol_start));
    });
    ready(b.device.ap_worker())?;
    b.device.ap_drain();
    if b.source.count(19) != 1
        || control_pdu(&b.source) != Some(eapol_start.to_vec())
        || b.authorize(true).is_ok()
    {
        return Err("SDIO AP same-drain association/EAPOL lost or sta_info fabricated port");
    }
    drop(b);
    let b = SdioBound::new()?;
    b.start(true)?;
    b.bus.change(|p| {
        p.associate(CLIENT, association(true));
        p.downlink.push_back(control_frame(&eapol_start));
        p.remove(CLIENT);
    });
    ready(b.device.ap_worker())?;
    b.device.ap_drain();
    if b.source.count(19) != 0 || control_pdu(&b.source).is_some() {
        return Err("SDIO AP native loss before SCB verification published held EAPOL");
    }
    Ok(())
}
fn smoke_cyw_ap_native_bss_up_queries_and_same_drain_association_eapol_keep_records() -> TestResult
{
    match early_control() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/wireless/cyw43439/ap",
    smoke_cyw_ap_native_bss_up_queries_and_same_drain_association_eapol_keep_records
);

fn tx_control(b: &SdioBound, pdu: Vec<u8>) -> Result<(), &'static str> {
    let expected = pdu.clone();
    if ready(b.device.tx_control_port_ap_async(
        &b.authority(),
        narf_wireless::ControlPortTxRequest::new(CLIENT, 0x888e, pdu, true, false),
    ))? != Ok(false)
        || !b
            .bus
            .change(|p| p.packets.last().is_some_and(|p| p[14..] == expected))
    {
        return Err("SDIO AP native EAPOL PIO terminal/body without invented ACK");
    }
    Ok(())
}
fn rsn_exchange() -> Result<(), &'static str> {
    use narf_wireless::eapol::*;
    let b = SdioBound::new()?;
    b.start(true)?;
    b.peer(true)?;
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
        .change(|profile| profile.response_on_control = Some(control_frame(&m2)));
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
        .change(|profile| profile.response_on_control = Some(control_frame(&m4)));
    tx_control(&b, m3.clone())?;
    let on_wire = b.bus.change(|p| p.packets.last().unwrap()[14..].to_vec());
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
        .change(|p| p.keys.iter().filter(|k| k[4] == 16).count())
        != 2
    {
        return Err("AP RSN keys not supplied through actual native transactions");
    }
    Ok(())
}
fn smoke_cyw_ap_actual_sdpcm_userspace_mic_wrapped_gtk_key_port_and_eapol_terminal() -> TestResult {
    match rsn_exchange() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/wireless/cyw43439/ap",
    smoke_cyw_ap_actual_sdpcm_userspace_mic_wrapped_gtk_key_port_and_eapol_terminal
);

fn prefix_losses() -> Result<(), &'static str> {
    for late in [false, true] {
        let b = SdioBound::new()?;
        b.start(false)?;
        b.peer(false)?;
        let before = b.bus.packets();
        let lost = b.source.count(20);
        b.device
            .enqueue(&ethernet())
            .map_err(|_| "SDIO AP retain original before loss prefix")?;
        if late {
            b.bus.loss_before_command(CLIENT);
        } else {
            b.bus.change(|p| {
                for _ in 0..72 {
                    p.event(23, CLIENT, &[]);
                }
                p.remove(CLIENT);
            });
        }
        for _ in 0..12 {
            b.device.ap_drain();
        }
        ready(b.device.ap_worker())?;
        b.device.ap_drain();
        if b.bus.packets() != before
            || b.source.count(20) != lost + 1
            || b.bus.change(|p| p.peers.contains_key(&CLIENT))
            || b.device.transport_failed()
            || !b.device.link_up()
        {
            return Err("SDIO AP old DATA crossed long or final-CARD_INT native peer loss");
        }
        b.peer(false)?;
        b.enqueue()?;
        if b.bus.packets() != before + 1 {
            return Err("SDIO AP native loss denied fresh successor");
        }
    }
    Ok(())
}
fn smoke_cyw_ap_long_native_prefix_and_late_card_interrupt_deny_original_data() -> TestResult {
    match prefix_losses() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/wireless/cyw43439/ap",
    smoke_cyw_ap_long_native_prefix_and_late_card_interrupt_deny_original_data
);
fn secure() -> Result<(), &'static str> {
    let b = SdioBound::new()?;
    b.install(1, None, 0x42)?;
    if !b.bus.change(|p| p.keys.is_empty()) || b.device.link_up() {
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
    if b.bus.change(|p| p.keys.len()) != 1 {
        return Err("AP staged key lacks native promotion");
    }
    if b.authorize(true).is_ok() {
        return Err("AP port opened without native PTK");
    }
    b.install(0, Some(CLIENT), 0x43)?;
    b.authorize(true)?;
    b.enqueue()?;
    let writes = b.bus.change(|p| p.keys.len());
    b.install(0, Some(CLIENT), 0x43)?;
    if b.bus.change(|p| p.keys.len()) != writes {
        return Err("AP identical retry rewrote native PN/RSC");
    }
    let a = b.authority();
    ready(b.device.del_key_ap_async(&a, 0, true, Some(CLIENT)))?
        .map_err(|_| "AP PTK deletion requires native SCB/flow absence")?;
    b.device.ap_drain();
    if b.source.count(20) != 1 || b.bus.change(|p| p.peers.contains_key(&CLIENT)) {
        return Err("AP PTK removal synthesized loss or retained native SCB");
    }
    drop(a);
    b.peer(true)?;
    if b.install(0, Some(CLIENT), 0x43).is_ok() {
        return Err("AP retired key material reinstalled after SCB replacement");
    }
    Ok(())
}
fn smoke_cyw_ap_native_staging_key_port_scb_absence_and_material_history() -> TestResult {
    match secure() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/wireless/cyw43439/ap",
    smoke_cyw_ap_native_staging_key_port_scb_absence_and_material_history
);

fn source_publication() -> Result<(), &'static str> {
    for issued in [false, true] {
        let mut b = SdioBound::new()?;
        b.start(false)?;
        b.peer(false)?;
        let original = {
            let state = b
                .device
                .state
                .try_lock()
                .ok_or("SDIO AP original DATA lock")?;
            state
                .ap
                .as_ref()
                .ok_or("SDIO AP original DATA owner")?
                .data_capture(&ethernet())
                .map_err(|_| "SDIO AP original DATA proof")?
        };
        let before = b.bus.packets();
        if issued {
            b.bus.revoke_after_chunk(b.proof.clone());
        } else {
            b.bus.revoke_before_command(b.proof.clone());
        }
        let result = ready(async {
            let mut state = b.device.state.lock().await;
            state.station.runtime.ap_send(&ethernet(), 0, &original)
        })?;
        if result.is_ok()
            || b.bus.packets() != before + usize::from(issued)
            || original.current().is_ok()
            || b.bus.partial() != 0
            || b.device.transport_failed() != issued
        {
            return Err("SDIO AP late original source loss invented issue/copy/terminal credit");
        }
        let count = b.bus.physical_packets().len();
        b.device.ap_drain();
        ready(b.device.ap_worker())?;
        b.device.ap_drain();
        b.host.take();
        let _ = ready(b.device.teardown())?;
        if b.device.link_up() || b.bus.drops() != 0 || b.bus.physical_packets().len() != count {
            return Err("SDIO AP revoked native source reclaimed/replayed unproved transport");
        }
    }
    Ok(())
}
fn smoke_cyw_ap_fixed_source_loss_at_command_and_after_issue_retains_uncertain_card() -> TestResult
{
    match source_publication() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/wireless/cyw43439/ap",
    smoke_cyw_ap_fixed_source_loss_at_command_and_after_issue_retains_uncertain_card
);

fn cancel_key() -> Result<(), &'static str> {
    let mut b = SdioBound::new()?;
    b.start(true)?;
    b.peer(true)?;
    b.bus.change(|profile| profile.hold_key = true);
    let authority = b.authority();
    {
        let mut future = pin!(b
            .device
            .add_key_ap_async(&authority, key(0, Some(CLIENT), 0x66)));
        if !matches!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ) || b.bus.change(|profile| profile.keys.len()) != 1
        {
            return Err("SDIO AP cancellation did not own actual accepted wsec_key request");
        }
    }
    drop(authority);
    ready(b.device.ap_worker())?;
    if b.device.link_up() || b.device.ap_generation().is_some() {
        return Err("SDIO AP dropped accepted key waiter kept live AP generation");
    }
    b.host.take();
    if b.bus.drops() != 0 {
        return Err("SDIO AP cancellation prematurely released original Card");
    }
    ready(b.device.teardown())?;
    if b.bus.drops() != 1 {
        return Err("SDIO AP actual passive/F2/IRQ/F1 stop failed to release original Card");
    }
    Ok(())
}
fn smoke_cyw_ap_cancelled_actual_key_waiter_releases_only_after_native_card_stop() -> TestResult {
    match cancel_key() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/wireless/cyw43439/ap",
    smoke_cyw_ap_cancelled_actual_key_waiter_releases_only_after_native_card_stop
);

fn policy_and_pm() -> Result<(), &'static str> {
    let b = SdioBound::new()?;
    b.start(false)?;
    b.peer(false)?;
    b.device
        .enqueue(&ethernet())
        .map_err(|_| "SDIO AP retained queued policy owner")?;
    let before = b.bus.packets();
    b.database.install(firmware::domain());
    b.device.ap_drain();
    ready(b.device.ap_worker())?;
    if b.device.link_up() || b.bus.packets() != before || b.bus.change(|profile| profile.active) {
        return Err(
            "SDIO AP equal-byte policy replacement revived old source or skipped native STOP",
        );
    }
    b.start(false)?;
    b.peer(false)?;
    let original = {
        let state = b
            .device
            .state
            .try_lock()
            .ok_or("SDIO AP PM original lock")?;
        state
            .ap
            .as_ref()
            .ok_or("SDIO AP PM role")?
            .data_capture(&ethernet())
            .map_err(|_| "SDIO AP PM capture")?
    };
    // SDIO system resume is a separate open feature. Refusal cannot retain
    // the old AP; no synthetic card-power/reset/resume receipt is supplied.
    if ready(Endpoint::suspend(&*b.device))?.is_ok()
        || original.current().is_ok()
        || b.device.link_up()
        || b.bus.change(|profile| profile.active)
    {
        return Err("SDIO AP unsupported system PM retained/replayed old BSS authority");
    }
    Ok(())
}
fn smoke_cyw_ap_policy_replacement_and_unsupported_system_pm_close_original_bss() -> TestResult {
    match policy_and_pm() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/wireless/cyw43439/ap",
    smoke_cyw_ap_policy_replacement_and_unsupported_system_pm_close_original_bss
);

fn uplink() -> Vec<u8> {
    let mut bytes = vec![0; 64];
    bytes[..6].copy_from_slice(&OWN);
    bytes[6..12].copy_from_slice(&CLIENT);
    bytes[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    bytes[14..30].copy_from_slice(b"cyw-ap-ordinary!");
    bytes
}
/// Ordinary peer DATA from the actual SDPCM DATA channel reaches the ring and
/// stack; a native peer loss newly queued on CARD_INT at either final sink
/// boundary denies that sink (and, at the ring, the later stack callback).
fn ordinary_rx() -> Result<(), &'static str> {
    for point in [
        ReceivePoint::AfterFrameAllocation,
        ReceivePoint::BeforeCallback,
    ] {
        let b = SdioBound::new()?;
        b.start(false)?;
        b.peer(false)?;
        let frame = uplink();
        let before = b.rx_packets();
        b.bus.change(|p| p.downlink.push_back(frame.clone()));
        ready(b.device.ap_worker())?;
        b.device.ap_drain();
        if !b.ring(&frame) || b.rx_packets() != before + 1 {
            return Err("SDIO AP ordinary native DATA missed its ring or stack");
        }
        let hit = Arc::new(AtomicBool::new(false));
        let once = hit.clone();
        let bus = b.bus.clone();
        *b.device.receive_hook.lock() = Some(Arc::new(move |at| {
            if at == point && !once.swap(true, Ordering::AcqRel) {
                bus.change(|p| p.remove(CLIENT));
            }
        }));
        let lost = b.source.count(20);
        let before = b.rx_packets();
        b.bus.change(|p| p.downlink.push_back(frame.clone()));
        ready(b.device.ap_worker())?;
        b.device.ap_drain();
        *b.device.receive_hook.lock() = None;
        let ringed = b.ring(&frame);
        if !hit.load(Ordering::Acquire)
            || b.rx_packets() != before
            || (point == ReceivePoint::AfterFrameAllocation && ringed)
        {
            return Err("SDIO AP ordinary DATA crossed a newly queued native peer loss");
        }
        for _ in 0..4 {
            ready(b.device.ap_worker())?;
            b.device.ap_drain();
        }
        if b.source.count(20) != lost + 1 || b.device.transport_failed() || b.ring(&frame) {
            return Err("SDIO AP native loss after denied DATA was not applied once");
        }
    }
    Ok(())
}
fn smoke_cyw_ap_ordinary_native_rx_final_ring_and_stack_boundaries() -> TestResult {
    match ordinary_rx() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/wireless/cyw43439/ap",
    smoke_cyw_ap_ordinary_native_rx_final_ring_and_stack_boundaries
);

/// Secondary firmware-SME AP on the actual SDIO/BCDC CYW43439 stack beside
/// the primary station (Linux 7.3-rc4 combo0: `brcmf_apsta_add_vif` on
/// ifidx 1, then `brcmf_cfg80211_start_ap` on that vif). Every Program
/// IOCTL carries `BCDC_DCMD_IF_SHIFT` ifidx 1; with `mchan` there is no
/// `BRCMF_C_DOWN`/`apsta 0`, no `nmode`/`vhtmode`/`qtxpower`, and the
/// security iovars are `bsscfg:` + le32 1. A peer association on bsscfg 1
/// reaches the AP shell's NEW_STATION, that peer's data received with BDC
/// `flags2` 1 (`bcdc.c` `brcmf_proto_bcdc_hdrpull`) reaches the AP shell's
/// netdev, and STOP retires only that BSS. With `joined` the primary is an
/// associated station first (interface 0 is the station model, not an AP
/// profile) and stays joined; the composed `event_msgs` keeps its events.
fn secondary_ap(joined: bool) -> Result<(), &'static str> {
    use crate::brcmfmac::runtime_tests::station_model::AP;
    use crate::cyw43439::fullmac_fixture::{cache, request};
    let name = if joined { "wlsvap8" } else { "wlsvap7" };
    let b = if joined {
        SdioBound::new_station(b"ap sta wme mchan\0")?
    } else {
        SdioBound::new_capability(b"ap sta wme mchan\0", false)?
    };
    b.bus.enable_vif_ap();
    if joined {
        let mut state = b.device.state.try_lock().ok_or("state")?;
        let station = &mut state.station;
        cache(station, AP, 6, narf_wireless::scan::BssSecurity::Open, &[]);
        ready(station.associate(request(
            AP,
            6,
            narf_wireless::SecurityConfig::Open,
            Vec::new(),
        )))?
        .map_err(|_| "SDIO primary station join")?;
        if station.bssid != Some(AP) {
            return Err("SDIO primary station not joined");
        }
    }
    let owner = {
        let mut state = b.device.state.try_lock().ok_or("state")?;
        let mac = state.station.mac;
        ready(vif::discover(&mut state.station.runtime, mac))?
            .map_err(|_| "SDIO cap discovery")?
            .ok_or("SDIO firmware cap refused")?
    };
    if !owner.features().mchan || owner.features().mbss {
        return Err("SDIO cap tokens not parsed as brcmf_feat_attach");
    }
    b.device.state.try_lock().ok_or("state")?.vif = Some(owner);
    vif::register_primary(&b.device);
    let result = (|| {
        let vap = b
            .device
            .vif_new(name, 3, None)
            .map_err(|_| "SDIO secondary AP shell admission")?;
        ready(b.device.vif_worker())?;
        if vap.ap_sme_capabilities() != Some(0) {
            return Err("SDIO secondary AP shell not attached after IF ADD");
        }
        narf_net::iface::set_link_state(name, true);
        let cap = narf_net::registry()
            .with_handle(name, |cap| *cap)
            .ok_or("SDIO secondary netdev handle")?;
        let admin = narf_net::stack::control_registered(&narf_net::stack::StackAttach {
            iface: cap,
            daemon: Cap::<narf_net::stack::StackDaemon, Invoke>::bootstrap(),
        })
        .map_err(|_| "SDIO secondary admin authority")?
        .admin;
        let iface: Arc<dyn WirelessNetIface> = vap.clone();
        let source = Arc::new(Source::new());
        let authority = ApControlAuthority::bind(
            admin,
            &iface,
            0,
            narf_net::iface::lookup(name).ok_or("ifindex")?.ifindex,
            source.clone(),
        )
        .map_err(|_| "SDIO AP authority bind")?
        .reserve()
        .map_err(|_| "SDIO AP control reservation")?;
        let vif_mac = crate::brcmfmac::runtime_tests::station_model::VIF;
        let (mut ap_config, settings) = config(false);
        ap_config.beacon_head[10..22].copy_from_slice(&[vif_mac, vif_mac].concat());
        let before = b.bus.commands().len();
        ready(vap.start_ap_with_settings_async(&authority, ap_config, settings))?
            .map_err(|_| "SDIO secondary AP START")?;
        let commands = b.bus.commands();
        let ifidx = b.bus.command_ifidx();
        let program: Vec<_> = commands[before..].iter().zip(&ifidx[before..]).collect();
        let mut wsec = b"bsscfg:wsec\0".to_vec();
        wsec.extend_from_slice(&1u32.to_le_bytes());
        if program.is_empty()
            || program.iter().any(|(_, index)| **index != 1)
            || program.iter().any(|((command, body), _)| {
                *command == 3
                    || *command == 263
                        && (body.starts_with(b"apsta\0")
                            || body.starts_with(b"nmode\0")
                            || body.starts_with(b"vhtmode\0")
                            || body.starts_with(b"qtxpower\0")
                            || body.starts_with(b"wsec\0"))
            })
            || !program.iter().any(|((_, body), _)| body.starts_with(&wsec))
        {
            return Err("SDIO secondary AP Program not the combo0 bsscfg-1 form");
        }
        if joined {
            // fweh.c brcmf_fweh_activate_events: one device-wide union.
            let mask = program
                .iter()
                .rev()
                .find(|((command, body), _)| *command == 263 && body.starts_with(b"event_msgs\0"))
                .map(|((_, body), _)| body[11..].to_vec())
                .ok_or("SDIO secondary AP wrote no event_msgs")?;
            let sta = crate::cyw43439::station::roam::event_mask(false);
            if sta.iter().zip(&mask).any(|(s, m)| s & m != *s) {
                return Err("SDIO secondary AP mask dropped the primary STA events");
            }
        }
        let primary_joined = |b: &SdioBound| {
            b.device
                .state
                .try_lock()
                .is_some_and(|state| state.station.bssid == Some(AP))
        };
        if !b.bus.vif_change(|p| p.active && p.up && p.formed)
            || !joined && b.bus.change(|p| p.active)
            || joined && !primary_joined(&b)
            || !vap.link_up()
        {
            return Err("SDIO secondary AP not running on its own interface");
        }
        b.bus
            .vif_change(|p| p.associate(CLIENT, association(false)));
        for _ in 0..4 {
            ready(b.device.vif_worker())?;
        }
        if source.count(19) != 1 {
            return Err("SDIO secondary AP NEW_STATION not observed on its shell");
        }
        // The associated peer's data arrives on BDC flags2 1 only.
        let rx = || narf_net::iface::lookup(name).map_or(0, |iface| iface.stats.rx_packets);
        let primary_rx = b.rx_packets();
        let before = rx();
        let mut frame = uplink();
        frame[..6].copy_from_slice(&vif_mac);
        b.bus.vif_change(|p| p.downlink.push_back(frame));
        for _ in 0..4 {
            ready(b.device.vif_worker())?;
        }
        if rx() != before + 1 || b.rx_packets() != primary_rx {
            return Err("SDIO secondary AP downlink not received on ifidx 1 only");
        }
        ready(vap.stop_ap_async(&authority))?.map_err(|_| "SDIO secondary AP STOP")?;
        if b.bus.vif_change(|p| p.active || !p.peers.is_empty())
            || vap.link_up()
            || joined && !primary_joined(&b)
        {
            return Err("SDIO secondary AP stop kept its BSS");
        }
        Ok(())
    })();
    vif::withdraw_family(crate::cyw43439::fullmac::Family::Sdio);
    result
}
fn smoke_cyw_vif_secondary_ap_on_actual_sdio_bcdc_ifidx_one() -> TestResult {
    match secondary_ap(false) {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/vif",
    smoke_cyw_vif_secondary_ap_on_actual_sdio_bcdc_ifidx_one
);
fn smoke_cyw_vif_joined_primary_station_beside_secondary_ap_on_actual_sdio() -> TestResult {
    match secondary_ap(true) {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/vif",
    smoke_cyw_vif_joined_primary_station_beside_secondary_ap_on_actual_sdio
);

/// Linux 7.3-rc4 `cfg80211.c` `brcmf_cfg80211_connect` on an additional
/// STA `brcmf_if` over the actual SDIO/BCDC stack: every join dcmd carries
/// `BCDC_DCMD_IF_SHIFT` ifidx 1, the security iovars are
/// `brcmf_fil_bsscfg_*` (`bsscfg:` + le32 1), the bsscfg-1 link events
/// (`fweh.c` dispatch by the event header) open only the secondary port,
/// and its `BRCMF_E_DEAUTH` closes only that port.
fn secondary_station() -> Result<(), &'static str> {
    use crate::brcmfmac::{
        runtime_tests::station_model::{AP, VIF},
        vif_bsscfg::{Bsscfg, Link},
        vif_owner::{Owner, Role},
        vif_wire::Features,
    };
    use crate::cyw43439::fullmac_fixture::{cache, request};
    let b = SdioBound::new_station(b"ap sta wme p2p mchan\0")?;
    let mut state = b.device.state.try_lock().ok_or("state")?;
    let station = &mut state.station;
    let features = Features {
        p2p: true,
        mchan: true,
        ..Features::default()
    };
    let mut owner = Owner::new(station.mac, features);
    let entry = ready(owner.create(&mut station.runtime, Role::Station, Some(VIF)))?
        .map_err(|_| "SDIO IF ADD over the BCDC event channel")?;
    station
        .runtime
        .vif_open(entry.ifidx)
        .map_err(|_| "SDIO vif_open")?;
    let parked = station.secondary(entry.mac);
    let mut link = Link::new(entry);
    let before = b.bus.commands().len();
    let parked = {
        let adapter = Bsscfg::new(&mut station.runtime, &mut owner, &mut link);
        let (mut secondary, rest) = parked.rebind(adapter);
        ready(secondary.configure_secondary())?
            .map_err(|_| "SDIO secondary per-interface dcmds")?;
        cache(
            &mut secondary,
            AP,
            6,
            narf_wireless::scan::BssSecurity::Open,
            &[],
        );
        ready(secondary.associate(request(
            AP,
            6,
            narf_wireless::SecurityConfig::Open,
            Vec::new(),
        )))?
        .map_err(|_| "SDIO secondary join")?;
        secondary.rebind(rest).0
    };
    let commands = b.bus.commands();
    let ifidx = b.bus.command_ifidx();
    let joined: Vec<_> = commands[before..].iter().zip(&ifidx[before..]).collect();
    let mut wpa_auth = b"bsscfg:wpa_auth\0".to_vec();
    wpa_auth.extend_from_slice(&1u32.to_le_bytes());
    if joined.iter().any(|(_, index)| **index != 1)
        || ![86u32, 20, 22, 26]
            .iter()
            .all(|dcmd| joined.iter().any(|((command, _), _)| command == dcmd))
        || joined.iter().any(|((command, _), _)| *command == 134)
        || !joined
            .iter()
            .any(|((_, body), _)| body.starts_with(&wpa_auth))
        || joined
            .iter()
            .any(|((_, body), _)| body.starts_with(b"wpa_auth\0") || body.starts_with(b"wsec\0"))
    {
        return Err("SDIO secondary join not addressed to BCDC ifidx 1 / bsscfg 1");
    }
    if link.peer() != Some(AP)
        || parked.bssid != Some(AP)
        || station.bssid.is_some()
        || station.runtime.pop_event().is_some()
    {
        return Err("SDIO secondary link leaked into the primary interface");
    }
    // BRCMF_E_DEAUTH (6) on bsscfg 1 closes only the secondary port.
    b.bus.secondary_event(6, 0, AP);
    let adapter = Bsscfg::new(&mut station.runtime, &mut owner, &mut link);
    let (mut secondary, rest) = parked.rebind(adapter);
    for _ in 0..4 {
        let _ = secondary.poll();
    }
    let (parked, _) = secondary.rebind(rest);
    if parked.bssid.is_some() || link.peer().is_some() || station.bssid.is_some() {
        return Err("SDIO secondary deauthentication kept the port open");
    }
    Ok(())
}
fn smoke_cyw_vif_secondary_station_joins_on_actual_sdio_bcdc_ifidx_one() -> TestResult {
    match secondary_station() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/vif",
    smoke_cyw_vif_secondary_station_joins_on_actual_sdio_bcdc_ifidx_one
);

impl crate::brcmfmac::p2p_transport_cases::Model for sdio_ap_model::Handle {
    fn event(&self, kind: u32, source: [u8; 6], data: &[u8]) {
        self.secondary_event_data(kind, source, data);
    }
    fn sets(&self) -> Vec<(u32, Vec<u8>)> {
        self.vif_sets()
    }
    fn commands(&self) -> Vec<(u8, Vec<u8>)> {
        self.command_ifidx()
            .into_iter()
            .zip(self.commands())
            .map(|(ifidx, (_, body))| (ifidx, body))
            .collect()
    }
}

/// P2P_DEVICE discovery bsscfg (create, listen + action RX, action TX,
/// SEARCH escan, delete) over the actual SDHCI/F2/SDPCM/BCDC transport.
fn p2p_discovery() -> Result<(), &'static str> {
    let b = SdioBound::new_station(b"ap sta wme p2p mchan\0")?;
    let mut state = b.device.state.try_lock().ok_or("state")?;
    crate::brcmfmac::p2p_transport_cases::discovery(&mut state.station, &b.bus)
}
fn smoke_cyw_p2p_discovery_listen_action_and_escan_on_actual_sdio() -> TestResult {
    match p2p_discovery() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/vif",
    smoke_cyw_p2p_discovery_listen_action_and_escan_on_actual_sdio
);

/// P2P_CLIENT `p2p_ifadd` + join on BCDC ifidx 1 + `p2p_ifdel`.
fn p2p_client() -> Result<(), &'static str> {
    let b = SdioBound::new_station(b"ap sta wme p2p mchan\0")?;
    let mut state = b.device.state.try_lock().ok_or("state")?;
    crate::brcmfmac::p2p_transport_cases::client_join(&mut state.station, &b.bus)
}
fn smoke_cyw_p2p_client_joins_on_actual_sdio_bcdc_ifidx_one() -> TestResult {
    match p2p_client() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/vif",
    smoke_cyw_p2p_client_joins_on_actual_sdio_bcdc_ifidx_one
);

/// P2P_GO shell over the actual SDIO/BCDC transport: `p2p_ifadd` GO on
/// the primary, the `brcmf_cfg80211_start_ap` P2P_GO branch on BCDC
/// ifidx 1 (`bsscfg:ssid` then `bss` enable, no `SET_AP`/`apsta`/`mbss`),
/// a client association on the GO, `bss` disable at STOP and
/// `p2p_ifdis` + `p2p_ifdel` at DEL_INTERFACE.
fn p2p_go() -> Result<(), &'static str> {
    const NAME: &str = "wlsgo9";
    let b = SdioBound::new_station(b"ap sta wme p2p mchan\0")?;
    b.bus.enable_vif_ap();
    let owner = {
        let mut state = b.device.state.try_lock().ok_or("state")?;
        let mac = state.station.mac;
        ready(vif::discover(&mut state.station.runtime, mac))?
            .map_err(|_| "SDIO cap discovery")?
            .ok_or("SDIO firmware cap refused")?
    };
    if !owner.features().p2p {
        return Err("SDIO p2p cap token not parsed");
    }
    b.device.state.try_lock().ok_or("state")?.vif = Some(owner);
    vif::register_primary(&b.device);
    let result = (|| {
        let before_add = b.bus.commands().len();
        let go = b
            .device
            .vif_new(NAME, 9, None)
            .map_err(|_| "SDIO P2P_GO shell admission")?;
        ready(b.device.vif_worker())?;
        let commands = b.bus.commands();
        let ifidx = b.bus.command_ifidx();
        let added: Vec<_> = commands[before_add..]
            .iter()
            .zip(&ifidx[before_add..])
            .collect();
        if go.current_iftype() != 9
            || go.ap_sme_capabilities() != Some(0)
            || !added.iter().any(|((command, body), index)| {
                *command == 263 && **index == 0 && body.starts_with(b"p2p_ifadd\0")
            })
            || added
                .iter()
                .any(|((_, body), _)| body.starts_with(b"interface_create\0"))
        {
            return Err("SDIO GO shell not created by p2p_ifadd");
        }
        narf_net::iface::set_link_state(NAME, true);
        let cap = narf_net::registry()
            .with_handle(NAME, |cap| *cap)
            .ok_or("SDIO GO netdev handle")?;
        let admin = narf_net::stack::control_registered(&narf_net::stack::StackAttach {
            iface: cap,
            daemon: Cap::<narf_net::stack::StackDaemon, Invoke>::bootstrap(),
        })
        .map_err(|_| "SDIO GO admin authority")?
        .admin;
        let iface: Arc<dyn WirelessNetIface> = go.clone();
        let source = Arc::new(Source::new());
        let authority = ApControlAuthority::bind(
            admin,
            &iface,
            0,
            narf_net::iface::lookup(NAME).ok_or("ifindex")?.ifindex,
            source.clone(),
        )
        .map_err(|_| "SDIO GO authority bind")?
        .reserve()
        .map_err(|_| "SDIO GO control reservation")?;
        let vif_mac = crate::brcmfmac::runtime_tests::station_model::VIF;
        let (mut ap_config, settings) = config(false);
        ap_config.beacon_head[10..22].copy_from_slice(&[vif_mac, vif_mac].concat());
        let before = b.bus.commands().len();
        ready(go.start_ap_with_settings_async(&authority, ap_config, settings))?
            .map_err(|_| "SDIO P2P GO START")?;
        let commands = b.bus.commands();
        let ifidx = b.bus.command_ifidx();
        let program: Vec<_> = commands[before..].iter().zip(&ifidx[before..]).collect();
        let mut ssid = b"bsscfg:ssid\0".to_vec();
        ssid.extend_from_slice(&1u32.to_le_bytes());
        let mut enable = b"bss\0".to_vec();
        enable.extend_from_slice(&[1, 0, 0, 0, 1, 0, 0, 0]);
        let position = |prefix: &[u8]| {
            program
                .iter()
                .position(|((_, body), _)| body.starts_with(prefix))
        };
        if program.iter().any(|(_, index)| **index != 1)
            || program.iter().any(|((command, body), _)| {
                matches!(*command, 2 | 3 | 26 | 118)
                    || body.starts_with(b"apsta\0")
                    || body.starts_with(b"mbss\0")
                    || body.starts_with(b"closednet\0")
            })
            || position(&ssid).is_none()
            || position(&enable).is_none()
            || position(&ssid) >= position(&enable)
        {
            return Err("SDIO GO Program not the start_ap P2P_GO branch on bsscfg 1");
        }
        if !b.bus.vif_change(|p| p.active && p.up && p.formed) || !go.link_up() {
            return Err("SDIO GO BSS not formed");
        }
        b.bus
            .vif_change(|p| p.associate(CLIENT, association(false)));
        for _ in 0..4 {
            ready(b.device.vif_worker())?;
        }
        if source.count(19) != 1 {
            return Err("SDIO GO NEW_STATION not observed on its shell");
        }
        let before = b.bus.commands().len();
        ready(go.stop_ap_async(&authority))?.map_err(|_| "SDIO P2P GO STOP")?;
        let mut disable = b"bss\0".to_vec();
        disable.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]);
        if !b.bus.commands()[before..]
            .iter()
            .any(|(command, body)| *command == 263 && *body == disable)
            || b.bus.vif_change(|p| p.active || !p.peers.is_empty())
            || go.link_up()
        {
            return Err("SDIO GO STOP not bss disable");
        }
        let before = b.bus.commands().len();
        go.delete_virtual_interface()
            .map_err(|_| "SDIO GO DEL_INTERFACE")?;
        for _ in 0..6 {
            ready(b.device.vif_worker())?;
        }
        let commands = b.bus.commands();
        let ifdis = commands[before..]
            .iter()
            .position(|(_, body)| body.starts_with(b"p2p_ifdis\0"));
        let ifdel = commands[before..]
            .iter()
            .position(|(_, body)| body.starts_with(b"p2p_ifdel\0"));
        if ifdis.is_none()
            || ifdel.is_none()
            || ifdis >= ifdel
            || narf_net::iface::lookup(NAME).is_some()
        {
            return Err("SDIO GO DEL not p2p_ifdis + p2p_ifdel + IF DEL");
        }
        Ok(())
    })();
    vif::withdraw_family(crate::cyw43439::fullmac::Family::Sdio);
    result
}
fn smoke_cyw_p2p_go_start_client_stop_and_delete_on_actual_sdio() -> TestResult {
    match p2p_go() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/vif",
    smoke_cyw_p2p_go_start_client_stop_and_delete_on_actual_sdio
);

/// Linux `sdio.c::brcmf_sdio_bus_reset` through the shared generation
/// owner over the actual SDHCI Card, AI/CM3 loader and SDPCM/BCDC: a joined
/// station whose generation turned terminal stops (native stop), the card
/// is power-cycled and re-enumerated (`mmc_hw_reset`: CCCR `sdio_reset`,
/// CMD0/CMD5/CMD3/CMD7), the signed selection is re-run and the firmware
/// downloaded again; `Station::initialize_live` replays over the fresh
/// generation, the shell republishes under the same name and the retained
/// association is rediscovered and rejoined.
fn sdio_reset_rejoin() -> Result<(), &'static str> {
    use crate::brcmfmac::runtime_tests::station_model::AP;
    use crate::cyw43439::fullmac_fixture::{cache, request};
    use crate::cyw43439::interface::generation::{Generation, Publish, Removal};
    let clm: crate::cyw43439::sdio_reset::Clm = Arc::new(IrqSafeSpinLock::new(Vec::new()));
    let mut b = SdioBound::build(b"sta wme\0", false, true, Some(clm.clone()))?;
    {
        let mut state = b.device.state.try_lock().ok_or("state")?;
        let station = &mut state.station;
        cache(station, AP, 6, narf_wireless::scan::BssSecurity::Open, &[]);
        ready(station.associate(request(
            AP,
            6,
            narf_wireless::SecurityConfig::Open,
            Vec::new(),
        )))?
        .map_err(|_| "SDIO station join")?;
        if station.bssid != Some(AP) || !station.runtime.resettable() {
            return Err("SDIO station not joined under a reset authority");
        }
        // A fatal bus error / firmware halt leaves the generation terminal.
        station.runtime.fail();
    }
    *b.device.lifecycle.request.lock() = Some(request(
        AP,
        6,
        narf_wireless::SecurityConfig::Open,
        Vec::new(),
    ));
    let host = b.host.clone().ok_or("SDIO host model")?;
    let before = host.native_commands().len();
    let database = b.database.clone();
    let published = clm.clone();
    let publish: Publish<SdioRuntime> = Box::new(move |name, runtime| {
        let database = database.clone();
        let clm = published.lock().clone();
        Box::pin(async move {
            let station = Station::initialize_live(runtime, &clm, database).await?;
            narf_net::iface::register(name, OWN, sdio_send);
            Ok(sdio_shell(String::from(name), station))
        })
    });
    let generation = Generation::with_publisher(b.device.clone(), publish);
    narf_scheduler::block_on(generation.recover())
        .map_err(|_| "SDIO transport reset did not republish the station")?;
    let device = generation
        .current()
        .ok_or("no generation after SDIO reset")?;
    let commands: Vec<(u8, u32, u16)> = host.native_commands()[before..].to_vec();
    let opcodes: Vec<u8> = commands.iter().map(|c| c.0).collect();
    let enumerated = opcodes
        .windows(7)
        .position(|w| w == [52, 52, 0, 5, 5, 3, 7])
        .ok_or("reset did not power-cycle and re-enumerate the card")?;
    if !opcodes[enumerated..].contains(&53) {
        return Err("reset did not download the firmware again");
    }
    if Arc::ptr_eq(&device, &b.device)
        || !b.device.withdrawn()
        || device.withdrawn()
        || device.interface_name() != b.name
        || generation.resets() != 1
        || device.transport_failed()
    {
        return Err("SDIO reset did not publish a fresh generation under the same name");
    }
    if WirelessNetIface::connected_bssid(&*device) != Some(AP) {
        return Err("retained association was not rejoined after the SDIO reset");
    }
    if narf_scheduler::block_on(generation.remove()) != Removal::Reclaimed {
        return Err("rebooted SDIO generation was not stopped and released");
    }
    // The harness drop tears down its (withdrawn) original shell.
    b.device = device;
    Ok(())
}
fn smoke_cyw_sdio_reset_power_cycles_reboots_replays_and_rejoins_same_netdev() -> TestResult {
    match sdio_reset_rejoin() {
        Ok(()) => TestResult::Pass,
        Err(error) => TestResult::Fail(error),
    }
}
kernel_test_in!(
    "drivers/wireless/cyw43439/sdio",
    smoke_cyw_sdio_reset_power_cycles_reboots_replays_and_rejoins_same_netdev
);

/// #1812 diagnostic: a policy loss before firmware-up makes
/// `Station::initialize_live` fail with `Error::Authority`, and the
/// surfaced fixture string must name the authority step instead of the
/// shared BCDC/Station string. The msgbuf adapter stands in for the SDIO
/// one here: both drive the same `initialize_live` and the same
/// `runtime::Error`, and the SDIO path itself cannot run on the host
/// (firmware registry install fails OutOfMemory without the kernel
/// frame/DMA allocator).
fn sdio_station_init_error_surfaces_authority() -> Result<(), &'static str> {
    use crate::cyw43439::runtime::Error;
    use crate::cyw43439::transport::TransportError;
    for version in [5, 6] {
        let database = Arc::new(narf_wireless::reg::db::Database::new());
        database.install(firmware::domain());
        let Ok((adapter, bus)) = firmware::create(version, true) else {
            return Err("native bootstrap owner");
        };
        bus.clear_policy_on(86, database.clone());
        let result = ready(Station::initialize_live(adapter, &[], database))?;
        let Err(error) = result else {
            return Err("policy loss during setup still initialized the station");
        };
        if !matches!(error, Error::Authority) {
            return Err("policy loss during setup did not fail with authority");
        }
        if station_init_error(error) != "SDIO AP actual BCDC/Station initialization: authority" {
            return Err("authority failure did not surface the authority step");
        }
        if bus.commands().iter().any(|(command, _, _)| *command == 2) {
            return Err("policy loss during setup enabled firmware");
        }
    }
    // Every inner variant maps to a distinct surfaced string.
    let cases = [
        (
            Error::Transport(TransportError::BadFraming),
            "SDIO AP actual BCDC/Station initialization: transport bad framing",
        ),
        (
            Error::Transport(TransportError::Busy),
            "SDIO AP actual BCDC/Station initialization: transport busy",
        ),
        (
            Error::Transport(TransportError::Denied),
            "SDIO AP actual BCDC/Station initialization: transport denied",
        ),
        (
            Error::Transport(TransportError::ChipFlowError),
            "SDIO AP actual BCDC/Station initialization: transport chip flow error",
        ),
        (
            Error::Transport(TransportError::LengthOverflow),
            "SDIO AP actual BCDC/Station initialization: transport length overflow",
        ),
        (
            Error::Transport(TransportError::AddressOverflow),
            "SDIO AP actual BCDC/Station initialization: transport address overflow",
        ),
        (
            Error::Transport(TransportError::Timeout),
            "SDIO AP actual BCDC/Station initialization: transport timeout",
        ),
        (
            Error::Transport(TransportError::NotReady),
            "SDIO AP actual BCDC/Station initialization: transport not ready",
        ),
        (
            Error::Transport(TransportError::Other(0)),
            "SDIO AP actual BCDC/Station initialization: transport other",
        ),
        (
            Error::Malformed,
            "SDIO AP actual BCDC/Station initialization: malformed",
        ),
        (
            Error::Unsupported,
            "SDIO AP actual BCDC/Station initialization: unsupported",
        ),
        (
            Error::Authority,
            "SDIO AP actual BCDC/Station initialization: authority",
        ),
        (
            Error::Busy,
            "SDIO AP actual BCDC/Station initialization: busy",
        ),
        (
            Error::Timeout,
            "SDIO AP actual BCDC/Station initialization: timeout",
        ),
        (
            Error::Failed,
            "SDIO AP actual BCDC/Station initialization: failed",
        ),
        (
            Error::EventOverflow,
            "SDIO AP actual BCDC/Station initialization: event overflow",
        ),
        (
            Error::Firmware(1),
            "SDIO AP actual BCDC/Station initialization: firmware",
        ),
    ];
    for (error, expected) in cases {
        if station_init_error(error) != expected {
            return Err("inner station error did not surface its step");
        }
    }
    Ok(())
}
fn smoke_cyw_sdio_station_init_error_surfaces_authority() -> TestResult {
    match sdio_station_init_error_surfaces_authority() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "drivers/wireless/cyw43439/sdio",
    smoke_cyw_sdio_station_init_error_surfaces_authority
);
