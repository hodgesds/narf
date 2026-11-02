//! Actual native AP MAC/LINK/peer/key/TVQM DMA conversations. The explicit
//! inert firmware observes queue bindings and receipts, never driver state.
use super::*;
#[path = "ap_client_native_tests.rs"]
mod client;
#[path = "ap_go_native_tests.rs"]
mod go;
use narf_capabilities::{Cap, Invoke};
use narf_net::netlink_generic::DeferredReplySink;
use narf_wireless::ap_control::ApControlAuthority;
const PEER: [u8; 6] = [2, 0x73, 2, 3, 4, 5];
const TK: [u8; 16] = [0x31; 16];
const GTK: [u8; 16] = [0x32; 16];
const IGTK: [u8; 16] = [0x33; 16];

struct Queue {
    id: u16,
    station: u8,
    tid: u8,
    read: u16,
    write: u16,
    live: bool,
}
pub(super) struct Model {
    started: bool,
    queues: Vec<Queue>,
    peers: Vec<(u8, [u8; 6])>,
    keys: Vec<(u8, u8, u32, [u8; 16])>,
    pub(super) hold: Option<(u8, u8)>,
    pub(super) held: Option<Vec<u8>>,
    malformed_flush: bool,
    tx: Vec<(u8, Vec<u8>, bool)>,
    beacon: bool,
    go: bool,
    go_pn: u64,
    initial_noa: bool,
    pending_initial_noa: bool,
}
impl Model {
    pub(super) fn new() -> Self {
        Self {
            started: false,
            queues: Vec::new(),
            peers: Vec::new(),
            keys: Vec::new(),
            hold: None,
            held: None,
            malformed_flush: false,
            tx: Vec::new(),
            beacon: false,
            go: false,
            go_pn: 0,
            initial_noa: false,
            pending_initial_noa: false,
        }
    }
    pub(super) fn arm_initial_noa(&mut self) {
        self.initial_noa = true;
    }
    pub(super) fn take_initial_noa(&mut self) -> Option<Vec<u8>> {
        if !core::mem::take(&mut self.pending_initial_noa) {
            return None;
        }
        Some(crate::iwlwifi::p2p_go_fixture::notice(0, 5, true))
    }
    pub(super) fn command(
        &mut self,
        group: u8,
        cmd: u8,
        version: u8,
        body: &[u8],
    ) -> R<Option<Vec<u8>>> {
        if (group, cmd) == (3, 9) && word(body, 0) == 3 {
            self.started = true;
        }
        if !self.started {
            return Ok(None);
        }
        let mut reply = Vec::new();
        if (group, cmd) == (3, 8)
            && body.len() == 52
            && word(body, 4) == 1
            && word(body, 8) == 8
            && self.initial_noa
        {
            self.initial_noa = false;
            self.pending_initial_noa = true;
        }
        match (group, cmd) {
            (3, 8) => require(
                body.len() == 52
                    && word(body, 0) == 0
                    && body[12..18] == OWN
                    && (word(body, 4) == 3 || word(body, 8) == 8)
                    && (word(body, 4) == 3 || word(body, 20) & !8 == 38),
                "AP actual MAC0 GO/filter contract",
            )?,
            (3, 9) => require(
                body.len() == 208
                    && body[16..22] == OWN
                    && word(body, 4) == 0
                    && word(body, 8) == 0
                    && (word(body, 28) == 0 || word(body, 136) == 100 && word(body, 140) == 200),
                "AP actual LINK0/PHY0/beacon timing",
            )?,
            (1, 8) => require(
                body.len() == 32 && word(body, 8) == 6 && body[12] == 1 && body[13..16] == [0; 3],
                "AP actual legacy20 PHY frequency/width",
            )?,
            (3, 10) => {
                let station = u8::try_from(word(body, 0)).map_err(|_| "AP STA extent")?;
                require(
                    body.len() == if version == 2 { 104 } else { 96 }
                        && station < 10
                        && word(body, 4) == 0,
                    "AP actual STA/link extent",
                )?;
                let address: [u8; 6] = body[8..14].try_into().unwrap();
                if station < 2 {
                    require(
                        if station == 0 {
                            address == [3, 0, 0, 0, 0, 0] && word(body, 24) == 2
                        } else {
                            address == [255; 6] && word(body, 24) == 1 && word(body, 36) == 1
                        },
                        "AP distinct native multicast/broadcast station type",
                    )?;
                } else {
                    require(
                        address[0] & 1 == 0 && word(body, 28) != 0 && word(body, 24) == 0,
                        "AP actual peer AID/address/type",
                    )?;
                }
                self.peers.retain(|(id, _)| *id != station);
                self.peers.push((station, address));
            }
            (5, 0x17) => {
                require(
                    version == 3 && body.len() == 36 && word(body, 4).count_ones() == 1,
                    "AP actual TVQM station-mask/v3 extent",
                )?;
                let station = word(body, 4).trailing_zeros() as u8;
                let tid = body[8];
                require(
                    self.peers.iter().any(|(id, _)| *id == station)
                        && matches!(tid, 0 | 1 | 4 | 6 | 15),
                    "AP queue needs actual native station/TID",
                )?;
                if word(body, 0) == 0 {
                    require(
                        !self
                            .queues
                            .iter()
                            .any(|q| q.live && q.station == station && q.tid == tid)
                            && word(body, 16) == 4
                            && body[20..28] != [0; 8]
                            && body[28..36] != [0; 8],
                        "AP native queue DMA/unique binding",
                    )?;
                    let id = self.queues.len() as u16 + 1;
                    self.queues.push(Queue {
                        id,
                        station,
                        tid,
                        read: 0,
                        write: 0,
                        live: true,
                    });
                    reply.resize(8, 0);
                    reply[..2].copy_from_slice(&id.to_le_bytes());
                } else {
                    let q = self
                        .queues
                        .iter_mut()
                        .find(|q| q.live && q.station == station && q.tid == tid)
                        .ok_or("AP remove unowned native queue")?;
                    require(
                        q.read == q.write && body[12..] == [0; 24],
                        "AP remove before terminal flush",
                    )?;
                    q.live = false;
                    reply.resize(8, 0);
                    reply[..2].copy_from_slice(&q.id.to_le_bytes());
                }
            }
            (5, 0xf) => {
                let station = if version == 4 {
                    body[0]
                } else {
                    word(body, 0).trailing_zeros() as u8
                };
                require(
                    body.len() == if version == 4 { 28 } else { 44 }
                        && station >= 2
                        && self.peers.iter().any(|(id, _)| *id == station),
                    "AP TLC must select exact real client, not internal STA0",
                )?;
            }
            (5, 0x18) => {
                require(
                    version == 1 && body.len() == 80 && word(body, 4).count_ones() == 1,
                    "AP SEC_KEYv1 exact native STA mask",
                )?;
                let station = word(body, 4).trailing_zeros() as u8;
                let id = word(body, 8) as u8;
                let flags = word(body, 12);
                require(
                    match station {
                        0 => id <= 3 && flags == 0x42,
                        1 => matches!(id, 4 | 5) && flags == 0x62,
                        _ => id == 0 && matches!(flags, 2 | 0x22),
                    },
                    "AP PTK/GTK/IGTK native TX identity/flags",
                )?;
                self.keys.retain(|(s, i, _, _)| *s != station || *i != id);
                if word(body, 0) == 1 {
                    require(
                        body[72..80] == [0; 8],
                        "AP fresh native TX nonce starts once",
                    )?;
                    self.keys
                        .push((station, id, flags, body[16..32].try_into().unwrap()));
                } else {
                    require(
                        word(body, 0) == 3 && body[16..] == [0; 64],
                        "AP exact native key removal",
                    )?;
                }
            }
            (1, 0x91) => {
                require(
                    matches!(version, 13 | 14)
                        && body.len() >= 74
                        && usize::from(half(body, 0)) + 32 == body.len()
                        && word(body, 12) == 0
                        && body[32] == 0x80
                        && body[42..48] == OWN,
                    "AP actual beacon template extent/firmware link/physical address",
                )?;
                let tim = word(body, 16) as usize;
                require(
                    body.get(32 + tim..38 + tim) == Some(&[5, 4, 0, 2, 0, 0])
                        && word(body, 20) == if version < 14 { 4 } else { 0 },
                    "AP native TIM index/body length versus BTWT",
                )?;
                self.go = body
                    .windows(8)
                    .any(|raw| raw == [221, 18, 0x50, 0x6f, 0x9a, 9, 2, 2]);
                if self.go {
                    require(half(body, 2) == 0, "GO native beacon used CCK")?;
                }
                self.beacon = true;
            }
            (1, 0x1e) => {
                require(
                    version == 2 && body.len() == 8 && half(body, 4) == 0xffff,
                    "AP actual TXPATH_FLUSHv2 request",
                )?;
                let station = word(body, 0) as u8;
                let queues: Vec<_> = self
                    .queues
                    .iter_mut()
                    .filter(|q| q.live && q.station == station)
                    .collect();
                reply.resize(132, 0);
                reply[..2].copy_from_slice(&u16::from(station).to_le_bytes());
                reply[2..4].copy_from_slice(&(queues.len() as u16).to_le_bytes());
                for (i, q) in queues.into_iter().enumerate() {
                    let at = 4 + i * 8;
                    reply[at..at + 2].copy_from_slice(&u16::from(q.tid).to_le_bytes());
                    reply[at + 2..at + 4].copy_from_slice(&q.id.to_le_bytes());
                    reply[at + 4..at + 6].copy_from_slice(&q.read.to_le_bytes());
                    reply[at + 6..at + 8].copy_from_slice(&q.write.to_le_bytes());
                    q.read = q.write;
                }
                if self.malformed_flush {
                    reply[6..8].copy_from_slice(&511u16.to_le_bytes());
                }
            }
            (3, 0xc) => {
                let station = word(body, 0) as u8;
                require(
                    body.len() == 4 && !self.queues.iter().any(|q| q.live && q.station == station),
                    "AP STA removal before exact terminal queue receipts",
                )?;
                self.peers.retain(|(id, _)| *id != station);
            }
            _ => return Ok(None),
        }
        Ok(Some(reply))
    }
    pub(super) fn transmit(&mut self, p: &Published, firmware: &mut model::Firmware) -> R {
        let q = self
            .queues
            .iter_mut()
            .find(|q| q.live && q.id == p.queue)
            .ok_or("AP TX unowned queue")?;
        let b = &p.bytes;
        require(b.len() >= 56 && b[0] == 0x1c, "AP actual TXv10/11 envelope")?;
        let header = ((word(b, 8) >> 8) & 31) as usize * 2;
        require(
            matches!(header, 24 | 26)
                && word(b, 8) & 0x4000 == 0
                && b.len() == 32 + usize::from(half(b, 4)) + header.next_multiple_of(4) - header,
            "AP exact native ordinary header/padding/length",
        )?;
        let mut frame = b[32..32 + header].to_vec();
        frame.extend_from_slice(&b[32 + header.next_multiple_of(4)..]);
        let encrypt = half(b, 6) & 2 == 0;
        require(
            frame[10..16] == OWN && frame[1] & 3 == if frame[0] & 12 == 8 { 2 } else { 0 },
            "AP TX physical FromDS/management owner",
        )?;
        if encrypt {
            require(
                self.keys.iter().any(|(s, _, _, _)| *s == q.station),
                "AP encryption lacks observed native key receipt",
            )?;
            if frame[0] & 12 == 8 {
                require(frame[1] & 0x40 != 0, "AP protected data omitted FC bit")?;
            } else if frame[4] & 1 != 0 {
                require(
                    q.station == 1 && frame[1] & 0x40 == 0,
                    "AP BIP must use IGTK despite clear Protected bit",
                )?;
            }
        } else if self.go && frame[0] & 12 == 8 && frame[1] & 0x40 != 0 && frame[4] & 1 != 0 {
            self.go_pn = crate::iwlwifi::p2p_go_fixture::open_group(&frame, OWN, GTK, self.go_pn)?;
        } else {
            require(
                frame[1] & 0x40 == 0,
                "AP native encryption bypass on protected frame",
            )?;
        }
        q.write = p.pointer;
        q.read = p.pointer;
        self.tx.push((q.station, frame, encrypt));
        firmware.tx_complete(p.queue, p.pointer);
        Ok(())
    }
}

#[derive(Debug)]
enum Callback {
    NativeLoss,
    SetUnauthorized(Box<ApControlAuthority>),
}
#[derive(Debug)]
struct Source {
    owner: narf_net::native_emission::ProviderLifetime,
    messages: IrqSafeSpinLock<Vec<Vec<u8>>>,
    callback: IrqSafeSpinLock<Option<Callback>>,
    callback_error: IrqSafeSpinLock<Option<&'static str>>,
}
impl Source {
    fn new() -> Self {
        Self {
            owner: narf_net::native_emission::ProviderLifetime::new(),
            messages: IrqSafeSpinLock::new(Vec::new()),
            callback: IrqSafeSpinLock::new(None),
            callback_error: IrqSafeSpinLock::new(None),
        }
    }
}
impl DeferredReplySink for Source {
    fn current(&self) -> bool {
        let callback = self.callback.lock().take();
        if let Some(callback) = callback {
            // These are intentionally arbitrary provider callbacks. Take the
            // hook and release its guard before reentering the real owner.
            let device = HARNESS.lock().as_ref().unwrap().0.clone();
            let result = match callback {
                Callback::NativeLoss => {
                    inject_loss(3);
                    let _ = device.step(None);
                    Ok(())
                }
                Callback::SetUnauthorized(authority) => {
                    let mut peer = station(PEER, 7, true);
                    peer.authorized = Some(false);
                    run(device.set_station_async(&authority, peer), service)
                        .and_then(|r| r.map_err(|_| "AP callback native SET authorization"))
                }
            };
            if let Err(error) = result {
                *self.callback_error.lock() = Some(error);
                return false;
            }
        }
        self.owner.observe().current()
    }
    fn native_source(&self) -> Option<narf_net::native_emission::Lifetime> {
        Some(self.owner.observe())
    }
    fn deliver(&self, message: Vec<u8>) -> Result<(), i32> {
        if !self.current() {
            return Err(125);
        }
        self.messages.lock().push(message);
        Ok(())
    }
}
struct Fixture {
    guard: Box<Guard>,
    source: Arc<Source>,
    admin: narf_net::AdminHandle,
    daemon: Cap<narf_net::StackDaemon, Invoke>,
}
impl Fixture {
    fn new(
        api89: Option<gen3_station_tests::Case>,
        bz: Option<super::super::super::bz_fixture::Case>,
    ) -> R<Self> {
        Self::new_role(api89, bz, false)
    }
    fn new_role(
        api89: Option<gen3_station_tests::Case>,
        bz: Option<super::super::super::bz_fixture::Case>,
        client: bool,
    ) -> R<Self> {
        let guard = Box::new(Guard::build_native_profile(
            client,
            Fault::None,
            None,
            None,
            None,
            NativeModel {
                receive_model: if client {
                    ReceiveModel::Client
                } else {
                    ReceiveModel::Ap
                },
                tx_model: None,
                api89,
                bz,
                six: None,
            },
        )?);
        let device = guard.device();
        narf_net::iface::set_link_state(device.name(), false);
        device
            .set_iftype(if client { 8 } else { 3 })
            .map_err(|_| "AP/client actual mode switch")?;
        let iface = narf_net::registry()
            .register(
                &narf_net::bootstrap_authority(),
                RegisteredDevice(device.clone()),
            )
            .map_err(|_| "AP actual typed registration")?;
        let daemon = Cap::<narf_net::StackDaemon, Invoke>::bootstrap();
        let admin = narf_net::stack::control_registered(&narf_net::StackAttach { iface, daemon })
            .map_err(|_| "AP actual delegated control")?
            .admin;
        narf_wireless::registry::register(device.clone());
        admin
            .set_link(true)
            .map_err(|_| "AP actual administrative UP")?;
        Ok(Self {
            guard,
            source: Arc::new(Source::new()),
            admin,
            daemon,
        })
    }
    fn device(&self) -> &Arc<Device> {
        self.guard.device()
    }
    fn authority(&self) -> R<ApControlAuthority> {
        let iface: Arc<dyn WirelessNetIface> = self.device().clone();
        let link = narf_net::iface::lookup(self.device().name()).ok_or("AP netdev disappeared")?;
        ApControlAuthority::bind(
            self.admin.clone(),
            &iface,
            0,
            link.ifindex,
            self.source.clone(),
        )
        .and_then(ApControlAuthority::reserve)
        .map_err(|_| "AP exact current request/reservation")
    }
    fn start(&self, secure: bool) -> R {
        let (config, settings) = config(secure);
        let authority = self.authority()?;
        run(
            self.device()
                .start_ap_with_settings_async(&authority, config, settings),
            service,
        )?
        .map_err(|_| "AP native START receipts")?;
        require(
            self.device().link_up(),
            "AP carrier before actual native beacon receipt",
        )
    }
    fn add(&self, mac: [u8; 6], aid: u16, secure: bool) -> R {
        let authority = self.authority()?;
        run(
            self.device()
                .add_station_async(&authority, station(mac, aid, secure)),
            service,
        )?
        .map_err(|_| "AP native client receipts")
    }
    fn key(&self, id: u8, pairwise: bool, peer: Option<[u8; 6]>, bytes: [u8; 16]) -> R {
        let authority = self.authority()?;
        let key = narf_wireless::OwnedKey::new(narf_wireless::KeyParams {
            idx: id,
            pairwise,
            peer,
            cipher: if id >= 4 {
                narf_wireless::CIPHER_SUITE_AES_CMAC
            } else {
                narf_wireless::CIPHER_SUITE_CCMP
            },
            key: bytes.to_vec(),
            seq: Vec::new(),
            default_mgmt: id >= 4,
        });
        run(self.device().add_key_ap_async(&authority, key), service)?
            .map_err(|_| "AP exact native key receipt")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // Actual stop path is independently exercised below. This is only
        // teardown of an unarmed RAM fixture, never a physical DMA release.
        narf_wireless::registry::unregister(self.device().name());
        narf_net::registry().unregister(self.device().name());
        if let Some(mut state) = self.device().state.try_lock() {
            self.device().retire_ap(&mut state);
        }
    }
}
fn config(secure: bool) -> (narf_wireless::ApConfig, narf_wireless::ApStartSettings) {
    let mut beacon = vec![0; 36];
    beacon[0] = 0x80;
    beacon[4..10].fill(255);
    beacon[10..16].copy_from_slice(&OWN);
    beacon[16..22].copy_from_slice(&OWN);
    beacon[34..36].copy_from_slice(&(1u16 | if secure { 0x10 } else { 0 }).to_le_bytes());
    beacon.extend_from_slice(&[
        0, 4, b'n', b'a', b'r', b'f', 1, 4, 0x82, 0x84, 0x8b, 0x96, 3, 1, 6,
    ]);
    if secure {
        let mut rsn = narf_wireless::rsn::RsnIe::wpa2_psk_ccmp();
        rsn.rsn_capabilities = 0xc0;
        rsn.group_management_cipher = Some(narf_wireless::rsn::Suite::standard(6));
        let body = rsn.encode_body();
        beacon.extend_from_slice(&[48, body.len() as u8]);
        beacon.extend_from_slice(&body);
    }
    let config = narf_wireless::ApConfig {
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
    };
    let mut settings = narf_wireless::ApStartSettings::default();
    if secure {
        settings.control_port = narf_wireless::ControlPort {
            enabled: true,
            ethertype: 0x888e,
            no_encrypt: false,
            over_nl80211: true,
            no_preauth: false,
        };
    }
    (config, settings)
}
fn station(mac: [u8; 6], aid: u16, secure: bool) -> narf_wireless::StationConfig {
    narf_wireless::StationConfig {
        mac,
        aid,
        listen_interval: 10,
        supported_rates: vec![2, 4, 11, 22],
        wme: Some(true),
        mfp: Some(secure),
        uapsd_queues: Some(1),
        uapsd_max_sp: Some(1),
        ht_capability: None,
        vht_capability: None,
        he_capability: None,
        he_6ghz_capability: None,
        authorized: Some(!secure),
        station_tx_power: None,
        capability: None,
        ext_capability: None,
    }
}

fn ethernet(destination: [u8; 6], kind: u16) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&destination);
    bytes.extend_from_slice(&OWN);
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(b"native AP owner");
    bytes
}
fn inject_uplink(
    pn: u64,
    encrypted: bool,
    integrity: bool,
    station: u8,
    band: u8,
    kind: u16,
) -> R<Vec<u8>> {
    let mut frame = vec![0; 24];
    frame[0] = 8;
    frame[1] = 1 | if encrypted { 0x40 } else { 0 };
    frame[4..10].copy_from_slice(&OWN);
    frame[10..16].copy_from_slice(&PEER);
    frame[16..22].copy_from_slice(&OWN);
    if encrypted {
        frame.extend_from_slice(&narf_wireless::ccmp::build_ccmp_header(pn, 0));
    }
    frame.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
    frame.extend_from_slice(&kind.to_be_bytes());
    frame.extend_from_slice(b"native AP uplink");
    let mut envelope = vec![0; 64];
    envelope[..2].copy_from_slice(&(frame.len() as u16).to_le_bytes());
    let status = 3u32
        | 4
        | (u32::from(station) << 24)
        | if encrypted {
            if integrity {
                0x240
            } else {
                0x40
            }
        } else {
            0
        };
    envelope[12..16].copy_from_slice(&status.to_le_bytes());
    envelope[7] = band << 6;
    envelope[40] = 40;
    envelope[42] = 6;
    envelope.extend_from_slice(&frame);
    HARNESS
        .lock()
        .as_mut()
        .unwrap()
        .1
        .firmware
        .inject(0xc1, 0, 0x8000, &envelope);
    let mut output = Vec::new();
    output.extend_from_slice(&OWN);
    output.extend_from_slice(&PEER);
    output.extend_from_slice(&kind.to_be_bytes());
    output.extend_from_slice(b"native AP uplink");
    Ok(output)
}
fn observed_data() -> usize {
    HARNESS
        .lock()
        .as_ref()
        .unwrap()
        .1
        .native_ap
        .as_ref()
        .unwrap()
        .tx
        .iter()
        .filter(|(_, frame, _)| {
            frame[0] & 12 == 8
                && frame.get(if frame[0] == 0x88 { 32..34 } else { 30..32 }) != Some(&[0x88, 0x8e])
        })
        .count()
}
fn authorize(f: &Fixture) -> R {
    let authority = f.authority()?;
    let mut peer = station(PEER, 7, true);
    peer.authorized = Some(true);
    run(f.device().set_station_async(&authority, peer), service)?
        .map_err(|_| "AP authorized port lacks exact keys")
}
fn secure(f: &Fixture) -> R {
    f.start(true)?;
    f.add(PEER, 7, true)?;
    f.key(0, true, Some(PEER), TK)?;
    f.key(1, false, None, GTK)?;
    f.key(4, false, None, IGTK)?;
    let authority = f.authority()?;
    run(
        f.device()
            .default_key_ap_async(&authority, 1, false, true, false, false),
        service,
    )?
    .map_err(|_| "AP default GTK selection")?;
    drop(authority);
    authorize(f)
}

#[inline(never)]
fn deleted_defaults(f: &Fixture, received: &[u8]) -> R {
    for (id, management) in [(1, false), (4, true)] {
        {
            let authority = f.authority()?;
            run(
                f.device().del_key_ap_async(&authority, id, false, None),
                service,
            )?
            .map_err(|_| "AP actual group delete receipt")?;
        }
        let commands = HARNESS.lock().as_ref().unwrap().1.commands.len();
        {
            let authority = f.authority()?;
            require(
                run(
                    f.device().default_key_ap_async(
                        &authority,
                        id,
                        false,
                        !management,
                        management,
                        false,
                    ),
                    service,
                )?
                .is_err(),
                "AP deleted group regained default authority without an installed owner",
            )?;
        }
        require(
            authorize(f).is_err() && HARNESS.lock().as_ref().unwrap().1.commands.len() == commands,
            "AP deleted default authorized a peer or published native state",
        )?;
        if management {
            let mut frame = vec![0; 26];
            frame[0] = 0xc0;
            frame[4..10].fill(255);
            frame[10..16].copy_from_slice(&OWN);
            frame[16..22].copy_from_slice(&OWN);
            frame[24] = 3;
            let authority = f.authority()?;
            require(
                run(
                    f.device().mgmt_tx_ap_async(
                        &authority,
                        18,
                        narf_wireless::MgmtTxRequest {
                            frame,
                            frequency_mhz: 2437,
                            offchannel_ok: false,
                            duration: 0,
                            no_cck: false,
                        },
                    ),
                    service,
                )?
                .is_err()
                    && HARNESS.lock().as_ref().unwrap().1.commands.len() == commands,
                "AP removed IGTK still protected group management",
            )?;
        } else {
            let before = observed_data();
            f.device()
                .enqueue(&ethernet([255; 6], 0x88b5), narf_net::TxMeta::default())
                .map_err(|_| "AP missing GTK multicast queue admission")?;
            flush()?;
            require(
                observed_data() == before,
                "AP stale deleted GTK default emitted multicast DATA",
            )?;
        }
        // Deletion preserves the history that prevents native PN restart.
        require(
            f.key(id, false, None, if management { IGTK } else { GTK })
                .is_err(),
            "AP deleted group reused retired material and restarted native PN",
        )?;
        let replacement = if management { 5 } else { 2 };
        f.key(
            replacement,
            false,
            None,
            if management { [0x45; 16] } else { [0x44; 16] },
        )?;
        {
            let authority = f.authority()?;
            run(
                f.device().default_key_ap_async(
                    &authority,
                    replacement,
                    false,
                    !management,
                    management,
                    false,
                ),
                service,
            )?
            .map_err(|_| "AP fresh installed replacement default")?;
        }
        authorize(f)?;
        flush()?;
    }
    inject_uplink(10, true, true, 2, 1, 0x88b5)?;
    flush()?;
    let delivered = HARNESS
        .lock()
        .as_ref()
        .unwrap()
        .1
        .received
        .iter()
        .filter(|frame| frame.as_slice() == received)
        .count();
    require(
        delivered == 1,
        "AP group deletion/default replacement reset peer replay floor",
    )
}

fn preauth_tx(f: &Fixture, no_encrypt: bool) -> R<Result<bool, i32>> {
    let authority = f.authority()?;
    run(
        f.device().tx_control_port_ap_async(
            &authority,
            narf_wireless::ControlPortTxRequest::new(
                PEER,
                narf_wireless::ETH_P_PREAUTH,
                vec![2, 0, 0, 0],
                no_encrypt,
                true,
            ),
        ),
        service,
    )
}
#[inline(never)]
fn preauthentication_flow() -> R {
    for no_preauth in [false, true] {
        let f = Fixture::new(None, None)?;
        let (config, mut settings) = config(true);
        settings.control_port.no_encrypt = true; // EAPOL-specific only
        settings.control_port.no_preauth = no_preauth;
        {
            let authority = f.authority()?;
            run(
                f.device()
                    .start_ap_with_settings_async(&authority, config, settings),
                service,
            )?
            .map_err(|_| "AP preauth actual START")?;
        }
        f.add(PEER, 7, true)?;
        let tx_before = HARNESS
            .lock()
            .as_ref()
            .unwrap()
            .1
            .native_ap
            .as_ref()
            .unwrap()
            .tx
            .len();
        for no_encrypt in [false, true] {
            require(
                preauth_tx(&f, no_encrypt)?.is_err(),
                "AP unkeyed unauthorized preauth inherited EAPOL exception",
            )?;
        }
        {
            let authority = f.authority()?;
            require(
                run(
                    f.device().tx_control_port_ap_async(
                        &authority,
                        narf_wireless::ControlPortTxRequest::new(
                            PEER,
                            0x888e,
                            vec![2, 0, 0, 0],
                            false,
                            true,
                        ),
                    ),
                    service,
                )? == Ok(true),
                "AP configured EAPOL plaintext exception disappeared",
            )?;
        }
        {
            let slot = HARNESS.lock();
            let model = slot.as_ref().unwrap().1.native_ap.as_ref().unwrap();
            require(
                model.tx.len() == tx_before + 1 && !model.tx.last().unwrap().2,
                "AP unauthorized preauth emitted or configured EAPOL was encrypted",
            )?;
        }
        f.key(0, true, Some(PEER), TK)?;
        f.key(1, false, None, GTK)?;
        f.key(4, false, None, IGTK)?;
        {
            let authority = f.authority()?;
            run(
                f.device()
                    .default_key_ap_async(&authority, 1, false, true, false, false),
                service,
            )?
            .map_err(|_| "AP preauth actual default GTK")?;
        }
        require(
            preauth_tx(&f, false)?.is_err() && preauth_tx(&f, true)?.is_err(),
            "AP preauth key receipts bypassed ordinary peer authorization",
        )?;
        let input = inject_uplink(5, true, true, 2, 1, narf_wireless::ETH_P_PREAUTH)?;
        flush()?;
        let before_authorization = {
            let slot = HARNESS.lock();
            !slot.as_ref().unwrap().1.received.contains(&input)
                && !f
                    .source
                    .messages
                    .lock()
                    .iter()
                    .any(|message| message[16] == 129)
        };
        require(
            before_authorization,
            "AP preauth RX bypassed unauthorized ordinary port",
        )?;
        let before_epoch = f
            .device()
            .state
            .try_lock()
            .unwrap()
            .hardware
            .receive_publication()
            .ok_or("AP unauthorized native capture epoch absent")?;
        // Leave this real RFH descriptor queued. STA/TLC command polling must
        // not reinterpret it under the authorization granted by those waits.
        inject_uplink(5, true, true, 2, 1, narf_wireless::ETH_P_PREAUTH)?;
        authorize(&f)?;
        flush()?;
        let crossed_authorization = {
            let on_netdev = HARNESS.lock().as_ref().unwrap().1.received.contains(&input);
            let on_control = f
                .source
                .messages
                .lock()
                .iter()
                .any(|message| message[16] == 129);
            on_netdev || on_control
        };
        require(
            !before_epoch.current() && !crossed_authorization,
            "AP queued preauthorization RFH crossed actual port transition",
        )?;
        require(
            preauth_tx(&f, false)? == Ok(true),
            "AP authorized encrypted preauth reply absent",
        )?;
        require(
            preauth_tx(&f, true)? == Ok(true),
            "AP authorized explicit plaintext preauth absent",
        )?;
        {
            let slot = HARNESS.lock();
            let tx = &slot.as_ref().unwrap().1.native_ap.as_ref().unwrap().tx;
            let encrypted = &tx[tx.len() - 2];
            let plaintext = &tx[tx.len() - 1];
            require(
                encrypted.0 == 2
                    && encrypted.2
                    && encrypted.1[1] & 0x40 != 0
                    && plaintext.0 == 2
                    && !plaintext.2
                    && plaintext.1[1] & 0x40 == 0,
                "AP preauth inherited configured EAPOL no_encrypt or ignored own TX request",
            )?;
        }
        let before = observed_data();
        f.device()
            .enqueue(
                &ethernet(PEER, narf_wireless::ETH_P_PREAUTH),
                narf_net::TxMeta::default(),
            )
            .map_err(|_| "AP authorized ordinary preauth enqueue")?;
        flush()?;
        require(
            observed_data() == before + 1,
            "AP RX no_preauth flag incorrectly blocked normal preauth TX",
        )?;
        inject_uplink(5, false, true, 2, 1, narf_wireless::ETH_P_PREAUTH)?;
        flush()?;
        let plaintext_refused = !HARNESS.lock().as_ref().unwrap().1.received.contains(&input)
            && !f
                .source
                .messages
                .lock()
                .iter()
                .any(|message| message[16] == 129);
        require(
            plaintext_refused,
            "AP preauth RX inherited EAPOL plaintext exception",
        )?;
        inject_uplink(5, true, true, 2, 1, narf_wireless::ETH_P_PREAUTH)?;
        flush()?;
        let on_netdev = HARNESS.lock().as_ref().unwrap().1.received.contains(&input);
        let on_control = f
            .source
            .messages
            .lock()
            .iter()
            .any(|message| message[16] == 129);
        require(
            on_netdev == no_preauth && on_control != no_preauth,
            "AP preauth RX endpoint, normal crypto or same-PN authorization admission invalid",
        )?;
        authorization_copy_epoch(&f)?;
        native_loss_epoch(&f)?;
        if !no_preauth {
            late_event_callbacks(&f)?;
        }
    }
    Ok(())
}

#[inline(never)]
fn authorization_copy_epoch(f: &Fixture) -> R {
    let key_receipts = || {
        HARNESS
            .lock()
            .as_ref()
            .unwrap()
            .1
            .commands
            .iter()
            .filter(|(group, command, _)| (*group, *command) == (5, 0x18))
            .count()
    };
    let before_keys = key_receipts();
    inject_uplink(6, true, true, 2, 1, 0x88b5)?;
    let copied = f.device().step(None);
    require(
        copied.len() == 1 && copied[0].current(),
        "AP authorization fixture lacks actual copied RFH DATA",
    )?;
    {
        let authority = f.authority()?;
        let mut peer = station(PEER, 7, true);
        peer.authorized = Some(false);
        run(f.device().set_station_async(&authority, peer), service)?
            .map_err(|_| "AP actual deauthorization transition")?;
    }
    let mut callbacks = 0;
    f.device().dispatch_with(copied, |_| callbacks += 1);
    let old_ipc = f
        .device()
        .rx
        .lock()
        .as_mut()
        .and_then(|rx| rx.try_recv().ok().flatten());
    require(
        callbacks == 0 && old_ipc.is_none(),
        "AP deauthorization retained copied publication or queued IPC DATA",
    )?;
    authorize(f)?;
    inject_uplink(6, true, true, 2, 1, 0x88b5)?;
    let replay = f.device().step(None);
    inject_uplink(7, true, true, 2, 1, 0x88b5)?;
    let fresh = f.device().step(None);
    require(
        replay.is_empty() && fresh.len() == 1 && key_receipts() == before_keys,
        "AP authorization transition reset peer PN or replaced installed key receipts",
    )
}

fn inject_loss(pn: u64) {
    let mut frame = vec![0; 24];
    frame[0] = 0xc0;
    frame[1] = 0x40;
    frame[4..10].copy_from_slice(&OWN);
    frame[10..16].copy_from_slice(&PEER);
    frame[16..22].copy_from_slice(&OWN);
    frame.extend_from_slice(&narf_wireless::ccmp::build_ccmp_header(pn, 0));
    frame.extend_from_slice(&[3, 0]);
    let mut envelope = vec![0; 64];
    envelope[..2].copy_from_slice(&(frame.len() as u16).to_le_bytes());
    envelope[7] = 1 << 6;
    envelope[12..16].copy_from_slice(&(3u32 | 4 | 0x240 | (2 << 24)).to_le_bytes());
    envelope[40] = 40;
    envelope[42] = 6;
    envelope.extend_from_slice(&frame);
    HARNESS
        .lock()
        .as_mut()
        .unwrap()
        .1
        .firmware
        .inject(0xc1, 0, 0x8000, &envelope);
}

#[inline(never)]
fn native_loss_epoch(f: &Fixture) -> R {
    {
        let authority = f.authority()?;
        run(
            f.device()
                .register_mgmt_frame_ap_async(&authority, 0xc0, vec![3, 0]),
            service,
        )?
        .map_err(|_| "AP native peer-loss event registration")?;
    }
    let before_events = f.source.messages.lock().len();
    let before_receive = f
        .device()
        .state
        .try_lock()
        .unwrap()
        .hardware
        .receive_publication()
        .ok_or("AP native loss lacks original receive proof")?;
    inject_uplink(8, true, true, 2, 1, 0x88b5)?;
    let copied = f.device().step(None);
    require(copied.len() == 1, "AP native loss lacks copied DATA")?;
    // All three physical descriptors are processed by one ordinary poll.
    // Both prior DATA and routed preauth must be denied; the actual protected
    // management loss notification must still reach its registered SME.
    inject_uplink(9, true, true, 2, 1, 0x88b5)?;
    inject_uplink(10, true, true, 2, 1, narf_wireless::ETH_P_PREAUTH)?;
    inject_loss(1);
    let same_drain = f.device().step(None);
    let mut callbacks = 0;
    f.device().dispatch_with(copied, |_| callbacks += 1);
    let old_ipc = f
        .device()
        .rx
        .lock()
        .as_mut()
        .and_then(|rx| rx.try_recv().ok().flatten());
    let loss_event = {
        let messages = f.source.messages.lock();
        messages.len() == before_events + 1 && messages.last().is_some_and(|m| m[16] == 59)
    };
    require(
        same_drain.is_empty()
            && callbacks == 0
            && old_ipc.is_none()
            && loss_event
            && before_receive.current()
            && f.device().link_up(),
        "AP native loss retained DATA/IPC/preauth or lost genuine management/carrier/key proof",
    )?;
    inject_uplink(11, true, true, 2, 1, 0x88b5)?;
    let without_authorization = f.device().step(None);
    require(
        without_authorization.is_empty(),
        "AP DATA crossed native-lost peer authorization",
    )?;
    inject_uplink(11, true, true, 2, 1, 0x88b5)?;
    authorize(f)?;
    let prefix = f.device().step(None);
    inject_uplink(10, true, true, 2, 1, 0x88b5)?;
    let old_replay = f.device().step(None);
    inject_uplink(11, true, true, 2, 1, 0x88b5)?;
    let fresh = f.device().step(None);
    inject_uplink(11, true, true, 2, 1, 0x88b5)?;
    let replay = f.device().step(None);
    require(
        prefix.is_empty()
            && old_replay.is_empty()
            && fresh.len() == 1
            && replay.is_empty()
            && f.device().link_up(),
        "AP native loss reauthorization skipped actual prefix or reset accepted replay floor",
    )?;
    let before_replay = f.source.messages.lock().len();
    inject_loss(1);
    let _ = f.device().step(None);
    inject_uplink(12, true, true, 2, 1, 0x88b5)?;
    let still_authorized = f.device().step(None);
    let management_replayed = f.source.messages.lock().len() != before_replay;
    require(
        !management_replayed && still_authorized.len() == 1,
        "AP native loss reset management replay floor or replayed loss revoked current port",
    )?;
    inject_loss(2);
    let _ = f.device().step(None);
    // Fresh PTK material after loss must not restore a stale configured
    // authorization flag. Only a new explicit SET and physical prefix may.
    f.key(0, true, Some(PEER), [0x39; 16])?;
    inject_uplink(13, true, true, 2, 1, 0x88b5)?;
    let without_authorization = f.device().step(None);
    require(
        without_authorization.is_empty(),
        "AP PTK replacement resurrected native-lost peer authorization",
    )?;
    inject_uplink(13, true, true, 2, 1, 0x88b5)?;
    authorize(f)?;
    let prefix = f.device().step(None);
    inject_uplink(13, true, true, 2, 1, 0x88b5)?;
    let fresh = f.device().step(None);
    require(
        prefix.is_empty() && fresh.len() == 1,
        "AP fresh PTK authorization lacked actual prefix/current PN admission",
    )?;
    {
        let authority = f.authority()?;
        run(
            f.device().del_key_ap_async(&authority, 0, true, Some(PEER)),
            service,
        )?
        .map_err(|_| "AP native exact PTK deletion")?;
    }
    f.key(0, true, Some(PEER), [0x3a; 16])?;
    inject_uplink(14, true, true, 2, 1, 0x88b5)?;
    let after_deleted_ptk = f.device().step(None);
    require(
        after_deleted_ptk.is_empty(),
        "AP fresh PTK after DEL_KEY restored stale configured authorization",
    )?;
    authorize(f)?;
    inject_uplink(14, true, true, 2, 1, 0x88b5)?;
    require(
        f.device().step(None).len() == 1,
        "AP explicit authorization after fresh PTK/DEL_KEY lost current DATA",
    )
}

fn inject_action() {
    let mut frame = vec![0; 26];
    frame[0] = 0xd0;
    frame[4..10].copy_from_slice(&OWN);
    frame[10..16].copy_from_slice(&PEER);
    frame[16..22].copy_from_slice(&OWN);
    frame[24..].copy_from_slice(&[4, 9]); // genuine nonrobust Public Action
    let mut envelope = vec![0; 64];
    envelope[..2].copy_from_slice(&(frame.len() as u16).to_le_bytes());
    envelope[7] = 1 << 6;
    envelope[12..16].copy_from_slice(&(3u32 | 4 | (2 << 24)).to_le_bytes());
    envelope[40] = 40;
    envelope[42] = 6;
    envelope.extend_from_slice(&frame);
    HARNESS
        .lock()
        .as_mut()
        .unwrap()
        .1
        .firmware
        .inject(0xc1, 0, 0x8000, &envelope);
}

#[inline(never)]
fn late_event_callbacks(f: &Fixture) -> R {
    let before = f.source.messages.lock().len();
    inject_uplink(15, true, true, 2, 1, narf_wireless::ETH_P_PREAUTH)?;
    let mut captured = f.device().step_owned(None);
    require(
        captured.data.is_empty() && captured.ap.len() == 1,
        "AP late callback fixture lacks actual copied preauth event",
    )?;
    *f.source.callback.lock() = Some(Callback::NativeLoss);
    captured.ap.pop().unwrap().publish();
    let messages = f.source.messages.lock();
    let denied = messages.len() == before + 1 && messages.last().is_some_and(|m| m[16] == 59);
    drop(messages);
    let callback_error = *f.source.callback_error.lock();
    require(
        denied && callback_error.is_none() && f.device().link_up(),
        "AP preauth survived real native loss inside late source callback or lost management/carrier",
    )?;
    authorize(f)?;
    {
        let authority = f.authority()?;
        run(
            f.device()
                .register_mgmt_frame_ap_async(&authority, 0xd0, vec![4, 9]),
            service,
        )?
        .map_err(|_| "AP late management callback registration")?;
    }
    inject_action();
    let mut captured = f.device().step_owned(None);
    require(
        captured.data.is_empty() && captured.ap.len() == 1,
        "AP late callback fixture lacks actual copied management event",
    )?;
    let before = f.source.messages.lock().len();
    let authority = f.authority()?;
    *f.source.callback.lock() = Some(Callback::SetUnauthorized(Box::new(authority)));
    captured.ap.pop().unwrap().publish();
    let denied = f.source.messages.lock().len() == before;
    let callback_error = *f.source.callback_error.lock();
    require(
        denied && callback_error.is_none() && f.device().link_up(),
        "AP management survived real receive-prefix transition inside late source callback",
    )?;
    // DATA is still denied, but a genuine current management observation must
    // not inherit that port denial or lose its original typed source route.
    inject_action();
    let _ = f.device().step(None);
    let messages = f.source.messages.lock();
    require(
        messages.len() == before + 1 && messages.last().is_some_and(|m| m[16] == 59),
        "AP prepared event suppressed genuine current management after DATA denial",
    )
}

fn smoke_iwl_native_ap_secure_ports_native_key_roles_replay_and_pmf_bip() -> TestResult {
    check(|| {
        let f = Fixture::new(None, None)?;
        f.start(true)?;
        f.add(PEER, 7, true)?;
        let bytes = ethernet(PEER, 0x88b5);
        f.device()
            .enqueue(&bytes, narf_net::TxMeta::default())
            .map_err(|_| "AP before-key queue admission")?;
        flush()?;
        require(
            observed_data() == 0,
            "AP unkeyed client ordinary TX escaped",
        )?;
        let early = inject_uplink(9, false, true, 2, 1, 0x888e)?;
        flush()?;
        require(
            !HARNESS.lock().as_ref().unwrap().1.received.contains(&early)
                && f.source
                    .messages
                    .lock()
                    .iter()
                    .any(|message| message[16] == 129),
            "AP EAPOL bypassed typed SME port or was lost before authorization",
        )?;
        {
            let authority = f.authority()?;
            let request = narf_wireless::ControlPortTxRequest::new(
                PEER,
                0x888e,
                vec![2, 0, 0, 0],
                true,
                true,
            );
            require(
                run(
                    f.device().tx_control_port_ap_async(&authority, request),
                    service,
                )? == Ok(true),
                "AP plaintext handshake control did not receive actual native ACK",
            )?;
        }
        f.key(0, true, Some(PEER), TK)?;
        f.key(1, false, None, GTK)?;
        f.key(4, false, None, IGTK)?;
        {
            let authority = f.authority()?;
            run(
                f.device()
                    .default_key_ap_async(&authority, 1, false, true, false, false),
                service,
            )?
            .map_err(|_| "AP actual default GTK")?;
        }
        authorize(&f)?;
        f.device()
            .enqueue(&bytes, narf_net::TxMeta::default())
            .map_err(|_| "AP authorized native TX queue")?;
        flush()?;
        require(
            observed_data() == 1,
            "AP exact native client-key DATA publication",
        )?;
        // Wrong physical STA, band, or native integrity cannot advance replay.
        inject_uplink(500, true, true, 3, 1, 0x88b5)?;
        inject_uplink(500, true, true, 2, 0, 0x88b5)?;
        inject_uplink(500, true, false, 2, 1, 0x88b5)?;
        flush()?;
        let received = inject_uplink(10, true, true, 2, 1, 0x88b5)?;
        flush()?;
        inject_uplink(10, true, true, 2, 1, 0x88b5)?;
        flush()?;
        require(
            HARNESS
                .lock()
                .as_ref()
                .unwrap()
                .1
                .received
                .iter()
                .filter(|frame| **frame == received)
                .count()
                == 1,
            "AP invalid native provenance advanced PN or accepted replay",
        )?;
        {
            let authority = f.authority()?;
            let mut frame = vec![0; 26];
            frame[0] = 0xc0;
            frame[4..10].fill(255);
            frame[10..16].copy_from_slice(&OWN);
            frame[16..22].copy_from_slice(&OWN);
            frame[24] = 3;
            let request = narf_wireless::MgmtTxRequest {
                frame,
                frequency_mhz: 2437,
                offchannel_ok: false,
                duration: 0,
                no_cck: false,
            };
            require(
                run(
                    f.device().mgmt_tx_ap_async(&authority, 17, request),
                    service,
                )? == Ok(false),
                "AP broadcast robust management falsely reported peer ACK",
            )?;
        }
        {
            let slot = HARNESS.lock();
            let model = slot.as_ref().unwrap().1.native_ap.as_ref().unwrap();
            require(
                model.tx.iter().any(|(station, frame, encrypt)| {
                    *station == 1 && frame[0] == 0xc0 && frame[1] & 0x40 == 0 && *encrypt
                }),
                "AP BIP clear Protected bit disabled actual installed IGTK encryption",
            )?;
        }
        // Same-key installation is receipt-idempotent and does not reset RX.
        let installs = HARNESS
            .lock()
            .as_ref()
            .unwrap()
            .1
            .commands
            .iter()
            .filter(|(g, c, _)| (*g, *c) == (5, 0x18))
            .count();
        f.key(0, true, Some(PEER), TK)?;
        require(
            HARNESS
                .lock()
                .as_ref()
                .unwrap()
                .1
                .commands
                .iter()
                .filter(|(g, c, _)| (*g, *c) == (5, 0x18))
                .count()
                == installs,
            "AP same-key retry reinstalled native material/reset nonce",
        )?;
        inject_uplink(10, true, true, 2, 1, 0x88b5)?;
        flush()?;
        require(
            HARNESS
                .lock()
                .as_ref()
                .unwrap()
                .1
                .received
                .iter()
                .filter(|frame| **frame == received)
                .count()
                == 1,
            "AP same-key retry reset accepted replay floor",
        )?;
        deleted_defaults(&f, &received)?;
        drop(f);
        preauthentication_flow()
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/ap",
    smoke_iwl_native_ap_secure_ports_native_key_roles_replay_and_pmf_bip
);

fn smoke_iwl_native_ap_active_source_revocation_and_malformed_flush_keep_dma_owned() -> TestResult {
    check(|| {
        for boundary in 0..4 {
            let f = Fixture::new(None, None)?;
            secure(&f)?;
            let bytes = ethernet(PEER, 0x88b5);
            let before = observed_data();
            let addresses = {
                let state = f.device().state.try_lock().ok_or("AP native DMA State")?;
                model::queue_dma_addresses(&state.hardware, 3).ok_or("AP actual peer queue DMA")?
            };
            match boundary {
                0 => f.source.owner.retire().notify(),
                1 => f.daemon.revoke(),
                2 => {
                    f.admin
                        .set_link(false)
                        .map_err(|_| "AP actual admin DOWN")?;
                    narf_net::iface::set_link_state(f.device().name(), true);
                }
                _ => {
                    HARNESS
                        .lock()
                        .as_mut()
                        .unwrap()
                        .1
                        .native_ap
                        .as_mut()
                        .unwrap()
                        .malformed_flush = true;
                    let authority = f.authority()?;
                    require(
                        run(
                            f.device().del_station_async(&authority, Some(PEER), 3),
                            service,
                        )?
                        .is_err(),
                        "AP malformed flush became peer/DMA retirement success",
                    )?;
                }
            }
            let _ = f.device().enqueue(&bytes, narf_net::TxMeta::default());
            for _ in 0..16 {
                let _ = f.device().step(None);
                service()?;
            }
            let state = f
                .device()
                .state
                .try_lock()
                .ok_or("AP physical cleanup owner pending")?;
            require(!f.device().link_up() && state.stop_completed && state.ap.is_none()
                && model::queue_dma_addresses(&state.hardware,3)==Some(addresses) && observed_data()==before,
                "AP retired authority/invalid flush leaked DATA or released native DMA before restart")?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/ap",
    smoke_iwl_native_ap_active_source_revocation_and_malformed_flush_keep_dma_owned
);

#[inline(never)]
fn add_open_with_prefix(f: &Fixture) -> R {
    let before_epoch = f
        .device()
        .state
        .try_lock()
        .unwrap()
        .hardware
        .receive_publication()
        .ok_or("AP pre-ADD native capture epoch absent")?;
    HARNESS
        .lock()
        .as_mut()
        .unwrap()
        .1
        .native_ap
        .as_mut()
        .unwrap()
        .hold = Some((5, 0xf));
    let authority = f.authority()?;
    let mut future = Box::pin(
        f.device()
            .add_station_async(&authority, station(PEER, 7, false)),
    );
    let mut cx = Context::from_waker(Waker::noop());
    run(
        core::future::poll_fn(|_| {
            let _ = future.as_mut().poll(&mut cx);
            let held = HARNESS
                .lock()
                .as_ref()
                .unwrap()
                .1
                .native_ap
                .as_ref()
                .unwrap()
                .held
                .is_some();
            if held {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }),
        service,
    )?;
    // The actual native STA and queues now exist, but the held TLC receipt
    // prevents host admission. Queue valid-STA DATA without a preflush.
    let input = inject_uplink(0, false, true, 2, 1, 0x88b5)?;
    {
        let mut slot = HARNESS.lock();
        let wire = &mut slot.as_mut().unwrap().1;
        let ap = wire.native_ap.as_mut().unwrap();
        ap.hold = None;
        let response = ap.held.take().ok_or("AP held Open peer TLC receipt")?;
        let (cmd, group, sequence) = wire
            .held
            .take()
            .ok_or("AP held Open TLC command identity")?;
        wire.firmware.inject(cmd, group, sequence, &response);
    }
    run(future, service)?.map_err(|_| "AP native client receipts")?;
    flush()?;
    let crossed_add = HARNESS.lock().as_ref().unwrap().1.received.contains(&input);
    require(
        !before_epoch.current() && !crossed_add,
        "AP initially authorized ADD adopted pre-admission RFH DATA",
    )?;
    inject_uplink(0, false, true, 2, 1, 0x88b5)?;
    flush()?;
    let current = HARNESS.lock().as_ref().unwrap().1.received.contains(&input);
    require(current, "AP current authorized Open peer lost native DATA")
}

fn smoke_iwl_native_ap_sc_api89_bz_beacon_multi_peer_receipts_and_stop() -> TestResult {
    check(|| {
        for (api89, bz) in [
            (None, None),
            (Some(gen3_station_tests::Case::Ty), None),
            (Some(gen3_station_tests::Case::So), None),
            (
                None,
                Some(super::super::super::bz_fixture::Case::FmDiscrete),
            ),
        ] {
            let f = Fixture::new(api89, bz)?;
            f.start(false)?;
            let receive_queues = f
                .device()
                .state
                .try_lock()
                .ok_or("AP profile retained State after START")?
                .hardware
                .receive_queue_count();
            let additional = HARNESS.lock().as_ref().unwrap().1.rx_queues.len();
            require(
                (receive_queues, additional)
                    == if api89.is_some() || bz.is_some() {
                        (3, 2)
                    } else {
                        (1, 0)
                    },
                "AP original profile lost actual RFH/RSS allocation receipts",
            )?;
            add_open_with_prefix(&f)?;
            f.add([2, 0x74, 2, 3, 4, 5], 8, false)?;
            {
                let slot = HARNESS.lock();
                let m = slot.as_ref().unwrap().1.native_ap.as_ref().unwrap();
                require(
                    m.beacon
                        && m.peers.len() == 4
                        && m.queues.iter().filter(|q| q.live).count() == 12,
                    "AP failed distinct two internal/two client stations and native queues",
                )?;
            }
            let authority = f.authority()?;
            run(f.device().stop_ap_async(&authority), service)?
                .map_err(|_| "AP physical stop completion")?;
            let state = f
                .device()
                .state
                .try_lock()
                .ok_or("AP retained State after stop")?;
            require(
                !f.device().link_up()
                    && state.ap.is_none()
                    && state.stop_completed
                    && state.hardware.is_failed(),
                "AP STOP did not retire beacon/data/transport owner",
            )?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/ap",
    smoke_iwl_native_ap_sc_api89_bz_beacon_multi_peer_receipts_and_stop
);

fn smoke_iwl_native_ap_held_beacon_source_and_dropped_waiter_retire_without_new_emission(
) -> TestResult {
    check(|| {
        for drop_waiter in [false, true] {
            let f = Fixture::new(None, None)?;
            HARNESS
                .lock()
                .as_mut()
                .unwrap()
                .1
                .native_ap
                .as_mut()
                .unwrap()
                .hold = Some((1, 0x91));
            let (cfg, settings) = config(false);
            let authority = f.authority()?;
            let mut future = Box::pin(
                f.device()
                    .start_ap_with_settings_async(&authority, cfg, settings),
            );
            let mut cx = Context::from_waker(Waker::noop());
            run(
                core::future::poll_fn(|_| {
                    let _ = future.as_mut().poll(&mut cx);
                    let held = HARNESS.lock().as_ref().unwrap().1.held.is_some();
                    if held {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                }),
                service,
            )?;
            let held = HARNESS.lock().as_ref().unwrap().1.held.is_some();
            require(
                held && !f.device().link_up(),
                "AP held actual beacon receipt did not hold carrier",
            )?;
            if drop_waiter {
                drop(future);
                run(
                    core::future::poll_fn(|_| {
                        let _ = f.device().step(None);
                        let stopped = f
                            .device()
                            .state
                            .try_lock()
                            .is_some_and(|state| state.stop_completed);
                        if stopped {
                            Poll::Ready(())
                        } else {
                            Poll::Pending
                        }
                    }),
                    service,
                )?;
            } else {
                f.source.owner.retire().notify();
                require(
                    run(future, service)?.is_err(),
                    "AP closed source produced START success",
                )?;
            }
            let state = f
                .device()
                .state
                .try_lock()
                .ok_or("AP dropped waiter released unresolved native owner")?;
            require(
                state.stop_completed && state.ap.is_none() && !f.device().link_up(),
                "AP cancelled/closed source did not physically retire held beacon owner",
            )?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/ap",
    smoke_iwl_native_ap_held_beacon_source_and_dropped_waiter_retire_without_new_emission
);

fn smoke_iwl_native_ap_early_group_metadata_needs_original_sources_and_key_receipts_before_beacon(
) -> TestResult {
    check(|| {
        for revoke in [false, true] {
            let mut f = Fixture::new(None, None)?;
            let original = f.source.clone();
            f.key(1, false, None, GTK)?;
            f.key(4, false, None, IGTK)?;
            {
                let authority = f.authority()?;
                run(
                    f.device()
                        .default_key_ap_async(&authority, 1, false, true, false, false),
                    service,
                )?
                .map_err(|_| "AP early default-choice metadata")?;
            }
            let native_keys = HARNESS
                .lock()
                .as_ref()
                .unwrap()
                .1
                .commands
                .iter()
                .filter(|(g, c, _)| (*g, *c) == (5, 0x18))
                .count();
            require(
                native_keys == 0 && !f.device().link_up(),
                "early AP metadata became an installed native key/carrier",
            )?;
            // START arrives on a distinct real delegated source. Earlier key
            // receipts must still name the original accepted source proof.
            f.source = Arc::new(Source::new());
            HARNESS
                .lock()
                .as_mut()
                .unwrap()
                .1
                .native_ap
                .as_mut()
                .unwrap()
                .hold = Some((5, 0x18));
            let (config, settings) = config(true);
            let authority = f.authority()?;
            let mut future = Box::pin(
                f.device()
                    .start_ap_with_settings_async(&authority, config, settings),
            );
            let mut cx = Context::from_waker(Waker::noop());
            run(
                core::future::poll_fn(|_| {
                    let _ = future.as_mut().poll(&mut cx);
                    let held = HARNESS.lock().as_ref().unwrap().1.held.is_some();
                    if held {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                }),
                service,
            )?;
            let beacon = HARNESS
                .lock()
                .as_ref()
                .unwrap()
                .1
                .native_ap
                .as_ref()
                .unwrap()
                .beacon;
            require(
                !beacon && !f.device().link_up(),
                "AP beacon escaped before actual early-group-key receipt",
            )?;
            if revoke {
                original.owner.retire().notify();
                require(
                    run(future, service)?.is_err(),
                    "new START source replaced a dead original early-key source",
                )?;
                let state = f
                    .device()
                    .state
                    .try_lock()
                    .ok_or("AP early-key physical cleanup owner")?;
                let stopped = state.stop_completed && state.ap.is_none();
                drop(state);
                let beacon = HARNESS
                    .lock()
                    .as_ref()
                    .unwrap()
                    .1
                    .native_ap
                    .as_ref()
                    .unwrap()
                    .beacon;
                require(
                    stopped && !beacon && !f.device().link_up(),
                    "revoked early-key owner leaked beacon or released cancellation cleanup",
                )?;
            } else {
                {
                    let mut slot = HARNESS.lock();
                    let wire = &mut slot.as_mut().unwrap().1;
                    wire.native_ap.as_mut().unwrap().hold = None;
                    let response = wire
                        .native_ap
                        .as_mut()
                        .unwrap()
                        .held
                        .take()
                        .ok_or("AP actual held key receipt")?;
                    let (cmd, group, seq) =
                        wire.held.take().ok_or("AP held key command identity")?;
                    wire.firmware.inject(cmd, group, seq, &response);
                }
                run(future, service)?
                    .map_err(|_| "AP early group keys did not finish native START")?;
                let state = f
                    .device()
                    .state
                    .try_lock()
                    .ok_or("AP early native default publication")?;
                let ap = state
                    .ap
                    .as_ref()
                    .ok_or("AP early-key role was not retained")?;
                let current = ap.current().is_ok();
                drop(state);
                require(
                    current && f.device().link_up(),
                    "AP early receipts did not publish current BSS",
                )?;
                let slot = HARNESS.lock();
                let commands = &slot.as_ref().unwrap().1.commands;
                let beacon = commands
                    .iter()
                    .position(|(g, c, _)| (*g, *c) == (1, 0x91))
                    .ok_or("AP native beacon absent")?;
                let keys: Vec<_> = commands
                    .iter()
                    .enumerate()
                    .filter(|(_, (g, c, _))| (*g, *c) == (5, 0x18))
                    .collect();
                require(
                    keys.len() == 2 && keys.iter().all(|(index, _)| *index < beacon),
                    "AP selected defaults or beacon before both actual early native key commands",
                )?;
            }
        }
        // Role replacement erases metadata instead of letting a same-name
        // station->AP successor inherit the old source's staged secrets.
        let f = Fixture::new(None, None)?;
        f.key(1, false, None, GTK)?;
        f.admin.set_link(false).map_err(|_| "AP early role DOWN")?;
        f.device()
            .set_iftype(2)
            .map_err(|_| "AP early role retirement")?;
        f.device()
            .set_iftype(3)
            .map_err(|_| "AP fresh role generation")?;
        f.admin
            .set_link(true)
            .map_err(|_| "AP fresh administrative UP")?;
        f.start(true)?;
        let keys = HARNESS
            .lock()
            .as_ref()
            .unwrap()
            .1
            .commands
            .iter()
            .filter(|(g, c, _)| (*g, *c) == (5, 0x18))
            .count();
        require(keys == 0, "AP mode ABA resurrected staged key bytes")?;
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/ap",
    smoke_iwl_native_ap_early_group_metadata_needs_original_sources_and_key_receipts_before_beacon
);
