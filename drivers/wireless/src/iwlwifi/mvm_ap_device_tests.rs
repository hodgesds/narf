//! Original API77 netdev AP conversations. The device side consumes only
//! posted TFH bytes/RFH buffers; it never reads Session or key/port booleans.
use super::*;
use narf_capabilities::Invoke;
use narf_net::netlink_generic::DeferredReplySink;
use narf_wireless::ap_control::ApControlAuthority;

const PEER: [u8; 6] = [2, 0x77, 1, 2, 3, 4];
const GTK: [u8; 16] = [0x71; 16];
const IGTK: [u8; 16] = [0x72; 16];
const TK: [u8; 16] = [0x73; 16];
fn word(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn half(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}
fn require(value: bool, reason: &'static str) -> Result<(), &'static str> {
    value.then_some(()).ok_or(reason)
}
pub(super) fn profile(image: &mut Vec<u8>, versions: &mut Vec<u8>) -> Result<(), &'static str> {
    let parsed = super::super::super::parse_ucode(image).map_err(|_| "API77 AP fixture image")?;
    let api = parsed.api.api_changes[0] | (1 << 30); // actual STA_TYPE
    let caps = parsed.api.capabilities[0] | (1 << 1); // actual LAR
    let mut changes = 0u32.to_le_bytes().to_vec();
    changes.extend_from_slice(&api.to_le_bytes());
    tlv(image, 29, &changes);
    let mut capabilities = 0u32.to_le_bytes().to_vec();
    capabilities.extend_from_slice(&caps.to_le_bytes());
    tlv(image, 30, &capabilities);
    for row in [
        [9, 3, 1, 0],
        [0x18, 5, 1, 0],
        [0x91, 1, 13, 0],
        [0x1e, 1, 2, 1],
    ] {
        versions.extend_from_slice(&row);
    }
    Ok(())
}
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
    keys: Vec<(u8, u8)>,
    beacon: bool,
    tx: Vec<(u8, Vec<u8>, bool)>,
    mcc_flags: u32,
}
impl Model {
    pub(super) fn new() -> Self {
        Self {
            started: false,
            queues: Vec::new(),
            peers: Vec::new(),
            keys: Vec::new(),
            beacon: false,
            tx: Vec::new(),
            mcc_flags: 0x109, // VALID | ACTIVE |20, deliberately NO IBSS
        }
    }
    pub(super) fn command(
        &mut self,
        group: u8,
        command: u8,
        b: &[u8],
    ) -> Result<Option<Vec<u8>>, &'static str> {
        if (group, command) == (1, 0xc8) {
            require(b.len() == 28, "AP actual MVM MCC request extent")?;
            let mut reply = vec![0; 20]; // v3 header16, channel count1
            reply[4..6].copy_from_slice(&u16::from_be_bytes(*b"US").to_le_bytes());
            reply[12] = 1;
            reply[16..20].copy_from_slice(&self.mcc_flags.to_le_bytes());
            return Ok(Some(reply));
        }
        if (group, command) == (3, 9) && word(b, 0) == 3 {
            self.started = true;
        }
        if !self.started {
            return Ok(None);
        }
        let mut reply = Vec::new();
        match (group, command) {
            (3, 8) => require(
                b.len() == 52
                    && word(b, 0) == 0
                    && b[12..18] == OWN
                    && if word(b, 4) == 3 {
                        word(b, 8) == 5 && word(b, 20) == 30
                    } else {
                        matches!(word(b, 4), 1 | 2) && word(b, 8) == 8 && word(b, 20) & !8 == 38
                    },
                "API77 AP actual MAC0 GO/filter identity",
            )?,
            (3, 9) => require(
                b.len() == 208 && word(b, 4) == 0 && b[16..22] == OWN,
                "API77 AP actual LINK0 physical owner",
            )?,
            (1, 8) => {
                let mut expected = [0; 36];
                expected[4] = 1;
                expected[16] = 1;
                expected[17] = 1;
                expected[20] = 3;
                expected[24..28].copy_from_slice(&0x2806u32.to_le_bytes());
                require(b == expected, "API77 AP literal legacy PHY36/chains")?;
            }
            (1, 0x18) => {
                require(
                    b.len() == 48 && b[16] < 10,
                    "API77 AP literal ADD_STA12 extent",
                )?;
                let station = b[16];
                let address: [u8; 6] = b[8..14].try_into().unwrap();
                require(
                    b[2..4] == [255; 2]
                        && b[35]
                            == if station == 0 {
                                2
                            } else if station == 1 {
                                1
                            } else {
                                0
                            }
                        && if station == 0 {
                            address == [3, 0, 0, 0, 0, 0]
                        } else if station == 1 {
                            address == [255; 6]
                        } else {
                            address[0] & 1 == 0 && half(b, 36) != 0 && b[17] == 4
                        },
                    "API77 AP actual station type/address/AID/UAPSD",
                )?;
                require(
                    (b[0] == 1) == self.peers.iter().any(|p| p.0 == station),
                    "API77 AP MODIFY before actual ADD status receipt",
                )?;
                self.peers.retain(|p| p.0 != station);
                self.peers.push((station, address));
                reply = vec![1, 0, 0, 0];
            }
            (5, 0x17) => {
                require(
                    b.len() == 36 && word(b, 4).count_ones() == 1,
                    "API77 AP TVQM3 extent/mask",
                )?;
                let station = word(b, 4).trailing_zeros() as u8;
                let tid = b[8];
                require(
                    self.peers.iter().any(|p| p.0 == station) && matches!(tid, 0 | 1 | 4 | 6 | 15),
                    "API77 AP native queue station/TID owner",
                )?;
                if word(b, 0) == 0 {
                    require(
                        !self
                            .queues
                            .iter()
                            .any(|q| q.live && q.station == station && q.tid == tid)
                            && word(b, 16) == 4
                            && b[20..28] != [0; 8]
                            && b[28..36] != [0; 8],
                        "API77 AP queue unique binding/actual retained DMA",
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
                        .ok_or("API77 AP removing unowned queue")?;
                    require(
                        word(b, 0) == 1 && q.read == q.write,
                        "API77 AP queue removal before native flush",
                    )?;
                    q.live = false;
                    reply.resize(8, 0);
                    reply[..2].copy_from_slice(&q.id.to_le_bytes());
                }
            }
            (5, 15) => {
                require(b.len() == 28, "API77 AP TLC4 exact client/legacy rate")?;
                let station = b[0];
                // Actual NVM enables both TX antennas (mask3), independently
                // of this non-HT peer's spatial streams. All four negotiated
                // CCK rates1/2/5.5/11Mbps occupy non_ht_rates bits0..3;
                // management TX chooses its own single rate separately.
                let mut expected = [0; 28];
                expected[0] = station;
                expected[6] = 3;
                expected[10] = 15;
                expected[24..26].copy_from_slice(&4095u16.to_le_bytes());
                require(
                    station >= 2 && self.peers.iter().any(|p| p.0 == station) && b == expected,
                    "API77 AP TLC4 exact client/legacy rate",
                )?;
            }
            (5, 0x18) => {
                require(
                    b.len() == 80 && word(b, 4).count_ones() == 1,
                    "API77 AP SEC_KEY1 extent/mask",
                )?;
                let station = word(b, 4).trailing_zeros() as u8;
                let id = word(b, 8) as u8;
                require(
                    if station == 0 {
                        id < 4 && word(b, 12) == 0x42
                    } else {
                        station >= 2 && id == 0 && matches!(word(b, 12), 2 | 0x22)
                    },
                    "API77 AP fabricated native IGTK or wrong native key role",
                )?;
                self.keys.retain(|k| *k != (station, id));
                if word(b, 0) == 1 {
                    self.keys.push((station, id));
                } else {
                    require(word(b, 0) == 3, "API77 AP unsupported key action")?;
                }
            }
            (1, 0x91) => {
                require(
                    b.len() >= 74
                        && usize::from(half(b, 0)) + 32 == b.len()
                        && b[32] == 0x80
                        && b[42..48] == OWN
                        && word(b, 20) == 4,
                    "API77 AP actual beacon13 physical owner/TIM extent",
                )?;
                self.beacon = true;
            }
            (5, 2) => require(
                b.len() == 20 && b[..16] == [0, 0, 0, 0, 1, 0, 0, 0, 8, 0, 0, 0, 0, 0, 1, 0],
                "API77 AP RX prefix must use actual MVM sync1",
            )?,
            (1, 0x1e) => {
                require(
                    b.len() == 8 && half(b, 4) == 0xffff,
                    "API77 AP native FLUSHv2",
                )?;
                let station = word(b, 0) as u8;
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
                    for (offset, value) in
                        [(0, u16::from(q.tid)), (2, q.id), (4, q.read), (6, q.write)]
                    {
                        reply[at + offset..at + offset + 2].copy_from_slice(&value.to_le_bytes());
                    }
                    q.read = q.write;
                }
            }
            (1, 0x19) => {
                let station = word(b, 0) as u8;
                require(
                    b.len() == 4 && !self.queues.iter().any(|q| q.live && q.station == station),
                    "API77 AP station removed before terminal queue ownership",
                )?;
                self.peers.retain(|p| p.0 != station);
            }
            _ => return Ok(None),
        }
        Ok(Some(reply))
    }
    pub(super) fn transmit(
        &mut self,
        p: &model::Published,
        fw: &mut model::Firmware,
    ) -> Result<(), &'static str> {
        let q = self
            .queues
            .iter_mut()
            .find(|q| q.live && q.id == p.queue)
            .ok_or("API77 AP TX unowned queue")?;
        let b = &p.bytes;
        require(
            b.len() >= 48 && b[0] == 0x1c,
            "API77 AP actual TXv9 envelope",
        )?;
        let header = usize::from((half(b, 6) >> 8) & 31) * 2;
        require(
            matches!(header, 24 | 26)
                && b.len() == 24 + usize::from(half(b, 4)) + header.next_multiple_of(4) - header,
            "API77 AP native TX9 length/header/padding",
        )?;
        let mut frame = b[24..24 + header].to_vec();
        frame.extend_from_slice(&b[24 + header.next_multiple_of(4)..]);
        let encrypt = word(b, 8) & 2 == 0;
        require(
            frame[10..16] == OWN && frame[1] & 3 == if frame[0] & 12 == 8 { 2 } else { 0 },
            "API77 AP TX physical owner/FromDS",
        )?;
        require(
            !encrypt || self.keys.iter().any(|k| k.0 == q.station),
            "API77 AP native encryption lacks actual station key receipt",
        )?;
        q.write = p.pointer;
        q.read = p.pointer;
        self.tx.push((q.station, frame, encrypt));
        fw.tx_complete(p.queue, p.pointer);
        Ok(())
    }
}

#[derive(Debug)]
struct Source {
    owner: narf_net::native_emission::ProviderLifetime,
    messages: IrqSafeSpinLock<Vec<Vec<u8>>>,
}
impl DeferredReplySink for Source {
    fn current(&self) -> bool {
        self.owner.observe().current()
    }
    fn native_source(&self) -> Option<narf_net::native_emission::Lifetime> {
        Some(self.owner.observe())
    }
    fn deliver(&self, b: Vec<u8>) -> Result<(), i32> {
        if !self.current() {
            return Err(125);
        }
        self.messages.lock().push(b);
        Ok(())
    }
}
struct Fixture {
    h: Harness,
    source: Arc<Source>,
    admin: narf_net::AdminHandle,
    _daemon: Cap<narf_net::StackDaemon, Invoke>,
}
impl Fixture {
    fn new() -> Result<Self, &'static str> {
        let h = Harness::version_profile(false, false, 7, 4)?;
        require(
            h.device.supports_ap(),
            "API77 complete actual adapter did not expose AP",
        )?;
        narf_net::iface::set_link_state(h.device.name(), false);
        h.device
            .set_iftype(3)
            .map_err(|_| "API77 original netdev AP mode")?;
        let iface = narf_net::registry()
            .register(
                &narf_net::bootstrap_authority(),
                Registered(h.device.clone()),
            )
            .map_err(|_| "API77 AP original typed registration")?;
        let daemon = Cap::<narf_net::StackDaemon, Invoke>::bootstrap();
        let admin = narf_net::stack::control_registered(&narf_net::StackAttach { iface, daemon })
            .map_err(|_| "API77 AP original delegated admin")?
            .admin;
        narf_wireless::registry::register(h.device.clone());
        admin
            .set_link(true)
            .map_err(|_| "API77 AP actual administrative UP")?;
        Ok(Self {
            h,
            source: Arc::new(Source {
                owner: narf_net::native_emission::ProviderLifetime::new(),
                messages: IrqSafeSpinLock::new(Vec::new()),
            }),
            admin,
            _daemon: daemon,
        })
    }
    fn authority(&self) -> Result<ApControlAuthority, &'static str> {
        let iface: Arc<dyn WirelessNetIface> = self.h.device.clone();
        let link = narf_net::iface::lookup(self.h.device.name()).ok_or("API77 AP netdev absent")?;
        ApControlAuthority::bind(
            self.admin.clone(),
            &iface,
            0,
            link.ifindex,
            self.source.clone(),
        )
        .and_then(ApControlAuthority::reserve)
        .map_err(|_| "API77 AP current original source/reservation")
    }
    fn start(&self, secure: bool) -> Result<(), &'static str> {
        let a = self.authority()?;
        let (c, s) = config(secure);
        let result = run(self.h.device.start_ap_with_settings_async(&a, c, s))?;
        if result.is_err() {
            self.diagnose("original START", &result);
        }
        result.map_err(|_| "API77 AP original START/native receipts")
    }
    #[inline(never)]
    fn diagnose(&self, label: &str, result: &dyn core::fmt::Debug) {
        use core::fmt::Write;
        // Failure-only owned metadata: never run on a healthy poll or add
        // I/O/callbacks under State. Scopes end before another lock is taken.
        let state = {
            self.h.device.state.try_lock().map(|mut state| {
                let active = state.ap.is_some();
                let owner = state.owner.as_mut().map(|owner| {
                    let phase = owner.phase();
                    let failed = owner.station_failed();
                    let hw = owner.ap_hardware();
                    (
                        phase,
                        failed,
                        hw.is_failed(),
                        model::retained(hw),
                        hw.ap_command_cursor(),
                        hw.receive_capture_epoch(),
                    )
                });
                (active, owner)
            })
        };
        let _ = writeln!(narf_console::Writer,
            "API77 AP failure {label} result={result:?} state(ap,ownerphase/stationfailed/hwfailed/retained/cursor/rxepoch)={state:?} stopped={} cleanup={} terminal={}",
            self.h.device.ap_stopped.load(Ordering::Acquire),
            self.h.device.ap_cleanup.load(Ordering::Acquire),
            self.h.device.terminal.load(Ordering::Acquire));
        let Some(actor) = self.h.actor.try_lock() else {
            return;
        };
        let held = actor
            .held
            .as_ref()
            .map(|(c, g, s, b)| (*g, *c, *s, b.len()));
        let native = actor.native_ap.as_ref().map(|m| {
            (
                m.started,
                m.beacon,
                m.peers.len(),
                m.queues.iter().filter(|q| q.live).count(),
                m.keys.len(),
                m.mcc_flags,
            )
        });
        let _ = writeln!(
            narf_console::Writer,
            "API77 AP actor held={held:?} model(started,beacon,peers,queues,keys,mcc)={native:?}"
        );
        for (g, c, b) in actor.commands.iter().rev().take(14).rev() {
            // Public command selectors only; never print key/nonce material.
            let selectors = matches!((*g, *c), (3, 8) | (3, 9) | (1, 8) | (1, 0x9f) | (1, 0xc8))
                .then_some((b.get(..4), b.get(4..8), b.get(8..12)));
            let _ = writeln!(
                narf_console::Writer,
                "API77 AP command {g:02x}:{c:02x} len={} selectors={selectors:?}",
                b.len()
            );
        }
    }
    fn key(&self, id: u8, material: [u8; 16]) -> Result<(), &'static str> {
        let a = self.authority()?;
        let key = narf_wireless::OwnedKey::new(narf_wireless::KeyParams {
            idx: id,
            pairwise: id == 0,
            peer: (id == 0).then_some(PEER),
            cipher: if id >= 4 {
                narf_wireless::CIPHER_SUITE_AES_CMAC
            } else {
                narf_wireless::CIPHER_SUITE_CCMP
            },
            key: material.to_vec(),
            seq: Vec::new(),
            default_mgmt: id >= 4,
        });
        run(self.h.device.add_key_ap_async(&a, key))?.map_err(|_| "API77 AP actual key owner")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        narf_wireless::registry::unregister(self.h.device.name());
        narf_net::registry().unregister(self.h.device.name());
    }
}
fn config(secure: bool) -> (narf_wireless::ApConfig, narf_wireless::ApStartSettings) {
    let mut beacon = vec![0; 36];
    beacon[0] = 0x80;
    beacon[4..10].fill(255);
    beacon[10..16].copy_from_slice(&OWN);
    beacon[16..22].copy_from_slice(&OWN);
    beacon[34..36].copy_from_slice(&(1u16 | if secure { 16 } else { 0 }).to_le_bytes());
    beacon.extend_from_slice(&[
        0, 3, b'n', b'e', b't', 1, 4, 0x82, 0x84, 0x8b, 0x96, 3, 1, 1,
    ]);
    if secure {
        let mut rsn = narf_wireless::rsn::RsnIe::wpa2_psk_ccmp();
        rsn.rsn_capabilities = 0xc0;
        rsn.group_management_cipher = Some(narf_wireless::rsn::Suite::standard(6));
        let body = rsn.encode_body();
        beacon.extend_from_slice(&[48, body.len() as u8]);
        beacon.extend_from_slice(&body);
    }
    let settings = narf_wireless::ApStartSettings {
        control_port: narf_wireless::ControlPort {
            enabled: secure,
            ethertype: 0x888e,
            no_encrypt: false,
            over_nl80211: true,
            no_preauth: false,
        },
        ..Default::default()
    };
    (
        narf_wireless::ApConfig {
            ssid: b"net".to_vec(),
            beacon_head: beacon,
            beacon_tail: Vec::new(),
            probe_resp: None,
            beacon_interval: 100,
            dtim_period: 2,
            frequency_mhz: 2412,
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
        settings,
    )
}
fn station(authorized: bool, secure: bool) -> narf_wireless::StationConfig {
    narf_wireless::StationConfig {
        mac: PEER,
        aid: 17,
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
        authorized: Some(authorized),
        station_tx_power: None,
        capability: None,
        ext_capability: None,
    }
}
// Parse explicit firmware structures through the real SMBIOS parser. Physical
// owners are excluded by check(); restore boot tables after this RAM owner dies.
pub(super) struct Platform;
impl Platform {
    pub(super) fn new() -> Self {
        let mut b = vec![0; 18];
        b[1] = 18;
        b[4] = 1;
        b[5] = 2;
        b[8] = 3;
        b.extend_from_slice(b"NARF RAM BIOS\0v7\0");
        b.extend_from_slice(b"2026-01-01\0\0");
        let mut system = vec![0; 25];
        system[0] = 1;
        system[1] = 25;
        system[4..8].copy_from_slice(&[1, 2, 3, 4]);
        system[8..24].fill(0x77);
        b.extend_from_slice(&system);
        b.extend_from_slice(b"NARF RAM\0API77 AP\0v1\0only-fixture\0\0");
        b.extend_from_slice(&[2, 9, 0, 0, 1, 2, 3, 4, 0]);
        b.extend_from_slice(b"NARF RAM\0AP board\0v1\0only-fixture\0\0");
        b.extend_from_slice(&[127, 4, 0, 0, 0, 0]);
        narf_firmware_smbios::parse_stream(&b);
        Self
    }
}
impl Drop for Platform {
    fn drop(&mut self) {
        narf_firmware_smbios::parse_stream(
            narf_firmware_smbios::boot_table().map_or(&[][..], |t| t.bytes()),
        );
    }
}

#[inline(never)]
fn unqualified_common_sync_is_refused(f: &Fixture, baid: bool) -> Result<(), &'static str> {
    let (refused, unchanged) = {
        let mut state =
            f.h.device
                .state
                .try_lock()
                .ok_or("API77 sync probe State busy")?;
        let owner = state
            .owner
            .as_mut()
            .ok_or("API77 sync probe original owner absent")?;
        let hw = owner.ap_hardware();
        require(
            hw.ap_legacy_selected(),
            "API77 sync probe lost actual AP ABI/NVM adapter",
        )?;
        if !baid {
            hw.close_receive_epoch()?;
        }
        let cursor = hw.ap_command_cursor();
        let epoch = hw.receive_capture_epoch();
        let refused = if baid {
            let mut future = Box::pin(hw.synchronize_rx_baid(3));
            matches!(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Err(_))
            )
        } else {
            let mut future = Box::pin(hw.synchronize_receive_epoch());
            matches!(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Err(_))
            )
        };
        (
            refused,
            hw.ap_command_cursor() == cursor && hw.receive_capture_epoch() == epoch,
        )
    };
    require(
        refused && unchanged,
        "API77 ordinary/ownerless BAID sync published without its actual role consumer",
    )
}

fn native() -> Result<(), &'static str> {
    let _platform = Platform::new();
    let f = Fixture::new()?;
    // A complete adapter and selected AP mode alone are not a current START
    // owner. Actual native command/DMA cursor must remain untouched here.
    unqualified_common_sync_is_refused(&f, false)?;
    // Legacy station/probe qualification cannot substitute for this record;
    // production obtains and checks the exact original PCI/RF/NVM/FW/SMBIOS hash.
    let request = run(f.h.device.ap_power_request())??;
    require(
        request.name.contains("ap-power-v7"),
        "API77 AP reused station/probe power name",
    )?;
    f.start(true)?;
    // This AP implements legacy20, not a fabricated Qu BAID owner. Its
    // successful EMPTY/sync1 receipt must not authorize a foreign BAID.
    unqualified_common_sync_is_refused(&f, true)?;
    require(
        f.h.device.link_up() && f.h.actor.lock().native_ap.as_ref().unwrap().beacon,
        "API77 AP carrier before actual beacon receipt",
    )?;
    f.key(1, GTK)?;
    f.key(4, IGTK)?;
    {
        let a = f.authority()?;
        run(f
            .h
            .device
            .default_key_ap_async(&a, 1, false, true, false, false))?
        .map_err(|_| "API77 AP current default GTK owner")?;
    }
    {
        let a = f.authority()?;
        run(f.h.device.add_station_async(&a, station(false, true)))?
            .map_err(|_| "API77 AP actual peer ADD/TLC/queues")?;
    }
    f.key(0, TK)?;
    let before_authorization =
        f.h.device
            .fence
            .lock()
            .clone()
            .ok_or("API77 AP initial receive publication absent")?;
    // A real queued RFH descriptor, deliberately not pumped before SET_STA.
    // Native STA/TLC acknowledgements alone cannot authorize this prefix.
    f.h.actor.lock().inject(0xc1, 0, 0x8000, &uplink(6));
    {
        let a = f.authority()?;
        run(f.h.device.set_station_async(&a, station(true, true)))?
            .map_err(|_| "API77 AP port before actual PTK/GTK/IGTK")?;
    }
    let domain = f.h.device.environment.ap_policy.snapshot()?;
    let old_publication = before_authorization.invoke(&domain, || Ok(()));
    let queued = f.h.device.step(None);
    require(
        old_publication.is_err() && queued.is_empty(),
        "API77 AP queued preauthorization RFH or copied epoch crossed SET_STA",
    )?;
    f.h.actor.lock().inject(0xc1, 0, 0x8000, &uplink(6));
    require(
        f.h.device.step(None).len() == 1,
        "API77 AP preauthorization prefix spent same current CCMP PN",
    )?;
    let mut ethernet = PEER.to_vec();
    ethernet.extend_from_slice(&[2, 0x22, 3, 4, 5, 6]); // actual bridged MSDU source
    ethernet.extend_from_slice(&[0x88, 0xb5, 1, 2, 3]);
    f.h.device
        .enqueue(&ethernet, narf_net::TxMeta::default())
        .map_err(|_| "API77 AP bridged TX admission")?;
    let deadline = narf_time::Deadline::after_ms(3000);
    loop {
        let _ = f.h.device.step(None);
        f.h.actor.lock().serve()?;
        if !f.h.actor.lock().native_ap.as_ref().unwrap().tx.is_empty() {
            break;
        }
        if deadline.expired() {
            return Err("API77 AP DATA did not reach original TVQM");
        }
        narf_scheduler::block_on_spin(narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
            2_000_000,
        )));
    }
    {
        let actor = f.h.actor.lock();
        let ap = actor.native_ap.as_ref().unwrap();
        let (station, frame, encrypt) = &ap.tx[0];
        require(
            *station == 2 && *encrypt && frame[4..10] == PEER && frame[16..22] == ethernet[6..12],
            "API77 AP lost physical peer, native encryption or bridged A3",
        )?;
        require(
            !ap.keys.iter().any(|(_, id)| *id >= 4),
            "API77 missing BIGTK_TX fabricated native IGTK receipt",
        )?;
    }
    // Wrong native station identity must not spend the same valid CCMP PN.
    let mut mpdu = uplink(7);
    for (station_id, accepted) in [(3, false), (2, true), (2, false)] {
        mpdu[12..16].copy_from_slice(&(3u32 | 4 | 0x240 | (station_id << 24)).to_le_bytes());
        f.h.actor.lock().inject(0xc1, 0, 0x8000, &mpdu);
        let received = f.h.device.step(None);
        require(
            (received.len() == 1) == accepted,
            "API77 AP actual RFH48 peer/PN admission",
        )?;
    }
    authorization_copies(&f)?;
    native_loss_copies(&f)?;
    // Missing BIGTK_TX selects real host CMAC plus native ENCRYPT_DIS.
    let mut management = vec![0; 26];
    management[0] = 0xc0;
    management[4..10].fill(255);
    management[10..16].copy_from_slice(&OWN);
    management[16..22].copy_from_slice(&OWN);
    management[24] = 3;
    {
        let a = f.authority()?;
        let request = narf_wireless::MgmtTxRequest {
            frequency_mhz: 2412,
            frame: management,
            offchannel_ok: false,
            duration: 0,
            no_cck: false,
        };
        require(
            !run(f.h.device.mgmt_tx_ap_async(&a, 1, request))?
                .map_err(|_| "API77 AP software-BIP native TX completion")?,
            "API77 AP invented a broadcast acknowledgement",
        )?;
    }
    {
        let actor = f.h.actor.lock();
        let (station, frame, encrypted) = actor.native_ap.as_ref().unwrap().tx.last().unwrap();
        let mut store = narf_wireless::mfp::MfpKeyStore::new();
        store
            .install_active(IGTK, 4)
            .map_err(|_| "API77 AP independent IGTK receiver")?;
        require(
            *station == 1
                && !encrypted
                && frame[1] & 0x40 == 0
                && narf_wireless::mfp::verify_inbound(&mut store, &frame[..24], &frame[24..])
                    .is_ok(),
            "API77 AP did not send genuine host BIP over exact native BCAST queue",
        )?;
    }
    {
        let a = f.authority()?;
        run(f.h.device.del_station_async(&a, Some(PEER), 3))?
            .map_err(|_| "API77 AP actual flush/queue/peer retirement")?;
    }
    let a = f.authority()?;
    run(f.h.device.stop_ap_async(&a))
        .map_err(|_| "API77 AP stop progress")?
        .map_err(|_| "API77 AP physical stop")?;
    require(
        !f.h.device.link_up() && f.h.device.ap_stopped.load(Ordering::Acquire),
        "API77 AP STOP left autonomous owner armed",
    )
}

fn uplink(pn: u64) -> Vec<u8> {
    let mut frame = vec![8, 0x41, 0, 0];
    frame.extend_from_slice(&OWN);
    frame.extend_from_slice(&PEER);
    frame.extend_from_slice(&OWN);
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&narf_wireless::ccmp::build_ccmp_header(pn, 0));
    frame.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0xb5, 7]);
    let mut mpdu = envelope(&frame);
    mpdu[12..16].copy_from_slice(&(3u32 | 4 | 0x240 | (2 << 24)).to_le_bytes());
    mpdu
}

#[inline(never)]
fn authorization_copies(f: &Fixture) -> Result<(), &'static str> {
    let keys = f.h.actor.lock().native_ap.as_ref().unwrap().keys.clone();
    f.h.actor.lock().inject(0xc1, 0, 0x8000, &uplink(8));
    let copied = f.h.device.step(None);
    require(
        copied.len() == 1,
        "API77 AP authorization fixture lacks copied native RFH DATA",
    )?;
    {
        let a = f.authority()?;
        run(f.h.device.set_station_async(&a, station(false, true)))?
            .map_err(|_| "API77 AP actual deauthorization")?;
    }
    let domain = f.h.device.environment.ap_policy.snapshot()?;
    let mut callbacks = 0;
    let stale = copied[0].1.invoke(&domain, || {
        callbacks += 1;
        Ok(())
    });
    let old_ipc =
        f.h.device
            .rx
            .lock()
            .as_mut()
            .and_then(|rx| rx.try_recv().ok().flatten());
    require(
        stale.is_err() && callbacks == 0 && old_ipc.is_none(),
        "API77 AP deauthorization retained copied publication or queued IPC DATA",
    )?;
    {
        let a = f.authority()?;
        run(f.h.device.set_station_async(&a, station(true, true)))?
            .map_err(|_| "API77 AP actual reauthorization")?;
    }
    f.h.actor.lock().inject(0xc1, 0, 0x8000, &uplink(8));
    let replay = f.h.device.step(None);
    f.h.actor.lock().inject(0xc1, 0, 0x8000, &uplink(9));
    let fresh = f.h.device.step(None);
    let current_keys = f.h.actor.lock().native_ap.as_ref().unwrap().keys.clone();
    require(
        replay.is_empty() && fresh.len() == 1 && current_keys == keys,
        "API77 AP authorization transition reset peer PN or installed keys",
    )
}

fn loss(pn: u64) -> Vec<u8> {
    let mut frame = vec![0; 24];
    frame[0] = 0xc0;
    frame[1] = 0x40;
    frame[4..10].copy_from_slice(&OWN);
    frame[10..16].copy_from_slice(&PEER);
    frame[16..22].copy_from_slice(&OWN);
    frame.extend_from_slice(&narf_wireless::ccmp::build_ccmp_header(pn, 0));
    frame.extend_from_slice(&[3, 0]);
    let mut mpdu = envelope(&frame);
    mpdu[12..16].copy_from_slice(&(3u32 | 4 | 0x240 | (2 << 24)).to_le_bytes());
    mpdu
}

#[inline(never)]
fn native_loss_copies(f: &Fixture) -> Result<(), &'static str> {
    {
        let a = f.authority()?;
        run(f
            .h
            .device
            .register_mgmt_frame_ap_async(&a, 0xc0, vec![3, 0]))?
        .map_err(|_| "API77 AP native management loss registration")?;
    }
    let before_events = f.source.messages.lock().len();
    let keys = f.h.actor.lock().native_ap.as_ref().unwrap().keys.clone();
    let before_receive = {
        let mut state =
            f.h.device
                .state
                .try_lock()
                .ok_or("API77 AP native loss State")?;
        state
            .owner
            .as_mut()
            .unwrap()
            .ap_hardware()
            .receive_publication()
            .ok_or("API77 AP native loss original receive epoch")?
    };
    f.h.actor.lock().inject(0xc1, 0, 0x8000, &uplink(10));
    let copied = f.h.device.step(None);
    require(copied.len() == 1, "API77 AP native loss copied DATA absent")?;
    f.h.actor.lock().inject(0xc1, 0, 0x8000, &uplink(11));
    f.h.actor.lock().inject(0xc1, 0, 0x8000, &loss(1));
    let same_drain = f.h.device.step(None);
    let domain = f.h.device.environment.ap_policy.snapshot()?;
    let mut callbacks = 0;
    let stale = copied[0].1.invoke(&domain, || {
        callbacks += 1;
        Ok(())
    });
    let old_ipc =
        f.h.device
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
            && !copied[0].1.current()
            && stale.is_err()
            && callbacks == 0
            && old_ipc.is_none()
            && loss_event
            && before_receive.current()
            && f.h.device.link_up(),
        "API77 AP native loss retained DATA/IPC or lost typed management/carrier/key proof",
    )?;
    let tx_before = f.h.actor.lock().native_ap.as_ref().unwrap().tx.len();
    let mut bytes = PEER.to_vec();
    bytes.extend_from_slice(&OWN);
    bytes.extend_from_slice(&[0x88, 0xb5, 1]);
    f.h.device
        .enqueue(&bytes, narf_net::TxMeta::default())
        .map_err(|_| "API77 AP carrier lost at current post-loss enqueue")?;
    let _ = f.h.device.step(None);
    let tx_after = f.h.actor.lock().native_ap.as_ref().unwrap().tx.len();
    require(
        tx_after == tx_before && f.h.device.link_up(),
        "API77 AP native loss admitted denied peer TX or retired entire AP carrier",
    )?;
    f.h.actor.lock().inject(0xc1, 0, 0x8000, &uplink(12));
    let unauthorized = f.h.device.step(None);
    require(
        unauthorized.is_empty(),
        "API77 AP DATA crossed native peer loss",
    )?;
    f.h.actor.lock().inject(0xc1, 0, 0x8000, &uplink(12));
    {
        let a = f.authority()?;
        run(f.h.device.set_station_async(&a, station(true, true)))?
            .map_err(|_| "API77 AP native-loss reauthorization")?;
    }
    let prefix = f.h.device.step(None);
    f.h.actor.lock().inject(0xc1, 0, 0x8000, &uplink(11));
    let replay = f.h.device.step(None);
    f.h.actor.lock().inject(0xc1, 0, 0x8000, &uplink(12));
    let fresh = f.h.device.step(None);
    let current_keys = f.h.actor.lock().native_ap.as_ref().unwrap().keys.clone();
    require(
        prefix.is_empty()
            && replay.is_empty()
            && fresh.len() == 1
            && current_keys == keys
            && f.h.device.link_up(),
        "API77 AP native-loss reauthorization skipped prefix or reset replay/keys/carrier",
    )
}
fn held_source() -> Result<(), &'static str> {
    for source_kind in 0..5 {
        let _platform = Platform::new();
        let f = Fixture::new()?;
        f.h.actor.lock().hold_phy = Some(11); // real SET_LINK power reply
        let authority = f.authority()?;
        let (config, settings) = config(false);
        let mut start = Box::pin(
            f.h.device
                .start_ap_with_settings_async(&authority, config, settings),
        );
        let deadline = narf_time::Deadline::after_ms(3000);
        loop {
            let result = start.as_mut().poll(&mut Context::from_waker(Waker::noop()));
            if result.is_ready() {
                f.diagnose("held power returned early", &result);
                return Err("API77 AP START escaped held power receipt");
            }
            f.h.actor.lock().serve()?;
            if f.h.actor.lock().held.is_some() {
                break;
            }
            if deadline.expired() {
                return Err("API77 AP held power stage absent");
            }
            narf_scheduler::block_on_spin(narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
                2_000_000,
            )));
        }
        require(
            !f.h.device.link_up() && !f.h.actor.lock().native_ap.as_ref().unwrap().beacon,
            "API77 AP beacon/carrier preceded actual power receipt",
        )?;
        if source_kind == 0 {
            f.source.owner.retire().notify();
        } else if source_kind == 1 {
            f.h.ap_power.lock().as_ref().unwrap().revoke();
        } else if source_kind == 2 {
            let mut changed = domain();
            changed.rules[0].max_power_dbm = 9;
            f.h.db.install(changed);
        } else if source_kind == 3 {
            f.admin
                .set_link(false)
                .map_err(|_| "API77 AP administrative down")?;
            f.admin
                .set_link(true)
                .map_err(|_| "API77 AP administrative up")?;
        } else {
            f.h.actor.lock().inject(0xc9, 0, 0x8000, &[0; 4]);
        }
        drop(start); // retained native Work, never the borrowed waiter, owns stop
        f.h.actor.lock().release();
        let deadline = narf_time::Deadline::after_ms(3000);
        loop {
            let _ = f.h.device.step(None);
            f.h.actor.lock().serve()?;
            if f.h.device.ap_stopped.load(Ordering::Acquire)
                && f.h.device.control.try_lock().is_some_and(|c| c.is_none())
            {
                break;
            }
            if deadline.expired() {
                return Err("API77 AP source loss did not retain physical cleanup");
            }
            narf_scheduler::block_on_spin(narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
                2_000_000,
            )));
        }
        require(
            !f.h.device.link_up() && !f.h.actor.lock().native_ap.as_ref().unwrap().beacon,
            "API77 AP emitted after held original source/power/policy retirement",
        )?;
    }
    for flags in [0x101, 0x119] {
        // absent ACTIVE; actual RADAR
        let _platform = Platform::new();
        let f = Fixture::new()?;
        f.h.actor.lock().native_ap.as_mut().unwrap().mcc_flags = flags;
        require(
            f.start(false).is_err() && !f.h.actor.lock().native_ap.as_ref().unwrap().beacon,
            "API77 AP ignored actual MCC ACTIVE/radar prohibition",
        )?;
    }
    Ok(())
}
fn smoke_iwl_native_ap_api77_original_netdev_power_peer_key_data_and_stop() -> TestResult {
    check(native)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/ap",
    smoke_iwl_native_ap_api77_original_netdev_power_peer_key_data_and_stop
);
fn smoke_iwl_native_ap_api77_held_power_original_source_policy_and_dropped_waiter_retire(
) -> TestResult {
    check(held_source)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/ap",
    smoke_iwl_native_ap_api77_held_power_original_source_policy_and_dropped_waiter_retire
);
