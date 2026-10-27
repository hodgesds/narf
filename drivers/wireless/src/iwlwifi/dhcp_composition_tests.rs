//! Sc c103 post-INIT station composition. The device side observes the real
//! TFH publication and writes receipts/MPDUs into posted RFH buffers. Device,
//! Connection, queues, RSNA, carrier, IPC and DHCP are production code. PCI,
//! firmware execution and radio/CCMP offload remain physical acceptance gates.

use super::super::runtime::model::{self, Published, TxTrace};
use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wifi_fixtures::{udp_ipv4, ApPhase, DhcpServer, FakeAp, NetworkPlan};

#[cfg(feature = "kernel-test")]
#[path = "sc_source_tests.rs"]
mod source_tests;

type R<T = ()> = Result<T, &'static str>;
const OWN: [u8; 6] = [2, 0x71, 2, 3, 4, 5];
const AP: [u8; 6] = [2, 0x72, 2, 3, 4, 5];
const SSID: &[u8] = b"narf-sc-native";
const PMK: [u8; 32] = [0x55; 32];
const ANONCE: [u8; 32] = [0xaa; 32];
const NETWORK: NetworkPlan = NetworkPlan {
    station: OWN,
    bssid: AP,
    server_ip: [10, 79, 0, 1],
    lease_ip: [10, 79, 0, 42],
    netmask: [255, 255, 255, 0],
    lease_seconds: 3600,
};

fn require(condition: bool, why: &'static str) -> R {
    if condition {
        Ok(())
    } else {
        Err(why)
    }
}
fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn half(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    HoldM4,
    HoldRemoval,
    HoldRxFence,
    HoldGroupReply,
}

struct Wire {
    firmware: model::Firmware,
    trace: TxTrace,
    versions: Vec<u8>,
    ap: FakeAp,
    server: DhcpServer,
    queues: Vec<(u16, u8, bool)>,
    commands: Vec<(u8, u8, Vec<u8>)>,
    data: Vec<(Vec<u8>, bool)>,
    received: Vec<Vec<u8>>,
    air: Vec<(u16, u16, u8, ApPhase)>,
    replies: Vec<u8>,
    key: Option<Vec<u8>>,
    ptk: Option<narf_wireless::eapol::Ptk>,
    group_rekey: bool,
    group_reply: bool,
    keys: usize,
    next_pn: u64,
    fault: Fault,
    held: Option<(u8, u8, u16)>,
    held_tx: Option<(u16, u16)>,
    held_rx: Option<u32>,
    m4: bool,
    error: Option<&'static str>,
}

// SAFETY: no real device or thread accesses these fixture pointers. The sole
// Wire is moved only between the local driver and HARNESS, and all device-side
// access is serialized by HARNESS. Its posted buffers stay owned by Device
// until Guard removes both global references and destroys Hardware last.
unsafe impl Send for Wire {}

impl Wire {
    fn service(&mut self) -> R<bool> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let mut progressed = false;
        for _ in 0..64 {
            let Some(published) = self.trace.take() else {
                return Ok(progressed);
            };
            progressed = true;
            if let Err(error) = self.observe(published) {
                self.error = Some(error);
                return Err(error);
            }
        }
        Err("Sc firmware observer did not become idle")
    }

    /// Independent Linux iwl_tfh_tfd/iwl_tfh_tb offsets: a 16-bit count,
    /// then packed ten-byte (len:u16,address:u64) entries. These snapshots
    /// are observations; no DMA address is converted into a CPU pointer.
    fn descriptor(p: &Published) -> R {
        let count = usize::from(half(&p.descriptor, 0));
        require((1..=3).contains(&count), "Sc TFH transfer count")?;
        let first = u64::from_le_bytes(p.descriptor[4..12].try_into().unwrap());
        require(
            first != 0 && first == p.dma_base,
            "Sc TFH retained DMA address",
        )?;
        let mut extent = 0usize;
        for i in 0..count {
            let offset = 2 + i * 10;
            let len = usize::from(half(&p.descriptor, offset));
            let addr =
                u64::from_le_bytes(p.descriptor[offset + 2..offset + 10].try_into().unwrap());
            require(
                len != 0 && addr == first + extent as u64,
                "Sc TFH packed extent",
            )?;
            extent += len;
        }
        require(
            extent == p.bytes.len(),
            "Sc TFH extent differs from submitted DMA",
        )?;
        require(
            half(&p.descriptor, 2) as usize == p.bytes.len().min(20),
            "Sc TFH TB0 split",
        )?;
        require(
            p.descriptor[2 + count * 10..].iter().all(|b| *b == 0),
            "Sc TFH unused tail",
        )
    }

    fn observe(&mut self, published: Published) -> R {
        require(
            published.doorbell == (u32::from(published.queue) << 16) | u32::from(published.pointer),
            "Sc observed doorbell queue/pointer mismatch",
        )?;
        Self::descriptor(&published)?;
        if published.queue == 0 {
            self.command(published)
        } else {
            self.transmit(published)
        }
    }

    fn command(&mut self, p: Published) -> R {
        let bytes = &p.bytes;
        require(bytes.len() >= 8, "Sc long command header")?;
        let (cmd, group, sequence) = (bytes[0], bytes[1], half(bytes, 2));
        let version = self
            .versions
            .chunks_exact(4)
            .find(|entry| entry[0] == cmd && entry[1] == group)
            .map(|entry| if entry[2] == 99 { 0 } else { entry[2] })
            .unwrap_or(0);
        require(
            bytes[7] == 0
                && usize::from(half(bytes, 4)) + 8 == bytes.len()
                && sequence == (p.pointer.wrapping_sub(1) & 0xff),
            "Sc bare/WIDE_ID command header",
        )?;
        let body = &bytes[8..];
        self.commands.push((group, cmd, body.to_vec()));
        let mut response = Vec::new();
        match (group, cmd) {
            (0xc, 2) => {
                require(body == [0; 4] && version == 1, "Sc NVM request")?;
                // The authored MLD table selects iwl_nvm_get_info_rsp v4:
                // legacy-only single-chain NVM, 14 valid channels/110 entries.
                response.resize(28 + 110 * 4, 0);
                response[12..16].copy_from_slice(&1u32.to_le_bytes());
                response[16..20].copy_from_slice(&1u32.to_le_bytes());
                response[24..28].copy_from_slice(&14u32.to_le_bytes());
                for i in 0..14 {
                    response[28 + i * 4..32 + i * 4].copy_from_slice(&1u32.to_le_bytes());
                }
            }
            (1, 0xc8) => {
                require(
                    body.len() == 28 && half(body, 0) == u16::from_be_bytes(*b"US") && body[2] == 2,
                    "Sc MCC source/country",
                )?;
                response.resize(24 + 14 * 4, 0);
                response[20..24].copy_from_slice(&14u32.to_le_bytes());
                for i in 0..14 {
                    response[24 + i * 4..28 + i * 4].copy_from_slice(&13u32.to_le_bytes());
                }
            }
            (5, 0x17) => {
                require(
                    version == 3 && body.len() == 36 && word(body, 4) == 1,
                    "Sc queue command ABI",
                )?;
                let tid = body[8];
                if word(body, 0) == 0 {
                    require(
                        matches!(tid, 0 | 15)
                            && word(body, 16) == 4
                            && body[20..28] != [0; 8]
                            && body[28..36] != [0; 8]
                            && !self.queues.iter().any(|(_, t, live)| *t == tid && *live),
                        "Sc native queue ownership",
                    )?;
                    let id = self.queues.len() as u16 + 1;
                    self.queues.push((id, tid, true));
                    response.resize(8, 0);
                    response[..2].copy_from_slice(&id.to_le_bytes());
                } else {
                    require(
                        word(body, 0) == 1 && body[12..].iter().all(|b| *b == 0),
                        "Sc queue remove layout",
                    )?;
                    let queue = self
                        .queues
                        .iter_mut()
                        .find(|(_, t, live)| *t == tid && *live)
                        .ok_or("Sc remove unowned queue")?;
                    if self.fault == Fault::HoldRemoval {
                        self.held = Some((cmd, group, sequence));
                        return Ok(());
                    }
                    queue.2 = false;
                    response.resize(8, 0);
                    response[..2].copy_from_slice(&queue.0.to_le_bytes());
                }
            }
            (5, 0x18) => {
                require(
                    version == 1 && body.len() == 80 && word(body, 0) == 1 && word(body, 4) == 1,
                    "Sc native key command",
                )?;
                match word(body, 12) {
                    2 => require(
                        word(body, 8) == 0 && self.key.as_deref() == Some(&body[16..32]),
                        "Sc installed PTK differs from AP exchange",
                    )?,
                    0x4a => require(
                        (word(body, 8) == 1 && body[16..32] == [0x77; 16])
                            || self.group_rekey && word(body, 8) == 2 && body[16..32] == [0x88; 16],
                        "Sc installed GTK differs from M3",
                    )?,
                    _ => return Err("Sc key flags"),
                }
                self.keys += 1;
            }
            (5, 2) => require(
                body.len() == 20
                    && bytes[6] == 0
                    && body[..16] == [0, 0, 0, 0, 1, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0]
                    && word(body, 16) != 0,
                "Sc EMPTY single-RFH epoch native contract",
            )?,
            (3, 8) => require(body.len() == 52 && body[12..18] == OWN, "Sc MAC identity")?,
            (3, 9) => require(body.len() == 208 && body[16..22] == OWN, "Sc LINK identity")?,
            (3, 10) => require(body.len() == 104 && body[8..14] == AP, "Sc peer identity")?,
            (1, 8) => require(body.len() == 32 && word(body, 8) == 6, "Sc PHY channel")?,
            (1, 0x9f) => require(
                body.len() == 108 && half(body, 8) == 136,
                "Sc TX power policy ceiling",
            )?,
            (5, 0xf) => require(body.len() == 44, "Sc TLC ABI")?,
            (3, 0xc) => require(
                body == [0; 4] && self.queues.iter().all(|q| !q.2),
                "Sc peer removal before queue receipts",
            )?,
            (3, 5) => require(
                body.len() == 24 && word(body, 4) == 1,
                "Sc association residency",
            )?,
            (1, 0xd) => require(
                body.len() == 1948 && half(body, 8) == 0x802 && body[45] == 1 && body[52] == 6,
                "Sc passive scan ABI",
            )?,
            (1, 0x98) => require(body == [1, 0, 0, 0], "Sc NVM chain identity")?,
            (1, 0x9b) => require(body == [1, 0, 0, 0, 17, 0, 0, 0], "Sc coexistence defaults")?,
            (2, 1) => require(
                body == [10, 0, 0, 0, 224, 46, 0, 0],
                "Sc integrated SoC defaults",
            )?,
            (1, 0xc) => require(
                body == [0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0],
                "Sc scan chain defaults",
            )?,
            (1, 0x77) => require(body == [0; 4], "Sc continuously awake defaults")?,
            _ => return Err("unexpected command in Sc composition"),
        }
        self.firmware
            .inject(cmd, if group == 1 { 0 } else { group }, sequence, &response);
        if (group, cmd) == (5, 2) {
            let mut marker = [8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            marker[8..12].copy_from_slice(&body[16..20]);
            if self.fault == Fault::HoldRxFence {
                require(
                    self.held_rx.is_none(),
                    "Sc repeated uncertain receive fence",
                )?;
                self.held_rx = Some(word(body, 16));
            } else {
                self.firmware.inject(0xff, 5, 0x8000, &marker);
            }
        } else if (group, cmd) == (3, 5) {
            self.firmware.inject(
                0xfb,
                3,
                0x8000,
                &[0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
            );
        } else if (group, cmd) == (1, 0xd) {
            self.mpdu(&self.ap.beacon(), false);
            let mut done = [0; 16];
            done[..4].copy_from_slice(&body[..4]);
            done[6] = 1;
            self.firmware.inject(0xf, 0, 0x8000, &done);
        }
        Ok(())
    }

    fn transmit(&mut self, p: Published) -> R {
        require(
            self.queues
                .iter()
                .any(|(id, _, live)| *id == p.queue && *live),
            "Sc TX used unowned queue",
        )?;
        let bytes = &p.bytes;
        require(
            bytes.len() >= 56 && bytes[0] == 0x1c,
            "Sc TX command header",
        )?;
        let len = usize::from(half(bytes, 4));
        let header = ((word(bytes, 8) >> 8) & 31) as usize * 2;
        require(
            matches!(header, 24 | 26)
                && bytes.len() == 32 + len + header.next_multiple_of(4) - header,
            "Sc TX length/padding",
        )?;
        require(
            half(bytes, 2) == ((p.queue & 31) << 8) | (p.pointer.wrapping_sub(1) & 127),
            "Sc TX sequence",
        )?;
        let mut frame = bytes[32..32 + header].to_vec();
        frame.extend_from_slice(&bytes[32 + header.next_multiple_of(4)..]);
        let protected = frame[1] & 0x40 != 0;
        if self.air.len() < 64 {
            self.air
                .push((p.queue, p.pointer, frame[0], self.ap.phase()));
        }
        require(
            (half(bytes, 6) & 2 == 0) == protected,
            "Sc native encryption flag",
        )?;
        let data = frame[0] & 0x0c == 8;
        let eapol =
            data && frame.get(header..header + 8) == Some(&[0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e]);
        if !data || eapol {
            if eapol && self.group_rekey {
                let pdu = frame.get(header + 8..).ok_or("Sc group reply PDU")?;
                let reply = narf_wireless::eapol::KeyFrame::decode(
                    pdu.get(4..).ok_or("Sc group reply header")?,
                    16,
                )
                .ok_or("Sc group reply key frame")?;
                let mut unsigned = pdu.to_vec();
                unsigned[81..97].fill(0);
                require(
                    protected
                        && reply.key_information == 0x302
                        && reply.replay_counter == 3
                        && reply.key_data.is_empty()
                        && reply.key_mic.as_slice()
                            == super::super::handshake::compute_mic(
                                &self.ptk.as_ref().ok_or("Sc group PTK absent")?.kck,
                                &unsigned,
                            ),
                    "Sc actual group response MIC/replay/port",
                )?;
                self.group_reply = true;
                if self.fault == Fault::HoldGroupReply {
                    self.held_tx = Some((p.queue, p.pointer));
                    return Ok(());
                }
            } else if frame[0] == 0xa0 {
                require(
                    self.ap.phase() == ApPhase::Authorized,
                    "Sc disconnect before association",
                )?;
            } else {
                let phase = self.ap.phase();
                let responses = self
                    .ap
                    .receive(&frame)
                    .map_err(|_| "shared AP rejected native Sc management/EAPOL")?;
                if phase == ApPhase::Message2 {
                    use narf_wireless::eapol::{derive_ptk, HmacPrimitive, KeyFrame};
                    struct Sha1;
                    impl HmacPrimitive for Sha1 {
                        fn out_len(&self) -> usize {
                            20
                        }
                        fn mac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
                            narf_crypto::pbkdf2_sha1::hmac_sha1(key, data).to_vec()
                        }
                    }
                    let m2 =
                        KeyFrame::decode(&frame[header + 12..], 16).ok_or("Sc M2 key frame")?;
                    let ptk = derive_ptk(&Sha1, &PMK, &AP, &OWN, &ANONCE, &m2.key_nonce, 16);
                    self.key = Some(ptk.tk.clone());
                    self.ptk = Some(ptk);
                }
                for response in responses {
                    self.mpdu(&response, false);
                }
                if phase == ApPhase::Message4 {
                    self.m4 = true;
                    require(self.keys == 2, "Sc M4 before key receipts")?;
                    if self.fault == Fault::HoldM4 {
                        self.held_tx = Some((p.queue, p.pointer));
                        return Ok(());
                    }
                }
            }
        } else {
            require(
                self.ap.phase() == ApPhase::Authorized
                    && protected == self.ap.protected()
                    && (!protected || self.keys == 2),
                "Sc controlled port/protection",
            )?;
            require(
                frame[1] & 3 == 1
                    && frame[4..10] == AP
                    && frame[10..16] == OWN
                    && frame[header..header + 6] == [0xaa, 0xaa, 3, 0, 0, 0],
                "Sc uplink DS/LLC",
            )?;
            let mut ethernet = frame[16..22].to_vec();
            ethernet.extend_from_slice(&OWN);
            ethernet.extend_from_slice(&frame[header + 6..]);
            if let Some(response) = self.server.receive(&ethernet) {
                self.ethernet(&response);
            }
            self.data.push((ethernet, protected));
        }
        self.firmware.tx_complete(p.queue, p.pointer);
        Ok(())
    }

    fn mpdu(&mut self, frame: &[u8], protected: bool) {
        if self.replies.len() < 64 {
            self.replies.push(frame[0]);
        }
        let mut payload = vec![0; 64];
        payload[..2].copy_from_slice(&(frame.len() as u16).to_le_bytes());
        payload[12..16].copy_from_slice(&(if protected { 0x243u32 } else { 3 }).to_le_bytes());
        payload[40] = 50;
        payload[41] = 60;
        payload[42] = 6;
        payload.extend_from_slice(frame);
        self.firmware.inject(0xc1, 0, 0x8000, &payload);
    }

    fn ethernet(&mut self, ethernet: &[u8]) {
        let protected = self.ap.protected();
        let mut frame = vec![0; 24];
        frame[0] = 8;
        frame[1] = 2 | if protected { 0x40 } else { 0 };
        frame[4..10].copy_from_slice(&ethernet[..6]);
        frame[10..16].copy_from_slice(&AP);
        frame[16..22].copy_from_slice(&ethernet[6..12]);
        if protected {
            self.next_pn += 1;
            let pn = self.next_pn.to_le_bytes();
            let key = if ethernet[0] & 1 != 0 { 1 << 6 } else { 0 };
            frame.extend_from_slice(&[pn[0], pn[1], 0, 0x20 | key, pn[2], pn[3], pn[4], pn[5]]);
        }
        frame.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
        frame.extend_from_slice(&ethernet[12..]);
        self.mpdu(&frame, protected);
    }
}

static HARNESS: IrqSafeSpinLock<Option<(Arc<Device>, Wire)>> = IrqSafeSpinLock::new(None);

fn service() -> R<bool> {
    HARNESS
        .lock()
        .as_mut()
        .ok_or("missing Sc composition")?
        .1
        .service()
}

fn drain() -> bool {
    let device = {
        let mut slot = HARNESS.lock();
        let Some((device, wire)) = slot.as_mut() else {
            return false;
        };
        if wire.service().is_err() {
            return false;
        }
        device.clone()
    };
    let frames = device.step(None);
    let mut progress = !frames.is_empty();
    {
        let mut slot = HARNESS.lock();
        if let Some((_, wire)) = slot.as_mut() {
            wire.received.extend(frames.iter().map(|d| d.bytes.clone()));
            progress |= wire.service().unwrap_or(false);
        }
    }
    device.dispatch(frames);
    progress
}

fn run<F: Future>(future: F, mut progress: impl FnMut() -> R<bool>) -> R<F::Output> {
    let mut future = core::pin::pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    let deadline = narf_time::Deadline::after_ms(3000);
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return Ok(value);
        }
        progress()?;
        if deadline.expired() {
            diagnose("Sc composition future stalled");
            return Err("Sc composition future stalled");
        }
        narf_scheduler::sleep_pumps::run();
        core::hint::spin_loop();
    }
}

struct Guard {
    device: Option<Arc<Device>>,
    #[cfg(feature = "kernel-test")]
    owner: Option<narf_wireless::nl80211::ConnectionOwnerFixture>,
}
impl Guard {
    fn new(secured: bool, fault: Fault) -> R<Self> {
        Self::new_named(secured, fault, None)
    }
    fn new_named(secured: bool, fault: Fault, name: Option<&'static str>) -> R<Self> {
        Self::build_named(secured, fault, name, None)
    }
    fn build_named(
        secured: bool,
        fault: Fault,
        name: Option<&'static str>,
        sources: Option<(&crate::firmware_asset::Asset, &crate::firmware_asset::Asset)>,
    ) -> R<Self> {
        require(
            ACTIVE.lock().is_none()
                && narf_net::iface::lookup(super::super::iwl_ifname()).is_none()
                && name.is_none_or(|name| narf_net::iface::lookup(name).is_none()),
            "live iwlwifi owner exists",
        )?;
        let versions = super::super::firmware_parser_tests::mld_commands();
        let (mut hardware, firmware, trace) = model::station_model();
        model::versions(&mut hardware, &versions);
        if let Some((firmware, pnvm)) = sources {
            let parsed = super::super::parse_ucode(&firmware.bytes)
                .map_err(|_| "Sc source fixture parse")?;
            require(
                parsed.api.commands == versions,
                "Sc source fixture executable/command table mismatch",
            )?;
            hardware.bind_sources(firmware, Some(pnvm))?;
        }
        Device::validate_station_profile(&hardware)?;
        let ap = if secured {
            FakeAp::wpa2(NETWORK, SSID, 6, 7, PMK, ANONCE)
        } else {
            FakeAp::open(NETWORK, SSID, 6, 7)
        }
        .map_err(|_| "shared Sc AP configuration")?;
        let mut wire = Wire {
            firmware,
            trace,
            versions,
            ap,
            server: DhcpServer::new(NETWORK),
            queues: Vec::new(),
            commands: Vec::new(),
            data: Vec::new(),
            received: Vec::new(),
            air: Vec::new(),
            replies: Vec::new(),
            key: None,
            ptk: None,
            group_rekey: false,
            group_reply: false,
            keys: 0,
            next_pn: 0,
            fault,
            held: None,
            held_tx: None,
            held_rx: None,
            m4: false,
            error: None,
        };
        let configured = run(Device::configure(&mut hardware, OWN), || wire.service());
        let nvm = match configured {
            Ok(Ok(nvm)) => nvm,
            _ => {
                // SAFETY: no host future remains and no physical DMA was armed.
                unsafe {
                    model::destroy(hardware);
                }
                return Err(wire.error.unwrap_or("Sc post-INIT configure failed"));
            }
        };
        let (rx_producer, rx_consumer) = narf_ipc::channel();
        let mut state = State {
            hardware,
            scan_uid: 0,
            beacons: Vec::new(),
            connection: None,
            needs_reset: false,
            producer: Some(rx_producer),
            receive_ipc: None,
            eapol: VecDeque::new(),
            tx: core::array::from_fn(|_| None),
            pending: core::array::from_fn(|_| None),
            tx_progress: false,
        };
        let tx = core::array::from_fn(|category| {
            let (producer, consumer) = narf_ipc::channel();
            state.tx[category] = Some(consumer);
            IrqSafeSpinLock::new(Some(producer))
        });
        let source = state.hardware.source_fence()?;
        let device = Arc::new(Device {
            test_name: name,
            state: Mutex::new(state),
            control: Mutex::new(None),
            publication: AtomicBool::new(true),
            source,
            generation: Arc::new(AtomicU64::new(0)),
            quarantined: AtomicBool::new(false),
            admission: IrqSafeSpinLock::new(()),
            mac: OWN,
            irq_vector: None,
            channels: nvm.channels,
            tx_chains: nvm.tx_chains,
            phy: nvm.phy,
            firmware: Vec::new(),
            pnvm: None,
            up: AtomicBool::new(false),
            bssid: AtomicU64::new(0),
            rx: IrqSafeSpinLock::new(Some(rx_consumer)),
            tx,
        });
        *ACTIVE.lock() = Some(device.clone());
        *HARNESS.lock() = Some((device.clone(), wire));
        narf_net::iface::register(device.name(), OWN, send_frame);
        narf_net::iface::set_link_state(device.name(), true); // operator IFF_UP
        device.set_link(false);
        narf_net::iface::install_rx_handler(narf_net::tcp_stack::rx_handler);
        narf_net::iface::install_rx_drain(drain);
        Ok(Self {
            device: Some(device),
            #[cfg(feature = "kernel-test")]
            owner: None,
        })
    }
    fn device(&self) -> &Arc<Device> {
        self.device.as_ref().unwrap()
    }
    #[cfg(feature = "kernel-test")]
    fn register_owner(&mut self, portid: u32) -> R {
        let device = self.device();
        require(
            !narf_wireless::registry::list()
                .iter()
                .any(|i| i.name() == device.name()),
            "Sc owner-close wireless name already registered",
        )?;
        narf_wireless::nl80211::register();
        narf_wireless::registry::register(device.clone());
        self.owner = Some(narf_wireless::nl80211::__connection_owner_for_test(
            device.name(),
            0,
            portid,
            AP,
        ));
        Ok(())
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        #[cfg(feature = "kernel-test")]
        if self.owner.take().is_some() {
            narf_wireless::registry::unregister(self.device().name());
        }
        if let Some(device) = &self.device {
            narf_net::iface::unregister(device.name());
        }
        let wire = HARNESS.lock().take().map(|(device, wire)| {
            drop(device);
            wire
        });
        let active = ACTIVE.lock().take();
        drop(active);
        if let Some(device) = self.device.take() {
            let Ok(device) = Arc::try_unwrap(device) else {
                // A failed lifecycle regression must retain the device-side
                // model storage while a spawned owner still holds Hardware.
                core::mem::forget(wire);
                return;
            };
            // SAFETY: all futures and fixture pointer views are gone; model
            // Hardware was never armed or published to a physical PCI device.
            unsafe {
                model::destroy(device.state.into_inner().hardware);
            }
        }
        drop(wire);
    }
}

fn policy() -> narf_wireless::reg::RegulatoryDomain {
    use narf_wireless::reg::*;
    RegulatoryDomain {
        country_code: *b"US",
        rules: vec![RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2482,
            max_bandwidth_mhz: 20,
            max_power_dbm: 17,
            flags: RegFlags::empty(),
        }],
    }
}
fn request(secured: bool) -> AssociateRequest {
    AssociateRequest {
        bssid: AP,
        ssid: SSID.to_vec(),
        frequency_mhz: 2437,
        channel: 6,
        security: if secured {
            narf_wireless::SecurityConfig::Wpa2 { psk: PMK }
        } else {
            narf_wireless::SecurityConfig::Open
        },
        ie: Vec::new(),
    }
}
fn scan(device: &Device) -> R {
    let request = ScanRequest {
        ssids: vec![SSID.to_vec()],
        channels: vec![6],
        frequencies_mhz: vec![2437],
        active: false,
        random_mac: None,
        colocated_6ghz: false,
        duration_tu: None,
        duration_mandatory: false,
        extra_ies: Vec::new(),
    };
    let bss = run(device.scan(request), service)?.map_err(|_| "Sc native scan failed")?;
    require(
        bss.len() == 1 && bss[0].bssid == AP && bss[0].ssid == SSID && bss[0].channel == 6,
        "Sc native scan did not populate association identity",
    )
}
fn carrier(device: &Device, expected: bool) -> R {
    require(
        device.link_up() == expected
            && narf_net::iface::lookup(device.name())
                .is_some_and(|iface| iface.link_up && iface.carrier == expected),
        "Sc owner/registered carrier mismatch",
    )
}
fn flush() -> R {
    for _ in 0..32 {
        if !drain() {
            return HARNESS.lock().as_ref().unwrap().1.error.map_or(Ok(()), Err);
        }
    }
    Err("Sc packet drain did not become idle")
}

fn composition(secured: bool) -> R {
    let guard = Guard::new(secured, Fault::None)?;
    let device = guard.device();
    carrier(device, false)?;
    require(
        narf_net::dhcp::acquire(device.name(), 400).is_err(),
        "Sc DHCP before association",
    )?;
    scan(device)?;
    run(
        device.associate_in_domain(request(secured), &policy()),
        service,
    )?
    .map_err(|_| "Sc native association failed")?;
    carrier(device, true)?;
    narf_net::iface::set_link_state(device.name(), false);
    // This is the same production physical publication used by station
    // activation, under the retained owner lock just as on native progress.
    {
        let _owner = device.state.try_lock().unwrap();
        device.publish_link(AP, device.generation.load(Ordering::Acquire))?;
    }
    require(
        narf_net::iface::lookup(device.name()).is_some_and(|iface| !iface.link_up && iface.carrier),
        "Sc physical carrier overwrote operator DOWN",
    )?;
    narf_net::iface::set_link_state(device.name(), true);
    require(
        device.connected_bssid() == Some(AP),
        "Sc association BSSID publication",
    )?;
    {
        let slot = HARNESS.lock();
        let wire = &slot.as_ref().unwrap().1;
        require(
            wire.ap.phase() == ApPhase::Authorized && (!secured || (wire.m4 && wire.keys == 2)),
            "Sc native RSNA receipts",
        )?;
    }
    let lease = narf_net::dhcp::dhcp_acquire(device.name(), 0)
        .map_err(|_| "Sc native DHCP lease failed")?;
    require(NETWORK.matches_lease(&lease), "Sc lease terms")?;
    {
        let slot = HARNESS.lock();
        let wire = &slot.as_ref().unwrap().1;
        let seen = wire.server.observations();
        require(
            seen.discovers == 1
                && seen.requests == 1
                && wire.data.len() == 2
                && wire.data.iter().all(|(_, p)| *p == secured),
            "Sc DISCOVER/REQUEST native protection",
        )?;
    }
    let uplink = udp_ipv4(
        AP,
        OWN,
        NETWORK.lease_ip,
        NETWORK.server_ip,
        49152,
        7,
        b"sc-native-uplink",
    );
    narf_net::iface::send_on(device.name(), &uplink).map_err(|_| "Sc IP uplink admission")?;
    flush()?;
    require(
        HARNESS
            .lock()
            .as_ref()
            .unwrap()
            .1
            .data
            .iter()
            .any(|(bytes, p)| bytes == &uplink && *p == secured),
        "Sc exact IP uplink bytes",
    )?;
    let downlink = udp_ipv4(
        OWN,
        AP,
        NETWORK.server_ip,
        NETWORK.lease_ip,
        12345,
        54321,
        b"sc-native-downlink",
    );
    let rx_before = narf_net::iface::snapshot_counters()
        .into_iter()
        .find(|counters| counters.name == device.name())
        .ok_or("Sc RX counters")?
        .rx_packets;
    HARNESS.lock().as_mut().unwrap().1.ethernet(&downlink);
    flush()?;
    require(
        HARNESS
            .lock()
            .as_ref()
            .unwrap()
            .1
            .received
            .contains(&downlink),
        "Sc exact IP downlink bytes",
    )?;
    require(
        narf_net::iface::snapshot_counters()
            .into_iter()
            .find(|counters| counters.name == device.name())
            .is_some_and(|c| c.rx_packets > rx_before),
        "Sc IP downlink did not enter network RX dispatch",
    )?;
    {
        let mut consumer = device.rx.lock();
        let consumer = consumer.as_mut().ok_or("Sc RX IPC not published")?;
        let mut delivered = false;
        while let Ok(Some(frame)) = consumer.try_recv() {
            delivered |= frame.payload() == downlink;
        }
        require(
            delivered,
            "Sc exact downlink bytes absent from native RX IPC",
        )?;
    }
    let before = HARNESS.lock().as_ref().unwrap().1.data.len();
    run(device.disassociate(), service)?.map_err(|_| "Sc native disconnect failed")?;
    carrier(device, false)?;
    {
        let state = device.state.try_lock().unwrap();
        require(
            !state.needs_reset && model::retained(&state.hardware) == (0, 0, 0),
            "Sc acknowledged teardown retained resources",
        )?;
    }
    require(
        narf_net::iface::send_on(device.name(), &uplink).is_err()
            && narf_net::dhcp::acquire(device.name(), 400).is_err(),
        "Sc post-disconnect admission",
    )?;
    flush()?;
    // Drop the static-slot guard before the tail expression: in edition2021
    // a tail temporary otherwise outlives Guard and deadlocks its cleanup.
    let unchanged = HARNESS.lock().as_ref().unwrap().1.data.len() == before;
    require(unchanged, "Sc post-disconnect data reached AP")
}

fn check(run: impl FnOnce() -> R) -> TestResult {
    if ACTIVE.lock().is_some() {
        return TestResult::Skip("live iwlwifi owner exists");
    }
    match run() {
        Ok(()) => TestResult::Pass,
        Err(error) => {
            diagnose(error);
            TestResult::Fail(error)
        }
    }
}

/// Bounded failure-only context. No per-poll logging changes wait timing and
/// no command/key payload, nonce or packet body is printed.
fn diagnose(error: &'static str) {
    use core::fmt::Write;
    let Some(slot) = HARNESS.try_lock() else {
        return;
    };
    let Some((device, wire)) = slot.as_ref() else {
        return;
    };
    let _ = writeln!(narf_console::Writer,
        "Sc fixture failure={error} phase={:?} keys={} m4={} held={:?} queues={:?} air={:?} replies={:?}",
        wire.ap.phase(), wire.keys, wire.m4, wire.held, wire.queues, wire.air, wire.replies);
    for (group, cmd, body) in wire.commands.iter().rev().take(12).rev() {
        let _ = writeln!(
            narf_console::Writer,
            "Sc command {group:02x}:{cmd:02x} len={}",
            body.len()
        );
    }
    if let Some(state) = device.state.try_lock() {
        let _ = writeln!(
            narf_console::Writer,
            "Sc owner reset={} failed={} retained={:?}",
            state.needs_reset,
            state.hardware.is_failed(),
            model::retained(&state.hardware)
        );
    };
}
fn smoke_sc_open_native_association_dhcp_ip() -> TestResult {
    check(|| composition(false))
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/dhcp",
    smoke_sc_open_native_association_dhcp_ip
);
fn smoke_sc_wpa2_native_association_dhcp_ip() -> TestResult {
    check(|| composition(true))
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/dhcp",
    smoke_sc_wpa2_native_association_dhcp_ip
);

fn smoke_sc_m4_cancellation_keeps_controlled_port_and_dma_closed() -> TestResult {
    check(|| {
        let guard = Guard::new(true, Fault::HoldM4)?;
        let device = guard.device();
        scan(device)?;
        let domain = policy();
        let mut future = Box::pin(device.associate_in_domain(request(true), &domain));
        let mut cx = Context::from_waker(Waker::noop());
        let deadline = narf_time::Deadline::after_ms(3000);
        loop {
            require(
                future.as_mut().poll(&mut cx).is_pending(),
                "Sc association completed without M4 receipt",
            )?;
            service()?;
            if HARNESS.lock().as_ref().unwrap().1.m4 {
                break;
            }
            if deadline.expired() {
                diagnose("Sc M4 cancellation fixture stalled");
                return Err("Sc M4 cancellation fixture stalled");
            }
        }
        carrier(device, false)?;
        require(
            narf_net::dhcp::acquire(device.name(), 400).is_err(),
            "Sc DHCP before M4 receipt",
        )?;
        drop(future);
        let state = device
            .state
            .try_lock()
            .ok_or("Sc cancelled future retained state lock")?;
        require(
            state.needs_reset
                && state.connection.is_none()
                && model::retained(&state.hardware) == (0, 2, 1),
            "Sc cancelled M4 released device-owned queues",
        )?;
        drop(state);
        device.step(None);
        require(
            device.state.try_lock().unwrap().hardware.is_failed(),
            "Sc cancelled association pump did not fail closed",
        )?;
        let no_data = HARNESS.lock().as_ref().unwrap().1.data.is_empty();
        require(no_data, "Sc cancelled association sent IP")
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/dhcp",
    smoke_sc_m4_cancellation_keeps_controlled_port_and_dma_closed
);

fn smoke_sc_disconnect_cancellation_and_wrong_receipt_retain_queue_owner() -> TestResult {
    check(|| {
        let guard = Guard::new(false, Fault::HoldRemoval)?;
        let device = guard.device();
        scan(device)?;
        run(
            device.associate_in_domain(request(false), &policy()),
            service,
        )?
        .map_err(|_| "Sc cancel setup association")?;
        let mut future = Box::pin(device.disassociate());
        let mut cx = Context::from_waker(Waker::noop());
        let deadline = narf_time::Deadline::after_ms(3000);
        loop {
            require(
                future.as_mut().poll(&mut cx).is_pending(),
                "Sc disconnect completed before queue receipt",
            )?;
            service()?;
            if HARNESS.lock().as_ref().unwrap().1.held.is_some() {
                break;
            }
            if deadline.expired() {
                diagnose("Sc removal cancellation fixture stalled");
                return Err("Sc removal cancellation fixture stalled");
            }
        }
        carrier(device, false)?;
        drop(future);
        {
            let state = device
                .state
                .try_lock()
                .ok_or("Sc disconnect cancellation retained mutex")?;
            require(
                state.needs_reset
                    && state.connection.is_none()
                    && model::retained(&state.hardware) == (1, 2, 0),
                "Sc unacknowledged queue removal released DMA",
            )?;
        }
        {
            let mut slot = HARNESS.lock();
            let wire = &mut slot.as_mut().unwrap().1;
            let (cmd, group, sequence) = wire.held.unwrap();
            wire.firmware.inject(cmd ^ 1, group, sequence, &[]);
        }
        let mut state = device.state.try_lock().unwrap();
        require(
            state.hardware.poll() == Err("command response identity mismatch"),
            "Sc wrong removal receipt was not rejected",
        )?;
        require(
            state.hardware.is_failed() && model::retained(&state.hardware) == (1, 2, 0),
            "Sc wrong removal receipt freed retained DMA",
        )?;
        let no_data = HARNESS.lock().as_ref().unwrap().1.data.is_empty();
        require(no_data, "Sc failed teardown admitted data")
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/dhcp",
    smoke_sc_disconnect_cancellation_and_wrong_receipt_retain_queue_owner
);

fn smoke_sc_disconnect_overrides_waiting_old_link_publication() -> TestResult {
    check(|| {
        let guard = Guard::new(false, Fault::None)?;
        let device = guard.device();
        scan(device)?;
        run(
            device.associate_in_domain(request(false), &policy()),
            service,
        )?
        .map_err(|_| "Sc racing disconnect setup association")?;
        carrier(device, true)?;
        let control = device.control.try_lock().ok_or("Sc fixture control busy")?;
        let state = device.state.try_lock().ok_or("Sc fixture state busy")?;
        let retired_epoch = device.generation.load(Ordering::Acquire);
        let mut disconnect = Box::pin(device.disassociate());
        require(
            disconnect
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending(),
            "Sc disconnect did not wait for prior control owner",
        )?;
        carrier(device, false)?;
        require(
            device.connected_bssid().is_none(),
            "Sc early disconnect left cached BSSID",
        )?;
        // Attempt the actual old association publication under its state guard,
        // after disconnect's early close but before it can acquire state.
        require(
            state.connection.as_ref().is_some_and(|c| c.authorized),
            "Sc fixture lacks the previous authorized publisher",
        )?;
        require(
            device.publish_link(AP, retired_epoch).is_err(),
            "old native association bypassed close publication generation",
        )?;
        carrier(device, false)?;
        drop(state);
        drop(control);
        run(disconnect, service)?.map_err(|_| "Sc interleaved native disconnect")?;
        // No Device.step runs between teardown and these observations.
        carrier(device, false)?;
        require(
            device.connected_bssid().is_none()
                && narf_net::iface::lookup(device.name()).is_some_and(|i| {
                    i.link_up && i.carrier_up_count == 1 && i.carrier_down_count == 1
                }),
            "Sc old publisher reopened cached peer after completed disconnect",
        )?;
        let state = device
            .state
            .try_lock()
            .ok_or("Sc teardown retained state lock")?;
        require(
            state.connection.is_none()
                && !state.needs_reset
                && model::retained(&state.hardware) == (0, 0, 0),
            "Sc racing disconnect left native peer/queue ownership",
        )
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/dhcp",
    smoke_sc_disconnect_overrides_waiting_old_link_publication
);

#[cfg(feature = "kernel-test")]
fn smoke_sc_socket_owner_close_waits_for_native_m4_then_tears_down() -> TestResult {
    check(|| {
        const NAME: &str = "sc-owner-close-test";
        const PORTID: u32 = 0x5343_c103;
        let mut guard = Guard::new_named(true, Fault::HoldM4, Some(NAME))?;
        guard.register_owner(PORTID)?;
        let device = guard.device();
        scan(device)?;
        let domain = policy();
        let mut association = Box::pin(device.associate_in_domain(request(true), &domain));
        let mut cx = Context::from_waker(Waker::noop());
        let deadline = narf_time::Deadline::after_ms(3000);
        loop {
            require(
                association.as_mut().poll(&mut cx).is_pending(),
                "Sc owner-close setup completed without M4 receipt",
            )?;
            service()?;
            if HARNESS.lock().as_ref().unwrap().1.held_tx.is_some() {
                break;
            }
            if deadline.expired() {
                return Err("Sc owner-close setup stalled before native M4");
            }
        }
        carrier(device, false)?;
        // No control-slot work owns association: it holds state independently.
        require(
            device.control.try_lock().is_some_and(|slot| slot.is_none())
                && device.state.try_lock().is_none(),
            "Sc owner-close fixture did not hold native association state",
        )?;
        let baseline = Arc::strong_count(device);
        // This is the actual registered NETLINK_URELEASE -> autodisconnect
        // worker, not a copied decision or a direct disassociate() invocation.
        narf_net::netlink_generic::notify_release(0, PORTID);
        narf_scheduler::poll_one_round();
        let waited_for_association = Arc::strong_count(device) == baseline + 1;
        {
            let mut harness = HARNESS.lock();
            let wire = &mut harness.as_mut().unwrap().1;
            let (queue, pointer) = wire.held_tx.take().unwrap();
            wire.fault = Fault::None;
            // Release precisely the M4 descriptor observed from actual DMA.
            wire.firmware.tx_complete(queue, pointer);
        }
        let association_result = run(association.as_mut(), service);
        // On a failing association, drop its state guard before driving the
        // independently retained socket-close worker to terminal completion.
        drop(association);
        let deadline = narf_time::Deadline::after_ms(3000);
        let mut worker_complete = false;
        loop {
            let _ = service();
            narf_scheduler::poll_one_round();
            if Arc::strong_count(device) == baseline {
                worker_complete = true;
                break;
            }
            if deadline.expired() {
                break;
            }
            narf_scheduler::sleep_pumps::run();
        }
        require(worker_complete, "Sc socket-close worker retained its task")?;
        require(
            association_result?.is_err(),
            "Sc closing owner allowed stale association carrier publication",
        )?;
        require(
            waited_for_association,
            "Sc socket-close worker returned Busy and abandoned pending association",
        )?;
        carrier(device, false)?;
        let state = device
            .state
            .try_lock()
            .ok_or("Sc owner-close state retained")?;
        require(
            device.connected_bssid().is_none()
                && state.connection.is_none()
                && !state.needs_reset
                && !state.hardware.is_failed()
                && model::retained(&state.hardware) == (0, 0, 0),
            "Sc socket close left an authorized peer or native DMA owners",
        )?;
        drop(state);
        let probe = udp_ipv4(
            AP,
            OWN,
            NETWORK.lease_ip,
            NETWORK.server_ip,
            49154,
            7,
            b"sc-owner-closed",
        );
        require(
            send_frame(&probe, narf_net::TxMeta::default()).is_err()
                && narf_net::iface::send_on(NAME, &probe).is_err()
                && HARNESS.lock().as_ref().unwrap().1.data.is_empty(),
            "Sc socket close admitted orphan IP data",
        )
    })
}
#[cfg(feature = "kernel-test")]
kernel_test_in!(
    "drivers/wireless/iwlwifi/dhcp",
    smoke_sc_socket_owner_close_waits_for_native_m4_then_tears_down
);
