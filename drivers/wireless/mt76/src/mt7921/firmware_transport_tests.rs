use super::*;
use alloc::sync::Arc;
use core::{
    cell::Cell,
    future::Future,
    pin::pin,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

fn firmware(bytes: usize) -> Firmware {
    let mut patch = vec![0u8; 96 + 64 + bytes];
    patch[44..48].copy_from_slice(&1u32.to_be_bytes());
    patch[96..100].copy_from_slice(&2u32.to_be_bytes());
    patch[100..104].copy_from_slice(&160u32.to_be_bytes());
    patch[104..108].copy_from_slice(&(bytes as u32).to_be_bytes());
    patch[108..112].copy_from_slice(&0x900000u32.to_be_bytes());
    patch[112..116].copy_from_slice(&(bytes as u32).to_be_bytes());
    patch[116..120].copy_from_slice(&u32::MAX.to_be_bytes());
    patch[160..].fill(0x55);
    let mut ram = vec![0u8; bytes + 40 + 36];
    ram[..bytes].fill(0xaa);
    ram[bytes + 16..bytes + 20].copy_from_slice(&0x400000u32.to_le_bytes());
    ram[bytes + 20..bytes + 24].copy_from_slice(&(bytes as u32).to_le_bytes());
    ram[bytes + 40 + 2] = 1;
    ram[bytes + 40 + 3] = 1;
    Firmware::prepare(&patch, &ram).unwrap()
}
fn event(cmd: u8, seq: u8, status: u8) -> Vec<u8> {
    let mut event = vec![0; 36];
    event[..4].copy_from_slice(&((7u32 << 27) | 36).to_le_bytes());
    event[24..26].copy_from_slice(&12u16.to_le_bytes());
    event[28] = if cmd == 0x10 { 4 } else { 1 };
    event[29] = seq;
    event[32] = status;
    event
}
#[derive(Debug)]
struct Model {
    ticks: Cell<u64>,
    live: bool,
    owner: Retained<Lease>,
    active: bool,
    frames: Vec<(bool, Vec<u8>)>,
    replies: VecDeque<Vec<u8>>,
    loaded: bool,
    tx_stall: bool,
    rx_stall: bool,
    idle_stall: bool,
    malformed: bool,
    semaphore: u8,
    notifications: usize,
    revoke_on_submit: bool,
    wtbl_stall: bool,
    clc_result: bool,
    packets: VecDeque<Vec<u8>>,
    scan_stall: bool,
    resources: Arc<AtomicUsize>,
    psk: [u8; 32],
    anonce: [u8; 32],
    ap_mac: [u8; 6],
    own_mac: [u8; 6],
}
impl Model {
    fn new() -> Self {
        let resources = Arc::new(AtomicUsize::new(1));
        Self {
            ticks: Cell::new(0),
            live: true,
            owner: Retained {
                storage: Some(Lease(resources.clone())),
                published: false,
            },
            active: false,
            frames: Vec::new(),
            replies: VecDeque::new(),
            loaded: false,
            tx_stall: false,
            rx_stall: false,
            idle_stall: false,
            malformed: false,
            semaphore: 2,
            notifications: 0,
            revoke_on_submit: false,
            wtbl_stall: false,
            clc_result: false,
            packets: VecDeque::new(),
            scan_stall: false,
            resources,
            psk: [0; 32],
            anonce: [0; 32],
            ap_mac: [0; 6],
            own_mac: [0; 6],
        }
    }
}
#[derive(Debug)]
struct Lease(Arc<AtomicUsize>);
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.store(0, Ordering::SeqCst);
    }
}
impl Backend for Model {
    fn now_ns(&self) -> u64 {
        let now = self.ticks.get();
        self.ticks.set(now + 1_000_000);
        now
    }
    fn check(&self) -> Result<(), Error> {
        if self.live {
            Ok(())
        } else {
            Err(Error::Authority)
        }
    }
    fn quiesce(&mut self) -> Result<(), Error> {
        Ok(())
    }
    fn idle(&mut self) -> Result<bool, Error> {
        Ok(!self.idle_stall)
    }
    fn initialize(&mut self) -> Result<(), Error> {
        self.owner.published = true;
        Ok(())
    }
    fn request_driver_own(&mut self) -> Result<(), Error> {
        Ok(())
    }
    fn driver_owned(&mut self) -> Result<bool, Error> {
        Ok(true)
    }
    fn fw_state(&mut self) -> Result<u32, Error> {
        Ok(if self.loaded { 3 } else { 1 })
    }
    fn submit(&mut self, scatter: bool, frame: &[u8]) -> Result<(), Error> {
        if self.active {
            return Err(Error::Busy);
        }
        self.active = true;
        self.frames.push((scatter, frame.to_vec()));
        if !scatter {
            let cmd = frame[36];
            if cmd == 2 {
                self.loaded = true;
            }
            if cmd != 4 {
                for _ in 0..self.notifications {
                    self.replies.push_back(event(1, 0, 0));
                }
                self.notifications = 0;
                let status = if cmd == 0x10 {
                    if frame[64] == 1 {
                        self.semaphore
                    } else {
                        3
                    }
                } else {
                    0
                };
                let mut reply = event(cmd, frame[39], status);
                if frame[43] == 7 {
                    let mut result = [0u8; 8];
                    result[0] = frame[34];
                    reply = runtime_event(1, frame[39], 0, &result);
                } else if cmd == 3 {
                    let mut done = [0u8; 8];
                    done[0] = frame[64];
                    reply = runtime_event(0x0d, 0, 0, &done);
                } else if cmd == 0x8a {
                    let mut caps = capabilities();
                    if self.clc_result {
                        caps[55] |= 1;
                    }
                    reply = runtime_event(0x8a, frame[39], 0, &caps);
                } else if cmd == 0xed && frame[41] == 1 {
                    let mut block = [0u8; 24];
                    block[..4].copy_from_slice(&frame[64..68]);
                    block[4] = 1;
                    block[19] = 1; // hardware type at 0x55b
                    reply = runtime_event(0xed, frame[39], 1, &block);
                } else if cmd == 0xed {
                    reply = runtime_event(0xed, frame[39], 0, &[]);
                } else if cmd == 0x5c {
                    let mut info = [0u8; 72];
                    info[6] = 68;
                    info[8] = 0x12;
                    reply = runtime_event(0x80, frame[39], 0, &info);
                }
                if self.malformed {
                    reply.truncate(10);
                }
                if !(cmd == 0x5c && frame[71] == 0 || cmd == 0x0f || cmd == 3 && self.scan_stall) {
                    self.replies.push_back(reply);
                }
            }
        }
        if self.revoke_on_submit {
            self.live = false;
        }
        Ok(())
    }
    fn tx_complete(&mut self, _: bool) -> Result<bool, Error> {
        if self.tx_stall {
            Ok(false)
        } else {
            self.active = false;
            Ok(true)
        }
    }
    fn receive(&mut self) -> Result<Option<Vec<u8>>, Error> {
        if self.rx_stall {
            Ok(None)
        } else {
            Ok(self.replies.pop_front())
        }
    }
    fn receive_data(&mut self) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.packets.pop_front())
    }
    fn release(&mut self) -> Result<(), Error> {
        self.owner.published = false;
        Ok(())
    }
    fn configure_mac(&mut self) -> Result<(), Error> {
        self.check()
    }
    fn clear_wtbl(&mut self, index: u8) -> Result<(), Error> {
        if index >= 20 {
            return Err(Error::Bounds);
        }
        self.check()
    }
    fn wtbl_idle(&mut self) -> Result<bool, Error> {
        Ok(!self.wtbl_stall)
    }
    fn submit_management(&mut self, frame: &[u8], _wcid: u16) -> Result<(), Error> {
        self.check()?;
        self.frames.push((false, frame.to_vec()));
        if self.psk != [0u8; 32] {
            if let Some(eapol) = super::extract_eapol(frame) {
                if let Some(m2) = eapol
                    .get(4..)
                    .and_then(|b| narf_wireless::eapol::KeyFrame::decode(b, 16))
                {
                    if m2.has_mic() && !m2.key_ack() && m2.key_nonce != [0u8; 32] {
                        let snonce = m2.key_nonce;
                        struct TestHmac;
                        impl narf_wireless::eapol::HmacPrimitive for TestHmac {
                            fn out_len(&self) -> usize {
                                20
                            }
                            fn mac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
                                narf_crypto::pbkdf2_sha1::hmac_sha1(key, data).to_vec()
                            }
                        }
                        let ptk = narf_wireless::eapol::derive_ptk(
                            &TestHmac,
                            &self.psk,
                            &self.ap_mac,
                            &self.own_mac,
                            &self.anonce,
                            &snonce,
                            16,
                        );
                        let mut m3 = narf_wireless::eapol::KeyFrame::empty(16);
                        m3.descriptor_type = narf_wireless::eapol::KEY_DESCRIPTOR_RSN;
                        m3.key_information = narf_wireless::eapol::KI_KEY_TYPE_PAIRWISE
                            | narf_wireless::eapol::KI_KEY_ACK
                            | narf_wireless::eapol::KI_KEY_MIC
                            | narf_wireless::eapol::KI_INSTALL
                            | narf_wireless::eapol::KI_VERSION_HMAC_SHA1_AES;
                        m3.key_length = 16;
                        m3.replay_counter = m2.replay_counter + 1;
                        m3.key_nonce = self.anonce;
                        let mut m3_bytes = m3.into_eapol();
                        let mic_full = narf_crypto::pbkdf2_sha1::hmac_sha1(&ptk.kck, &m3_bytes);
                        m3_bytes[81..97].copy_from_slice(&mic_full[..16]);
                        let m3_frame =
                            super::wrap_eapol_frame(self.ap_mac, self.own_mac, &m3_bytes);
                        let mut m3_packet = vec![0u8; 32 + m3_frame.len()];
                        let len = m3_packet.len();
                        m3_packet[..4].copy_from_slice(&((2u32 << 27) | len as u32).to_le_bytes());
                        m3_packet[4..8].copy_from_slice(&(1u32 << 13).to_le_bytes());
                        m3_packet[12..16].copy_from_slice(&(6u32 << 8).to_le_bytes());
                        m3_packet[28..32].copy_from_slice(&0x00007864u32.to_le_bytes());
                        m3_packet[32..].copy_from_slice(&m3_frame);
                        self.packets.push_back(m3_packet);
                    }
                }
            }
        }
        Ok(())
    }
    fn submit_data(&mut self, frame: &[u8]) -> Result<(), Error> {
        self.check()?;
        self.frames.push((false, frame.to_vec()));
        Ok(())
    }
    fn management_complete(
        &mut self,
    ) -> Result<Option<crate::mt7921::packet_tx::Completion>, Error> {
        self.check()?;
        Ok(Some(crate::mt7921::packet_tx::Completion {
            token: 1,
            status: 0,
        }))
    }
}
fn run<T>(future: impl Future<Output = T>) -> T {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..20000 {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
    }
    panic!("transport wait was not bounded")
}
fn mcu_firmware_header_matches_linux_and_scatter_is_headerless() -> TestResult {
    let frame = command_frame(0x10, 15, &[1, 0, 0, 0]).unwrap();
    if frame.len() != 68
        || frame[..8] != [68, 0, 0, 0x41, 0, 0, 1, 0x80]
        || frame[32..40] != [36, 0, 0, 0x80, 0x10, 0xa0, 3, 15]
    {
        return TestResult::Fail("MCU TXD differs from Linux connac2 framing");
    }
    let mut session = Session::new(Model::new(), firmware(9000));
    let report = match run(session.run()) {
        Ok(report) => report,
        Err(_) => return TestResult::Fail("firmware boot model failed"),
    };
    let scatter: Vec<_> = session
        .backend
        .frames
        .iter()
        .filter(|frame| frame.0)
        .collect();
    if report.bytes_transferred != 18000
        || scatter.len() != 6
        || scatter
            .iter()
            .any(|(_, frame)| frame.len() > 4096 || !matches!(frame[0], 0x55 | 0xaa))
        || !session.backend.owner.published
        || !matches!(session.state, State::Ready(_))
        || run(session.run()) != Err(Error::Busy)
    {
        return TestResult::Fail("scatter framing, ownership or single-attempt state");
    }
    let commands: Vec<_> = session
        .backend
        .frames
        .iter()
        .filter(|frame| !frame.0)
        .map(|(_, frame)| frame[36])
        .collect();
    if commands != [4, 0x10, 5, 7, 0x10, 1, 2] {
        return TestResult::Fail("firmware command order differs from Linux");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mcu_firmware_header_matches_linux_and_scatter_is_headerless
);

fn mcu_firmware_preflight_rejects_truncation_and_metadata_overlap() -> TestResult {
    let fw = firmware(32);
    for length in [0, 31, 92, 95, 96, 159] {
        if Firmware::prepare(&fw.patch[..length], &fw.ram).is_ok() {
            return TestResult::Fail("truncated patch accepted");
        }
    }
    let mut patch = fw.patch.to_vec();
    patch[100..104].copy_from_slice(&100u32.to_be_bytes());
    if Firmware::prepare(&patch, &fw.ram).is_ok() {
        return TestResult::Fail("patch copied its own metadata");
    }
    let mut ram = fw.ram.to_vec();
    ram[32 + 20..32 + 24].copy_from_slice(&u32::MAX.to_le_bytes());
    if Firmware::prepare(&fw.patch, &ram).is_ok() {
        return TestResult::Fail("RAM region exceeded payload");
    }
    let mut patch = fw.patch.to_vec();
    patch[44..48].copy_from_slice(&u32::MAX.to_be_bytes());
    if Firmware::prepare(&patch, &fw.ram).is_ok() {
        return TestResult::Fail("patch region count overflow");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mcu_firmware_preflight_rejects_truncation_and_metadata_overlap
);

fn mcu_firmware_timeouts_and_revocation_preserve_published_memory() -> TestResult {
    for failure in 0..5 {
        let mut model = Model::new();
        let expected = match failure {
            0 => {
                model.tx_stall = true;
                Error::Timeout
            }
            1 => {
                model.rx_stall = true;
                Error::Timeout
            }
            2 => {
                model.malformed = true;
                Error::MalformedEvent
            }
            3 => {
                model.revoke_on_submit = true;
                Error::Authority
            }
            _ => {
                model.semaphore = 0;
                Error::Rejected(0)
            }
        };
        let resources = model.resources.clone();
        let mut session = Session::new(model, firmware(32));
        if run(session.run()) != Err(expected)
            || !matches!(session.state, State::Failed { .. })
            || run(session.run()) != Err(Error::Busy)
        {
            return TestResult::Fail("failed session continued/replayed");
        }
        drop(session);
        if resources.load(Ordering::SeqCst) != 1 {
            return TestResult::Fail("failure released published buffers");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mcu_firmware_timeouts_and_revocation_preserve_published_memory
);

fn mcu_firmware_cancelled_future_cannot_replay_or_free_dma() -> TestResult {
    let mut model = Model::new();
    model.tx_stall = true;
    let resources = model.resources.clone();
    let mut session = Session::new(model, firmware(32));
    {
        let mut future = pin!(session.run());
        if future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return TestResult::Fail("stalled submission completed");
        }
    }
    if session.state != State::Running(Stage::Restart) || run(session.run()) != Err(Error::Busy) {
        return TestResult::Fail("cancelled firmware sequence replayed");
    }
    drop(session);
    if resources.load(Ordering::SeqCst) != 1 {
        return TestResult::Fail("cancellation freed DMA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mcu_firmware_cancelled_future_cannot_replay_or_free_dma
);

fn mcu_firmware_notifications_are_bounded_and_patch_skip_is_explicit() -> TestResult {
    let mut model = Model::new();
    model.notifications = 2;
    model.semaphore = 1;
    let mut session = Session::new(model, firmware(32));
    if !matches!(
        run(session.run()),
        Ok(Report {
            patch_already_loaded: true,
            bytes_transferred: 32,
            ..
        })
    ) || session.events.len() != 2
    {
        return TestResult::Fail("patch skip or notification preservation");
    }
    let mut model = Model::new();
    model.notifications = 33;
    if run(Session::new(model, firmware(32)).run()) != Err(Error::EventOverflow) {
        return TestResult::Fail("unsolicited events exhausted an unbounded queue");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mcu_firmware_notifications_are_bounded_and_patch_skip_is_explicit
);

fn mcu_firmware_shutdown_frees_only_after_verified_idle() -> TestResult {
    for stuck in [false, true] {
        let model = Model::new();
        let resources = model.resources.clone();
        let mut session = Session::new(model, firmware(32));
        if run(session.run()).is_err() {
            return TestResult::Fail("setup boot failed");
        }
        session.backend.idle_stall = stuck;
        if run(session.shutdown()) != if stuck { Err(Error::Timeout) } else { Ok(()) } {
            return TestResult::Fail("shutdown idle result");
        }
        drop(session);
        if resources.load(Ordering::SeqCst) != if stuck { 1 } else { 0 } {
            return TestResult::Fail("shutdown reclaimed DMA before idle");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mcu_firmware_shutdown_frees_only_after_verified_idle
);

// Match the installed MT7922 format-2 image layout, including its opaque
// trailer gap and the non-downloadable CLC region; no firmware bytes embedded.
fn mcu_dma_mt7922_image_layout() -> TestResult {
    let mut patch = vec![0u8; 137632];
    patch[44..48].copy_from_slice(&1u32.to_be_bytes());
    for (offset, value) in [
        (96, 0x40002u32),
        (100, 160),
        (104, 137472),
        (108, 0x900000),
        (112, 137472),
        (116, 0x01000000),
    ] {
        patch[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }
    let mut ram = vec![0u8; 1231252];
    let table = ram.len() - 36 - 6 * 40;
    let lengths = [341904u32, 292816, 15312, 8144, 97168, 475488];
    let addresses = [9547776u32, 33643520, 4211712, 34643968, 3760193536, 0];
    for i in 0..6 {
        let region = table + i * 40;
        ram[region + 16..region + 20].copy_from_slice(&addresses[i].to_le_bytes());
        ram[region + 20..region + 24].copy_from_slice(&lengths[i].to_le_bytes());
        ram[region + 25] = if i == 5 { 2 } else { 0 };
        ram[region + 24] = if i == 0 {
            33
        } else if i == 5 {
            64
        } else {
            1
        };
    }
    // Structural stand-in for the opaque CLC payload, with the real extent.
    ram[755344..755348].copy_from_slice(&475488u32.to_le_bytes());
    ram[755349] = 1;
    let tail = ram.len() - 36;
    ram[tail + 2] = 6;
    ram[tail + 3] = 2;
    let Ok(fw) = Firmware::prepare(&patch, &ram) else {
        return TestResult::Fail("real MT7922 layout rejected");
    };
    if fw.patch_regions.len() != 1
        || fw.patch_regions[0].mode != 0x80000009
        || fw.ram_regions.len() != 5
        || fw.override_addr != 9547776
        || fw.ram_regions.iter().any(|r| r.mode != 0x80000009)
        || fw.ram_regions.last().unwrap().bytes.end != 755344
    {
        return TestResult::Fail("MT7922 encrypted or non-downloadable regions");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mcu_dma_mt7922_image_layout
);

fn runtime_event(eid: u8, seq: u8, ext: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; 36 + payload.len()];
    let len = bytes.len();
    bytes[..4].copy_from_slice(&((7u32 << 27) | len as u32).to_le_bytes());
    bytes[24..26].copy_from_slice(&((len - 24) as u16).to_le_bytes());
    bytes[28] = eid;
    bytes[29] = seq;
    bytes[32] = ext;
    bytes[36..].copy_from_slice(payload);
    bytes
}
fn capabilities() -> Vec<u8> {
    let mut bytes = vec![4, 0, 0, 0];
    for (kind, value) in [
        (7u32, &[2u8, 0x11, 0x22, 0x33, 0x44, 0x55][..]),
        (8, &[1, 1, 1, 2, 2, 0, 1, 1, 1, 1, 3, 1][..]),
        (0x18, &[1][..]),
        (0x20, &[0x56, 0x34, 0x12, 0, 0, 0, 0, 0][..]),
    ] {
        bytes.extend_from_slice(&kind.to_le_bytes());
        bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
        bytes.extend_from_slice(value);
    }
    bytes
}
fn mcu_runtime_header_formats_and_status() -> TestResult {
    use super::station::Command;
    let ce = Command::Ce {
        id: 0x8a,
        query: false,
    }
    .encode(15, &[])
    .unwrap();
    let ext = Command::Extended { id: 1, query: true }
        .encode(1, &[0; 24])
        .unwrap();
    let uni = Command::Unified { id: 2 }.encode(2, &[0; 4]).unwrap();
    if ce.len() != 64
        || ce[32..40] != [32, 0, 0, 0x80, 0x8a, 0xa0, 1, 15]
        || ext[36..44] != [0xed, 0xa0, 0, 1, 0, 1, 0, 1]
        || uni.len() != 52
        || uni[32..44] != [20, 0, 2, 0, 0, 0xa0, 0, 2, 0, 0, 0, 7]
    {
        return TestResult::Fail("post-ROM CE/ext/unified wire headers");
    }
    let mut session = Session::new(Model::new(), firmware(32));
    let mut response = [0u8; 8];
    response[0] = 2;
    response[4..8].copy_from_slice(&0x12345678u32.to_le_bytes());
    session
        .backend
        .replies
        .push_back(runtime_event(1, 1, 0, &response));
    if run(session.exchange(Command::Unified { id: 2 }, &[0; 4]))
        != Err(Error::RejectedCommand(0x12345678))
    {
        return TestResult::Fail("unified rejection discarded or truncated");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/station",
    mcu_runtime_header_formats_and_status
);
fn mcu_nic_capability_parser_rejects_incomplete_identity() -> TestResult {
    let bytes = capabilities();
    let info = NicCapabilities::parse(&bytes).unwrap();
    if info.mac != [2, 0x11, 0x22, 0x33, 0x44, 0x55]
        || info.phy.spatial_streams != 2
        || info.phy.bands != 3
        || !info.has_6ghz
        || info.chip_capabilities != 0x123456
    {
        return TestResult::Fail("capabilities were inferred or misdecoded");
    }
    for end in 0..bytes.len() {
        if NicCapabilities::parse(&bytes[..end]).is_ok() {
            return TestResult::Fail("truncated capability table accepted");
        }
    }
    for bad in [0u8, 1, 0xff] {
        let mut invalid = bytes.clone();
        invalid[12] = bad;
        if bad == 0 {
            invalid[12..18].fill(0);
        }
        if NicCapabilities::parse(&invalid).is_ok() {
            return TestResult::Fail("invalid MAC accepted");
        }
    }
    let mut duplicate = bytes.clone();
    duplicate[0] = 5;
    duplicate.extend_from_slice(&bytes[4..18]);
    if NicCapabilities::parse(&duplicate).is_ok() {
        return TestResult::Fail("duplicate identity accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/station",
    mcu_nic_capability_parser_rejects_incomplete_identity
);
fn mcu_post_firmware_identity_and_calibration_are_real_commands() -> TestResult {
    let mut session = Session::new(Model::new(), firmware(32));
    if run(session.initialize_radio()) != Err(Error::Busy) || !session.backend.frames.is_empty() {
        return TestResult::Fail("radio configuration before firmware-ready");
    }
    if run(session.run()).is_err() {
        return TestResult::Fail("boot failed");
    }
    let before = session.backend.frames.len();
    let info = match run(session.initialize_radio()) {
        Ok(info) => info,
        Err(_) => return TestResult::Fail("post-firmware configuration failed"),
    };
    let frames = &session.backend.frames[before..];
    if frames.len() != 4
        || frames[0].1[36] != 0x8a
        || frames[1].1[41] != 1
        || frames[1].1[64..68] != [0x50, 5, 0, 0]
        || frames[2].1[41] != 0x21
        || frames[2].1[64..] != [0, 1, 0, 0]
        || info.hardware_type != 1
        || session.state != State::RadioReady(info)
        || run(session.initialize_radio()) != Err(Error::Busy)
    {
        return TestResult::Fail("real identity/EFUSE sequence or replay guard");
    }
    if run(session.shutdown()).is_err() {
        return TestResult::Fail("shutdown failed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/station",
    mcu_post_firmware_identity_and_calibration_are_real_commands
);
fn mcu_post_firmware_timeout_retains_owner_and_failure_stage() -> TestResult {
    let mut session = Session::new(Model::new(), firmware(32));
    if run(session.run()).is_err() {
        return TestResult::Fail("boot failed");
    }
    session.backend.rx_stall = true;
    let resources = session.backend.resources.clone();
    if run(session.initialize_radio()) != Err(Error::Timeout)
        || session.state
            != (State::Failed {
                stage: Stage::NicCapabilities,
                error: Error::Timeout,
            })
        || run(session.initialize_radio()) != Err(Error::Busy)
    {
        return TestResult::Fail("configuration timeout/replay guard");
    }
    drop(session);
    if resources.load(Ordering::SeqCst) != 1 {
        return TestResult::Fail("post-firmware failure released DMA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/station",
    mcu_post_firmware_timeout_retains_owner_and_failure_stage
);

fn clc_table(index: u8, package: u8, byte: u8) -> Vec<u8> {
    let mut table = vec![0u8; 42];
    table[..4].copy_from_slice(&42u32.to_le_bytes());
    table[4] = index;
    table[5] = 1;
    table[6] = 1;
    table[7] = package;
    table[16..20].copy_from_slice(b"00AB");
    table[20..22].copy_from_slice(&20u16.to_le_bytes());
    table[22..].fill(byte);
    table
}
fn mcu_clc_world_limits_select_package_and_validate_before_dispatch() -> TestResult {
    let mut fw = firmware(32);
    let mut tables = clc_table(0, 0, 0xaa);
    tables.extend_from_slice(&clc_table(0, 1, 0xbb));
    tables.extend_from_slice(&clc_table(3, 0, 0xcc));
    fw.ram = tables.clone().into();
    fw.clc_regions.clear();
    fw.clc_regions.push(0..tables.len());
    let commands = match fw.world_limits(1, true) {
        Ok(commands) => commands,
        Err(_) => return TestResult::Fail("valid CLC world table rejected"),
    };
    if commands.len() != 2
        || commands[0][..14] != [1, 0, 96, 0, 0, 1, 0, 1, b'0', b'0', b'A', b'B', 0, 0]
        || commands[0][76..] != [0xbb; 20]
        || commands[1][4] != 3
        || commands[1][76..] != [0xcc; 20]
    {
        return TestResult::Fail("CLC package/country/payload/header mismatch");
    }
    for length in [0u32, 15, 1000000] {
        let mut bad = tables.clone();
        bad[..4].copy_from_slice(&length.to_le_bytes());
        if station::validate_clc_tables(&bad).is_ok() {
            return TestResult::Fail("invalid CLC table length accepted");
        }
    }
    let mut missing = clc_table(0, 0, 0);
    missing[16..18].copy_from_slice(b"US");
    fw.ram = missing.clone().into();
    fw.clc_regions.clear();
    fw.clc_regions.push(0..missing.len());
    if fw.world_limits(0, false) != Err(Error::UnsupportedFirmware) {
        return TestResult::Fail("missing world rules silently bypassed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/station",
    mcu_clc_world_limits_select_package_and_validate_before_dispatch
);

fn mcu_station_cancel_and_wtbl_timeout_are_terminal() -> TestResult {
    let mut session = Session::new(Model::new(), firmware(32));
    if run(session.run()).is_err() {
        return TestResult::Fail("firmware boot");
    }
    session.backend.rx_stall = true;
    {
        let mut future = pin!(session.initialize_radio());
        let mut cx = Context::from_waker(Waker::noop());
        if future.as_mut().poll(&mut cx).is_ready() {
            return TestResult::Fail("expected identity RX wait");
        }
    }
    if session.state != State::Running(Stage::NicCapabilities)
        || run(session.initialize_radio()) != Err(Error::Busy)
        || !session.backend.owner.published
    {
        return TestResult::Fail("cancelled initialization was replayed or freed");
    }
    let mut stalled = Session::new(Model::new(), firmware(32));
    if run(stalled.run()).is_err() {
        return TestResult::Fail("firmware boot");
    }
    stalled.backend.wtbl_stall = true;
    if run(stalled.initialize_radio()) != Err(Error::Timeout)
        || stalled.state
            != (State::Failed {
                stage: Stage::MacInitialize,
                error: Error::Timeout,
            })
    {
        return TestResult::Fail("WTBL wait was unbounded or lost stage");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/station",
    mcu_station_cancel_and_wtbl_timeout_are_terminal
);

fn mcu_clc_commands_reach_dma_and_consume_capability_requested_result() -> TestResult {
    for responses in [false, true] {
        let mut fw = firmware(32);
        let mut table = clc_table(0, 1, 0xbb);
        table.extend_from_slice(&clc_table(3, 0, 0xcc));
        fw.ram = table.clone().into();
        fw.clc_regions.push(0..table.len());
        let mut model = Model::new();
        model.clc_result = responses;
        let mut session = Session::new(model, fw);
        if run(session.run()).is_err() {
            return TestResult::Fail("boot");
        }
        let info = match run(session.initialize_radio()) {
            Ok(info) => info,
            Err(_) => return TestResult::Fail("CLC init sequence"),
        };
        if info.world_limit_commands != 2
            || info.channel_configuration != if responses { Some(0x12) } else { None }
        {
            return TestResult::Fail("CLC result expectations differ from NIC capability");
        }
        let commands: Vec<_> = session
            .backend
            .frames
            .iter()
            .filter(|(scatter, f)| !scatter && f[36] == 0x5c)
            .collect();
        if commands.len() != 2
            || commands[0].1[64 + 76..] != [0xbb; 20]
            || commands[1].1[64 + 4] != 3
            || commands[0].1[71] != u8::from(responses)
        {
            return TestResult::Fail("CLC country table never reached real command submission");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/station",
    mcu_clc_commands_reach_dma_and_consume_capability_requested_result
);

fn scan_beacon(channel: u8, ssid: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; 32 + 36 + 2 + ssid.len() + 3];
    let len = packet.len();
    packet[..4].copy_from_slice(&((2u32 << 27) | len as u32).to_le_bytes());
    packet[4..8].copy_from_slice(&(1u32 << 13).to_le_bytes());
    packet[12..16].copy_from_slice(&(u32::from(channel) << 8).to_le_bytes());
    packet[28..32].copy_from_slice(&0x00007864u32.to_le_bytes());
    let frame = &mut packet[32..];
    frame[0] = 0x80;
    frame[10..16].copy_from_slice(&[2, 1, 2, 3, 4, 5]);
    frame[16..22].copy_from_slice(&[2, 1, 2, 3, 4, 5]);
    frame[32..34].copy_from_slice(&100u16.to_le_bytes());
    frame[34..36].copy_from_slice(&0x11u16.to_le_bytes());
    frame[37] = ssid.len() as u8;
    frame[38..38 + ssid.len()].copy_from_slice(ssid);
    frame[38 + ssid.len()..].copy_from_slice(&[3, 1, channel]);
    packet
}
fn mcu_passive_scan_wire_layout_and_beacon_validation() -> TestResult {
    let body = scan::scan_request(127, &[1, 6, 11]).unwrap();
    if body.len() != 1186
        || body[..8] != [127, 0, 0, 1, 0, 0, 32, 1]
        || body[158..166] != [4, 3, 1, 1, 1, 6, 1, 11]
        || body[1110..1116] != [255; 6]
        || body[224..1110].iter().any(|b| *b != 0)
    {
        return TestResult::Fail("passive CONNAC2 scan wire layout");
    }
    for channels in [&[][..], &[0], &[12], &[1, 1]] {
        if scan::scan_request(1, channels).is_ok() {
            return TestResult::Fail("invalid or non-world channels accepted");
        }
    }
    let packet = scan_beacon(6, b"narf-test");
    let Some(bss) = scan::beacon(&packet, 2) else {
        return TestResult::Fail("valid beacon");
    };
    if bss.ssid != b"narf-test"
        || bss.signal_dbm != Some(-50)
        || bss.channel != 6
        || bss.beacon_interval != 100
    {
        return TestResult::Fail("RX group/IE/signal parse");
    }
    let mut forwarded = packet.clone();
    let length = forwarded.len() as u32;
    forwarded[..4].copy_from_slice(&((7u32 << 27) | (1 << 16) | length).to_le_bytes());
    if scan::beacon(&forwarded, 2).is_none() {
        return TestResult::Fail("firmware-forwarded normal beacon rejected");
    }
    for end in 0..packet.len() {
        if scan::beacon(&packet[..end], 2).is_some() {
            return TestResult::Fail("truncated beacon accepted");
        }
    }
    for (offset, mask) in [(7, 8u8), (9, 32), (10, 128), (11, 1)] {
        let mut bad = packet.clone();
        bad[offset] |= mask;
        if scan::beacon(&bad, 2).is_some() {
            return TestResult::Fail("FCS/translated/AMSDU/length error accepted");
        }
    }
    let mut bad = packet.clone();
    *bad.last_mut().unwrap() = 11;
    if scan::beacon(&bad, 2).is_some() {
        return TestResult::Fail("DS/RX channel mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/scan",
    mcu_passive_scan_wire_layout_and_beacon_validation
);
fn mcu_passive_scan_dispatches_real_setup_and_deduplicates_bss() -> TestResult {
    let mut session = Session::new(Model::new(), firmware(32));
    if run(session.run()).is_err() || run(session.initialize_radio()).is_err() {
        return TestResult::Fail("radio init");
    }
    session.backend.packets.push_back(scan_beacon(6, &[]));
    session
        .backend
        .packets
        .push_back(scan_beacon(6, b"narf-test"));
    session
        .backend
        .packets
        .push_back(scan_beacon(11, b"off-channel"));
    session.backend.packets.push_back(vec![0; 8]);
    let before = session.backend.frames.len();
    let report = match run(session.scan_passive(&[1, 6])) {
        Ok(report) => report,
        Err(_) => return TestResult::Fail("hardware scan model failed"),
    };
    if report.bss.len() != 1
        || report.bss[0].ssid != b"narf-test"
        || report.received != 4
        || report.ignored != 1
        || report.truncated
        || !matches!(session.state, State::ScanReady(_))
    {
        return TestResult::Fail("scan observations/deduplication/state");
    }
    let frames = &session.backend.frames[before..];
    if frames.len() != 6
        || frames[0].1[34] != 1
        || frames[1].1[34] != 2
        || frames[2].1[36] != 0x0f
        || frames[3].1[41] != 0x46
        || frames[4].1[41] != 0x4e
        || frames[5].1[36] != 3
        || frames[5].1[66] != 0
        || frames[5].1[69] != 0
    {
        return TestResult::Fail("VIF/domain/MAC/RX/passive scan sequence");
    }
    for channel in frames[2].1[76..].chunks_exact(8) {
        if channel[4..8] != [2, 0, 0, 0] {
            return TestResult::Fail("channel domain allows active radiation");
        }
    }
    let before = session.backend.frames.len();
    if run(session.scan_passive(&[6])).is_err() || session.backend.frames.len() != before + 1 {
        return TestResult::Fail("repeat scan rebuilt VIF or reused stale completion");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/scan",
    mcu_passive_scan_dispatches_real_setup_and_deduplicates_bss
);
fn mcu_passive_scan_timeout_cancel_and_stale_completion_retain_dma() -> TestResult {
    let mut session = Session::new(Model::new(), firmware(32));
    if run(session.run()).is_err() || run(session.initialize_radio()).is_err() {
        return TestResult::Fail("radio init");
    }
    session.backend.scan_stall = true;
    let before = session.backend.frames.len();
    if !matches!(run(session.scan_passive(&[12])), Err(Error::Bounds))
        || session.backend.frames.len() != before
    {
        return TestResult::Fail("invalid scan published commands");
    }
    let mut done = [0u8; 8];
    done[0] = 127;
    session
        .backend
        .replies
        .push_back(runtime_event(0x0d, 0, 0, &done));
    if !matches!(run(session.scan_passive(&[1])), Err(Error::Timeout))
        || session.state
            != (State::Failed {
                stage: Stage::ScanWait,
                error: Error::Timeout,
            })
        || !session.backend.owner.published
    {
        return TestResult::Fail("stale completion accepted or timeout freed owner");
    }
    let mut cancelled = Session::new(Model::new(), firmware(32));
    if run(cancelled.run()).is_err() || run(cancelled.initialize_radio()).is_err() {
        return TestResult::Fail("radio init");
    }
    cancelled.backend.scan_stall = true;
    {
        let mut future = pin!(cancelled.scan_passive(&[1]));
        let mut cx = Context::from_waker(Waker::noop());
        if future.as_mut().poll(&mut cx).is_ready() {
            return TestResult::Fail("scan should wait");
        }
    }
    if !matches!(run(cancelled.scan_passive(&[1])), Err(Error::Busy))
        || !cancelled.backend.owner.published
    {
        return TestResult::Fail("cancelled scan replayed or freed DMA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/scan",
    mcu_passive_scan_timeout_cancel_and_stale_completion_retain_dma
);

fn mcu_live_join_open_dispatches_auth_assoc_and_sta_record() -> TestResult {
    let mut session = Session::new(Model::new(), firmware(32));
    if run(session.run()).is_err() || run(session.initialize_radio()).is_err() {
        return TestResult::Fail("radio init");
    }
    let own = [2, 0x11, 0x22, 0x33, 0x44, 0x55];
    let ap = [2, 1, 2, 3, 4, 5];
    let bss = ScanBss {
        bssid: ap,
        ssid: b"narf-join".to_vec(),
        channel: 6,
        signal_dbm: Some(-45),
        capability: 1, // ESS, open
        beacon_interval: 100,
        information_elements: vec![
            0, 9, b'n', b'a', b'r', b'f', b'-', b'j', b'o', b'i', b'n', 1, 4, 0x82, 0x84, 0x8b,
            0x96, 3, 1, 6,
        ],
    };
    // Packet 1: unrelated beacon
    session
        .backend
        .packets
        .push_back(scan_beacon(6, b"other-bss"));

    // Packet 2: Authentication response (subtype 0xb0) from AP to own MAC
    let mut auth_resp = vec![0u8; 30];
    auth_resp[0] = 0xb0;
    auth_resp[4..10].copy_from_slice(&own);
    auth_resp[10..16].copy_from_slice(&ap);
    auth_resp[16..22].copy_from_slice(&ap);
    auth_resp[24..30].copy_from_slice(&[0, 0, 2, 0, 0, 0]); // Alg 0, Seq 2, Status 0
    let mut auth_packet = vec![0u8; 32 + auth_resp.len()];
    let len = auth_packet.len();
    auth_packet[..4].copy_from_slice(&((2u32 << 27) | len as u32).to_le_bytes());
    auth_packet[4..8].copy_from_slice(&(1u32 << 13).to_le_bytes());
    auth_packet[12..16].copy_from_slice(&(6u32 << 8).to_le_bytes());
    auth_packet[28..32].copy_from_slice(&0x00007864u32.to_le_bytes());
    auth_packet[32..].copy_from_slice(&auth_resp);
    session.backend.packets.push_back(auth_packet);

    // Packet 3: Association response (subtype 0x10) from AP to own MAC with AID 42
    let mut assoc_resp = vec![0u8; 30];
    assoc_resp[0] = 0x10;
    assoc_resp[4..10].copy_from_slice(&own);
    assoc_resp[10..16].copy_from_slice(&ap);
    assoc_resp[16..22].copy_from_slice(&ap);
    assoc_resp[24..26].copy_from_slice(&1u16.to_le_bytes()); // Capability: ESS
    assoc_resp[26..28].copy_from_slice(&0u16.to_le_bytes()); // Status: 0
    assoc_resp[28..30].copy_from_slice(&(42u16 | 0xc000).to_le_bytes()); // AID 42
    let mut assoc_packet = vec![0u8; 32 + assoc_resp.len()];
    let len = assoc_packet.len();
    assoc_packet[..4].copy_from_slice(&((2u32 << 27) | len as u32).to_le_bytes());
    assoc_packet[4..8].copy_from_slice(&(1u32 << 13).to_le_bytes());
    assoc_packet[12..16].copy_from_slice(&(6u32 << 8).to_le_bytes());
    assoc_packet[28..32].copy_from_slice(&0x00007864u32.to_le_bytes());
    assoc_packet[32..].copy_from_slice(&assoc_resp);
    session.backend.packets.push_back(assoc_packet);

    let before = session.backend.frames.len();
    let res = run(session.associate_station(
        &bss,
        b"narf-join",
        crate::mt7921::association::Security::Open,
    ));
    if res != Ok(42) {
        return TestResult::Fail("associate_station failed");
    }
    match session.state {
        State::Associated {
            peer, channel, aid, ..
        } => {
            if peer != ap || channel != 6 || aid != 42 {
                return TestResult::Fail("associated state mismatch");
            }
        }
        _ => return TestResult::Fail("session state not Associated"),
    }
    let frames = &session.backend.frames[before..];
    let ch_switch = frames.iter().find(|(scatter, f)| {
        !scatter
            && f.len() >= 42
            && f[36] == 0xed
            && f[41] == crate::mt7921::regs::MCU_EXT_CMD_CHANNEL_SWITCH
    });
    if ch_switch.is_none() {
        return TestResult::Fail("channel switch command not emitted");
    }
    let sta_rec = frames.iter().find(|(scatter, f)| {
        !scatter
            && f.len() >= 42
            && f[36] == 0xed
            && f[41] == crate::mt7921::txrx::MCU_EXT_CMD_STA_REC_UPDATE
    });
    if sta_rec.is_none() {
        return TestResult::Fail("STA_REC_UPDATE not emitted");
    }

    if run(session.disassociate_station()).is_err() {
        return TestResult::Fail("disassociate_station failed");
    }
    match session.state {
        State::RadioReady(_) => {}
        _ => return TestResult::Fail("session state not RadioReady after disassociate"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/join",
    mcu_live_join_open_dispatches_auth_assoc_and_sta_record
);

fn mcu_live_join_peer_rejection_and_timeout() -> TestResult {
    let mut session = Session::new(Model::new(), firmware(32));
    if run(session.run()).is_err() || run(session.initialize_radio()).is_err() {
        return TestResult::Fail("radio init");
    }
    let own = [2, 0x11, 0x22, 0x33, 0x44, 0x55];
    let ap = [2, 1, 2, 3, 4, 5];
    let bss = ScanBss {
        bssid: ap,
        ssid: b"narf-join".to_vec(),
        channel: 6,
        signal_dbm: Some(-45),
        capability: 1,
        beacon_interval: 100,
        information_elements: vec![
            0, 9, b'n', b'a', b'r', b'f', b'-', b'j', b'o', b'i', b'n', 1, 4, 0x82, 0x84, 0x8b,
            0x96, 3, 1, 6,
        ],
    };
    let mut auth_resp = vec![0u8; 30];
    auth_resp[0] = 0xb0;
    auth_resp[4..10].copy_from_slice(&own);
    auth_resp[10..16].copy_from_slice(&ap);
    auth_resp[16..22].copy_from_slice(&ap);
    auth_resp[24..30].copy_from_slice(&[0, 0, 2, 0, 1, 0]); // Status: 1 (rejected)
    let mut auth_packet = vec![0u8; 32 + auth_resp.len()];
    let len = auth_packet.len();
    auth_packet[..4].copy_from_slice(&((2u32 << 27) | len as u32).to_le_bytes());
    auth_packet[4..8].copy_from_slice(&(1u32 << 13).to_le_bytes());
    auth_packet[12..16].copy_from_slice(&(6u32 << 8).to_le_bytes());
    auth_packet[28..32].copy_from_slice(&0x00007864u32.to_le_bytes());
    auth_packet[32..].copy_from_slice(&auth_resp);
    session.backend.packets.push_back(auth_packet);

    let res = run(session.associate_station(
        &bss,
        b"narf-join",
        crate::mt7921::association::Security::Open,
    ));
    if res != Err(Error::MalformedEvent) && !matches!(session.state, State::Failed { .. }) {
        return TestResult::Fail("rejection should fail join");
    }
    if !session.backend.owner.published {
        return TestResult::Fail("DMA should stay published on join failure");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/join",
    mcu_live_join_peer_rejection_and_timeout
);

fn mcu_live_join_wpa2_psk_dispatches_4way_handshake_and_secure_sta_record() -> TestResult {
    let mut model = Model::new();
    let own = [2, 0x11, 0x22, 0x33, 0x44, 0x55];
    let ap = [2, 1, 2, 3, 4, 5];
    let psk = [0x55u8; 32];
    let anonce = [0xaau8; 32];
    model.psk = psk;
    model.anonce = anonce;
    model.ap_mac = ap;
    model.own_mac = own;

    let mut session = Session::new(model, firmware(32));
    if run(session.run()).is_err() || run(session.initialize_radio()).is_err() {
        return TestResult::Fail("radio init");
    }

    let rsn = narf_wireless::rsn::RsnIe::wpa2_psk_ccmp().encode_body();
    let mut ies = vec![
        0,
        9,
        b'n',
        b'a',
        b'r',
        b'f',
        b'-',
        b'j',
        b'o',
        b'i',
        b'n',
        1,
        4,
        0x82,
        0x84,
        0x8b,
        0x96,
        3,
        1,
        6,
        48,
        rsn.len() as u8,
    ];
    ies.extend_from_slice(&rsn);
    let bss = ScanBss {
        bssid: ap,
        ssid: b"narf-join".to_vec(),
        channel: 6,
        signal_dbm: Some(-45),
        capability: 1 | 0x10,
        beacon_interval: 100,
        information_elements: ies,
    };

    // 1. Auth response (status 0)
    let mut auth_resp = vec![0u8; 30];
    auth_resp[0] = 0xb0;
    auth_resp[4..10].copy_from_slice(&own);
    auth_resp[10..16].copy_from_slice(&ap);
    auth_resp[16..22].copy_from_slice(&ap);
    auth_resp[24..30].copy_from_slice(&[0, 0, 2, 0, 0, 0]);
    let mut auth_packet = vec![0u8; 32 + auth_resp.len()];
    let len = auth_packet.len();
    auth_packet[..4].copy_from_slice(&((2u32 << 27) | len as u32).to_le_bytes());
    auth_packet[4..8].copy_from_slice(&(1u32 << 13).to_le_bytes());
    auth_packet[12..16].copy_from_slice(&(6u32 << 8).to_le_bytes());
    auth_packet[28..32].copy_from_slice(&0x00007864u32.to_le_bytes());
    auth_packet[32..].copy_from_slice(&auth_resp);
    session.backend.packets.push_back(auth_packet);

    // 2. Assoc response (status 0, aid 42)
    let mut assoc_resp = vec![0u8; 30];
    assoc_resp[0] = 0x10;
    assoc_resp[4..10].copy_from_slice(&own);
    assoc_resp[10..16].copy_from_slice(&ap);
    assoc_resp[16..22].copy_from_slice(&ap);
    assoc_resp[24..26].copy_from_slice(&0x0031u16.to_le_bytes());
    assoc_resp[26..28].copy_from_slice(&0u16.to_le_bytes());
    assoc_resp[28..30].copy_from_slice(&(42u16 | 0xc000).to_le_bytes());
    let mut assoc_packet = vec![0u8; 32 + assoc_resp.len()];
    let len = assoc_packet.len();
    assoc_packet[..4].copy_from_slice(&((2u32 << 27) | len as u32).to_le_bytes());
    assoc_packet[4..8].copy_from_slice(&(1u32 << 13).to_le_bytes());
    assoc_packet[12..16].copy_from_slice(&(6u32 << 8).to_le_bytes());
    assoc_packet[28..32].copy_from_slice(&0x00007864u32.to_le_bytes());
    assoc_packet[32..].copy_from_slice(&assoc_resp);
    session.backend.packets.push_back(assoc_packet);

    // 3. EAPOL M1 from AP
    let mut m1 = narf_wireless::eapol::KeyFrame::empty(16);
    m1.descriptor_type = narf_wireless::eapol::KEY_DESCRIPTOR_RSN;
    m1.key_information = narf_wireless::eapol::KI_KEY_TYPE_PAIRWISE
        | narf_wireless::eapol::KI_KEY_ACK
        | narf_wireless::eapol::KI_VERSION_HMAC_SHA1_AES;
    m1.key_length = 16;
    m1.replay_counter = 1;
    m1.key_nonce = anonce;
    let m1_pdu = m1.into_eapol();
    let m1_frame = super::wrap_eapol_frame(ap, own, &m1_pdu);
    let mut m1_packet = vec![0u8; 32 + m1_frame.len()];
    let len = m1_packet.len();
    m1_packet[..4].copy_from_slice(&((2u32 << 27) | len as u32).to_le_bytes());
    m1_packet[4..8].copy_from_slice(&(1u32 << 13).to_le_bytes());
    m1_packet[12..16].copy_from_slice(&(6u32 << 8).to_le_bytes());
    m1_packet[28..32].copy_from_slice(&0x00007864u32.to_le_bytes());
    m1_packet[32..].copy_from_slice(&m1_frame);
    session.backend.packets.push_back(m1_packet);

    let before = session.backend.frames.len();
    let res = run(session.associate_station(
        &bss,
        b"narf-join",
        crate::mt7921::association::Security::Wpa2Psk { psk },
    ));
    if res != Ok(42) {
        return TestResult::Fail("associate_station WPA2 failed");
    }
    match session.state {
        State::Associated {
            peer, channel, aid, ..
        } => {
            if peer != ap || channel != 6 || aid != 42 {
                return TestResult::Fail("associated state mismatch");
            }
        }
        _ => return TestResult::Fail("session state not Associated"),
    }

    let frames = &session.backend.frames[before..];
    let eapol_frames: Vec<_> = frames
        .iter()
        .filter_map(|(scatter, f)| {
            if !scatter {
                super::extract_eapol(f)
            } else {
                None
            }
        })
        .collect();
    if eapol_frames.len() < 2 {
        return TestResult::Fail("expected at least M2 and M4 emitted");
    }

    let secure_sta_rec = frames.iter().find(|(scatter, f)| {
        !scatter
            && f.len() >= 42
            && f[36] == 0xed
            && f[41] == crate::mt7921::txrx::MCU_EXT_CMD_STA_REC_UPDATE
            && f.len() >= 64 + 44
            && f[64..]
                .windows(4)
                .any(|w| u16::from_le_bytes([w[0], w[1]]) == 0x12)
    });
    if secure_sta_rec.is_none() {
        return TestResult::Fail("secure STA_REC with key tag 0x12 not emitted");
    }

    if run(session.disassociate_station()).is_err() {
        return TestResult::Fail("disassociate_station failed");
    }
    match session.state {
        State::RadioReady(_) => {}
        _ => return TestResult::Fail("session state not RadioReady after disassociate"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/join",
    mcu_live_join_wpa2_psk_dispatches_4way_handshake_and_secure_sta_record
);

fn mcu_ethernet_tx_rx_frame_transport() -> TestResult {
    let mut session = Session::new(Model::new(), firmware(32));
    if run(session.run()).is_err() || run(session.initialize_radio()).is_err() {
        return TestResult::Fail("radio init");
    }

    // Test TX:
    let eth = vec![
        2, 1, 2, 3, 4, 5, // DA
        2, 0x11, 0x22, 0x33, 0x44, 0x55, // SA
        0x08, 0x00, // EtherType: IPv4
        1, 2, 3, 4, 5, 6, 7, 8, // payload
    ];
    let before = session.backend.frames.len();
    if run(session.send_ethernet(&eth)).is_err() {
        return TestResult::Fail("send_ethernet failed");
    }
    if session.backend.frames.len() != before + 1 {
        return TestResult::Fail("send_ethernet frame not recorded");
    }
    let last = &session.backend.frames.last().unwrap().1;
    if last != &eth {
        return TestResult::Fail("transmitted payload mismatch");
    }

    // Test RX (CONNAC2 packet containing 802.11 QoS Data with LLC/SNAP):
    let mut dot11 = Vec::new();
    dot11.extend_from_slice(&[0x88, 0x02]); // QoS Data, from-DS
    dot11.extend_from_slice(&[0x00, 0x00]); // duration
    dot11.extend_from_slice(&[2, 0x11, 0x22, 0x33, 0x44, 0x55]); // Addr1: DA
    dot11.extend_from_slice(&[2, 1, 2, 3, 4, 5]); // Addr2: BSSID
    dot11.extend_from_slice(&[2, 1, 2, 3, 4, 5]); // Addr3: SA
    dot11.extend_from_slice(&[0x00, 0x00]); // seq
    dot11.extend_from_slice(&[0x00, 0x00]); // QoS control
    dot11.extend_from_slice(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00]); // LLC/SNAP IPv4
    dot11.extend_from_slice(&[10, 20, 30, 40]); // payload

    let mut rx_packet = vec![0u8; 32 + dot11.len()];
    let len = rx_packet.len();
    rx_packet[..4].copy_from_slice(&((2u32 << 27) | len as u32).to_le_bytes());
    rx_packet[4..8].copy_from_slice(&(1u32 << 13).to_le_bytes());
    rx_packet[12..16].copy_from_slice(&(6u32 << 8).to_le_bytes());
    rx_packet[28..32].copy_from_slice(&0x00007864u32.to_le_bytes());
    rx_packet[32..].copy_from_slice(&dot11);
    session.backend.packets.push_back(rx_packet);

    let received = session
        .backend
        .receive_data()
        .expect("receive_data")
        .expect("packet present");
    let frame = super::rx_frame(&received).expect("rx_frame parse");
    let eth_out = super::to_ethernet(frame).expect("to_ethernet parse");
    if eth_out.len() != 14 + 4
        || eth_out[..6] != [2, 0x11, 0x22, 0x33, 0x44, 0x55]
        || eth_out[6..12] != [2, 1, 2, 3, 4, 5]
        || eth_out[12..14] != [0x08, 0x00]
        || eth_out[14..] != [10, 20, 30, 40]
    {
        return TestResult::Fail("translated Ethernet frame mismatch");
    }

    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mcu_ethernet_tx_rx_frame_transport
);

fn native_data_packet(qos: bool) -> Vec<u8> {
    let mut frame = vec![0u8; if qos { 26 } else { 24 }];
    frame[..2].copy_from_slice(&[if qos { 0x88 } else { 0x08 }, 0x02]);
    frame[4..10].copy_from_slice(&[2, 0x11, 0x22, 0x33, 0x44, 0x55]);
    frame[10..16].copy_from_slice(&[2, 1, 2, 3, 4, 5]);
    frame[16..22].copy_from_slice(&[2, 6, 7, 8, 9, 10]);
    frame.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 0x08, 0x00, 1, 2, 3]);
    let mut packet = vec![0u8; 24];
    packet[..4].copy_from_slice(&((2u32 << 27) | (24 + frame.len()) as u32).to_le_bytes());
    packet.extend_from_slice(&frame);
    packet
}

fn mt76_native_ethernet_conversion_rejects_unsupported_frame_layouts() -> TestResult {
    let packet = native_data_packet(true);
    let frame = &packet[24..];
    let Some(ethernet) = to_ethernet(frame) else {
        return TestResult::Fail("valid native QoS data rejected");
    };
    if ethernet
        != [
            2, 0x11, 0x22, 0x33, 0x44, 0x55, 2, 6, 7, 8, 9, 10, 0x08, 0x00, 1, 2, 3,
        ]
    {
        return TestResult::Fail("native address/SNAP conversion");
    }
    let mut invalid = Vec::new();
    invalid.push(ethernet); // An Ethernet frame is not a native 802.11 packet.
    for (offset, value) in [
        (0, 0x80),  // Beacon.
        (0, 0x48),  // Null data.
        (0, 0x89),  // Nonzero protocol version.
        (1, 0x03),  // Four-address WDS.
        (1, 0x06),  // More fragments.
        (1, 0x42),  // Protected payload without a decrypt/replay path.
        (1, 0x82),  // HT control changes header length.
        (22, 1),    // Nonzero fragment number.
        (24, 0x80), // A-MSDU requires deaggregation.
        (26, 0),    // Missing SNAP header.
        (32, 0),    // A length field is not an EtherType.
    ] {
        let mut bad = frame.to_vec();
        bad[offset] = value;
        invalid.push(bad);
    }
    for len in 0..34 {
        invalid.push(frame[..len].to_vec());
    }
    for bad in invalid {
        if to_ethernet(&bad).is_some() {
            return TestResult::Fail("unsupported native frame became Ethernet");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mt76_native_ethernet_conversion_rejects_unsupported_frame_layouts
);

fn mt76_receive_discards_bad_descriptors_and_other_station_frames() -> TestResult {
    let mut session = Session::new(Model::new(), firmware(32));
    if run(session.run()).is_err() || run(session.initialize_radio()).is_err() {
        return TestResult::Fail("radio init");
    }
    let State::RadioReady(info) = session.state else {
        return TestResult::Fail("radio state");
    };
    let packet = native_data_packet(true);
    session.backend.packets.push_back(packet.clone());
    if session.receive_ethernet() != Err(Error::Busy) || session.backend.packets.len() != 1 {
        return TestResult::Fail("unassociated receive consumed data");
    }
    session.backend.packets.clear();
    session.state = State::Associated {
        info,
        peer: [2, 1, 2, 3, 4, 5],
        channel: 6,
        aid: 42,
    };
    for (offset, value) in [
        (3, 0),       // Invalid RX packet discriminator.
        (7, 0x02),    // Descriptor integrity-error bit.
        (24, 0x80),   // Management frame.
        (25, 0x42),   // Still-protected native payload.
        (24 + 4, 4),  // Unicast to another station.
        (24 + 10, 4), // A different transmitter/AP.
        (24 + 16, 3), // Multicast source address.
    ] {
        let mut bad = packet.clone();
        bad[offset] = value;
        session.backend.packets.push_back(bad);
    }
    session.backend.packets.push_back(packet.clone());
    let expected = to_ethernet(&packet[24..]).unwrap();
    if session.receive_ethernet() != Ok(Some(expected))
        || !session.backend.packets.is_empty()
        || session.receive_ethernet() != Ok(None)
    {
        return TestResult::Fail("rejected hardware/native packets reached Ethernet");
    }
    for _ in 0..17 {
        session.backend.packets.push_back(vec![0; 32]);
    }
    session.backend.packets.push_back(packet);
    if session.receive_ethernet() != Ok(None) || session.backend.packets.len() != 2 {
        return TestResult::Fail("malformed RX burst exceeded bounded work");
    }
    if !matches!(session.receive_ethernet(), Ok(Some(_))) {
        return TestResult::Fail("valid packet stranded behind malformed burst");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mt76_receive_discards_bad_descriptors_and_other_station_frames
);
