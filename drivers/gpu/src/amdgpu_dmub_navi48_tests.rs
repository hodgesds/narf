use super::*;
use alloc::{collections::BTreeMap, sync::Arc, vec};
use core::{
    future::Future,
    sync::atomic::AtomicBool,
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
#[path = "amdgpu_dmub_navi48_mailbox_tests.rs"]
mod mailbox_tests;
const DCN: u64 = 0x10000;
const NBIO: u64 = 0x30000;
struct Fake {
    regs: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
    bytes: Vec<u32>,
    dirty: bool,
    stop: bool,
    pwait: bool,
    boot: bool,
    released: Arc<AtomicBool>,
    reject: Option<u32>,
    revoke: Option<(u32, Cap<BusDeviceCap, Write>)>,
    mailbox: usize,
    invalidated: bool,
    gpint: bool,
    version: u32,
    commands: bool,
    caps: bool,
    aux: bool,
    aux_status: u8,
    notify: bool,
    corrupt: Option<(usize, u8)>,
    aux_corrupt: Option<(usize, u8)>,
    complete_pointer: Option<u32>,
    /// Firmware acknowledges inbox0 commands (DMCUB_SCRATCH17).
    inbox0: bool,
    /// dmub_feature_caps.fw_assisted_mclk_switch_ver the caps query reports.
    fams_version: u8,
    cea: bool,
    cea_seen: Vec<[u8; 64]>,
}
impl Fake {
    fn slot(&self, offset: usize) -> [u8; 64] {
        let mut bytes = [0; 64];
        for (i, word) in bytes.chunks_exact_mut(4).enumerate() {
            word.copy_from_slice(&self.bytes[offset / 4 + i].to_le_bytes());
        }
        bytes
    }
    fn put_slot(&mut self, offset: usize, bytes: [u8; 64]) {
        for (i, word) in bytes.chunks_exact(4).enumerate() {
            self.bytes[offset / 4 + i] = u32::from_le_bytes(word.try_into().unwrap());
        }
        self.invalidated = false;
    }
    fn event(&mut self, event: [u8; 64]) {
        let wp = self.regs[&(DCN + 0x1de * 4)] as usize;
        self.put_slot(self.mailbox + 8192 + wp, event);
        self.regs.insert(DCN + 0x1de * 4, ((wp + 64) % 8192) as u32);
    }
    fn execute(&mut self, next: u32) {
        assert!(!self.dirty, "inbox published before HDP flush");
        let rp = self.regs[&(DCN + 0x1d7 * 4)] as usize;
        assert_eq!(next as usize, (rp + 64) % 8192);
        let offset = self.mailbox + rp;
        let mut request = self.slot(offset);
        match request[0] {
            6 if self.caps => {
                assert_eq!(&request[..4], &[6, 0, 1, 14]);
                request[2] = 0;
                request[4] = 1;
                request[5] = self.fams_version;
                request[16] = 1;
            }
            79 if self.cea => {
                self.cea_seen.push(request);
                let offset = u16::from_le_bytes([request[4], request[5]]);
                assert_eq!(&request[..4], &[79, 0, 0, 16]);
                assert_eq!(&request[6..9], &[8, 128, 0]);
                assert_eq!(&request[17..20], &[0; 3]);
                request[4..20].fill(0);
                if offset == 120 {
                    request[4] = 1;
                    request[5] = 1;
                    request[6] = 1;
                    request[7..9].copy_from_slice(&3u16.to_le_bytes());
                    request[9..11].copy_from_slice(&48u16.to_le_bytes());
                    request[11..13].copy_from_slice(&144u16.to_le_bytes());
                } else {
                    request[4] = 2;
                    request[5..7].copy_from_slice(&offset.to_le_bytes());
                    request[7] = 1;
                }
            }
            82 => {
                assert_eq!(request[3], 12);
                assert_eq!(&request[8..12], &[0; 4]);
                request[5] = 1;
                request[12..16].fill(0);
            }
            70 if self.aux => {
                assert_eq!(request[3], 36);
                assert_eq!(&request[8..10], &4000u16.to_le_bytes());
                assert_eq!(&request[12..16], &[0; 4]);
                assert!(request[18] <= 16);
                if self.notify {
                    let mut event = [0; 64];
                    event[..8].copy_from_slice(&[2, 0, 0, 4, request[4], 0, 1, 0]);
                    self.event(event);
                }
                let mut reply = [0; 64];
                reply[0] = 1;
                reply[3] = 28;
                reply[8] = request[4];
                reply[12] = self.aux_status;
                if request[17] & 0x10 != 0 {
                    reply[13] = request[18];
                    for i in 0..request[18] as usize {
                        reply[16 + i] = 0x40 + i as u8;
                    }
                }
                if let Some((index, value)) = self.aux_corrupt {
                    reply[index] = value;
                }
                self.event(reply);
            }
            _ => {}
        }
        if let Some((index, value)) = self.corrupt {
            request[index] = value;
        }
        self.put_slot(offset, request);
        self.regs
            .insert(DCN + 0x1d7 * 4, self.complete_pointer.unwrap_or(next));
    }
}
impl Io for Fake {
    fn read(&mut self, address: u64) -> u32 {
        *self.regs.get(&address).unwrap_or(&0)
    }
    fn write(&mut self, address: u64, value: u32) {
        // Secure instruction/stack windows and security state belong to PSP.
        for reg in [
            0x1a5, 0x1a6, 0x1ad, 0x1ae, 0x1b5, 0x1b6, 0x1b7, 0x1b8, 0x1ce,
        ] {
            assert_ne!(address, DCN + reg * 4, "DMUB overwrote PSP secure window");
        }
        self.writes.push((address, value));
        if self.reject.map(|reg| DCN + u64::from(reg) * 4) != Some(address) {
            self.regs.insert(address, value);
        }
        if address == 0x7f000 {
            self.dirty = false;
            self.invalidated = true;
        }
        if address == DCN + 0x1d2 * 4 && self.inbox0 {
            assert_eq!(
                self.regs.get(&(DCN + 0x1f4 * 4)),
                Some(&0),
                "stale inbox0 ack"
            );
            self.regs.insert(DCN + 0x1f4 * 4, 1);
        }
        if address == DCN + 0x1f8 * 4 && value == 0x10010000 && self.gpint {
            self.regs.insert(address, 0x10000);
            self.regs.insert(DCN + 0x1ea * 4, self.version);
        }
        if address == DCN + 0x1d6 * 4
            && self.commands
            && self.regs.get(&(DCN + 0x1e3 * 4)) == Some(&3)
        {
            for _ in 0..127 {
                let rp = self.regs[&(DCN + 0x1d7 * 4)];
                if rp == value {
                    break;
                }
                self.execute((rp + 64) % 8192);
                if self.complete_pointer.is_some() {
                    break;
                }
            }
        }
        if address == DCN + 0x1f8 * 4 && value == 0x10020000 && self.stop {
            self.regs.insert(address, 0x20000);
            self.regs.insert(DCN + 0x1ea * 4, 0xdeaddead);
            if self.pwait {
                *self.regs.entry(DCN + 0x1f6 * 4).or_default() |= 1 << 20;
            }
        }
        if address == DCN + 0x200 * 4
            && value & 1 == 0
            && self.regs[&(DCN + 0x1f6 * 4)] & (1 << 16) != 0
        {
            *self.regs.get_mut(&(DCN + 0x1f6 * 4)).unwrap() &= !(1 << 20);
            assert!(!self.dirty, "released with unflushed storage");
            self.released.store(true, Ordering::SeqCst);
            if self.boot {
                self.regs.insert(DCN + 0x1e3 * 4, 3);
            }
        }
        if let Some((reg, cap)) = self.revoke {
            if address == DCN + u64::from(reg) * 4 {
                cap.revoke();
            }
        }
    }
    fn upload(&mut self, _: MmioRegion, offset: u64, value: u32) {
        self.dirty = true;
        self.bytes[offset as usize / 4] = value;
    }
    fn download(&mut self, _: MmioRegion, offset: u64) -> u32 {
        assert!(
            self.invalidated,
            "firmware reply read without HDP invalidation"
        );
        self.bytes[offset as usize / 4]
    }
}
fn image() -> Vec<u8> {
    let mut b = fw::tests::combined(256, 0);
    b[12] = 4;
    b[14] = 0;
    let offset = b.len() - 256 - 64 + 12;
    b[offset..offset + 4].copy_from_slice(&0x0a00_0c00u32.to_le_bytes());
    let meta = b.len() - 256 - 64;
    b[meta + 20..meta + 24].copy_from_slice(&1280u32.to_le_bytes());
    b[meta + 24..meta + 26].copy_from_slice(&4u16.to_le_bytes());
    b
}
fn fixture() -> (Pool, Engine<Fake>) {
    let prepared = Prepared::new(&image(), &[0x55, 0xaa, 0x42, 0x43], 0x00110023).unwrap();
    let bytes = prepared.layout.size() as u64;
    let map = MmioRegion {
        phys: narf_memory::PhysAddr::new(0x90400000),
        virt: 0,
        len: bytes,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // SAFETY: fake owns I/O; this inert mapping is never dereferenced.
    let pool = unsafe { Pool::from_owned_range(map, 0x8_0040_0000) }.unwrap();
    let mut regs = BTreeMap::new();
    for (reg, value) in [
        (0x1f6, 0x10000),
        (0x341, 0),
        (0xca, 0x10000),
        (0x475, 0x800),
        (0x476, 0xbff),
        (0x477, 0x100),
        (0x1a5, 0x60000000),
        (0x1ad, 0x800001ff),
        (0x1b5, 0x01000000),
        (0x1b6, 1),
        (0x1a6, 0x61000000),
        (0x1ae, 0x8109ffff),
        (0x1b7, 0x01100000),
        (0x1b8, 1),
    ] {
        regs.insert(DCN + reg * 4, value);
    }
    regs.insert(NBIO + 0x12d * 4, 0x7f000);
    let engine = Engine {
        io: Fake {
            regs,
            writes: Vec::new(),
            bytes: vec![u32::MAX; bytes as usize / 4],
            dirty: false,
            stop: true,
            pwait: true,
            boot: true,
            released: Arc::new(AtomicBool::new(false)),
            reject: None,
            revoke: None,
            mailbox: prepared.layout.region(fw::Window::Mailbox).offset as usize,
            invalidated: false,
            gpint: true,
            version: 0x0a000c00,
            commands: true,
            caps: true,
            aux: true,
            aux_status: 0,
            notify: false,
            corrupt: None,
            aux_corrupt: None,
            complete_pointer: None,
            inbox0: true,
            fams_version: 0x21,
            cea: false,
            cea_seen: Vec::new(),
        },
        authority: Cap::bootstrap(),
        layout: Layout {
            dcn: DCN,
            nbio: NBIO,
        },
        memory: pool.reserve(bytes).unwrap(),
        prepared,
        state: State::Prepared,
        status: None,
        mailbox: mailbox::Mailbox::new(),
        hw_lock_uncertain: false,
    };
    (pool, engine)
}
fn tmr() -> Range<u64> {
    0x8_0100_0000..0x8_0200_0000
}
fn run<T>(f: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}
fn dmub_navi48_preserves_psp_windows_and_starts_dcn401() -> TestResult {
    let (pool, mut engine) = fixture();
    let secure = engine.io.regs.clone();
    run(engine.quiesce()).unwrap();
    if engine.state != State::Reset
        || engine.io.regs[&(DCN + 0x1f6 * 4)] != 0x100000
        || engine.io.regs[&(DCN + 0x200 * 4)] != 1
        || engine.io.regs[&(DCN + 0x341 * 4)] != 0x100
    {
        return TestResult::Fail("wrong DCN401 reset registers");
    }
    let report = run(engine.start(tmr())).unwrap();
    if report.firmware_version != 0x0a000c00
        || report.boot_status != 3
        || report.outbox != report.inbox + 8192
        || engine.state != State::Running
    {
        return TestResult::Fail("DMUB boot report");
    }
    for (reg, value) in [
        (0x1f6, 0x90000),
        (0x341, 0),
        (0x1d4, 0x64000000),
        (0x1d5, 8192),
        (0x1dc, 0x64002000),
        (0x1dd, 8192),
        (0x1d8, 0xa0000010),
        (0x1f1, 0x1a0070),
        (0x1f2, 0x110023),
        (0x1bd, report.inbox as u32),
        (0x1be, 8),
    ] {
        if engine.io.regs.get(&(DCN + reg * 4)).copied() != Some(value) {
            return TestResult::Fail("window/mailbox address units or reset encoding");
        }
    }
    for reg in [0x1a5, 0x1a6, 0x1ad, 0x1ae, 0x1b5, 0x1b6, 0x1b7, 0x1b8] {
        if engine.io.regs.get(&(DCN + reg * 4)) != secure.get(&(DCN + reg * 4)) {
            return TestResult::Fail("secure window changed");
        }
    }
    let bios = engine.prepared.layout.region(fw::Window::Vbios);
    if engine.io.bytes[bios.offset as usize / 4] != 0x4342aa55 {
        return TestResult::Fail("board VBIOS not staged");
    }
    if engine
        .io
        .writes
        .iter()
        .any(|(reg, _)| *reg == DCN + 0x342 * 4 || *reg == 0x50000 + 0xd1 * 4)
    {
        return TestResult::Fail("legacy DMUB/HDP register used on Navi48");
    }
    let shared = engine.prepared.layout.region(fw::Window::SharedState);
    if shared.size != 1536
        || engine.io.regs[&(DCN + 0x1a3 * 4)] != 0x800005ff
        || engine.io.regs[&(DCN + 0x19a * 4)] != 0x00400000 + shared.offset
        || engine.io.regs[&(DCN + 0x19b * 4)] != 8
        || engine.io.bytes[shared.offset as usize / 4..(shared.offset + shared.size) as usize / 4]
            .iter()
            .any(|v| *v != 0)
    {
        return TestResult::Fail("DCN401 shared state not bounded, staged or mapped");
    }
    let writes = engine.io.writes.len();
    if run(engine.start(tmr())) != Err(Error::Busy)
        || run(engine.quiesce()) != Err(Error::Busy)
        || engine.io.writes.len() != writes
    {
        return TestResult::Fail("DMUB replay");
    }
    drop(engine);
    if pool.available() != 0 {
        return TestResult::Fail("running DMUB storage recycled");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi48",
    dmub_navi48_preserves_psp_windows_and_starts_dcn401
);
fn dmub_navi48_rejects_untrusted_windows_before_upload() -> TestResult {
    for case in 0..6 {
        let (pool, mut engine) = fixture();
        let bytes = engine.memory.size();
        run(engine.quiesce()).unwrap();
        match case {
            0 => {
                engine.io.regs.insert(DCN + 0x1b6 * 4, 8);
            }
            1 => {
                engine.io.regs.insert(DCN + 0x1ae * 4, 0x0109ffff);
            }
            2 => {
                engine.io.regs.insert(DCN + 0x1ad * 4, 0x9fffffff);
            }
            3 => {
                engine.io.regs.insert(DCN + 0x475 * 4, u32::MAX);
            }
            4 => {
                engine.io.regs.insert(DCN + 0x1ce * 4, 1 << 16);
            }
            _ => {
                engine.authority.revoke();
            }
        }
        let writes = engine.io.writes.len();
        if run(engine.start(tmr())).is_ok()
            || engine.io.bytes[0] != u32::MAX
            || engine.io.writes.len() != writes
            || engine.io.released.load(Ordering::SeqCst)
        {
            return TestResult::Fail("untrusted DMUB start touched memory/windows");
        }
        drop(engine);
        if pool.available() != bytes {
            return TestResult::Fail("unpublished storage leaked");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi48",
    dmub_navi48_rejects_untrusted_windows_before_upload
);
fn dmub_navi48_stop_boot_timeout_readback_and_revocation() -> TestResult {
    for case in 0..4 {
        let (pool, mut engine) = fixture();
        if case == 0 {
            engine.io.stop = false;
            if run(engine.quiesce()) != Err(Error::StopTimeout) || engine.io.writes.len() != 1 {
                return TestResult::Fail("unacknowledged STOP forced reset");
            }
        } else {
            run(engine.quiesce()).unwrap();
            let error = match case {
                1 => {
                    engine.io.boot = false;
                    Error::BootTimeout
                }
                2 => {
                    engine.io.reject = Some(0x1bd);
                    Error::Readback
                }
                _ => {
                    engine.io.revoke = Some((0x1f6, engine.authority));
                    Error::Revoked
                }
            };
            if run(engine.start(tmr())) != Err(error) || engine.status.is_some() {
                return TestResult::Fail("bad DMUB start accepted");
            }
        }
        if engine.state != State::Failed {
            return TestResult::Fail("failed DMUB state");
        }
        let size = engine.memory.size();
        drop(engine);
        if pool.available() != if case == 0 { size } else { 0 } {
            return TestResult::Fail("wrong DMUB storage lifetime after fault");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi48",
    dmub_navi48_stop_boot_timeout_readback_and_revocation
);
fn dmub_navi48_cancellation_preserves_stage_and_storage() -> TestResult {
    for boot in [false, true] {
        let (pool, mut engine) = fixture();
        let bytes = engine.memory.size();
        if boot {
            run(engine.quiesce()).unwrap();
            engine.io.boot = false;
            let released = engine.io.released.clone();
            {
                let mut future = core::pin::pin!(engine.start(tmr()));
                for _ in 0..1024 {
                    if future
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_ready()
                    {
                        return TestResult::Fail("stalled start completed");
                    }
                    if released.load(Ordering::SeqCst) {
                        break;
                    }
                }
            }
            if !released.load(Ordering::SeqCst)
                || engine.state != State::Starting
                || run(engine.start(tmr())) != Err(Error::Busy)
            {
                return TestResult::Fail("cancelled boot replayed");
            }
        } else {
            engine.io.stop = false;
            {
                let mut future = core::pin::pin!(engine.quiesce());
                if future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_ready()
                {
                    return TestResult::Fail("stalled stop completed");
                }
            }
            if engine.state != State::Stopping || run(engine.quiesce()) != Err(Error::Busy) {
                return TestResult::Fail("cancelled stop replayed");
            }
        }
        drop(engine);
        if pool.available() != if boot { 0 } else { bytes } {
            return TestResult::Fail("cancelled DMUB backing lifetime");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi48",
    dmub_navi48_cancellation_preserves_stage_and_storage
);
fn dmub_navi48_preparation_and_layout_are_generation_specific() -> TestResult {
    let bytes = image();
    for case in 0..4 {
        let mut bad = bytes.clone();
        let o = bad.len() - 256 - 64;
        match case {
            0 => bad[12] = 3,
            1 => bad[o + 24..o + 26].copy_from_slice(&5u16.to_le_bytes()),
            2 => bad[o + 20..o + 24].copy_from_slice(&0u32.to_le_bytes()),
            _ => bad.truncate(bad.len() - 1),
        }
        if Prepared::new(&bad, &[0x55, 0xaa], 0).is_ok() {
            return TestResult::Fail("invalid DCN4 firmware/shared state accepted");
        }
    }
    let mut backing = vec![0; 0x80000 / 4];
    let mut g = crate::amdgpu_gmc_navi48::tests::descriptor(&mut backing);
    let mut dcn = g.ip_blocks[0];
    dcn.hw_id = ip::HW_ID_DCN;
    dcn.major = 4;
    dcn.minor = 1;
    dcn.revision = 0;
    dcn.base_addrs[2] = 0x4000;
    g.ip_blocks.push(dcn);
    if Layout::resolve(&g).unwrap().dcn != DCN {
        return TestResult::Fail("DCN4 used wrong bank");
    }
    let b = g.ip_blocks.last_mut().unwrap();
    b.minor = 0;
    b.revision = 1;
    if Layout::resolve(&g).is_err() {
        return TestResult::Fail("normalized DCN4 rejected");
    }
    g.ip_blocks.last_mut().unwrap().major = 3;
    if Layout::resolve(&g).is_ok() {
        return TestResult::Fail("legacy DCN admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi48",
    dmub_navi48_preparation_and_layout_are_generation_specific
);

fn dmub_navi48_stop_requires_pwait_and_reads_reset_back() -> TestResult {
    let (_, mut engine) = fixture();
    engine.io.pwait = false;
    if run(engine.quiesce()) != Err(Error::StopTimeout)
        || engine.io.writes != [(DCN + 0x1f8 * 4, 0x10020000)]
    {
        return TestResult::Fail("DCN4 acknowledged STOP without PWAIT forced reset");
    }
    let (_, mut engine) = fixture();
    engine.io.reject = Some(0x200);
    if run(engine.quiesce()) != Err(Error::Readback)
        || engine
            .io
            .writes
            .iter()
            .any(|(reg, _)| *reg == DCN + 0x1af * 4)
    {
        return TestResult::Fail("DCN4 windows changed without reset acknowledgement");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi48",
    dmub_navi48_stop_requires_pwait_and_reads_reset_back
);

fn cea_edid() -> Vec<u8> {
    let mut edid = vec![0; 384];
    edid[126] = 2;
    edid[128] = 0x70;
    for (i, b) in edid[256..].iter_mut().enumerate() {
        *b = i as u8;
    }
    edid[256] = 2;
    edid
}
fn dmub_navi48_amd_vsdb_uses_exact_cea_chunks_and_reply_layout() -> TestResult {
    let (_pool, mut e) = fixture();
    run(e.quiesce()).unwrap();
    run(e.start(tmr())).unwrap();
    run(e.initialize_mailbox()).unwrap();
    e.io.cea = true;
    let edid = cea_edid();
    assert_eq!(
        run(e.amd_freesync_vsdb(&edid)).unwrap(),
        Some(crate::amdgpu_freesync::AmdVsdb {
            version: 3,
            min_hz: 48,
            max_hz: 144,
            vcp_code: 0,
        })
    );
    assert_eq!(e.io.cea_seen.len(), 16);
    for (i, request) in e.io.cea_seen.iter().enumerate() {
        assert_eq!(u16::from_le_bytes([request[4], request[5]]), (8 * i) as u16);
        assert_eq!(&request[9..17], &edid[256 + 8 * i..264 + 8 * i]);
    }
    assert_eq!(e.mailbox.state, MailboxState::Ready);
    // Undeclared/truncated extensions do not issue a firmware query.
    let writes = e.io.writes.len();
    assert_eq!(run(e.amd_freesync_vsdb(&edid[..256])), Ok(None));
    assert_eq!(writes, e.io.writes.len());
    e.io.cea = false;
    assert_eq!(run(e.amd_freesync_vsdb(&edid)), Ok(None));
    assert_eq!(e.mailbox.state, MailboxState::Ready);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub",
    dmub_navi48_amd_vsdb_uses_exact_cea_chunks_and_reply_layout
);
fn dmub_navi48_amd_vsdb_bad_ack_and_cancel_retain_the_mailbox() -> TestResult {
    for cancel in [false, true] {
        let (_pool, mut e) = fixture();
        run(e.quiesce()).unwrap();
        run(e.start(tmr())).unwrap();
        run(e.initialize_mailbox()).unwrap();
        e.io.cea = true;
        let edid = cea_edid();
        if cancel {
            e.io.commands = false;
            {
                let mut future = core::pin::pin!(e.amd_freesync_vsdb(&edid));
                let mut cx = Context::from_waker(Waker::noop());
                assert!(future.as_mut().poll(&mut cx).is_pending());
            }
            assert_eq!(e.mailbox.state, MailboxState::InFlight);
        } else {
            e.io.corrupt = Some((5, 8)); // ACK belongs to another offset.
            assert_eq!(run(e.amd_freesync_vsdb(&edid)), Err(Error::Protocol));
            assert_eq!(e.mailbox.state, MailboxState::Failed);
        }
        assert_eq!(run(e.amd_freesync_vsdb(&edid)), Err(Error::Busy));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub",
    dmub_navi48_amd_vsdb_bad_ack_and_cancel_retain_the_mailbox
);
