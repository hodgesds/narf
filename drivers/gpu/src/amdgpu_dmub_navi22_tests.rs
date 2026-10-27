use super::*;
use alloc::{collections::BTreeMap, sync::Arc, vec};
use core::ops::Range;
use core::{
    future::Future,
    sync::atomic::AtomicBool,
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
#[path = "amdgpu_dmub_navi22_mailbox_tests.rs"]
mod mailbox_tests;
const DCN: u64 = 0x10000;
const NBIO: u64 = 0x30000;
const HDP: u64 = 0x50000;
struct Fake {
    regs: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
    bytes: Vec<u32>,
    dirty: bool,
    stop: bool,
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
    edid_caps: Option<crate::amdgpu_freesync::AmdVsdb>,
    edid_chunks: Vec<(u16, [u8; 8])>,
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
                request[5] = 0x21;
                request[16] = 1;
            }
            79 if self.edid_caps.is_some() => {
                assert_eq!(&request[..4], &[79, 0, 0, 16]);
                assert_eq!(request[6], 8);
                assert_eq!(&request[7..9], &128u16.to_le_bytes());
                let offset = u16::from_le_bytes(request[4..6].try_into().unwrap());
                self.edid_chunks
                    .push((offset, request[9..17].try_into().unwrap()));
                request[4..].fill(0);
                if offset == 120 {
                    let caps = self.edid_caps.unwrap();
                    request[4..7].copy_from_slice(&[1, 1, 1]);
                    request[7..9].copy_from_slice(&caps.version.to_le_bytes());
                    request[9..11].copy_from_slice(&caps.min_hz.to_le_bytes());
                    request[11..13].copy_from_slice(&caps.max_hz.to_le_bytes());
                    request[13] = caps.vcp_code;
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
        }
        if address == HDP + 0xd1 * 4 {
            assert_eq!(value, 1);
            self.invalidated = true;
        }
        if address == DCN + 0x1f8 * 4 && value == 0x10010000 && self.gpint {
            self.regs.insert(address, 0x10000);
            self.regs.insert(DCN + 0x1ea * 4, self.version);
        }
        if address == DCN + 0x1d6 * 4
            && self.commands
            && self.regs.get(&(DCN + 0x1e3 * 4)) == Some(&3)
        {
            self.execute(value);
        }
        if address == DCN + 0x1f8 * 4 && value == 0x10020000 && self.stop {
            self.regs.insert(address, 0x20000);
            self.regs.insert(DCN + 0x1ea * 4, 0xdeaddead);
        }
        if address == DCN + 0x1f6 * 4 && value & 0x30000 == 0x10000 {
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
    b[14] = 0;
    let offset = b.len() - 256 - 64 + 12;
    b[offset..offset + 4].copy_from_slice(&0x0202_2280u32.to_le_bytes());
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
        // DCN_VM_FB_LOCATION_* (DCN3.0 0x493..0x495) stay unprogrammed, as
        // before DC init on hardware: DMUB must use the GMC aperture.
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
            boot: true,
            released: Arc::new(AtomicBool::new(false)),
            reject: None,
            revoke: None,
            mailbox: prepared.layout.region(fw::Window::Mailbox).offset as usize,
            invalidated: false,
            gpint: true,
            version: 0x02022280,
            commands: true,
            caps: true,
            aux: true,
            aux_status: 0,
            notify: false,
            corrupt: None,
            aux_corrupt: None,
            complete_pointer: None,
            edid_caps: None,
            edid_chunks: Vec::new(),
        },
        authority: Cap::bootstrap(),
        layout: Layout {
            dcn: DCN,
            nbio: NBIO,
            hdp: HDP,
        },
        memory: pool.reserve(bytes).unwrap(),
        prepared,
        state: State::Prepared,
        status: None,
        mailbox: mailbox::Mailbox::new(),
    };
    (pool, engine)
}
fn tmr() -> Range<u64> {
    0x8_0100_0000..0x8_0200_0000
}
/// gmc.fb_start / vm_manager.vram_base_offset for a 12 GiB GMC10 aperture.
fn fb() -> Aperture {
    Aperture {
        base: 0x8_0000_0000,
        end: 0x8_0000_0000 + (0x300 << 24),
        offset: 0x1_0000_0000,
    }
}
fn dmub_navi22_secure_windows_outside_tmr_stay_bounded_and_unchanged() -> TestResult {
    let fb = Aperture {
        base: 0x8000000000,
        end: 0x8300000000,
        offset: 1 << 32,
    };
    let windows = [
        Some(0x82fee00000..0x82feec0000),
        Some(0x82fef00000..0x82fefa0000),
    ];
    let plan = crate::amdgpu_vram_boot::tests::secure_plan(
        fb.base,
        fb.end - fb.base,
        fb.offset,
        windows.clone(),
    );
    for case in 0..7 {
        let (_, mut engine) = fixture();
        // Owned nonsecure storage must use this fixture's GMC address space.
        let mut memory = crate::amdgpu_psp_ring::DmubMemory {
            tmr: 0x8002300000..0x8002d00000,
            inherited: (case != 1).then(|| plan.secure_dmub()),
            reported: None,
        };
        for (index, window) in windows.iter().enumerate() {
            let window = window.as_ref().unwrap();
            let physical = window.start - fb.base + fb.offset;
            for (reg, value) in [
                (0x1a5 + index as u64, (index as u32) << 24),
                (
                    0x1ad + index as u64,
                    1 << 31 | (index as u32) << 24 | (window.end - window.start - 1) as u32,
                ),
                (0x1b5 + index as u64 * 2, physical as u32),
                (0x1b6 + index as u64 * 2, (physical >> 32) as u32),
            ] {
                engine.io.regs.insert(DCN + reg * 4, value);
            }
        }
        if case == 2 {
            *engine.io.regs.get_mut(&(DCN + 0x1ad * 4)).unwrap() += 4096;
        }
        if case == 3 {
            *engine.io.regs.get_mut(&(DCN + 0x1b7 * 4)).unwrap() += 0x100000;
        }
        let secure = engine.io.regs.clone();
        // Use an aperture including both fixture-owned storage and secure
        // windows, but keep the physical translation at the real MC base.
        // The fixture storage is relocated by a fresh model allocator.
        let map = engine.memory.mapping();
        let pool_base = fb.base + 0x400000;
        let pool_map = MmioRegion {
            len: if case >= 4 {
                fb.end - pool_base
            } else {
                map.len
            },
            ..map
        };
        // SAFETY: inert model mapping; no physical accesses.
        let pool = unsafe { Pool::from_owned_range(pool_map, pool_base) }.unwrap();
        engine.memory = pool.reserve(map.len).unwrap();
        let available_without_secure = pool.available();
        if case >= 4 {
            // Inventory happened before PSP programmed these windows. Its
            // reply identifies an image inside CW0, with page-rounded bounds
            // that do not by themselves cover the complete CW0 or CW1.
            let image_base = if case == 5 {
                // A valid PSP image elsewhere does not authorize these CWs.
                0x82fed00100
            } else {
                0x82fee00100
            };
            let image = image_base
                ..image_base + engine.prepared.signed_size + if case == 6 { 4 } else { 0 };
            pool.claim(image.start - pool_base..image.end - pool_base)
                .unwrap();
            memory.inherited = None;
            memory.reported = Some((image, pool.clone()));
        }
        run(engine.quiesce()).unwrap();
        let result = run(engine.start(memory, fb));
        if (matches!(case, 0 | 4) && result.is_err())
            || (!matches!(case, 0 | 4) && result != Err(Error::Invalid))
        {
            return TestResult::Fail("inherited secure-window extent check");
        }
        if case == 4 {
            let secure_bytes: u64 = windows.iter().flatten().map(|w| w.end - w.start).sum();
            if available_without_secure - pool.available() != secure_bytes {
                return TestResult::Fail("fresh PSP secure windows not permanently reserved");
            }
        }
        for reg in [0x1a5, 0x1a6, 0x1ad, 0x1ae, 0x1b5, 0x1b6, 0x1b7, 0x1b8] {
            if engine.io.regs.get(&(DCN + reg * 4)) != secure.get(&(DCN + reg * 4)) {
                return TestResult::Fail("secure firmware window overwritten");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi22",
    dmub_navi22_secure_windows_outside_tmr_stay_bounded_and_unchanged
);
fn dmub_navi22_zero_secure_readback_requires_authenticated_owned_image() -> TestResult {
    const SECURE: [u32; 9] = [
        0x1a5, 0x1a6, 0x1ad, 0x1ae, 0x1b5, 0x1b6, 0x1b7, 0x1b8, 0x1ce,
    ];
    for case in 0..8 {
        let (_, mut engine) = fixture();
        let map = engine.memory.mapping();
        let pool_base = fb().base + 0x400000;
        // SAFETY: model bookkeeping only; the Fake owns all I/O.
        let pool = unsafe {
            Pool::from_owned_range(
                MmioRegion {
                    len: fb().end - pool_base,
                    ..map
                },
                pool_base,
            )
        }
        .unwrap();
        engine.memory = pool.reserve(map.len).unwrap();
        let signed_size = engine.prepared.signed_size;
        let image_base = match case {
            4 => fb().end + 0x1000,          // outside the matching pool
            5 => engine.memory.address(),    // aliases live nonsecure storage
            6 => fb().end - signed_size / 2, // signed packaging straddles pool end
            7 => tmr().start,                // PSP may place the opaque image in this TMR
            _ => fb().end - 0x1200000 + 0x100,
        };
        let image = image_base..image_base + signed_size + if case == 2 { 4 } else { 0 };
        let memory = crate::amdgpu_psp_ring::DmubMemory {
            tmr: tmr(),
            inherited: None,
            reported: (case != 1).then(|| (image.clone(), pool.clone())),
        };
        // Match a PSP reply whose entire image was already claimed. The
        // rejected alias/out-of-pool cases exercise the consumer's guard too.
        if matches!(case, 0 | 2 | 3) {
            pool.claim(image.start - pool_base..image.end - pool_base)
                .unwrap();
        }
        if case == 7 {
            pool.claim(tmr().start - pool_base..tmr().end - pool_base)
                .unwrap();
        }
        for reg in SECURE {
            engine.io.regs.insert(DCN + u64::from(reg) * 4, 0);
        }
        if case == 3 {
            // Only fully zero readback is opaque; partial enabled windows
            // must still pass the existing complete-window validator.
            engine.io.regs.insert(DCN + 0x1ae * 4, 1 << 31);
        }
        run(engine.quiesce()).unwrap();
        let writes = engine.io.writes.len();
        let result = run(engine.start(memory, fb()));
        let good = matches!(case, 0 | 7);
        if (good && (result.is_err() || engine.state != State::Running))
            || (!good && result != Err(Error::Invalid))
        {
            return TestResult::Fail(
                "opaque secure windows accepted without full PSP image ownership",
            );
        }
        // Dmub::start follows the low-level start with this transport proof.
        if good && run(engine.initialize_mailbox()).is_err() {
            return TestResult::Fail("opaque PSP path failed mailbox initialization");
        }
        if good
            && engine
                .status
                .is_none_or(|s| s.boot_status != 3 || s.capabilities.is_none())
        {
            return TestResult::Fail("opaque PSP path skipped fresh boot or mailbox proof");
        }
        if engine.io.writes[writes..].iter().any(|&(reg, _)| {
            SECURE
                .iter()
                .any(|&secure| reg == DCN + u64::from(secure) * 4)
        }) {
            return TestResult::Fail("opaque PSP secure register overwritten");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi22",
    dmub_navi22_zero_secure_readback_requires_authenticated_owned_image
);
fn run<T>(f: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}
fn dmub_navi22_preserves_psp_windows_and_starts_dcn30() -> TestResult {
    let (pool, mut engine) = fixture();
    let secure = engine.io.regs.clone();
    run(engine.quiesce()).unwrap();
    if engine.state != State::Reset
        || engine.io.regs[&(DCN + 0x1f6 * 4)] != 0x20000
        || engine.io.regs[&(DCN + 0x341 * 4)] != 0x100
    {
        return TestResult::Fail("wrong DCN30 reset registers");
    }
    let report = run(engine.start(tmr(), fb())).unwrap();
    if report.firmware_version != 0x02022280
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
        (0x1f1, 0),
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
        .any(|(reg, _)| *reg == DCN + 0x200 * 4 || *reg == DCN + 0x342 * 4)
    {
        return TestResult::Fail("Phoenix reset used on Navi22");
    }
    let writes = engine.io.writes.len();
    if run(engine.start(tmr(), fb())) != Err(Error::Busy)
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
    "drivers/gpu/dmub-navi22",
    dmub_navi22_preserves_psp_windows_and_starts_dcn30
);
fn dmub_navi22_rejects_untrusted_windows_before_upload() -> TestResult {
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
                // Storage/TMR outside the GMC aperture cannot be validated.
                let writes = engine.io.writes.len();
                let shifted = Aperture {
                    base: 0x8_0200_0000,
                    ..fb()
                };
                if run(engine.start(tmr(), shifted)).is_ok() || engine.io.writes.len() != writes {
                    return TestResult::Fail("TMR outside the GMC aperture accepted");
                }
                drop(engine);
                if pool.available() != bytes {
                    return TestResult::Fail("unpublished storage leaked");
                }
                continue;
            }
            4 => {
                engine.io.regs.insert(DCN + 0x1ce * 4, 1 << 16);
            }
            _ => {
                engine.authority.revoke();
            }
        }
        let writes = engine.io.writes.len();
        if run(engine.start(tmr(), fb())).is_ok()
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
    "drivers/gpu/dmub-navi22",
    dmub_navi22_rejects_untrusted_windows_before_upload
);
fn dmub_navi22_stop_boot_timeout_readback_and_revocation() -> TestResult {
    for case in 0..4 {
        let (pool, mut engine) = fixture();
        if case == 0 {
            // dmub_dcn20_reset: an unacknowledged STOP_FW still clears GPINT
            // and forces the reset ("DMCUB is likely hung").
            engine.io.stop = false;
            if run(engine.quiesce()).is_err()
                || engine.state != State::Reset
                || engine.io.writes.first() != Some(&(DCN + 0x1f8 * 4, 0x10020000))
                || engine.io.writes.get(1) != Some(&(DCN + 0x1f8 * 4, 0))
                || engine.io.regs[&(DCN + 0x1f6 * 4)] & 0x30000 != 0x20000
                || engine.io.regs[&(DCN + 0x341 * 4)] & 0x100 == 0
            {
                return TestResult::Fail("unacknowledged STOP did not force the reset");
            }
            // The forced reset leaves the owner startable, like Linux.
            if run(engine.start(tmr(), fb())).is_err() {
                return TestResult::Fail("force-reset DMCUB not startable");
            }
            continue;
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
            if run(engine.start(tmr(), fb())) != Err(error) || engine.status.is_some() {
                return TestResult::Fail("bad DMUB start accepted");
            }
        }
        if engine.state != State::Failed {
            return TestResult::Fail("failed DMUB state");
        }
        let size = engine.memory.size();
        drop(engine);
        if pool.available() != 0 || size == 0 {
            return TestResult::Fail("wrong DMUB storage lifetime after fault");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi22",
    dmub_navi22_stop_boot_timeout_readback_and_revocation
);
/// Linux dmub_srv_hw_init re-runs dmub_dcn20_reset after PSP loading even
/// when PSP released DMCUB, and never reads DCN's unprogrammed FB copy.
fn dmub_navi22_start_resets_released_dmcub_without_dcn_fb_copy() -> TestResult {
    let (_pool, mut engine) = fixture();
    run(engine.quiesce()).unwrap();
    // PSP authentication released DMCUB from reset and it runs again.
    engine.io.regs.insert(DCN + 0x1f6 * 4, 0x10000);
    engine.io.regs.insert(DCN + 0x341 * 4, 0);
    for reg in [0x475, 0x476, 0x477, 0x493, 0x494, 0x495] {
        engine.io.regs.insert(DCN + reg * 4, 0);
    }
    let before = engine.io.writes.len();
    if run(engine.start(tmr(), fb())).is_err() || engine.state != State::Running {
        return TestResult::Fail("released DMCUB was not reset again before start");
    }
    let writes = &engine.io.writes[before..];
    if writes.first() != Some(&(DCN + 0x1f8 * 4, 0x10020000))
        || !writes.contains(&(DCN + 0x1f6 * 4, 0x30000))
    {
        return TestResult::Fail("dmub_dcn20_reset STOP/soft-reset sequence missing");
    }
    if engine.io.writes.iter().any(|(reg, _)| {
        [0x475, 0x476, 0x477, 0x493, 0x494, 0x495]
            .map(|r| DCN + r * 4)
            .contains(reg)
    }) {
        return TestResult::Fail("DMUB touched DCN_VM_FB_* registers");
    }
    if engine.io.regs[&(DCN + 0x1f1 * 4)] != 0 {
        return TestResult::Fail("DCN3.0 SCRATCH14 boot options must be zero");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi22",
    dmub_navi22_start_resets_released_dmcub_without_dcn_fb_copy
);
fn dmub_navi22_cancellation_preserves_stage_and_storage() -> TestResult {
    for boot in [false, true] {
        let (pool, mut engine) = fixture();
        let bytes = engine.memory.size();
        if boot {
            run(engine.quiesce()).unwrap();
            engine.io.boot = false;
            let released = engine.io.released.clone();
            {
                let mut future = core::pin::pin!(engine.start(tmr(), fb()));
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
                || run(engine.start(tmr(), fb())) != Err(Error::Busy)
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
    "drivers/gpu/dmub-navi22",
    dmub_navi22_cancellation_preserves_stage_and_storage
);
fn dmub_navi22_preparation_and_layout_are_generation_specific() -> TestResult {
    let bytes = image();
    for case in 0..4 {
        let mut bad = bytes.clone();
        match case {
            0 => bad[14] = 1,
            1 => {
                let o = bad.len() - 256 - 64 + 12;
                bad[o..o + 4].copy_from_slice(&0x010a0000u32.to_le_bytes());
            }
            2 => {
                let o = bad.len() - 256 - 64 + 20;
                bad[o..o + 4].copy_from_slice(&4096u32.to_le_bytes());
            }
            _ => bad.truncate(bad.len() - 1),
        }
        if Prepared::new(&bad, &[0x55, 0xaa], 0).is_ok() {
            return TestResult::Fail("unsupported DMUB layout accepted");
        }
    }
    let mut gpu = crate::amdgpu_navi22_boot::tests::gpu();
    let mut dcn = gpu.ip_blocks[0];
    dcn.hw_id = ip::HW_ID_DCN;
    dcn.major = 3;
    dcn.minor = 0;
    dcn.revision = 0;
    dcn.base_addrs[2] = 0x4000;
    gpu.ip_blocks.push(dcn);
    if Layout::resolve(&gpu).unwrap().dcn != DCN {
        return TestResult::Fail("wrong DCN bank index");
    }
    gpu.ip_blocks.last_mut().unwrap().minor = 1;
    if Layout::resolve(&gpu).is_ok() {
        return TestResult::Fail("DCN31 accepted as DCN30");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi22",
    dmub_navi22_preparation_and_layout_are_generation_specific
);

/// dm_dmub_hw_init: CC_DC_PIPE_DIS.DC_DMCUB_ENABLE clear means "DMUB
/// unsupported on ASIC" -- reported as Unsupported without any DMUB write.
fn dmub_navi22_fused_off_dmcub_is_unsupported_without_writes() -> TestResult {
    let (_pool, mut engine) = fixture();
    engine.io.regs.insert(DCN + 0xca * 4, 0);
    if run(engine.quiesce()) != Err(Error::Unsupported) || !engine.io.writes.is_empty() {
        return TestResult::Fail("fused-off DMCUB touched or not reported unsupported");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi22",
    dmub_navi22_fused_off_dmcub_is_unsupported_without_writes
);

/// A DMCUB that GOP never started (DMCUB_ENABLE = 0, not in reset) cannot
/// acknowledge STOP_FW: dmub_dcn20_reset still posts it, clears GPINT and
/// forces the reset, but the 100 ms acknowledgement wait (and its "not
/// acknowledged" fault line) is for a running DMCUB only.
fn dmub_navi22_never_started_dmcub_skips_the_stop_wait() -> TestResult {
    let (_pool, mut engine) = fixture();
    engine.io.stop = false;
    engine.io.regs.insert(DCN + 0x1f6 * 4, 0);
    let quick = narf_time::Deadline::after_ms(60);
    if run(engine.quiesce()).is_err() || engine.state != State::Reset {
        return TestResult::Fail("never-started DMCUB not reset");
    }
    if quick.expired() {
        return TestResult::Fail("waited for a STOP_FW ack from a DMCUB that never ran");
    }
    if engine.io.writes.first() != Some(&(DCN + 0x1f8 * 4, 0x10020000))
        || engine.io.writes.get(1) != Some(&(DCN + 0x1f8 * 4, 0))
        || engine.io.regs[&(DCN + 0x1f6 * 4)] & 0x30000 != 0x20000
    {
        return TestResult::Fail("dmub_dcn20_reset sequence for a stopped DMCUB");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi22",
    dmub_navi22_never_started_dmcub_skips_the_stop_wait
);

/// command_table2.c `*_dmcub` + dc_wake_and_execute_dmub_cmd(WAIT): the
/// DMUB_CMD__VBIOS slot carries header and parameters, completes once DMCUB
/// consumes it, and a DMCUB that never does fails within the 100 ms bound.
fn dmub_navi22_vbios_command_executes_through_the_inbox() -> TestResult {
    let (_pool, mut engine) = fixture();
    let payload = [0xa5u8; 16];
    if engine.vbios(VbiosCommand::SetPixelClock, &payload) != Err(Error::Busy) {
        return TestResult::Fail("VBIOS command before DMUB runs");
    }
    run(engine.quiesce()).unwrap();
    run(engine.start(tmr(), fb())).unwrap();
    run(engine.initialize_mailbox()).unwrap();
    let slot = engine.io.regs[&(DCN + 0x1d6 * 4)] as usize;
    if engine.vbios(VbiosCommand::SetPixelClock, &payload).is_err()
        || engine.mailbox.state != MailboxState::Ready
    {
        return TestResult::Fail("VBIOS SetPixelClock not executed");
    }
    let sent = engine.io.slot(engine.io.mailbox + slot);
    if sent[..4] != [128, 2, 0, 16] || sent[4..20] != payload || sent[20..] != [0; 44] {
        return TestResult::Fail("DMUB_CMD__VBIOS_SET_PIXEL_CLOCK slot");
    }
    if engine
        .vbios(VbiosCommand::EnableDispPowerGating, &payload)
        .is_ok()
    {
        return TestResult::Fail("oversized VBIOS payload accepted");
    }
    engine.io.commands = false;
    if engine.vbios(VbiosCommand::EnableDispPowerGating, &payload[..4])
        != Err(Error::CommandTimeout)
        || engine.mailbox.state != MailboxState::Failed
    {
        return TestResult::Fail("unconsumed VBIOS command did not time out");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi22",
    dmub_navi22_vbios_command_executes_through_the_inbox
);
