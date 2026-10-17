use super::*;
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

fn put(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
pub(crate) fn firmware() -> Firmware {
    Firmware {
        bytes: container(3),
        target: Target::Navi22,
    }
}
fn container(minor: u16) -> Vec<u8> {
    let mut bytes = vec![0; 256 + 37];
    let len = bytes.len() as u32;
    put(&mut bytes, 0, len);
    put(
        &mut bytes,
        4,
        if minor == 0 {
            44
        } else if minor == 3 {
            116
        } else {
            68
        },
    );
    put(&mut bytes, 8, 1 | (minor as u32) << 16);
    put(&mut bytes, 12, 11);
    put(&mut bytes, 16, 0x22000c);
    put(&mut bytes, 20, 37);
    put(&mut bytes, 24, 256);
    put(&mut bytes, 36, 9); // implied system driver [0,9)
    put(&mut bytes, 40, 11); // SOS [9,20)
    if minor > 0 {
        if minor != 2 {
            put(&mut bytes, 48, 20); // TOC [20,24)
            put(&mut bytes, 52, 4);
        }
        put(&mut bytes, 60, 24); // KDB [24,31)
        put(&mut bytes, 64, 7);
    }
    if minor == 3 {
        put(&mut bytes, 72, 31); // SPL [31,37)
        put(&mut bytes, 76, 6);
    }
    for (index, byte) in bytes[256..].iter_mut().enumerate() {
        *byte = index as u8 + 1;
    }
    bytes
}
fn container14() -> Vec<u8> {
    // Intentionally in packaging order rather than boot order. Odd lengths
    // exercise partial final dwords and clearing the staging tail.
    let descriptors = [
        (3, 7),
        (2, 9),
        (1, 11),
        (7, 13),
        (8, 15),
        (9, 17),
        (4, 4),
        (11, 19),
        (5, 6),
        (10, 21),
        (6, 3),
    ];
    let size: usize = descriptors.iter().map(|(_, len)| len).sum();
    let mut bytes = vec![0u8; 256 + size];
    put(&mut bytes, 0, (256 + size) as u32);
    put(&mut bytes, 4, 36);
    put(&mut bytes, 8, 2);
    put(&mut bytes, 12, 14);
    put(&mut bytes, 16, 0x3a1014);
    put(&mut bytes, 20, size as u32);
    put(&mut bytes, 24, 256);
    put(&mut bytes, 32, descriptors.len() as u32);
    let mut offset = 0;
    for (i, (kind, len)) in descriptors.into_iter().enumerate() {
        let at = 36 + 16 * i;
        put(&mut bytes, at, kind);
        put(&mut bytes, at + 4, 0x3a1014);
        put(&mut bytes, at + 8, offset as u32);
        put(&mut bytes, at + 12, len as u32);
        bytes[256 + offset..256 + offset + len].fill(kind as u8);
        offset += len;
    }
    bytes
}
pub(crate) fn firmware14() -> Firmware {
    Firmware {
        target: Target::Psp14_0_3,
        bytes: container14(),
    }
}

fn psp14_container_descriptors_and_boot_order_are_bounded() -> TestResult {
    let bytes = container14();
    let image = Image::parse_psp14(&bytes).unwrap();
    let expected = [
        (Component::KeyDatabase, 3, 7),
        (Component::Spl, 5, 6),
        (Component::SystemDriver, 2, 9),
        (Component::SocDriver, 7, 13),
        (Component::InterfaceDriver, 8, 15),
        (Component::HardwareDebugDriver, 9, 17),
        (Component::RasDriver, 10, 21),
        (Component::IpKeyManager, 11, 19),
        (Component::SecureOs, 1, 11),
    ];
    let parts: Vec<_> = image.components().collect();
    if parts.len() != expected.len()
        || image.version() != 0x3a1014
        || image.toc() != Some(&[4u8; 4][..])
        || Image::parse(&bytes).is_ok()
    {
        return TestResult::Fail("PSP14 identity, TOC or separation from PSP11");
    }
    for ((kind, data), (want_kind, marker, len)) in parts.into_iter().zip(expected) {
        if kind != want_kind || data.len() != len || data.iter().any(|&b| b != marker) {
            return TestResult::Fail("PSP14 payload offsets or Linux boot order");
        }
    }
    for end in 0..bytes.len() {
        if Image::parse_psp14(&bytes[..end]).is_ok() {
            return TestResult::Fail("truncated PSP14 container admitted");
        }
    }
    for (offset, value) in [
        (0, 0),
        (4, 212),
        (8, 0x10002),
        (12, 11),
        (20, u32::MAX),
        (24, 36),
        (24, u32::MAX),
        (32, 0),
        (32, 12),
        (32, u32::MAX),
        (36, 12),
        (36, 0),
        (52, 3), // unknown and duplicate descriptor ids
        (44, u32::MAX),
        (48, 0),
        (48, STAGING_SIZE as u32 + 1),
        (60, 0),              // system overlaps KDB
        (36 + 6 * 16 + 8, 0), // even non-boot TOC overlap must be rejected
    ] {
        let mut bad = bytes.clone();
        put(&mut bad, offset, value);
        if Image::parse_psp14(&bad).is_ok() {
            return TestResult::Fail("malformed/unsupported PSP14 descriptor accepted");
        }
    }
    // A well-formed table without its system driver or SOS is not bootable.
    for (at, kind) in [(52, 10), (68, 10)] {
        let mut bad = bytes.clone();
        put(&mut bad, 32, 9); // excludes RAS/RL so substituting RAS is unique
        put(&mut bad, at, kind);
        if Image::parse_psp14(&bad).is_ok() {
            return TestResult::Fail("PSP14 accepted missing system/SOS");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-boot",
    psp14_container_descriptors_and_boot_order_are_bounded
);

fn psp14_boot_uploads_all_components_and_quarantines_cancellation() -> TestResult {
    let bytes = container14();
    let image = Image::parse_psp14(&bytes).unwrap();
    let (pool, mut engine) = fixture();
    if run(engine.load(&image)).is_err() || engine.state != State::Ready || engine.io.violation {
        return TestResult::Fail("PSP14 boot failed or published dirty VRAM");
    }
    let commands = [
        0x80000, 0x10000000, 0x10000, 0xb0000, 0xd0000, 0xc0000, 0xe0000, 0xf0000, 0x20000,
    ];
    let expected: Vec<_> = commands
        .into_iter()
        .flat_map(|cmd| [(0x64, 0x2000), (0x63, cmd)])
        .collect();
    if engine.io.writes != expected || engine.io.images.len() != 9 {
        return TestResult::Fail("PSP14 command encoding, GPU address or component count");
    }
    for (uploaded, (_, expected)) in engine.io.images.iter().zip(image.components()) {
        if &uploaded[..expected.len()] != expected
            || uploaded[expected.len()..].iter().any(|b| *b != 0)
        {
            return TestResult::Fail("PSP14 staged header, stale tail or wrong payload");
        }
    }
    drop(engine);
    if pool.available() != map().len {
        return TestResult::Fail("consumed PSP14 staging leaked");
    }
    for polls in [1, 260] {
        let (pool, mut engine) = fixture();
        engine.io.complete = false;
        {
            let mut future = core::pin::pin!(engine.load(&image));
            for _ in 0..polls {
                if future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_ready()
                {
                    return TestResult::Fail("incomplete PSP14 operation completed");
                }
            }
        }
        if engine.state != State::Loading || run(engine.load(&image)) != Err(Error::Busy) {
            return TestResult::Fail("cancelled PSP14 bootstrap replayed");
        }
        drop(engine);
        if pool.available()
            != if polls == 1 {
                map().len
            } else {
                STAGING_SIZE as u64
            }
        {
            return TestResult::Fail("PSP14 publication/quarantine mismatch");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-boot",
    psp14_boot_uploads_all_components_and_quarantines_cancellation
);

fn psp14_profile_pins_firmware_revision_and_refuses_cross_target_loads() -> TestResult {
    use crate::amdgpu_discovery as ip;
    let mut gpu = crate::amdgpu_navi22_boot::tests::gpu();
    gpu.chip = crate::amdgpu::__test_chip_info_for_pci_id(AMD_VENDOR, NAVI48).unwrap();
    for b in &mut gpu.ip_blocks {
        if b.hw_id == ip::HW_ID_GC {
            b.major = 12;
            b.minor = 0;
            b.revision = 1;
        }
        if b.hw_id == ip::HW_ID_MP0 {
            b.major = 14;
            b.minor = 0;
            b.revision = 3;
        }
    }
    let (target, base) = profile(&gpu).unwrap();
    if target != Target::Psp14_0_3 || base != 0 || target.name() != "amdgpu/psp_14_0_3_sos.bin" {
        return TestResult::Fail("PSP14 firmware selection or mailbox base index");
    }
    let mp0 = gpu
        .ip_blocks
        .iter()
        .position(|b| b.hw_id == ip::HW_ID_MP0)
        .unwrap();
    gpu.ip_blocks[mp0].revision = 2;
    if profile(&gpu).unwrap().0.name() != "amdgpu/psp_14_0_2_sos.bin" {
        return TestResult::Fail("PSP14.0.2 inherited 14.0.3 container");
    }
    gpu.ip_blocks[mp0].revision = 3;
    gpu.fb_bar = map();
    gpu.vram.visible_size = map().len;
    // SAFETY: bookkeeping only; profile and firmware mismatch reject all MMIO.
    let pool = unsafe { Pool::from_owned_range(map(), 0x2_0000_0000) }.unwrap();
    let cap = Cap::bootstrap();
    cap.revoke();
    // SAFETY: permanent inert maps; revoked cap prevents device accesses.
    let mut boot = unsafe { Bootloader::new(&gpu, cap, &pool) }.unwrap();
    for target in [Target::Navi22, Target::Psp14_0_2] {
        let other = Firmware {
            target,
            bytes: container14(),
        };
        if run(boot.load(&other)) != Err(Error::Unsupported) || boot.state() != State::Prepared {
            return TestResult::Fail(
                "PSP14 accepted different-target firmware or started on mismatch",
            );
        }
    }
    let correct = Firmware {
        target,
        bytes: container14(),
    };
    if run(boot.load(&correct)) != Err(Error::Revoked) || boot.state() != State::Failed {
        return TestResult::Fail("PSP14 bootstrap ignored revocation");
    }
    let (_, firmware) = narf_firmware::bootstrap_authority();
    firmware.revoke();
    if Firmware::open(&gpu, &firmware).err() != Some(Error::Revoked) {
        return TestResult::Fail("PSP14 registry capability bypassed");
    }
    let good = gpu.ip_blocks.clone();
    for case in 0..5 {
        gpu.ip_blocks = good.clone();
        gpu.regs.len = 0x80000;
        match case {
            0 => gpu.ip_blocks[mp0].revision = 1,
            1 => gpu.ip_blocks.push(gpu.ip_blocks[mp0]),
            2 => gpu.ip_blocks[mp0].num_bases = 0,
            3 => gpu.regs.len = 0x91 * 4 + 3,
            _ => gpu.chip.did = NAVI22,
        }
        if profile(&gpu).is_ok() || Firmware::open(&gpu, &firmware).err() == Some(Error::Revoked) {
            return TestResult::Fail("unsupported PSP14 profile reached the registry");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-boot",
    psp14_profile_pins_firmware_revision_and_refuses_cross_target_loads
);
fn psp_sos_container_versions_and_boundaries() -> TestResult {
    for minor in 0..=3 {
        let bytes = container(minor);
        let image = Image::parse(&bytes).unwrap();
        let toc = if minor == 1 || minor == 3 {
            Some(&bytes[276..280])
        } else {
            None
        };
        if image.toc() != toc {
            return TestResult::Fail("embedded TOC incorrectly selected");
        }
        let parts: Vec<_> = image.components().collect();
        let count = if minor == 0 {
            2
        } else if minor == 3 {
            4
        } else {
            3
        };
        if parts.len() != count
            || image.version() != 0x22000c
            || parts[count - 2] != (Component::SystemDriver, &bytes[256..265])
            || parts[count - 1] != (Component::SecureOs, &bytes[265..276])
            || minor > 0 && parts[0] != (Component::KeyDatabase, &bytes[280..287])
            || minor == 3 && parts[1] != (Component::Spl, &bytes[287..293])
        {
            return TestResult::Fail("payload-relative PSP component selection");
        }
        for len in 0..bytes.len() {
            if Image::parse(&bytes[..len]).is_ok() {
                return TestResult::Fail("truncated container accepted");
            }
        }
    }
    for (offset, value) in [
        (0, 0),
        (4, 68),
        (8, 2),
        (8, 0x40001),
        (12, 13),
        (20, u32::MAX),
        (24, 32),
        (24, u32::MAX),
        (36, 0),
        (40, 0),
        (40, STAGING_SIZE as u32 + 1),
        (48, 0),
        (60, u32::MAX),
        (60, 19),
        (64, u32::MAX),
        (72, 30),
        (100, u32::MAX),
    ] {
        let mut bytes = container(3);
        put(&mut bytes, offset, value);
        if Image::parse(&bytes).is_ok() {
            return TestResult::Fail("malformed or overlapping PSP descriptor accepted");
        }
    }
    let mut reserved = container(2);
    put(&mut reserved, 48, u32::MAX);
    put(&mut reserved, 52, u32::MAX);
    if Image::parse(&reserved).is_err() {
        return TestResult::Fail("v1.2 reserved descriptor interpreted as TOC");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-boot",
    psp_sos_container_versions_and_boundaries
);

struct Fake {
    status: u32,
    heartbeat: u32,
    running: bool,
    frozen: bool,
    complete: bool,
    reject: u32,
    dirty: bool,
    violation: bool,
    memory: Vec<u32>,
    writes: Vec<(u32, u32)>,
    images: Vec<Vec<u8>>,
    /// STATUS reads that report DONE with nonzero low bits before settling.
    busy: usize,
}
impl Io for Fake {
    fn read(&mut self, reg: u32) -> u32 {
        match reg {
            STATUS if self.busy > 0 && !self.writes.is_empty() => {
                self.busy -= 1;
                DONE | 0x5
            }
            STATUS => self.status,
            SOS => {
                if self.running && !self.frozen {
                    self.heartbeat = self.heartbeat.wrapping_add(1);
                }
                self.heartbeat
            }
            _ => panic!("unexpected PSP read"),
        }
    }
    fn write(&mut self, reg: u32, value: u32) {
        self.writes.push((reg, value));
        if reg == STATUS {
            self.violation |= self.dirty;
            self.images.push(
                self.memory
                    .iter()
                    .flat_map(|word| word.to_le_bytes())
                    .collect(),
            );
            self.status = if self.complete {
                DONE | self.reject
            } else {
                value
            };
            if value == 0x20000 && self.complete && self.reject == 0 {
                self.running = true;
            }
        }
    }
    fn write_mem(&mut self, offset: usize, value: u32) {
        self.dirty = true;
        self.memory[offset / 4] = value;
    }
    fn finish_upload(&mut self) {
        self.dirty = false;
    }
}
fn map() -> MmioRegion {
    MmioRegion {
        phys: narf_memory::PhysAddr::new(0x8000_0000),
        virt: 0,
        len: 2 * STAGING_SIZE as u64,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    }
}
fn fixture() -> (Pool, Engine<Fake>) {
    // SAFETY: bookkeeping only. Fake handles every memory access.
    let pool = unsafe { Pool::from_owned_range(map(), 0x2_0000_0000) }.unwrap();
    let memory = pool
        .reserve_aligned(STAGING_SIZE as u64, STAGING_SIZE as u64)
        .unwrap();
    let io = Fake {
        status: DONE,
        heartbeat: 0,
        running: false,
        frozen: false,
        complete: true,
        reject: 0,
        dirty: false,
        violation: false,
        memory: vec![u32::MAX; STAGING_SIZE / 4],
        writes: Vec::new(),
        images: Vec::new(),
        busy: 0,
    };
    (
        pool,
        Engine {
            io,
            authority: Cap::bootstrap(),
            memory,
            state: State::Prepared,
            psp11: false,
        },
    )
}
fn run<T>(future: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(future)
}
fn psp_boot_order_gpu_address_and_zero_padding() -> TestResult {
    let bytes = container(3);
    let image = Image::parse(&bytes).unwrap();
    let (pool, mut engine) = fixture();
    if run(engine.load(&image)).is_err() || engine.state != State::Ready || engine.io.violation {
        return TestResult::Fail("PSP11 bootstrap failed or published dirty staging memory");
    }
    if engine.io.writes
        != [
            (ADDRESS, 0x2000),
            (STATUS, 0x80000),
            (ADDRESS, 0x2000),
            (STATUS, 0x10000000),
            (ADDRESS, 0x2000),
            (STATUS, 0x10000),
            (ADDRESS, 0x2000),
            (STATUS, 0x20000),
        ]
    {
        return TestResult::Fail("wrong PSP11 order or host address instead of GPU MiB address");
    }
    for (uploaded, (_, expected)) in engine.io.images.iter().zip(image.components()) {
        if &uploaded[..expected.len()] != expected
            || uploaded[expected.len()..].iter().any(|b| *b != 0)
        {
            return TestResult::Fail("staged header/wrong component or stale bytes after image");
        }
    }
    if run(engine.load(&image)) != Err(Error::Busy) {
        return TestResult::Fail("bootstrap replay allowed");
    }
    drop(engine);
    if pool.available() != map().len {
        return TestResult::Fail("consumed staging reservation not released");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-boot",
    psp_boot_order_gpu_address_and_zero_padding
);

fn psp_boot_cancellation_quarantines_only_published_memory() -> TestResult {
    let bytes = container(3);
    let image = Image::parse(&bytes).unwrap();
    for polls in [1, 260] {
        let (pool, mut engine) = fixture();
        engine.io.complete = false;
        {
            let mut future = core::pin::pin!(engine.load(&image));
            for _ in 0..polls {
                if future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_ready()
                {
                    return TestResult::Fail("uncompleted boot command returned ready");
                }
            }
        }
        if engine.state != State::Loading
            || run(engine.load(&image)) != Err(Error::Busy)
            || engine.io.writes.is_empty() != (polls == 1)
        {
            return TestResult::Fail("cancelled bootstrap was retried or wrong publication point");
        }
        drop(engine);
        let expected = if polls == 1 {
            map().len
        } else {
            STAGING_SIZE as u64
        };
        if pool.available() != expected {
            return TestResult::Fail("published staging recycled or unpublished staging leaked");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-boot",
    psp_boot_cancellation_quarantines_only_published_memory
);

fn psp_boot_revocation_rejection_and_absent_device() -> TestResult {
    let bytes = container(3);
    let image = Image::parse(&bytes).unwrap();
    for polls in [0, 1, 260] {
        let (pool, mut engine) = fixture();
        engine.io.complete = false;
        let authority = engine.authority;
        {
            let mut future = core::pin::pin!(engine.load(&image));
            for _ in 0..polls {
                if future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_ready()
                {
                    return TestResult::Fail("command completed before revoke");
                }
            }
            authority.revoke();
            if run(future) != Err(Error::Revoked) {
                return TestResult::Fail("revocation not checked after async suspension");
            }
        }
        if engine.io.writes.len() != if polls == 260 { 2 } else { 0 } {
            return TestResult::Fail("revoked authority performed mailbox writes");
        }
        drop(engine);
        if pool.available()
            != if polls == 260 {
                STAGING_SIZE as u64
            } else {
                map().len
            }
        {
            return TestResult::Fail("revocation lost staging ownership");
        }
    }
    let (_, mut engine) = fixture();
    engine.io.reject = 7;
    if run(engine.load(&image)) != Err(Error::Rejected(7)) || engine.io.writes.len() != 2 {
        return TestResult::Fail("rejected component did not stop the sequence");
    }
    // psp_v11_0_wait_for_bootloader masks 0x8000FFFF: DONE with low status
    // bits is "not ready yet", and the bootloader settles to 0x80000000.
    let (_, mut engine) = fixture();
    engine.psp11 = true;
    engine.io.busy = 3;
    if run(engine.load(&image)).is_err() || engine.io.busy != 0 {
        return TestResult::Fail("PSP11 bootloader low status bits treated as rejection");
    }
    // A bootloader that needs ~3 s (one poll per millisecond) is still within
    // psp_v11_0_wait_for_bootloader's 20 x usec_timeout register polls.
    let (_, mut engine) = fixture();
    engine.psp11 = true;
    engine.io.busy = 3000;
    if PSP11_BOOTLOADER_TIMEOUT_MS < 6000
        || run(engine.load(&image)).is_err()
        || engine.io.busy != 0
    {
        return TestResult::Fail("PSP11 bootloader wait shorter than Linux's");
    }
    let (_, mut engine) = fixture();
    engine.psp11 = true;
    engine.io.reject = 7;
    if run(engine.load(&image)) != Err(Error::Rejected(7)) || engine.io.writes.len() != 2 {
        return TestResult::Fail("persistent PSP11 status did not stop after the deadline");
    }
    for missing_heartbeat in [false, true] {
        let (pool, mut engine) = fixture();
        if missing_heartbeat {
            engine.io.heartbeat = u32::MAX;
        } else {
            engine.io.status = u32::MAX;
        }
        if run(engine.load(&image)) != Err(Error::DeviceGone) || !engine.io.writes.is_empty() {
            return TestResult::Fail("all-ones MMIO treated as completion/liveness");
        }
        drop(engine);
        if pool.available() != map().len {
            return TestResult::Fail("absent device leaked unpublished BO");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-boot",
    psp_boot_revocation_rejection_and_absent_device
);

fn psp_boot_running_sos_and_bounded_timeouts() -> TestResult {
    let bytes = container(3);
    let image = Image::parse(&bytes).unwrap();
    let (_, mut engine) = fixture();
    engine.io.heartbeat = 10;
    engine.io.running = true;
    if run(engine.load(&image)).is_err() || !engine.io.writes.is_empty() || engine.io.dirty {
        return TestResult::Fail("resident SOS was overwritten");
    }
    for case in 0..4 {
        let (pool, mut engine) = fixture();
        match case {
            0 => engine.io.complete = false,
            1 => {
                engine.io.heartbeat = 10;
                engine.io.frozen = true;
            }
            2 => engine.io.frozen = true, // SOS load completes but never starts.
            _ => engine.io.status = 0,    // Bootloader never becomes ready.
        }
        if run(engine.load(&image)) != Err(Error::Timeout) || engine.state != State::Failed {
            return TestResult::Fail("stalled bootloader or stale heartbeat accepted");
        }
        if engine.io.writes.len() != [2, 0, 8, 0][case] {
            return TestResult::Fail("timeout at wrong bootstrap phase");
        }
        drop(engine);
        if pool.available()
            != if case == 0 || case == 2 {
                STAGING_SIZE as u64
            } else {
                map().len
            }
        {
            return TestResult::Fail("timeout staging lifetime incorrect");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-boot",
    psp_boot_running_sos_and_bounded_timeouts
);

fn gpu() -> AmdGpu {
    fn ip(hw_id: u16, version: (u8, u8, u8)) -> discovery::IpBlock {
        let mut bases = [0; discovery::MAX_BASE_ADDRS];
        bases[0] = 0x100;
        bases[1] = 0x400;
        discovery::IpBlock {
            hw_id,
            instance: 0,
            major: version.0,
            minor: version.1,
            revision: version.2,
            sub_revision: 0,
            variant: 0,
            base_addrs: bases,
            num_bases: 2,
        }
    }
    AmdGpu {
        fb_bar: map(),
        regs: MmioRegion {
            len: 0x4000,
            ..map()
        },
        chip: crate::amdgpu::__test_chip_info_for_pci_id(AMD_VENDOR, NAVI22).unwrap(),
        vram: crate::amdgpu::VramInfo {
            base: map().phys.raw(),
            size: 12 << 30,
            visible_size: map().len,
        },
        mode: None,
        fw_loaded: false,
        vbios: None,
        gc_info: None,
        ip_blocks: vec![
            ip(discovery::HW_ID_GC, (10, 3, 2)),
            ip(discovery::HW_ID_MP0, (11, 0, 11)),
        ],
    }
}
fn psp_boot_exact_ip_and_aperture_gates() -> TestResult {
    let mut gpu = gpu();
    let (pool, engine) = fixture();
    drop(engine);
    if mp0_bank(&gpu) != Ok(0x400) || gpu.chip.fw_name != firmware::NAVI22_SOS {
        return TestResult::Fail("PSP11 used base index 1 or wrong firmware name");
    }
    for case in 0..8 {
        let mut bad = self::gpu();
        match case {
            0 => bad.chip.did = crate::amdgpu::PHOENIX1,
            1 => bad.ip_blocks[0].revision = 1,
            2 => bad.ip_blocks[1].revision = 7,
            3 => bad.ip_blocks.push(bad.ip_blocks[0]),
            4 => bad.ip_blocks.push(bad.ip_blocks[1]),
            5 => bad.ip_blocks[1].num_bases = 0,
            6 => bad.regs.len = 0x400 + SOS as u64 * 4,
            _ => bad.ip_blocks.clear(),
        }
        if mp0_bank(&bad).is_ok() {
            return TestResult::Fail("unaudited IP/register window accepted");
        }
    }
    // SAFETY: construction performs no MMIO; these are bookkeeping-only maps.
    if unsafe { Bootloader::new(&gpu, Cap::bootstrap(), &pool) }.is_err() {
        return TestResult::Fail("valid owned aperture rejected");
    }
    gpu.vram.visible_size = STAGING_SIZE as u64;
    // SAFETY: same no-MMIO constructor; pool now deliberately exceeds visible VRAM.
    if unsafe { Bootloader::new(&gpu, Cap::bootstrap(), &pool) }.is_ok() {
        return TestResult::Fail("pool beyond visible VRAM accepted");
    }
    gpu.vram.visible_size = map().len;
    gpu.fb_bar.virt += 4096;
    // SAFETY: same no-MMIO constructor, with deliberately mismatched mappings.
    if unsafe { Bootloader::new(&gpu, Cap::bootstrap(), &pool) }.is_ok() {
        return TestResult::Fail("pool mapped for another aperture accepted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/psp-boot", psp_boot_exact_ip_and_aperture_gates);
