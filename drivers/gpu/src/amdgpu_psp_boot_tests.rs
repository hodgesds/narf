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
fn psp_sos_container_versions_and_boundaries() -> TestResult {
    for minor in 0..=3 {
        let bytes = container(minor);
        let image = Image::parse(&bytes).unwrap();
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
}
impl Io for Fake {
    fn read(&mut self, reg: u32) -> u32 {
        match reg {
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
    };
    (
        pool,
        Engine {
            io,
            authority: Cap::bootstrap(),
            memory,
            state: State::Prepared,
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
