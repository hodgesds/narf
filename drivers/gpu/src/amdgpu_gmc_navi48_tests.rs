use super::*;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::{
    future::Future,
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
struct Fake {
    registers: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
    memory: Vec<u32>,
    stall: Option<u64>,
    revoke_on: Option<(u64, Cap<BusDeviceCap, Write>)>,
}
impl Io for Fake {
    fn read(&mut self, address: u64) -> u32 {
        if self.stall == Some(address) {
            0
        } else {
            *self.registers.get(&address).unwrap_or(&0)
        }
    }
    fn write(&mut self, address: u64, value: u32) {
        self.writes.push((address, value));
        self.registers.insert(address, value);
        if let Some((when, cap)) = self.revoke_on {
            if address == when {
                cap.revoke();
            }
        }
    }
    fn memory(&mut self, _: MmioRegion, offset: u64, value: u32) {
        self.memory[offset as usize / 4] = value;
    }
}
fn run<T>(future: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(future)
}
fn fixture() -> (Pool, Engine<Fake>) {
    let layout = Layout {
        bases: [0x10000, 0x20000],
        nbio: 0x30000,
    };
    let mut registers = BTreeMap::new();
    for (base, r) in layout.bases.into_iter().zip([GFX, MM]) {
        registers.insert(base + u64::from(r.fb_base) * 4, 0x800);
        registers.insert(base + u64::from(r.fb_top) * 4, 0xbff);
        registers.insert(base + u64::from(r.inv_ack) * 4, 1);
        registers.insert(base + u64::from(r.inv_sem) * 4, 1);
    }
    registers.insert(0x10000 + 0x15a7 * 4, 0x100);
    registers.insert(0x20000 + 0x4c7 * 4, 0x100);
    registers.insert(0x30000 + 0x12d * 4, 0x7f000);
    let map = MmioRegion {
        phys: narf_memory::PhysAddr::new(0x90000000),
        virt: 0,
        len: BYTES,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // SAFETY: Fake owns all memory accesses; mapping is never dereferenced.
    let pool = unsafe { Pool::from_owned_range(map, 0x8_0000_4000) }.unwrap();
    let engine = Engine {
        io: Fake {
            registers,
            writes: Vec::new(),
            memory: vec![u32::MAX; BYTES as usize / 4],
            stall: None,
            revoke_on: None,
        },
        authority: Cap::bootstrap(),
        layout,
        memory: pool.reserve(BYTES).unwrap(),
        vram_size: 16 << 30,
        state: State::Prepared,
        aperture: None,
    };
    (pool, engine)
}
fn gmc_navi48_uses_vram_physical_ptes_and_bounds_vmid0() -> TestResult {
    let (pool, mut engine) = fixture();
    let aperture = run(engine.initialize()).unwrap();
    if aperture.start != 0xc_0000_0000
        || aperture.destination != aperture.source + 4096
        || engine.io.memory[..4] != [0x6061, 1, 0x7061, 1]
        || engine.io.memory[4..].iter().any(|v| *v != 0)
    {
        return TestResult::Fail("PTE encoded CPU BAR/GMC address or mapped unowned pages");
    }
    // Golden offsets/fields from the two Linux primary register headers.
    for (base, root, ctx, l2, syslo, syshi, fault, req) in [
        (
            0x10000, 0x168f, 0x1624, 0x15c4, 0x1619, 0x161a, 0x15cc, 0x1658,
        ),
        (0x20000, 0x5cf, 0x564, 0x4e4, 0x559, 0x55a, 0x4ec, 0x598),
    ] {
        for (reg, want) in [
            (root, 0x4001),
            (root + 1, 1),
            (ctx, 0xaaa801),
            (l2, 0x80001),
            (syslo, 0x20000),
            (syshi, 0x2ffff),
            (fault, 0x1ffc),
            (req, 0xf80001),
        ] {
            if engine.io.registers.get(&(base + reg * 4)).copied() != Some(want) {
                return TestResult::Fail("hub register/address/VRAM-default encoding");
            }
        }
        for other in 1..16 {
            if engine
                .io
                .writes
                .iter()
                .any(|(address, _)| *address == base + (ctx + other) * 4)
            {
                return TestResult::Fail("user VMID enabled during kernel bring-up");
            }
        }
    }
    if engine.state != State::Ready || run(engine.initialize()) != Err(Error::Busy) {
        return TestResult::Fail("GMC replayed initialization");
    }
    // GMC12 private invalidation follows the MM semaphore release. VMID0
    // default-response bits have moved; fault IRQs must remain clear.
    let sem = engine
        .io
        .writes
        .iter()
        .position(|&(a, v)| a == 0x20000 + 0x586 * 4 && v == 0)
        .unwrap();
    let private = engine
        .io
        .writes
        .iter()
        .position(|&(a, v)| a == 0x20000 + 0x500 * 4 && v == 1 << 25)
        .unwrap();
    if sem >= private
        || engine.io.registers.get(&(0x10000 + 0x161b * 4)) != Some(&0x1859)
        || engine.io.registers.get(&(0x20000 + 0x4ed * 4)) != Some(&0x40000)
    {
        return TestResult::Fail("GMC12 private invalidation or fault/L1 fields");
    }
    drop(engine);
    if pool.available() != 0 {
        return TestResult::Fail("published PT/default/test pages recycled");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gmc-navi48",
    gmc_navi48_uses_vram_physical_ptes_and_bounds_vmid0
);

fn gmc_navi48_preflight_refuses_active_hubs_bad_geometry_and_revocation() -> TestResult {
    for case in 0..8 {
        let (pool, mut engine) = fixture();
        match case {
            0 => {
                engine
                    .io
                    .registers
                    .insert(0x10000 + u64::from(GFX.ctx) * 4, 1);
            }
            1 => {
                engine
                    .io
                    .registers
                    .insert(0x20000 + u64::from(MM.ctx + 15) * 4, 1);
            }
            2 => {
                engine
                    .io
                    .registers
                    .insert(0x20000 + u64::from(MM.fb_top) * 4, 0xbfe);
            }
            3 => {
                engine
                    .io
                    .registers
                    .insert(0x10000 + u64::from(GFX.fb_base) * 4, u32::MAX);
            }
            4 => {
                engine.io.registers.insert(0x30000 + 0x12d * 4, 0);
            }
            5 => engine.vram_size = 8 << 30,
            6 => {
                engine.io.registers.insert(0x20000 + 0x4c7 * 4, 0);
            }
            _ => {
                engine.authority.revoke();
            }
        }
        if run(engine.initialize()).is_ok()
            || !engine.io.writes.is_empty()
            || engine.io.memory.iter().any(|v| *v != u32::MAX)
        {
            return TestResult::Fail("bad preflight touched registers or VRAM");
        }
        drop(engine);
        if pool.available() != BYTES {
            return TestResult::Fail("unpublished GMC reservation leaked");
        }
    }
    for (fields, size, address) in [
        ([0x800, 0xbff, 0x100], 16 << 30, 0x7_ffff_f000),
        ([0x800, 0xbff, 0x100], 16 << 30, 0x8_0000_4001),
        ([0xffff00, 0xffffff, 0], 4 << 30, 0xffff_0000_0000),
        ([0x800, 0xbff, 0xffff00], 16 << 30, 0x8_0000_4000),
    ] {
        if Geometry::new(fields, size, address).is_ok() {
            return TestResult::Fail("GMC bounds/overflow accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gmc-navi48",
    gmc_navi48_preflight_refuses_active_hubs_bad_geometry_and_revocation
);

fn gmc_navi48_cancel_timeout_and_revoke_retain_translation_memory() -> TestResult {
    for (address, state) in [
        (
            0x10000 + u64::from(GFX.inv_ack) * 4,
            State::Invalidating(Hub::Gfx),
        ),
        (
            0x20000 + u64::from(MM.inv_sem) * 4,
            State::Invalidating(Hub::Mm),
        ),
        (
            0x20000 + u64::from(MM.inv_ack) * 4,
            State::Invalidating(Hub::Mm),
        ),
    ] {
        let (pool, mut engine) = fixture();
        engine.io.stall = Some(address);
        {
            let mut future = core::pin::pin!(engine.initialize());
            if future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
            {
                return TestResult::Fail("stalled TLB completed");
            }
        }
        let count = engine.io.writes.len();
        if engine.state != state
            || run(engine.initialize()) != Err(Error::Busy)
            || engine.io.writes.len() != count
        {
            return TestResult::Fail("cancelled GMC replayed or forgot stage");
        }
        drop(engine);
        if pool.available() != 0 {
            return TestResult::Fail("cancelled PT backing reused");
        }
    }
    let (pool, mut engine) = fixture();
    engine.io.stall = Some(0x20000 + u64::from(MM.inv_ack) * 4);
    if run(engine.initialize()) != Err(Error::Timeout) || engine.state != State::Failed {
        return TestResult::Fail("unbounded TLB ACK wait");
    }
    drop(engine);
    if pool.available() != 0 {
        return TestResult::Fail("timed-out PT backing reused");
    }
    let (pool, mut engine) = fixture();
    engine.io.revoke_on = Some((0x7f000, engine.authority));
    if run(engine.initialize()) != Err(Error::Revoked) || engine.io.writes.len() != 1 {
        return TestResult::Fail("revoked GMC programmed hubs");
    }
    drop(engine);
    if pool.available() != 0 {
        return TestResult::Fail("revoked publication not retained");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gmc-navi48",
    gmc_navi48_cancel_timeout_and_revoke_retain_translation_memory
);

pub(crate) fn descriptor(regs: &mut [u32]) -> AmdGpu {
    let mut gpu = crate::amdgpu_navi48_firmware::tests::gpu();
    gpu.regs.virt = regs.as_mut_ptr() as u64;
    gpu.regs.len = (regs.len() * 4) as u64;
    gpu.ip_blocks.clear();
    for (id, version, bases) in [
        (ip::HW_ID_GC, (12, 0, 1), [0x4000, 0, 0]),
        (ip::HW_ID_MMHUB, (4, 1, 0), [0x8000, 0, 0]),
        (ip::HW_ID_NBIF, (7, 7, 0), [0, 0, 0xc000]),
        (ip::HW_ID_MP0, (14, 0, 3), [0x10000, 0, 0]),
        (ip::HW_ID_HDP, (6, 1, 0), [0x11000, 0, 0]),
    ] {
        let mut b = [0; ip::MAX_BASE_ADDRS];
        b[..3].copy_from_slice(&bases);
        gpu.ip_blocks.push(ip::IpBlock {
            hw_id: id,
            instance: 0,
            major: version.0,
            minor: version.1,
            revision: version.2,
            sub_revision: 0,
            variant: 0,
            num_bases: 3,
            base_addrs: b,
        });
    }
    gpu.vram.size = 16 << 30;
    gpu.vram.visible_size = 256 << 20;
    gpu.fb_bar = MmioRegion {
        phys: narf_memory::PhysAddr::new(0x90000000 - 0x4000),
        virt: 0,
        len: 256 << 20,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    regs[0x4000 + 0x1614] = 0x800;
    regs[0x4000 + 0x1615] = 0xbff;
    regs[0x4000 + 0x15a7] = 0x100;
    gpu
}
fn gmc_navi48_constructor_checks_exact_banks_and_pool_before_allocation() -> TestResult {
    let (pool, engine) = fixture();
    drop(engine);
    let mut regs = vec![0; 0x80000 / 4];
    let mut gpu = descriptor(&mut regs);
    // The fixture's bookkeeping-only map has a null virtual base. Shift this
    // descriptor's BAR origin to test a real, nonzero matching pool mapping.
    let map = MmioRegion {
        phys: narf_memory::PhysAddr::new(0x90000000),
        virt: 0x4000,
        len: BYTES,
        kind: gpu.fb_bar.kind,
    };
    // SAFETY: initialization is not called; only metadata/backing ownership.
    let mapped = unsafe { Pool::from_owned_range(map, 0x8_0000_4000) }.unwrap();
    let cap = Cap::bootstrap();
    for case in 0..8 {
        let old_blocks = gpu.ip_blocks.clone();
        let old_bar = gpu.fb_bar;
        let old_regs = gpu.regs;
        let old_did = gpu.chip.did;
        match case {
            0 => gpu.chip.did = crate::amdgpu::NAVI22,
            1 => gpu.regs.len = 0x7f000,
            2 => gpu.ip_blocks[0].revision = 0,
            3 => gpu.ip_blocks[1].minor = 0,
            4 => gpu.ip_blocks[2].num_bases = 2,
            5 => gpu.ip_blocks[0].base_addrs[0] = 0x20000 - 0x16d0,
            6 => gpu.fb_bar.phys = narf_memory::PhysAddr::new(0x80000000),
            _ => gpu.ip_blocks.push(gpu.ip_blocks[0]),
        }
        // SAFETY: owned register fixture; all unsupported paths reject.
        if unsafe { Gmc::new(&gpu, cap, &mapped) }.is_ok() || mapped.available() != BYTES {
            return TestResult::Fail("GMC12 accepted foreign layout/pool or leaked allocation");
        }
        gpu.ip_blocks = old_blocks;
        gpu.fb_bar = old_bar;
        gpu.regs = old_regs;
        gpu.chip.did = old_did;
    }
    // SAFETY: only bounded reads of the owned register fixture.
    let owner = unsafe { Gmc::new(&gpu, cap, &mapped) }.unwrap();
    if owner.state() != State::Prepared || owner.aperture().is_some() {
        return TestResult::Fail("GMC12 constructor programmed hardware");
    }
    drop(owner);
    cap.revoke();
    // SAFETY: revoked authority must prevent MMIO/allocation.
    if !matches!(unsafe { Gmc::new(&gpu, cap, &mapped) }, Err(Error::Revoked))
        || mapped.available() != BYTES
        || pool.available() != BYTES
    {
        return TestResult::Fail("GMC12 revoked construction or release");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gmc-navi48",
    gmc_navi48_constructor_checks_exact_banks_and_pool_before_allocation
);
