use super::*;
use alloc::{collections::BTreeMap, vec::Vec};
use core::{
    future::Future,
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
pub(super) struct Fake {
    pub(super) registers: BTreeMap<u64, u32>,
    pub(super) writes: Vec<(u64, u32)>,
    /// Fake VRAM keyed by BAR-physical byte address.
    pub(super) memory: BTreeMap<u64, u32>,
    pub(super) stall: Option<u64>,
    pub(super) revoke_on: Option<(u64, Cap<BusDeviceCap, Write>)>,
    pub(super) stores: usize,
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
        // A released MMHUB semaphore reads 1 (acquired) on the next sample.
        if address == 0x20000 + u64::from(MM.inv_sem) * 4 && value == 0 {
            self.registers.insert(address, 1);
        }
        // Engine-17 model: a request acknowledges exactly its VMID bits.
        for (base, r) in [(0x10000, GFX), (0x20000, MM)] {
            if address == base + u64::from(r.inv_req) * 4 {
                self.registers
                    .insert(base + u64::from(r.inv_ack) * 4, value & 0xffff);
            }
        }
        if let Some((when, cap)) = self.revoke_on {
            if address == when {
                cap.revoke();
            }
        }
    }
    fn memory(&mut self, map: MmioRegion, offset: u64, value: u32) {
        assert!(offset + 4 <= map.len);
        self.memory.insert(map.phys.raw() + offset, value);
    }
    fn memory64(&mut self, map: MmioRegion, offset: u64, value: u64) {
        assert!(offset % 8 == 0 && offset + 8 <= map.len);
        let address = map.phys.raw() + offset;
        self.stores += 1;
        // Sparse: zero is the default, so megabyte table clears stay cheap.
        for (address, half) in [(address, value as u32), (address + 4, (value >> 32) as u32)] {
            if half == 0 {
                self.memory.remove(&address);
            } else {
                self.memory.insert(address, half);
            }
        }
    }
}
impl Fake {
    pub(super) fn word(&self, phys: u64) -> u32 {
        self.memory.get(&phys).copied().unwrap_or(0)
    }
}
pub(super) fn run<T>(future: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(future)
}
pub(super) const BAR: u64 = 0x9000_0000;
pub(super) const VRAM: u64 = 0x8_0000_4000;
/// BAR-physical address of a GPU physical address: fb 0x8_0000_0000 and
/// FB_OFFSET 0x1_0000_0000 put VRAM byte `VRAM` at physical 0x1_0000_4000.
pub(super) fn bar(physical: u64) -> u64 {
    physical - 0x1_0000_4000 + BAR
}
pub(super) fn fixture() -> (Pool, Engine<Fake>) {
    fixture_sized(BYTES)
}
pub(super) fn fixture_sized(len: u64) -> (Pool, Engine<Fake>) {
    fixture_with(len, &[])
}
pub(super) fn fixture_with(len: u64, protected: &[core::ops::Range<u64>]) -> (Pool, Engine<Fake>) {
    let layout = Layout {
        bases: [0x10000, 0x20000],
        nbio: 0x30000,
    };
    let mut registers = BTreeMap::new();
    for (base, r) in layout.bases.into_iter().zip([GFX, MM]) {
        registers.insert(base + u64::from(r.fb_base) * 4, 0x800);
        registers.insert(base + u64::from(r.fb_top) * 4, 0xaff);
        registers.insert(base + u64::from(r.inv_ack) * 4, 1);
        registers.insert(base + u64::from(r.inv_sem) * 4, 1);
    }
    registers.insert(0x10000 + 0x16e7 * 4, 0x100);
    registers.insert(0x30000 + 0x12d * 4, 0x7f000);
    let map = MmioRegion {
        phys: narf_memory::PhysAddr::new(BAR),
        virt: 0,
        len,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // SAFETY: Fake owns all memory accesses; mapping is never dereferenced.
    let pool = unsafe { Pool::from_owned_aperture(map, VRAM, protected) }.unwrap();
    let fake = Fake {
        registers,
        writes: Vec::new(),
        memory: BTreeMap::new(),
        stall: None,
        revoke_on: None,
        stores: 0,
    };
    let engine = Engine::new(fake, Cap::bootstrap(), layout, &pool, 12 << 30).unwrap();
    (pool, engine)
}
fn gmc_navi22_uses_vram_physical_ptes_and_bounds_vmid0() -> TestResult {
    let (pool, mut engine) = fixture();
    let aperture = run(engine.initialize()).unwrap();
    if aperture.start != 0xb_0000_0000
        || aperture.destination != aperture.source + 4096
        || (0..4)
            .map(|i| engine.io.word(BAR + i * 4))
            .ne([0x6061, 1, 0x7061, 1])
        || engine.io.memory.len() != BYTES as usize / 4
        || engine.io.memory.iter().skip(4).any(|(_, v)| *v != 0)
    {
        return TestResult::Fail("PTE encoded CPU BAR/GMC address or mapped unowned pages");
    }
    // Golden offsets/fields from the two Linux primary register headers.
    for (base, root, ctx, l2, syslo, syshi, fault, req) in [
        (
            0x10000, 0x1667, 0x15fc, 0x15bc, 0x1701, 0x1702, 0x15c4, 0x1630,
        ),
        (0x20000, 0x72b, 0x6c0, 0x680, 0x871, 0x872, 0x688, 0x6f4),
    ] {
        for (reg, want) in [
            (root, 0x4001),
            (root + 1, 1),
            (ctx, 0x555401),
            (l2, 0x80001),
            (syslo, 0x20000),
            (syshi, 0x2bfff),
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
    drop(engine);
    if pool.available() != 0 {
        return TestResult::Fail("published PT/default/test pages recycled");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gmc-navi22",
    gmc_navi22_uses_vram_physical_ptes_and_bounds_vmid0
);

fn gmc_navi22_preflight_refuses_active_hubs_bad_geometry_and_revocation() -> TestResult {
    for case in 0..7 {
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
                    .insert(0x20000 + u64::from(MM.fb_top) * 4, 0xafe);
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
            _ => {
                engine.authority.revoke();
            }
        }
        if run(engine.initialize()).is_ok()
            || !engine.io.writes.is_empty()
            || !engine.io.memory.is_empty()
        {
            return TestResult::Fail("bad preflight touched registers or VRAM");
        }
        drop(engine);
        if pool.available() != BYTES {
            return TestResult::Fail("unpublished GMC reservation leaked");
        }
    }
    for (fields, size, address) in [
        ([0x800, 0xaff, 0x100], 12 << 30, 0x7_ffff_f000),
        ([0x800, 0xaff, 0x100], 12 << 30, 0x8_0000_4001),
        ([0xffff00, 0xffffff, 0], 4 << 30, 0xffff_0000_0000),
        ([0x800, 0xaff, 0xffff00], 12 << 30, 0x8_0000_4000),
    ] {
        if Geometry::new(fields, size, address).is_ok() {
            return TestResult::Fail("GMC bounds/overflow accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gmc-navi22",
    gmc_navi22_preflight_refuses_active_hubs_bad_geometry_and_revocation
);

fn gmc_navi22_cancel_timeout_and_revoke_retain_translation_memory() -> TestResult {
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
    "drivers/gpu/gmc-navi22",
    gmc_navi22_cancel_timeout_and_revoke_retain_translation_memory
);

fn gmc_navi22_constructor_checks_exact_banks_before_allocation() -> TestResult {
    let gpu = || {
        let mut gpu = crate::amdgpu_navi22_boot::tests::gpu();
        let mut mm = gpu.ip_blocks[0];
        mm.hw_id = ip::HW_ID_MMHUB;
        mm.major = 2;
        mm.minor = 1;
        mm.revision = 0;
        gpu.ip_blocks.push(mm);
        gpu
    };
    let (pool, engine) = fixture();
    drop(engine);
    let authority = Cap::bootstrap();
    authority.revoke();
    for case in 0..7 {
        let mut descriptor = gpu();
        match case {
            0 => descriptor.chip.did = crate::amdgpu::PHOENIX1,
            1 => descriptor.regs.len = 0x7f000,
            2 => descriptor.ip_blocks[0].revision = 1,
            3 => descriptor.ip_blocks.last_mut().unwrap().minor = 2,
            4 => descriptor.ip_blocks[4].num_bases = 2,
            5 => descriptor.ip_blocks[0].base_addrs[0] = 0x20000 - 0x1703,
            _ => descriptor.ip_blocks.push(descriptor.ip_blocks[0]),
        }
        // SAFETY: constructor has no I/O; revoked cap and inert metadata.
        if unsafe { Gmc::new(&descriptor, authority, &pool) }.is_ok() || pool.available() != BYTES {
            return TestResult::Fail("unsupported or truncated GMC bank allocated memory");
        }
    }
    // SAFETY: same inert mapping; constructor must not access it even with a
    // revoked cap. Dropping unpublished backing must return it to the pool.
    let owner = unsafe { Gmc::new(&gpu(), authority, &pool) }.unwrap();
    if owner.state() != State::Prepared || owner.aperture().is_some() {
        return TestResult::Fail("GMC constructor performed initialization");
    }
    drop(owner);
    if pool.available() != BYTES {
        return TestResult::Fail("unused GMC allocation leaked");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gmc-navi22",
    gmc_navi22_constructor_checks_exact_banks_before_allocation
);
