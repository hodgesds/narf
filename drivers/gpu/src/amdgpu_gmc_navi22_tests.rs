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
    /// The MMHUB table the model answers at 0x20000 (the layout's hubs[1]).
    pub(super) mm: HubRegs,
}
impl Io for Fake {
    fn wait_poll_limit(&self) -> Option<u32> {
        // The model presets the semaphore to acquired and acknowledges
        // an invalidate request synchronously in write(), so both TLB
        // waits complete on the first read. A wait still incomplete
        // after sixteen polls is a designed non-completion (a stalled
        // register) whose outcome is the timeout — reached by count
        // instead of burning the wall-clock deadline under the spin
        // executor (#879).
        Some(16)
    }
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
        if address == 0x20000 + u64::from(self.mm.inv_sem) * 4 && value == 0 {
            self.registers.insert(address, 1);
        }
        // Engine-17 model: a request acknowledges exactly its VMID bits.
        for (base, r) in [(0x10000, GFX), (0x20000, self.mm)] {
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
    fixture_hub(len, protected, MM)
}
/// [`fixture_with`] whose MMHUB is `mm`'s layout (MMHUB 2.3 for Raphael).
pub(super) fn fixture_hub(
    len: u64,
    protected: &[core::ops::Range<u64>],
    mm: HubRegs,
) -> (Pool, Engine<Fake>) {
    let layout = Layout {
        bases: [0x10000, 0x20000],
        hubs: [GFX, mm],
        nbio: 0x30000,
        init: NbioInit::Smn { pcie: 0x40000 },
        hdp: Some(0x50000),
        mmhub: (2, 1, 0),
    };
    let mut registers = BTreeMap::new();
    for (base, r) in layout.bases.into_iter().zip(layout.hubs) {
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
        mm,
    };
    let engine = Engine::new(fake, Cap::bootstrap(), layout, &pool, 12 << 30).unwrap();
    (pool, engine)
}
fn gmc_navi22_uses_vram_physical_ptes_and_bounds_vmid0() -> TestResult {
    let (pool, mut engine) = fixture();
    let aperture = run(engine.initialize()).unwrap();
    // amdgpu_gmc_gart_location BEST_FIT: 32 GiB below the FB fits the GART.
    if aperture.start != 0
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
                    .insert(0x10000 + u64::from(GFX.ctx + 1) * 4, 1);
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
                    .insert(0x20000 + u64::from(MM.fb_base) * 4, 0x801);
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
            5 => engine.vram_size = 0,
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
        ([0x800, 0x100], 12 << 30, 0x7_ffff_f000),
        ([0x800, 0x100], 12 << 30, 0x8_0000_4001),
        ([0xffff00, 0], 4 << 30, 0xffff_0000_0000),
        ([0x800, 0xffff00], 12 << 30, 0x8_0000_4000),
        ([0x800, 0x100], 0, 0x8_0000_4000),
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

/// The host's Linux log for this RX 6750 XT: `VRAM: 12272M
/// 0x8000000000-0x82FEFFFFFF`, `GART: 512M 0x0-0x1FFFFFFF`. A GART placed
/// above the VRAM end would cross a 4 GiB boundary; GOP leaves VMID0 enabled
/// and FB_LOCATION_TOP is not authoritative (Linux reads MEMSIZE).
fn gmc_navi22_12272m_gop_handoff_places_gart_like_linux() -> TestResult {
    const SIZE: u64 = 12272 << 20;
    if gart_location(0x80_0000_0000, 0x80_0000_0000 + SIZE, GART_SIZE) != Some(0)
        || gart_location(0, 8 << 30, GART_SIZE) != Some(0x7fff_0000_0000)
    {
        return TestResult::Fail("amdgpu_gmc_gart_location BEST_FIT placement");
    }
    let (_pool, mut engine) = fixture_sized(BYTES + (1 << 20) + 4096);
    engine.vram_size = SIZE;
    for (base, r) in engine.layout.bases.into_iter().zip([GFX, MM]) {
        // GOP-lit card: VMID0 enabled, TOP from a different (stale) size.
        engine.io.registers.insert(base + u64::from(r.ctx) * 4, 1);
        engine
            .io
            .registers
            .insert(base + u64::from(r.fb_top) * 4, 0x1234);
    }
    let Ok(aperture) = run(engine.initialize()) else {
        return TestResult::Fail("GOP-enabled VMID0 or stale TOP refused");
    };
    if aperture.start != 0 {
        return TestResult::Fail("boot aperture not at Linux's GART start");
    }
    for (base, r) in engine.layout.bases.into_iter().zip([GFX, MM]) {
        // MC_VM_SYSTEM_APERTURE_HIGH covers the last byte of 12272 MiB.
        if engine.io.registers[&(base + u64::from(r.sys_high) * 4)]
            != ((0x8_0000_0000 + SIZE - 1) >> 18) as u32
        {
            return TestResult::Fail("system aperture not derived from MEMSIZE");
        }
    }
    if engine
        .io
        .registers
        .get(&(0x50000 + HDP_MISC_CNTL * 4))
        .copied()
        != Some(HDP_FLUSH_INVALIDATE_CACHE)
        || engine
            .io
            .registers
            .get(&(0x40000 + PCIE_DATA2 * 4))
            .copied()
            != Some(MAX_READ_REQUEST_MODE | (1 << 28))
    {
        return TestResult::Fail("hdp_v5_0/nbio_v2_3 init_registers skipped");
    }
    engine.prepare_gart().unwrap();
    match run(engine.enable_gart()) {
        Ok(info) if info.start == 0 && info.size == 512 << 20 => {}
        _ => return TestResult::Fail("12272 MiB GART placement refused or moved"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gmc-navi22",
    gmc_navi22_12272m_gop_handoff_places_gart_like_linux
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
    // PCIE_CONFIG_CNTL index, re-index and data (nbio_v2_3_init_registers),
    // then the first HDP flush, which revokes.
    if run(engine.initialize()) != Err(Error::Revoked) || engine.io.writes.len() != 4 {
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

pub(super) fn rdna2_gpu(
    profile: &crate::amdgpu_rdna2::Profile,
    did: u16,
    mmhub: (u8, u8, u8),
) -> AmdGpu {
    let mut gpu = crate::amdgpu_navi22_boot::tests::gpu();
    gpu.chip = crate::amdgpu::__test_chip_info_for_pci_id(0x1002, did).unwrap();
    gpu.regs.len = 0x80000;
    for block in &mut gpu.ip_blocks {
        match block.hw_id {
            ip::HW_ID_GC => {
                (block.major, block.minor, block.revision) = profile.gc_version;
                block.base_addrs[0] = 0x10000 / 4;
            }
            ip::HW_ID_NBIF => {
                block.base_addrs[0] = 0x40000 / 4;
                block.base_addrs[2] = 0x30000 / 4;
            }
            ip::HW_ID_HDP => block.base_addrs[0] = 0x50000 / 4,
            _ => {}
        }
    }
    let mut block = gpu
        .ip_blocks
        .iter()
        .find(|b| b.hw_id == ip::HW_ID_GC)
        .copied()
        .unwrap();
    block.hw_id = ip::HW_ID_MMHUB;
    (block.major, block.minor, block.revision) = mmhub;
    block.base_addrs[0] = 0x20000 / 4;
    gpu.ip_blocks.push(block);
    gpu
}

fn rdna2_gmc_exact_gc_and_supported_hubs_precede_allocation() -> TestResult {
    for profile in crate::amdgpu_rdna2::PROFILES {
        for &did in profile.pci_ids {
            for &mm in crate::amdgpu_rdna2::GMC_MMHUB_VERSIONS {
                let gpu = rdna2_gpu(profile, did, mm);
                let layout = Layout::resolve_rdna2(&gpu).unwrap();
                if layout.bases != [0x10000, 0x20000]
                    || layout.nbio != 0x30000
                    || !matches!(layout.init, NbioInit::Smn { pcie: 0x40000 })
                    || layout.hdp != Some(0x50000)
                {
                    return TestResult::Fail("RDNA2 GMC resolved another IP base index");
                }
                let (pool, engine) = fixture();
                drop(engine);
                let authority = Cap::bootstrap();
                authority.revoke();
                // SAFETY: inert mapping; construction performs no I/O. Revoked
                // authority guarantees the attempted initialize cannot touch MMIO.
                let mut owner = unsafe { Gmc::new_rdna2(&gpu, authority, &pool) }.unwrap();
                let prepared = owner.state() == State::Prepared && owner.aperture().is_none();
                // SAFETY: inert mapping with revoked authority; no MMIO can execute.
                let initialized = unsafe { run(owner.initialize()) };
                if !prepared || initialized != Err(Error::Revoked) {
                    return TestResult::Fail("RDNA2 GMC initialized without live authority");
                }
                drop(owner);
                if pool.available() != BYTES {
                    return TestResult::Fail("unpublished RDNA2 GMC backing was retained");
                }
                if (did != crate::amdgpu::NAVI22 || mm != (2, 1, 0))
                    && Layout::resolve(&gpu).is_ok()
                {
                    return TestResult::Fail("shared GMC widened the native Navi22 gate");
                }
            }
        }
        let gpu = rdna2_gpu(profile, profile.pci_ids[0], (2, 1, 0));
        for id in [ip::HW_ID_GC, ip::HW_ID_MMHUB, ip::HW_ID_NBIF, ip::HW_ID_HDP] {
            for change in 0..4 {
                let mut bad = rdna2_gpu(profile, profile.pci_ids[0], (2, 1, 0));
                let index = bad.ip_blocks.iter().position(|b| b.hw_id == id).unwrap();
                match change {
                    0 => bad.ip_blocks[index].major = 0xff,
                    1 => bad.ip_blocks.push(bad.ip_blocks[index]),
                    2 => bad.ip_blocks[index].num_bases = 0,
                    _ => {
                        bad.ip_blocks.remove(index);
                    }
                }
                let (pool, engine) = fixture();
                drop(engine);
                // SAFETY: malformed discovery must reject before any I/O/allocation.
                if unsafe { Gmc::new_rdna2(&bad, Cap::bootstrap(), &pool) }.is_ok()
                    || pool.available() != BYTES
                {
                    return TestResult::Fail(
                        "RDNA2 GMC accepted invalid IP layout or allocated early",
                    );
                }
            }
        }
        for mmhub in [(2, 0, 0), (2, 3, 0), (2, 4, 0), (2, 1, 3)] {
            let bad = rdna2_gpu(profile, profile.pci_ids[0], mmhub);
            if Layout::resolve_rdna2(&bad).is_ok() {
                return TestResult::Fail("RDNA2 GMC accepted a different MMHUB backend");
            }
        }
        let mut bad = gpu;
        bad.chip.vid = 0x10de;
        if Layout::resolve_rdna2(&bad).is_ok() {
            return TestResult::Fail("non-AMD device entered shared GMC");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/rdna2",
    rdna2_gmc_exact_gc_and_supported_hubs_precede_allocation
);

/// Raphael's discovery: GC 10.3.6 at 0x10000, MMHUB `mmhub` on segment 1 at
/// 0x20000, NBIO `nbio` with Raphael's six segments, HDP 5.2.1.
fn raphael_gpu(mmhub: (u8, u8, u8), nbio: (u8, u8, u8)) -> AmdGpu {
    let mut gpu = crate::amdgpu_navi22_boot::tests::gpu();
    gpu.chip = crate::amdgpu::__test_chip_info_for_pci_id(0x1002, crate::amdgpu::RAPHAEL).unwrap();
    gpu.regs.len = 0x80000;
    let template = gpu.ip_blocks[0];
    let block = |id, v: (u8, u8, u8), bases: &[u32]| {
        let mut b = template;
        b.hw_id = id;
        (b.major, b.minor, b.revision) = v;
        b.num_bases = bases.len() as u8;
        b.base_addrs[..bases.len()].copy_from_slice(bases);
        b
    };
    gpu.ip_blocks = alloc::vec![
        block(ip::HW_ID_GC, (10, 3, 6), &[0x10000 / 4, 0]),
        block(ip::HW_ID_MMHUB, mmhub, &[0, 0x20000 / 4]),
        block(
            ip::HW_ID_NBIF,
            nbio,
            &[0, 0x14, 0xd20, 0x10400, 0x241_b000, 0x404_0000]
        ),
        block(ip::HW_ID_HDP, (5, 2, 1), &[0x50000 / 4]),
    ];
    gpu
}

/// `mmhub_2_3_0_offset.h`: the same programming as MMHUB 2.0 over every
/// register on `_BASE_IDX` 1, with context page tables 8 dwords apart (context
/// 1's base 0x948 after context 0's 0x940, START and END alike) and engine
/// ranges 8 apart (ENG1 0xa0b after ENG0 0xa03).
fn raphael_mmhub_2_3_table_matches_the_header() -> TestResult {
    if (MM23.fb_base, MM23.l1, MM23.l2, MM23.l2_5, MM23.ctx) != (0x8ec, 0x8f3, 0x700, 0x720, 0x740)
        || (MM23.pt_base, MM23.pt_start, MM23.pt_end) != (0x940, 0x942, 0x944)
        || (MM23.inv_req, MM23.inv_ack, MM23.inv_sem, MM23.inv_range)
            != (0xa89, 0xa8a, 0xa88, 0xa03)
        || (
            MM23.ctx_distance,
            MM23.ctx_addr_distance,
            MM23.eng_addr_distance,
        ) != (1, 8, 8)
        || (
            MM.ctx_addr_distance,
            MM.eng_addr_distance,
            GFX.ctx_addr_distance,
        ) != (2, 2, 2)
    {
        return TestResult::Fail("MMHUB 2.3 register table differs from mmhub_2_3_0");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gmc-raphael",
    raphael_mmhub_2_3_table_matches_the_header
);

/// Raphael resolves GC 10.3.6's gfxhub, mmhub_v2_3 on segment 1 for MMHUB
/// 2.3.0/2.4.0/2.4.1, NBIO 7.2 and HDP 5.2.1, with no HDP init; Navi22's
/// MMHUB 2.1, HDP 5.0 and NBIO 2.3 are refused, as is a discrete GPU.
fn raphael_gmc_layout_takes_only_raphaels_blocks() -> TestResult {
    for mm in [(2, 3, 0), (2, 4, 0), (2, 4, 1)] {
        let Ok(layout) = Layout::resolve_raphael(&raphael_gpu(mm, (7, 2, 1))) else {
            return TestResult::Fail("Raphael GMC layout refused");
        };
        if layout.bases != [0x10000, 0x20000]
            || layout.nbio != 0xd20 * 4
            || layout.hdp.is_some()
            || !matches!(layout.init, NbioInit::V7_2(b) if b.version == (7, 2, 1))
            || layout.hubs[1].ctx != MM23.ctx
            || layout.hubs[0].ctx != GFX.ctx
        {
            return TestResult::Fail("Raphael GMC banks or tables");
        }
    }
    let mut hdp50 = raphael_gpu((2, 3, 0), (7, 2, 1));
    hdp50.ip_blocks[3].revision = 0;
    hdp50.ip_blocks[3].minor = 0;
    let mut navi22 = raphael_gpu((2, 3, 0), (7, 2, 1));
    navi22.chip =
        crate::amdgpu::__test_chip_info_for_pci_id(0x1002, crate::amdgpu::NAVI22).unwrap();
    for (bad, why) in [
        (
            raphael_gpu((2, 1, 0), (7, 2, 1)),
            "Raphael GMC took MMHUB 2.1",
        ),
        (
            raphael_gpu((2, 3, 0), (2, 3, 0)),
            "Raphael GMC took NBIO 2.3",
        ),
        (
            raphael_gpu((2, 3, 0), (7, 7, 0)),
            "Raphael GMC took NBIO 7.7",
        ),
        (hdp50, "Raphael GMC took HDP 5.0"),
        (navi22, "Raphael GMC took a discrete GPU"),
    ] {
        if Layout::resolve_raphael(&bad).is_ok() {
            return TestResult::Fail(why);
        }
    }
    if Layout::resolve_rdna2(&raphael_gpu((2, 3, 0), (7, 2, 1))).is_ok() {
        return TestResult::Fail("the discrete GMC layout took Raphael");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gmc-raphael",
    raphael_gmc_layout_takes_only_raphaels_blocks
);

/// `nbio_v7_2_init_registers` through the hubs' register model: on 7.2.1 the
/// read-request register (`BIF1_PCIE_MST_CTRL_3`) goes through the port pair
/// and is written only on change; on 7.3.0 the DEV2 strap is then cleared
/// through PCIE_INDEX2/DATA2, written unconditionally.
fn raphael_nbio_init_follows_nbio_v7_2() -> TestResult {
    use crate::amdgpu_nbio_v7_2 as nbio;
    let fake = |registers: &[(u64, u32)]| Fake {
        registers: registers.iter().copied().collect(),
        writes: Vec::new(),
        memory: BTreeMap::new(),
        stall: None,
        revoke_on: None,
        stores: 0,
        mm: MM,
    };
    let banks = |version| nbio::Banks::resolve(&raphael_gpu((2, 3, 0), version)).unwrap();
    let b = banks((7, 2, 1));
    let ((port_index, port_data), (smn_index, smn_data)) = (b.port_pair(), b.smn_pair());
    let mst = b.seg5_address(nbio::BIF1_PCIE_MST_CTRL_3).unwrap();
    let mut io = fake(&[(port_data, 0)]);
    if init_nbio_v7_2(&mut io, b).is_err()
        || io.writes
            != alloc::vec![
                (port_index, mst),
                (port_index, mst),
                (port_data, 0x1800_0000)
            ]
    {
        return TestResult::Fail("NBIO 7.2.1 read-request update");
    }
    let mut io = fake(&[(port_data, 0x1800_0000)]);
    if init_nbio_v7_2(&mut io, b).is_err() || io.writes != alloc::vec![(port_index, mst)] {
        return TestResult::Fail("NBIO 7.2 rewrote an unchanged read-request register");
    }
    let b = banks((7, 3, 0));
    let strap = b.seg5_address(nbio::RCC_DEV2_EPF0_STRAP2).unwrap();
    let mut io = fake(&[(port_data, 0x1800_0000), (smn_data, 0xff)]);
    if init_nbio_v7_2(&mut io, b).is_err()
        || io.writes
            != alloc::vec![
                (port_index, mst),
                (smn_index, strap),
                (smn_index, strap),
                (smn_data, 0x7f),
            ]
    {
        return TestResult::Fail("NBIO 7.3.0 DEV2 strap");
    }
    let b = banks((7, 2, 0));
    let config = b.seg5_address(nbio::PCIE_CONFIG_CNTL).unwrap();
    let mut io = fake(&[(port_data, 0x1800_0000)]);
    if init_nbio_v7_2(&mut io, b).is_err() || io.writes != alloc::vec![(port_index, config)] {
        return TestResult::Fail("NBIO 7.2.0 read-request register");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gmc-raphael",
    raphael_nbio_init_follows_nbio_v7_2
);

/// Re-armed after a reset (the hub registers back to the handoff), the GMC
/// programs both hubs and enables the same GART table again and lends its
/// VMIDs under a new owner token. A live VM refuses the re-arm, unchanged.
fn gmc_navi22_rearm_reuses_the_aperture_and_gart() -> TestResult {
    // The boot pages, the GART table and its empty root, then a VM's root.
    let (pool, mut engine) = fixture_sized(BYTES + (1 << 20) + 2 * 4096);
    engine.vram_size = 12272 << 20;
    let handoff = engine.io.registers.clone();
    if run(engine.initialize()).is_err() || engine.prepare_gart().is_err() {
        return TestResult::Fail("first GMC bring-up");
    }
    let Ok(gart) = run(engine.enable_gart()) else {
        return TestResult::Fail("first GART enable");
    };
    let Ok(vmids) = engine.reserve_client_vmids() else {
        return TestResult::Fail("first VMID lending");
    };
    let Ok(vm) = run(engine.create_vm()) else {
        return TestResult::Fail("VM creation");
    };
    // SAFETY: refused below; nothing is reset.
    if unsafe { engine.rearm() } != Err(Error::Busy) || engine.state != State::Ready {
        return TestResult::Fail("re-armed under a live VM");
    }
    if run(engine.destroy_vm(vm)).is_err() {
        return TestResult::Fail("VM teardown");
    }
    // After the teardown, which may keep the root page quarantined.
    let free = pool.available();
    // SAFETY: the registers are put back below, as a reset would.
    if unsafe { engine.rearm() }.is_err()
        || engine.state != State::Prepared
        || engine.aperture.is_some()
        || engine.gart.as_ref().is_some_and(|g| g.info().is_some())
    {
        return TestResult::Fail("re-arm refused or kept the last run");
    }
    engine.io.registers = handoff;
    if run(engine.initialize()).is_err() || run(engine.enable_gart()) != Ok(gart) {
        return TestResult::Fail("re-armed GMC bring-up or a moved GART");
    }
    match engine.reserve_client_vmids() {
        Ok(again) if again.range() == vmids.range() && again.owner() != vmids.owner() => {}
        _ => return TestResult::Fail("re-armed GMC did not lend its VMIDs anew"),
    }
    if pool.available() != free {
        return TestResult::Fail("re-armed GMC reserved more");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gmc-navi22",
    gmc_navi22_rearm_reuses_the_aperture_and_gart
);
