//! Fixtures for the Navi31/32/33 GMC v11 owner, mirroring
//! `amdgpu_gmc_navi48_tests.rs`.

use super::*;
use crate::amdgpu::__test_chip_info_for_pci_id;
use crate::amdgpu_gfx_navi22::tests::gpu as base_gpu;
use crate::amdgpu_vmhub_regs::{GFXHUB_V3_0, GFXHUB_V3_0_3, MMHUB_V3_0};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::future::Future;
use narf_bus::BusDeviceCap;
use narf_capabilities::Cap;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_memory::PhysAddr;

#[derive(Debug)]
struct Fake {
    registers: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
    memory: Vec<u32>,
    stall: Option<u64>,
    revoke_on: Option<(u64, Cap<BusDeviceCap, Write>)>,
}
impl Fake {
    fn new() -> Self {
        Self {
            registers: BTreeMap::new(),
            writes: Vec::new(),
            memory: alloc::vec![0; (BYTES / 4) as usize],
            stall: None,
            revoke_on: None,
        }
    }
    fn base_regs(&mut self, base: u64, r: HubRegs) {
        self.registers
            .insert(base + u64::from(r.fb_base) * 4, 0x800);
        self.registers.insert(base + u64::from(r.fb_top) * 4, 0xbff);
        self.registers
            .insert(base + u64::from(r.fb_offset) * 4, 0x100);
        // VMID0's ACK is live from the start.
        self.registers.insert(base + u64::from(r.inv_ack) * 4, 1);
        // The MMHUB semaphore is free (a read returning 1).
        self.registers.insert(base + u64::from(r.inv_sem) * 4, 1);
    }
}
impl Io for Fake {
    fn read(&mut self, address: u64) -> u32 {
        if Some(address) == self.stall {
            return 0;
        }
        *self.registers.get(&address).unwrap_or(&0)
    }
    fn write(&mut self, address: u64, value: u32) {
        self.writes.push((address, value));
        self.registers.insert(address, value);
        // A released MMHUB semaphore reads 1 (acquired) on the next sample.
        if address == 0x20000 + u64::from(MM.inv_sem) * 4 && value == 0 {
            self.registers.insert(address, 1);
        }
        if let Some((when, cap)) = self.revoke_on {
            if address == when {
                cap.revoke();
            }
        }
    }
    fn memory(&mut self, map: MmioRegion, offset: u64, value: u32) {
        let base = map.phys.raw() - 0x9000_0000;
        let index = (base + offset) / 4;
        self.memory[index as usize] = value;
    }
    fn memory64(&mut self, map: MmioRegion, offset: u64, value: u64) {
        self.memory(map, offset, value as u32);
        self.memory(map, offset + 4, (value >> 32) as u32);
    }
}

fn pool() -> Pool {
    let map = MmioRegion {
        phys: PhysAddr::new(0x9000_0000),
        virt: 0x4000,
        len: BYTES,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // SAFETY: Fake owns all memory accesses; mapping is never dereferenced.
    unsafe { Pool::from_owned_range(map, 0x8_0000_4000) }.unwrap()
}
fn layout_for(die: Navi31Die) -> Layout {
    let (gfx, gfx_vmhub) = match die {
        Navi31Die::Navi32 => (GFX_11_0_3, GFXHUB_V3_0_3),
        _ => (GFX, GFXHUB_V3_0),
    };
    Layout {
        die,
        bases: [0x10000, 0x20000],
        hubs: [gfx, MM],
        vmhub: [gfx_vmhub, MMHUB_V3_0],
        nbio: 0x30000,
        osssys: 0x40000,
    }
}
fn fixture_for(die: Navi31Die) -> (Pool, Engine<Fake>) {
    let pool = pool();
    let mut io = Fake::new();
    let layout = layout_for(die);
    io.registers.insert(0x30000 + 0x12d * 4, 0x7f000);
    io.base_regs(0x10000, layout.hubs[0]);
    io.base_regs(0x20000, MM);
    let engine = Engine {
        io,
        authority: Cap::bootstrap(),
        layout,
        memory: pool.reserve(BYTES).unwrap(),
        vram_size: 16 << 30,
        state: State::Prepared,
        aperture: None,
        geometry: None,
    };
    (pool, engine)
}
fn fixture() -> (Pool, Engine<Fake>) {
    fixture_for(Navi31Die::Navi31)
}
fn run<T>(future: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(future)
}

/// The corrected die↔GC pairing (lane 1), and Phoenix's GC 11.0.1
/// refused by every Navi31/32/33 entry point.
fn gmc_navi31_die_identity() -> TestResult {
    if Navi31Die::from_gc((11, 0, 0)) != Some(Navi31Die::Navi31)
        || Navi31Die::from_gc((11, 0, 3)) != Some(Navi31Die::Navi32)
        || Navi31Die::from_gc((11, 0, 2)) != Some(Navi31Die::Navi33)
        || Navi31Die::from_gc((11, 0, 1)).is_some()
        || Navi31Die::from_gc((11, 5, 0)).is_some()
    {
        return TestResult::Fail("die from GC version");
    }
    if Navi31Die::Navi31.gc_version() != (11, 0, 0)
        || Navi31Die::Navi32.gc_version() != (11, 0, 3)
        || Navi31Die::Navi33.gc_version() != (11, 0, 2)
    {
        return TestResult::Fail("GC version round trip");
    }
    let blocks = [
        ip::IpBlock {
            hw_id: ip::HW_ID_GC,
            instance: 0,
            major: 11,
            minor: 0,
            revision: 0,
            sub_revision: 0,
            variant: 0,
            num_bases: 1,
            base_addrs: [0x4000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        },
        ip::IpBlock {
            hw_id: ip::HW_ID_GC,
            instance: 0,
            major: 11,
            minor: 0,
            revision: 0,
            sub_revision: 0,
            variant: 0,
            num_bases: 1,
            base_addrs: [0x4000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        },
    ];
    if Navi31Die::from_ip_blocks(&blocks).is_some() {
        return TestResult::Fail("duplicate GC block accepted");
    }
    if GART_SIZE != 512 << 20 || GART_TABLE_PAGES != 131072 {
        return TestResult::Fail("GART size");
    }
    if FIRST_KFD_VMID != 8
        || is_gfx_vmid(0)
        || !is_gfx_vmid(1)
        || !is_gfx_vmid(7)
        || is_gfx_vmid(8)
        || is_kfd_vmid(7)
        || !is_kfd_vmid(8)
        || !is_kfd_vmid(15)
        || is_kfd_vmid(16)
    {
        return TestResult::Fail("VMID split");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/gmc-navi31", gmc_navi31_die_identity);

/// The Navi32 GFXHUB table in `amdgpu_vmhub_regs` matches
/// `gc_11_0_3_offset.h`: the +0x10 GCMC/GCVM shift and the +0x4 L2
/// shift, against the 11.0.0 table it replaces.
fn gmc_navi31_navi32_hub_table_matches_linux() -> TestResult {
    if GFXHUB_V3_0_3.ctx0_pt_base_lo != 0x1703
        || GFXHUB_V3_0_3.ctx0_pt_start_lo != 0x1723
        || GFXHUB_V3_0_3.ctx0_pt_end_lo != 0x1743
        || GFXHUB_V3_0_3.ctx0_cntl != 0x1698
        || GFXHUB_V3_0_3.inv_eng0_req != 0x16bb
        || GFXHUB_V3_0_3.inv_eng0_ack != 0x16cd
        || GFXHUB_V3_0_3.inv_eng0_sem != 0x16a9
        || GFXHUB_V3_0_3.eng_distance != 1
        || GFXHUB_V3_0_3.semaphore
        || GFXHUB_V3_0.ctx0_pt_base_lo != 0x16f3
        || GFXHUB_V3_0.ctx0_pt_base_lo != GFX.pt_base
    {
        return TestResult::Fail("GFXHUB_V3_0_3");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gmc-navi31",
    gmc_navi31_navi32_hub_table_matches_linux
);

fn descriptor(mut f: impl FnMut(&mut AmdGpu)) -> AmdGpu {
    let mut gpu = base_gpu();
    gpu.chip = __test_chip_info_for_pci_id(0x1002, 0x744C).unwrap();
    // bank() bounds every bank against this: the NBIF bank needs
    // 0x304b8 bytes (base 0xc000 dwords + the 0x12d remap dword).
    gpu.regs.len = 0x40000;
    gpu.vram.size = 16 << 30;
    gpu.ip_blocks = alloc::vec![
        ip::IpBlock {
            hw_id: ip::HW_ID_GC,
            instance: 0,
            major: 11,
            minor: 0,
            revision: 0,
            sub_revision: 0,
            variant: 0,
            num_bases: 1,
            base_addrs: [0x4000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        },
        ip::IpBlock {
            hw_id: ip::HW_ID_MMHUB,
            instance: 0,
            major: 3,
            minor: 0,
            revision: 0,
            sub_revision: 0,
            variant: 0,
            num_bases: 1,
            base_addrs: [0x8000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        },
        ip::IpBlock {
            hw_id: ip::HW_ID_NBIF,
            instance: 0,
            major: 7,
            minor: 7,
            revision: 0,
            sub_revision: 0,
            variant: 0,
            num_bases: 3,
            base_addrs: [0, 0, 0xc000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        },
        ip::IpBlock {
            hw_id: ip::HW_ID_OSSSYS,
            instance: 0,
            major: 6,
            minor: 0,
            revision: 0,
            sub_revision: 0,
            variant: 0,
            num_bases: 1,
            base_addrs: [0x9000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        },
    ];
    f(&mut gpu);
    gpu
}
fn gmc_new(gpu: &AmdGpu, cap: Cap<BusDeviceCap, Write>, pool: &Pool) -> Result<Gmc, Error> {
    // SAFETY: owned register fixture; all unsupported paths reject
    // before any allocation, and the happy path reserves only.
    unsafe { Gmc::new(gpu, cap, pool) }
}

/// Every identity, bank and pool precondition is checked before any
/// allocation, on the exact bank tables the device would get.
#[allow(clippy::type_complexity)]
fn gmc_navi31_constructor_checks_exact_banks_and_pool_before_allocation() -> TestResult {
    let pool = pool();
    let cap = || Cap::bootstrap();
    let cases: [(&str, fn(&mut AmdGpu)); 12] = [
        ("wrong device", |g| {
            g.chip = __test_chip_info_for_pci_id(0x1002, 0x73ff).unwrap()
        }),
        ("non-AMD vendor", |g| g.chip.vid = 0x8086),
        ("short BAR", |g| g.regs.len = 0x20000),
        ("GC revision", |g| g.ip_blocks[0].revision = 1),
        ("Phoenix GC", |g| {
            g.ip_blocks[0].minor = 0;
            g.ip_blocks[0].revision = 1;
        }),
        ("GC minor", |g| g.ip_blocks[0].minor = 1),
        ("GC duplicate", |g| {
            g.ip_blocks.push(g.ip_blocks[0]);
        }),
        ("MMHUB minor", |g| g.ip_blocks[1].minor = 1),
        ("MMHUB revision", |g| g.ip_blocks[1].revision = 2),
        ("NBIF bases", |g| g.ip_blocks[2].num_bases = 2),
        ("GC base too high", |g| {
            g.ip_blocks[0].base_addrs[0] = 0xf000;
        }),
        ("OSSSYS version", |g| g.ip_blocks[3].major = 7),
    ];
    for (name, mutate) in cases {
        let gpu = descriptor(mutate);
        if gmc_new(&gpu, cap(), &pool).is_ok() || pool.available() != BYTES {
            return TestResult::Fail(name);
        }
    }
    // Phoenix's GC 11.0.1 is refused even on the Navi31 device id.
    let gpu = descriptor(|g| g.ip_blocks[0].revision = 1);
    if gmc_new(&gpu, cap(), &pool).is_ok() {
        return TestResult::Fail("Phoenix GC 11.0.1");
    }
    let gpu = descriptor(|_| {});
    let cap = cap();
    let gmc = match gmc_new(&gpu, cap, &pool) {
        Ok(gmc) => gmc,
        Err(_) => return TestResult::Fail("happy path"),
    };
    if gmc.die() != Navi31Die::Navi31
        || gmc.state() != State::Prepared
        || gmc.aperture().is_some()
        || gmc.framebuffer().is_some()
    {
        return TestResult::Fail("prepared state");
    }
    drop(gmc);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gmc-navi31",
    gmc_navi31_constructor_checks_exact_banks_and_pool_before_allocation
);

/// VMID0 bring-up on both hubs, with the GFX11 literals from
/// `gc_11_0_0_sh_mask.h` / `mmhub_3_0_0_sh_mask.h`, and one TLB
/// invalidation of VMID0 per hub on engine 17 — GFX then MM, the
/// MMHUB semaphore held around its flush, then the MMHUB private-cache
/// invalidation bit.
fn gmc_navi31_initialize_programs_both_hubs_and_flushes_tlb() -> TestResult {
    let (_pool, mut engine) = fixture();
    let aperture = match run(engine.initialize()) {
        Ok(aperture) => aperture,
        Err(_) => return TestResult::Fail("initialize"),
    };
    if engine.state != State::Ready || !engine.state.vmid0_ready() {
        return TestResult::Fail("ready state");
    }
    // The aperture starts on a 2 MiB boundary past the 16 GiB VRAM.
    if aperture.start != 0xc_0000_0000 || aperture.size != APERTURE_SIZE {
        return TestResult::Fail("aperture placement");
    }
    let reg = |base: u64, r: u32| engine.io.registers.get(&(base + u64::from(r) * 4)).copied();
    for (base, r) in [(0x10000, GFX), (0x20000, MM)] {
        // L1: ENABLE_L1_TLB | SYSTEM_ACCESS_MODE=3 | ADM | MTYPE=UC(3).
        if reg(base, r.l1) != Some(0x1859) {
            return TestResult::Fail("L1 TLB control");
        }
        // L2: ENABLE_L2_CACHE | CONTEXT1_IDENTITY_ACCESS_MODE=1, the
        // default page staying in VRAM (OUT_TO_SYSTEM_MEMORY clear).
        if reg(base, r.l2) != Some(0x80001) {
            return TestResult::Fail("L2 cache control");
        }
        if reg(base, r.l2_3) != Some(0x80130009) {
            return TestResult::Fail("L2 CNTL3");
        }
        if reg(base, r.l2_4) != Some(0x01) || reg(base, r.l2_5) != Some(0x3fe0) {
            return TestResult::Fail("L2 CNTL4/5");
        }
        // All eleven fault-enable defaults, status-address bits clear.
        if reg(base, r.fault_cntl) != Some(0x1ffc) {
            return TestResult::Fail("fault control");
        }
        if reg(base, r.fault_cntl2) != Some(0x40000) {
            return TestResult::Fail("fault CNTL2");
        }
        // VMID0: ENABLE + the seven fault-enable defaults, flat PT.
        if reg(base, r.ctx) != Some(0x555401) {
            return TestResult::Fail("VMID0 context");
        }
        // The invalidation ranges cover the 48-bit space.
        for index in 0..18u64 {
            let lo = reg(base, r.inv_range + (index * 2) as u32);
            let hi = reg(base, r.inv_range + (index * 2) as u32 + 1);
            if lo != Some(0xffffffff) || hi != Some(0x1f) {
                return TestResult::Fail("invalidation range");
            }
        }
        // The kernel engine's invalidation of VMID0.
        if !engine
            .io
            .writes
            .contains(&(base + u64::from(r.inv_req) * 4, 0xf80001))
        {
            return TestResult::Fail("TLB invalidation request");
        }
    }
    // MMHUB-only: the semaphore was released, then the private-cache
    // invalidation bit was set in the bank-select register.
    if !engine
        .io
        .writes
        .contains(&(0x20000 + u64::from(MM.inv_sem) * 4, 0))
        || reg(0x20000, MM.l2_bank_select) != Some(1 << 25)
    {
        return TestResult::Fail("MMHUB private-cache invalidation");
    }
    // The GFX hub's semaphore was never touched.
    if engine
        .io
        .writes
        .iter()
        .any(|(a, _)| *a == 0x10000 + u64::from(GFX.inv_sem) * 4)
    {
        return TestResult::Fail("GFX semaphore touched");
    }
    // The test pages: PTE 0x61 (V/R/W, NC VRAM) for the source and
    // destination pages, at the physical addresses the FB geometry gives.
    let phys = |addr: u64| addr - 0x800000000 + 0x100000000;
    for (index, offset) in [8192u64, 12288].into_iter().enumerate() {
        let pte = phys(0x8_0000_4000 + offset) | 0x61;
        let lo = engine.io.memory[index * 2];
        let hi = engine.io.memory[index * 2 + 1];
        if u64::from(hi) << 32 | u64::from(lo) != pte {
            return TestResult::Fail("test PTEs");
        }
    }
    if run(engine.initialize()) != Err(Error::Busy) {
        return TestResult::Fail("initialize replayed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gmc-navi31",
    gmc_navi31_initialize_programs_both_hubs_and_flushes_tlb
);

/// Navi32's GFX hub programs through the shifted 11.0.3 table; the
/// MMHUB table is shared with Navi31/33.
fn gmc_navi31_navi32_programs_shifted_registers() -> TestResult {
    let (_pool, mut engine) = fixture_for(Navi31Die::Navi32);
    if run(engine.initialize()).is_err() {
        return TestResult::Fail("Navi32 initialize");
    }
    let reg = |base: u64, r: u32| engine.io.registers.get(&(base + u64::from(r) * 4)).copied();
    if reg(0x10000, GFX_11_0_3.l1) != Some(0x1859)
        || reg(0x10000, GFX_11_0_3.ctx) != Some(0x555401)
        || reg(0x10000, GFX_11_0_3.inv_req) != Some(0xf80001)
        || reg(0x20000, MM.ctx) != Some(0x555401)
    {
        return TestResult::Fail("Navi32 hub registers");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gmc-navi31",
    gmc_navi31_navi32_programs_shifted_registers
);

/// `gfxhub_v3_0_setup_vmid_config` / `mmhub_v3_0_setup_vmid_config` for
/// VMIDs 1..15: each enabled with depth 3 and block size 9, every fault
/// default and no retry, bounded to the 48-bit space, based at an owned
/// root whose every entry is GMC 11's invalid pattern. One invalidation
/// of all fifteen per hub on engine 17, the MMHUB semaphore held.
fn gmc_navi31_client_contexts_start_at_an_empty_root() -> TestResult {
    let (_pool, mut engine) = fixture();
    if run(engine.prepare_clients()) != Err(Error::Busy) {
        return TestResult::Fail("client contexts before VMID0");
    }
    run(engine.initialize()).unwrap();
    let ack = |hub: u64, reg: u64| hub + reg * 4;
    for (hub, a, s) in [(0x10000, 0x16ce, 0x16aa), (0x20000, 0x786, 0x762)] {
        engine.io.registers.insert(ack(hub, a), 0xffff);
        engine.io.registers.insert(ack(hub, s), 1);
    }
    let writes = engine.io.writes.len();
    if let Err(e) = run(engine.prepare_clients()) {
        let _ = e;
        return TestResult::Fail("client contexts");
    }
    if engine.state != State::ClientsReady || !engine.state.vmid0_ready() {
        return TestResult::Fail("clients ready state");
    }
    // The empty root: 512 entries of PDE_PTE (bit 54 on GMC 11 —
    // `AMDGPU_PDE_PTE`, `amdgpu_vm.h`; bit 63 is the GFX12 pattern),
    // none VALID.
    let root = 16384 / 4;
    if (0..512).any(|i| engine.io.memory[root + 2 * i..root + 2 * i + 2] != [0, 0x0040_0000]) {
        return TestResult::Fail("empty root pattern");
    }
    // depth 3 at 2:1, block size 9 encodes as 0 (the field holds
    // block_size - 9), no retry (bit 8 clear — faults raise instead),
    // the seven fault defaults at 10..22.
    let cntl = 1 | 3 << 1 | 0x555400;
    for (hub, base, start, end, ctx, req, sem) in [
        (0x10000u64, 0x16f3, 0x1713, 0x1733, 0x1688, 0x16bc, 0x16aa),
        (0x20000, 0x7ab, 0x7cb, 0x7eb, 0x740, 0x774, 0x762),
    ] {
        let reg = |r: u64| engine.io.registers.get(&(hub + r * 4)).copied();
        for vmid in 1..16u64 {
            // The fixture's VRAM physical addresses carry a high word of 1
            // (VMID0's root is 0x1_0000_8001).
            if reg(base + 2 * vmid) != Some(0x8001)
                || reg(base + 2 * vmid + 1) != Some(1)
                || reg(start + 2 * vmid) != Some(0)
                || reg(end + 2 * vmid) != Some(u32::MAX)
                || reg(end + 2 * vmid + 1) != Some(0xf)
                || reg(ctx + vmid) != Some(cntl)
            {
                return TestResult::Fail("client context registers");
            }
        }
        // VMID0's context is untouched.
        if engine.io.writes[writes..]
            .iter()
            .any(|(a, _)| *a == hub + ctx * 4 || *a == hub + base * 4)
        {
            return TestResult::Fail("VMID0 reprogrammed");
        }
        if !engine.io.writes[writes..].contains(&(hub + req * 4, 0x00f8_fffe)) {
            return TestResult::Fail("one invalidation of every client VMID");
        }
        let released = engine.io.writes[writes..].contains(&(hub + sem * 4, 0));
        if released != (hub == 0x20000) {
            return TestResult::Fail("semaphore only on MMHUB");
        }
    }
    if run(engine.prepare_clients()) != Err(Error::Busy) {
        return TestResult::Fail("client contexts replayed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gmc-navi31",
    gmc_navi31_client_contexts_start_at_an_empty_root
);

/// The PASID LUTs: both hubs' slots written, read back from the GFX
/// LUT, 0 unmapping, and a PASID flush touching only its VMIDs.
fn gmc_navi31_pasid_mapping_round_trip() -> TestResult {
    let (_pool, mut engine) = fixture();
    run(engine.initialize()).unwrap();
    if engine.map_pasid(16, 1) != Err(Error::Invalid)
        || engine.pasid_for_vmid(16) != Err(Error::Invalid)
    {
        return TestResult::Fail("VMID bounds");
    }
    if engine.pasid_for_vmid(3) != Ok(None) {
        return TestResult::Fail("unmapped PASID");
    }
    engine.map_pasid(3, 0x1234).unwrap();
    engine.map_pasid(7, 0x1234).unwrap();
    if engine.pasid_for_vmid(3) != Ok(Some(0x1234))
        || engine.pasid_for_vmid(7) != Ok(Some(0x1234))
        || engine
            .io
            .registers
            .get(&(0x40000 + 0x10 * 4 + 3 * 4))
            .copied()
            != Some(0x1234)
    {
        return TestResult::Fail("PASID written to both LUTs");
    }
    // Only VMIDs 3 and 7 are flushed, on both hubs.
    let ack = |hub: u64, reg: u64| hub + reg * 4;
    for (hub, a) in [(0x10000, 0x16ce), (0x20000, 0x786)] {
        engine.io.registers.insert(ack(hub, a), 0xffff);
    }
    let writes = engine.io.writes.len();
    if run(engine.flush_tlb_pasid(0x1234)).is_err() {
        return TestResult::Fail("PASID flush");
    }
    for (base, req) in [(0x10000u64, 0x16bc_u32), (0x20000, 0x774_u32)] {
        for vmid in [3u32, 7] {
            // The request word is (1 << vmid) | 0xF80000.
            if !engine.io.writes[writes..]
                .contains(&(base + u64::from(req) * 4, (1 << vmid) | 0xf80000))
            {
                return TestResult::Fail("PASID flush request");
            }
        }
        // No other VMID was flushed.
        if engine.io.writes[writes..]
            .iter()
            .filter(|(a, _)| *a == base + u64::from(req) * 4)
            .count()
            != 2
        {
            return TestResult::Fail("PASID flush scope");
        }
    }
    if run(engine.flush_tlb_pasid(0x9999)).is_err() {
        return TestResult::Fail("unknown PASID flush");
    }
    engine.map_pasid(3, 0).unwrap();
    if engine.pasid_for_vmid(3) != Ok(None) {
        return TestResult::Fail("PASID unmap");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gmc-navi31",
    gmc_navi31_pasid_mapping_round_trip
);

/// A TLB invalidation whose ACK never comes fails closed and quarantines
/// the owner; a revoked authority does the same, retaining the published
/// backing pages instead of freeing translations the GPU may still hold.
fn gmc_navi31_cancel_timeout_and_revoke_retain_translation_memory() -> TestResult {
    let (pool, mut engine) = fixture();
    engine.io.stall = Some(0x10000 + 0x16ce * 4);
    if run(engine.initialize()) != Err(Error::Timeout) {
        return TestResult::Fail("stalled ACK times out");
    }
    if engine.state != State::Failed {
        return TestResult::Fail("timeout quarantines");
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
    if engine.state != State::Failed {
        return TestResult::Fail("revocation quarantines");
    }
    drop(engine);
    if pool.available() != 0 {
        return TestResult::Fail("revoked publication not retained");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gmc-navi31",
    gmc_navi31_cancel_timeout_and_revoke_retain_translation_memory
);
