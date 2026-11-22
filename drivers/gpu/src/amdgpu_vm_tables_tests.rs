//! Client page-table placement against Linux `amdgpu_vm_pt_create`: on a
//! dGPU every PD/PT lives in VRAM, its PDEs and the context base carry
//! `amdgpu_gmc_vram_mc2pa` addresses with VALID and no SYSTEM bit
//! (`amdgpu_gmc_get_pde_for_bo`, `gmc_v10_0_get_vm_pde`), and CPU updates
//! end with `amdgpu_vm_cpu_commit`'s HDP flush. A hub model walks the
//! tables from the base both hubs are given, through the VRAM bytes only.
use super::*;
use core::sync::atomic::{AtomicUsize, Ordering};
use narf_kernel_test::{kernel_test_in, TestResult};

/// MC address of the fake heap's first byte; the card's `vram_start` and
/// `vram_base_offset` differ, so a missing MC→PA conversion shows.
const MC: u64 = 0x8_0040_0000;
const FB_BASE: u64 = 0x8_0000_0000;
const FB_OFFSET: u64 = 0x1_0000_0000;
const PAGES: usize = 64;
const ADDRESS: u64 = 0x0000_ffff_ffff_f000;

#[derive(Debug, Default)]
struct Flushes(AtomicUsize);
impl HdpFlush for Flushes {
    fn flush(&self) -> Result<(), FsError> {
        self.0.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

/// CPU-visible "VRAM" for one card: page-aligned bytes behind a pool.
struct Vram {
    bytes: Vec<u8>,
    start: usize,
    pool: crate::amdgpu_vram::Pool,
    flushes: Arc<Flushes>,
}
impl Vram {
    fn new() -> Self {
        let mut bytes = alloc::vec![0u8; (PAGES + 1) * 4096];
        let start = (4096 - (bytes.as_mut_ptr() as usize % 4096)) % 4096;
        let map = narf_bus::MmioRegion {
            phys: narf_memory::PhysAddr::new(0xc000_0000),
            virt: bytes.as_mut_ptr() as u64 + start as u64,
            len: (PAGES * 4096) as u64,
            kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
        };
        // SAFETY: the fixture owns these bytes until every table and the
        // registered heap are gone; no hardware reaches them.
        let pool = unsafe { crate::amdgpu_vram::Pool::from_owned_range(map, MC) }.unwrap();
        Self {
            bytes,
            start,
            pool,
            flushes: Arc::new(Flushes::default()),
        }
    }
    fn heap(&self) -> TableHeap {
        TableHeap {
            pool: self.pool.clone(),
            fb_base: FB_BASE,
            fb_offset: FB_OFFSET,
            hdp: self.flushes.clone(),
        }
    }
    fn flushes(&self) -> usize {
        self.flushes.0.load(Ordering::Acquire)
    }
    /// The 8 bytes at GPU physical address `pa`, if it is in this VRAM.
    fn read(&self, pa: u64) -> Option<u64> {
        let mc = pa.checked_sub(FB_OFFSET)? + FB_BASE;
        let at = usize::try_from(mc.checked_sub(MC)?).ok()?;
        if at + 8 > PAGES * 4096 {
            return None;
        }
        let s = self.start + at;
        Some(u64::from_le_bytes(self.bytes[s..s + 8].try_into().unwrap()))
    }
    /// A VRAM loss: every byte of the heap is gone.
    fn lose(&mut self) {
        let (s, len) = (self.start, PAGES * 4096);
        self.bytes[s..s + len].fill(0);
    }
}

/// A hub walking a GMC10 context from `base` through VRAM only: every
/// directory entry must be VALID and in VRAM; returns each entry read.
fn hub_walk(vram: &Vram, base: u64, va: u64) -> Result<Vec<u64>, &'static str> {
    let mut entry = base;
    let mut read = Vec::new();
    for level in [Level::Pdb2, Level::Pdb1, Level::Pdb0, Level::Ptb] {
        if entry & PTE_VALID == 0 {
            return Err("invalid directory entry");
        }
        if entry & PTE_SYSTEM != 0 {
            return Err("directory entry points at system memory");
        }
        let index = Geometry::GMC11.index_at(va, level);
        entry = vram
            .read((entry & ADDRESS) + index * 8)
            .ok_or("directory entry points outside VRAM")?;
        read.push(entry);
    }
    Ok(read)
}

fn amd(nr: u32) -> u32 {
    0xc000_0000 | (0x64 << 8) | (0x40 + nr)
}
/// A GTT buffer of `pages` pages mapped R/W/X at `va` in `vm`.
fn map_gtt(gem: &crate::amdgpu_gem::GemState, vm: &VmState, va: u64, pages: u64) {
    let size = pages * 4096;
    let mut create = [0u8; 32];
    create[0..8].copy_from_slice(&size.to_le_bytes());
    create[16..24].copy_from_slice(&u64::from(uapi::AMDGPU_GEM_DOMAIN_GTT).to_le_bytes());
    crate::amdgpu_gem::dispatch(
        amd(uapi::DRM_AMDGPU_GEM_CREATE),
        create.as_mut_ptr() as usize,
        gem,
    )
    .unwrap();
    let mut map = [0u8; 40];
    map[0..4].copy_from_slice(&create[0..4]);
    map[8..12].copy_from_slice(&uapi::AMDGPU_VA_OP_MAP.to_le_bytes());
    map[12..16].copy_from_slice(&0x0eu32.to_le_bytes());
    map[16..24].copy_from_slice(&va.to_le_bytes());
    map[32..40].copy_from_slice(&size.to_le_bytes());
    dispatch(
        amd(uapi::DRM_AMDGPU_GEM_VA),
        map.as_mut_ptr() as usize,
        vm,
        gem,
        None,
    )
    .unwrap();
}
fn unmap(gem: &crate::amdgpu_gem::GemState, vm: &VmState, va: u64, pages: u64) {
    let mut map = [0u8; 40];
    map[8..12].copy_from_slice(&uapi::AMDGPU_VA_OP_CLEAR.to_le_bytes());
    map[16..24].copy_from_slice(&va.to_le_bytes());
    map[32..40].copy_from_slice(&(pages * 4096).to_le_bytes());
    dispatch(
        amd(uapi::DRM_AMDGPU_GEM_VA),
        map.as_mut_ptr() as usize,
        vm,
        gem,
        None,
    )
    .unwrap();
}

/// The entries a hub reads for `va` match the CPU's own copy of the
/// tables, end in this space's leaf PTE, and that PTE maps system memory
/// (a GTT page keeps SYSTEM/SNOOPED).
fn walks_to_the_leaf(vram: &Vram, vm: &VmState, va: u64) -> bool {
    let va = strip_hole(va);
    let Some(root) = vm.root_pde() else {
        return false;
    };
    match hub_walk(vram, root, va) {
        Ok(read) => {
            let space = vm.describe_va(va);
            read == space.walk
                && vm.leaf_entry(va) == read.last().copied()
                && read[3] & (PTE_VALID | PTE_SYSTEM | PTE_SNOOPED)
                    == PTE_VALID | PTE_SYSTEM | PTE_SNOOPED
        }
        Err(_) => false,
    }
}

/// A root that is a VRAM directory entry: VALID, no SYSTEM/SNOOPED, an
/// MC→PA address inside the heap.
fn vram_root(root: Option<u64>) -> bool {
    root.is_some_and(|root| {
        root & (PTE_VALID | PTE_SYSTEM | PTE_SNOOPED) == PTE_VALID
            && (root & ADDRESS)
                .checked_sub(FB_OFFSET)
                .is_some_and(|pa| (MC..MC + (PAGES * 4096) as u64).contains(&(pa + FB_BASE)))
    })
}

struct Registered(u32);
impl Drop for Registered {
    fn drop(&mut self) {
        unregister_table_heap(self.0);
    }
}

/// With the card's table heap registered (the RX 6750 XT's client VRAM),
/// a client space's root and every directory are VRAM tables: the base
/// both hubs are given and every PDE carry the MC→PA address with VALID
/// and no SYSTEM bit, a hub walk through VRAM alone reaches the GTT page's
/// PTE, and each update ends with an HDP flush. The decode ring's MMHUB
/// flush and the gfx ring's GFXHUB flush both program that base.
fn vm_tables_live_in_vram_like_amdgpu_vm_pt_create() -> TestResult {
    const CARD: u32 = 0xfa17_0101;
    const HIGH: u64 = 0xffff_8001_0000_0000;
    const LOW: u64 = 0x0000_0001_0020_0000;
    let vram = Vram::new();
    let _registered = Registered(CARD);
    register_table_heap(CARD, vram.heap());
    let gem = crate::amdgpu_gem::GemState::new();
    let vm = VmState::for_card(CARD);
    map_gtt(&gem, &vm, HIGH, 2);
    map_gtt(&gem, &vm, LOW, 1);
    let root = vm.root_pde();
    if !vram_root(root) {
        return TestResult::Fail("the root is not a VRAM directory entry");
    }
    for level in [Level::Pdb2, Level::Pdb1, Level::Pdb0] {
        for va in [HIGH, LOW] {
            let entry = vm.directory_entry(strip_hole(va), level).unwrap_or(0);
            if entry & (PTE_VALID | PTE_SYSTEM | PTE_SNOOPED) != PTE_VALID {
                return TestResult::Fail("a directory entry is not a VRAM PDE");
            }
        }
    }
    if [HIGH, HIGH + 4096, LOW]
        .iter()
        .any(|&va| !walks_to_the_leaf(&vram, &vm, va))
    {
        return TestResult::Fail("a hub walk through VRAM does not reach the PTE");
    }
    let mapped = vram.flushes();
    if mapped == 0 {
        return TestResult::Fail("table updates were not followed by an HDP flush");
    }
    unmap(&gem, &vm, LOW, 1);
    let root = root.unwrap();
    if vram.flushes() == mapped
        || hub_walk(&vram, root, strip_hole(LOW))
            .is_ok_and(|read| read.last().is_some_and(|pte| pte & PTE_VALID != 0))
        || !walks_to_the_leaf(&vram, &vm, HIGH)
    {
        return TestResult::Fail("an unmap did not reach the VRAM tables");
    }
    // Both hubs are pointed at the same base: the MMHUB flush of the decode
    // ring and the GFXHUB flush of the gfx ring.
    use crate::amdgpu_navi22_submit::{
        encode_cp, encode_media, Frame, Ib, MediaFrame, MediaHub, MediaRing,
    };
    let pasid = vm.pasid().unwrap();
    let request = crate::amdgpu_navi22_cs::grab_request(&vm, root, pasid, 4);
    let vm_ref = crate::amdgpu_navi22_cs::vm_ref(
        &request,
        crate::amdgpu_vmid::Grant {
            vmid: 3,
            needs_flush: true,
            map_pasid: false,
        },
    );
    let ibs = [Ib {
        va: strip_hole(HIGH),
        dwords: 16,
        flags: 0,
    }];
    let media = encode_media(&MediaFrame {
        ring: MediaRing::Dec,
        hub: MediaHub::mmhub_v2_0(0x1a000),
        hdp: Some(0xf20),
        engine: 0,
        flush: Some(vm_ref),
        pasid_map: None,
        vmid: 3,
        ibs: &ibs,
        fence: 0x1000,
        seq: 1,
        ring_base: 0,
    });
    // vcn_v2_0_dec_ring_emit_wreg of MMVM_CONTEXT3_PAGE_TABLE_BASE_ADDR_LO32/HI32.
    let mm = |reg: u32, value: u32| [0x10, (0x1a000 + reg + 6) << 2, 0x11, value];
    let layout = crate::amdgpu_cp_navi22::tests::layout();
    let gfx = encode_cp(
        layout,
        &Frame {
            gfx: true,
            engine: 0,
            sync: None,
            flush: Some(vm_ref),
            pasid_map: None,
            vm_fence: None,
            vmid: 3,
            context_switch: false,
            gds_max_wave_id: None,
            ibs: &ibs,
            fence: 0x1000,
            seq: 1,
            wptr: 0,
        },
    );
    // WRITE_DATA to GCVM_CONTEXT3_PAGE_TABLE_BASE_ADDR_LO32/HI32 (0x1667 + 6).
    let gc = |reg: u32, value: u32| [layout.segment(0) + reg + 6, 0, value];
    if vm_ref.page_table_base != root
        || !media.windows(4).any(|w| w == mm(0x72b, root as u32))
        || !media
            .windows(4)
            .any(|w| w == mm(0x72c, (root >> 32) as u32))
        || !gfx.windows(3).any(|w| w == gc(0x1667, root as u32))
        || !gfx.windows(3).any(|w| w == gc(0x1668, (root >> 32) as u32))
    {
        return TestResult::Fail("a hub's VM flush does not program the VRAM root");
    }
    drop(vm);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu-vm/vram-tables",
    vm_tables_live_in_vram_like_amdgpu_vm_pt_create
);

/// A card without a table heap keeps system-memory tables (VALID|SYSTEM|
/// SNOOPED PDEs). Once the card's heap arrives, a space that already has
/// tables moves them into VRAM (as Linux's are there from the start), and
/// after a VRAM loss (S3, a recovery) re-registering the heap rewrites
/// every table from the CPU's copy before the next job, as Linux rebuilds a
/// VM's tables when `amdgpu_vm_generation` changes.
fn vm_tables_move_to_vram_and_survive_vram_loss() -> TestResult {
    const CARD: u32 = 0xfa17_0102;
    const VA: u64 = 0xffff_8001_0007_0000;
    let mut vram = Vram::new();
    let _registered = Registered(CARD);
    let gem = crate::amdgpu_gem::GemState::new();
    let vm = VmState::for_card(CARD);
    map_gtt(&gem, &vm, VA, 1);
    let system = vm.root_pde().unwrap_or(0);
    if system & (PTE_VALID | PTE_SYSTEM | PTE_SNOOPED) != PTE_VALID | PTE_SYSTEM | PTE_SNOOPED
        || vm.directory_entry(strip_hole(VA), Level::Pdb1).unwrap_or(0) & PTE_SYSTEM == 0
    {
        return TestResult::Fail("a card without a table heap left system tables");
    }
    let seq = vm.tlb_seq();
    register_table_heap(CARD, vram.heap());
    let root = vm.root_pde();
    if !vram_root(root) || !walks_to_the_leaf(&vram, &vm, VA) || vm.tlb_seq() == seq {
        return TestResult::Fail("existing tables did not move into the card's VRAM");
    }
    // S3 or a recovery loses VRAM; the heap is withdrawn and registered again.
    unregister_table_heap(CARD);
    vram.lose();
    let seq = vm.tlb_seq();
    register_table_heap(CARD, vram.heap());
    if vm.root_pde() != root || !walks_to_the_leaf(&vram, &vm, VA) || vm.tlb_seq() == seq {
        return TestResult::Fail("tables were not rewritten after a VRAM loss");
    }
    map_gtt(&gem, &vm, VA + (1 << 30), 1);
    if !walks_to_the_leaf(&vram, &vm, VA + (1 << 30)) || !walks_to_the_leaf(&vram, &vm, VA) {
        return TestResult::Fail("a mapping after the restore");
    }
    drop(vm);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu-vm/vram-tables",
    vm_tables_move_to_vram_and_survive_vram_loss
);

/// A GFX12 hub walking a 4-level context (GC 12.0.x, 48-bit) through VRAM
/// only. Besides VALID and SYSTEM, a directory entry must not carry
/// `AMDGPU_PDE_PTE_GFX12` (bit 63), which would make the hub take it for a
/// leaf. Returns each entry read.
fn hub_walk_gfx12(vram: &Vram, base: u64, va: u64) -> Result<Vec<u64>, &'static str> {
    let mut entry = base;
    let mut read = Vec::new();
    for level in [Level::Pdb2, Level::Pdb1, Level::Pdb0, Level::Ptb] {
        if entry & PTE_VALID == 0 {
            return Err("invalid directory entry");
        }
        if entry & (PTE_SYSTEM | PDE_PTE_GFX12) != 0 {
            return Err("directory entry points at system memory or is a leaf");
        }
        let index = Geometry::GMC12.index_at(va, level);
        entry = vram
            .read((entry & ADDRESS) + index * 8)
            .ok_or("directory entry points outside VRAM")?;
        read.push(entry);
    }
    Ok(read)
}

struct Navi48Heap(u32);
impl Drop for Navi48Heap {
    fn drop(&mut self) {
        crate::amdgpu_navi48_boot::withdraw_heap(self.0);
    }
}

/// Navi48 (GC 12.0.x, gmc_v12_0) is a dGPU too: `amdgpu_vm_pt_create` puts
/// its client tables in VRAM, and `gmc_v12_0_get_vm_pde` gives a VRAM
/// directory `vram_base_offset + mc - vram_start` with VALID; GMC12 never
/// sets `translate_further`, so no BFS/TF bits, and a directory that points
/// at a table carries no `AMDGPU_PDE_PTE_GFX12`. Publishing the card's
/// client heap (`amdgpu_navi48_boot::publish_heap`, with the GMC's HDP flush)
/// gives its spaces those tables; withdrawing and publishing it again after
/// a VRAM loss (S3) rewrites them.
fn vm_tables_live_in_vram_on_navi48_like_gmc_v12_0() -> TestResult {
    const CARD: u32 = 0xfa17_0103;
    const VA: u64 = 0xffff_8001_0000_0000;
    let mut vram = Vram::new();
    let _registered = Registered(CARD);
    let _published = Navi48Heap(CARD);
    let heap = crate::amdgpu_gem::VramHeap {
        pool: vram.pool.clone(),
        fb_base: FB_BASE,
        fb_offset: FB_OFFSET,
        unmapped: None,
    };
    let flushes = vram.flushes.clone();
    let hdp = || Some(flushes.clone() as Arc<dyn HdpFlush>);
    crate::amdgpu_navi48_boot::publish_heap(CARD, &heap, hdp());
    let gem = crate::amdgpu_gem::GemState::new();
    let vm = VmState::build(Geometry::GMC12, Some(CARD));
    map_gtt(&gem, &vm, VA, 2);
    let root = vm.root_pde();
    if !vram_root(root) || root.is_some_and(|root| root & PDE_PTE_GFX12 != 0) {
        return TestResult::Fail("the GFX12 root is not a VRAM directory entry");
    }
    for level in [Level::Pdb2, Level::Pdb1, Level::Pdb0] {
        let entry = vm.directory_entry(strip_hole(VA), level).unwrap_or(0);
        if entry & (PTE_VALID | PTE_SYSTEM | PTE_SNOOPED | PDE_PTE_GFX12) != PTE_VALID {
            return TestResult::Fail("a GFX12 directory entry is not a VRAM PDE");
        }
    }
    let walks = |vram: &Vram| {
        [VA, VA + 4096].iter().all(|&va| {
            let va = strip_hole(va);
            hub_walk_gfx12(vram, vm.root_pde().unwrap_or(0), va).is_ok_and(|read| {
                read == vm.describe_va(va).walk
                    && read[3] & (PTE_VALID | PTE_SYSTEM | PTE_SNOOPED)
                        == PTE_VALID | PTE_SYSTEM | PTE_SNOOPED
            })
        })
    };
    if !walks(&vram) || vram.flushes() == 0 {
        return TestResult::Fail("a GFX12 walk through VRAM, or the HDP flush");
    }
    // S3: the heap is withdrawn, VRAM is lost, the heap is published again.
    crate::amdgpu_navi48_boot::withdraw_heap(CARD);
    vram.lose();
    crate::amdgpu_navi48_boot::publish_heap(CARD, &heap, hdp());
    if vm.root_pde() != root || !walks(&vram) {
        return TestResult::Fail("GFX12 tables were not rewritten after a VRAM loss");
    }
    drop(vm);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu-vm/vram-tables-gfx12",
    vm_tables_live_in_vram_on_navi48_like_gmc_v12_0
);
