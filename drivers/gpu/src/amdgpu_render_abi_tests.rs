//! The generic amdgpu render ABI additions Mesa 26.2.4 needs on GFX10.3
//! (docs/MESA_AMD.md): the user fence chunk end to end through
//! `amdgpu_cs::dispatch_async` with a card submitter, GEM_METADATA, the
//! GEM_MMAP union layout, PRIME import identity, GET_CLIENT and the
//! no-KMS VERSION answer.
use super::*;
use crate::amdgpu_cs::Submitter;
use core::future::Future;
use core::pin::Pin;
use narf_kernel_test::{kernel_test_in, TestResult};

const fn cmd(nr: u32) -> u32 {
    0xc000_0000 | (0x64 << 8) | nr
}
const fn amd(nr: u32) -> u32 {
    cmd(0x40 + nr)
}
fn create(state: &GemState, size: u64, domains: u64) -> u32 {
    let mut b = [0u8; 32];
    b[0..8].copy_from_slice(&size.to_le_bytes());
    b[16..24].copy_from_slice(&domains.to_le_bytes());
    dispatch(
        amd(uapi::DRM_AMDGPU_GEM_CREATE),
        b.as_mut_ptr() as usize,
        state,
    )
    .unwrap();
    u32::from_le_bytes(b[0..4].try_into().unwrap())
}

/// A card engine that completes everything at once.
#[derive(Debug)]
struct Instant;
impl Submitter for Instant {
    fn submit<'a>(
        &'a self,
        _vm: &'a crate::amdgpu_vm::VmState,
        _submission: &'a crate::amdgpu_cs::Submission,
        _health: &'a alloc::sync::Arc<crate::amdgpu_ctx::Health>,
    ) -> Pin<alloc::boxed::Box<dyn Future<Output = Result<u64, FsError>> + Send + 'a>> {
        alloc::boxed::Box::pin(async { Ok(1 << 32 | 7) })
    }
    fn signalled(&self, _ticket: u64) -> bool {
        true
    }
    fn ring_for(&self, ip_type: u32, _: u32, _: u32) -> Option<u32> {
        (ip_type == uapi::AMDGPU_HW_IP_GFX).then_some(0)
    }
    fn wait(
        &self,
        _seq: u64,
        _deadline_ns: u64,
    ) -> Pin<alloc::boxed::Box<dyn Future<Output = Result<bool, FsError>> + Send + '_>> {
        alloc::boxed::Box::pin(async { Ok(true) })
    }
}

fn render_abi_user_fence_reaches_the_bo_after_completion() -> TestResult {
    const CARD: u32 = 0xfee1;
    let gem = GemState::new();
    let vm = crate::amdgpu_vm::VmState::new();
    let ctxs = crate::amdgpu_ctx::CtxState::new();
    let syncobjs = IrqSafeSpinLock::new(crate::drm::syncobj::SyncObjTable::new());
    let ib_bo = create(&gem, 4096, uapi::AMDGPU_GEM_DOMAIN_GTT as u64);
    let fence_bo = create(&gem, 4096, uapi::AMDGPU_GEM_DOMAIN_GTT as u64);
    // GEM_VA MAP the IB buffer at a high VA, as radeonsi does.
    let mut va = [0u8; 40];
    va[0..4].copy_from_slice(&ib_bo.to_le_bytes());
    va[8..12].copy_from_slice(&uapi::AMDGPU_VA_OP_MAP.to_le_bytes());
    va[12..16].copy_from_slice(&0x0eu32.to_le_bytes());
    va[16..24].copy_from_slice(&0xffff_8001_0000_0000u64.to_le_bytes());
    va[32..40].copy_from_slice(&4096u64.to_le_bytes());
    if crate::amdgpu_vm::dispatch(
        amd(uapi::DRM_AMDGPU_GEM_VA),
        va.as_mut_ptr() as usize,
        &vm,
        &gem,
    )
    .is_err()
    {
        return TestResult::Fail("GEM_VA at the high VA");
    }
    let mut c = [0u8; 16];
    c[0..4].copy_from_slice(&uapi::AMDGPU_CTX_OP_ALLOC_CTX.to_le_bytes());
    crate::amdgpu_ctx::dispatch(
        amd(uapi::DRM_AMDGPU_CTX),
        c.as_mut_ptr() as usize,
        &ctxs,
        false,
    )
    .unwrap();
    let ctx_id = u32::from_le_bytes(c[0..4].try_into().unwrap());
    // FENCE { handle, offset 16 } then IB { va, 64 bytes, GFX }.
    let fence = [fence_bo, 16u32];
    let mut ib = [0u8; 32];
    ib[8..16].copy_from_slice(&0xffff_8001_0000_0100u64.to_le_bytes());
    ib[16..20].copy_from_slice(&64u32.to_le_bytes());
    let mut chunks = [[0u8; 16]; 2];
    for (k, (id, data, len)) in [
        (uapi::AMDGPU_CHUNK_ID_FENCE, fence.as_ptr() as u64, 2u32),
        (uapi::AMDGPU_CHUNK_ID_IB, ib.as_ptr() as u64, 8),
    ]
    .into_iter()
    .enumerate()
    {
        chunks[k][0..4].copy_from_slice(&id.to_le_bytes());
        chunks[k][4..8].copy_from_slice(&len.to_le_bytes());
        chunks[k][8..16].copy_from_slice(&data.to_le_bytes());
    }
    let ptrs = [chunks[0].as_ptr() as u64, chunks[1].as_ptr() as u64];
    let mut cs = [0u8; 24];
    cs[0..4].copy_from_slice(&ctx_id.to_le_bytes());
    cs[8..12].copy_from_slice(&2u32.to_le_bytes());
    cs[16..24].copy_from_slice(&(ptrs.as_ptr() as u64).to_le_bytes());
    crate::amdgpu_cs::register_submitter(CARD, alloc::sync::Arc::new(Instant));
    let result = narf_scheduler::block_on_spin(crate::amdgpu_cs::dispatch_async(
        CARD,
        amd(uapi::DRM_AMDGPU_CS),
        cs.as_mut_ptr() as usize,
        &crate::amdgpu_cs::CsOpen {
            vm: &vm,
            gem: &gem,
            ctx: &ctxs,
            syncobjs: &syncobjs,
            bo_lists: &crate::amdgpu_bo_list::BoListTable::new(),
            files: None,
        },
    ));
    let ticket = u64::from_le_bytes(cs[0..8].try_into().unwrap());
    crate::amdgpu_cs::retire(CARD, &|_| true);
    crate::amdgpu_cs::unregister_submitter(CARD);
    let object = gem.object(fence_bo).unwrap();
    // SAFETY: a live system-memory object of at least 24 bytes.
    let written = unsafe {
        core::ptr::read_volatile(
            narf_memory::PhysAddr::new(object.phys() + 16).kernel_mut_ptr::<u64>(),
        )
    };
    if result != Ok(0) || ticket != 1 << 32 | 7 || written != ticket {
        return TestResult::Fail("user fence not written with the CS handle on completion");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/render-abi",
    render_abi_user_fence_reaches_the_bo_after_completion
);

fn render_abi_metadata_mmap_layout_and_prime_identity() -> TestResult {
    let (a, b) = (
        GemState::for_card(0x7ffe_0303),
        GemState::for_card(0x7ffe_0303),
    );
    // A buffer bound to no card is no device's, so it is never imported.
    let unbound = GemState::new();
    let orphan = create(&unbound, 4096, uapi::AMDGPU_GEM_DOMAIN_GTT as u64);
    if GemState::new().import(&unbound.object(orphan).unwrap()) != Err(FsError::InvalidData)
        || a.import(&unbound.object(orphan).unwrap()) != Err(FsError::InvalidData)
    {
        return TestResult::Fail("a buffer of no card must not import");
    }
    let h = create(&a, 8192, uapi::AMDGPU_GEM_DOMAIN_GTT as u64);
    // GEM_MMAP: out.addr_ptr at offset 0 of the 8-byte union.
    let mut m = [0u8; 8];
    m[0..4].copy_from_slice(&h.to_le_bytes());
    dispatch(amd(uapi::DRM_AMDGPU_GEM_MMAP), m.as_mut_ptr() as usize, &a).unwrap();
    if u64::from_le_bytes(m) != u64::from(h) << 12 {
        return TestResult::Fail("GEM_MMAP offset layout");
    }
    // SET then GET metadata (tiling + 8 bytes of UMD data).
    let mut md = [0u8; 288];
    md[0..4].copy_from_slice(&h.to_le_bytes());
    md[4..8].copy_from_slice(&uapi::AMDGPU_GEM_METADATA_OP_SET_METADATA.to_le_bytes());
    md[16..24].copy_from_slice(&0x1234_5678u64.to_le_bytes());
    md[24..28].copy_from_slice(&8u32.to_le_bytes());
    md[28..36].copy_from_slice(b"umd-data");
    let set = dispatch(
        amd(uapi::DRM_AMDGPU_GEM_METADATA),
        md.as_mut_ptr() as usize,
        &a,
    );
    // An importer sees the same object and its metadata.
    let imported = b.import(&a.object(h).unwrap());
    let ih = match imported {
        Ok(ih) => ih,
        Err(_) => return TestResult::Fail("PRIME import"),
    };
    let mut get = [0u8; 288];
    get[0..4].copy_from_slice(&ih.to_le_bytes());
    get[4..8].copy_from_slice(&uapi::AMDGPU_GEM_METADATA_OP_GET_METADATA.to_le_bytes());
    let got = dispatch(
        amd(uapi::DRM_AMDGPU_GEM_METADATA),
        get.as_mut_ptr() as usize,
        &b,
    );
    let mut big = [0u8; 288];
    big[0..4].copy_from_slice(&h.to_le_bytes());
    big[4..8].copy_from_slice(&uapi::AMDGPU_GEM_METADATA_OP_SET_METADATA.to_le_bytes());
    big[24..28].copy_from_slice(&257u32.to_le_bytes());
    if set.is_err()
        || got.is_err()
        || u64::from_le_bytes(get[16..24].try_into().unwrap()) != 0x1234_5678
        || &get[28..36] != b"umd-data"
        || b.import(&a.object(h).unwrap()) != Ok(ih)
        || !alloc::sync::Arc::ptr_eq(&b.object(ih).unwrap(), &a.object(h).unwrap())
        || dispatch(
            amd(uapi::DRM_AMDGPU_GEM_METADATA),
            big.as_mut_ptr() as usize,
            &a,
        ) != Err(FsError::InvalidData)
    {
        return TestResult::Fail("metadata or PRIME identity");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/render-abi",
    render_abi_metadata_mmap_layout_and_prime_identity
);

/// Kernel-pointer ioctl context.
struct K;
impl narf_filesystem::IoctlContext for K {
    fn read(&self, address: u64, destination: &mut [u8]) -> Result<(), FsError> {
        // SAFETY: tests pass live kernel buffers of this length.
        unsafe {
            core::ptr::copy_nonoverlapping(
                address as *const u8,
                destination.as_mut_ptr(),
                destination.len(),
            )
        };
        Ok(())
    }
    fn write(&self, address: u64, source: &[u8]) -> Result<(), FsError> {
        // SAFETY: as above.
        unsafe {
            core::ptr::copy_nonoverlapping(source.as_ptr(), address as *mut u8, source.len())
        };
        Ok(())
    }
    fn nonblocking(&self) -> bool {
        false
    }
    fn process_id(&self) -> u32 {
        77
    }
}

fn render_abi_get_client_matches_drm_getclient() -> TestResult {
    let mut b = [0u8; 40];
    let ok = crate::drm_ioctl_bridge::get_client(b.as_mut_ptr() as u64, &K, true);
    let mut other = [0u8; 40];
    other[0..4].copy_from_slice(&1i32.to_le_bytes());
    if ok != Ok(0)
        || i32::from_le_bytes(b[4..8].try_into().unwrap()) != 1
        || u64::from_le_bytes(b[8..16].try_into().unwrap()) != 77
        || u64::from_le_bytes(b[16..24].try_into().unwrap()) != 65534
        || crate::drm_ioctl_bridge::get_client(other.as_mut_ptr() as u64, &K, false)
            != Err(FsError::InvalidData)
        || crate::drm_ioctl_bridge::DRM_IOCTL_GET_CLIENT != 0xc028_6405
    {
        return TestResult::Fail("GET_CLIENT");
    }
    // The Navi22 DRM version follows the switch as this boot applies it.
    let v = crate::amdgpu_info_navi22::drm_version();
    let wired =
        crate::amdgpu_info_navi22::submission() == crate::amdgpu_info_navi22::Submission::Wired;
    if v != if wired { (3, 64, 0) } else { (3, 0, 0) } {
        return TestResult::Fail("Navi22 DRM version");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/render-abi",
    render_abi_get_client_matches_drm_getclient
);

fn rdna2_visible_vram_eviction_roundtrip_and_pins() -> TestResult {
    const CARD: u32 = 0xfee2;
    struct Busy(core::sync::atomic::AtomicBool);
    impl narf_filesystem::DrmFence for Busy {
        fn is_signalled(&self) -> bool {
            self.0.load(Ordering::Acquire)
        }
        fn wait(&self, _: u64) -> bool {
            self.is_signalled()
        }
    }
    impl Submitter for Busy {
        fn submit<'a>(
            &'a self,
            _: &'a crate::amdgpu_vm::VmState,
            _: &'a crate::amdgpu_cs::Submission,
            _: &'a Arc<crate::amdgpu_ctx::Health>,
        ) -> Pin<alloc::boxed::Box<dyn Future<Output = Result<u64, FsError>> + Send + 'a>> {
            alloc::boxed::Box::pin(async { Err(FsError::Unsupported) })
        }
        fn signalled(&self, _: u64) -> bool {
            self.0.load(Ordering::Acquire)
        }
        fn ring_for(&self, _: u32, _: u32, _: u32) -> Option<u32> {
            None
        }
        fn wait(
            &self,
            _: u64,
            _: u64,
        ) -> Pin<alloc::boxed::Box<dyn Future<Output = Result<bool, FsError>> + Send + '_>>
        {
            alloc::boxed::Box::pin(core::future::poll_fn(|_| {
                if self.0.load(Ordering::Acquire) {
                    core::task::Poll::Ready(Ok(true))
                } else {
                    core::task::Poll::Pending
                }
            }))
        }
    }
    struct Registered;
    impl Drop for Registered {
        fn drop(&mut self) {
            // This test engine executes no hardware jobs.
            crate::amdgpu_cs::retire(CARD, &|_| true);
            crate::amdgpu_cs::unregister_submitter(CARD);
            unregister_vram_heap(CARD);
        }
    }
    let mut memory = alloc::vec![0u8; 5 * 4096];
    let map = narf_bus::MmioRegion {
        phys: narf_memory::PhysAddr::new(0xb000_0000),
        virt: memory.as_mut_ptr() as u64,
        len: memory.len() as u64,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // SAFETY: this test exclusively owns memory until the registered heap and
    // every object have been dropped; no hardware accesses these mappings.
    let pool = unsafe { crate::amdgpu_vram::Pool::from_owned_range(map, 0x8_0000_0000) }.unwrap();
    register_vram_heap(
        CARD,
        VramHeap {
            pool: pool.clone(),
            fb_base: 0x8_0000_0000,
            fb_offset: 0x9_0000_0000,
            unmapped: None,
        },
    );
    let _registered = Registered;
    let before = gtt_used();
    let state = GemState::for_card(CARD);
    let a = create(&state, 4096, u64::from(uapi::AMDGPU_GEM_DOMAIN_VRAM));
    // Preserve the requested (non-power-of-two) alignment in GET_INFO,
    // but normalize it identically during creation and later promotion.
    let mut aligned = [
        3 * 4096u64,
        5000,
        u64::from(uapi::AMDGPU_GEM_DOMAIN_VRAM),
        0,
    ];
    super::create(&state, aligned.as_mut_ptr() as usize).unwrap();
    let b = aligned[0] as u32;
    // Neither a same-card PRIME import nor an exported dma-buf identity is
    // an address lease. All handles must observe the same relocated BO.
    let peer = GemState::for_card(CARD);
    let shared = state.object(b).unwrap();
    let imported = peer.import(&shared).unwrap();
    let exported = shared.dma_buf().clone();
    let export_file = crate::drm_devfs_bridge::amdgpu_dma_buf_file(shared.clone()).unwrap();
    let pin_a = state.mapping_object(u64::from(a) << 12, 4096).unwrap();
    let fence = Arc::new(Busy(core::sync::atomic::AtomicBool::new(false)));
    {
        let b = state.object(b).unwrap();
        b.store_u64(16, 0x1234_5678);
        b.store_u64(8192 + 16, 0x8765_4321);
        b.dma_buf()
            .resv
            .add_fence(fence.clone(), narf_filesystem::dma_buf::DmaResvUsage::Write);
    }
    let mut blocked = [0u64; 4];
    blocked[0] = 3 * 4096;
    blocked[2] = u64::from(uapi::AMDGPU_GEM_DOMAIN_VRAM);
    blocked[3] = u64::from(uapi::AMDGPU_GEM_CREATE_DISCARDABLE);
    if super::create(&state, blocked.as_mut_ptr() as usize) != Err(FsError::NoSpace) {
        return TestResult::Fail("eviction moved backing before its reservation fence");
    }
    fence.0.store(true, Ordering::Release);
    let c = create(&state, 3 * 4096, u64::from(uapi::AMDGPU_GEM_DOMAIN_VRAM));
    {
        let evicted = state.object(b).unwrap();
        if !evicted.system()
            || !peer.get(imported).unwrap().system()
            || !Arc::ptr_eq(&evicted, &shared)
            || !Arc::ptr_eq(evicted.dma_buf(), &exported)
            || evicted.load_u64(16) != Some(0x1234_5678)
            || evicted.load_u64(8192 + 16) != Some(0x8765_4321)
            || pin_a.system
            || gtt_used() < before + 3 * 4096
        {
            return TestResult::Fail("VRAM pressure failed to preserve data or pinned mapping");
        }
        let frames = state.mmap_frames(u64::from(b) << 12, 3 * 4096).unwrap();
        if frames != evicted.frames(0, 3 * 4096).unwrap() {
            return TestResult::Fail("evicted scattered GTT mapping used a contiguous assumption");
        }
    }
    state.remove(c);
    let pin_b = state.object(b).unwrap().placement();
    if pin_b.system
        || pin_b.gpu != 0x9_0000_2000
        || pin_b.load_u64(16) != Some(0x1234_5678)
        || pin_b.load_u64(8192 + 16) != Some(0x8765_4321)
    {
        return TestResult::Fail("GTT to VRAM promotion lost data or framebuffer translation");
    }
    let mut request = [0u64; 4];
    request[0] = 2 * 4096;
    request[2] = u64::from(uapi::AMDGPU_GEM_DOMAIN_VRAM);
    request[3] = u64::from(uapi::AMDGPU_GEM_CREATE_DISCARDABLE);
    if super::create(&state, request.as_mut_ptr() as usize) != Err(FsError::NoSpace) {
        return TestResult::Fail("eviction moved CPU/GPU referenced backing");
    }
    let mut placement = [0u8; 16];
    placement[..4].copy_from_slice(&b.to_le_bytes());
    placement[4..8].copy_from_slice(&uapi::AMDGPU_GEM_OP_SET_PLACEMENT.to_le_bytes());
    placement[8..16].copy_from_slice(&u64::from(uapi::AMDGPU_GEM_DOMAIN_GTT).to_le_bytes());
    if op(&state, placement.as_ptr() as usize) != Ok(0) || pin_b.system {
        return TestResult::Fail("placement preference moved pinned BO or refused valid request");
    }
    let cpu_map = export_file.mmap_backing(0, 3 * 4096).unwrap();
    drop(pin_b);
    if state.object(b).unwrap().system() || cpu_map.frames != shared.frames(0, 3 * 4096).unwrap() {
        return TestResult::Fail("PRIME CPU mapping failed to pin physical frames");
    }
    drop(cpu_map);
    // A page-table mapping, including split surviving ranges, must hold an
    // address lease even though ordinary references no longer do.
    let vm = crate::amdgpu_vm::VmState::new();
    let mut va = [0u8; 40];
    va[..4].copy_from_slice(&b.to_le_bytes());
    va[8..12].copy_from_slice(&uapi::AMDGPU_VA_OP_MAP.to_le_bytes());
    va[12..16].copy_from_slice(&uapi::AMDGPU_VM_PAGE_READABLE.to_le_bytes());
    va[16..24].copy_from_slice(&0x2_0000_0000u64.to_le_bytes());
    va[32..40].copy_from_slice(&(3 * 4096u64).to_le_bytes());
    // Mapping validation applies the pending preference; use a new explicit
    // VRAM preference first, then request GTT after the PTEs exist.
    placement[8..16].copy_from_slice(&u64::from(uapi::AMDGPU_GEM_DOMAIN_VRAM).to_le_bytes());
    op(&state, placement.as_ptr() as usize).unwrap();
    let nr = crate::drm_uapi::DRM_COMMAND_BASE + uapi::DRM_AMDGPU_GEM_VA;
    if crate::amdgpu_vm::dispatch(nr, va.as_ptr() as usize, &vm, &state).is_err() {
        return TestResult::Fail("setup: shared BO GPU mapping");
    }
    placement[8..16].copy_from_slice(&u64::from(uapi::AMDGPU_GEM_DOMAIN_GTT).to_le_bytes());
    op(&state, placement.as_ptr() as usize).unwrap();
    if state.object(b).unwrap().system() {
        return TestResult::Fail("shared BO moved underneath live GPU PTEs");
    }
    va[8..12].copy_from_slice(&uapi::AMDGPU_VA_OP_CLEAR.to_le_bytes());
    va[16..24].copy_from_slice(&(0x2_0000_0000u64 + 4096).to_le_bytes());
    va[32..40].copy_from_slice(&4096u64.to_le_bytes());
    crate::amdgpu_vm::dispatch(nr, va.as_ptr() as usize, &vm, &state).unwrap();
    if state.object(b).unwrap().system() {
        return TestResult::Fail("split GPU mapping dropped its address lease");
    }
    drop(vm);
    let moved = state.object(b).unwrap();
    if !moved.system()
        || moved.preferred_domains() != u64::from(uapi::AMDGPU_GEM_DOMAIN_GTT)
        || moved.load_u64(8192 + 16) != Some(0x8765_4321)
    {
        return TestResult::Fail("GEM_SET_PLACEMENT not honored after unpinning");
    }
    // Registered VMs can be rebound under the card gate, preserving their
    // virtual addresses, table allocations, and buffer contents.
    let vm = crate::amdgpu_vm::VmState::for_card(CARD);
    va[8..12].copy_from_slice(&uapi::AMDGPU_VA_OP_MAP.to_le_bytes());
    va[16..24].copy_from_slice(&0x2_0000_0000u64.to_le_bytes());
    va[32..40].copy_from_slice(&(3 * 4096u64).to_le_bytes());
    crate::amdgpu_vm::dispatch(nr, va.as_ptr() as usize, &vm, &state).unwrap();
    let peer_vm = crate::amdgpu_vm::VmState::for_card(CARD);
    let mut peer_va = va;
    peer_va[..4].copy_from_slice(&imported.to_le_bytes());
    peer_va[16..24].copy_from_slice(&0x3_0000_0000u64.to_le_bytes());
    peer_va[24..32].copy_from_slice(&4096u64.to_le_bytes());
    peer_va[32..40].copy_from_slice(&(2 * 4096u64).to_le_bytes());
    crate::amdgpu_vm::dispatch(nr, peer_va.as_ptr() as usize, &peer_vm, &peer).unwrap();
    let peer_tlb = peer_vm.tlb_seq();
    let tables = vm.table_count();
    let tlb = vm.tlb_seq();
    placement[8..16].copy_from_slice(&u64::from(uapi::AMDGPU_GEM_DOMAIN_VRAM).to_le_bytes());
    op(&state, placement.as_ptr() as usize).unwrap();
    let promoted = narf_scheduler::block_on_spin(async {
        let gate = lock_placement(CARD).await;
        crate::amdgpu_vm::relocate(&gate, &shared, true).await
    });
    if promoted.is_err()
        || shared.system()
        || vm.table_count() != tables
        || vm.tlb_seq() <= tlb
        || vm.leaf_entry(0x2_0000_2000).is_none_or(|pte| {
            pte & crate::amdgpu_vm::PTE_SYSTEM != 0
                || Some(pte & crate::amdgpu_vm::GMC_HOLE_MASK & !4095) != shared.gpu_at(8192)
        })
        || shared.load_u64(8192 + 16) != Some(0x8765_4321)
        || peer_vm.tlb_seq() <= peer_tlb
        || peer_vm.leaf_entry(0x3_0000_1000).is_none_or(|pte| {
            pte & crate::amdgpu_vm::PTE_SYSTEM != 0
                || Some(pte & crate::amdgpu_vm::GMC_HOLE_MASK & !4095) != shared.gpu_at(8192)
        })
    {
        return TestResult::Fail("GPU mapped promotion failed to rebind stable VA");
    }
    va[8..12].copy_from_slice(&uapi::AMDGPU_VA_OP_CLEAR.to_le_bytes());
    va[16..24].copy_from_slice(&(0x2_0000_0000u64 + 4096).to_le_bytes());
    va[32..40].copy_from_slice(&4096u64.to_le_bytes());
    crate::amdgpu_vm::dispatch(nr, va.as_ptr() as usize, &vm, &state).unwrap();
    // Cancellation while waiting for a reservation fence must leave the
    // tables and their leases unchanged, and release submission admission.
    let busy = Arc::new(Busy(core::sync::atomic::AtomicBool::new(false)));
    shared
        .dma_buf()
        .resv
        .add_fence(busy.clone(), narf_filesystem::dma_buf::DmaResvUsage::Write);
    let previous = vm.leaf_entry(0x2_0000_0000);
    {
        use core::future::Future;
        let mut future = core::pin::pin!(async {
            let gate = lock_placement(CARD).await;
            crate::amdgpu_vm::relocate(&gate, &shared, false).await
        });
        let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
        if future.as_mut().poll(&mut cx).is_ready() {
            return TestResult::Fail("migration ignored busy reservation");
        }
    }
    if try_placement(CARD).is_none() || vm.leaf_entry(0x2_0000_0000) != previous || shared.system()
    {
        return TestResult::Fail("cancelled migration changed PTEs or leaked card gate");
    }
    busy.0.store(true, Ordering::Release);
    let jobs = Arc::new(Busy(core::sync::atomic::AtomicBool::new(false)));
    crate::amdgpu_cs::register_submitter(CARD, jobs.clone());
    vm.note_job(1);
    {
        let mut future = core::pin::pin!(async {
            let gate = lock_placement(CARD).await;
            crate::amdgpu_vm::relocate(&gate, &shared, false).await
        });
        let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
        if future.as_mut().poll(&mut cx).is_ready()
            || vm.leaf_entry(0x2_0000_0000) != previous
            || shared.system()
        {
            return TestResult::Fail("migration released mapping before active VM job");
        }
        if try_placement(CARD).is_some()
            || crate::amdgpu_vm::dispatch(nr, va.as_ptr() as usize, &vm, &state)
                != Err(FsError::Busy)
        {
            return TestResult::Fail("active relocation admitted concurrent VA edits");
        }
    }
    jobs.0.store(true, Ordering::Release);
    // The async ioctl retries a strict allocation after reclaiming mapped
    // VRAM. The VM's PTEs must point at GTT before new submissions can enter.
    let mut pressure = [
        2 * 4096u64,
        0,
        u64::from(uapi::AMDGPU_GEM_DOMAIN_VRAM),
        u64::from(uapi::AMDGPU_GEM_CREATE_DISCARDABLE),
    ];
    let created = narf_scheduler::block_on_spin(dispatch_async(
        crate::drm_uapi::DRM_COMMAND_BASE + uapi::DRM_AMDGPU_GEM_CREATE,
        pressure.as_mut_ptr() as usize,
        &state,
    ));
    if created != Some(Ok(0))
        || !shared.system()
        || vm.leaf_entry(0x2_0000_0000).is_none_or(|pte| {
            pte & crate::amdgpu_vm::PTE_SYSTEM == 0
                || Some(pte & crate::amdgpu_vm::GMC_HOLE_MASK & !4095) != shared.gpu_at(0)
        })
        || shared.load_u64(16) != Some(0x1234_5678)
        || vm
            .leaf_entry(0x2_0000_1000)
            .is_some_and(|pte| pte & crate::amdgpu_vm::PTE_VALID != 0)
        || peer_vm.leaf_entry(0x3_0000_1000).is_none_or(|pte| {
            pte & crate::amdgpu_vm::PTE_SYSTEM == 0
                || Some(pte & crate::amdgpu_vm::GMC_HOLE_MASK & !4095) != shared.gpu_at(8192)
        })
    {
        return TestResult::Fail("strict allocation failed to evict and rebind mapped BO");
    }
    state.remove(pressure[0] as u32);
    drop(vm);
    drop(peer_vm);
    crate::amdgpu_cs::retire(CARD, &|_| true);
    drop(moved);
    drop(pin_a);
    drop(exported);
    drop(export_file);
    drop(shared);
    drop(peer);
    drop(state);
    if gtt_used() != before || pool.available() != pool.size() {
        return TestResult::Fail("migration leaked GTT accounting or VRAM reservations");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/rdna2",
    rdna2_visible_vram_eviction_roundtrip_and_pins
);

fn rdna2_retirement_allows_reentrant_completion_queries() -> TestResult {
    const CARD: u32 = 0xfee3;
    let backing = Arc::new(());
    crate::amdgpu_cs::defer_until(
        CARD,
        alloc::vec![7],
        alloc::boxed::Box::new(backing.clone()),
    );
    let entered = core::sync::atomic::AtomicBool::new(false);
    crate::amdgpu_cs::retire(CARD, &|ticket| {
        if !entered.swap(true, Ordering::AcqRel) {
            // Native signalled() reads progress, which reaps completed jobs.
            crate::amdgpu_cs::retire(CARD, &|_| true);
        }
        ticket == 7
    });
    if !entered.load(Ordering::Acquire)
        || crate::amdgpu_cs::deferred(CARD) != 0
        || Arc::strong_count(&backing) != 1
    {
        return TestResult::Fail("reentrant fence query lost or retained deferred backing");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/rdna2",
    rdna2_retirement_allows_reentrant_completion_queries
);

fn rdna2_hidden_readback_preserves_vm_and_rolls_back_failure() -> TestResult {
    const CARD: u32 = 0xfee4;
    const P: u64 = 4096;
    #[derive(Debug)]
    struct Done;
    impl narf_filesystem::DrmFence for Done {
        fn is_signalled(&self) -> bool {
            true
        }
        fn wait(&self, _: u64) -> bool {
            true
        }
    }
    impl VramClear for Done {
        fn clear(&self, _: u64, _: u64) -> Result<Arc<dyn narf_filesystem::DrmFence>, FsError> {
            Ok(Arc::new(Done))
        }
    }
    #[derive(Debug)]
    struct Reader {
        pattern: alloc::vec::Vec<u8>,
        fail: core::sync::atomic::AtomicBool,
        stall: core::sync::atomic::AtomicBool,
    }
    impl VramTransfer for Reader {
        fn write<'a>(
            &'a self,
            _object: Arc<GemObject>,
            source: Arc<GemPlacement>,
            destination: Arc<GemPlacement>,
        ) -> Pin<alloc::boxed::Box<dyn Future<Output = Result<(), FsError>> + Send + 'a>> {
            alloc::boxed::Box::pin(async move {
                if destination.hidden_address() != Some(0x8_0000_1000) {
                    return Err(FsError::InvalidData);
                }
                if self.stall.load(Ordering::Acquire) {
                    core::future::pending::<()>().await;
                }
                let mut bytes = alloc::vec![0; self.pattern.len()];
                // SAFETY: the model owns the destination and retains the idle
                // System source for this complete bounded copy.
                unsafe {
                    source.write_staging(0, bytes.as_mut_ptr(), bytes.len())?;
                }
                if bytes != self.pattern {
                    return Err(FsError::InvalidData);
                }
                if self.fail.load(Ordering::Acquire) {
                    Err(FsError::TimedOut)
                } else {
                    Ok(())
                }
            })
        }
        fn read<'a>(
            &'a self,
            _object: Arc<GemObject>,
            source: Arc<GemPlacement>,
            destination: &'a mut GemPlacement,
        ) -> Pin<alloc::boxed::Box<dyn Future<Output = Result<(), FsError>> + Send + 'a>> {
            alloc::boxed::Box::pin(async move {
                if source.hidden_address() != Some(0x8_0000_1000) {
                    return Err(FsError::InvalidData);
                }
                if self.stall.load(Ordering::Acquire) {
                    core::future::pending::<()>().await;
                }
                // SAFETY: this model owns all pattern bytes; destination is
                // the coordinator's private, newly allocated System backing.
                unsafe {
                    destination.read_staging(0, self.pattern.as_ptr(), self.pattern.len())?;
                }
                if self.fail.load(Ordering::Acquire) {
                    Err(FsError::TimedOut)
                } else {
                    Ok(())
                }
            })
        }
    }
    struct Registered;
    impl Drop for Registered {
        fn drop(&mut self) {
            unregister_vram_heap(CARD);
        }
    }
    let before = gtt_used();
    let mut visible = alloc::vec![0u8; P as usize];
    let map = narf_bus::MmioRegion {
        phys: narf_memory::PhysAddr::new(0xc000_0000),
        virt: visible.as_mut_ptr() as u64,
        len: P,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // SAFETY: exclusively owned fake ranges; the model performs no device IO.
    let pool = unsafe { crate::amdgpu_vram::Pool::from_owned_range(map, 0x8_0000_0000) }.unwrap();
    // SAFETY: disjoint fake above-BAR allocation, owned solely by this test.
    let hidden =
        unsafe { crate::amdgpu_vram::UnmappedPool::from_owned(0x8_0000_1000, 3 * P, &[]) }.unwrap();
    let reader = Arc::new(Reader {
        pattern: (0..3 * P).map(|i| (i % 251) as u8).collect(),
        fail: core::sync::atomic::AtomicBool::new(true),
        stall: core::sync::atomic::AtomicBool::new(false),
    });
    register_vram_heap(
        CARD,
        VramHeap {
            pool,
            fb_base: 0x8_0000_0000,
            fb_offset: 0x9_0000_0000,
            unmapped: Some(UnmappedHeap {
                pool: hidden.clone(),
                clear: Arc::new(Done),
                transfer: Some(reader.clone()),
            }),
        },
    );
    let _registered = Registered;
    let state = GemState::for_card(CARD);
    let mut create = [
        3 * P,
        P,
        u64::from(uapi::AMDGPU_GEM_DOMAIN_VRAM),
        u64::from(uapi::AMDGPU_GEM_CREATE_NO_CPU_ACCESS),
    ];
    super::create(&state, create.as_mut_ptr() as usize).unwrap();
    let handle = create[0] as u32;
    let object = state.object(handle).unwrap();
    let exported = crate::drm_devfs_bridge::amdgpu_dma_buf_file(object.clone()).unwrap();
    let vm = crate::amdgpu_vm::VmState::for_card(CARD);
    let mut va = [0u8; 40];
    va[..4].copy_from_slice(&handle.to_le_bytes());
    va[8..12].copy_from_slice(&uapi::AMDGPU_VA_OP_MAP.to_le_bytes());
    va[12..16].copy_from_slice(&uapi::AMDGPU_VM_PAGE_READABLE.to_le_bytes());
    va[16..24].copy_from_slice(&0x2_0000_0000u64.to_le_bytes());
    va[32..40].copy_from_slice(&(3 * P).to_le_bytes());
    crate::amdgpu_vm::dispatch(
        crate::drm_uapi::DRM_COMMAND_BASE + uapi::DRM_AMDGPU_GEM_VA,
        va.as_ptr() as usize,
        &vm,
        &state,
    )
    .unwrap();
    let pte = vm.leaf_entry(0x2_0000_2000);
    let tables = vm.table_count();
    #[derive(Debug)]
    struct Moving(core::sync::atomic::AtomicBool);
    impl narf_filesystem::DrmFence for Moving {
        fn is_signalled(&self) -> bool {
            self.0.load(Ordering::Acquire)
        }
        fn wait(&self, _: u64) -> bool {
            self.is_signalled()
        }
    }
    let moving = Arc::new(Moving(core::sync::atomic::AtomicBool::new(false)));
    let fence: Arc<dyn narf_filesystem::DrmFence> = moving.clone();
    object.dma_buf().resv.add_fence(
        fence.clone(),
        narf_filesystem::dma_buf::DmaResvUsage::Kernel,
    );
    if !vm
        .kernel_fences()
        .iter()
        .any(|pending| Arc::ptr_eq(pending, &fence))
    {
        return TestResult::Fail("VM missed a move fence attached after GEM_VA");
    }
    moving.0.store(true, Ordering::Release);
    if !vm.kernel_fences().is_empty() {
        return TestResult::Fail("VM retained completed move fence");
    }
    let failed = narf_scheduler::block_on_spin(async {
        let gate = lock_placement(CARD).await;
        crate::amdgpu_vm::relocate(&gate, &object, false).await
    });
    if failed != Err(FsError::TimedOut)
        || object.cpu_visible()
        || vm.leaf_entry(0x2_0000_2000) != pte
        || gtt_used() != before
        || hidden.available() != 0
    {
        return TestResult::Fail("failed invisible copy changed backing, PTEs or accounting");
    }
    reader.fail.store(false, Ordering::Release);
    reader.stall.store(true, Ordering::Release);
    {
        let mut future = core::pin::pin!(async {
            let gate = lock_placement(CARD).await;
            crate::amdgpu_vm::relocate(&gate, &object, false).await
        });
        let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
        if future.as_mut().poll(&mut cx).is_ready() {
            return TestResult::Fail("stalled copy did not park");
        }
    }
    if gtt_used() != before || vm.leaf_entry(0x2_0000_2000) != pte || try_placement(CARD).is_none()
    {
        return TestResult::Fail("cancelled invisible copy leaked backing or admission");
    }
    reader.stall.store(false, Ordering::Release);
    let moved = narf_scheduler::block_on_spin(async {
        let gate = lock_placement(CARD).await;
        crate::amdgpu_vm::relocate(&gate, &object, false).await
    });
    if moved.is_err()
        || !object.system()
        || hidden.available() != 3 * P
        || gtt_used() != before + 3 * P
        || vm.table_count() != tables
        || vm.leaf_entry(0x2_0000_2000).is_none_or(|e| {
            e & crate::amdgpu_vm::PTE_SYSTEM == 0
                || Some(e & crate::amdgpu_vm::GMC_HOLE_MASK & !4095) != object.gpu_at(2 * P)
        })
        || object.load_u64(3 * P - 8)
            != Some(u64::from_le_bytes(
                reader.pattern[reader.pattern.len() - 8..]
                    .try_into()
                    .unwrap(),
            ))
    {
        return TestResult::Fail("invisible readback lost data, ownership or VM rebinding");
    }
    let offset = u64::from(handle) << 12;
    if state.mapping_object(offset, P as usize).is_some()
        || state.mmap_frames(offset, P as usize) != Err(FsError::OperationNotPermitted)
        || exported.mmap_frames(0, P as usize) != Err(FsError::OperationNotPermitted)
    {
        return TestResult::Fail("NO_CPU_ACCESS bypassed with forged GEM/PRIME mmap offset");
    }
    let system_pte = vm.leaf_entry(0x2_0000_2000);
    reader.fail.store(true, Ordering::Release);
    let cpu_writer = object.mapping();
    let pinned = narf_scheduler::block_on_spin(async {
        let gate = lock_placement(CARD).await;
        crate::amdgpu_vm::relocate(&gate, &object, true).await
    });
    if pinned != Err(FsError::Busy) || hidden.available() != 3 * P {
        return TestResult::Fail("staging read started with a retained CPU writer");
    }
    drop(cpu_writer);
    let failed = narf_scheduler::block_on_spin(async {
        let gate = lock_placement(CARD).await;
        crate::amdgpu_vm::relocate(&gate, &object, true).await
    });
    if failed != Err(FsError::TimedOut)
        || !object.system()
        || vm.leaf_entry(0x2_0000_2000) != system_pte
        || hidden.available() != 3 * P
    {
        return TestResult::Fail("failed hidden upload changed source or leaked destination");
    }
    reader.fail.store(false, Ordering::Release);
    reader.stall.store(true, Ordering::Release);
    {
        let mut future = core::pin::pin!(async {
            let gate = lock_placement(CARD).await;
            crate::amdgpu_vm::relocate(&gate, &object, true).await
        });
        let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
        if future.as_mut().poll(&mut cx).is_ready() {
            return TestResult::Fail("stalled upload did not park");
        }
    }
    if hidden.available() != 3 * P
        || vm.leaf_entry(0x2_0000_2000) != system_pte
        || try_placement(CARD).is_none()
    {
        return TestResult::Fail("cancelled upload leaked destination or changed PTEs");
    }
    reader.stall.store(false, Ordering::Release);
    let moved = narf_scheduler::block_on_spin(async {
        let gate = lock_placement(CARD).await;
        crate::amdgpu_vm::relocate(&gate, &object, true).await
    });
    if moved.is_err()
        || object.cpu_visible()
        || hidden.available() != 0
        || gtt_used() != before
        || vm.table_count() != tables
        || vm.leaf_entry(0x2_0000_2000) != pte
    {
        return TestResult::Fail("hidden roundtrip lost placement, VM or GTT accounting");
    }
    drop(vm);
    drop(exported);
    drop(object);
    drop(state);
    if gtt_used() != before {
        return TestResult::Fail("readback leaked GTT after last reference");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/rdna2",
    rdna2_hidden_readback_preserves_vm_and_rolls_back_failure
);

/// System suspend eviction (ttm_resource_manager_evict_all): every VRAM
/// buffer of the card moves to system memory even when VRAM is its only
/// allowed domain; restore_domains puts the original domains back.
fn suspend_eviction_moves_vram_only_buffers_and_restores_domains() -> TestResult {
    const CARD: u32 = 0xfee3;
    let mut memory = alloc::vec![0u8; 4 * 4096];
    let map = narf_bus::MmioRegion {
        phys: narf_memory::PhysAddr::new(0xb100_0000),
        virt: memory.as_mut_ptr() as u64,
        len: memory.len() as u64,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // SAFETY: this test exclusively owns memory until the heap and every
    // object are dropped; no hardware accesses these mappings.
    let pool = unsafe { crate::amdgpu_vram::Pool::from_owned_range(map, 0x8_0000_0000) }.unwrap();
    register_vram_heap(
        CARD,
        VramHeap {
            pool: pool.clone(),
            fb_base: 0x8_0000_0000,
            fb_offset: 0x9_0000_0000,
            unmapped: None,
        },
    );
    let state = GemState::for_card(CARD);
    let vram_only = u64::from(uapi::AMDGPU_GEM_DOMAIN_VRAM);
    let a = state.get(create(&state, 4096, vram_only)).unwrap();
    let b = state
        .get(create(
            &state,
            8192,
            vram_only | u64::from(uapi::AMDGPU_GEM_DOMAIN_GTT),
        ))
        .unwrap();
    assert!(!a.system() && !b.system());
    // VRAM-preferred buffers allow GTT as in Linux; make `a` VRAM-only, as
    // a DISCARDABLE buffer is. Plain relocation refuses it.
    a.allowed_domains.store(vram_only, Ordering::Release);
    assert_eq!(a.relocate(false), Err(FsError::Busy));
    let (touched, result) = narf_scheduler::block_on_spin(async {
        let gate = lock_placement(CARD).await;
        evict_all(&gate).await
    });
    assert_eq!(result, Ok(()));
    assert!(a.system() && b.system());
    assert_eq!(touched.len(), 2);
    assert_eq!(pool.available(), 4 * 4096);
    restore_domains(touched);
    assert_eq!(a.allowed_domains.load(Ordering::Acquire), vram_only);
    assert_ne!(
        b.allowed_domains.load(Ordering::Acquire) & u64::from(uapi::AMDGPU_GEM_DOMAIN_GTT),
        0
    );
    unregister_vram_heap(CARD);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/render-abi",
    suspend_eviction_moves_vram_only_buffers_and_restores_domains
);

/// amdgpu_gem_userptr_ioctl argument checks, which run before any page is
/// touched: alignment and flags EINVAL, a writable range without REGISTER
/// EACCES; a kernel task (no user address space) faults.
fn userptr_ioctl_validates_like_linux() -> TestResult {
    let state = GemState::for_card(0xfee4);
    let call = |addr: u64, size: u64, flags: u32| {
        let mut b = [0u8; 24];
        b[0..8].copy_from_slice(&addr.to_le_bytes());
        b[8..16].copy_from_slice(&size.to_le_bytes());
        b[16..20].copy_from_slice(&flags.to_le_bytes());
        dispatch(
            amd(uapi::DRM_AMDGPU_GEM_USERPTR),
            b.as_mut_ptr() as usize,
            &state,
        )
    };
    let ro = uapi::AMDGPU_GEM_USERPTR_READONLY;
    assert_eq!(call(0x1000_0001, 4096, ro), Err(FsError::InvalidData));
    assert_eq!(call(0x1000_0000, 4095, ro), Err(FsError::InvalidData));
    assert_eq!(call(0x1000_0000, 0, ro), Err(FsError::InvalidData));
    assert_eq!(call(0x1000_0000, 4096, 1 << 4), Err(FsError::InvalidData));
    assert_eq!(call(0x1000_0000, 4096, 0), Err(FsError::PermissionDenied));
    assert_eq!(
        call(0x1000_0000, 4096, uapi::AMDGPU_GEM_USERPTR_VALIDATE),
        Err(FsError::PermissionDenied)
    );
    assert_eq!(call(0x1000_0000, 4096, ro), Err(FsError::BadAddress));
    assert_eq!(
        call(
            0x1000_0000,
            4096,
            uapi::AMDGPU_GEM_USERPTR_REGISTER | uapi::AMDGPU_GEM_USERPTR_ANONONLY
        ),
        Err(FsError::BadAddress)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/render-abi",
    userptr_ioctl_validates_like_linux
);

/// A userptr buffer is its pinned pages: GPU entries follow each pin, a
/// READONLY one maps without WRITEABLE, and it is never CPU mapped through
/// GEM_MMAP, exported or migrated.
fn userptr_backing_follows_pins_and_refuses_mmap_export_and_moves() -> TestResult {
    use narf_memory::address_space::UserPagePin;
    let frames: Vec<_> = (0..2)
        .map(|_| narf_memory::alloc_frame().unwrap())
        .collect();
    let pins: Vec<_> = frames
        .iter()
        // SAFETY: freshly allocated frames, freed below after the pins drop.
        .map(|f| unsafe { UserPagePin::retain_ram(f.start_address()) })
        .collect();
    let (a, b) = (
        frames[0].start_address().raw(),
        frames[1].start_address().raw(),
    );
    let gtt = u64::from(uapi::AMDGPU_GEM_DOMAIN_GTT);
    let object = Arc::new(GemObject {
        placement: IrqSafeSpinLock::new(Arc::new(GemPlacement {
            phys: a,
            gpu: a,
            system: true,
            byte_len: 2 * PAGE_SIZE,
            backing: Backing::User(pins),
        })),
        byte_len: 2 * PAGE_SIZE,
        alignment: PAGE_SIZE,
        preferred_domains: AtomicU64::new(gtt),
        allowed_domains: AtomicU64::new(gtt),
        flags: BO_GPU_READONLY,
        metadata: IrqSafeSpinLock::new(Metadata::default()),
        card: Some(0xfee5),
        dma_buf: Arc::new(narf_filesystem::dma_buf::DmaBufObject::default()),
    });
    assert!(object.is_userptr());
    assert_eq!(object.frames(0, 2 * 4096).unwrap(), [a, b]);
    let placement = object.placement();
    assert_eq!(placement.gpu_at(4096 + 8), Some(b + 8));
    assert_eq!(object.relocate(true), Err(FsError::Busy));
    assert_eq!(object.relocate(false), Err(FsError::Busy));
    assert!(crate::drm_devfs_bridge::amdgpu_dma_buf_file(object.clone()).is_err());
    let rw = uapi::AMDGPU_VM_PAGE_READABLE | uapi::AMDGPU_VM_PAGE_WRITEABLE;
    let flags = crate::amdgpu_vm::PteFormat::Gfx12.pte_flags(0, rw, object.flags);
    assert_eq!(flags & crate::amdgpu_vm::PTE_WRITEABLE, 0);
    let writable = crate::amdgpu_vm::PteFormat::Gfx12.pte_flags(0, rw, 0);
    assert_ne!(writable & crate::amdgpu_vm::PTE_WRITEABLE, 0);
    drop((placement, object));
    for frame in frames {
        narf_memory::free_frame(frame);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/render-abi",
    userptr_backing_follows_pins_and_refuses_mmap_export_and_moves
);
