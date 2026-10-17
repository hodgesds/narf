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
            narf_memory::PhysAddr::new(object.phys + 16).kernel_mut_ptr::<u64>(),
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
