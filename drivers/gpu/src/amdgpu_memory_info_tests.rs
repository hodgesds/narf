//! Memory INFO replies through the real ioctl dispatcher and GEM owners.
//! Linux reference: amdgpu_kms.c:amdgpu_info_ioctl, MEMORY / VRAM_GTT /
//! VRAM_USAGE / VIS_VRAM_USAGE / GTT_USAGE. No hardware is accessed.
use super::*;
use crate::amdgpu_gem::{self as gem, GemState, UnmappedHeap, VramHeap};
use crate::amdgpu_uapi as u;
use crate::amdgpu_vm::VmState;
use crate::amdgpu_vram::{Pool, UnmappedPool};
use alloc::sync::Arc;
use alloc::vec;
use narf_filesystem::FsError;
use narf_kernel_test::{kernel_test_in, TestResult};

const CARD: u32 = 0xfef0;

struct Registered;
impl Drop for Registered {
    fn drop(&mut self) {
        gem::unregister_vram_heap(CARD);
        *CONTROLLER.lock() = None;
    }
}

#[derive(Debug)]
struct NoClear;
impl gem::VramClear for NoClear {
    fn clear(&self, _: u64, _: u64) -> Result<Arc<dyn narf_filesystem::DrmFence>, FsError> {
        Err(FsError::Unsupported)
    }
}

fn ask(vm: &VmState, which: u32, size: u32) -> Result<[u8; 104], FsError> {
    let mut out = [0xa5u8; 104];
    let mut req = [0u8; 32];
    req[0..8].copy_from_slice(&(out.as_mut_ptr() as u64).to_le_bytes());
    req[8..12].copy_from_slice(&size.to_le_bytes());
    req[12..16].copy_from_slice(&which.to_le_bytes());
    crate::amdgpu_info::dispatch_for(
        crate::drm_uapi::DRM_COMMAND_BASE + u::DRM_AMDGPU_INFO,
        req.as_mut_ptr() as usize,
        Some(vm),
    )?;
    Ok(out)
}

fn words(vm: &VmState, which: u32, count: usize) -> Vec<u64> {
    let out = ask(vm, which, (count * 8) as u32).unwrap();
    assert!(out[count * 8..].iter().all(|&b| b == 0xa5));
    out[..count * 8]
        .chunks_exact(8)
        .map(|word| u64::from_le_bytes(word.try_into().unwrap()))
        .collect()
}

fn create(state: &GemState, size: u64, domain: u32) -> u32 {
    let mut req = [size, 0, u64::from(domain), 0];
    gem::dispatch(
        crate::drm_uapi::DRM_COMMAND_BASE + u::DRM_AMDGPU_GEM_CREATE,
        req.as_mut_ptr() as usize,
        state,
    )
    .unwrap();
    req[0] as u32
}

fn close(state: &GemState, handle: u32) {
    let mut req = [handle, 0];
    gem::dispatch(0x09, req.as_mut_ptr() as usize, state).unwrap();
}

fn memory_info_tracks_allocations_and_retained_owners() -> TestResult {
    if is_probed() {
        return TestResult::Skip("real controller owns the global slot");
    }
    // Both native families must use their card's heap, regardless of which
    // snapshot query path answers their topology and firmware.
    for mut gpu in [
        crate::amdgpu_navi22_boot::tests::gpu(),
        crate::amdgpu_navi48_firmware::tests::gpu(),
    ] {
        gpu.vram.size = 12 << 30;
        gpu.vram.visible_size = 256 << 20;
        *CONTROLLER.lock() = Some(gpu);
        let mut memory = vec![0u8; 4 * 4096];
        let map = narf_bus::MmioRegion {
            phys: narf_memory::PhysAddr::new(0xb500_0000),
            virt: memory.as_mut_ptr() as u64,
            len: memory.len() as u64,
            kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
        };
        // SAFETY: this test owns the backing through every heap and object;
        // the hidden range is bookkeeping only and is never dereferenced.
        let (pool, hidden) = unsafe {
            (
                Pool::from_owned_range(map, 0x8_0000_0000).unwrap(),
                UnmappedPool::from_owned(0x8_1000_0000, 8 * 4096, &[]).unwrap(),
            )
        };
        gem::register_vram_heap(
            CARD,
            VramHeap {
                pool: pool.clone(),
                fb_base: 0x8_0000_0000,
                fb_offset: 0x9_0000_0000,
                unmapped: Some(UnmappedHeap {
                    pool: hidden.clone(),
                    clear: Arc::new(NoClear),
                    transfer: None,
                }),
            },
        );
        let _registered = Registered;
        let vm = VmState::for_card(CARD);
        let state = GemState::for_card(CARD);
        let baseline = gem::gtt_used();
        let gtt = gem::gtt_limit();
        let check = |visible_used, hidden_used, gtt_used| {
            let m = words(&vm, u::AMDGPU_INFO_MEMORY, 12);
            assert_eq!(
                &m[..4],
                &[12 << 30, 49152, visible_used + hidden_used, 36864]
            );
            assert_eq!(&m[4..8], &[256 << 20, 16384, visible_used, 12288]);
            assert_eq!(&m[8..], &[gtt, gtt, gtt_used, gtt * 3 / 4]);
            assert_eq!(words(&vm, u::AMDGPU_INFO_VRAM_GTT, 3), [49152, 16384, gtt]);
            assert_eq!(
                words(&vm, u::AMDGPU_INFO_VRAM_USAGE, 1),
                [visible_used + hidden_used]
            );
            assert_eq!(words(&vm, u::AMDGPU_INFO_VIS_VRAM_USAGE, 1), [visible_used]);
            assert_eq!(words(&vm, u::AMDGPU_INFO_GTT_USAGE, 1), [gtt_used]);
        };
        check(0, 0, baseline);
        let vram = create(&state, 4096, u::AMDGPU_GEM_DOMAIN_VRAM);
        let system = create(&state, 8193, u::AMDGPU_GEM_DOMAIN_GTT);
        let hidden_allocation = hidden.reserve_aligned(4096, 4096).unwrap();
        check(4096, 4096, baseline + 12288);
        // PRIME import shares the object; handle closure cannot reduce usage
        // until the last owner drops. A foreign open has no VRAM usage.
        let peer = GemState::for_card(CARD);
        let retained = state.object(system).unwrap();
        let imported = peer.import(&retained).unwrap();
        close(&state, system);
        close(&peer, imported);
        check(4096, 4096, baseline + 12288);
        let other = VmState::for_card(CARD + 1);
        assert_eq!(words(&other, u::AMDGPU_INFO_VRAM_USAGE, 1), [0]);
        assert_eq!(words(&other, u::AMDGPU_INFO_VIS_VRAM_USAGE, 1), [0]);
        assert_eq!(
            words(&other, u::AMDGPU_INFO_GTT_USAGE, 1),
            [baseline + 12288]
        );
        // Linux permits short and oversized replies without touching bytes
        // past min(return_size, sizeof(result)).
        let short = ask(&vm, u::AMDGPU_INFO_GTT_USAGE, 3).unwrap();
        assert_eq!(&short[..3], &(baseline + 12288).to_le_bytes()[..3]);
        assert!(short[3..].iter().all(|&b| b == 0xa5));
        let large = ask(&vm, u::AMDGPU_INFO_MEMORY, 104).unwrap();
        assert!(large[96..].iter().all(|&b| b == 0xa5));
        drop(retained);
        close(&state, vram);
        drop(hidden_allocation);
        check(0, 0, baseline);
        assert_eq!(pool.available(), pool.size());
        assert_eq!(hidden.available(), hidden.size());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/memory-info",
    memory_info_tracks_allocations_and_retained_owners
);
