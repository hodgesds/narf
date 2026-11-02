//! Exercise RDNA2 framebuffer creation through the primary device's ioctl
//! dispatcher, rather than bypassing its generation gate with Card methods.
#![cfg(target_arch = "x86_64")]

use crate::amdgpu_gem::{self as gem, VramHeap};
use crate::drm::card::Card;
use alloc::{format, sync::Arc, vec, vec::Vec};
use narf_filesystem::{FileOps, FsError};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Fixture {
    index: u32,
    mode: Arc<narf_lib::sync::IrqSafeSpinLock<Card>>,
    _bar: Vec<u8>,
}

impl Fixture {
    fn new() -> Option<Self> {
        let mut card = Card::new("amdgpu", "Navi22 ioctl fixture", (3, 60, 0));
        card.native_atomic = true;
        card.plane_formats = Some(&[0x3432_5258, 0x3432_5241]);
        let iface = Arc::new(crate::drm_devfs_bridge::AmdgpuCard::new(
            format!("card{}", crate::drm_registry::count()),
            0x1002,
            0x73df,
            0,
            0,
            None,
        ));
        let index = crate::drm_registry::register_drm_card_with_state(iface, card);
        let mode = crate::drm_registry::mode_state(index)?;
        let mut bar = vec![0u8; 64 * 1024];
        let map = narf_bus::MmioRegion {
            phys: narf_memory::PhysAddr::new(0xbc00_0000),
            virt: bar.as_mut_ptr() as u64,
            len: bar.len() as u64,
            kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
        };
        // SAFETY: fixture-owned bytes outlive the heap and all device files.
        let pool =
            unsafe { crate::amdgpu_vram::Pool::from_owned_range(map, 0x8_0000_0000) }.ok()?;
        gem::register_vram_heap(
            index,
            VramHeap {
                pool,
                fb_base: 0x8_0000_0000,
                fb_offset: 0x8_0000_0000,
                unmapped: None,
            },
        );
        Some(Self {
            index,
            mode,
            _bar: bar,
        })
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.mode.lock().framebuffers.clear();
        gem::unregister_vram_heap(self.index);
    }
}

fn request(handle: u32, format: u32, flags: u32) -> [u8; 104] {
    let mut arg = [0u8; 104];
    for (offset, value) in [
        (4, 64u32),
        (8, 12),
        (12, format),
        (16, flags),
        (20, handle),
        (36, 256),
    ] {
        arg[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    arg
}

fn legacy_request(handle: u32) -> [u8; 28] {
    let mut arg = [0u8; 28];
    for (offset, value) in [
        (4, 64u32),
        (8, 12),
        (12, 256),
        (16, 32),
        (20, 24),
        (24, handle),
    ] {
        arg[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    arg
}

fn rdna2_primary_ioctl_accepts_own_linear_gem_framebuffers() -> TestResult {
    let Some(f) = Fixture::new() else {
        return TestResult::Fail("fixture");
    };
    let Some(file) = crate::drm_devfs_bridge::DriCardFile::new(f.index) else {
        return TestResult::Fail("primary open");
    };
    let mut create = [0u8; 32];
    create[..8].copy_from_slice(&4096u64.to_le_bytes());
    create[8..16].copy_from_slice(&4096u64.to_le_bytes());
    create[16..24]
        .copy_from_slice(&u64::from(crate::amdgpu_uapi::AMDGPU_GEM_DOMAIN_VRAM).to_le_bytes());
    if file.ioctl(0xc020_6440, create.as_mut_ptr() as usize) != Ok(0) {
        return TestResult::Fail("GEM_CREATE through primary file");
    }
    let handle = u32::from_le_bytes(create[..4].try_into().unwrap());
    if f.mode.lock().gem.lookup(handle).is_some() {
        return TestResult::Fail("native GEM handle leaked into the generic card table");
    }
    let mut fbs = Vec::new();
    for format in [0x3432_5258, 0x3432_5241] {
        for flags in [0, 2] {
            let mut arg = request(handle, format, flags);
            if file.ioctl(
                crate::drm_uapi::DRM_IOCTL_MODE_ADDFB2,
                arg.as_mut_ptr() as usize,
            ) != Ok(0)
            {
                return TestResult::Fail("RDNA2 ioctl rejected a valid native GEM framebuffer");
            }
            let id = u32::from_le_bytes(arg[..4].try_into().unwrap());
            if !f
                .mode
                .lock()
                .framebuffer(id)
                .is_ok_and(|fb| fb.bo.is_some() && fb.modifier == 0)
            {
                return TestResult::Fail("framebuffer lost its native BO");
            }
            fbs.push(id);
        }
    }
    let mut legacy = legacy_request(handle);
    if file.ioctl(
        crate::drm_uapi::DRM_IOCTL_MODE_ADDFB,
        legacy.as_mut_ptr() as usize,
    ) != Ok(0)
    {
        return TestResult::Fail("RDNA2 legacy ioctl rejected its native GEM framebuffer");
    }
    fbs.push(u32::from_le_bytes(legacy[..4].try_into().unwrap()));
    let Some(other) = crate::drm_devfs_bridge::DriCardFile::new(f.index) else {
        return TestResult::Fail("other primary open");
    };
    let mut foreign = request(handle, 0x3432_5258, 2);
    if other
        .ioctl(
            crate::drm_uapi::DRM_IOCTL_MODE_ADDFB2,
            foreign.as_mut_ptr() as usize,
        )
        .is_ok()
    {
        return TestResult::Fail("another open used the creator's GEM handle");
    }
    let mut legacy = legacy_request(handle);
    if other.ioctl(
        crate::drm_uapi::DRM_IOCTL_MODE_ADDFB,
        legacy.as_mut_ptr() as usize,
    ) != Err(FsError::PermissionDenied)
    {
        return TestResult::Fail("legacy ADDFB bypassed DRM master authority");
    }
    let mut tiled = request(handle, 0x3432_5258, 2);
    tiled[72..80].copy_from_slice(&crate::amdgpu_dm_modifiers::PLANE_MODIFIERS[1].to_le_bytes());
    if file.ioctl(
        crate::drm_uapi::DRM_IOCTL_MODE_ADDFB2,
        tiled.as_mut_ptr() as usize,
    ) != Err(FsError::InvalidData)
    {
        return TestResult::Fail("RDNA2 ioctl admitted a tiled framebuffer");
    }
    let mut close = [0u8; 8];
    close[..4].copy_from_slice(&handle.to_le_bytes());
    if file.ioctl(
        crate::drm_uapi::DRM_IOCTL_GEM_CLOSE,
        close.as_mut_ptr() as usize,
    ) != Ok(0)
        || fbs.iter().any(|&id| f.mode.lock().framebuffer(id).is_err())
    {
        return TestResult::Fail("GEM_CLOSE released a retained framebuffer");
    }
    drop(other);
    drop(file);
    if !f.mode.lock().framebuffers.is_empty() {
        return TestResult::Fail("closing the creator leaked native framebuffers");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm/rdna2_fb",
    rdna2_primary_ioctl_accepts_own_linear_gem_framebuffers
);
