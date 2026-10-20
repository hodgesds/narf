//! MMHUB client bindings and unified VCN ring publication under OWNER.
use super::*;
use narf_filesystem::FsError;

pub(super) fn native_ring(
    ip_type: u32,
    instance: u32,
    ring: u32,
    sdma_ready: bool,
    media_ready: bool,
    jpeg_ready: bool,
) -> Option<u32> {
    use crate::amdgpu_uapi::*;
    match (ip_type, instance, ring) {
        (AMDGPU_HW_IP_GFX, 0, 0) => Some(0),
        (AMDGPU_HW_IP_COMPUTE, 0, 0) => Some(1),
        (AMDGPU_HW_IP_DMA, 0, 0) if sdma_ready => Some(SDMA_RING),
        // VCN5 carries both decode and encode on Linux's VCN_ENC ring;
        // legacy VCN_DEC stays unavailable. JPEG5 has its own decode ring.
        (AMDGPU_HW_IP_VCN_ENC, 0, 0) if media_ready => Some(MEDIA_RING),
        (AMDGPU_HW_IP_VCN_JPEG, 0, 0) if jpeg_ready => Some(JPEG_RING),
        _ => None,
    }
}
impl Submitter {
    pub(super) fn vmids_for(
        &self,
        ring: u32,
    ) -> &narf_lib::sync::IrqSafeSpinLock<crate::amdgpu_vmid::VmidManager> {
        if matches!(ring, MEDIA_RING | JPEG_RING) {
            &self.mm_vmids
        } else {
            &self.vmids
        }
    }
}
/// # Safety
/// Hold OWNER and retain the complete job's mappings/BOs and matching hub
/// VMID until its translated fence passes or reset proves retirement.
pub(super) unsafe fn publish_client(
    boot: &mut boot::ColdBoot,
    ring: u32,
    job: crate::amdgpu_gfx12_queue::Job,
) -> Result<u32, FsError> {
    match ring {
        0 | 1 => {
            // SAFETY: the caller holds OWNER; the frozen/normal CS ledger
            // retains this complete job and its GFXHUB VMID through its fence.
            unsafe { boot.submit_client_job(PIPES[ring as usize], job) }.map_err(|e| {
                use crate::amdgpu_gfx12_queue::Error;
                match e {
                    Error::Busy => FsError::Busy,
                    Error::Invalid => FsError::InvalidData,
                    _ => FsError::NoDevice,
                }
            })
        }
        SDMA_RING => {
            // SAFETY: same owner and retained GFXHUB binding/resources.
            unsafe { boot.submit_client_sdma_job(job) }.map_err(|e| {
                use crate::amdgpu_sdma_navi48::Error;
                match e {
                    Error::Busy => FsError::Busy,
                    Error::Invalid => FsError::InvalidData,
                    _ => FsError::NoDevice,
                }
            })
        }
        MEDIA_RING => {
            // SAFETY: same owner; a separate MMHUB manager lends this VMID.
            // Return synchronously after publication so CS can retain BOs.
            unsafe { boot.submit_client_media_job(job) }.map_err(|e| {
                use crate::amdgpu_vcn_navi48::Error;
                match e {
                    Error::Busy => FsError::Busy,
                    Error::Invalid => FsError::InvalidData,
                    _ => FsError::NoDevice,
                }
            })
        }
        JPEG_RING => {
            // SAFETY: same owner; the MMHUB VMID and staged kernel IB slot
            // are retained with the job's resources through its fence.
            unsafe { boot.submit_client_jpeg_job(job) }.map_err(|e| {
                use crate::amdgpu_jpeg_navi48::Error;
                match e {
                    Error::Busy => FsError::Busy,
                    Error::Invalid => FsError::InvalidData,
                    _ => FsError::NoDevice,
                }
            })
        }
        _ => Err(FsError::Unsupported),
    }
}
/// Called with OWNER after both native media proofs and before client work.
pub(super) fn activate_media(boot: &boot::ColdBoot) {
    let Some(submitter) = SUBMITTER.lock().clone() else {
        return;
    };
    let generation = READ_GENERATION.lock();
    if *generation == submitter.generation {
        *submitter.media_fence.lock() = boot.client_media_fence_reader();
        *submitter.jpeg_fence.lock() = boot.client_jpeg_fence_reader();
        crate::amdgpu_info::publish_navi48_video(boot.proven_video());
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use crate::amdgpu_uapi::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn navi48_unified_media_ring_requires_proven_owner_and_exact_route() -> TestResult {
        for bits in 0..8u8 {
            let (sdma, media, jpeg) = (bits & 1 != 0, bits & 2 != 0, bits & 4 != 0);
            let route = |ip, instance, ring| native_ring(ip, instance, ring, sdma, media, jpeg);
            assert_eq!(route(AMDGPU_HW_IP_GFX, 0, 0), Some(0));
            assert_eq!(route(AMDGPU_HW_IP_COMPUTE, 0, 0), Some(1));
            assert_eq!(route(AMDGPU_HW_IP_DMA, 0, 0), sdma.then_some(2));
            assert_eq!(route(AMDGPU_HW_IP_VCN_ENC, 0, 0), media.then_some(3));
            assert_eq!(route(AMDGPU_HW_IP_VCN_JPEG, 0, 0), jpeg.then_some(4));
            assert_eq!(route(AMDGPU_HW_IP_VCN_DEC, 0, 0), None);
            for ip in [AMDGPU_HW_IP_VCN_ENC, AMDGPU_HW_IP_VCN_JPEG] {
                for (instance, ring) in [(1, 0), (0, 1), (u32::MAX, u32::MAX)] {
                    assert_eq!(route(ip, instance, ring), None);
                }
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/navi48-platform",
        navi48_unified_media_ring_requires_proven_owner_and_exact_route
    );
}
