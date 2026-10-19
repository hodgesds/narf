//! MMHUB client bindings and unified VCN ring publication under OWNER.
use super::*;
use narf_filesystem::FsError;

pub(super) fn native_ring(
    ip_type: u32,
    instance: u32,
    ring: u32,
    sdma_ready: bool,
    media_ready: bool,
) -> Option<u32> {
    use crate::amdgpu_uapi::*;
    match (ip_type, instance, ring) {
        (AMDGPU_HW_IP_GFX, 0, 0) => Some(0),
        (AMDGPU_HW_IP_COMPUTE, 0, 0) => Some(1),
        (AMDGPU_HW_IP_DMA, 0, 0) if sdma_ready => Some(SDMA_RING),
        // VCN5 carries both decode and encode on Linux's VCN_ENC ring.
        // Legacy VCN_DEC and independent JPEG remain unavailable here.
        (AMDGPU_HW_IP_VCN_ENC, 0, 0) if media_ready => Some(MEDIA_RING),
        _ => None,
    }
}
impl Submitter {
    pub(super) fn vmids_for(
        &self,
        ring: u32,
    ) -> &narf_lib::sync::IrqSafeSpinLock<crate::amdgpu_vmid::VmidManager> {
        if ring == MEDIA_RING {
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
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use crate::amdgpu_uapi::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn navi48_unified_media_ring_requires_proven_owner_and_exact_route() -> TestResult {
        for sdma in [false, true] {
            for media in [false, true] {
                assert_eq!(native_ring(AMDGPU_HW_IP_GFX, 0, 0, sdma, media), Some(0));
                assert_eq!(
                    native_ring(AMDGPU_HW_IP_COMPUTE, 0, 0, sdma, media),
                    Some(1)
                );
                assert_eq!(
                    native_ring(AMDGPU_HW_IP_DMA, 0, 0, sdma, media),
                    sdma.then_some(2)
                );
                assert_eq!(
                    native_ring(AMDGPU_HW_IP_VCN_ENC, 0, 0, sdma, media),
                    media.then_some(3)
                );
                for ip in [AMDGPU_HW_IP_VCN_DEC, AMDGPU_HW_IP_VCN_JPEG] {
                    assert_eq!(native_ring(ip, 0, 0, sdma, media), None);
                }
                for (instance, ring) in [(1, 0), (0, 1), (u32::MAX, u32::MAX)] {
                    assert_eq!(
                        native_ring(AMDGPU_HW_IP_VCN_ENC, instance, ring, sdma, media),
                        None
                    );
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
