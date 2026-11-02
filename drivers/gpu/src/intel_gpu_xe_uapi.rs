//! Native Xe wire ABI. MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad,
//! include/uapi/drm/xe_drm.h. Decode fixed byte offsets, never Rust padding.
use crate::drm_uapi::{iow, iowr, DRM_IOCTL_BASE as D};
pub const DEVICE_QUERY: u32 = iowr(D, 0x40, 40);
pub const GEM_CREATE: u32 = iowr(D, 0x41, 56);
pub const GEM_MMAP_OFFSET: u32 = iowr(D, 0x42, 40);
pub const VM_CREATE: u32 = iowr(D, 0x43, 32);
pub const VM_DESTROY: u32 = iow(D, 0x44, 24);
pub const VM_BIND: u32 = iow(D, 0x45, 136);
pub const EXEC_QUEUE_CREATE: u32 = iowr(D, 0x46, 48);
pub const EXEC_QUEUE_DESTROY: u32 = iow(D, 0x47, 24);
pub const EXEC_QUEUE_GET_PROPERTY: u32 = iowr(D, 0x48, 40);
pub const EXEC: u32 = iow(D, 0x49, 56);
pub const WAIT_USER_FENCE: u32 = iowr(D, 0x4a, 72);
pub const OBSERVATION: u32 = iow(D, 0x4b, 32);

pub(crate) fn driver_ioctl(cmd: u32) -> bool {
    matches!(
        cmd,
        DEVICE_QUERY
            | GEM_CREATE
            | GEM_MMAP_OFFSET
            | VM_CREATE
            | VM_DESTROY
            | VM_BIND
            | EXEC_QUEUE_CREATE
            | EXEC_QUEUE_DESTROY
            | EXEC_QUEUE_GET_PROPERTY
            | EXEC
            | WAIT_USER_FENCE
            | OBSERVATION
            | crate::intel_gpu_uapi::GEM_CLOSE
    )
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn smoke_native_xe_ioctl_wire_numbers() -> TestResult {
        assert_eq!(
            [
                DEVICE_QUERY,
                GEM_CREATE,
                GEM_MMAP_OFFSET,
                VM_CREATE,
                VM_DESTROY,
                VM_BIND,
                EXEC_QUEUE_CREATE,
                EXEC_QUEUE_DESTROY,
                EXEC_QUEUE_GET_PROPERTY,
                EXEC,
                WAIT_USER_FENCE,
                OBSERVATION
            ],
            [
                0xc0286440, 0xc0386441, 0xc0286442, 0xc0206443, 0x40186444, 0x40886445, 0xc0306446,
                0x40186447, 0xc0286448, 0x40386449, 0xc048644a, 0x4020644b
            ]
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_xe",
        smoke_native_xe_ioctl_wire_numbers
    );
}
