//! Intel DRM wire ABI, shared by Xe-LP and Xe-LPG.
//!
//! Source: Linux `include/uapi/drm/i915_drm.h` (MIT), as published in
//! the kernel's DRM Driver uAPI documentation. These are wire definitions,
//! not the kernel-internal execlists engine-class numbering.

use crate::drm_uapi::{iow, iowr, DRM_IOCTL_BASE as D};

pub const GETPARAM: u32 = iowr(D, 0x46, 16);
pub const GEM_BUSY: u32 = iowr(D, 0x57, 8);
pub const GEM_THROTTLE: u32 = crate::drm_uapi::io(D, 0x58);
pub const GEM_CREATE: u32 = iowr(D, 0x5b, 16);
pub const GEM_PREAD: u32 = iow(D, 0x5c, 32);
pub const GEM_PWRITE: u32 = iow(D, 0x5d, 32);
pub const GEM_SET_DOMAIN: u32 = iow(D, 0x5f, 12);
pub const GEM_SW_FINISH: u32 = iow(D, 0x60, 4);
pub const GEM_SET_TILING: u32 = iowr(D, 0x61, 16);
pub const GEM_GET_TILING: u32 = iowr(D, 0x62, 16);
pub const GEM_GET_APERTURE: u32 = crate::drm_uapi::ior(D, 0x63, 16);
pub const GEM_MMAP_GTT: u32 = iowr(D, 0x64, 16);
pub const GEM_MMAP_OFFSET: u32 = iowr(D, 0x64, 32);
pub const GEM_MADVISE: u32 = iowr(D, 0x66, 12);
pub const GEM_EXECBUFFER2: u32 = iow(D, 0x69, 64);
pub const GEM_EXECBUFFER2_WR: u32 = iowr(D, 0x69, 64);
pub const GEM_WAIT: u32 = iowr(D, 0x6c, 16);
pub const GEM_CONTEXT_CREATE: u32 = iowr(D, 0x6d, 8);
pub const GEM_CONTEXT_CREATE_EXT: u32 = iowr(D, 0x6d, 16);
pub const GEM_CONTEXT_DESTROY: u32 = iow(D, 0x6e, 8);
pub const GEM_SET_CACHING: u32 = iow(D, 0x6f, 8);
pub const GEM_GET_CACHING: u32 = iowr(D, 0x70, 8);
pub const GET_RESET_STATS: u32 = iowr(D, 0x72, 24);
pub const GEM_CONTEXT_GETPARAM: u32 = iowr(D, 0x74, 24);
pub const GEM_CONTEXT_SETPARAM: u32 = iowr(D, 0x75, 24);
pub const QUERY: u32 = iowr(D, 0x79, 16);
pub const GEM_VM_CREATE: u32 = iowr(D, 0x7a, 16);
pub const GEM_VM_DESTROY: u32 = iow(D, 0x7b, 16);
pub const GEM_CREATE_EXT: u32 = iowr(D, 0x7c, 24);
pub const GEM_CLOSE: u32 = iow(D, 0x09, 8);

pub const ENGINE_RENDER: u16 = 0;
pub const ENGINE_COPY: u16 = 1;
pub const ENGINE_VIDEO: u16 = 2;
pub const ENGINE_VIDEO_ENHANCE: u16 = 3;
pub const ENGINE_COMPUTE: u16 = 4;
pub const QUERY_TOPOLOGY: u64 = 1;
pub const QUERY_ENGINES: u64 = 2;
pub const QUERY_MEMORY_REGIONS: u64 = 4;
pub const QUERY_HWCONFIG: u64 = 5;
pub const QUERY_GEOMETRY_SUBSLICES: u64 = 6;
pub const QUERY_GUC_SUBMISSION_VERSION: u64 = 7;

pub const EXEC_RENDER: u64 = 1;
pub const EXEC_BLT: u64 = 3;
pub const CONTEXT_PARAM_ENGINES: u64 = 0xa;
pub const CONTEXT_ENGINES_EXT_LOAD_BALANCE: u32 = 0;
/// I915_ENGINE_CLASS_INVALID with I915_ENGINE_CLASS_INVALID_NONE: an empty
/// engine-map slot.
pub const ENGINE_INVALID: u16 = 0xffff;
pub const EXEC_NO_RELOC: u64 = 1 << 11;
pub const EXEC_HANDLE_LUT: u64 = 1 << 12;
pub const EXEC_FENCE_IN: u64 = 1 << 16;
pub const EXEC_FENCE_OUT: u64 = 1 << 17;
pub const EXEC_BATCH_FIRST: u64 = 1 << 18;
pub const EXEC_FENCE_ARRAY: u64 = 1 << 19;
pub const EXEC_FENCE_SUBMIT: u64 = 1 << 20;
pub const EXEC_USE_EXTENSIONS: u64 = 1 << 21;
pub const OBJECT_WRITE: u64 = 1 << 2;
pub const OBJECT_SUPPORTS_48B: u64 = 1 << 3;
pub const OBJECT_PINNED: u64 = 1 << 4;
pub const OBJECT_PAD_TO_SIZE: u64 = 1 << 5;

/// Exact wire encodings accepted alongside Xe on a production GuC card.
/// Number-only routing is ambiguous (for example GETPARAM/QUEUE_CREATE).
pub(crate) fn compatibility_ioctl(cmd: u32) -> bool {
    matches!(
        cmd,
        GETPARAM
            | GEM_BUSY
            | GEM_THROTTLE
            | GEM_CREATE
            | GEM_CREATE_EXT
            | GEM_PREAD
            | GEM_PWRITE
            | GEM_SET_DOMAIN
            | GEM_SW_FINISH
            | GEM_SET_TILING
            | GEM_GET_TILING
            | GEM_GET_APERTURE
            | GEM_MMAP_GTT
            | GEM_MMAP_OFFSET
            | GEM_MADVISE
            | GEM_EXECBUFFER2
            | GEM_EXECBUFFER2_WR
            | GEM_WAIT
            | GEM_CONTEXT_CREATE
            | GEM_CONTEXT_CREATE_EXT
            | GEM_CONTEXT_DESTROY
            | GEM_SET_CACHING
            | GEM_GET_CACHING
            | GET_RESET_STATS
            | GEM_CONTEXT_GETPARAM
            | GEM_CONTEXT_SETPARAM
            | QUERY
            | GEM_VM_CREATE
            | GEM_VM_DESTROY
            | GEM_CLOSE
    )
}

/// Fixed little-endian wire accessors avoid Rust layout/padding in user copies.
pub(crate) fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("fixed UAPI field"))
}
pub(crate) fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("fixed UAPI field"))
}
pub(crate) fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
pub(crate) fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_i915_ioctl_wire_numbers() -> TestResult {
        // Literal Linux asm-generic encodings; do not regenerate from ioc().
        if GETPARAM != 0xc010_6446
            || GEM_CREATE != 0xc010_645b
            || GEM_PREAD != 0x4020_645c
            || GEM_PWRITE != 0x4020_645d
            || GEM_MMAP_GTT != 0xc010_6464
            || GEM_MMAP_OFFSET != 0xc020_6464
            || GEM_EXECBUFFER2 != 0x4040_6469
            || GEM_EXECBUFFER2_WR != 0xc040_6469
            || GEM_CONTEXT_CREATE != 0xc008_646d
            || GEM_CONTEXT_CREATE_EXT != 0xc010_646d
            || QUERY != 0xc010_6479
            || GEM_CREATE_EXT != 0xc018_647c
        {
            return TestResult::Fail("i915 ioctl wire encoding");
        }
        if [
            ENGINE_RENDER,
            ENGINE_COPY,
            ENGINE_VIDEO,
            ENGINE_VIDEO_ENHANCE,
            ENGINE_COMPUTE,
        ] != [0, 1, 2, 3, 4]
        {
            return TestResult::Fail("UAPI engine classes differ from execlists classes");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_uapi", smoke_i915_ioctl_wire_numbers);
}
