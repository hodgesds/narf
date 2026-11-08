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
pub const GEM_USERPTR: u32 = iowr(D, 0x73, 24);
pub const I915_USERPTR_READ_ONLY: u32 = 1 << 0;
pub const I915_USERPTR_PROBE: u32 = 1 << 1;
pub const I915_USERPTR_UNSYNCHRONIZED: u32 = 1 << 31;
pub const GEM_CONTEXT_GETPARAM: u32 = iowr(D, 0x74, 24);
pub const GEM_CONTEXT_SETPARAM: u32 = iowr(D, 0x75, 24);
pub const PERF_OPEN: u32 = iow(D, 0x76, 16);
pub const PERF_ADD_CONFIG: u32 = iow(D, 0x77, 72);
pub const PERF_REMOVE_CONFIG: u32 = iow(D, 0x78, 8);
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
pub const QUERY_PERF_CONFIG: u64 = 3;
pub const QUERY_PERF_CONFIG_LIST: u32 = 1;
pub const QUERY_PERF_CONFIG_DATA_FOR_UUID: u32 = 2;
pub const QUERY_PERF_CONFIG_DATA_FOR_ID: u32 = 3;
pub const QUERY_MEMORY_REGIONS: u64 = 4;
pub const QUERY_HWCONFIG: u64 = 5;
pub const QUERY_GEOMETRY_SUBSLICES: u64 = 6;
pub const QUERY_GUC_SUBMISSION_VERSION: u64 = 7;

pub const PARAM_PERF_REVISION: u32 = 54;

pub const PERF_PROP_CTX_HANDLE: u64 = 1;
pub const PERF_PROP_SAMPLE_OA: u64 = 2;
pub const PERF_PROP_OA_METRICS_SET: u64 = 3;
pub const PERF_PROP_OA_FORMAT: u64 = 4;
pub const PERF_PROP_OA_EXPONENT: u64 = 5;
pub const PERF_PROP_HOLD_PREEMPTION: u64 = 6;
pub const PERF_PROP_GLOBAL_SSEU: u64 = 7;
pub const PERF_PROP_POLL_OA_PERIOD: u64 = 8;
pub const PERF_PROP_OA_ENGINE_CLASS: u64 = 9;
pub const PERF_PROP_OA_ENGINE_INSTANCE: u64 = 10;

pub const EXEC_RENDER: u64 = 1;
pub const EXEC_BLT: u64 = 3;
pub const EXEC_BSD: u64 = 2;
pub const EXEC_VEBOX: u64 = 4;
pub const EXEC_BSD_SHIFT: u32 = 13;
pub const EXEC_BSD_MASK: u64 = 3 << EXEC_BSD_SHIFT;
pub const CONTEXT_PARAM_GTT_SIZE: u64 = 0x3;
pub const CONTEXT_PARAM_NO_ERROR_CAPTURE: u64 = 0x4;
pub const CONTEXT_PARAM_BANNABLE: u64 = 0x5;
pub const CONTEXT_PARAM_PRIORITY: u64 = 0x6;
pub const CONTEXT_PARAM_RECOVERABLE: u64 = 0x8;
pub const CONTEXT_PARAM_VM: u64 = 0x9;
pub const CONTEXT_PARAM_ENGINES: u64 = 0xa;
pub const CONTEXT_PARAM_PERSISTENCE: u64 = 0xb;
pub const CONTEXT_PARAM_PROTECTED_CONTENT: u64 = 0xd;
pub const CONTEXT_PARAM_LOW_LATENCY: u64 = 0xe;
pub const CONTEXT_ENGINES_EXT_LOAD_BALANCE: u32 = 0;
/// I915_ENGINE_CLASS_INVALID with I915_ENGINE_CLASS_INVALID_NONE: an empty
/// engine-map slot.
pub const ENGINE_INVALID: u16 = 0xffff;
pub const EXEC_SECURE: u64 = 1 << 9;
pub const EXEC_IS_PINNED: u64 = 1 << 10;
pub const EXEC_NO_RELOC: u64 = 1 << 11;
pub const EXEC_HANDLE_LUT: u64 = 1 << 12;
pub const EXEC_FENCE_IN: u64 = 1 << 16;
pub const EXEC_FENCE_OUT: u64 = 1 << 17;
pub const EXEC_BATCH_FIRST: u64 = 1 << 18;
pub const EXEC_FENCE_ARRAY: u64 = 1 << 19;
pub const EXEC_FENCE_SUBMIT: u64 = 1 << 20;
pub const EXEC_USE_EXTENSIONS: u64 = 1 << 21;

/// Execbuffer extension names (`drm_i915_gem_execbuffer_ext_*`,
/// include/uapi/drm/i915_drm.h). TIMELINE_FENCES = 0 is VERIFIED against the
/// kernel uAPI documentation rendered from that header. PERF = 1 is
/// UNVERIFIED: it is the next extension id in the series that added these
/// two extensions (timeline fences, then the perf config), in that order;
/// confirm against i915_drm.h before relying on the value on silicon.
pub const EXECBUFFER_EXT_TIMELINE_FENCES: u32 = 0;
pub const EXECBUFFER_EXT_PERF: u32 = 1;

/// `struct drm_i915_gem_execbuffer_ext_perf` wire layout: a 32-byte
/// `i915_user_extension` base, then `flags` (MBZ) and `oa_format`. The base
/// size is VERIFIED (see `user_extensions`); the field order after the base
/// is UNVERIFIED against the uAPI header — confirm before relying on it on
/// silicon. Offsets are byte offsets from the extension struct's start.
pub const EXECBUFFER_EXT_PERF_FLAGS_OFF: u64 = 32;
pub const EXECBUFFER_EXT_PERF_OA_FORMAT_OFF: u64 = 40;
pub const OBJECT_WRITE: u64 = 1 << 2;
pub const OBJECT_SUPPORTS_48B: u64 = 1 << 3;
pub const OBJECT_PINNED: u64 = 1 << 4;
pub const OBJECT_PAD_TO_SIZE: u64 = 1 << 5;
/// Skip only this object's prior implicit GPU dependencies; retain CPU fencing.
pub const OBJECT_ASYNC: u64 = 1 << 6;
/// Retain this BO range for bounded error-state payload capture.
pub const OBJECT_CAPTURE: u64 = 1 << 7;

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
            | GEM_USERPTR
            | GEM_CONTEXT_GETPARAM
            | GEM_CONTEXT_SETPARAM
            | QUERY
            | GEM_VM_CREATE
            | GEM_VM_DESTROY
            | GEM_CLOSE
            | PERF_OPEN
            | PERF_ADD_CONFIG
            | PERF_REMOVE_CONFIG
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

/// i915_user_extensions.c::i915_user_extensions' `stackdepth`: 512 links
/// are walked and the 513th is -E2BIG.
pub(crate) const USER_EXTENSIONS_DEPTH: usize = 512;

/// get_user of one `struct i915_user_extension` field.
fn extension_field<const N: usize>(
    user: &dyn narf_filesystem::IoctlContext,
    extension: u64,
    offset: u64,
) -> Result<[u8; N], narf_filesystem::FsError> {
    let mut field = [0; N];
    let address = extension
        .checked_add(offset)
        .ok_or(narf_filesystem::FsError::BadAddress)?;
    user.read(address, &mut field)?;
    Ok(field)
}

/// i915_user_extensions.c::i915_user_extensions over a chain of
/// `struct i915_user_extension { u64 next_extension; u32 name; u32 flags;
/// u32 rsvd[4]; }`, in its order. Per link: the stack-depth bound (-E2BIG;
/// there is no visited set, so a cycle ends here), check_user_mbz of flags
/// then of each rsvd word (each its own get_user: -EFAULT, then -EINVAL if
/// nonzero), get_user(name), the handler, and only then get_user of
/// next_extension. `handler(address, name)` is the caller's table: like
/// Linux it must answer -EINVAL for a name it has no entry for.
pub(crate) fn user_extensions(
    user: &dyn narf_filesystem::IoctlContext,
    mut extension: u64,
    mut handler: impl FnMut(u64, u32) -> Result<(), narf_filesystem::FsError>,
) -> Result<(), narf_filesystem::FsError> {
    use narf_filesystem::FsError;
    let mut stackdepth = USER_EXTENSIONS_DEPTH;
    while extension != 0 {
        if stackdepth == 0 {
            return Err(FsError::ArgumentListTooLong);
        }
        stackdepth -= 1;
        // flags at 12, then rsvd[0..4] at 16, 20, 24 and 28.
        for offset in [12, 16, 20, 24, 28] {
            if extension_field::<4>(user, extension, offset)? != [0; 4] {
                return Err(FsError::InvalidData);
            }
        }
        let name = u32::from_le_bytes(extension_field(user, extension, 8)?);
        handler(extension, name)?;
        extension = u64::from_le_bytes(extension_field(user, extension, 0)?);
    }
    Ok(())
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_filesystem::{FsError, IoctlContext};
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
            || GEM_USERPTR != 0xc018_6473
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

    const BASE: u64 = 0x10000;
    /// A synthetic user range from BASE to `limit`: `links` chained
    /// extensions 64 bytes apart (the last pointing back to BASE when
    /// `cycle`), every other byte zero except one `word` at an offset from
    /// BASE. Reads outside the range fault.
    struct Chain {
        links: u64,
        cycle: bool,
        limit: u64,
        word: Option<(u64, u32)>,
    }
    impl Chain {
        fn byte(&self, at: u64) -> u8 {
            let offset = at - BASE;
            if let Some((word, value)) = self.word {
                if (word..word + 4).contains(&offset) {
                    return value.to_le_bytes()[(offset - word) as usize];
                }
            }
            let (link, field) = (offset / 64, offset % 64);
            if link >= self.links || field >= 8 {
                return 0;
            }
            let next = if link + 1 < self.links {
                BASE + 64 * (link + 1)
            } else if self.cycle {
                BASE
            } else {
                0
            };
            next.to_le_bytes()[field as usize]
        }
        fn walk(&self, at: u64, verdict: Result<(), FsError>) -> (Result<(), FsError>, u32) {
            let mut calls = 0;
            let result = user_extensions(self, at, |address, name| {
                assert_eq!(address, BASE + 64 * u64::from(calls) % (64 * self.links));
                calls += 1;
                if name != 0 {
                    return Err(FsError::InvalidData);
                }
                verdict
            });
            (result, calls)
        }
    }
    impl IoctlContext for Chain {
        fn read(&self, address: u64, bytes: &mut [u8]) -> Result<(), FsError> {
            let end = address
                .checked_add(bytes.len() as u64)
                .ok_or(FsError::BadAddress)?;
            if address < BASE || end > self.limit {
                return Err(FsError::BadAddress);
            }
            for (at, byte) in (address..end).zip(bytes.iter_mut()) {
                *byte = self.byte(at);
            }
            Ok(())
        }
        fn write(&self, _: u64, _: &[u8]) -> Result<(), FsError> {
            Err(FsError::BadAddress)
        }
        fn nonblocking(&self) -> bool {
            false
        }
    }

    /// MIT Linux b90c984d i915_user_extensions.c::i915_user_extensions.
    fn smoke_i915_user_extensions_follow_linux_walk() -> TestResult {
        let chain = |links, cycle, limit, word| Chain {
            links,
            cycle,
            limit,
            word,
        };
        let open = BASE + 64 * 1024;
        // `if (!stackdepth--) return -E2BIG;` from 512: 512 links are
        // walked, the 513th is -E2BIG before any of it is read (here it is
        // unreadable), and there is no visited set, so a cycle of one or
        // two links also ends at -E2BIG after 512 handler calls.
        assert_eq!(
            chain(512, false, open, None).walk(BASE, Ok(())),
            (Ok(()), 512)
        );
        assert_eq!(
            chain(513, false, BASE + 64 * 512, None).walk(BASE, Ok(())),
            (Err(FsError::ArgumentListTooLong), 512)
        );
        for links in [1, 2] {
            assert_eq!(
                chain(links, true, open, None).walk(BASE, Ok(())),
                (Err(FsError::ArgumentListTooLong), 512)
            );
        }
        // check_user_mbz(&ext->flags) and then each rsvd word are separate
        // get_users: a nonzero word is -EINVAL even when a later one is
        // unreadable, an unreadable word -EFAULT; neither reaches the
        // handler.
        for (word, limit, expected) in [
            (Some((12, 1)), BASE + 16, FsError::InvalidData),
            (None, BASE + 16, FsError::BadAddress),
            (Some((16, 1)), BASE + 20, FsError::InvalidData),
            (None, BASE + 20, FsError::BadAddress),
            (Some((28, 1)), open, FsError::InvalidData),
        ] {
            assert_eq!(
                chain(1, false, limit, word).walk(BASE, Ok(())),
                (Err(expected), 0)
            );
        }
        // The name goes to the caller's table, whose missing entry is
        // -EINVAL; a later link is never read.
        assert_eq!(
            chain(2, false, BASE + 64, Some((8, 3))).walk(BASE, Ok(())),
            (Err(FsError::InvalidData), 1)
        );
        // next_extension is read only after the handler ran: an extension
        // whose first eight bytes are unreadable reaches its handler, whose
        // error wins, and is otherwise -EFAULT.
        let straddle = chain(0, false, open, None);
        let mut calls = 0;
        let result = user_extensions(&straddle, BASE - 8, |address, name| {
            assert_eq!((address, name), (BASE - 8, 0));
            calls += 1;
            Err(FsError::AlreadyExists)
        });
        assert_eq!((result, calls), (Err(FsError::AlreadyExists), 1));
        calls = 0;
        let result = user_extensions(&straddle, BASE - 8, |_, _| {
            calls += 1;
            Ok(())
        });
        assert_eq!((result, calls), (Err(FsError::BadAddress), 1));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_uapi",
        smoke_i915_user_extensions_follow_linux_walk
    );
}
