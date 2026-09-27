//! Linux DRM PRIME and VirtIO-GPU fence-fd ioctl ABI.
//!
//! Mesa opens the DRM **render** node (`/dev/dri/renderD1NN`) for its GBM/EGL
//! context and imports the compositor's scanout dma-buf THERE via
//! `DRM_IOCTL_PRIME_FD_TO_HANDLE`. `sys_ioctl` once gated both PRIME ioctls on
//! `ops.as_drm_card_index().is_some()` — a CARD-only check — so a render-node
//! import fell through to the driver dispatch → `-EOPNOTSUPP` →
//! `eglCreateImageKHR(EGL_LINUX_DMA_BUF_EXT)` = `EGL_BAD_ALLOC`, and kwin never
//! reached OpenGL compositing / modeset (the CachyOS greeter stayed black).
//!
//! These pin the fixed gate: `PRIME_FD_TO_HANDLE` on a render node resolves the
//! dma-buf's GEM handle, while a non-DRM fd is still rejected (the gate did not
//! become node-agnostic).
use crate::abi_test_support::*;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};
use narf_filesystem::{FileOps, FsFuture, Mode, Stat};

/// `_IOWR('d'=0x64, 0x2e, struct drm_prime_handle)` — 12-byte payload.
const DRM_IOCTL_PRIME_FD_TO_HANDLE: u64 = 0xC00C_642E;
/// `_IOWR('d'=0x64, 0x42, struct drm_virtgpu_execbuffer)` — 64 bytes.
const DRM_IOCTL_VIRTGPU_EXECBUFFER: u64 = 0xC040_6442;
const VIRTGPU_EXECBUF_FENCE_FD_IN: u32 = 0x01;
const VIRTGPU_EXECBUF_FENCE_FD_OUT: u32 = 0x02;
/// Arbitrary non-zero GEM handle the fake dma-buf reports.
const FAKE_GEM_HANDLE: u32 = 0x4B57;
static EXECBUFFER_CALLS: AtomicU32 = AtomicU32::new(0);

/// A minimal DRM render-node fd: it reports a render index (the card it renders
/// for) and nothing else — exactly what `DriRenderFile` exposes.
struct FakeRenderNode;
impl FileOps for FakeRenderNode {
    fn read<'a>(&'a self, _o: u64, _b: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Ok(0) })
    }
    fn write<'a>(&'a self, _o: u64, b: &'a [u8]) -> FsFuture<'a, usize> {
        let n = b.len();
        Box::pin(async move { Ok(n) })
    }
    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode::FILE_RO,
            mtime_cycles: 0,
        }
    }
    fn as_drm_render_index(&self) -> Option<u32> {
        Some(0)
    }
    fn ioctl(&self, cmd: u32, _arg: usize) -> Result<u64, narf_filesystem::FsError> {
        if cmd as u64 == DRM_IOCTL_VIRTGPU_EXECBUFFER {
            EXECBUFFER_CALLS.fetch_add(1, Ordering::Relaxed);
            Ok(0)
        } else {
            Err(narf_filesystem::FsError::Unsupported)
        }
    }
}

/// A minimal PRIME dma-buf fd: it reports the GEM handle it wraps, the way
/// `PrimeDmaBufFile` does.
struct FakeDmabuf;
impl FileOps for FakeDmabuf {
    fn read<'a>(&'a self, _o: u64, _b: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Ok(0) })
    }
    fn write<'a>(&'a self, _o: u64, b: &'a [u8]) -> FsFuture<'a, usize> {
        let n = b.len();
        Box::pin(async move { Ok(n) })
    }
    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode::FILE_RO,
            mtime_cycles: 0,
        }
    }
    fn as_prime_gem_handle(&self) -> Option<u32> {
        Some(FAKE_GEM_HANDLE)
    }
}

/// A plain fd with no DRM identity at all — the negative control.
struct FakePlain;
impl FileOps for FakePlain {
    fn read<'a>(&'a self, _o: u64, _b: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Ok(0) })
    }
    fn write<'a>(&'a self, _o: u64, b: &'a [u8]) -> FsFuture<'a, usize> {
        let n = b.len();
        Box::pin(async move { Ok(n) })
    }
    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode::FILE_RO,
            mtime_cycles: 0,
        }
    }
}

fn install_ops(ops: Arc<dyn FileOps>) -> Option<u32> {
    crate::fd::install(
        FAKE_TASK,
        crate::fd::FdEntry {
            ops,
            offset: 0,
            flags: 0,
            status_flags: crate::fd::O_RDWR,
        },
    )
}

/// `struct drm_prime_handle { u32 handle; u32 flags; s32 fd; }` (12 bytes,
/// LP64). `handle` (offset 0) is written out; `fd` (offset 8) is the dma-buf
/// fd passed in.
fn drm_prime_handle(dmabuf_fd: u32) -> [u8; 12] {
    let mut s = [0u8; 12];
    s[8..12].copy_from_slice(&dmabuf_fd.to_ne_bytes());
    s
}

/// `struct drm_virtgpu_execbuffer`, with `flags` at 0 and the shared input /
/// output `fence_fd` at byte offset 28.
fn virtgpu_execbuffer(flags: u32, fence_fd: i32) -> [u8; 64] {
    let mut execbuf = [0u8; 64];
    execbuf[0..4].copy_from_slice(&flags.to_ne_bytes());
    execbuf[28..32].copy_from_slice(&fence_fd.to_ne_bytes());
    execbuf
}

// PRIME_FD_TO_HANDLE on a RENDER node must resolve the dma-buf's GEM handle.
// The old card-only gate returned nothing here → EGL_BAD_ALLOC → black greeter.
fn smoke_abi_drm_prime_fd_to_handle_on_render_node() -> TestResult {
    with_setup(|| {
        let render_fd = install_ops(Arc::new(FakeRenderNode)).ok_or("install render node")?;
        let dmabuf_fd = install_ops(Arc::new(FakeDmabuf)).ok_or("install dmabuf")?;
        let mut s = drm_prime_handle(dmabuf_fd);
        let r = call(
            Syscall::Ioctl.raw(),
            a3(
                render_fd as u64,
                DRM_IOCTL_PRIME_FD_TO_HANDLE,
                s.as_mut_ptr() as u64,
                0,
            ),
        );
        if r != Some(0) {
            return Err(
                "PRIME_FD_TO_HANDLE on a render node must succeed (was the EGL_BAD_ALLOC root)",
            );
        }
        let handle = u32::from_ne_bytes([s[0], s[1], s[2], s[3]]);
        if handle != FAKE_GEM_HANDLE {
            return Err("PRIME import wrote the wrong GEM handle back");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_drm_prime_fd_to_handle_on_render_node
);

// A non-DRM fd must NOT be treated as a PRIME import: the gate skips it and the
// generic ioctl path rejects it. Guards against the gate becoming node-agnostic.
fn smoke_abi_drm_prime_fd_to_handle_rejects_non_drm_fd() -> TestResult {
    with_setup(|| {
        let plain_fd = install_ops(Arc::new(FakePlain)).ok_or("install plain fd")?;
        let dmabuf_fd = install_ops(Arc::new(FakeDmabuf)).ok_or("install dmabuf")?;
        let mut s = drm_prime_handle(dmabuf_fd);
        let r = call(
            Syscall::Ioctl.raw(),
            a3(
                plain_fd as u64,
                DRM_IOCTL_PRIME_FD_TO_HANDLE,
                s.as_mut_ptr() as u64,
                0,
            ),
        );
        if r == Some(0) {
            return Err("PRIME import must reject a non-DRM fd (gate too loose)");
        }
        let handle = u32::from_ne_bytes([s[0], s[1], s[2], s[3]]);
        if handle == FAKE_GEM_HANDLE {
            return Err("a non-DRM fd must not yield a GEM handle");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_drm_prime_fd_to_handle_rejects_non_drm_fd
);

// Linux drivers/gpu/drm/virtio/virtgpu_submit.c installs an O_CLOEXEC
// sync_file for FENCE_FD_OUT. NARF submissions finish synchronously, so the
// returned fence must be immediately POLLIN and reusable as FENCE_FD_IN.
fn smoke_abi_drm_virtgpu_execbuffer_signalled_out_fence() -> TestResult {
    with_setup(|| {
        EXECBUFFER_CALLS.store(0, Ordering::Relaxed);
        let render_fd = install_ops(Arc::new(FakeRenderNode)).ok_or("install render node")?;
        let mut execbuf = virtgpu_execbuffer(VIRTGPU_EXECBUF_FENCE_FD_OUT, -1);
        let r = call(
            Syscall::Ioctl.raw(),
            a3(
                render_fd as u64,
                DRM_IOCTL_VIRTGPU_EXECBUFFER,
                execbuf.as_mut_ptr() as u64,
                0,
            ),
        );
        if r != Some(0) || EXECBUFFER_CALLS.load(Ordering::Relaxed) != 1 {
            return Err("EXECBUFFER FENCE_FD_OUT did not submit exactly once");
        }
        let fence_fd = i32::from_ne_bytes(execbuf[28..32].try_into().unwrap());
        if fence_fd < 0 {
            return Err("EXECBUFFER did not return an output fence fd");
        }
        let fence_state = fd::with_table(FAKE_TASK, |table| {
            table.get(fence_fd as u32).map(|entry| {
                (
                    entry.flags,
                    entry.ops.poll_readiness(),
                    entry.ops.as_any().is_some(),
                )
            })
        })
        .flatten()
        .ok_or("output fence fd was not installed")?;
        if fence_state.0 & crate::fd::FD_CLOEXEC == 0 {
            return Err("output fence fd must be O_CLOEXEC");
        }
        if fence_state.1 != narf_filesystem::POLL_IN || !fence_state.2 {
            return Err("synchronous output fence must be a signalled sync file");
        }

        let mut reuse = virtgpu_execbuffer(VIRTGPU_EXECBUF_FENCE_FD_IN, fence_fd);
        let reused = call(
            Syscall::Ioctl.raw(),
            a3(
                render_fd as u64,
                DRM_IOCTL_VIRTGPU_EXECBUFFER,
                reuse.as_mut_ptr() as u64,
                0,
            ),
        );
        if reused != Some(0) || EXECBUFFER_CALLS.load(Ordering::Relaxed) != 2 {
            return Err("returned sync-file fd was not accepted as an input fence");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_drm_virtgpu_execbuffer_signalled_out_fence
);

// sync_file_get_fence() returns NULL for both an invalid descriptor and an fd
// of another type; virtio_gpu_wait_in_fence() maps either case to -EINVAL.
fn smoke_abi_drm_virtgpu_execbuffer_bad_in_fence_is_einval() -> TestResult {
    with_setup(|| {
        EXECBUFFER_CALLS.store(0, Ordering::Relaxed);
        let render_fd = install_ops(Arc::new(FakeRenderNode)).ok_or("install render node")?;
        let plain_fd = install_ops(Arc::new(FakePlain)).ok_or("install plain fd")?;
        for bad_fd in [-1, plain_fd as i32] {
            let mut execbuf = virtgpu_execbuffer(VIRTGPU_EXECBUF_FENCE_FD_IN, bad_fd);
            let r = call(
                Syscall::Ioctl.raw(),
                a3(
                    render_fd as u64,
                    DRM_IOCTL_VIRTGPU_EXECBUFFER,
                    execbuf.as_mut_ptr() as u64,
                    0,
                ),
            );
            if r != Some(EINVAL) {
                return Err("bad/non-sync EXECBUFFER input fence must be -EINVAL");
            }
        }
        if EXECBUFFER_CALLS.load(Ordering::Relaxed) != 0 {
            return Err("an invalid input fence must not submit GPU work");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_drm_virtgpu_execbuffer_bad_in_fence_is_einval
);

// Linux reserves the output descriptor before queueing the command. At
// RLIMIT_NOFILE, the ioctl therefore returns -EMFILE and performs no submit.
fn smoke_abi_drm_virtgpu_execbuffer_out_fence_emfile_before_submit() -> TestResult {
    with_setup(|| {
        EXECBUFFER_CALLS.store(0, Ordering::Relaxed);
        let render_fd = install_ops(Arc::new(FakeRenderNode)).ok_or("install render node")?;
        let limit = render_fd as u64 + 1;
        if !crate::handlers::__test_set_rlimit(FAKE_TASK, 7, limit, 4096) {
            return Err("lower RLIMIT_NOFILE for fence test");
        }
        let mut execbuf = virtgpu_execbuffer(VIRTGPU_EXECBUF_FENCE_FD_OUT, -1);
        let r = call(
            Syscall::Ioctl.raw(),
            a3(
                render_fd as u64,
                DRM_IOCTL_VIRTGPU_EXECBUFFER,
                execbuf.as_mut_ptr() as u64,
                0,
            ),
        );
        if r != Some(EMFILE) {
            return Err("EXECBUFFER output-fd exhaustion must be -EMFILE");
        }
        if EXECBUFFER_CALLS.load(Ordering::Relaxed) != 0 {
            return Err("EMFILE must prevent the GPU submission");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_drm_virtgpu_execbuffer_out_fence_emfile_before_submit
);
