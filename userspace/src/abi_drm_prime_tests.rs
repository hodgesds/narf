//! Linux DRM PRIME ioctl ABI — render-node import/export gate.
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
use narf_filesystem::{FileOps, FsFuture, Mode, Stat};

/// `_IOWR('d'=0x64, 0x2e, struct drm_prime_handle)` — 12-byte payload.
const DRM_IOCTL_PRIME_FD_TO_HANDLE: u64 = 0xC00C_642E;
/// Arbitrary non-zero GEM handle the fake dma-buf reports.
const FAKE_GEM_HANDLE: u32 = 0x4B57;

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
