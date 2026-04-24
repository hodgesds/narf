//! FUSE protocol — opcode + structure shapes for Stage-4 virtiofs.
//!
//! Spec: `filesystem/specification/spec.md` (Stage-4 virtiofs).
//! virtiofs-over-virtio speaks the FUSE protocol on the
//! request/response virtqueue. The kernel acts as a FUSE *client*
//! — it builds requests, submits them through the virtqueue, and
//! parses responses back into `narf_filesystem` types.
//!
//! This module pins the opcode table + the struct shapes that the
//! Stage-4 virtiofs driver will serialize/deserialize. No actual
//! virtqueue / DAX window plumbing — that lands with the real
//! driver body under `drivers/virtio/`.

/// FUSE opcode. Values match Linux `fuse_opcode` enum in
/// `include/uapi/linux/fuse.h` so the kernel can peer with a Linux
/// virtiofsd without translation.
#[non_exhaustive]
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FuseOpcode {
    Lookup      = 1,
    Forget      = 2,
    Getattr     = 3,
    Setattr     = 4,
    Readlink    = 5,
    Symlink     = 6,
    Mknod       = 8,
    Mkdir       = 9,
    Unlink      = 10,
    Rmdir       = 11,
    Rename      = 12,
    Link        = 13,
    Open        = 14,
    Read        = 15,
    Write       = 16,
    Statfs      = 17,
    Release     = 18,
    Fsync       = 20,
    Init        = 26,
    Destroy     = 38,
    ReadDir     = 28,
}

/// Header prepended to every FUSE request. Matches the wire layout
/// `struct fuse_in_header` in the Linux UAPI.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseInHeader {
    pub len:        u32,
    pub opcode:     u32,
    pub unique:     u64,
    pub nodeid:     u64,
    pub uid:        u32,
    pub gid:        u32,
    pub pid:        u32,
    pub _padding:   u32,
}

/// Header prepended to every FUSE response.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseOutHeader {
    pub len:      u32,
    pub error:    i32,   // 0 on success, -errno on failure
    pub unique:   u64,
}

/// FUSE_INIT request body. Client + server negotiate the protocol
/// version and feature set; NARF advertises support for only the
/// stable subset.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FuseInitIn {
    pub major:          u32,
    pub minor:          u32,
    pub max_readahead:  u32,
    pub flags:          u32,
}

/// FUSE_INIT response body.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FuseInitOut {
    pub major:          u32,
    pub minor:          u32,
    pub max_readahead:  u32,
    pub flags:          u32,
    pub max_background: u16,
    pub congestion_threshold: u16,
    pub max_write:      u32,
    pub time_gran:      u32,
    pub _reserved:      [u32; 9],
}

/// FUSE protocol version NARF negotiates. 7.36 covers everything
/// Linux virtiofsd speaks that we care about.
pub const FUSE_KERNEL_VERSION:      u32 = 7;
pub const FUSE_KERNEL_MINOR_VERSION: u32 = 36;

/// FUSE_INIT flags we request: writeback cache, posix locks, async
/// read. Values match the Linux FUSE UAPI.
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FuseInitFlag {
    AsyncRead     = 1 << 0,
    PosixLocks    = 1 << 1,
    FileOps       = 1 << 2,
    AtomicOTrunc  = 1 << 3,
    WritebackCache = 1 << 16,
}
