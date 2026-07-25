//! FUSE protocol — opcode + structure shapes for Stage-4 virtiofs.
//!
//! Spec: `filesystem/specification/spec.md` (Stage-4 virtiofs).
//! virtiofs-over-virtio speaks the FUSE protocol on the
//! request/response virtqueue. The kernel acts as a FUSE *client*
//! — it builds requests, submits them through the virtqueue, and
//! parses responses back into `narf_filesystem` types.
//!   <https://www.kernel.org/doc/html/latest/filesystems/fuse.html>
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
    Lookup = 1,
    Forget = 2,
    Getattr = 3,
    Setattr = 4,
    Readlink = 5,
    Symlink = 6,
    Mknod = 8,
    Mkdir = 9,
    Unlink = 10,
    Rmdir = 11,
    Rename = 12,
    Link = 13,
    Open = 14,
    Read = 15,
    Write = 16,
    Statfs = 17,
    Release = 18,
    Fsync = 20,
    Setxattr = 21,
    Getxattr = 22,
    Listxattr = 23,
    Removexattr = 24,
    Flush = 25,
    Init = 26,
    OpenDir = 27,
    ReadDir = 28,
    ReleaseDir = 29,
    FsyncDir = 30,
    Getlk = 31,
    Setlk = 32,
    Setlkw = 33,
    Access = 34,
    Create = 35,
    Interrupt = 36,
    Destroy = 38,
    Poll = 40,
    Fallocate = 43,
    Rename2 = 45,
    Lseek = 46,
    CopyFileRange = 47,
}

/// Header prepended to every FUSE request. Matches the wire layout
/// `struct fuse_in_header` in the Linux UAPI.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseInHeader {
    pub len: u32,
    pub opcode: u32,
    pub unique: u64,
    pub nodeid: u64,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub _padding: u32,
}

/// Header prepended to every FUSE response.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseOutHeader {
    pub len: u32,
    pub error: i32, // 0 on success, -errno on failure
    pub unique: u64,
}

/// FUSE_INIT request body. Client + server negotiate the protocol
/// version and feature set; NARF advertises support for only the
/// stable subset.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FuseInitIn {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
    pub flags2: u32,
    pub unused: [u32; 11],
}

/// FUSE_INIT response body.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FuseInitOut {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
    pub max_background: u16,
    pub congestion_threshold: u16,
    pub max_write: u32,
    pub time_gran: u32,
    pub max_pages: u16,
    pub map_alignment: u16,
    pub flags2: u32,
    pub max_stack_depth: u32,
    pub request_timeout: u16,
    pub unused: [u16; 11],
}

/// FUSE protocol version NARF negotiates. 7.36 covers everything
/// Linux virtiofsd speaks that we care about.
pub const FUSE_KERNEL_VERSION: u32 = 7;
pub const FUSE_KERNEL_MINOR_VERSION: u32 = 36;

/// FUSE_INIT flags we request: writeback cache, posix locks, async
/// read. Values match the Linux FUSE UAPI.
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FuseInitFlag {
    AsyncRead = 1 << 0,
    PosixLocks = 1 << 1,
    FileOps = 1 << 2,
    AtomicOTrunc = 1 << 3,
    BigWrites = 1 << 5,
    FlockLocks = 1 << 10,
    AsyncDio = 1 << 15,
    WritebackCache = 1 << 16,
    ParallelDirops = 1 << 18,
    MaxPages = 1 << 22,
    SetxattrExt = 1 << 29,
    InitExt = 1 << 30,
}

pub const FUSE_SUPPORTED_INIT_FLAGS: u32 = FuseInitFlag::AsyncRead as u32
    | FuseInitFlag::PosixLocks as u32
    | FuseInitFlag::BigWrites as u32
    | FuseInitFlag::FlockLocks as u32
    | FuseInitFlag::AsyncDio as u32
    | FuseInitFlag::ParallelDirops as u32
    | FuseInitFlag::MaxPages as u32
    | FuseInitFlag::SetxattrExt as u32
    | FuseInitFlag::InitExt as u32;

// ── Additional wire structs (Linux include/uapi/linux/fuse.h) ─────────
//
// These pin the request/response bodies the client marshals over the
// `/dev/fuse` transport for the ops `FuseFs` implements. Every layout is
// `#[repr(C)]` and matches the Linux UAPI field order + width exactly, so
// an in-kernel emulated daemon (the tests) and a real virtiofsd/libfuse
// daemon both parse them identically. Sizes are asserted in the kernel
// tests (`smoke_fs_fuse_struct_sizes`).

/// `struct fuse_attr` — the per-inode attributes returned by LOOKUP and
/// GETATTR. 88 bytes.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseAttr {
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub atimensec: u32,
    pub mtimensec: u32,
    pub ctimensec: u32,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
    pub blksize: u32,
    pub flags: u32,
}

/// `struct fuse_entry_out` — LOOKUP reply: a `nodeid` for the child plus
/// its attributes and the cache-validity timers. 128 bytes.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseEntryOut {
    pub nodeid: u64,
    pub generation: u64,
    pub entry_valid: u64,
    pub attr_valid: u64,
    pub entry_valid_nsec: u32,
    pub attr_valid_nsec: u32,
    pub attr: FuseAttr,
}

/// `struct fuse_attr_out` — GETATTR reply. 104 bytes.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseAttrOut {
    pub attr_valid: u64,
    pub attr_valid_nsec: u32,
    pub dummy: u32,
    pub attr: FuseAttr,
}

/// `struct fuse_getattr_in` — GETATTR request body. 16 bytes.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseGetattrIn {
    pub getattr_flags: u32,
    pub dummy: u32,
    pub fh: u64,
}

/// `struct fuse_open_in` — OPEN / OPENDIR request body. 8 bytes.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseOpenIn {
    pub flags: u32,
    pub open_flags: u32,
}

/// `struct fuse_open_out` — OPEN / OPENDIR reply: the daemon's file
/// handle. 16 bytes.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseOpenOut {
    pub fh: u64,
    pub open_flags: u32,
    pub padding: u32,
}

/// `struct fuse_read_in` — READ / READDIR request body. 40 bytes.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseReadIn {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
    pub read_flags: u32,
    pub lock_owner: u64,
    pub flags: u32,
    pub padding: u32,
}

/// `struct fuse_write_in` — WRITE request body (followed by the payload
/// bytes). 40 bytes.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseWriteIn {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
    pub write_flags: u32,
    pub lock_owner: u64,
    pub flags: u32,
    pub padding: u32,
}

/// `struct fuse_write_out` — WRITE reply: bytes actually written. 8 bytes.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseWriteOut {
    pub size: u32,
    pub padding: u32,
}

/// `struct fuse_kstatfs` nested in `struct fuse_statfs_out`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseKstatfs {
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub bsize: u32,
    pub namelen: u32,
    pub frsize: u32,
    pub padding: u32,
    pub spare: [u32; 6],
}

/// `struct fuse_statfs_out`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseStatfsOut {
    pub st: FuseKstatfs,
}

/// `struct fuse_mknod_in` — MKNOD request body.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseMknodIn {
    pub mode: u32,
    pub rdev: u32,
    pub umask: u32,
    pub padding: u32,
}

/// `struct fuse_mkdir_in` — MKDIR request body.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseMkdirIn {
    pub mode: u32,
    pub umask: u32,
}

/// `struct fuse_rename_in` — RENAME request prefix.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseRenameIn {
    pub newdir: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseRename2In {
    pub newdir: u64,
    pub flags: u32,
    pub padding: u32,
}

/// `struct fuse_link_in` — LINK request prefix.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseLinkIn {
    pub oldnodeid: u64,
}

/// `struct fuse_create_in` — CREATE request prefix.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseCreateIn {
    pub flags: u32,
    pub mode: u32,
    pub umask: u32,
    pub open_flags: u32,
}

/// `struct fuse_setattr_in` — SETATTR request body.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseSetattrIn {
    pub valid: u32,
    pub padding: u32,
    pub fh: u64,
    pub size: u64,
    pub lock_owner: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub atimensec: u32,
    pub mtimensec: u32,
    pub ctimensec: u32,
    pub mode: u32,
    pub unused4: u32,
    pub uid: u32,
    pub gid: u32,
    pub unused5: u32,
}

pub const FATTR_MODE: u32 = 1 << 0;
pub const FATTR_UID: u32 = 1 << 1;
pub const FATTR_GID: u32 = 1 << 2;
pub const FATTR_SIZE: u32 = 1 << 3;

/// `struct fuse_release_in` — RELEASE / RELEASEDIR request body. 24 bytes.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseReleaseIn {
    pub fh: u64,
    pub flags: u32,
    pub release_flags: u32,
    pub lock_owner: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseFlushIn {
    pub fh: u64,
    pub unused: u32,
    pub padding: u32,
    pub lock_owner: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseFsyncIn {
    pub fh: u64,
    pub fsync_flags: u32,
    pub padding: u32,
}

pub const FUSE_FSYNC_FDATASYNC: u32 = 1;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseSetxattrIn {
    pub size: u32,
    pub flags: u32,
    pub setxattr_flags: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseGetxattrIn {
    pub size: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseGetxattrOut {
    pub size: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseAccessIn {
    pub mask: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct FuseFileLock {
    pub start: u64,
    pub end: u64,
    pub type_: u32,
    pub pid: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseLkIn {
    pub fh: u64,
    pub owner: u64,
    pub lk: FuseFileLock,
    pub lk_flags: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseLkOut {
    pub lk: FuseFileLock,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseFallocateIn {
    pub fh: u64,
    pub offset: u64,
    pub length: u64,
    pub mode: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseLseekIn {
    pub fh: u64,
    pub offset: u64,
    pub whence: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseLseekOut {
    pub offset: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseCopyFileRangeIn {
    pub fh_in: u64,
    pub off_in: u64,
    pub nodeid_out: u64,
    pub fh_out: u64,
    pub off_out: u64,
    pub len: u64,
    pub flags: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseInterruptIn {
    pub unique: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FusePollIn {
    pub fh: u64,
    pub kh: u64,
    pub flags: u32,
    pub events: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FusePollOut {
    pub revents: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseNotifyPollWakeupOut {
    pub kh: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseNotifyInvalInodeOut {
    pub ino: u64,
    pub offset: i64,
    pub len: i64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseNotifyInvalEntryOut {
    pub parent: u64,
    pub namelen: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseNotifyDeleteOut {
    pub parent: u64,
    pub child: u64,
    pub namelen: u32,
    pub padding: u32,
}

pub const FUSE_POLL_SCHEDULE_NOTIFY: u32 = 1;
pub const FUSE_NOTIFY_POLL: i32 = 1;
pub const FUSE_NOTIFY_INVAL_INODE: i32 = 2;
pub const FUSE_NOTIFY_INVAL_ENTRY: i32 = 3;
pub const FUSE_NOTIFY_DELETE: i32 = 6;

/// `struct fuse_forget_in` — FORGET request body: the drop count for a
/// nodeid the client no longer caches. 8 bytes.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseForgetIn {
    pub nlookup: u64,
}

/// `struct fuse_dirent` header — one READDIR entry. The variable-length
/// name follows this 24-byte header and the whole record is padded up to
/// an 8-byte boundary (`FUSE_DIRENT_ALIGN`).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuseDirent {
    pub ino: u64,
    pub off: u64,
    pub namelen: u32,
    pub type_: u32,
}

/// Fixed size of the `fuse_dirent` header (name bytes follow).
pub const FUSE_DIRENT_HEADER_LEN: usize = core::mem::size_of::<FuseDirent>();

/// 8-byte alignment applied to each `fuse_dirent` record on the wire.
pub const FUSE_DIRENT_ALIGN: usize = 8;

/// Round `len` up to the next `FUSE_DIRENT_ALIGN` boundary.
pub const fn fuse_dirent_align(len: usize) -> usize {
    (len + FUSE_DIRENT_ALIGN - 1) & !(FUSE_DIRENT_ALIGN - 1)
}

/// The well-known root inode id. Linux fixes the FUSE root at nodeid 1.
pub const FUSE_ROOT_ID: u64 = 1;

// Linux `stat.st_mode` type bits — the daemon reports the full mode
// (type | perms) in `fuse_attr.mode`; the client masks with `S_IFMT` to
// recover the [`FileType`].
pub const S_IFMT: u32 = 0o170_000;
pub const S_IFDIR: u32 = 0o040_000;
pub const S_IFCHR: u32 = 0o020_000;
pub const S_IFIFO: u32 = 0o010_000;
pub const S_IFREG: u32 = 0o100_000;
pub const S_IFLNK: u32 = 0o120_000;
pub const S_IFSOCK: u32 = 0o140_000;

// ── Small (de)serialization helpers ───────────────────────────────────
//
// `#[repr(C)]` POD structs are copied to/from the byte transport with a
// plain memcpy. These helpers keep the `unsafe` at one audited place and
// return `None` on a short buffer rather than panicking on an
// out-of-bounds slice — a hostile or buggy daemon must never fault the
// kernel.

/// Reinterpret a POD `#[repr(C)]` value as its raw little-endian bytes.
///
/// # Safety
/// `T` must be a `#[repr(C)]` plain-old-data type with no padding-sensitive
/// invariants and no pointers/references — every bit pattern is a valid
/// wire value. All the `Fuse*` structs above satisfy this.
pub fn pod_as_bytes<T: Copy>(v: &T) -> alloc::vec::Vec<u8> {
    let len = core::mem::size_of::<T>();
    // SAFETY: `v` is a live `T` of exactly `len` bytes; we read it as an
    // immutable byte slice of that same length. `T: Copy` + the POD
    // contract above guarantees there are no niche/uninit bytes to expose.
    let slice = unsafe { core::slice::from_raw_parts(v as *const T as *const u8, len) };
    slice.to_vec()
}

/// Parse a POD `#[repr(C)]` value out of the front of `buf`. Returns
/// `None` if `buf` is shorter than `size_of::<T>()`.
pub fn pod_from_bytes<T: Copy>(buf: &[u8]) -> Option<T> {
    let len = core::mem::size_of::<T>();
    if buf.len() < len {
        return None;
    }
    // Read into an aligned local — `buf` is only byte-aligned, so a direct
    // `*(buf.as_ptr() as *const T)` would be an unaligned load (UB on some
    // targets). Copying through a `MaybeUninit<T>` sidesteps that.
    let mut val = core::mem::MaybeUninit::<T>::uninit();
    // SAFETY: `val` has room for exactly `len` bytes and `buf[..len]` is a
    // readable byte range of the same length; the copy fully initializes
    // `val`, and `T: Copy` POD makes any bit pattern a valid `T`.
    unsafe {
        core::ptr::copy_nonoverlapping(buf.as_ptr(), val.as_mut_ptr() as *mut u8, len);
        Some(val.assume_init())
    }
}
