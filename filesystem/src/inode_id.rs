//! Inode identity for files that are not backed by an on-disk inode.
//!
//! On Linux every open file has an inode on some superblock, and
//! `(st_dev, st_ino)` names it. Userspace relies on that pair being stable
//! and unique: `flock(2)` conflicts per inode, systemd compares a stream fd
//! against `$JOURNAL_STREAM`, `find`/`du`/`tar`/`rsync` detect hardlinks,
//! musl dedups shared objects, and fish notices `fish_variables` changing.
//!
//! Disk filesystems use their own inode numbers. Everything else follows
//! the Linux pseudo-filesystem model implemented here:
//!
//! * [`alloc_anon_dev`] is `get_anon_bdev`: one allocator for every
//!   anonymous `st_dev` (tmpfs mounts, pipefs, sockfs, ...), so two
//!   superblocks never share a device number.
//! * [`get_next_ino`] is `fs/inode.c::get_next_ino`: a nonzero counter for
//!   inodes created on pseudo filesystems (`new_inode_pseudo` users such as
//!   pipefs and sockfs).
//! * [`PseudoFs`] names the kernel-internal superblocks, each with its own
//!   lazily allocated anonymous `st_dev`.
//! * [`anon_inode`] is `fs/anon_inodes.c::anon_inode_inode`: the ONE inode
//!   shared by every `anon_inode_getfile` file (eventfd, epoll, signalfd,
//!   timerfd, inotify, ...). Linux really does report the same `st_ino` for
//!   all of them.

use core::sync::atomic::{AtomicU64, Ordering};

/// A file's inode identity: `(st_dev, st_ino)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InodeId {
    pub dev: u64,
    pub ino: u64,
}

impl InodeId {
    /// The `InodeAttrs` a `FileOps::inode_attrs` on this inode reports: just
    /// its `st_dev` (a pseudo inode tracks no links or separate times).
    pub fn attrs(self) -> crate::InodeAttrs {
        crate::InodeAttrs {
            dev: self.dev,
            ..Default::default()
        }
    }
}

static NEXT_ANON_MINOR: AtomicU64 = AtomicU64::new(1);

/// `get_anon_bdev`: a fresh anonymous device number (major 0), encoded as
/// Linux `new_encode_dev` does for major 0 — the low 8 bits of the minor
/// stay put and the rest moves above the 12-bit major field.
pub fn alloc_anon_dev() -> u64 {
    let minor = NEXT_ANON_MINOR.fetch_add(1, Ordering::Relaxed);
    (minor & 0xff) | ((minor & !0xff) << 12)
}

/// A superblock's anonymous `st_dev`, allocated from [`alloc_anon_dev`] on
/// first use and fixed afterwards. For singleton mounted pseudo filesystems
/// (procfs, sysfs, debugfs, ...) whose superblock is a `static`.
#[derive(Debug)]
pub struct LazyAnonDev(AtomicU64);

impl LazyAnonDev {
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    /// The device number, allocated on the first call.
    pub fn get(&self) -> u64 {
        let dev = self.0.load(Ordering::Acquire);
        if dev != 0 {
            return dev;
        }
        let fresh = alloc_anon_dev();
        match self
            .0
            .compare_exchange(0, fresh, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => fresh,
            Err(existing) => existing,
        }
    }
}

impl Default for LazyAnonDev {
    fn default() -> Self {
        Self::new()
    }
}

static NEXT_INO: AtomicU64 = AtomicU64::new(0);

/// `get_next_ino`: the next inode number for a pseudo-filesystem inode.
/// Never 0 (0 means "no inode" to userspace and to NARF's `FileOps::ino`).
/// Linux keeps it to 32 bits so a non-LFS `stat` does not EOVERFLOW; the
/// counter wraps the same way.
pub fn get_next_ino() -> u64 {
    loop {
        let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed).wrapping_add(1) & 0xffff_ffff;
        if ino != 0 {
            return ino;
        }
    }
}

/// Kernel-internal superblocks that files without a mounted filesystem
/// live on (Linux `kern_mount`ed pseudo filesystems).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PseudoFs {
    /// `pipefs`: pipe(2) inodes, one per pipe, shared by both ends.
    Pipe,
    /// `sockfs`: one inode per socket.
    Sock,
    /// `anon_inodefs`: eventfd, epoll, signalfd, timerfd, inotify, ...
    AnonInode,
    /// `pidfs`: pidfd inodes (Linux 6.9+), one per process.
    Pid,
    /// `nsfs`: namespace file inodes.
    Ns,
    /// `dmabuf` / DRM sync files and other driver-private anon files.
    DmaBuf,
    /// `shm_mnt`, the internal tmpfs `kern_mount` that `memfd_create`,
    /// SysV shm and shared anonymous mappings allocate inodes on
    /// (`mm/shmem.c::shmem_file_setup`). Not `/dev/shm`, which is a
    /// separate, user-visible tmpfs mount.
    Shm,
    /// `secretmem`: `memfd_secret(2)` inodes (`mm/secretmem.c`).
    SecretMem,
}

impl PseudoFs {
    fn slot(self) -> &'static AtomicU64 {
        static DEVS: [AtomicU64; 8] = [const { AtomicU64::new(0) }; 8];
        &DEVS[self as usize]
    }

    /// The superblock's `st_dev`, allocated on first use.
    pub fn dev(self) -> u64 {
        let slot = self.slot();
        let dev = slot.load(Ordering::Acquire);
        if dev != 0 {
            return dev;
        }
        let fresh = alloc_anon_dev();
        match slot.compare_exchange(0, fresh, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => fresh,
            Err(existing) => existing,
        }
    }

    /// A new inode on this superblock (`new_inode_pseudo` + `get_next_ino`).
    pub fn new_inode(self) -> InodeId {
        InodeId {
            dev: self.dev(),
            ino: get_next_ino(),
        }
    }
}

/// A new inode on `shm_mnt` (see [`PseudoFs::Shm`]).
///
/// `shmem_reserve_inode` numbers `SB_KERNMOUNT` inodes from the
/// superblock's own `next_ino` counter rather than `get_next_ino`, and — the
/// mount never being visible to a non-LFS `stat` — without the 32-bit
/// wrap; 0 is skipped (`is_zero_ino`).
pub fn shmem_kernel_inode() -> InodeId {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let mut ino = NEXT.fetch_add(1, Ordering::Relaxed);
    if ino == 0 {
        ino = NEXT.fetch_add(1, Ordering::Relaxed);
    }
    InodeId {
        dev: PseudoFs::Shm.dev(),
        ino,
    }
}

/// The single `anon_inodefs` inode every anonymous-inode file shares.
pub fn anon_inode() -> InodeId {
    static INO: AtomicU64 = AtomicU64::new(0);
    let mut ino = INO.load(Ordering::Acquire);
    if ino == 0 {
        let fresh = get_next_ino();
        ino = match INO.compare_exchange(0, fresh, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => fresh,
            Err(existing) => existing,
        };
    }
    InodeId {
        dev: PseudoFs::AnonInode.dev(),
        ino,
    }
}

mod tests {
    use narf_kernel_test::{kernel_test_in, TestResult};

    use super::{alloc_anon_dev, anon_inode, get_next_ino, PseudoFs};

    fn smoke_pseudo_inode_identity_is_linux_shaped() -> TestResult {
        let a = get_next_ino();
        let b = get_next_ino();
        if a == 0 || b == 0 || a == b {
            return TestResult::Fail("get_next_ino returned 0 or a repeat");
        }
        if PseudoFs::Pipe.dev() == 0 || PseudoFs::Pipe.dev() != PseudoFs::Pipe.dev() {
            return TestResult::Fail("a pseudo superblock's st_dev is 0 or unstable");
        }
        if PseudoFs::Pipe.dev() == PseudoFs::Sock.dev() {
            return TestResult::Fail("two pseudo superblocks share an st_dev");
        }
        if alloc_anon_dev() == PseudoFs::Pipe.dev() {
            return TestResult::Fail("a new anonymous device reused pipefs's st_dev");
        }
        let p = PseudoFs::Sock.new_inode();
        let q = PseudoFs::Sock.new_inode();
        if p.ino == q.ino || p.dev != q.dev {
            return TestResult::Fail("two sockfs inodes share an st_ino");
        }
        // Every anon-inode file shares one inode, as on Linux.
        if anon_inode() != anon_inode() || anon_inode().ino == 0 {
            return TestResult::Fail("the anon inode is not one stable nonzero inode");
        }
        if anon_inode().dev != PseudoFs::AnonInode.dev() {
            return TestResult::Fail("the anon inode is not on anon_inodefs");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "filesystem/inode_id",
        smoke_pseudo_inode_identity_is_linux_shaped
    );
}
