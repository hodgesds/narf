//! narf-filesystem — VFS core, path resolution, mount tree, initramfs.
//!
//! Spec: `filesystem/specification/spec.md`. Stage-3 scope per
//! `STAGE3.md` §"What deliberately does not land in Stage 3" / per-spec
//! §7: VFS trait surface, scoped path resolution, open/read/write/stat,
//! a read-only in-memory initramfs (CPIO newc), and a virtiofs mount
//! skeleton whose ops are `unimplemented!()` until Stage 4 wires the
//! DAX shared-region protocol.
//!
//! What lands in Stage 3:
//! - `NodeRef` / `DirNodeRef`: cap-type markers (→ `CapKind::FileNode` /
//!   `CapKind::DirNode`) so file/directory handles ride the same
//!   `Cap<T, R>` machinery the rest of the kernel uses.
//! - `FsInstance` trait: every concrete filesystem exposes `root()` +
//!   `name()`. Mounted instances are owned by `VfsRegistry`.
//! - `FileOps` / `DirOps`: async I/O contract. Returns
//!   `Pin<Box<dyn Future<Output = …> + '_>>` because trait-method
//!   `impl Future` is not object-safe — same trick `drivers/`'s
//!   `DriverFuture<'a>` uses.
//! - `Stat`: size / blocks / mode / mtime in monotonic cycles
//!   (`narf_time::Instant::as_cycles`).
//! - `FsError`: `NotFound`, `PermissionDenied`, `Io(BlockError)`,
//!   `InvalidPath`, `Busy`, `ReadOnly`, `Unsupported`. `From<CapError>`
//!   collapses revocation onto `PermissionDenied` so the cap-gated
//!   mount path surfaces a meaningful FS error.
//! - `resolve(root, path)`: walks an ASCII path segment-by-segment.
//!   Stage 3 rejects `..` (no parent traversal) and rejects leading
//!   `/` because the supplied `root` *is* the mount root — the
//!   no-ambient-root invariant from §4 of the spec.
//! - `VfsRegistry`: global, cap-gated `mount` / `unmount`. The
//!   authority is a `Cap<MountPoint, Grant>`; per-mount handle is a
//!   `Cap<MountPoint, Write>` — same authority/handle split the
//!   `drivers/` and `net/` registries use. Revoking the authority
//!   short-circuits `mount` with `FsError::PermissionDenied`.
//! - `Initramfs`: read-only in-memory FS built from a `&'static [u8]`
//!   CPIO newc archive. Files share storage with the archive — zero
//!   copy on `read`. The format choice is deliberate: CPIO newc has
//!   fixed-width hex headers that parse without an arithmetic crate
//!   (TAR's octal fields are easy too, but CPIO's `070701` magic +
//!   13 hex fields = trivially-skimmable).
//! - `VirtiofsMount`: skeleton `FsInstance` whose root's ops all
//!   `unimplemented!()`. Stage 4 wires the DAX shared-region transport
//!   from `drivers/virtio/` + `io/`.
//!
//! Non-goals for Stage 3 (Stage 4 / later):
//! - Symlinks + symlink-bound resolution (spec §3.2).
//! - Parent traversal (`..`) and Unicode normalisation (spec §4).
//! - Page cache (spec §3.7) — unified cache lands with virtiofs.
//! - Dentry cache wired to sleepable RCU (spec §6).
//! - virtiofs DAX protocol — only the skeleton ships now.
//! - Permission checking beyond the cap-gate stub at `mount` time.
//! - mmap, quotas, xattrs, rename, link, mkdir, unlink — Stage 4+.
//! - `block/`-backed loaders. The initramfs sits above `block/`'s API
//!   surface but does not consume it; the byte slice comes from the
//!   bootloader's initramfs region (Stage 4 hands that in).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod devfs;
pub mod fuse;
pub mod memfs;
pub mod page_cache;

mod tests;
pub use devfs::{mount_default as mount_devfs_default, DevFs};
pub use fuse::{
    FuseInHeader, FuseInitFlag, FuseInitIn, FuseInitOut, FuseOpcode, FuseOutHeader,
    FUSE_KERNEL_MINOR_VERSION, FUSE_KERNEL_VERSION,
};
pub use memfs::{new_anon_file as new_anon_memfile, MemFs};
pub use page_cache::{Page, PageCache, PageKey, PAGE_SIZE};

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::future::Future;
use core::pin::Pin;

use narf_block::BlockError;
use narf_capabilities::{Cap, CapError, CapKind, CapType, Grant, Write};
use narf_lib::sync::IrqSafeSpinLock;

// ── Cap-type markers ────────────────────────────────────────────────

/// Cap marker for a file node. Held as `Cap<NodeRef, R>` where `R`
/// is the rights tier (Stage 3 uses the base `Read` / `Write` /
/// `Grant` set). Maps to `CapKind::FileNode`.
#[derive(Debug)]
pub struct NodeRef;
impl CapType for NodeRef {
    const KIND: CapKind = CapKind::FileNode;
}

/// Cap marker for a directory node. Maps to `CapKind::DirNode`.
#[derive(Debug)]
pub struct DirNodeRef;
impl CapType for DirNodeRef {
    const KIND: CapKind = CapKind::DirNode;
}

/// Cap marker for a mount point. Maps to `CapKind::MountPoint`. The
/// `Grant`-rights flavour is the registry authority; `Write`-rights
/// flavours are returned per successful mount and authorise unmount.
#[derive(Debug)]
pub struct MountPoint;
impl CapType for MountPoint {
    const KIND: CapKind = CapKind::MountPoint;
}

/// Cap marker for a filesystem instance. Maps to `CapKind::FsInstance`.
/// Stage 3 doesn't mint `Cap<FsInstanceMarker, _>` outside the registry
/// itself, but the marker exists so Stage 4 can attach an
/// `FsInstance`-rooted `Cap<…, Attach>` per spec §3.5.
#[derive(Debug)]
pub struct FsInstanceMarker;
impl CapType for FsInstanceMarker {
    const KIND: CapKind = CapKind::FsInstance;
}

// ── Stat / FileType ─────────────────────────────────────────────────

/// File-type discriminant. Stage 3 only ever produces `File` or `Dir`;
/// `Symlink` and `Special` are reserved for Stage 4.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FileType {
    File,
    Dir,
    Symlink,
    Special,
}

/// Stat result. `mode` is a stub: Stage 3 reports `(FileType, perms)`
/// where `perms` is a low-9-bit POSIX-style triplet only for parity
/// with what userspace will eventually expect — the kernel does no
/// permission check off it. `mtime_cycles` is monotonic-clock cycles
/// from `narf_time::Instant::as_cycles`; wall-clock time is Stage 4.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Stat {
    pub size: u64,
    pub blocks: u64,
    pub mode: Mode,
    pub mtime_cycles: u64,
}

/// Combined `(FileType, perms)` mode word.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Mode {
    pub file_type: FileType,
    /// Low 9 bits: rwxrwxrwx. Stage 3 ignores these on access — the
    /// cap on the open file is the real check.
    pub perms: u16,
}

impl Mode {
    pub const FILE_RO: Mode = Mode {
        file_type: FileType::File,
        perms: 0o444,
    };
    pub const FILE_RW: Mode = Mode {
        file_type: FileType::File,
        perms: 0o666,
    };
    pub const DIR_RO: Mode = Mode {
        file_type: FileType::Dir,
        perms: 0o555,
    };
    pub const DIR_RW: Mode = Mode {
        file_type: FileType::Dir,
        perms: 0o777,
    };
}

// ── Errors ─────────────────────────────────────────────────────────

/// Filesystem error surface. `Io` wraps `block/`'s error so a backing
/// store failure surfaces with context preserved.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FsError {
    NotFound,
    PermissionDenied,
    Io(BlockError),
    InvalidPath,
    Busy,
    ReadOnly,
    NoSpace,
    /// The backing FS doesn't implement this op (e.g. virtiofs skeleton
    /// pre-Stage-4).
    Unsupported,
}

impl From<CapError> for FsError {
    /// Cap-side errors collapse to `PermissionDenied` at the FS layer.
    /// Spec §4: a revoked mount cap should refuse further access via
    /// that path. The distinction between `Revoked` and `RightsTooWeak`
    /// is preserved at the cap layer; FS callers only need "no".
    fn from(_: CapError) -> Self {
        FsError::PermissionDenied
    }
}

// ── Async trait future alias ───────────────────────────────────────
//
// `dyn FileOps`/`dyn DirOps` cannot host `impl Future`-returning
// methods (not object-safe), so we surface the same `Pin<Box<dyn …>>`
// shape `drivers/` uses for `DriverFuture<'a>`. Wave-N may swap to
// `async-trait`-style return-position-impl-trait once stabilised.

/// Future returned by every async file/dir op.
pub type FsFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, FsError>> + Send + 'a>>;

// ── Directory entry ────────────────────────────────────────────────

/// One entry returned by `DirOps::iter`. Stage 3 keeps the name as
/// `&'static str` because the only producer is the initramfs (whose
/// names live in the `&'static [u8]` archive). Stage 4 will widen this
/// to an owned `String` once persistent FSes appear.
#[derive(Copy, Clone, Debug)]
pub struct DirEntry {
    pub name: &'static str,
    pub file_type: FileType,
}

// ── FileOps / DirOps ───────────────────────────────────────────────

/// Per-file async op surface. Methods take `&self` because a file
/// node may be looked up concurrently from multiple tasks; per-file
/// state (e.g. an offset cursor) lives in the *handle*, not here.
pub trait FileOps: Send + Sync {
    /// Read up to `buf.len()` bytes starting at `offset`. Short reads
    /// (returning `< buf.len()`) signify EOF on Stage-3 in-memory
    /// FSes; Stage 4 disk-backed FSes may also short-read on a torn
    /// page boundary and the caller is expected to loop.
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize>;

    /// Write `buf` at `offset`. Returns `FsError::ReadOnly` for the
    /// initramfs and the virtiofs skeleton.
    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize>;

    /// Synchronous stat — every Stage-3 FS knows its file size + mtime
    /// cheaply.
    fn stat(&self) -> Stat;

    /// Asynchronous stat — required for disk-backed or remote FS.
    fn stat_async<'a>(&'a self) -> FsFuture<'a, Stat> {
        Box::pin(async move { Ok(self.stat()) })
    }

    /// Resize the file to exactly `len` bytes. Growing zero-fills;
    /// shrinking truncates.
    fn truncate<'a>(&'a self, _len: u64) -> FsFuture<'a, ()> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }
}

/// Per-directory async op surface. `lookup` is synchronous because
/// the only Stage-3 directory implementation (initramfs) is a flat
/// in-memory map; Stage 4 backing-store directories will need an
/// async variant — `lookup_async` will land alongside virtiofs.
pub trait DirOps: Send + Sync {
    /// Resolve a single name component. Returns `None` if absent.
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>>;

    /// Look up a child as a directory (so multi-segment `resolve`
    /// can descend without round-tripping through `Arc<dyn FileOps>`).
    /// Stage 3 only has flat directories at the top level so the
    /// default returns `None`; the initramfs nests via `/`-in-name
    /// (CPIO encodes paths whole), not via subdirectory entries.
    fn lookup_dir(&self, _name: &str) -> Option<Arc<dyn DirOps>> {
        None
    }

    /// Iterate this directory. Stage 3 returns a boxed iterator so the
    /// trait stays object-safe; an `impl Iterator` shape would force
    /// a GAT. Names are `&'static str` per `DirEntry`'s comment.
    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a>;

    /// Snapshot up-to `max` entries starting at `cursor` and return
    /// them as `(owned_name, file_type)` pairs. Default impl walks
    /// `iter()` and clones each entry's `&'static str` to a `String`.
    /// Filesystems whose names live in non-static storage (e.g. the
    /// `MemFs` `BTreeMap<String, _>`) override this to return their
    /// real entries — `iter()` still returns empty for those, since
    /// the trait's `&'static str` payload can't be synthesised.
    ///
    /// Used by `sys_listdir` (kernel readdir surface). Cheap: a
    /// few dozen Strings per call at the typical scale.
    fn enumerate(
        &self,
        cursor: usize,
        max: usize,
    ) -> alloc::vec::Vec<(alloc::string::String, FileType)> {
        use alloc::string::ToString;
        self.iter()
            .skip(cursor)
            .take(max)
            .map(|de| (de.name.to_string(), de.file_type))
            .collect()
    }

    /// Resolve a single name component asynchronously.
    fn lookup_async<'a>(&'a self, _name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }

    /// Look up a child as a directory asynchronously.
    fn lookup_dir_async<'a>(&'a self, _name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }

    /// Snapshot entries asynchronously.
    fn enumerate_async<'a>(&'a self, _cursor: usize, _max: usize) -> FsFuture<'a, alloc::vec::Vec<(alloc::string::String, FileType)>> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }

    // ── Stage-4 r/w surface ──────────────────────────────────────

    /// Remove the file entry named `name` from this directory.
    fn unlink<'a>(&'a self, _name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }

    /// Create a new empty file named `name` and return a handle.
    fn create<'a>(&'a self, _name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }

    /// Create a new empty subdirectory named `name`.
    fn mkdir<'a>(&'a self, _name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }

    /// Remove the empty subdirectory named `name`.
    fn rmdir<'a>(&'a self, _name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }

    /// Create a symlink entry named `name` pointing at the textual
    /// `target` path.
    fn symlink<'a>(&'a self, _name: &'a str, _target: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }

    /// Rename the entry `old_name` to `new_name` within this
    /// directory.
    fn rename<'a>(&'a self, _old_name: &'a str, _new_name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }
}

// ── FsInstance ─────────────────────────────────────────────────────

/// One mounted filesystem.
pub trait FsInstance: Send + Sync + 'static {
    /// Root directory. Path resolution starts here for any path under
    /// the mount.
    fn root(&self) -> Arc<dyn DirOps>;
    /// Human-readable name (for logging + lookups). Must remain
    /// stable across the FS's lifetime.
    fn name(&self) -> &str;
}

// ── Path resolution ────────────────────────────────────────────────

/// Resolve a slash-separated relative path against `root`. Stage-3
/// rules (per spec §4):
///
/// - Reject leading `/` — `root` IS the mount root, no ambient root
///   exists for resolution to escape into.
/// - Reject `..` — parent traversal is Stage 4 (spec §3.2 calls out
///   resolver-scope guarantees that the Stage-3 walker doesn't yet
///   need to enforce because it can't walk up).
/// - Reject empty path. The caller already has `root`; opening an
///   empty path is a programming error, not "open the root".
/// - Empty segments (consecutive `/`) and a single trailing `/` are
///   tolerated — common in user-supplied paths.
/// - ASCII-only at the byte level. We don't reject non-ASCII (the
///   archive may carry UTF-8 names) but we don't normalise either.
///
/// Returns the file at the leaf. Stage 3 has no `lookup_dir` traffic
/// because the initramfs is single-level — every CPIO entry is a leaf
/// directly under the root.
pub fn resolve(root: Arc<dyn DirOps>, path: &str) -> Result<Arc<dyn FileOps>, FsError> {
    if path.is_empty() {
        return Err(FsError::InvalidPath);
    }
    if path.as_bytes()[0] == b'/' {
        return Err(FsError::InvalidPath);
    }

    let mut current_dir = root;
    let mut last_component: Option<&str> = None;

    for segment in path.split('/') {
        if segment.is_empty() {
            continue;
        } // tolerate //
        if segment == ".." {
            return Err(FsError::InvalidPath);
        }
        if segment == "." {
            continue;
        } // tolerate .

        // Hold the previous "leaf candidate" — if there's another
        // segment after it, it has to have been a directory.
        if let Some(prev) = last_component.take() {
            match current_dir.lookup_dir(prev) {
                Some(d) => current_dir = d,
                None => return Err(FsError::NotFound),
            }
        }
        last_component = Some(segment);
    }

    let leaf = last_component.ok_or(FsError::InvalidPath)?;
    current_dir.lookup(leaf).ok_or(FsError::NotFound)
}

/// Resolve a relative path asynchronously.
pub fn resolve_async<'a>(root: Arc<dyn DirOps>, path: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
    Box::pin(async move {
        if path.is_empty() {
            return Err(FsError::InvalidPath);
        }
        if path.as_bytes()[0] == b'/' {
            return Err(FsError::InvalidPath);
        }

        let mut current_dir = root;
        let mut components: Vec<&str> = path.split('/').filter(|s| !s.is_empty() && *s != ".").collect();
        
        if components.is_empty() {
             return Err(FsError::InvalidPath);
        }

        let last = components.pop().unwrap();

        for segment in components {
            if segment == ".." {
                return Err(FsError::InvalidPath);
            }
            current_dir = current_dir.lookup_dir_async(segment).await?;
        }

        current_dir.lookup_async(last).await
    })
}

// ── Mount + VfsRegistry ────────────────────────────────────────────

/// One mount in the global mount table. Owns the `FsInstance` (so
/// dropping the mount drops the FS) and the path it's mounted at.
/// Path is stored as `&'static str` for Stage-3 simplicity — every
/// mount in the harness today is mount-once-at-boot.
pub struct Mount {
    pub path: &'static str,
    pub fs: Arc<dyn FsInstance>,
    pub handle: Cap<MountPoint, Write>,
}

impl fmt::Debug for Mount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mount")
            .field("path", &self.path)
            .field("fs", &self.fs.name())
            .finish_non_exhaustive()
    }
}

/// Global VFS mount registry. Mirrors the cap-gate pattern used by
/// `drivers/` + `net/`: an `IrqSafeSpinLock<Vec<Mount>>` is fine
/// because mount/unmount are control-plane events, not data-plane.
#[derive(Debug)]
pub struct VfsRegistry {
    inner: IrqSafeSpinLock<Vec<Mount>>,
}

static REGISTRY: VfsRegistry = VfsRegistry {
    inner: IrqSafeSpinLock::new(Vec::new()),
};

/// Reference the global VFS registry.
#[inline]
pub fn registry() -> &'static VfsRegistry {
    &REGISTRY
}

/// Bootstrap the mount-authority cap. TCB-only path — the kernel
/// calls this once at boot and hands the result to whatever subsystem
/// actually mounts the initial root.
pub fn bootstrap_mount_authority() -> Cap<MountPoint, Grant> {
    Cap::<MountPoint, Grant>::bootstrap()
}

impl VfsRegistry {
    /// Mount `fs` at `path`. The `authority` cap is checked live;
    /// a revoked authority returns `FsError::PermissionDenied`
    /// (via the `From<CapError>` impl) before any side effect.
    /// Duplicate-path mounts return `FsError::Busy` — Stage 4 will
    /// add bind-mount semantics under a separate `mount_bind` entry.
    pub fn mount<F: FsInstance>(
        &self,
        authority: &Cap<MountPoint, Grant>,
        path: &'static str,
        fs: F,
    ) -> Result<Cap<MountPoint, Write>, FsError> {
        authority.check_live()?;

        let mut q = self.inner.lock();
        if q.iter().any(|m| m.path == path) {
            return Err(FsError::Busy);
        }
        let handle: Cap<MountPoint, Write> = Cap::<MountPoint, Write>::bootstrap();
        let arc: Arc<dyn FsInstance> = Arc::new(fs);
        q.push(Mount {
            path,
            fs: arc,
            handle,
        });
        Ok(handle)
    }

    /// Unmount the FS at `path`. The `handle` cap must be live and
    /// must be the one returned from the matching `mount`. A revoked
    /// handle surfaces as `PermissionDenied`. Holding the lock across
    /// the comparison guarantees the unmount and the handle-match are
    /// observed atomically — no two concurrent unmounts can race on
    /// the same slot.
    pub fn unmount(&self, handle: &Cap<MountPoint, Write>, path: &str) -> Result<(), FsError> {
        handle.check_live()?;

        let mut q = self.inner.lock();
        let pos = q
            .iter()
            .position(|m| m.path == path)
            .ok_or(FsError::NotFound)?;
        // Stage 3 doesn't track in-flight ops against a mount, so we
        // pop the entry directly. Stage 4 needs a refcount drain
        // (per spec §3.5) before the FS object goes away.
        let m = q.swap_remove(pos);
        // Drop the FS Arc outside the lock to keep the critical
        // section short — important once page-cache eviction lands.
        drop(q);
        drop(m);
        Ok(())
    }

    /// Run `f` against the named mount's `FsInstance`. Returns `None`
    /// if no mount matches. The lock is held across `f`; `f` should be
    /// short.
    pub fn with_mount<R, F>(&self, path: &str, f: F) -> Option<R>
    where
        F: FnOnce(&dyn FsInstance) -> R,
    {
        let q = self.inner.lock();
        q.iter().find(|m| m.path == path).map(|m| f(&*m.fs))
    }

    /// Resolve a POSIX-shaped absolute path by finding the
    /// longest mount-prefix match and running `f` against the
    /// matching FS with the remaining suffix (leading `/`
    /// stripped). Returns `None` when no mount covers the path.
    ///
    /// Examples (with `/test` and `/test/sub` both mounted):
    ///   `/test/foo`     → `/test`     + `foo`
    ///   `/test/sub/bar` → `/test/sub` + `bar`
    ///   `/elsewhere`    → None
    pub fn resolve_absolute<R, F>(&self, abs: &str, f: F) -> Option<R>
    where
        F: FnOnce(&dyn FsInstance, &str) -> R,
    {
        if abs.is_empty() || abs.as_bytes()[0] != b'/' {
            return None;
        }
        let q = self.inner.lock();
        // Find the longest matching mount path.
        let mut best: Option<&Mount> = None;
        for m in q.iter() {
            if abs == m.path
                || (abs.starts_with(m.path) && abs.as_bytes().get(m.path.len()) == Some(&b'/'))
            {
                if best.map(|b| b.path.len()).unwrap_or(0) < m.path.len() {
                    best = Some(m);
                }
            }
        }
        let m = best?;
        let rel = &abs[m.path.len()..];
        // Strip the leading slash; if the absolute path equals the
        // mount path exactly, the relative is empty (caller's
        // problem — `resolve` rejects empty paths).
        let rel = rel.strip_prefix('/').unwrap_or(rel);
        Some(f(&*m.fs, rel))
    }

    /// Resolve `abs` to its parent directory + leaf name and run
    /// `f(fs, parent_dir, leaf)` against the result. Used by
    /// directory-mutation syscalls (`unlink` / `mkdir` / `rmdir`)
    /// which need to walk to the parent and operate on the leaf.
    ///
    /// Splits at the LAST `/` of the relative-to-mount portion. So
    /// `/tmp/foo` against a `/tmp` mount produces `(parent=root,
    /// leaf="foo")`; `/tmp/sub/bar` produces `(parent=root.sub,
    /// leaf="bar")`. The walk uses `lookup_dir` for every parent
    /// segment and bails with `NotFound` if any intermediate is
    /// absent. Returns `None` when no mount covers `abs`.
    pub fn resolve_parent_absolute<R, F>(&self, abs: &str, f: F) -> Option<R>
    where
        F: FnOnce(&dyn FsInstance, Arc<dyn DirOps>, &str) -> R,
    {
        if abs.is_empty() || abs.as_bytes()[0] != b'/' {
            return None;
        }
        // Split at last `/`. Need at least one slash and a leaf.
        let last = abs.rfind('/')?;
        let parent_path = &abs[..last];
        let leaf = &abs[last + 1..];
        if leaf.is_empty() {
            return None;
        }
        // The parent path may be empty (e.g. abs == "/foo" → parent
        // == "/"). In that case we resolve against the root mount of
        // the leaf's mount; conceptually the parent is the mount
        // root itself.
        let parent_path = if parent_path.is_empty() {
            "/"
        } else {
            parent_path
        };
        let q = self.inner.lock();
        // Match the longest mount prefix against `parent_path`.
        let mut best: Option<&Mount> = None;
        for m in q.iter() {
            if parent_path == m.path
                || (parent_path.starts_with(m.path)
                    && parent_path.as_bytes().get(m.path.len()) == Some(&b'/'))
            {
                if best.map(|b| b.path.len()).unwrap_or(0) < m.path.len() {
                    best = Some(m);
                }
            }
        }
        let m = best?;
        let rel = &parent_path[m.path.len()..];
        let rel = rel.strip_prefix('/').unwrap_or(rel);
        // Walk segments to reach the parent dir.
        let mut dir = m.fs.root();
        for seg in rel.split('/') {
            if seg.is_empty() || seg == "." {
                continue;
            }
            if seg == ".." {
                return None;
            }
            dir = dir.lookup_dir(seg)?;
        }
        Some(f(&*m.fs, dir, leaf))
    }

    /// Number of mounts.
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// `true` iff no FS is mounted.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }
}

// ── Initramfs (CPIO newc reader) ───────────────────────────────────
//
// CPIO newc format: each entry is a 110-byte fixed-width header
// (magic "070701" + 13 ASCII-hex u32 fields), followed by `namesize`
// bytes of NUL-terminated name, padded to a 4-byte boundary, then
// `filesize` bytes of file data, also padded to a 4-byte boundary.
// Archive ends with a sentinel entry named "TRAILER!!!" (filesize 0).
//
// We parse the whole archive at construction time into a flat
// `Vec<InitramfsEntry>`; file data is borrowed by `&'static [u8]`
// from the source archive. No copy on read — the FileOps::read impl
// memcpys into the caller's buffer (the only copy is the unavoidable
// kernel→caller move).

/// One pre-parsed entry from the initramfs archive.
struct InitramfsEntry {
    /// Path as it appeared in the archive, `'static` because it
    /// borrows from the archive byte slice.
    name: &'static str,
    /// File contents, also borrowed from the archive.
    data: &'static [u8],
    /// File mode from the CPIO header (low bits = perms, high bits
    /// = file type per POSIX). Stage 3 only inspects the
    /// "is-it-a-regular-file" bit (0o100000).
    mode: u32,
    /// mtime as `(seconds since epoch)` from the CPIO header. Stage
    /// 3 stuffs this directly into `Stat::mtime_cycles` — the units
    /// disagree but the spec already calls mtime_cycles a stub for
    /// Stage 3 and Stage 4 introduces a real wall-clock conversion.
    mtime: u64,
}

impl fmt::Debug for InitramfsEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InitramfsEntry")
            .field("name", &self.name)
            .field("len", &self.data.len())
            .finish_non_exhaustive()
    }
}

/// Read-only in-memory filesystem backed by a CPIO newc archive.
pub struct Initramfs {
    name: &'static str,
    entries: Vec<InitramfsEntry>,
}

impl fmt::Debug for Initramfs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Initramfs")
            .field("name", &self.name)
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

/// Parse error surfaced from `Initramfs::from_cpio`. The discriminant
/// is non-exhaustive so additional checks can land without breaking
/// callers' match arms.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CpioError {
    /// Header magic wasn't `070701`.
    BadMagic,
    /// Archive truncated mid-header or mid-data.
    Truncated,
    /// Header field wasn't valid ASCII hex.
    BadHex,
    /// Filename wasn't valid UTF-8.
    BadName,
}

impl Initramfs {
    /// Iterate every regular-file entry as `(name, data)` pairs.
    /// `name` is the path-as-it-appeared in the archive (CPIO has
    /// no directory hierarchy beyond what's encoded in slashes).
    /// External crates use this to scoop subtrees — e.g.
    /// `narf-firmware` walks `firmware/*` entries at boot.
    pub fn iter_files(&self) -> impl Iterator<Item = (&'static str, &'static [u8])> + '_ {
        self.entries
            .iter()
            .filter(|e| (e.mode & 0o170000) == 0o100000) // S_IFREG
            .map(|e| (e.name, e.data))
    }

    /// Parse a CPIO newc archive. The slice must outlive the
    /// `Initramfs` (we borrow names + file data straight from it);
    /// `&'static [u8]` is the natural Stage-3 lifetime because the
    /// bootloader places the initramfs in identity-mapped low RAM.
    pub fn from_cpio(name: &'static str, archive: &'static [u8]) -> Result<Self, CpioError> {
        let mut entries = Vec::new();
        let mut off = 0usize;

        loop {
            // 110-byte fixed header.
            if off + 110 > archive.len() {
                return Err(CpioError::Truncated);
            }
            let hdr = &archive[off..off + 110];
            if &hdr[..6] != b"070701" {
                return Err(CpioError::BadMagic);
            }

            // Field offsets per CPIO newc layout:
            //   6:14  c_ino,    14:22 c_mode,  22:30 c_uid,    30:38 c_gid,
            //  38:46  c_nlink,  46:54 c_mtime, 54:62 c_filesize, 62:70 c_devmajor,
            //  70:78  c_devminor, 78:86 c_rdevmajor, 86:94 c_rdevminor,
            //  94:102 c_namesize, 102:110 c_check.
            let mode = parse_hex8(&hdr[14..22])?;
            let mtime = parse_hex8(&hdr[46..54])? as u64;
            let filesize = parse_hex8(&hdr[54..62])? as usize;
            let namesize = parse_hex8(&hdr[94..102])? as usize;

            off += 110;

            if off + namesize > archive.len() {
                return Err(CpioError::Truncated);
            }
            // Name includes the trailing NUL — drop it before UTF-8.
            let name_bytes = &archive[off..off + namesize - 1];
            let name_str = core::str::from_utf8(name_bytes).map_err(|_| CpioError::BadName)?;

            off += namesize;
            // Pad to 4-byte boundary, measured from start of header.
            // The header starts at `off - 110 - namesize` and the
            // name follows; total bytes-since-archive-start at the
            // end of the name is `off`. Round up to 4.
            off = (off + 3) & !3;

            // TRAILER!!! sentinel ends the archive.
            if name_str == "TRAILER!!!" {
                break;
            }

            if off + filesize > archive.len() {
                return Err(CpioError::Truncated);
            }
            let data = &archive[off..off + filesize];

            // Skip "." root entries — useful when produced by
            // `find . | cpio -o -H newc`. Not an error; just no
            // observable file to expose.
            if name_str != "." {
                entries.push(InitramfsEntry {
                    name: name_str,
                    data,
                    mode,
                    mtime,
                });
            }

            off += filesize;
            off = (off + 3) & !3;
        }

        Ok(Self { name, entries })
    }
}

/// Parse exactly 8 ASCII hex digits into a u32.
fn parse_hex8(bytes: &[u8]) -> Result<u32, CpioError> {
    if bytes.len() != 8 {
        return Err(CpioError::BadHex);
    }
    let mut acc = 0u32;
    for &b in bytes {
        let v = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return Err(CpioError::BadHex),
        };
        acc = (acc << 4) | (v as u32);
    }
    Ok(acc)
}

/// `FsInstance` impl: the root `DirOps` is built fresh on each call
/// because the lookup table is a borrowed slice of the FS itself.
/// `Arc<dyn DirOps>` wraps a thin handle that holds the entries via
/// shared `Arc` state.
impl FsInstance for Initramfs {
    fn root(&self) -> Arc<dyn DirOps> {
        // Stage-3 lifetime trick: build a fresh `InitramfsRoot` that
        // holds a raw pointer back into our `entries` Vec. Safe
        // because `Initramfs` lives inside the registry's `Arc<dyn
        // FsInstance>` — the entries Vec doesn't move until the FS
        // is dropped, and the FS isn't dropped while the registry
        // holds the Arc.
        //
        // SAFETY argument expanded inside `InitramfsRoot::lookup` /
        // `iter` where the pointer is dereffed.
        Arc::new(InitramfsRoot {
            entries_ptr: self.entries.as_ptr(),
            entries_len: self.entries.len(),
        })
    }
    fn name(&self) -> &str {
        self.name
    }
}

/// Thin handle exposing the initramfs as a `DirOps`. See the SAFETY
/// note in `Initramfs::root`.
struct InitramfsRoot {
    entries_ptr: *const InitramfsEntry,
    entries_len: usize,
}

// SAFETY: the pointer is to a `Vec` owned by an `Initramfs` held
// behind an `Arc<dyn FsInstance>` in the global registry; `Send` +
// `Sync` are sound because the underlying entries are immutable
// after `from_cpio` returns and the `&'static [u8]` data slices are
// trivially `Sync`.
// SAFETY: see paragraph above.
unsafe impl Send for InitramfsRoot {}
// SAFETY: see paragraph above.
unsafe impl Sync for InitramfsRoot {}

impl fmt::Debug for InitramfsRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InitramfsRoot")
            .field("entries_len", &self.entries_len)
            .finish_non_exhaustive()
    }
}

impl InitramfsRoot {
    /// Borrow the entries slice. SAFETY: as documented on the struct.
    fn entries(&self) -> &'static [InitramfsEntry] {
        // SAFETY: pointer + length come from a Vec owned by an
        // Initramfs that is alive for the duration of the registry
        // mount that produced this root. The `'static` lifetime here
        // is a white lie to the borrow checker — the actual lifetime
        // is "as long as the mount lives", which Stage 3 enforces by
        // not exposing `unmount-while-handle-live` (the FsFuture's
        // returned by `read` borrow `&'a self`, so the borrow checker
        // catches use-after-unmount in the normal case).
        unsafe { core::slice::from_raw_parts(self.entries_ptr, self.entries_len) }
    }
}

impl DirOps for InitramfsRoot {
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        // Match either bare name ("hello") or leading-slash-stripped
        // form ("/hello") — CPIO archives produced with `find ./` or
        // `find /` differ on the prefix; tolerating both keeps
        // archive-generation flexible.
        for e in self.entries().iter() {
            let canonical = e.name.strip_prefix("./").unwrap_or(e.name);
            let canonical = canonical.strip_prefix('/').unwrap_or(canonical);
            if canonical == name {
                return Some(Arc::new(InitramfsFile {
                    data: e.data,
                    mode: e.mode,
                    mtime: e.mtime,
                }));
            }
        }
        None
    }

    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            self.lookup(name).ok_or(FsError::NotFound)
        })
    }

    fn lookup_dir_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move {
            // Initramfs in Stage 3 is flat; every entry is a leaf.
            // If we find an entry that matches and looks like a dir,
            // we could return it? But CPIO newc usually stores dirs
            // explicitly.
            for e in self.entries().iter() {
                let canonical = e.name.strip_prefix("./").unwrap_or(e.name);
                let canonical = canonical.strip_prefix('/').unwrap_or(canonical);
                if canonical == name && (e.mode & 0o170000 == 0o040000) {
                     // We don't have nested DirOps for Initramfs yet.
                     return Err(FsError::Unsupported);
                }
            }
            Err(FsError::NotFound)
        })
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        Box::new(self.entries().iter().map(|e| {
            let canonical = e.name.strip_prefix("./").unwrap_or(e.name);
            let canonical = canonical.strip_prefix('/').unwrap_or(canonical);
            DirEntry {
                name: canonical,
                file_type: if e.mode & 0o170000 == 0o040000 {
                    FileType::Dir
                } else {
                    FileType::File
                },
            }
        }))
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(String, FileType)> {
        use alloc::string::ToString;
        self.iter()
            .skip(cursor)
            .take(max)
            .map(|de| (de.name.to_string(), de.file_type))
            .collect()
    }

    fn enumerate_async<'a>(&'a self, cursor: usize, max: usize) -> FsFuture<'a, Vec<(String, FileType)>> {
        Box::pin(async move {
            Ok(self.enumerate(cursor, max))
        })
    }
}

/// File handle into an initramfs entry.
struct InitramfsFile {
    data: &'static [u8],
    mode: u32,
    mtime: u64,
}

impl fmt::Debug for InitramfsFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InitramfsFile")
            .field("len", &self.data.len())
            .finish_non_exhaustive()
    }
}

impl FileOps for InitramfsFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let off = offset as usize;
            if off >= self.data.len() {
                return Ok(0); // EOF
            }
            let n = core::cmp::min(buf.len(), self.data.len() - off);
            buf[..n].copy_from_slice(&self.data[off..off + n]);
            Ok(n)
        })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: self.data.len() as u64,
            blocks: (self.data.len() as u64).div_ceil(512),
            mode: Mode {
                file_type: if self.mode & 0o170000 == 0o040000 {
                    FileType::Dir
                } else {
                    FileType::File
                },
                perms: (self.mode & 0o777) as u16,
            },
            mtime_cycles: self.mtime,
        }
    }
}

pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Fs, "devfs-mount", || {
        mount_devfs_default();
        InitResult::Ok
    });
}

/// Stage 3 placeholder for a virtiofs mount. Stage 4 wires the DAX
/// shared-region protocol (FUSE-over-virtio plus a host-shared
/// memory window mapped through `io/`'s coherent allocator) — at that
/// point this struct grows real fields (FUSE session id, DAX window
/// caps, queue refs) and the `unimplemented!()` ops below get real
/// bodies.
///
/// Kept in-tree at Stage 3 so the registry's `mount` API can already
/// take a virtiofs FS without churning when Stage 4 lands.
#[derive(Debug)]
pub struct VirtiofsMount {
    name: &'static str,
}

impl VirtiofsMount {
    pub fn new(name: &'static str) -> Self {
        Self { name }
    }
}

impl FsInstance for VirtiofsMount {
    fn root(&self) -> Arc<dyn DirOps> {
        Arc::new(VirtiofsRoot)
    }
    fn name(&self) -> &str {
        self.name
    }
}

#[derive(Debug)]
struct VirtiofsRoot;

// Stage-3 placeholder. The FUSE/DAX transport that backs virtiofs is
// Stage-4 work; until then the root looks like an empty, read-only
// directory rather than panicking on access. The `*_async` variants
// inherit the trait default of `FsError::Unsupported`, which is the
// correct shape for a callable-but-unbacked filesystem.
impl DirOps for VirtiofsRoot {
    fn lookup(&self, _name: &str) -> Option<Arc<dyn FileOps>> {
        None
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        Box::new(core::iter::empty())
    }

    fn enumerate(&self, _cursor: usize, _max: usize) -> Vec<(String, FileType)> {
        Vec::new()
    }
}
