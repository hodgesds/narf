//! `bpffs` — the filesystem BPF objects are *pinned* into.
//!
//! Linux mounts one instance of this at `/sys/fs/bpf`; `bpf(BPF_OBJ_PIN)`
//! gives a loaded program / map / link a name in it, and `bpf(BPF_OBJ_GET)`
//! turns that name back into a fresh fd. The point of the exercise is
//! **lifetime**: a pinned object outlives the process that created it, which is
//! how a loader hands an object to a later process (libbpf, `bpftool`, systemd
//! units) without keeping a daemon alive to hold the fd.
//!
//! ## Shape: a directory tree whose leaves are `Arc<dyn FileOps>`, not bytes
//!
//! Structurally this is [`crate::memfs::MemFs`] with one entry kind swapped:
//! where `MemFs` holds `Arc<MemFile>` (a byte buffer), a `BpfDir` holds a
//! [`BpfPin`], and a `BpfPin` holds an `Arc<dyn FileOps>` — the *same* fd
//! wrapper (`ProgFile` / `MapFile` / `LinkFile`) the creating `bpf(2)` command
//! installed in the fd table. So:
//!
//! ```text
//!   BPF_PROG_LOAD  →  Arc<ProgFile> ──┬──→ fd table entry     (one strong ref)
//!                                      └──→ BpfPin in bpffs   (one strong ref)
//! ```
//!
//! The `Arc` **is** the reference count, and both holders are strong. Closing
//! the fd drops one; `unlink`ing the path drops the other; the object dies when
//! the last of them goes. Storing a `Weak` here — the obvious way to avoid a
//! leak — would make the pin a path that resolves to nothing the moment the
//! creating process exits, which is precisely the thing pinning exists to
//! prevent.
//!
//! ## Why `BpfPin` is a wrapper and not the object itself
//!
//! `lookup` hands out the `BpfPin`, not the object. That keeps `open(2)` on a
//! pin path from being a second, ungated `BPF_OBJ_GET`: the fd a plain `open`
//! yields reads and writes as `EINVAL` (Linux's `bpf_dummy_read` /
//! `bpf_dummy_write`) and downcasts to `BpfPin`, not to `ProgFile`, so no
//! `bpf(2)` command will accept it as a program or map fd. Recovering the real
//! object is [`BpfDir::pinned_object`], which only a caller that already knows
//! about bpffs can reach.
//!
//! ## What is deliberately absent
//!
//! // LINUX-GAP: `symlink(2)` inside bpffs. Linux's `bpf_dir_iops` has
//! `.symlink` (`bpftool` never uses it, but `ln -s` in `/sys/fs/bpf` works
//! there). A symlink entry needs a third entry kind whose only consumer would
//! be a shell; the default `Unsupported` → `EPERM` is an honest "no".
//!
//! // LINUX-GAP: `rename(2)` inside bpffs (Linux uses `simple_rename`). Nothing
//! renames a pin — `bpftool` unpins and re-pins — and an unexercised
//! atomic-replace path is a place for a reference to go missing silently.
//!
//! // LINUX-GAP: no per-mount `mode=`/`uid=`/`gid=` options. Every pin stats as
//! `0600 root:root`, which is what Linux's default umask produces anyway.
//!
//! GPL-2.0-or-later — NARF is GPL-2.0-or-later as of 2026-05-20.

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::{DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, FsInstance, Mode, Stat};

/// Monotonic inode allocator for bpffs nodes.
///
/// A separate counter from `memfs`'s, based far away from it: NARF reports
/// `st_dev = 0` for every mount, so two filesystems sharing an inode-number
/// range would hand userspace two nodes with the same `(st_dev, st_ino)` — and
/// systemd's `rm_rf` treats that as "you have reached a filesystem root" and
/// refuses to descend. `memfs` bases at `0x1000_0000`; this base is high enough
/// that it cannot be reached by that counter within a boot.
static NEXT_INO: AtomicU64 = AtomicU64::new(0x2000_0000_0000);

fn alloc_ino() -> u64 {
    NEXT_INO.fetch_add(1, Ordering::Relaxed)
}

/// Permission bits a pin stats with. Linux uses
/// `S_IFREG | ((S_IRUSR | S_IWUSR) & ~current_umask())` in `bpf_obj_do_pin`.
const PIN_PERMS: u16 = 0o600;

/// The inode a `BPF_OBJ_PIN` materialises: a name, and one strong reference to
/// the BPF object behind it.
///
/// Dropping this — which happens when the last directory entry naming it goes
/// away — drops that reference. It is the *only* thing that drops it, so a
/// `BpfPin` that outlives its directory entry would be a leak and one that is
/// removed while an `unlink` racer still holds it is not: the `Arc` handles
/// both.
pub struct BpfPin {
    ino: u64,
    obj: Arc<dyn FileOps>,
}

impl BpfPin {
    /// A fresh strong reference to the pinned object.
    ///
    /// This is the `BPF_OBJ_GET` primitive — the returned `Arc` is the same
    /// allocation the creating fd holds, so an fd installed from it shares the
    /// program/map/link rather than copying it.
    #[must_use]
    pub fn object(&self) -> Arc<dyn FileOps> {
        Arc::clone(&self.obj)
    }
}

impl fmt::Debug for BpfPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `Arc<dyn FileOps>` is not `Debug`; the inode identifies the pin.
        f.debug_struct("BpfPin")
            .field("ino", &self.ino)
            .finish_non_exhaustive()
    }
}

impl FileOps for BpfPin {
    fn ino(&self) -> u64 {
        self.ino
    }

    /// `EINVAL`, matching Linux's `bpf_dummy_read`. A pin is not a byte
    /// stream, and returning zero bytes (i.e. EOF) would let `cat` report an
    /// empty file rather than a category error.
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::InvalidData) })
    }

    /// `EINVAL`, matching Linux's `bpf_dummy_write`.
    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::InvalidData) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::File,
                perms: PIN_PERMS,
            },
            mtime_cycles: 0,
        }
    }

    /// The hook `BPF_OBJ_GET` recovers the pin through when it has resolved a
    /// path to a `FileOps` rather than to a `(dir, leaf)` pair.
    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}

/// One bpffs directory entry.
enum BpfEntry {
    Pin(Arc<BpfPin>),
    Dir(Arc<BpfDir>),
}

impl fmt::Debug for BpfEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BpfEntry::Pin(p) => f.debug_tuple("Pin").field(p).finish(),
            BpfEntry::Dir(d) => f.debug_tuple("Dir").field(d).finish(),
        }
    }
}

/// A bpffs directory. Both the mount root and every `mkdir`-created
/// subdirectory are one of these.
pub struct BpfDir {
    ino: u64,
    entries: IrqSafeSpinLock<BTreeMap<String, BpfEntry>>,
    perms: AtomicU32,
}

impl fmt::Debug for BpfDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BpfDir")
            .field("ino", &self.ino)
            .field("entries", &self.entries.lock().len())
            .finish_non_exhaustive()
    }
}

impl BpfDir {
    fn new(perms: u16) -> Self {
        Self {
            ino: alloc_ino(),
            entries: IrqSafeSpinLock::new(BTreeMap::new()),
            perms: AtomicU32::new(u32::from(perms)),
        }
    }

    /// Pin `obj` under `name`, taking a strong reference to it.
    ///
    /// `Err(FsError::Busy)` when the name is taken — the caller maps that to
    /// `EEXIST`, matching Linux, where `user_path_create` refuses a positive
    /// dentry before `bpf_obj_do_pin` ever runs. It is deliberately NOT an
    /// atomic replace: silently dropping the previous pin's reference would
    /// free an object out from under a loader that believed its pin still
    /// named it.
    pub fn pin_object(&self, name: &str, obj: Arc<dyn FileOps>) -> Result<Arc<BpfPin>, FsError> {
        if name.is_empty() || name == "." || name == ".." || name.contains('/') {
            return Err(FsError::InvalidPath);
        }
        let mut g = self.entries.lock();
        if g.contains_key(name) {
            return Err(FsError::Busy);
        }
        let pin = Arc::new(BpfPin {
            ino: alloc_ino(),
            obj,
        });
        g.insert(name.to_string(), BpfEntry::Pin(Arc::clone(&pin)));
        Ok(pin)
    }

    /// The object pinned under `name`, with a fresh strong reference.
    ///
    /// `None` for an absent name *and* for a name that is a subdirectory: a
    /// directory is not a BPF object, and the caller distinguishes the two
    /// cases (`ENOENT` vs `EACCES`) by also asking [`Self::has_entry`].
    #[must_use]
    pub fn pinned_object(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        let g = self.entries.lock();
        match g.get(name)? {
            BpfEntry::Pin(p) => Some(p.object()),
            BpfEntry::Dir(_) => None,
        }
    }

    /// Whether `name` exists in this directory at all, of any kind.
    ///
    /// Exists so `BPF_OBJ_GET` can tell "no such path" (`ENOENT`) from "that
    /// path is not a BPF object" (`EACCES`) — Linux's `bpf_inode_type` draws
    /// exactly that line, and collapsing the two makes a loader's probe for a
    /// pin indistinguishable from a probe that hit a directory.
    #[must_use]
    pub fn has_entry(&self, name: &str) -> bool {
        self.entries.lock().contains_key(name)
    }

    /// Number of entries directly in this directory. Diagnostic / test use.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    /// Whether this directory is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.lock().is_empty()
    }
}

/// Recover the `BpfDir` behind an erased directory handle.
///
/// Returns `None` for any directory that is not bpffs, which is what
/// `BPF_OBJ_PIN` turns into `EPERM` (Linux's `bpf_obj_do_pin` compares
/// `dir->i_op` against `bpf_dir_iops` and returns exactly that).
#[must_use]
pub fn as_bpf_dir(dir: &dyn DirOps) -> Option<&BpfDir> {
    dir.as_any()?.downcast_ref::<BpfDir>()
}

/// Recover the pinned object behind an erased file handle.
///
/// The `FileOps`-side counterpart of [`as_bpf_dir`], for a caller that resolved
/// a whole path rather than a `(parent, leaf)` pair.
#[must_use]
pub fn pinned_object_of(ops: &dyn FileOps) -> Option<Arc<dyn FileOps>> {
    Some(ops.as_any()?.downcast_ref::<BpfPin>()?.object())
}

impl DirOps for BpfDir {
    fn ino(&self) -> u64 {
        self.ino
    }

    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        let g = self.entries.lock();
        match g.get(name)? {
            BpfEntry::Pin(p) => Some(Arc::clone(p) as Arc<dyn FileOps>),
            BpfEntry::Dir(_) => None,
        }
    }

    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move { self.lookup(name).ok_or(FsError::NotFound) })
    }

    fn lookup_dir(&self, name: &str) -> Option<Arc<dyn DirOps>> {
        let g = self.entries.lock();
        match g.get(name)? {
            BpfEntry::Dir(d) => Some(Arc::clone(d) as Arc<dyn DirOps>),
            BpfEntry::Pin(_) => None,
        }
    }

    fn lookup_dir_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move { self.lookup_dir(name).ok_or(FsError::NotFound) })
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        // `DirEntry::name` is `&'static str` and our keys are `String`s, so
        // this cannot be synthesised without leaking — same reason `MemFs`
        // returns an empty iterator here. `enumerate` below is the real one.
        Box::new(core::iter::empty())
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(String, FileType)> {
        let g = self.entries.lock();
        g.iter()
            .skip(cursor)
            .take(max)
            .map(|(name, entry)| {
                let ft = match entry {
                    BpfEntry::Pin(_) => FileType::File,
                    BpfEntry::Dir(_) => FileType::Dir,
                };
                (name.clone(), ft)
            })
            .collect()
    }

    fn enumerate_async<'a>(
        &'a self,
        cursor: usize,
        max: usize,
    ) -> FsFuture<'a, Vec<(String, FileType)>> {
        Box::pin(async move { Ok(self.enumerate(cursor, max)) })
    }

    /// Remove a pin. **This is the reference-dropping half of pinning**: the
    /// `BpfPin` leaves the map, and with it the last non-fd strong reference to
    /// the object.
    fn unlink<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let mut g = self.entries.lock();
            match g.get(name) {
                None => Err(FsError::NotFound),
                // POSIX `unlink(2)` on a directory is EISDIR/EPERM; `MemFs`
                // reports `InvalidPath` for the same case and the syscall layer
                // already maps it, so match that rather than invent a shape.
                Some(BpfEntry::Dir(_)) => Err(FsError::InvalidPath),
                Some(BpfEntry::Pin(_)) => {
                    g.remove(name);
                    Ok(())
                }
            }
        })
    }

    /// Refused. Linux's `bpf_dir_iops` has no `->create`, so `open(O_CREAT)` in
    /// bpffs fails in the VFS before it reaches the filesystem. A bpffs entry
    /// can only be born from `BPF_OBJ_PIN`, and a `create` that quietly made an
    /// empty regular file would give `BPF_OBJ_GET` a name that resolves to
    /// something it must then reject.
    fn create<'a>(&'a self, _name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async { Err(FsError::PermissionDenied) })
    }

    fn mkdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move {
            let mut g = self.entries.lock();
            if g.contains_key(name) {
                return Err(FsError::Busy);
            }
            let d = Arc::new(BpfDir::new(0o755));
            g.insert(name.to_string(), BpfEntry::Dir(Arc::clone(&d)));
            Ok(d as Arc<dyn DirOps>)
        })
    }

    fn rmdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let mut g = self.entries.lock();
            match g.get(name) {
                None => Err(FsError::NotFound),
                Some(BpfEntry::Pin(_)) => Err(FsError::InvalidPath),
                Some(BpfEntry::Dir(d)) => {
                    if !d.is_empty() {
                        return Err(FsError::Busy);
                    }
                    g.remove(name);
                    Ok(())
                }
            }
        })
    }

    fn dir_mode(&self) -> u16 {
        (self.perms.load(Ordering::Relaxed) & 0o7777) as u16
    }

    fn set_dir_mode(&self, perms: u16) {
        self.perms
            .store(u32::from(perms) & 0o7777, Ordering::Relaxed);
    }

    /// The hook [`as_bpf_dir`] downcasts through — and therefore the thing that
    /// makes "is this path in bpffs?" answerable at all.
    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}

/// A bpffs mount.
pub struct BpfFs {
    root: Arc<BpfDir>,
}

impl BpfFs {
    /// A fresh, empty bpffs.
    #[must_use]
    pub fn new() -> Self {
        // 0o700: Linux's bpffs root is world-traversable, but NARF has no
        // per-mount `mode=` option to tighten it with afterwards, and a pin is
        // a capability. `dir_mode` is settable through `chmod(2)` if a
        // deployment wants it looser.
        Self {
            root: Arc::new(BpfDir::new(0o700)),
        }
    }

    /// The root directory, as the concrete type — so a caller holding the
    /// `BpfFs` (a test, or a boot-time pre-populator) can pin without going
    /// through the registry.
    #[must_use]
    pub fn root_dir(&self) -> Arc<BpfDir> {
        Arc::clone(&self.root)
    }
}

impl Default for BpfFs {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for BpfFs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BpfFs")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl FsInstance for BpfFs {
    fn root(&self) -> Arc<dyn DirOps> {
        Arc::clone(&self.root) as Arc<dyn DirOps>
    }
    /// `bpf`, the name Linux reports in `/proc/mounts` for this filesystem.
    fn name(&self) -> &str {
        "bpf"
    }
}

// ── In-kernel smokes ────────────────────────────────────────────────
//
// These drive the `DirOps` surface DIRECTLY, with a stand-in object rather
// than a real `ProgFile`: the filesystem crate cannot depend on `narf-bpf`
// (the dependency runs the other way), and the property under test here is
// the *reference* discipline, which is object-agnostic. The syscall-level
// half — that a real program survives its fd's close and dies with its pin —
// lives in `userspace/src/abi_bpf_tests.rs`.

mod smoke {
    use super::*;
    use alloc::sync::Weak;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// A stand-in for a BPF object fd wrapper. Carries nothing: every
    /// assertion below is about whether the `Arc` to it is alive, which
    /// `Weak::upgrade` answers exactly.
    #[derive(Debug)]
    struct Probe;

    impl FileOps for Probe {
        fn read<'a>(&'a self, _o: u64, _b: &'a mut [u8]) -> FsFuture<'a, usize> {
            Box::pin(async { Err(FsError::Unsupported) })
        }
        fn write<'a>(&'a self, _o: u64, _b: &'a [u8]) -> FsFuture<'a, usize> {
            Box::pin(async { Err(FsError::Unsupported) })
        }
        fn stat(&self) -> Stat {
            Stat {
                size: 0,
                blocks: 0,
                mode: Mode::FILE_RO,
                mtime_cycles: 0,
            }
        }
        fn as_any(&self) -> Option<&dyn core::any::Any> {
            Some(self)
        }
    }

    fn probe() -> (Arc<dyn FileOps>, Weak<Probe>) {
        let p = Arc::new(Probe);
        let w = Arc::downgrade(&p);
        (p as Arc<dyn FileOps>, w)
    }

    /// Drive an immediately-ready `FsFuture` to completion. Every bpffs op is
    /// a `BTreeMap` mutation behind a spinlock, so one poll always finishes.
    fn poll_once<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
        use core::pin::Pin;
        use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
        fn raw_waker() -> RawWaker {
            unsafe fn no_clone(_: *const ()) -> RawWaker {
                raw_waker()
            }
            unsafe fn no_op(_: *const ()) {}
            const VTAB: RawWakerVTable = RawWakerVTable::new(no_clone, no_op, no_op, no_op);
            RawWaker::new(core::ptr::null(), &VTAB)
        }
        // SAFETY: raw_waker() returns a vtable whose no-op/no-clone fns are
        // sound for a single-threaded test poll; the RawWaker is not used
        // after this scope.
        let waker = unsafe { Waker::from_raw(raw_waker()) };
        let mut cx = Context::from_waker(&waker);
        // SAFETY: `fut` is a local mut binding that outlives this block; not
        // moved.
        let pinned = unsafe { Pin::new_unchecked(&mut fut) };
        match pinned.poll(&mut cx) {
            Poll::Ready(v) => Some(v),
            Poll::Pending => None,
        }
    }

    /// The keystone: a pin is a STRONG reference, so the object outlives the
    /// caller's handle — and dies when the pin is removed, not before and not
    /// after.
    fn smoke_bpffs_pin_holds_a_strong_reference() -> TestResult {
        let fs = BpfFs::new();
        let root = fs.root_dir();
        let (obj, weak) = probe();

        if root.pin_object("prog", obj.clone()).is_err() {
            return TestResult::Fail("pin_object refused a fresh name");
        }

        // Drop the caller's handle — the "creating process closed its fd" step.
        drop(obj);
        let Some(_alive) = weak.upgrade() else {
            return TestResult::Fail("object died when the creating handle closed — pin is weak");
        };
        drop(_alive);

        // …and it is still *retrievable*, not merely alive — an object kept
        // alive by a reference nothing can find again would pass the check
        // above while being useless.
        let Some(back) = root.pinned_object("prog") else {
            return TestResult::Fail("pinned_object lost the object after the handle closed");
        };
        drop(back);

        // Removing the pin drops the last reference.
        match poll_once(root.unlink("prog")) {
            Some(Ok(())) => {}
            _ => return TestResult::Fail("unlink of a live pin failed"),
        }
        if weak.upgrade().is_some() {
            return TestResult::Fail("object survived its last pin — the reference leaked");
        }
        TestResult::Pass
    }
    kernel_test_in!("bpf", smoke_bpffs_pin_holds_a_strong_reference);

    /// `BPF_OBJ_GET` must hand back the *same* object, not a copy: the whole
    /// contract is that two fds address one program.
    fn smoke_bpffs_get_returns_the_same_object() -> TestResult {
        let fs = BpfFs::new();
        let root = fs.root_dir();
        let (obj, _weak) = probe();
        if root.pin_object("m", Arc::clone(&obj)).is_err() {
            return TestResult::Fail("pin_object refused a fresh name");
        }
        let Some(back) = root.pinned_object("m") else {
            return TestResult::Fail("pinned_object found nothing");
        };
        if !Arc::ptr_eq(&obj, &back) {
            return TestResult::Fail("pinned_object returned a different allocation");
        }
        // A miss is a miss, not a fabrication.
        if root.pinned_object("absent").is_some() {
            return TestResult::Fail("pinned_object invented an entry");
        }
        TestResult::Pass
    }
    kernel_test_in!("bpf", smoke_bpffs_get_returns_the_same_object);

    /// A second pin at a live name is refused, and — the part that matters —
    /// refusing does not disturb the first pin's reference.
    fn smoke_bpffs_pin_rejects_an_existing_name() -> TestResult {
        let fs = BpfFs::new();
        let root = fs.root_dir();
        let (first, first_weak) = probe();
        let (second, second_weak) = probe();
        if root.pin_object("dup", first).is_err() {
            return TestResult::Fail("first pin refused");
        }
        match root.pin_object("dup", second) {
            Err(FsError::Busy) => {}
            Err(_) => return TestResult::Fail("duplicate pin reported the wrong error"),
            Ok(_) => return TestResult::Fail("duplicate pin succeeded — it must be EEXIST"),
        }
        // The rejected object's reference was returned to the caller and then
        // dropped at the end of `pin_object`'s argument lifetime, so it is
        // gone; the incumbent is untouched.
        if second_weak.upgrade().is_some() {
            return TestResult::Fail("rejected pin kept a reference to the loser");
        }
        if first_weak.upgrade().is_none() {
            return TestResult::Fail("rejected pin dropped the incumbent's reference");
        }
        TestResult::Pass
    }
    kernel_test_in!("bpf", smoke_bpffs_pin_rejects_an_existing_name);

    /// Negatives on the directory surface: names that cannot be pins, opening a
    /// pin as a byte stream, and creating a plain file.
    fn smoke_bpffs_rejects_non_object_entries() -> TestResult {
        let fs = BpfFs::new();
        let root = fs.root_dir();
        let (obj, _w) = probe();

        for bad in ["", ".", "..", "a/b"] {
            if root.pin_object(bad, Arc::clone(&obj)).is_ok() {
                return TestResult::Fail("pin_object accepted a name that is not a leaf");
            }
        }

        // `open(O_CREAT)` has no filesystem to land on.
        match poll_once(root.create("plain")) {
            Some(Err(FsError::PermissionDenied)) => {}
            _ => return TestResult::Fail("create() in bpffs did not refuse with PermissionDenied"),
        }

        // A pin is not readable or writable as bytes.
        if root.pin_object("p", obj).is_err() {
            return TestResult::Fail("pin_object refused a fresh name");
        }
        let Some(node) = root.lookup("p") else {
            return TestResult::Fail("lookup did not see the pin");
        };
        let mut buf = [0u8; 4];
        match poll_once(node.read(0, &mut buf)) {
            Some(Err(FsError::InvalidData)) => {}
            _ => return TestResult::Fail("read of a pin did not report InvalidData"),
        }
        match poll_once(node.write(0, &buf)) {
            Some(Err(FsError::InvalidData)) => {}
            _ => return TestResult::Fail("write to a pin did not report InvalidData"),
        }
        // …and it downcasts to `BpfPin`, NOT to the pinned object: that is what
        // stops a plain `open` from being a second `BPF_OBJ_GET`.
        if node
            .as_any()
            .and_then(|a| a.downcast_ref::<Probe>())
            .is_some()
        {
            return TestResult::Fail("open of a pin path yielded the object itself");
        }
        if pinned_object_of(&*node).is_none() {
            return TestResult::Fail("pinned_object_of failed to recover the object");
        }
        TestResult::Pass
    }
    kernel_test_in!("bpf", smoke_bpffs_rejects_non_object_entries);

    /// Directories: `mkdir` nests, `rmdir` refuses a non-empty one, `unlink`
    /// refuses a directory, and a directory is not a pin.
    fn smoke_bpffs_directory_semantics() -> TestResult {
        let fs = BpfFs::new();
        let root = fs.root_dir();
        let (obj, obj_weak) = probe();

        let Some(Ok(sub)) = poll_once(root.mkdir("sub")) else {
            return TestResult::Fail("mkdir failed");
        };
        let Some(sub) = as_bpf_dir(&*sub) else {
            return TestResult::Fail("a bpffs subdirectory is not a BpfDir");
        };
        if sub.pin_object("inner", obj).is_err() {
            return TestResult::Fail("pin into a subdirectory failed");
        }
        if root.pinned_object("sub").is_some() {
            return TestResult::Fail("a directory answered as a pinned object");
        }
        if !root.has_entry("sub") {
            return TestResult::Fail("has_entry missed a subdirectory");
        }
        match poll_once(root.unlink("sub")) {
            Some(Err(FsError::InvalidPath)) => {}
            _ => return TestResult::Fail("unlink of a directory was not refused"),
        }
        match poll_once(root.rmdir("sub")) {
            Some(Err(FsError::Busy)) => {}
            _ => return TestResult::Fail("rmdir of a non-empty directory was not refused"),
        }
        // Emptying it releases the nested pin's reference.
        match poll_once(sub.unlink("inner")) {
            Some(Ok(())) => {}
            _ => return TestResult::Fail("unlink inside a subdirectory failed"),
        }
        if obj_weak.upgrade().is_some() {
            return TestResult::Fail("nested pin's reference outlived its entry");
        }
        match poll_once(root.rmdir("sub")) {
            Some(Ok(())) => {}
            _ => return TestResult::Fail("rmdir of an emptied directory failed"),
        }
        if root.has_entry("sub") {
            return TestResult::Fail("rmdir left the entry behind");
        }
        TestResult::Pass
    }
    kernel_test_in!("bpf", smoke_bpffs_directory_semantics);

    /// The VFS-facing half: a mounted bpffs is reachable through
    /// `resolve_parent_absolute`, downcasts to `BpfDir` there, and a *non*-bpffs
    /// mount does not — which is the check `BPF_OBJ_PIN` turns into `EPERM`.
    fn smoke_bpffs_mounts_and_downcasts() -> TestResult {
        use crate::{registry, MemFs, MountPoint};
        use narf_capabilities::{Cap, Grant};

        // `Cap::bootstrap()` allocates an object-table slot per call, so this
        // smoke mints exactly one and reuses it for both mounts.
        let authority: Cap<MountPoint, Grant> = crate::bootstrap_mount_authority();

        const BPF_AT: &str = "/bpffs-smoke";
        const MEM_AT: &str = "/bpffs-smoke-not";
        let fs = Arc::new(BpfFs::new());
        let Ok(bpf_handle) = registry().mount_arc(&authority, BPF_AT, fs.clone()) else {
            return TestResult::Fail("mounting bpffs failed");
        };
        let Ok(mem_handle) =
            registry().mount_arc(&authority, MEM_AT, Arc::new(MemFs::new("tmpfs")))
        else {
            let _ = registry().unmount(&bpf_handle, BPF_AT);
            return TestResult::Fail("mounting the control tmpfs failed");
        };

        let (obj, weak) = probe();
        let mut verdict = TestResult::Pass;

        // Pin through the registry the way the syscall handler will.
        let pinned = registry().resolve_parent_absolute("/bpffs-smoke/x", |_fs, dir, leaf| {
            as_bpf_dir(&*dir).map(|d| d.pin_object(leaf, Arc::clone(&obj)).is_ok())
        });
        if pinned != Some(Some(true)) {
            verdict = TestResult::Fail("pin through resolve_parent_absolute failed");
        }
        // The control mount must NOT downcast — that is the EPERM check.
        let non_bpf = registry()
            .resolve_parent_absolute("/bpffs-smoke-not/x", |_fs, dir, _leaf| {
                as_bpf_dir(&*dir).is_some()
            });
        if non_bpf != Some(false) {
            verdict = TestResult::Fail("a tmpfs directory downcast to BpfDir");
        }
        drop(obj);
        if weak.upgrade().is_none() {
            verdict = TestResult::Fail("the mounted pin did not hold the object");
        }

        // Unmounting drops the whole tree — and with it the pin.
        let _ = registry().unmount(&mem_handle, MEM_AT);
        let _ = registry().unmount(&bpf_handle, BPF_AT);
        drop(fs);
        if weak.upgrade().is_some() {
            verdict = TestResult::Fail("unmounting bpffs leaked its pins");
        }
        verdict
    }
    kernel_test_in!("bpf", smoke_bpffs_mounts_and_downcasts);
}
