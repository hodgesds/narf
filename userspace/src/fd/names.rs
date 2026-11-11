//! What an open file names — the `file->f_path` half of
//! [`OpenFileDescription`].
//!
//! On Linux a `struct file` holds `f_path` (mount + dentry) and `d_path`
//! renders it on demand: every descriptor of the file reads the same name in
//! `/proc/<pid>/fd`, the name follows `rename(2)` because the dentry is moved
//! (`d_move`), and an unlinked dentry reads `<path> (deleted)`.
//!
//! NARF's dcache unhashes a dentry on rename or unlink instead of moving it,
//! so a retained [`narf_filesystem::Dentry`] would go on naming the old
//! place. The equivalent kept here is the name itself, stored in the open
//! file description — shared by `dup`, `fork`, `SCM_RIGHTS` and the threads
//! of a process exactly as the description is — plus the reverse map a move
//! needs: every named open file, by path. The three calls that change the
//! namespace report to it ([`renamed`], [`exchanged`], [`unlinked`]), which
//! is what `d_move` and `d_delete` do to the dentries Linux's files hold.
//!
//! Paths are host-absolute (the initial root's view), symlink-free and
//! without a trailing slash; a reader's `chroot` is applied when the link is
//! rendered.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::ops::Bound;

use narf_lib::sync::IrqSafeSpinLock;

use super::OpenFileDescription;

/// The name of an open file.
#[derive(Clone, Debug)]
pub(crate) struct FileName {
    /// Where the file is (or, once `deleted`, last was).
    pub(crate) path: Arc<str>,
    /// The mount the file was opened through (`mnt_id` in `fdinfo`).
    pub(crate) mount_id: Option<u64>,
    /// Whether it names a directory (the close event says so).
    pub(crate) is_dir: bool,
    /// `d_unlinked`: the name was removed, or replaced by a rename, while
    /// the file stayed open. The link reads `<path> (deleted)` and the path
    /// no longer leads to the file.
    pub(crate) deleted: bool,
}

type Files = Vec<Weak<OpenFileDescription>>;
type Names = BTreeMap<Arc<str>, Files>;

const SHARDS: usize = 64;

/// One cache-line-isolated slice of the path → open files map. An exact
/// path lives in the shard its hash selects, so `open`, `close` and
/// `unlink` take one lock; a subtree query visits every shard.
#[repr(align(64))]
struct Shard {
    names: IrqSafeSpinLock<Names>,
}

impl Shard {
    const fn new() -> Self {
        Self {
            names: IrqSafeSpinLock::new(BTreeMap::new()),
        }
    }
}

static INDEX: [Shard; SHARDS] = [const { Shard::new() }; SHARDS];

fn shard_of(path: &str) -> &'static Shard {
    // FNV-1a.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in path.bytes() {
        hash = (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    &INDEX[(hash as usize) & (SHARDS - 1)]
}

fn insert(path: Arc<str>, file: Weak<OpenFileDescription>) {
    let shard = shard_of(&path);
    shard.names.lock().entry(path).or_default().push(file);
}

/// Drop `file` from the files listed at `path`.
fn remove(path: &str, file: *const OpenFileDescription) {
    let mut names = shard_of(path).names.lock();
    let emptied = names.get_mut(path).is_some_and(|files| {
        files.retain(|other| !core::ptr::eq(other.as_ptr(), file));
        files.is_empty()
    });
    if emptied {
        names.remove(path);
    }
}

impl OpenFileDescription {
    /// What this file names, if it was opened by path.
    pub(crate) fn name(&self) -> Option<FileName> {
        self.name.lock().clone()
    }
}

/// `do_dentry_open`: `file` was opened on `path`. A file is opened on one
/// path; naming it again replaces the name.
pub(crate) fn bind(
    file: &Arc<OpenFileDescription>,
    path: String,
    mount_id: Option<u64>,
    is_dir: bool,
) {
    let path: Arc<str> = Arc::from(path);
    let previous = file.name.lock().replace(FileName {
        path: Arc::clone(&path),
        mount_id,
        is_dir,
        deleted: false,
    });
    if let Some(previous) = previous.filter(|previous| !previous.deleted) {
        remove(&previous.path, Arc::as_ptr(file));
    }
    insert(path, Arc::downgrade(file));
}

/// `d_tmpfile`: `file` is an inode created without a name inside the
/// directory `dir` (`O_TMPFILE`). Linux names its dentry `#<ino>` and never
/// hashes it, so the link reads `<dir>/#<ino> (deleted)`.
pub(crate) fn bind_unlinked(file: &OpenFileDescription, path: String, mount_id: Option<u64>) {
    *file.name.lock() = Some(FileName {
        path: Arc::from(path),
        mount_id,
        is_dir: false,
        deleted: true,
    });
}

/// `__fput`: the last reference to `file` is gone. Returns the name it had.
pub(super) fn unbind(file: &OpenFileDescription) -> Option<FileName> {
    let name = file.name.lock().take()?;
    if !name.deleted {
        remove(&name.path, file);
    }
    Some(name)
}

/// Unlist and return the live open files named exactly `path`.
fn take_exact(path: &str, out: &mut Vec<(Arc<str>, Arc<OpenFileDescription>)>) {
    let taken = shard_of(path).names.lock().remove_entry(path);
    if let Some((key, files)) = taken {
        out.extend(
            files
                .iter()
                .filter_map(Weak::upgrade)
                .map(|file| (Arc::clone(&key), file)),
        );
    }
}

/// Unlist and return the live open files named `path` or anything below it,
/// each with the path it had.
///
/// The files come back as strong references on purpose: the caller drops
/// them only after every index lock is released, because dropping the last
/// reference to a description runs [`unbind`].
fn take_tree(path: &str) -> Vec<(Arc<str>, Arc<OpenFileDescription>)> {
    let mut out = Vec::new();
    take_exact(path, &mut out);
    let below = alloc::format!("{}/", path.trim_end_matches('/'));
    for shard in INDEX.iter() {
        let mut names = shard.names.lock();
        let keys: Vec<Arc<str>> = names
            .range::<str, _>((Bound::Included(below.as_str()), Bound::Unbounded))
            .take_while(|(key, _)| key.starts_with(below.as_str()))
            .map(|(key, _)| Arc::clone(key))
            .collect();
        for key in keys {
            if let Some(files) = names.remove(&*key) {
                out.extend(
                    files
                        .iter()
                        .filter_map(Weak::upgrade)
                        .map(|file| (Arc::clone(&key), file)),
                );
            }
        }
    }
    out
}

/// Re-list `files`, which were named `from` or below it, at the same place
/// under `to`.
fn move_tree(files: &[(Arc<str>, Arc<OpenFileDescription>)], from: &str, to: &str) {
    for (path, file) in files {
        let Some(below) = path.strip_prefix(from) else {
            continue;
        };
        let moved: Arc<str> = Arc::from(alloc::format!("{to}{below}"));
        let renamed = match file.name.lock().as_mut() {
            Some(name) if !name.deleted => {
                name.path = Arc::clone(&moved);
                true
            }
            _ => false,
        };
        if renamed {
            insert(moved, Arc::downgrade(file));
        }
    }
}

fn mark_deleted(files: &[(Arc<str>, Arc<OpenFileDescription>)]) {
    for (_, file) in files {
        if let Some(name) = file.name.lock().as_mut() {
            name.deleted = true;
        }
    }
}

/// `d_move` after a successful `rename(old, new)`: whatever was open at
/// `new` has lost its name (`d_delete` of the replaced target), and every
/// open file at `old` — or below it, when a directory moved — now names the
/// same place under `new`.
///
/// `tree` says `old` may be a directory; a plain file has nothing below it
/// and skips the subtree scan.
pub(crate) fn renamed(old: &str, new: &str, tree: bool) {
    if old == new {
        return;
    }
    let mut replaced = Vec::new();
    take_exact(new, &mut replaced);
    mark_deleted(&replaced);
    let moved = if tree {
        take_tree(old)
    } else {
        let mut moved = Vec::new();
        take_exact(old, &mut moved);
        moved
    };
    move_tree(&moved, old, new);
}

/// `d_exchange` after `renameat2(RENAME_EXCHANGE)`: the two names swap,
/// along with everything open below either.
pub(crate) fn exchanged(a: &str, b: &str) {
    if a == b {
        return;
    }
    let from_a = take_tree(a);
    let from_b = take_tree(b);
    move_tree(&from_a, a, b);
    move_tree(&from_b, b, a);
}

/// `d_delete` after a successful `unlink` or `rmdir` of `path`: the files
/// open there stay open and read `<path> (deleted)`.
pub(crate) fn unlinked(path: &str) {
    let mut gone = Vec::new();
    take_exact(path, &mut gone);
    mark_deleted(&gone);
}

/// Whether any open file is named `prefix` or something below it — NARF's
/// stand-in for the per-mount reference count (`mnt_get_count`) that makes
/// `umount(2)` answer -EBUSY. `prefix` has no trailing slash; `/` covers
/// everything.
pub(crate) fn any_under(prefix: &str) -> bool {
    let live = |files: &Files| files.iter().any(|file| file.strong_count() != 0);
    if prefix == "/" {
        return INDEX
            .iter()
            .any(|shard| shard.names.lock().values().any(live));
    }
    if shard_of(prefix).names.lock().get(prefix).is_some_and(live) {
        return true;
    }
    let below = alloc::format!("{prefix}/");
    INDEX.iter().any(|shard| {
        shard
            .names
            .lock()
            .range::<str, _>((Bound::Included(below.as_str()), Bound::Unbounded))
            .take_while(|(key, _)| key.starts_with(below.as_str()))
            .any(|(_, files)| live(files))
    })
}
