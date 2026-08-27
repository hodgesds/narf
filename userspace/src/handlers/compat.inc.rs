// ── Per-task cwd state ────────────────────────────────────────────
//
// Storage shape mirrors the other per-task tables in this file:
// a `BTreeMap<task_id, String>` behind an `IrqSafeSpinLock` with
// an explicit init hook + a test-reset hook. Lifecycle is
// independent of the fd table — agent B owns fd-table extensions
// in `fd.rs`; this state lives in handlers.rs to keep the
// ownership boundary clean.
//
// Default cwd is `/`. Stage-4 first cut: absolute paths only.
// Relative-path resolution + the `*at(2)` family land later;
// today the kernel just records the string the user supplied.

// ── Per-task sharded map (cwd / chroot-root / brk) ──────────────────
//
// These are consulted on hot path-resolution and heap-growth syscalls (every
// path-taking syscall reads the cwd + chroot prefix; brk reads/writes its top),
// so a single global lock bounced one cache line between every CPU. Shard
// 64-way by task id (same transform as the signal / futex tables): a given
// task always hits one shard, but unrelated tasks on other CPUs no longer
// contend.
const TASK_MAP_SHARDS: usize = 64;

#[repr(align(64))]
struct TaskMapShard<V> {
    map: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, V>>>,
}

impl<V> TaskMapShard<V> {
    const fn new() -> Self {
        Self {
            map: narf_lib::sync::IrqSafeSpinLock::new(None),
        }
    }
}

type TaskMapTable<V> = [TaskMapShard<V>; TASK_MAP_SHARDS];

#[inline]
fn task_map_shard(task: u64) -> usize {
    task as usize & (TASK_MAP_SHARDS - 1)
}

fn task_map_init<V>(table: &TaskMapTable<V>) {
    for s in table {
        *s.map.lock() = Some(BTreeMap::new());
    }
}

fn task_map_get<V: Clone>(table: &TaskMapTable<V>, task: u64) -> Option<V> {
    table[task_map_shard(task)]
        .map
        .lock()
        .as_ref()
        .and_then(|m| m.get(&task).cloned())
}

fn task_map_set<V>(table: &TaskMapTable<V>, task: u64, val: V) {
    table[task_map_shard(task)]
        .map
        .lock()
        .get_or_insert_with(BTreeMap::new)
        .insert(task, val);
}

fn task_map_remove<V>(table: &TaskMapTable<V>, task: u64) {
    if let Some(m) = table[task_map_shard(task)].map.lock().as_mut() {
        m.remove(&task);
    }
}

/// fork/clone inheritance: copy `parent`'s entry to `child` (which may be in a
/// different shard). No-op if the parent has no entry.
fn task_map_fork<V: Clone>(table: &TaskMapTable<V>, parent: u64, child: u64) {
    if let Some(v) = task_map_get(table, parent) {
        task_map_set(table, child, v);
    }
}

static CWD_TABLE: TaskMapTable<alloc::string::String> =
    [const { TaskMapShard::new() }; TASK_MAP_SHARDS];

/// Initialise the per-task cwd registry. Boot calls this once
/// before any user task can issue `Syscall::Chdir` / `Getcwd`.
pub fn cwd_init() {
    task_map_init(&CWD_TABLE);
}

/// Reset the registry — test hook. Drops every per-task entry.
#[doc(hidden)]
pub fn __test_cwd_reset() {
    task_map_init(&CWD_TABLE);
}

/// fork(2) inheritance: copy `parent`'s cwd to `child`. No-op
/// if the parent has no entry (child inherits the default `/`).
pub fn cwd_fork(parent: u64, child: u64) {
    task_map_fork(&CWD_TABLE, parent, child);
}

/// Diagnostic: peek the recorded cwd for `task`. Returns the
/// default `"/"` if `task` has never called Chdir.
pub fn cwd_of(task: u64) -> alloc::string::String {
    task_map_get(&CWD_TABLE, task).unwrap_or_else(|| alloc::string::String::from("/"))
}

/// Set `task`'s cwd (USER-view, chroot-relative — the same frame chdir stores).
/// Used by `sys_pivot_root` to recompute the cwd in the new root's frame after
/// the root swap, so a following relative resolution doesn't double-apply the
/// new chroot prefix.
pub(crate) fn set_cwd(task: u64, path: &str) {
    task_map_set(&CWD_TABLE, task, alloc::string::String::from(path));
}

/// Collapse `.`/`..`/empty segments into a clean absolute path.
/// `normalize_abs("/a/./b/../c")` → `/c`; an empty result is `/`.
fn normalize_abs(p: &str) -> alloc::string::String {
    let mut out: alloc::vec::Vec<&str> = alloc::vec::Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    let mut r = alloc::string::String::from("/");
    r.push_str(&out.join("/"));
    r
}

/// Turn a user-supplied path (absolute or relative to `task`'s cwd)
/// into a normalized absolute path. Relative paths are joined onto the
/// task's current working directory; `.`/`..` are collapsed.
pub(crate) fn resolve_cwd_path(task: u64, path: &str) -> alloc::string::String {
    let normalized = resolve_cwd_path_user(task, path);
    // Re-root under the task's chroot (if any) so a chrooted process —
    // e.g. a container — resolves paths against the chrooted rootfs, not
    // the host root. No-op for tasks without a chroot.
    {
        apply_chroot(&normalized)
    }
}

/// The number of symlink expansions (`SYMLOOP_MAX`) a single
/// `resolve_vfs_symlink_path` call will perform before giving up with
/// `ELOOP`. Matches Linux (the 2.6-era de-facto ceiling) and the
/// filesystem-local resolver's own `SYMLOOP_MAX` in `resolve_async_ext`.
const SYMLOOP_MAX: usize = 40;

/// True when every component of `path` is served by a SINGLE covering mount,
/// so a per-component walk against that mount's `fs.root()` faithfully
/// reproduces VFS resolution. Returns `false` (→ take the slow per-prefix
/// path) when a proper prefix of `path` enters a deeper mount, or when
/// `path` is an ancestor of a mount point (a component that has no real
/// node in the covering filesystem, only a synthetic dir). Both cases mean
/// a component "crosses a mount", which the single-fs fast walk cannot see.
fn fast_walk_stays_in_one_mount(path: &str) -> bool {
    // Longest mount prefix covering the full path — the mount the fast walk
    // would descend within. `current_mount_list` is namespace-aware.
    let mounts = current_mount_list();
    let cover_len = mounts
        .iter()
        .filter(|m| {
            path == m.as_str()
                || m.as_str() == "/"
                || (path.starts_with(m.as_str()) && path.as_bytes().get(m.len()) == Some(&b'/'))
        })
        .map(|m| m.len())
        .max();
    let Some(cover_len) = cover_len else {
        // No mount covers the path (not even "/"): nothing for the fast
        // walk to descend. Defer to the slow path.
        return false;
    };
    for m in &mounts {
        // A deeper mount whose path lies strictly inside `path` (at a
        // component boundary) means a proper prefix crosses into it: e.g.
        // resolving `/a/b/c` while `/a/b` is its own mount. Bail so the
        // per-prefix slow walk re-selects the covering mount per component.
        if m.len() > cover_len
            && path.starts_with(m.as_str())
            && (path.len() == m.len() || path.as_bytes().get(m.len()) == Some(&b'/'))
        {
            return false;
        }
    }
    // A path that is a proper ancestor of a mount point has no real node in
    // the covering fs (only a synthetic S_IFDIR); the fast walk would miss
    // it. Defer to the slow path, which the callers already reconcile with
    // the mount-ancestor stat/mkdir synthesis.
    if path_is_mount_ancestor(path) {
        return false;
    }
    true
}

/// Fast path for [`resolve_vfs_symlink_path`]: a single O(depth) forward walk
/// that carries the parent-directory handle and looks each component up
/// WITHOUT following symlinks. Returns `Some(path)` only when it has PROVEN
/// the whole path resolves through real directories with no symlink to
/// expand (so the input needs no rewriting); returns `None` to signal the
/// caller to fall back to the slow per-prefix loop — either because a symlink
/// was found (it must be expanded there) or because a lookup could not
/// prove the component is a plain directory.
///
/// This replaces the old O(depth²) behaviour where the caller rebuilt and
/// re-resolved `/c0/…/ci` from the mount root for every component `i`.
fn resolve_vfs_symlink_path_fast(
    expanded: &str,
    follow_final: bool,
) -> Option<alloc::string::String> {
    // Only sound while the whole path lives in one mount (see the helper):
    // the walk descends within a single `fs.root()` and cannot cross a
    // mount boundary the way the slow per-prefix resolver does.
    if !fast_walk_stays_in_one_mount(expanded) {
        return None;
    }

    // Clone the covering mount's root `Arc` AND the path RELATIVE to that
    // mount OUT of the mount-table lock before any (block-)I/O: the lookups
    // below drive `poll_blocking`, which busy-spins on the backing device
    // IRQ. Holding the IrqSafeSpinLock across that deadlocks the box (see
    // `resolve_absolute`). `rel` has the mount prefix stripped, so the walk
    // starts at `fs.root()` and steps through the in-mount components only.
    let (root, rel) = current_resolve_absolute(expanded, |fs, rel| {
        (fs.root(), alloc::string::String::from(rel))
    })?;

    let components: alloc::vec::Vec<&str> = rel
        .split('/')
        .filter(|component| !component.is_empty())
        .collect();
    if components.is_empty() {
        // The path IS the mount root. A file-rooted mount's root could in
        // principle be a symlink (`fs.root_file()`), so defer to the slow
        // path, which inspects the root node exactly as before rather than
        // assuming the mount root is a plain directory.
        return None;
    }

    let mut current_dir = root;
    for (index, component) in components.iter().enumerate() {
        let is_final = index + 1 == components.len();

        // NOFOLLOW single-component lookup: `lookup_async` returns the raw
        // node so a symlink is SEEN, not followed. `resolve_async_nofollow`
        // only spares the FINAL component of a multi-component path, so a
        // one-component lookup is exactly the nofollow primitive we need.
        let node = poll_blocking(current_dir.lookup_async(component)).and_then(|r| r.ok());

        let Some(node) = node else {
            // Not a file-shaped node. It may be a dir-only child (e.g.
            // `/dev/pts`): descend if we can. If neither, the component is
            // absent or non-traversable — no symlink to expand here, and
            // any downstream error matches the slow path returning the
            // path unchanged.
            if is_final {
                return Some(alloc::string::String::from(expanded));
            }
            match poll_blocking(current_dir.lookup_dir_async(component)).and_then(|r| r.ok()) {
                Some(next) => {
                    current_dir = next;
                    continue;
                }
                None => return Some(alloc::string::String::from(expanded)),
            }
        };

        let kind = node.stat().mode.file_type;
        if kind == narf_filesystem::FileType::Symlink {
            if is_final && !follow_final {
                // NOFOLLOW final symlink: the link itself is the answer;
                // nothing to expand. Mirrors the slow loop's
                // `is_final && !follow_final` skip.
                return Some(alloc::string::String::from(expanded));
            }
            // A symlink that must be expanded (any intermediate symlink, or
            // a final one under FOLLOW). The fast path cannot rewrite the
            // path itself — hand off to the slow per-prefix loop.
            return None;
        }

        if is_final {
            // Final real file/dir, no symlink anywhere on the path.
            return Some(alloc::string::String::from(expanded));
        }

        // Intermediate component: it must be a real directory to keep
        // walking. If it is not (a plain file, or a dir with no `DirOps`
        // shape), stop — there is no symlink here and the path needs no
        // rewrite; downstream open/stat produces the same error the slow
        // path would.
        if kind != narf_filesystem::FileType::Dir {
            return Some(alloc::string::String::from(expanded));
        }
        match poll_blocking(current_dir.lookup_dir_async(component)).and_then(|r| r.ok()) {
            Some(next) => current_dir = next,
            None => return Some(alloc::string::String::from(expanded)),
        }
    }
    Some(alloc::string::String::from(expanded))
}

/// Expand symlinks component-by-component through the current task's mount
/// table. This supplies the VFS boundary that a filesystem-local resolver
/// cannot cross after an absolute symlink target.
///
/// A symlink-free path in a single mount takes the O(depth) fast walk
/// ([`resolve_vfs_symlink_path_fast`]); anything with a symlink to expand,
/// or that crosses a mount boundary, falls through to the O(depth²) slow
/// per-prefix loop below (which re-selects the covering mount per component
/// and performs the splice / re-root / ELOOP handling).
pub(crate) fn resolve_vfs_symlink_path(
    path: &str,
    follow_final: bool,
) -> Option<alloc::string::String> {
    let mut expanded = normalize_abs(path);

    if let Some(resolved) = resolve_vfs_symlink_path_fast(&expanded, follow_final) {
        return Some(resolved);
    }

    for _ in 0..SYMLOOP_MAX {
        let components: alloc::vec::Vec<&str> = expanded
            .split('/')
            .filter(|component| !component.is_empty())
            .collect();
        let mut prefix = alloc::string::String::new();
        // SLOW PATH marker: reached only when the fast walk found a symlink
        // to expand or a mount boundary it could not cross.
        let mut followed = false;

        for (index, component) in components.iter().enumerate() {
            prefix.push('/');
            prefix.push_str(component);
            let is_final = index + 1 == components.len();
            let node = current_resolve_absolute(&prefix, |fs, rel| {
                if rel.is_empty() {
                    fs.root_file()
                } else {
                    poll_blocking(narf_filesystem::resolve_async_nofollow(fs.root(), rel))
                        .and_then(|result| result.ok())
                }
            })
            .flatten();
            let Some(node) = node else {
                continue;
            };
            if node.stat().mode.file_type != narf_filesystem::FileType::Symlink
                || (is_final && !follow_final)
            {
                continue;
            }

            let mut bytes = alloc::vec![0u8; 4096];
            let n = poll_blocking(node.read(0, &mut bytes)).and_then(|result| result.ok())?;
            let target = core::str::from_utf8(&bytes[..n]).ok()?;
            if target.is_empty() {
                return None;
            }
            let parent = prefix
                .rsplit_once('/')
                .map(|(parent, _)| parent)
                .unwrap_or("");
            let target_path = if target.starts_with('/') {
                apply_chroot(target)
            } else if parent.is_empty() {
                normalize_abs(&alloc::format!("/{target}"))
            } else {
                normalize_abs(&alloc::format!("{parent}/{target}"))
            };
            let tail = &components[index + 1..];
            expanded = if tail.is_empty() {
                target_path
            } else {
                normalize_abs(&alloc::format!("{}/{}", target_path, tail.join("/")))
            };
            followed = true;
            break;
        }

        if !followed {
            return Some(expanded);
        }
    }
    None
}

/// The join-and-normalize half of [`resolve_cwd_path`] — the USER-VIEW
/// absolute path, before the chroot prefix. This is what CWD_TABLE must
/// store: chdir used to store the post-chroot result, so a chrooted
/// task's next RELATIVE open re-applied the prefix (`cd /proc` in the
/// alpine chroot → cwd "/mnt/proc" → open("stat") resolved
/// "/mnt/mnt/proc/stat" → busybox top's "can't open 'stat'"), and
/// getcwd leaked the host-side prefix into the container.
pub(crate) fn resolve_cwd_path_user(task: u64, path: &str) -> alloc::string::String {
    if path.starts_with('/') {
        normalize_abs(path)
    } else {
        let mut joined = cwd_of(task);
        if !joined.ends_with('/') {
            joined.push('/');
        }
        joined.push_str(path);
        normalize_abs(&joined)
    }
}

/// Resolve an absolute path to a [`DirOps`] if (and only if) it names a
/// directory. Mirrors the segment-walk in `sys_getdents64` /
/// `sys_readdir`: pick the longest-matching mount, then descend by
/// `lookup_dir_async` per path component.
/// True if `path` is a proper ancestor directory of an existing mount
/// point (e.g. `/sys/fs` when `/sys/fs/cgroup` is mounted). In NARF's flat
/// mount model such an intermediate component has no real node in the
/// underlying filesystem, but it must resolve and stat as a directory:
/// systemd's `mkdir_parents_safe` mkdir()s each path component then
/// `newfstatat()`s it to confirm it is a directory, and cg_create fails
/// (ENOENT/EEXIST mismatch) if mkdir and stat disagree. Both `sys_mkdir`
/// (→ EEXIST) and the dir-aware stat resolver (→ synthetic S_IFDIR) use
/// this so the two views stay consistent.
fn path_is_mount_ancestor(path: &str) -> bool {
    let p = path.trim_end_matches('/');
    if p.is_empty() {
        return false;
    }
    narf_filesystem::registry()
        .list()
        .iter()
        .any(|m| m.len() > p.len() && m.starts_with(p) && m.as_bytes()[p.len()] == b'/')
}

fn resolve_dir_absolute(path: &str) -> Option<alloc::sync::Arc<dyn narf_filesystem::DirOps>> {
    current_resolve_absolute(path, |fs, rel| {
        let dir: alloc::sync::Arc<dyn narf_filesystem::DirOps> = if rel.is_empty() {
            fs.root()
        } else {
            let mut cur = fs.root();
            for seg in rel.split('/').filter(|s| !s.is_empty()) {
                cur = poll_blocking(cur.lookup_dir_async(seg)).and_then(|r| r.ok())?;
            }
            cur
        };
        Some(dir)
    })
    .flatten()
}

/// Resolve a path to its file-shaped node in the current task's mount
/// namespace. `follow_final` mirrors Linux's `LOOKUP_FOLLOW` choice for the
/// chmod/chown families.
fn resolve_file_absolute_ext(
    path: &str,
    follow_final: bool,
) -> Option<alloc::sync::Arc<dyn narf_filesystem::FileOps>> {
    current_resolve_absolute(path, |fs, rel| {
        if rel.is_empty() {
            fs.root_file()
        } else {
            poll_blocking(narf_filesystem::resolve_async_ext(
                fs.root(),
                rel,
                follow_final,
            ))
            .and_then(Result::ok)
        }
    })
    .flatten()
}

/// Apply Linux `*at` anchoring before the ordinary cwd/chroot rewrite.
/// Absolute paths ignore `dirfd`; relative paths require `AT_FDCWD` or an
/// open directory fd. Errors are negative Linux errno values.
fn resolve_at_path(task: u64, dirfd: i64, raw: &str) -> Result<alloc::string::String, i64> {
    const AT_FDCWD: i64 = -100;
    if raw.starts_with('/') || dirfd == AT_FDCWD {
        return Ok(alloc::string::String::from(raw));
    }
    if dirfd < 0 {
        return Err(-9); // -EBADF
    }
    let is_directory = fd::with_table(task, |table| {
        table
            .get(dirfd as u32)
            .map(|entry| entry.ops.as_dir().is_some())
    })
    .flatten()
    .ok_or(-9i64)?;
    if !is_directory {
        return Err(-20); // -ENOTDIR
    }
    let base = fd_path_for_task(task, dirfd as u32).ok_or(-9i64)?;
    Ok(alloc::format!("{}/{}", base.trim_end_matches('/'), raw))
}

/// Stat an absolute path, handling both files and directories.
/// Files come from the FileOps `stat()`; directories (mount roots and
/// sub-directories alike) synthesise a `DIR_RW`-shaped stat so callers
/// see `S_IFDIR`. Returns `None` only when the path names nothing.
fn stat_path_dir_aware(path: &str) -> Option<narf_filesystem::Stat> {
    stat_ino_path_dir_aware(path).map(|(s, _ino, _rdev, _uid, _gid)| s)
}

// Same resolution as `stat_path_dir_aware`, but also returns the file's
// real inode number (0 for synthetic FS / dir-root synthesis). Used by
// the stat/statx handlers so the Linux `st_ino` is a stable per-file id
// rather than a size-derived hash that aliases same-size DSOs.
/// `fs/namei.c::link_path_walk` — why did this path walk fail?
///
/// A resolver that reports only "no" forces every caller to guess, and the
/// guess they all made was -ENOENT. But Linux distinguishes:
///
/// ```text
/// /* link_path_walk, per non-final component */
/// if (unlikely(!d_can_lookup(nd->path.dentry)))
///         return -ENOTDIR;
/// ```
///
/// so `stat("/etc/passwd/foo")` is -ENOTDIR, not -ENOENT — a real
/// distinction, because ENOENT invites a caller to create the path while
/// ENOTDIR says the prefix is a file and creating it never will work.
/// Configure scripts and package installers branch on exactly this.
///
/// Classification runs only on the FAILURE path, so the cost (one stat per
/// ancestor) is never paid by a successful lookup. It walks the ancestors
/// in order and stops at the first one that is absent (-ENOENT, since no
/// later component can be reached) or is not a directory (-ENOTDIR).
///
/// LINUX-GAP: -ELOOP needs symlink-depth accounting inside the resolver,
/// and -EACCES needs directory execute bits that NARF does not enforce at
/// all. Both still surface here as -ENOENT.
fn path_lookup_errno(path: &str) -> i64 {
    const ENOENT: i64 = 2;
    const ENOTDIR: i64 = 20;
    let trimmed = path.trim_end_matches('/');
    // No parent to walk (""/"/"/"foo") — nothing can be a non-directory.
    let Some((parent, _leaf)) = trimmed.rsplit_once('/') else {
        return ENOENT;
    };
    let mut prefix = alloc::string::String::new();
    for comp in parent.split('/').filter(|c| !c.is_empty()) {
        prefix.push('/');
        prefix.push_str(comp);
        // Non-final components are always followed, as in a real walk.
        match stat_ino_path_dir_aware_ext(&prefix, true) {
            Some((st, ..)) => {
                if st.mode.file_type != narf_filesystem::FileType::Dir {
                    return ENOTDIR;
                }
            }
            None => return ENOENT,
        }
    }
    ENOENT
}

fn stat_ino_path_dir_aware(path: &str) -> Option<(narf_filesystem::Stat, u64, u64, u32, u32)> {
    stat_ino_path_dir_aware_ext(path, true)
}

/// Like [`stat_ino_path_dir_aware`] but `follow_final` selects whether a
/// trailing symlink is followed. `lstat(2)` /
/// `fstatat(AT_SYMLINK_NOFOLLOW)` pass `false` so the returned stat
/// describes the symlink itself (S_IFLNK, st_size = target length)
/// rather than its target; plain `stat`/`fstatat` pass `true`.
fn stat_ino_path_dir_aware_ext(
    path: &str,
    follow_final: bool,
) -> Option<(narf_filesystem::Stat, u64, u64, u32, u32)> {
    let file = current_resolve_absolute(path, |fs, rel| {
        if rel.is_empty() {
            // A file-rooted mount (mount --bind of a file, e.g. systemd's
            // read-only /proc/sys/kernel/domainname protection) IS the file at
            // its own path — stat it directly. A directory-rooted mount falls
            // through to the resolve_dir_absolute path below.
            fs.root_file().map(|f| {
                let (uid, gid) = f.owners();
                (f.stat(), f.ino(), f.rdev(), uid, gid)
            })
        } else {
            // Drive the ASYNC resolver (same as the open/execve path):
            // on-disk filesystems like ext2 implement `lookup_async` but
            // stub the sync `lookup` (block reads can't run synchronously),
            // so the old `narf_filesystem::resolve` always missed real
            // files — `stat("/mnt/bin/busybox")` failed while
            // `open`/`execve` of the same path succeeded. That made every
            // PATH probe (busybox/ash search applets via stat) report
            // "not found" inside a mounted distro rootfs.
            poll_blocking(narf_filesystem::resolve_async_ext(
                fs.root(),
                rel,
                follow_final,
            ))
            .and_then(|r| r.ok())
            // rdev() is needed by seatd/libudev, which validate a
            // device node's type via the MAJOR:MINOR from a PATH
            // stat (not just fstat) — a 0 rdev reads as "not an
            // evdev/drm device" and they refuse to open it.
            .map(|ops| {
                let (uid, gid) = ops.owners();
                (ops.stat(), ops.ino(), ops.rdev(), uid, gid)
            })
        }
    })
    .flatten();
    if file.is_some() {
        return file;
    }
    if let Some(dir) = resolve_dir_absolute(path) {
        let (uid, gid) = dir.dir_owners();
        // Report the directory's real (chmod-settable) mode, not a
        // hardcoded 0o777 — dbus/systemd reject XDG_RUNTIME_DIR unless
        // it is not group/other-writable, so `chmod 0700` must show.
        // Thread the directory's real inode (0 for filesystems with no
        // stable id) so a dir is distinguishable from its parent —
        // systemd's rm_rf root-guard aborts ("Attempted to remove entire
        // root file system") when a dir and its parent share st_ino.
        return Some((
            narf_filesystem::Stat {
                size: 0,
                blocks: 0,
                mode: narf_filesystem::Mode {
                    file_type: narf_filesystem::FileType::Dir,
                    perms: dir.dir_mode(),
                },
                mtime_cycles: 0,
            },
            dir.ino(),
            0,
            uid,
            gid,
        ));
    }
    // A path that is an ancestor of a mount point (e.g. /sys/fs when
    // /sys/fs/cgroup is mounted) has no real node in the underlying fs but
    // is logically a directory — synthesize an S_IFDIR stat so it agrees
    // with mkdir's EEXIST (see `path_is_mount_ancestor`). A path-derived
    // pseudo-inode keeps it distinct from its parent (rm_rf root-guard).
    if path_is_mount_ancestor(path) {
        let mut ino: u64 = 0xcabb_a6e0_0000_0000;
        for b in path.trim_end_matches('/').bytes() {
            ino = ino.wrapping_mul(1099511628211).wrapping_add(b as u64);
        }
        return Some((
            narf_filesystem::Stat {
                size: 0,
                blocks: 0,
                mode: narf_filesystem::Mode {
                    file_type: narf_filesystem::FileType::Dir,
                    perms: 0o755,
                },
                mtime_cycles: 0,
            },
            ino,
            0,
            0,
            0,
        ));
    }
    None
}

/// `FileOps` backing an open *directory* fd (from `open(path,
/// O_DIRECTORY)` or opening a path that resolves to a directory).
/// Read/write fail; `stat` reports a directory so `fstat(2)` sees
/// `S_IFDIR`; `as_dir` hands the `DirOps` to `getdents64(2)`. The read
/// cursor lives in the fd's `offset` field.
struct DirFdFile {
    dir: alloc::sync::Arc<dyn narf_filesystem::DirOps>,
}

impl narf_filesystem::FileOps for DirFdFile {
    fn ino(&self) -> u64 {
        // Forward the backing directory's real inode so fstat(2) on an
        // open dir fd matches a path-based stat of the same directory —
        // and stays distinct from the parent (systemd's rm_rf root-guard).
        self.dir.ino()
    }

    fn read<'a>(
        &'a self,
        _offset: u64,
        _buf: &'a mut [u8],
    ) -> narf_filesystem::FsFuture<'a, usize> {
        // EISDIR — a directory fd can't be read(2), only getdents64'd.
        alloc::boxed::Box::pin(async move { Err(narf_filesystem::FsError::InvalidPath) })
    }
    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> narf_filesystem::FsFuture<'a, usize> {
        alloc::boxed::Box::pin(async move { Err(narf_filesystem::FsError::InvalidPath) })
    }
    fn stat(&self) -> narf_filesystem::Stat {
        // Report the directory's real (chmod-settable) mode. A hardcoded
        // 0o777 made dbus/systemd reject XDG_RUNTIME_DIR as group/other-
        // writable even after `chmod 0700`.
        narf_filesystem::Stat {
            size: 0,
            blocks: 0,
            mode: narf_filesystem::Mode {
                file_type: narf_filesystem::FileType::Dir,
                perms: self.dir.dir_mode(),
            },
            mtime_cycles: 0,
        }
    }
    fn owners(&self) -> (u32, u32) {
        self.dir.dir_owners()
    }
    fn set_owners<'a>(&'a self, uid: u32, gid: u32) -> narf_filesystem::FsFuture<'a, ()> {
        self.dir.set_dir_owners_async(uid, gid)
    }
    fn set_perms<'a>(&'a self, perms: u16) -> narf_filesystem::FsFuture<'a, ()> {
        self.dir.set_dir_mode_async(perms)
    }
    fn as_dir(&self) -> Option<alloc::sync::Arc<dyn narf_filesystem::DirOps>> {
        Some(self.dir.clone())
    }
    fn fsync<'a>(&'a self, data_only: bool) -> narf_filesystem::FsFuture<'a, ()> {
        self.dir.fsync(data_only)
    }
    fn syncfs<'a>(&'a self) -> narf_filesystem::FsFuture<'a, ()> {
        self.dir.syncfs()
    }
    fn ioctl_async<'a>(
        &'a self,
        cmd: u32,
        arg: u64,
        input: &'a [u8],
        out_size: usize,
    ) -> narf_filesystem::FsFuture<'a, narf_filesystem::FsIoctlReply> {
        self.dir.ioctl_async(cmd, arg, input, out_size)
    }
    /// A directory fd has no readable/writable stream (read/write are
    /// EISDIR; enumeration is getdents64). Report NOT ready so a poll/epoll
    /// consumer never spuriously wakes on it — the always-ready FileOps
    /// default made dbus-daemon busy-spin on an epoll'd service directory.
    fn poll_readiness(&self) -> u32 {
        0
    }
}

/// One successful open of `/dev/tty`. Linux keeps the 5:0 device-node
/// identity while dispatching operations to the caller's current controlling
/// terminal. The wrapper preserves that path metadata and forwards tty I/O,
/// readiness, and job-control state to the selected console or PTY slave.
struct CurrentTtyFile {
    inner: alloc::sync::Arc<dyn narf_filesystem::FileOps>,
    inode: u64,
}

impl narf_filesystem::FileOps for CurrentTtyFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> narf_filesystem::FsFuture<'a, usize> {
        self.inner.read(offset, buf)
    }

    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> narf_filesystem::FsFuture<'a, usize> {
        self.inner.write(offset, buf)
    }

    fn stat(&self) -> narf_filesystem::Stat {
        narf_filesystem::Stat {
            size: 0,
            blocks: 0,
            mode: narf_filesystem::Mode {
                file_type: narf_filesystem::FileType::Special,
                perms: 0o666,
            },
            mtime_cycles: 0,
        }
    }

    fn ino(&self) -> u64 {
        self.inode
    }

    fn rdev(&self) -> u64 {
        // Linux alternate TTY device `/dev/tty`.
        (5 << 8) as u64
    }

    fn ioctl(&self, cmd: u32, arg: usize) -> Result<u64, narf_filesystem::FsError> {
        self.inner.ioctl(cmd, arg)
    }

    fn poll_readiness(&self) -> u32 {
        self.inner.poll_readiness()
    }

    fn poll_readiness_at(&self, offset: u64) -> u32 {
        self.inner.poll_readiness_at(offset)
    }

    fn poll_edge_token(&self) -> (u64, u64) {
        self.inner.poll_edge_token()
    }

    fn acknowledge_poll_readiness(&self, readiness: u32) {
        self.inner.acknowledge_poll_readiness(readiness);
    }

    fn tty_id(&self) -> Option<u32> {
        self.inner.tty_id()
    }

    fn tty_fg_pgrp(&self) -> Option<u64> {
        self.inner.tty_fg_pgrp()
    }

    fn tty_tostop(&self) -> bool {
        self.inner.tty_tostop()
    }

    fn write_should_block(&self) -> bool {
        self.inner.write_should_block()
    }

    fn is_stream(&self) -> bool {
        self.inner.is_stream()
    }

    fn block_on_input(&self) -> bool {
        self.inner.block_on_input()
    }

    fn nonblock_read_eagain(&self) -> bool {
        self.inner.nonblock_read_eagain()
    }
}

/// Test-only: install a directory fd for `path` in `task`'s fd table
/// and return it. Mirrors `sys_open`'s directory-fd fallback without
/// going through the open syscall (whose native-vs-linux ABI differs by
/// build feature). Returns `None` if `path` is not a directory or the
/// fd table is unavailable.
#[doc(hidden)]
pub fn __test_open_dir_fd(task: u64, path: &str) -> Option<u32> {
    let dirops = resolve_dir_absolute(path)?;
    fd::install(task, crate::fd::FdEntry {
            ops: alloc::sync::Arc::new(DirFdFile { dir: dirops }),
            offset: 0,
            flags: 0,
            status_flags: 0,
        })
}

// ── Brk — per-task heap break ──────────────────────────────────────
//
// POSIX `brk(2)` shape: arg0 carries the requested new break, or 0
// to query. The per-task break starts at a fixed default well above
// the mmap cursor (`MMAP_CURSOR` starts at 0x4080..) and below the
// user stack (`DEFAULT_USER_STACK_BASE = 0x7FFF_FFFC_0000`). Growing
// the heap allocates frames + maps them R+W. Shrinking walks the
// per-grow Region list and calls `unmap_region` on every Region whose
// base falls in [new_break_aligned, cur_aligned) — the PTE walk inside
// `unmap_region` frees each physical page back to the allocator, so a
// task that drops back to its base on `brk(0)` doesn't leak pages
// until exit. Regions that straddle `new_break` are left intact
// (partial unmap would need a region-split primitive). POSIX brk's
// failure contract is "return the unchanged break", so allocation /
// mapping failure is silent: we just hand back the current value.
// Reference: Linux `mm/mmap.c:do_munmap` does the same "find the
// VMAs covered by the range and unmap them" walk; the partial-VMA
// case there is handled by `__split_vma` which NARF will add when a
// real workload demands it.

/// Default per-task heap base. Lives in the gap between the program image
/// (`PROGRAM_DYN_BASE = 0x0000_0080_…`) and the interpreter bias
/// (`INTERP_BIAS = 0x0000_4000_…`), and grows UP toward `BRK_ARENA_TOP`.
///
/// INVARIANT (load-bearing): the brk arena `[BRK_DEFAULT_BASE, BRK_ARENA_TOP)`
/// is DISJOINT from the anonymous mmap window
/// `[MMAP_CURSOR_BASE, MMAP_WINDOW_TOP) = [0x4080_…, 0x7F00_…)`. When brk
/// overlapped that window (the old base `0x0000_5000_…` sat inside it), a
/// `brk` grow dragged the shared `mmap_cursor` up to the heap top, so a
/// subsequent anonymous `mmap` (e.g. glibc's per-child `posix_spawn` stack)
/// was handed a VA just above the heap; its region collided with / was never
/// registered against the brk arena, and the cloned child faulted on a stack
/// with no VMA (unserviceable #PF → SIGSEGV). Keeping the arenas disjoint is
/// what Linux does (brk follows the executable, never inside the mmap region).
/// Must also stay clear of `crate::vdso::VDSO_MAP_BASE`.
const BRK_DEFAULT_BASE: u64 = 0x0000_1000_0000_0000;
/// Hard ceiling for brk growth — keeps the heap below the interpreter bias so
/// the arena can never climb into the interpreter or the mmap window.
const BRK_ARENA_TOP: u64 = 0x0000_4000_0000_0000;
const _: () = assert!(BRK_DEFAULT_BASE != crate::vdso::VDSO_MAP_BASE);
const _: () = assert!(BRK_DEFAULT_BASE < BRK_ARENA_TOP);
// The whole arena must sit below the anon mmap window so brk and mmap can
// never alias (the bug this base was moved to fix).
const _: () = assert!(BRK_ARENA_TOP <= narf_memory::AddressSpace::MMAP_CURSOR_BASE);

// The program break is ADDRESS-SPACE state (`AddressSpace::brk_top`), not a
// per-task registry: CLONE_VM threads share it and a real fork inherits it in
// `clone_for_fork`. It used to live in a per-task `BRK_TABLE`, which let a fresh
// worker thread answer `brk(0)` with the arena base and poison glibc's
// process-global `__curbrk` — see `sys_brk::brk_core`.

// ── execve — re-image the current task ─────────────────────────────
//
// POSIX execve(2) replaces the calling task's executable image
// (text + data + heap + stack) with a freshly-loaded program
// while preserving the task id, fd table, brk top, sigaction
// table, and other per-pid bookkeeping. NARF's wire shape is
// six args:
//
//   arg0 = elf bytes pointer (user vaddr)
//   arg1 = elf bytes length
//   arg2 = argv pack pointer (user vaddr) — concatenated
//          NUL-separated strings, terminated by an extra NUL
//   arg3 = argv pack length
//   arg4 = envp pack pointer (same shape)
//   arg5 = envp pack length
//
// The user-side libc shim is responsible for opening the program
// file, reading the bytes into a buffer, and packing argv/envp
// into the wire format — the syscall path doesn't open files
// because the kernel-side VFS surface is async and the syscall
// handler can't safely block_on (it runs from inside the
// executor's poll body for the calling task).
//
// Implementation flow:
//   1. Validate args (non-null pointers, sane lengths).
//   2. Copy ELF bytes from user memory into a kernel-owned Vec
//      (the user buffer is about to be unmapped when we activate
//      the new AS — must capture before that point).
//   3. Parse argv + envp from packs into kernel-owned Vec<String>.
//   4. Call `load_user_process_with(elf, argv, envp, &[])` which
//      builds a fresh AddressSpace, materialises page tables,
//      lays out the SysV startup contract on the stack, and
//      returns a UserProcess.
//   5. Replace the scheduler slot's `addr_space` so future polls
//      activate the new AS.
//   6. Box an ExecRequest carrying the new AS + entry + stack;
//      publish via `ctx.pending_exec`.
//   7. Set `exit_reason = EXIT_REASON_EXECVE`.
//   8. Save user state (the polling routine reads it but the
//      EXECVE branch ignores the saved RIP — the new image
//      starts at its own entry).
//   9. Call the EXECVE hook → longjmps into the polling
//      routine. The polling routine sees EXIT_REASON_EXECVE,
//      consumes pending_exec, swaps the future's UserProcess,
//      and re-polls. The next iteration enters user mode at
//      the new entry with a fresh GPR file and zeroed RFLAGS.
//
// POSIX preserve list (unchanged across execve): pid, ppid,
// fd table (close-on-exec scrubbing is a future refinement),
// brk top, working directory, sigaction handlers (SIG_IGN +
// SIG_DFL stay as-is; user-installed handlers reset to SIG_DFL
// per POSIX §8.5.4 — we don't enforce that yet, future fix).

/// Shared execve body: `path_owned` is the already-resolved (kernel-side)
/// pathname of the image; `argv_uptr`/`envp_uptr` are the user vectors.
/// `image_override`, when `Some`, supplies the ELF bytes directly (skipping
/// path resolution + shebang) — used by `execveat(fd,"",AT_EMPTY_PATH)` on a
/// pathless fd (a memfd; systemd fexecve's its sd-executor from a sealed
/// memfd copy). `path_owned` is then just the /proc/self/exe label.
/// `sys_execve` (path from user) and `sys_execveat` (dirfd/AT_EMPTY_PATH)
/// funnel through here.
fn do_execve_resolved(
    ctx: &mut dyn TrapContext,
    mut path_owned: alloc::string::String,
    argv_uptr: u64,
    envp_uptr: u64,
    mut image_override: Option<alloc::vec::Vec<u8>>,
) {
    // fexecve via the /proc/self/fd/N (or /proc/<pid>/fd/N) magic symlink:
    // glibc's fexecve and systemd 257's sd-executor spawn open the binary
    // O_PATH then execve("/proc/self/fd/<N>"). Resolve N to the fd's real
    // filesystem path (on-disk binary) or, failing that, its bytes (memfd).
    if image_override.is_none() {
        if let Some(n) = parse_proc_self_fd(&path_owned) {
            let t = current_task_id();
            // Only an ABSOLUTE filesystem path is exec'able by re-reading the FS.
            // A pathless/anonymous fd (a memfd — systemd seals its sd-executor
            // into a memfd and fexecve's /proc/self/fd/N — whose recorded "path"
            // is the "anon_inode:[FileOps]" placeholder) must be exec'd from the
            // fd's own bytes instead.
            let fs_path = fd_path_string_of(t, n).filter(|p| p.starts_with('/'));
            if let Some(real) = fs_path {
                path_owned = real;
            } else if let Some(bytes) = read_fd_image(t, n) {
                image_override = Some(bytes);
            }
        }
    }
    let path: &str = &path_owned;

    // [VERIFY-PROBE] Unconditional (no trace feature, so it prints in a CLEAN
    // fast boot even while the console is otherwise quiet): mark when the
    // session reaches its compositor / shell. Its presence = the greeter got
    // past the session-bus step and the desktop path is unblocked; its absence
    // across a boot = still stuck. One substring check per execve (cold path).
    if path.contains("kwin_wayland")
        || path.contains("plasmashell")
        || path.contains("kwin_wrapper")
    {
        use core::fmt::Write as _;
        let _ = writeln!(narf_console::Writer, "SESSION-EXEC path={}", path);
    }

    #[cfg(feature = "syscall-trace")]
    if crate::syscall::syscall_trace_target_task() {
        use core::fmt::Write as _;
        let _ = writeln!(narf_console::Writer, "EXECVE path={}", path);
    }

    // Step 2: copy argv + envp — each a NUL-terminated array of
    // user-mode `char *`, walked until the first null pointer.
    let argv_strs = match copy_user_strarr(argv_uptr, 1024) {
        Some(v) => v,
        None => {
            // Faulting argv array pointer → EFAULT.
            ctx.set_return(SyscallReturn::ok((-14i64) as u64));
            return;
        }
    };
    let envp_strs = match copy_user_strarr(envp_uptr, 4096) {
        Some(v) => v,
        None => {
            // Faulting envp array pointer → EFAULT.
            ctx.set_return(SyscallReturn::ok((-14i64) as u64));
            return;
        }
    };
    let envp_refs: alloc::vec::Vec<&str> = envp_strs.iter().map(|s| s.as_str()).collect();

    // Resolve a path under the caller's chroot (containers/distros exec
    // `/bin/sh` expecting the chrooted rootfs) and slurp its bytes, capped at
    // 64 MiB. Returns the bytes, or a negative errno on failure. The errno
    // distinction is load-bearing: `execvp(3)` PATH-searches by execve'ing
    // each candidate and treating -ENOENT as "try the next dir" but -EINVAL/
    // -EIO as fatal. Returning EINVAL for a not-found path (the old behaviour)
    // aborted the search on the first miss, so any binary not in the first
    // PATH entry (e.g. weston in /usr/bin while PATH starts with /bin) was
    // "can't execute: Invalid argument" even though it existed.
    let read_exec = |p: &str| -> Result<alloc::vec::Vec<u8>, i64> {
        let ep = apply_chroot(p);
        // Resolve through the caller's PRIVATE mount namespace, not the global
        // registry: a systemd service sandbox unshare(NEWNS)s, recursively binds
        // its rootfs onto /run/systemd/mount-rootfs, and pivot_roots into it, so
        // the binary is reachable ONLY via that task's private mount table. The
        // O_PATH open in find_executable already resolves namespace-aware
        // (current_resolve_absolute); execve must match, or a pivoted service's
        // binary (e.g. systemd-udevd → ../../bin/udevadm) is invisible → ENOENT
        // → 203/EXIT_EXEC. (Global resolution only worked while a pivot_root bug
        // leaked the bind into the global registry.)
        // Pump every FS future with `poll_io_to_completion`, NOT the
        // budget-capped `poll_blocking`: the image read streams the whole
        // binary, and under concurrent block I/O (KDE startup streams tens of
        // MB of DSOs while services exec) one healthy read legitimately takes
        // more re-polls than poll_blocking's budget. The overrun surfaced as
        // execve(2) = EIO for large binaries exec'd at busy moments
        // (plasmashell, xdg-desktop-portal-kde, systemd-executor) while the
        // same binaries exec'd fine when quiet. Overrunning ALSO drops the
        // in-flight read future, abandoning a virtio-blk request that is
        // still DMA'ing into a scratch buffer Drop just returned to the pool
        // — the exact hazard poll_io_to_completion exists for, and which the
        // PT_INTERP read (read_path_from_vfs) already avoids the same way.
        let ops = match current_resolve_absolute(&ep, |fs, rel| {
            poll_io_to_completion(narf_filesystem::resolve_async(fs.root(), rel))
        }) {
            Some(Some(Ok(o))) => o,
            // Not found (or no mount) → ENOENT so execvp keeps searching PATH.
            None | Some(Some(Err(narf_filesystem::FsError::NotFound))) => return Err(-2),
            // Genuinely-wedged device (2G-poll backstop exhausted) → EIO.
            // Loud: a silent EIO here cost a full debugging session (bash
            // reports only "Input/output error").
            Some(None) => {
                use core::fmt::Write as _;
                let _ = writeln!(narf_console::Writer, "EXECVE-EIO resolve overrun path={ep}");
                return Err(-5);
            }
            // A real FS error → EIO.
            Some(Some(Err(e))) => {
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "EXECVE-EIO resolve err={e:?} path={ep}"
                );
                return Err(-5);
            }
        };
        let file_size = ops.stat().size as usize;
        if file_size == 0 {
            return Err(-8); // ENOEXEC — empty file is not an executable
        }
        if file_size > 64 * 1024 * 1024 {
            return Err(-7); // E2BIG
        }
        let mut buf = alloc::vec![0u8; file_size];
        let mut off = 0usize;
        while off < file_size {
            match poll_io_to_completion(ops.read(off as u64, &mut buf[off..])) {
                Some(Ok(0)) => break, // short read at EOF
                Some(Ok(n)) => off += n,
                Some(Err(e)) => {
                    use core::fmt::Write as _;
                    let _ = writeln!(
                        narf_console::Writer,
                        "EXECVE-EIO read err={e:?} off={off} size={file_size} path={ep}"
                    );
                    return Err(-5);
                }
                // Only a genuinely-wedged device exhausts the 2G-poll
                // backstop. Loud, then EIO — never silently truncate.
                None => {
                    use core::fmt::Write as _;
                    let _ = writeln!(
                        narf_console::Writer,
                        "EXECVE-EIO read overrun off={off} size={file_size} path={ep}"
                    );
                    return Err(-5);
                }
            }
        }
        buf.truncate(off);
        Ok(buf)
    };

    // Step 3: read the image. A leading `#!` is an interpreter directive
    // (Linux fs/binfmt_script.c): re-target exec at the named interpreter
    // with the script path spliced into argv as
    //   [interp, optional-arg, scriptpath, original-argv[1..]]
    // Follow nested shebangs up to a small depth so a script interpreting a
    // script still terminates. Without this, every `#!`-script execve EINVALs.
    let mut cur_path = alloc::string::String::from(path);
    let mut cur_argv: alloc::vec::Vec<alloc::string::String> = argv_strs.clone();
    let elf_buf;
    // fexecve fast path: the bytes are already in hand (a memfd fd with no
    // filesystem path). Skip path resolution + shebang — a fexecve'd image is
    // a real binary, and argv[0] is whatever the caller passed.
    if let Some(bytes) = image_override {
        if bytes.len() < 64 {
            // Too small to be a valid ELF → ENOEXEC.
            ctx.set_return(SyscallReturn::ok((-8i64) as u64));
            return;
        }
        elf_buf = bytes;
    } else {
        let mut depth = 0u32;
        loop {
            let buf = match read_exec(&cur_path) {
                Ok(b) => b,
                Err(code) => {
                    ctx.set_return(SyscallReturn::ok(code as u64));
                    return;
                }
            };
            if buf.len() >= 2 && &buf[..2] == b"#!" {
                if depth >= 4 {
                    ctx.set_return(SyscallReturn::ok((-40i64) as u64)); // -ELOOP
                    return;
                }
                depth += 1;
                let line_end = buf.iter().position(|&c| c == b'\n').unwrap_or(buf.len());
                let line = core::str::from_utf8(&buf[2..line_end]).unwrap_or("").trim();
                // interpreter = first whitespace-delimited token; the remainder
                // (trimmed) is a SINGLE optional argument (Linux semantics).
                let (interp, optarg) = match line.find([' ', '\t']) {
                    Some(i) => {
                        let rest = line[i..].trim();
                        (&line[..i], if rest.is_empty() { None } else { Some(rest) })
                    }
                    None => (line, None),
                };
                if interp.is_empty() {
                    // Shebang with an empty interpreter name → ENOEXEC.
                    ctx.set_return(SyscallReturn::ok((-8i64) as u64));
                    return;
                }
                let mut new_argv: alloc::vec::Vec<alloc::string::String> = alloc::vec::Vec::new();
                new_argv.push(interp.into());
                if let Some(a) = optarg {
                    new_argv.push(a.into());
                }
                new_argv.push(cur_path.clone());
                new_argv.extend(cur_argv.iter().skip(1).cloned());
                cur_path = interp.into();
                cur_argv = new_argv;
                continue;
            }
            if buf.len() < 64 {
                // Too small for a valid ELF and not a shebang → ENOEXEC.
                ctx.set_return(SyscallReturn::ok((-8i64) as u64));
                return;
            }
            elf_buf = buf;
            break;
        }
    }
    let argv_refs: alloc::vec::Vec<&str> = cur_argv.iter().map(|s| s.as_str()).collect();

    let task = current_task_id();

    // Step 4: load the new image. exec REPLACES this process's image, so the
    // loaded `UserProcess` carries the caller's EXISTING pid — minting a fresh
    // one here (the pre-fix `load_user_process_with` behaviour) leaked one
    // pid-pool entry per exec, marching the pool toward PID_MAX exhaustion.
    // SAFETY: load_user_process_with_root's contract — identity-mapped low
    // 4 GiB, frame allocator initialised. Both hold by the time any user
    // task is running.
    // SAFETY: Valid memory or trusted environment
    let new_proc = match unsafe {
        crate::process::load_user_process_with_root(
            &elf_buf,
            &argv_refs,
            &envp_refs,
            &[],
            None,
            crate::ProcessId(task_to_pid_raw(task).unwrap_or(task)),
        )
    } {
        Ok(p) => p,
        // Linux: a dynamic binary whose PT_INTERP interpreter can't be
        // opened fails the execve with ENOENT. The loader hard-fails
        // rather than starting the image without ld.so — that "fallback"
        // executed _start against an unrelocated GOT and killed the fresh
        // process at rip=0 (#PF errcode 0x15, instruction fetch at 0).
        Err(crate::process::ProcessLoadError::InterpUnavailable) => {
            ctx.set_return(SyscallReturn::ok((-2i64) as u64)); // -ENOENT
            return;
        }
        Err(_) => {
            // Malformed ELF (bad magic, unsupported class, etc.) → ENOEXEC.
            ctx.set_return(SyscallReturn::ok((-8i64) as u64));
            return;
        }
    };

    // CLONE_VFORK release: this child is now replacing its image, so it no
    // longer needs the shared address space — wake a parent suspended in
    // do_clone3's vfork park. (Load succeeded above, so the exec is committed.)
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    vfork_child_release(task_to_pid_raw(task).unwrap_or(task));

    // POSIX execve: reset caught signal handlers to SIG_DFL — their code
    // addresses belong to the old image. (Inherited e.g. via fork from a shell
    // that handles SIGCHLD; without this the next SIGCHLD branches to the stale
    // handler vaddr in the new image and crashes.) Mask + pending are kept.
    sigaction_exec_reset(task);
    // The alternate signal stack, robust-list head, and clear_child_tid
    // uaddr all point into the OLD image's address space — Linux clears
    // all three on exec. A surviving sigaltstack sp would have the next
    // SA_ONSTACK delivery build a frame at an address the new image
    // repurposed (wild user-stack write); a surviving clear_child_tid
    // would zero an arbitrary word in the new image on exit.
    if let Some(m) = SIG_ALTSTACK.lock().as_mut() {
        m.remove(&task);
    }
    if let Some(m) = ROBUST_LIST_TABLE.lock().as_mut() {
        m.remove(&task);
    }
    // clear_child_tid tracking is a linux-compat-only path.
    let _ = take_clear_child_tid(task);
    // FD_CLOEXEC sweep: close every fd marked close-on-exec (Linux
    // does this in the exec path). Without it, O_CLOEXEC fds leak
    // across exec — an fd-table leak that is also a sandbox-escape
    // vector (a descriptor the new image was never meant to inherit).
    crate::fd::close_cloexec(task);

    // /proc/[pid]/cmdline + comm: preserve argv as NUL-separated
    // bytes, derive comm from argv[0]'s basename (Linux convention).
    set_proc_argv(task, &argv_refs);
    if let Some(first) = argv_refs.first() {
        let basename = first.rsplit('/').next().unwrap_or(first);
        set_proc_comm(task, basename);
    }
    // Commit perf enable_on_exec and PERF_RECORD_COMM only after both the new
    // image and its Linux comm name have been published.
    crate::perf_event::on_exec(task, &new_proc.loaded_mappings, &cur_path);
    // /proc/[pid]/exe: `cur_path` survived the shebang loop, so it names
    // the binary actually being mapped (the interpreter for scripts).
    set_proc_exe(task, &cur_path);

    // Step 5: swap the scheduler slot's AS Arc. Without this the
    // poll path's later activate() would still target the old AS
    // until the future's process.address_space update lands.
    let prev_slot_as = narf_scheduler::replace_address_space(
        narf_scheduler::TaskId(task),
        new_proc.address_space.clone(),
    );

    // Own-stack model: there is no poll trap-back half to apply a staged
    // ExecRequest after a longjmp. Apply the new image inline — activate the new
    // AS + TLS, then enter the new entry at the TOP of this task's own kernel
    // stack (abandoning the execve syscall frames), which DIVERGES.
    //
    // BECAUSE it diverges, no destructor of any local still live at the jump
    // ever runs — the abandoned frames are simply overwritten by the next
    // trap. Every heap-owning local must therefore be dropped BY HAND before
    // the jump. The pre-fix version dropped nothing: each exec leaked the
    // `UserProcess` (including one strong `Arc<AddressSpace>`, which kept the
    // whole post-exec address space — PML4 tree + every faulted user frame —
    // alive FOREVER, surviving process exit), the ELF image buffer, and the
    // argv/envp copies. Under a process-churning desktop boot (~1 exec/s,
    // ~15 MiB/exec) that exhausted 8 GiB in ~5 minutes: the
    // "memory allocation of N bytes failed" kernel-heap OOM panic.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    if narf_scheduler::stackful::user_own_stack_enabled() {
        let entry = new_proc.entry.0.as_u64();
        let rsp = new_proc.stack_top.as_u64();
        #[cfg(target_arch = "x86_64")]
        let fs_base = new_proc.fs_base;
        // The scheduler slot (PENDING_SLOT_AS entry from Step 5) holds the
        // persistent reference that keeps the new AS alive while the task
        // runs; this local clone only bridges the activate() below.
        let new_as = new_proc.address_space.clone();
        // Borrow-holders first, then owners.
        drop(argv_refs);
        drop(envp_refs);
        drop(new_proc);
        drop(elf_buf);
        drop(cur_argv);
        drop(cur_path);
        drop(argv_strs);
        drop(envp_strs);
        drop(path_owned);
        let _ = new_as.activate();
        // Publish the new CR3 so a later preempt/park resume re-activates the
        // post-execve AS (not the pre-execve one) — see set_current_user_cr3.
        #[cfg(target_arch = "x86_64")]
        {
            let cr3: u64;
            // SAFETY: Reading the current CPU's CR3 register has no side-effects.
            unsafe {
                core::arch::asm!("mov {v}, cr3", v = out(reg) cr3,
                    options(nostack, nomem, preserves_flags));
            }
            narf_scheduler::stackful::set_current_user_cr3(cr3);
        }
        #[cfg(target_arch = "x86_64")]
        if let Some(fb) = fs_base {
            // SAFETY: canonical user vaddr from the new image's TLS staging.
            unsafe { narf_scheduler::set_user_fs_base(fb) };
            narf_scheduler::stackful::set_current_user_fs_base(fb);
        }
        #[cfg(target_arch = "aarch64")]
        {
            // Linux arm64 flush_thread clears TLS and FPSIMD during exec.
            // NARF does not stage an AArch64 TLS image here, so the new image
            // begins with an explicit zero thread pointer and clean Q/FP state.
            // SAFETY: TPIDR_EL0 is writable at EL1; `reset_fp` is aligned and
            // FPEN is enabled on every booted CPU.
            unsafe { narf_scheduler::set_user_tls_base(0) };
            narf_scheduler::stackful::set_current_user_tls_base(0);
            let reset_fp = narf_arch::aarch64::UserFpState::zeroed();
            // SAFETY: `reset_fp` is live and aligned; FPEN is enabled at EL1.
            unsafe { narf_arch::aarch64::restore_user_fp_state(reset_fp.as_ptr()) };
        }
        // The new AS is active and referenced by the slot; the pre-exec AS
        // (if Step 5 displaced one) is dead to this task. Release both local
        // refs now — after activate(), so teardown of a last-ref pre-exec AS
        // never races the CR3 it used to back.
        shm_process_exit(task_to_pid_raw(task).unwrap_or(task), task);
        drop(new_as);
        drop(prev_slot_as);
        let top = narf_scheduler::stackful::current_stackful_stack_top();
        // SAFETY: new AS active; entry/rsp mapped by the loader; resets the EL1
        // exception stack to this task's top and enters the new image.
        unsafe { narf_scheduler::enter_user_mode_at_top(entry, rsp, top) };
    }

    // Step 6: package the new image into an ExecRequest and
    // publish via the calling task's UserTaskCtx so the polling
    // routine can apply it after the longjmp returns.
    let req = alloc::boxed::Box::new(crate::user_task::ExecRequest {
        new_as: new_proc.address_space.clone(),
        entry: new_proc.entry.0.as_u64(),
        stack_top: new_proc.stack_top.as_u64(),
        fs_base: new_proc.fs_base,
    });
    let uctx_ptr = match crate::user_task::current_user_task() {
        Some(p) => p,
        None => {
            // No active user-task ctx — execve called outside a
            // polling future (e.g. from a kernel-test stub). Roll
            // back the slot AS swap and bail.
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    // SAFETY: uctx_ptr is valid for the duration of the polling
    // routine's user-mode round-trip (the routine pinned it).
    // SAFETY: Valid memory or trusted environment
    unsafe {
        let prev = (*uctx_ptr)
            .pending_exec
            .swap(alloc::boxed::Box::into_raw(req), Ordering::AcqRel);
        if !prev.is_null() {
            // Another execve was queued and never consumed — drop it
            // so the frame doesn't leak.
            let _ = alloc::boxed::Box::from_raw(prev);
        }
    }

    // Step 7-9: longjmp into the polling routine via the EXECVE
    // hook. save_user_state populates the slot for invariant; the
    // EXECVE branch ignores the saved RIP/RSP since the new image
    // has its own entry.
    if let Some(uctx) = crate::user_task::current_user_task() {
        // SAFETY: same — uctx is live throughout the round-trip.
        unsafe {
            let uc = &*uctx;
            ctx.save_user_state(uc.state.get() as *mut u8);
            *uc.exit_reason.get() = crate::user_task::EXIT_REASON_EXECVE;
        }
    }
    let hook = crate::user_task::execve_hook();
    if let Some(h) = hook {
        // The hook longjmps back into the polling routine and never returns
        // — the same divergence discipline as the own-stack branch above
        // applies: destructors of locals still live here never run, so drop
        // every heap-owning local by hand first. (`req` was consumed into
        // `pending_exec`; the ExecRequest itself is freed by the poll that
        // applies it.)
        shm_process_exit(task_to_pid_raw(task).unwrap_or(task), task);
        drop(argv_refs);
        drop(envp_refs);
        drop(new_proc);
        drop(elf_buf);
        drop(cur_argv);
        drop(cur_path);
        drop(argv_strs);
        drop(envp_strs);
        drop(path_owned);
        drop(prev_slot_as);
        // SAFETY: hook is a fn ptr installed at boot; uctx is live.
        unsafe { h(uctx_ptr) };
        // longjmp doesn't return; if it does (no jmp buf installed),
        // surface a clean error.
    }
    // Fallback path — execve not wired (e.g. early boot or test).
    ctx.set_return(SyscallReturn::invalid_op());
}

/// A `TrapContext` proxy that overrides the syscall args while forwarding
/// the return + control-flow hooks to the wrapped context. Used by the
/// `*at`/`*at2` reshapers to call an existing handler with a different
/// argument layout.
struct ArgReshape<'a> {
    inner: &'a mut dyn TrapContext,
    args: SyscallArgs,
}
impl<'a> TrapContext for ArgReshape<'a> {
    fn args(&self) -> &SyscallArgs {
        &self.args
    }
    fn set_return(&mut self, ret: SyscallReturn) {
        self.inner.set_return(ret);
    }
    fn user_rsp(&self) -> u64 {
        self.inner.user_rsp()
    }
    fn rip(&self) -> u64 {
        0
    }
    fn set_rip(&mut self, _rip: u64) {}
    fn redirect_to_kernel(&mut self, rip: u64, rsp: u64) -> bool {
        self.inner.redirect_to_kernel(rip, rsp)
    }
}

/// Parse `/proc/self/fd/<N>` or `/proc/<pid>/fd/<N>` → the fd number `N`.
/// These are the magic symlinks glibc's fexecve / systemd's spawn execve.
pub(crate) fn parse_proc_self_fd(path: &str) -> Option<u32> {
    let rest = if let Some(r) = path.strip_prefix("/proc/self/fd/") {
        r
    } else {
        let r = path.strip_prefix("/proc/")?;
        let (pid, tail) = r.split_once("/fd/")?;
        if pid.parse::<u64>().is_err() {
            return None;
        }
        tail
    };
    // Reject a trailing sub-path (e.g. /proc/self/fd/3/foo) — only the bare fd.
    if rest.is_empty() || rest.contains('/') {
        return None;
    }
    rest.parse::<u32>().ok()
}

/// Read an entire open fd's contents into a Vec (for `execveat(fd,"",
/// AT_EMPTY_PATH)` on a pathless fd such as a memfd). Returns None if the fd
/// isn't open, isn't readable, or is empty.
fn read_fd_image(task: u64, fd: u32) -> Option<alloc::vec::Vec<u8>> {
    let ops = fd::with_table(task, |t| t.get(fd).map(|e| e.ops.clone())).flatten()?;
    let size = ops.stat().size as usize;
    if size == 0 || size > 64 * 1024 * 1024 {
        return None;
    }
    let mut buf = alloc::vec![0u8; size];
    let mut off = 0usize;
    while off < size {
        // Same rule as the main image read in read_exec: an exec image read
        // is never pumped with the budget-capped poll_blocking (overrun both
        // fails a healthy exec AND drops an in-flight block-I/O future).
        match poll_io_to_completion(ops.read(off as u64, &mut buf[off..])) {
            Some(Ok(0)) => break,
            Some(Ok(n)) => off += n,
            _ => return None,
        }
    }
    buf.truncate(off);
    if buf.len() < 64 {
        None
    } else {
        Some(buf)
    }
}

/// Parse a NUL-separated user-supplied string pack into a Vec of
/// kernel-owned `String`s. Returns Err on any UTF-8 violation,
/// pointer issue, or pack-too-long-without-terminator condition.
///
/// Pack format: zero or more strings, each terminated by a NUL
/// byte. The pack itself is `len` bytes long; we read until we
/// see len bytes total. An empty pack (len == 0) returns an
/// empty Vec (legal — `execve` with no argv).
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
fn copy_user_pack(
    ptr: *const u8,
    len: usize,
) -> Result<alloc::vec::Vec<alloc::string::String>, ()> {
    if len == 0 {
        return Ok(alloc::vec::Vec::new());
    }
    if ptr.is_null() || len > 64 * 1024 {
        return Err(());
    }
    // Copy the whole pack into a kernel Vec under the SMAP bracket first,
    // then parse without touching user memory again.
    let mut buf = alloc::vec![0u8; len];
    // SAFETY: ptr is a user VA; SMAP bracket inside copy_from_user.
    unsafe { copy_from_user(&mut buf, ptr as u64) }.map_err(|_| ())?;
    // Split on NUL boundaries.
    let mut out = alloc::vec::Vec::new();
    let mut start = 0usize;
    for i in 0..buf.len() {
        if buf[i] == 0 {
            if start < i {
                let s = core::str::from_utf8(&buf[start..i]).map_err(|_| ())?;
                out.push(alloc::string::String::from(s));
            }
            start = i + 1;
        }
    }
    Ok(out)
}

// ── mount / umount2 / statfs / fstatfs ─────────────────────────────
//
// POSIX-2017 mount-control surface. The kernel's `narf_filesystem`
// crate already exposes a cap-gated VfsRegistry; these handlers wire
// userspace through to it. The cap-mint (a `Cap<MountPoint, Grant>`)
// is TCB-only — userspace cannot forge one — so the syscall itself
// is the privilege boundary. Today we accept any caller; once UID/
// GID land we'll gate on UID==0 (root) per POSIX `mount(2)`.

#[allow(dead_code)]
fn copy_user_str(ptr: *const u8, len: usize, cap: usize) -> Result<alloc::string::String, ()> {
    if len == 0 || ptr.is_null() || len > cap {
        return Err(());
    }
    let mut buf = alloc::vec![0u8; len];
    // SAFETY: ptr is a user VA; SMAP bracket inside copy_from_user.
    unsafe { copy_from_user(&mut buf, ptr as u64) }.map_err(|_| ())?;
    core::str::from_utf8(&buf)
        .map(alloc::string::String::from)
        .map_err(|_| ())
}

/// Copy a path string from userspace into a kernel-owned `String`.
///
/// - `ptr`: raw userspace pointer (u64 — already cast from *const u8)
/// - `len`: byte length of the path string
///
/// Uses [`copy_from_user`] for the SMAP-bracketed copy, then validates
/// as UTF-8.  Returns `None` on null pointer, zero length, length > 4 KiB,
/// copy failure, or UTF-8 violation.
///
/// Under `linux-compat`, absolute paths are rewritten through the
/// calling task's chroot prefix (if any) so every path-resolving
/// syscall transparently respects chroot(2) / pivot_root(2). Use
/// `copy_user_path_raw` to bypass the chroot rewrite (the chroot
/// syscalls themselves want the literal user string).
fn copy_user_path(ptr: u64, len: usize) -> Option<alloc::string::String> {
    let raw = copy_user_path_raw(ptr, len)?;
    Some(apply_chroot(&raw))
}

/// Copy a NUL-terminated C string from user memory. Reads up to
/// `max_len` bytes (defensive cap) and stops at the first NUL.
/// Returns `None` on any of: null ptr, copy fault, non-UTF-8,
/// no NUL within `max_len`.
///
/// Used by execve(2), stat(2), and friends — Linux-shape syscalls
/// whose path arg is just a bare user pointer with no length, and
/// the kernel finds the end at the NUL.
pub(crate) fn copy_user_cstr(ptr: u64, max_len: usize) -> Option<alloc::string::String> {
    copy_user_cstr_checked(ptr, max_len).ok()
}

/// `fs/namei.c::getname_flags` — copy a NUL-terminated path from user
/// memory, reporting WHY it failed.
///
/// ```text
/// len = strncpy_from_user(kname, filename, EMBEDDED_NAME_MAX);
/// if (unlikely(len < 0))          { ... return ERR_PTR(len); }   /* -EFAULT */
/// ...
/// if (unlikely(len == PATH_MAX))  { ... return ERR_PTR(-ENAMETOOLONG); }
/// ```
///
/// Linux distinguishes two failures that [`copy_user_cstr`] folds into one
/// `None`: a pointer it cannot read is -EFAULT, and a path that reaches
/// PATH_MAX without a terminator is -ENAMETOOLONG. Every path syscall that
/// mapped `None` to EFAULT therefore reported a bad POINTER for a caller
/// whose pointer was fine and whose PATH was too long — which sends a
/// program looking at the wrong argument entirely.
///
/// LINUX-GAP: a path that is valid bytes but not valid UTF-8 still takes
/// the -EFAULT arm. Linux paths are byte strings with no encoding, so it
/// has no counterpart to this case at all; NARF's VFS is UTF-8-only, and
/// inventing an errno here would be a guess rather than a mapping.
pub(crate) fn copy_user_cstr_checked(
    ptr: u64,
    max_len: usize,
) -> Result<alloc::string::String, i64> {
    const EFAULT: i64 = 14;
    const ENAMETOOLONG: i64 = 36;
    if ptr == 0 || max_len == 0 || max_len > 65536 {
        return Err(EFAULT);
    }
    // Bulk-reading `max_len` blindly would walk past the NUL into
    // pages that may not be mapped (a path string that ends near a
    // page boundary). Read in page-sized chunks until we find the
    // NUL or hit `max_len`.
    let mut out = alloc::vec::Vec::with_capacity(64);
    let mut cursor = ptr;
    let end_cap = ptr.saturating_add(max_len as u64);
    while cursor < end_cap {
        // Read up to the next page boundary, capped at the remaining
        // budget.
        let next_page = (cursor + 0x1000) & !0xFFF;
        let chunk_end = next_page.min(end_cap);
        let chunk_len = (chunk_end - cursor) as usize;
        let mut chunk = alloc::vec![0u8; chunk_len];
        // SAFETY: SMAP bracket inside copy_from_user; pointer
        // validated against canonical range there.
        // SAFETY: Valid memory or trusted environment
        unsafe { copy_from_user(&mut chunk, cursor) }.map_err(|_| EFAULT)?;
        if let Some(nul_pos) = chunk.iter().position(|&b| b == 0) {
            out.extend_from_slice(&chunk[..nul_pos]);
            return alloc::string::String::from_utf8(out).map_err(|_| EFAULT);
        }
        out.extend_from_slice(&chunk);
        cursor = chunk_end;
    }
    // `len == PATH_MAX` with no terminator — the path is too long, the
    // pointer was perfectly readable.
    Err(ENAMETOOLONG)
}

/// Walk a NULL-terminated user array of `char *` (e.g. argv or
/// envp). Each element points to a C string copied via
/// [`copy_user_cstr`]. Returns `None` on any copy fault or if
/// the array doesn't terminate within `max_entries`.
fn copy_user_strarr(
    arr_ptr: u64,
    max_entries: usize,
) -> Option<alloc::vec::Vec<alloc::string::String>> {
    if arr_ptr == 0 {
        // POSIX permits argv=NULL to mean "no args"; envp=NULL
        // similarly. Treat as empty rather than rejecting.
        return Some(alloc::vec::Vec::new());
    }
    let mut out = alloc::vec::Vec::new();
    for i in 0..max_entries {
        let slot_ptr = arr_ptr.checked_add((i as u64) * 8)?;
        let mut slot_bytes = [0u8; 8];
        // SAFETY: SMAP bracket inside copy_from_user.
        unsafe { copy_from_user(&mut slot_bytes, slot_ptr) }.ok()?;
        let element_ptr = u64::from_le_bytes(slot_bytes);
        if element_ptr == 0 {
            // NULL terminator → end of array.
            return Some(out);
        }
        out.push(copy_user_cstr(element_ptr, 4096)?);
    }
    // Array didn't terminate — reject rather than truncate silently.
    None
}

/// Like `copy_user_path` but never applies the chroot rewrite. Used
/// by chroot(2) / pivot_root(2) themselves so the kernel sees the
/// literal target the caller typed.
fn copy_user_path_raw(ptr: u64, len: usize) -> Option<alloc::string::String> {
    if len == 0 || ptr == 0 || len > 4096 {
        return None;
    }
    let mut buf = alloc::vec![0u8; len];
    // SAFETY: ptr is a user VA; SMAP bracket inside copy_from_user.
    unsafe { copy_from_user(&mut buf, ptr) }.ok()?;
    core::str::from_utf8(&buf)
        .map(alloc::string::String::from)
        .ok()
}

// ── SMAP-safe user-memory copy helpers ────────────────────────────
//
// Linux analogues: `arch/x86/include/asm/uaccess.h` `copy_from_user`
// / `copy_to_user`, which open a `user_access_begin` / `user_access_end`
// (STAC/CLAC) window around the actual memory transfer.
//
// NARF stance: the bulk transfers below go through
// `narf_arch::x86_64::smap::copy_user_guarded`, which brackets the
// copy with STAC/CLAC *and* arms the per-CPU recoverable probe so an
// unrecoverable fault mid-copy (#GP on a non-canonical address, #PF
// on a range a sibling thread munmap'd after validation) returns
// -EFAULT instead of panicking the kernel — Linux's exception-table
// fixup semantics. `smap::with_user_access` remains the sanctioned
// bracket for the small fixed-size accesses elsewhere. On non-x86_64
// targets the helpers degrade to a plain volatile copy because those
// architectures have no SMAP equivalent (and no probe wiring yet).
//
// Maximum single-call transfer: 16 MiB.  Larger requests are rejected
// with EINVAL (-22) so a malicious/buggy userspace cannot force a
// multi-gigabyte kernel allocation.

/// Linux EFAULT errno value (14).
const EFAULT: u64 = 14;
/// Linux EINVAL errno value (22).
const EINVAL_CODE: u64 = 22;
/// 16 MiB per-call cap.
const MAX_USER_COPY: usize = 16 * 1024 * 1024;

/// First address above the user half of a 48-bit canonical VA space.
///
/// Both supported architectures split at bit 47: a user-half VA has
/// bits 47..=63 all zero, so `addr < USER_VA_LIMIT` is simultaneously
/// the canonicality test and the user/kernel-half test. The highest
/// legal user byte is `USER_VA_LIMIT - 1` (0x0000_7FFF_FFFF_FFFF).
///
/// Linux analogue: `TASK_SIZE_MAX`, against which `__access_ok()`
/// (`include/asm-generic/access_ok.h`) tests `addr <= limit - size`.
pub(crate) const USER_VA_LIMIT: u64 = 1 << 47;

/// True when `a` is a canonical *user-half* address.
#[inline]
fn in_user_half(a: u64) -> bool {
    a < USER_VA_LIMIT
}

/// True when `a` is canonical at all — user half (bits 47..=63 zero)
/// or kernel half (bits 47..=63 one). Bit 63 and bit 47 are PART of
/// the rule: an earlier version of this check masked bit 63 out and
/// only examined bits 48..=62, so the non-canonical shapes
///   0x8000_0000_0000_0000 (bit 63 set, middle bits clear) and
///   0x7FFF_8000_0000_0000 (bit 63 clear, middle bits set)
/// slipped through and the copy took a kernel #GP.
///
/// The production predicate is [`in_user_half`], which is strictly
/// stronger; this laxer form exists only to keep the `kernel-test`
/// opt-in from ever admitting a hole-spanning range.
#[cfg(feature = "kernel-test")]
#[inline]
fn canonical(a: u64) -> bool {
    let top = a >> 47; // bits 47..=63, 17 bits
    top == 0 || top == 0x1_FFFF
}

/// Scoped opt-in that lets the *calling task* pass kernel-half
/// pointers through [`validate_user_range`] for the duration of `f`.
///
/// The bypass it enables is compiled **only** into the `kernel-test`
/// build; in every production build this is an inlined no-op wrapper
/// and `validate_user_range` contains no path that accepts a kernel
/// address at all. The wrapper itself is unconditional because the
/// `abi_*_tests.rs` modules are compiled into every build of this
/// crate (they register into the `narf.tests` link section) and so
/// must always be able to name it.
///
/// Even in the test build the opt-in is deliberately narrow:
///
/// - it is **dynamically scoped**, not a build-wide switch, so every
///   one of the thousands of `kernel-test` cases that does not wrap
///   itself in it keeps exercising the production predicate — which
///   is what makes a negative test for a rejected kernel-half
///   destination possible at all; and
/// - it is **keyed on the CPU**, so a syscall issued concurrently on
///   any other CPU is still checked strictly.
///
/// Use it only where the kernel pointer is the *point* of the test
/// (a handler being unit-tested with a kernel scratch buffer standing
/// in for a user buffer). Never wrap an assertion about the check
/// itself in it.
#[inline]
pub(crate) fn with_kernel_buffers<R>(f: impl FnOnce() -> R) -> R {
    let _guard = kernel_buffers_guard();
    f()
}

/// RAII form of [`with_kernel_buffers`], for the in-kernel smokes that
/// are written as a bare `fn … -> TestResult` with early returns rather
/// than as a closure passed to a harness. Bind it to a named local
/// (`let _guard = …;`) at the top of the test: it closes on every exit
/// path, including the early ones.
#[inline]
pub(crate) fn kernel_buffers_guard() -> KernelBufferGuard {
    KernelBufferGuard {
        #[cfg(feature = "kernel-test")]
        _scope: kernel_buf_scope::KernelBufScope::new(),
    }
}

/// See [`kernel_buffers_guard`]. Outside `kernel-test` this is a
/// zero-sized nothing and `validate_user_range` has no bypass at all.
pub(crate) struct KernelBufferGuard {
    #[cfg(feature = "kernel-test")]
    _scope: kernel_buf_scope::KernelBufScope,
}

#[cfg(feature = "kernel-test")]
pub(crate) mod kernel_buf_scope {
    use core::sync::atomic::{AtomicU32, Ordering};

    /// Nesting depth of the opt-in, per CPU.
    ///
    /// Keyed on the CPU rather than the task id on purpose. The scope
    /// describes *a block of code*, and an in-kernel smoke runs that
    /// block straight through with no `.await` — so the syscalls it
    /// issues run on the same CPU. Task-keying looked tighter but was
    /// wrong: several smokes call `set_task()` *inside* the block, and
    /// a scope keyed on the id read at entry silently stopped applying
    /// the moment the test changed it. A CPU that is not running the
    /// block has depth 0 and gets the production predicate.
    static DEPTH: [AtomicU32; narf_lib::percpu::MAX_CPUS] =
        [const { AtomicU32::new(0) }; narf_lib::percpu::MAX_CPUS];

    /// RAII guard. While alive, `validate_user_range` accepts canonical
    /// kernel-half ranges *on the CPU that created it*.
    pub(crate) struct KernelBufScope {
        cpu: usize,
    }

    impl KernelBufScope {
        /// Open the scope on the calling CPU.
        pub(crate) fn new() -> Self {
            let cpu = narf_lib::percpu::current_cpu();
            DEPTH[cpu].fetch_add(1, Ordering::AcqRel);
            Self { cpu }
        }
    }

    impl Drop for KernelBufScope {
        fn drop(&mut self) {
            DEPTH[self.cpu].fetch_sub(1, Ordering::AcqRel);
        }
    }

    /// Is a scope open on the calling CPU?
    #[inline]
    pub(crate) fn active() -> bool {
        DEPTH[narf_lib::percpu::current_cpu()].load(Ordering::Acquire) != 0
    }
}

/// Validate that `[ptr, ptr + len)` is a plausible *user-space* range.
///
/// Rejects:
/// - `ptr == 0` (null) → EFAULT
/// - `len > MAX_USER_COPY` → EINVAL
/// - Integer overflow of `ptr + len` → EFAULT
/// - A FIRST or LAST byte address outside the user half — either
///   non-canonical (bits 47–63 partial) or canonical-but-kernel
///   (≥ 0xFFFF_8000_0000_0000) → EFAULT.
///
/// Checking the last byte matters twice over. A canonical user-half
/// base whose `len` pushes the range across 0x0000_8000_0000_0000
/// would walk the kernel copy into the canonical hole — a mid-`rep
/// movsb` **#GP**, not #PF, because non-canonical linear addresses are
/// the one data-access fault x86_64 reports as #GP (stress-ng --vma's
/// randomized write() buffers hit exactly this). And a base one byte
/// below `USER_VA_LIMIT` with a large `len` would otherwise put all
/// but the first byte of the transfer in the kernel half.
///
/// # Why the kernel half must be rejected here
///
/// SMAP does **not** enforce this boundary, and a prior version of
/// this comment claimed it did. SMAP faults a CPL-0 access to a page
/// whose PTE has `U=1` while `EFLAGS.AC` is clear; it says nothing
/// about a kernel page (`U=0`), and `copy_user_guarded` runs the whole
/// `rep movsb` inside a `STAC`/`CLAC` bracket, which disables SMAP for
/// the duration regardless. A mapped kernel-half destination is
/// therefore written *silently* — no #PF, no #GP — the guarded copy's
/// fault path never fires and the caller is handed `Ok(())`. Without
/// the check below, every syscall that copies a caller-supplied length
/// of caller-influenced bytes to a caller-supplied address is an
/// arbitrary-kernel-write primitive (`bpf(BPF_OBJ_GET_INFO_BY_FD)` on
/// a loaded BTF blob was the demonstrated gadget).
///
/// Linux analogue: `__access_ok()` in `include/asm-generic/access_ok.h`
/// — `(size <= TASK_SIZE_MAX) && (addr <= TASK_SIZE_MAX - size)` — which
/// likewise confines both ends of the range to the user half rather
/// than deferring to hardware.
#[inline]
pub(crate) fn validate_user_range(ptr: u64, len: usize) -> Result<(), u64> {
    if len > MAX_USER_COPY {
        return Err(EINVAL_CODE);
    }
    if ptr == 0 {
        return Err(EFAULT);
    }
    // Reject integer overflow of the range end.
    if ptr.checked_add(len as u64).is_none() {
        return Err(EFAULT);
    }
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        // `ptr + len` can't overflow — checked above — so
        // `ptr + len - 1` can't either for len > 0.
        let last = if len > 0 { ptr + (len as u64 - 1) } else { ptr };
        if !in_user_half(ptr) || !in_user_half(last) {
            // The kernel-test opt-in is the only way past this, and it
            // still demands a canonical range in ONE half so a test
            // buffer can never be handed a hole-spanning transfer.
            #[cfg(feature = "kernel-test")]
            if kernel_buf_scope::active()
                && canonical(ptr)
                && canonical(last)
                && (ptr >> 63) == (last >> 63)
            {
                return Ok(());
            }
            return Err(EFAULT);
        }
    }
    Ok(())
}

/// Copy `len` bytes from userspace address `src_uptr` into the
/// kernel-owned slice `dst`.
///
/// Opens the SMAP window (`STAC`) for the duration of the transfer,
/// then closes it (`CLAC`). On non-x86_64 targets the bracket is a
/// no-op.
///
/// Returns `Ok(())` on success or `Err(errno)` on validation failure.
/// The caller converts the errno to a negative `SyscallReturn::ok` value.
///
/// # Safety
/// - The caller's address space must match the AS that mapped `src_uptr`.
/// - Must not be called from IRQ context.
pub(crate) unsafe fn copy_from_user(dst: &mut [u8], src_uptr: u64) -> Result<(), u64> {
    validate_user_range(src_uptr, dst.len())?;
    let src = src_uptr as *const u8;
    // SAFETY: dst is a live kernel slice; src is range-validated; the
    // guarded copy opens the SMAP bracket itself and catches any
    // unrecoverable fault (#GP non-canonical, #PF on an address a
    // racing munmap just removed from the AS) as Err instead of a
    // kernel panic — Linux's extable-fixup -EFAULT semantics.
    #[cfg(target_arch = "x86_64")]
    // SAFETY: Valid memory or trusted environment
    unsafe {
        narf_arch::x86_64::smap::copy_user_guarded(dst.as_mut_ptr(), src, dst.len())
            .map_err(|_remaining| EFAULT)?;
    }
    // SAFETY: dst is a live kernel slice; src is range-validated; the
    // guarded copy catches any unrecoverable EL1 data abort (a validated-
    // but-unmapped user page, or a racing munmap) as Err instead of a
    // kernel panic — Linux's arm64 uaccess extable-fixup -EFAULT semantics.
    // A legitimately-healable fault (demand page / stack grow / COW) heals
    // in the data-abort handler first and the copy resumes transparently.
    #[cfg(target_arch = "aarch64")]
    // SAFETY: Valid memory or trusted environment
    unsafe {
        narf_arch::aarch64::uaccess::copy_user_guarded(dst.as_mut_ptr(), src, dst.len())
            .map_err(|_remaining| EFAULT)?;
    }
    // SAFETY: any other target — plain volatile read of each in-range user
    // byte (no fault-fixup surface implemented there).
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    // SAFETY: Valid memory or trusted environment
    unsafe {
        for (i, b) in dst.iter_mut().enumerate() {
            *b = core::ptr::read_volatile(src.add(i));
        }
    }
    Ok(())
}

/// Allocate a kernel `Vec<u8>` of `len` bytes and fill it from userspace
/// address `src_uptr`.
///
/// Validates `len <= MAX_USER_COPY` (EINVAL) and pointer canonicality
/// (EFAULT) *before* the allocation, so an oversized user-supplied length
/// never reaches the heap allocator.  This is the correct helper to use
/// whenever a syscall would otherwise `vec![0u8; len]` and then call
/// `copy_from_user` — the two steps are merged here so the ordering
/// cannot be violated per call site.
///
/// # Safety
/// Same as `copy_from_user`.
pub(crate) unsafe fn copy_from_user_vec(
    src_uptr: u64,
    len: usize,
) -> Result<alloc::vec::Vec<u8>, u64> {
    validate_user_range(src_uptr, len)?;
    let mut buf = alloc::vec![0u8; len];
    // SAFETY: validated above; SMAP bracket inside copy_from_user.
    unsafe { copy_from_user(&mut buf, src_uptr) }?;
    Ok(buf)
}

/// Copy `len` bytes from the kernel-owned slice `src` into userspace
/// address `dst_uptr`.
///
/// Mirror of [`copy_from_user`] for the write direction.
///
/// # Safety
/// Same as `copy_from_user`.
pub(crate) unsafe fn copy_to_user(dst_uptr: u64, src: &[u8]) -> Result<(), u64> {
    validate_user_range(dst_uptr, src.len())?;
    let dst = dst_uptr as *mut u8;
    // SAFETY: src is a live kernel slice; dst is range-validated; the
    // guarded copy opens the SMAP bracket itself and catches any
    // unrecoverable fault as Err — see copy_from_user.
    #[cfg(target_arch = "x86_64")]
    // SAFETY: Valid memory or trusted environment
    unsafe {
        narf_arch::x86_64::smap::copy_user_guarded(dst, src.as_ptr(), src.len())
            .map_err(|_remaining| EFAULT)?;
    }
    // SAFETY: src is a live kernel slice; dst is range-validated; the
    // guarded copy catches any unrecoverable EL1 data abort as Err — see
    // copy_from_user. Healable faults heal first and the copy resumes.
    #[cfg(target_arch = "aarch64")]
    // SAFETY: Valid memory or trusted environment
    unsafe {
        narf_arch::aarch64::uaccess::copy_user_guarded(dst, src.as_ptr(), src.len())
            .map_err(|_remaining| EFAULT)?;
    }
    // SAFETY: any other target — plain volatile write of each in-range user
    // byte (no fault-fixup surface implemented there).
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    // SAFETY: Valid memory or trusted environment
    unsafe {
        for (i, b) in src.iter().enumerate() {
            core::ptr::write_volatile(dst.add(i), *b);
        }
    }
    Ok(())
}

// Wave-71: Linux MS_* flag bits — userspace passes them in arg5.
// Only the bits NARF acts on are documented here; the rest are
// accepted but currently a no-op (relatime, nosuid, nodev, noexec,
// ro modulate read-only state — they're parked until the FsInstance
// trait grows a per-mount option vector).
const MS_RDONLY: u64 = 1 << 0;
const MS_NOSUID: u64 = 1 << 1;
const MS_NODEV: u64 = 1 << 2;
const MS_NOEXEC: u64 = 1 << 3;
const MS_REMOUNT: u64 = 1 << 5;
const MS_BIND: u64 = 1 << 12;
const MS_MOVE: u64 = 1 << 13;
const MS_REC: u64 = 1 << 14;
// Mount-propagation flags. When any of these is set, Linux `mount(2)` ONLY
// changes the propagation type of the mount already at `target` — source,
// fstype and data are ignored and nothing new is mounted. NARF does not model
// propagation (all mounts are effectively private), so honouring these as a
// no-op success is the correct behaviour. systemd's generator/service sandbox
// does `mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL)` right after
// `clone(CLONE_NEWNS)`; failing it aborted the sandbox fork ("Protocol error")
// and left an empty generator dir that tripped systemd's rm_rf root-guard.
const MS_UNBINDABLE: u64 = 1 << 17;
const MS_PRIVATE: u64 = 1 << 18;
const MS_SLAVE: u64 = 1 << 19;
const MS_SHARED: u64 = 1 << 20;
const MS_PROPAGATION: u64 = MS_UNBINDABLE | MS_PRIVATE | MS_SLAVE | MS_SHARED;
const MS_RELATIME: u64 = 1 << 21;

// Wave-71: Linux MNT_* flags for umount2(2).
const MNT_FORCE: u64 = 1 << 0;
const MNT_DETACH: u64 = 1 << 1;
const MNT_EXPIRE: u64 = 1 << 2;
const UMOUNT_NOFOLLOW: u64 = 1 << 3;

/// Linux x86_64 `struct statfs` (fs/statfs). The FIRST field is `f_type`,
/// the filesystem super-magic — programs like elogind statfs a path and check
/// `f_type == CGROUP2_SUPER_MAGIC` to detect an already-mounted cgroup2. The
/// previous shape here was a `statvfs` (started with `f_bsize`), so `f_type`
/// read back as a block size and every magic check failed. 15 × u64 = 120 B.
#[repr(C)]
#[derive(Default)]
struct StatfsBuf {
    f_type: u64,    // filesystem super-magic
    f_bsize: u64,   // block size in bytes
    f_blocks: u64,  // total blocks
    f_bfree: u64,   // free blocks
    f_bavail: u64,  // free blocks available to non-root
    f_files: u64,   // total inodes
    f_ffree: u64,   // free inodes
    f_fsid: u64,    // fs id (two int32; unused → 0)
    f_namelen: u64, // max filename length
    f_frsize: u64,  // fragment size
    f_flags: u64,   // mount flags (unused)
    f_spare0: u64,
    f_spare1: u64,
    f_spare2: u64,
    f_spare3: u64,
}

// Linux super-magics (include/uapi/linux/magic.h) userspace probes for.
const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;
const SYSFS_MAGIC: u64 = 0x6265_6572;
const PROC_SUPER_MAGIC: u64 = 0x9fa0;
const MQUEUE_MAGIC: u64 = 0x1980_0202;
const TMPFS_MAGIC: u64 = 0x0102_1994;
const RAMFS_MAGIC: u64 = 0x8584_58f6;
const EXT2_SUPER_MAGIC: u64 = 0xEF53;

fn fill_statfs_for_path(path: &str, buf_ptr: u64) -> bool {
    if buf_ptr == 0 {
        return false;
    }
    // Both statfs(path) and fstatfs(fd) hand us a path in the caller's
    // namespace: fds deliberately retain a chroot-relative path so
    // /proc/self/fd can expose a reopenable link. Re-root it before finding
    // the backing mount, otherwise a chrooted PID 1's /run resolves against
    // NARF's host root rather than /mnt/run.
    let path = resolve_cwd_path(current_task_id(), path);
    // Map the filesystem covering `path` to its Linux super-magic so callers
    // detect the fs type (elogind → CGROUP2_SUPER_MAGIC at /sys/fs/cgroup).
    let fs = match current_fs_arc_at(&path) {
        Some(fs) => fs,
        None => return false,
    };
    let f_type = match fs.name() {
        "cgroup2" | "cgroup" => CGROUP2_SUPER_MAGIC,
        "sysfs" => SYSFS_MAGIC,
        "procfs" | "proc" => PROC_SUPER_MAGIC,
        "mqueue" => MQUEUE_MAGIC,
        "ramfs" => RAMFS_MAGIC,
        n if n.starts_with("ext") => EXT2_SUPER_MAGIC,
        _ => TMPFS_MAGIC, // tmpfs / devtmpfs / shm / other memfs-backed
    };
    let fs_stat = match poll_blocking(fs.statfs()) {
        Some(Ok(stat)) => stat,
        _ => return false,
    };
    let stat = StatfsBuf {
        f_type,
        f_bsize: u64::from(fs_stat.block_size),
        f_blocks: fs_stat.blocks,
        f_bfree: fs_stat.blocks_free,
        f_bavail: fs_stat.blocks_available,
        f_files: fs_stat.files,
        f_ffree: fs_stat.files_free,
        f_namelen: u64::from(fs_stat.name_len),
        f_frsize: u64::from(fs_stat.fragment_size),
        ..Default::default()
    };
    // Copy the statfs struct to user space under the SMAP bracket.
    // SAFETY: StatfsBuf is repr(C) of fifteen u64s with no padding; transmuting
    // it to a `[u8; size_of::<StatfsBuf>()]` reinterprets its bytes 1:1.
    let bytes: [u8; core::mem::size_of::<StatfsBuf>()] = unsafe { core::mem::transmute(stat) };
    // SAFETY: `buf_ptr` is the user statfs buffer (non-zero, checked above);
    // copy_to_user range-validates it and SMAP-brackets the write of `bytes`.
    unsafe { copy_to_user(buf_ptr, &bytes) }.is_ok()
}

// Per-task mount namespace table. Entries appear when a task calls
// unshare(CLONE_NEWNS) or is created with clone(CLONE_NEWNS); absent entries
// fall back to the global VfsRegistry.
static TASK_MOUNT_NS: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u64, alloc::sync::Arc<narf_filesystem::MountNamespace>>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

fn task_mount_ns_init() {
    let mut g = TASK_MOUNT_NS.lock();
    if g.is_none() {
        *g = Some(alloc::collections::BTreeMap::new());
    }
}

/// Look up the calling task's mount namespace. None means the task
/// shares the global registry (the default).
pub fn current_mount_namespace() -> Option<alloc::sync::Arc<narf_filesystem::MountNamespace>> {
    let task = current_task_id();
    let g = TASK_MOUNT_NS.lock();
    g.as_ref().and_then(|m| m.get(&task).cloned())
}

pub(crate) fn snapshot_current_mount_namespace() -> alloc::sync::Arc<narf_filesystem::MountNamespace>
{
    current_mount_namespace()
        .map(|ns| ns.snapshot())
        .unwrap_or_else(narf_filesystem::MountNamespace::snapshot_global)
}

pub(crate) fn clear_current_mount_namespace_for_test() {
    let task = current_task_id();
    if let Some(namespaces) = TASK_MOUNT_NS.lock().as_mut() {
        namespaces.remove(&task);
    }
}

/// Test hook — ABI smokes share one kernel image, so reset every task's
/// namespace rather than relying on whichever task-id lookup a prior test
/// left installed.
#[doc(hidden)]
pub fn __test_mount_namespaces_reset() {
    *TASK_MOUNT_NS.lock() = Some(alloc::collections::BTreeMap::new());
}

pub(crate) fn current_resolve_absolute<R, F>(path: &str, resolve: F) -> Option<R>
where
    F: FnOnce(&dyn narf_filesystem::FsInstance, &str) -> R,
{
    if let Some(ns) = current_mount_namespace() {
        ns.resolve_absolute(path, resolve)
    } else {
        narf_filesystem::registry().resolve_absolute(path, resolve)
    }
}

/// Namespace-aware `resolve_parent_absolute`. Every directory-MUTATION
/// syscall must go through this rather than `registry()` directly, or a task
/// in a private mount namespace can create a file it cannot then rename or
/// unlink — see `MountNamespace::resolve_parent_absolute`.
pub(crate) fn current_resolve_parent_absolute<R, F>(path: &str, f: F) -> Option<R>
where
    F: FnOnce(
        &dyn narf_filesystem::FsInstance,
        alloc::sync::Arc<dyn narf_filesystem::DirOps>,
        &str,
    ) -> R,
{
    if let Some(ns) = current_mount_namespace() {
        ns.resolve_parent_absolute(path, f)
    } else {
        narf_filesystem::registry().resolve_parent_absolute(path, f)
    }
}

/// Namespace-aware `resolve_two_parents_absolute` — the cross-DIRECTORY
/// rename counterpart of [`current_resolve_parent_absolute`].
pub(crate) fn current_resolve_two_parents_absolute<R, F>(a: &str, b: &str, f: F) -> Option<R>
where
    F: FnOnce(
        &dyn narf_filesystem::FsInstance,
        alloc::sync::Arc<dyn narf_filesystem::DirOps>,
        &str,
        alloc::sync::Arc<dyn narf_filesystem::DirOps>,
        &str,
    ) -> R,
{
    if let Some(ns) = current_mount_namespace() {
        ns.resolve_two_parents_absolute(a, b, f)
    } else {
        narf_filesystem::registry().resolve_two_parents_absolute(a, b, f)
    }
}

pub(crate) fn current_clone_tree_at(
    path: &str,
) -> Option<alloc::sync::Arc<dyn narf_filesystem::FsInstance>> {
    if let Some(ns) = current_mount_namespace() {
        ns.clone_tree_at(path)
    } else {
        narf_filesystem::registry().clone_tree_at(path)
    }
}

pub(crate) fn current_fs_arc_at(
    path: &str,
) -> Option<alloc::sync::Arc<dyn narf_filesystem::FsInstance>> {
    if let Some(ns) = current_mount_namespace() {
        ns.fs_arc_at(path)
    } else {
        narf_filesystem::registry().fs_arc_at(path)
    }
}

fn current_mount_list() -> alloc::vec::Vec<alloc::string::String> {
    current_mount_namespace()
        .map(|ns| ns.list())
        .unwrap_or_else(|| narf_filesystem::registry().list())
}

type DetachedMountSubtree = (
    alloc::sync::Arc<dyn narf_filesystem::FsInstance>,
    alloc::vec::Vec<(
        alloc::string::String,
        alloc::sync::Arc<dyn narf_filesystem::FsInstance>,
    )>,
);

pub(crate) fn current_clone_mount_subtree(path: &str) -> Option<DetachedMountSubtree> {
    let base = if path == "/" {
        "/"
    } else {
        path.trim_end_matches('/')
    };
    let root = current_clone_tree_at(base)?;
    let paths = current_mount_namespace()
        .map(|ns| ns.list())
        .unwrap_or_else(|| narf_filesystem::registry().list());
    let mut seen = alloc::collections::BTreeSet::new();
    let mut descendants = alloc::vec::Vec::new();
    for mount_path in paths {
        if mount_path.len() <= base.len()
            || !mount_path.starts_with(base)
            || (base != "/" && mount_path.as_bytes().get(base.len()) != Some(&b'/'))
        {
            continue;
        }
        let relative = if base == "/" {
            alloc::format!("/{}", mount_path.trim_start_matches('/'))
        } else {
            alloc::string::String::from(&mount_path[base.len()..])
        };
        if !seen.insert(relative.clone()) {
            continue;
        }
        if let Some(fs) = current_fs_arc_at(&mount_path) {
            descendants.push((relative, fs));
        }
    }
    descendants.sort_by_key(|(relative, _)| relative.len());
    Some((root, descendants))
}

fn current_mount_list_with_names() -> alloc::vec::Vec<(alloc::string::String, alloc::string::String)>
{
    current_mount_namespace()
        .map(|ns| ns.list_with_names())
        .unwrap_or_else(|| narf_filesystem::registry().list_with_names())
}

fn current_mount_id_at(path: &str) -> Option<u64> {
    match current_mount_namespace() {
        Some(ns) => ns.mount_id_at(path),
        None => narf_filesystem::registry().mount_id_at(path),
    }
}

/// Whether `path` is the visible root of a mount in the calling task's
/// namespace. This is deliberately an exact-path lookup: a file *under* a
/// mount inherits its mount ID, but is not itself a mount root.
fn current_path_is_mount_root(path: &str) -> bool {
    let path = if path == "/" {
        path
    } else {
        path.trim_end_matches('/')
    };
    current_mount_namespace()
        .map(|ns| ns.list().iter().any(|mount| mount == path))
        .unwrap_or_else(|| {
            narf_filesystem::registry()
                .list()
                .iter()
                .any(|mount| mount == path)
        })
}

pub(crate) fn current_mount_arc(
    authority: &narf_capabilities::Cap<narf_filesystem::MountPoint, narf_capabilities::Grant>,
    path: &str,
    fs: alloc::sync::Arc<dyn narf_filesystem::FsInstance>,
) -> Result<
    narf_capabilities::Cap<narf_filesystem::MountPoint, narf_capabilities::Write>,
    narf_filesystem::FsError,
> {
    if let Some(ns) = current_mount_namespace() {
        ns.mount_arc(authority, path, fs)
    } else {
        narf_filesystem::registry().mount_arc(authority, path, fs)
    }
}

fn current_bind_mount(
    authority: &narf_capabilities::Cap<narf_filesystem::MountPoint, narf_capabilities::Grant>,
    source: &str,
    target: &str,
) -> Result<
    narf_capabilities::Cap<narf_filesystem::MountPoint, narf_capabilities::Write>,
    narf_filesystem::FsError,
> {
    if let Some(ns) = current_mount_namespace() {
        ns.bind_mount(authority, source, target)
    } else {
        narf_filesystem::registry().bind_mount(authority, source, target)
    }
}

fn current_move_mount(
    authority: &narf_capabilities::Cap<narf_filesystem::MountPoint, narf_capabilities::Grant>,
    source: &str,
    target: &str,
) -> Result<(), narf_filesystem::FsError> {
    if let Some(ns) = current_mount_namespace() {
        let _ = authority;
        ns.move_mount(source, target)
    } else {
        narf_filesystem::registry().move_mount(authority, source, target)
    }
}

/// Look up the mount namespace of an arbitrary task by id.
pub fn mount_namespace_of(task: u64) -> Option<alloc::sync::Arc<narf_filesystem::MountNamespace>> {
    let g = TASK_MOUNT_NS.lock();
    g.as_ref().and_then(|m| m.get(&task).cloned())
}

/// Stable nsfs identity for the shared initial mount namespace. Unlike a
/// private `MountNamespace`, this namespace is backed directly by the global
/// registry and therefore has no snapshot object to hold.
#[cfg(feature = "container")]
fn initial_mount_namespace_id() -> u64 {
    use core::sync::atomic::{AtomicU64, Ordering};
    static ID: AtomicU64 = AtomicU64::new(0);
    let current = ID.load(Ordering::Acquire);
    if current != 0 {
        return current;
    }
    let fresh = crate::namespaces::alloc_ns_id();
    match ID.compare_exchange(0, fresh, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => fresh,
        Err(existing) => existing,
    }
}

/// Mint the real namespace fd named by `/proc/<pid>/ns/<flavour>` or the
/// equivalent pidfd ioctl. Mount and cgroup namespaces are bridged here
/// because their backing objects live outside `userspace::namespaces`.
#[cfg(feature = "container")]
pub fn namespace_fd_for_task(
    task: u64,
    flavour: crate::namespaces::NsFlavour,
) -> Option<alloc::sync::Arc<crate::namespaces::NsFd>> {
    use crate::namespaces::{HeldNs, NsFd, NsFlavour};
    let held = match flavour {
        NsFlavour::Mnt => mount_namespace_of(task)
            .map(HeldNs::Mnt)
            .unwrap_or_else(|| HeldNs::MntGlobal(initial_mount_namespace_id())),
        NsFlavour::Cgroup => {
            #[cfg(feature = "cgroup")]
            {
                // Procfs namespace fds are also exercised before the normal
                // cross-crate init path in host tests.  Install the shared
                // allocator here as well so the initial cgroup namespace can
                // never be minted with the filesystem fallback identity 0.
                narf_filesystem::install_ns_id_alloc_hook(crate::namespaces::alloc_ns_id);
                let pid = task_to_pid_raw(task).unwrap_or(task);
                HeldNs::Cgroup(narf_filesystem::cgroupfs::cgroup_namespace_of(pid))
            }
            #[cfg(not(feature = "cgroup"))]
            {
                return None;
            }
        }
        other => return crate::namespaces::ns_fd_for(task, other),
    };
    Some(NsFd::new(held))
}

/// Rejoin the shared initial mount namespace represented by `MntGlobal`.
#[cfg(feature = "container")]
pub fn install_initial_mount_namespace(task: u64) {
    if let Some(namespaces) = TASK_MOUNT_NS.lock().as_mut() {
        namespaces.remove(&task);
    }
}

/// Wave-67 — install a private mount namespace for `task`. Replaces
/// any existing entry. Used by `setns` and the fork-inheritance
/// path.
pub fn install_mount_namespace(task: u64, ns: alloc::sync::Arc<narf_filesystem::MountNamespace>) {
    task_mount_ns_init();
    let mut g = TASK_MOUNT_NS.lock();
    if let Some(m) = g.as_mut() {
        m.insert(task, ns);
    }
}

/// Wave-67 — child inherits the parent's mount namespace by Arc
/// share (no deep clone — they keep the same view until one calls
/// unshare(CLONE_NEWNS) again). A parent in the root-global view
/// leaves the child in the same root-global view.
pub(crate) fn mount_ns_inherit(parent_task: u64, child_task: u64) {
    let parent_ns = {
        let g = TASK_MOUNT_NS.lock();
        g.as_ref().and_then(|m| m.get(&parent_task).cloned())
    };
    if let Some(ns) = parent_ns {
        install_mount_namespace(child_task, ns);
    }
}

// ── procfs /proc/<pid>/ns/* + uid_map/gid_map + mountinfo hooks ──
//
// Installed via `narf_filesystem::procfs::install_ns_proc_hooks` at
// boot so procfs can render namespace state without depending on the
// namespaces module. All take an OUTER pid (what /proc/<pid> names)
// and resolve it to a TaskId.

/// `/proc/<pid>/ns/<flavour>` readlink text, e.g. "uts:[42]".
#[cfg(feature = "container")]
pub fn proc_ns_readlink(pid: u64, tag: u8) -> Option<alloc::string::String> {
    use narf_filesystem::procfs::ns_tag;
    let task = pid_to_task_raw(pid).unwrap_or(pid);
    let flavour = match tag {
        ns_tag::UTS => crate::namespaces::NsFlavour::Uts,
        ns_tag::NET => crate::namespaces::NsFlavour::Net,
        ns_tag::IPC => crate::namespaces::NsFlavour::Ipc,
        ns_tag::PID => crate::namespaces::NsFlavour::Pid,
        ns_tag::MNT => crate::namespaces::NsFlavour::Mnt,
        ns_tag::USER => crate::namespaces::NsFlavour::User,
        ns_tag::CGROUP => crate::namespaces::NsFlavour::Cgroup,
        _ => return None,
    };
    namespace_fd_for_task(task, flavour).map(|fd| fd.link_text())
}

/// `/proc/<pid>/mountinfo` in the task's visible mount and chroot view.
///
/// The global registry stores backing paths, while a task with a chroot must
/// observe those paths relative to its root. Returning `None` for a global
/// task used to make procfs render the backing paths directly (for example
/// `/mnt/sys/kernel/debug` to PID 1 rooted at `/mnt`), so systemd could not
/// find the mount it had just created when it rescanned mountinfo.
pub fn proc_ns_mountinfo(pid: u64) -> Option<alloc::string::String> {
    let task = pid_to_task_raw(pid).unwrap_or(pid);
    let process_root = root_dir_of(task).unwrap_or_else(|| alloc::string::String::from("/"));
    let mut s = alloc::string::String::new();
    use core::fmt::Write as _;
    let rows = mount_namespace_of(task)
        .map(|ns| ns.list_mountinfo())
        .unwrap_or_else(|| narf_filesystem::registry().list_mountinfo());
    for (id, parent, path, name) in rows {
        let visible = if process_root == "/" {
            path
        } else if path == process_root {
            alloc::string::String::from("/")
        } else if path.starts_with(process_root.as_str())
            && path.as_bytes().get(process_root.len()) == Some(&b'/')
        {
            alloc::string::String::from(&path[process_root.len()..])
        } else {
            continue;
        };
        let _ = writeln!(s, "{}\t{}\t{}\t{}", id, parent, visible, name);
    }
    Some(s)
}

/// Current mount-table generation in the named task's mount namespace. Procfs
/// uses this to expose Linux's `POLLPRI` edge on an open mountinfo file after
/// attach, detach, or move operations.
pub fn proc_ns_mountinfo_generation(pid: u64) -> u64 {
    let task = pid_to_task_raw(pid).unwrap_or(pid);
    mount_namespace_of(task)
        .map(|ns| ns.mountinfo_generation())
        .unwrap_or_else(|| narf_filesystem::registry().mountinfo_generation())
}

/// `/proc/<pid>/{uid,gid}_map` render.
#[cfg(feature = "container")]
pub fn proc_ns_idmap_render(pid: u64, is_uid: bool) -> Option<alloc::string::String> {
    let task = pid_to_task_raw(pid).unwrap_or(pid);
    Some(crate::namespaces::current_user_ns(task).render_map(is_uid))
}

/// `/proc/<pid>/{uid,gid}_map` write — parses the Linux triple lines
/// `inner outer count` and applies them under the one-shot rule.
#[cfg(feature = "container")]
pub fn proc_ns_idmap_write(
    pid: u64,
    is_uid: bool,
    bytes: &[u8],
) -> Result<usize, narf_filesystem::FsError> {
    let task = pid_to_task_raw(pid).unwrap_or(pid);
    let text = core::str::from_utf8(bytes).map_err(|_| narf_filesystem::FsError::InvalidData)?;
    let mut entries = alloc::vec::Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut it = line.split_whitespace();
        let inner: u32 = it
            .next()
            .and_then(|v| v.parse().ok())
            .ok_or(narf_filesystem::FsError::InvalidData)?;
        let outer: u32 = it
            .next()
            .and_then(|v| v.parse().ok())
            .ok_or(narf_filesystem::FsError::InvalidData)?;
        let count: u32 = it
            .next()
            .and_then(|v| v.parse().ok())
            .ok_or(narf_filesystem::FsError::InvalidData)?;
        if it.next().is_some() || count == 0 {
            return Err(narf_filesystem::FsError::InvalidData);
        }
        entries.push(crate::namespaces::IdMapEntry {
            inner_start: inner,
            outer_start: outer,
            count,
        });
    }
    let uns = crate::namespaces::current_user_ns(task);
    let r = if is_uid {
        uns.write_uid_map(entries)
    } else {
        uns.write_gid_map(entries)
    };
    r.map(|_| bytes.len())
        .map_err(|_| narf_filesystem::FsError::InvalidData)
}

// ── Wave-67: setns(target, nstype) ─────────────────────────────────
//
// Linux setns takes a namespace fd opened from /proc/[pid]/ns/<type> (or
// returned by a pidfd namespace ioctl). NARF supports that primary path and
// retains the older TaskId/ProcessId form only for compatibility tests.

// ── Wave-71: Per-task chroot table ────────────────────────────────
//
// Tracks each task's chroot-overridden notion of `/`. Absent entries
// mean the task sees the global root; present entries cause every
// absolute path the task hands to a path-resolving syscall to be
// rewritten under the stored prefix before resolution.
//
// pivot_root atomically replaces the entry; chroot installs it
// directly. fork inherits parent's entry; exec preserves it.
// Stored under linux-compat because chroot(2) is the entry point;
// pivot_root reuses the same slot.

static ROOT_DIR_TABLE: TaskMapTable<alloc::string::String> =
    [const { TaskMapShard::new() }; TASK_MAP_SHARDS];

/// Diagnostic: read the chroot prefix for `task`, or `None` if the
/// task sees the global root. Used by tests + procfs.
pub fn root_dir_of(task: u64) -> Option<alloc::string::String> {
    task_map_get(&ROOT_DIR_TABLE, task)
}

/// Install the filesystem root for a task before its first instruction.
///
/// Kernel boot uses this to make a directly loaded dynamic PID 1 observe the
/// mounted distro root from its first interpreter and pathname lookup.  It is
/// the same per-task root state `chroot(2)` installs, but does not require a
/// temporary userspace launcher to perform that syscall.
pub fn install_root_dir(task: u64, root: &str) -> bool {
    if !root.starts_with('/') {
        return false;
    }
    let root = root.trim_end_matches('/');
    let root = if root.is_empty() { "/" } else { root };
    task_map_set(&ROOT_DIR_TABLE, task, alloc::string::String::from(root));
    true
}


/// fork(2) inheritance — child inherits parent's chroot.
pub fn root_dir_fork(parent: u64, child: u64) {
    task_map_fork(&ROOT_DIR_TABLE, parent, child);
}

/// Test hook — drop every per-task entry.
#[doc(hidden)]
pub fn __test_root_dir_reset() {
    task_map_init(&ROOT_DIR_TABLE);
}

/// Rewrite `path` under the calling task's chroot, if any. Absolute
/// paths get the chroot prefix prepended; relative paths pass
/// through unchanged. Joining strips a leading `/` from `path` so
/// the result has no double-slash.
pub(crate) fn apply_chroot(path: &str) -> alloc::string::String {
    let task = current_task_id();
    let prefix = match task_map_get(&ROOT_DIR_TABLE, task) {
        Some(p) => p,
        None => return alloc::string::String::from(path),
    };
    if !path.starts_with('/') {
        return alloc::string::String::from(path);
    }
    // Compose prefix + path; prefix has no trailing `/` (except when
    // it equals `/`), path starts with `/`.
    let mut out = alloc::string::String::with_capacity(prefix.len() + path.len());
    if prefix != "/" {
        out.push_str(&prefix);
    }
    out.push_str(path);
    out
}


// ── Wave-71: chroot(2) ────────────────────────────────────────────

// ── Wave-71: pivot_root(2) ────────────────────────────────────────
//
// Linux semantics: the calling task's old root becomes accessible at
// `put_old` (an absolute path under `new_root`), and `new_root`
// becomes the new `/`. NARF approximation: register `put_old`
// (resolved under the new root) as a bind mount of the previous
// root path, then install the new chroot.

// ── Wave-71 test hooks ────────────────────────────────────────────
//
// Smokes in `mount_e2e_tests` drive the syscall handlers through a
// synthetic TrapContext + kernel-heap path buffers. These thin
// wrappers expose the file-private handlers without re-exporting
// the entire `sys_*` family.

#[doc(hidden)]
pub fn apply_chroot_for_test(p: &str) -> alloc::string::String {
    apply_chroot(p)
}

// ── ClockGetTime — write timespec to user buffer ──────────────────
//
// arg0 = clock id (POSIX-shaped):
//   0 = CLOCK_REALTIME   — wall time via `time::now_wall()`,
//                          driven by `set_wall_offset` / leap-smear.
//   1 = CLOCK_MONOTONIC  — `narf_time::monotonic_ns()`.
//   Anything else → InvalidOp (no boot-time / process-cpu clocks yet).
//
// arg1 is the user vaddr of a `timespec { i64 tv_sec; i64 tv_nsec; }`.
// Handlers run in the calling task's CR3 / TTBR so the user pointer
// resolves directly.
//
// The wall offset starts at 0 (the kernel's "epoch" coincides with
// boot-time monotonic 0), and a future userspace `settimeofday`
// surface will drive `set_wall_offset` to push it onto Unix time.
// Until then a CLOCK_REALTIME read just looks like a monotonic
// counter — which still satisfies the documented C99 "monotonic
// non-decreasing" contract that `clock_gettime` consumers check.

const CLOCK_REALTIME: u64 = 0;
const CLOCK_MONOTONIC: u64 = 1;
const CLOCK_PROCESS_CPUTIME_ID: u64 = 2;
const CLOCK_THREAD_CPUTIME_ID: u64 = 3;
// Wave-73: CLOCK_MONOTONIC_RAW skips NTP slew (we have no NTP, so
// RAW == MONOTONIC for now). CLOCK_BOOTTIME counts wall time across
// suspend (no suspend support → same as MONOTONIC).
const CLOCK_MONOTONIC_RAW: u64 = 4;
const CLOCK_REALTIME_COARSE: u64 = 5;
const CLOCK_MONOTONIC_COARSE: u64 = 6;
const CLOCK_BOOTTIME: u64 = 7;

// ── I/O Priority (ioprio_set / ioprio_get) ─────────────────────────
//
// Store I/O priority per (which, who) tuple. ioprio_get returns the
// stored value or a Linux default.

static IOPRIO_TABLE: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<(i32, u64), u32>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

// ── Signal delivery: pending + mask + delivery hook ────────────────
//
// Stage-4 round 2: kill / sigprocmask + a hook on the trap-return
// path that, for any int-0x80 from user mode, picks the lowest
// pending unmasked signal, looks up its handler in the SIGACTION
// table, and rewrites the trap frame so iretq lands at the user
// handler with `[saved_rip, signum]` synthesised on the user
// stack. The handler signature is `extern "C" fn(u32)` — `signum`
// is in `rdi` (SysV first integer arg), and a `ret` pops the
// saved_rip we pushed and resumes the trapped code.
//
// Storage shape mirrors SIGACTION_TABLE: BTreeMap<task_id, u64
// bitmask>. Two tables: pending signals (set by `kill`) and the
// per-task block mask (modified by `sigprocmask`). Linux _NSIG = 64.
// NARF stores signal N at bit N-1 — IDENTICAL to the userspace
// `sigset_t` convention — so a u64 holds the full valid range 1..=64
// (SIGRTMAX = 64 included, which stress-ng --sigrt installs handlers
// for). Because the internal and ABI layouts match, the sigset ABI
// boundaries copy the mask through verbatim: no `<<1`/`>>1` shim, and
// no "bit 0 is the null signal" hazard — signal 0 simply has no bit.
// Use `sig_bit`/`sig_from_bit` at every conversion so the mapping
// lives in exactly one place.

/// Bit mask for `signum` in the NARF pending/mask u64 (signal N → bit
/// N-1). `signum` must be in 1..=64; out-of-range yields 0 (no bit).
#[inline]
pub(crate) fn sig_bit(signum: u32) -> u64 {
    if signum == 0 || signum > 64 {
        0
    } else {
        1u64 << (signum - 1)
    }
}

/// Signal number of the lowest set bit in `bits` (bit N-1 → signal N),
/// or 0 when `bits` is empty. Inverse of `sig_bit` for the low bit.
#[inline]
pub(crate) fn sig_from_bit(bits: u64) -> u32 {
    if bits == 0 {
        0
    } else {
        bits.trailing_zeros() + 1
    }
}

const SIGNAL_TABLE_BUCKETS: usize = 64;

#[repr(align(64))]
pub(crate) struct SignalBitsBucket {
    values: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u64>>>,
}

impl SignalBitsBucket {
    const fn new() -> Self {
        Self {
            values: narf_lib::sync::IrqSafeSpinLock::new(None),
        }
    }
}

type SignalBitsTable = [SignalBitsBucket; SIGNAL_TABLE_BUCKETS];

pub(crate) static SIGNAL_PENDING: SignalBitsTable =
    [const { SignalBitsBucket::new() }; SIGNAL_TABLE_BUCKETS];
static SIGNAL_READABLE_GEN: SignalBitsTable =
    [const { SignalBitsBucket::new() }; SIGNAL_TABLE_BUCKETS];
/// Per-task generation bumped on EVERY signal raise (unlike SIGNAL_READABLE_GEN,
/// which bumps only on the empty->non-empty transition and also feeds the
/// signalfd EPOLLET edge token). A poll/epoll park snapshots this before its
/// scan (beside `epoll_park_gen`) and the park routine re-checks it after
/// registering the signal waker: a raise in the scan->register window (which
/// `is_signal_pending`'s block-filter misses for a BLOCKED signal a signalfd
/// reads) advances the generation and forces a re-execution instead of a park
/// on the ~10 ms lost-wake backstop. Edge, not level, so a STANDING
/// blocked-pending signal with no fresh raise never spins.
static SIGNAL_RAISE_GEN: SignalBitsTable =
    [const { SignalBitsBucket::new() }; SIGNAL_TABLE_BUCKETS];

#[inline]
fn signal_bits_bucket(task: u64) -> usize {
    // Task IDs are monotonic and already carry entropy in their low bits.
    task as usize & (SIGNAL_TABLE_BUCKETS - 1)
}

#[inline]
fn signal_bits_get_opt(table: &SignalBitsTable, task: u64) -> Option<u64> {
    table[signal_bits_bucket(task)]
        .values
        .lock()
        .as_ref()
        .and_then(|map| map.get(&task).copied())
}

#[inline]
fn signal_bits_get(table: &SignalBitsTable, task: u64) -> u64 {
    signal_bits_get_opt(table, task).unwrap_or(0)
}

fn signal_bits_clear(table: &SignalBitsTable) {
    for bucket in table {
        *bucket.values.lock() = Some(BTreeMap::new());
    }
}

fn signal_bits_remove(table: &SignalBitsTable, task: u64) {
    if let Some(map) = table[signal_bits_bucket(task)].values.lock().as_mut() {
        map.remove(&task);
    }
}

fn signal_bits_contains(table: &SignalBitsTable, task: u64) -> bool {
    table[signal_bits_bucket(task)]
        .values
        .lock()
        .as_ref()
        .is_some_and(|map| map.contains_key(&task))
}

fn signal_bits_update<R>(
    table: &SignalBitsTable,
    task: u64,
    update: impl FnOnce(&mut u64) -> R,
) -> Option<R> {
    let mut values = table[signal_bits_bucket(task)].values.lock();
    let slot = values.as_mut()?.entry(task).or_insert(0);
    Some(update(slot))
}

fn signal_bits_update_or_init<R>(
    table: &SignalBitsTable,
    task: u64,
    update: impl FnOnce(&mut u64) -> R,
) -> R {
    let mut values = table[signal_bits_bucket(task)].values.lock();
    let slot = values
        .get_or_insert_with(BTreeMap::new)
        .entry(task)
        .or_insert(0);
    update(slot)
}

fn signal_bits_update_existing<R>(
    table: &SignalBitsTable,
    task: u64,
    update: impl FnOnce(&mut u64) -> R,
) -> Option<R> {
    let mut values = table[signal_bits_bucket(task)].values.lock();
    let slot = values.as_mut()?.get_mut(&task)?;
    Some(update(slot))
}

/// Test hook: expose only shard identity so signal smokes can guarantee they
/// exercise independent task buckets.
#[doc(hidden)]
pub fn __test_signal_bucket_index(task: u64) -> usize {
    signal_bits_bucket(task)
}

// ── Per-task CPU-time accounting (getrusage / times) ────────────────
//
// NARF previously reported `monotonic_ns()` (wall-clock uptime since
// boot) as every process's user CPU time — so getrusage(RUSAGE_SELF)
// / times() returned the same huge, ever-growing value for every
// task, inflating e.g. stress-ng's per-stressor usr-time ~17x. These
// two tables instead track REAL consumed CPU time, keyed by TaskId
// (tid) — the same key getrusage/times resolve via current_task_id().
//
// `TASK_CPU_NS`: nanoseconds this task itself has spent executing in
// user mode, summed over every user run-slice (accumulated by the
// UserTaskFuture poll boundary in user_task.rs: it brackets each
// enter-user-mode → trap-return slice and folds the delta in here).
// The ledgers are per-CPU: hot-path folds touch only the executing CPU's
// cache line, while cold readers aggregate a task across every CPU it ran on.
// This mirrors Linux's per-CPU accounting shape and removes the global lock
// cache-line bounce between unrelated tasks on different CPUs.
//
// `TASK_CHILD_CPU_NS`: nanoseconds of CPU time charged to this task's
// REAPED children (RUSAGE_CHILDREN / tms.cutime), folded in by wait4 /
// waitid when a zombie is collected (Linux charges child time at reap,
// not at exit).
const TASK_ACCOUNT_CPUS: usize = narf_lib::percpu::MAX_CPUS;

/// One CPU's task-time ledger. Cache-line alignment keeps the lock word and
/// BTreeMap root from false-sharing with the neighbouring CPU's hot ledger.
#[repr(align(64))]
struct TaskCpuLedger {
    values: narf_lib::sync::IrqSafeSpinLock<BTreeMap<u64, u64>>,
}

impl TaskCpuLedger {
    const fn new() -> Self {
        Self {
            values: narf_lib::sync::IrqSafeSpinLock::new(BTreeMap::new()),
        }
    }
}

type TaskCpuLedgers = [TaskCpuLedger; TASK_ACCOUNT_CPUS];

static TASK_CPU_NS: TaskCpuLedgers = [const { TaskCpuLedger::new() }; TASK_ACCOUNT_CPUS];

/// Task creation timestamp (monotonic ns) — /proc/[pid]/stat field 22
/// (starttime, in USER_HZ ticks since boot). Recorded by
/// `Task::new_registered`, swept with the other per-task tables.
static TASK_START_NS: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u64>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Record `tid`'s creation time. Called from `Task::new_registered`.
pub(crate) fn record_task_start_ns(tid: u64) {
    let now = narf_scheduler::narf_time::monotonic_ns();
    let mut g = TASK_START_NS.lock();
    g.get_or_insert_with(BTreeMap::new)
        .entry(tid)
        .or_insert(now);
}

fn task_start_ns(tid: u64) -> u64 {
    TASK_START_NS
        .lock()
        .as_ref()
        .and_then(|m| m.get(&tid).copied())
        .unwrap_or(0)
}
static TASK_CHILD_CPU_NS: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u64>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

#[inline]
fn task_account_cpu() -> usize {
    narf_lib::percpu::current_cpu() % TASK_ACCOUNT_CPUS
}

fn task_account_add_on_cpu(ledgers: &TaskCpuLedgers, cpu: usize, task: u64, delta_ns: u64) {
    let mut values = ledgers[cpu % TASK_ACCOUNT_CPUS].values.lock();
    let entry = values.entry(task).or_insert(0);
    *entry = entry.saturating_add(delta_ns);
}

#[inline]
fn task_account_add(ledgers: &TaskCpuLedgers, task: u64, delta_ns: u64) {
    // Keep CPU selection and the update on one CPU. Without this bracket a
    // timer could migrate the task after `current_cpu()` and make the resumed
    // CPU write the old CPU's ledger, reintroducing cross-CPU contention.
    narf_lib::sync::without_interrupts(|| {
        task_account_add_on_cpu(ledgers, task_account_cpu(), task, delta_ns);
    });
}

fn task_account_ensure_on_cpu(ledgers: &TaskCpuLedgers, cpu: usize, task: u64) {
    ledgers[cpu % TASK_ACCOUNT_CPUS]
        .values
        .lock()
        .entry(task)
        .or_insert(0);
}

fn task_account_get(ledgers: &TaskCpuLedgers, task: u64) -> u64 {
    ledgers.iter().fold(0u64, |total, ledger| {
        total.saturating_add(ledger.values.lock().get(&task).copied().unwrap_or(0))
    })
}

#[cfg(feature = "unix-latency-trace")]
fn task_account_try_get(ledgers: &TaskCpuLedgers, task: u64) -> Option<u64> {
    let mut total = 0u64;
    for ledger in ledgers {
        total = total.saturating_add(ledger.values.try_lock()?.get(&task).copied().unwrap_or(0));
    }
    Some(total)
}

fn task_account_remove(ledgers: &TaskCpuLedgers, task: u64) {
    for ledger in ledgers {
        ledger.values.lock().remove(&task);
    }
}

/// Fold a completed user run-slice (`delta_ns` of on-CPU user time) into
/// the currently-running task's accumulated CPU time. Called from the
/// UserTaskFuture poll on every trap-return. Alloc-free on the hot path
/// once the task's slot exists; IRQ-safe (the poll runs with IF=0 around
/// the trap boundary).
pub fn account_user_cpu_ns(delta_ns: u64) {
    if delta_ns == 0 {
        return;
    }
    let task = current_task_id();
    if task == 0 {
        return;
    }
    task_account_add(&TASK_CPU_NS, task, delta_ns);
}

/// Time this task has spent inside syscall handlers (ns) — the
/// ru_stime / tms_stime / stat-field-15 source. Folded by
/// `kernel_syscall_entry`'s dispatch bracket; same shape and cost as
/// the user-time fold above (one map lock per syscall).
static TASK_KERN_NS: TaskCpuLedgers = [const { TaskCpuLedger::new() }; TASK_ACCOUNT_CPUS];

/// Fold a completed syscall's handler duration into the current task's
/// kernel-time accumulator. Called from `kernel_syscall_entry`.
pub fn account_kernel_cpu_ns(delta_ns: u64) {
    if delta_ns == 0 {
        return;
    }
    let task = current_task_id();
    if task == 0 {
        return;
    }
    task_account_add(&TASK_KERN_NS, task, delta_ns);
}

/// Timer-trap-safe `(user_ns, kernel_ns)` for `task`. `None` on lock
/// contention.
///
/// The split is the discriminator when a process burns tens of seconds
/// before it starts serving: overwhelmingly USER time is compute the
/// kernel cannot help with (llvmpipe/LLVM under a software renderer),
/// while a large KERNEL share names the syscall or fault path as the
/// cost, which IS ours.
#[cfg(feature = "unix-latency-trace")]
pub fn cpu_split_ns_try(task: u64) -> Option<(u64, u64)> {
    let u = task_account_try_get(&TASK_CPU_NS, task)?;
    let k = task_account_try_get(&TASK_KERN_NS, task)?;
    Some((u, k))
}

/// Fold the currently-open on-CPU kernel span into `task`'s accumulator and
/// close it. Idempotent: a closed span (start == 0) folds nothing.
///
/// Called at every point the task stops executing kernel code — the park
/// sites and the syscall-dispatch exit — so what accumulates is on-CPU time
/// only, never the sleep in between.
pub fn close_kernel_span(uc: &crate::user_task::UserTaskCtx, task: u64) {
    let start = uc
        .kern_span_start_ns
        .swap(0, core::sync::atomic::Ordering::AcqRel);
    if start == 0 {
        return;
    }
    let now = narf_scheduler::narf_time::monotonic_ns();
    let delta = now.saturating_sub(start);
    if delta == 0 {
        return;
    }
    task_account_add(&TASK_KERN_NS, task, delta);
}

fn open_kernel_span_for(uc: &crate::user_task::UserTaskCtx, task: u64) {
    narf_lib::sync::without_interrupts(|| {
        // The pause hook can close this span from timer IRQ context. Create
        // the task's row here, on the normal syscall path, so that close only
        // updates an existing BTreeMap node and never allocates in the
        // interrupt handler. Keep IRQs masked from CPU selection through the
        // span-start store: otherwise a migration in that window could make
        // the first close on the destination CPU allocate.
        let cpu = task_account_cpu();
        let cpu_bit = 1u64 << cpu;
        if uc
            .kern_account_ready
            .load(core::sync::atomic::Ordering::Acquire)
            & cpu_bit
            == 0
            && task != 0
        {
            task_account_ensure_on_cpu(&TASK_KERN_NS, cpu, task);
            uc.kern_account_ready
                .fetch_or(cpu_bit, core::sync::atomic::Ordering::Release);
        }
        uc.kern_span_start_ns.store(
            narf_scheduler::narf_time::monotonic_ns(),
            core::sync::atomic::Ordering::Release,
        );
    });
}

/// Open (or re-open) the on-CPU kernel span for the current task.
pub fn open_kernel_span(uc: &crate::user_task::UserTaskCtx) {
    open_kernel_span_for(uc, current_task_id());
}

/// Test hook: open a kernel span for an explicit stand-in task. Kernel-test
/// functions execute outside a user-task poll, so the production current-task
/// lookup correctly returns zero there.
#[doc(hidden)]
pub fn __test_open_kernel_span_for(uc: &crate::user_task::UserTaskCtx, task: u64) {
    open_kernel_span_for(uc, task);
}

/// Pause the current user task's active syscall span before the scheduler
/// switches a timer-preempted CPL0 continuation off-CPU. Returns true only
/// when a matching resume must re-open the span.
fn pause_kernel_span_for(uc: &crate::user_task::UserTaskCtx, task: u64) -> bool {
    if uc
        .kern_span_start_ns
        .load(core::sync::atomic::Ordering::Acquire)
        == 0
    {
        return false;
    }
    close_kernel_span(uc, task);
    true
}

pub fn pause_current_kernel_span() -> bool {
    let Some(uc) = crate::user_task::current_user_task() else {
        return false;
    };
    // SAFETY: current_user_task returns the poller-pinned context of the
    // current own-stack user continuation.
    pause_kernel_span_for(unsafe { &*uc }, current_task_id())
}

/// Test hook: pause a kernel span for an explicit stand-in task.
#[doc(hidden)]
pub fn __test_pause_kernel_span_for(uc: &crate::user_task::UserTaskCtx, task: u64) -> bool {
    pause_kernel_span_for(uc, task)
}

/// Resume a syscall span previously paused by `pause_current_kernel_span`.
pub fn resume_current_kernel_span() {
    let Some(uc) = crate::user_task::current_user_task() else {
        return;
    };
    // SAFETY: current_user_task returns the poller-pinned context of the
    // resumed own-stack user continuation.
    open_kernel_span(unsafe { &*uc });
}

/// Elapsed time in the current task's still-open syscall span. Adding this to
/// the folded kernel ledger produces a monotonic live snapshot: close folds
/// the same interval before clearing the start timestamp.
pub fn current_kernel_span_elapsed_ns() -> u64 {
    let Some(uc) = crate::user_task::current_user_task() else {
        return 0;
    };
    // SAFETY: current_user_task returns the poller-pinned context of the
    // current user continuation.
    let start = unsafe { &*uc }
        .kern_span_start_ns
        .load(core::sync::atomic::Ordering::Acquire);
    if start == 0 {
        0
    } else {
        narf_scheduler::narf_time::monotonic_ns().saturating_sub(start)
    }
}

/// This task's accumulated in-syscall (kernel) CPU time (ns).
pub fn kern_time_ns_of(task: u64) -> u64 {
    task_account_get(&TASK_KERN_NS, task)
}

/// Test hook: clear the current task's accumulated in-syscall (kernel) CPU
/// time. The kernel-test harness runs every test as ONE shared task, so every
/// prior test's `kernel_syscall_entry` bracket accumulates here; under slow
/// (TCG) execution that cumulative time crosses one tick and flaps the `times`
/// stime==0 assertion. The times test resets it first so it measures a fresh
/// task, which is what the assertion means.
/// Test hook: clear `task`'s accumulated in-syscall CPU time. The
/// no-argument form only reaches the CURRENT task, which a test driving a
/// stand-in `UserTaskCtx` is not.
#[doc(hidden)]
pub fn __test_reset_kernel_time_for(task: u64) {
    task_account_remove(&TASK_KERN_NS, task);
}

#[doc(hidden)]
pub fn __test_reset_kernel_time() {
    let task = current_task_id();
    task_account_remove(&TASK_KERN_NS, task);
}

/// Test hook: account `delta_ns` to an arbitrary task (the production
/// path only ever charges the currently-running task). Lets the ABI test
/// seed a stand-in child's CPU time to exercise the RUSAGE_CHILDREN fold.
#[doc(hidden)]
pub fn __test_account_cpu_ns(task: u64, delta_ns: u64) {
    task_account_add(&TASK_CPU_NS, task, delta_ns);
}

/// Test hook: seed a task's user CPU time on a selected CPU ledger. Models a
/// task migrating between CPUs without relying on test-runner affinity.
#[doc(hidden)]
pub fn __test_account_cpu_ns_on_cpu(task: u64, cpu: usize, delta_ns: u64) {
    task_account_add_on_cpu(&TASK_CPU_NS, cpu, task, delta_ns);
}

/// Test hook: charge syscall CPU time to a stand-in task so perf inheritance
/// tests can exercise the exit snapshot without running a real child syscall.
#[doc(hidden)]
pub fn __test_account_kernel_ns(task: u64, delta_ns: u64) {
    task_account_add(&TASK_KERN_NS, task, delta_ns);
}

/// Test hook: seed a task's kernel CPU time on a selected CPU ledger.
#[doc(hidden)]
pub fn __test_account_kernel_ns_on_cpu(task: u64, cpu: usize, delta_ns: u64) {
    task_account_add_on_cpu(&TASK_KERN_NS, cpu, task, delta_ns);
}

/// Test hook: model the master exit-table sweep after perf has captured a
/// child's final software-clock contribution.
#[doc(hidden)]
pub fn __test_reset_cpu_times_for(task: u64) {
    task_account_remove(&TASK_CPU_NS, task);
    task_account_remove(&TASK_KERN_NS, task);
}

/// This task's own accumulated user CPU time (ns).
pub fn cpu_time_ns_of(task: u64) -> u64 {
    task_account_get(&TASK_CPU_NS, task)
}

/// Accumulated CPU time (ns) of `task`'s reaped children.
fn child_cpu_time_ns_of(task: u64) -> u64 {
    TASK_CHILD_CPU_NS
        .lock()
        .as_ref()
        .and_then(|m| m.get(&task).copied())
        .unwrap_or(0)
}

// Exit-time rusage snapshot: `(cpu_ns, vm_kb)` captured in the DYING
// task's own context — the only point where its address space is still
// resolvable (`current_address_space`); by reap time the scheduler slot
// that owned the AS Arc is long dropped, so a reap-time
// `task_vm_bytes(child)` reads 0. Consumed (removed) at reap by both
// the synchronous wait4 path and `finish_wait_child`; an orphan that is
// never reaped leaks one small entry, same lifetime class as its
// PENDING_EXITS record.
static EXIT_RUSAGE: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, (u64, u64)>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Snapshot the current (dying) task's rusage numbers for its parent's
/// wait4. MUST run in the exiting task's own trap context. Keyed by the
/// VISIBLE pid — the key wait4 reaps with — while the CPU tables are
/// read by tid (fork mints ProcessId and TaskId separately).
pub(crate) fn record_exit_rusage(tid: u64, pid: u64) {
    // Include the CURRENT (never-to-be-yielded) slice: the dying task is
    // mid-slice right now and exit_current_stackful switches away without
    // folding it.
    let cpu = cpu_time_ns_of(tid)
        .saturating_add(child_cpu_time_ns_of(tid))
        .saturating_add(narf_scheduler::stackful::current_slice_elapsed_ns());
    let vm_kb = task_vm_bytes(tid) / 1024;
    let mut g = EXIT_RUSAGE.lock();
    g.get_or_insert_with(BTreeMap::new)
        .insert(pid, (cpu, vm_kb));
}

fn take_exit_rusage(tid: u64) -> Option<(u64, u64)> {
    let mut g = EXIT_RUSAGE.lock();
    g.as_mut().and_then(|m| m.remove(&tid))
}

// The user `struct rusage*` of the parent's IN-FLIGHT blocking wait4,
// keyed by parent tid. `finish_wait_child` runs as the parent (both the
// poll route and own_stack_wait_child) but only receives the status
// pointer, so the rusage pointer travels through this table. Every
// blocking wait entry (wait4 AND waitid) overwrites its slot — waitid
// with 0 — so a stale pointer from an aborted wait can never be written
// through by a later one.
static WAIT_RUSAGE_PTR: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u64>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

fn set_wait_rusage_ptr(parent: u64, ptr: u64) {
    let mut g = WAIT_RUSAGE_PTR.lock();
    g.get_or_insert_with(BTreeMap::new).insert(parent, ptr);
}

fn take_wait_rusage_ptr(parent: u64) -> u64 {
    let mut g = WAIT_RUSAGE_PTR.lock();
    g.as_mut().and_then(|m| m.remove(&parent)).unwrap_or(0)
}

/// Reaping `child` from `parent`: charge the child's total CPU time (its
/// own + whatever it had already accumulated from its own reaped
/// grandchildren, per POSIX) to the parent's child-time accumulator, then
/// drop the child's rows. Returns the child's total CPU ns so wait4 can
/// also fill its `struct rusage` out-param. Idempotent-safe: a second
/// reap of an already-dropped child contributes 0.
pub fn account_reaped_child(parent: u64, child: u64) -> u64 {
    // `child` is the VISIBLE pid (wait4's reap key); the CPU tables key
    // on TaskId (folds run under current_task_id()). Fork mints the two
    // separately, so an untranslated lookup read 0 for every forked
    // child — `time`'s user column showed 0.00 for a 5 s burn (alpine
    // probe). Translate first, like proc_task_info does.
    let child_tid = pid_to_task_raw(child).unwrap_or(child);
    let child_total = cpu_time_ns_of(child_tid).saturating_add(child_cpu_time_ns_of(child_tid));
    if parent != 0 {
        let mut g = TASK_CHILD_CPU_NS.lock();
        let m = g.get_or_insert_with(BTreeMap::new);
        let e = m.entry(parent).or_insert(0);
        *e = e.saturating_add(child_total);
    }
    task_account_remove(&TASK_CPU_NS, child_tid);
    if let Some(m) = TASK_CHILD_CPU_NS.lock().as_mut() {
        m.remove(&child_tid);
    }
    child_total
}

/// Write a glibc `struct rusage` (18 i64s = 144 bytes) into user memory
/// with `ru_utime` set from `ns` and every other field zero. Best-effort
/// (a failed copy is swallowed — wait4 still succeeds). Shared by wait4's
/// rusage out-param.
fn write_rusage_utime(out_ptr: u64, ns: u64, maxrss_kb: u64) {
    let mut kbuf = [0u8; 18 * 8];
    let sec = (ns / 1_000_000_000) as i64;
    let usec = ((ns % 1_000_000_000) / 1_000) as i64;
    kbuf[..8].copy_from_slice(&sec.to_ne_bytes()); // ru_utime.tv_sec
    kbuf[8..16].copy_from_slice(&usec.to_ne_bytes()); // ru_utime.tv_usec
                                                      // ru_stime (16..32) stays 0 — NARF doesn't split kernel time out.
    kbuf[32..40].copy_from_slice(&(maxrss_kb as i64).to_ne_bytes()); // ru_maxrss (KB)
                                                                     // SAFETY: `out_ptr` is the user `struct rusage` pointer (non-zero,
                                                                     // checked by the caller); copy_to_user range-validates and
                                                                     // SMAP-brackets the 144-byte write.
    let _ = unsafe { copy_to_user(out_ptr, &kbuf) };
}

/// Total mapped bytes of `pid`'s address space (region-span sum) —
/// the `ru_maxrss` source. NARF has no per-page RSS or peak tracking,
/// so this reports the CURRENT (for a zombie: final) VM footprint,
/// an honest lower-noise stand-in for "peak resident" that gives
/// `time -v`-style consumers a real number instead of 0.
fn task_vm_bytes(pid: u64) -> u64 {
    let as_arc = narf_scheduler::address_space_of(narf_scheduler::TaskId(pid)).or_else(|| {
        if pid == current_task_id() {
            narf_scheduler::current_address_space()
        } else {
            None
        }
    });
    match as_arc {
        Some(a) => a.mapped_bytes(),
        None => 0,
    }
}

/// Queued-siginfo payloads for signals raised via rt_sigqueueinfo /
/// sigqueue: `(task, signum) -> FIFO of (si_code, si_value)`.
///
/// Linux semantics (signal(7)): STANDARD signals (1..=31) do not queue —
/// duplicates coalesce, so their slot holds at most ONE payload (the
/// latest wins, matching the collapsed pending bit). REALTIME signals
/// (32..=64) DO queue: each sigqueue(2) is an independent delivery with
/// its own `si_value`, delivered in FIFO order. The pending bitmask in
/// `SIGNAL_PENDING` still carries one bit per signum; consumers re-arm
/// the bit after draining one instance while more remain queued
/// (`rearm_pending_if_queued`), so N queued RT signals produce N
/// deliveries instead of collapsing to one.
///
/// Drained on delivery (`default_signal_delivery`), by `rt_sigtimedwait`,
/// or by a `signalfd` read so a stale payload never attaches to a later
/// instance.
type SigqueueMap = BTreeMap<(u64, u32), alloc::collections::VecDeque<(i32, u64, u32)>>;
const SIGQUEUE_BUCKETS: usize = 64;

#[repr(align(64))]
struct SigqueueBucket {
    values: narf_lib::sync::IrqSafeSpinLock<Option<SigqueueMap>>,
}

impl SigqueueBucket {
    const fn new() -> Self {
        Self {
            values: narf_lib::sync::IrqSafeSpinLock::new(None),
        }
    }
}

static SIGQUEUE_INFO: [SigqueueBucket; SIGQUEUE_BUCKETS] =
    [const { SigqueueBucket::new() }; SIGQUEUE_BUCKETS];

#[inline]
fn sigqueue_bucket(task: u64) -> usize {
    task as usize & (SIGQUEUE_BUCKETS - 1)
}

fn sigqueue_clear() {
    for bucket in &SIGQUEUE_INFO {
        *bucket.values.lock() = Some(BTreeMap::new());
    }
}

#[doc(hidden)]
pub fn __test_sigqueue_bucket_index(task: u64) -> usize {
    sigqueue_bucket(task)
}

/// First realtime signal at the KERNEL level (libc reserves the first few
/// for its own use, but queueing is a property of the kernel range).
const SIGRT_QUEUE_MIN: u32 = 32;

/// Per-task cap on TOTAL queued signal payloads — the RLIMIT_SIGPENDING
/// analogue (Linux defaults to a few thousand). Without a cap, a
/// CPU-bound sigqueue(2) loop against a slower consumer (exactly
/// stress-ng --sigrt's parent hammering 30 parked children) grows the
/// kernel-heap FIFOs without bound; Linux callers already handle the
/// EAGAIN this overflow produces.
const SIGQUEUE_MAX_PER_TASK: usize = 4096;

/// Record the `si_code` + `si_value` + sender `si_pid` carried by a
/// queued signal. RT signals append (true queueing); standard signals
/// replace (coalesce, latest payload wins — their pending bit collapses
/// anyway). Returns `false` when the target's queue is at
/// `SIGQUEUE_MAX_PER_TASK` (→ the sender surfaces -EAGAIN, Linux
/// RLIMIT_SIGPENDING semantics); coalescing standard signals never fail.
pub(crate) fn store_sigqueue_info(
    task: u64,
    signum: u32,
    si_code: i32,
    si_value: u64,
    si_pid: u32,
) -> bool {
    store_sigqueue_info_depth(task, signum, si_code, si_value, si_pid).is_some()
}

/// Like [`store_sigqueue_info`], but returns the target's TOTAL queued-payload
/// depth AFTER the insert (`None` when the per-task cap was already hit, i.e.
/// the caller must surface -EAGAIN). The depth is computed from the same
/// `range().sum()` the cap check already walks, so the sender-side
/// back-pressure decision (see `sys_rt_sigqueueinfo`) reads it here instead of
/// re-taking the bucket lock and re-scanning in a separate `sigqueue_depth`
/// call — one lock round-trip per send instead of two.
pub(crate) fn store_sigqueue_info_depth(
    task: u64,
    signum: u32,
    si_code: i32,
    si_value: u64,
    si_pid: u32,
) -> Option<usize> {
    let mut g = SIGQUEUE_INFO[sigqueue_bucket(task)].values.lock();
    let m = g.get_or_insert_with(BTreeMap::new);
    // Total queued across ALL of the target's signums (the per-process pending
    // budget, like Linux's ucounts sigpending charge). For RT signals this is
    // the cap gate; for every send it is the depth returned for back-pressure.
    let queued: usize = m.range((task, 0)..=(task, 64)).map(|(_, q)| q.len()).sum();
    if signum >= SIGRT_QUEUE_MIN && queued >= SIGQUEUE_MAX_PER_TASK {
        return None;
    }
    let q = m.entry((task, signum)).or_default();
    if signum < SIGRT_QUEUE_MIN {
        // Standard signals coalesce: replace the slot with the latest payload.
        // If the slot already held an instance, that entry was part of
        // `queued`, so the depth is unchanged; a brand-new slot adds one.
        let existed = !q.is_empty();
        q.clear();
        q.push_back((si_code, si_value, si_pid));
        return Some(if existed { queued } else { queued + 1 });
    }
    q.push_back((si_code, si_value, si_pid));
    Some(queued + 1)
}

/// Threshold above which a signal sender is asked to yield at syscall exit:
/// the target is this many payloads behind, so the producer has outrun the
/// consumer and should donate its CPU (stress-ng --sigrt's parent flooding
/// its 30 sigwaitinfo children; the graceful-shutdown `sival=0` marker must
/// find the children DRAINED and parked, or the nop-handler sigreturn chain
/// can consume it and the run never terminates). Linux gets the equivalent
/// pacing from preemptive multi-CPU scheduling; this is the cooperative
/// analogue, and it only triggers on genuinely backlogged floods.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) const SIGQUEUE_BACKPRESSURE_DEPTH: usize = 4;

/// Pop and return the OLDEST queued `(si_code, si_value, si_pid)` for
/// `(task, signum)`, if any. FIFO order preserves rt_sigqueueinfo
/// submission order for RT signals; standard signals hold at most one.
pub(crate) fn take_sigqueue_info(task: u64, signum: u32) -> Option<(i32, u64, u32)> {
    let mut g = SIGQUEUE_INFO[sigqueue_bucket(task)].values.lock();
    let m = g.as_mut()?;
    let q = m.get_mut(&(task, signum))?;
    let v = q.pop_front();
    if q.is_empty() {
        m.remove(&(task, signum));
    }
    v
}

/// True when more queued instances of `(task, signum)` remain after a
/// `take_sigqueue_info` pop.
pub(crate) fn sigqueue_more_queued(task: u64, signum: u32) -> bool {
    SIGQUEUE_INFO[sigqueue_bucket(task)]
        .values
        .lock()
        .as_ref()
        .is_some_and(|m| m.get(&(task, signum)).is_some_and(|q| !q.is_empty()))
}

/// Re-set the pending bit for `signum` when more queued instances remain
/// — the RT-queue drain step every consumer (handler delivery,
/// rt_sigtimedwait, signalfd) runs after clearing the bit, so the NEXT
/// return-to-user / wait delivers the next instance with its own payload.
pub(crate) fn rearm_pending_if_queued(task: u64, signum: u32) {
    if !sigqueue_more_queued(task, signum) {
        return;
    }
    let _ = signal_bits_update_existing(&SIGNAL_PENDING, task, |slot| {
        *slot |= sig_bit(signum);
    });
}

/// Drop every queued payload for `(task, signum)` — used when the signal
/// is consumed by an ignoring disposition (SIG_IGN / default-Ignore):
/// Linux "delivers" each queued ignored instance by discarding it, which
/// collapses to discarding the whole queue.
pub(crate) fn purge_sigqueue(task: u64, signum: u32) {
    if let Some(m) = SIGQUEUE_INFO[sigqueue_bucket(task)].values.lock().as_mut() {
        m.remove(&(task, signum));
    }
}

/// Wake condition for a task parked in `rt_sigtimedwait` on userspace
/// sigset `set` (bit N-1 = signal N — identical to `SIGNAL_PENDING`'s
/// layout). True when a signal IN the set is pending (block mask
/// deliberately ignored: sigwait consumes blocked signals — callers
/// block the set first, per sigwaitinfo(2)) or any OTHER deliverable
/// signal is pending (the re-executed syscall returns -EINTR and the
/// return-to-user hook delivers it).
pub(crate) fn sigwait_should_wake(task: u64, set: u64) -> bool {
    let pending = signal_pending_of(task);
    (pending & set) != 0 || (pending & !signal_mask_of(task)) != 0
}

pub fn is_signal_pending(task_id: u64) -> bool {
    let pending = signal_bits_get(&SIGNAL_PENDING, task_id);
    let mask = signal_bits_get(&SIGNAL_MASK, task_id);
    (pending & !mask) != 0
}

/// True when an unmasked pending signal can interrupt a blocking syscall.
///
/// A pending signal whose disposition is `SIG_IGN`, or whose default action
/// is Ignore (notably `SIGCHLD`), is still visible through `sigpending(2)` but
/// must not make `wait4(2)` return `EINTR`. Linux's signal wakeup path makes
/// the same distinction between pending bits and a signal that requires an
/// action. Keep `is_signal_pending` as the raw deliverability probe used by
/// diagnostics and signal consumption; blocking waits use this filtered form.
pub(crate) fn has_interrupting_signal(task_id: u64) -> bool {
    let pending = signal_bits_get(&SIGNAL_PENDING, task_id);
    let mut deliverable = pending & !signal_mask_of(task_id);
    while deliverable != 0 {
        let signum = sig_from_bit(deliverable);
        deliverable &= !sig_bit(signum);
        let ignored = match sigaction_lookup_full(task_id, signum as usize) {
            Some(action) if action.handler == 1 => true, // SIG_IGN
            Some(action) if action.handler == 0 => {
                default_signal_action(signum) == DefaultAction::Ignore
            }
            Some(_) => false,
            None => default_signal_action(signum) == DefaultAction::Ignore,
        };
        if !ignored {
            return true;
        }
    }
    false
}

static SIGNAL_MASK: SignalBitsTable = [const { SignalBitsBucket::new() }; SIGNAL_TABLE_BUCKETS];

/// fork/clone inheritance of the signal mask (Linux `copy_process`
/// copies `blocked` unconditionally, for threads and forks alike).
/// Without it a new thread starts with an EMPTY mask and takes
/// signals its creator had deliberately blocked.
pub(crate) fn signal_mask_fork(parent: u64, child: u64) {
    let Some(parent_mask) = signal_bits_get_opt(&SIGNAL_MASK, parent) else {
        return;
    };
    // Fork-ordering hazard: `do_clone3`/`sys_fork` spawn the child (making
    // it runnable) BEFORE this inheritance runs. musl always calls fork/
    // clone from inside its `__block_all_sigs` window, so `parent`'s LIVE
    // mask here is the transient all-blocked value — NOT the process's real
    // mask. The child's own `__restore_sigs` (which runs the instant it is
    // scheduled) sets the correct pre-fork mask. If we unconditionally
    // copied `parent`'s mask we would clobber that restore with all-blocked,
    // leaving the exec'd image with every application signal masked (SIGALRM
    // handlers never fire — the stress-ng --sigrt hang). So only SEED a
    // child that has not yet established a mask of its own: a raw clone that
    // never restores still inherits correctly, while a musl child that has
    // already restored keeps its authoritative value.
    let mut child_values = SIGNAL_MASK[signal_bits_bucket(child)].values.lock();
    if let Some(map) = child_values.as_mut() {
        map.entry(child).or_insert(parent_mask);
    }
}

/// SIGKILL(9)/SIGSTOP(19) can never be blocked — Linux silently strips
/// them from every mask install (`sigdelsetmask(&blocked, sigmask(
/// SIGKILL) | sigmask(SIGSTOP))`). NARF masks store signal N at bit N.
// SIGKILL(9)=bit 8, SIGSTOP(19)=bit 18 in the N-1 convention.
const UNBLOCKABLE_MASK: u64 = (1 << 8) | (1 << 18);

// Per-task flag recording whether the most recently delivered signal
// frame is the Linux `rt_sigframe` (restorer-based) layout. The Linux
// `rt_sigreturn` (x86_64 #15) takes no argument — the frame is found
// at the user RSP. NARF's own libc trampoline instead forwards the
// SigContext vaddr in arg0. We can't tell them apart at sigreturn time
// from registers alone (a restorer leaves arbitrary garbage in RDI),
// so we remember the delivery style here. `true` ⇒ resolve the frame
// from RSP; `false` ⇒ trust arg0.
static SIGRETURN_USE_RSP: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, bool>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

fn set_sigreturn_use_rsp(task: u64, use_rsp: bool) {
    let mut g = SIGRETURN_USE_RSP.lock();
    let map = g.get_or_insert_with(BTreeMap::new);
    map.insert(task, use_rsp);
}

fn sigreturn_use_rsp(task: u64) -> bool {
    SIGRETURN_USE_RSP
        .lock()
        .as_ref()
        .and_then(|m| m.get(&task).copied())
        .unwrap_or(false)
}

// Per-task record of the LAST delivered signal frame's layout: `true` ⇒ the
// kernel laid out an rt_sigframe (McContext at sc_vaddr+168), `false` ⇒ a legacy
// SigContext. `sys_sigreturn` reads this and hands it to `perform_sigreturn` so
// the restore reads RIP from the correct offset. Previously the arch code GUESSED
// rt-vs-legacy by sniffing the user `si_signo` word — a wrong guess (e.g. user
// data in (0,64) over a legacy frame) read RIP from the rt offset, which lands on
// the frame's `cs`/`ss` selector fields → control transfer to a tiny RPL-3 address
// (#UD). The kernel BUILT the frame, so it must record the layout, not re-derive it.
// `is_rt` mirrors deliver_signal's `want_siginfo || force_rt` decision exactly.
static SIGRETURN_IS_RT: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, bool>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

fn set_sigreturn_is_rt(task: u64, is_rt: bool) {
    let mut g = SIGRETURN_IS_RT.lock();
    let map = g.get_or_insert_with(BTreeMap::new);
    map.insert(task, is_rt);
}

fn sigreturn_is_rt(task: u64) -> bool {
    SIGRETURN_IS_RT
        .lock()
        .as_ref()
        .and_then(|m| m.get(&task).copied())
        // Default true: modern (rt_sigaction + SA_SIGINFO/restorer) is the
        // overwhelming case; a missing record means rt.
        .unwrap_or(true)
}

// Pre-handler signal mask, saved when a signal is delivered so `sys_sigreturn`
// can restore it. POSIX: on return from a handler the signal mask in effect
// just before the handler ran is restored — crucially undoing the auto-block of
// the delivered signal. Without this the auto-blocked signal stays masked
// forever, so a SECOND occurrence is never delivered (observed: a second
// setitimer(ITIMER_REAL)/raise SIGALRM never firing after the first handler ran
// — whichever alarm phase ran second hung). Single-slot per task, matching the
// SIGRETURN_IS_RT / SIGRETURN_USE_RSP records (nested handlers share NARF's
// existing single-record limitation). Only the async delivery path records here
// (it is the one that auto-blocks); a `None` on return leaves the mask alone.
static SIGRETURN_SAVED_MASK: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u64>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

fn set_sigreturn_saved_mask(task: u64, mask: u64) {
    let mut g = SIGRETURN_SAVED_MASK.lock();
    let map = g.get_or_insert_with(BTreeMap::new);
    map.insert(task, mask);
}

fn take_sigreturn_saved_mask(task: u64) -> Option<u64> {
    let mut g = SIGRETURN_SAVED_MASK.lock();
    g.as_mut().and_then(|m| m.remove(&task))
}

// Pre-`rt_sigsuspend` signal mask, saved when sigsuspend installs its
// temporary wait mask. POSIX (and Linux's TIF_RESTORE_SIGMASK): the mask
// restored by the interrupting handler's sigreturn must be the mask in
// effect BEFORE sigsuspend replaced it — NOT the temporary suspend mask.
// Without this record, `default_signal_delivery` captured the live (=
// suspend) mask into SIGRETURN_SAVED_MASK, so the temporary mask survived
// the handler return and the process ran on the suspend mask forever.
// Consumed (take) by the first delivery after the suspend; a record left
// by an aborted suspend is dropped by the next explicit sigprocmask
// install (the user retook control of the mask) and swept on task exit.
static SUSPEND_SAVED_MASK: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u64>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

fn set_suspend_saved_mask(task: u64, mask: u64) {
    let mut g = SUSPEND_SAVED_MASK.lock();
    g.get_or_insert_with(BTreeMap::new).insert(task, mask);
}

fn take_suspend_saved_mask(task: u64) -> Option<u64> {
    let mut g = SUSPEND_SAVED_MASK.lock();
    g.as_mut().and_then(|m| m.remove(&task))
}

/// Install a syscall-scoped temporary signal mask while preserving the mask
/// from the syscall's first entry across RIP-rewind park/re-executions.
///
/// pselect6/ppoll/epoll_pwait share Linux's TIF_RESTORE_SIGMASK model with
/// rt_sigsuspend: normal completion restores the saved mask directly, while
/// an interrupting signal delivery consumes the saved value and arranges for
/// sigreturn to restore it after the handler.
pub(crate) fn install_temporary_signal_mask(task: u64, mask: u64) {
    let already_installed = SUSPEND_SAVED_MASK
        .lock()
        .as_ref()
        .is_some_and(|m| m.contains_key(&task));
    if already_installed {
        let _ = set_signal_mask_for_task(task, mask);
        return;
    }
    let prior = set_signal_mask_for_task(task, mask);
    set_suspend_saved_mask(task, prior);
}

/// Restore a syscall-scoped temporary signal mask on a non-signal return.
/// If signal delivery already consumed the saved value, sigreturn owns the
/// restoration and this is intentionally a no-op.
pub(crate) fn restore_temporary_signal_mask(task: u64) {
    if let Some(prior) = take_suspend_saved_mask(task) {
        let _ = set_signal_mask_for_task(task, prior);
    }
}

/// Initialise the per-task pending+mask+altstack registries.
/// Pair with `sigaction_init` at boot.
pub fn signal_init() {
    signal_bits_clear(&SIGNAL_PENDING);
    signal_bits_clear(&SIGNAL_READABLE_GEN);
    signal_bits_clear(&SIGNAL_RAISE_GEN);
    signal_bits_clear(&SIGNAL_MASK);
    *SIG_ALTSTACK.lock() = Some(BTreeMap::new());
    // Pending bits and queued siginfo payloads are one logical signal state.
    // Reinitialising only the bitmaps leaves an unreachable payload behind;
    // the next signal of the same number can then consume stale si_code/value
    // even though the failed/current send never published anything. This is
    // also what made ABI transactionality tests misattribute a payload queued
    // by an earlier fixture to a later EFAULT/EINVAL call.
    sigqueue_clear();
}

/// Reset the registries — test hook. Drops every per-task entry.
#[doc(hidden)]
pub fn __test_signal_reset() {
    signal_bits_clear(&SIGNAL_PENDING);
    signal_bits_clear(&SIGNAL_READABLE_GEN);
    signal_bits_clear(&SIGNAL_RAISE_GEN);
    signal_bits_clear(&SIGNAL_MASK);
    *SIG_ALTSTACK.lock() = Some(BTreeMap::new());
    sigqueue_clear();
    *SUSPEND_SAVED_MASK.lock() = Some(BTreeMap::new());
}

/// Diagnostic: peek the pending bitmap for `task`.
pub fn signal_pending_of(task: u64) -> u64 {
    signal_bits_get(&SIGNAL_PENDING, task)
}

pub fn signal_readable_generation(task: u64) -> u64 {
    signal_bits_get(&SIGNAL_READABLE_GEN, task)
}

/// Per-task raise generation — bumped on every signal raise. See
/// [`SIGNAL_RAISE_GEN`]. Read by the poll/epoll park's signalfd lost-wake guard.
pub fn signal_raise_generation(task: u64) -> u64 {
    signal_bits_get(&SIGNAL_RAISE_GEN, task)
}

/// POSIX default action for a signal when no handler is installed.
/// Mirrors the table in `signal(7)`. Used by the kernel to decide
/// what to do when a signal is pending + deliverable but the task
/// has no sigaction registered: terminate it, terminate + dump,
/// stop it, continue it, or ignore it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DefaultAction {
    /// Default action is "terminate the process" (POSIX `Term`).
    Terminate,
    /// Default action is "terminate + core dump" (POSIX `Core`).
    CoreDump,
    /// Default action is "stop the process" (POSIX `Stop`).
    Stop,
    /// Default action is "continue the process if stopped" (POSIX `Cont`).
    Continue,
    /// Default action is "ignore the signal" (POSIX `Ign`).
    Ignore,
}

/// Look up the POSIX-default action for `signum`. Reference table:
/// `signal(7)`, Linux's `kernel/signal.c::sig_kernel_*` family.
/// Signals not assigned in the standard table fall through to
/// `Terminate` — Linux uses the same fallback.
pub fn default_signal_action(signum: u32) -> DefaultAction {
    match signum {
        1 => DefaultAction::Terminate,  // SIGHUP
        2 => DefaultAction::Terminate,  // SIGINT
        3 => DefaultAction::CoreDump,   // SIGQUIT
        4 => DefaultAction::CoreDump,   // SIGILL
        5 => DefaultAction::CoreDump,   // SIGTRAP
        6 => DefaultAction::CoreDump,   // SIGABRT / SIGIOT
        7 => DefaultAction::CoreDump,   // SIGBUS
        8 => DefaultAction::CoreDump,   // SIGFPE
        9 => DefaultAction::Terminate,  // SIGKILL (cannot be caught)
        10 => DefaultAction::Terminate, // SIGUSR1
        11 => DefaultAction::CoreDump,  // SIGSEGV
        12 => DefaultAction::Terminate, // SIGUSR2
        13 => DefaultAction::Terminate, // SIGPIPE
        14 => DefaultAction::Terminate, // SIGALRM
        15 => DefaultAction::Terminate, // SIGTERM
        16 => DefaultAction::Terminate, // SIGSTKFLT (Linux-specific)
        17 => DefaultAction::Ignore,    // SIGCHLD
        18 => DefaultAction::Continue,  // SIGCONT
        19 => DefaultAction::Stop,      // SIGSTOP (cannot be caught)
        20 => DefaultAction::Stop,      // SIGTSTP
        21 => DefaultAction::Stop,      // SIGTTIN
        22 => DefaultAction::Stop,      // SIGTTOU
        23 => DefaultAction::Ignore,    // SIGURG
        24 => DefaultAction::CoreDump,  // SIGXCPU
        25 => DefaultAction::CoreDump,  // SIGXFSZ
        26 => DefaultAction::Terminate, // SIGVTALRM
        27 => DefaultAction::Terminate, // SIGPROF
        28 => DefaultAction::Ignore,    // SIGWINCH
        29 => DefaultAction::Terminate, // SIGIO / SIGPOLL
        30 => DefaultAction::Terminate, // SIGPWR
        31 => DefaultAction::CoreDump,  // SIGSYS
        _ => DefaultAction::Terminate,
    }
}

// ── /proc/[pid]/{cmdline,comm} backing tables ───────────────────
//
// Both are populated at task-creation time (boot init, sys_execve)
// and queried by the proc_task_info hook below. The comm name is
// also writable through prctl(PR_SET_NAME).

static PROC_ARGV: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u64, alloc::vec::Vec<u8>>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

static PROC_COMM: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u64, alloc::string::String>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

// /proc/[pid]/exe target: the absolute path of the last successfully
// exec'd image (for a `#!` script, the interpreter — Linux points the
// exe link at whatever binary is actually mapped). Recorded by
// sys_execve next to the argv/comm publish; a fork child has no entry
// until it execs (the procfs hook then renders an empty target).
static PROC_EXE: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u64, alloc::string::String>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

fn proc_identity_fork(parent_task: u64, child_task: u64) {
    let inherited_comm = {
        let g = PROC_COMM.lock();
        g.as_ref().and_then(|m| m.get(&parent_task).cloned())
    };
    if let Some(comm) = inherited_comm {
        PROC_COMM
            .lock()
            .get_or_insert_with(alloc::collections::BTreeMap::new)
            .insert(child_task, comm);
    }
    let inherited_exe = {
        let g = PROC_EXE.lock();
        g.as_ref().and_then(|m| m.get(&parent_task).cloned())
    };
    if let Some(exe) = inherited_exe {
        PROC_EXE
            .lock()
            .get_or_insert_with(alloc::collections::BTreeMap::new)
            .insert(child_task, exe);
    }
}

/// Record the exec'd binary path for `/proc/[pid]/exe`. A relative
/// exec path is resolved against the caller's cwd so the link is
/// always absolute (Linux renders a resolved path here, never `./x`).
pub fn set_proc_exe(pid: u64, path: &str) {
    let abs = if path.starts_with('/') {
        alloc::string::String::from(path)
    } else {
        let mut s = cwd_of(pid);
        if !s.ends_with('/') {
            s.push('/');
        }
        s.push_str(path);
        s
    };
    let mut g = PROC_EXE.lock();
    let map = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    map.insert(pid, abs);
}

/// `/proc/[pid]/exe` hook — None until the task has exec'd.
pub fn proc_exe_path(pid: u64) -> Option<alloc::string::String> {
    let tid = proc_pid_to_tid(pid);
    let g = PROC_EXE.lock();
    g.as_ref().and_then(|m| m.get(&tid).cloned())
}

/// `/proc/[pid]/cwd` hook — `cwd_of` defaults to `/` for a task that
/// never chdir'd, which is also the Linux boot-task answer.
pub fn proc_cwd_path(pid: u64) -> Option<alloc::string::String> {
    Some(cwd_of(proc_pid_to_tid(pid)))
}

/// `/proc/[pid]/root` hook — the chroot prefix, or None (procfs falls
/// back to `/`) when the task never chroot'd or the build has no
/// linux-compat chroot support.
pub fn proc_root_path(pid: u64) -> Option<alloc::string::String> {
    {
        let tid = proc_pid_to_tid(pid);
        task_map_get(&ROOT_DIR_TABLE, tid)
    }
}

/// Store NUL-separated argv bytes for a task. /proc/[pid]/cmdline
/// reads this exact byte stream — Linux's shape is `argv[0]\0argv[1]\0...`.
pub fn set_proc_argv(pid: u64, argv: &[&str]) {
    let mut packed = alloc::vec::Vec::new();
    for s in argv {
        packed.extend_from_slice(s.as_bytes());
        packed.push(0);
    }
    let mut g = PROC_ARGV.lock();
    let map = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    map.insert(pid, packed);
}

/// Pre-packed variant — the caller already owns the NUL-separated bytes.
pub fn set_proc_argv_packed(pid: u64, packed: alloc::vec::Vec<u8>) {
    let mut g = PROC_ARGV.lock();
    let map = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    map.insert(pid, packed);
}

/// Set the per-task comm name. Truncated to 15 bytes per Linux's
/// PR_SET_NAME (TASK_COMM_LEN = 16 including NUL).
pub fn set_proc_comm(pid: u64, name: &str) {
    let trimmed: alloc::string::String = name.chars().take(15).collect();
    let mut g = PROC_COMM.lock();
    let map = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    map.insert(pid, trimmed);
}

/// Read-only accessor for the NUL-separated argv pack recorded
/// against `pid`. Used by `/proc/[pid]/cmdline` and by the execve
/// smoke tests to verify the post-load argv publish step.
pub fn proc_argv_of(pid: u64) -> alloc::vec::Vec<u8> {
    let tid = proc_pid_to_tid(pid);
    let g = PROC_ARGV.lock();
    g.as_ref()
        .and_then(|m| m.get(&tid).cloned())
        .unwrap_or_default()
}

/// Read-only accessor for the comm name recorded against `pid`. Used
/// by `/proc/[pid]/comm` and by the execve smoke tests to confirm
/// the comm-from-argv[0]-basename step ran.
pub fn proc_comm_of(pid: u64) -> Option<alloc::string::String> {
    let tid = proc_pid_to_tid(pid);
    proc_comm_of_task(tid)
}

/// Read the comm table by scheduler task id. Diagnostic filters run before
/// translating to a user-visible PID and must not feed a TaskId through
/// `proc_pid_to_tid` a second time.
pub fn proc_comm_of_task(tid: u64) -> Option<alloc::string::String> {
    let g = PROC_COMM.lock();
    g.as_ref().and_then(|m| m.get(&tid).cloned())
}

/// `proc_comm_of_task` for callers running in the timer trap, which can
/// interrupt a CPU already holding `PROC_COMM` — blocking there deadlocks
/// the machine the caller is trying to observe. Returns `None` on
/// contention; a missing name in a diagnostic line is the right trade.
#[cfg(feature = "unix-latency-trace")]
pub fn proc_comm_of_task_try(tid: u64) -> Option<alloc::string::String> {
    let g = PROC_COMM.try_lock()?;
    g.as_ref().and_then(|m| m.get(&tid).cloned())
}

/// Timer-trap-safe argv lookup, keyed by TID (both `PROC_ARGV` and
/// `PROC_COMM` are tid-keyed despite their `pid` parameter names — see
/// `proc_argv_of`, which resolves pid→tid before indexing). Returns the
/// NUL-separated pack; `None` on lock contention.
#[cfg(feature = "unix-latency-trace")]
pub fn proc_argv_of_task_try(tid: u64) -> Option<alloc::vec::Vec<u8>> {
    let g = PROC_ARGV.try_lock()?;
    g.as_ref().and_then(|m| m.get(&tid).cloned())
}

/// Match a `comm` string against comma-separated `trace_comm=` selectors. A
/// selector ending in `$` matches the complete name; others are prefixes. The
/// single definition of the selector grammar, shared by the tid-keyed lookup
/// below and the UNIXENQ/UNIXACC latency filter, so the two never drift.
pub fn comm_matches_selectors(comm: &str, prefixes: &str) -> bool {
    prefixes
        .split(',')
        .any(|selector| match selector.strip_suffix('$') {
            Some(exact) => !exact.is_empty() && comm == exact,
            None => !selector.is_empty() && comm.starts_with(selector),
        })
}

/// Check a task's Linux `comm` name against comma-separated prefixes without
/// cloning it. A selector ending in `$` matches the complete comm name; other
/// selectors retain prefix semantics. Diagnostic paths call this on every
/// syscall, so cloning the short comm string (and taking a second configuration
/// lock) would itself perturb the workload being traced.
pub fn proc_comm_of_task_matches(tid: u64, prefixes: &str) -> bool {
    let g = PROC_COMM.lock();
    let Some(comm) = g.as_ref().and_then(|m| m.get(&tid)) else {
        return false;
    };
    comm_matches_selectors(comm, prefixes)
}

// ── /proc/[pid]/comm writable hook ─────────────────────────────

/// Update comm from a procfs write. Linux ref: `comm_write` in
/// `fs/proc/base.c`. Truncates to 15 chars; returns `Ok(())`.
pub fn proc_set_comm(pid: u64, name: &str) -> Result<(), narf_filesystem::FsError> {
    // PROC_COMM is TaskId-keyed (see proc_comm_of); write under the TaskId so a
    // subsequent /proc/<pid>/comm read matches.
    set_proc_comm(proc_pid_to_tid(pid), name);
    Ok(())
}

// ── /proc/[pid]/oom_score_adj ───────────────────────────────────

static PROC_OOM_ADJ: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u64, i16>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

/// Return the oom_score_adj for `pid`. Default 0.
pub fn proc_oom_adj_of(pid: u64) -> i16 {
    let g = PROC_OOM_ADJ.lock();
    g.as_ref().and_then(|m| m.get(&pid).copied()).unwrap_or(0)
}

/// Set the oom_score_adj for `pid`. Range is validated by the caller.
pub fn proc_set_oom_adj(pid: u64, val: i16) -> Result<(), narf_filesystem::FsError> {
    let mut g = PROC_OOM_ADJ.lock();
    let map = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    map.insert(pid, val);
    Ok(())
}

/// Compute a 0..1000 oom_score for `pid`.
///
/// Stub formula: `clamp(rss_pages * 1000 / total_pages + adj, 0, 1000)`.
/// Linux ref: `oom_badness` in `mm/oom_kill.c`.
pub fn proc_oom_score_of(pid: u64) -> i32 {
    let stats = narf_memory::frame::stats();
    // RSS is approximated as the task's VMA pages. NARF tracks
    // VMAs but not resident pages yet — use vma_count as a proxy.
    let rss_pages = {
        // Address spaces are keyed by TaskId; resolve the outer ProcessId first.
        let task = narf_scheduler::address_space_of(narf_scheduler::TaskId(proc_pid_to_tid(pid)));
        task.map(|as_arc| as_arc.mapped_bytes().saturating_add(4095) / 4096)
            .unwrap_or(0)
    };
    let total = stats.total.max(1);
    let base = (rss_pages as i64 * 1000 / total as i64) as i32;
    let adj = proc_oom_adj_of(pid) as i32;
    (base + adj).clamp(0, 1000)
}

// ── /proc/[pid]/coredump_filter ────────────────────────────────

/// Default coredump_filter: anonymous + anonymous-huge + ELF headers.
/// Linux ref: `DEFAULT_MAP_WINDOW` macros + `PR_SET_DUMPABLE` handler.
const DEFAULT_COREDUMP_FILTER: u32 = 0x33;

static PROC_COREDUMP_FILTER: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u64, u32>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

/// Return the coredump_filter bitmap for `pid`. Default 0x33.
pub fn proc_coredump_filter_of(pid: u64) -> u32 {
    let g = PROC_COREDUMP_FILTER.lock();
    g.as_ref()
        .and_then(|m| m.get(&pid).copied())
        .unwrap_or(DEFAULT_COREDUMP_FILTER)
}

/// Set the coredump_filter bitmap for `pid`.
pub fn proc_set_coredump_filter(pid: u64, bits: u32) -> Result<(), narf_filesystem::FsError> {
    let mut g = PROC_COREDUMP_FILTER.lock();
    let map = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    map.insert(pid, bits);
    Ok(())
}

/// /proc/self readlink hook — the calling process's pid in ITS OWN namespace
/// view (== `getpid()`), so `readlink(/proc/self)` yields a number the caller
/// can re-open. (Was the raw TaskId, a third number space that matched neither
/// getpid nor the /proc path numbers.)
pub fn proc_current_pid() -> u64 {
    let task = current_task_id();
    let outer = task_to_pid_raw(task).unwrap_or(task);
    report_pid_to(task, outer)
}

/// /proc/self + /proc/thread-self DIRECTORY-resolution hook — the caller's
/// OUTER ProcessId. `ProcPidDir` keys on the outer pid (that is what every
/// per-pid `/proc` renderer expects), so the "self" magic dirs resolve to the
/// same space the numeric `/proc/<N>` resolver produces.
pub fn proc_current_outer_pid() -> u64 {
    let task = current_task_id();
    task_to_pid_raw(task).unwrap_or(task)
}

/// `/proc/<N>` numeric-resolution hook. `N` is a pid in the READER's PID
/// namespace; return the outer ProcessId the kernel keys on, or `None` when
/// the reader is namespaced and `N` names no process in its namespace (so
/// `/proc/<N>` is invisible — namespace isolation). Identity in the root
/// namespace, where every ProcessId (and, via the caller's identity fallback,
/// every TaskId) resolves to itself.
pub fn proc_pid_resolve(reader_view_pid: u64) -> Option<u64> {
    accept_pid_from(current_task_id(), reader_view_pid)
}

/// Translate an outer ProcessId into the CURRENT reader's namespace view for
/// listing surfaces (cgroup.procs), returning `None` when the process is not
/// visible in the reader's namespace so the caller drops it. Identity in the
/// root namespace / non-`container` builds.
pub fn proc_pid_report(outer: u64) -> Option<u64> {
    #[cfg(feature = "container")]
    {
        crate::pid_ns::ns_visible_inner(current_task_id(), outer)
    }
    #[cfg(not(feature = "container"))]
    {
        Some(outer)
    }
}

/// /proc enumerator — every live PROCESS (thread-group leader, keyed in
/// `PID_TO_TASK` by its outer ProcessId) that is visible in the READER's PID
/// namespace, reported as the reader's inner pid. A namespaced reader sees
/// only its own namespace; the root namespace sees every process by its outer
/// pid. (Was every raw TaskId — threads included, un-namespaced.)
pub fn proc_list_pids() -> alloc::vec::Vec<u64> {
    let reader = current_task_id();
    let outers: alloc::vec::Vec<u64> = PID_TO_TASK
        .lock()
        .as_ref()
        .map(|m| m.keys().copied().collect())
        .unwrap_or_default();
    #[cfg(feature = "container")]
    {
        outers
            .into_iter()
            .filter_map(|outer| crate::pid_ns::ns_visible_inner(reader, outer))
            .collect()
    }
    #[cfg(not(feature = "container"))]
    {
        let _ = reader;
        outers
    }
}

/// /proc/[pid]/* metadata accessor.
pub fn proc_task_info(
    pid: u64,
    query: narf_filesystem::procfs::TaskInfoQuery,
) -> Option<narf_filesystem::procfs::ProcTaskInfo> {
    use narf_filesystem::procfs::{ProcTaskInfo, TaskInfoQuery};
    // Don't gate on "is on a ready queue" — the currently-running
    // task has been popped from its queue for polling and would
    // fail that check while it's the very task asking. Treat any
    // pid that matches the caller OR a queued task as live.
    let current = current_task_id();
    // `pid` is the outer ProcessId: the procfs `/proc/<N>` resolver already
    // translated the reader's namespace-local path number into the outer pid
    // (see `proc_pid_resolve`), so every kernel-state lookup below keys on it
    // directly and no hook double-translates. The reported pid field is
    // rendered back into the READER's namespace view (`visible_pid`); identity
    // in the root namespace.
    let visible_pid = report_pid_to(current, pid);
    // Visible PID → scheduler TaskId. NARF allocates process ids and
    // scheduler task ids from separate spaces (a process's pid is NOT its
    // tid), so every liveness / address-space probe below goes through the
    // pid→tid map rather than using `TaskId(pid)` directly (which is only
    // correct when the two coincide).
    let mapped_tid = pid_to_task_raw(pid);
    let tid = mapped_tid.unwrap_or(pid);
    // The task registry is the /proc-visibility window (Linux semantics):
    // it holds every task from spawn registration to reap, so a pid whose
    // pid→tid binding resolves to a registered Task is /proc-visible in
    // EVERY state — running on any CPU, parked, or an exited-but-unreaped
    // zombie (reported as state Z with its real PPid until the parent
    // reaps). The ready-queue scans below can NOT stand in for this: the
    // executor pops a slot off its per-CPU queue for the whole time it
    // polls the task, so a child actively running on another CPU is
    // invisible to both `all_task_ids` and `address_space_of` — exactly
    // the window in which systemd PID 1 forks a service and immediately
    // reads /proc/<child>/stat's PPid ("is process N my child"); a miss
    // there surfaces as ESRCH. Gating on `mapped_tid` keeps a recycled-
    // but-unmapped pid from resolving through a numerically-coincident
    // live tid. systemd's child tracking also depends on the zombie arm:
    // it peeks waitid(..., WNOWAIT) and then reads /proc/<pid>/stat's
    // PPid BEFORE the real reap.
    let task = crate::task::task_get(tid);
    let zombie = task
        .as_ref()
        .map(|t| t.state.load(Ordering::Acquire) == crate::task::TASK_ZOMBIE)
        .unwrap_or(false);
    // Liveness: a registered Task under a real pid→tid binding, or (for
    // contexts that never register a Task — boot init, test harnesses)
    // the caller itself (the running task is popped off its ready queue
    // while polling, so it wouldn't match the queue scan), a ready-queue
    // entry, or a registered address space (covers parked/sleeping
    // processes like init).
    let live = zombie
        || (mapped_tid.is_some() && task.is_some())
        || tid == current
        || narf_scheduler::all_task_ids().iter().any(|t| t.0 == tid)
        || narf_scheduler::address_space_of(narf_scheduler::TaskId(tid)).is_some();
    if !live {
        return None;
    }
    // brk top — the break is ADDRESS-SPACE state now (not per-task), so read it
    // off the task's AS. This also gives every CLONE_VM thread the same `[heap]`
    // range in its /proc/<tid>/maps (per-task keying showed threads no heap).
    let brk_top = narf_scheduler::address_space_of(narf_scheduler::TaskId(tid))
        .map(|as_arc| as_arc.brk_top())
        .unwrap_or(0);
    // Stack top — the exclusive high end of the user-stack region.
    // Stage-1 just reports the standard fixed top.
    let stack_top = crate::process::DEFAULT_USER_STACK_TOP;
    // Comm name — from the PROC_COMM table (written at exec time
    // or via prctl(PR_SET_NAME)). Falls back to a "task-N"
    // default when no name has been set.
    let comm = proc_comm_of(pid).unwrap_or_else(|| {
        if pid == 0 {
            alloc::string::String::from("kernel")
        } else {
            alloc::format!("task-{}", pid)
        }
    });
    // cmdline — argv preserved at exec time. Empty for bare-spawn
    // tasks (initramfs init / shell) until their argv is recorded.
    let cmdline = proc_argv_of(pid);
    let as_arc = narf_scheduler::address_space_of(narf_scheduler::TaskId(tid)).or_else(|| {
        // Currently-polling task isn't in the queue scan; fall back to the
        // active-AS slot.
        if tid == current_task_id() {
            narf_scheduler::current_address_space()
        } else {
            None
        }
    });
    let memory_stats = as_arc
        .as_ref()
        .map(|as_arc| as_arc.memory_stats())
        .unwrap_or_default();
    let stack_bytes = as_arc
        .as_ref()
        .and_then(|as_arc| {
            as_arc.region_len_at_base(narf_memory::VirtAddr::new(
                crate::process::DEFAULT_USER_STACK_BASE,
            ))
        })
        .unwrap_or(0);
    // VMAs — walk the task's AS regions table. Linux's
    // /proc/[pid]/maps tags certain ranges with brackets ([heap],
    // [stack]); we apply the same labels by matching base address.
    use narf_filesystem::procfs::ProcVma;
    use narf_memory::RegionPerms;
    let mut vmas = alloc::vec::Vec::new();
    if query == TaskInfoQuery::Vmas {
        if let Some(as_arc) = as_arc {
            for r in as_arc.numa_regions_snapshot() {
                let base = r.base.as_u64();
                let end = base + r.len;
                let prot = r.perms.prot_only();
                let policy = resolve_policy(tid, base);
                let effective_nodemask =
                    mpol_effective_nodemask(policy, narf_scheduler::task_mems_allowed(tid));
                let label: &'static str = if base == crate::process::DEFAULT_USER_STACK_BASE {
                    "[stack]"
                } else if base == 0x8000_0000_0000_u64
                    || (base & 0xffff_ff00_0000_0000) == 0x8000_0000_0000
                {
                    "[text]"
                } else if brk_top != 0 && base <= brk_top && brk_top <= end {
                    "[heap]"
                } else {
                    ""
                };
                vmas.push(ProcVma {
                    start: base,
                    end,
                    readable: prot.contains(RegionPerms::READ),
                    writable: prot.contains(RegionPerms::WRITE),
                    executable: prot.contains(RegionPerms::EXEC),
                    // From the UN-stripped perms — prot_only() drops the
                    // SHARED bit. Feeds maps' s/p column + statm's shared.
                    shared: r.perms.contains(RegionPerms::SHARED),
                    label,
                    numa_policy: policy.mode,
                    numa_nodemask: effective_nodemask,
                    numa_node_pages: r.node_pages,
                    resident_pages: r.resident_pages,
                    kernel_page_kb: r.kernel_page_kb,
                });
            }
        }
    }
    // stat fields 7-8: controlling terminal device (tty_nr) + its foreground
    // process group (tpgid). `task_ctty` resolves the boot-console default and
    // the setsid-detached state; the fg pgrp is TASK-space, rendered in the
    // reader's namespace like pgrp/session. No ctty → tty_nr 0, tpgid -1
    // (Linux). Linux dev_t = (major << 8) | minor: console (5,1); pts/N (136,N).
    let (tty_nr, tpgid): (u64, i64) = match task_ctty(tid) {
        None => (0, -1),
        Some(ctty) => {
            let (tty_nr, fg) = if ctty == CTTY_CONSOLE {
                ((5u64 << 8) | 1, narf_filesystem::console_tty::fg_pgrp())
            } else {
                (
                    (136u64 << 8) | ctty as u64,
                    narf_filesystem::devfs_pty::pty_fg_pgrp(ctty),
                )
            };
            let tpgid = if fg == 0 { -1 } else { pgid_to_user(fg) as i64 };
            (tty_nr, tpgid)
        }
    };
    // stat fields 4-6, 14, 22: parentage + CPU + start time. `tid` (hoisted
    // above) resolves the accounting tables (they key on TaskId); PARENT_OF
    // keys on the visible pid. USER_HZ = 100 → 10ms per tick.
    const NS_PER_TICK: u64 = 10_000_000;
    Some(ProcTaskInfo {
        // Report the pid the reader asked for (its namespace view), not the
        // outer ProcessId — stat field 1 must echo /proc/<N>.
        pid: visible_pid,
        comm,
        state: if zombie { 'Z' } else { 'R' },
        brk_top,
        stack_top,
        cmdline,
        vmas,
        vm_size_bytes: memory_stats.mapped_bytes,
        resident_pages: memory_stats.resident_pages,
        data_bytes: memory_stats
            .writable_nonexec_bytes
            .saturating_sub(stack_bytes),
        stack_bytes,
        // PARENT_OF values are parent TaskIds — translate to the parent's
        // outer ProcessId, then into the READER's namespace view. This is the
        // field systemd's `pidref_is_my_child` compares against its own
        // getpid()==1: rendering it in outer space made every service log
        // "Supervising process N which is not our child" (project_pidns_flow_model).
        ppid: parent_of_get(pid)
            .map(|t| report_pid_to(current, task_to_pid_raw(t).unwrap_or(t)))
            .unwrap_or(0),
        // pgrp/session are held in TaskId space; render them in the reader's
        // visible-pid + namespace view (same boundary getpgid()/getsid() use).
        pgrp: pgid_to_user(read_pgid(tid)),
        session: pgid_to_user(read_sid(tid)),
        tty_nr,
        tpgid,
        utime_ticks: cpu_time_ns_of(tid) / NS_PER_TICK,
        stime_ticks: kern_time_ns_of(tid) / NS_PER_TICK,
        starttime_ticks: task_start_ns(tid) / NS_PER_TICK,
        // Effective uid/gid from the per-task credential table — surfaced as
        // the status Uid:/Gid: lines. Defaults to 0/0 (root) for tasks that
        // never called setuid/setgid, matching NARF's default identity.
        uid: {
            let c = read_uidgid(tid);
            c.euid
        },
        gid: {
            let c = read_uidgid(tid);
            c.egid
        },
        // Live thread count of this thread-group (visible pid keys the table).
        num_threads: thread_group_live_count(pid),
    })
}

// ── Extended /proc/[pid]/* public accessors ────────────────────────
//
// Called by `narf_filesystem::procfs::pid_ext` via fn-pointer hooks
// wired in `cross_crate_init::install_proc_ext_hooks`.

/// Return the full rlimit table for `pid` as `[(cur, max); 16]`.
/// Indices follow RLIMIT_* numbering (0=CPU, 3=STACK, 7=NOFILE, …).
pub fn rlimits_of(pid: u64) -> [(u64, u64); 16] {
    // Rows are keyed by the monotonic group-leader TaskId; /proc hands this
    // accessor an outer ProcessId, so resolve it before entering the table.
    let key = pid_to_task_raw(pid).unwrap_or(pid);
    let row = {
        let g = RLIMIT_TABLE.lock();
        g.as_ref()
            .filter(|state| !state.reaped.contains_key(&key))
            .and_then(|state| state.rows.get(&key).copied())
            .unwrap_or_else(default_rlimits)
    };
    let mut out = [(0u64, 0u64); 16];
    for (i, p) in row.iter().enumerate() {
        out[i] = (p.cur, p.max);
    }
    out
}

/// Return the nice value for `pid`. Default 0.
pub fn nice_of(pid: u64) -> i32 {
    // NICE_TABLE is keyed by TaskId (read_nice's param is a task id).
    read_nice(proc_pid_to_tid(pid))
}

/// Return the environ block for `pid` (NUL-separated key=value bytes).
/// Returns empty Vec when no environ has been recorded.
pub fn proc_environ_of(pid: u64) -> alloc::vec::Vec<u8> {
    let tid = proc_pid_to_tid(pid);
    let g = PROC_ENVIRON.lock();
    g.as_ref()
        .and_then(|m| m.get(&tid).cloned())
        .unwrap_or_default()
}

/// Return the packed ELF auxv bytes for `pid`.  Each entry is two
/// little-endian u64s (key, value).  AT_NULL (0, 0) terminates.
pub fn proc_auxv_of(pid: u64) -> alloc::vec::Vec<u8> {
    let tid = proc_pid_to_tid(pid);
    let g = PROC_AUXV.lock();
    g.as_ref()
        .and_then(|m| m.get(&tid).cloned())
        .unwrap_or_else(|| alloc::vec![0u8; 16])
}

/// Record NUL-separated environ for a task at execve time.
pub fn set_proc_environ(pid: u64, envp: &[&str]) {
    let mut packed = alloc::vec::Vec::new();
    for s in envp {
        packed.extend_from_slice(s.as_bytes());
        packed.push(0);
    }
    let mut g = PROC_ENVIRON.lock();
    let map = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    map.insert(pid, packed);
}

/// Record packed auxv (key, value) pairs for a task at execve time.
/// AT_NULL is appended automatically.
pub fn set_proc_auxv_pairs(pid: u64, aux: &[(u64, u64)]) {
    let mut packed: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity((aux.len() + 1) * 16);
    for (key, val) in aux {
        packed.extend_from_slice(&key.to_le_bytes());
        packed.extend_from_slice(&val.to_le_bytes());
    }
    packed.extend_from_slice(&0u64.to_le_bytes());
    packed.extend_from_slice(&0u64.to_le_bytes());
    let mut g = PROC_AUXV.lock();
    let map = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    map.insert(pid, packed);
}

/// Return the backing description for fd `n` of `pid`.  Shaped like
/// a Linux `/proc/[pid]/fd/<n>` symlink target.  Returns `None` when
/// the fd or task doesn't exist.
/// The open fd numbers for `pid`, ascending — backs `/proc/<pid>/fd`
/// enumeration. Keyed the same way as [`fd_path_of`] so a per-fd lookup
/// and the directory listing agree.
pub fn proc_fd_list(pid: u64) -> alloc::vec::Vec<u32> {
    crate::fd::open_fds(proc_pid_to_tid(pid))
}

/// `Some(target_pid)` iff fd `n` of `pid` is a pidfd — backs the
/// `Pid:`/`NSpid:` lines of `/proc/<pid>/fdinfo/<n>` (Linux
/// `fs/pidfs.c::pidfd_show_fdinfo`). systemd 258's `pidfd_get_pid()`
/// parses the `Pid:` line to resolve a `pidfd_spawn`-minted pidfd when
/// pidfs/PIDFD_GET_INFO is unavailable; without it every service spawn
/// fails ENOTTY.
pub fn proc_fd_pidfd_pid(pid: u64, n: u32) -> Option<u64> {
    // `pid` is the outer ProcessId of the /proc/<pid> owner; the fd table is
    // keyed by TaskId, so resolve pid→tid first (proc_pid_to_tid). The stored
    // pidfd target is an outer ProcessId; the fdinfo `Pid:` line is the
    // target's pid in the READER's namespace (Linux fs/pidfs.c) so systemd's
    // pidfd_get_pid() fallback sees a number consistent with the pid it holds.
    let tid = proc_pid_to_tid(pid);
    crate::fd::with_table(tid, |t| t.get(n).and_then(|e| e.ops.pidfd_target_pid()))
        .flatten()
        .map(|outer| report_pid_to(current_task_id(), outer))
}

fn fd_path_string_of(pid: u64, n: u32) -> Option<alloc::string::String> {
    // `pid` is the outer ProcessId; the fd/path tables key on TaskId, so
    // resolve pid→tid. Getting this wrong made /proc/self/fd/<n> unresolvable —
    // systemd execs its executor via `execve("/proc/self/fd/N")`, so an empty
    // resolution turned every service spawn into EBADF (project_pidns_flow_model).
    let tid = proc_pid_to_tid(pid);
    if let Some(path) = crate::mqueue::fd_path(tid, n) {
        // Validate that the slot still exists before trusting the separately
        // maintained fd→path table (fd numbers may be closed and reused).
        if crate::fd::with_table(tid, |table| table.get(n).is_some()).unwrap_or(false) {
            return Some(strip_chroot_prefix(tid, &path));
        }
    }
    crate::fd::with_table(tid, |table| {
        let entry = table.get(n)?;
        let name = core::any::type_name_of_val(&*entry.ops);
        let short = name.rsplit("::").next().unwrap_or(name);
        Some(alloc::format!("anon_inode:[{}]", short))
    })
    .flatten()
}

pub fn fd_path_of(pid: u64, n: u32) -> Option<narf_filesystem::procfs::ProcFdSnapshot> {
    let tid = proc_pid_to_tid(pid);
    let (pos, flags, ino) = crate::fd::with_table(tid, |table| {
        let entry = table.get(n)?;
        Some((table.offset(n)?, table.status_flags(n)?, entry.ops.ino()))
    })
    .flatten()?;
    // Preferred: the real backing path recorded at open() time (the same
    // fd→path table inotify/landlock use). This is what /proc/<pid>/fd/<n>
    // readlinks to — musl's realpath() opens O_PATH then readlinks here.
    // Report it chroot-relative so a chrooted process (e.g. udev in a
    // distro chroot) can re-open the link target in its own namespace.
    Some(narf_filesystem::procfs::ProcFdSnapshot {
        path: fd_path_string_of(pid, n)?,
        info: narf_filesystem::procfs::ProcFdInfo {
            pos,
            flags,
            mnt_id: crate::mqueue::fd_mount_id(tid, n).unwrap_or(0),
            ino,
        },
    })
}

/// Return an fd path for an internal scheduler TaskId. Syscall handlers must
/// use this rather than `fd_path_of`: the latter intentionally interprets
/// its first argument as a Linux PID for procfs. Treating a TaskId as a PID
/// misroutes a lookup whenever it numerically collides with another process's
/// PID (as systemd's forked mount helpers routinely do).
pub(crate) fn fd_path_for_task(task: u64, n: u32) -> Option<alloc::string::String> {
    if let Some(p) = crate::mqueue::fd_path(task, n) {
        return Some(strip_chroot_prefix(task, &p));
    }
    crate::fd::with_table(task, |t| {
        let entry = t.get(n)?;
        let name = core::any::type_name_of_val(&*entry.ops);
        let short = name.rsplit("::").next().unwrap_or(name);
        Some(alloc::format!("anon_inode:[{}]", short))
    })
    .flatten()
}

/// Strip the task's chroot prefix from a host-absolute path, yielding the
/// path as the (possibly chrooted) task sees it. No-op for un-chrooted
/// tasks. Used so `/proc/<pid>/fd/<n>` and similar surfaces report paths a
/// chrooted process can actually re-open.
fn strip_chroot_prefix(task: u64, path: &str) -> alloc::string::String {
    if let Some(prefix) = task_map_get(&ROOT_DIR_TABLE, task) {
        if prefix != "/" {
            if let Some(rest) = path.strip_prefix(prefix.as_str()) {
                if rest.is_empty() {
                    return alloc::string::String::from("/");
                }
                if rest.starts_with('/') {
                    return alloc::string::String::from(rest);
                }
            }
        }
    }
    alloc::string::String::from(path)
}

// Per-task environ and auxv byte stores.
static PROC_ENVIRON: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u64, alloc::vec::Vec<u8>>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

static PROC_AUXV: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u64, alloc::vec::Vec<u8>>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

/// Set the pending bit for `signum` on `task`. Used by Wave-73
/// POSIX timer expiries to queue a signal without going through
/// `sys_kill` (which expects a syscall trap frame). Mirrors the
/// `*slot |= 1 << signum` step inside `sys_kill`.
/// Record the sender's identity for a user-initiated signal (kill / tkill /
/// tgkill) so the receiver's `signalfd` record and any `SA_SIGINFO` handler
/// see `si_code == SI_USER` and `si_pid` = the sender's pid IN THE RECEIVER's
/// pid namespace. Linux fills this unconditionally at `kernel/signal.c:1097`
/// (`si_pid = task_tgid_nr_ns(current, task_active_pid_ns(t))`); NARF set only
/// the pending bit, so every plain-kill receiver read `ssi_pid == 0` —
/// indistinguishable from a kernel signal, which is what systemd PID 1's and
/// udevd's signalfd dispatchers reject or misattribute. Standard signals
/// coalesce, so this overwrites any prior queued instance (Linux does too).
pub(crate) fn queue_sender_siginfo(target: u64, signum: u32) {
    const SI_USER: i32 = 0;
    let sender = current_task_id();
    let sender_outer = task_to_pid_raw(sender).unwrap_or(sender);
    let si_pid = report_pid_to(target, sender_outer) as u32;
    let _ = store_sigqueue_info(target, signum, SI_USER, 0, si_pid);
}

pub fn raise_signal_pending(task: u64, signum: u32) {
    // Reject signal 0: it's the POSIX null signal (existence probe), never a
    // real signal. Setting pending bit 0 would later be taken by the delivery
    // loop as a Terminate-default "signal 0". Bit-N-=-signal-N caps the
    // representable range at 63 (see SIGNAL_PENDING).
    if signum == 0 || signum > 64 {
        return;
    }
    // [PROBE] Name the SENDER of a termination signal aimed at a systemd
    // manager/helper or any task in the user-957 session cgroup — to find who
    // (PID1's job logic? logind? a timeout escalation?) tears down user@957
    // before its manager can exec `systemd --user`. cgevt_trace-gated and
    // limited to termination signals so the common per-signal path (SIGCHLD,
    // SIGCONT, timers) pays nothing.
    #[cfg(feature = "cgroup")]
    if narf_filesystem::cgroupfs::cgevt_trace_enabled() && matches!(signum, 6 | 15) {
        let tgt_comm = proc_comm_of_task(task).unwrap_or_default();
        let tgt_pid = task_to_pid_raw(task).unwrap_or(task);
        let tgt_cg = narf_filesystem::cgroupfs::cgroup_path_of(tgt_pid);
        if tgt_comm == "systemd"
            || tgt_comm.starts_with("(sd")
            || tgt_comm.starts_with("(systemd")
            || tgt_cg.contains("user-957")
        {
            let sender = current_task_id();
            let sender_pid = task_to_pid_raw(sender).unwrap_or(sender);
            let sender_comm = proc_comm_of_task(sender).unwrap_or_default();
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "SIGSEND sig={} -> pid={} comm={} cg={} FROM pid={} comm={}",
                signum,
                tgt_pid,
                tgt_comm,
                tgt_cg,
                sender_pid,
                sender_comm
            );
        }
    }
    // Job-control stop/continue bookkeeping (SIGCONT resume + stop/cont
    // mutual cancellation) runs before the pending bit is set.
    signal_stopcont_interaction(task, signum);
    let Some(was_empty) = signal_bits_update(&SIGNAL_PENDING, task, |slot| {
        let was_empty = *slot == 0;
        *slot |= sig_bit(signum);
        was_empty
    }) else {
        return;
    };
    if was_empty {
        signal_bits_update_or_init(&SIGNAL_READABLE_GEN, task, |generation| {
            *generation = generation.wrapping_add(1);
        });
    }
    // Bump the raise generation on EVERY raise (not just was_empty): the
    // signalfd park guard needs to see a second signal arriving while a first
    // is still pending, so a poll/epoll parked on a signalfd whose mask matches
    // the SECOND signal is not stranded on the backstop. See [`SIGNAL_RAISE_GEN`].
    signal_bits_update_or_init(&SIGNAL_RAISE_GEN, task, |generation| {
        *generation = generation.wrapping_add(1);
    });
    // Wake the task if it is parked (sleep/pause) so an asynchronously
    // raised signal — e.g. SIGALRM from an interval timer — is taken
    // promptly rather than only at the next self-driven re-poll.
    wake_signal(task);
}

/// Deliver `signum` to every task in process group `pgrp` (job-control
/// terminal signals: ^C/^\/^Z → SIGINT/SIGQUIT/SIGTSTP go to the whole
/// foreground group, not just one process). Members are the tasks mapped
/// to `pgrp` in `PGID_TABLE` plus the group leader (`pid == pgrp`) when it
/// has no divergent mapping. Returns true if at least one task was
/// targeted. Syscall context only (allocates).
pub fn deliver_signal_to_pgrp(pgrp: u64, signum: u32) -> bool {
    if pgrp == 0 || signum > 64 {
        return false;
    }
    let mut targets: alloc::vec::Vec<u64> = alloc::vec::Vec::new();
    {
        let g = PGID_TABLE.lock();
        if let Some(m) = g.as_ref() {
            for (&task, &pg) in m.iter() {
                if pg == pgrp {
                    targets.push(task);
                }
            }
        }
    }
    // The leader (pid == pgrp) defaults to pgid == pid when unmapped;
    // include it unless it was explicitly moved to another group.
    if !targets.contains(&pgrp) && read_pgid(pgrp) == pgrp {
        targets.push(pgrp);
    }
    if targets.is_empty() {
        return false;
    }
    for t in targets {
        signal_stopcont_interaction(t, signum);
        raise_signal_pending(t, signum);
        // Kick parked targets — without the wake a pgrp SIGTERM to a
        // blocked task waits out its wheel-fallback deadline.
        wake_signal(t);
    }
    true
}

/// Job-control check for a read/write on a controlling terminal by a
/// process in a *background* process group (POSIX):
///   - a background READ of the controlling tty → SIGTTIN
///   - a background WRITE, only when TOSTOP is set → SIGTTOU
///
/// If the generating signal is blocked or ignored by the caller the I/O
/// fails with EIO instead (an un-stoppable process can't be made to wait);
/// otherwise the signal goes to the caller's whole pgrp (default action:
/// stop) and the syscall is interrupted with EINTR. Returns `Some(neg
/// errno)` when the caller should abort the syscall with that value, or
/// `None` to proceed with the I/O. The fd's tty identity / fg pgrp / TOSTOP
/// are read in one short fd-table borrow; signal delivery happens after it
/// is released (no fd-table reentrancy).
fn tty_background_access(task: u64, fd: u32, is_write: bool) -> Option<i64> {
    let (tty_id, fg, tostop) = crate::fd::with_table(task, |t| {
        t.get(fd).and_then(|e| {
            e.ops
                .tty_id()
                .map(|id| (id, e.ops.tty_fg_pgrp().unwrap_or(0), e.ops.tty_tostop()))
        })
    })??;

    if fg == 0 {
        return None; // no job control configured on this tty
    }
    let caller_pgrp = read_pgid(task);
    if caller_pgrp == 0 || caller_pgrp == fg {
        return None; // foreground process group — proceed
    }
    if task_ctty(task) != Some(tty_id) {
        return None; // not this process's controlling terminal — proceed
    }
    if is_write && !tostop {
        return None; // background writes are allowed unless TOSTOP
    }

    let signum: u32 = if is_write { 22 } else { 21 }; // SIGTTOU / SIGTTIN
    let blocked = (signal_mask_of(task) & (sig_bit(signum))) != 0;
    let ignored = sigaction_lookup_full(task, signum as usize).is_some_and(|sa| sa.handler == 1);
    if blocked || ignored {
        return Some(-5); // -EIO: signal can't stop the process
    }
    deliver_signal_to_pgrp(caller_pgrp, signum);
    Some(-4) // -EINTR: the stopped pgrp restarts the read/write on continue
}

/// Pre-create `task`'s `SIGNAL_PENDING` entry (bits = 0) so a later
/// IRQ-context raise can be alloc-free. Called from syscall context
/// (e.g. arming an interval timer), where allocation is allowed. No-op
/// if the entry already exists or the table is uninitialised.
pub fn ensure_signal_pending_slot(task: u64) {
    let _ = signal_bits_update(&SIGNAL_PENDING, task, |_| {});
    // The IRQ raise advances readability on the first pending signal. Seed
    // that row here too so the IRQ path never allocates.
    let _ = signal_bits_update(&SIGNAL_READABLE_GEN, task, |_| {});
    // Same for the raise generation the signalfd park guard reads.
    let _ = signal_bits_update(&SIGNAL_RAISE_GEN, task, |_| {});
}

/// Alloc-free, IRQ-safe variant of `raise_signal_pending`: OR the
/// `signum` bit into an *existing* `SIGNAL_PENDING` entry. Returns false
/// (signal dropped) if `task` has no entry yet — callers that need this
/// path must have pre-created the slot via `ensure_signal_pending_slot`.
///
/// Unlike `raise_signal_pending` it deliberately does NOT run
/// `signal_stopcont_interaction` or `wake_signal` — both can allocate /
/// take further locks, neither is needed for the timer-IRQ case (the
/// interrupted task is running, not parked, and SIGALRM is not a
/// stop/cont signal). The signal is taken on the same trap's
/// return-to-user via the preemptive delivery hook.
pub fn raise_signal_pending_irq(task: u64, signum: u32) -> bool {
    // Signal 0 is the null signal — never deliverable (see raise_signal_pending).
    if signum == 0 || signum > 64 {
        return false;
    }
    if let Some(was_empty) = signal_bits_update_existing(&SIGNAL_PENDING, task, |slot| {
        let was_empty = *slot == 0;
        *slot |= sig_bit(signum);
        was_empty
    }) {
        if was_empty
            && signal_bits_update_existing(&SIGNAL_READABLE_GEN, task, |generation| {
                *generation = generation.wrapping_add(1);
            })
            .is_none()
        {
            let _ = signal_bits_update_existing(&SIGNAL_PENDING, task, |slot| {
                *slot &= !sig_bit(signum);
            });
            return false;
        }
        // Raise generation, every raise (alloc-free existing-only; the row is
        // pre-seeded by `ensure_signal_pending_slot`). See [`SIGNAL_RAISE_GEN`].
        let _ = signal_bits_update_existing(&SIGNAL_RAISE_GEN, task, |generation| {
            *generation = generation.wrapping_add(1);
        });
        return true;
    }
    false
}

/// Timer-tick hook (called from the arch timer ISR). Raises any signal
/// whose timer has expired for the *currently running* task, so a
/// CPU-bound task that never parks still receives e.g. SIGALRM from
/// `alarm()` / `setitimer(ITIMER_REAL)`. Alloc-free — safe to call with
/// interrupts disabled from the trap handler. The raised signal is then
/// delivered by `signal_delivery_hook` on the same trap's return to user.
pub fn timer_tick_raise_due_signals() {
    {
        let now = narf_scheduler::narf_time::monotonic_ns();
        // Scan EVERY armed ITIMER_REAL slot, not just the interrupted task's.
        // The owner of a `setitimer(ITIMER_REAL)` is frequently PARKED (e.g.
        // blocked in waitpid while CPU-bound children spin) — so it's never
        // the interrupted task, and the sleep-pump that would catch it
        // starves under that load. Without this scan the parked owner's
        // SIGALRM never fires (the kernel cause of the SMP chroot_run /
        // stress-ng hang, where a parent stops its workers via an alarm).
        //
        // O(1)-stack drain: take one due owner at a time, then raise + wake it
        // OUTSIDE the ITIMERS lock. We MUST NOT collect the owners into a large
        // on-stack `[u64; N]` buffer here: this runs in the timer ISR on the
        // *user task's own kernel stack* (per-task-own-stack model), and a
        // ~512 B array on that IRQ-path frame deterministically smashed this
        // handler's return chain (`rip=0x3` #UD) under stress-ng fork/exec churn
        // — the same "no big on-stack array in IRQ context" hazard the timer
        // wheel documents (`timer_wheel::drain_due_to_deferred`).
        let mut after: Option<u64> = None;
        while let Some(t) = crate::posix_timer::itimer_real_take_one_due_irq(now, after) {
            after = Some(t);
            // SIGALRM (14). Slot was pre-created when the timer was armed, so
            // this only sets a bit in an existing entry (never allocates).
            let _ = raise_signal_pending_irq(t, 14);
            // Wake the owner if it's parked so waitpid/pause returns EINTR and
            // SIGALRM is delivered on its return-to-user. For the currently
            // running owner (the original CPU-bound case) this is a harmless
            // no-op — it has no parked waker and takes the signal on this
            // trap's return. Every lock `wake_signal` touches is an
            // `IrqSafeSpinLock`, so this is safe from the timer ISR.
            wake_signal(t);
        }
    }
}

/// Preemptive time-slice: hand a CPU-bound user task back to the
/// cooperative executor from the timer ISR so sibling tasks make
/// progress instead of being monopolized. Mirrors `sys_yield`'s
/// polling-executor path exactly — save the interrupted register state
/// into the task's `UserTaskCtx` and longjmp to the executor via the
/// yield hook — but driven by the timer instead of an explicit syscall.
///
/// Why this is enough (no executor changes needed): a parked user task's
/// sleep is *self-driven* — its `poll` re-checks `sleep_deadline_ns`,
/// `wake_by_ref`s, and returns `Pending`, so it's re-polled every round.
/// Without preemption a CPU-bound sibling never returns from its own
/// `poll` (no syscall, no yield), so the executor never completes the
/// round and never re-polls the sleeper. Yielding here lets the round
/// finish, the sleeper's deadline fire on time, and other runnable tasks
/// run.
///
/// Does NOT return when it preempts (the yield hook longjmps; the task
/// resumes later via `enter_user_mode_resume`). Returns normally — a
/// no-op — when no polling executor is wired or no user task is current
/// (e.g. the in-kernel test harness), so those contexts are unaffected.
///
/// The caller MUST gate on returning-to-user (CPL=3): a task interrupted
/// inside a syscall is at CPL=0 and must not be yanked mid-kernel.
pub fn timer_preempt_user_task(ctx: &mut dyn TrapContext) {
    // Only hand a CPU-bound task back to the cooperative executor if something
    // else actually needs the CPU. With a 1000 Hz tick, yielding on EVERY tick
    // made a task that never parks spend almost all its wall-clock in the
    // yield -> executor-round -> resume cycle (measured ~25-94x slower than
    // native). When nothing else is runnable that round-trip just resumes the
    // same task, so skip it and let the task keep running; it still takes the
    // timer IRQ each tick (signal delivery, the alarm SIGALRM that stops it,
    // wheel arming), so fairness/liveness are preserved the moment any peer
    // wakes. Voluntary yields (syscall/park) don't come through here.
    if !narf_scheduler::has_other_runnable_work(current_task_id()) {
        return;
    }
    if let (Some(uctx), Some(hook)) = (
        crate::user_task::current_user_task(),
        crate::user_task::yield_hook(),
    ) {
        // SAFETY: identical contract to sys_yield's hook path — `uctx` is
        // the live per-task `UserTaskCtx` published by the executor before
        // it entered user mode; we save the interrupted CPU state into
        // `uc.state` and hand the task back to the executor via the yield
        // hook, which longjmps to the executor's `setjmp` and does not
        // return. The timer ISR has already EOI'd and exited the trap
        // handler frame, so abandoning the IRQ frame here is clean (same
        // as sys_yield abandoning its syscall frame).
        unsafe {
            let uc = &*uctx;
            ctx.save_user_state(uc.state.get() as *mut u8);
            *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
            if narf_scheduler::stackful::user_own_stack_enabled() {
                own_stack_block(ctx);
                return;
            }
            hook(uctx);
        }
        // unreachable when preempted
    }
}

/// Clear the pending bit for `signum` on `task`. Used by signalfd
/// after delivering the signal through the fd path.
pub fn clear_signal_pending(task: u64, signum: u32) {
    if signum > 64 {
        return;
    }
    let _ = signal_bits_update_existing(&SIGNAL_PENDING, task, |slot| {
        *slot &= !(sig_bit(signum));
    });
}

/// Diagnostic: peek the block mask for `task`.
pub fn signal_mask_of(task: u64) -> u64 {
    signal_bits_get(&SIGNAL_MASK, task)
}

pub(crate) fn set_signal_mask_for_task(task: u64, mask: u64) -> u64 {
    // SIGKILL/SIGSTOP can never be blocked, whichever install path the
    // mask arrives through (sigsuspend / ppoll / epoll_pwait / sigreturn
    // restore all funnel here) — same strip sys_sigprocmask applies.
    signal_bits_update_or_init(&SIGNAL_MASK, task, |slot| {
        let old = *slot;
        *slot = mask & !UNBLOCKABLE_MASK;
        old
    })
}

/// Send `signum` to the single process named by outer pid `pid`.
/// Resolves the group leader; if the leader is already a zombie the
/// signal still "succeeds" (Linux: signalling a zombie is a no-op
/// success), and if the leader tid is dead but live CLONE_THREAD
/// siblings remain, one of them takes delivery. A fatal SIGKILL fans
/// out to every live thread in the group (Linux group-kill).
/// Returns false when no such process exists (→ ESRCH).
fn kill_process(pid: u64, signum: u32) -> bool {
    let Some(leader_tid) = pid_to_task_raw(pid) else {
        return false;
    };
    let Some(leader) = crate::task::task_get(leader_tid) else {
        return false;
    };
    // Collect group member tids (leader + CLONE_THREAD tids mapping to
    // the same visible pid) under the TASK_TO_PID lock, THEN filter by
    // liveness — `task_get` takes the TASKS lock, which must never be
    // acquired while holding TASK_TO_PID (lock-order discipline).
    let candidates: alloc::vec::Vec<u64> = {
        let g = TASK_TO_PID.lock();
        g.as_ref()
            .map(|m| {
                m.iter()
                    .filter(|&(_, &p)| p == pid)
                    .map(|(&t, _)| t)
                    .collect()
            })
            .unwrap_or_default()
    };
    let members: alloc::vec::Vec<u64> = candidates
        .into_iter()
        .filter(|&t| {
            crate::task::task_get(t)
                .is_some_and(|t| t.state.load(Ordering::Acquire) == crate::task::TASK_RUNNING)
        })
        .collect();
    if members.is_empty() {
        // Whole group already exited (zombie awaiting reap): success,
        // signal discarded.
        return leader.state.load(Ordering::Acquire) == crate::task::TASK_ZOMBIE;
    }
    if signum == 9 {
        // Fatal group kill: every live thread dies.
        for t in members {
            queue_sender_siginfo(t, signum);
            signal_stopcont_interaction(t, signum);
            raise_signal_pending(t, signum);
            wake_signal(t);
        }
        return true;
    }
    // Process-directed: deliver to the leader if alive, else the first
    // live sibling. (Full shared-pending "any thread with it unblocked
    // may dequeue" semantics are a follow-up; see the redesign doc.)
    let target = if members.contains(&leader_tid) {
        leader_tid
    } else {
        members[0]
    };
    queue_sender_siginfo(target, signum);
    signal_stopcont_interaction(target, signum);
    raise_signal_pending(target, signum);
    wake_signal(target);
    true
}

/// Does a signal target tid exist? A live task satisfies at least one
/// of: the refcounted registry (real spawned tasks), the tid→pid map
/// (also true for real tasks and for boot-init tasks that predate the
/// registry), or being the caller itself (self is always alive). A
/// truly unknown tid satisfies none → the caller gets ESRCH, instead
/// of the old behaviour of setting a pending bit on a phantom key.
fn signal_target_exists(tid: u64) -> bool {
    if crate::task::task_get(tid).is_some() || tid == current_task_id() {
        return true;
    }
    TASK_TO_PID
        .lock()
        .as_ref()
        .is_some_and(|m| m.contains_key(&tid))
}

/// Resolve the thread identifier supplied by a Linux signal syscall to the
/// TaskId that owns NARF's signal state.  A thread-group leader is visible as
/// its PID through gettid(2), while CLONE_THREAD siblings retain their
/// distinct TaskId-derived TIDs.  Resolve the caller's own gettid value first:
/// a leader PID can numerically collide with an unrelated sibling's raw
/// TaskId, and treating raw task space as authoritative would misroute a
/// self-directed tkill or make tgkill fail its tgid check with ESRCH.
/// Keep other non-leader TIDs in task space, then map a leader PID (including
/// the caller's PID-namespace view) back to its task.
fn signal_tid_from_user(caller: u64, tid: u64) -> Option<u64> {
    if tid == linux_tid_for_task(caller) {
        return Some(caller);
    }
    // A CLONE_THREAD sibling is a raw TaskId whose thread-group leader lives at
    // task_to_pid_raw(tid) but is a DIFFERENT task. Its gettid() is that raw
    // TaskId, so intra-process tkill must accept it directly.
    if let Some(group_pid) = task_to_pid_raw(tid) {
        if pid_to_task_raw(group_pid) != Some(tid) {
            // #26: only accept the raw sibling tid if its thread group is
            // visible in the CALLER's pid namespace. Without this a container
            // that passed a raw TaskId numerically matching a HOST (or
            // sibling-namespace) thread signalled across the boundary. Linux
            // resolves tkill/tgkill tids via the caller's ns
            // (kernel/signal.c find_task_by_vpid on the thread's pid).
            // Identity/visible in the root ns → unchanged there.
            #[cfg(feature = "container")]
            crate::pid_ns::ns_visible_inner(caller, group_pid)?;
            return Some(tid);
        }
    }
    let pid = accept_pid_from(caller, tid)?;
    Some(pid_to_task_raw(pid).unwrap_or(pid))
}

/// Linux-visible gettid(2) value for `task`. A thread-group leader reports
/// its process ID (translated into its own PID namespace); a CLONE_THREAD
/// sibling reports its distinct scheduler-derived TID.
fn linux_tid_for_task(task: u64) -> u64 {
    match task_to_pid_raw(task) {
        Some(pid) if pid_to_task_raw(pid) == Some(task) => {
            #[cfg(feature = "container")]
            {
                crate::pid_ns::self_inner_pid(task, pid)
            }
            #[cfg(not(feature = "container"))]
            {
                pid
            }
        }
        _ => task,
    }
}

/// Linux's in-kernel siginfo representation is 48 bytes on both architectures
/// NARF supports. `copy_siginfo_from_user()` imports this whole fixed prefix,
/// even though queued-signal delivery currently consumes only the fields below.
const KERNEL_SIGINFO_SIZE: usize = 48;

#[derive(Copy, Clone)]
struct ImportedSiginfo {
    signo: u32,
    code: i32,
    pid: u32,
    value: u64,
}

/// Import a user `siginfo_t` without changing signal state.
///
/// Keeping copy and enqueue separate is load-bearing: Linux performs the user
/// copy before most argument/target validation, and a failed copy must return
/// `EFAULT` without making a pending bit or payload visible. The rt_sigqueueinfo
/// wrappers overwrite `si_signo` with their syscall argument after this copy;
/// pidfd_send_signal instead compares the imported value with that argument.
fn import_queued_siginfo(info_ptr: u64) -> Result<ImportedSiginfo, u64> {
    let mut b = [0u8; KERNEL_SIGINFO_SIZE];
    // SAFETY: copy_from_user validates the complete fixed-size user range and
    // SMAP/fault-brackets the read. NULL and unreadable pointers become EFAULT.
    unsafe { copy_from_user(&mut b, info_ptr) }?;
    Ok(ImportedSiginfo {
        signo: u32::from_ne_bytes(b[0..4].try_into().unwrap()),
        code: i32::from_ne_bytes(b[8..12].try_into().unwrap()),
        // si_pid (offset 16 in the rt union) — musl/glibc `sigqueue` fill
        // getpid() here, and consumers reply to it.
        pid: u32::from_ne_bytes(b[16..20].try_into().unwrap()),
        value: u64::from_ne_bytes(b[24..32].try_into().unwrap()),
    })
}

/// Store an already-imported payload. `None` is the queued-signal budget's
/// `EAGAIN`; user-copy failures cannot reach this function.
fn enqueue_imported_siginfo(target: u64, sig: u32, info: ImportedSiginfo) -> Option<usize> {
    store_sigqueue_info_depth(target, sig, info.code, info.value, info.pid)
}

#[inline]
fn siginfo_requires_self_target(info: ImportedSiginfo) -> bool {
    const SI_TKILL: i32 = -6;
    info.code >= 0 || info.code == SI_TKILL
}

// ── futex — minimal scaffold ────────────────────────────────────────
//
// Linux futex(2) is the kernel-side primitive backing pthread
// mutexes / condvars / once-init. Even a no-op handler lets
// libstdc++ + glibc thread fixtures load. NARF is single-
// threaded; there are no waiters to wake or block.
//
// Honoured ops (after stripping the FUTEX_PRIVATE / FUTEX_CLOCK_
// REALTIME bits):
//   FUTEX_WAIT (0): would block until the futex word is woken
//                   or the timeout fires. Single-threaded NARF
//                   has no other task to do the wake, so we
//                   return 0 (the spec permits spurious wakes
//                   so the caller will re-check the condition).
//   FUTEX_WAKE (1): would wake up to `val` waiters. We have
//                   none; return 0.
//
// Anything else returns -1 with the libc shim setting
// errno = ENOSYS.

const FUTEX_WAIT: u64 = 0;
const FUTEX_WAKE: u64 = 1;
/// `FUTEX_REQUEUE` (3) / `FUTEX_CMP_REQUEUE` (4): wake up to `val` waiters
/// on `uaddr`, then MOVE up to `val2` more onto `uaddr2`'s wait queue
/// WITHOUT waking them (they wake on a later `FUTEX_WAKE` of `uaddr2`).
/// CMP additionally fails with -EAGAIN unless `*uaddr == val3`.
///
/// musl's condvar depends on this: `pthread_cond_broadcast` wakes only the
/// oldest waiter directly; each woken waiter then hands off to the next via
/// `unlock_requeue(&node.prev->barrier, &m->_m_lock, ...)`, which zeroes
/// the next waiter's barrier word and REQUEUES its (still-parked) kernel
/// wait onto the mutex so the eventual mutex unlock wakes it. Returning a
/// non-ENOSYS error here made musl treat the requeue as done — the waiter
/// stayed parked on a barrier word nobody would ever wake again (musl's
/// `unlock()` only wakes when the swap saw 2, and the word was already 0)
/// — a permanent, deterministic strand of any broadcast to >= 2 parked
/// waiters. That is the `condbcast_smoke` hang and the mechanism behind
/// the "SMP scheduler-resume strand" class of wedges.
const FUTEX_REQUEUE: u64 = 3;
const FUTEX_CMP_REQUEUE: u64 = 4;
/// `FUTEX_WAKE_OP` (5): atomically RMW a second futex word, wake `val`
/// waiters on `uaddr`, and — if the pre-RMW value satisfies an encoded
/// comparison — wake `val2` waiters on `uaddr2`. glibc's (and Qt's)
/// pthread_cond_signal/broadcast use this to wake a condvar waiter while
/// bumping the condvar's internal sequence word in one call. Without it,
/// a Qt6 worker thread's wake of the main thread was dropped and the app
/// deadlocked at startup (the kcalc QtWayland-init hang).
const FUTEX_WAKE_OP: u64 = 5;
/// `FUTEX_WAIT_BITSET` (9) / `FUTEX_WAKE_BITSET` (10): wait/wake gated by
/// a 32-bit bitmask. NARF's wait queue is per-uaddr (not per-bit), so we
/// treat them as plain WAIT/WAKE — a superset wake is always safe, and
/// the common musl/glibc callers pass FUTEX_BITSET_MATCH_ANY.
const FUTEX_WAIT_BITSET: u64 = 9;
const FUTEX_WAKE_BITSET: u64 = 10;
const FUTEX_PRIVATE: u64 = 0x80;
const FUTEX_CLOCK_REALTIME: u64 = 0x100;
const FUTEX_OP_MASK: u64 = !(FUTEX_PRIVATE | FUTEX_CLOCK_REALTIME);

/// Convert Linux futex's optional `struct timespec *` to NARF's monotonic
/// deadline. `FUTEX_WAIT` supplies a relative duration; `FUTEX_WAIT_BITSET`
/// supplies an absolute deadline, using CLOCK_REALTIME only when requested.
fn futex_timeout_deadline(
    timeout_ptr: u64,
    absolute: bool,
    realtime: bool,
) -> Result<Option<u64>, i64> {
    const EFAULT: i64 = 14;
    const EINVAL: i64 = 22;
    if timeout_ptr == 0 {
        return Ok(None);
    }
    let mut bytes = [0u8; 16];
    // SAFETY: the syscall supplied a `const struct timespec *`; uaccess
    // validates the range and SMAP-brackets the fixed-size read.
    unsafe { copy_from_user(&mut bytes, timeout_ptr) }.map_err(|_| EFAULT)?;
    let seconds = i64::from_ne_bytes(bytes[0..8].try_into().unwrap());
    let nanoseconds = i64::from_ne_bytes(bytes[8..16].try_into().unwrap());
    if seconds < 0 || !(0..1_000_000_000).contains(&nanoseconds) {
        return Err(EINVAL);
    }
    let requested = (seconds as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(nanoseconds as u64);
    let monotonic_now = narf_scheduler::narf_time::monotonic_ns();
    if !absolute {
        return Ok(Some(monotonic_now.saturating_add(requested)));
    }
    if !realtime {
        return Ok(Some(requested));
    }
    let wall_now = narf_scheduler::narf_time::now_wall().as_nanos();
    let remaining = i128::from(requested).saturating_sub(wall_now);
    if remaining <= 0 {
        Ok(Some(monotonic_now))
    } else {
        Ok(Some(monotonic_now.saturating_add(
            u64::try_from(remaining).unwrap_or(u64::MAX),
        )))
    }
}

/// Perform `FUTEX_WAKE_OP` (Linux `kernel/futex/core.c::futex_wake_op`).
/// `nr_wake`/`nr_wake2` = arg2/arg3, `uaddr2` = arg4, `encoded_op` = arg5.
/// Returns the syscall result (total woken, or a negative errno).
fn futex_wake_op(
    namespace: u64,
    uaddr: u64,
    nr_wake: u32,
    nr_wake2: u32,
    uaddr2: u64,
    encoded_op: u32,
) -> i64 {
    const EFAULT: i64 = 14;
    if uaddr2 == 0 {
        return -EFAULT;
    }
    // Decode the op word: [31:28]=op (bit 0x8 = OPARG_SHIFT), [27:24]=cmp,
    // [23:12]=oparg (12b), [11:0]=cmparg (12b).
    let op_raw = (encoded_op >> 28) & 0xF;
    let oparg_shift = op_raw & 0x8 != 0;
    let op = op_raw & 0x7;
    let cmp = (encoded_op >> 24) & 0xF;
    let mut oparg = (encoded_op >> 12) & 0xFFF;
    let cmparg = (encoded_op & 0xFFF) as i32;
    if oparg_shift {
        oparg = 1u32 << (oparg & 31);
    }
    // Atomically-ish RMW *uaddr2 (single-CPU cooperative for the handler;
    // matches NARF's other user-word futex accesses).
    let mut b = [0u8; 4];
    // SAFETY: copy_from_user range-validates uaddr2 + SMAP-brackets the read.
    if unsafe { copy_from_user(&mut b, uaddr2) }.is_err() {
        return -EFAULT;
    }
    let oldval = u32::from_ne_bytes(b);
    let newval = match op {
        0 => oparg,                      // FUTEX_OP_SET
        1 => oldval.wrapping_add(oparg), // FUTEX_OP_ADD
        2 => oldval | oparg,             // FUTEX_OP_OR
        3 => oldval & !oparg,            // FUTEX_OP_ANDN
        4 => oldval ^ oparg,             // FUTEX_OP_XOR
        _ => return -22,                 // EINVAL — unknown op
    };
    // SAFETY: copy_to_user range-validates uaddr2 + SMAP-brackets the write.
    if unsafe { copy_to_user(uaddr2, &newval.to_ne_bytes()) }.is_err() {
        return -EFAULT;
    }
    // Wake `nr_wake` on uaddr unconditionally.
    let key = futex_key(namespace, uaddr);
    futex_bump_counter_key(key);
    let mut woken = futex_wake_waiters_key(key, nr_wake) as i64;
    // Conditionally wake `nr_wake2` on uaddr2 if (oldval CMP cmparg).
    let ov = oldval as i32;
    let cond = match cmp {
        0 => ov == cmparg, // FUTEX_OP_CMP_EQ
        1 => ov != cmparg, // NE
        2 => ov < cmparg,  // LT
        3 => ov <= cmparg, // LE
        4 => ov > cmparg,  // GT
        5 => ov >= cmparg, // GE
        _ => return -22,   // EINVAL
    };
    if cond {
        let key2 = futex_key(namespace, uaddr2);
        futex_bump_counter_key(key2);
        woken += futex_wake_waiters_key(key2, nr_wake2) as i64;
    }
    woken
}

/// Per-uaddr wait counter. FUTEX_WAKE bumps it; FUTEX_WAIT samples
/// it before parking and re-samples on every poll iteration —
/// progress means a wake landed. Futex semantics aren't strictly
/// "queue + dequeue" — Linux models them as "tagged wakeup events",
/// and the counter gives us that without per-task ownership, which
/// keeps the implementation lock-free except for the table mutation.
#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct FutexKey {
    namespace: u64,
    uaddr: u64,
}

#[inline]
pub(crate) fn futex_key(namespace: u64, uaddr: u64) -> FutexKey {
    FutexKey { namespace, uaddr }
}

/// Namespace for a futex operation. Private futexes are scoped to the live
/// AddressSpace Arc; CLONE_VM threads share it, unrelated processes do not.
#[inline]
fn futex_namespace_for_address_space(space: &Arc<AddressSpace>) -> u64 {
    Arc::as_ptr(space) as usize as u64
}

fn futex_namespace(private: bool) -> u64 {
    if !private {
        return 0;
    }
    current_address_space()
        .map(|space| futex_namespace_for_address_space(&space))
        .unwrap_or(0)
}

const FUTEX_BUCKET_COUNT: usize = 64;

#[inline]
fn futex_bucket_index(key: FutexKey) -> usize {
    // Futex words are normally 4-byte aligned and adjacent words are common,
    // so mix rather than masking the low address bits directly.
    let mut x = key.uaddr ^ key.namespace.rotate_left(17);
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^= x >> 31;
    x as usize & (FUTEX_BUCKET_COUNT - 1)
}

#[repr(align(64))]
struct FutexCounterBucket {
    values: narf_lib::sync::IrqSafeSpinLock<alloc::collections::BTreeMap<FutexKey, u64>>,
}

impl FutexCounterBucket {
    const fn new() -> Self {
        Self {
            values: narf_lib::sync::IrqSafeSpinLock::new(alloc::collections::BTreeMap::new()),
        }
    }
}

static FUTEX_WAKE_COUNTERS: [FutexCounterBucket; FUTEX_BUCKET_COUNT] =
    [const { FutexCounterBucket::new() }; FUTEX_BUCKET_COUNT];

fn futex_wake_counter_key(key: FutexKey) -> u64 {
    FUTEX_WAKE_COUNTERS[futex_bucket_index(key)]
        .values
        .lock()
        .get(&key)
        .copied()
        .unwrap_or(0)
}

pub(crate) fn futex_bump_counter_key(key: FutexKey) {
    let mut values = FUTEX_WAKE_COUNTERS[futex_bucket_index(key)].values.lock();
    let slot = values.entry(key).or_insert(0);
    *slot = slot.wrapping_add(1);
}

fn futex_wake_counter(uaddr: u64) -> u64 {
    futex_wake_counter_key(futex_key(0, uaddr))
}

fn futex_bump_counter(uaddr: u64) {
    futex_bump_counter_key(futex_key(0, uaddr));
}

/// Live per-uaddr `FUTEX_WAKE` generation. The user-task poll routine
/// snapshots this (`futex_park_gen`) before parking and re-reads it after
/// registering the waker — a change means a wake raced the registration
/// (lost-wakeup guard). Public mirror of `futex_wake_counter`.
pub fn futex_gen(uaddr: u64) -> u64 {
    futex_wake_counter(uaddr)
}

#[cfg_attr(target_arch = "aarch64", allow(dead_code))]
pub(crate) fn futex_gen_key(key: FutexKey) -> u64 {
    futex_wake_counter_key(key)
}

/// `FUTEX_WAIT` seqlock read: sample the per-uaddr wake generation FIRST,
/// then read the futex word. This ORDER is load-bearing. The generation is a
/// seqlock the waiter reads as "sample gen → read value → (at park) recheck
/// gen": a `FUTEX_WAKE` that races between the word read and the park
/// registration bumps the generation PAST this snapshot, so the park guard
/// (`futex_gen(uaddr) != futex_park_gen`) detects it and the waiter re-checks
/// instead of parking. Sampling the generation AFTER the word read loses that
/// wake — the waiter captures the post-bump generation, parks, and the guard
/// sees "no change": the classic futex lost-wakeup that deadlocks a contended
/// pthread mutex/condvar under SMP (invisible at SMP=1, where no waker can run
/// between the read and the park). Returns `(gen, *uaddr)`, or `None` if
/// `read_word` reports a fault. `read_word` is a closure so the exact
/// user-memory read (or, in tests, an injected racing bump) is the caller's.
pub(crate) fn futex_wait_seqlock_read(
    uaddr: u64,
    read_word: impl FnOnce() -> Option<u32>,
) -> Option<(u64, u32)> {
    futex_wait_seqlock_read_key(futex_key(0, uaddr), read_word)
}

pub(crate) fn futex_wait_seqlock_read_key(
    key: FutexKey,
    read_word: impl FnOnce() -> Option<u32>,
) -> Option<(u64, u32)> {
    let gen = futex_wake_counter_key(key);
    let current = read_word()?;
    Some((gen, current))
}

/// Test-only: bump a uaddr's wake generation (models a `FUTEX_WAKE`), so a
/// seqlock-ordering test can inject a wake that races the futex-word read.
#[doc(hidden)]
pub fn __test_futex_bump_counter(uaddr: u64) {
    futex_bump_counter(uaddr);
}

/// Per-uaddr blocking-futex wait queue: futex word → (task id → Waker).
/// `FUTEX_WAIT` registers the caller's waker here (via the user-task poll
/// routine) and truly parks; `FUTEX_WAKE` pops up to `val` wakers and fires
/// them. This is what makes the futex a REAL blocking primitive instead of
/// the old fixed-1ms nanosleep park: under contention musl's `__wait` spin
/// loop otherwise re-parks every ~1ms (no early wake), so a contended pthread
/// lock handoff cost ~1ms. Keyed by task id so a re-registering waiter
/// overwrites its own slot (bounded) and `futex_drop_waiter` can remove it.
type FutexWaiterSet = alloc::collections::BTreeMap<u64, core::task::Waker>;
type FutexWaiterMap = alloc::collections::BTreeMap<FutexKey, FutexWaiterSet>;

#[repr(align(64))]
struct FutexWaitBucket {
    values: narf_lib::sync::IrqSafeSpinLock<FutexWaiterMap>,
}

impl FutexWaitBucket {
    const fn new() -> Self {
        Self {
            values: narf_lib::sync::IrqSafeSpinLock::new(FutexWaiterMap::new()),
        }
    }
}

static FUTEX_WAITERS: [FutexWaitBucket; FUTEX_BUCKET_COUNT] =
    [const { FutexWaitBucket::new() }; FUTEX_BUCKET_COUNT];

#[inline]
fn futex_wait_bucket(key: FutexKey) -> &'static FutexWaitBucket {
    &FUTEX_WAITERS[futex_bucket_index(key)]
}

fn futex_drop_task_waiters(task_id: u64) {
    for bucket in &FUTEX_WAITERS {
        bucket.values.lock().retain(|_, waiters| {
            waiters.remove(&task_id);
            !waiters.is_empty()
        });
    }
}

fn futex_has_task_waiter(task_id: u64) -> bool {
    FUTEX_WAITERS.iter().any(|bucket| {
        bucket
            .values
            .lock()
            .values()
            .any(|waiters| waiters.contains_key(&task_id))
    })
}

/// Register `task_id`'s waker as parked on futex word `uaddr`. Called from
/// the user-task poll routine while a task blocks in `FUTEX_WAIT`.
pub fn futex_register_waiter(uaddr: u64, task_id: u64, waker: core::task::Waker) {
    futex_register_waiter_key(futex_key(0, uaddr), task_id, waker);
}

pub(crate) fn futex_register_waiter_key(key: FutexKey, task_id: u64, waker: core::task::Waker) {
    futex_wait_bucket(key)
        .values
        .lock()
        .entry(key)
        .or_default()
        .insert(task_id, waker);
}

/// Remove `task_id`'s futex waker on `uaddr` without firing it (the task
/// woke for another reason — lost-wakeup re-poll, timeout, or exit).
pub fn futex_drop_waiter(uaddr: u64, task_id: u64) {
    futex_drop_waiter_key(futex_key(0, uaddr), task_id);
}

pub(crate) fn futex_drop_waiter_key(key: FutexKey, task_id: u64) {
    let mut values = futex_wait_bucket(key).values.lock();
    if let Some(set) = values.get_mut(&key) {
        set.remove(&task_id);
        if set.is_empty() {
            values.remove(&key);
        }
    }
}

/// Wake up to `n` tasks parked on futex word `uaddr`. Returns the count
/// woken. Drains the wakers under the table lock, then fires them after
/// dropping it (wake() may re-enter the scheduler). Mirrors `wake_one`:
/// clears each woken task's finite sleep deadline so its re-poll falls
/// through to re-enter user mode (where musl re-checks the futex word).
fn futex_wake_waiters(uaddr: u64, n: u32) -> usize {
    futex_wake_waiters_key(futex_key(0, uaddr), n)
}

pub(crate) fn futex_wake_waiters_key(key: FutexKey, n: u32) -> usize {
    let drained: alloc::vec::Vec<(u64, core::task::Waker)> = {
        let mut values = futex_wait_bucket(key).values.lock();
        let Some(set) = values.get_mut(&key) else {
            return 0;
        };
        // BTreeMap has no pop; collect the first `n` keys then remove them.
        let take: alloc::vec::Vec<u64> = set.keys().take(n as usize).copied().collect();
        let mut out = alloc::vec::Vec::with_capacity(take.len());
        for tid in take {
            if let Some(w) = set.remove(&tid) {
                out.push((tid, w));
            }
        }
        if set.is_empty() {
            values.remove(&key);
        }
        out
    };
    let count = drained.len();
    for (tid, w) in drained {
        wake_one(tid, w);
    }
    count
}

/// `FUTEX_REQUEUE`/`FUTEX_CMP_REQUEUE` core: wake up to `n_wake` waiters on
/// `uaddr`, then MOVE up to `n_move` of the remaining waiters onto
/// `uaddr2`'s wait queue without firing their wakers (Linux
/// `futex_requeue`). Returns `(woken, moved)`.
///
/// The queue move holds the source and destination bucket locks in ascending
/// bucket order. After the move — with both locks DROPPED — each mover's park
/// state is retargeted to the destination
/// word: `futex_park_gen` is set to a destination-generation snapshot
/// taken BEFORE the queue move (so a `FUTEX_WAKE(uaddr2)` racing the move
/// bumps past the snapshot and the waiter's gen guard fires), then
/// `futex_uaddr`/`futex_val` flip to the destination word and `new_val`
/// (the caller-sampled current `*uaddr2`). A backstop re-poll that
/// interleaves anywhere in this window is caught by the park loop's word
/// re-validation (`futex_park_should_stay`): the source word was already
/// rewritten by the userspace caller (musl stores the barrier word before
/// issuing the requeue), so a stale-state re-check proceeds to userspace
/// and re-evaluates there — a bounded spurious wake, never a lost one.
fn futex_requeue_waiters(
    uaddr: u64,
    uaddr2: u64,
    n_wake: u32,
    n_move: u32,
    new_val: u32,
) -> (usize, usize) {
    futex_requeue_waiters_keyed(
        futex_key(0, uaddr),
        futex_key(0, uaddr2),
        uaddr2,
        n_wake,
        n_move,
        new_val,
    )
}

fn futex_take_waiters(
    values: &mut FutexWaiterMap,
    key: FutexKey,
    n: u32,
) -> alloc::vec::Vec<(u64, core::task::Waker)> {
    let Some(set) = values.get_mut(&key) else {
        return alloc::vec::Vec::new();
    };
    let take: alloc::vec::Vec<u64> = set.keys().take(n as usize).copied().collect();
    let mut movers = alloc::vec::Vec::with_capacity(take.len());
    for tid in take {
        if let Some(waker) = set.remove(&tid) {
            movers.push((tid, waker));
        }
    }
    if set.is_empty() {
        values.remove(&key);
    }
    movers
}

fn futex_insert_waiters(
    values: &mut FutexWaiterMap,
    key: FutexKey,
    movers: alloc::vec::Vec<(u64, core::task::Waker)>,
) -> alloc::vec::Vec<u64> {
    let mut tids = alloc::vec::Vec::with_capacity(movers.len());
    let dst = values.entry(key).or_default();
    for (tid, waker) in movers {
        dst.insert(tid, waker);
        tids.push(tid);
    }
    tids
}

fn futex_requeue_waiters_keyed(
    key: FutexKey,
    key2: FutexKey,
    uaddr2: u64,
    n_wake: u32,
    n_move: u32,
    new_val: u32,
) -> (usize, usize) {
    // Wake side first, exactly like FUTEX_WAKE: bump the source generation
    // (so a waiter racing its park registration re-checks), then pop + fire.
    futex_bump_counter_key(key);
    let woken = futex_wake_waiters_key(key, n_wake);
    if n_move == 0 {
        return (woken, 0);
    }
    // Destination-generation snapshot BEFORE the queue move (see above).
    let gen2 = futex_wake_counter_key(key2);
    let source_bucket = futex_bucket_index(key);
    let destination_bucket = futex_bucket_index(key2);
    let moved: alloc::vec::Vec<u64> = if source_bucket == destination_bucket {
        let mut values = FUTEX_WAITERS[source_bucket].values.lock();
        let movers = futex_take_waiters(&mut values, key, n_move);
        futex_insert_waiters(&mut values, key2, movers)
    } else if source_bucket < destination_bucket {
        // A total bucket order makes opposite-direction concurrent requeues
        // deadlock-free.
        let mut source = FUTEX_WAITERS[source_bucket].values.lock();
        let mut destination = FUTEX_WAITERS[destination_bucket].values.lock();
        let movers = futex_take_waiters(&mut source, key, n_move);
        futex_insert_waiters(&mut destination, key2, movers)
    } else {
        let mut destination = FUTEX_WAITERS[destination_bucket].values.lock();
        let mut source = FUTEX_WAITERS[source_bucket].values.lock();
        let movers = futex_take_waiters(&mut source, key, n_move);
        futex_insert_waiters(&mut destination, key2, movers)
    };
    // Retarget each mover's park state OUTSIDE the table lock (the task
    // registry lock in with_user_task_ctx must never nest inside it).
    for tid in &moved {
        crate::user_task::with_user_task_ctx(*tid, |uc| {
            uc.futex_park_gen.store(gen2, Ordering::Release);
            uc.futex_val.store(new_val, Ordering::Release);
            uc.futex_uaddr.store(uaddr2, Ordering::Release);
            uc.futex_namespace.store(key2.namespace, Ordering::Release);
        });
    }
    (woken, moved.len())
}

/// Read the 4-byte futex word at user address `uaddr` in the CURRENT
/// address space. `None` on fault/unmapped. Used by `FUTEX_CMP_REQUEUE`'s
/// `*uaddr == val3` check and by the park loop's word re-validation.
pub(crate) fn futex_read_user_word(uaddr: u64) -> Option<u32> {
    if uaddr == 0 {
        return None;
    }
    let mut b = [0u8; 4];
    // SAFETY: copy_from_user range-validates the user pointer and
    // SMAP-brackets the read.
    if unsafe { copy_from_user(&mut b, uaddr) }.is_ok() {
        Some(u32::from_ne_bytes(b))
    } else {
        None
    }
}

/// Decide whether a parked `FUTEX_WAIT` should STAY parked on its next
/// park-loop re-check (the ~10 ms wheel-backstop re-poll): only while BOTH
/// no `FUTEX_WAKE` generation has landed on the word (`gen_now ==
/// park_gen`) AND the futex word itself still holds the value the waiter
/// parked on (`word_now == Some(expected)`).
///
/// The word re-validation is the load-bearing half. Futex protocols may
/// change the word WITHOUT a wake on the old word — musl's
/// `unlock_requeue` stores the barrier word and then only requeues; a
/// robust-futex owner death rewrites the word; any PI/handoff scheme does
/// the same — and Linux waiters tolerate that because every spurious
/// return re-checks the word in userspace. NARF's own-stack park loop
/// swallows the backstop wake INSIDE the kernel, so before this check a
/// silently-rewritten word meant the waiter re-parked forever on a word
/// nobody would ever wake again — the permanent variant of the SMP strand
/// (`condbcast_smoke`). An unreadable word (`None` — AS torn down,
/// unmapped) also proceeds: never re-park on memory we cannot re-check.
pub(crate) fn futex_park_should_stay(
    gen_now: u64,
    park_gen: u64,
    word_now: Option<u32>,
    expected: u32,
) -> bool {
    gen_now == park_gen && word_now == Some(expected)
}

/// Test-only accessor for the futex wake counter — Wave-65 smokes
/// observe CLONE_CHILD_CLEARTID's exit-side futex wake by reading
/// this counter before/after the exit notification.
#[doc(hidden)]
pub fn __test_futex_wake_counter(uaddr: u64) -> u64 {
    futex_wake_counter(uaddr)
}

/// Test-only accessor for a private futex namespace's wake counter.
#[doc(hidden)]
pub fn __test_futex_wake_counter_scoped(namespace: u64, uaddr: u64) -> u64 {
    futex_wake_counter_key(futex_key(namespace, uaddr))
}

/// Test-only: register a waiter / requeue / count parked waiters, so the
/// kernel-test suite can pin the FUTEX_REQUEUE queue-move semantics
/// without a user address space.
#[doc(hidden)]
pub fn __test_futex_requeue(uaddr: u64, uaddr2: u64, n_wake: u32, n_move: u32) -> (usize, usize) {
    futex_requeue_waiters(uaddr, uaddr2, n_wake, n_move, 0)
}

/// Test hook: expose only bucket identity so the requeue smoke can guarantee
/// it exercises the ordered two-bucket path.
#[doc(hidden)]
pub fn __test_futex_bucket_index(namespace: u64, uaddr: u64) -> usize {
    futex_bucket_index(futex_key(namespace, uaddr))
}

#[doc(hidden)]
pub fn __test_futex_waiter_count(uaddr: u64) -> usize {
    let key = futex_key(0, uaddr);
    futex_wait_bucket(key)
        .values
        .lock()
        .get(&key)
        .map(|set| set.len())
        .unwrap_or(0)
}

#[doc(hidden)]
pub fn __test_futex_register_waiter_scoped(
    namespace: u64,
    uaddr: u64,
    task_id: u64,
    waker: core::task::Waker,
) {
    futex_register_waiter_key(futex_key(namespace, uaddr), task_id, waker);
}

#[doc(hidden)]
pub fn __test_futex_wake_scoped(namespace: u64, uaddr: u64, n: u32) -> usize {
    let key = futex_key(namespace, uaddr);
    futex_bump_counter_key(key);
    futex_wake_waiters_key(key, n)
}

/// Watchdog probe: is `tid`'s waker actually registered in the wait queue
/// for `(namespace, uaddr)`? A task claiming (via `futex_uaddr`) to be
/// blocked on a word while absent from its queue can never receive a
/// `FUTEX_WAKE` — the lost-waiter signature the park census looks for.
pub fn dbg_futex_waiter_registered(namespace: u64, uaddr: u64, tid: u64) -> bool {
    let key = futex_key(namespace, uaddr);
    futex_wait_bucket(key)
        .values
        .lock()
        .get(&key)
        .map(|set| set.contains_key(&tid))
        .unwrap_or(false)
}

/// Fatal-path futex snapshot: `(live_generation, registered_waiters)`.
pub fn dbg_futex_state(namespace: u64, uaddr: u64) -> (u64, usize) {
    let key = futex_key(namespace, uaddr);
    let generation = futex_wake_counter_key(key);
    let waiters = futex_wait_bucket(key)
        .values
        .lock()
        .get(&key)
        .map(|set| set.len())
        .unwrap_or(0);
    (generation, waiters)
}

/// Test-only FUTEX_WAKE equivalent (gen bump + pop-and-fire), so tests can
/// drive the wake side of the wait queue without a TrapContext.
#[doc(hidden)]
pub fn futex_wake_waiters_for_test(uaddr: u64, n: u32) -> usize {
    futex_bump_counter(uaddr);
    futex_wake_waiters(uaddr, n)
}

/// Shared FUTEX_WAIT core for both the classic `futex(2)` FUTEX_WAIT op
/// and the futex2 `futex_wait(2)` syscall. Implements the same real
/// cooperative wait NARF's pthreads already rely on:
///
///  - `*uaddr != val` ⇒ the wait condition no longer holds; return
///    `-EAGAIN` (Linux's contract — the caller's fast path observes the
///    change and proceeds without sleeping).
///  - `*uaddr == val` ⇒ park the caller via a bounded yield back to the
///    executor (the deadline branch of `UserTaskFuture::poll` keeps it
///    off-CPU until the park expires or a wake bumps the per-uaddr
///    counter), then resume with `0`. The libc-side recheck loop re-arms
///    the wait until the condition is satisfied, so a `futex_wake` on the
///    same word makes the waiter progress.
///
/// `uaddr == 0` is treated as an immediate (POSIX-permitted) spurious
/// wake so wake-path smokes can run without a backing mapping.
fn futex_wait_core(
    ctx: &mut dyn TrapContext,
    namespace: u64,
    uaddr: u64,
    val: u32,
    park_cap_ns: u64,
) {
    const EAGAIN: i64 = 11;
    const EFAULT: i64 = 14;
    if uaddr == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    // Seqlock read: sample the wake generation BEFORE reading `*uaddr` (see
    // `futex_wait_seqlock_read` — sampling after the read loses a racing
    // FUTEX_WAKE and deadlocks a contended mutex/condvar under SMP).
    let key = futex_key(namespace, uaddr);
    let (gen, current) = match futex_wait_seqlock_read_key(key, || {
        let mut buf4 = [0u8; 4];
        // SAFETY: copy_from_user range-validates `uaddr` + SMAP-brackets the read.
        if unsafe { copy_from_user(&mut buf4, uaddr) }.is_ok() {
            Some(u32::from_ne_bytes(buf4))
        } else {
            None
        }
    }) {
        Some(x) => x,
        None => {
            ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
            return;
        }
    };
    if current != val {
        ctx.set_return(SyscallReturn::ok((-EAGAIN) as u64));
        return;
    }
    // REAL blocking park, same wait queue + per-uaddr wake counter as the
    // classic `sys_futex` FUTEX_WAIT (Linux futex2 and classic futex operate
    // on the SAME words — a FUTEX_WAKE must wake either). Register happens in
    // the poll routine; here we publish the uaddr + counter snapshot + an
    // infinite (or timeout-bounded) deadline and yield.
    let deadline = if park_cap_ns == 0 {
        u64::MAX
    } else {
        narf_scheduler::narf_time::monotonic_ns().saturating_add(park_cap_ns)
    };
    if let (Some(uctx), Some(hook)) = (
        crate::user_task::current_user_task(),
        crate::user_task::yield_hook(),
    ) {
        ctx.set_return(SyscallReturn::ok(0));
        // SAFETY: uctx is live for the trap round-trip.
        unsafe {
            let uc = &*uctx;
            uc.futex_park_gen.store(gen, Ordering::Release);
            // Park-loop word re-validation snapshot (see sys_futex).
            uc.futex_val.store(val, Ordering::Release);
            uc.futex_uaddr.store(uaddr, Ordering::Release);
            uc.futex_namespace.store(namespace, Ordering::Release);
            uc.sleep_deadline_ns.store(deadline, Ordering::Release);
            ctx.save_user_state(uc.state.get() as *mut u8);
            *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
            if narf_scheduler::stackful::user_own_stack_enabled() {
                own_stack_block(ctx);
                return;
            }
            hook(uctx);
        }
        // unreachable
    }
    // Test/no-future fallback: synchronous success.
    ctx.set_return(SyscallReturn::ok(0));
}

/// Bounded cooperative-park cap for the futex2 wait ops. Unlike the classic
/// `sys_futex` FUTEX_WAIT — whose no-timeout park is infinite (`u64::MAX`) and
/// only ever resumed by a FUTEX_WAKE waker (matching Linux block-until-woken) —
/// the futex2 `futex_wait`/`futex_waitv` are documented (and smoke-tested) to
/// park via a *bounded* yield and resume with 0, letting the caller's recheck
/// loop re-arm. Passing 0 here would map to an infinite deadline that the poll
/// routine's one-tick fallback re-parks forever (never resuming to user mode),
/// so a self-directed wait with no concurrent waker hangs. A finite cap makes
/// the park expire → resume 0 (POSIX-permitted spurious wake); a real waker
/// still fires promptly through the per-uaddr wait queue well before the cap.
const FUTEX2_PARK_CAP_NS: u64 = 50_000_000; // 50 ms

const SIG_BLOCK: u32 = 0;
const SIG_UNBLOCK: u32 = 1;
const SIG_SETMASK: u32 = 2;

// ── Phase-2 signal gap-fills ────────────────────────────────────────
//
// Six more Linux signal-surface syscalls needed for relibc to bind
// directly: sigaltstack, rt_sigtimedwait, tkill, rt_sigsuspend,
// rt_sigpending. Each follows the same per-task BTreeMap storage
// shape as SIGNAL_PENDING / SIGNAL_MASK so the test reset hook
// drops all of it on `__test_signal_reset`.

/// Per-task alternate signal stack registration (Linux `stack_t`
/// shape: sp + flags + size). A signal whose handler has
/// `SA_ONSTACK` builds its sigframe on the alt stack instead of
/// the regular user RSP. `flags = SS_DISABLE (2)` means "no alt
/// stack active"; the entry stays in the table for round-trip
/// query semantics but no rewrite happens.
#[derive(Copy, Clone, Debug, Default)]
pub struct SigAltStack {
    pub sp: u64,
    pub flags: u32,
    pub size: u64,
}

/// `stack_t` flag bits Linux honours.
const SS_DISABLE: u32 = 2;
const SS_ONSTACK: u32 = 1;
/// Minimum altstack size — Linux MINSIGSTKSZ on x86_64 is 2048;
/// we honour the same lower bound.
const MIN_SIGSTKSZ: u64 = 2048;

static SIG_ALTSTACK: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, SigAltStack>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

fn sigaltstack_table_init() {
    let mut g = SIG_ALTSTACK.lock();
    if g.is_none() {
        *g = Some(BTreeMap::new());
    }
}

/// Read the alternate signal stack for `task`. Returns the
/// registered slot or a zero-initialised `SigAltStack` with
/// `flags = SS_DISABLE` if the task never installed one.
pub fn sigaltstack_of(task: u64) -> SigAltStack {
    let g = SIG_ALTSTACK.lock();
    g.as_ref()
        .and_then(|m| m.get(&task).copied())
        .unwrap_or(SigAltStack {
            sp: 0,
            flags: SS_DISABLE,
            size: 0,
        })
}

/// Atomically consume the LOWEST pending signal in `set` for `task`:
/// clear its bit under the `SIGNAL_PENDING` lock and return the signum,
/// or `None` when nothing in `set` is pending. The single-lock
/// check-and-clear is what makes two racing consumers (e.g. the
/// return-to-user delivery hook vs a re-executed `rt_sigtimedwait`)
/// unable to both take the same instance.
fn sigwait_consume(task: u64, set: u64) -> Option<u32> {
    signal_bits_update_existing(&SIGNAL_PENDING, task, |slot| {
        let candidates = *slot & set;
        if candidates == 0 {
            return None;
        }
        let signum = sig_from_bit(candidates);
        *slot &= !(sig_bit(signum));
        Some(signum)
    })
    .flatten()
}

// Function-pointer hook: arch trap dispatcher invokes this on
// every int-0x80 / syscall trap-return that's heading back to
// user mode, just before the asm tail iretq's. The arch passes
// the raw syscall number the user trapped on so SA_RESTART can
// consult the restartable-syscall table; a non-syscall caller
// (e.g. a future trap-after-IRQ delivery point) would pass
// `SYSCALL_NUM_NONE` and the restart path would short-circuit.
//
// Same shape as `install_address_space_lookup` so the trap path
// doesn't need a direct dep on this crate's signal internals.
pub type SignalDeliveryHook = fn(&mut dyn TrapContext, u32) -> bool;

// Installed once during boot and immutable afterward. Trap return consults
// this slot for every userspace-bound syscall, so a global IRQ-disabling lock
// here serialized otherwise unrelated CPUs and added interrupt masking to the
// common no-signal path.
static SIGNAL_DELIVERY_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Install the function the arch trap path calls on every
/// user-bound int-0x80 trap-return. `install_core_syscalls`
/// auto-installs `default_signal_delivery`.
pub fn install_signal_delivery_hook(hook: SignalDeliveryHook) {
    SIGNAL_DELIVERY_HOOK.store(hook as usize, Ordering::Release);
}

/// Look up the currently-installed delivery hook, if any. The
/// arch trap dispatcher calls this on its way back to user.
pub fn signal_delivery_hook() -> Option<SignalDeliveryHook> {
    let raw = SIGNAL_DELIVERY_HOOK.load(Ordering::Acquire);
    if raw == 0 {
        None
    } else {
        // SAFETY: every non-zero value stored in SIGNAL_DELIVERY_HOOK is a
        // complete SignalDeliveryHook pointer. Acquire pairs with install.
        Some(unsafe { core::mem::transmute::<usize, SignalDeliveryHook>(raw) })
    }
}

/// Sentinel passed by callers that aren't on a syscall trap path.
/// Today only int 0x80 invokes the hook, but the constant exists
/// so future call sites (e.g. on-IRQ delivery) can reach the hook
/// without faking a syscall number — `is_restartable_syscall`
/// short-circuits to `false` on this value.
pub const SYSCALL_NUM_NONE: u32 = u32::MAX;

/// Subset of syscalls that observe Linux's "automatic restart on
/// SA_RESTART" semantics. POSIX-2017 §2.4 lists the not-restartable
/// set (the timeout/sleep/wait family); everything outside that set
/// is restartable when SA_RESTART is set.
///
/// NARF round 1: most syscalls are non-blocking today, so the
/// "interrupted by signal" return only fires from the explicitly
/// blocking ones. Of those, the timeout family is NOT restarted;
/// the rest ARE.
///
/// Returns `true` if the named syscall is in the "auto-restart on
/// SA_RESTART" set. The check is keyed on `Syscall::from_raw` so a
/// versioned wire number (top byte = version) still resolves to the
/// canonical syscall.
fn is_restartable_syscall(raw: u32) -> bool {
    if raw == SYSCALL_NUM_NONE {
        return false;
    }
    // Strip the version byte (top 8 bits) — restartability is a
    // property of the canonical syscall, not its versioned variant.
    let canonical = crate::syscall::syscall_number(raw);
    let n = match crate::syscall::Syscall::from_raw(canonical) {
        Some(s) => s,
        None => return false,
    };
    // Linux: signal-targeted timeout variants (nanosleep,
    // clock_nanosleep, rt_sigtimedwait, rt_sigsuspend, poll/
    // epoll_wait with a timeout, ...) are NEVER auto-restarted
    // regardless of SA_RESTART. The kernel returns
    // ERESTART_RESTARTBLOCK / EINTR and the user sees the
    // abbreviated sleep. See arch/x86/kernel/signal.c
    // §handle_signal.
    !matches!(
        n,
        crate::syscall::Syscall::Sleep
            | crate::syscall::Syscall::Nanosleep
            | crate::syscall::Syscall::ClockNanosleep
            | crate::syscall::Syscall::RtSigtimedwait
            | crate::syscall::Syscall::RtSigsuspend
            | crate::syscall::Syscall::Poll
            | crate::syscall::Syscall::Ppoll
            | crate::syscall::Syscall::Select
            | crate::syscall::Syscall::Pselect6
            | crate::syscall::Syscall::EpollWait
            | crate::syscall::Syscall::EpollPwait
            | crate::syscall::Syscall::EpollPwait2
            | crate::syscall::Syscall::Semop
            | crate::syscall::Syscall::Semtimedop
            | crate::syscall::Syscall::Msgsnd
            | crate::syscall::Syscall::Msgrcv
    )
}

#[doc(hidden)]
pub(crate) fn __test_is_restartable_syscall(raw: u32) -> bool {
    is_restartable_syscall(raw)
}

/// Build the `SigDeliveryParams` for `(task, action, signum,
/// syscall_no)`. Consults the per-task altstack registry + the
/// restartable-syscall table so the arch `deliver_signal` impl
/// has every signal-delivery decision pre-computed.
// A siginfo carries several independent scalars (code/addr/value/pid) plus the
// delivery context; bundling them would just move the same fields behind a
// struct the two call sites fill inline.
#[allow(clippy::too_many_arguments)]
fn build_delivery_params(
    task: u64,
    action: SigAction,
    signum: u32,
    syscall_no: u32,
    si_code: i32,
    si_addr: u64,
    si_value: u64,
    si_pid: u32,
) -> SigDeliveryParams {
    // Altstack: only honour if SA_ONSTACK is set AND the slot is
    // installed AND it's not SS_DISABLE. A misconfigured altstack
    // (size below MIN_SIGSTKSZ) was already rejected at install
    // time by `sys_sigaltstack`.
    let altstack = sigaltstack_of(task);
    let altstack_valid = (action.flags & SA_ONSTACK) != 0
        && (altstack.flags & SS_DISABLE) == 0
        && altstack.sp != 0
        && altstack.size != 0;
    SigDeliveryParams {
        handler: action.handler,
        restorer: action.restorer,
        signum,
        flags: action.flags,
        altstack_sp: if altstack_valid { altstack.sp } else { 0 },
        altstack_size: if altstack_valid { altstack.size } else { 0 },
        restartable_syscall: is_restartable_syscall(syscall_no),
        si_code,
        si_addr,
        si_value,
        si_pid,
    }
}

/// Default delivery hook: pick the lowest pending unmasked
/// signal, look up its handler, ask the trap context to rewrite
/// itself to deliver. Fast path — when nothing's pending it
/// takes a single lock + a single bitmap read and returns.
///
/// `syscall_no` is the raw wire number of the syscall the trap
/// is returning from (or `SYSCALL_NUM_NONE` if the hook is being
/// driven from a non-syscall path). Consulted only for the
/// `SA_RESTART` decision.
///
/// SA flag handling:
/// - SA_NODEFER (0x4000_0000): if set, don't auto-block the
///   delivered signal during handler execution. Default Linux
///   behaviour adds the delivered signal to the mask for the
///   duration of the handler; SA_NODEFER opts out so the handler
///   can recursively re-enter on the same signal (used by stack
///   traces, dump-and-die handlers).
/// - SA_RESETHAND (0x8000_0000): clear the handler after delivery
///   so the next occurrence falls through to the default action.
/// - SA_ONSTACK / SA_SIGINFO / SA_RESTART: passed through to the
///   arch `deliver_signal` via the `SigDeliveryParams` so the
///   arch can lay out the frame on the altstack (SA_ONSTACK),
///   push the 3-arg siginfo_t+ucontext frame (SA_SIGINFO), and
///   rewind RIP for re-execution (SA_RESTART).
pub fn default_signal_delivery(ctx: &mut dyn TrapContext, syscall_no: u32) -> bool {
    // u64::MAX = no restriction: consider every deliverable signal. The
    // timer-IRQ preemptive path calls the restricted form with a narrower
    // mask (eager / fatal-unhandled only).
    default_signal_delivery_restricted(ctx, syscall_no, u64::MAX)
}

/// Body of `default_signal_delivery`, but only signals whose bit is set in
/// `restrict` are eligible. Picks the lowest eligible deliverable signal
/// (`pending & !mask & restrict`) and delivers it through the same handler
/// / default-action path.
pub(crate) fn default_signal_delivery_restricted(
    ctx: &mut dyn TrapContext,
    syscall_no: u32,
    restrict: u64,
) -> bool {
    if !ctx.returning_to_user() {
        return false;
    }
    let task = current_task_id();

    let pending = signal_bits_get(&SIGNAL_PENDING, task);
    if pending == 0 {
        return false;
    }
    let mask = signal_bits_get(&SIGNAL_MASK, task);
    // `& !1`: bit 0 is the POSIX null signal and is NEVER deliverable. Send
    // paths already refuse to set it (kill/tkill/tgkill/sigqueue treat sig 0
    // as an existence probe), but mask it here too so a stray bit-0 raise can
    // never be taken as "signal 0" → default-action Terminate.
    // No null-signal bit in the N-1 convention (signal 0 has no bit),
    // so no `& !1` guard is needed — every set bit is a real signal.
    // Linux `do_sigtimedwait` `real_blocked` semantics: while this task is
    // parked in / re-executing `rt_sigtimedwait` (`sigwait_set` armed), signals
    // in the waited set belong to the WAITER — `sigwait_consume` dequeues them
    // on the re-execution — and must NOT be delivered to a handler here even
    // when they are unblocked. stress-ng --sigrt waits on RT signals it leaves
    // UNBLOCKED with nop handlers installed; without this reservation the nop
    // handler steals the graceful-shutdown `sigqueue(sival=0)` and the child
    // parks in `sigwaitinfo` forever (the --sigrt hang).
    // Both the live park routing (`sigwait_set`) AND the sticky reservation
    // (`sigwait_reserve`, armed by every rt_sigtimedwait and released at the
    // task's next non-sigwait park) — the latter covers the processing gap
    // BETWEEN consecutive sigtimedwaits, where the nop-handler sigreturn
    // chain would otherwise drain the waiter's queue (and eat stress-ng
    // --sigrt's shutdown marker).
    let sigwait_reserved = crate::user_task::current_user_task()
        .map(|u| {
            // SAFETY: in-flight task's poller-pinned UserTaskCtx; atomic load only.
            unsafe {
                (*u).sigwait_set.load(Ordering::Acquire)
                    | (*u).sigwait_reserve.load(Ordering::Acquire)
            }
        })
        .unwrap_or(0);
    let deliverable = pending & !mask & restrict & !sigwait_reserved;
    if deliverable == 0 {
        return false;
    }
    let signum = sig_from_bit(deliverable);
    if crate::ptrace::ptrace_intercept_signal(ctx, signum) {
        return true;
    }

    let action = match sigaction_lookup_full(task, signum as usize) {
        Some(a) => a,
        None => {
            // No user handler installed → POSIX default action.
            // Clear the pending bit before applying the action so a
            // retry trap doesn't re-fire the same signal.
            let _ = signal_bits_update_existing(&SIGNAL_PENDING, task, |slot| {
                *slot &= !(sig_bit(signum));
            });
            match default_signal_action(signum) {
                DefaultAction::Ignore => {
                    // Silently consumed (existing behaviour). Discard any
                    // queued RT payloads too — each queued ignored instance
                    // is "delivered" by being dropped (signal(7)).
                    purge_sigqueue(task, signum);
                }
                DefaultAction::Terminate => {
                    terminate_current_task(ctx, task, signum, false);
                    // unreachable when a UserTaskFuture is in flight.
                }
                DefaultAction::CoreDump => {
                    terminate_current_task(ctx, task, signum, true);
                    // unreachable when a UserTaskFuture is in flight.
                }
                DefaultAction::Stop => {
                    // Job control: actually stop the task (the pending bit
                    // was cleared above). enter_stopped records the stopped
                    // state, notifies the parent, and parks until SIGCONT.
                    enter_stopped(ctx, task, signum);
                    // No executor wired (kernel-test context): enter_stopped
                    // returns without parking — fall through and consume.
                }
                DefaultAction::Continue => {
                    // A SIGCONT with no handler. The actual resume of a
                    // stopped task happens eagerly in the raise path
                    // (signal_stopcont_interaction); here there is just
                    // nothing left to do — consume it.
                }
            }
            return true;
        }
    };
    // SIG_IGN (handler == 1) is NOT a real handler: silently consume the
    // pending signal instead of building a frame and "delivering" it. The old
    // code passed handler==1 straight to deliver_signal, which set the user
    // RIP to 1 and returned there → an immediate user fault. SIG_DFL (0) is
    // stored as `None`, so it never reaches here (the None arm above applies
    // the default action); a SIG_IGN slot is the only `handler <= 1` case.
    if action.handler <= 1 {
        let _ = signal_bits_update_existing(&SIGNAL_PENDING, task, |slot| {
            *slot &= !(sig_bit(signum));
        });
        // SIG_IGN consumes every queued RT instance with the bit.
        purge_sigqueue(task, signum);
        return true;
    }
    // Async signals: si_code = SI_USER (0), si_addr = 0 — unless this
    // instance was queued by rt_sigqueueinfo/sigqueue, in which case
    // honour its si_code (SI_QUEUE) + si_value (the sigval payload).
    let (si_code, si_value, si_pid) = take_sigqueue_info(task, signum).unwrap_or((0, 0, 0));
    let params = build_delivery_params(
        task, action, signum, syscall_no, si_code, 0, si_value, si_pid,
    );
    if !ctx.deliver_signal(&params) {
        return false;
    }
    // If this task is parked in rt_sigtimedwait, this handler-bound signal
    // (necessarily OUT of the sigwait set — in-set signals are blocked and
    // consumed by sigwait_consume, never delivered here) is interrupting
    // the wait. Mark it so the re-executed rt_sigtimedwait returns -EINTR
    // even though this delivery is about to clear the pending bit before
    // the re-execution can observe it. Without this a SIGALRM (stress-ng
    // --sigrt's timeout) is delivered but the syscall re-parks forever.
    if let Some(u) = crate::user_task::current_user_task() {
        // SAFETY: the in-flight task's poller-pinned UserTaskCtx; atomics only.
        unsafe {
            let sw = (*u).sigwait_set.load(Ordering::Acquire);
            if sw != 0 && (sw & sig_bit(signum)) == 0 {
                (*u).sigwait_interrupted.store(true, Ordering::Release);
            }
        }
    }
    // Remember whether this frame is the restorer-based Linux
    // rt_sigframe so `sys_sigreturn` resolves it from RSP.
    set_sigreturn_use_rsp(task, params.restorer != 0);
    // Record the frame layout we just built so sys_sigreturn restores from the
    // right offsets — must match deliver_signal's `want_siginfo || force_rt`
    // (SA_SIGINFO=0x4, see syscall.rs). Never re-derive the layout from user memory.
    set_sigreturn_is_rt(task, (params.flags & 0x4) != 0 || params.restorer != 0);
    // Clear only after the rewrite succeeded — a failed
    // delivery (e.g. arch returns false) should leave pending
    // alone so the next trap retries.
    let _ = signal_bits_update_existing(&SIGNAL_PENDING, task, |slot| {
        *slot &= !(sig_bit(signum));
    });
    // RT queueing: this delivery drained ONE queued instance (the take
    // above); if more remain, re-arm the bit so the next return-to-user
    // delivers the next instance with its own si_value.
    rearm_pending_if_queued(task, signum);
    // Save the pre-handler mask so `sys_sigreturn` restores it (POSIX),
    // undoing the auto-block below. Captured BEFORE the SA_NODEFER OR so the
    // restored value is the mask in effect when the handler was entered.
    // A pending `rt_sigsuspend` record takes precedence: the mask this
    // handler's sigreturn must restore is the PRE-SUSPEND mask, not the
    // temporary suspend mask the wait installed (Linux TIF_RESTORE_SIGMASK).
    {
        let cur = take_suspend_saved_mask(task).unwrap_or_else(|| signal_mask_of(task));
        set_sigreturn_saved_mask(task, cur);
    }
    // SA_NODEFER: skip the auto-block. Default: add the delivered
    // signal to the mask so the handler runs without re-entrancy.
    if (action.flags & SA_NODEFER) == 0 {
        let _ = signal_bits_update(&SIGNAL_MASK, task, |slot| *slot |= sig_bit(signum));
    }
    // SA_RESETHAND: one-shot — clear the handler so the next
    // occurrence falls through to the default action. Cleared in the
    // (possibly shared) live sighand, per Linux thread-group semantics.
    if (action.flags & SA_RESETHAND) != 0 {
        let h = {
            let g = SIGACTION_TABLE.lock();
            g.as_ref().and_then(|m| m.get(&task).cloned())
        };
        if let Some(h) = h {
            h.lock()[signum as usize] = None;
        }
    }
    true
}

// ── Synchronous-signal delivery for CPU exceptions ────────────────
//
// Counterpart to the async hook above. The async path runs on
// every int-0x80 trap-return and consumes the per-task pending
// bitmap (the work `kill(2)` leaves behind). The synchronous path
// runs from `rust_trap_handler` for vectors 0..31 (CPU exceptions)
// when the trap came from user mode AND a sigaction handler is
// registered for the matching signal. It rewrites the trap frame
// to deliver the signal at user mode, mirroring the async hook's
// `deliver_signal` path so the frame layout the handler observes
// is identical.
//
// Strict gating on `frame.cs.RPL == 3` (caller's responsibility)
// keeps kernel-mode CPU exceptions on the existing probe-catch /
// panic path: probes are for kernel-issued recovery (test
// infrastructure), user-mode crashes are this new path. The two
// don't overlap.

/// POSIX signal numbers we map to. Stage-4 first cut: the
/// minimum set the synchronous-signal path can possibly raise.
/// The full table is `[1..=31]`, but only these can come from
/// CPU exceptions on x86_64 today.
const SIGILL: u32 = 4;
const SIGTRAP: u32 = 5;
const SIGBUS: u32 = 7;
const SIGFPE: u32 = 8;
const SIGSEGV: u32 = 11;

/// Map an x86_64 CPU-exception vector to the POSIX signal a
/// synchronous-delivery handler should observe. Returns `None`
/// for vectors that aren't user-recoverable through a signal
/// handler (the trap path falls back to its existing panic
/// surface for those).
///
/// References: AMD APM Vol 2 §8.2 (vector → exception map),
/// SUSv5 `<signal.h>` for the signal-number table.
pub fn vector_to_signum(vector: u64) -> Option<u32> {
    match vector {
        0 => Some(SIGFPE),   // #DE divide-by-zero / div overflow
        1 => Some(SIGTRAP),  // #DB debug / single step
        3 => Some(SIGTRAP),  // #BP breakpoint
        4 => Some(SIGFPE),   // #OF overflow
        6 => Some(SIGILL),   // #UD undefined opcode
        13 => Some(SIGSEGV), // #GP general protection
        14 => Some(SIGSEGV), // #PF page fault
        17 => Some(SIGBUS),  // #AC alignment check
        _ => None,
    }
}

/// Per-fault payload the arch trap path hands to the sync-signal
/// hook. Wave-58: `addr` is the faulting address (CR2 on x86_64
/// #PF, FAR_EL1 on aarch64 sync EL0 aborts). 0 for vectors that
/// don't have one (#UD/#DE/#OF/#BP — the hook substitutes RIP).
#[derive(Copy, Clone, Debug, Default)]
pub struct SyncFaultInfo {
    /// Faulting address (CR2 / FAR_EL1). 0 when N/A.
    pub addr: u64,
}

/// Function-pointer hook the arch trap dispatcher calls for
/// every CPU exception (vectors 0..31) that originated in user
/// mode. Returns `true` if the trap frame was rewritten to
/// deliver a signal — the trap dispatcher should then return
/// directly so `iretq` lands at the rewritten user RIP.
/// Returns `false` if no handler was installed (or the vector
/// has no signal mapping); the caller falls through to the
/// existing panic / probe-catch path.
type SyncSignalHook = fn(&mut dyn TrapContext, u64, SyncFaultInfo) -> bool;

// CPU-exception delivery has the same install-once lifetime as the normal
// trap-return hook. Keep faults on a lock-free lookup path too.
static SYNC_SIGNAL_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Install the function the arch trap path calls on user-mode
/// CPU exceptions. `install_core_syscalls` auto-installs
/// `default_sync_signal_delivery`.
pub fn install_sync_signal_hook(hook: SyncSignalHook) {
    SYNC_SIGNAL_HOOK.store(hook as usize, Ordering::Release);
}

/// Look up the currently-installed sync-signal hook, if any.
pub fn sync_signal_hook() -> Option<SyncSignalHook> {
    let raw = SYNC_SIGNAL_HOOK.load(Ordering::Acquire);
    if raw == 0 {
        None
    } else {
        // SAFETY: every non-zero value stored in SYNC_SIGNAL_HOOK is a
        // complete SyncSignalHook pointer. Acquire pairs with install.
        Some(unsafe { core::mem::transmute::<usize, SyncSignalHook>(raw) })
    }
}

/// Default sync-signal hook: map vector → signum, look up the
/// calling task's handler, rewrite the trap frame.
///
/// Returns `false` (no rewrite) when:
///   - the vector has no signal mapping (e.g. #NMI)
///   - the arch's `deliver_signal` rejects the rewrite
///
/// Returns `true` when:
///   - a sigaction handler was installed and the frame was rewritten
///     to deliver it, OR
///   - no handler was installed and the POSIX default action for the
///     signal was Terminate / CoreDump — in which case the task is
///     retired through the same exit hook `sys_exit_task` uses, with
///     wstatus pre-staged so wait4 sees `WIFSIGNALED + WTERMSIG`.
///     The trap dispatcher must NOT fall through to its panic path.
///
/// SA_RESTART is intentionally a no-op on this path: a CPU
/// exception is not a syscall trap (`restartable_syscall =
/// false`), so the arch never rewinds RIP. SA_ONSTACK and
/// SA_SIGINFO are honoured the same way as the async path.
///
/// For SA_SIGINFO synchronous signals, the arch stamps an
/// architecture-specific `si_code` and the faulting address into
/// the user-visible `siginfo_t`. Mapping per
/// `arch/x86/include/uapi/asm/siginfo.h`:
///   #PF (vector 14) → SIGSEGV, si_code = SEGV_ACCERR (2) /
///                                 SEGV_MAPERR (1) depending on
///                                 PF error-code bit 0 (present).
///                                 si_addr = CR2.
///   #GP (13)        → SIGSEGV, si_code = SI_KERNEL (0x80),
///                                 si_addr = 0.
///   #UD (6)         → SIGILL,  si_code = ILL_ILLOPC (1),
///                                 si_addr = trapping RIP.
///   #AC (17)        → SIGBUS,  si_code = BUS_ADRALN (1),
///                                 si_addr = trapping RIP.
///   #DE/#OF         → SIGFPE,  si_code = FPE_INTDIV (1) for #DE,
///                                            FPE_INTOVF (2) for #OF,
///                                 si_addr = trapping RIP.
///   #BP (3)         → SIGTRAP, si_code = TRAP_BRKPT (1),
///                                 si_addr = trapping RIP.
pub fn default_sync_signal_delivery(
    ctx: &mut dyn TrapContext,
    vector: u64,
    info: SyncFaultInfo,
) -> bool {
    let signum = match vector_to_signum(vector) {
        Some(s) => s,
        None => return false,
    };
    if crate::ptrace::ptrace_intercept_signal(ctx, signum) {
        return true;
    }
    let task = current_task_id();
    let action = match sigaction_lookup_full(task, signum as usize) {
        Some(a) => a,
        None => {
            // No user handler → POSIX default action. CPU exceptions
            // map to Terminate or CoreDump only; Ignore/Stop/Continue
            // never appear in this table. Anything that's neither is
            // a kernel bug — fall through to the panic surface.
            // Diagnostic: a fatal CPU fault with no user handler. Log the
            // cause vector + faulting VA alongside the terminate line so a
            // crash can be symbolized against the process's mmap layout —
            // RIP alone is ambiguous across the many shared libraries a
            // desktop app maps (kwin, Qt, Mesa, glibc/musl, ...).
            {
                use core::fmt::Write;
                let pid = task_to_pid_raw(task).unwrap_or(task);
                let comm = proc_comm_of(pid).unwrap_or_else(|| alloc::string::String::from("?"));
                let exe = proc_exe_path(pid).unwrap_or_else(|| alloc::string::String::from("?"));
                let cause = match vector {
                    6 => "#UD",
                    13 => "#GP",
                    14 => "#PF",
                    17 => "#AC",
                    0 => "#DE",
                    _ => "fault",
                };
                let _ = writeln!(
                    narf_console::Writer,
                    "fatal-fault: task={} pid={} comm={} sig={} {} vec={} faultva={:x} rip={:x}",
                    task,
                    pid,
                    comm,
                    signum,
                    cause,
                    vector,
                    info.addr,
                    ctx.rip()
                );
                let _ = writeln!(narf_console::Writer, "  exe={}", exe);
                // Dump the GP register file — a faulting instruction's
                // operands (e.g. a corrupted heap/meta pointer in r13/r15)
                // pin whether the fault is a slightly-off pointer (adjacent
                // overwrite / stale TLB) or a wild value (deeper corruption).
                ctx.dump_gprs();
                // Dump plausible return addresses off the faulting stack so
                // the CALLER can be symbolized (a leaf like strlen faults with
                // [rsp] == its caller's return address). Print only words that
                // land in an executable window — the ld-musl interp bias
                // (0x4000_0000_0000) or the mmap DSO arena (0x4080_.. up).
                let rsp = ctx.user_rsp();
                let _ = writeln!(narf_console::Writer, "  user-rsp={:x}", rsp);
                {
                    if let Some(info) =
                        proc_task_info(pid, narf_filesystem::procfs::TaskInfoQuery::Vmas)
                    {
                        for vma in info.vmas.iter().filter(|vma| vma.executable) {
                            let _ = writeln!(
                                narf_console::Writer,
                                "  exec-vma={:016x}-{:016x} {}",
                                vma.start,
                                vma.end,
                                vma.label
                            );
                        }
                    }
                }
                // The region CONTAINING the faulting address, with its perms
                // — the decisive datum for a #PF. A write (error-code W=1) to a
                // PRESENT page (P=1) whose region shows w=true means WRITE was
                // granted but the leaf PTE was mapped read-only: a page-table
                // permission-derivation bug (the mmap-scalability materializer
                // regressed). A w=false region is a genuine PROT_READ mapping
                // the task wrongly wrote to. This single line disambiguates.
                {
                    if let Some(pinfo) =
                        proc_task_info(pid, narf_filesystem::procfs::TaskInfoQuery::Vmas)
                    {
                        match pinfo
                            .vmas
                            .iter()
                            .find(|v| info.addr >= v.start && info.addr < v.end)
                        {
                            Some(vma) => {
                                let _ = writeln!(
                                    narf_console::Writer,
                                    "  fault-vma={:016x}-{:016x} r={} w={} x={} shared={} {}",
                                    vma.start,
                                    vma.end,
                                    vma.readable,
                                    vma.writable,
                                    vma.executable,
                                    vma.shared,
                                    vma.label
                                );
                            }
                            None => {
                                let _ = writeln!(
                                    narf_console::Writer,
                                    "  fault-vma=<no region contains {:x}>",
                                    info.addr
                                );
                            }
                        }
                    }
                }
                for i in 0..96u64 {
                    let mut w = [0u8; 8];
                    // SAFETY: copy_from_user range-validates the source VA and
                    // SMAP-brackets the read; a bad slot just errors out.
                    if unsafe { copy_from_user(&mut w, rsp.wrapping_add(i * 8)) }.is_err() {
                        break;
                    }
                    let v = u64::from_le_bytes(w);
                    // Fatal-path-only raw dump: selector-shaped corruption
                    // often lands outside executable windows, and filtering
                    // those words discards the evidence needed to localize it.
                    let _ = writeln!(narf_console::Writer, "  stk[{}]={:016x}", i, v);
                }
            }
            match default_signal_action(signum) {
                DefaultAction::Terminate => {
                    terminate_current_task(ctx, task, signum, false);
                    // Caller treats `true` as "we handled it, don't panic."
                    return true;
                }
                DefaultAction::CoreDump => {
                    terminate_current_task(ctx, task, signum, true);
                    return true;
                }
                _ => return false,
            }
        }
    };
    // Wave-58: arch trap forwards the faulting address (CR2 / FAR_EL1)
    // via `info.addr`. For #PF that becomes si_addr verbatim. For
    // RIP-flavoured vectors (#UD/#DE/#OF/#BP/#AC) the arch passes
    // RIP through the same field.
    let (si_code, si_addr) = match vector {
        1 => (2 /* TRAP_TRACE */, info.addr),
        14 => (2 /* SEGV_ACCERR */, info.addr),
        13 => (0x80 /* SI_KERNEL */, info.addr),
        6 => (1 /* ILL_ILLOPC */, info.addr),
        17 => (1 /* BUS_ADRALN */, info.addr),
        0 => (1 /* FPE_INTDIV */, info.addr),
        4 => (2 /* FPE_INTOVF */, info.addr),
        3 => (1 /* TRAP_BRKPT */, info.addr),
        // SI_KERNEL (0x80), not 0: a fault must keep a POSITIVE si_code so the
        // arch siginfo builder writes `si_addr` at the union offset 16 (a
        // non-positive code there means "user/queue-origin" → si_pid instead).
        _ => (0x80, info.addr),
    };
    // Synchronous: not a syscall trap, so restartable_syscall =
    // false (passed via SYSCALL_NUM_NONE to is_restartable_syscall).
    // Synchronous faults carry si_addr, not a sigqueue sigval.
    let params = build_delivery_params(
        task,
        action,
        signum,
        SYSCALL_NUM_NONE,
        si_code,
        si_addr,
        0,
        0,
    );
    let delivered = ctx.deliver_signal(&params);
    if delivered {
        set_sigreturn_use_rsp(task, params.restorer != 0);
        // Record the frame layout we just built so sys_sigreturn restores from the
        // right offsets — must match deliver_signal's `want_siginfo || force_rt`
        // (SA_SIGINFO=0x4, see syscall.rs). Never re-derive the layout from user memory.
        set_sigreturn_is_rt(task, (params.flags & 0x4) != 0 || params.restorer != 0);
        return true;
    }
    // The handler's signal frame couldn't be placed — `deliver_signal` only
    // fails here when the target user stack is unwritable, i.e. it overflowed
    // during delivery (classically a SIGSEGV handler that itself faults,
    // walking the stack down one rt_sigframe at a time). Linux's response is
    // `force_sigsegv`: reset the disposition to default and apply it. Returning
    // `false` would instead fall through to the kernel panic surface — taking
    // the whole system down for one runaway user task. Terminate the task so
    // the kernel survives.
    terminate_current_task(ctx, task, signum, false);
    true
}

// ── Sigaction — record a per-task handler vaddr ────────────────────
//
// Stage-4 round 2: the recorded handler is fired on the trap
// return path of any subsequent int-0x80 from the same task that
// observes a pending signal not blocked by SIGNAL_MASK. See
// `default_signal_delivery` above. Cross-task delivery happens
// when another task calls `Kill` to set a bit in this task's
// pending bitmap.

// Linux _NSIG = 64. The per-task handler array is indexed by signum
// directly (bit-N-=-signal-N, like SIGNAL_PENDING), so slot 0 is the
// never-deliverable null signal and 1..=63 are real signals — RT
// signals (musl SIGRTMIN=35..) included.
// _NSIG = 64 real signals; the handler array is indexed by signum
// directly (slot 0 = the never-delivered null signal), so it needs
// 65 slots to address signal 64.
const NSIG: usize = 65;

/// Linux `sa_flags` bits NARF honours.
pub const SA_NODEFER: u32 = 0x40_00_00_00;
pub const SA_RESTART: u32 = 0x10_00_00_00;
pub const SA_SIGINFO: u32 = 0x00_00_00_04;
pub const SA_ONSTACK: u32 = 0x08_00_00_00;
pub const SA_RESETHAND: u32 = 0x80_00_00_00;

/// Per-task per-signal action: (handler_vaddr, sa_flags). Stored
/// as a single struct so a single atomic write covers both fields.
#[derive(Copy, Clone, Debug, Default)]
pub struct SigAction {
    /// User vaddr of the handler. `None` slot ⇒ no handler installed.
    pub handler: u64,
    /// User vaddr of the restorer trampoline (for Linux ABI).
    pub restorer: u64,
    /// Linux `sa_flags` (SA_*).
    pub flags: u32,
}

/// A thread group's shared signal-handler table — Linux
/// `sighand_struct`. Held by `Arc` so CLONE_SIGHAND/CLONE_THREAD
/// children observe the LIVE table (a handler installed by any thread
/// is instantly visible to all siblings), while plain fork deep-copies.
pub type SigHand = alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<[Option<SigAction>; NSIG]>>;

fn new_sighand() -> SigHand {
    alloc::sync::Arc::new(narf_lib::sync::IrqSafeSpinLock::new([None; NSIG]))
}

static SIGACTION_TABLE: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, SigHand>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Get (or create) `task`'s sighand reference. The `Arc` clone lets
/// callers operate on the table after the registry lock is released;
/// lock ordering is always SIGACTION_TABLE → inner sighand.
fn sighand_of(task: u64) -> Option<SigHand> {
    let mut g = SIGACTION_TABLE.lock();
    let map = g.as_mut()?;
    Some(map.entry(task).or_insert_with(new_sighand).clone())
}

/// Initialise the per-task sigaction registry. Boot calls this once
/// before any user task can issue `Syscall::Sigaction`.
pub fn sigaction_init() {
    *SIGACTION_TABLE.lock() = Some(BTreeMap::new());
}

/// fork(2) inheritance: DEEP-copy `parent`'s handler table to `child`
/// (a post-fork sigaction() in one process must not affect the other).
/// POSIX: handlers are inherited; pending signals are not.
pub fn sigaction_fork(parent: u64, child: u64) {
    let snapshot = {
        let g = SIGACTION_TABLE.lock();
        g.as_ref()
            .and_then(|m| m.get(&parent).cloned())
            .map(|h| *h.lock())
    };
    if let Some(v) = snapshot {
        let mut g = SIGACTION_TABLE.lock();
        if let Some(map) = g.as_mut() {
            map.insert(
                child,
                alloc::sync::Arc::new(narf_lib::sync::IrqSafeSpinLock::new(v)),
            );
        }
    }
}

/// CLONE_SIGHAND / CLONE_THREAD inheritance: `child` SHARES `parent`'s
/// live handler table (Linux `sighand_struct` refcount semantics). A
/// handler installed by either is immediately visible to both — what
/// pthreads rely on (musl installs its setxid/cancel handlers once,
/// from one thread, for the whole group).
pub fn sigaction_share(parent: u64, child: u64) {
    let mut g = SIGACTION_TABLE.lock();
    if let Some(map) = g.as_mut() {
        let h = map.entry(parent).or_insert_with(new_sighand).clone();
        map.insert(child, h);
    }
}

/// execve(2) handler reset (POSIX §2.4.3): a successful exec resets every
/// CAUGHT signal (one with a real handler function) to SIG_DFL, because the
/// handler's code address belonged to the OLD image and is meaningless — often
/// unmapped — in the new one. Signals set to SIG_IGN stay ignored; SIG_DFL
/// (a `None` slot) stays default. The signal MASK and pending set are NOT
/// touched (POSIX preserves them across exec).
///
/// Without this, a child that inherited a handler across fork (e.g. busybox
/// `sh`'s SIGCHLD handler) and then exec'd a different binary would, on the
/// next delivery of that signal, jump to the stale handler vaddr — a wild
/// branch into whatever (if anything) is mapped there in the new image.
///
/// Also UNSHARES the table (fresh `Arc`), mirroring Linux's
/// `unshare_sighand` in execve: the post-exec image must not keep a
/// live handler table shared with pre-exec CLONE_SIGHAND siblings.
pub fn sigaction_exec_reset(task: u64) {
    let snapshot = {
        let g = SIGACTION_TABLE.lock();
        g.as_ref()
            .and_then(|m| m.get(&task).cloned())
            .map(|h| *h.lock())
    };
    if let Some(mut v) = snapshot {
        for slot in v.iter_mut() {
            // handler > 1 ⇒ a real caught handler (0 = SIG_DFL, 1 = SIG_IGN).
            if matches!(slot, Some(a) if a.handler > 1) {
                *slot = None;
            }
        }
        let mut g = SIGACTION_TABLE.lock();
        if let Some(map) = g.as_mut() {
            map.insert(
                task,
                alloc::sync::Arc::new(narf_lib::sync::IrqSafeSpinLock::new(v)),
            );
        }
    }
}

/// Reset the registry — test hook.
#[doc(hidden)]
pub fn __test_sigaction_reset() {
    *SIGACTION_TABLE.lock() = Some(BTreeMap::new());
}

/// Test hook: install a handler vaddr for `(task, signum)` directly,
/// through the same shared-sighand path a real `rt_sigaction` uses.
#[doc(hidden)]
pub fn __test_set_sigaction(task: u64, signum: usize, handler: u64) {
    __test_set_sigaction_flags(task, signum, handler, 0);
}

/// Test hook: like `__test_set_sigaction` but with an explicit
/// `sa_flags` (e.g. `SA_RESTART`), so a test can exercise the
/// restart / altstack / siginfo delivery decisions.
#[doc(hidden)]
pub fn __test_set_sigaction_flags(task: u64, signum: usize, handler: u64, flags: u32) {
    if let Some(h) = sighand_of(task) {
        h.lock()[signum] = Some(SigAction {
            handler,
            restorer: 0,
            flags,
        });
    }
}

/// Diagnostic: peek the recorded handler vaddr for `(task, signum)`.
/// Returns `None` if no handler is registered.
pub fn sigaction_lookup(task: u64, signum: usize) -> Option<u64> {
    sigaction_lookup_full(task, signum).map(|a| a.handler)
}

/// Diagnostic: peek the full `SigAction` for `(task, signum)` —
/// handler + flags. Used by the signal delivery path to know
/// whether to honour SA_ONSTACK / SA_SIGINFO / SA_NODEFER.
pub fn sigaction_lookup_full(task: u64, signum: usize) -> Option<SigAction> {
    if signum >= NSIG {
        return None;
    }
    let h = {
        let g = SIGACTION_TABLE.lock();
        g.as_ref()?.get(&task)?.clone()
    };
    let slot = h.lock()[signum];
    slot
}

// ── Sockets — POSIX shims over the SocketOp dispatcher ───────────
//
// Both POSIX-shaped syscalls (sys_socket / sys_bind / ...) and the
// future ZC ring opcodes call into `socket::SocketFile::dispatch_op`.
// Per the design doc: kernel surface stays small, libc translates
// POSIX sockaddr_* unions in/out, the dispatcher owns per-family
// state.

fn current_socket(fd: u32) -> Option<alloc::sync::Arc<crate::socket::SocketFile>> {
    let task = current_task_id();
    fd::with_table(task, |t| t.get(fd).cloned())
        .flatten()
        .and_then(|entry| {
            // Downcast Arc<dyn FileOps> → Arc<SocketFile>. Manual
            // because Arc downcast for trait objects isn't in core;
            // we identify a SocketFile by raw-pointer comparison
            // through a marker — but simpler: try downcast via
            // unsafe transmute is risky. Use a manual pattern: keep
            // a side table mapping fd → Arc<SocketFile>.
            let raw = alloc::sync::Arc::as_ptr(&entry.ops) as *const ();
            socket_arc_lookup(raw)
        })
}

/// Resolve a socket descriptor without collapsing Linux's two descriptor
/// errors.  `current_socket()` predates exact errno reporting and returns
/// `None` for both an absent slot and a live non-socket file; send-family
/// syscalls must distinguish those as `EBADF` and `ENOTSOCK` respectively.
fn current_socket_result(fd: u32) -> Result<alloc::sync::Arc<crate::socket::SocketFile>, i64> {
    let task = current_task_id();
    let entry = fd::with_table(task, |table| table.get(fd).cloned())
        .flatten()
        .ok_or(9i64)?; // EBADF
    let raw = alloc::sync::Arc::as_ptr(&entry.ops) as *const ();
    socket_arc_lookup(raw).ok_or(88) // ENOTSOCK
}

/// Install the kernel-held admin authority returned by a successful stack
/// attach onto one of the calling task's route-netlink sockets.
///
/// This is deliberately an internal launcher/attach bridge, not a Linux
/// syscall: no raw capability representation crosses userspace, and fd lookup
/// is confined to the current task's table.
pub fn delegate_stack_admin_to_route_socket(
    fd: u32,
    reply: &narf_net::StackAttachReply,
) -> Result<(), crate::socket::SockError> {
    let task = current_task_id();
    let entry = fd::with_table(task, |table| table.get(fd).cloned())
        .flatten()
        .ok_or(crate::socket::SockError::BadFd)?;
    let socket = entry
        .ops
        .as_any()
        .and_then(|ops| ops.downcast_ref::<crate::socket::SocketFile>())
        .ok_or(crate::socket::SockError::BadFd)?;
    socket.delegate_netlink_admin(reply.admin.clone())
}

/// Transfer kernel-held namespace firewall authority to one of the calling
/// task's NETLINK_NETFILTER sockets. Raw capability slots never cross the
/// userspace ABI.
pub fn delegate_netfilter_admin_to_socket(
    fd: u32,
    admin: narf_net::netfilter::NetfilterAdminHandle,
) -> Result<(), crate::socket::SockError> {
    let task = current_task_id();
    let entry = fd::with_table(task, |table| table.get(fd).cloned())
        .flatten()
        .ok_or(crate::socket::SockError::BadFd)?;
    let socket = entry
        .ops
        .as_any()
        .and_then(|ops| ops.downcast_ref::<crate::socket::SocketFile>())
        .ok_or(crate::socket::SockError::BadFd)?;
    socket.delegate_netfilter_admin(admin)
}

// Side table to enable Arc<dyn FileOps> -> Arc<SocketFile> recovery.
// `fd::FdEntry` stores Arc<dyn FileOps>; `dyn FileOps` is not
// `Any`, so a downcast isn't possible. Stage-1: register the
// concrete Arc when the socket is created; look it up by the same
// raw pointer the FdEntry holds.
// fd → SocketFile resolver. Holds a `Weak`, NOT a strong `Arc`: the SocketFile
// is kept alive by its fd-table entries (and, for a listener, the LISTENERS
// map), so the resolver entry must follow that liveness rather than pin it.
// A strong ref here made `sys_close` remove the entry to avoid a leak — which
// broke socketpair-across-fork (weston's helper launch): the parent's close
// deleted the entry while the child still held an fd to the same SocketFile.
// With a Weak, a surviving fd keeps the entry resolvable and the entry
// self-invalidates only when the final fd drops (pruned lazily on lookup).
// ── Pointer-keyed Arc side-tables (socket / epoll / timerfd / signalfd /
// memfd), sharded ──────────────────────────────────────────────────
//
// Each recovers a concrete `Arc<T>` from a `dyn FileOps` pointer. They sit on
// hot syscall paths (`SOCKET_ARCS` on every socket send/recv; `EPOLL_ARCS` on
// every epoll_wait/ctl), so a single global lock bounced one cache line between
// every CPU. Shard 64-way by the pointer key (same transform as the signal /
// futex tables) so unrelated fds no longer contend.
const ARC_SHARDS: usize = 64;

#[repr(align(64))]
struct ArcShard<T> {
    map: narf_lib::sync::IrqSafeSpinLock<
        Option<alloc::collections::BTreeMap<usize, alloc::sync::Weak<T>>>,
    >,
}

impl<T> ArcShard<T> {
    const fn new() -> Self {
        Self {
            map: narf_lib::sync::IrqSafeSpinLock::new(None),
        }
    }
}

type ArcShardTable<T> = [ArcShard<T>; ARC_SHARDS];

#[inline]
fn arc_shard_idx(key: usize) -> usize {
    // Heap allocations are aligned, so the low bits carry no entropy — shift
    // them out before masking to spread keys across shards.
    (key >> 4) & (ARC_SHARDS - 1)
}

fn arc_shard_register<T>(table: &ArcShardTable<T>, arc: &alloc::sync::Arc<T>) {
    let key = alloc::sync::Arc::as_ptr(arc) as usize;
    let mut g = table[arc_shard_idx(key)].map.lock();
    g.get_or_insert_with(alloc::collections::BTreeMap::new)
        .insert(key, alloc::sync::Arc::downgrade(arc));
}

/// Resolve a pointer key back to its live `Arc<T>`, pruning a dead `Weak`
/// entry (the last fd dropped, the allocation may be freed/reused) so the map
/// can't grow unbounded and a reused address can't resolve to a stale object.
fn arc_shard_get<T>(table: &ArcShardTable<T>, key: usize) -> Option<alloc::sync::Arc<T>> {
    let mut g = table[arc_shard_idx(key)].map.lock();
    let map = g.as_mut()?;
    match map.get(&key)?.upgrade() {
        Some(arc) => Some(arc),
        None => {
            map.remove(&key);
            None
        }
    }
}

static SOCKET_ARCS: ArcShardTable<crate::socket::SocketFile> =
    [const { ArcShard::new() }; ARC_SHARDS];

fn socket_arc_register(arc: &alloc::sync::Arc<crate::socket::SocketFile>) {
    arc_shard_register(&SOCKET_ARCS, arc);
}

fn socket_arc_lookup(raw: *const ()) -> Option<alloc::sync::Arc<crate::socket::SocketFile>> {
    arc_shard_get(&SOCKET_ARCS, raw as usize)
}

/// Import a MANDATORY user sockaddr for bind/connect, distinguishing Linux's
/// two `move_addr_to_kernel` errors: an `addrlen` outside
/// `[0, sizeof(sockaddr_storage)]` (or too short to hold `sa_family_t`) is
/// -EINVAL, and a faulting copy is -EFAULT.
fn copy_user_addr_result(ptr: u64, raw_len: u64) -> Result<crate::socket::SockAddr, i64> {
    let len = raw_len as i32;
    // move_addr_to_kernel: ulen < 0 || ulen > sizeof(sockaddr_storage) → EINVAL.
    if !(0..=128).contains(&len) || len < 2 {
        return Err(22); // -EINVAL (no room for a complete sa_family_t)
    }
    let mut buf = alloc::vec![0u8; len as usize];
    // SAFETY: copy_from_user range-validates the whole address (catching a NULL
    // or faulting ptr) and SMAP-brackets the read.
    unsafe { copy_from_user(&mut buf, ptr) }.map_err(|_| 14i64)?; // -EFAULT
    Ok(crate::socket::SockAddr {
        family: u16::from_le_bytes([buf[0], buf[1]]),
        body: buf[2..].to_vec(),
    })
}

/// Return the listener's shared open-file-description `O_NONBLOCK` state.
///
/// `SocketFile` is shared across dup, exec remapping, and SCM_RIGHTS while an
/// `FdEntry` is only a descriptor-slot snapshot. Prefer the shared state so a
/// transferred systemd activation socket cannot accidentally become blocking;
/// retain the slot bit as a compatibility fallback for older construction
/// paths that populated only `FdEntry::status_flags`.
fn socket_listener_nonblock(task: u64, fd: u32, socket: &crate::socket::SocketFile) -> bool {
    socket.is_nonblock()
        || fd::with_table(task, |table| {
            table
                .status_flags(fd)
                .is_some_and(|flags| flags & crate::fd::O_NONBLOCK != 0)
        })
        .unwrap_or(false)
}

pub(crate) fn __test_socket_listener_nonblock(fd: u32) -> bool {
    let task = current_task_id();
    current_socket(fd).is_some_and(|socket| socket_listener_nonblock(task, fd, socket.as_ref()))
}

fn accept_common(ctx: &mut dyn TrapContext, flags: u32) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let _addr_out = args.arg1;
    let _addr_len_out = args.arg2;
    // Linux accept4 error ORDER (net/socket.c): __sys_accept4 does
    // `fd_empty → -EBADF` FIRST, then __sys_accept4_file checks
    // `flags & ~(SOCK_CLOEXEC|SOCK_NONBLOCK) → -EINVAL` BEFORE
    // `sock_from_file → -ENOTSOCK`. So: EBADF, then EINVAL, then ENOTSOCK. A
    // full descriptor table on the new fd → -EMFILE; the accept op → -EAGAIN/…
    // (plain accept passes flags=0, so the flag check is a no-op there.)
    let flags_bad = flags & !(crate::fd::O_CLOEXEC | crate::fd::O_NONBLOCK) != 0;
    let sock = match current_socket_result(fd) {
        Ok(s) => {
            if flags_bad {
                ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL (flags)
                return;
            }
            s
        }
        // EBADF (absent fd) is reported regardless of the flags.
        Err(9) => {
            ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
            return;
        }
        // A present non-socket fd: the flag check precedes -ENOTSOCK in Linux.
        Err(88) => {
            if flags_bad {
                ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL (flags)
            } else {
                ctx.set_return(SyscallReturn::ok((-88i64) as u64)); // -ENOTSOCK
            }
            return;
        }
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
        }
    };
    // Single-shot: pop pending if any, else WouldBlock-style yield
    // mirroring sys_futex. Caller (libc accept) loops.
    match sock.dispatch_op(crate::socket::SocketOp::Accept) {
        crate::socket::SocketOpResult::Accepted { socket, .. } => {
            // accept4 flag bits: SOCK_NONBLOCK marks the new endpoint
            // non-blocking; SOCK_CLOEXEC sets FD_CLOEXEC on the slot.
            let nonblock = flags & crate::fd::O_NONBLOCK != 0;
            if nonblock {
                socket.set_nonblock(true);
            }
            let fd_flags = if flags & crate::fd::O_CLOEXEC != 0 {
                crate::fd::FD_CLOEXEC
            } else {
                0
            };
            let status_flags = crate::fd::O_RDWR
                | if nonblock {
                    crate::fd::O_NONBLOCK
                } else {
                    0
                };
            socket_arc_register(&socket);
            let task = current_task_id();
            // Pairs with UNIXENQ (socket.rs Connect): stamps when the
            // listener's owner finally accept()ed, so connect→accept
            // latency is measurable from the serial log.
            #[cfg(any(feature = "syscall-trace", feature = "unix-latency-trace"))]
            {
                use core::fmt::Write as _;
                let comm = proc_comm_of_task(task).unwrap_or_default();
                if crate::syscall::unix_latency_line_wanted(&comm) {
                    let _ = writeln!(
                        narf_console::Writer,
                        "UNIXACC ms={} by={} lfd={}",
                        narf_scheduler::narf_time::monotonic_ns() / 1_000_000,
                        comm,
                        fd,
                    );
                }
            }
            let new_fd = match fd::install(task, crate::fd::FdEntry {
                    ops: socket,
                    offset: 0,
                    flags: fd_flags,
                    status_flags,
                }) {
                Some(n) => n,
                None => {
                    // `net/socket.c::__sys_accept4_file`:
                    // `newfd = get_unused_fd_flags(flags);
                    //  if (unlikely(newfd < 0)) return newfd;`
                    // -EMFILE, and it matters more here than almost anywhere:
                    // an accept loop at its descriptor limit must shed the
                    // connection and keep serving, which is what EMFILE tells
                    // it to do. EPERM reads as a permission fault and takes
                    // the server down instead.
                    ctx.set_return(SyscallReturn::ok((-24i64) as u64)); // -EMFILE
                    return;
                }
            };
            ctx.set_return(SyscallReturn::ok(new_fd as u64));
        }
        crate::socket::SocketOpResult::Err(crate::socket::SockError::WouldBlock) => {
            // No pending connection. A NON-blocking listen fd gets
            // -EAGAIN immediately; a BLOCKING one must truly block until
            // a peer connects — musl's `accept()` does NOT retry -EAGAIN
            // on a blocking fd, so returning it here would make every
            // real server fail its first accept (only a loopback client
            // that races in before the syscall wins). Block the same way
            // blocking console/pipe reads do: park ~1 ms and REWIND RIP
            // so the `syscall` instruction re-executes on resume (no
            // return value set), looping in-kernel until `Accepted`.
            let task = current_task_id();
            let listen_nonblock = socket_listener_nonblock(task, fd, sock.as_ref());
            if listen_nonblock {
                ctx.set_return(SyscallReturn::ok((-11i64) as u64)); // -EAGAIN
                return;
            }
            if let (Some(uctx), Some(hook)) = (
                crate::user_task::current_user_task(),
                crate::user_task::yield_hook(),
            ) {
                // Rewind past the 2-byte `syscall` instruction so the
                // resumed task re-issues accept; do NOT set a return value.
                let resume_rip = ctx.rip().wrapping_sub(2);
                ctx.set_rip(resume_rip);
                let deadline = narf_scheduler::narf_time::monotonic_ns().saturating_add(1_000_000);
                // SAFETY: `uctx` is the live per-task UserTaskCtx from current_user_task();
                // we hold the only reference while setting the deadline and saving the
                // RIP-rewound CPU state into `uc.state` before the yield hook hands the
                // task to the executor.
                // SAFETY: Valid memory or trusted environment
                unsafe {
                    let uc = &*uctx;
                    uc.sleep_deadline_ns.store(deadline, Ordering::Release);
                    // Park on NET-I/O READINESS (the TCP stack `readiness::notify`s
                    // the listener when a connection becomes accept-ready, and a
                    // socket when data arrives) with the ~1ms deadline as a mere
                    // backstop. Without net_io_wait the park only re-polled every
                    // ~1ms off the timer wheel — and under own-stack cooperative
                    // scheduling with other busy tasks (redis bg threads) that
                    // wheel service is delayed enough that the connection/data
                    // sits ACK'd-but-unread past the client's deadline (net-smoke
                    // echo flake). Snapshot the readiness generation for the
                    // check→park lost-wake guard (park_should_block re-executes if
                    // it moved). Clear a stale `futex_uaddr` so this can't be
                    // mis-routed into the futex branch.
                    uc.futex_uaddr.store(0, Ordering::Release);
                    uc.net_io_wait.store(true, Ordering::Release);
                    uc.epoll_park_gen
                        .store(narf_net::readiness::generation(), Ordering::Release);
                    ctx.save_user_state(uc.state.get() as *mut u8);
                    *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
                    if narf_scheduler::stackful::user_own_stack_enabled() {
                        own_stack_block(ctx);
                        return;
                    }
                    hook(uctx);
                }
                // unreachable — hook() longjmps to the executor
            }
            // No executor (kernel-test context): surface EAGAIN.
            ctx.set_return(SyscallReturn::ok((-11i64) as u64));
        }
        crate::socket::SocketOpResult::Err(e) => {
            ctx.set_return(SyscallReturn::ok((-(e.errno() as i64)) as u64));
        }
        _ => ctx.set_return(SyscallReturn::ok((-22i64) as u64)), // -EINVAL (unreachable)
    }
}

/// Parse a `msg_control` buffer for an `SOL_SOCKET` / `SCM_RIGHTS` cmsg and
/// resolve each passed int fd to its file object in the *sender's* fd table.
/// Returns an empty vec when there's no fd ancillary data.
fn parse_scm_rights_fds(
    ctrl_ptr: u64,
    ctrl_len: usize,
) -> Result<alloc::vec::Vec<crate::socket::ScmRightsFile>, i64> {
    const SOL_SOCKET: i32 = 1;
    const SCM_RIGHTS: i32 = 1;
    // struct cmsghdr { u64 cmsg_len; i32 cmsg_level; i32 cmsg_type; } = 16 B.
    let mut out = alloc::vec::Vec::new();
    if ctrl_len == 0 {
        return Ok(out);
    }
    if ctrl_ptr == 0 {
        return Err(14); // EFAULT
    }
    if !(16..=MAX_USER_COPY).contains(&ctrl_len) {
        return Err(22); // EINVAL
    }
    let mut ctrl = alloc::vec![0u8; ctrl_len];
    // SAFETY: ctrl sized to ctrl_len; copy_from_user range-validates + SMAP.
    if unsafe { copy_from_user(&mut ctrl, ctrl_ptr) }.is_err() {
        return Err(14); // EFAULT
    }
    let task = current_task_id();
    // Walk cmsg records (8-byte aligned).
    let mut off = 0usize;
    while off + 16 <= ctrl_len {
        let cmsg_len = u64::from_le_bytes(ctrl[off..off + 8].try_into().unwrap()) as usize;
        let level = i32::from_le_bytes(ctrl[off + 8..off + 12].try_into().unwrap());
        let ctype = i32::from_le_bytes(ctrl[off + 12..off + 16].try_into().unwrap());
        if cmsg_len < 16 || off + cmsg_len > ctrl_len {
            return Err(22); // EINVAL
        }
        if level == SOL_SOCKET && ctype == SCM_RIGHTS {
            let nfds = (cmsg_len - 16) / 4;
            for i in 0..nfds {
                let fpos = off + 16 + i * 4;
                let fd = i32::from_le_bytes(ctrl[fpos..fpos + 4].try_into().unwrap());
                if fd < 0 {
                    return Err(9); // EBADF
                }
                let Some(passed) = fd::with_table(task, |t| {
                    let (ops, description, status_flags) = t.export_description(fd as u32)?;
                    Some(crate::socket::ScmRightsFile {
                        ops,
                        status_flags,
                        description: Some(description),
                    })
                })
                .flatten() else {
                    return Err(9); // EBADF: send no payload or partial rights
                };
                out.push(passed);
            }
        }
        // Advance to the next cmsg (CMSG_ALIGN to 8 bytes).
        off += (cmsg_len + 7) & !7;
    }
    Ok(out)
}

/// Install kernel-sender credentials and, when requested through
/// `NETLINK_PKTINFO`, the multicast group associated with this datagram.
fn install_netlink_ancillary(msg_ptr: u64, pktinfo_group: Option<u32>) {
    const SOL_SOCKET: i32 = 1;
    const SCM_CREDENTIALS: i32 = 2;
    const SOL_NETLINK: i32 = 270;
    const NETLINK_PKTINFO: i32 = 3;
    let ctrl_ptr = read_user_u64(msg_ptr + 32);
    let ctrl_len = read_user_u64(msg_ptr + 40) as usize;
    let mut ctrl = alloc::vec::Vec::new();
    let push_cmsg = |ctrl: &mut alloc::vec::Vec<u8>, level: i32, kind: i32, payload: &[u8]| {
        let len = 16 + payload.len();
        ctrl.extend_from_slice(&(len as u64).to_le_bytes());
        ctrl.extend_from_slice(&level.to_le_bytes());
        ctrl.extend_from_slice(&kind.to_le_bytes());
        ctrl.extend_from_slice(payload);
        while ctrl.len() % 8 != 0 {
            ctrl.push(0);
        }
    };
    push_cmsg(&mut ctrl, SOL_SOCKET, SCM_CREDENTIALS, &[0u8; 12]);
    if let Some(group) = pktinfo_group {
        push_cmsg(
            &mut ctrl,
            SOL_NETLINK,
            NETLINK_PKTINFO,
            &group.to_ne_bytes(),
        );
    }
    if ctrl_ptr == 0 || ctrl_len < ctrl.len() {
        // SAFETY: 8-byte write to msg_controllen; copy_to_user range-checks + SMAP.
        let _ = unsafe { copy_to_user(msg_ptr + 40, &0u64.to_le_bytes()) };
        return;
    }
    // SAFETY: ctrl_ptr is the user msg_control buffer, len-checked above.
    let _ = unsafe { copy_to_user(ctrl_ptr, &ctrl) };
    // SAFETY: 8-byte write to msg_controllen at msg_ptr+40.
    let _ = unsafe { copy_to_user(msg_ptr + 40, &(ctrl.len() as u64).to_le_bytes()) };
}

/// Install received AF_UNIX ancillary data into the calling task's
/// `msg_control` buffer: an `SCM_RIGHTS` control message (any passed fds,
/// each dup'd into a fresh fd in this task's table) and, when
/// `cred` is `Some` (SO_PASSCRED set), an `SCM_CREDENTIALS` control message
/// naming the message sender. Sets `msg_controllen` to the bytes written
/// (0 when there's no ancillary data or the user control buffer is absent).
fn install_recv_ancillary(
    msg_ptr: u64,
    fds: alloc::vec::Vec<crate::socket::ScmRightsFile>,
    cred: Option<crate::socket::Ucred>,
    cloexec: bool,
) -> bool {
    const SOL_SOCKET: i32 = 1;
    const SCM_RIGHTS: i32 = 1;
    const SCM_CREDENTIALS: i32 = 2;
    let ctrl_ptr = read_user_u64(msg_ptr + 32);
    let ctrl_len = read_user_u64(msg_ptr + 40) as usize;
    if fds.is_empty() && cred.is_none() {
        // No ancillary data — report an empty control buffer.
        // SAFETY: writing 8 bytes to the `msg_controllen` field at `msg_ptr + 40`;
        // `copy_to_user` range-validates the user address and SMAP-brackets the
        // write, so a bad pointer returns Err rather than faulting the kernel.
        let _ = unsafe { copy_to_user(msg_ptr + 40, &0u64.to_le_bytes()) };
        return false;
    }
    // Only install descriptors that fit in the caller's control buffer.
    // Installing an fd whose number cannot be reported leaks an unreachable
    // slot in the receiver. Linux instead closes truncated SCM_RIGHTS entries.
    let control_capacity = if ctrl_ptr == 0 { 0 } else { ctrl_len };
    let mut max_rights = control_capacity.saturating_sub(16) / 4;
    while max_rights > 0 && ((16 + max_rights * 4 + 7) & !7) > control_capacity {
        max_rights -= 1;
    }
    let rights_to_install = core::cmp::min(fds.len(), max_rights);
    let mut truncated = rights_to_install < fds.len();
    let task = current_task_id();
    let mut new_fds: alloc::vec::Vec<i32> = alloc::vec::Vec::new();
    for passed in fds.into_iter().take(rights_to_install) {
        // `scm_detach_fds` stops installing once `get_unused_fd_flags` fails
        // and reports the shortfall as MSG_CTRUNC rather than failing the
        // whole recvmsg — the payload was already delivered. A receiver at
        // its RLIMIT_NOFILE therefore sees a truncated control message, which
        // is the documented signal to close descriptors and retry.
        if let Some(newfd) = fd::with_table_alloc(task, |t| {
            t.open_transferred(
                passed.ops,
                passed.description,
                passed.status_flags,
                if cloexec { crate::fd::FD_CLOEXEC } else { 0 },
            )
        })
        .flatten()
        {
            new_fds.push(newfd as i32);
        } else {
            truncated = true;
        }
    }
    // Build the control buffer: each cmsg is cmsghdr(16) + data, padded to
    // an 8-byte (CMSG_ALIGN) boundary before the next record.
    let mut ctrl: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let push_cmsg = |ctrl: &mut alloc::vec::Vec<u8>, ctype: i32, data: &[u8]| {
        let cmsg_len = 16 + data.len();
        let mut hdr = [0u8; 16];
        hdr[0..8].copy_from_slice(&(cmsg_len as u64).to_le_bytes());
        hdr[8..12].copy_from_slice(&SOL_SOCKET.to_le_bytes());
        hdr[12..16].copy_from_slice(&ctype.to_le_bytes());
        ctrl.extend_from_slice(&hdr);
        ctrl.extend_from_slice(data);
        // CMSG_ALIGN the running length to the next 8-byte boundary.
        while ctrl.len() % 8 != 0 {
            ctrl.push(0);
        }
    };
    if !new_fds.is_empty() {
        let mut data = alloc::vec::Vec::with_capacity(new_fds.len() * 4);
        for &nfd in &new_fds {
            data.extend_from_slice(&nfd.to_le_bytes());
        }
        push_cmsg(&mut ctrl, SCM_RIGHTS, &data);
    }
    if let Some(c) = cred {
        let mut data = [0u8; 12];
        data[0..4].copy_from_slice(&c.pid.to_le_bytes());
        data[4..8].copy_from_slice(&c.uid.to_le_bytes());
        data[8..12].copy_from_slice(&c.gid.to_le_bytes());
        // SCM_RIGHTS precedes SCM_CREDENTIALS. If the latter does not fit,
        // omit it and report MSG_CTRUNC while retaining any rights that did.
        if ctrl.len().saturating_add(32) <= control_capacity {
            push_cmsg(&mut ctrl, SCM_CREDENTIALS, &data);
        } else {
            truncated = true;
        }
    }
    if ctrl_ptr == 0 {
        // SAFETY: 8-byte write to `msg_controllen` at `msg_ptr + 40`.
        let _ = unsafe { copy_to_user(msg_ptr + 40, &0u64.to_le_bytes()) };
        return true;
    }
    // SAFETY: ctrl_ptr is the user msg_control buffer, len-checked above.
    let _ = unsafe { copy_to_user(ctrl_ptr, &ctrl) };
    // SAFETY: 8-byte write to `msg_controllen` at `msg_ptr + 40`.
    let _ = unsafe { copy_to_user(msg_ptr + 40, &(ctrl.len() as u64).to_le_bytes()) };
    truncated
}

#[inline]
fn read_user_u32(ptr: u64) -> u32 {
    let mut b = [0u8; 4];
    // SAFETY: caller guarantees ptr is a valid user address; SMAP bracket
    // guards the access.
    // SAFETY: Valid memory or trusted environment
    let _ = unsafe { copy_from_user(&mut b, ptr) };
    u32::from_ne_bytes(b)
}

#[inline]
fn read_user_u64(ptr: u64) -> u64 {
    let mut b = [0u8; 8];
    // SAFETY: same contract as read_user_u32.
    let _ = unsafe { copy_from_user(&mut b, ptr) };
    u64::from_ne_bytes(b)
}

/// Write a u32 to a user address (helper for getsockopt length field, etc.)
#[inline]
fn write_user_u32(ptr: u64, val: u32) {
    let b = val.to_ne_bytes();
    // SAFETY: caller guarantees ptr is a valid user address; SMAP bracket
    // guards the access.
    // SAFETY: Valid memory or trusted environment
    let _ = unsafe { copy_to_user(ptr, &b) };
}

/// Write a u16 to a user address.
#[inline]
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
fn write_user_u16(ptr: u64, val: u16) {
    let b = val.to_le_bytes();
    // SAFETY: caller guarantees `ptr` is a valid user address; copy_to_user
    // range-validates it and SMAP-brackets the 2-byte write.
    // SAFETY: Valid memory or trusted environment
    let _ = unsafe { copy_to_user(ptr, &b) };
}

// ── flock(2) — advisory file locking ────────────────────────────
//
// Per-file lock state keyed by the FdEntry's Arc<dyn FileOps>
// raw pointer (so dup'd fds share a lock; distinct files get
// distinct locks). Stage-1: shared (LOCK_SH = N readers) /
// exclusive (LOCK_EX = single writer) / unlock (LOCK_UN). Lock
// owner tracking lets a future LOCK_EX acquire detect "this
// task already holds an exclusive lock" and return success.

const LOCK_SH: u32 = 1;
const LOCK_EX: u32 = 2;
const LOCK_NB: u32 = 4;
const LOCK_UN: u32 = 8;

#[derive(Default, Debug)]
struct FlockEntry {
    /// Number of shared (read) holders. > 0 means SH-locked.
    shared_count: u32,
    /// Task id holding an exclusive lock; 0 means no exclusive.
    exclusive_owner: u64,
}

static FLOCK_TABLE: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<usize, FlockEntry>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

fn flock_try(file_ptr: usize, op: u32, task: u64) -> Result<(), ()> {
    let mut g = FLOCK_TABLE.lock();
    let map = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    let e = map.entry(file_ptr).or_default();
    if op & LOCK_UN != 0 {
        if e.exclusive_owner == task {
            e.exclusive_owner = 0;
        } else if e.shared_count > 0 {
            e.shared_count -= 1;
        }
        return Ok(());
    }
    if op & LOCK_EX != 0 {
        // Exclusive: succeed iff no shared, no other exclusive.
        if e.exclusive_owner == task {
            return Ok(());
        }
        if e.shared_count == 0 && e.exclusive_owner == 0 {
            e.exclusive_owner = task;
            return Ok(());
        }
        return Err(());
    }
    if op & LOCK_SH != 0 {
        // Shared: succeed iff no exclusive (or we hold it).
        if e.exclusive_owner == 0 || e.exclusive_owner == task {
            e.shared_count += 1;
            return Ok(());
        }
        return Err(());
    }
    Err(())
}

// ── Terminal attributes (termios) ───────────────────────────────
//
// Per-task kernel-side termios store. tcgetattr/tcsetattr round
// trip through this so consumers (libreadline, password prompts,
// Rust's Stdin::lock) see the values they wrote. The console
// driver consults the same storage to decide whether to deliver
// ^C as SIGINT (ISIG bit), echo input (ECHO bit), buffer until
// newline (ICANON bit).
//
// The c_lflag bits that matter here:
const ICANON: u32 = 0x0002;
const ECHO_FLAG: u32 = 0x0008;
const ISIG: u32 = 0x0001;

/// Wire-stable termios image. 60 bytes — matches glibc's shape on
/// x86_64 (4*tcflag + 1 line-disc + 32 cc + 2 speed).
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct KTermios {
    pub c_iflag: u32,
    pub c_oflag: u32,
    pub c_cflag: u32,
    pub c_lflag: u32,
    pub c_line: u8,
    pub c_cc: [u8; 32],
    pub _pad: [u8; 3],
    pub c_ispeed: u32,
    pub c_ospeed: u32,
}

impl KTermios {
    pub const fn cooked() -> Self {
        Self {
            c_iflag: 0,
            c_oflag: 0,
            c_cflag: 0x0080, // CREAD
            c_lflag: ICANON | ECHO_FLAG | ISIG,
            c_line: 0,
            c_cc: [0; 32],
            _pad: [0; 3],
            c_ispeed: 0,
            c_ospeed: 0,
        }
    }
}

static TASK_TERMIOS: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u64, KTermios>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

pub fn termios_of_task(task: u64) -> KTermios {
    let g = TASK_TERMIOS.lock();
    g.as_ref()
        .and_then(|m| m.get(&task).copied())
        .unwrap_or(KTermios::cooked())
}

pub fn set_termios_of_task(task: u64, t: KTermios) {
    let mut g = TASK_TERMIOS.lock();
    let map = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    map.insert(task, t);
}

/// Most recent task to read from the console. Tracked so the
/// console driver knows which task to deliver SIGINT to when ^C
/// is read. Updated on each console read.
static FOREGROUND_TASK: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

pub fn note_console_reader(task: u64) {
    FOREGROUND_TASK.store(task, Ordering::Release);
}

pub fn foreground_task() -> u64 {
    FOREGROUND_TASK.load(Ordering::Acquire)
}

/// Console line-discipline hook: invoked by `console_tty` when ISIG is
/// set on the console termios and an input byte matches a signal-
/// generating control char. ^C → SIGINT (2), ^\ → SIGQUIT (3),
/// ^Z → SIGTSTP (20). The signal goes to the entire FOREGROUND PROCESS
/// GROUP (proper job control), which is the group of the task currently
/// reading the console. Returns true iff the byte was consumed as a
/// signal (so it is NOT returned through read).
///
/// ISIG gating + c_cc matching already happened in `console_tty`; this
/// only maps the byte to a signal and fans it out to the pgrp. The
/// trap-return signal-delivery hook takes it on each member's next
/// return to user mode.
pub fn maybe_deliver_signal_for_input(byte: u8) -> bool {
    let signum = match byte {
        0x03 => 2,  // SIGINT  (^C)
        0x1C => 3,  // SIGQUIT (^\)
        0x1A => 20, // SIGTSTP (^Z)
        _ => return false,
    };
    let task = foreground_task();
    if task == 0 {
        return false;
    }
    let pgrp = read_pgid(task);
    if deliver_signal_to_pgrp(pgrp, signum) {
        return true;
    }
    // Fallback: no pgrp members resolved — deliver to the reader itself.
    raise_signal_pending(task, signum);
    true
}

// ── I/O multiplexing — poll / epoll / eventfd / timerfd / signalfd ──

const EPOLL_CTL_ADD: u32 = 1;
const EPOLL_CTL_DEL: u32 = 2;
const EPOLL_CTL_MOD: u32 = 3;

// EpollFile recovery from FdEntry — same shape as the SocketFile
// side table since Arc<dyn FileOps> can't be downcast generically.
static EPOLL_ARCS: ArcShardTable<crate::io_mux::EpollFile> =
    [const { ArcShard::new() }; ARC_SHARDS];

fn epoll_arc_register(arc: &alloc::sync::Arc<crate::io_mux::EpollFile>) {
    arc_shard_register(&EPOLL_ARCS, arc);
}

fn epoll_arc_from_fd(task: u64, fd: u32) -> Option<alloc::sync::Arc<crate::io_mux::EpollFile>> {
    let arc_ops = fd::with_table(task, |t| t.get(fd).map(|e| e.ops.clone())).flatten()?;
    let raw = alloc::sync::Arc::as_ptr(&arc_ops) as *const () as usize;
    arc_shard_get(&EPOLL_ARCS, raw)
}

// Wave-61: pidfd_open(pid, flags) → fd that signals POLLIN on exit.
// Linux x86_64 number 434. flags is currently ignored — PIDFD_NONBLOCK
// (0x0800) is the only documented bit and our pidfd reads return
// immediately anyway.

// Wave-64: `timerfd_gettime(fd, &curr_value)` — snapshot the
// currently-armed timer. Writes `itimerspec` (16 B interval +
// 16 B value-remaining; absolute time stripped because the read
// view is the relative gap from `now` to the next fire). Returns
// 0 on success or -1 on a bad fd / NULL out ptr.
//
// Linux ref: `fs/timerfd.c`:SYSCALL_DEFINE2(timerfd_gettime, …)
// (GPL-2.0-or-later, kernel.org).

static TIMERFD_ARCS: ArcShardTable<crate::io_mux::TimerFd> =
    [const { ArcShard::new() }; ARC_SHARDS];

fn timerfd_arc_register(arc: &alloc::sync::Arc<crate::io_mux::TimerFd>) {
    arc_shard_register(&TIMERFD_ARCS, arc);
}

/// Recover the concrete `TimerFd` behind a descriptor, distinguishing Linux's two rejection reasons.
/// `do_timerfd_gettime`/`do_timerfd_settime` (fs/timerfd.c) both open with
///
/// ```text
/// CLASS(fd, f)(ufd);
/// if (fd_empty(f))                             return -EBADF;
/// if (fd_file(f)->f_op != &timerfd_fops)       return -EINVAL;
/// ```
///
/// so "no such descriptor" and "that descriptor is not a timerfd" are
/// different errnos. Collapsing both into one `None` (and then into a bare
/// -1 → EPERM) hid a plain programming error behind a permissions failure.
/// Returns `Err(EBADF)` / `Err(EINVAL)` as positive errno codes.
pub(crate) fn timerfd_arc_from_fd_checked(
    task: u64,
    fd: u32,
) -> Result<alloc::sync::Arc<crate::io_mux::TimerFd>, i64> {
    const EBADF: i64 = 9;
    const EINVAL: i64 = 22;
    let arc_ops = fd::with_table(task, |t| t.get(fd).map(|e| e.ops.clone()))
        .flatten()
        .ok_or(EBADF)?;
    let raw = alloc::sync::Arc::as_ptr(&arc_ops) as *const () as usize;
    arc_shard_get(&TIMERFD_ARCS, raw).ok_or(EINVAL)
}

// ── Wave-70 SignalFdFile side table ────────────────────────────────
// Same shape as the EpollFile / SocketFile / TimerFd Arc maps: a raw-
// pointer-keyed Arc map lets us recover the concrete type from the
// `dyn FileOps` we stored in the fd table.
static SIGNALFD_ARCS: ArcShardTable<crate::linux_compat::SignalFdFile> =
    [const { ArcShard::new() }; ARC_SHARDS];

fn signalfd_arc_register(arc: &alloc::sync::Arc<crate::linux_compat::SignalFdFile>) {
    arc_shard_register(&SIGNALFD_ARCS, arc);
}

pub(crate) fn signalfd_arc_from_fd(
    task: u64,
    fd: u32,
) -> Option<alloc::sync::Arc<crate::linux_compat::SignalFdFile>> {
    let arc_ops = fd::with_table(task, |t| t.get(fd).map(|e| e.ops.clone())).flatten()?;
    let raw = alloc::sync::Arc::as_ptr(&arc_ops) as *const () as usize;
    arc_shard_get(&SIGNALFD_ARCS, raw)
}

// ── Installer ──────────────────────────────────────────────────────

/// Bridge fn boot installs into `narf_abi::install_file_op_bridge`.
/// Routes ring-submitted file ops through the same `SyscallTable`
/// the int-0x80 / svc gate uses. The `cx` cancel context is the
/// per-inflight token the dispatcher hands us — we check it before
/// dispatching the (synchronous) syscall body so a parallel
/// `OpCode::Cancel` lands cleanly.
pub fn abi_file_op_bridge(
    kind: narf_abi::FileOpKind,
    args: &narf_abi::FileOpArgs,
    cx: &narf_abi::CancelCtx<'_>,
) -> narf_abi::FileOpReturn {
    if cx.is_cancel_requested() {
        // Signal Cancelled to the dispatcher (status=2 mirrors
        // NarfStatus::Cancelled). The dispatcher converts to
        // Cancelled / CancelRequested based on CANCELLABLE.
        return narf_abi::FileOpReturn {
            status: 2,
            value: 0,
        };
    }
    // The stable v1 ring operation is base-only and predates Linux-range
    // munmap support. Preserve that ABI here instead of teaching raw syscall
    // 11 to accept `len == 0` (Linux requires EINVAL for that call).
    if kind == narf_abi::FileOpKind::Munmap {
        let status = current_address_space()
            .ok_or(())
            .and_then(|as_ref| handler_sys_munmap::munmap_native_v1(&as_ref, args.a0))
            .map(|()| 0)
            .unwrap_or(1);
        return narf_abi::FileOpReturn { status, value: 0 };
    }
    let num: u32 = match kind {
        narf_abi::FileOpKind::Open => Syscall::OpenFile.raw(),
        narf_abi::FileOpKind::Read => Syscall::Read.raw(),
        narf_abi::FileOpKind::Write => Syscall::Write.raw(),
        narf_abi::FileOpKind::Close => Syscall::Close.raw(),
        narf_abi::FileOpKind::Mmap => Syscall::Mmap.raw(),
        // Returned by the native-v1 compatibility arm above.
        narf_abi::FileOpKind::Munmap => unreachable!(),
    };
    let sargs = crate::SyscallArgs {
        arg0: args.a0,
        arg1: args.a1,
        arg2: args.a2,
        arg3: args.a3,
        arg4: args.a4,
        arg5: args.a5,
    };
    // Plain entry only fires plain handlers; our file ops are
    // raw. Build a synthetic `TrapContext` whose
    // `redirect_to_kernel` returns false (so handlers that would
    // unwind fall back to `set_return`), then route through
    // `kernel_syscall_entry`.
    struct BridgeCtx {
        args: crate::SyscallArgs,
        ret: crate::SyscallReturn,
    }
    impl crate::TrapContext for BridgeCtx {
        fn args(&self) -> &crate::SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: crate::SyscallReturn) {
            self.ret = r;
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
    }
    let mut ctx = BridgeCtx {
        args: sargs,
        ret: crate::SyscallReturn::invalid_op(),
    };
    crate::kernel_syscall_entry(num, &mut ctx);
    narf_abi::FileOpReturn {
        status: ctx.ret.status as u32,
        value: ctx.ret.value,
    }
}

// ── Dispatcher spawn helper ────────────────────────────────────────
//
// After Bootstrap mints the ring pair, the kernel-side ends sit in
// the per-task table waiting for somebody to drive them. The boot
// path (or a test fixture) calls `spawn_dispatcher_for(task_id)` to
// transfer ownership of the kernel ends to a freshly-spawned async
// task running `Dispatcher::run`. Returns the dispatcher's
// scheduler `TaskId`, or `None` if Bootstrap hasn't run for `task_id`
// (or its kernel ends were already taken).

/// Spawn an `abi::Dispatcher` task to drive the ring pair Bootstrap
/// minted for `task_id`. Returns the scheduler TaskId of the new
/// dispatcher task, or `None` if there's nothing to drive.
pub fn spawn_dispatcher_for(task_id: u64) -> Option<narf_scheduler::TaskId> {
    let ends = take_kernel_ends(task_id)?;
    Some(narf_scheduler::spawn(async move {
        let mut d = narf_abi::Dispatcher::new(ends.sq_drain, ends.cq_prod);
        d.run().await;
    }))
}

// ── Loadable kernel modules ─────────────────────────────────────────
//
// `init_module(2)` and `finit_module(2)` take an in-memory image of
// a relocatable ELF and link it into the running kernel via the
// `narf-modules` crate. `delete_module(2)` removes a loaded module
// by name. All three accept user pointers; we copy the image into
// kernel space before parsing so the user can't race the parser.

/// Map a module-loader outcome to a Linux return value. A foreign
/// image (a real Linux `.ko`, or anything lacking NARF's module
/// contract) becomes a success no-op: NARF is monolithic, so the
/// drivers `modprobe`/`systemd-modules-load` ask for are already
/// built in or genuinely absent — Linux answers builtin loads with
/// `EEXIST`, which modprobe treats as success. Returning 0 lets those
/// oneshot units complete instead of failing (and blocking dependents
/// past the systemd job timeout). Genuine NARF-module failures and
/// argument errors keep their real errno.
fn init_module_result(
    r: Result<alloc::sync::Arc<narf_modules::Module>, narf_modules::syscalls::ModuleSyscallError>,
) -> u64 {
    match r {
        Ok(_) => 0,
        Err(e) if e.is_foreign_image() => 0,
        Err(e) => (e.to_errno() as i64) as u64,
    }
}

/// Drop the core set of handlers into `table`. Idempotent — later
/// subsystems can install richer handlers over the same slots
/// (e.g. a real file-descriptor-backed `Read`).
pub fn install_core_syscalls(table: &mut SyscallTable) {
    table.install_raw(Syscall::Bootstrap, "bootstrap", RawFnHandler(sys_bootstrap));
    table.install_raw(Syscall::OpenFile, "open", RawFnHandler(sys_open));
    table.install_raw(Syscall::Write, "write", RawFnHandler(sys_write));
    table.install_raw(Syscall::Writev, "writev", RawFnHandler(sys_writev));
    table.install_raw(Syscall::Read, "read", RawFnHandler(sys_read));
    table.install_raw(Syscall::Close, "close", RawFnHandler(sys_close));
    table.install_raw(Syscall::Stat, "stat", RawFnHandler(sys_stat));
    table.install_raw(Syscall::Fstat, "fstat", RawFnHandler(sys_fstat));
    table.install_raw(Syscall::Lstat, "lstat", RawFnHandler(sys_stat));
    table.install_raw(
        Syscall::Newfstatat,
        "newfstatat",
        RawFnHandler(sys_newfstatat),
    );
    table.install_raw(Syscall::Mmap, "mmap", RawFnHandler(sys_mmap));
    table.install_raw(Syscall::Munmap, "munmap", RawFnHandler(sys_munmap));
    table.install_raw(Syscall::Mremap, "mremap", RawFnHandler(sys_mremap));
    table.install_raw(Syscall::Sendfile, "sendfile", RawFnHandler(sys_sendfile));
    table.install_raw(Syscall::MProtect, "mprotect", RawFnHandler(sys_mprotect));
    table.install_raw(Syscall::MLock, "mlock", RawFnHandler(sys_mlock));
    table.install_raw(Syscall::MUnlock, "munlock", RawFnHandler(sys_munlock));
    table.install_raw(Syscall::Madvise, "madvise", RawFnHandler(sys_madvise));
    // Batch 18: AS-wide locking, secret memory, NUMA placement.
    table.install_raw(Syscall::Mlockall, "mlockall", RawFnHandler(sys_mlockall));
    table.install_raw(
        Syscall::Munlockall,
        "munlockall",
        RawFnHandler(sys_munlockall),
    );
    table.install_raw(
        Syscall::MemfdSecret,
        "memfd_secret",
        RawFnHandler(sys_memfd_secret),
    );
    table.install_raw(
        Syscall::ProcessMadvise,
        "process_madvise",
        RawFnHandler(sys_process_madvise),
    );
    table.install_raw(
        Syscall::MovePages,
        "move_pages",
        RawFnHandler(sys_move_pages),
    );
    table.install_raw(
        Syscall::SetMempolicyHomeNode,
        "set_mempolicy_home_node",
        RawFnHandler(sys_set_mempolicy_home_node),
    );
    table.install_raw(
        Syscall::MigratePages,
        "migrate_pages",
        RawFnHandler(sys_migrate_pages),
    );
    table.install_raw(Syscall::Execve, "execve", RawFnHandler(sys_execve));
    // Batch 19: process & scheduling.
    table.install_raw(Syscall::Vfork, "vfork", RawFnHandler(sys_fork));
    table.install_raw(Syscall::Execveat, "execveat", RawFnHandler(sys_execveat));
    table.install_raw(Syscall::Rseq, "rseq", RawFnHandler(sys_rseq));
    table.install_raw(
        Syscall::Faccessat2,
        "faccessat2",
        RawFnHandler(sys_faccessat),
    );
    table.install_raw(
        Syscall::Fchmodat2,
        "fchmodat2",
        RawFnHandler(sys_at2_reshape),
    );
    table.install_raw(
        Syscall::FutexWaitv,
        "futex_waitv",
        RawFnHandler(sys_futex_waitv),
    );
    table.install_raw(
        Syscall::FutexWake,
        "futex_wake",
        RawFnHandler(sys_futex_wake),
    );
    table.install_raw(
        Syscall::FutexWait,
        "futex_wait",
        RawFnHandler(sys_futex_wait),
    );
    table.install_raw(
        Syscall::FutexRequeue,
        "futex_requeue",
        RawFnHandler(sys_futex_requeue),
    );
    table.install_raw(Syscall::Wait4, "wait4", RawFnHandler(sys_wait4));
    table.install_raw(Syscall::Waitid, "waitid", RawFnHandler(sys_waitid));
    table.install_raw(Syscall::Mount, "mount", RawFnHandler(sys_mount));
    table.install_raw(Syscall::Umount2, "umount2", RawFnHandler(sys_umount2));
    table.install_raw(Syscall::Quotactl, "quotactl", RawFnHandler(sys_quotactl));
    table.install_raw(Syscall::Statfs, "statfs", RawFnHandler(sys_statfs));
    table.install_raw(Syscall::Fstatfs, "fstatfs", RawFnHandler(sys_fstatfs));
    table.install_raw(Syscall::Unshare, "unshare", RawFnHandler(sys_unshare));
    table.install_raw(Syscall::Setns, "setns", RawFnHandler(sys_setns));
    table.install_raw(Syscall::Chroot, "chroot", RawFnHandler(sys_chroot));
    table.install_raw(
        Syscall::PivotRoot,
        "pivot_root",
        RawFnHandler(sys_pivot_root),
    );
    table.install_raw(Syscall::Sigreturn, "sigreturn", RawFnHandler(sys_sigreturn));
    table.install_raw(Syscall::SocketOpen, "socket", RawFnHandler(sys_socket));
    table.install_raw(Syscall::SocketBind, "bind", RawFnHandler(sys_socket_bind));
    table.install_raw(
        Syscall::SocketListen,
        "listen",
        RawFnHandler(sys_socket_listen),
    );
    table.install_raw(
        Syscall::SocketAccept,
        "accept",
        RawFnHandler(sys_socket_accept),
    );
    table.install_raw(
        Syscall::SocketAccept4,
        "accept4",
        RawFnHandler(sys_socket_accept4),
    );
    table.install_raw(
        Syscall::SocketPair,
        "socketpair",
        RawFnHandler(sys_socketpair),
    );
    table.install_raw(
        Syscall::SocketConnect,
        "connect",
        RawFnHandler(sys_socket_connect),
    );
    table.install_raw(Syscall::SocketSend, "send", RawFnHandler(sys_socket_send));
    table.install_raw(Syscall::SocketRecv, "recv", RawFnHandler(sys_socket_recv));
    table.install_raw(
        Syscall::SocketShutdown,
        "shutdown",
        RawFnHandler(sys_socket_shutdown),
    );
    table.install_raw(
        Syscall::SocketGetSockOpt,
        "getsockopt",
        RawFnHandler(sys_socket_getsockopt),
    );
    table.install_raw(
        Syscall::SocketSetSockOpt,
        "setsockopt",
        RawFnHandler(sys_socket_setsockopt),
    );
    table.install_raw(
        Syscall::SocketGetSockName,
        "getsockname",
        RawFnHandler(sys_socket_getsockname),
    );
    table.install_raw(
        Syscall::SocketGetPeerName,
        "getpeername",
        RawFnHandler(sys_socket_getpeername),
    );
    table.install_raw(
        Syscall::SocketSendMsg,
        "sendmsg",
        RawFnHandler(sys_socket_sendmsg),
    );
    table.install_raw(
        Syscall::SocketRecvMsg,
        "recvmsg",
        RawFnHandler(sys_socket_recvmsg),
    );
    table.install_raw(
        Syscall::SockRegisterBuf,
        "sock_register_buf",
        RawFnHandler(sys_sock_register_buf),
    );
    table.install_raw(
        Syscall::SockSendZc,
        "sock_send_zc",
        RawFnHandler(sys_sock_send_zc),
    );
    table.install_raw(Syscall::Poll, "poll", RawFnHandler(sys_poll));
    // Shadowed below by the `crate::epoll` implementations; kept so the
    // legacy `io_mux::EpollFile` path stays wired while it still exists.
    table.install_raw(
        Syscall::EpollCreate,
        "epoll_create1",
        RawFnHandler(sys_epoll_create),
    );
    table.install_raw(Syscall::EpollCtl, "epoll_ctl", RawFnHandler(sys_epoll_ctl));
    table.install_raw(
        Syscall::EpollWait,
        "epoll_wait",
        RawFnHandler(sys_epoll_wait),
    );
    table.install_raw(Syscall::Eventfd, "eventfd2", RawFnHandler(sys_eventfd2));
    table.install_raw(Syscall::Bpf, "bpf", RawFnHandler(sys_bpf));
    table.install_raw(
        Syscall::PidfdOpen,
        "pidfd_open",
        RawFnHandler(sys_pidfd_open),
    );
    table.install_raw(
        Syscall::TimerfdCreate,
        "timerfd_create",
        RawFnHandler(sys_timerfd_create),
    );
    table.install_raw(
        Syscall::TimerfdSettime,
        "timerfd_settime",
        RawFnHandler(sys_timerfd_settime),
    );
    table.install_raw(
        Syscall::TimerfdGettime,
        "timerfd_gettime",
        RawFnHandler(sys_timerfd_gettime),
    );
    table.install_raw(Syscall::Signalfd, "signalfd", RawFnHandler(sys_signalfd));
    table.install_raw(Syscall::Tcgetattr, "tcgetattr", RawFnHandler(sys_tcgetattr));
    table.install_raw(Syscall::Tcsetattr, "tcsetattr", RawFnHandler(sys_tcsetattr));
    table.install_raw(Syscall::Flock, "flock", RawFnHandler(sys_flock));
    table.install_raw(
        Syscall::FbConnect,
        "fb_connect",
        RawFnHandler(sys_fb_connect),
    );
    table.install_raw(Syscall::FbInfo, "fb_info", RawFnHandler(sys_fb_info));
    table.install_raw(
        Syscall::FbRingMap,
        "fb_ring_map",
        RawFnHandler(sys_fb_ring_map),
    );
    table.install_raw(
        Syscall::FbFlushWait,
        "fb_flush_wait",
        RawFnHandler(sys_fb_flush_wait),
    );
    table.install_raw(
        Syscall::FbDisconnect,
        "fb_disconnect",
        RawFnHandler(sys_fb_disconnect),
    );
    table.install_raw(
        Syscall::ShmemCreate,
        "shmem_create",
        RawFnHandler(sys_shmem_create),
    );
    table.install_raw(Syscall::ShmemMap, "shmem_map", RawFnHandler(sys_shmem_map));
    table.install_raw(
        Syscall::ShmemDestroy,
        "shmem_destroy",
        RawFnHandler(sys_shmem_destroy),
    );
    table.install_raw(
        Syscall::FirmwareInstall,
        "firmware_install",
        RawFnHandler(sys_firmware_install),
    );
    table.install_raw(Syscall::RingKick, "ringkick", RawFnHandler(sys_ring_kick));
    table.install_raw(Syscall::GetPid, "getpid", RawFnHandler(sys_getpid));
    table.install_raw(Syscall::GetPpid, "getppid", RawFnHandler(sys_getppid));
    table.install_raw(Syscall::Gettid, "gettid", RawFnHandler(sys_gettid));
    table.install_raw(Syscall::Clone, "clone", RawFnHandler(sys_clone));
    table.install_raw(Syscall::Fork, "fork", RawFnHandler(sys_fork));
    {
        table.install_raw(Syscall::Clone3, "clone3", RawFnHandler(sys_clone3));
        table.install_raw(
            Syscall::SetTidAddress,
            "set_tid_address",
            RawFnHandler(sys_set_tid_address),
        );
    }
    #[cfg(target_arch = "x86_64")]
    {
        table.install_raw(
            Syscall::ArchPrctl,
            "arch_prctl",
            RawFnHandler(sys_arch_prctl),
        );
    }
    table.install_raw(Syscall::GetUid, "getuid", RawFnHandler(sys_getuid));
    table.install_raw(Syscall::GetGid, "getgid", RawFnHandler(sys_getgid));
    table.install_raw(Syscall::SetUid, "setuid", RawFnHandler(sys_setuid));
    table.install_raw(Syscall::SetGid, "setgid", RawFnHandler(sys_setgid));
    table.install_raw(Syscall::Getresuid, "getresuid", RawFnHandler(sys_getresuid));
    table.install_raw(Syscall::Setresuid, "setresuid", RawFnHandler(sys_setresuid));
    table.install_raw(Syscall::Getresgid, "getresgid", RawFnHandler(sys_getresgid));
    table.install_raw(Syscall::Setresgid, "setresgid", RawFnHandler(sys_setresgid));
    table.install_raw(Syscall::Getgroups, "getgroups", RawFnHandler(sys_getgroups));
    table.install_raw(Syscall::Setgroups, "setgroups", RawFnHandler(sys_setgroups));
    table.install_raw(Syscall::Getpgid, "getpgid", RawFnHandler(sys_getpgid));
    table.install_raw(Syscall::Setpgid, "setpgid", RawFnHandler(sys_setpgid));
    table.install_raw(Syscall::Getsid, "getsid", RawFnHandler(sys_getsid));
    table.install_raw(Syscall::Setsid, "setsid", RawFnHandler(sys_setsid));
    table.install_raw(Syscall::Vhangup, "vhangup", RawFnHandler(sys_vhangup));
    table.install_raw(
        Syscall::GetHostname,
        "gethostname",
        RawFnHandler(sys_gethostname),
    );
    table.install_raw(
        Syscall::SetHostname,
        "sethostname",
        RawFnHandler(sys_sethostname),
    );
    // POSIX uname(2) — always present. Reads the UTS struct only;
    // doesn't depend on per-task UTS-namespace infrastructure.
    table.install_raw(Syscall::Uname, "uname", RawFnHandler(sys_uname));
    table.install_raw(
        Syscall::Setdomainname,
        "setdomainname",
        RawFnHandler(sys_setdomainname),
    );
    #[cfg(feature = "container")]
    {
        table.install_raw(Syscall::Shmget, "shmget", RawFnHandler(sys_shmget));
        // The self-contained sysvipc module supersedes the id-by-key
        // semget/msgget in any linux-compat build; only register the
        // container-namespace versions when linux-compat is absent.
    }
    table.install_raw(Syscall::Getrlimit, "getrlimit", RawFnHandler(sys_getrlimit));
    table.install_raw(Syscall::Setrlimit, "setrlimit", RawFnHandler(sys_setrlimit));
    table.install_raw(Syscall::Prlimit64, "prlimit64", RawFnHandler(sys_prlimit64));
    table.install_raw(Syscall::Umask, "umask", RawFnHandler(sys_umask));
    table.install_raw(Syscall::Getcpu, "getcpu", RawFnHandler(sys_getcpu));
    table.install_raw(
        Syscall::SchedGetaffinity,
        "sched_getaffinity",
        RawFnHandler(sys_sched_getaffinity),
    );
    table.install_raw(
        Syscall::SchedSetaffinity,
        "sched_setaffinity",
        RawFnHandler(sys_sched_setaffinity),
    );
    table.install_raw(
        Syscall::SchedGetPriorityMax,
        "sched_get_priority_max",
        RawFnHandler(sys_sched_get_priority_max),
    );
    table.install_raw(
        Syscall::SchedGetPriorityMin,
        "sched_get_priority_min",
        RawFnHandler(sys_sched_get_priority_min),
    );
    table.install_raw(
        Syscall::SchedGetparam,
        "sched_getparam",
        RawFnHandler(sys_sched_getparam),
    );
    table.install_raw(
        Syscall::SchedSetparam,
        "sched_setparam",
        RawFnHandler(sys_sched_setparam),
    );
    table.install_raw(Syscall::Prctl, "prctl", RawFnHandler(sys_prctl));
    table.install_raw(Syscall::Seccomp, "seccomp", RawFnHandler(sys_seccomp));
    table.install_raw(
        Syscall::Getpriority,
        "getpriority",
        RawFnHandler(sys_getpriority),
    );
    table.install_raw(
        Syscall::Setpriority,
        "setpriority",
        RawFnHandler(sys_setpriority),
    );
    table.install_raw(Syscall::Times, "times", RawFnHandler(sys_times));
    table.install_raw(Syscall::Getrusage, "getrusage", RawFnHandler(sys_getrusage));
    table.install_raw(Syscall::ExitTask, "exit", RawFnHandler(sys_exit_task));
    table.install_raw(
        Syscall::ExitGroup,
        "exit_group",
        RawFnHandler(sys_exit_group),
    );
    table.install_raw(Syscall::Yield, "yield", RawFnHandler(sys_yield));
    table.install_raw(Syscall::Sleep, "sleep", RawFnHandler(sys_sleep));
    table.install_raw(Syscall::Brk, "brk", RawFnHandler(sys_brk));
    table.install_raw(
        Syscall::ClockGetTime,
        "clock_gettime",
        RawFnHandler(sys_clock_gettime),
    );
    table.install_raw(
        Syscall::ClockSetTime,
        "clock_settime",
        RawFnHandler(sys_clock_settime),
    );
    {
        table.install_raw(
            Syscall::Gettimeofday,
            "gettimeofday",
            RawFnHandler(sys_gettimeofday),
        );
        table.install_raw(
            Syscall::Settimeofday,
            "settimeofday",
            RawFnHandler(sys_settimeofday),
        );
        table.install_raw(Syscall::Time, "time", RawFnHandler(sys_time));
        table.install_raw(
            Syscall::IoprioSet,
            "ioprio_set",
            RawFnHandler(sys_ioprio_set),
        );
        table.install_raw(
            Syscall::IoprioGet,
            "ioprio_get",
            RawFnHandler(sys_ioprio_get),
        );
    }
    {
        // Wave-73: POSIX per-process timers + clock_nanosleep.
        table.install_raw(
            Syscall::TimerCreate,
            "timer_create",
            RawFnHandler(crate::posix_timer::sys_timer_create),
        );
        table.install_raw(
            Syscall::TimerSettime,
            "timer_settime",
            RawFnHandler(crate::posix_timer::sys_timer_settime),
        );
        table.install_raw(
            Syscall::TimerGettime,
            "timer_gettime",
            RawFnHandler(crate::posix_timer::sys_timer_gettime),
        );
        table.install_raw(
            Syscall::TimerDelete,
            "timer_delete",
            RawFnHandler(crate::posix_timer::sys_timer_delete),
        );
        table.install_raw(
            Syscall::ClockNanosleep,
            "clock_nanosleep",
            RawFnHandler(crate::posix_timer::sys_clock_nanosleep),
        );
        table.install_raw(
            Syscall::Nanosleep,
            "nanosleep",
            RawFnHandler(crate::posix_timer::sys_nanosleep),
        );
        // Batch 7: BSD interval timers (ITIMER_REAL → SIGALRM) + alarm.
        table.install_raw(
            Syscall::Setitimer,
            "setitimer",
            RawFnHandler(crate::posix_timer::sys_setitimer),
        );
        table.install_raw(
            Syscall::Getitimer,
            "getitimer",
            RawFnHandler(crate::posix_timer::sys_getitimer),
        );
        table.install_raw(
            Syscall::Alarm,
            "alarm",
            RawFnHandler(crate::posix_timer::sys_alarm),
        );
        // Batch 8: POSIX message queues + inotify.
        table.install_raw(
            Syscall::MqOpen,
            "mq_open",
            RawFnHandler(crate::mqueue::sys_mq_open),
        );
        table.install_raw(
            Syscall::MqUnlink,
            "mq_unlink",
            RawFnHandler(crate::mqueue::sys_mq_unlink),
        );
        table.install_raw(
            Syscall::MqTimedsend,
            "mq_timedsend",
            RawFnHandler(crate::mqueue::sys_mq_timedsend),
        );
        table.install_raw(
            Syscall::MqTimedreceive,
            "mq_timedreceive",
            RawFnHandler(crate::mqueue::sys_mq_timedreceive),
        );
        table.install_raw(
            Syscall::MqNotify,
            "mq_notify",
            RawFnHandler(crate::mqueue::sys_mq_notify),
        );
        table.install_raw(
            Syscall::MqGetsetattr,
            "mq_getsetattr",
            RawFnHandler(crate::mqueue::sys_mq_getsetattr),
        );
        table.install_raw(
            Syscall::InotifyInit1,
            "inotify_init1",
            RawFnHandler(crate::mqueue::sys_inotify_init1),
        );
        table.install_raw(
            Syscall::InotifyInit,
            "inotify_init",
            RawFnHandler(crate::mqueue::sys_inotify_init_no_flags),
        );
        table.install_raw(
            Syscall::InotifyAddWatch,
            "inotify_add_watch",
            RawFnHandler(crate::mqueue::sys_inotify_add_watch),
        );
        table.install_raw(
            Syscall::InotifyRmWatch,
            "inotify_rm_watch",
            RawFnHandler(crate::mqueue::sys_inotify_rm_watch),
        );
        // Batch 23: fanotify — events delivered through the same fs_notify
        // dispatch as inotify, each carrying an open fd to the object.
        table.install_raw(
            Syscall::FanotifyInit,
            "fanotify_init",
            RawFnHandler(crate::mqueue::sys_fanotify_init),
        );
        table.install_raw(
            Syscall::FanotifyMark,
            "fanotify_mark",
            RawFnHandler(crate::mqueue::sys_fanotify_mark),
        );
        // Batch 24: Landlock — path-based access control, enforced at open.
        table.install_raw(
            Syscall::LandlockCreateRuleset,
            "landlock_create_ruleset",
            RawFnHandler(crate::landlock::sys_landlock_create_ruleset),
        );
        table.install_raw(
            Syscall::LandlockAddRule,
            "landlock_add_rule",
            RawFnHandler(crate::landlock::sys_landlock_add_rule),
        );
        table.install_raw(
            Syscall::LandlockRestrictSelf,
            "landlock_restrict_self",
            RawFnHandler(crate::landlock::sys_landlock_restrict_self),
        );
        // Batch 25: generic LSM self-attribute syscalls.
        table.install_raw(
            Syscall::LsmGetSelfAttr,
            "lsm_get_self_attr",
            RawFnHandler(crate::lsm::sys_lsm_get_self_attr),
        );
        table.install_raw(
            Syscall::LsmSetSelfAttr,
            "lsm_set_self_attr",
            RawFnHandler(crate::lsm::sys_lsm_set_self_attr),
        );
        table.install_raw(
            Syscall::LsmListModules,
            "lsm_list_modules",
            RawFnHandler(crate::lsm::sys_lsm_list_modules),
        );
        // New mount API round 1: file handles.
        table.install_raw(
            Syscall::NameToHandleAt,
            "name_to_handle_at",
            RawFnHandler(sys_name_to_handle_at),
        );
        table.install_raw(
            Syscall::OpenByHandleAt,
            "open_by_handle_at",
            RawFnHandler(sys_open_by_handle_at),
        );
        // New mount API round 2: fsopen/fsconfig/fsmount/move_mount/...
        table.install_raw(
            Syscall::Fsopen,
            "fsopen",
            RawFnHandler(crate::mount_api::sys_fsopen),
        );
        table.install_raw(
            Syscall::Fsconfig,
            "fsconfig",
            RawFnHandler(crate::mount_api::sys_fsconfig),
        );
        table.install_raw(
            Syscall::Fsmount,
            "fsmount",
            RawFnHandler(crate::mount_api::sys_fsmount),
        );
        table.install_raw(
            Syscall::MoveMount,
            "move_mount",
            RawFnHandler(crate::mount_api::sys_move_mount),
        );
        table.install_raw(
            Syscall::OpenTree,
            "open_tree",
            RawFnHandler(crate::mount_api::sys_open_tree),
        );
        table.install_raw(
            Syscall::OpenTreeAttr,
            "open_tree_attr",
            RawFnHandler(crate::mount_api::sys_open_tree_attr),
        );
        table.install_raw(
            Syscall::Fspick,
            "fspick",
            RawFnHandler(crate::mount_api::sys_fspick),
        );
        table.install_raw(
            Syscall::MountSetattr,
            "mount_setattr",
            RawFnHandler(crate::mount_api::sys_mount_setattr),
        );
        // Batch 21: keyrings — a real in-kernel key store.
        table.install_raw(
            Syscall::AddKey,
            "add_key",
            RawFnHandler(crate::keyring::sys_add_key),
        );
        table.install_raw(
            Syscall::RequestKey,
            "request_key",
            RawFnHandler(crate::keyring::sys_request_key),
        );
        table.install_raw(
            Syscall::Keyctl,
            "keyctl",
            RawFnHandler(crate::keyring::sys_keyctl),
        );
        // Batch 11: System V semaphores + message queues. These override
        // the container-only id-by-key `semget`/`msgget` (registered
        // earlier) with self-contained backing that works without the
        // container feature.
        table.install_raw(
            Syscall::Semget,
            "semget",
            RawFnHandler(crate::sysvipc::sys_semget),
        );
        table.install_raw(
            Syscall::Semop,
            "semop",
            RawFnHandler(crate::sysvipc::sys_semop),
        );
        table.install_raw(
            Syscall::Semctl,
            "semctl",
            RawFnHandler(crate::sysvipc::sys_semctl),
        );
        table.install_raw(
            Syscall::Semtimedop,
            "semtimedop",
            RawFnHandler(crate::sysvipc::sys_semtimedop),
        );
        table.install_raw(
            Syscall::Msgget,
            "msgget",
            RawFnHandler(crate::sysvipc::sys_msgget),
        );
        table.install_raw(
            Syscall::Msgsnd,
            "msgsnd",
            RawFnHandler(crate::sysvipc::sys_msgsnd),
        );
        table.install_raw(
            Syscall::Msgrcv,
            "msgrcv",
            RawFnHandler(crate::sysvipc::sys_msgrcv),
        );
        table.install_raw(
            Syscall::Msgctl,
            "msgctl",
            RawFnHandler(crate::sysvipc::sys_msgctl),
        );
        // Batch 12: System V shared memory with real frame backing. The
        // linux-compat shmget supersedes the container id-by-key version.
        table.install_raw(Syscall::Shmget, "shmget", RawFnHandler(sys_shmget_compat));
        table.install_raw(Syscall::Shmat, "shmat", RawFnHandler(sys_shmat));
        table.install_raw(Syscall::Shmdt, "shmdt", RawFnHandler(sys_shmdt));
        table.install_raw(Syscall::Shmctl, "shmctl", RawFnHandler(sys_shmctl));
    }
    table.install_raw(Syscall::Sigaction, "sigaction", RawFnHandler(sys_sigaction));
    table.install_raw(
        Syscall::RtSigaction,
        "rt_sigaction",
        RawFnHandler(sys_rt_sigaction),
    );
    table.install_raw(Syscall::Kill, "kill", RawFnHandler(sys_kill));
    table.install_raw(Syscall::Pause, "pause", RawFnHandler(sys_pause));
    table.install_raw(Syscall::Tgkill, "tgkill", RawFnHandler(sys_tgkill));
    table.install_raw(Syscall::Tkill, "tkill", RawFnHandler(sys_tkill));
    // Batch 16: signal queueing with siginfo (delivered via the pending
    // bitmask; the siginfo payload isn't preserved yet).
    table.install_raw(
        Syscall::RtSigqueueinfo,
        "rt_sigqueueinfo",
        RawFnHandler(sys_rt_sigqueueinfo),
    );
    table.install_raw(
        Syscall::RtTgsigqueueinfo,
        "rt_tgsigqueueinfo",
        RawFnHandler(sys_rt_tgsigqueueinfo),
    );
    table.install_raw(Syscall::Ptrace, "ptrace", RawFnHandler(sys_ptrace));
    table.install_raw(Syscall::Futex, "futex", RawFnHandler(sys_futex));
    table.install_raw(
        Syscall::Sigprocmask,
        "sigprocmask",
        RawFnHandler(sys_sigprocmask),
    );
    table.install_raw(
        Syscall::Sigaltstack,
        "sigaltstack",
        RawFnHandler(sys_sigaltstack),
    );
    table.install_raw(
        Syscall::RtSigpending,
        "rt_sigpending",
        RawFnHandler(sys_rt_sigpending),
    );
    table.install_raw(
        Syscall::RtSigsuspend,
        "rt_sigsuspend",
        RawFnHandler(sys_rt_sigsuspend),
    );
    table.install_raw(
        Syscall::RtSigtimedwait,
        "rt_sigtimedwait",
        RawFnHandler(sys_rt_sigtimedwait),
    );
    // restart_syscall — kernel-injected continuation. NARF has no
    // restart_block, so (like Linux's do_no_restart_syscall) it returns
    // -EINTR. See sys_restart_syscall's comment for the restart model.
    table.install_raw(
        Syscall::RestartSyscall,
        "restart_syscall",
        RawFnHandler(sys_restart_syscall),
    );

    // Tier-2 fd-table breadth + path-resolution + pipe(2).
    table.install_raw(Syscall::Dup, "dup", RawFnHandler(sys_dup));
    table.install_raw(Syscall::Dup2, "dup2", RawFnHandler(sys_dup2));
    table.install_raw(Syscall::Dup3, "dup3", RawFnHandler(sys_dup3));
    table.install_raw(Syscall::Fcntl, "fcntl", RawFnHandler(sys_fcntl));
    table.install_raw(Syscall::Ioctl, "ioctl", RawFnHandler(sys_ioctl));
    {
        table.install_raw(Syscall::Stat, "stat", RawFnHandler(sys_stat_linux));
        table.install_raw(Syscall::Lstat, "lstat", RawFnHandler(sys_lstat_linux));
        table.install_raw(Syscall::Fstat, "fstat", RawFnHandler(sys_fstat_linux));
        table.install_raw(Syscall::OpenFile, "open", RawFnHandler(sys_open_linux));
    }
    table.install_raw(Syscall::Pipe, "pipe", RawFnHandler(sys_pipe));
    table.install_raw(Syscall::Ftruncate, "ftruncate", RawFnHandler(sys_ftruncate));
    table.install_raw(Syscall::Truncate, "truncate", RawFnHandler(sys_truncate));
    table.install_raw(Syscall::Pread64, "pread64", RawFnHandler(sys_pread64));
    table.install_raw(Syscall::Pwrite64, "pwrite64", RawFnHandler(sys_pwrite64));
    table.install_raw(Syscall::Fsync, "fsync", RawFnHandler(sys_fsync));
    table.install_raw(Syscall::Fdatasync, "fdatasync", RawFnHandler(sys_fdatasync));
    table.install_raw(Syscall::Pipe2, "pipe2", RawFnHandler(sys_pipe2));
    table.install_raw(Syscall::Fallocate, "fallocate", RawFnHandler(sys_fallocate));
    table.install_raw(
        Syscall::CopyFileRange,
        "copy_file_range",
        RawFnHandler(sys_copy_file_range),
    );
    table.install_raw(
        Syscall::MemfdCreate,
        "memfd_create",
        RawFnHandler(sys_memfd_create),
    );
    table.install_raw(Syscall::Fchmod, "fchmod", RawFnHandler(sys_fchmod));
    table.install_raw(Syscall::Fchown, "fchown", RawFnHandler(sys_fchown));
    table.install_raw(Syscall::Fchmodat, "fchmodat", RawFnHandler(sys_fchmodat));
    table.install_raw(
        Syscall::Fchownat,
        "fchownat",
        RawFnHandler(sys_fchmodat_or_fchownat),
    );
    table.install_raw(Syscall::Faccessat, "faccessat", RawFnHandler(sys_faccessat));
    table.install_raw(Syscall::Openat, "openat", RawFnHandler(sys_openat));
    table.install_raw(
        Syscall::Newfstatat,
        "newfstatat",
        RawFnHandler(sys_newfstatat_linux),
    );
    table.install_raw(Syscall::Statx, "statx", RawFnHandler(sys_statx));
    table.install_raw(Syscall::Unlinkat, "unlinkat", RawFnHandler(sys_unlinkat));
    table.install_raw(Syscall::Mkdirat, "mkdirat", RawFnHandler(sys_mkdirat));
    table.install_raw(Syscall::Mknodat, "mknodat", RawFnHandler(sys_mknodat));
    table.install_raw(Syscall::Mknod, "mknod", RawFnHandler(sys_mknod));
    table.install_raw(Syscall::Renameat, "renameat", RawFnHandler(sys_renameat));
    table.install_raw(Syscall::Symlinkat, "symlinkat", RawFnHandler(sys_symlinkat));
    table.install_raw(
        Syscall::Readlinkat,
        "readlinkat",
        RawFnHandler(sys_readlinkat),
    );
    table.install_raw(Syscall::Access, "access", RawFnHandler(sys_access));
    table.install_raw(Syscall::Chmod, "chmod", RawFnHandler(sys_chmod));
    table.install_raw(Syscall::Chown, "chown", RawFnHandler(sys_chown));

    // Tier-2 cwd state + nanosleep wired into the table. Sleep
    // already replaced the noop_ok stub above.
    table.install_raw(Syscall::Chdir, "chdir", RawFnHandler(sys_chdir));
    table.install_raw(Syscall::Getcwd, "getcwd", RawFnHandler(sys_getcwd));
    table.install_raw(Syscall::Lseek, "lseek", RawFnHandler(sys_lseek));
    table.install_raw(Syscall::Unlink, "unlink", RawFnHandler(sys_unlink));
    table.install_raw(Syscall::Mkdir, "mkdir", RawFnHandler(sys_mkdir));
    table.install_raw(Syscall::Rmdir, "rmdir", RawFnHandler(sys_rmdir));
    table.install_raw(Syscall::Rename, "rename", RawFnHandler(sys_rename));
    table.install_raw(Syscall::Link, "link", RawFnHandler(sys_link));
    table.install_raw(Syscall::Linkat, "linkat", RawFnHandler(sys_linkat));
    table.install_raw(Syscall::Fchdir, "fchdir", RawFnHandler(sys_fchdir));
    table.install_raw(Syscall::Readlink, "readlink", RawFnHandler(sys_readlink));
    table.install_raw(Syscall::Symlink, "symlink", RawFnHandler(sys_symlink));
    table.install_raw(Syscall::Listdir, "listdir", RawFnHandler(sys_listdir));
    table.install_raw(
        Syscall::Getdents64,
        "getdents64",
        RawFnHandler(sys_getdents64),
    );
    // Legacy 32-bit-offset getdents (x86_64 78; no aarch64 wire number).
    table.install_raw(Syscall::Getdents, "getdents", RawFnHandler(sys_getdents));

    // Tier-3z entropy.
    table.install_raw(Syscall::GetRandom, "getrandom", RawFnHandler(sys_getrandom));

    // I/O multiplexing: poll / select / pselect6 / epoll.
    table.install_raw(Syscall::Poll, "poll", RawFnHandler(crate::poll::sys_poll));
    table.install_raw(
        Syscall::Ppoll,
        "ppoll",
        RawFnHandler(crate::poll::sys_ppoll),
    );
    table.install_raw(Syscall::Sysinfo, "sysinfo", RawFnHandler(sys_sysinfo));
    table.install_raw(Syscall::Splice, "splice", RawFnHandler(sys_splice));
    table.install_raw(
        Syscall::Membarrier,
        "membarrier",
        RawFnHandler(sys_membarrier),
    );
    table.install_raw(
        Syscall::ClockGetres,
        "clock_getres",
        RawFnHandler(sys_clock_getres),
    );
    table.install_raw(
        Syscall::CloseRange,
        "close_range",
        RawFnHandler(sys_close_range),
    );
    table.install_raw(
        Syscall::SchedGetScheduler,
        "sched_getscheduler",
        RawFnHandler(sys_sched_getscheduler),
    );
    table.install_raw(
        Syscall::SchedSetScheduler,
        "sched_setscheduler",
        RawFnHandler(sys_sched_setscheduler),
    );
    table.install_raw(
        Syscall::SchedRrGetInterval,
        "sched_rr_get_interval",
        RawFnHandler(sys_sched_rr_get_interval),
    );
    table.install_raw(Syscall::Msync, "msync", RawFnHandler(sys_msync));
    table.install_raw(Syscall::Mincore, "mincore", RawFnHandler(sys_mincore));
    table.install_raw(Syscall::Sync, "sync", RawFnHandler(sys_sync));
    table.install_raw(Syscall::Syncfs, "syncfs", RawFnHandler(sys_syncfs));
    table.install_raw(
        Syscall::Personality,
        "personality",
        RawFnHandler(sys_personality),
    );
    table.install_raw(Syscall::Fadvise64, "fadvise64", RawFnHandler(sys_fadvise64));
    table.install_raw(Syscall::Mlock2, "mlock2", RawFnHandler(sys_mlock2));
    table.install_raw(
        Syscall::SetRobustList,
        "set_robust_list",
        RawFnHandler(sys_set_robust_list),
    );
    table.install_raw(
        Syscall::GetRobustList,
        "get_robust_list",
        RawFnHandler(sys_get_robust_list),
    );
    table.install_raw(Syscall::Renameat2, "renameat2", RawFnHandler(sys_renameat2));
    table.install_raw(
        Syscall::PidfdSendSignal,
        "pidfd_send_signal",
        RawFnHandler(sys_pidfd_send_signal),
    );
    table.install_raw(
        Syscall::Sendmmsg,
        "sendmmsg",
        RawFnHandler(sys_socket_sendmmsg),
    );
    table.install_raw(
        Syscall::Recvmmsg,
        "recvmmsg",
        RawFnHandler(sys_socket_recvmmsg),
    );
    table.install_raw(Syscall::Openat2, "openat2", RawFnHandler(sys_openat2));
    table.install_raw(Syscall::Preadv, "preadv", RawFnHandler(sys_preadv));
    table.install_raw(Syscall::Pwritev, "pwritev", RawFnHandler(sys_pwritev));
    // Batch 7: capabilities, extended attributes, file-range hints.
    table.install_raw(Syscall::Capget, "capget", RawFnHandler(sys_capget));
    table.install_raw(Syscall::Capset, "capset", RawFnHandler(sys_capset));
    table.install_raw(Syscall::Setxattr, "setxattr", RawFnHandler(sys_setxattr));
    table.install_raw(Syscall::Getxattr, "getxattr", RawFnHandler(sys_getxattr));
    table.install_raw(Syscall::Listxattr, "listxattr", RawFnHandler(sys_listxattr));
    // Batch 13: xattr l*/f*/remove variants. NARF has no symlink-follow
    // distinction, so the l* variants alias the path handlers.
    table.install_raw(Syscall::Lsetxattr, "lsetxattr", RawFnHandler(sys_setxattr));
    table.install_raw(Syscall::Lgetxattr, "lgetxattr", RawFnHandler(sys_getxattr));
    table.install_raw(
        Syscall::Llistxattr,
        "llistxattr",
        RawFnHandler(sys_listxattr),
    );
    table.install_raw(
        Syscall::Removexattr,
        "removexattr",
        RawFnHandler(sys_removexattr),
    );
    table.install_raw(
        Syscall::Lremovexattr,
        "lremovexattr",
        RawFnHandler(sys_removexattr),
    );
    table.install_raw(Syscall::Fsetxattr, "fsetxattr", RawFnHandler(sys_fsetxattr));
    table.install_raw(Syscall::Fgetxattr, "fgetxattr", RawFnHandler(sys_fgetxattr));
    table.install_raw(
        Syscall::Flistxattr,
        "flistxattr",
        RawFnHandler(sys_flistxattr),
    );
    table.install_raw(
        Syscall::Fremovexattr,
        "fremovexattr",
        RawFnHandler(sys_fremovexattr),
    );
    // Batch 14: filesystem misc (legacy x86_64-only entries).
    table.install_raw(Syscall::Creat, "creat", RawFnHandler(sys_creat));
    table.install_raw(Syscall::Lchown, "lchown", RawFnHandler(sys_lchown));
    table.install_raw(Syscall::Utime, "utime", RawFnHandler(sys_utime));
    table.install_raw(Syscall::Utimes, "utimes", RawFnHandler(sys_utimes));
    table.install_raw(Syscall::Futimesat, "futimesat", RawFnHandler(sys_futimesat));
    table.install_raw(Syscall::Reboot, "reboot", RawFnHandler(sys_reboot));
    table.install_raw(Syscall::Utimensat, "utimensat", RawFnHandler(sys_utimensat));
    // Batch 15: credential gaps (real/effective/fs uid+gid).
    table.install_raw(Syscall::Geteuid, "geteuid", RawFnHandler(sys_geteuid));
    table.install_raw(Syscall::Getegid, "getegid", RawFnHandler(sys_getegid));
    table.install_raw(Syscall::Getpgrp, "getpgrp", RawFnHandler(sys_getpgrp));
    table.install_raw(Syscall::Setreuid, "setreuid", RawFnHandler(sys_setreuid));
    table.install_raw(Syscall::Setregid, "setregid", RawFnHandler(sys_setregid));
    table.install_raw(Syscall::Setfsuid, "setfsuid", RawFnHandler(sys_setfsuid));
    table.install_raw(Syscall::Setfsgid, "setfsgid", RawFnHandler(sys_setfsgid));
    table.install_raw(Syscall::Readahead, "readahead", RawFnHandler(sys_readahead));
    table.install_raw(
        Syscall::SyncFileRange,
        "sync_file_range",
        RawFnHandler(sys_sync_file_range),
    );
    // Batch 8: protection keys + cross-AS bulk copy.
    table.install_raw(
        Syscall::PkeyAlloc,
        "pkey_alloc",
        RawFnHandler(sys_pkey_alloc),
    );
    table.install_raw(Syscall::PkeyFree, "pkey_free", RawFnHandler(sys_pkey_free));
    table.install_raw(
        Syscall::PkeyMprotect,
        "pkey_mprotect",
        RawFnHandler(sys_pkey_mprotect),
    );
    table.install_raw(
        Syscall::ProcessVmReadv,
        "process_vm_readv",
        RawFnHandler(sys_process_vm_readv),
    );
    table.install_raw(
        Syscall::ProcessVmWritev,
        "process_vm_writev",
        RawFnHandler(sys_process_vm_writev),
    );
    // Batch 9: NUMA mempolicy, extended scheduling, clock adjust, introspection.
    table.install_raw(Syscall::Mbind, "mbind", RawFnHandler(sys_mbind));
    table.install_raw(
        Syscall::SetMempolicy,
        "set_mempolicy",
        RawFnHandler(sys_set_mempolicy),
    );
    table.install_raw(
        Syscall::GetMempolicy,
        "get_mempolicy",
        RawFnHandler(sys_get_mempolicy),
    );
    table.install_raw(
        Syscall::SchedSetattr,
        "sched_setattr",
        RawFnHandler(sys_sched_setattr),
    );
    table.install_raw(
        Syscall::SchedGetattr,
        "sched_getattr",
        RawFnHandler(sys_sched_getattr),
    );
    table.install_raw(Syscall::Adjtimex, "adjtimex", RawFnHandler(sys_adjtimex));
    table.install_raw(
        Syscall::ClockAdjtime,
        "clock_adjtime",
        RawFnHandler(sys_clock_adjtime),
    );
    table.install_raw(
        Syscall::PidfdGetfd,
        "pidfd_getfd",
        RawFnHandler(sys_pidfd_getfd),
    );
    table.install_raw(Syscall::Kcmp, "kcmp", RawFnHandler(sys_kcmp));
    // Batch 10: vectored + extended I/O.
    table.install_raw(Syscall::Readv, "readv", RawFnHandler(sys_readv));
    table.install_raw(Syscall::Preadv2, "preadv2", RawFnHandler(sys_preadv2));
    table.install_raw(Syscall::Pwritev2, "pwritev2", RawFnHandler(sys_pwritev2));
    table.install_raw(Syscall::Tee, "tee", RawFnHandler(sys_tee));
    table.install_raw(Syscall::Vmsplice, "vmsplice", RawFnHandler(sys_vmsplice));
    table.install_raw(
        Syscall::Select,
        "select",
        RawFnHandler(crate::select::sys_select),
    );
    table.install_raw(
        Syscall::Pselect6,
        "pselect6",
        RawFnHandler(crate::select::sys_pselect6),
    );
    table.install_raw(
        Syscall::EpollCreate,
        "epoll_create1",
        RawFnHandler(crate::epoll::sys_epoll_create1),
    );
    // x86_64 213. A separate syscall from epoll_create1, not an alias:
    // arg0 is a size the kernel validates, not a flag word.
    table.install_raw(
        Syscall::EpollCreateLegacy,
        "epoll_create",
        RawFnHandler(crate::epoll::sys_epoll_create),
    );
    // x86_64 284. Likewise separate from eventfd2: it has no flag word.
    table.install_raw(
        Syscall::EventfdLegacy,
        "eventfd",
        RawFnHandler(sys_eventfd),
    );
    table.install_raw(
        Syscall::EpollCtl,
        "epoll_ctl",
        RawFnHandler(crate::epoll::sys_epoll_ctl),
    );
    table.install_raw(
        Syscall::EpollWait,
        "epoll_wait",
        RawFnHandler(crate::epoll::sys_epoll_wait),
    );
    table.install_raw(
        Syscall::EpollPwait,
        "epoll_pwait",
        RawFnHandler(crate::epoll::sys_epoll_pwait),
    );
    table.install_raw(
        Syscall::EpollPwait2,
        "epoll_pwait2",
        RawFnHandler(crate::epoll::sys_epoll_pwait2),
    );
    table.install_raw(
        Syscall::PerfEventOpen,
        "perf_event_open",
        RawFnHandler(crate::perf_event::sys_perf_event_open),
    );

    // Loadable kernel modules.
    table.install_raw(
        Syscall::InitModule,
        "init_module",
        RawFnHandler(sys_init_module),
    );
    table.install_raw(
        Syscall::FinitModule,
        "finit_module",
        RawFnHandler(sys_finit_module),
    );
    table.install_raw(
        Syscall::DeleteModule,
        "delete_module",
        RawFnHandler(sys_delete_module),
    );

    // Linux kernel-AIO (libaio) — synchronous backend. See the `aio`
    // module below and [[narf-libaio-sync-backend]].
    table.install_raw(
        Syscall::IoSetup,
        "io_setup",
        RawFnHandler(aio::sys_io_setup),
    );
    table.install_raw(
        Syscall::IoDestroy,
        "io_destroy",
        RawFnHandler(aio::sys_io_destroy),
    );
    table.install_raw(
        Syscall::IoSubmit,
        "io_submit",
        RawFnHandler(aio::sys_io_submit),
    );
    table.install_raw(
        Syscall::IoGetevents,
        "io_getevents",
        RawFnHandler(aio::sys_io_getevents),
    );
    table.install_raw(
        Syscall::IoCancel,
        "io_cancel",
        RawFnHandler(aio::sys_io_cancel),
    );

    // Auto-wire both delivery hooks so any kernel that uses
    // `install_core_syscalls` gets the async + sync signal paths
    // on for free. Idempotent.
    install_signal_delivery_hook(default_signal_delivery);
    install_sync_signal_hook(default_sync_signal_delivery);
}

// ══════════════════════════════════════════════════════════════════════
// Linux kernel-AIO (libaio) — synchronous backend
// See [[narf-libaio-sync-backend]].
//
// NARF's filesystems are in-memory/fast and the executor is cooperative,
// so a real async DMA/threadpool engine buys nothing. Instead each
// submitted `iocb` is executed *synchronously* at `io_submit` time and
// its `io_event` is queued immediately; `io_getevents` just drains the
// queue. glibc/libaio callers (submit → reap) are correct against this
// backend: they never observe an in-flight request.
//
// The per-task `io_context` table mirrors the shape of the other
// tid-keyed tables in this file (an `IrqSafeSpinLock<Option<BTreeMap>>`
// installed lazily, swept in `release_task_tables`).
//
// SMAP RIGOUR: every user-pointer access here — the `iocb *` array, each
// 64-byte `iocb` body, the `io_event` output array, the `aio_context_t`
// out/in words — goes through `copy_from_user` / `copy_to_user`, which
// bracket the transfer with STAC/CLAC. A raw deref of a user VA #PFs
// under SMAP; there are deliberately no raw user derefs below.
// ══════════════════════════════════════════════════════════════════════
mod aio {
    use super::{
        copy_from_user, copy_to_user, current_task_id, fd, poll_blocking, validate_user_range,
        SyscallReturn, TrapContext,
    };
    use alloc::collections::{BTreeMap, VecDeque};
    use alloc::vec::Vec;
    use narf_lib::sync::IrqSafeSpinLock;

    // ── errno constants (negated on return, Linux convention) ────────
    const EINVAL: i64 = -22;
    const EBADF: i64 = -9;
    const EFAULT: i64 = -14;

    // ── Linux <uapi/linux/aio_abi.h> opcodes ─────────────────────────
    const IOCB_CMD_PREAD: u16 = 0;
    const IOCB_CMD_PWRITE: u16 = 1;
    const IOCB_CMD_FSYNC: u16 = 2;
    const IOCB_CMD_FDSYNC: u16 = 3;
    const IOCB_CMD_NOOP: u16 = 6;
    const IOCB_CMD_PREADV: u16 = 7;
    const IOCB_CMD_PWRITEV: u16 = 8;

    // aio_flags bits.
    const IOCB_FLAG_RESFD: u32 = 1 << 0;

    // Struct sizes (repr(C), LP64) — verified against aio_abi.h.
    const IOCB_SIZE: usize = 64;
    const IO_EVENT_SIZE: usize = 32;

    // Cap a single io_submit batch so a bogus `nr` can't drive an
    // unbounded loop / allocation.
    const AIO_RING_MAX: i64 = 65536;

    /// A decoded `struct iocb` (Linux <uapi/linux/aio_abi.h>, 64 bytes).
    /// Field order + offsets are load-bearing; see `decode_iocb`.
    struct Iocb {
        aio_data: u64,       // off 0  — echoed into io_event.data
        aio_lio_opcode: u16, // off 16
        aio_fildes: u32,     // off 20
        aio_buf: u64,        // off 24
        aio_nbytes: u64,     // off 32
        aio_offset: i64,     // off 40
        aio_flags: u32,      // off 56
        aio_resfd: u32,      // off 60
    }

    /// Decode a 64-byte `iocb` from a kernel buffer previously filled by
    /// `copy_from_user`. Offsets per aio_abi.h:
    ///   0  u64 aio_data
    ///   8  u32 aio_key
    ///   12 u32 aio_rw_flags
    ///   16 u16 aio_lio_opcode
    ///   18 s16 aio_reqprio
    ///   20 u32 aio_fildes
    ///   24 u64 aio_buf
    ///   32 u64 aio_nbytes
    ///   40 s64 aio_offset
    ///   48 u64 aio_reserved2
    ///   56 u32 aio_flags
    ///   60 u32 aio_resfd
    fn decode_iocb(b: &[u8; IOCB_SIZE]) -> Iocb {
        let u32_at = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        let u64_at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        Iocb {
            aio_data: u64_at(0),
            aio_lio_opcode: u16::from_le_bytes(b[16..18].try_into().unwrap()),
            aio_fildes: u32_at(20),
            aio_buf: u64_at(24),
            aio_nbytes: u64_at(32),
            aio_offset: i64::from_le_bytes(b[40..48].try_into().unwrap()),
            aio_flags: u32_at(56),
            aio_resfd: u32_at(60),
        }
    }

    /// Encode a `struct io_event` (32 bytes): data, obj, res, res2.
    fn encode_event(data: u64, obj: u64, res: i64, res2: i64) -> [u8; IO_EVENT_SIZE] {
        let mut out = [0u8; IO_EVENT_SIZE];
        out[0..8].copy_from_slice(&data.to_le_bytes());
        out[8..16].copy_from_slice(&obj.to_le_bytes());
        out[16..24].copy_from_slice(&res.to_le_bytes());
        out[24..32].copy_from_slice(&res2.to_le_bytes());
        out
    }

    /// A completed AIO request, staged for `io_getevents`.
    #[derive(Clone, Copy)]
    struct Completion {
        data: u64, // echoes iocb.aio_data
        obj: u64,  // the user `iocb *` pointer
        res: i64,  // bytes transferred, or -errno
    }

    /// One AIO context: a bounded completion queue. `nr_events` is the
    /// caller's sizing hint (Linux uses it to size the mmap ring; we only
    /// keep it for bookkeeping / validation).
    struct AioContext {
        _nr_events: u32,
        completions: VecDeque<Completion>,
    }

    /// Per-task context table: tid → (ctx_id → AioContext). Context ids
    /// are minted from a global monotonic counter so they never alias
    /// across tasks (Linux hands back an opaque `aio_context_t`; callers
    /// only round-trip it, so any unique non-zero token is valid).
    static AIO_CONTEXTS: IrqSafeSpinLock<Option<BTreeMap<u64, BTreeMap<u64, AioContext>>>> =
        IrqSafeSpinLock::new(None);

    /// Monotonic context-id source. Starts at 1 so a freshly minted id is
    /// always non-zero (Linux requires the caller's `*ctx_idp` to be zero
    /// on entry and writes a non-zero id).
    static NEXT_CTX_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

    fn mint_ctx_id() -> u64 {
        NEXT_CTX_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
    }

    /// Run `f` with the calling task's context map, creating the outer
    /// table + per-task entry lazily.
    fn with_task_ctxs<R>(tid: u64, f: impl FnOnce(&mut BTreeMap<u64, AioContext>) -> R) -> R {
        let mut g = AIO_CONTEXTS.lock();
        let outer = g.get_or_insert_with(BTreeMap::new);
        let inner = outer.entry(tid).or_default();
        f(inner)
    }

    /// Exit-time sweep: drop every context (and its queued completions)
    /// owned by `tid`. Called from `release_task_tables` so a process that
    /// forgets `io_destroy` doesn't leak. See [[narf-libaio-sync-backend]].
    pub(super) fn release_task_aio(tid: u64) {
        if let Some(outer) = AIO_CONTEXTS.lock().as_mut() {
            outer.remove(&tid);
        }
    }

    // ── io_setup(nr_events, aio_context_t *ctx_idp) ──────────────────
    pub(super) fn sys_io_setup(ctx: &mut dyn TrapContext) {
        let args = *ctx.args();
        let nr_events = args.arg0 as u32;
        let ctx_idp = args.arg1;

        // Linux rejects nr_events == 0 and requires *ctx_idp be zero on
        // entry. We validate the out-pointer and mint an id.
        if ctx_idp == 0 || validate_user_range(ctx_idp, 8).is_err() {
            ctx.set_return(SyscallReturn::ok(EFAULT as u64));
            return;
        }
        if nr_events == 0 {
            ctx.set_return(SyscallReturn::ok(EINVAL as u64));
            return;
        }

        let id = mint_ctx_id();
        let tid = current_task_id();
        with_task_ctxs(tid, |m| {
            m.insert(
                id,
                AioContext {
                    _nr_events: nr_events,
                    completions: VecDeque::new(),
                },
            );
        });

        // SAFETY: `ctx_idp` range-validated above; copy_to_user brackets
        // the 8-byte write with STAC/CLAC.
        if unsafe { copy_to_user(ctx_idp, &id.to_le_bytes()) }.is_err() {
            // Roll back the context we just minted so it doesn't leak.
            with_task_ctxs(tid, |m| {
                m.remove(&id);
            });
            ctx.set_return(SyscallReturn::ok(EFAULT as u64));
            return;
        }
        ctx.set_return(SyscallReturn::ok(0));
    }

    // ── io_destroy(aio_context_t ctx) ────────────────────────────────
    pub(super) fn sys_io_destroy(ctx: &mut dyn TrapContext) {
        let ctx_id = ctx.args().arg0;
        let tid = current_task_id();
        let removed = with_task_ctxs(tid, |m| m.remove(&ctx_id).is_some());
        if removed {
            ctx.set_return(SyscallReturn::ok(0));
        } else {
            ctx.set_return(SyscallReturn::ok(EINVAL as u64));
        }
    }

    // ── io_cancel(ctx, iocb *, io_event *result) ─────────────────────
    // Synchronous completions are already done → never cancellable.
    pub(super) fn sys_io_cancel(ctx: &mut dyn TrapContext) {
        ctx.set_return(SyscallReturn::ok(EINVAL as u64));
    }

    /// Positioned read: resolve `fd`, read `len` bytes at `offset` into a
    /// kernel buffer, then copy them to the user `buf`. Reuses the same
    /// fd-resolution + `FileOps::read` path as `sys_pread64`. Returns
    /// bytes read or -errno.
    fn do_pread(tid: u64, fd_no: u32, buf: u64, len: usize, offset: u64) -> i64 {
        if len == 0 {
            return 0;
        }
        if validate_user_range(buf, len).is_err() {
            return EFAULT;
        }
        if !fd::with_table(tid, |t| t.get(fd_no).is_some()).unwrap_or(false) {
            return EBADF;
        }
        let mut kbuf = alloc::vec![0u8; len];
        let outcome = fd::with_table(tid, |t| {
            let entry = t.get(fd_no)?;
            let ops = entry.ops.clone();
            poll_blocking(ops.read(offset, &mut kbuf))
                .unwrap_or(Err(narf_filesystem::FsError::ReadOnly))
                .ok()
        });
        match outcome {
            Some(Some(n)) => {
                // SAFETY: `buf` range-validated above; copy_to_user brackets it.
                if unsafe { copy_to_user(buf, &kbuf[..n]) }.is_err() {
                    EFAULT
                } else {
                    n as i64
                }
            }
            _ => EINVAL,
        }
    }

    /// Positioned write: reuses the `sys_pwrite64` fd-resolution +
    /// `FileOps::write` path. Returns bytes written or -errno.
    fn do_pwrite(tid: u64, fd_no: u32, buf: u64, len: usize, offset: u64) -> i64 {
        if len == 0 {
            return 0;
        }
        // SAFETY: single-threaded syscall; AS active. copy_from_user_vec
        // range-validates + brackets the read of the user source buffer.
        let kbuf = match unsafe { super::copy_from_user_vec(buf, len) } {
            Ok(b) => b,
            Err(_) => return EFAULT,
        };
        if !fd::with_table(tid, |t| t.get(fd_no).is_some()).unwrap_or(false) {
            return EBADF;
        }
        let outcome = fd::with_table(tid, |t| {
            let entry = t.get(fd_no)?;
            let ops = entry.ops.clone();
            poll_blocking(ops.write(offset, &kbuf))
                .unwrap_or(Err(narf_filesystem::FsError::ReadOnly))
                .ok()
        });
        match outcome {
            Some(Some(n)) => n as i64,
            _ => EINVAL,
        }
    }

    /// Vectored positioned read/write over a user iovec array. Mirrors the
    /// `preadv_pwritev` loop but drives it off explicit args (the AIO iocb
    /// carries the iovec base in `aio_buf` and the count in `aio_nbytes`).
    fn do_preadv_pwritev(
        tid: u64,
        fd_no: u32,
        iov_ptr: u64,
        iovcnt: usize,
        mut off: u64,
        is_write: bool,
    ) -> i64 {
        const IOV_MAX: usize = 1024;
        if iovcnt > IOV_MAX {
            return EINVAL;
        }
        if iovcnt == 0 {
            return 0;
        }
        if !fd::with_table(tid, |t| t.get(fd_no).is_some()).unwrap_or(false) {
            return EBADF;
        }
        // SAFETY: single-threaded syscall; copy_from_user_vec validates
        // + brackets the iovec array (16 bytes each).
        let iov_buf = match unsafe { super::copy_from_user_vec(iov_ptr, iovcnt.saturating_mul(16)) }
        {
            Ok(b) => b,
            Err(_) => return EFAULT,
        };
        let mut total: usize = 0;
        for i in 0..iovcnt {
            let o = i * 16;
            let base = u64::from_le_bytes(iov_buf[o..o + 8].try_into().unwrap());
            let len = u64::from_le_bytes(iov_buf[o + 8..o + 16].try_into().unwrap()) as usize;
            if len == 0 {
                continue;
            }
            let done = if is_write {
                do_pwrite(tid, fd_no, base, len, off)
            } else {
                do_pread(tid, fd_no, base, len, off)
            };
            if done < 0 {
                if total == 0 {
                    return done;
                }
                break;
            }
            let n = done as usize;
            total = total.saturating_add(n);
            off = off.saturating_add(n as u64);
            if n < len {
                break; // short transfer / EOF
            }
        }
        total as i64
    }

    /// If the iocb requested eventfd completion notification
    /// (`IOCB_FLAG_RESFD`), bump the `aio_resfd` eventfd by 1 by writing an
    /// 8-byte counter increment through its `FileOps::write` — the same
    /// path a userspace `write(efd, &1u64, 8)` takes. Silently ignored if
    /// the fd isn't open.
    fn signal_resfd(tid: u64, iocb: &Iocb) {
        if iocb.aio_flags & IOCB_FLAG_RESFD == 0 {
            return;
        }
        let one = 1u64.to_le_bytes();
        let _ = fd::with_table(tid, |t| {
            let entry = t.get(iocb.aio_resfd)?;
            let ops = entry.ops.clone();
            poll_blocking(ops.write(0, &one))
        });
    }

    /// Execute one decoded iocb synchronously; return its `res` (bytes or
    /// -errno). NOOP/FSYNC/FDSYNC succeed (in-memory FS has nothing to
    /// flush; the fd is still validated for FSYNC/FDSYNC).
    fn execute_iocb(tid: u64, iocb: &Iocb) -> i64 {
        match iocb.aio_lio_opcode {
            IOCB_CMD_PREAD => do_pread(
                tid,
                iocb.aio_fildes,
                iocb.aio_buf,
                iocb.aio_nbytes as usize,
                iocb.aio_offset as u64,
            ),
            IOCB_CMD_PWRITE => do_pwrite(
                tid,
                iocb.aio_fildes,
                iocb.aio_buf,
                iocb.aio_nbytes as usize,
                iocb.aio_offset as u64,
            ),
            IOCB_CMD_PREADV => do_preadv_pwritev(
                tid,
                iocb.aio_fildes,
                iocb.aio_buf,
                iocb.aio_nbytes as usize,
                iocb.aio_offset as u64,
                false,
            ),
            IOCB_CMD_PWRITEV => do_preadv_pwritev(
                tid,
                iocb.aio_fildes,
                iocb.aio_buf,
                iocb.aio_nbytes as usize,
                iocb.aio_offset as u64,
                true,
            ),
            IOCB_CMD_FSYNC | IOCB_CMD_FDSYNC => {
                // In-memory FS: nothing to flush. Success for a valid fd,
                // -EBADF otherwise (matches sys_fsync).
                if fd::with_table(tid, |t| t.get(iocb.aio_fildes).is_some()).unwrap_or(false) {
                    0
                } else {
                    EBADF
                }
            }
            IOCB_CMD_NOOP => 0,
            _ => EINVAL,
        }
    }

    // ── io_submit(ctx, long nr, iocb **iocbpp) ───────────────────────
    pub(super) fn sys_io_submit(ctx: &mut dyn TrapContext) {
        let args = *ctx.args();
        let ctx_id = args.arg0;
        let nr = args.arg1 as i64;
        let iocbpp = args.arg2;
        let tid = current_task_id();

        // Unknown context → -EINVAL.
        let known = with_task_ctxs(tid, |m| m.contains_key(&ctx_id));
        if !known {
            ctx.set_return(SyscallReturn::ok(EINVAL as u64));
            return;
        }
        if !(0..=AIO_RING_MAX).contains(&nr) {
            ctx.set_return(SyscallReturn::ok(EINVAL as u64));
            return;
        }
        if nr == 0 {
            ctx.set_return(SyscallReturn::ok(0));
            return;
        }

        // The user pointer array is `nr` little-endian u64 pointers.
        // SAFETY: copy_from_user_vec validates + brackets the array read.
        let ptr_bytes = match unsafe { super::copy_from_user_vec(iocbpp, (nr as usize) * 8) } {
            Ok(b) => b,
            Err(_) => {
                ctx.set_return(SyscallReturn::ok(EFAULT as u64));
                return;
            }
        };

        let mut submitted: i64 = 0;
        let mut pending: Vec<Completion> = Vec::new();
        for i in 0..(nr as usize) {
            let uptr = u64::from_le_bytes(ptr_bytes[i * 8..i * 8 + 8].try_into().unwrap());

            // Read the 64-byte iocb body.
            let mut iocb_bytes = [0u8; IOCB_SIZE];
            // SAFETY: copy_from_user range-validates `uptr` + brackets the read.
            if unsafe { copy_from_user(&mut iocb_bytes, uptr) }.is_err() {
                // Linux: return the count submitted so far, or -errno if
                // the very first iocb fails.
                if submitted == 0 {
                    ctx.set_return(SyscallReturn::ok(EFAULT as u64));
                    return;
                }
                break;
            }
            let iocb = decode_iocb(&iocb_bytes);

            // Execute synchronously; a bad fd is NOT a syscall error — it
            // surfaces as io_event.res = -EBADF.
            let res = execute_iocb(tid, &iocb);
            signal_resfd(tid, &iocb);

            pending.push(Completion {
                data: iocb.aio_data,
                obj: uptr,
                res,
            });
            submitted += 1;
        }

        // Stage all completions on the context queue.
        with_task_ctxs(tid, |m| {
            if let Some(c) = m.get_mut(&ctx_id) {
                for comp in pending {
                    c.completions.push_back(comp);
                }
            }
        });

        ctx.set_return(SyscallReturn::ok(submitted as u64));
    }

    // ── io_getevents(ctx, min_nr, nr, io_event *events, timespec *) ──
    pub(super) fn sys_io_getevents(ctx: &mut dyn TrapContext) {
        let args = *ctx.args();
        let ctx_id = args.arg0;
        let _min_nr = args.arg1 as i64;
        let nr = args.arg2 as i64;
        let events_ptr = args.arg3;
        // arg4 = timespec* timeout — ignored: completions are synchronous
        // so events are already queued; we never need to block. This is the
        // documented cooperative simplification (return available count).
        let tid = current_task_id();

        // Unknown context → -EINVAL.
        let known = with_task_ctxs(tid, |m| m.contains_key(&ctx_id));
        if !known {
            ctx.set_return(SyscallReturn::ok(EINVAL as u64));
            return;
        }
        if nr < 0 {
            ctx.set_return(SyscallReturn::ok(EINVAL as u64));
            return;
        }
        if nr == 0 {
            ctx.set_return(SyscallReturn::ok(0));
            return;
        }
        if events_ptr == 0
            || validate_user_range(events_ptr, (nr as usize) * IO_EVENT_SIZE).is_err()
        {
            ctx.set_return(SyscallReturn::ok(EFAULT as u64));
            return;
        }

        // Drain up to `nr` completions. We copy each 32-byte io_event out
        // individually so a mid-array EFAULT only loses that event.
        let mut count: i64 = 0;
        for slot in 0..(nr as usize) {
            let comp = with_task_ctxs(tid, |m| {
                m.get_mut(&ctx_id).and_then(|c| c.completions.pop_front())
            });
            let comp = match comp {
                Some(c) => c,
                None => break, // queue drained
            };
            let ev = encode_event(comp.data, comp.obj, comp.res, 0);
            let dst = events_ptr + (slot as u64) * IO_EVENT_SIZE as u64;
            // SAFETY: `events_ptr` range-validated above for the whole
            // array; copy_to_user brackets each 32-byte write.
            if unsafe { copy_to_user(dst, &ev) }.is_err() {
                // Re-queue the popped completion at the front so it isn't
                // lost, then stop.
                with_task_ctxs(tid, |m| {
                    if let Some(c) = m.get_mut(&ctx_id) {
                        c.completions.push_front(comp);
                    }
                });
                break;
            }
            count += 1;
        }
        ctx.set_return(SyscallReturn::ok(count as u64));
    }
}

// ── per-syscall handlers (auto-split from handlers.rs) ──
#[path = "sys_access_chmod_chown.rs"]
mod handler_sys_access_chmod_chown;
#[path = "sys_adjtimex.rs"]
mod handler_sys_adjtimex;
#[path = "sys_arch_prctl.rs"]
mod handler_sys_arch_prctl;
#[path = "sys_at2_reshape.rs"]
mod handler_sys_at2_reshape;
#[path = "sys_bootstrap.rs"]
mod handler_sys_bootstrap;
#[path = "sys_bpf.rs"]
mod handler_sys_bpf;
#[path = "sys_bpf_attach.rs"]
mod handler_sys_bpf_attach;
#[path = "sys_bpf_btf.rs"]
mod handler_sys_bpf_btf;
#[path = "sys_bpf_info.rs"]
mod handler_sys_bpf_info;
#[path = "sys_bpf_pin.rs"]
mod handler_sys_bpf_pin;
#[path = "sys_brk.rs"]
mod handler_sys_brk;
#[path = "sys_capget.rs"]
mod handler_sys_capget;
#[path = "sys_capset.rs"]
mod handler_sys_capset;
#[path = "sys_chdir.rs"]
mod handler_sys_chdir;
#[path = "sys_chdir_for_test.rs"]
mod handler_sys_chdir_for_test;
#[path = "sys_chmod.rs"]
mod handler_sys_chmod;
#[path = "sys_chroot.rs"]
mod handler_sys_chroot;
#[path = "sys_chroot_for_test.rs"]
mod handler_sys_chroot_for_test;
#[path = "sys_clock_adjtime.rs"]
mod handler_sys_clock_adjtime;
#[path = "sys_clock_getres.rs"]
mod handler_sys_clock_getres;
#[path = "sys_clock_gettime.rs"]
mod handler_sys_clock_gettime;
#[path = "sys_clock_settime.rs"]
mod handler_sys_clock_settime;
#[path = "sys_clone.rs"]
mod handler_sys_clone;
#[path = "sys_clone3.rs"]
mod handler_sys_clone3;
#[path = "sys_close.rs"]
mod handler_sys_close;
#[path = "sys_close_range.rs"]
mod handler_sys_close_range;
#[path = "sys_copy_file_range.rs"]
mod handler_sys_copy_file_range;
#[path = "sys_creat.rs"]
mod handler_sys_creat;
#[path = "sys_delete_module.rs"]
mod handler_sys_delete_module;
#[path = "sys_dup.rs"]
mod handler_sys_dup;
#[path = "sys_dup2.rs"]
mod handler_sys_dup2;
#[path = "sys_dup3.rs"]
mod handler_sys_dup3;
#[path = "sys_epoll_create.rs"]
mod handler_sys_epoll_create;
#[path = "sys_epoll_ctl.rs"]
mod handler_sys_epoll_ctl;
#[path = "sys_epoll_wait.rs"]
mod handler_sys_epoll_wait;
#[path = "sys_eventfd.rs"]
mod handler_sys_eventfd;
#[path = "sys_execve.rs"]
mod handler_sys_execve;
#[path = "sys_execveat.rs"]
mod handler_sys_execveat;
#[path = "sys_exit_group.rs"]
mod handler_sys_exit_group;
#[path = "sys_exit_task.rs"]
mod handler_sys_exit_task;
#[path = "sys_fadvise64.rs"]
mod handler_sys_fadvise64;
#[path = "sys_fallocate.rs"]
mod handler_sys_fallocate;
#[path = "sys_fb_connect.rs"]
mod handler_sys_fb_connect;
#[path = "sys_fb_disconnect.rs"]
mod handler_sys_fb_disconnect;
#[path = "sys_fb_flush_wait.rs"]
mod handler_sys_fb_flush_wait;
#[path = "sys_fb_info.rs"]
mod handler_sys_fb_info;
#[path = "sys_fb_ring_map.rs"]
mod handler_sys_fb_ring_map;
#[path = "sys_fchdir.rs"]
mod handler_sys_fchdir;
#[path = "sys_fchmod_or_fchown.rs"]
mod handler_sys_fchmod_or_fchown;
#[path = "sys_fchmodat.rs"]
mod handler_sys_fchmodat;
#[path = "sys_fchmodat_or_fchownat.rs"]
mod handler_sys_fchmodat_or_fchownat;
#[path = "sys_fcntl.rs"]
mod handler_sys_fcntl;
#[path = "sys_fgetxattr.rs"]
mod handler_sys_fgetxattr;
#[path = "sys_finit_module.rs"]
mod handler_sys_finit_module;
#[path = "sys_firmware_install.rs"]
mod handler_sys_firmware_install;
#[path = "sys_flistxattr.rs"]
mod handler_sys_flistxattr;
#[path = "sys_flock.rs"]
mod handler_sys_flock;
#[path = "sys_fork.rs"]
mod handler_sys_fork;
#[path = "sys_fremovexattr.rs"]
mod handler_sys_fremovexattr;
#[path = "sys_fsetxattr.rs"]
mod handler_sys_fsetxattr;
#[path = "sys_fstat.rs"]
mod handler_sys_fstat;
#[path = "sys_fstat_linux.rs"]
mod handler_sys_fstat_linux;
#[path = "sys_fstatfs.rs"]
mod handler_sys_fstatfs;
#[path = "sys_fsync.rs"]
mod handler_sys_fsync;
#[path = "sys_ftruncate.rs"]
mod handler_sys_ftruncate;
#[path = "sys_futex.rs"]
mod handler_sys_futex;
#[path = "sys_futex_requeue.rs"]
mod handler_sys_futex_requeue;
#[path = "sys_futex_wait.rs"]
mod handler_sys_futex_wait;
#[path = "sys_futex_waitv.rs"]
mod handler_sys_futex_waitv;
#[path = "sys_futex_wake.rs"]
mod handler_sys_futex_wake;
#[path = "sys_futimesat.rs"]
mod handler_sys_futimesat;
#[path = "sys_get_mempolicy.rs"]
mod handler_sys_get_mempolicy;
#[path = "sys_get_robust_list.rs"]
mod handler_sys_get_robust_list;
#[path = "sys_getcpu.rs"]
mod handler_sys_getcpu;
#[path = "sys_getcwd.rs"]
mod handler_sys_getcwd;
#[path = "sys_getdents.rs"]
mod handler_sys_getdents;
#[path = "sys_getdents64.rs"]
mod handler_sys_getdents64;
#[path = "sys_getegid.rs"]
mod handler_sys_getegid;
#[path = "sys_geteuid.rs"]
mod handler_sys_geteuid;
#[path = "sys_getgid.rs"]
mod handler_sys_getgid;
#[path = "sys_getgroups.rs"]
mod handler_sys_getgroups;
#[path = "sys_gethostname.rs"]
mod handler_sys_gethostname;
#[path = "sys_getpgid.rs"]
mod handler_sys_getpgid;
#[path = "sys_getpgrp.rs"]
mod handler_sys_getpgrp;
#[path = "sys_getpid.rs"]
mod handler_sys_getpid;
#[path = "sys_getppid.rs"]
mod handler_sys_getppid;
#[path = "sys_getpriority.rs"]
mod handler_sys_getpriority;
#[path = "sys_getrandom.rs"]
mod handler_sys_getrandom;
#[path = "sys_getresgid.rs"]
mod handler_sys_getresgid;
#[path = "sys_getresuid.rs"]
mod handler_sys_getresuid;
#[path = "sys_getrlimit.rs"]
mod handler_sys_getrlimit;
#[path = "sys_getrusage.rs"]
mod handler_sys_getrusage;
#[path = "sys_getsid.rs"]
mod handler_sys_getsid;
#[path = "sys_gettid.rs"]
mod handler_sys_gettid;
#[path = "sys_gettimeofday.rs"]
mod handler_sys_gettimeofday;
#[path = "sys_getuid.rs"]
mod handler_sys_getuid;
#[path = "sys_getxattr.rs"]
mod handler_sys_getxattr;
#[path = "sys_init_module.rs"]
mod handler_sys_init_module;
#[path = "sys_ioctl.rs"]
mod handler_sys_ioctl;
#[path = "sys_ioprio_get.rs"]
mod handler_sys_ioprio_get;
#[path = "sys_ioprio_set.rs"]
mod handler_sys_ioprio_set;
#[path = "sys_kcmp.rs"]
mod handler_sys_kcmp;
#[path = "sys_kill.rs"]
mod handler_sys_kill;
#[path = "sys_link.rs"]
mod handler_sys_link;
#[path = "sys_linkat.rs"]
mod handler_sys_linkat;
#[path = "sys_listdir.rs"]
mod handler_sys_listdir;
#[path = "sys_listxattr.rs"]
mod handler_sys_listxattr;
#[path = "sys_lseek.rs"]
mod handler_sys_lseek;
#[path = "sys_lstat_linux.rs"]
mod handler_sys_lstat_linux;
#[path = "sys_madvise.rs"]
mod handler_sys_madvise;
#[path = "sys_mbind.rs"]
mod handler_sys_mbind;
#[path = "sys_membarrier.rs"]
mod handler_sys_membarrier;
#[path = "sys_memfd_create.rs"]
mod handler_sys_memfd_create;
#[path = "sys_memfd_secret.rs"]
mod handler_sys_memfd_secret;
#[path = "sys_migrate_pages.rs"]
mod handler_sys_migrate_pages;
#[path = "sys_mincore.rs"]
mod handler_sys_mincore;
#[path = "sys_mkdir.rs"]
mod handler_sys_mkdir;
#[path = "sys_mkdirat.rs"]
mod handler_sys_mkdirat;
#[path = "sys_mknod.rs"]
mod handler_sys_mknod;
#[path = "sys_mknodat.rs"]
mod handler_sys_mknodat;
#[path = "sys_mlock.rs"]
mod handler_sys_mlock;
#[path = "sys_mlock2.rs"]
mod handler_sys_mlock2;
#[path = "sys_mlockall.rs"]
mod handler_sys_mlockall;
#[path = "sys_mmap.rs"]
mod handler_sys_mmap;
#[path = "sys_mount.rs"]
mod handler_sys_mount;
#[path = "sys_mount_for_test.rs"]
mod handler_sys_mount_for_test;
#[path = "sys_move_pages.rs"]
mod handler_sys_move_pages;
#[path = "sys_mprotect.rs"]
mod handler_sys_mprotect;
#[path = "sys_mremap.rs"]
mod handler_sys_mremap;
#[path = "sys_msgget.rs"]
mod handler_sys_msgget;
#[path = "sys_msync.rs"]
mod handler_sys_msync;
#[path = "sys_munlock.rs"]
mod handler_sys_munlock;
#[path = "sys_munlockall.rs"]
mod handler_sys_munlockall;
#[path = "sys_munmap.rs"]
mod handler_sys_munmap;
#[path = "sys_name_to_handle_at.rs"]
mod handler_sys_name_to_handle_at;
#[path = "sys_newfstatat.rs"]
mod handler_sys_newfstatat;
#[path = "sys_newfstatat_linux.rs"]
mod handler_sys_newfstatat_linux;
#[path = "sys_noop_ok.rs"]
mod handler_sys_noop_ok;
#[path = "sys_open.rs"]
mod handler_sys_open;
#[path = "sys_open_by_handle_at.rs"]
mod handler_sys_open_by_handle_at;
#[path = "sys_open_linux.rs"]
mod handler_sys_open_linux;
#[path = "sys_openat.rs"]
pub(crate) mod handler_sys_openat;
#[path = "sys_openat2.rs"]
mod handler_sys_openat2;
#[path = "sys_pause.rs"]
mod handler_sys_pause;
#[path = "sys_personality.rs"]
mod handler_sys_personality;
#[path = "sys_pidfd_getfd.rs"]
mod handler_sys_pidfd_getfd;
#[path = "sys_pidfd_open.rs"]
mod handler_sys_pidfd_open;
#[path = "sys_pidfd_send_signal.rs"]
mod handler_sys_pidfd_send_signal;
#[path = "sys_pipe.rs"]
mod handler_sys_pipe;
#[path = "sys_pipe2.rs"]
mod handler_sys_pipe2;
#[path = "sys_pivot_root.rs"]
mod handler_sys_pivot_root;
#[path = "sys_pivot_root_for_test.rs"]
mod handler_sys_pivot_root_for_test;
#[path = "sys_pkey_alloc.rs"]
mod handler_sys_pkey_alloc;
#[path = "sys_pkey_free.rs"]
mod handler_sys_pkey_free;
#[path = "sys_pkey_mprotect.rs"]
mod handler_sys_pkey_mprotect;
#[path = "sys_poll.rs"]
mod handler_sys_poll;
#[path = "sys_prctl.rs"]
mod handler_sys_prctl;
#[path = "sys_pread64.rs"]
mod handler_sys_pread64;
#[path = "sys_preadv.rs"]
mod handler_sys_preadv;
#[path = "sys_preadv2.rs"]
mod handler_sys_preadv2;
#[path = "sys_prlimit64.rs"]
mod handler_sys_prlimit64;
#[path = "sys_process_madvise.rs"]
mod handler_sys_process_madvise;
#[path = "sys_process_vm_readv.rs"]
mod handler_sys_process_vm_readv;
#[path = "sys_process_vm_writev.rs"]
mod handler_sys_process_vm_writev;
#[path = "sys_ptrace.rs"]
mod handler_sys_ptrace;
#[path = "sys_pwrite64.rs"]
mod handler_sys_pwrite64;
#[path = "sys_pwritev.rs"]
mod handler_sys_pwritev;
#[path = "sys_pwritev2.rs"]
mod handler_sys_pwritev2;
#[path = "sys_quotactl.rs"]
mod handler_sys_quotactl;
#[path = "sys_read.rs"]
mod handler_sys_read;
#[path = "sys_readahead.rs"]
mod handler_sys_readahead;
#[path = "sys_readlink.rs"]
mod handler_sys_readlink;
#[path = "sys_readlinkat.rs"]
mod handler_sys_readlinkat;
#[path = "sys_readv.rs"]
mod handler_sys_readv;
#[path = "sys_reboot.rs"]
mod handler_sys_reboot;
#[path = "sys_removexattr.rs"]
mod handler_sys_removexattr;
#[path = "sys_rename.rs"]
mod handler_sys_rename;
#[path = "sys_renameat.rs"]
mod handler_sys_renameat;
#[path = "sys_renameat2.rs"]
mod handler_sys_renameat2;
#[path = "sys_restart_syscall.rs"]
mod handler_sys_restart_syscall;
#[path = "sys_ring_kick.rs"]
mod handler_sys_ring_kick;
#[path = "sys_rmdir.rs"]
mod handler_sys_rmdir;
#[path = "sys_rseq.rs"]
mod handler_sys_rseq;
#[path = "sys_rt_sigaction.rs"]
mod handler_sys_rt_sigaction;
#[path = "sys_rt_sigpending.rs"]
mod handler_sys_rt_sigpending;
#[path = "sys_rt_sigqueueinfo.rs"]
mod handler_sys_rt_sigqueueinfo;
#[path = "sys_rt_sigsuspend.rs"]
mod handler_sys_rt_sigsuspend;
#[path = "sys_rt_sigtimedwait.rs"]
mod handler_sys_rt_sigtimedwait;
#[path = "sys_rt_tgsigqueueinfo.rs"]
mod handler_sys_rt_tgsigqueueinfo;
#[path = "sys_sched_get_priority_max.rs"]
mod handler_sys_sched_get_priority_max;
#[path = "sys_sched_get_priority_min.rs"]
mod handler_sys_sched_get_priority_min;
#[path = "sys_sched_getaffinity.rs"]
mod handler_sys_sched_getaffinity;
#[path = "sys_sched_getattr.rs"]
mod handler_sys_sched_getattr;
#[path = "sys_sched_getparam.rs"]
mod handler_sys_sched_getparam;
#[path = "sys_sched_getscheduler.rs"]
mod handler_sys_sched_getscheduler;
#[path = "sys_sched_rr_get_interval.rs"]
mod handler_sys_sched_rr_get_interval;
#[path = "sys_sched_setaffinity.rs"]
mod handler_sys_sched_setaffinity;
#[path = "sys_sched_setattr.rs"]
mod handler_sys_sched_setattr;
#[path = "sys_sched_setparam.rs"]
mod handler_sys_sched_setparam;
#[path = "sys_sched_setscheduler.rs"]
mod handler_sys_sched_setscheduler;
#[path = "sys_seccomp.rs"]
mod handler_sys_seccomp;
#[path = "sys_semget.rs"]
mod handler_sys_semget;
#[path = "sys_sendfile.rs"]
mod handler_sys_sendfile;
#[path = "sys_set_mempolicy.rs"]
mod handler_sys_set_mempolicy;
#[path = "sys_set_mempolicy_home_node.rs"]
mod handler_sys_set_mempolicy_home_node;
#[path = "sys_set_robust_list.rs"]
mod handler_sys_set_robust_list;
#[path = "sys_set_tid_address.rs"]
mod handler_sys_set_tid_address;
#[path = "sys_setdomainname.rs"]
mod handler_sys_setdomainname;
#[path = "sys_setfsgid.rs"]
mod handler_sys_setfsgid;
#[path = "sys_setfsuid.rs"]
mod handler_sys_setfsuid;
#[path = "sys_setgid.rs"]
mod handler_sys_setgid;
#[path = "sys_setgroups.rs"]
mod handler_sys_setgroups;
#[path = "sys_sethostname.rs"]
mod handler_sys_sethostname;
#[path = "sys_setns.rs"]
mod handler_sys_setns;
#[path = "sys_setpgid.rs"]
mod handler_sys_setpgid;
#[path = "sys_setpriority.rs"]
mod handler_sys_setpriority;
#[path = "sys_setregid.rs"]
mod handler_sys_setregid;
#[path = "sys_setresgid.rs"]
mod handler_sys_setresgid;
#[path = "sys_setresuid.rs"]
mod handler_sys_setresuid;
#[path = "sys_setreuid.rs"]
mod handler_sys_setreuid;
#[path = "sys_setrlimit.rs"]
mod handler_sys_setrlimit;
#[path = "sys_setsid.rs"]
mod handler_sys_setsid;
#[path = "sys_settimeofday.rs"]
mod handler_sys_settimeofday;
#[path = "sys_setuid.rs"]
mod handler_sys_setuid;
#[path = "sys_setxattr.rs"]
mod handler_sys_setxattr;
#[path = "sys_shmat.rs"]
mod handler_sys_shmat;
#[path = "sys_shmctl.rs"]
mod handler_sys_shmctl;
#[path = "sys_shmdt.rs"]
mod handler_sys_shmdt;
#[path = "sys_shmem_create.rs"]
mod handler_sys_shmem_create;
#[path = "sys_shmem_destroy.rs"]
mod handler_sys_shmem_destroy;
#[path = "sys_shmem_map.rs"]
mod handler_sys_shmem_map;
#[path = "sys_shmget.rs"]
mod handler_sys_shmget;
#[path = "sys_shmget_compat.rs"]
mod handler_sys_shmget_compat;
#[path = "sys_sigaction.rs"]
mod handler_sys_sigaction;
#[path = "sys_sigaltstack.rs"]
mod handler_sys_sigaltstack;
#[path = "sys_signalfd.rs"]
mod handler_sys_signalfd;
#[path = "sys_sigprocmask.rs"]
mod handler_sys_sigprocmask;
#[path = "sys_sigreturn.rs"]
mod handler_sys_sigreturn;
#[path = "sys_sleep.rs"]
mod handler_sys_sleep;
#[path = "sys_sock_register_buf.rs"]
mod handler_sys_sock_register_buf;
#[path = "sys_sock_send_zc.rs"]
mod handler_sys_sock_send_zc;
#[path = "sys_socket.rs"]
mod handler_sys_socket;
#[path = "sys_socket_accept.rs"]
mod handler_sys_socket_accept;
#[path = "sys_socket_accept4.rs"]
mod handler_sys_socket_accept4;
#[path = "sys_socket_bind.rs"]
mod handler_sys_socket_bind;
#[path = "sys_socket_connect.rs"]
mod handler_sys_socket_connect;
#[path = "sys_socket_get_addr.rs"]
mod handler_sys_socket_get_addr;
#[path = "sys_socket_getpeername.rs"]
mod handler_sys_socket_getpeername;
#[path = "sys_socket_getsockname.rs"]
mod handler_sys_socket_getsockname;
#[path = "sys_socket_getsockopt.rs"]
mod handler_sys_socket_getsockopt;
#[path = "sys_socket_listen.rs"]
mod handler_sys_socket_listen;
#[path = "sys_socket_recv.rs"]
mod handler_sys_socket_recv;
#[path = "sys_socket_recvmmsg.rs"]
mod handler_sys_socket_recvmmsg;
#[path = "sys_socket_recvmsg.rs"]
mod handler_sys_socket_recvmsg;
#[path = "sys_socket_send.rs"]
mod handler_sys_socket_send;
#[path = "sys_socket_sendmmsg.rs"]
mod handler_sys_socket_sendmmsg;
#[path = "sys_socket_sendmsg.rs"]
mod handler_sys_socket_sendmsg;
#[path = "sys_socket_setsockopt.rs"]
mod handler_sys_socket_setsockopt;
#[path = "sys_socket_shutdown.rs"]
mod handler_sys_socket_shutdown;
#[path = "sys_socketpair.rs"]
mod handler_sys_socketpair;
#[path = "sys_splice.rs"]
mod handler_sys_splice;
#[path = "sys_stat.rs"]
mod handler_sys_stat;
#[path = "sys_stat_linux.rs"]
mod handler_sys_stat_linux;
#[path = "sys_statfs.rs"]
mod handler_sys_statfs;
#[path = "sys_statx.rs"]
mod handler_sys_statx;
#[path = "sys_symlink.rs"]
mod handler_sys_symlink;
#[path = "sys_symlinkat.rs"]
mod handler_sys_symlinkat;
#[path = "sys_sync.rs"]
mod handler_sys_sync;
#[path = "sys_sync_file_range.rs"]
mod handler_sys_sync_file_range;
#[path = "sys_syncfs.rs"]
mod handler_sys_syncfs;
#[path = "sys_sysinfo.rs"]
mod handler_sys_sysinfo;
#[path = "sys_tcgetattr.rs"]
mod handler_sys_tcgetattr;
#[path = "sys_tcsetattr.rs"]
mod handler_sys_tcsetattr;
#[path = "sys_tee.rs"]
mod handler_sys_tee;
#[path = "sys_tgkill.rs"]
mod handler_sys_tgkill;
#[path = "sys_time.rs"]
mod handler_sys_time;
#[path = "sys_timerfd_create.rs"]
mod handler_sys_timerfd_create;
#[path = "sys_timerfd_gettime.rs"]
mod handler_sys_timerfd_gettime;
#[path = "sys_timerfd_settime.rs"]
mod handler_sys_timerfd_settime;
#[path = "sys_times.rs"]
mod handler_sys_times;
#[path = "sys_tkill.rs"]
mod handler_sys_tkill;
#[path = "sys_truncate.rs"]
mod handler_sys_truncate;
#[path = "sys_umask.rs"]
mod handler_sys_umask;
#[path = "sys_umount2.rs"]
mod handler_sys_umount2;
#[path = "sys_umount2_for_test.rs"]
mod handler_sys_umount2_for_test;
#[path = "sys_uname.rs"]
mod handler_sys_uname;
#[path = "sys_unlink.rs"]
mod handler_sys_unlink;
#[path = "sys_unlinkat.rs"]
mod handler_sys_unlinkat;
#[path = "sys_unshare.rs"]
mod handler_sys_unshare;
#[path = "sys_utime.rs"]
mod handler_sys_utime;
#[path = "sys_utimensat.rs"]
mod handler_sys_utimensat;
#[path = "sys_utimes.rs"]
mod handler_sys_utimes;
#[path = "sys_vhangup.rs"]
mod handler_sys_vhangup;
#[path = "sys_vmsplice.rs"]
mod handler_sys_vmsplice;
#[path = "sys_wait4.rs"]
mod handler_sys_wait4;
#[path = "sys_waitid.rs"]
mod handler_sys_waitid;
#[path = "sys_write.rs"]
mod handler_sys_write;
#[path = "sys_writev.rs"]
mod handler_sys_writev;
#[path = "sys_yield.rs"]
mod handler_sys_yield;

#[allow(unused_imports)]
pub(crate) use handler_sys_arch_prctl::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_bpf::*;
pub(crate) use handler_sys_bpf_attach::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_bpf_btf::*;
pub(crate) use handler_sys_bpf_info::*;
pub(crate) use handler_sys_bpf_pin::*;
#[allow(unused_imports)]
pub use handler_sys_chdir_for_test::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_chroot::*;
pub use handler_sys_chroot_for_test::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_clone::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_clone3::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_fstat_linux::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_lstat_linux::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_madvise::*;
#[allow(unused_imports)]
pub use handler_sys_mount_for_test::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_msgget::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_name_to_handle_at::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_newfstatat_linux::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_open_by_handle_at::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_pivot_root::*;
#[allow(unused_imports)]
pub use handler_sys_pivot_root_for_test::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_semget::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_set_tid_address::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_shmat::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_shmctl::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_shmdt::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_shmget::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_shmget_compat::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_stat_linux::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_statx::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_timerfd_gettime::*;
#[allow(unused_imports)]
pub use handler_sys_umount2_for_test::*;
#[allow(unused_imports)]
pub(crate) use {
    handler_sys_access_chmod_chown::{sys_access, sys_chown, sys_faccessat, sys_lchown},
    handler_sys_adjtimex::sys_adjtimex,
    handler_sys_at2_reshape::sys_at2_reshape,
    handler_sys_bootstrap::sys_bootstrap,
    handler_sys_brk::sys_brk,
    handler_sys_capget::sys_capget,
    handler_sys_capset::sys_capset,
    handler_sys_chdir::sys_chdir,
    handler_sys_chmod::sys_chmod,
    handler_sys_clock_adjtime::sys_clock_adjtime,
    handler_sys_clock_getres::sys_clock_getres,
    handler_sys_clock_gettime::sys_clock_gettime,
    handler_sys_clock_settime::sys_clock_settime,
    handler_sys_close::sys_close,
    handler_sys_close_range::sys_close_range,
    handler_sys_copy_file_range::sys_copy_file_range,
    handler_sys_creat::sys_creat,
    handler_sys_delete_module::sys_delete_module,
    handler_sys_dup::sys_dup,
    handler_sys_dup2::sys_dup2,
    handler_sys_dup3::sys_dup3,
    handler_sys_epoll_create::sys_epoll_create,
    handler_sys_epoll_ctl::sys_epoll_ctl,
    handler_sys_epoll_wait::sys_epoll_wait,
    handler_sys_eventfd::sys_eventfd,
    handler_sys_eventfd::sys_eventfd2,
    handler_sys_execve::sys_execve,
    handler_sys_execveat::sys_execveat,
    handler_sys_exit_group::sys_exit_group,
    handler_sys_exit_task::sys_exit_task,
    handler_sys_fadvise64::sys_fadvise64,
    handler_sys_fallocate::sys_fallocate,
    handler_sys_fb_connect::sys_fb_connect,
    handler_sys_fb_disconnect::sys_fb_disconnect,
    handler_sys_fb_flush_wait::sys_fb_flush_wait,
    handler_sys_fb_info::sys_fb_info,
    handler_sys_fb_ring_map::sys_fb_ring_map,
    handler_sys_fchdir::sys_fchdir,
    handler_sys_fchmod_or_fchown::{sys_fchmod, sys_fchown},
    handler_sys_fchmodat::{sys_fchmodat, sys_fchmodat2},
    handler_sys_fchmodat_or_fchownat::sys_fchmodat_or_fchownat,
    handler_sys_fcntl::sys_fcntl,
    handler_sys_fgetxattr::sys_fgetxattr,
    handler_sys_finit_module::sys_finit_module,
    handler_sys_firmware_install::sys_firmware_install,
    handler_sys_flistxattr::sys_flistxattr,
    handler_sys_flock::sys_flock,
    handler_sys_fork::sys_fork,
    handler_sys_fremovexattr::sys_fremovexattr,
    handler_sys_fsetxattr::sys_fsetxattr,
    handler_sys_fstat::sys_fstat,
    handler_sys_fstatfs::sys_fstatfs,
    handler_sys_fsync::{sys_fdatasync, sys_fsync},
    handler_sys_ftruncate::sys_ftruncate,
    handler_sys_futex::sys_futex,
    handler_sys_futex_requeue::sys_futex_requeue,
    handler_sys_futex_wait::sys_futex_wait,
    handler_sys_futex_waitv::sys_futex_waitv,
    handler_sys_futex_wake::sys_futex_wake,
    handler_sys_futimesat::sys_futimesat,
    handler_sys_get_mempolicy::sys_get_mempolicy,
    handler_sys_get_robust_list::sys_get_robust_list,
    handler_sys_getcpu::sys_getcpu,
    handler_sys_getcwd::sys_getcwd,
    handler_sys_getdents::sys_getdents,
    handler_sys_getdents64::sys_getdents64,
    handler_sys_getegid::sys_getegid,
    handler_sys_geteuid::sys_geteuid,
    handler_sys_getgid::sys_getgid,
    handler_sys_getgroups::sys_getgroups,
    handler_sys_gethostname::sys_gethostname,
    handler_sys_getpgid::sys_getpgid,
    handler_sys_getpgrp::sys_getpgrp,
    handler_sys_getpid::sys_getpid,
    handler_sys_getppid::sys_getppid,
    handler_sys_getpriority::sys_getpriority,
    handler_sys_getrandom::sys_getrandom,
    handler_sys_getresgid::sys_getresgid,
    handler_sys_getresuid::sys_getresuid,
    handler_sys_getrlimit::sys_getrlimit,
    handler_sys_getrusage::sys_getrusage,
    handler_sys_getsid::sys_getsid,
    handler_sys_gettid::sys_gettid,
    handler_sys_gettimeofday::sys_gettimeofday,
    handler_sys_getuid::sys_getuid,
    handler_sys_getxattr::sys_getxattr,
    handler_sys_init_module::sys_init_module,
    handler_sys_ioctl::sys_ioctl,
    handler_sys_ioprio_get::sys_ioprio_get,
    handler_sys_ioprio_set::sys_ioprio_set,
    handler_sys_kcmp::sys_kcmp,
    handler_sys_kill::sys_kill,
    handler_sys_link::sys_link,
    handler_sys_linkat::sys_linkat,
    handler_sys_listdir::sys_listdir,
    handler_sys_listxattr::sys_listxattr,
    handler_sys_lseek::sys_lseek,
    handler_sys_mbind::sys_mbind,
    handler_sys_membarrier::sys_membarrier,
    handler_sys_memfd_create::sys_memfd_create,
    handler_sys_memfd_secret::sys_memfd_secret,
    handler_sys_migrate_pages::sys_migrate_pages,
    handler_sys_mincore::sys_mincore,
    handler_sys_mkdir::sys_mkdir,
    handler_sys_mkdirat::sys_mkdirat,
    handler_sys_mknod::sys_mknod,
    handler_sys_mknodat::sys_mknodat,
    handler_sys_mlock::sys_mlock,
    handler_sys_mlock2::sys_mlock2,
    handler_sys_mlockall::sys_mlockall,
    handler_sys_mmap::sys_mmap,
    handler_sys_mount::sys_mount,
    handler_sys_move_pages::sys_move_pages,
    handler_sys_mprotect::sys_mprotect,
    handler_sys_mremap::sys_mremap,
    handler_sys_msync::sys_msync,
    handler_sys_munlock::sys_munlock,
    handler_sys_munlockall::sys_munlockall,
    handler_sys_munmap::sys_munmap,
    handler_sys_newfstatat::sys_newfstatat,
    handler_sys_noop_ok::sys_noop_ok,
    handler_sys_open::sys_open,
    handler_sys_open_linux::sys_open_linux,
    handler_sys_openat::sys_openat,
    handler_sys_openat2::sys_openat2,
    handler_sys_pause::sys_pause,
    handler_sys_personality::sys_personality,
    handler_sys_pidfd_getfd::sys_pidfd_getfd,
    handler_sys_pidfd_open::sys_pidfd_open,
    handler_sys_pidfd_send_signal::sys_pidfd_send_signal,
    handler_sys_pipe::sys_pipe,
    handler_sys_pipe2::sys_pipe2,
    handler_sys_pkey_alloc::sys_pkey_alloc,
    handler_sys_pkey_free::sys_pkey_free,
    handler_sys_pkey_mprotect::sys_pkey_mprotect,
    handler_sys_poll::sys_poll,
    handler_sys_prctl::sys_prctl,
    handler_sys_pread64::sys_pread64,
    handler_sys_preadv::sys_preadv,
    handler_sys_preadv2::sys_preadv2,
    handler_sys_prlimit64::sys_prlimit64,
    handler_sys_process_madvise::sys_process_madvise,
    handler_sys_process_vm_readv::sys_process_vm_readv,
    handler_sys_process_vm_writev::sys_process_vm_writev,
    handler_sys_ptrace::sys_ptrace,
    handler_sys_pwrite64::sys_pwrite64,
    handler_sys_pwritev::sys_pwritev,
    handler_sys_pwritev2::sys_pwritev2,
    handler_sys_quotactl::sys_quotactl,
    handler_sys_read::sys_read,
    handler_sys_readahead::sys_readahead,
    handler_sys_readlink::sys_readlink,
    handler_sys_readlinkat::sys_readlinkat,
    handler_sys_readv::sys_readv,
    handler_sys_reboot::sys_reboot,
    handler_sys_removexattr::sys_removexattr,
    handler_sys_rename::{rename_absolute, sys_rename},
    handler_sys_renameat::sys_renameat,
    handler_sys_renameat2::sys_renameat2,
    handler_sys_restart_syscall::sys_restart_syscall,
    handler_sys_ring_kick::sys_ring_kick,
    handler_sys_rmdir::{rmdir_absolute, sys_rmdir},
    handler_sys_rseq::sys_rseq,
    handler_sys_rt_sigaction::sys_rt_sigaction,
    handler_sys_rt_sigpending::sys_rt_sigpending,
    handler_sys_rt_sigqueueinfo::sys_rt_sigqueueinfo,
    handler_sys_rt_sigsuspend::sys_rt_sigsuspend,
    handler_sys_rt_sigtimedwait::sys_rt_sigtimedwait,
    handler_sys_rt_tgsigqueueinfo::sys_rt_tgsigqueueinfo,
    handler_sys_sched_get_priority_max::sys_sched_get_priority_max,
    handler_sys_sched_get_priority_min::sys_sched_get_priority_min,
    handler_sys_sched_getaffinity::sys_sched_getaffinity,
    handler_sys_sched_getattr::sys_sched_getattr,
    handler_sys_sched_getparam::sys_sched_getparam,
    handler_sys_sched_getscheduler::sys_sched_getscheduler,
    handler_sys_sched_rr_get_interval::sys_sched_rr_get_interval,
    handler_sys_sched_setaffinity::sys_sched_setaffinity,
    handler_sys_sched_setattr::sys_sched_setattr,
    handler_sys_sched_setparam::sys_sched_setparam,
    handler_sys_sched_setscheduler::sys_sched_setscheduler,
    handler_sys_seccomp::sys_seccomp,
    handler_sys_sendfile::sys_sendfile,
    handler_sys_set_mempolicy::sys_set_mempolicy,
    handler_sys_set_mempolicy_home_node::sys_set_mempolicy_home_node,
    handler_sys_set_robust_list::sys_set_robust_list,
    handler_sys_setdomainname::sys_setdomainname,
    handler_sys_setfsgid::sys_setfsgid,
    handler_sys_setfsuid::sys_setfsuid,
    handler_sys_setgid::sys_setgid,
    handler_sys_setgroups::sys_setgroups,
    handler_sys_sethostname::sys_sethostname,
    handler_sys_setns::sys_setns,
    handler_sys_setpgid::sys_setpgid,
    handler_sys_setpriority::sys_setpriority,
    handler_sys_setregid::sys_setregid,
    handler_sys_setresgid::sys_setresgid,
    handler_sys_setresuid::sys_setresuid,
    handler_sys_setreuid::sys_setreuid,
    handler_sys_setrlimit::sys_setrlimit,
    handler_sys_setsid::sys_setsid,
    handler_sys_settimeofday::sys_settimeofday,
    handler_sys_setuid::sys_setuid,
    handler_sys_setxattr::sys_setxattr,
    handler_sys_shmem_create::sys_shmem_create,
    handler_sys_shmem_destroy::sys_shmem_destroy,
    handler_sys_shmem_map::sys_shmem_map,
    handler_sys_sigaction::sys_sigaction,
    handler_sys_sigaltstack::sys_sigaltstack,
    handler_sys_signalfd::sys_signalfd,
    handler_sys_sigprocmask::sys_sigprocmask,
    handler_sys_sigreturn::sys_sigreturn,
    handler_sys_sleep::sys_sleep,
    handler_sys_sock_register_buf::sys_sock_register_buf,
    handler_sys_sock_send_zc::sys_sock_send_zc,
    handler_sys_socket::sys_socket,
    handler_sys_socket_accept::sys_socket_accept,
    handler_sys_socket_accept4::sys_socket_accept4,
    handler_sys_socket_bind::sys_socket_bind,
    handler_sys_socket_connect::sys_socket_connect,
    handler_sys_socket_get_addr::sys_socket_get_addr,
    handler_sys_socket_getpeername::sys_socket_getpeername,
    handler_sys_socket_getsockname::sys_socket_getsockname,
    handler_sys_socket_getsockopt::sys_socket_getsockopt,
    handler_sys_socket_listen::sys_socket_listen,
    handler_sys_socket_recv::sys_socket_recv,
    handler_sys_socket_recvmmsg::sys_socket_recvmmsg,
    handler_sys_socket_recvmsg::sys_socket_recvmsg,
    handler_sys_socket_send::sys_socket_send,
    handler_sys_socket_sendmmsg::sys_socket_sendmmsg,
    handler_sys_socket_sendmsg::sys_socket_sendmsg,
    handler_sys_socket_setsockopt::sys_socket_setsockopt,
    handler_sys_socket_shutdown::sys_socket_shutdown,
    handler_sys_socketpair::sys_socketpair,
    handler_sys_splice::sys_splice,
    handler_sys_stat::{stat_absolute, sys_stat},
    handler_sys_statfs::sys_statfs,
    handler_sys_symlink::{symlink_absolute, sys_symlink},
    handler_sys_symlinkat::sys_symlinkat,
    handler_sys_sync::sys_sync,
    handler_sys_sync_file_range::sys_sync_file_range,
    handler_sys_syncfs::sys_syncfs,
    handler_sys_sysinfo::sys_sysinfo,
    handler_sys_tcgetattr::sys_tcgetattr,
    handler_sys_tcsetattr::sys_tcsetattr,
    handler_sys_tee::sys_tee,
    handler_sys_tgkill::sys_tgkill,
    handler_sys_time::sys_time,
    handler_sys_timerfd_create::sys_timerfd_create,
    handler_sys_timerfd_settime::sys_timerfd_settime,
    handler_sys_times::sys_times,
    handler_sys_tkill::sys_tkill,
    handler_sys_truncate::sys_truncate,
    handler_sys_umask::sys_umask,
    handler_sys_umount2::sys_umount2,
    handler_sys_uname::sys_uname,
    handler_sys_unlink::{sys_unlink, unlink_absolute},
    handler_sys_unlinkat::sys_unlinkat,
    handler_sys_unshare::sys_unshare,
    handler_sys_utime::sys_utime,
    handler_sys_utimensat::sys_utimensat,
    handler_sys_utimes::sys_utimes,
    handler_sys_vhangup::sys_vhangup,
    handler_sys_vmsplice::sys_vmsplice,
    handler_sys_wait4::sys_wait4,
    handler_sys_waitid::sys_waitid,
    handler_sys_write::sys_write,
    handler_sys_writev::sys_writev,
    handler_sys_yield::sys_yield,
};
