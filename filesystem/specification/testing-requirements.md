# Filesystem testing requirements (conformance spec)

Every concrete filesystem in NARF — `MemFs`, `DevFs`, `ProcFs`, `SysFs`,
`CgroupFs`, `OverlayFs`, and the block/network-backed drivers under
`drivers/fs/` (ext2/ext4, fat, exfat, iso9660, 9p, virtiofs, fuse) — implements
the same three VFS traits: `FsInstance`, `DirOps`, `FileOps`
(`filesystem/src/lib.rs`). Callers (path resolution, mount, bind-mount, execve,
the syscall layer) rely on a **uniform contract** across all of them. A missing
or stubbed method is not "unsupported" — it is a latent bug that surfaces only
when a specific caller exercises that path.

This document is the checklist a filesystem MUST satisfy in tests before it is
considered conformant. New drivers add their tests under
`drivers/fs/<name>/src/tests.rs` (or `filesystem/src/<name>_tests.rs`) with
`kernel_test_in!("drivers/fs/<name>", ...)`; they run in the standard
`cargo xtask test` suite.

## Why this exists

Two classes of bug motivated this spec, both from filesystems that "worked" in
the common path but stubbed a method a less-common caller needed:

1. **Sync/async parity.** ext2/fat/exfat/iso9660/9p implement `lookup` /
   `lookup_dir` (sync) as `None` stubs, doing the real work only in
   `lookup_async` / `lookup_dir_async`. That is invisible until a **synchronous**
   caller walks a deep path: `build_bind_fs` resolving a bind source (systemd's
   `StateDirectory=`, e.g. binding `/var/lib/systemd/linger`) walked
   `var → lib → systemd` with the sync API, got `None`, and failed the whole
   service `226/EXIT_NAMESPACE`. A block-backed FS must drive its async I/O to
   completion from the sync method (`narf_scheduler::block_on_spin`), not stub it.

2. **Whole-op no-ops that lie about state.** A method that returns success
   without doing the work (e.g. an unmount that keeps the mount, a mount that
   silently drops a submount) breaks callers that re-observe state — systemd's
   `umount_recursive` loops on `/proc/self/mountinfo` forever if a reported
   unmount didn't actually remove the entry.

The rule: **a method either does the operation and reports the true result, or
returns a precise error — never a success-shaped stub.**

## Required conformance tests

### A. Directory lookup (the most bug-prone surface)

For a mounted instance with a known tree (`root/`, `root/file`, `root/sub/`,
`root/sub/deep`):

- [ ] **A1. sync `lookup` resolves a real file** — returns `Some` with correct
      `stat().size` / `file_type`. (Not `None`.)
- [ ] **A2. sync `lookup` of a missing name → `None`.**
- [ ] **A3. sync `lookup_dir` resolves a real directory** → `Some`.
- [ ] **A4. sync `lookup_dir` on a FILE → `None`** (type dispatch is correct).
- [ ] **A5. async `lookup_async` / `lookup_dir_async`** mirror A1–A4 and return
      `Err(FsError::NotFound)` (not a generic error) for a missing name.
- [ ] **A6. sync ≡ async.** The sync and async forms return the *same* node for
      the same name. A driver that can only do one MUST bridge the other, not
      stub it.
- [ ] **A7. deep multi-component walk** via the sync API:
      `root.lookup_dir("sub").lookup("deep")` resolves. This is the
      bind-mount-source shape; it is the single most important test.

### B. Enumeration

- [ ] **B1. `enumerate_async`** lists every non-empty entry with the correct
      `FileType` (File / Dir / Symlink), and honours `cursor` / `max` paging.
- [ ] **B2.** `.` and `..` handling matches the driver's iteration contract
      (either both present or both filtered — consistently).

### C. File I/O

- [ ] **C1. full read** returns the exact bytes and byte count.
- [ ] **C2. partial read at a non-zero offset** returns the correct slice.
- [ ] **C3. read at/after EOF** returns `0`.
- [ ] **C4.** if writable: **write-then-read round-trips**; if read-only, writes
      return `FsError::ReadOnly` (not a silent success).

### D. Mutation (only if the FS supports it)

- [ ] **D1. `create` / `mkdir`** make a node that a subsequent `lookup` finds.
- [ ] **D2. `unlink` / `rmdir`** remove a node that `lookup` then misses;
      `rmdir` on a non-empty dir errors.
- [ ] **D3. `rename`** moves a node (old name misses, new name hits).
- [ ] **D4. `symlink`** creates a `Symlink`-typed node whose `read` yields the
      target; resolution follows it (see `resolve_async` symlink handling).
- [ ] **D5. unsupported mutations** return `FsError::Unsupported` — never a
      no-op success.

### E. Metadata

- [ ] **E1. `stat` / `stat_async`** report a plausible `size`, `mode.file_type`,
      and owners; a directory reports `FileType::Dir`.
- [ ] **E2. `ino`** is stable across two lookups of the same node and distinct
      for distinct nodes (Linux-visible via `/proc`, `st_ino`, `mountinfo`).

### F. Integration with the mount/bind layer

- [ ] **F1. mount + resolve.** Mounting the instance and resolving an absolute
      path through `VfsRegistry` / `MountNamespace` reaches its nodes.
- [ ] **F2. bind a deep subtree.** `registry().bind_mount(&auth,
      "/mnt/a/b/c", "/target")` succeeds when `/mnt/a/b/c` is a real directory
      (exercises `build_bind_fs`'s sync walk end-to-end — the ext2 linger bug).
- [ ] **F3. bind a single file** (`build_bind_fs` FileMount path) resolves to
      the file, not an empty dir.

## Harness notes

- Block-backed drivers build a synthetic image in-heap and mount it via a
  `RamBlockDevice` (`narf_block::ram`); see `drivers/fs/ext2/src/tests.rs`
  (`build_ext2_image`, `build_ext2_image_nested`, `mount_root`) for the pattern
  including a nested directory for the A7/F2 deep-walk test.
- `poll_once` (single poll) suffices when the backing device completes
  synchronously. A test that calls the **sync** VFS API on a block-backed FS
  implicitly exercises the driver's `block_on_spin` bridge — do not add a mock
  that stubs the sync side; test the real driver.
- Errors must be precise `FsError` variants (`NotFound`, `ReadOnly`, `Busy`,
  `Unsupported`, `PermissionDenied`) so the syscall layer maps the right errno.

## Definition of done

A filesystem is conformant when sections A, B, C, E, F pass, plus D for any
mutation it advertises. A stub that returns `None` / `Ok(())` / a default in
place of real work fails this spec even if no current caller hits it — the next
caller (a new syscall, a distro's sandbox) will.
