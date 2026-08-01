# Overlayfs Linux compatibility audit

Audit date: 2026-08-01

## Reference points

- NARF baseline: `origin/main` at
  `27ea206af20d6c7d188adefb0406020cd5d19477`.
- Linux reference checkout: `/usr/src/linux` at
  `9bd577abc6fcf9c07995705220487f743e074de0`. The referenced overlayfs
  directory and documentation had no local modifications.
- Primary Linux sources:
  `Documentation/filesystems/overlayfs.rst`, `fs/overlayfs/namei.c`,
  `fs/overlayfs/dir.c`, `fs/overlayfs/copy_up.c`,
  `fs/overlayfs/super.c`, and `fs/overlayfs/util.c`.

This audit targets observable Linux behavior through NARF's current
`FileOps`/`DirOps` surface. It does not claim Linux overlayfs backing-store
format compatibility.

## Call-chain audit

The requested semcode MCP analysis was run against the baseline branch.

- `sys_renameat2` reaches `cross_dir_rename`, parent resolution, and the
  `DirOps::rename`/`rename_to` surface. This is the path that must preserve
  Linux `RENAME_*` validation and EXDEV fallback behavior.
- `sys_unlinkat` selects `sys_unlink` or `sys_rmdir`, which resolve the parent
  and dispatch to the corresponding `DirOps` mutation.
- `sys_mount` is the overlay construction boundary. Its baseline parser
  ignored the real mount data argument and required a writable upper.
- `OverlayFile::ensure_copied_up` was reached by the four baseline mutating
  file methods: `write`, `truncate`, `set_owners`, and `set_perms`. The audit
  extended that boundary to xattrs, locks, fallocate, and mapping setup while
  forwarding read-only operations to the active layer.
- semcode bounded `OverlayDir::lookup_dir` precisely at
  `filesystem/src/overlayfs.rs:193-242` in the baseline. That implementation
  assigned the highest lower directory to the writable slot and therefore
  could not create missing upper parents.

Semcode's database is commit-based, so the recorded chain describes the
audited baseline; the tests in this change pin the replacement behavior.

## Compatibility matrix

| Linux behavior | NARF status after this audit | Evidence |
| --- | --- | --- |
| Upper-first lookup and lower priority | Implemented | `smoke_overlay_union_shadow` |
| A higher file masks a lower directory and vice versa | Implemented | `smoke_overlay_cross_layer_type_masking` |
| Same-name directories merge | Implemented | union and nested-parent tests |
| Whiteout hides the target and is absent from readdir | Implemented in every layer | whiteout tests |
| Opaque directory suppresses all deeper directories | Implemented | `smoke_overlay_opaque_directory` |
| Lower-only read-only overlay | Implemented | `OverlayFs::new_read_only`; read-only test |
| Missing upper parents copied before descendant mutation | Implemented lazily | `smoke_overlay_lower_only_parent_copy_up` |
| Regular-file copy-up on data/metadata mutation | Implemented | copy-up and metadata tests |
| Copy-up preserves owner, mode, mtime, and supported xattrs | Implemented | metadata test |
| Copy-up memory is bounded | Implemented with 64 KiB chunks | `OverlayFile::copy_regular_data` |
| Unlink of upper-over-lower does not reveal lower | Implemented | upper-with-lower unlink test |
| `rmdir` checks the merged view for emptiness | Implemented | merged-rmdir test |
| Lower regular-file rename | Implemented as copy-up, upper rename, old whiteout | rename test |
| Lower/merged directory rename with redirects disabled | EXDEV | `FsError::CrossDevice`, syscall errno mapping |
| Lower regular-file hard link | Implemented after copy-up | hard-link test |
| Cross-parent rename/link inside one overlay | Implemented through `rename_to`/`link_to` | mount identity checked |
| `RENAME_NOREPLACE` | Checked against the merged destination, then delegated | cross-parent rename test |
| `RENAME_EXCHANGE` involving lower objects | Rejected | avoids a non-atomic partial emulation |
| Linux mount data argument | Implemented; legacy source fallback retained | `sys_mount` |
| Escaped colons in legacy `lowerdir=` | Implemented | `parse_overlay_lowerdirs` |
| `upperdir`/`workdir` pairing and empty workdir | Validated | `sys_mount` |
| Unknown overlay mount options | Rejected with EINVAL | no silent feature claims |
| Internal markers hidden from lookup/readdir/create | Implemented | name validation and merge tests |

## Correctness fixes found by the audit

1. Lower-only directories were treated as writable upper directories. Writes
   either failed or risked targeting the wrong layer. Missing upper ancestors
   are now materialized from the nearest existing upper parent.
2. A directory in one layer and a file in another could make `lookup` and
   `lookup_dir` return contradictory objects. Lookup now stops at the first
   object type.
3. Lookup ignored whiteouts stored in lower layers even though enumeration
   partially recognized them. Both paths now apply identical layer masking.
4. Opaque directories were not recognized. `.wh..wh..opq` now terminates
   lower merging and remains invisible.
5. Removing an upper object could reveal a same-name lower object. Removal
   now creates a whiteout whenever a lower object remains.
6. `rmdir` checked only the raw upper directory. It now rejects any non-empty
   merged view and removes internal markers before deleting an otherwise
   empty upper directory.
7. Lower-file rename and hard-link returned unsupported. Both now copy up
   first and preserve the lower layer.
8. Copy-up allocated the whole lower file and omitted xattrs/metadata. It now
   streams data and carries supported metadata.
9. Mount parsing read options from `source` despite the Linux data argument
   already being available, ignored workdir constraints, and could not create
   read-only overlays. These mount forms now follow the documented ABI.

## Intentional or interface-blocked gaps

These are explicit gaps, not silently accepted features.

- **Backing format:** NARF stores `.wh.<name>` and `.wh..wh..opq` regular
  files. Linux normally uses a 0:0 character device or
  `trusted.overlay.whiteout`, and `trusted.overlay.opaque`. A NARF upper is
  not directly portable to a Linux overlay mount.
- **Atomic workdir transactions:** workdir is required, resolved, and checked
  empty, but copy-up/rename do not yet stage a temporary object there. A crash
  or competing copy-up can expose a partial upper object. Fixing this needs a
  VFS transaction/temporary-rename primitive and backing-filesystem identity.
- **Same-superblock validation:** `DirOps` exposes no stable filesystem
  identity, so mount cannot prove that upper and work reside on the same
  filesystem or reject every overlapping subtree. Exact equality among a
  lower, upper, and work path is rejected.
- **Redirects and advanced features:** `redirect_dir`, `index`, `metacopy`,
  `nfs_export`, `volatile`, `verity`, data-only lower layers, `userxattr`, and
  new mount API `lowerdir+`/fd-valued layers are not implemented. Their mount
  options are rejected rather than accepted as no-ops.
- **Directory metadata copy-up:** owner and mode are copied when a missing
  upper parent is created. `DirOps` has no directory xattr/time API, and its
  chmod/chown setters are synchronous, so a metadata-only mutation cannot
  asynchronously materialize a lower-only directory.
- **Synchronous file timestamps:** `FileOps::set_times` is synchronous while
  copy-up is asynchronous. A timestamp-only mutation on a lower-only file
  cannot initiate copy-up through that hook.
- **Hard-link origin/index tracking:** separate lower names that already alias
  one inode are not recognized as one origin during independent copy-ups.
  Linux's index/xino machinery is not present.
- **Readdir lifetime:** `enumerate` rebuilds a deterministic merged snapshot
  per call. Linux caches one merged name list per open directory description,
  so changes during a partially consumed readdir are isolated differently.
- **Open-handle copy-up races:** NARF lacks a shared overlay inode/dentry cache.
  Concurrent handles can race copy-up by name; a winner is reused, but this is
  not Linux's workdir-backed atomic copy-up protocol.
- **`RENAME_EXCHANGE` with lower objects:** rejected. Pure-upper exchange is
  delegated to the upper filesystem.
- **Copy-file-range and mmap write faults:** the current VFS does not tell the
  overlay wrapper whether a mapping is writable, and optimized
  `copy_file_range_to` cannot safely downcast arbitrary overlay endpoints.
- **Credential model:** Linux's stashed mount credentials and two-layer
  permission checks do not map one-to-one to NARF's capability authority.
  NARF preserves the lower metadata it can represent and relies on its normal
  capability/DAC checks.

## Regression coverage

The overlay kernel-test set covers union/shadow, upper create, lower and
upper-origin whiteout removal, data and metadata copy-up, missing-parent
copy-up, lower-layer whiteouts, opacity, cross-layer type conflicts, merged
directory emptiness, read-only overlays, lower-file rename, lower-file hard
links, and cross-parent rename with `RENAME_NOREPLACE`. Both architectures
run these architecture-neutral tests through the ordinary filesystem test
subsystem.
