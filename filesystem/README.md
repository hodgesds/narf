# filesystem — Virtual Filesystem

NARF's VFS. Capability-addressed nodes (no ambient namespace),
async path resolution, mount tree, per-task roots, file-as-a-cap.
In-memory and synthetic filesystems live here; block/network-backed drivers
under `drivers/fs/` include ext2, FAT/exFAT, 9p, ISO 9660, UDF, SquashFS,
Minix, ext4, and the single-device read-write btrfs implementation.
The btrfs driver includes native snapshots, full-qgroup accounting and hard
limits, and 4–64 KiB filesystem sectors; multi-device profiles remain out of
scope.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Testing requirements (conformance checklist every FS must satisfy):
  [`specification/testing-requirements.md`](./specification/testing-requirements.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: 3 (VFS core + in-memory FS) → 4 (persistent/remote drivers, Linux
  compatibility, and caching).
