# filesystem — Virtual Filesystem

NARF's VFS. Capability-addressed nodes (no ambient namespace),
async path resolution, mount tree, per-task roots, file-as-a-cap.
Concrete filesystems (virtiofs, ext4-ish, initramfs) plug in under
`drivers/fs/` and are glued here.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: 3 (VFS core + in-memory FS) → 4 (virtiofs, persistent FS, caching).
