# SquashFS

Read-only SquashFS 4.0 driver for Linux-produced immutable images. The
driver is block-backed, implements NARF `FsInstance`/`DirOps`/`FileOps`,
registers for `FsType::SquashFs` root detection and `mount -t squashfs`,
and currently decodes zlib and LZ4 images. See
[`SQUASHFS_LINUX_COMPAT_AUDIT.md`](SQUASHFS_LINUX_COMPAT_AUDIT.md) for the
compatibility matrix and `specification/spec.md` for invariants.
