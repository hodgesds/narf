# SquashFS research

Primary implementation references:

- Linux `/usr/src/linux/fs/squashfs/`, especially `squashfs_fs.h`,
  `super.c`, `block.c`, `inode.c`, `dir.c`, `file.c`, `fragment.c`,
  `id.c`, `xattr_id.c`, and `xattr.c`.
- Squashfs-tools 4.6.1 `mksquashfs` and `unsquashfs`, used to produce and
  independently inspect the checked-in conformance fixture.
- The SquashFS 4.0 format notes distributed by the squashfs-tools project:
  <https://github.com/plougher/squashfs-tools>.

The Linux tree is GPL-2.0-or-later and NARF is GPL-2.0-or-later. This is an
independent Rust implementation of the documented layouts and algorithms;
no C source is copied.
