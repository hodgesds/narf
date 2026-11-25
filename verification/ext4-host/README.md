# verification/ext4-host

Host-side (std process, no QEMU) write harness for NARF's ext4 driver
(`drivers/fs/ext2`, which the ext4 crate shares).

Each run builds a CachyOS-shaped tree on the host and packs it into a fresh
image with the real `mkfs.ext4 -d`, using the host's default features
(metadata_csum, orphan_file, 64bit, flex_bg, half-MD4 dir_index). It mounts
the image through the same named `ext4` constructor a boot uses, applies a
seeded random workload mirrored into a model, and then lets e2fsprogs judge
the result:

- `e2fsck -fn` must find nothing;
- `debugfs rdump /` must produce exactly the model's tree;
- a fresh NARF mount must read the same tree back.

```sh
cargo xtask ext4-host-rw                      # every scenario, 2 seeds
cargo xtask ext4-host-rw --scenario baseline --seeds 20 --ops 5000
```

A failing run keeps its image under `target/ext4-host/<scenario>-<seed>/`
and prints the last operations and the driver's log tail.

Scenarios:

- `baseline`: create, write, append, truncate, unlink, mkdir, rmdir, fast
  and slow symlinks, renames (within and across directories), fsync and
  syncfs, under `/work` (linear directories). The last unmount must leave
  the filesystem clean.
- `lifecycle`: the image mounted the way a `narf.disks=root-rw` boot mounts
  it (registered, designated by `root=UUID=`, named `ext4` constructor).
  While mounted, `dumpe2fs` must say "not clean" with one more mount
  counted, `syncfs` must not change that, and a remount read-only must say
  "clean".
- `gate`: root-rw must refuse, with EROFS and without changing a byte, an
  unclean filesystem (`ssv state 0`), one with recorded errors
  (`ssv state 3`), and one with an orphan list (`ssv last_orphan 12`).
- `htree`: 1 KiB blocks, so the root index holds 123 leaves; a workload
  into the indexed `/usr/lib`, then 6000 long names, enough leaves that the
  index gains its second level and its nodes split, then every third
  deleted. `debugfs htree` must report `Indirect levels: 1`.
- `extents`: a sparse file written one block in two, in shuffled order, so
  inserts split leaves and index nodes mid-tree and ahead of a subtree's
  first key. 30000 extents reach depth 3 at 1 KiB blocks and depth 2 at
  2 KiB, where the extent tail checksum sits 8 bytes before the block's
  end. `debugfs ex` must report the depth.
- `uninit`: a 4 GiB image whose small tree leaves most groups lazily
  initialized (`BLOCK_UNINIT`, `INODE_UNINIT`), then 1.5 GiB of data and
  9000 files: allocation must move into those groups (dumpe2fs counts fewer
  uninit groups afterwards) with every bitmap, flag and count e2fsck-clean.
