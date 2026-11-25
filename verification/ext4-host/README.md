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
  syncfs, under `/work` (linear directories).
