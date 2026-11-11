# verification/btrfs-host — Host-side btrfs root-rw harness

`narf-btrfs-host` runs NARF's btrfs driver in a plain `std` process on the
host — no QEMU — against image files: CachyOS-shaped fixtures built with
`mkfs.btrfs --rootdir`, the committed Linux snapshot fixture, and the sparse
fixtures in `drivers/fs/btrfs/testdata/`. Each scenario mounts the image
exactly as a `narf.disks=root-rw` boot does, runs a seeded random workload
mirrored op-for-op into a model, then judges the result with Linux
userspace (`btrfs check`, `btrfs restore`), a fresh NARF remount, and a
crash-consistency replay of the recorded write/flush stream.

Scenarios (`--scenario`): `regress`, `root`, `snapshots`, `lba4k`, `gate`,
`fst` (free-space trees maintained incrementally: grown multi-level by
thousands of punched holes, and the bitmap fixture), `enospc` (metadata
filled on a full device until `ENOSPC`, and block groups filled until a DATA
or METADATA chunk is allocated at reservation time — never an abort),
`scale` (the shape of an installed root on a sparse image: hundreds of
mostly-full DATA block groups, free space in hundreds of thousands of
single-sector pieces, three-level free-space and extent trees;
then a desktop-like workload in small transactions, with what each commit
cost — nodes visited and written per tree, recording passes, blocks beyond
the reservation, wall time — reported), `overwrite` (files of 1,000 to
16,000 single-page extents, one written in a shuffled page order as a mapped
file is written back; single-page overwrites at random and in file order
must not visit more fs-tree nodes, read more from the device or — loosely —
take longer as the file's extent count grows; then sequential writes in
128 KiB and 4 KiB calls, with MiB/s reported) and `release` (files of 1,
1,000 and 100,000 extents, a 256 MiB and a 1 GiB file on a 6 GiB filesystem,
truncated to nothing and unlinked: each must succeed, allocate no METADATA
chunk, and reserve no more per step than a step's worth; then truncates and
an unlink with every step committed and the write stream cut at every
flush, each crashed image checked and remounted). Every commit is audited against the
on-disk free-space tree (in `scale`, every commit of its second workload
pass), and the run reports the most any commit allocated beyond its batch's
reservation. `scale` takes a few minutes and about 2 GiB of disk at the
default `--ops`; it scales down with it and is then not held to the tree
depth.
Defaults are seed 1, 2 seeds per scenario, 3000 ops in `root` (the others
scale from it), 48 crash cut points in `root` (0 disables the crash pass),
and 3 concurrent `btrfs check` processes. Run it with
`cargo xtask btrfs-host-rw`.

| module | role |
|---|---|
| `workload` | seeded random namespace/data workload, mirrored into the model |
| `model` | expected state of one subvolume (inodes, dirents) |
| `narf` | mount/read through NARF the way a `root-rw` boot does |
| `dev` | image-file block device recording the write/flush stream; polices the request shapes the driver promises (driver spec §4) |
| `linux` | Linux userspace (`btrfs check`, `btrfs restore`, `dump-tree`) as the independent oracle |
| `crash` | replay of write-stream prefixes under a volatile-write-cache device model |
| `fixture` | fixture images |
| `fst`, `enospc`, `scale`, `overwrite`, `release` | the scenarios of those names |
| `host` | host stand-ins the kernel crate graph needs in a `std` process (RAM, linker anchors, executor) |

`file_loading_tests` holds the `#[cfg(test)]` file-loading tests.

- Driver: [`drivers/fs/btrfs/README.md`](../../drivers/fs/btrfs/README.md)
- Driver spec: [`drivers/fs/btrfs/specification/spec.md`](../../drivers/fs/btrfs/specification/spec.md)
- Verification: [`../README.md`](../README.md)
