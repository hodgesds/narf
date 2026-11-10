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
thousands of punched holes, and the bitmap fixture) and `enospc` (metadata
filled on a full device until `ENOSPC`, and block groups filled until a DATA
or METADATA chunk is allocated at reservation time — never an abort). Every
commit is audited against the on-disk free-space tree, and the run reports
the most any commit allocated beyond its batch's reservation.
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
| `host` | host stand-ins the kernel crate graph needs in a `std` process (RAM, linker anchors, executor) |

`file_loading_tests` holds the `#[cfg(test)]` file-loading tests.

- Driver: [`drivers/fs/btrfs/README.md`](../../drivers/fs/btrfs/README.md)
- Driver spec: [`drivers/fs/btrfs/specification/spec.md`](../../drivers/fs/btrfs/specification/spec.md)
- Verification: [`../README.md`](../README.md)
