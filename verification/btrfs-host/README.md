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
or METADATA chunk is allocated at reservation time — never an abort) and
`scale` (the shape of an installed root on a sparse image: hundreds of
mostly-full DATA block groups, free space in hundreds of thousands of
single-sector pieces, three-level free-space and extent trees;
then a desktop-like workload in small transactions, with what each commit
cost — nodes visited and written per tree, recording passes, blocks beyond
the reservation, wall time — reported) and `fsync-linux` (the tree log
against a real kernel, below). Every commit is audited against the
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
| `linuxvm` | a real Linux kernel as the oracle: the host's installed kernel under QEMU with a one-binary initramfs (`vminit.c`), no root |
| `fsynclog` | tree-log scenarios: a log written by one implementation, replayed by both |
| `crash` | replay of write-stream prefixes under a volatile-write-cache device model |
| `fixture` | fixture images |
| `fst`, `enospc`, `scale` | the scenarios of those names |
| `host` | host stand-ins the kernel crate graph needs in a `std` process (RAM, linker anchors, executor) |

`file_loading_tests` holds the `#[cfg(test)]` file-loading tests.

## Tree-log scenarios and the Linux guest

`fsync-linux` needs a kernel, not just btrfs-progs: only a mount replays a
tree log. `linuxvm` boots a kernel from `/boot/vmlinuz*` (newest first;
`NARF_LINUX_KERNEL=/path` picks one) under `qemu-system-x86_64` — KVM when
`/dev/kvm` is usable, TCG otherwise — with the test image as a virtio disk
and an initramfs holding one static binary built from `src/vminit.c` by the
host `cc`. The kernel must have btrfs and virtio-blk built in; each
candidate is probed with a fresh filesystem and the first that mounts it is
used. The guest mounts the image (replaying any log), optionally runs an op
script from a second disk, lists every entry with size, mode, link count and
a content hash on the serial console, unmounts and powers off; a script that
ends in `crash` is killed there instead.

Each case is a script (fixed cases for every fsync shape, plus seeded random
ones). Linux runs it and is killed at `crash`; the image is then replayed
twice from copies, by Linux and by NARF, and the two trees must be
identical, pass `btrfs check --check-data-csum`, keep what the script's
fsyncs promised, and the NARF-replayed image must mount on Linux unchanged.

When no kernel can be booted (no readable `/boot/vmlinuz*`, btrfs built as a
module, no QEMU, no static libc) the scenario prints
`SKIPPED — UNVERIFIED, NOT A PASS` with the reason and the run's verdict
does not count it as tested; `--require-linux` turns that into a failure.

- Driver: [`drivers/fs/btrfs/README.md`](../../drivers/fs/btrfs/README.md)
- Driver spec: [`drivers/fs/btrfs/specification/spec.md`](../../drivers/fs/btrfs/specification/spec.md)
- Verification: [`../README.md`](../README.md)
