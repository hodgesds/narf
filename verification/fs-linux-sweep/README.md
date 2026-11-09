# Filesystem comparison sweep

Initial diagnostic workload for NARF versus Linux on ext2, ext4, and Btrfs.
The same static musl binary and the same seeded image for each format run on
both kernels. Each guest gets its own writable image copy; the base hashes are
checked again after the sweep. No host mounts or privileged filesystem tools
are used. Images, extracted files, raw serial logs, tool versions, kernel and
source hashes, and `diagnostics.json` stay in the requested new work directory.

This is **diagnostic infrastructure**, not the statistical performance gate.
Without `--diagnostic`, the runner reports structured `PreconditionFailed` and
exits before making images or booting guests. Diagnostic runs retain raw elapsed
times but emit no performance record, speed ratios, or regression decisions.
The required controlled-host checks and independent sampling/statistical
analysis in [verification §8](../specification/spec.md#8-performance-testing--statistical-protocol)
must be implemented before promoting this workload to a performance gate.
TCG is useful for functional checks only.

## Run

Requires Python 3.11+, `musl-gcc`, QEMU x86_64, `cpio`, GNU `cp`,
e2fsprogs (`mke2fs`, `e2fsck`, `debugfs`), btrfs-progs, the committed static
BusyBox fixture, and a Linux kernel with built-in virtio-blk/ext2/ext4/Btrfs
support. No downloads are performed. The NARF production shell is x86_64-only.

```sh
cargo xtask build --arch=x86_64 --features boot-init,firmware-allow-unsigned
python3 verification/fs-linux-sweep/run.py
python3 verification/fs-linux-sweep/run.py --diagnostic \
  --workdir target/perf-sweeps/filesystems-new \
  --narf-kernel target/x86_64-unknown-none/release/narf-frame \
  --linux-kernel /path/to/vmlinuz --accel tcg
python3 -m unittest discover -s verification/fs-linux-sweep -p 'test_*.py'
```

Use `--sides linux` or `--sides narf` for one kernel, `--filesystems ext4 btrfs`
to narrow the sweep, or `--btrfs-features '^block-group-tree'` to explicitly
investigate an older Btrfs layout. The default uses the installed mkfs defaults;
its feature list is recorded in `mkfs-btrfs.log`. Compatibility variants should
use separate work directories so the default-layout result remains visible.
The default accelerator is KVM; passing `--accel tcg` is explicit. Every guest
and offline checker has a host timeout; an individual failure does not stop
the remaining filesystem/kernel combinations. The runner exits nonzero when
any guest, workload case, integrity check, or content comparison fails.

## Workload contract

All I/O is synchronous buffered POSIX I/O with 4 KiB application blocks and
one worker. File seeds are 1 MiB; the directory contains 64 named files.
Images are 512 MiB. Btrfs uses 4 KiB sectors, 16 KiB metadata nodes, and mkfs's
default data/metadata profiles. Ext images use 4 KiB filesystem blocks.

| Case | Fixed work and verification |
| --- | --- |
| `seq-read-first`, `seq-read-warm` | Read and check every seeded byte; the second pass reuses the same file. |
| `random-read` | 128 deterministic 4 KiB reads, checking every returned byte. |
| `stat` | 512 lookups, checking type and size. |
| `readdir` | Verify every expected name exactly once. |
| `seq-write-sync` | Create/write 1 MiB, fsync, reread/check bytes and size. |
| `random-overwrite-sync` | Overwrite 128 blocks of an existing seeded file; fsync; check modified and untouched blocks. |
| `append-sync` | Extend an existing seeded file by 64 KiB; fsync; check old data, new data, and size. |
| `fsync-each` | Create a file; write/fsync eight consecutive blocks; reread/check bytes. |
| `create-unlink` | Create/close/unlink 16 files; verify absence; fsync the directory. |
| `rename-unlink` | Create/close/rename/unlink 16 files; verify old/new names; fsync the directory. |

Write-case elapsed times include readback verification. These are workload
completion times, not pure storage throughput. `seq-read-first` does not assert
cold page-cache or cold device-cache state. Direct I/O, mmap, concurrent workers,
large directories, compressed Btrfs, and crash/power-loss replay are further
workloads, not measured by this sweep.

NARF's ext-family boot mount is retained at `/mnt`; the runner verifies the
boot log identifies `vblk0` and rejects an overlay/fallback. It never builds a
second independent ext cache over that device. Linux and NARF Btrfs use an
explicit `noatime` mount. The ext boot mount uses NARF's boot defaults; that
difference is another reason these runs cannot establish relative performance.
Every workload ends with `syncfs`, a one-second settling interval for deferred
reference reclamation, and a second `syncfs`, outside all timed cases.
Explicitly created mounts are unmounted;
NARF's ext boot mount stays attached until guest termination. The report records
this distinction. Guest success alone is insufficient: afterward `e2fsck -fn`
or `btrfs check --readonly --check-data-csum` must pass, and independently
extracted files (`debugfs rdump` or `btrfs restore`) must match expected bytes.
Neither checker repairs an image. Persistent readback checks accepted writes;
they do not prove power-loss durability or journal recovery semantics.
