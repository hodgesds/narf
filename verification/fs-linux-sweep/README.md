# Filesystem comparison sweep

Diagnostic workload for NARF versus Linux on ext2, ext4, Btrfs and FAT32.
The same static musl binary and the same seeded image for each format run on
both kernels. Each guest gets its own writable image copy; the base hashes are
checked again after the sweep. No host mounts or privileged filesystem tools
are used. Images, extracted files, raw serial logs, tool versions, kernel and
source hashes, and `diagnostics.json` stay in the requested new work directory.

This is **diagnostic infrastructure**, not the statistical performance gate.
Without `--diagnostic`, the runner reports structured `PreconditionFailed` and
exits before making images or booting guests. Diagnostic runs retain raw elapsed
times but emit no performance record, speed ratios, or regression decisions.
The separate controlled measurement runner below implements independent
sampling and [verification §8](../specification/spec.md#8-performance-testing--statistical-protocol)
statistics for a larger workload.
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
`--filesystems vfat` adds FAT32 diagnostics and requires `mkfs.vfat`,
`fsck.vfat` and mtools (`mcopy`). Images are seeded and independently
extracted without host mounts. FAT32 is not promoted to the timed write
comparison while its VFS directory-sync hooks inherit no-op defaults.
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

## Controlled measurements

`measure.py` runs the same static `bench.c` binary on both kernels with matching
QEMU machine, devices, CPU model, memory and writeback cache settings. It uses
KVM, two vCPUs pinned to host CPUs 8/9, a worker pinned to guest CPU 0, and
serialized invariant-TSC cycles (lower is better). Verification is outside the
timed intervals. Both kernels use `noatime`; ASLR must be disabled in the
benchmark and QEMU processes. No host-wide ASLR change is required.

The host-specific `controlled_host.py` requires review before use elsewhere:
it reserves the entire CPUs 8–15 LLC in an isolated cgroup partition, disables
SMT and boost, and fixes those cores at their firmware-reported nominal
frequency under the performance governor. It checks effective isolation,
policies, CPU/NVMe temperature tripwires and the benchmark drive's alarm at
start and throughout each guest. A 30-second window must show temperatures
below the tripwires and all reserved cores below 5% load before collection.
It snapshots all frequency policies before hotplug/governor changes and
restores policies, preferences, SMT, boost and the partition on every exit.
The CPU tripwire is 85°C, retaining 15°C below AMD's specified 100°C maximum
for this runner's [Ryzen 9 7940HX](https://www.amd.com/en/products/processors/laptop/ryzen/7000-series/amd-ryzen-9-7940hx.html).
An interrupted cleanup can be retried with `--restore-existing` and the same
work directory; saved policies are verified after asynchronous transitions.
Missing controls abort the run; `--pilot` produces no performance record.

```sh
python3 verification/fs-linux-sweep/measure.py --pilot --samples 1 \
  --workdir /tmp/filesystem-pilot-new --narf-kernel /path/to/narf-frame \
  --linux-kernel /path/to/vmlinuz
python3 verification/fs-linux-sweep/controlled_host.py --apply \
  --workdir /tmp/filesystem-sweep-new --narf-kernel /path/to/narf-frame \
  --linux-kernel /path/to/vmlinuz --samples 100
```

Full collection uses 100 fresh boots per kernel per format (800 total), with
randomized order, fresh 512 MiB images, 8 MiB data files and 1,024 directory
entries. Every boot must pass the offline checker and independent content
readback for persistent formats. Tmpfs is a memory baseline: the guest creates
the seed before all timers and verifies every final file/name before success;
there is no offline or durability check for a volatile filesystem. Its
first-read case is necessarily memory-backed. A failure preserves its image
and aborts collection. Kernel, source
and base-image hashes are recorded and checked again after collection. The
installed Linux image is identified by its hash; the local source reference
and its dirty status are recorded separately, without asserting build provenance.

| Timed case | Fixed work |
| --- | --- |
| `first-read-64k` | 8 MiB, no target-file data warmup; host/device cache state is uncontrolled. |
| `cached-read-64k` | 16 passes over 8 MiB after two warmup passes. |
| `cached-random-read-4k` | 4,096 reads from that cached file. |
| `sequential-write-64k-fsync` | 8 MiB in 64 KiB writes, then fsync. |
| `random-overwrite-4k-fsync` | 4,096 writes over an existing 8 MiB file, then fsync. |
| `append-64k-fsync` | Append 64 KiB to 8 MiB, then fsync. |
| `write-4k-fsync-each` | 64 writes, each followed by fsync. |
| `cached-stat` | 16,384 warmed lookups. |
| `readdir` | 32 complete scans of 1,024 entries. |
| `create-directory-fsync`, `rename-directory-fsync` | 128 operations, then directory fsync. |

Two 4 KiB create/fsync operations warm the write path before measurement.
Created/renamed files remain linked; unlink failures are still covered by the
diagnostic harness. Results describe accepted writes and persistent readback,
not power-loss durability or equivalent journal/flush guarantees.

`analyze.rs` reuses `build/xtask/src/bench_stats.rs`. It reports median and mean
with 95% bootstrap CIs (10,000 resamples), p95/p99/p99.9 and CV. Welch and
Mann–Whitney tests receive separate BH corrections across the selected suite
at q=0.05 (44 comparisons by default). Both must agree, and the ratio CI must
exceed the declared 3% delta,
to label a difference. Insufficient samples prevent a performance record.
These kernel-to-kernel comparisons are not a before/after optimization claim
or a schema-2 CI regression record for two clean source builds.
