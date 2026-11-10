# Filesystem comparison workloads

`probe.c` and `bench.c` provide static POSIX workloads for comparing NARF with
Linux. `analyze.rs` reuses the repository's statistical implementation in
`build/xtask/src/bench_stats.rs`. Python orchestration and host provisioning
used for local sweeps are intentionally kept outside version control.

Build the workload and analyzer from the repository root:

```sh
musl-gcc -O2 -static -no-pie -std=c11 -Wall -Wextra -Werror \
  verification/fs-linux-sweep/bench.c -o /tmp/fs-bench
rustc --edition=2021 -O verification/fs-linux-sweep/analyze.rs \
  -o /tmp/fs-analyze
cargo xtask build --arch=x86_64 --features boot-init,firmware-allow-unsigned
```

The same binary must run on both kernels. Keep the local collection scripts,
raw logs, tool versions, hashes, host-control/restoration records, and image
checks with each measurement artifact. A functional or TCG run alone cannot
establish relative performance.

## Diagnostic contract

`probe.c` checks first and repeated sequential reads, deterministic random
reads, stat/readdir, sequential writes, random overwrite, append, per-write
fsync, and create/rename/unlink followed by directory fsync. It checks returned
bytes and names. Data seeds are 1 MiB, blocks are 4 KiB, and the lookup directory
has 64 files. Write timers include readback, so these are diagnostic workload
completion times rather than pure storage throughput.

Use separate writable copies of each seeded 512 MiB image for ext2, ext4 and
Btrfs. NARF retains its ext-family boot mount at `/mnt`; a second independent
cache over the same device is invalid. Btrfs uses 4 KiB sectors and mkfs's
default metadata/data profiles; ext images use 4 KiB blocks. Record mkfs
features and mount options. FAT32 may be checked separately with mtools and
`fsck.vfat`; its no-op directory-sync hooks exclude it from timed write claims.

Finish with `syncfs`, a one-second deferred-reclamation settling interval and
another `syncfs`, outside the timers. Guest success requires independent
`e2fsck -fn` or `btrfs check --readonly --check-data-csum`, followed by extraction
with `debugfs rdump` or `btrfs restore` and comparison of every expected byte
and name. Never repair a failing diagnostic image.

## Controlled measurement contract

`bench.c` measures serialized invariant-TSC cycles on guest CPU 0, with
verification outside timed intervals. Use matching KVM/QEMU machine, devices,
CPU model, memory and writeback settings, two pinned vCPUs, and `noatime` on
both kernels. Pin emulator/I/O and collector work separately from the vCPUs.
Disable benchmark and QEMU ASLR. Reserve dedicated host cores, pin frequency,
disable SMT and turbo, check thermal/storage limits throughout collection,
and verify a 30-second initial thermal/idle window. Restore host settings on
all exits.

Use fresh images and boots in randomized order, with 8 MiB seeds and 1,024
lookup names. Tmpfs is a volatile memory baseline: seed it before timing and
verify all final bytes and names in the guest. Persistent formats additionally
require independent checker and extraction results after every boot. The
complete workload verifies 1,159 final files. A failure aborts collection.

| Timed case | Fixed work |
| --- | --- |
| `first-read-64k` | 8 MiB without target-file data warmup; host/device cache state is uncontrolled. |
| `cached-read-64k` | 16 passes over 8 MiB after two warmups. |
| `cached-random-read-4k` | 4,096 reads from the warmed file. |
| `sequential-write-64k-fsync` | Write 8 MiB, then fsync. |
| `random-overwrite-4k-fsync` | 4,096 writes over 8 MiB, then fsync. |
| `append-64k-fsync` | Append 64 KiB, then fsync. |
| `write-4k-fsync-each` | 64 writes, each followed by fsync. |
| `cached-stat` | 16,384 warmed lookups. |
| `readdir` | 32 scans of 1,024 names. |
| `create-directory-fsync`, `rename-directory-fsync` | 128 operations, then directory fsync. |

Two 4 KiB create/fsync operations warm the write path. Created and renamed
files remain linked; the diagnostic workload covers unlink. Record and
recheck kernel, workload, source and base-image hashes. Identify an installed
Linux kernel by hash and record its source reference separately unless its
build provenance is verified. Persistent readback does not establish
power-loss durability or equivalent journal semantics.

Follow [verification §8](../specification/spec.md#8-performance-testing--statistical-protocol):
at least 30 independent samples, or 100 when CV exceeds 5%; median and 95%
bootstrap CI with 10,000 resamples; p95/p99/p99.9; Welch and Mann–Whitney tests
with separate Benjamini–Hochberg corrections at q=0.05. Both tests must agree
and the ratio CI must exceed the declared 3% delta to label a difference.
A focused Btrfs run with 100 samples per kernel takes 200 boots; four formats
take 800. Kernel comparisons are distinct from before/after patch comparisons
and clean-source CI regression records.
