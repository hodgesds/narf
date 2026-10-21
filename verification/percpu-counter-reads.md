# Per-CPU counter-read validation

The CPU-major counter-read API is intended to reduce cache-coherence work for
diagnostic surfaces that render several values for each CPU. It does **not**
change any userspace-visible counter, `/proc/interrupts` field, or ordering
guarantee: all reads remain eventually consistent telemetry snapshots.

`interrupts::snapshot_counters()` is the first consumer. IRQ delivery writes
only the current CPU's cache-line-isolated vector row; the collector reads all
requested vectors in that row before proceeding to the next CPU. The prior
vector-major layout put counts for different CPUs for the same vector next to
each other and scanned every CPU separately for every vector.

## Correctness

Run the kernel interrupt smoke suite. In particular,
`smoke_irq_counter_snapshot_matches_per_cpu_accessor` checks that the
`snapshot_counters()` value rendered by `/proc/interrupts` is still identical
to `fire_count_on_cpu()` after an IRQ. The public `fire_count` and
`fire_count_on_cpu` interfaces are unchanged.

## Cache-efficiency measurement

Use a dedicated, otherwise-idle KVM runner with a virtual PMU exposed to the
guest. First build the perf rootfs once:

```sh
sudo verification/data/musl-demo/REGEN_perf_rootfs.sh
```

Collect the baseline on `main`, then collect the candidate branch with the
same runner, kernel command line, CPU count, and rootfs:

```sh
NARF_PERCPU_SAMPLES=30 \
  verification/data/musl-demo/BENCH_percpu_interrupts.sh
```

The collector writes raw `perf stat -x,` records for `cache-references`,
`cache-misses`, `cycles`, and `instructions` to
`target/bench/percpu-interrupts-<commit>.log`. Its guest workload repeatedly
opens and consumes the real `/proc/interrupts`; it does not use a synthetic
counter implementation. Set `NARF_PERCPU_COHERENCE_EVENT` to a
runner-validated, CPU-specific coherence event (for example a HITM event) to
capture direct sharing traffic in addition to portable cache metrics.

The script intentionally refuses fewer than 30 samples and rejects unavailable
PMU events. It is a raw-data collector, not a source of publishable numbers.
Before asserting an improvement, apply the full
[`verification/specification/spec.md`](specification/spec.md#8-performance-testing--statistical-protocol)
protocol: runner preconditions, median and bootstrap CI, Welch's t-test plus
Mann-Whitney U, and the declared effect size. Generic cache misses are a proxy
for read-path cache efficiency; a supported coherence event is required to
claim fewer cache-line invalidations specifically.
