# Linux `perf` compatibility audit

Status: initial full-surface audit, 2026-07-25.

Target: run an unmodified Linux `perf` CLI on NARF, beginning with
`perf stat` and fixed-period `perf record`. Remaining scheduler-attribution
gaps, cgroups, and unsupported sampling modes must return a Linux-shaped error
and must never fabricate measurements.

## Compatibility boundary

Linux `perf` is not a single PMU API consumer. It depends on five connected
surfaces:

1. `perf_event_open(2)` and `struct perf_event_attr`.
2. Perf-event fd `read(2)`, `ioctl(2)`, `poll(2)`, and `mmap(2)` behavior.
3. PMU programming and overflow interrupts.
4. `/sys/bus/event_source/devices`, tracefs, and selected procfs sysctls.
5. Process, scheduler, signal, ELF, and unwind behavior used by the command
   being profiled.

NARF's native capability-gated observability API remains the authority.
The Linux ABI in `userspace/src/perf_event.rs` is a compatibility adapter
over that authority; it is not a second PMU subsystem.

## Audited command matrix

| `perf` surface | Required kernel ABI | NARF status | Notes |
| --- | --- | --- | --- |
| `perf --version`, help | ELF loader, libc, terminal | supported in Alpine rootfs | `REGEN_perf_rootfs.sh` packages Alpine's unmodified musl-linked perf and its shared-library closure. |
| `perf list` | sysfs event-source discovery | supported slice | The upstream CLI discovers software events plus architecture-correct raw formats. On aarch64, generic hardware aliases are published only when PMCEID advertises the corresponding event. Model-specific aliases remain absent. |
| `perf stat -- <cmd>` | default event selection and honest event admission | supported slice | Supported counters are measured; unavailable hardware events are reported as `<not supported>` rather than fabricated. |
| `perf stat -e cycles <cmd>` | counting event, enable-on-exec, target-exit stop, 24-byte read format | supported slice | The count window is bounded by successful exec and process exit and scheduler switch hooks attribute the PMU counter only while the target runs. |
| `perf stat -e cycles,instructions <cmd>` | independent fds, scaling times | supported slice | Hardware availability still bounds simultaneous events. |
| `perf stat -e '{cycles,instructions}'` | event groups and group leader reads | supported slice | Members are linked to the leader; group reads and group lifecycle ioctls cover the non-multiplexed counting case. |
| `perf stat -a` | per-CPU events and online CPU discovery | supported slice | Per-CPU hardware operations execute on the owning CPU through a synchronous x2APIC rendezvous. Unmodified `perf stat -a -d --per-node` reports both SRAT nodes and real supported counters; scheduler software events and unavailable model-specific cache events remain `<not supported>`. Systems without the required rendezvous backend return `EOPNOTSUPP`. |
| `perf stat -p PID` | task-scoped accounting | supported slice | Scheduler switch hooks allocate the target's architecture-specific counter only on the CPU where it runs and fold counts across preemption and migration on x86_64 and aarch64. |
| `perf record` | overflow sampling, mmap metadata/data ring, poll wakeups | partial (x86_64 and aarch64 PMUv3) | Intel architectural PMU and AMD legacy/PerfMonV2 GP counters route real LVT-PC overflow IRQs into SAMPLE/LOST ring records; task counters switch architecture-specific per-CPU PMU state across preemption and migration and inherit across process/thread clones; frequency mode adapts real reload periods from observed overflow timing. On x86_64, system-wide allocation, PMI routing, arm, pause, period update, read, and release execute synchronously on each owning CPU through x2APIC IPIs; unmodified `perf record -a -c ... -e cycles` produces a nonempty data file on an SMP guest. On aarch64, fixed cycle and PMCEID-advertised programmable events are verified end to end through counter preload, firmware-discovered level-sensitive PPI 23, GICv3 dispatch, PMOVS acknowledgement/reload, interrupted-ELR capture, deferred drain, and a visible mmap sample. Exec publishes exact program/interpreter PT_LOAD and stack VMAs, and later mmap/comm/fork/exit paths emit MMAP/MMAP2/COMM/FORK/EXIT with `sample_id_all` trailers. Ring overflow is reported through both `PERF_RECORD_LOST` and `PERF_FORMAT_LOST`; `PERF_EVENT_IOC_PAUSE_OUTPUT` suppresses production until resumed; `PERF_EVENT_IOC_SET_OUTPUT` redirects compatible events into a shared mapped ring; `PERF_EVENT_IOC_REFRESH` budgets genuine overflows and stops with `POLLHUP` on the last credit. |
| `perf report` | perf.data parser, symbols, unwind | userspace-only after record | Kernel ELFs now carry deterministic SHA-1 build IDs and expose the exact GNU note at `/sys/kernel/notes`. Full kernel DSO attribution still requires real kallsyms/relocation metadata; an unmodified record of the no-build-ID BusyBox workload therefore honestly omits `HEADER_BUILD_ID` instead of inventing one. NUMA memory topology is authoritative through SRAT-backed node, CPU-membership, distance, and memory-block sysfs objects. Hybrid CPU topology metadata remains absent pending an authoritative cross-architecture interface. |
| `perf trace` | tracepoint PMU, tracefs event metadata | unsupported | NARF tracing rings are not yet projected as Linux tracepoints. |
| `perf top` | sampling plus periodic display | unsupported | Blocked by the same ring/PMI work as `perf record`. |
| probes (`kprobe`, `uprobe`) | probe PMUs, tracefs dynamic events | unsupported | Must be capability-gated when added. |
| cgroup mode | `PERF_FLAG_PID_CGROUP`, cgroup scheduler hooks | unsupported | Deferred with scheduler attribution. |
| BPF attachment | SET_BPF/QUERY_BPF ioctls, BPF runtime | unsupported | Returns `ENOTTY`; no BPF program loading, execution, attachment, query, or synthesized BPF records are implemented. Perf's `bpf_event` metadata selector is accepted only on its dummy sideband event; because no BPF objects can exist, that event domain is empty and perf may print its normal synthesis warning. |

## `perf_event_open` audit

Implemented:

- Linux syscall numbers on x86_64 and aarch64.
- `PERF_ATTR_SIZE_VER0` minimum, forward-compatible zero tail acceptance,
  and `E2BIG` for a non-zero unknown tail.
- Hardware, software, hardware-cache, and raw event parsing on x86_64;
  PMCEID-gated hardware and architectural raw-event parsing on aarch64.
- Exact scheduler-accounted task clocks and per-CPU user clocks selected with
  `exclude_kernel`; all-context per-CPU software clocks remain unsupported.
- PID, CPU, group-fd existence, open flags, CLOEXEC, and reserved-field
  validation.
- Stable fd lifetime and PMU counter release.
- `PERF_FORMAT_TOTAL_TIME_ENABLED`, `TOTAL_TIME_RUNNING`, `ID`, `GROUP`,
  and `LOST` wire layouts.
- `PERF_EVENT_IOC_ENABLE`, `DISABLE`, `REFRESH`, `RESET`, and `ID`.

Gaps:

- Pinned/exclusive events, filters, SIGTRAP delivery, and
  namespace/cgroup modes are absent.
- No security policy equivalent to Linux
  `perf_event_paranoid`/`CAP_PERFMON` has been projected into the Linux ABI.
  The final adapter must derive authorization from NARF PMU capabilities.

## Accuracy findings

- A successful open must correspond to a real counter or a precisely
  implemented software event. Returning cycle-derived estimates for cache,
  branch, or stalled-cycle events is incompatible and invalid for performance
  claims.
- `time_enabled` measures the complete enabled interval while `time_running`
  measures only intervals in which a hardware event owns a real PMU slot.
  Oversubscribed task events rotate their allocation priority when a CPU
  selects a different task, so unavailable events remain stopped and later
  receive a real slot rather than being estimated. Syscall/poll re-entry for
  the same task does not advance the multiplex epoch. Per-CPU events still
  allocate eagerly and fail when no physical slot is available. A 1 ms
  user-mode timer quantum rotates oversubscribed task hardware events even for
  a lone runnable task. Sampled task events preserve the exact hardware
  `period_left` across physical-counter rotation and CPU migration; the first
  resumed overflow reports that shortened period before the configured full
  reload cadence resumes.
- Raw PMU formats are architecture-specific: sysfs exposes the x86
  event/unit-mask controls or the aarch64 16-bit architectural event number.
  Model-specific event aliases must still be generated from the detected CPU
  before the CLI can safely use symbolic raw aliases.
- aarch64 maps instructions, cache misses, branch instructions, and branch
  misses to architectural PMUv3 event numbers and admits each event only when
  PMCEID advertises it. Model-specific aliases still require CPU-aware sysfs
  discovery.

## Required implementation sequence

1. Finish `perf stat`: task/CPU attribution, multiplex scaling, and capability
   authorization. The upstream CLI smoke is reproducible via
   `TEST_perf_cli.sh`.
2. Extend the PMCEID-gated aarch64 aliases with model-specific aliases only
   after CPU-aware PMU discovery exists; retain fail-closed admission.
3. Complete sampling portability with synchronous cross-CPU PMU control;
   retain the real-overflow QEMU gate on both IRQ backends.
4. Add unwind and build-id prerequisites for `perf record/report`; initial
   ELF/interpreter/stack and post-exec `mmap(2)` MMAP/MMAP2 records are wired,
   and the real kernel GNU build-ID note is published. Kernel symbol and
   relocation metadata remain before perf can associate sampled kernel IPs
   with that ID.
5. Project selected NARF tracing events into tracepoint IDs and tracefs for
   `perf trace`; add probes and BPF only after their capability and safety
   model is reviewed.

## Test gates

Every completed row requires:

- Rust ABI layout and validation tests.
- Kernel syscall/fd lifecycle tests, including close and fd-table exhaustion.
- A static-musl C smoke using the Linux headers and raw syscall ABI.
- An upstream `perf` CLI QEMU smoke for the affected command.
- Cross-architecture build and functional coverage.
- For measurement accuracy, comparison against a known instruction workload
  on physical hardware under `verification/specification/spec.md` section 8;
  no accuracy or overhead number may be claimed from QEMU or a single sample.

Run the current upstream CLI gate as root:

```sh
verification/data/musl-demo/TEST_perf_cli.sh
```

On an x86_64 host with KVM PMU passthrough, the record gate validates both
fixed-period and frequency mode and requires `perf report --stdio` to parse
the resulting file:

```sh
verification/data/musl-demo/TEST_perf_record_kvm.sh
```
