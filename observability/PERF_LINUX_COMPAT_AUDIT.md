# Linux `perf` compatibility audit

Status: initial full-surface audit, 2026-07-25.

Target: run an unmodified Linux `perf` CLI on NARF, beginning with
`perf stat`. Scheduler attribution, cgroups, and sampling are explicitly
deferred; unsupported operations must return a Linux-shaped error and must
never fabricate measurements.

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
| `perf stat -e cycles <cmd>` | counting event, enable-on-exec, 24-byte read format | supported slice | Counting is system-global during the window; exact target-task attribution is deferred. |
| `perf stat -e cycles,instructions <cmd>` | independent fds, scaling times | supported slice | Hardware availability still bounds simultaneous events. |
| `perf stat -e '{cycles,instructions}'` | event groups and group leader reads | supported slice | Members are linked to the leader; group reads and group lifecycle ioctls cover the non-multiplexed counting case. |
| `perf stat -a` | per-CPU events and online CPU discovery | partial | CPU validation exists; counters are not pinned or migrated per CPU. |
| `perf stat -p PID` | task-scoped accounting | partial | PID validation exists; accounting is not scheduler-switched with the target. |
| `perf record` | overflow sampling, mmap metadata/data ring, poll wakeups | unsupported | No `perf_event_mmap_page` producer or PMI-to-record path yet. |
| `perf report` | perf.data parser, symbols, unwind | userspace-only after record | Kernel work is primarily `/proc`, build-id, and mmap metadata fidelity. |
| `perf trace` | tracepoint PMU, tracefs event metadata | unsupported | NARF tracing rings are not yet projected as Linux tracepoints. |
| `perf top` | sampling plus periodic display | unsupported | Blocked by the same ring/PMI work as `perf record`. |
| probes (`kprobe`, `uprobe`) | probe PMUs, tracefs dynamic events | unsupported | Must be capability-gated when added. |
| cgroup mode | `PERF_FLAG_PID_CGROUP`, cgroup scheduler hooks | unsupported | Deferred with scheduler attribution. |
| BPF attachment | SET_BPF/QUERY_BPF ioctls, BPF runtime | unsupported | Returns `ENOTTY`; no silent acceptance. |

## `perf_event_open` audit

Implemented:

- Linux syscall numbers on x86_64 and aarch64.
- `PERF_ATTR_SIZE_VER0` minimum, forward-compatible zero tail acceptance,
  and `E2BIG` for a non-zero unknown tail.
- Hardware, software, hardware-cache, and raw event parsing on x86_64.
- PID, CPU, group-fd existence, open flags, CLOEXEC, and reserved-field
  validation.
- Stable fd lifetime and PMU counter release.
- `PERF_FORMAT_TOTAL_TIME_ENABLED`, `TOTAL_TIME_RUNNING`, `ID`, `GROUP`,
  and `LOST` wire layouts.
- `PERF_EVENT_IOC_ENABLE`, `DISABLE`, `RESET`, and `ID`.

Gaps:

- `pid == -1`/per-CPU and PID-target semantics are validated but not
  scheduler-attributed.
- `enable_on_exec` currently enables when the event is installed. This gives
  the CLI a usable counting window but includes setup overhead.
- Pinned/exclusive events, inheritance, output redirection, refresh,
  period changes, filters, SIGTRAP delivery, and namespace/cgroup modes are
  absent.
- No security policy equivalent to Linux
  `perf_event_paranoid`/`CAP_PERFMON` has been projected into the Linux ABI.
  The final adapter must derive authorization from NARF PMU capabilities.

## Accuracy findings

- A successful open must correspond to a real counter or a precisely
  implemented software event. Returning cycle-derived estimates for cache,
  branch, or stalled-cycle events is incompatible and invalid for performance
  claims.
- `time_enabled` and `time_running` are currently equal. That is correct only
  while no multiplexing occurs. Counter multiplexing must report the actual
  running interval before more events than hardware slots can be accepted.
- x86 raw encodings are model-specific. Sysfs PMU format/event aliases must be
  generated from the detected CPU before the CLI can safely use symbolic raw
  aliases.
- aarch64 has architectural cycle access in observability but does not yet
  provide the programmable-event backend needed for instructions/cache/branch
  events through this adapter.

## Required implementation sequence

1. Finish `perf stat`: task/CPU attribution, multiplex scaling, and capability
   authorization. The upstream CLI smoke is reproducible via
   `TEST_perf_cli.sh`.
2. Extend the minimal perf sysfs projection with only event aliases backed by
   the detected PMU.
3. Add sampling: pinned user pages, `perf_event_mmap_page`, data ring,
   acquire/release indices, `PERF_RECORD_SAMPLE`/`LOST`, poll wakeups, and
   overflow interrupt routing.
4. Add process metadata records (`COMM`, `MMAP2`, `FORK`, `EXIT`) and unwind
   prerequisites for `perf record/report`.
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
