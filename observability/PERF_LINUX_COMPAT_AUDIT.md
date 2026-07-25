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
| `perf list software` | sysfs event-source discovery | supported slice | The upstream CLI discovers only software events implemented by the adapter. |
| `perf stat -- <cmd>` | default event selection and honest event admission | supported slice | Supported counters are measured; unavailable hardware events are reported as `<not supported>` rather than fabricated. |
| `perf stat -e cycles <cmd>` | counting event, enable-on-exec, target-exit stop, 24-byte read format | supported slice | The count window is bounded by successful exec and process exit and scheduler switch hooks attribute the PMU counter only while the target runs. |
| `perf stat -e cycles,instructions <cmd>` | independent fds, scaling times | supported slice | Hardware availability still bounds simultaneous events. |
| `perf stat -e '{cycles,instructions}'` | event groups and group leader reads | supported slice | Members are linked to the leader; group reads and group lifecycle ioctls cover the non-multiplexed counting case. |
| `perf stat -a` | per-CPU events and online CPU discovery | partial | Exact hardware counting is admitted only for the calling CPU on a uniprocessor boot; SMP/remote-CPU operation returns `EOPNOTSUPP`. |
| `perf stat -p PID` | task-scoped accounting | supported slice (x86_64) | Scheduler switch hooks allocate the target's counter only on the CPU where it runs and fold counts across preemption and migration. |
| `perf record` | overflow sampling, mmap metadata/data ring, poll wakeups | partial (x86_64) | Intel architectural PMU and AMD legacy/PerfMonV2 GP counters route real LVT-PC overflow IRQs into SAMPLE/LOST ring records; scheduler-attributed task counters switch per-CPU PMU state across preemption and migration and inherit across process/thread clones; frequency mode adapts real reload periods from observed overflow timing. Exec publishes exact program/interpreter PT_LOAD and stack VMAs, and later mmap/comm/fork/exit paths emit MMAP/MMAP2/COMM/FORK/EXIT with `sample_id_all` trailers. Ring overflow is reported through both `PERF_RECORD_LOST` and `PERF_FORMAT_LOST`; `PERF_EVENT_IOC_PAUSE_OUTPUT` suppresses production until resumed; and `PERF_EVENT_IOC_SET_OUTPUT` redirects compatible events into a shared mapped ring. Hardware per-CPU events on SMP and aarch64 PMUv3 overflow routing remain. |
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
- Raw PMU formats are architecture-specific: sysfs exposes the x86
  event/unit-mask controls or the aarch64 16-bit architectural event number.
  Model-specific event aliases must still be generated from the detected CPU
  before the CLI can safely use symbolic raw aliases.
- aarch64 has architectural cycle access in observability but does not yet
  provide the programmable-event backend needed for instructions/cache/branch
  events through this adapter.

## Required implementation sequence

1. Finish `perf stat`: task/CPU attribution, multiplex scaling, and capability
   authorization. The upstream CLI smoke is reproducible via
   `TEST_perf_cli.sh`.
2. Extend the minimal perf sysfs projection with only event aliases backed by
   the detected PMU.
3. Complete sampling portability: wire aarch64 PMUv3 overflow through GICv3
   and add hardware/QEMU coverage for the x86 LVT-PC route.
4. Add unwind and build-id prerequisites for `perf record/report`; initial
   ELF/interpreter/stack and post-exec `mmap(2)` MMAP/MMAP2 records are wired.
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
