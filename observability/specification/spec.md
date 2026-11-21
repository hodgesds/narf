# observability — Specification

> Status: **v1.0** (Stage 4 design lock). v0.2 narrowed scope
> to state inspection (event streams moved to `tracing/`);
> v1.0 locks the core-dump storage path, the debugger-attach
> trust model, the live-peek policy, the ELF-core layout, and
> the pre-panic telemetry channel.

## 1. Purpose & scope

**Owns:** The non-event-stream observability surfaces.

- **Hardware performance counters** — enable, multiplex, read.
- **Debugger integration** — GDB remote-serial stub.
- **Crash / post-mortem** — kernel core-dump format; panic-time
  capture including snapshots from `tracing/` flight-recorder rings.
- **Live inspection primitives** — capability-gated "peek" into domain
  state, per-CPU run queues, and cap-table summaries for diagnosis.

**Does NOT own:**

- USDT markers, dynamic probes, flight-recorder rings, tracer task,
  `FnTime`, live aggregate sketches — all in `tracing/`.
- Statistical analysis of captured data — `verification/`.

Put differently: `tracing/` answers "what is happening right now?";
`observability/` answers "what is the current state?" and "what did
the state look like when it broke?"

## 2. Assumptions

- `tracing/` provides a flight-recorder snapshot API whose output can
  be embedded in a crash dump.
- `capabilities/` gates PMU access, debugger attach, and live-state
  peeks.
- `console/` is available as the fallback sink for crash output.
- `arch/` exposes PMU primitives and debug breakpoint registers.

## 3. Public interface

### 3.1 Hardware performance counters

```rust
pub struct Counter;
pub struct CounterSet { /* group multiplexed on one CPU */ }

pub fn open_counter(ev: HwEvent, cap: &Cap<Pmu, Read>) -> Counter;
pub fn read(c: &Counter) -> u64;
pub fn enable(cs: &mut CounterSet);
pub fn disable(cs: &mut CounterSet);
pub fn snapshot(cs: &CounterSet) -> CounterSample;
```

`HwEvent` is an arch-neutral enum (`Cycles`, `Instructions`, `LlcMiss`,
`BranchMiss`, `DtlbMiss`, `ItlbMiss`, `L1dLoadMiss`, …) with
per-arch backends in `arch/`.

**Multiplexing.** When more counters are requested than hardware
provides, `CounterSet` time-multiplexes them with a scaling factor
reported alongside each read. Honest-number reporting per
`verification/` §8 — raw + scaling factor, never silently scaled.
`time_enabled` covers the whole enabled lifetime; `time_running` covers only
intervals in which the event owns a physical PMU slot. Sampled events preserve
their exact remaining overflow period when multiplexing moves them between
physical counters or CPUs.

**Sampling.** Interrupt-on-overflow is exposed as a `Cap<Pmu, Sample>`
capability and, when used, delivers a sample via a `tracing/`
Narf-Ring. The sampling infrastructure lives here (counter config)
but the event transport is `tracing/`.

**Linux compatibility.** `userspace/` may project this cap-gated surface as
Linux `perf_event_open(2)` fds. The adapter must preserve Linux
`perf_event_attr`, read-format, ioctl, mmap-ring, and error semantics for every
feature it advertises. Events without a real backend are rejected rather than
estimated. `observability/PERF_LINUX_COMPAT_AUDIT.md` is the compatibility
matrix; Linux ABI mechanics remain owned by `userspace/`. A system-wide
hardware event is configured, read, updated, and released on its owning CPU;
an architecture without a synchronous remote-PMU rendezvous rejects remote
CPU operation instead of accessing CPU-local PMU registers indirectly.

### 3.2 Debugger integration

```rust
pub fn gdb_stub_start(cap: &Cap<Debugger, Attach>);
```

- **Transport:** serial console (Stage 4 default), virtio-console
  (optional), network gdbserver (post-1.0).
- **Protocol:** GDB Remote Serial Protocol.
- **Halt mode:** all CPUs stopped on attach; per-CPU selection for
  register inspection.
- **Hardware watchpoints:** use x86_64 DR0–DR3 or aarch64
  `DBGBVR`/`DBGWVR` registers; typed `Cap<Watchpoint, Install>`.

### 3.3 Crash / post-mortem

```rust
pub fn panic_hook(info: &PanicInfo);              // called from frame::panic
pub fn kernel_core_dump() -> CoreImage;           // structured snapshot
```

`panic_hook` is called by `frame/`'s panic path (no allocation, no
locks, signal-safe):

1. Capture the fault registers, faulting CPU state, domain id,
   faulting address.
2. Invoke `tracing::snapshot_panic_rings()` to freeze and copy every
   ring registered as a panic-snapshot source. **If `tracing/` has
   not initialised (early-boot panic before Stage 1 tracing setup),
   the call is a documented no-op** — `panic_hook` checks the init
   flag and skips the recorder section without aborting.
3. Append cap-table root summaries per task (Stage 4).
4. Write a structured CoreImage to the configured sink (console by
   default; persistent storage where available).

**Section ordering for partial dumps.** Sections are written in
priority order:

1. Header (magic + version).
2. **Domain fault section** (highest diagnostic value per byte).
3. Per-CPU register state.
4. Memory map.
5. Cap-table summaries (Stage 4).
6. Recorder snapshots (largest; lowest priority).

The dump is *valid* if any sections are present, not only if all
are. A panic that runs out of console buffer space partway through
section 6 still leaves a usable dump containing 1–5. Userspace
parsers must tolerate truncation at any section boundary.

`CoreImage` format:

- **Header:** magic, version, kernel build hash, timestamp, arch.
- **CPU state section:** per-CPU register dumps.
- **Memory map section:** active mappings at the time of fault, with
  domain tags.
- **Domain fault section:** attribution (which domain, which access,
  which PFEC.PK / ESR bits).
- **Recorder snapshots section:** one sub-section per
  `tracing/`-registered panic-snapshot ring.
- **String table + note section** (ELF-core-compatible where
  possible, for tool reuse — `gdb`, `crash`).

### 3.3a Kernel symbol table (`kallsyms`)

The image's own symbol table, written into the linker-reserved `.kallsyms`
section after the link by `xtask kallsyms` (`build/` §3) in the
`narf-kallsyms` format (`observability/kallsyms/specification/spec.md`).
Linux's `kernel/kallsyms.c` decoder:

```rust
pub use narf_kallsyms::{Entry, Error, NameBuf, Table, KSYM_NAME_LEN, MAX_NAME};

pub fn table() -> Result<Table<'static>, Error>;   // validated once; BadMagic if unpatched
pub fn text_base() -> u64;                         // runtime _text (link + KASLR slide)
pub fn address(entry: &Entry) -> u64;              // text_base() + entry.offset
pub fn lookup(addr: u64, name: &mut NameBuf)       // kallsyms_lookup_size_offset
    -> Option<(Entry, u64 /* offset in symbol */, Option<u32> /* size */)>;
```

Addresses are runtime addresses: offsets are relative to `_text`, and
`text_base()` takes `_text`'s address, which the KASLR pass relocates like
any other reference. Allocation-free after the first `table()` call, and
lock-free (usable on fatal paths). This module decides nothing about who may
see an address — exposing one defeats KASLR, so each presenter applies
`kallsyms_show_value` (`/proc/kallsyms`: `filesystem/` §3.14).

### 3.4 Live inspection (diagnostic peek)

Capability-gated read-only access to kernel state for diagnosis:

```rust
pub fn peek_cpu(c: CpuId, cap: &Cap<Diagnostics, Read>) -> CpuStateView;
pub fn peek_domain(d: DomainId, cap: &Cap<Diagnostics, Read>) -> DomainView;
pub fn peek_cap_root(t: TaskId, cap: &Cap<Diagnostics, Read>) -> CapRootView;
```

- Read-only. Never mutates state.
- Stage 4 feature; consumed by an on-host diagnostic tool over a
  tracer Narf-Ring.
- No backdoor: these caps are minted by the boot process and can be
  revoked.

### 3.5 Lockup detector decisions (`watchdog`)

```rust
pub const WATCHDOG_THRESH_SECS: u64 = 10;          // Linux watchdog_thresh
pub struct CpuSample { pub online: bool, pub halted: bool,
                       pub sched_passes: u64, pub timer_ticks: u64,
                       pub runnable: bool }
pub enum Lockup { Soft { stuck_ns: u64, first: bool }, Hard { stuck_ns: u64 },
                  Stalled { stuck_ns: u64, first: bool } }
pub struct CpuWatch;                 // per-CPU state, const-constructible
impl CpuWatch {
    pub fn touch(&self, s: &CpuSample, now_ns: u64);
    pub fn observe(&self, s: &CpuSample, now_ns: u64, thresh_ns: u64) -> Option<Lockup>;
}
pub struct LockupWatch<const CPUS: usize>;
impl<const CPUS: usize> LockupWatch<CPUS> {
    pub fn begin_round(&self, now_ns: u64, thresh_ns: u64) -> bool;
    pub fn observe(&self, cpu: usize, s: &CpuSample, now_ns: u64, thresh_ns: u64) -> Option<Lockup>;
}

pub const RUNNABLE_THRESH_SECS: u64 = 10;          // workqueue.watchdog_thresh
pub struct RunnableSample { pub task: u64, pub since: u64 }
pub struct RunnableWatch<const CPUS: usize>;
impl<const CPUS: usize> RunnableWatch<CPUS> {
    pub fn observe(&self, cpu: usize, sample: Option<RunnableSample>,
                   now: u64, thresh: u64) -> Option<u64>;   // waited, once per stall
}
```

Pure decision logic of Linux's `kernel/watchdog.c` over samples the caller
takes (the `frame/` stall watchdog, from the timer tick). A **soft lockup**
is an awake CPU with no executor scheduling point for `2 * thresh`,
reported then and every `2 * thresh` while it lasts (`first` marks the
episode's first report). A **hard lockup** is an awake CPU with neither a
timer interrupt nor a scheduling point for `thresh`, reported once per
episode. A halted CPU is responsive and touches both detectors, so an idle
system never reports, unless it is halted over work its executor would not
halt over (`runnable`): an **executor lockup** (Linux's workqueue lockup),
reported with the soft cadence when such a CPU passes no scheduling point
for `2 * thresh`. `thresh == 0` disables all three. `begin_round` returns
`false` (and re-baselines every CPU) when the previous round is more than
`2 * thresh` old — the checker itself did not run (suspend, paused VM).

`RunnableWatch` is Linux's workqueue watchdog (`wq_watchdog_timer_fn`,
`show_cpu_pool_hog`) at task granularity: the caller samples, per CPU, the
task that has been runnable longest without being dispatched
(`narf_scheduler::dbg_oldest_runnable`: ready queue, wake inbox, woken
parked set; `since` is the later of its last wake and the end of its last
run, a new task counting from its creation). A stall — one task runnable
since one instant — is reported once, when it has waited `thresh` and the
previous round saw the same stall (one sighting can catch a wake between its
runnable bit and its stamp). The task running or leaving ends the stall.
`thresh == 0` disables it.

**Reports** (`frame/` stall watchdog, `--features stall-watchdog`, from the
per-CPU watchdog hrtimer; checks once a second on one CPU; lock-free or
try-lock reads only):

| Report | Linux | Threshold (boot parameter) |
| --- | --- | --- |
| `BUG: soft lockup - CPU#N stuck for Ns! [comm:pid]` | `watchdog_timer_fn` | `2 * watchdog_thresh` |
| `CPUr: Watchdog detected hard LOCKUP on cpu N (...)` | buddy detector | `watchdog_thresh` (10 s) |
| `BUG: executor lockup - CPU#N idle with runnable work for Ns! [comm:pid]` | workqueue lockup | `2 * watchdog_thresh` |
| `BUG: CPU#N: task [comm:pid] runnable for Ns without running` | `wq_watchdog_timer_fn` per task | `workqueue.watchdog_thresh` (10 s; Linux's workqueue default is 30) |
| `INFO: task comm:pid blocked for more than N seconds.` | `check_hung_uninterruptible_tasks` | `sysctl.kernel.hung_task_timeout_secs` (120), `sysctl.kernel.hung_task_warnings` (10) |

A kernel task is named `comm:id`, `comm` being the function its future came
from (`narf_scheduler::origin_comm`), as Linux names a kthread. The
runnable report adds the task's holding place, spawn site and affinity and
the CPU's current task, scheduling-point count and last-tick RIP with its
symbol.

## 4. Invariants & safety properties

- `panic_hook` completes in bounded time even when the system is
  otherwise broken; it does not rely on the heap, scheduler, or IPC.
- PMU counters are read-mostly. Writing (program / start / stop)
  requires `Cap<Pmu, Control>`.
- Debugger attach requires `Cap<Debugger, Attach>`; this cap is minted
  only at boot and under a documented boot-option.
- Live peek never returns pointers into kernel memory — only values
  and typed views.
- The debugger stub runs at the Frame's trust level; reviewing its
  code counts as TCB per `process/` §4.

## 5. Architecture notes

### x86_64
- PMU: architectural perf-mon (v3+); fixed counters 0..2 for
  Instructions / Cycles / RefCycles; programmable counters on v4+.
- Debug: INT3 (0xCC) for soft breakpoints; DR0–DR3 for hardware
  breakpoints; DR6/DR7 for status/config.
- Crash-dump ELF-core compat: reuse `NT_PRSTATUS` layout where
  possible.

### aarch64
- PMU: ARMv8 PMUv3 (`PMCCNTR_EL0`, `PMEVCNTRn_EL0`, `PMEVTYPERn_EL0`).
- Debug: `BRK #n` for soft breakpoints; `DBGBVRn_EL1` / `DBGBCRn_EL1`
  for hardware breakpoints; `DBGWVRn_EL1` / `DBGWCRn_EL1` for watchpoints.
- Crash-dump compat: ELF-core with aarch64 note types.

## 6. Dependencies

- **Consumes:** `arch/` (PMU + debug-register primitives), `frame/`
  (panic hook), `console/` (fallback sink), `capabilities/` (cap
  gating), `tracing/` (flight-recorder snapshot API), `observability/kallsyms`
  (symbol-table format).
- **Provides to:** `verification/` (PMU readings feeding perf
  benchmarks), `process/` (crash dumps referenced in bug reports),
  maintainers and AI agents (debugger, post-mortem), `filesystem/`
  (`/proc/kallsyms`).

## 7. Stage assignment

| Stage | Lands                                                           |
| ----- | --------------------------------------------------------------- |
| 1     | PMU Cycles + Instructions; basic crash dump (register state + stack). |
| 2     | Multiplexed counter groups; domain-attribution in crash dump.   |
| 3     | PMU sampling via `tracing/` transport; core-dump enrichment with flight-recorder snapshots. |
| 4     | GDB remote stub; live-inspection peek API; userland tooling to parse core dumps. |

## 8. Resolved decisions

### 8.1 Core-dump storage (resolved)

**Decision:** **block device via the kernel's persistent
storage stack, with serial-console as a fallback**.

The boot manifest declares a `dump_partition: Option<DiskUuid>`
(typically a small partition, ~256 MiB). On panic, the
`narf-frame` panic path:
1. Quiesces APs via NMI-IPI.
2. Composes the ELF-core (§8.4) in a pre-reserved buffer.
3. Writes to the dump partition via the panic-safe block
   write path (`drivers/nvme` panic_write hook, similar for
   AHCI / virtio-blk).
4. If the dump partition is unavailable / write fails,
   streams the dump out the console (slow but always works).

On next boot, a userspace daemon (`narf-dumpd`) detects the
fresh dump on the partition and uploads / archives it before
clearing.

### 8.2 Debugger attach trust (resolved)

**Decision:** **debugger attach requires `Cap<Debugger,
Attach>` AND a boot-time enable**. Two-factor:

1. The boot param `narf.debug.allow_attach=1` must be set;
   otherwise the cap is unmintable regardless of who claims
   it.
2. Even with the boot param, the `Cap<Debugger, Attach>` is
   minted only by the bootstrap-authority chain to a
   designated "debug" process (configured per system).

Production images set `narf.debug.allow_attach=0` permanently.
Dev images set it 1; the cap is held by the running
debugger's process which exits releasing it.

### 8.3 Live-peek policy (resolved)

**Decision:** **default-off with explicit `Cap<Diagnostics,
Read>` enable**.

Live peek (read-only access to kernel-side state for
inspection) is gated by `Cap<Diagnostics, Read>`. Default
production builds don't mint this cap to any process.
Dev/CI builds mint it to the test harness; vendor support
images can mint it to a vendor-tools process behind audited
authorisation.

The cap badges with a per-domain allowlist: a `Diagnostics`
cap may be scoped to "read driver-domain N's state only,"
not unlimited kernel introspection.

### 8.4 ELF-core layout (resolved)

**Decision:** **single ELF-core per panic** containing:

- One `PT_NOTE` with NARF-specific note types describing
  which CPUs were running which tasks, the panic message,
  the kernel version + commit hash.
- `PT_LOAD` segments for the kernel image (text + data).
- `PT_LOAD` segments per-recorder ring (per `tracing/spec`
  §8.3 double-buffer flip).
- A `PT_NOTE` with the per-CPU register state snapshots.

Tools (`gdb`, `readelf`, `objdump`) read the ELF natively.
Note types are in the `NARF` vendor namespace; `narf-coretools`
is the friendly extractor.

### 8.5 Pre-panic telemetry (resolved)

**Decision:** **via `tracing/` rings**, not a separate PMU
channel. `tracing/` already supports per-domain rings with
priority dispatch; pre-panic health signals (low memory,
cap-table near-full, slab-high-watermark) emit as structured
events to the `kernel-health` ring.

A userspace daemon (`narf-healthd`) subscribes and exposes a
Prometheus-style metric endpoint or syslog output. The
in-kernel cost is the same as any tracing event (~50 cycles).

This unifies introspection — there's no parallel
"out-of-band" channel separate from the rest of telemetry.

## 9. ABI versioning

`observability/` exports through SDK at `@v0`:

- `Cap<Diagnostics, Read>` for live-peek consumers.
- `Cap<Debugger, _>` for attach.
- ELF-core note-type IDs (frozen at v1.0).
- Pre-panic event field schemas (drivers wanting to emit
  health signals use these).

`OBS_ABI_MAJOR = 1`, `OBS_ABI_MINOR = 0`.

## 10. Open questions

(none — all v0.2 questions resolved in §8)
