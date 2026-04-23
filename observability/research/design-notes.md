# observability — Design Notes

> 2026-04-22. Author: Claude Sonnet 4.6 (design-phase analysis).

---

## Load-bearing decisions

**The scope split from `tracing/` is correct but the boundary has a shared infrastructure problem.** `observability/` owns "state inspection" and `tracing/` owns "event streams." The crash dump uses `tracing/`'s flight-recorder snapshot API — `tracing::snapshot_panic_rings()` is called from `observability/`'s `panic_hook`. This means `observability/` has a hard runtime dependency on `tracing/` even in the minimal Stage 1 crash path. If `tracing/` is not initialized (early-boot crash before Stage 1 tracing lands), `observability/`'s panic hook must degrade gracefully. §4's invariant says "panic_hook completes in bounded time even when the system is otherwise broken" — it must also work when `tracing/` is not yet initialized.

**The debugger stub runs at Frame's trust level — it is TCB.** §4 states this explicitly. This means every line of GDB stub code is in the TCB change class (two-maintainer review, security-review pass). The stub is Stage 4, which is correct; but the design must be constrained *now* to minimize TCB surface. Key decision: the stub should not have its own memory allocation, its own domain, or its own IPC path. It must reuse the console transport, the already-mapped kernel state (read-only views via peek API), and a minimal handshake protocol. Any custom allocation or IPC in the GDB stub is a future CVE.

**PMU multiplexing with scaling factors is honest but produces subtly wrong numbers.** §3.1 specifies that when more counters are requested than hardware provides, `CounterSet` time-multiplexes with a scaling factor. The scaling factor is `(total_time / counter_active_time)`. On a CPU with 4 programmable counters and 8 requested, each counter is active ~50% of the time, so the scaling factor is ~2. But workloads that are bursty in a specific counter (e.g., LLC misses spike during one phase, not uniformly) will produce scaling-corrected numbers that can be off by an order of magnitude. The spec says "honest-number reporting: raw + scaling factor, never silently scaled" — this is correct, but it should also specify that FnTime in `tracing/` §3.2.1 must *disable* multiplexing (or fail at install time) because delta-per-call semantics are incompatible with multiplexed counters.

**The ELF-core compatibility goal ("tool reuse — gdb, crash") creates a maintenance burden.** §3.3 says the CoreImage format is "ELF-core-compatible where possible." ELF core compatibility means maintaining `NT_PRSTATUS` layout per-arch, which is a Linux-kernel-specific format (the struct layout is not in the ELF spec; it is in Linux's `asm/elf.h`). For GDB to read NARF core dumps without modification, NARF must mimic Linux's exact NT_PRSTATUS layout for both x86_64 and aarch64. This is doable but ties NARF's crash dump format to Linux's internal struct layout — a form of ABI dependency on Linux. Alternatively, NARF defines a separate section type and ships a GDB plugin. The plugin path is more work short-term but avoids long-term struct drift.

**Live-peek API is a read-only oracle, but "read-only" hides side-channels.** §3.4 says "read-only, never mutates state." But `peek_cpu()` returning the current register state of a running CPU requires either a stop-the-CPU (making it observably intrusive) or a best-effort sampling (data may be inconsistent across registers). On a running system, `peek_domain()` returning "active, currently processing IPC from task X" is side-channel information that enables timing attacks. The spec says "default-off with explicit enable cap" in §8 — this must be promoted to an invariant in §4, not left as an open question.

---

## Divergences from precedent

**Humility (Hubris) vs. NARF's GDB stub:** Humility is the closest philosophical precedent. Its key insight is that the debugger should encode domain semantics (tasks, capability grants, IPC patterns) as first-class commands rather than providing raw register/memory access. NARF's GDB stub (`gdb_stub_start` + standard RSP) goes the opposite direction — it exposes raw GDB RSP, which is architecture-specific register dumps and memory reads. This is a pragmatic choice (GDB and LLDB are already installed on every developer workstation), but it means domain-aware debugging requires a GDB Python script or a Humility-style companion tool. The spec should at a minimum define the custom `q` packet extensions (`qNarfDomain`, `qNarfCapRoot`, `qNarfTask`) that expose NARF-specific state, even if the initial implementation is a stub that returns "not yet implemented."

**Linux kdump vs. NARF's CoreImage:** Linux kdump uses a second kernel to capture the crash — it can write to disk because it has a functioning block stack. NARF's panic path has no second kernel and no guarantee of a functional block stack. The CoreImage must go to console by default, which is lossy (console buffer is small, serial output is slow). For any crash dump larger than ~64 KiB, console output is impractical for the full image. The persistent storage path requires `drivers/nvme` which is Stage 4 — so for Stages 1–3, crash dumps are console-only and must be designed to be *useful* at console scale. This means the CoreImage's "most critical first" ordering matters: register state and domain fault attribution must come before the recorder snapshots. The spec does not specify the section ordering.

**FreeBSD hwpmc vs. NARF's CounterSet:** FreeBSD's `hwpmc` is a clean PMU abstraction that supports both sampling and counting, with event group semantics. NARF's `CounterSet` mirrors this design. The key difference: FreeBSD's PMU attribution is per-process; NARF's is per-domain. A PMU sample interrupt fires on a CPU; the domain attribution must use the domain-ID stored in the faulting task's context block, not the PID. This requires that the PMU overflow interrupt handler reads the current domain from the scheduler's per-CPU state, which is a `scheduler/` dependency not listed in §6.

**Solaris mdb vs. NARF's post-mortem path:** mdb is a two-pass debugger (live + post-mortem, same tool). NARF splits these: GDB stub for live (Stage 4), core dump parser tooling for post-mortem (also Stage 4). The split is fine but means no post-mortem capability until Stage 4. In practice, Stage 1–3 crashes will produce a console dump that must be manually parsed, which is a significant developer experience gap. Consider adding a minimal in-QEMU crash-state printer (not a full debugger) that runs from the panic hook and prints the most critical fields in a structured text format that can be grepped.

---

## Proposed spec changes

- **§4 Invariants — add graceful-degradation when `tracing/` is not initialized:** "If `tracing/snapshot_panic_rings()` is called before `tracing/` has initialized its rings, it must be a safe no-op. `panic_hook` must check for this condition and proceed with register + memory-map sections even if recorder snapshots are unavailable."

- **§3.3 Crash dump — specify section ordering:** "Sections are written in this priority order: header, domain fault section, per-CPU register state, memory map, cap-table summaries (Stage 4), recorder snapshots. The panic path writes as many sections as time/space allow; the dump is valid if any sections are present, not only if all are present."

- **§3.2 GDB stub — define custom q-packet extension set:** "The GDB stub implements the following NARF-specific query packets in addition to standard RSP: `qNarfDomains` (list active domains and their PKS/MTE configuration), `qNarfCapRoot(task_id)` (return cap-table root summary as a structured text block), `qNarfTask(task_id)` (return async executor state for a task: pending/blocked/running + reason). These return `E00` until Stage 4 implementation; the packet names are reserved." This prevents incompatible naming if a maintainer implements them ad-hoc.

- **§4 Invariants — promote live-peek default-off to an invariant:** Move from §8 open question to §4: "Live-peek operations (`peek_cpu`, `peek_domain`, `peek_cap_root`) are disabled at boot and can only be enabled by presenting a `Cap<Diagnostics, Activate>` that was minted at boot under a documented boot-time flag. Enabling live-peek is logged by `tracing/` as a USDT event."

- **§3.1 PMU — disallow multiplexed counters for delta-per-call use:** "When `CounterSet` is being used for per-call delta measurement (e.g., via `FnTime` in `tracing/`), multiplexing must be disabled. If more hardware events are requested than physical counters permit, `open_counter` returns `Err(TooManyCounters)`. Scaled multiplexed reads are valid only for time-averaged profiling."

- **§3.3 CoreImage — add build ID field to header:** "The CoreImage header must include the kernel build ID (a SHA-256 hash of the kernel binary, or the GNU `.build-id` ELF section content) so post-mortem analysis tools can verify symbol compatibility."

---

## Open invariants / cross-subsystem hazards

**`tracing/` §3.3 (snapshot trigger) → `observability/` §3.3 (panic hook):** The panic hook calls `tracing::snapshot_panic_rings()`. But the tracing spec's snapshot implementation requires the flight-recorder ring cursors to be frozen. If the panic occurred inside the tracing subsystem's own ring-write path, the cursor may be in a partially-updated state. `observability/` must either detect this (check for a "tracing_inside_write" per-CPU flag) or accept that the recorder snapshot may be corrupt. Define a per-CPU `tracing_panic_safe` flag that `record()` sets on entry and clears on exit; `snapshot_panic_rings()` skips rings that are live-writing.

**`scheduler/` per-CPU state → PMU domain attribution:** PMU overflow interrupts arrive at a physical CPU. The interrupt handler in `observability/` must attribute the sample to the domain currently active on that CPU. This requires reading `scheduler::current_domain(cpu)` from inside an interrupt handler. The scheduler's per-CPU state must be accessible without locks from interrupt context (it should be in a per-CPU struct, not behind a `Mutex`). This is not explicitly stated in either spec; `scheduler/` §3 must add a `current_domain(cpu: CpuId) -> DomainId` function that is async-signal-safe.

**`capabilities/` §? → `observability/` §3.4 (peek_cap_root):** `peek_cap_root(task: TaskId)` returns a `CapRootView`. The cap table is in `capabilities/` domain. Reading it from a diagnostic context (no capability-check, just a read) is a capability bypass: an observer without a cap can see what caps a task holds. The cap root view must be a *summary* (counts, types, no tokens/handles), not a raw dump of the cap table. The `CapRootView` type must be defined in `capabilities/` with these constraints, not in `observability/`.

**`frame/` §? panic reentrancy:** If `panic_hook` itself panics (e.g., because the domain-fault section writer has a bug), `frame/`'s panic path re-enters. The spec says `panic_hook` "does not rely on heap, scheduler, or IPC" but it does not say it is reentrant. A double-fault in the panic hook should produce at minimum a register dump to the console via the lowest-level console path, bypassing all NARF infrastructure. This needs a `frame/`-level "bare metal panic" path that `observability/`'s panic hook eventually calls.

---

## Additional opinionated commentary

The GDB stub is a necessary evil. The right design is a Humility-style external tool that understands NARF's domain semantics, but that requires a protocol and a userspace client tool — significant development effort. GDB RSP is available today and understood by every developer. The pragmatic path is: implement minimal GDB RSP in Stage 4 (halt, registers, memory read), ship a GDB Python script that adds `narf-domains`, `narf-tasks`, and `narf-caps` commands, and document that the Python script is the intended interface. Raw GDB memory commands should be available but not documented as the primary workflow.

The PMU multiplexing accuracy problem is more serious than the spec acknowledges. At domain-switch frequencies possible in NARF (50–200 cycles per WRMSR, potentially thousands per millisecond), the PMU counter active-time can be very short per domain. Scaling factors of 10x or 100x become common, and scaled numbers are not useful for per-domain attribution. The real solution is to read PMU counters *at domain-switch time* and accumulate domain-specific totals — identical to how perf_event_open handles task-switch perf counters in Linux. This is a design that must be coordinated with the `memory/` domain-switch path, not implemented purely in `observability/`.
