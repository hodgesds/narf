# AGENTS.md — NARF Navigation Map

Token-efficient orientation for AI agents (and humans in a hurry).
Everything here is terse by design. Follow links for depth.

## Project in 3 lines

- **NARF** = Rust *framekernel*: minimal Ring-0 TCB + 16 hardware
  domains (PKS on x86_64, MTE on aarch64).
- **Async-first** executor, zero-copy Narf-Ring IPC, capability-typed
  access control, no root user.
- **Status:** Stages 1–4 closed. Stage 4 exit gate met for the
  in-tree shell + coreutils (`cargo xtask run-interactive` types
  `echo hello world` over serial; full IRQ-4 → byte ring → fd 0 →
  shell → fd 1 → UART chain). `cargo xtask test` runs 5022+ smokes
  / 0 fail / 73 skip on x86_64 + aarch64. Stage 5 "Silicon" — boot
  on AMD Zen2 Renoir + Phoenix HawkPoint1 laptops — is in progress.

## Canonical docs (read when relevant, not always)

| File                | When to read                                    |
| ------------------- | ----------------------------------------------- |
| `DESIGN.md`         | Need the v1.0 vision verbatim.                  |
| `GLOSSARY.md`       | Unknown term (Framekernel, Narf-Ring, Domain…). |
| `ROADMAP.md`        | Which subsystems are active in which stage.     |
| `STAGE1.md`         | Writing Stage 1 code — topo-sorted order + critical path. |
| `process/…/spec.md` | **Before touching anything** — review bars, AI-agent rules. |
| `security-model/…`  | Any TCB or security-critical work.              |
| `verification/…`    | Writing tests, perf numbers, CI gates.          |

## Repo map (one line per folder)

| Folder              | Owns                                                     |
| ------------------- | -------------------------------------------------------- |
| `arch/`             | HAL trait surface + per-arch impls (x86_64, aarch64).    |
| `abi/`              | Kernel↔user boundary: async submission/completion rings. |
| `security-model/`   | Threat model, caps × domains composition.                |
| `build/`            | Cargo workspace, LTO, linker scripts, xtask, QEMU.       |
| `verification/`     | Test taxonomy + statistical perf protocol.               |
| `process/`          | Contribution flow, AI-agent rules, bug/sec handling.     |
| `frame/`            | TCB: boot CPU, traps, panic path, domain entry hooks.    |
| `memory/`           | Phys alloc, VM, PKS/MTE domain manager.                  |
| `capabilities/`     | Cap tables, `Cap<T, R>` Rust types, derivation.          |
| `scheduler/`        | Global async executor, direct context transfer.          |
| `ipc/`              | Narf-Ring zero-copy rings, ownership transfer.           |
| `interrupts/`       | UIPI, GICv3, IRQ routing into domains.                   |
| `io/`               | DMA, IOMMU/SMMU, P2P DMA.                                |
| `drivers/`          | Driver framework; subfolders per driver.                 |
| `drivers/virtio/`   | First real driver (Stage 3).                             |
| `drivers/{nvme,net,gpu}/` | Stage 4 drivers.                                   |
| `bus/`              | PCIe ECAM / MMIO / devicetree enumeration; produces devices for `drivers/`. |
| `boot/`             | Bootloader handoff, memory map parse.                    |
| `console/`          | Early serial (16550A / PL011), panic sink.               |
| `time/`             | Monotonic + wall clocks, hrtimers, clocksource/clockevent, NTP/PTP. |
| `rcu/`              | Deferred reclamation: QSBR (default), epoch, hazard pointers, sleepable (cap-gated). |
| `block/`            | Generic block-device trait + I/O scheduler; sits above drivers, below filesystem. |
| `filesystem/`       | VFS: cap-addressed nodes, path resolution, mount tree, page cache. |
| `net/`              | Frame-ring contract; real L3/L4 stack lives in userspace daemon. |
| `tracing/`          | USDT, dynamic probes, FnTime, flight-recorder rings, tracer task. |
| `observability/`    | PMU counters, GDB stub, crash dumps (state inspection).  |
| `crypto/`           | Primitives, DRBG, `Cap<Key>`, signed manifests, measured boot, SecureRing. |
| `power/`            | Idle states, DVFS governor, suspend/resume, thermal, runtime PM. |
| `lib/`              | no_std sync, intrusive collections, bitmaps, typed IDs, assertion macros. |
| `userspace/`        | Process model, ELF loader, relibc glue.                  |

Every folder has: `README.md` (1-paragraph pointer), `specification/spec.md`
(8-section template), `research/README.md` (annotated reading list),
`research/summaries/*.md` (distilled primary sources for load-bearing refs).

## Spec template (all `specification/spec.md` files)

`1. Purpose & scope` → `2. Assumptions` → `3. Public interface` →
`4. Invariants` → `5. Architecture notes (x86_64, aarch64)` →
`6. Dependencies` → `7. Stage assignment` → `8. Open questions`.

When modifying a subsystem interface, update §3 **in the same PR**.

## Stage → active subsystems (exit criteria in `ROADMAP.md`)

| Stage | Theme          | Active                                              |
| ----- | -------------- | --------------------------------------------------- |
| 1     | Skeleton       | boot, console, frame, memory (basic), scheduler (basic), arch (partial), build, verification (harness), tracing (USDT infra), observability (PMU basics + crash), crypto (SHA-256 + BLAKE3), time (monotonic + basic timers), rcu (API surface + stub), lib (minimum primitives) |
| 2     | Barrier        | memory (PKS/MTE), interrupts (UIPI), arch (full), security-model v0.5, drivers (framework), tracing (tracer domain), crypto (AEAD + manifest verify), time (hrtimers + SMP sync), scheduler (SMP + topology + hot-plug up), rcu (QSBR + epoch), bus (PCIe + MMIO scan), power (C-states), lib (SeqLock + intrusive collections) |
| 3     | Flow           | ipc, capabilities, io, abi, drivers/virtio, scheduler (donation + affinity + budgets), tracing (dynamic probes + FnTime), crypto (SecureRing + per-task RNG), block (core trait), filesystem (VFS + initramfs), rcu (hazard + sleepable), net (contract + loopback), bus (hot-plug + MSI-X), power (DVFS governor + runtime PM) |
| 4     | Compatibility  | userspace (Linux-compat syscall surface, dyn-linker, /dev/pts), drivers/{nvme,net,gpu,usb,input,hwmon}, verification (expanded), observability (GDB + peek + FB status-panel), tracing (HW trace), crypto (TPM / measured boot), block (multi-queue + discard), filesystem (virtiofs + persistent FS + ext2 + devpts), time (POSIX timers + NTP/PTP hooks), net (userspace stack-daemon protocol + iface::for_dst per-flow routing), power (suspend/resume + thermal) |
| 5     | Silicon        | drivers/gpu (AMDGPU DCN 2.0 / 3.5 modeset), drivers/platform (EC), drivers/input (I²C-HID touchpad), drivers/wireless (iwlwifi data path + WPA2-PSK), time (AMD MSR_PSTATE0 calibration), fb (status panel), power (S3 suspend + thermal via EC) |

## TCB definition (matters for review bar)

`frame/` + `memory/` domain manager + `capabilities/` core + executor
core in `scheduler/` + `security-model/`. Touching any = TCB change =
two maintainers + `security-review` pass mandatory.

## Load-bearing invariants (cheat sheet)

These are the rules that, if violated, make the design unsound.
Each links to its owning spec for the full text.

| # | Rule | Spec |
|---|---|---|
| 1 | PKRS / TCF lives in **task-context** `DomainSavedState`; scheduler saves on preempt + restores before any access in resumed task's domain. Direct context transfer restores before callee's first instruction. | `memory/` §4, `scheduler/` §4, `frame/` §4 |
| 2 | `enter_domain`/`exit_domain` paired; nested same-domain entry is an assertion. Trap prologue saves PKRS to trap frame and switches to `DomainId::FRAME` before any Rust runs. | `frame/` §3–§4 |
| 3 | `DomainPrimitive::BACKEND = Pks \| Mte` is a **type-level** contract — code that needs O(1) rights flip must `#[cfg]` to `Pks` or accept the MTE pointer-tagging cost. | `arch/` §3–§4 |
| 4 | All domain / TLB / cache / MSR intrinsics are wrapped with `compiler_fence(SeqCst)` before AND after the `asm!`. Fat LTO can otherwise reorder loads/stores across a `WRMSR`. | `build/` §4, `arch/` §4 |
| 5 | **Holding `Cap<T, R>` proves *prior grant*; only `Cap::invoke()` proves *current validity*.** Epoch revocation is O(1); never dereference around `invoke`. | `capabilities/` §3–§4 |
| 6 | `CapSlot` is **128 bits** (generation + index + rights + type_tag), updated via CMPXCHG16B / LDXP-STXP. | `capabilities/` §3 |
| 7 | Dropping a submission Future **requests** cancellation (`OpCode::Cancel`); resources release only on terminal completion (`Ok` \| `Cancelled` \| `CancelRequested` \| `Error`). | `abi/` §3.1 |
| 8 | Narf-Ring: **explicit release/acquire pair** on every index transition (`STLR`/`LDAR` on aarch64); cache-line partitioned head/tail/payload; pointer **retag** on cross-domain aarch64 writes; `Result<T, RecvError>` on `recv`; SQ-full **blocks via waker**, CQ-full sets **overflow flag**. | `ipc/` §4, `abi/` §4 |
| 9 | `console::remap_to_virtual(VirtAddr)` is part of the MMU bring-up critical section — without it the console silently dies the moment paging turns on. | `console/` §3.1, `memory/` §6, `boot/` §4 |
| 10 | `DomainId` namespace is **owned by `security-model/` §4.1** (FRAME=0, CAPS=1, MEMORY_MGR=2, SCHED=3, IPC=4, TRACER=5, KEYS=6, OBSERVE=7, USERSPACE_K=8, DRIVER(0..5)=9..14, SCRATCH=15). `memory/` §3 mirrors as `DomainId::*` constants. |
| 11 | QSBR readers may **not `await`** inside a critical section — only sleepable-RCU may. `ReadGuard` is `!Send` to enforce. Sleepable-RCU is **cap-gated** with budget + timeout-bounded sync. | `rcu/` §3.3, §3.5 |
| 12 | `SeqLock<T: Copy>` bound is load-bearing (torn-state sampling is UB without `Copy`). `SpinLockGuard<'_, T, IrqState>` typestate makes mixed-IRQ-context use a compile error. | `lib/` §3 |
| 13 | AI-originated TCB PRs include `safety-argument.toml` referencing `security-model/` invariants by `section#Lline`; CI rejects unresolvable refs. Audit trail is SLSA in-toto + `narf-agent` predicate. | `process/` §6.3, §6.5 |

## Sync → async bridge primitives (`narf_scheduler`)

Drivers and sync subsystems should **never hand-roll spin loops on
hardware registers**. Use the right primitive from `narf_scheduler`:

| Primitive | When to use | Lock-safe? | CPU |
|---|---|---|---|
| `spawn(fut)` | Normal async work in executor context | yes | scheduler-managed |
| `yield_now().await` | Cooperative yield from inside an async task | yes | yields |
| `block_on(fut)` | Sync caller bridging to async path; **no IrqSafeSpinLock held** | **no** (halts on IRQ) | idles between IRQs |
| `block_on_spin(fut)` | Same as above but caller holds an `IrqSafeSpinLock`, is in an IRQ handler, or runs in a panic / SMP-startup path with IRQs disabled | yes | 100% spin |
| `sleep_pumps::run()` | Inside any waiting loop (or as a periodic tick) — drives FB drain, cursor pump, future audio drain | yes | trivial |

**Constraints both `block_on` variants share:**
- **Never call from inside an executor poll** — re-entrant deadlock; the
  executor's polling loop blocks waiting for a future that needs the
  same loop to make progress. No runtime check; caller's responsibility.
- **The awaited future must be IRQ-driven or self-waking.** A future
  that depends on another scheduler task to make progress will hang
  because `block_on` doesn't run the executor.

**Cooperative `block_on` lock rule (load-bearing):** holding any
`IrqSafeSpinLock` across `block_on` deadlocks. The lock disables IRQs
while held and `halt_until_irq` waits for one. Migration patterns
should drop the lock, capture any owned data (clone an `Arc`, copy a
phys address), then `block_on(...)`. Use `block_on_spin` if you can't.

**Same rule applies inside the awaited future.** Async driver
functions that `block_on` is supposed to bridge to (e.g. NVMe's
`submit_io_irq_async`) currently take `&mut Controller` via an
`IrqSafeSpinLock` guard for their *entire* duration — which means
the IRQ wake they're waiting for can never fire. The migration is
**not** "wrap existing sync code in block_on"; it's:

1. Convert per-driver lock from `IrqSafeSpinLock` to a regular
   `Mutex` (safe to hold across await), OR
2. Restructure the async path to release the lock before the
   `.await` point and re-acquire after.

Until that lands, `block_on(driver_async_fn(...))` will deadlock on
real HW. `block_on_spin` is fine because it doesn't disable IRQs.

`block_on` and `block_on_spin` both **panic on call from inside an
executor poll** (`CURRENT_TASK != 0`) — caught at the call site
instead of becoming a silent re-entrant deadlock.

**Compile-time enforcement: `IrqSafeSpinLockGuard` is `!Send`.** Any
`async fn` that holds an `IrqSafeSpinLock` guard across `.await`
becomes itself `!Send`, breaking the `Send` bound in
`narf_scheduler::spawn`. Build error instead of a runtime hang.
Use a block scope (`{ let g = lock.lock(); ... }; foo().await`) to
shrink the guard's lifetime explicitly — `drop(g)` does **not**
shrink an async future's captured-state lifetime the way it does
in sync code.

### Sync-wrapper decision tree

A sync wrapper (`BlockDeviceSync::read`, future `FsOps` sync paths,
etc.) needs `block_on` ONLY when its underlying driver path
**waits on an IRQ**. If the driver polls a hardware register
(MMIO read of a "done" bit) without IRQ involvement, the existing
hold-lock-across-busy-spin pattern is correct — no IRQ wake means
no deadlock risk under IrqSafeSpinLock.

| Sync wrapper | Underlying path | Migration? |
|---|---|---|
| `NvmeBlockSync::read/write` | `read_lba`/`write_lba` polled CQE | no |
| `AhciBlockSync::read/write` | polled DD bit | no |
| `VirtioBlkBlockSync::read/write` | polled used-ring | no |

If a future driver needs IRQ-driven sync I/O (e.g. NVMe over
MSI-X for latency-sensitive workloads), the migration is:
1. Convert the per-driver `IrqSafeSpinLock<Option<Controller>>`
   to `narf_lib::mutex::Mutex<Option<Controller>>` (async-safe).
2. Have the async path take `&self` + internally lock the Mutex.
3. Sync wrapper calls `block_on(driver.read_async(...))`.

**Why this exists:** the audit (commit `de5dabc`) found drivers
re-implementing 10M-iteration spin loops on MMIO registers in
NVMe / AHCI / e1000 / r8169 / ixgbe. Each spin froze the cursor /
FB / serial console for the wait duration. The unified primitives
let drivers hand the wait off to a single mechanism that ticks
sleep_pumps + idles cleanly.

**Per-driver migration is bespoke.** Drivers expose async functions
(e.g. NVMe's `submit_io_irq_async`); their sync wrappers
(`BlockDeviceSync::read`/`write`) call `block_on(...)` after dropping
their per-driver locks. Don't sweep `spin_tick` everywhere — the
abstraction lives in `block_on`, not in every driver.

## Stage::Late spawn rule (load-bearing)

`narf_scheduler::init()` panics on a second call (since commit `3f4eadd`
— `__reset_queues_for_test` is the test-only equivalent). The historic
"second `init()` in `run_async_demo` silently wipes Stage::Late spawns"
bug killed the cursor pump and USB HID supervisor for weeks before
diagnosis; the panic now surfaces double-init at the call site.

Drivers can spawn from Stage::Late initcalls again; the spawn survives.

## AI-agent rules (from `process/…/spec.md`)

Binding. The full spec governs; this table is a cheat sheet.

| Action                                  | Allowed?                       |
| --------------------------------------- | ------------------------------ |
| Open a PR                               | ✅                             |
| Merge to `main`                         | ❌ (human maintainer only)     |
| Touch TCB files                         | ◐ Must attach safety argument; 2 maintainer review inc. security. |
| Modify `process/…/spec.md`              | ❌ unless human explicitly prompts |
| Modify `security-model/…/spec.md`       | ❌ unless Security-critical class + human prompt |
| Sign a release                          | ❌                             |
| Sole reviewer of security fix           | ❌                             |
| Use repo secrets beyond one scoped task | ❌                             |

**Every AI-originated PR must include:** the originating prompt, the
model + version, and a `Co-Authored-By:` trailer naming the agent.

## Change classes (from `process/…/spec.md` §4)

| Class              | Reviewers                               | Notes                                   |
| ------------------ | --------------------------------------- | --------------------------------------- |
| Trivial            | 1                                       | docs/typos/formatting only              |
| Standard           | 2 (1 subsystem owner)                   | default                                 |
| Interface          | subsystem owner + 1 maintainer          | must update `specification/spec.md` §3  |
| TCB                | 2 maintainers (1 security)              | signed commit, security-review skill    |
| Security-critical  | private embargo flow (`process/` §8)    | not a normal PR                         |

## Merge gates (all must be green)

1. Build (x86_64 + aarch64, release + debug).
2. `cargo clippy --all-targets -- -D warnings`.
3. `cargo fmt --check`.
4. Unit tests.
5. Functional tests (QEMU on both arches).
6. Spec consistency: §3 updated if interface changed.
7. Perf gate (if `perf-sensitive`-tagged) — statistical protocol in
   `verification/…/spec.md` §8.
8. Review bar per change class.

## Performance numbers — never claim without the protocol

From `verification/…/spec.md` §8:

- N ≥ 30 samples (100 if CV > 5%). Dedicated core, freq pinned, SMT
  off, no turbo, ASLR off.
- Report **median + 95% bootstrap CI** (10k resamples) + p95/p99/p99.9.
  Never mean alone. Never a single sample.
- Regression detection: Welch's t-test **and** Mann-Whitney U (both
  must agree). Apply Benjamini-Hochberg FDR (q = 0.05) across the suite.
- Blocking only if significant **and** beyond declared δ.

## Quick commands (once `build/` lands)

```
cargo xtask run   --arch=x86_64
cargo xtask test  --arch=aarch64
cargo xtask image --arch=x86_64 --bootloader=limine
```

(Not available in design phase; documented here so the first
implementer points them here.)

## When in doubt

1. Check this file.
2. Check the target subsystem's `specification/spec.md`.
3. Check `process/…/spec.md` for process questions.
4. Ask a human maintainer.

Do not invent interfaces without updating the spec. Do not claim perf
numbers without the statistical protocol. Do not merge your own PRs.
