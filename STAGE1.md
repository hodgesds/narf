# Stage 1 Implementation Order

Derived from the v0.2-era spec dependency graph. The order below is
the minimum sequence in which a single implementer can land Stage 1
without back-tracking. Independent tracks are flagged so a small team
can parallelise.

**Stage 1 exit criterion** (from `ROADMAP.md`): kernel boots on
QEMU for x86_64 *and* aarch64, prints a log line from a `Future`
driven by the global executor, and survives a timer-driven yield
loop.

## Wave 0 — pure-utility, no other deps

These can land in any order; nothing depends on them being later.

1. **`lib/`** — typed IDs (`CpuId`, `DomainId`, `TaskId`, …),
   `SpinLock`, `IrqSafeSpinLock`, `Once`, `OnceLock`, `Bitmap`,
   `IntrusiveList`, base assertion macros.
   *Spec:* `lib/specification/spec.md` §3 (Stage 1 row).

2. **`build/`** — Cargo workspace, `build-std`, linker scripts per
   arch (with `.boot` section + `.boot before .text` assertion),
   `cargo xtask {run,test,image}`, QEMU harness, **CPU-feature
   flags emitted to rustc** (`+pks` on x86_64; `+mte` on aarch64),
   reproducible-build flags.
   *Spec:* `build/specification/spec.md` §3–§5. Required for
   everything that follows.

## Wave 1 — boot ↔ console ↔ HAL trio

These three are cyclically coupled by the MMU-handoff protocol
(`console/` §3.1) and must land together as one piece of work.

3. **`arch/` (Stage 1 subset)** — `Cpu`, `Mmu` (base + 2 MiB / 1 GiB
   page sizes; PKS/MTE primitives stubbed), `IntCtrl`,
   `Timer`, `DomainPrimitive` (constant `BACKEND` only — full
   save/restore lands in Wave 4). Includes the
   `compiler_fence(SeqCst)` pair around every MSR/system-register
   intrinsic — non-negotiable per `arch/` §4 / `build/` §4.
   *Spec:* `arch/specification/spec.md` §3–§5.

4. **`boot/`** — Limine handoff (x86_64) / U-Boot FDT entry
   (aarch64), `validate_boot_info` (untrusted-input checks),
   passes `uart_phys` and `uart_virt` in `BootInfo`, calls
   `console::early_init` immediately after parse.
   *Spec:* `boot/specification/spec.md` §3–§5.

5. **`console/`** — 16550A (x86_64) / PL011 (aarch64) driver,
   `early_init`, `write_str`, `panic_sink`, **`remap_to_virtual`
   plus the AtomicPtr base-pointer machinery.** The handoff
   protocol in `console/` §3.1 is co-designed with `memory/`'s
   MMU bring-up.

## Wave 2 — memory, then frame

6. **`memory/` (Stage 1 subset)** — buddy frame allocator,
   `PhysFrame` / `VirtAddr` types, `Folio { order, head }`
   primitive, page-table manipulation (4 KiB + 2 MiB + 1 GiB on
   x86_64; 4 KiB + 2 MiB + 1 GiB on aarch64), identity map for the
   Frame, `DomainId::*` reserved constants, slab-cache header type
   (real cache + magazines land in Stage 2).
   **MMU bring-up calls `console::remap_to_virtual` inside the
   critical section** — without this Stage 1 silently dies at
   paging-enable.
   *Spec:* `memory/specification/spec.md` §3, §4 (subset),
   §5 (page-size tables), §6.

7. **`frame/`** — boot CPU bring-up (BSP only; APs are Stage 2),
   per-CPU `CpuLocal` with `current_domain` + `saved_domain_state`
   stubs (Stage 1 has only `DomainId::FRAME`, so the slots exist
   but never change), GDT/IDT/TSS (with **IST1=NMI, IST2=#DF,
   IST3=#MC, IST4=#VC, IST5..7 reserved**) on x86_64 / EL1 vector
   table on aarch64, trap-prologue PKRS-save scaffolding (no-op
   in Stage 1 since only one domain exists), panic path that
   broadcasts an IPI-NMI on SMP (Stage 2 wires the IPI; Stage 1
   stubs).
   *Spec:* `frame/specification/spec.md` §3–§5.

## Wave 3 — verification harness, time, scheduler skeleton

8. **`verification/` (Stage 1 subset)** — `#[kernel_test]` macro,
   QEMU exit-code harness wired into `cargo xtask test`,
   trivial pass/fail test. Required by every subsequent piece so
   we can run things.
   *Spec:* `verification/specification/spec.md` §6, §7.

9. **`time/` (Stage 1 subset)** — `Instant` from TSC (x86_64) /
   `CNTPCT_EL0` (aarch64), `now_monotonic`, `now_monotonic_raw`,
   per-CPU "next deadline" cache (so `next_deadline()` is O(1)
   when `power/` lands), basic timer wheel for `sleep_until`.
   No SMP skew handling yet (Stage 2).
   *Spec:* `time/specification/spec.md` §3, §7.

10. **`scheduler/` (Stage 1 subset)** — single-CPU cooperative
    executor, intrusive ready queue, `spawn`, `yield_now`,
    waker plumbing. Stage 1 has only one CPU, only `DomainId::FRAME`,
    no preemption. The `report_quiescent` hook is wired through
    every `Future::poll` even though `rcu/` is a no-op stub.
    *Spec:* `scheduler/specification/spec.md` §3.1, §3.2 (read
    topology only, n=1), §7.

## Wave 4 — RCU stub + tracing infra

11. **`rcu/` (Stage 1 subset)** — API surface (`Atomic<T>`,
    `ReadGuard<'g>`, `pin`, `sync` stub returning ready
    immediately, `defer_drop` queue stub). The executor's
    `report_quiescent` call exists but reclamation is a no-op.
    Real QSBR + epoch lands in Stage 2. Critical to land the API
    now so consumers don't have to retrofit the type signatures.
    *Spec:* `rcu/specification/spec.md` §3, §7.

12. **`tracing/` (Stage 1 subset)** — `usdt!` macro infrastructure
    (compile-time markers + `.note.narf.probes` ELF section),
    basic flight-recorder ring (`Recorder<E>` + `record`), no
    arming and no tracer task yet (those are Stage 2). Hot-path
    cost when unarmed must be one nop — measured in
    `verification/` immediately.
    *Spec:* `tracing/specification/spec.md` §3.1, §3.3, §7.

## Wave 5 — observability + crypto baseline

These can land in either order; both depend only on what's above.

13. **`observability/` (Stage 1 subset)** — PMU baseline (Cycles,
    Instructions only), `panic_hook` writing a structured CoreImage
    to console (with `tracing/` snapshot graceful-degradation per
    §3.3 if the tracer is not yet initialised), no GDB stub yet.
    *Spec:* `observability/specification/spec.md` §3.1, §3.3, §7.

14. **`crypto/` (Stage 1 subset)** — SHA-256 + BLAKE3 only
    (needed for build-hash and Stage 2 measurement prep), entropy
    plumbing (`RDSEED`/`RNDR` reads), `BootKeyStore` stub. No
    AEAD, no key caps yet.
    *Spec:* `crypto/specification/spec.md` §3, §7.

## Stage 1 exit gate

The kernel image, on either x86_64 or aarch64 in QEMU, must:

1. Boot through `boot::_start` → `frame::init_bsp`.
2. Print `mmu: handoff...` from physical UART, then continue
   logging through the virtual UART (verifies `console::remap_to_virtual`).
3. Spawn a Future via `scheduler::spawn` that prints "hello from
   future N" on each timer tick for 10 seconds, then exit cleanly.
4. Run the `verification/` smoke test against this kernel and
   produce a `Pass` exit code.
5. Boot-time domain enumeration log: confirm every reserved
   `DomainId::*` from `security-model/` §4.1 has been declared
   (even if PKS/MTE enable is deferred to Stage 2).
6. **No `unsafe` block in any Stage 1 code may directly touch a
   privileged MSR / system register without going through the
   `arch/` HAL wrapper** — Clippy lint or post-build scan
   verifies, per `build/` §8.

## What deliberately does not land in Stage 1

- SMP / AP bring-up (Stage 2).
- PKS / MTE actual enable (Stage 2 — the hooks exist; the rights
  are `all-allow` in Stage 1).
- Any driver beyond console (Stage 2 framework, Stage 3 first device).
- Capabilities runtime — the type sketches exist in source,
  but `Cap::invoke` is `unimplemented!()` (Stage 3).
- Userspace, ABI rings, IPC, block/filesystem/net (Stages 3–4).

## Critical-path analysis

Longest dependency chain:

```
  build → arch → boot ↔ console ↔ memory → frame
                                         → time → scheduler → tracing → verification (smoke)
                                         → rcu (stub)
                                         → observability (panic hook)
                                         → crypto (basic hashes)
```

Wave 1 (`arch ↔ boot ↔ console`) is the highest-risk chunk because
of the MMU-handoff cycle. Land it as one atomic PR series with all
three subsystems present from the first commit; do not ship `boot/`
without `console/`'s `remap_to_virtual` and the `memory/` handoff
caller in the same train.

Waves 4 and 5 are fully parallel — two implementers can take
`rcu`+`tracing` and `observability`+`crypto` simultaneously after
Wave 3 lands.
