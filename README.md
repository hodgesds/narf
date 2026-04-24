# NARF

**Not Another Rust Frankenkernel** — a Rust *framekernel* that combines the
safety of a microkernel TCB with the performance of hardware-assisted
intra-address-space isolation.

> "NARF: Because security shouldn't feel like a speed limit."

Status: **Stage 3 composition landed**. Stages 1 ("Skeleton") and 2
("Barrier") are closed; Stage 3 ("Flow") has every subsystem the
ROADMAP lists for it wired end-to-end, with `smoke_exit_gate_*`
proving the `DmaBuffer → Narf-Ring → cap-gated consumer` composition
on both x86_64 and aarch64. Stage 4 ("Compatibility") — real PKS/MTE
enforcement on buffer pages, driving real virtio hardware, IOMMU
programming, user-mode consumer via `abi/` — is next. See `STATUS.md`
for current test tallies and `ROADMAP.md` / `STAGE3.md` for the plan.

## Core ideas

- **Framekernel architecture.** A minimalist Rust TCB ("the Frame") carves its
  own Ring 0 address space into 16 hardware-protected domains using Intel
  PKS/PKU (on x86_64) or ARM Memory Tagging Extension (on aarch64). Drivers
  run in these domains — same virtual map, hardware-blocked from each other.
- **Async-first scheduling.** Every syscall, interrupt, and driver task is a
  stackless Rust `Future` on a global executor. A caller can donate its
  remaining time-slice directly to the callee ("direct context transfer") to
  eliminate double-trip context switches.
- **Narf-Ring IPC.** Zero-copy shared-memory rings. Data moves via Rust
  ownership transfer — the bytes never move in physical RAM.
- **Capability-based security.** No root user. Every operation requires an
  unforgeable `Cap<T>` token enforced by the Rust type system.
- **Hardware bypass where it pays off.** P2P DMA, User Interrupts (UIPI),
  Global LTO across the whole kernel.

## Repository layout

```
narf/
├── DESIGN.md                 # Verbatim v1.0 vision doc
├── ROADMAP.md                # Stage 1→4 mapped to subsystems
├── GLOSSARY.md               # Framekernel, Narf-Link, Narf-Ring, etc.
│
│ ── Cross-cutting ──
├── arch/                     # HAL: x86_64 + aarch64
├── abi/                      # Kernel↔user boundary
├── security-model/           # Threat model, capabilities × domains
├── build/                    # Global LTO, cross-compile, linker
├── verification/             # Tests, fuzzing, perf stats, formal methods
├── process/                  # Dev process: humans + AI agents, reviews, security
│
│ ── Subsystems ──
├── frame/                    # TCB: bootstrap, CPU state, privilege config
├── memory/                   # Physical alloc, VM, PKS/MTE domains
├── capabilities/             # Cap tables, Rust-typed tokens
├── scheduler/                # Async executor, direct context transfer
├── ipc/                      # Narf-Ring zero-copy channels
├── interrupts/               # UIPI + IRQ routing
├── io/                       # P2P DMA, IOMMU/SMMU
├── drivers/                  # Framework + virtio/nvme/net/gpu
├── bus/                      # PCIe / MMIO / devicetree enumeration
├── boot/                     # Bootloader handoff
├── console/                  # Early serial + logging
├── time/                     # Monotonic/wall clocks, hrtimers, NTP/PTP
├── rcu/                      # Deferred reclamation: QSBR, epoch, hazard, sleepable
├── block/                    # Block-device trait, I/O scheduler
├── filesystem/               # VFS: cap-addressed nodes, mount, page cache
├── net/                      # Network frame-ring contract (stack in userspace)
├── tracing/                  # USDT, probes, FnTime, flight recorders
├── observability/            # Perf counters, debugger, crash dumps
├── crypto/                   # Primitives, RNG, Cap<Key>, measured boot
├── power/                    # Idle states, DVFS, suspend/resume, thermal
├── lib/                      # no_std shared primitives: sync, collections, bitmaps
└── userspace/                # Process model, ELF, relibc
```

Every subsystem folder contains:

- `specification/spec.md` — the design contract (8-section template).
- `research/README.md` — annotated reading list of primary and secondary sources.
- `research/summaries/` — distilled summaries of load-bearing references.

## Target architectures

Dual-primary from day one: **x86_64** and **aarch64**. Every spec must
address both in its *Architecture notes* section.

## Roadmap

| Stage | Theme |
| --- | --- |
| 1. Skeleton | Bootloader + async executor + serial console |
| 2. Barrier | PKS/MTE domain switching + UIPI |
| 3. Flow | Narf-Ring + capabilities + first VirtIO driver |
| 4. Compatibility | relibc integration; run standard Rust binaries |

See [`ROADMAP.md`](./ROADMAP.md) for the stage × subsystem matrix.

## Where to start reading

1. [`AGENTS.md`](./AGENTS.md) — token-efficient navigation map (for AI
   agents and humans in a hurry).
2. [`DESIGN.md`](./DESIGN.md) — the one-page vision.
3. [`GLOSSARY.md`](./GLOSSARY.md) — vocabulary you'll see repeated.
4. [`STAGE1.md`](./STAGE1.md) — topo-sorted Stage 1 implementation
   order once you're ready to write code.
5. [`process/specification/spec.md`](./process/specification/spec.md) —
   how to contribute (binding on both humans and AI agents).
6. [`security-model/specification/spec.md`](./security-model/specification/spec.md)
   and [`arch/specification/spec.md`](./arch/specification/spec.md) — the
   two specs every other subsystem depends on.
