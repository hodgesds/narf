# NARF

**Not Another Rust Frame Kernel** — a Rust *framekernel* that combines the
safety of a microkernel TCB with the performance of hardware-assisted
intra-address-space isolation.

> "NARF: Because security shouldn't feel like a speed limit."

Status: **Stage 4 driver-set landed**. Stages 1 ("Skeleton") and 2
("Barrier") are closed; Stage 3 ("Flow") shipped end-to-end with
`smoke_exit_gate_*` proving the `DmaBuffer → Narf-Ring → cap-gated
consumer` composition on both arches. The current round added the
driver framework + 7 working in-tree PCIe drivers: NVMe (full I/O +
MSI-X), virtio-blk-pci, virtio-net-pci, virtio-rng-pci,
virtio-balloon-pci, e1000/e1000e (TX + RX), AHCI (IDENTIFY + READ +
WRITE DMA EXT). Surfaces under it: full IDT (32..=254); generic IRQ
dispatch + vector allocator + `wait_for_irq` future; x2APIC + GICv3
ITS; BAR sizing/map; PCI command + cap-list + extended-cap walkers;
MSI + MSI-X programming on both arches; PCIe driver-match registry;
DTB-driven PCIe ECAM enumeration on aarch64; typed driver-parameter
surface + rights lattice (`Read ⊂ Write/Invoke/Spend`); syscall
versioning via upper 8 bits + stable-ABI promise. Latest tally:
**x86_64 248/0/0, aarch64 190/0/3**. Stage 4 ("Compatibility")
proper — real PKS/MTE enforcement, IOMMU programming, user-mode
consumer via `abi/`, relibc — is next. See `STATUS.md` for current
details and `ROADMAP.md` for the stage × subsystem matrix.

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

## What works today (both arches on QEMU)

Live from boot through `cargo xtask run`:

- BSP bring-up, IDT (32..=254), GDT/TSS with IST stacks; PKS + NX
  enabled on x86_64; GICv3 + GIC ITS bring-up on aarch64.
- Frame allocator + heap, MMU handoff (4-level paging on x86_64,
  TTBR0/TTBR1 split on aarch64), console remap.
- Cooperative async executor with hardware LAPIC-timer / generic-timer
  IRQs; per-task waker plumbing; cap-gated CPU-budget tasks.
- Bus enumeration: PCIe ECAM walk on x86_64 (q35), DTB-driven PCIe
  ECAM walk on aarch64 (QEMU virt with `highmem-ecam=off`),
  virtio-mmio fallback. xtask attaches an `nvme,drive=nvm0` device
  on both arches.
- BAR sizing + MMIO mapping (`bus::bar`); LAPIC-directed MSI-X
  programming on x86_64; GIC ITS doorbell + `MAPC`/`MAPD`/`MAPTI`
  command queue on aarch64.
- IRQ dispatch table + vector allocator + `wait_for_irq.await` future
  bridging hardware IRQs to the async executor.
- NVMe end-to-end on x86_64: BAR0 map, CAP/VS decode, controller
  reset, ASQ/ACQ allocation, IDENTIFY CONTROLLER + IDENTIFY
  NAMESPACE, I/O queue pair (`Create I/O CQ` + `Create I/O SQ`),
  Read/Write LBA with both polled and MSI-X-driven completions.
- virtio-blk-pci modern: cap walk, queue-0 setup, polled +
  IRQ-driven Read/Write sector.
- virtio-net-pci: TX + RX over RX/TX virtqueues with QEMU's
  user-mode net backend.
- e1000 / e1000e: BAR0, MAC read from RAL/RAH, TX + RX descriptor
  rings, link up via CTRL.SLU.
- AHCI ICH9: HBA reset, port enumeration via PORT_SIG/SSTS,
  IDENTIFY DEVICE + READ DMA EXT + WRITE DMA EXT against a
  QEMU-emulated SATA disk.
- virtio-rng-pci + virtio-balloon-pci: structural probe.
- xHCI USB host controller: HCRST reset, DCBAA + Command Ring +
  scratchpad pointers, USBCMD.RS=1 → running.

Cross-driver integration: a unified `block::BlockDeviceSync`
adapter lets the kernel address NVMe + virtio-blk-pci + AHCI
behind one `dyn`-friendly trait. `narf_drivers::bound` keeps a
live inventory of bound drivers; boot prints the full portfolio.
`narf_net::pkt` ships Ethernet / ARP / IPv4 / ICMP echo
parse+build helpers — the e1000 driver's RX loop verifies
interop with QEMU's user-mode net backend.
- Cap-system epoch tables, RCU (QSBR + epoch + hazard pointers),
  filesystem skeleton (devfs + memfs), syscall surface (~230
  syscalls), tracing/observability/PMU sampling probes.

`cargo xtask test --arch=x86_64` passes **255/0/0** smokes;
`--arch=aarch64` passes **193/0/3** (the 3 skips are x86-specific
PCIe surfaces). See `STATUS.md` for the full tally and per-subsystem
breakdown.

## Repository layout

```
narf/
├── DESIGN.md                 # Verbatim v1.0 vision doc
├── ROADMAP.md                # Stage 1→4 mapped to subsystems
├── STATUS.md                 # What's implemented vs. what's planned
├── GLOSSARY.md               # Framekernel, Narf-Link, Narf-Ring, etc.
│
│ ── Cross-cutting ──
├── arch/                     # HAL: x86_64 + aarch64
├── abi/                      # Kernel↔user boundary
├── security-model/           # Threat model, capabilities × domains
├── build/                    # Global LTO, cross-compile, linker, xtask
├── verification/             # Tests, fuzzing, perf stats, formal methods
├── process/                  # Dev process: humans + AI agents, reviews, security
│
│ ── Subsystems ──
├── frame/                    # TCB: bootstrap, CPU state, privilege config
├── memory/                   # Physical alloc, VM, PKS/MTE domains
├── capabilities/             # Cap tables, Rust-typed tokens
├── scheduler/                # Async executor, direct context transfer
├── ipc/                      # Narf-Ring zero-copy channels
├── interrupts/               # x2APIC + GICv3/ITS + IRQ dispatch + wait_for_irq
├── io/                       # P2P DMA, IOMMU/SMMU
├── drivers/                  # Framework + virtio/nvme/net/gpu/tpm
├── bus/                      # PCIe ECAM + DTB walkers, BAR map, MSI-X
├── boot/                     # Bootloader handoff (PVH on x86_64, FDT on aarch64)
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
├── userspace/                # Process model, ELF, syscall table
└── narf-libc/                # libc shim layered over the Narf syscall ABI
```

Every subsystem folder contains:

- `specification/spec.md` — the design contract (8-section template).
- `research/README.md` — annotated reading list of primary and secondary sources.
- `research/summaries/` — distilled summaries of load-bearing references.

## Target architectures

Dual-primary from day one: **x86_64** and **aarch64**. Every spec must
address both in its *Architecture notes* section, and every commit
runs `cargo xtask test` on both arches before landing.

## Roadmap

| Stage | Theme | State |
| --- | --- | --- |
| 1. Skeleton | Bootloader + async executor + serial console | **closed** |
| 2. Barrier | PKS/MTE domain switching + UIPI | **closed** |
| 3. Flow | Narf-Ring + capabilities + first VirtIO driver | **closed** |
| 4. Compatibility | relibc integration; run standard Rust binaries | **structural surfaces + driver readiness landed; relibc gate next** |

See [`ROADMAP.md`](./ROADMAP.md) for the stage × subsystem matrix and
[`STATUS.md`](./STATUS.md) for what specifically is implemented.

## How to run

```sh
# Boot the async demo:
cargo xtask run  --arch=x86_64
cargo xtask run  --arch=aarch64

# Run the kernel-test harness:
cargo xtask test --arch=x86_64
cargo xtask test --arch=aarch64
```

xtask cross-builds against `x86_64-unknown-none` / `aarch64-unknown-none`
with `build-std`, then launches QEMU. NVMe images and the QEMU virt
DTB are generated lazily into `target/`.

## Where to start reading

1. [`AGENTS.md`](./AGENTS.md) — token-efficient navigation map (for AI
   agents and humans in a hurry).
2. [`DESIGN.md`](./DESIGN.md) — the one-page vision.
3. [`GLOSSARY.md`](./GLOSSARY.md) — vocabulary you'll see repeated.
4. [`STATUS.md`](./STATUS.md) — current implementation state.
5. [`process/specification/spec.md`](./process/specification/spec.md) —
   how to contribute (binding on both humans and AI agents).
6. [`security-model/specification/spec.md`](./security-model/specification/spec.md)
   and [`arch/specification/spec.md`](./arch/specification/spec.md) — the
   two specs every other subsystem depends on.
