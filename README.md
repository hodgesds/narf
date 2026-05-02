# NARF

**Not Another Rust Frame Kernel** — a Rust *framekernel* that combines the
safety of a microkernel TCB with the performance of hardware-assisted
intra-address-space isolation.

> "NARF: Because security shouldn't feel like a speed limit."

## Core ideas

- **Framekernel architecture.** A minimalist Rust TCB ("the Frame") carves
  its own Ring 0 address space into 16 hardware-protected domains. Drivers
  run in these domains — same virtual map, hardware-blocked from each other.
  Three enforcement backends, picked at boot from CPUID: **PKS** on
  Intel SPR-class silicon (one `WRMSR IA32_PKRS` per crossing), **MTE** on
  aarch64 with Memory Tagging Extension (one SR write per crossing), and a
  **PCID-tagged per-domain page-table** fallback on AMD x86_64 / pre-SPR
  Intel (one `MOV CR3` per crossing — measurably more expensive than the
  MSR path, but still hardware-enforced and same-VA). Compromise of one
  driver cannot read or corrupt another driver's heap, ring buffers, or
  descriptor tables under any of these backends; the silicon decides how
  cheap that guarantee is. See [Domain enforcement by silicon](#domain-enforcement-by-silicon)
  below for the full matrix.
- **Async-first scheduling.** Every syscall, interrupt, and driver task is a
  stackless Rust `Future` on a global executor. A caller can donate its
  remaining time-slice directly to the callee ("direct context transfer") to
  eliminate double-trip context switches. Per-CPU run queues with optional
  NUMA-aware work stealing keep latency local; QSBR / epoch / hazard-pointer
  RCU lets readers run without locks while reclamation is deferred to a safe
  point. There is no kernel thread pool to size and no `kthread` to migrate
  — the executor *is* the scheduler.
- **Narf-Ring IPC.** Zero-copy shared-memory rings. Data moves via Rust
  ownership transfer — the bytes never move in physical RAM. A producer
  surrenders a `DmaBuffer` into the ring; the consumer receives the
  unforgeable owning handle and can read, mutate, or forward it without ever
  re-entering the kernel. This collapses the classical "syscall →
  copy-in → copy-out → syscall" dance to a pair of `release` / `acquire`
  fences against a cache line.
- **Capability-based security.** No root user, no ambient authority, no
  `CAP_SYS_*` flag soup. Every operation requires an unforgeable `Cap<T>`
  token whose *type* encodes what the holder may do (`Cap<Read>` ⊂
  `Cap<Write>` / `Cap<Invoke>` / `Cap<Spend>`). Rights are checked by the
  Rust type system at compile time and by an epoch-versioned cap table at
  runtime, so a revoked capability becomes inert globally on the next epoch
  boundary. Confused-deputy attacks are structurally precluded: there is no
  "current user" the kernel could be tricked into impersonating.
- **Hardware bypass where it pays off.** P2P DMA between PCIe devices
  without a bounce through DRAM; User Interrupts (UIPI) on x86_64 to skip
  ring transitions on signal delivery; Global LTO across the whole kernel
  so cross-subsystem calls inline like a single binary; per-NUMA-node frame
  allocators wired off ACPI SRAT/HMAT/PMTT so DMA buffers land local to the
  device's home node.
- **Two arches, one tree, every commit.** x86_64 and aarch64 are co-equal
  primaries — there is no "port." Every subsystem spec has an *Architecture
  notes* section that must address both; every PR runs `cargo xtask test`
  on both arches before landing. PKS↔MTE, x2APIC↔GICv3, INVPCID↔TLBI, ECAM
  on q35↔ECAM via DTB on QEMU virt — each pair is symmetric in the API and
  asymmetric in the HAL only where the silicon forces it.
- **ACPI / AML in tree, in Rust.** A from-scratch DSDT/SSDT parser and AML
  bytecode interpreter (method evaluator, OpRegion accessors for
  SystemMemory / SystemIO / PCI_Config, resource templates, Mutex/Event,
  GPE dispatch, `_PRT` / `_CRS` round-trip) replaces ACPICA's C ball-of-mud
  inside the TCB. Firmware is parsed under the same `unsafe`-discipline and
  cap rules as the rest of the kernel; nothing executes outside the
  framekernel's domain model.
- **Verification and observability are first-class.** A kernel-resident
  test harness (`cargo xtask test`) boots the real kernel under QEMU and
  asserts on live invariants — 562 smokes on x86_64, 292 on aarch64 at
  time of writing — alongside USDT-style probes, flight-recorder rings, a
  PMU-sampling surface, and an ABI promise (syscall numbers carry an upper
  8-bit version, `relibc` will gate against it). Bugs are caught at the
  invariant boundary rather than diagnosed from a stack trace.

## How NARF compares to Linux and the BSDs

NARF is not a clone of either family — it occupies a different point in the
design space. The table is for orientation, not scoring; "absent" features
are usually deliberate choices, not omissions.

| Dimension | Linux | FreeBSD / OpenBSD / NetBSD | NARF |
| --- | --- | --- | --- |
| Kernel model | Monolithic with loadable modules | Monolithic | **Framekernel**: minimal Ring-0 TCB + 16 hw-isolated driver domains in the same address space |
| Driver isolation | None inside kernel; a buggy module can scribble anywhere | None inside kernel | **PKS** (Intel SPR+), **MTE** (aarch64), or **PCID-tagged per-domain PTs** (AMD / pre-SPR Intel) — hardware blocks cross-domain loads/stores; cost varies by backend |
| Implementation language | C (Rust permitted in tree, opt-in subsystems) | C (predominantly) | **Rust, no_std**, top-to-bottom; `unsafe` walled into the HAL |
| Concurrency model | Preemptive kthreads + softirqs + workqueues + BHs | Preemptive kthreads + taskqueues + netisr | Stackless **async `Future`s** on a single global executor; per-CPU queues; optional NUMA-aware work stealing |
| Cross-context call | `syscall` → schedule → return; copy_to/from_user | `syscall` → schedule → return; `copyin/copyout` | **Direct context transfer** — caller donates its time-slice to the callee, no double trip |
| IPC | pipes, UDS, SysV, futex, io_uring (zero-copy in narrow paths) | pipes, UDS, kqueue, capsicum sandboxing | **Narf-Ring**: zero-copy ownership-transfer over shared-memory rings, cap-gated |
| Authorization | uid/gid + capabilities(7) + LSM (SELinux/AppArmor) | uid/gid + (FreeBSD) Capsicum + (OpenBSD) pledge/unveil | **`Cap<T>` everywhere**: no root, no ambient authority, type-encoded rights, epoch-revocable |
| RCU / deferred reclaim | RCU (classic / SRCU / Tasks RCU) | epoch (`epoch(9)`) | **QSBR + epoch + hazard pointers + sleepable** in tree |
| Interrupt model | top-half ISR + softirq/threaded IRQ | ithread | **`wait_for_irq.await`** future bridging hw IRQ → executor; **UIPI** on x86_64 |
| ACPI / AML | ACPICA (C, imported) | ACPI-CA (C, imported) | **From-scratch Rust** parser + AML interpreter inside the TCB |
| PCIe enumeration | Per-arch ECAM + ACPI / DT bring-up | Per-arch ECAM + ACPI / DT bring-up | Unified ECAM walker: ACPI MCFG on x86_64, DTB on aarch64; same driver-match registry |
| NUMA | `numactl`, per-node zoned allocator, autoNUMA | `cpuset`, per-domain VM | SRAT/HMAT/PMTT-driven **per-node frame allocator** + node-aware steal |
| User-mode networking | Kernel TCP/IP; AF_XDP / DPDK for bypass | Kernel TCP/IP; netmap | **Stack lives in userspace**; kernel ships only the frame-ring contract + driver |
| libc story | glibc / musl / etc. on a stable syscall ABI | platform libc bundled with kernel | **`relibc`** gated by a versioned syscall ABI (upper 8 bits of the syscall number) |
| Build / link | Per-object compile, no whole-kernel LTO by default | Per-object compile | **Global LTO** across the whole kernel — cross-subsystem calls inline |
| Test surface | kselftest, KUnit, LTP (out-of-tree mostly) | ATF / Kyua | **In-tree QEMU-resident** smokes; every commit runs both arches |
| Architectures (primary) | x86_64, aarch64, many more | x86_64, aarch64, others | **x86_64 + aarch64 co-equal** from day one |
| Stable kernel ABI | "We do not break userspace" — strong de-facto, no version stamp | Stable across a major branch | **Versioned**: syscall number carries an 8-bit ABI version, surfaced to libc |
| TCB size | Multi-million LoC; every driver is in the TCB | ~Million LoC; every driver is in the TCB | **Frame** is small; drivers are *not* in the TCB even though they share the address space |

The headline trade is **isolation without an IPC tax**. Linux and the BSDs
get throughput by putting drivers inside the kernel and accepting that a
buggy driver can corrupt anything. Classical microkernels (Mach, L4,
seL4, Minix 3) get isolation by putting drivers in user processes and
paying for an address-space crossing on every interaction. NARF puts
drivers in the kernel address space **and** isolates them, using PKS/MTE
to make the boundary a single instruction instead of a TLB shootdown
when the silicon supports it. The cost is hardware sensitivity — the
fast backend is restricted to specific generations — and a smaller
mature driver set than a 30-year-old project. The win is that "`Cap<T>`
+ domain + zero-copy ring" is enforceable end-to-end without falling
back to "trust every kthread."

## Domain enforcement by silicon

Domain isolation is a runtime-selected backend. The framekernel boots,
probes CPUID / arch features, and picks the strongest enforcer the
silicon supports. The cap-system, Narf-Ring contract, and same-VA
invariant are identical across backends — only the cost-per-crossing
differs.

| Silicon | Backend | Switch cost | Domain count | Notes |
| --- | --- | --- | --- | --- |
| Intel Sapphire Rapids and later (server), Alder Lake / Raptor Lake (client, where exposed) | **PKS** | One `WRMSR IA32_PKRS` (~tens of cycles, no TLB hit) | 16 | The reference fast path. CR4.PKS=1, per-PTE 4-bit PK field selects the domain. |
| aarch64 with **MTE** (Cortex-X2+, Apple M-series with MTE exposed, ARMv9 server cores) | **MTE** | One SR write (`SCTLR_EL1.TCF` + tag bits) | 16 | Tag-on-load enforcement at the 16-byte granule. Same hot-path cost class as PKS. |
| **AMD** Zen 3 / Zen 4 / Zen 5 (no PKS), pre-SPR Intel Xeon and Core (no PKS exposed) | **PCID** | One `MOV CR3` with PCID-preserve flag (~50–100 cycles, hot PCID stays warm) | 16 (capped — architecture has 4096 PCIDs) | Domain N → PCID N+1; **strict isolation live**: 16 byte-cloned PML4s share downstream PDPTs (KAISER-style fan-out for kernel-shared mappings), each domain owns a private PDPT installed at PML4 slot 256+N — accesses to a domain's private VA range from any other domain hard-fault at PML4 level. `memory::map_domain_private(D, va, pa, flags)` lands a leaf in domain D's subtree only. |
| aarch64 without MTE | **ASID-PT** *(planned)* | One `TTBR0_EL1` write with ASID | 16 | Conceptual mirror of PCID on x86_64. Not yet implemented; today's `frame/` boot path reports the fallback intent. |
| AMD SEV-SNP guest | *Could* use **VMPL** | `RMPADJUST` / `VMGEXIT` (~thousand cycles) | 4 (architectural cap) | Research only — see `memory/research/snp_vmpl.md`. Composes with SEV memory encryption. |
| Older silicon, no PK / MTE / PCID-class fallback acceptable | **SFI** *(research)* | Zero per crossing; cost in inserted bounds checks per memory op | Compiler-defined | Software fault isolation — Rust dialect verified at compile time. See `memory/research/sfi.md`. |

**What this means for security claims.** On PKS or MTE silicon, the
framekernel's domain story is hardware-enforced at MSR/SR-write speed —
the design's reference deployment. On AMD x86_64 today, the PCID
backend is wired end-to-end: boot enables CR4.PCIDE on the BSP and
on every AP, allocates 16 per-domain PML4s as byte-clones of the
bootstrap (so kernel-shared mappings auto-fan-out via shared
downstream PDPTs), installs a private PDPT in each domain's PML4 at
slot 256+N, and arms the CR3-swap path. Cross-CPU TLB consistency is
maintained by a `VECTOR_TLB_SHOOTDOWN` IPI broadcaster — `unmap_4kb`
fans out to every online AP after the local INVLPG. Drivers claim
private MMIO regions through `narf_drivers::claim_mmio_in_domain`,
which lands the leaf inside the driver's own PML4 subtree only. A
cross-domain access to a private VA hits a not-present PML4E and
#PFs at the very first level of the walk — hardware-enforced, no
software check. Domain crossings cost ~50–100 cycles for the
`MOV CR3` (vs the ~tens-of-cycles `WRMSR` cost on PKS); same
correctness, different throughput class.

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
- The complete modern virtio-PCI matrix: blk / net / rng / balloon /
  console / scsi / 9p / fs / vsock / iommu / gpu / input / snd. Every
  driver in the matrix is live data-path, not just bring-up: scsi
  exposes `submit_cmd` / `submit_tmf` / `report_luns`, 9p exposes the
  full Tversion / Tattach / Twalk / Tlopen / Tread / Tclunk request
  set with R-side decoding, fs ships FUSE_INIT / FUSE_LOOKUP /
  FUSE_READ helpers on top of the FUSE-on-virtio submit path, gpu
  paints (`init_scanout` / `paint_solid` / `paint_test_pattern` /
  `flush`), vsock has `send` / `recv` / `drain_events`, iommu has
  `attach` / `detach` / `map` / `unmap` with §5.16.6 tail-status
  decode, snd has `set_params` / `prepare` / `start` + `play_buffer`
  PCM submit, balloon does live `inflate(pfns)` / `deflate(pfns)`,
  rng pumps entropy via `read_bytes(out)`. Each driver programs MSI-X
  on its primary completion queue via the shared
  `pci::enable_msix_queue` helper; polled-completion fallbacks stay
  in place so sync callers and IRQ-less environments keep working.
- e1000 / e1000e: BAR0, MAC read from RAL/RAH, TX + RX descriptor
  rings, link up via CTRL.SLU.
- AHCI ICH9: HBA reset, port enumeration via PORT_SIG/SSTS,
  IDENTIFY DEVICE + READ DMA EXT + WRITE DMA EXT against a
  QEMU-emulated SATA disk.
- ixgbe (Intel 82599 / X540 / X550 10 GbE): clean-room from the
  public Intel datasheet — PCI match, master reset, EEPROM-backed
  MAC read, advanced TX + RX rings, MSI-X, `HwNic` impl.
- iwlwifi (Intel Wi-Fi 6 / 6E AX200..AX211): structural probe only;
  operational register map is not in any public Intel doc, so the
  driver lands the PCI-match table + spec doc and stops at the
  documented public-docs wall.
- xHCI USB host controller: HCRST reset, DCBAA + Command/Event
  Rings + scratchpad pointers, USBCMD.RS=1, port reset, Enable
  Slot, Address Device, GET_DESCRIPTOR, Configure Endpoint,
  bulk + interrupt IN/OUT.
- USB HID keyboard: hot-plug enumeration over xHCI → Set
  Protocol(Boot) → interrupt-IN polling → HID Usage 0x07 →
  `narf_input::KeyCode` press/release diffing with 8-modifier
  tracking + roll-over filter.
- USB Mass Storage (Bulk-Only Transport): hot-plug enumeration
  over xHCI for class 08:06:50, descriptor walk for the bulk-IN +
  bulk-OUT pair, CBW/CSW protocol per USB MSC BBB rev 1.0,
  INQUIRY / READ CAPACITY(10) / READ(10) / WRITE(10) on top, plus
  multi-block read/write helpers (≤ 8 LBAs per call).
- AHCI: HBA reset, port enumeration, IDENTIFY DEVICE +
  READ/WRITE DMA EXT, plus READ/WRITE FPDMA QUEUED (NCQ on a
  per-tag basis with PORT_SACT bookkeeping) and a placeholder for
  port-multiplier topology discovery.
- SDHCI: SD Host Controller (any vendor, PCI class 08:05) —
  software reset, 3.3V power, 400 kHz init clock, full SD
  identification sequence (CMD0 / CMD8 / ACMD41 / CMD2 / CMD3 /
  CMD7), and `read_block(lba)` / `write_block(lba, data)` over
  PIO with the standard Buffer Data Port.
- igc (Intel I225 / I226): clean-room from public Intel
  datasheets. PCI match against 6 VID/DIDs across the I225 LM/V/IT
  + I226 LM/V/IT families, CTRL.RST reset, MAC read from RAL/RAH,
  legacy TX + RX descriptor rings, polled `tx(&[u8])` / `rx(&mut)`
  + `HwNic` adapter.
- Intel HD Audio (HDA): clean-room driver for the AMD Ryzen /
  Phoenix and Radeon HD Audio Controllers — BAR0 mapping, GCTL
  reset, CORB/RIRB ring DMA, STATESTS codec walk, Get Parameter
  verbs for codec discovery, output stream descriptor + BDL +
  cyclic 4 KiB period buffer, 48 kHz S16LE stereo, `start_output`
  + `stop_output` (SDnCTL.RUN) + `load_period` + sine-wave test
  tone. Wired into `narf_audio::AudioWriter::submit` so consumers
  hit it transparently when virtio-sound isn't available.
- QEMU `fw_cfg` interface (x86_64 PIO): magic-string presence
  probe, file-directory parse, `find` / `read` / `read_string`
  for SMBIOS / boot-order / cmdline-style entries.

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

`cargo xtask test --arch=x86_64` passes **562/0/22** smokes;
`--arch=aarch64` passes **292/0/10**. Skips are x86-specific PCIe
surfaces or live-device tests that skip cleanly when QEMU doesn't
expose the device. See `STATUS.md` for the full tally and per-
subsystem breakdown.

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
