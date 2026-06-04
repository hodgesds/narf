# NARF Roadmap

Four stages, each with a clear theme and a concrete exit criterion. Every
subsystem spec carries a *Stage assignment* field that must line up with
the matrix below.

## Stage 1 — The Skeleton

**Theme:** Boot, print, tick. One CPU, one address space, no isolation yet.

**Exit criterion:** Kernel boots on QEMU for x86_64 *and* aarch64, prints a
log line from a `Future` driven by the global executor, and survives a
timer-driven yield loop.

**Subsystems that land content:**

- `boot/` — bootloader handoff, memory map parsing.
- `console/` — 16550A (x86_64) and PL011 (aarch64) serial, panic sink.
- `frame/` — boot CPU bring-up, IDT/GDT or EL1 vector table, panic path.
- `memory/` — physical frame allocator + basic virtual memory (no domains yet).
- `scheduler/` — single-CPU async executor, cooperative yield.
- `arch/` — HAL trait surface, enough of x86_64 and aarch64 to boot.
- `build/` — Global LTO config, `build-std`, QEMU harness.
- `verification/` — test-in-QEMU harness skeleton.
- `tracing/` — USDT marker infrastructure (compile-time), basic flight-recorder ring.
- `observability/` — PMU cycles + instructions; basic crash dump (registers + stack).
- `crypto/` — Design sketch, entropy plumbing, SHA-256 + BLAKE3 for build-hash / measurement prep.
- `time/` — Monotonic clock from TSC / `CNTPCT_EL0`; `sleep` / `sleep_until`; timer wheel.
- `rcu/` — API surface, `Atomic<T>` / guard types; single-CPU executor wires the quiescent hook as a no-op.
- `lib/` — typed IDs, `SpinLock`, `IrqSafeSpinLock`, `Once`, `Bitmap`, intrusive list, base assertion macros.

## Stage 2 — The Barrier

**Theme:** Hardware isolation turns on. The Frame starts enforcing domains.

**Exit criterion:** A fault-injected write from domain N into domain M's
data is blocked by hardware (PKS on x86_64, MTE on aarch64), and the kernel
recovers cleanly.

**Subsystems:**

- `memory/` — PKS/MTE domain manager, domain-tagged mappings.
- `interrupts/` — UIPI configuration on x86_64, GICv3 ITS path on aarch64.
- `arch/` — complete HAL: full privilege/domain surface.
- `security-model/` — v0.5 threat model, domain attacker bounds.
- `drivers/` — driver framework (lifecycle, domain assignment, cap bootstrap).
- `tracing/` — tracer task in reserved domain, streaming Narf-Ring transport, panic-snapshot path.
- `observability/` — domain-attribution in crash dumps, multiplexed PMU groups.
- `crypto/` — AEAD (AES-GCM + ChaCha20-Poly1305), HMAC, Ed25519 verify, HKDF; driver-manifest signature verification.
- `time/` — hrtimers, SMP skew detection + correction.
- `scheduler/` — SMP with topology discovery, timer-driven preemption, NUMA per-CPU state, CPU hot-plug up.
- `rcu/` — real QSBR + Epoch variants, per-domain `defer_drop` queues, reclamation worker Future.
- `bus/` — Boot-time PCIe ECAM walk; MMIO discovery from ACPI/DT; device registry with claim API.
- `power/` — C-state registration + simple idle governor (WFI / MWAIT C1).
- `lib/` — `SeqLock`, `BinaryHeap`, `RbTree`, async-aware `Mutex`/`RwLock`, bounded-string types.

## Stage 3 — The Flow

**Theme:** Components talk. Zero-copy IPC + capabilities come online.

**Exit criterion:** A VirtIO device, running in its own PKS domain, moves a
buffer through a Narf-Ring to another domain using only capability
invocations, with no copy and no Ring-0 trap on the fast path.

**Subsystems:**

- `ipc/` — Narf-Ring SPSC/MPSC rings, ownership-transfer semantics.
- `capabilities/` — full cap tables, derivation, revocation, `Cap<T>` types.
- `io/` — DMA buffer management, IOMMU/SMMU programming, P2P DMA.
- `abi/` — stable kernel↔user boundary for async entry.
- `drivers/virtio/` — first real driver.
- `scheduler/` — direct context transfer / time-slice donation.
- `tracing/` — dynamic probes (entry/return/at), `FnTime`, live aggregates (Welford + tDigest).
- `observability/` — PMU sampling via `tracing/` transport, core-dump enrichment with flight-recorder snapshots.
- `crypto/` — Ed25519 sign, full `Cap<Key, _>` surface, `SecureRing` AEAD IPC, per-task RNGs.
- `block/` — Core `BlockDevice` trait, single-queue deadline scheduler, flush, virtio-blk backing.
- `filesystem/` — VFS core (trait, path resolution, open/read/write/stat), initramfs, virtiofs glue skeleton.
- `scheduler/` — direct context transfer, capability-checked donation, work stealing, affinity, `ResourceBudget`.
- `rcu/` — hazard-pointer variant; **sleepable** variant with cap-gated scopes, budgets, timeout-bounded sync; adoption by `capabilities/`, `interrupts/`, `time/`, and `filesystem/` dentry cache.
- `net/` — Frame-ring contract, interface registry, loopback implementation, virtio-net bound to contract.
- `bus/` — MSI-X allocation path, PCIe Native Hot Plug, IOMMU-group coordination with `io/`.
- `power/` — DVFS governor framework (`Performance` / `Powersave`), per-driver runtime PM trait.
- `lib/` — domain-aware assertion macros wired into `tracing/` and `frame/` panic.

## Stage 4 — The Compatibility

**Theme:** Run real software.

**Exit criterion:** A standard Rust binary compiled against `relibc` runs
on NARF and performs block and network I/O through capability-gated paths.

**Subsystems:**

- `userspace/` — process model, ELF loader, relibc integration.
- `drivers/nvme/` — block storage.
- `drivers/net/` — network.
- `drivers/gpu/` — graphics (may land partial in Stage 4, full later).
- `drivers/hwmon/` — hardware monitoring: thermal/fan management (k10temp, coretemp, nct6775, dell_smm).
- `verification/` — expanded fuzzing + integration matrix.
- `tracing/` — HW trace integration (Intel PT / CoreSight ETM), userspace tracer tooling.
- `observability/` — GDB remote stub, live-peek API, core-dump parser tooling.
- `crypto/` — TPM 2.0 integration, measured-boot chain, post-quantum algorithm plan, FIPS-mode decision.
- `time/` — NTP/PTP userspace hooks, leap-second smear.
- `block/` — Multi-queue dispatch, discard/TRIM, write-zeroes, NVMe backing.
- `filesystem/` — virtiofs driver, simple persistent FS, unified page cache.
- `scheduler/` — CPU take-offline for suspend/resume, SMT-aware placement, deadline class.
- `rcu/` — batched reclamation tuning, per-domain pacing, NUMA-aware queues, expanded consumers.
- `net/` — Userspace stack-daemon attach protocol, Admin cap flow, hardware-NIC integration via `drivers/net/`.
- `bus/` — Thunderbolt / PCIe switch awareness, virtio-mmio runtime injection, ACPI notify integration.
- `power/` — Suspend-to-RAM (S3 / PSCI), thermal zones + throttling, EnergyAware governor coupled to `scheduler/`.

## Stage × subsystem matrix

| Subsystem         | 1 | 2 | 3 | 4 |
| ----------------- |:-:|:-:|:-:|:-:|
| `boot/`           | ● |   |   |   |
| `console/`        | ● |   |   |   |
| `frame/`          | ● | ◐ |   |   |
| `memory/`         | ◐ | ● |   |   |
| `scheduler/`      | ◐ |   | ● |   |
| `arch/`           | ◐ | ● |   |   |
| `build/`          | ● | ◐ | ◐ | ◐ |
| `verification/`   | ◐ | ◐ | ◐ | ● |
| `interrupts/`     |   | ● |   |   |
| `drivers/` (fw)   |   | ● |   |   |
| `security-model/` |   | ◐ | ● | ◐ |
| `ipc/`            |   |   | ● |   |
| `capabilities/`   | ○ |   | ● |   |
| `io/`             |   |   | ● |   |
| `abi/`            |   |   | ● |   |
| `drivers/virtio/` |   |   | ● |   |
| `userspace/`      |   |   |   | ● |
| `drivers/nvme/`   |   |   |   | ● |
| `drivers/net/`    |   |   |   | ● |
| `drivers/gpu/`    |   |   |   | ◐ |
| `drivers/hwmon/`  |   |   |   | ● |
| `tracing/`        | ◐ | ◐ | ● | ◐ |
| `observability/`  | ◐ | ◐ | ◐ | ● |
| `crypto/`         | ○ | ● | ◐ | ● |
| `time/`           | ● | ● | ◐ | ◐ |
| `rcu/`            | ○ | ● | ● | ◐ |
| `block/`          |   |   | ● | ◐ |
| `filesystem/`     |   |   | ● | ● |
| `net/`            |   |   | ● | ● |
| `bus/`            |   | ● | ● | ◐ |
| `power/`          |   | ● | ● | ● |
| `lib/`            | ● | ● | ◐ | ◐ |

Legend: ● primary work, ◐ partial / iterated, ○ design sketch only.
