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

**Status:** Exit gate met for the in-tree shell + coreutils, with end-to-end
`echo hello world` working through the IRQ-4 → BYTE_RING → fd 0 → shell →
fd 1 → UART chain (the in-kernel `smoke_echo_hello_world_end_to_end` plus
the interactive `cargo xtask run-interactive` harness both verify it).
`cargo xtask test` runs 5022+ smokes / 0 fail / 73 skip.  Linux-compat
syscalls (epoll, eventfd, timerfd, clone3, mprotect, madvise, statx,
signalfd, memfd, mount/umount/chroot/pivot_root, POSIX timers, namespaces)
land behind the `linux-compat` / `container` Cargo features —
see [`docs/PERSONAS.md`](docs/PERSONAS.md).

**Subsystems:**

- `userspace/` — process model, ELF loader, relibc integration,
  Linux-shaped syscall surface, dynamic linker (PT_INTERP +
  ld-musl), `/dev/pts` PTY plumbing.
- `drivers/nvme/` — block storage.
- `drivers/net/` — network.
- `drivers/gpu/` — graphics. DRM/KMS dumb-buffer modeset on `/dev/dri/card0`
  (+ `/dev/fb0`, evdev) runs unmodified libdrm + libwayland under QEMU; a
  Wayland compositor serves multiple GUI client processes. See
  [`docs/DESKTOP_LINUX_PLAN.md`](docs/DESKTOP_LINUX_PLAN.md). Native AMDGPU
  modeset on real silicon is later.
- `drivers/hwmon/` — hardware monitoring: thermal/fan management (k10temp, coretemp, nct6775, dell_smm).
- `drivers/usb/` — xHCI host controller + HID keyboard/mouse class
  + USB hub class; first USB device flows IRQ → BYTE_RING → fd 0.
- `verification/` — expanded fuzzing + integration matrix.
- `tracing/` — HW trace integration (Intel PT / CoreSight ETM), userspace tracer tooling.
- `observability/` — GDB remote stub, live-peek API, core-dump parser tooling, FB status-panel for
  bare-metal diagnostics.
- `crypto/` — TPM 2.0 integration, measured-boot chain, post-quantum algorithm plan, FIPS-mode decision.
- `time/` — NTP/PTP userspace hooks, leap-second smear.
- `block/` — Multi-queue dispatch, discard/TRIM, write-zeroes, NVMe backing.
- `filesystem/` — virtiofs, persistent block filesystems including ext2 and
  btrfs (single-device plus RAID0/1/10/5/6), unified page cache, and devpts.
- `scheduler/` — CPU take-offline for suspend/resume, SMT-aware placement, deadline class.
- `rcu/` — batched reclamation tuning, per-domain pacing, NUMA-aware queues, expanded consumers.
- `net/` — Userspace stack-daemon attach protocol, Admin cap flow, hardware-NIC integration via `drivers/net/`,
  `iface::for_dst` per-flow routing across TCP/UDP/ICMP/ARP send paths.
- `bus/` — Thunderbolt / PCIe switch awareness, virtio-mmio runtime injection, ACPI notify integration.
- `power/` — Suspend-to-RAM (S3 / PSCI), thermal zones + throttling, EnergyAware governor coupled to `scheduler/`.

## Stage 5 — The Silicon

**Theme:** Boot and run on real consumer laptop silicon.

**Exit criterion:** Boot on a Zen2 Renoir or Phoenix HawkPoint1 laptop
from USB, display via native AMDGPU modeset (not UEFI GOP fallback),
type into the keyboard / touchpad, connect to WiFi, persist files on
an NVMe partition through ext2 or single-device btrfs.

**Bring-up targets:** two AMD laptops are the canonical test silicon:
- **Zen2 Renoir / Lucienne** (Family 0x17 0x30–0xAF) — Vega8 iGPU,
  DCN 2.0.
- **Phoenix HawkPoint1** (Zen4) — RDNA3.5 iGPU (1002:1900), DCN 3.5.

**Subsystems:**

- `drivers/gpu/` (AMDGPU) — PCI match + MMIO BAR map + ATOMBIOS
  + IP Discovery (Phoenix) + GMC/GFX register surfaces + PSP MP0
  mailbox + SMU MP1 + DCN 2.0 / 3.5 modeset sequences + GFX9/GFX11
  CP ring init + PM4 / Ring / Fence + DRM card registration.
  Foundation landed (Wave 80); full bare-metal modeset is the
  next major lift.
- `drivers/platform/` — ACPI Embedded Controller (PNP0C09) for
  battery / AC / fan / lid / thermal; AML `_QXX` event dispatch
  via SCI.  Sysfs surface for `/sys/class/power_supply` +
  `/sys/class/thermal`.
- `drivers/input/i2c_hid/` — I²C-HID touchpad over AMD FCH I²C;
  PNP0C50 enumeration + HID Descriptor Register read + Reset
  sequence + Report Descriptor parse + INT pin via GPIO; events
  feed `narf_input`.
- `drivers/wireless/iwlwifi/` — Intel iwlwifi data path: MSI-X cause
  routing, firmware load to ALIVE, BCAST flush, RX/TX TFD rings,
  WPA2-PSK 4-way handshake, CCMP key install.
- `drivers/wireless/rtw89/` / `rtl8xxxu/` — Realtek WiFi for
  laptops shipping Realtek chipsets; firmware download + RX/TX
  bring-up.
- `drivers/usb/xhci/` — already running on QEMU; real-silicon
  bring-up needs the Zen2 Renoir VID/DID in the explicit match
  table (currently relying on the class catch-all).
- `time/` — TSC calibration via AMD MSR_PSTATE0 (Family 0x17+
  P-state-0 register decoding) + HPET cross-check fallback; LAPIC
  timer InitialCount calibration against the worst-case slow bus.
- `fb/` — FB status-panel diagnostic slot for bare-metal boots
  where serial isn't reachable; pinned boot-phase + last-IRQ-vector
  + CR2-on-#PF + panic-marker indicators.
- `power/` — Suspend-to-RAM (S3) tested on real silicon; battery
  reporting via EC `_BIF`/`_BST`; thermal throttling via EC
  `_TMP` methods and AMD RAPL.

## Stage × subsystem matrix

| Subsystem         | 1 | 2 | 3 | 4 | 5 |
| ----------------- |:-:|:-:|:-:|:-:|:-:|
| `boot/`           | ● |   |   |   |   |
| `console/`        | ● |   |   |   |   |
| `frame/`          | ● | ◐ |   |   | ◐ |
| `memory/`         | ◐ | ● |   |   |   |
| `scheduler/`      | ◐ |   | ● |   |   |
| `arch/`           | ◐ | ● |   |   |   |
| `build/`          | ● | ◐ | ◐ | ◐ | ◐ |
| `verification/`   | ◐ | ◐ | ◐ | ● |   |
| `interrupts/`     |   | ● |   |   |   |
| `drivers/` (fw)   |   | ● |   |   |   |
| `security-model/` |   | ◐ | ● | ◐ |   |
| `ipc/`            |   |   | ● |   |   |
| `capabilities/`   | ○ |   | ● |   |   |
| `io/`             |   |   | ● |   |   |
| `abi/`            |   |   | ● |   |   |
| `drivers/virtio/` |   |   | ● |   |   |
| `userspace/`      |   |   |   | ● | ◐ |
| `drivers/nvme/`   |   |   |   | ● |   |
| `drivers/net/`    |   |   |   | ● |   |
| `drivers/gpu/`    |   |   |   | ◐ | ● |
| `drivers/hwmon/`  |   |   |   | ● | ◐ |
| `drivers/usb/`    |   |   |   | ● | ◐ |
| `drivers/input/`  |   |   |   | ◐ | ● |
| `drivers/platform/` (EC) |   |   |   |   | ● |
| `drivers/wireless/` |   |   |   | ◐ | ● |
| `tracing/`        | ◐ | ◐ | ● | ◐ |   |
| `observability/`  | ◐ | ◐ | ◐ | ● | ◐ |
| `crypto/`         | ○ | ● | ◐ | ● |   |
| `time/`           | ● | ● | ◐ | ◐ | ◐ |
| `rcu/`            | ○ | ● | ● | ◐ |   |
| `block/`          |   |   | ● | ◐ |   |
| `filesystem/`     |   |   | ● | ● | ◐ |
| `net/`            |   |   | ● | ● |   |
| `bus/`            |   | ● | ● | ◐ |   |
| `power/`          |   | ● | ● | ● | ◐ |
| `fb/`             | ◐ |   |   | ◐ | ● |
| `lib/`            | ● | ● | ◐ | ◐ |   |

Legend: ● primary work, ◐ partial / iterated, ○ design sketch only.
