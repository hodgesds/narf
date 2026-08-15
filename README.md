# NARF

**A framekernel with first-class Linux compatibility.**

**Not Another Rust Frame Kernel** is a `no_std` Rust operating system
for x86_64 and aarch64. NARF combines a small Ring-0 trusted computing
base (TCB) with a kernel organized into protection domains, then
exposes both a native interface and a Linux-compatible userspace
interface. The goal is to contain kernel faults without giving up the
shared-memory performance of a monolithic kernel or the software
ecosystem built around the Linux ABI.

GPL-2.0-or-later. See [`LICENSE`](LICENSE).

---

## What is a framekernel?

A **framekernel** is a kernel architecture in which a small trusted
core — the *frame* — establishes the system's protection rules, while
the rest of the kernel runs in hardware-isolated domains. The frame
handles the operations that must be globally trusted: bootstrapping
the machine, entering and leaving protection domains, dispatching
traps, scheduling work, and managing memory protection.

A framekernel occupies a middle ground between familiar kernel models:

| Model | Where kernel services run | What must be trusted |
|---|---|---|
| Monolithic kernel | One privileged address space | The whole kernel, including every in-kernel driver |
| Microkernel | Separate user processes and address spaces | A small kernel; service calls cross address-space boundaries |
| Framekernel | One privileged address space split into hardware-enforced domains | The frame; isolated services remain outside the TCB |

Sharing an address space preserves direct calls and shared-memory data
paths. Hardware domains prevent “runs in Ring 0” from meaning “may
read or overwrite the entire kernel.” The result is a small security
boundary without requiring a process and page-table switch for every
kernel service.

## How NARF uses the framekernel model

NARF's frame consists of `frame/`, the memory domain manager, the
capability core, and the executor core; `security-model/` defines that
trusted boundary. Drivers and other kernel subsystems execute at Ring
0 / EL1. On the x86_64 backends, domain protection prevents them from
freely accessing the frame or one another; the aarch64 design applies
the same boundary with MTE tags.

NARF turns that architecture into a complete system with three
connected mechanisms:

1. **Domain backends.** NARF defines up to 16 protection domains. On
   x86_64, boot-time feature detection selects **PKS** on supported
   Intel systems or **PCID-tagged page tables** on AMD and older Intel
   systems. The aarch64 design maps the same contract to **MTE** tags.
   See
   [`docs/DOMAIN_BACKENDS.md`](docs/DOMAIN_BACKENDS.md).

2. **The async executor is the scheduler.** Syscalls, IRQ work, and
   driver tasks are stackless Rust `Future`s. Direct context transfer
   lets a caller donate its remaining time slice to a callee, avoiding
   a second scheduling round trip.

3. **Narf-Ring carries data across boundaries.** Shared-memory rings
   transfer ownership of buffers instead of copying their bytes. The
   domain system constrains access, and the executor wakes the
   receiving task.

## Linux compatibility is a first-class feature

Linux compatibility is a supported userspace contract, not an
afterthought or a claim that NARF is internally Linux. NARF implements
a growing Linux ABI surface directly on its native process, VFS,
networking, device, and async primitives. That surface
includes Linux syscall numbers and semantics, dynamic ELF loading for
musl, familiar interfaces such as epoll/eventfd/timerfd, and Linux
device ABIs including fbdev, evdev, uinput, and DRM/KMS. Composable
`container` and `cgroup` personalities add namespaces and the cgroup-v2
hierarchy.

This compatibility is delivered as the composable `linux-compat`
personality and is enabled by default in the userspace crate. A
NARF-native build can omit it with `--no-default-features`, and CI
checks the native, Linux-compatible, container, and cgroup feature
combinations independently.

The important boundary is deliberate: Linux programs see the ABI they
expect, while NARF retains isolated kernel domains and an async-first
implementation underneath. See
[`docs/PERSONAS.md`](docs/PERSONAS.md) for feature composition and
[`docs/DESKTOP_LINUX_PLAN.md`](docs/DESKTOP_LINUX_PLAN.md) for the
end-to-end compatibility track.

---

## Quick start

**Prerequisites:** Rust nightly (pinned in `rust-toolchain.toml`),
`qemu-system-x86_64` + `qemu-system-aarch64`, `xorriso`, `mtools`,
`ovmf` + `qemu-efi-aarch64` for the x86_64 and aarch64 UEFI paths.

```sh
# Boot the async demo under QEMU
cargo xtask run --arch=x86_64
cargo xtask run --arch=aarch64

# Boot the interactive shell — type `echo hello world` at the narf> prompt
cargo xtask run --arch=x86_64 --display=gtk

# Run the full kernel-test suite (prints a pass/fail/skip summary)
cargo xtask test --arch=x86_64

# Run an OCI-style container end-to-end: the `oci_smoke` runtime reads a
# kernel-seeded bundle at /oci, unshares namespaces, chroots into the
# bundle rootfs, and execs the contained entrypoint, which proves it is
# isolated (sees the container's own /etc/os-release). The nightly
# `nightly-oci` CI job runs this same demo on a schedule.
cargo xtask run-interactive --arch=x86_64 --cmd "oci_smoke" --expect "oci-smoke-ok"

# Serve off-box: boot a guest TCP echo server reachable from the host via
# a QEMU port-forward, then connect a real host socket and round-trip a
# line over virtio-net (kernel TCP server path + blocking accept).
cargo xtask net-smoke --arch=x86_64

# Boot via Limine ISO + OVMF UEFI and require a clean boot marker
cargo xtask iso-boot --arch=x86_64 --release

# Boot the AA64 fallback loader + ESP under AAVMF
cargo xtask iso-boot --arch=aarch64 --release

# Build the ISO without booting
cargo xtask image --arch=x86_64 --release
```

**Hardware profiles** isolate driver paths under `cargo xtask run`:

```sh
cargo xtask run --arch=x86_64 --hw-profile=minimal      # serial only
cargo xtask run --arch=x86_64 --hw-profile=virtio-only  # virtio + serial
cargo xtask run --arch=x86_64 --hw-profile=legacy-only  # non-virtio + serial
```

**Burning to USB** for real-hardware boot:

```sh
# Auto-detect the first USB-attached disk
sudo cargo xtask disk-write

# Or specify the device + fast-wipe (zeroes MBR/GPT/ESP regions only)
sudo cargo xtask disk-write --device=/dev/sdX --fast-wipe
sync && sudo eject /dev/sdX
```

xtask refuses to write to a non-USB-attached device — `/dev/sda`
that's your system disk won't be touched by accident. For a real
partitioned install (GPT + ESP + ext4 root), use `disk-write-partitioned`
with `--esp-size-mib` / `--root-fs` / `--root-label` flags.

---

## How it differs from Linux / BSD

| | Linux / BSD | NARF |
|---|---|---|
| TCB | Monolithic kernel — every driver is in the TCB | Minimal `frame/` + memory domain manager + caps core + executor + `security-model/`; drivers are *not* in the TCB |
| Isolation | Address space (rings 0/3) | Up to 16 Ring-0 domains; PKS / PCID enforcement on x86_64, MTE design on aarch64 |
| IPC | pipes / UDS / SysV / futex / io_uring | `Narf-Ring` — typed zero-copy ownership transfer with explicit acquire/release |
| Concurrency | Threads + locks | Stackless `Future`s on a domain-aware executor; direct context transfer |
| ACPI / AML | ACPICA (C, imported) | From-scratch Rust parser + AML interpreter inside the TCB |

A Linux-compat persona (`--features linux-compat`) sits on top of the
native surface and exposes Linux syscall numbers so musl-static binaries
can run. A `container` persona adds PID / mount / network / UTS / IPC
namespaces orthogonally. See [`docs/PERSONAS.md`](docs/PERSONAS.md) and
[`COMPARISON.md`](COMPARISON.md) (longer-form comparison with Linux,
the BSDs, and classical microkernels).

---

## Repository layout

```
narf/
├── DESIGN.md / ROADMAP.md / STATUS.md / GLOSSARY.md / AGENTS.md
├── docs/                       — PERSONAS, DOMAIN_BACKENDS, design notes
│
│ ── Cross-cutting ──
├── arch/                       — HAL: x86_64 + aarch64
├── abi/                        — Kernel ↔ user boundary (async rings)
├── security-model/             — Threat model, capabilities × domains
├── build/xtask/                — Cargo workspace orchestration + QEMU harness
├── verification/               — Kernel-test harness, smoke registry
├── process/                    — Contribution flow, AI-agent rules, security
│
│ ── TCB + core ──
├── frame/                      — TCB: boot CPU, traps, panic path
├── memory/                     — Phys alloc, VM, PKS / MTE / PCID domains
├── capabilities/               — Cap tables, `Cap<T, R>` types, derivation
├── scheduler/                  — Async executor, direct context transfer
├── ipc/                        — Narf-Ring zero-copy rings
├── interrupts/                 — UIPI (x86_64), GICv3 ITS (aarch64), IRQ routing
├── lib/                        — no_std sync, intrusive collections, typed IDs
│
│ ── Platform ──
├── boot/                       — Bootloader handoff (PVH / FDT)
├── console/                    — Early serial (16550A / PL011), panic sink
├── time/                       — Monotonic + wall clocks, hrtimers
├── rcu/                        — QSBR, epoch, hazard pointers, sleepable
├── bus/                        — PCIe ECAM + MMIO + devicetree enumeration
├── io/                         — DMA buffer management, IOMMU / SMMU
├── acpi/  aml/                 — ACPI table parser + AML interpreter
├── power/                      — Idle states, DVFS, suspend / resume, thermal
├── crypto/                     — Primitives, DRBG, `Cap<Key>`, signed manifests
├── tpm/                        — TPM 2.0 (TIS / CRB) + measured boot
├── wireless/                   — WPA3 SAE, common 802.11 utilities
│
│ ── Drivers ──
├── drivers/                    — Driver framework
│   ├── virtio/  nvme/  net/    — Block, network
│   ├── gpu/  hwmon/  usb/      — Display, thermal, USB host + HID
│   ├── input/  i2c/  gpio/     — Touchpad / keyboard, bus controllers
│   ├── platform/  storage/     — EC, SDHCI, AHCI
│   └── wireless/               — iwlwifi, ath11k, rtw88, rtw89, rtl8xxxu, mt76
│
│ ── Storage + filesystems ──
├── block/                      — Block-device trait + I/O scheduler
├── filesystem/                 — VFS, mount tree, page cache, ext2/Btrfs, devpts
│
│ ── Userspace ──
├── userspace/                  — Process model, ELF loader, syscall surface
├── user-runtime/               — Userspace syscall wrappers
├── narf-libc/                  — In-tree no_std libc shim
│
│ ── Networking ──
├── net/                        — Frame-ring contract, iface registry, TCP/UDP/ICMP host stack
│
│ ── Observability ──
├── tracing/                    — USDT, dynamic probes, FnTime, flight recorders
├── observability/              — PMU, GDB stub, crash dumps, FB status-panel
├── fb/                         — Framebuffer driver + FB status-panel slot
```

Every subsystem folder contains a `specification/spec.md` (purpose,
public interface, invariants), a `research/README.md` (annotated
reading list), and `research/summaries/` (distilled primary sources).

---

## Target architectures

| Arch | Status |
|---|---|
| **x86_64** | First-class. Limine multiboot2 path; UEFI removable-media boot is tested through OVMF with Secure Boot disabled. |
| **aarch64** | First-class. Linux-compatible FDT entry via direct boot or the removable-media `BOOTAA64.EFI` loader; AAVMF-gated in CI. Generic Timer + GICv3 + PSCI. |

Real-hardware bring-up targets: AMD Zen2 Renoir (Vega8 / DCN 2.0) and
AMD Phoenix HawkPoint1 (RDNA3.5 / DCN 3.5).

---

## Documentation index

| Doc | When to read |
|---|---|
| [`AGENTS.md`](AGENTS.md) | Token-efficient navigation map (for AI agents and humans in a hurry) |
| [`DESIGN.md`](DESIGN.md) | One-page v1.0 vision |
| [`GLOSSARY.md`](GLOSSARY.md) | Framekernel / Narf-Ring / Domain definitions |
| [`ROADMAP.md`](ROADMAP.md) | Per-stage subsystem activity + exit criteria + Stage × subsystem matrix |
| [`STATUS.md`](STATUS.md) | Per-feature landing log + live driver portfolio tables |
| [`COMPARISON.md`](COMPARISON.md) | Long-form comparison with Linux, the BSDs, and classical microkernels |
| [`docs/PERSONAS.md`](docs/PERSONAS.md) | `linux-compat` + `container` feature surfaces |
| [`docs/DOMAIN_BACKENDS.md`](docs/DOMAIN_BACKENDS.md) | Per-silicon enforcement matrix (PKS / MTE / PCID / VMPL / SFI) |
| [`process/specification/spec.md`](process/specification/spec.md) | Contribution flow (binding on humans and AI agents) |
| [`security-model/specification/spec.md`](security-model/specification/spec.md) | Threat model, cap × domain composition |
| `<subsystem>/specification/spec.md` | Per-crate purpose, public interface, invariants |

---

## License

GPL-2.0-or-later as of 2026-05-20. Code that landed before the
relicense was originally MPL-2.0 and was authored as clean-room. New
code after the relicense may cite and adapt directly from GPLv2-compatible
projects (Linux, U-Boot, GPL BSD drivers). See `LICENSES/` for SPDX
entries.
