# NARF

**Not Another Rust Frame Kernel** — a `no_std` Rust *framekernel* for
x86_64 + aarch64. Minimal Ring-0 TCB, hardware-enforced domain
isolation (PKS / MTE / PCID-tagged page tables), zero-copy `Narf-Ring`
IPC, async-first executor, capability-typed access control, no root
user.

GPL-2.0-or-later. See [`LICENSE`](LICENSE).

---

## What it is

NARF is a research kernel built around four ideas:

1. **Framekernel.** A small Rust TCB (boot, traps, scheduler, memory,
   capabilities) plus everything else — drivers, the network stack,
   filesystems above the VFS — in isolated *domains* that run at Ring 0
   but can't access each other's memory. Three runtime-selected
   backends enforce this in hardware: **PKS** on Intel SPR+, **MTE** on
   aarch64, **PCID-tagged per-domain page tables** on AMD x86_64 /
   pre-SPR Intel. See [`docs/DOMAIN_BACKENDS.md`](docs/DOMAIN_BACKENDS.md).

2. **Async-first.** Every syscall, IRQ, and driver task is a stackless
   Rust `Future` on a global executor. Direct context transfer lets a
   caller donate its time-slice to the callee — no double-trip
   scheduling. The executor *is* the scheduler.

3. **Narf-Ring IPC.** Zero-copy shared-memory rings. Data moves via
   Rust ownership transfer — bytes never relocate in physical RAM. A
   producer surrenders a `DmaBuffer` into the ring; the consumer
   receives the owning handle. No syscall on the fast path.

4. **Capabilities, not permissions.** Every resource — memory region,
   file, IPC ring, device — is named by a typed `Cap<T, R>`. No root,
   no setuid, no ambient authority. Revocation is O(1) via an epoch
   counter.

The Linux-compat surface (epoll, eventfd, timerfd, clone3, mmap,
fcntl, statx, signalfd, memfd, mount/umount/chroot/pivot_root, POSIX
timers, namespaces) lives behind Cargo features so you can build a
NARF-native kernel without it. It is complete enough to run unmodified
musl binaries (BusyBox sh, dynamically linked) and an **OCI-style
container** end-to-end — read a bundle (`config.json` + `rootfs/`),
unshare namespaces, `chroot` into the rootfs, and `execve` the
contained entrypoint, which then sees only the container's own
filesystem. See [`docs/PERSONAS.md`](docs/PERSONAS.md).

---

## Status

| Stage | Theme | State |
|---|---|---|
| 1 — Skeleton | Boot, async exec, console | **closed** |
| 2 — Barrier | PKS / MTE + UIPI + GICv3 | **closed** |
| 3 — Flow | Caps + Narf-Ring + first virtio | **closed** |
| 4 — Compatibility | relibc / Linux-compat surface | **closed for in-tree shell + coreutils** |
| 5 — Silicon | Boot on AMD Zen2 Renoir + Phoenix HawkPoint1 laptops | **in progress** |
| G — Desktop Linux | `/dev/fb0` + evdev + DRM/KMS; unmodified libdrm & libwayland | **Wayland compositor runs multiple GUI apps** |

Today, both arches boot under QEMU and run the full async demo. The
interactive end-to-end loop (`echo hello world` over `-serial stdio`)
works through the IRQ-4 → byte ring → fd 0 → shell → fd 1 → UART chain.
`cargo xtask test` runs 5022+ kernel-test smokes / 0 fail / 73 skip.

On the graphics track, NARF exposes Linux device files — `/dev/fb0`
(fbdev), `/dev/input/event*` (evdev), `/dev/dri/card0` (DRM/KMS
dumb-buffer modeset) — and runs **unmodified** `libdrm` (`modetest`
enumerates + modesets + page-flips) and `libwayland`: a Wayland
compositor serves multiple independent GUI client processes that pass
shared frame buffers over the socket (`SCM_RIGHTS`) and are blitted to
the screen. See [`docs/DESKTOP_LINUX_PLAN.md`](docs/DESKTOP_LINUX_PLAN.md).

For the full per-feature landing log and live driver portfolio see
[`STATUS.md`](STATUS.md). For the per-stage subsystem matrix see
[`ROADMAP.md`](ROADMAP.md).

---

## Quick start

**Prerequisites:** Rust nightly (pinned in `rust-toolchain.toml`),
`qemu-system-x86_64` + `qemu-system-aarch64`, `xorriso`, `mtools`,
`ovmf` for the ISO + UEFI path.

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

# Boot via Limine ISO + OVMF UEFI (closer to real-hardware boot path)
cargo xtask iso-boot --arch=x86_64 --release

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
| Isolation | Address space (rings 0/3) | Address space + 16 hardware-enforced domains within Ring 0 |
| IPC | pipes / UDS / SysV / futex / io_uring | `Narf-Ring` — typed zero-copy ownership transfer with explicit acquire/release |
| Authorization | uid/gid + LSM / capsicum / pledge | `Cap<T, R>` everywhere with O(1) epoch revocation; no root user |
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
├── filesystem/                 — VFS, mount tree, page cache, ext2, devpts
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
| **x86_64** | First-class. Limine multiboot2 boot path; UEFI + OVMF supported. |
| **aarch64** | First-class. Boots under `qemu-system-aarch64 -M virt`. Generic Timer + GICv3 + PSCI. |

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
