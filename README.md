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
  asserts on live invariants — 595 smokes on x86_64, 292 on aarch64 at
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
- RTL8139: clean-room from the public Realtek programming guide
  — the canonical legacy 10/100 Mbps PCI NIC. CONFIG1 unlock +
  CR.RST + MAC read from IDR0..5 + 64 KiB cyclic RX ring + four
  2 KiB TX buffers + `tx` / `rx` + link-status read.
- HPET (`narf_time::hpet`): clean-room from the Intel HPET 1.0a
  spec — capabilities + clock-period decode at the
  platform-fixed `0xFED00000` MMIO base, main counter read,
  enable / disable, ticks-to-nanos conversion. Used as a
  TSC-validation cross-check + fallback clocksource.
- Intel ICH SMBus (`narf_drivers_platform::smbus`): clean-room
  from the public ICH9 datasheet. PCI class 0x0C / subclass 0x05
  match (any vendor), IO BAR4 capture, byte-data + word-data
  read/write transactions through the host-controller PIO
  registers.
- TPM 2.0 (`narf-tpm`): clean-room from the TCG-published PC
  Client PTP (CRB interface) and TIS v1.21 (legacy
  memory-mapped) specs. Auto-detects the interface at
  `0xFED40000`, exposes `submit(cmd)` for raw wire-format
  transactions, and supports Measured Boot PCR extension.
- Measured Boot (`frame/src/measure`): hardware-anchored
  TCB integrity. Automatically hashes the kernel, initramfs,
  and boot-handoff data into TPM PCRs 0, 4, and 9.
- SPDM 1.2 Device Attestation (`narf-spdm`): clean-room
  Security Protocol and Data Model for peripheral verification.
  Collects hardware measurements during boot and extends them
  into PCR 10.
- MediaTek MT7921 Wi-Fi 6 (`narf-drivers-wireless`): clean-room
  driver bring-up on PCIe — BAR0 mapping, Wireless MCU reset
  pulse, and structural integration with the capability-gated
  802.11 wireless registry.
- MIPI I3C Master Controller (`narf-drivers-i3c`): clean-room
  NXP-style controller support — master initialization,
  dynamic address assignment hooks, and async transfer state
  machine with In-Band Interrupt (IBI) support.
- PWM Control (`narf-pwm`): generic 1-32 channel controller
  abstraction for fan and display-backlight management;
  integrated with `PwmCap` capability-gated access.
- SCMI Platform Management (`narf-scmi`): ARM System Control
  and Management Interface for unified clock, power domain,
  and performance state management.
- PMBus Power Telemetry (`narf-pmbus`): ATX 3.x digital
  sideband support for real-time voltage, current, and
  thermal monitoring over I2C/SMBus.
- Transparent Encrypted Storage (`narf-block::encrypted`):
  AES-256-XTS volume encryption anchored in Measured Boot
  PCRs via TPM 2.0 unsealing.
- USB Hub class (`narf_drivers_usb::hub`): clean-room from the
  USB 2.0 Specification chapter 11. GET_DESCRIPTOR(Hub) + per-
  downstream-port SET_FEATURE(PORT_POWER) + GET_STATUS +
  PORT_RESET / C_PORT_RESET drive the per-port reset flow that
  enables enumeration through external hubs.
- ACPI parser (`narf_arch::x86_64::acpi`): RSDP scan (EBDA + BIOS
  read-only area, with override for Limine-discovered RSDP) →
  XSDT walk → MADT (LAPIC + x2APIC + IOAPIC + interrupt
  overrides) + HPET (MMIO base) + MCFG (PCIe ECAM segments) +
  FADT (IA-PC boot flags). Replaces the hard-coded HPET / ECAM
  base addresses with firmware-discovered ones.
- TSC calibration (`narf_arch::x86_64::tsc`): CPUID 15h
  (TSC/crystal ratio) primary + CPUID 16h (processor base
  frequency) fallback. HPET cross-check hook is exposed for
  older CPUs that don't implement either leaf. Replaces the
  1 GHz nominal that `narf-time` was using.
- Microcode loading (`narf_arch::x86_64::microcode`): vendor
  detection (Intel / AMD via CPUID leaf 0), revision read via
  MSR 0x8B (with the Intel CPUID handshake), Intel update via
  WRMSR 0x79 + AMD patch via WRMSR 0xC0010020, plus an
  `IntelUcodeHeader` decoder for caller-side blob validation.
- PSCI + SMCCC (`narf_arch::aarch64::psci`): clean-room from
  Arm DEN0022D + DEN0028E. `smc` / `hvc` instruction wrappers,
  conduit selector (HVC default for QEMU virt + KVM, SMC for
  bare-metal with secure monitor), and PSCI_VERSION /
  SYSTEM_OFF / SYSTEM_RESET / CPU_OFF.
- MCA / MCE (`narf_arch::x86_64::mce`): Machine-Check
  Architecture per SDM Vol 3 Ch 16. `MCG_CAP` / `MCG_STATUS`
  decode, per-bank `MCi_STATUS` / `ADDR` / `MISC` snapshot, W1C
  clear, init-time enable of every architectural bank. The
  `#MC` IDT vector handler in `frame/` calls into `snapshot()`
  to log + recover instead of triple-faulting.
- MTRR (`narf_arch::x86_64::mtrr`): per SDM §12.11. Capabilities
  + default-type decode, variable-range read/write, plus
  `set_write_combining(phys, size)` for the framebuffer / GPU
  drivers to claim WC on their MMIO BARs.
- Spectre mitigations (`narf_arch::x86_64::spec_ctrl`): per SDM
  Vol 4 §2.16. CPUID-gated `IA32_SPEC_CTRL` (IBRS / STIBP /
  SSBD), `IA32_PRED_CMD` (IBPB), `IA32_FLUSH_CMD` (L1D_FLUSH).
  `enable_default_mitigations()` flips on every supported bit;
  `ibpb()` / `l1d_flush()` are call-site barriers.
- CMOS RTC (`narf_arch::x86_64::rtc`): MC146818 wall-clock read
  via IO 0x70/0x71 with UIP poll for coherency, BCD/binary +
  12/24-hour decode, optional century byte handling, plus a
  `to_unix_seconds(WallTime)` helper for epoch conversion.
- i8254 PIT (`narf_arch::x86_64::pit`): one-shot + rate-gen +
  square-wave modes at IO 0x40-0x43 with the 1.193182 MHz input
  clock. Channel 2 latch + PPI gate at 0x61 for a free-running
  boot timer used as the TSC pre-LAPIC calibration source.
- Generic Timer (`narf_arch::aarch64::timer`): `CNTFRQ_EL0`
  calibration + `CNTPCT_EL0` read with `isb` ordering.
  Replaces the 1 GHz aarch64 fallback in `narf-time::wall`.
- P-states (`narf_power::pstate`): clean-room from SDM Vol 4
  §14.4 + AMD APM Vol 2 §17. Detection picks Intel HWP first
  (CPUID(6).EAX[7]), legacy SpeedStep second (CPUID(1).ECX[7]),
  AMD legacy P-states third (CPUID(0x80000007).EDX[7]); HWP
  capabilities + per-CPU request (`min` / `max` / `desired` /
  `EPP`); legacy `IA32_PERF_CTL` / `MSR_PSTATE_LIMIT` write
  path. Spec: `power/specification/cpu-power.md` §1.
- MWAIT idle (`narf_power::idle`): CPUID(5) decode for the
  supported sub-state set, encode helper for C1..C7 hint
  values, MONITOR/MWAIT entry with interrupt-break extension.
  `idle()` is the canonical kernel idle entry; falls back to
  STI;HLT when MWAIT isn't advertised.
  Spec: `power/specification/cpu-power.md` §2.
- RAPL (`narf_power::rapl`): MSR_RAPL_POWER_UNIT decode into
  µJ-per-unit, package / PP0 (cores) / PP1 (uncore + iGPU) /
  DRAM energy reads, plus `read_temp_c` / `read_pkg_temp_c`
  built on `MSR_IA32_THERM_STATUS` + `MSR_TEMPERATURE_TARGET`.
  Spec: `power/specification/cpu-power.md` §3.
- CPU topology (`narf_arch::x86_64::topology`): CPUID 0x1F (V2
  extended topology) preferred + 0x0B (extended topology) +
  0x04 (deterministic cache parameters) + 0x1A (hybrid info).
  Returns `Topology { levels, n_levels, package_count,
  core_count, thread_count, hybrid, core_type }` + per-level
  `CacheLevelInfo` for L1/L2/L3 size, line, ways, sets,
  threads-sharing. Spec: `arch/specification/smp-topology.md` §1.
- SMP CPU bring-up (`narf_arch::x86_64::smp`): xAPIC + x2APIC
  ICR helpers for the INIT-IPI / SIPI-IPI / SIPI-IPI sequence
  per SDM Vol 3 §9.4.4.1. `aps_from_madt(&Tables, bsp_apic_id)`
  extracts the AP APIC-id list from ACPI MADT entries
  (LocalApic + LocalX2Apic), `start_ap_xapic(lapic_mmio,
  apic_id, trampoline_phys)` blocks until the AP bumps the
  alive counter via `mark_alive()`. Spec:
  `arch/specification/smp-topology.md` §2.
- Intel HFI / Thread Director (`narf_arch::x86_64::hfi`):
  per SDM Vol 4 §14.6 — CPUID(7, 1).EAX[19] gate, the
  `IA32_HW_FEEDBACK_PTR` / `CONFIG` / `THREAD_FEEDBACK_CHAR`
  MSR write surface, and a timestamp poll for detecting class
  changes on the per-package feedback page. Spec:
  `arch/specification/smp-topology.md` §3.
- PMU (`narf_arch::x86_64::pmu`): Intel architectural perfmon
  per SDM Vol 3 Ch 19. CPUID(0xA) capabilities decode, per-CPU
  general-purpose counter programming via `IA32_PERFEVTSELi`,
  fixed-counter enable via `MSR_PERF_FIXED_CTR_CTRL`, atomic
  enable/disable via `IA32_PERF_GLOBAL_CTRL`. Pre-baked
  `arch_event` constructors for the seven architectural events
  (unhalted core cycles, instructions retired, ref cycles,
  LLC reference / miss, branch retired / mispredict). Spec:
  `observability/specification/perfmon.md` §1.
- LBR (`narf_arch::x86_64::lbr`): Last Branch Records per SDM
  Vol 3 §17.5. Family/model classification picks the ring
  depth (4 / 8 / 16 / 32 entries) and the corresponding MSR
  base (Skylake+ 0x680/0x6C0 vs legacy 0x40/0x60).
  `enable(filter)` / `disable` / `read_pair(idx)` / `read_tos`
  for the standard ring walk. Spec:
  `observability/specification/perfmon.md` §2.
- Intel PT (`narf_arch::x86_64::pt`): Processor Trace per SDM
  Vol 3 Ch 35. CPUID(0x14) caps decode, `topa_entry(base,
  size_log2, end, int)` builder, single-entry ToPA install +
  ring-buffer wiring, `enable(os, usr)` flips `IA32_RTIT_CTL`
  with branch-trace + ToPA + per-ring filter; `output_offset` +
  `status` surface ring progress to userspace decoders. Spec:
  `observability/specification/perfmon.md` §3.
- CET (`narf_arch::x86_64::cet`): Control-flow Enforcement per
  SDM Vol 1 §17.2. Shadow-stack (CPUID(7,0).ECX[7]) and IBT
  (CPUID(7,0).EDX[20]) gates, CR4.CET global enable,
  `IA32_S_CET` / `IA32_U_CET` per-ring config (SH_STK_EN +
  WR_SHSTK_EN + ENDBR_EN + NO_TRACK_EN), `IA32_PL0_SSP` /
  `IA32_PL3_SSP` shadow-stack pointer access. Spec:
  `arch/specification/security-hardening.md` §1.
- PEBS (`narf_arch::x86_64::pebs`): Precise Event-Based
  Sampling per SDM Vol 3 §19.6. CPUID + `IA32_MISC_ENABLE.bit12`
  gate, DS save-area install (BTS/PEBS pointer block at
  offsets 0x20..0x40), `MSR_PEBS_ENABLE` per-counter mask, +
  a `PebsBuffer::skylake_basic` constructor for 192-byte
  records. Spec: `arch/specification/security-hardening.md` §2.
- Boot CPU validation (`narf_arch::x86_64::cpu_validate`):
  probes CPUID (Long Mode, RDTSCP, Invariant TSC, NX, SMEP,
  SMAP, UMIP, FSGSBASE, PCID, x2APIC, XSAVE) + CR4 (PAE / PGE /
  OSFXSR / OSXSAVE / SMEP / SMAP / UMIP / FSGSBASE) + EFER
  (LME / NXE) actually-on bits. `baseline_ok(&v)` returns
  `Err(reason)` for the first hard-required miss. Spec:
  `arch/specification/security-hardening.md` §3.
- VMX caps (`narf_arch::x86_64::vmx`): Intel VMX detection per
  SDM Vol 3 Ch 24-25. CPUID(1).ECX[5] gate +
  `IA32_FEATURE_CONTROL` lock check + `IA32_VMX_BASIC` decode
  (revision id, VMCS region size, memory type, true-controls
  bit) + `IA32_VMX_PROCBASED_CTLS2` decode for EPT / VPID /
  unrestricted-guest / APICv / VMCS-shadowing. Spec:
  `arch/specification/virt-confidential.md` §1.
- SVM caps (`narf_arch::x86_64::svm`): AMD SVM detection per
  AMD APM Vol 2 Ch 15. CPUID(0x80000001).ECX[2] gate +
  CPUID(0x8000000A) decode (revision, n_asids, NP, LBR-virt,
  SVM lock, NRIPS, TSC-rate-MSR, VMCB-clean, flush-by-ASID,
  decode-assists, pause-filter) + `MSR_VM_CR.SVMDIS` check.
  Spec: `arch/specification/virt-confidential.md` §2.
- SGX caps (`narf_arch::x86_64::sgx`): SGX detection per SDM
  Vol 3 §38.7. CPUID(7, 0).EBX[2] gate + CPUID(0x12, 0/1/N)
  decode → SGX1/SGX2 + miscselect bitmap + max enclave size +
  EPC section list (up to 4 sections, base/size from sub-leaves
  ≥ 2). Spec: `arch/specification/virt-confidential.md` §3.
- Confidential guest detection
  (`narf_arch::x86_64::confidential`): TDX detection via
  CPUID(0x21, 0) `b"IntelTDX    "` vendor signature; SEV /
  SEV-ES / SEV-SNP detection via `CPUID(0x8000001F)` gate +
  `MSR_AMD64_SEV` (0xC0010131) bits. `detect_environment()`
  returns `ConfidentialEnvironment { Bare, TdxGuest,
  SevGuest, SevEsGuest, SevSnpGuest }`. Spec:
  `arch/specification/virt-confidential.md` §4.
- ASID/PCID-based domain isolation: per-domain page-table root
  (`narf_memory::per_domain_root`) registers a private user-half
  PML4 (x86_64) / TTBR0 (aarch64) for each `DomainId`; the
  generation-tagged allocator (`narf_memory::asid_alloc`) maps
  `DomainId → (tag, generation)` and rolls over when the
  architectural tag space (12-bit PCID / 8-or-16-bit ASID)
  wraps. Selective TLB invalidation lands as `INVPCID` type 0
  through 3 on x86_64 (`narf_arch::x86_64::pcid::invpcid_*`)
  and `TLBI ASIDE1IS` / `TLBI VAE1IS` on aarch64
  (`narf_arch::aarch64::sysreg::tlbi_*`). The
  `narf_memory::tlb_shootdown::shootdown(req)` cross-CPU
  shootdown is wired through
  `narf_interrupts::install_tlb_shootdown_bridge` to fan out via
  the existing IPI infra (x86_64: vector 0xF0 + per-CPU pending
  state; aarch64: `SGI_TLB_SHOOTDOWN`). Spec:
  `memory/specification/asid-pcid-isolation.md`.
- Hypervisor detection (`narf_arch::x86_64::hypervisor`):
  CPUID(1).ECX[31] gate + CPUID(0x40000000) 12-byte signature
  decode → `Hypervisor { None, Kvm, HyperV, Xen, VMware,
  QemuTcg, Bhyve, Parallels, Other }`. KVM feature bitmap from
  CPUID(0x40000001).EAX, Hyper-V version + recommendations
  from 0x40000002 / 0x40000004. Spec:
  `arch/specification/modern-cpu.md` §1.
- XSAVE state management (`narf_arch::x86_64::xsave`): per SDM
  Vol 1 §13. CPUID(0x0D, 0/1/N) decode for XCR0/XSS supported
  bits, area size, per-component feature flags (XSAVEOPT /
  XSAVEC / XSAVES, AVX / AVX-512 / AMX / PKRU classification).
  XGETBV/XSETBV-based `read_xcr0` / `write_xcr0`, MSR-based
  `read_xss` / `write_xss`, `enable_default()` boot policy,
  `xsave` / `xrstor` instruction wrappers. Spec:
  `arch/specification/modern-cpu.md` §2.
- WAITPKG (`narf_arch::x86_64::waitpkg`): per SDM Vol 2.
  CPUID(7, 0).ECX[5] gate, `IA32_UMWAIT_CONTROL` (0xE1)
  config + `umonitor` / `umwait` / `tpause` instruction
  wrappers; latter two return `true` if the monitor fired
  before the deadline. Spec:
  `arch/specification/modern-cpu.md` §3.
- AMD SMCA (`narf_arch::x86_64::smca`): Scalable MCA per AMD
  APM Vol 2 + BKDG. CPUID(0x80000007).EBX[3] gate, per-bank
  extended registers at `0xC0002000 + 16*i + offset` (CONFIG /
  IPID / SYND / DESTAT / MISC0) read + decoded into
  `SmcaBankInfo { instance_id, hardware_id, mca_type }` +
  `BankType` enum (LS, IF, L2, DE, EX, FP, L3, MP5, SMU, PB,
  UMC, PCIe). Augments the legacy MCA decode in `mce` for
  Zen+ silicon. Spec:
  `arch/specification/modern-cpu.md` §4.
- AMD INVLPGB (`narf_arch::x86_64::invlpgb`):
  CPUID(0x80000008).EBX[3] gate. Raw `INVLPGB` (`0F 01 FE`) +
  `TLBSYNC` (`0F 01 FF`) wrappers, `count_max` / `asid_max`
  decode, plus `invalidate_all_global` / `invalidate_asid`
  conveniences for the broadcast-TLB path on Zen3+. Spec:
  `arch/specification/cpu-perf-niche.md` §1.
- AMD RDPRU (`narf_arch::x86_64::rdpru`):
  CPUID(0x80000008).EBX[4] gate. Raw `RDPRU` (`0F 01 FD`)
  wrapper plus `read_mperf` / `read_aperf` that dispatch to
  RDPRU when supported and fall through to RDMSR otherwise.
  Spec: `arch/specification/cpu-perf-niche.md` §2.
- CLDEMOTE / MOVDIRI / MOVDIR64B (`narf_arch::x86_64::movdir`):
  CPUID(7, 0).ECX[25/27/28] gates + instruction wrappers for
  cache-demote hints (NOP-safe on older silicon) and write-
  combining direct stores (`movdiri32`, `movdiri64`, atomic
  64-byte `movdir64b`). Spec:
  `arch/specification/cpu-perf-niche.md` §3.
- WRMSRNS (`narf_arch::x86_64::wrmsrns`): non-serialising MSR
  write per Sapphire Rapids+. CPUID(7, 1).EAX[19] gate, raw
  `0F 01 C6` wrapper, and a `write(msr, value)` helper that
  picks WRMSRNS when supported and falls through to WRMSR
  otherwise. Spec: `arch/specification/cpu-perf-niche.md` §4.
- AVX10 (`narf_arch::x86_64::avx10`): CPUID(7, 1).EDX[19]
  gate + CPUID(0x24, 0) decode → `Avx10Caps { supported,
  version, xmm, ymm, zmm, converged_with_avx512 }` for the
  unified AVX-512 / AVX2 ISA enumeration leaf. Spec:
  `arch/specification/cpu-perf-niche.md` §5.
- x86_64 CPU identification (`narf_arch::x86_64::ident`):
  CPUID(0) vendor decode → `Vendor { Intel, Amd, Hygon, Centaur,
  Via, Zhaoxin, Other }`. CPUID(1).EAX → family / model /
  stepping with extended-family + extended-model fold per
  SDM §3.2. CPUID(0x80000002..4) brand string + leading-space
  trim. Spec: `arch/specification/cpu-info-errata.md` §1.
- x86_64 cache geometry (`narf_arch::x86_64::cache`): CPUID(1).EBX
  `CLFLUSH line size`, CPUID(7,0).EBX[23/24] for CLFLUSHOPT /
  CLWB, CPUID(0x80000008).EBX[9] for WBNOINVD. Instruction
  wrappers (`clflush`, `clflushopt`, `clwb`, `wbnoinvd`) +
  `CacheCaps` snapshot. Spec:
  `arch/specification/cpu-info-errata.md` §2.
- x86_64 errata workarounds (`narf_arch::x86_64::errata`):
  `&'static [Errata]` table sorted by (vendor, family,
  model_lo). v0.1 carries Intel SKL-X TSX-RTM disable
  (`MSR_IA32_TSX_CTRL`) and AMD Zen1 erratum 1474
  (`MSR_DE_CFG[9]`). `apply_for_current_cpu()` fans out matching
  entries; tail-of-table marker keeps appends mechanical. Spec:
  `arch/specification/cpu-info-errata.md` §3.
- x86_64 PMI binding (`narf_arch::x86_64::pmi`): LAPIC LVT-PC
  programming at `LAPIC_BASE + 0x340` — `program_lvt_pc(vector,
  nmi, masked)`, `mask_lvt_pc`, `unmask_lvt_pc`. Wire-once
  primitive for the PMU / LBR / Intel-PT subsystems; the actual
  handler stays in `pmu`. Spec:
  `arch/specification/cpu-info-errata.md` §4.
- aarch64 CPU identification (`narf_arch::aarch64::ident`):
  MIDR_EL1 → `AarchIdent { implementer, variant, part, revision,
  raw }` + REVIDR_EL1 + implementer-name lookup (Arm / Apple /
  Ampere / Qualcomm / NVIDIA / Marvell / Samsung / Broadcom /
  Cavium / Fujitsu / Faraday). Spec:
  `arch/specification/cpu-info-errata.md` §5.1.
- aarch64 cache geometry (`narf_arch::aarch64::cache`): CTR_EL0
  decode → `AarchCacheCaps { iline_bytes, dline_bytes,
  cwg_bytes }` per the architectural `4 << field` rule. Spec:
  `arch/specification/cpu-info-errata.md` §5.2.
- Intel RDT (`narf_arch::x86_64::rdt`): Cache + memory-bandwidth
  QoS per SDM Vol 3 §17. CPUID(7, 0).EBX[12/15] master gates,
  CPUID(0x0F) / CPUID(0x10) sub-feature decode → `RdtCaps`
  (monitoring, allocation, L3-CMT, L3-CAT, L2-CAT, MBA, RMID +
  CLOSID ranges). `assoc(rmid, closid)` via IA32_PQR_ASSOC,
  `read_event(rmid, evt_id)` via QM_EVTSEL / QM_CTR,
  `write_l3_mask` / `write_l2_mask` / `write_mba_throttle`
  per CLOSID. Spec: `arch/specification/cpu-telemetry-qos.md` §1.
- Intel FRED (`narf_arch::x86_64::fred`): Flexible Return and
  Event Delivery. CPUID(7, 1).EAX[17] gate, IA32_FRED_RSP{0..3} /
  SSP{1..3} / STKLVLS / CONFIG MSR programming, CR4.FRED (bit 32)
  enable + disable, `write_handler_base(va)` for the page-aligned
  event-handler base. Spec:
  `arch/specification/cpu-telemetry-qos.md` §2.
- aarch64 BRBE (`narf_arch::aarch64::brbe`): Branch Record Buffer
  Extension — LBR analogue. `ID_AA64DFR0_EL1.BRBE` decode +
  `BRBCR_EL1` / `BRBFCR_EL1` read/write via raw
  `S2_1_C9_C0_0/1` encodings + `enable` (E0BRE+E1BRE) / `disable`
  / `freeze` (BRBCR.PAUSED). Spec:
  `arch/specification/cpu-telemetry-qos.md` §3.
- aarch64 TRBE (`narf_arch::aarch64::trbe`): Trace Buffer
  Extension — Intel-PT analogue.
  `ID_AA64DFR0_EL1.TraceBuffer` gate + `TRBLIMITR_EL1` /
  `TRBPTR_EL1` / `TRBBASER_EL1` / `TRBIDR_EL1` programming via
  raw `S3_0_C9_C11_*` encodings + `write_base(base, limit)` +
  enable / disable. Spec:
  `arch/specification/cpu-telemetry-qos.md` §4.
- aarch64 MPAM (`narf_arch::aarch64::mpam`): Memory Partitioning
  and Monitoring — RDT analogue.
  `ID_AA64PFR0_EL1.MPAM` major + `ID_AA64PFR1_EL1.MPAM_frac`
  minor decode, `MPAMIDR_EL1` PARTID/PMG ranges, `write_mpam0` /
  `write_mpam1` packing PARTID_D + PARTID_I + PMG_D + PMG_I +
  MPAMEN. Spec: `arch/specification/cpu-telemetry-qos.md` §5.
- aarch64 SPE (`narf_arch::aarch64::spe`): Statistical Profiling
  Extension — PEBS analogue. `ID_AA64DFR0_EL1.PMSVer` decode +
  PMSCR / PMSIRR / PMSIDR / PMBLIMITR / PMBPTR programming via
  raw `S3_0_C9_C9_*` and `S3_0_C9_C10_*` encodings,
  `program_buffer(base, limit)` + `enable` / `disable`. Spec:
  `arch/specification/cpu-arch-extensions.md` §1.
- aarch64 ETE (`narf_arch::aarch64::ete`): Embedded Trace
  Extension — pairs with TRBE as the in-core trace generator.
  `ID_AA64DFR0_EL1.TraceVer` gate + TRCPRGCTLR (`S2_1_C0_C1_0`)
  enable bit + TRCSTATR readback. Spec:
  `arch/specification/cpu-arch-extensions.md` §2.
- aarch64 GCS (`narf_arch::aarch64::gcs`): Guarded Control Stack
  — CET-SHSTK analogue. `ID_AA64PFR1_EL1.GCS` decode +
  GCSCR_EL1 / GCSCRE0_EL1 / GCSPR_EL{0,1} access via raw
  `S3_0_C2_C5_*` + `S3_3_C2_C5_1` encodings.
  `enable_el1(rvcheck, exception_push)` / `enable_el0(rvcheck)`
  + matching disablers. Spec:
  `arch/specification/cpu-arch-extensions.md` §3.
- aarch64 RNDR / RNDRRS (`narf_arch::aarch64::rndr`):
  architecturally-mandated hardware RNG.
  `ID_AA64ISAR0_EL1.RNDR` gate + `try_rndr()` and
  `try_rndrrs()` returning `Option<u64>` — failures map to
  `None` via the architectural `NZCV.C = 0` signal captured
  with `cset`. Spec:
  `arch/specification/cpu-arch-extensions.md` §4.
- Intel LASS (`narf_arch::x86_64::lass`): Linear Address Space
  Separation. CPUID(7, 1).EAX[6] gate + CR4.LASS (bit 27)
  enable / disable. Defeats SMAP-bypass-style probes by faulting
  any cross-half load/store before paging permissions are
  consulted. Spec:
  `arch/specification/cpu-arch-extensions.md` §5.
- aarch64 SME (`narf_arch::aarch64::sme`): Scalable Matrix
  Extension. `ID_AA64PFR1_EL1.SME` decode → `SmeCaps { sme,
  sme2 }`, `SVCR` (`S3_3_C4_C2_2`) + `SMCR_EL1`
  (`S3_0_C1_C2_6`) read/write, plus `enter_streaming` /
  `leave_streaming` / `enable_za` / `disable_za`. Spec:
  `arch/specification/cpu-compute-confidential.md` §1.
- aarch64 RME (`narf_arch::aarch64::rme`): Realm Management
  Extension. `ID_AA64PFR0_EL1.RME` decode + `supported()`
  predicate; state-management lives in the RMM at EL3. Spec:
  `arch/specification/cpu-compute-confidential.md` §2.
- aarch64 SPECRES (`narf_arch::aarch64::specres`): speculation-
  restriction primitives. `ID_AA64ISAR1_EL1.SPECRES` decode +
  `cfp_rctx(ctx)` raw `SYS #3, C7, C3, #4, Xt` wrapper. Spec:
  `arch/specification/cpu-compute-confidential.md` §3.
- Intel BHI controls (`narf_arch::x86_64::bhi`): branch-history
  injection mitigation. CPUID(7, 2).EDX[4] `BHI_NO` detection +
  `IA32_SPEC_CTRL.BHI_DIS_S` (bit 10) enable / disable. Spec:
  `arch/specification/cpu-compute-confidential.md` §4.
- Intel PASID (`narf_arch::x86_64::pasid`): Process-Address-
  Space-ID for accelerator Shared Virtual Memory. CPUID(7, 0)
  .ECX[2] gate + `IA32_PASID` (`0xD93`) read/write/invalidate
  (20-bit PASID + VALID bit). Spec:
  `arch/specification/cpu-compute-confidential.md` §5.
- Intel VT-d (`narf_arch::x86_64::vtd`): DMA-Remap engine
  register-block layout per SDM Vol 3 §10. VER / CAP / ECAP /
  GCMD / GSTS / RTADDR / FSTS / PMEN offsets, GCMD/GSTS bit
  constants, and `decode_caps(ver, cap, ecap)` → `VtdCaps`
  (version, num_domains, sagaw, num_fault_regs, queued
  invalidation, interrupt remap) + MMIO read / write helpers.
  Spec: `arch/specification/iommu-interconnect.md` §1.
- AMD-Vi IOMMU (`narf_arch::x86_64::amd_vi`): per the AMD IOMMU
  spec rev 3.10. DEV_TAB_BASE / CMD_BUF_BASE / EVT_LOG_BASE /
  IOMMU_CTRL / EXT_FEATURES / PPR_LOG_BASE offsets,
  `decode_caps(ctrl, efr)` → `AmdViCaps` (enable bits + PPR /
  GT / XTS) + MMIO read / write helpers. Spec:
  `arch/specification/iommu-interconnect.md` §2.
- Intel RAR (`narf_arch::x86_64::rar`): Remote Action Request
  fast-path doorbell. CPUID(7, 1).EAX[31] gate +
  IA32_RAR_INFO_BASE / IA32_RAR_CTRL MSRs +
  `doorbell(mmio_base, action, target_lpid, payload)` for
  vector-less remote TLB shootdown / RDPMC / INVD on Sapphire
  Rapids+. Spec:
  `arch/specification/iommu-interconnect.md` §3.
- ARM SMMUv3 (`narf_arch::aarch64::smmuv3`): per Arm IHI 0070.
  IDR0..5 / CR0..2 / GBPA / STRTAB_BASE offsets,
  `decode_caps(idr0, idr1, idr5)` → `SmmuCaps` (S1P / S2P,
  TTF16 / TTF64 granule support, OAS class, SIDSIZE,
  queue-base shareability) + MMIO read / write helpers. Spec:
  `arch/specification/iommu-interconnect.md` §4.
- Intel IR (`narf_arch::x86_64::ir`): Interrupt Remapping Table
  Entry encode / decode (present, fault-disable, dest-mode,
  vector, delivery-mode, destination) + `write_irtar(reg_base,
  table_pa, log2_size)` IRTAR programming on top of the
  existing VT-d primitives. Spec:
  `arch/specification/irq-cache-numa.md` §1.
- AMD GA (`narf_arch::x86_64::amd_ga`): thin predicates
  `ga_supported(efr)` / `ia_supported(efr)` over the AMD-Vi
  `EXT_FEATURES` bitmap so callers don't reach into the bitmap
  directly. Spec: `arch/specification/irq-cache-numa.md` §2.
- GICv3 ITS (`narf_arch::aarch64::gits`): per Arm IHI 0069.
  CTLR / IIDR / TYPER / CBASER / CWRITER / CREADR / BASER0
  offsets, `decode_caps(typer)` → `GitsCaps` (id_bits, dev_bits,
  hcc, physical) + enable / disable / write_cbaser MMIO
  helpers. Spec: `arch/specification/irq-cache-numa.md` §3.
- x86_64 cache topology (`narf_arch::x86_64::cache_topology`):
  per-level enumerator over CPUID(4) (Intel) / CPUID(0x80000_01D)
  (AMD/Hygon) → `CacheLevel { level, kind, line_bytes,
  partitions, ways, sets, size_bytes, fully_assoc,
  apic_ids_sharing }`. Spec:
  `arch/specification/irq-cache-numa.md` §4.
- aarch64 cache topology (`narf_arch::aarch64::cache_topology`):
  per-level enumerator over CLIDR_EL1 + CSSELR_EL1 + CCSIDR_EL1
  → `CacheLevel { level, kind, line_bytes, ways, sets,
  size_bytes }`. Handles separate I/D + unified caches via the
  CLIDR field-per-level encoding. Spec:
  `arch/specification/irq-cache-numa.md` §5.
- NUMA primitives (`narf_arch::x86_64::numa` /
  `narf_arch::aarch64::numa`): x86 `set_apic_to_domain(cb)`
  hook for SRAT consumers + `domain_for_apic_id(apic_id)`
  lookup; aarch64 `cluster_id(mpidr)` decode helper +
  `domain_for_current_cpu()` (Aff2). Spec:
  `arch/specification/irq-cache-numa.md` §6.
- Intel TME / MKTME (`narf_arch::x86_64::tme`): Total Memory
  Encryption + multi-key extension. CPUID(7, 0).ECX[13] gate +
  `IA32_TME_CAPABILITY` (`0x981`) decode → `TmeCaps`
  (AES-XTS-128 / AES-XTS-128-integrity / AES-XTS-256,
  max_keyid_bits, max_keys) + `IA32_TME_ACTIVATE` (`0x982`)
  read / write + LOCK predicate. Spec:
  `arch/specification/cpu-mem-encrypt-virt.md` §1.
- Intel RTM-abort kill-switch (`narf_arch::x86_64::rtm_abort`):
  CPUID(7, 0).EDX[11] `RTM_ALWAYS_ABORT` detection +
  `IA32_TSX_FORCE_ABORT` (`0x10F`) read / write +
  `force_rtm_abort()` boot-baseline helper that sets bit 0.
  Spec: `arch/specification/cpu-mem-encrypt-virt.md` §2.
- aarch64 ECV (`narf_arch::aarch64::ecv`): Enhanced Counter
  Virtualization. `ID_AA64MMFR0_EL1.ECV` decode +
  `supported()` / `cntpoff_supported()` (ECV ≥ 2). Spec:
  `arch/specification/cpu-mem-encrypt-virt.md` §3.
- aarch64 NV / NV2 (`narf_arch::aarch64::nv2`): Nested
  Virtualization. `ID_AA64MMFR2_EL1.NV` decode +
  `supported()` (FEAT_NV) and `nv2_supported()` (FEAT_NV2).
  Spec: `arch/specification/cpu-mem-encrypt-virt.md` §4.
- aarch64 FEAT_E0PD (`narf_arch::aarch64::e0pd`):
  privileged-only-data on TTBR0/TTBR1.
  `ID_AA64MMFR2_EL1.E0PD` decode + `enable_kernel_half()` /
  `disable_kernel_half()` flipping `TCR_EL1.E0PD1` (Meltdown-
  style KASLR-bypass mitigation independent of KPTI). Spec:
  `arch/specification/cpu-mem-encrypt-virt.md` §5.
- Intel Split Lock Detect (`narf_arch::x86_64::sld`):
  CPUID(7, 0).EDX[5] gate + `IA32_CORE_CAPABILITIES.SLD`
  (bit 5) + `IA32_TEST_CTRL` (`0x33`) read / write +
  `enable_ac()` (raise `#AC` on split locks) / `disable()`.
  Spec: `arch/specification/cpu-atomics-mitigations.md` §1.
- Intel Bus Lock Trap (`narf_arch::x86_64::buslock`):
  CPUID(7, 0).ECX[24] gate + `IA32_DEBUGCTL.BUS_LOCK_DETECT`
  (bit 2) enable / disable so userspace bus locks raise a
  trap before they tank line-rate. Spec:
  `arch/specification/cpu-atomics-mitigations.md` §2.
- aarch64 LSE / LSE128 + RCPC / RCPC2 / RCPC3
  (`narf_arch::aarch64::lse`): `ID_AA64ISAR0_EL1.Atomic`
  decode → `lse_supported()` / `lse128_supported()` and
  `ID_AA64ISAR1_EL1.LRCPC` decode →
  `rcpc{,2,3}_supported()`. Spec:
  `arch/specification/cpu-atomics-mitigations.md` §3 + §4.
- aarch64 FEAT_S1PIE / FEAT_S2PIE
  (`narf_arch::aarch64::pie`): Permission Indirect Encoding.
  `ID_AA64MMFR3_EL1.S1PIE` + `S2PIE` decode → `PieCaps {
  s1pie, s2pie }` + PIR_EL1 (`S3_0_C10_C2_3`) / PIRE0_EL1
  (`S3_0_C10_C2_2`) read + write helpers. Spec:
  `arch/specification/cpu-atomics-mitigations.md` §5.
- aarch64 FEAT_SCTLR2 (`narf_arch::aarch64::sctlr2`):
  `ID_AA64MMFR3_EL1.SCTLRX` decode + SCTLR2_EL1
  (`S3_0_C1_C0_3`) read + write helpers. Spec:
  `arch/specification/cpu-atomics-mitigations.md` §6.
- ACPI PPTT / IORT / DMAR / IVRS / SPCR (`narf_acpi`):
  enumeration parsers for the IOMMU + topology + console
  tables. PPTT yields `PpttCpu` (acpi_uid, package, thread,
  leaf) + `PpttCache` (line, ways, sets, size, kind). IORT
  yields `IortSmmuv3` + `IortIts`. DMAR yields `DmarDrhd`
  (register base, segment, include-all-PCI) + an
  INTR_REMAP-supported predicate. IVRS yields `IvrsIommu`
  (base, segment, capability offset). SPCR yields `SpcrInfo`
  (interface, GAS base, GSI, baud code, PCI device id). Each
  table follows the existing idempotent / sticky-flag pattern
  on top of `walk_xsdt`. Spec:
  `acpi/specification/tables-iommu-topology.md`.
- ACPI HEST / PCCT / SLIT / CEDT / BERT (`narf_acpi`):
  RAS + locality + CXL + boot-error parsers. HEST yields
  `HestMceSource` (Type 0) + `HestGhesSource` (Type 9/10) for
  the Machine-Check and Generic Hardware Error reporting
  paths. PCCT yields `PcctChannel` (shmem base + length,
  doorbell GAS + write mask, min turnaround) for OSPM↔BMC /
  HFI plumbing. SLIT yields an N×N distance-matrix lookup
  via `slit_distance(from, to)`. CEDT yields `CedtChbs` (CXL
  Host Bridge MMIO base + version) and `CedtCfmws` (Fixed
  Memory Window). BERT yields `BertInfo { region_addr,
  region_length }` for the boot-error region. Spec:
  `acpi/specification/tables-ras-cxl-locality.md`.
- FDT / DTB v17 (`narf_firmware_fdt`): pure-byte-slice
  parser for the Devicetree-Specification-v0.4 / FDT-v17 blob.
  Validates the 40-byte big-endian header (magic / totalsize /
  off_dt_struct / off_dt_strings / off_mem_rsvmap / version /
  size fields), decodes the memory-reserve map, and walks the
  struct block via `walk_nodes(blob, |path, props| { … })`
  with the FDT_BEGIN / END / PROP / NOP / END token state
  machine. `Path` carries a depth-tracked stack of segment
  lengths so `path.matches(&["cpus", "cpu@0"])` works against
  `/cpus/cpu@0` without allocating. Convenience helpers
  `chosen_bootargs(blob)`, `copy_memory_ranges(blob, …)`, and
  `copy_reservations(blob, …)` ride on top. Spec:
  `firmware/fdt/specification/spec.md`.
- SMBIOS / DMI (`narf_firmware_smbios`): entry-point-
  agnostic structure-stream parser with **full SMBIOS 3.x
  type coverage** — every defined structure (Types 0..46
  plus 126 / 127) is decoded into a strongly-typed record
  with per-type accessors (`copy_*` / `*_info`). Decoded
  surface includes BIOS / System / Baseboard / Chassis /
  Processor; Cache / Port / Slot; OEM-Strings / SysConfig /
  BIOS-Language / Group-Assoc / Event-Log; Physical-Memory-
  Array / Memory-Device / Mem-Err-32 / Mem-Array-Addr /
  Mem-Device-Addr; Pointing / Battery / SysReset /
  HwSecurity / SysPowerCtrl; Voltage / Cooling / Temperature
  / Current probes; OOB-Remote-Access / BIS / SystemBoot;
  Mem-Err-64; Mgmt-Device / Mgmt-Device-Component / Threshold
  / Memory-Channel; IPMI / Power-Supply; Additional-Info /
  Onboard-Ext / Mgmt-Ctrl-HCI; TPM / Proc-Additional /
  Firmware-Inventory / String-Property. Types 5 / 6 / 10
  (deprecated) are walked but not decoded; Type 126 is
  counted; Type 127 ends the stream. Spec:
  `firmware/smbios/specification/spec.md`.
- ACPI TCPA / MCHI / PHAT / StAO / UEFI (`narf_acpi`):
  TPM-1.2 + management-controller + platform-health +
  status-override + UEFI-data parsers. TCPA yields `TcpaInfo`
  (platform class, log area min, log area phys). MCHI yields
  `MchiInfo` (interface type — KCS / SMIC / BT / SMBus —
  protocols bitmap, identifier, GAS base). PHAT yields per-
  Type-1-record `PhatHealthRecord` (AmHealthy + 16-byte device
  GUID). StAO yields `StaoInfo` (ignore-UART boolean). UEFI
  yields `UefiTableInfo` (16-byte vendor / data GUID + payload
  data offset). Spec:
  `acpi/specification/tables-tcpa-mchi-phat-stao-uefi.md`.
- ACPI BOOT / DBGP / WPBT / MSCT / XENV (`narf_acpi`):
  boot-flag + legacy-debug-port + Windows-platform-binary +
  max-system-characteristics + Xen-environment parsers. BOOT
  yields `BootInfo` (CMOS index for boot flag). DBGP yields
  `DbgpInfo` (interface, GAS base) — the legacy single-port
  sibling of DBG2. WPBT yields `WpbtInfo` (handoff size +
  address, layout / content types) for the Windows platform-
  binary handoff. MSCT yields `MsctInfo` (max proximity / clock
  domains, max phys-addr cap) + per-PDIS `MsctPdis` (domain
  range, max processors, max memory). XENV yields `XenvInfo`
  (Xen grant-table base + size, event-channel SPI). Spec:
  `acpi/specification/tables-boot-dbgp-wpbt-msct-xenv.md`.
- ACPI ECDT / NHLT / IBFT / CSRT / AGDI (`narf_acpi`):
  embedded-controller, audio-link, iSCSI-boot, generic-resource,
  Arm-diagnostic parsers. ECDT yields `EcdtInfo` (control GAS,
  data GAS, UID, GPE bit). NHLT yields per-endpoint
  `NhltEndpoint` (link type, instance id, vendor / device id,
  direction). IBFT yields `IbftTarget` (16-byte IPv6-mapped
  target IP, port, LUN). CSRT yields per-Resource-Group
  `CsrtGroup` (vendor, device, revision). AGDI yields
  `AgdiInfo` (SDEI vs SMC, SDEI event number, SMC id). Spec:
  `acpi/specification/tables-ec-audio-iscsi-csrt-agdi.md`.
- ACPI CCEL / MPST / SDEV / SBST / RAS2 (`narf_acpi`):
  Confidential-compute + memory-power + secure-devices +
  smart-battery + RAS-feature parsers. CCEL yields
  `CcelInfo` (CC type / subtype, log buffer min length, log
  buffer physical address). MPST yields per-node `MpstNode`
  with enable / power-managed / hot-pluggable flags + base +
  length. SDEV yields `SdevPci` (segment + start-BDF) for
  Type-1 PCI-endpoint entries. SBST yields `SbstInfo`
  (warning / low / critical levels in mWh). RAS2 yields
  per-PCC `Ras2Descriptor` (pcc id, feature type, instance
  count). Spec:
  `acpi/specification/tables-confidential-power-secure.md`.
- ACPI WSMT / WAET / HPET / FACS / PRMT (`narf_acpi`):
  Windows-mitigation + emulated-device + HPET-description +
  firmware-control + Platform-Runtime-Mechanism parsers.
  WSMT yields `WsmtInfo` (fixed comm buffers, nested-ptr
  protection, system-resource protection). WAET yields
  `WaetInfo` (RTC-good, ACPI-PM-timer-good). HPET-desc yields
  `HpetDesc` (block id, GAS base, HPET number, counter-min,
  OEM attrs) — pairs with the existing
  `arch::x86_64::hpet` driver. FACS is reached via FADT and
  yields `FacsInfo` (hardware signature, 32-bit + 64-bit
  firmware waking vectors, global lock, flags, version).
  PRMT yields per-module `PrmtModule` (major / minor revision,
  handler count, MMIO range). Spec:
  `acpi/specification/tables-firmware-hpet-prm.md`.
- ACPI ERST / EINJ / TPM2 / BGRT / DBG2 (`narf_acpi`):
  RAS-injection + serialization + TPM2 + boot-graphics +
  debug-port parsers. ERST and EINJ share the 32-byte
  instruction-entry shape and surface
  `ErstInstruction` / `EinjInstruction` (action + instruction
  + addr + value + mask). TPM2 yields `Tpm2Info` (platform
  class, control area address, start method). BGRT yields
  `BgrtInfo` (displayed-status, image address, x/y offsets).
  DBG2 walks the per-table DeviceInfo array and yields
  `Dbg2Device` (port type, subtype, MMIO base from the first
  GAS in the BAR array). Spec:
  `acpi/specification/tables-ras-tpm-debug.md`.
- ACPI AEST / SDEI / WDDT / LPIT / NFIT (`narf_acpi`):
  Arm-RAS, software-delegated-exception, watchdog,
  low-power-idle, and NVDIMM table parsers. AEST yields
  per-node `AestNode { kind, iface, base }`. SDEI surfaces
  just a sticky `is_sdei_known()` flag — the actual SDEI ABI
  is reached via SMCCC. WDDT yields `WddtInfo` (timer
  min/max/period, status, capability, GAS base). LPIT yields
  `LpitState` (UID + trigger GAS + residency + latency +
  counter GAS + counter freq) for the Native-C-State subtable.
  NFIT yields `NfitSpaRange` (range index, proximity, base,
  length, memory-mapping attribute) for the System-Physical-
  Address subtable. Spec:
  `acpi/specification/tables-arm-ras-power-pm.md`.
- aarch64 SVE / SVE2 (`narf_arch::aarch64::sve`):
  `ID_AA64PFR0_EL1.SVE` + `ID_AA64ZFR0_EL1.SVEver` decode →
  `SveCaps { sve, sve2, sve21 }` (CPACR-safe; reads ID-group
  registers only). `probe_max_vl_bits` / `set_vl_bits` /
  `read|write_zcr_el1` use raw `S3_0_*` system-register
  encodings and require `CPACR_EL1.ZEN` open. Spec:
  `arch/specification/cpu-perf-niche.md` §6.
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

Run `cargo xtask test --arch=x86_64` (or `--arch=aarch64`) for the
full kernel-test summary; the runner prints
`── summary: <pass> pass, <fail> fail, <skip> skip ──`. Skips are
x86-specific PCIe surfaces or live-device tests that skip cleanly
when QEMU doesn't expose the device.

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

### Prerequisites

- Rust nightly (pinned by `rust-toolchain.toml` to
  `nightly-2025-09-14` with `rust-src`, `llvm-tools`, `clippy`, and
  `rustfmt`). `rustup` reads the pin automatically on first
  `cargo` invocation — no manual `+nightly` needed.
- `qemu-system-x86_64` and/or `qemu-system-aarch64` (e.g.
  `apt install qemu-system-x86 qemu-system-arm` on Debian /
  Ubuntu, `pacman -S qemu-full` on Arch). The aarch64 host
  binary is needed for `--arch=aarch64`.
- `xorriso` and `mtools` for ISO building (`apt install xorriso
  mtools`, `pacman -S libisoburn mtools`). Only the `image` /
  `iso-boot` / `disk-write` subcommands need these.
- `OVMF` UEFI firmware for `iso-boot`
  (`apt install ovmf`, `pacman -S edk2-ovmf`). Defaults to
  `/usr/share/OVMF/OVMF_CODE.fd` paths; xtask probes a few
  common locations.

xtask cross-builds against `x86_64-unknown-none` /
`aarch64-unknown-none` with `build-std`, then launches QEMU.
NVMe images and the QEMU virt DTB are generated lazily into
`target/`.

### Boot under QEMU

```sh
# Async demo, serial-only (default --display=none):
cargo xtask run --arch=x86_64
cargo xtask run --arch=aarch64

# With a graphical display window (gtk / sdl / cocoa, depending
# on host) — useful for the framebuffer / shell:
cargo xtask run --arch=x86_64 --display=gtk

# Pick a hardware profile (default is `full` — all supported
# devices enabled). Useful for isolating driver paths:
cargo xtask run --arch=x86_64 --hw-profile=minimal      # serial only
cargo xtask run --arch=x86_64 --hw-profile=virtio-only  # VirtIO + serial
cargo xtask run --arch=x86_64 --hw-profile=legacy-only  # non-VirtIO + serial
```

### Run the kernel-test suite

```sh
# Boots a kernel build that runs every `kernel_test_in!` smoke
# under QEMU and exits via isa-debug-exit when done. The runner
# prints `── summary: <pass> pass, <fail> fail, <skip> skip ──`
# on the way out.
cargo xtask test --arch=x86_64
cargo xtask test --arch=aarch64
```

Skips are tests that need a device QEMU doesn't emulate (e.g.
Intel 82599); they exit cleanly without failing the run.

### Build an ISO + boot it under OVMF

```sh
# Build the Limine ISO (lands at target/narf-x86_64.iso) and
# boot it under QEMU + OVMF UEFI in one step:
cargo xtask iso-boot --arch=x86_64

# Just produce the ISO without booting:
cargo xtask image --arch=x86_64

# Boot the ISO with a graphical display + the user-mode testbin
# running (interactive shell at the `narf>` prompt):
cargo xtask demo --arch=x86_64 --display=gtk
```

The ISO uses Limine as the bootloader on x86_64. On aarch64
`xtask image` produces a kernel + DTB image bootable via QEMU
`-kernel`; no ISO is built since the aarch64 boot path is
direct-kernel today.

### Burn the ISO to a USB stick

> Writes are destructive. xtask refuses to write to a device
> that isn't USB-attached (no `/dev/sda` that's actually your
> system disk by accident). Always double-check the device path
> via `lsblk` first.

```sh
# Auto-detect the first USB-attached disk:
sudo cargo xtask disk-write

# Or pin a specific device:
sudo cargo xtask disk-write --device /dev/sdX

# Skip the slow full-device wipe if you know the USB has no
# leftover bootable signatures past the ISO size:
sudo cargo xtask disk-write --device /dev/sdX --no-wipe

# Fast wipe: zero the MBR / GPT / EFI / El Torito regions only
# (first 100 MiB + last 4 MiB), skip the middle-of-disk zero-fill.
# Same boot-correctness as a full wipe when the USB is larger
# than the ISO.
sudo cargo xtask disk-write --device /dev/sdX --fast-wipe

# Burn a custom ISO path:
sudo cargo xtask disk-write --device /dev/sdX --iso path/to/narf.iso
```

After the `dd` finishes, xtask does a logical detach + re-probe
+ read-back verification so the burn is guaranteed to land on
the USB stick's flash NAND, not the USB controller's write
cache. The check catches the failure mode where a successful
`dd` exit code paired with a still-default boot sector means
the firmware has the writes buffered but they never reached
the device.

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

## License

GPL-2.0-or-later. See [`LICENSE`](./LICENSE) for the full text.

The license posture lets kernel code interface with and adapt
from GPLv2-compatible projects — most importantly the Linux
kernel, so register layouts, driver patterns, and protocol
implementations can flow in either direction. Code that landed
before the 2026-05-20 relicense was originally under MPL-2.0
and was authored as clean-room (no GPL source consulted); the
clean-room marker on files like `memory/src/{buddy,slab,heap}.rs`
and `crypto/src/clean/*` stays accurate as a historical
statement of provenance. New code after the relicense does not
need to follow the clean-room rule.
