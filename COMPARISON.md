# NARF compared to Linux, the BSDs, and classical microkernels

NARF is not a clone of either the monolithic-kernel family or the
microkernel family — it occupies a different point in the design space.
This document is for orientation, not scoring; "absent" features in any
column are usually deliberate choices, not omissions.

The headline trade NARF makes is **isolation without an IPC tax**. Linux
and the BSDs get throughput by putting drivers inside the kernel and
accepting that a buggy driver can corrupt anything. Classical microkernels
(Mach, L4, seL4, Minix 3) get isolation by putting drivers in user
processes and paying for an address-space crossing on every interaction.
NARF puts drivers in the kernel address space **and** isolates them,
using PKS/MTE to make the boundary a single instruction instead of a TLB
shootdown when the silicon supports it. The cost is hardware sensitivity
— the fast backend is restricted to specific generations — and a smaller
mature driver set than a 30-year-old project. The win is that
"`Cap<T>` + domain + zero-copy ring" is enforceable end-to-end without
falling back to "trust every kthread."

## Design-space chart

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
| Syscall numbers | Stable, per-arch | Stable, per-arch | **Linux-ABI compatible** for ~120 common syscalls; NARF-only above `0x4000` |
| Build / link | Per-object compile, no whole-kernel LTO by default | Per-object compile | **Global LTO** across the whole kernel — cross-subsystem calls inline |
| Test surface | kselftest, KUnit, LTP (out-of-tree mostly) | ATF / Kyua | **In-tree QEMU-resident** smokes; every commit runs both arches |
| Architectures (primary) | x86_64, aarch64, many more | x86_64, aarch64, others | **x86_64 + aarch64 co-equal** from day one |
| Stable kernel ABI | "We do not break userspace" — strong de-facto, no version stamp | Stable across a major branch | **Versioned**: syscall number carries an 8-bit ABI version, surfaced to libc |
| TCB size | Multi-million LoC; every driver is in the TCB | ~Million LoC; every driver is in the TCB | **Frame** is small; drivers are *not* in the TCB even though they share the address space |

## Where NARF goes further than KSPP / lockdown

Linux ships ~40 kernel-hardening flags across `Documentation/admin-guide/kernel-parameters.txt`,
each gated by config and runtime sysctl. NARF makes the equivalent guarantees
**structural** instead of policy-driven.

| Linux KSPP / hardening | Cost on Linux | NARF equivalent | Cost on NARF |
| --- | --- | --- | --- |
| `copy_to_user` / `copy_from_user` discipline; forgetting it is a silent vuln on non-SMAP CPUs | runtime check per call | `with_user_access(|| ...)` bracket; forgetting it is a **type error** — user pointers are `unsafe`-deref + cap-gated | same HW cost (STAC..CLAC); compile-time guarantee |
| RWX mappings allowed; W^X enforced by SELinux/AppArmor policy | runtime check + policy lookup | W^X **absolute at `mmap`**; RW→RX requires a named revocable `CAP_JIT` | type-level rejection; no per-syscall page walk |
| `%pK` pointer redaction is a sysctl (`kptr_restrict`); audit varies by distro | runtime | `redact_pointer` is **cap-gated** by default; `Cap<KernelDebug>` reveals | one cap check |
| KPTI on by default on Intel parts (paid fleet-wide) | 5–30% syscall tax | **Skipped on AMD silicon** + on Intel parts with `IA32_ARCH_CAPABILITIES.RDCL_NO`; gated per-CPU at boot | zero on immune parts |
| LSM hooks for permission checks (each driver wires in a hook) | runtime cred-chain walk | `Cap<T, Right>` presence; **O(1)** stack-local move | constant time |
| KCFI / IBT (Clang CFI) | per indirect call cost | Intel CET shadow stacks + IBT, ARM PAC for forward + backward edge | HW-enforced, near-free |
| Refcount overflow saturate (Linux's `refcount_t`) | runtime saturate-check | Rust's `Arc<T>` uses **checked** refcount + panics on overflow | language-level guarantee |
| `__read_only` post-init scan | linker-section policy | `ro_after_init.rs` + `RoCell<T>` latch; pages re-mapped RO at `mark_init_complete()` | same |
| Hardened usercopy (`HARDENED_USERCOPY`) | per-copy slab boundary check | `with_user_access` + cap-gated user ptr | structural |

## Performance posture vs Linux

On equivalent silicon:

| Workload | Linux | NARF | Why |
| --- | --- | --- | --- |
| Syscall throughput on AMD Zen+ | KPTI tax (~10–30% on syscall-heavy) | No KPTI tax | NARF gates KPTI per-vendor; AMD parts don't have Meltdown, so no PTI |
| Driver↔driver call | Function call (no isolation) | One MSR write (PKS) or one CR3 (PCID) | Same call-graph, hardware boundary |
| Driver→userspace data path | `copy_to_user` per byte | Narf-Ring ownership transfer (zero copy) | Move semantics; no memcpy |
| TLB pressure across domain crossings | N/A — no isolation | None on PKS/MTE; PCID-preserve flag on CR3 keeps hot PCIDs warm | Single MSR; INVPCID rarely needed |
| Capability check on common call | `current->cred` chain walk | `Cap<T>` move; epoch compare | Stack-local; O(1) |
| Refcount cost | Atomic add (`refcount_inc`) | Atomic add (`Arc::clone`) | Equal |
| Async task switch | `schedule()` + cred swap | Direct context transfer when synchronous; future-park otherwise | NARF's executor *is* the scheduler |

On Intel SPR-class silicon, the framekernel premise is fully realized:
PKS gives per-PTE 4-bit PK selectors with single-MSR domain crossing.
On AMD, the PCID backend is wired end-to-end but the cost-per-crossing
is higher (one `MOV CR3` rather than one `WRMSR`). On aarch64 with MTE,
crossings are SR writes at MSR-class cost.

## Where NARF is behind

The honest comparison list — areas where Linux or the BSDs are
materially ahead, and NARF is closing the gap or has explicitly chosen
not to:

- **Driver coverage**: Linux supports tens of thousands of devices.
  NARF supports the ones we've written or ported. The wave-by-wave
  status in [`STATUS.md`](./STATUS.md) is up-to-date.
- **Filesystem coverage**: ext2 (file-data write), exfat (bitmap +
  cluster write), 9p, minix, iso9660/udf/SquashFS (RO), and read-write btrfs on
  one device with SINGLE/DUP chunks, compression, alternate checksums,
  subvolumes, and snapshots. Missing: ext4 with journal, multi-device/RAID
  btrfs, xfs, zfs, NFS, and SMB; FUSE is available as the userspace escape
  hatch. See the [Btrfs capability matrix](./drivers/fs/btrfs/README.md) for
  precise on-disk and mutation limits.
- **Networking depth**: NARF's kernel ships the frame-ring contract and
  per-NIC drivers. The TCP/IP stack lives in userspace (deliberate
  design choice — frees the kernel from socket buffer copies). Linux's
  in-kernel TCP/IP has a 30-year head start on tuning.
- **Stable APIs for userspace drivers**: Linux's `/sys`, `/proc`,
  `netlink`, and the various character-device conventions are deeply
  established. NARF's kernel surface is small and Linux-ABI-compatible
  at the syscall level but doesn't try to mirror procfs/sysfs.
- **Out-of-tree module support**: Linux has decades of out-of-tree
  driver convention (DKMS, signed modules). NARF has no out-of-tree
  driver model — all drivers are in tree and pass `cargo xtask test`.
- **Distro packaging**: NARF has none. You build it from source today.

## Where NARF and Linux are roughly equivalent

- **Hardware feature use**: NUMA, IOMMU (AMD-Vi + Intel VT-d), CET,
  PAC, MTE, PMU, microcode loading.
- **Async I/O ergonomics**: Linux has `io_uring`; NARF's IPC is
  `Narf-Ring` which is *conceptually* `io_uring` with capability
  typing baked in.
- **Crypto primitives**: AES, SHA-1/256/384/512, HMAC, PBKDF2-SHA1,
  AES Key Wrap (RFC 3394), CMAC-AES128. Both have clean test-vector
  coverage. NARF's are clean-room implementations or adaptations
  under GPL-2.0-or-later.

## When NOT to use NARF

- You need a driver Linux supports that NARF hasn't ported yet.
- You need long-term ABI promises that exceed what NARF has signed up
  to (we version syscall numbers but we don't promise binary
  compatibility across release branches the way Linus does).
- You need third-party closed-source drivers — NARF has no concept
  of a binary blob driver. Firmware blobs are fine; driver binaries
  are not.
- You need a fully POSIX-conformant userspace today. NARF's libc
  surface is functional but not exhaustive — variadic printf,
  `dlopen`, full pthread mutex/cond semantics are still maturing.
