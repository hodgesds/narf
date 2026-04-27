# NARF — Current Status

Snapshot of what's implemented vs. what `STAGE1.md` / `ROADMAP.md` still
asks for. Updated when observable kernel behaviour changes.

## Stage progression

| stage | theme                                     | status |
|-------|-------------------------------------------|--------|
| 1. Skeleton      | Bootloader + async executor + console | **closed** — all 6 exit-gate items met |
| 2. Barrier       | PKS/MTE domain switching + UIPI        | **closed** — both arches boot; higher-half, MTE, GICv3 all landed |
| 3. Flow          | Narf-Ring + capabilities + first VirtIO | **composition complete; enforcement deferred to Stage 4** — caps/epoch, ipc SPSC, drivers framework, io DMA, rcu, tracing, abi, virtio-mmio skeleton all landed; `smoke_exit_gate_*` pass both arches, proving DmaBuffer → Narf-Ring → cap-gated consumer composes end-to-end. Real PKS/MTE enforcement on buffer pages, real virtio device I/O, real IOMMU, real user-mode consumer: Stage 4 items. |
| 4. Compatibility | relibc integration; run standard Rust bins | **structural surfaces landed; exit-gate blocked on host toolchain work** — see §"Stage 4 structural landing" below |

## Working today (both arches on QEMU)

- `cargo xtask run --arch=x86_64` boots, runs the full async demo,
  delivers hardware LAPIC-timer IRQs, exits cleanly.
- `cargo xtask run --arch=aarch64` boots, runs the full async demo
  using CNTPCT_EL0 as the clock, exits via ARM semihosting.
- `cargo xtask test --arch=x86_64` passes **20/20** kernel tests.
- `cargo xtask test --arch=aarch64` passes **11/11** kernel tests
  (10 arch-neutral + `smoke_aarch64_features` for the ID-register
  probe; x86_64-specific tests correctly cfg-out).

Representative x86_64 boot transcript:

```
$ cargo xtask run --arch=x86_64
NARF Stage 1 Wave 1 — hello from a bare kernel.
  arch: x86_64 | backend: Pks
  idt: loaded — 32 CPU-exception vectors routed
  features: nx=true tsc_inv=false pku=true pks=true uipi=false rdseed=true rdrand=true
  pks: enabled (CR4.PKS=1, IA32_PKRS=0 / all-allow)
  domains: 16 declared (Stage 1 all PKS/MTE-off, rights = all-allow)
  boot info: 9 memory region(s), uart_phys=PhysAddr(0x00000000000003f8)
  usable RAM: 255 MiB
  frames: total 65406 / free 65094 / reserved 312 (254 MiB usable)
  mmu: handoff...
  mmu: installed, PML4 @ PhysAddr(0x000000000ffde000), console remapped
  scheduler: ready queue initialised
  scheduler: spawning 1 task, running to completion
  tick 0: elapsed 100 Mcycles
  tick 1: elapsed 200 Mcycles
  ...
  halting — Stage 1 exit-gate demo complete.
```

```
$ cargo xtask test --arch=x86_64
...
── kernel_test harness ──────────────────────────
  [ OK ] smoke_domain_switch            ← enter_domain scope enforcement
  [ OK ] smoke_nx_enforces_no_exec      ← NX enforces NO_EXEC
  [ OK ] smoke_timer_irq_fires          ← hardware LAPIC-timer IRQ
  [ OK ] smoke_pks_enforces_deny_all    ← live PKS #PF/PK demo
  [ OK ] smoke_probe_catches_page_fault ← recoverable trap
  [ OK ] smoke_pks_set_get_rights
  [ OK ] smoke_pkrs_roundtrip
  [ OK ] smoke_map_preserves_pk_field
  [ OK ] smoke_pte_pk_field
  [ OK ] smoke_paging_map_translate_unmap
  [ OK ] smoke_frame_alloc_roundtrip
  [ OK ] smoke_scheduler_drives_future
  [ OK ] smoke_sleep_future_waits
  [ OK ] smoke_monotonic_advances
  [ OK ] smoke_box_roundtrip
  [ OK ] smoke_spin_lock_cycle
  [ OK ] smoke_bitmap_first_set
  [ OK ] smoke_arch_backend
  [ OK ] smoke_typed_id_sanity
── summary: 17 pass, 0 fail, 0 skip ──
```

## Crates that exist

| crate               | role                                                     |
| ------------------- | -------------------------------------------------------- |
| `narf-lib`          | Typed IDs, SpinLock, OnceLock, Bitmap, IntrusiveList.    |
| `narf-arch`         | HAL: halt, interrupts, io_port, msr/cr, cpuid, pks.      |
| `narf-memory`       | PhysAddr/VirtAddr, bump heap, PhysFrame allocator, paging API, MMU bring-up. |
| `narf-boot`         | RawBootInfo, PVH / FDT memory-map parse.                 |
| `narf-console`      | 16550A / PL011 + `remap_to_virtual` handoff plumbing.    |
| `narf-time`         | Instant from TSC/CNTPCT + `SleepUntil` Future.           |
| `narf-scheduler`    | Cooperative executor: spawn, yield_now, run_until_empty. |
| `narf-verification` | `#[kernel_test]` collector + runtime + 14 built-in tests.|
| `narf-frame`        | Bin: `_start`, long-mode transition, IDT/GDT/TSS, demo.  |
| `xtask`             | `cargo xtask {build,run,test,image}` per arch.           |

## Stage 1 exit-gate status (closed)

| # | requirement                                                    | state |
|---|----------------------------------------------------------------|-------|
| 1 | boot through `boot::_start` → `frame::init_bsp`                | ✓     |
| 2 | print `mmu: handoff...` via `remap_to_virtual`                 | ✓     |
| 3 | Future-on-executor prints per tick, exits cleanly              | ✓     |
| 4 | `verification/` smoke test produces Pass exit                  | ✓     |
| 5 | boot-time domain enumeration                                   | ✓     |
| 6 | no unsafe block outside `arch/` touches privileged MSRs        | ~ design-enforced; Clippy / post-link scan TBD |

## Stage 2 Barrier — what exists

- **CPUID feature probe** (`arch/x86_64/cpuid.rs`): NX, PKU, PKS, UIPI,
  invariant-TSC, RDSEED, RDRAND, x2APIC, APIC detected at boot and
  reported.
- **x2APIC enable** (`narf-interrupts` crate, `apic::init_bsp`):
  IA32_APIC_BASE set with EN + EXTD; SIVR programmed; both legacy
  8259 PICs masked (via I/O ports 0x21 + 0xA1 writing 0xFF);
  LVT timer masked by default; `start_timer` / `stop_timer` for
  periodic-mode configuration; `self_ipi` helper.
- **IRQ-vector IDT entries** (`frame/x86_64`): stubs + IDT installs
  for vectors 32..=47 and 255 (spurious). `rust_trap_handler`
  dispatches IRQ vectors (>= 32) separately from exceptions,
  calling the appropriate subsystem handler and EOI-ing the LAPIC.
- **Hardware timer IRQs live**: LAPIC timer fires vector 32 at the
  configured cadence; `on_timer_tick` increments a counter visible
  via `narf_interrupts::x86_64::apic::timer_ticks()`. Default
  boot runs with IRQs unmasked for the duration of the async demo;
  typical observed tick counts: 15 during a 5-tick demo.
  Regression-guarded by `smoke_timer_irq_fires` kernel test.
- **IRQ-driven scheduler**: `scheduler::run_until_empty` polls every
  ready task once per round; if no task became `Ready` in the round,
  it calls `arch::halt_until_irq` (HLT on x86_64 when IF=1, WFI on
  aarch64, `spin_loop` fallback when IRQs are masked). The LAPIC
  timer IRQ wakes the CPU, a new round runs, progress repeats. On
  the 5-tick demo: 15 timer IRQs delivered vs. the previous busy-
  poll's ~0 IRQs while spinning `Instant::now`.
- **NX enable**: `IA32_EFER.NXE = 1` at boot (gated on CPUID.NX) so
  PTE bit 63 (`PtFlags::NO_EXEC`) actually prevents instruction
  fetch. Regression-guarded by `smoke_nx_enforces_no_exec`: maps a
  page `WRITABLE | NO_EXEC`, jumps to it, catches the `#PF` with
  error-code bit 4 (instruction-fetch) set.
- **Domain switch API**: `arch::x86_64::pks::enter_domain(kernel,
  driver)` + matching `exit_domain` — single-PKRS-write that denies
  every PK domain except the two named. Regression-guarded by
  `smoke_domain_switch`: maps a PK=DRIVER_0 page, verifies
  `enter_domain(FRAME, DRIVER_0)` allows access, then
  `enter_domain(FRAME, DRIVER_1)` denies it (PK-violation #PF).
  This is the Stage-2 canonical "entering driver scope" primitive
  that Stage-3 driver dispatch will call.
- **`DomainPrimitive` trait**: the shape spec'd in `arch/` §3 now
  exists as an actual trait. `narf_arch::x86_64::Pks` impls it
  (forwards to `pks::*`); `narf_arch::aarch64::Mte` is a stub with
  the same signatures (bodies `unimplemented!`). `narf_arch::Domain`
  type alias resolves to the current-arch concrete type so
  arch-agnostic consumers write `Domain::save()` / `Domain::enter_domain(...)`.
- **MSR / CR helpers** (`arch/x86_64/msr.rs`, `.../cr.rs`): `rdmsr`,
  `wrmsr`, `read_cr4`, `write_cr4`, with the compiler_fence(SeqCst)
  pair per `arch/` §4.
- **CR4.PKS + PKRS live**: frame/'s boot path flips the bit when CPUID
  says PKS is available and initialises IA32_PKRS to 0 (all-allow).
- **Domain primitive** (`arch/x86_64/pks.rs`): `save` / `restore` /
  `get_rights` / `set_rights` — matches the shape of `arch/` spec §3's
  `DomainPrimitive` trait without formally declaring the trait yet
  (comes when aarch64 MTE lands the symmetric counterpart).
- **PTE PK field** (`memory/paging.rs`): `PtFlags::pk(domain)` /
  `pk_of()`; `map_4kb` tags a page with any of 16 PK domains.
- **4 KiB page-table walk API**: `map_4kb` / `unmap_4kb` / `translate` /
  `flags_at` / `read_cr3` operating on an arbitrary PML4 — including
  the live one.
- **Recoverable trap handler** (`frame/x86_64/trap.rs` +
  `arch/x86_64/probe.rs`): Linux-style exception-table pattern. Arm
  a probe with a recovery RIP; CPU exceptions redirect there via
  `iretq` instead of panic-exiting. Captures vector + error code.
- **Live PKS enforcement, verified**: `smoke_pks_enforces_deny_all`
  kernel test maps a page with PK=9, sets IA32_PKRS domain 9 to
  DENY_ALL, writes → `#PF` with error-code bit 5 (PK violation) set,
  handler catches, test checks both vector and error-code bit. The
  full PTE-PK → PKRS-rights → hardware-check → #PF → recovery loop
  is exercised every run.

## Stage 2 Barrier — status

**Substantively complete. All core items landed, both arches green.**

- ~~Higher-half kernel~~ ✓ done. Linker scripts place
  `.text`/`.rodata`/`.data`/`.bss` at high virt
  (`0xFFFFFFFF_80000000` on x86_64, `0xFFFFFF80_00000000` on aarch64)
  with `AT()` phys LMA. `.boot` / `.boot.data` stay at low phys for
  the pre-MMU bootstrap. Both arches boot with kernel RIPs at
  high-half.
- ~~aarch64 MTE mirror~~ ✓ done. `arch::aarch64::mte::Mte` impls
  `DomainPrimitive` with live `save` / `restore` on `SCTLR_EL1`.
  `smoke_domain_primitive_trait` exercises the save/restore round-
  trip on aarch64 through the trait. GCR_EL1 access (MTE L2) deferred
  to Stage 3 when QEMU `-machine virt,mte=on` + tag storage lands;
  `enter_domain` is currently a structural save-only (actual
  `SCTLR_EL1.TCF = Sync` flip needs tag storage coherent first,
  else every subsequent access tag-faults).
- ~~GICv3 skeleton on aarch64~~ ✓ done. `init_bsp` programs the
  CPU interface (system registers) + distributor (MMIO 0x0800_0000)
  + redistributor (MMIO 0x080A_0000), enables the generic-timer
  PPI (INTID 30). Default boot delivers ~100 timer IRQs during
  the 5-tick demo; `smoke_aarch64_features` guards the probe.

Remaining Stage 2 items (all additive / out of scope for local test):

- **UIPI** (Sapphire Rapids+ only). QEMU `-cpu max` doesn't expose
  UIPI on this host, so exercising it requires new hardware. The
  IDT / IRQ infrastructure is ready; the actual UIPI MSR programming
  would be <100 lines when there's a test target.
- ~~Proper per-task waker plumbing~~ ✓ done. Each `TaskSlot`
  owns an `Arc<AtomicBool>` awake flag; the `Waker` vtable
  flips it via `wake` / `wake_by_ref`. `run_until_empty`
  `swap(false)`s the flag before polling and skips slots whose
  flag is still `false` on the next round, so a future stashed
  behind an IRQ/IPC signal no longer costs a poll per loop.
  The halt-on-no-progress backstop is kept as the energy-save
  path for self-waking futures (today's `SleepUntil` /
  `yield_now`). Regression-guarded by
  `smoke_scheduler_respects_waker` (both arches).
- **Per-CPU probe state** — this is actually a Stage 3 SMP item
  (current single-CPU state is correct by construction for Stage 2).

## Stage 3 Flow — what exists

- **`capabilities/`**: 128-bit `CapSlot` (`repr(C, align(16))`,
  CMPXCHG16B / LDXP-STXP / CASPAL-sized), `Cap<T, R: Rights>` with
  hand-rolled `Copy`/`Clone`/`Send`/`Sync`, `Read`/`Write`/`Grant`
  + reflexive `SubsetOf<R>` compile-time narrowing, full `CapKind`
  wire registry (§3.1), `CapType` marker, `parse_kind`/`kind_name`.
  Live cap-table runtime: per-object `AtomicU32` epoch in an
  append-only `Vec<Entry>` under `IrqSafeSpinLock`; `check_live`
  compares stored generation to current epoch; `revoke(self)`
  `fetch_add(AcqRel)`s the epoch → O(1) mass invalidation across
  every clone / badged copy / derived narrowing; `invoke<O: CapOp>`
  gates on `check_live` then dispatches `op.execute(cap)`; safe
  `Cap::<T: CapType, R>::bootstrap()` allocates a fresh object
  entry and mints a cap with the right `CapKind` tag.
- **`ipc/`**: Narf-Ring SPSC. `Ring<T, N>` with cache-line-partitioned
  head/tail via `Align64<AtomicU64>`, `MaybeUninit<T>` slot ownership
  transfer (T moves through the ring; no byte-level copy), explicit
  release/acquire pair on every index transition (correct under
  aarch64's weaker ordering model), both-side waker slots
  (`SpinLock` producer-side + `IrqSafeSpinLock` consumer-side for
  driver-IRQ publish contexts), `closed` latch on drop, `Drop for
  Ring` drains undelivered slots. `CapType` → `CapKind::Ring`.
- **`abi/`**: wire shapes. `Submission { op, flags, caps: [CapSlot; 4],
  tag, inline: [u64; 6] }` sized 144 B / 16-aligned (`CapSlot`'s
  16-align forces an 8-byte mid pad + 8-byte tail pad — the naive
  128-byte arithmetic undercounts both), `Completion { tag, status,
  result: [u64; 6] }` at 64 B / 8-aligned, `OpCode` (`repr(u32)`,
  7 variants with pinned discriminants), `SubmissionFlags`
  (`repr(transparent)` u32 bit-set), `NarfStatus` (`repr(u32)`,
  8 pinned variants), `Tag(u64)` correlation newtype,
  `SubmissionQueue` / `CompletionQueue` type aliases over
  `narf-ipc` Producer/Consumer. Stage-3 round lands the §3.1
  cooperative cancellation protocol: `Dispatcher::pending` tracks
  cancel-pending tags; `OpCode::Cancel` reads `target_tag` from
  inline[0], records it, and always completes Ok; the target's
  completion is routed to `Cancelled` (when
  `SubmissionFlags::CANCELLABLE` is set) or `CancelRequested`
  (non-cancellable path) on drain. Mid-op cancellation via
  per-inflight flags remains Stage 4 (needs concurrent dispatch).
- **`drivers/`**: framework. `Driver` trait (async `start`/`quiesce`
  via `Pin<Box<dyn Future>>` so the registry holds heterogeneous
  drivers), `DriverHandle` cap marker → `CapKind::Driver`,
  `DriverManifest` (typed `&[CapKind]`, compile-checked — a manifest
  naming an unknown cap is a build error), `DomainPolicy::{Shared,
  Dedicated}` with §4.1 6-driver-dedicated-domain cap, `DriverEnv`
  handed to `start`, `DriverRegistry` + global `registry()` with
  cap-gated `register()` (Wave-3a fix landed: count+push in one
  critical section), `DriverPhase` state machine providing shared
  exclusivity for both `start_named` and `quiesce_named` (Wave-3a
  aliasing-UB fix), `with_entry` observer accessor, `NoopDriver`
  reference impl, `bootstrap_authority()`.
- **`drivers/virtio/`**: virtio-mmio skeleton. Register constants
  per spec §4.2.2, `VirtioMmioDevice::probe` / `probe_raw`
  validating magic / version / device-id / vendor-id with
  `compiler_fence(SeqCst)` pair per `arch/` §4, `ProbeError`,
  `VirtioSkeletonDriver` implementing the `Driver` trait. Feature
  negotiation, virtqueue ring, doorbells, IRQ binding, subdrivers:
  Stage 4.
- **`io/`**: DMA buffer + IOMMU stub. `DmaBuffer` (backed by a
  single `PhysFrame`, `CapType` → `CapKind::DmaBuffer`, `phys_addr`
  / `len` / `domain` / `coherency` getters), `alloc_coherent` /
  `free_coherent` (page-aligned), `IommuContext` with `map` /
  `unmap` as QEMU-compatible no-ops, `IoError` enum, `p2p_map`
  signature-only placeholder. Multi-frame contig, real VT-d/AMD-Vi/
  SMMUv3, P2P, aarch64 `DC CIVAC`: Stage 4.
- **`rcu/`**: real QSBR (per-CPU reader counters + global epoch +
  per-CPU deferred-drop buckets with `u64::MAX` offline-CPU
  sentinel), Epoch variant (`pin`/`unpin`/`advance`/`min_pinned`),
  Hazard + Sleepable shape-only stubs, `Owned<T>` /
  `Shared<'g, T>` / `Atomic<T>` public surface. `scheduler/`
  calls `narf_rcu::report_quiescent()` after every `Future::poll`
  return per rcu/ §3.7 — every cooperative yield advances the
  grace period.
- **`tracing/`**: static markers + flight recorder + dynamic probes +
  live aggregates. `probe!` macro emits a nop-sled + `.note.narf.probes`
  ELF-note record (KEEP'd on both arches, bounded by
  `__narf_probes_start`/`_end`), `FlightRing<T, N>` with per-slot
  seqlock publish protocol (odd=in-flight, even=published),
  const-asserted non-zero power-of-two `N`. Stage-3 round 5 lands:
  `dispatch::fire(probe_id, args)` with a cap-gated
  `ProbeHandlerInstall` registry (linear-scan, up to 256 handlers),
  `FnTime` scope accumulator with Welford online mean/variance, and a
  log2-bucket `Histogram` stub standing in for the Stage-4 tDigest.
  Real tDigest accuracy contract + per-CPU hazard-pointer handler
  table: Stage 4.
- **`bus/`**: enumeration + BAR sizing + LAPIC-directed MSI-X
  programming. PCIe ECAM walker on x86_64 (q35 default `0xb000_0000`,
  MCFG deferred), FDT bus walker on aarch64 with a QEMU-virt fallback
  layout, `BusDevice` / `BusKind::{Pcie, VirtioMmio}` / `DeviceId`,
  read-only registry, `claim_device` stub. `bus::init` is now wired
  into `frame::_start_rust` after MMU bring-up (x86_64 walks q35 ECAM,
  aarch64 falls back to the virtio-mmio probe). `bus::bar` adds
  `read_bar` (size detection via the standard write-all-1s / read-back
  / restore cycle, decoding 32-bit MMIO / 64-bit MMIO / I/O BARs) and
  `map_bar` returning an `MmioRegion` with volatile `read32`/`write32`.
  `MsixTable::program_vector` writes the four-u32 MSI-X table entry
  (msg_addr_lo = `0xFEE0_0000 | (apic_id<<12)`, msg_addr_hi = 0,
  msg_data = vector, vector_control = 0); `MsixTable::enable` flips
  the Message-Control "MSI-X enable" bit. aarch64 `program_vector`
  returns `Unsupported` until the GIC ITS doorbell path lands.
  Hot-plug, IOMMU-group coordination, real MCFG parsing: still later
  waves.
- **`scheduler/`**: per-task waker plumbing (Wave-0 + Stage-2 close)
  plus Stage-3 §3.3/§3.4 task-spec surface. Each `TaskSlot` owns an
  `Arc<AtomicBool>` awake flag; `Waker` vtable flips it via
  `wake`/`wake_by_ref`. `run_until_empty` `swap(false)`s before polling
  and skips slots whose flag is still false, so IRQ/IPC-driven futures
  no longer cost a poll per loop iteration. `narf_rcu::report_quiescent()`
  invoked after each poll. Stage-3 round adds `TaskSpec` (affinity +
  budget + optional `Cap<CpuBudget, Spend>`), `spawn_with_spec` /
  `spawn_budgeted` entry points, `BudgetAccount` running totals
  (cycles_spent / polls / overruns), `ResourceBudget` + `OverrunPolicy`
  + `Affinity` + `CpuSet` types. Every poll `check_live`-gates the
  attached budget cap — revoking stops the task O(1) on the next round
  — and charges measured `narf_time::Instant` cycles into the account.
  Direct context transfer, work stealing, multi-CPU: Stage 4.
- **`observability/`**: Stage-3 round wires PMU sampling through the
  tracing transport. `sample_pmu(cap, ring)` reads cycles (+
  instructions when available) and records an
  `ObservabilityEvent::Pmu` into a `FlightRing`; `PmuProbeHandler`
  bridges `tracing::ProbeHandler::fire` to a sample, so registering
  one handler on a probe id samples the PMU on every fire.
  `capture_core_dump(regs)` bundles `CrashFrame` + `take_snapshot()`
  into the single struct a panic path emits. Stage-4 items unchanged
  (real arch PMU primitives, multiplexed counter groups).
- **`capabilities/`**: Stage-3 round adds the `Spend` rights marker
  (reflexive under `Grant`, orthogonal to Read/Write) so cap types
  that represent consumable quotas (`CpuBudget`, future `DmaAllowance`)
  can be distinguished from policy-mutation rights at the type level.

### Stage 3 exit-gate integration

`smoke_exit_gate_buffer_handoff` + `smoke_exit_gate_revoked_cap_rejected`
(both arches) compose the spec's Stage-3 criterion: task-1 `alloc_coherent`
→ writes a 17-byte pattern to the buffer's phys address → mints
`Cap::<DmaBuffer, Read>::bootstrap()` → sends `(DmaBuffer, Cap)` through
an `ipc/` channel; task-2 `recv().await` → `cap.check_live()` gate →
volatile-reads the pattern → asserts match. Ownership moves by handle
(no memcpy of the payload). The revoked-cap variant confirms O(1) mass
invalidation on the fast path.

What Stage 4 adds that Stage 3 elides (tracked as follow-ups in each
subsystem's README): real PKS/MTE enforcement on buffer pages, driving
real virtio silicon (feature negotiation, virtqueue rings, doorbells,
IRQ binding, subdrivers), real IOMMU programming, user-mode consumer
via `abi/` submission surface (makes "no Ring-0 trap on the fast path"
literal instead of trivial-in-kernel-AS), `BootstrapRequest` / Reply
slow path in `frame/`, cooperative-cancel state machine in `abi/`.

## Stage 2 design debt (not blocking, worth tracking)

- **Higher-half migration**. Linker script lives at phys 0x100000,
  code-model=small. Every Stage-2+ convention expects -2 GiB kernel.
- **Full buddy allocator**. `memory::frame` is free-stack / 4 KiB only.
  Buddy + `Folio { order, head }` land when 2 MiB / 1 GiB mapping
  gets consumers.
- **Slab heap**. Retires the 1 MiB bump arena. Currently the bump arena
  is ~50% consumed by the frame allocator's free-stack Vec.
- **`frame/` trap-prologue PKRS save**. Scaffolding only. Once the
  scheduler's context-switch save/restore needs it (Stage 3 direct
  context transfer), wire the PKRS save into the trap prologue.

## Deviations from the v0.2 design (in-code comments flag each)

1. **PVH instead of Limine** on x86_64. `boot/` spec §5 pins Limine
   as sole Stage-1 x86_64 bootloader; we use Xen-PVH because it's
   the only ELF64 direct-kernel path `qemu-system-x86_64 -kernel`
   supports. `boot/src/x86_64/multiboot2.rs` is still named
   multiboot2 for future compat, but its contents parse
   `hvm_start_info`.
2. **Low-half linking**. Kernel links at phys 0x100000 today.
3. **Bump heap** under `#[global_allocator]` — not the buddy+slab.
4. **aarch64 FDT walker is a stub** — synthesises a 128-MiB region
   from QEMU-virt defaults.
5. **Formal `DomainPrimitive` trait not declared yet** — the
   `arch::x86_64::pks` module has the shape (save/restore/get/set),
   but the trait itself waits for aarch64 MTE to provide the second
   implementation needed to justify the abstraction.

## How to run

```bash
# Default flavour: async executor demo, 5 ticks, clean exit.
cargo xtask run  --arch=x86_64

# Kernel-test harness: 14 tests, isa-debug-exit signals pass/fail.
cargo xtask test --arch=x86_64

# IDT self-test: deliberately trigger #UD; print trap frame; exit 42.
cargo xtask run  --arch=x86_64 --features=idt-selftest

# Cross-compile for aarch64 (qemu-system-aarch64 not installed locally).
cargo xtask build --arch=aarch64 --package=narf-frame

# Host-side unit tests on narf-lib.
cargo test -p narf-lib
```

## Commit log (high-level)

| commit        | landed                                                       |
|---------------|--------------------------------------------------------------|
| Baseline      | 217-file NARF v0.2 design tree                               |
| Wave 0        | Cargo workspace + nightly + build-std + narf-lib primitives  |
| Wave 1        | arch/ + console/ + boot/ + frame/ ⇒ bootable x86_64          |
| Wave 2a       | IDT + trap dispatch (ud2 self-test verified)                 |
| Wave 3        | time/ + scheduler/ + async executor + timer-driven demo      |
| domains+verif | 16-domain enumeration + verification/ harness + 4 tests      |
| more tests    | 4 additional smoke tests covering scheduler/time/alloc       |
| Wave 2 GDT    | GDT + TSS + 4 IST stacks (NMI/#DF/#MC/#VC)                   |
| Wave 2b       | PhysFrame + free-stack frame allocator                       |
| Wave 2c       | MMU handoff — own PML4, CR3 swap, console::remap_to_virtual  |
| Stage 2 paging| `map_4kb` / `unmap_4kb` / `translate` + kernel test          |
| Stage 2 PKS   | CR4.PKS enable, CPUID probe, `arch::x86_64::pks` module      |
| Stage 2 PK    | PTE PK field, `DomainPrimitive`-shaped save/restore/get/set  |
| probe         | Recoverable trap handler + arm/disarm exception-table probe  |
| PKS live      | `smoke_pks_enforces_deny_all` — end-to-end #PF/PK demo      |
| APIC partial  | `narf-interrupts` + IRQ IDT entries; soft INT 32 works      |
| APIC full     | 8259 PICs masked; hardware LAPIC timer IRQs live + tested   |
| IRQ sched     | run_until_empty halts between no-progress rounds            |
| NX enable     | IA32_EFER.NXE + NO_EXEC enforcement test                    |
| Domain switch | enter_domain/exit_domain API + cross-domain denial test     |
| Domain trait  | DomainPrimitive trait; Pks impl live, Mte stub for aarch64  |
| aarch64 boot  | `virt` machine boots; full async demo runs on aarch64 too   |
| per-task waker| `Arc<AtomicBool>` waker vtable — Pending tasks skip repoll |

## Pickup hint for the next session

The critical-path Stage-2 items remaining:

1. **Interrupt controller bring-up** (`interrupts/`). ✓ landed —
   x2APIC init + LAPIC-timer periodic IRQ + IRQ-vector IDT entries +
   `rust_trap_handler` IRQ dispatch all wired into boot;
   `smoke_timer_irq_fires` proves end-to-end delivery. The follow-up
   "real waker driving the scheduler" remains a Stage-3 polish item;
   today the timer just bumps a counter.

   Adjacent driver-readiness work also closed in this round:
   `bus::init` wired into boot, BAR sizing + MMIO mapping
   (`bus::bar::{read_bar, map_bar, MmioRegion}`), and LAPIC-directed
   MSI-X programming (`MsixTable::{program_vector, enable}`) on
   x86_64. aarch64 `program_vector` returns `Unsupported` until the
   GIC ITS doorbell path lands.

   NVMe admin-queue bring-up landed on top: `Controller::bring_up`
   maps BAR0, decodes CAP/VS, resets the controller, allocates the
   ASQ + ACQ via `narf_io::alloc_coherent`, programs `AQA/ASQ/ACQ`,
   re-enables `CC.EN`, polls `CSTS.RDY=1`, and issues IDENTIFY
   CONTROLLER (CNS=1) — completion is observed via the CQE phase-tag
   flip and acknowledged by ringing the head doorbell. xtask
   attaches a QEMU `nvme,drive=nvm0,serial=narf` device on x86_64
   backed by `target/narf-nvme.img`. End-to-end guarded by
   `smoke_nvme_admin_identify_controller`, which asserts the
   IDENTIFY response carries QEMU's vendor id (0x1B36) and model
   prefix (`"QEMU"`).

   IRQ-driven driver readiness: `narf_interrupts` now exposes a
   generic dispatch table (`on_irq(vector)` + per-vector fire counts
   + waker bridge), an IDT-vector bitmap allocator
   (`vector::alloc/free`), and a `wait_for_irq(vector).await` future
   that bridges IRQ delivery to the async executor. Both arch trap
   paths route vectors ≥ 32 (x86_64) / non-timer SPIs+LPIs (aarch64)
   through `narf_interrupts::on_irq`. `MsixTable::program_vector`
   is now arch-symmetric: x86_64 emits `0xFEE0_0000 | (apic_id<<12)`
   + IDT vector; aarch64 emits the GIC ITS doorbell PA
   (`GITS_TRANSLATER` = 0x0809_0040 on QEMU virt) + EventID. ITS
   bring-up runs at boot under aarch64 — allocates device /
   collection / command-queue tables, programs `GITS_BASER`,
   `GITS_CBASER`, `GICR_PROPBASER`, `GICR_PENDBASER`, enables LPIs,
   submits MAPC for collection 0 → CPU 0. `its::map_event(device,
   event, lpi, collection)` issues MAPD + MAPTI. Smokes:
   `smoke_irq_dispatch_fire_count`, `smoke_vector_alloc_unique`,
   `smoke_wait_for_irq_resolves_after_on_irq`, `smoke_its_doorbell_addr`.

   NVMe end-to-end I/O is now real on x86_64: `Controller::create_io_queue`
   issues Create I/O CQ + Create I/O SQ admin commands and `read_lba`
   / `write_lba` submit NVM Read/Write through the I/O queue, polled.
   `smoke_nvme_io_round_trip` writes a 512-byte pattern at LBA 0 and
   reads it back. IDENTIFY NAMESPACE is also issued during bring_up
   so `Controller::lba_bytes` and `Controller::nsze` are real.

   IRQ-driven NVMe is also live on x86_64: `create_io_queue_msix`
   walks the MSI-X cap, allocates an IDT vector via
   `narf_interrupts::vector::alloc`, programs MSI-X table entry 0
   to deliver that vector to APIC 0, flips the global enable, then
   re-issues Create I/O CQ with `IV=0, IEN=1`. `submit_io_irq`
   spins on `narf_interrupts::fire_count(vector)` (the same atomic
   `wait_for_irq.await` consumes), confirming MSI delivery actually
   reaches the dispatch table. The full IDT now installs vectors
   32..=254 (not just 32..=47) so the allocator pool 48..=240 is
   guaranteed to land on a present gate. End-to-end guarded by
   `smoke_nvme_io_msix_irq_driven`, which verifies the round-trip
   pattern *and* asserts the dispatch table observed at least one
   MSI during the I/O.

   PCIe ECAM walker is now shared between arches via `bus::pcie`.
   x86_64 (q35, 256-bus ECAM) walks live; aarch64 (QEMU virt,
   16-bus ECAM) has the constants + the shared walker but no live
   walk yet — QEMU's host bridge aborts naked reads of
   `0x3F00_0000` until it's programmed via DTB-described init,
   and we don't parse the relevant DTB properties yet (`bus-range`,
   `reg`, `ranges`). That's the only remaining "real driver"
   blocker on aarch64; once it lands, every IRQ + DMA + BAR + MSI-X
   + ITS surface aarch64 already exposes connects to live PCIe.

2. **Higher-half kernel relocation**. Conventional -2 GiB layout.
   Touches the linker script, boot.S (far-jump-to-virtual after
   long-mode enable), and `.cargo/config.toml` (code-model back
   to `kernel`). The MMU handoff already owns its own PML4, so
   this is mostly adding high-half PML4/PDPT entries and a
   far-jump.

3. **NX enable**. `IA32_EFER.NXE = 1` so `PtFlags::NO_EXEC` is
   actually honoured. Small (~20 lines + a kernel test that maps
   a page NX and probes a jump-to-that-page).

4. **aarch64 MTE mirror**. SCTLR_EL1.TCF / tag storage /
   replace the `Mte` stub in `arch::aarch64::mte` with a live
   impl. Running end-to-end works now (qemu-system-aarch64 is
   available on the dev host), and `smoke_domain_primitive_trait`
   will exercise the new path once the stub becomes real.

5. **`DomainPrimitive` trait extraction**. Once 4 lands, pull the
   shared shape out of `arch::x86_64::pks` and `arch::aarch64::mte`
   into `arch::DomainPrimitive`.

6. **Per-CPU probe state** (`arch::probe`). Needed for Wave-3 SMP.
   Low-value until APs come up.

Parallel-safe micro-tasks:
- Replace free-stack frame allocator with a buddy.
- `rcu/` stub API so downstream crates don't retrofit.
- `tracing/` USDT marker macro — `.note.narf.probes` section exists.

## Stage 4 structural landing

This session landed a broad Stage-4 **structural** pass — every
subsystem listed in `ROADMAP.md` Stage 4 has its type surface,
cap-type markers, and enough stub bodies to compile, test, and
interop with the rest of the tree. The bodies that actually do
something on real hardware are not yet wired because they depend on
three host-toolchain / deep-arch pieces that were out of scope:

1. **`frame/` syscall entry** — a real `syscall` (x86_64) / `svc
   #0` (aarch64) trap handler that reads `SyscallArgs` off the
   register file, dispatches through a `SyscallTable`, and returns
   a `SyscallReturn`. Needs register save/restore in the trap
   prologue, not just the existing CPU-exception path.
2. **`memory/` per-process address spaces** — every user process
   needs its own PML4/TTBR0 so user-mode mappings don't collide
   with the kernel half. The loader (`userspace::ExecImage`) places
   `PT_LOAD` segments into that address space.
3. **External relibc build** — the Stage-4 exit gate requires a
   relibc compiled against NARF's syscall ABI
   (`narf_userspace::Syscall`). That is a separate repo / build
   artefact outside this tree.

Without those three, the spec's Stage-4 exit criterion ("relibc-
linked standard Rust binary doing block + network I/O through
capability-gated paths") is unreachable from this tree alone.

### Stage 4 structural surfaces landed (both arches green)

| subsystem             | what shipped                                              |
| --------------------- | --------------------------------------------------------- |
| `block::mq`           | `MqDeadlineScheduler` with N-lane round-robin + deadline promotion (`MAX_LANES = 64`). |
| `scheduler::priority` | `SchedClass { Normal, RealTime, Idle }`, `Priority(i8)`, `SmtSharePolicy`; `TaskSpec::realtime(deadline_cycles)`. |
| `scheduler::cpu_lifecycle` | Cap-gated `cpu_bring_up` / `cpu_take_offline` against `Cap<CpuLifecycle, Invoke>` with a 64-wide online bitmap; boot CPU protected. |
| `power::thermal`      | `ThermalZone` registry + `ThermalEvent` subscribers; Normal/Warm/Critical transitions fire exactly once. |
| `power::suspend`      | Nine-phase `SuspendPhase` pipeline + `suspend(cap)` that walks the phases and returns `NotImplemented` until `arch/` exposes S3 / PSCI. |
| `EnergyAware` governor | Three-band DVFS pick keyed off `load_permille`. |
| `time::wall`          | `WallInstant`, `set_wall_offset(cap, ns)`, `begin_leap_smear(cap, delta, window)`, `now_wall()` reader. |
| `observability::gdb`  | `GdbPacket` framing + checksum helper, `GdbCommand` enum covering the RSP subset, `attach(cap)` stub. |
| `observability::peek` | `Provider` trait + cap-gated `sample_all(cap, out)` registry for live-peek metrics. |
| `userspace`           | `ProcessId`, `ExecImage` with `Segment` + `SegmentFlags` matching ELF `PF_*`, `AuxEntry` with `AT_*` tags, `SyscallTable` pinning the canonical numbers (Submit=100, …, Munmap=121). |
| `drivers/nvme`        | BAR0 register offsets, `NvmeCaps::from_raw` bitfield decoder, `AdminOpcode` + `IoOpcode` tables, `Controller::probe(cap)` stub, `NvmeBlockDevice` impl of `BlockDevice`. |
| `drivers/net`         | `NicModel` enum (e1000/igb/ixgbe/mlx5/rtl8139) with `primary_pci_id()` lookup, `NicCaps` feature bitmap, `NicDescriptor`, `HwNic` trait. |
| `drivers/gpu`         | `GpuFamily` backend list, `Mode { width, height, refresh_hz, bpp }` with `FHD_60` / `XGA_60` presets, `SubmitKind` + `CommandBuffer` + `GpuFence`. |
| `crypto::tpm`         | TCG-spec `TpmCc` command codes (PcrExtend/Read/GetRandom/Startup/SelfTest/…), `TpmAlgHash` enum, `Tpm2Command` wrapper, `submit()` stub. |
| `crypto::pq`          | `MlKem768` / `MlDsa65` / `SphincsPlus` CapType markers, `HybridMode`, runtime `fips_mode()` + `fips_allowed(alg)` gate. |
| `net::stack`          | `StackAttach` / `StackAttachReply` protocol, `AdminCap` marker, `StackDaemon` identity cap, `attach()` stub. |
| `filesystem::page_cache` | `PageKey` + `Page { data: Arc<[u8; 4096]>, dirty, gen }` + `PageCache` with `lookup` / `insert` / `mark_dirty` / `drain_dirty`. |
| `filesystem::fuse`    | `FuseOpcode` values matching Linux UAPI verbatim, `FuseInHeader` / `FuseOutHeader` / `FuseInitIn` / `FuseInitOut` wire structs, `FUSE_KERNEL_VERSION = 7.36`. |
| `bus::acpi_notify`    | `NotifyKind` event table (BusCheck/DeviceCheck/Thermal/…), cap-gated subscriber registry, `dispatch_notify` fan-out. |
| `rcu::batched`        | `BatchedReclaimer` grouping callbacks into capped `ReclaimBatch` (BATCH_CAP = 128), `submit` / `flush`, `pace(node, quantum)` NUMA hint. |
| `tracing::hwtrace`    | `HwTraceConfig` shared between Intel PT + CoreSight ETM, `HwTraceStatus`, `HwTraceMarker` CapType, `start` / `stop` / `status` stubs. |

Test coverage for each of the above: a dedicated `smoke_*`
kernel_test in `verification/src/lib.rs` exercising either the
happy path, the cap-revoke fail-closed, or the structural
invariants. Totals after the Stage-4 round: **x86_64 134 pass,
aarch64 124 pass + 3 skip** (same three skips as Stage 3 —
arch-gated bus test, sleepable-RCU detail, virtio probe without
hardware).
