# NARF — Current Status

Snapshot of what's implemented vs. what `STAGE1.md` / `ROADMAP.md` still
asks for. Updated when observable kernel behaviour changes.

## Stage progression

| stage | theme                                     | status |
|-------|-------------------------------------------|--------|
| 1. Skeleton      | Bootloader + async executor + console | **closed** — all 6 exit-gate items met |
| 2. Barrier       | PKS/MTE domain switching + UIPI        | **closed** — both arches boot; higher-half, MTE, GICv3 all landed |
| 3. Flow          | Narf-Ring + capabilities + first VirtIO | **composition complete; enforcement deferred to Stage 4** — caps/epoch, ipc SPSC, drivers framework, io DMA, rcu, tracing, abi, virtio-mmio skeleton all landed; `smoke_exit_gate_*` pass both arches, proving DmaBuffer → Narf-Ring → cap-gated consumer composes end-to-end. Real PKS/MTE enforcement on buffer pages, real virtio device I/O, real IOMMU, real user-mode consumer: Stage 4 items. |
| 4. Compatibility | relibc integration; run standard Rust bins | not started |

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

1. **Interrupt controller bring-up** (`interrupts/`). x2APIC init,
   LAPIC timer → real IRQ handler driving the scheduler's waker.
   ~300 LoC. Unblocks UIPI (remaining Stage 2) and preemption
   (Stage 3). Today's scheduler busy-polls `Instant::now()`; with
   a timer IRQ we'd use real wakers instead.

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
