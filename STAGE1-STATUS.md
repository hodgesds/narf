# Stage 1 — Status

Snapshot of what's implemented vs. what `STAGE1.md` still asks for. Updated
when the kernel's observable behaviour changes.

## Working today (on x86_64 / QEMU)

```
$ cargo xtask run --arch=x86_64
NARF Stage 1 Wave 1 — hello from a bare kernel.
  arch: x86_64 | backend: Pks
  idt: loaded — 32 CPU-exception vectors routed
  domains: 16 declared (Stage 1 all PKS/MTE-off, rights = all-allow)
  boot info: 9 memory region(s), uart_phys=PhysAddr(0x00000000000003f8)
  usable RAM: 255 MiB
  frames: total 65406 / free 65095 / reserved 311 (254 MiB usable)
  mmu: handoff...
  mmu: installed, PML4 @ PhysAddr(0x000000000ffde000), console remapped
  scheduler: ready queue initialised
  scheduler: spawning 1 task, running to completion
  tick 0: elapsed 100 Mcycles
  tick 1: elapsed 200 Mcycles
  tick 2: elapsed 300 Mcycles
  tick 3: elapsed 400 Mcycles
  tick 4: elapsed 500 Mcycles
  async demo: done
  heap used: 520952 / 1048576 bytes
  halting — Stage 1 exit-gate demo complete.
```

```
$ cargo xtask test --arch=x86_64
...
── kernel_test harness ──────────────────────────
  [ OK ] smoke_frame_alloc_roundtrip
  [ OK ] smoke_bitmap_first_set
  [ OK ] smoke_spin_lock_cycle
  [ OK ] smoke_monotonic_advances
  [ OK ] smoke_typed_id_sanity
  [ OK ] smoke_arch_backend
  [ OK ] smoke_scheduler_drives_future
  [ OK ] smoke_box_roundtrip
  [ OK ] smoke_sleep_future_waits
── summary: 9 pass, 0 fail, 0 skip ──
```

## Crates that exist

| crate             | role                                                      |
| ----------------- | --------------------------------------------------------- |
| `narf-lib`        | Typed IDs, SpinLock, OnceLock, Bitmap, IntrusiveList.     |
| `narf-arch`       | HAL: halt/enable_interrupts/exit_kernel + io_port/MMIO.   |
| `narf-memory`     | PhysAddr/VirtAddr + Stage-1 bump allocator.               |
| `narf-boot`       | RawBootInfo, memory-map parse (PVH on x86_64, FDT on aarch64). |
| `narf-console`    | 16550A / PL011 + `remap_to_virtual` plumbing.             |
| `narf-time`       | Instant from TSC/CNTPCT + `SleepUntil` Future.            |
| `narf-scheduler`  | Cooperative executor: spawn, yield_now, run_until_empty.  |
| `narf-verification` | `#[kernel_test]` collector + runtime + built-in smokes. |
| `narf-frame`      | Bin with `_start` + long-mode transition + IDT + demo.    |
| `xtask`           | `cargo xtask {build,run,test,image}` per arch.            |

## Stage 1 exit-gate status (from `STAGE1.md`)

| # | requirement                                                    | state |
|---|----------------------------------------------------------------|-------|
| 1 | boot through `boot::_start` → `frame::init_bsp`                | ✓     |
| 2 | print `mmu: handoff...` via `remap_to_virtual`                 | ✓ (Wave 2: own PML4 + CR3 swap + console remap) |
| 3 | Future-on-executor prints per tick, exits cleanly              | ✓     |
| 4 | `verification/` smoke test produces Pass exit                  | ✓     |
| 5 | boot-time domain enumeration                                   | ✓     |
| 6 | no unsafe block outside `arch/` touches privileged MSRs        | ~ design-enforced; Clippy / post-link scan TBD |

## Deferred (Stage 1 closure work + Stage 2 prep)

Every Stage 1 exit-gate criterion is now met or explicitly deferred-
with-scaffolding. What's left is the set-up required before the
Stage 2 "Barrier" theme (PKS/MTE domain switching + UIPI) can land:

- **4 KiB / 2 MiB page-table manipulation**: `memory/paging.rs`
  currently has the PML4 / PDPT types and 1-GiB-huge-page wiring used
  by the Wave 2c handoff. `map_4kb` / `unmap_4kb` / `map_2mb` are
  needed before domain-tagged mappings (PKS PK bits, MTE tag storage)
  can exist.
- **Higher-half kernel**: today phys==virt. Stage 2's domain assign
  doesn't strictly require -2 GiB, but it's the conventional layout
  every other Stage 2 subsystem expects.
- **Full buddy allocator**: today's `memory::frame` is a free-stack
  allocator (4 KiB granularity). Buddy + `Folio { order, head }`
  land once 2 MiB / 1 GiB mapping has consumers.
- **Slab (SLAB/SLUB-lite) over the frame allocator**: retires the
  Stage-1 bump heap. Currently the bump arena is 1 MiB and uses
  ~500 KiB just for the frame-allocator's free-stack Vec, leaving
  limited headroom for `alloc::` in long-running kernel code.
- **`frame/` trap-prologue PKRS save**: scaffolding only until
  Stage 2 wires PKS enable.
- **`boot/` full `validate_boot_info`**: magic + min-RAM only today;
  all 6 checks land with Stage 2's memory-map consumers.
- **`interrupts/`**: no external IRQ routing yet. APIC / GICv3 bring-
  up gates Stage 2 UIPI.

## Deviations from the v0.2 design

Each of these has an in-code comment calling it out; listing them here
for the handoff.

1. **PVH instead of Limine on x86_64.** `boot/` spec §5 pins Limine as
   the sole Stage-1 x86_64 bootloader. We use Xen-PVH because it's the
   only ELF64 path `qemu-system-x86_64 -kernel` supports natively.
   Limine needs an external bootloader binary + ISO tooling that Stage
   1 doesn't need to land its exit-gate demo. File `boot/src/x86_64/
   multiboot2.rs` is still *named* multiboot2 for future compat, but
   its contents parse `hvm_start_info`.

2. **Low-half linking for the kernel.** `build/linker/x86_64.ld` links
   at phys 0x100000. The higher-half migration to `-2 GiB` happens in
   Wave 2 when `memory/` takes the MMU up with the proper kernel-virtual
   mapping and runs the `console::remap_to_virtual` handoff. `code-model
   = small` is used today; `code-model = kernel` comes back with the
   higher-half switch.

3. **Bump heap under `#[global_allocator]`.** `memory/src/heap.rs` is a
   1-MiB linear arena, not the Stage-1 buddy+slab described in
   `memory/` spec §3. Both the buddy and the slab land in Wave 2; the
   bump heap retires at that point.

4. **aarch64 FDT walker is a stub.** Wave-1 aarch64 synthesises a
   single 128-MiB usable region from QEMU-virt defaults rather than
   parsing the `/memory` + `/reserved-memory` nodes. Real FDT walk
   lands alongside Wave 2 memory work.

## How to run

```bash
# Default (async executor demo), prints 5 ticks then exits.
cargo xtask run  --arch=x86_64

# Kernel-test harness flavour, runs all #[kernel_test]s.
cargo xtask test --arch=x86_64

# Trigger the IDT self-test (#UD → trap frame → exit 42).
cargo xtask run  --arch=x86_64 --features=idt-selftest

# Cross-compile for aarch64 (can't run locally without qemu-system-aarch64).
cargo xtask build --arch=aarch64 --package=narf-frame

# Host-side unit tests for narf-lib.
cargo test -p narf-lib
```

## Commit log (high-level)

| commit       | landed                                                        |
|--------------|---------------------------------------------------------------|
| Baseline     | 217-file NARF v0.2 design tree                                |
| Wave 0       | Cargo workspace + nightly + build-std + narf-lib primitives   |
| Wave 1       | arch/ + console/ + boot/ + frame/ ⇒ bootable x86_64           |
| Wave 2a      | IDT + trap dispatch (ud2 self-test verified)                  |
| Wave 3       | time/ + scheduler/ + async executor + timer-driven demo       |
| domains+verif| 16-domain enumeration + verification/ harness + 4 tests       |
| more tests   | 4 additional smoke tests covering scheduler/time/alloc        |
| Wave 2 gdt   | GDT + TSS + 4 IST stacks (NMI/#DF/#MC/#VC)                    |
| Wave 2b      | PhysFrame + free-stack frame allocator (Vec<PhysFrame>)       |
| Wave 2c      | MMU handoff — own PML4, CR3 swap, console::remap_to_virtual   |

## Pickup hint for the next session

**Stage 1 is effectively closed** — exit-gate items 1–5 all pass,
with item 6 (MSR lint) being the remaining infrastructure task.
The next big chunk is the bridge from Stage 1 to Stage 2 "Barrier":

1. **`memory/paging.rs` 4 KiB mapping**: `map_4kb(virt, phys, flags)`
   walks or builds PML4 / PDPT / PD / PT, allocating new tables via
   `alloc_frame`. Needed before PKS PK bits can live on individual
   PTEs.
2. **`interrupts/` APIC skeleton**: x2APIC init, local-APIC timer
   (replace TSC-based busy-wait with real timer IRQs driving the
   scheduler's waker).
3. **`rcu/` stub API** (Wave 4 in STAGE1.md, but low-cost to land
   now): `Atomic<T>`, `ReadGuard`, `defer_drop` stubs so downstream
   consumers don't retrofit the types later. The executor's
   `report_quiescent` hook already exists in spirit — a real call
   site is one line.
4. **`tracing/` USDT markers**: `.note.narf.probes` section is
   already carved out in both linker scripts; add the `usdt!` macro
   + the `Recorder<E>` flight-recorder ring.
5. **Stage 2 Barrier proper**: PKS enable on x86_64, MTE enable on
   aarch64, the `DomainPrimitive::set_rights` implementations,
   UIPI bring-up. This is the next major theme and is gated on (1).

Parallel-safe micro-tasks:
- Replace the free-stack frame allocator with a buddy (retains the
  Vec-based free-list API so callers don't change).
- Add `kernel_test!`-level coverage for MMU bring-up (build a PML4
  in isolation, verify entries decode correctly).
