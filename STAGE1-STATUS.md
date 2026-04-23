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
| 2 | print `mmu: handoff...` via `remap_to_virtual`                 | ✗ deferred (Wave 2: memory/ owns this) |
| 3 | Future-on-executor prints per tick, exits cleanly              | ✓     |
| 4 | `verification/` smoke test produces Pass exit                  | ✓     |
| 5 | boot-time domain enumeration                                   | ✓     |
| 6 | no unsafe block outside `arch/` touches privileged MSRs        | ~ design-enforced; Clippy / post-link scan TBD |

## Deferred to Wave 2 (next big push)

- **`memory/` page tables + MMU handoff**: frame allocator landed
  (Wave 2b below); what's still open is page-table manipulation
  (4 KiB / 2 MiB / 1 GiB), final kernel page tables,
  `console::remap_to_virtual` handoff, and replacing the bump heap
  with a proper slab over the frame allocator. *This remains the
  largest Stage-1 critical-path item.*
- **Full buddy allocator**: today's `memory::frame` is a free-stack
  allocator (4 KiB granularity only). The buddy + Folio { order, head }
  structures from `memory/` §3 land with the page-table work.
- **`frame/` trap-prologue PKRS save**: scaffolding only. The domain-
  switch work from STAGE1.md Wave 2 #7 needs a defined place to save
  the MSR; wiring happens when Wave 2 lands PKS enable.
- **`boot/` full `validate_boot_info`**: today only magic-presence +
  min-RAM. The 6-check validation from `boot/` §3 lands when its
  callers need the stricter guarantees.
- **`interrupts/`**: no external IRQ routing yet. APIC / GICv3
  bring-up is Wave 2 after MMU.

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

## Pickup hint for the next session

`memory/` Wave 2 is still the biggest open chunk. PhysFrame + the
frame allocator landed; what remains:

1. Page-table manipulation helpers (`map_page`, `unmap_page`) in
   `memory/src/paging.rs`; start with 4 KiB pages, add 2 MiB / 1 GiB
   as `Folio::order` consumers arrive. On x86_64 this is PML4 / PDPT /
   PD / PT walkers with entry flags; on aarch64 it's TTBR0/1 with
   three levels of table descriptors.
2. Build the final kernel page tables: identity-map the low 4 GiB
   (devices, early boot) + higher-half-map the kernel text/data at
   -2 GiB. Flip `code-model` back to `kernel` when the higher-half
   mapping is ready.
3. Execute the `console/` §3.1 MMU-enable handoff and print
   `mmu: handoff...` — closes Stage 1 exit-gate #2.
4. Retire the bump heap; wire a real slab (SLAB/SLUB-lite) over the
   `frame::alloc_frame` source.
5. Upgrade the free-stack frame allocator to the buddy + Folio
   structures described in `memory/` §3.

Parallel tasks with no dependency on Wave 2 memory:
- `interrupts/` APIC/GICv3 skeleton so `enable_interrupts()` doesn't
  get us a spurious IRQ triple-fault.
- `rcu/` stub API (Wave 4 item) — the types land so that consumers
  don't have to retrofit them later.
- `tracing/` USDT compile-time markers (Wave 4 item) — the
  `.note.narf.probes` section is already carved out in both linker
  scripts; only the `usdt!` macro + recorder ring is missing.
