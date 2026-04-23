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
  scheduler: ready queue initialised
  scheduler: spawning 1 task, running to completion
  tick 0: elapsed 100 Mcycles
  tick 1: elapsed 200 Mcycles
  tick 2: elapsed 300 Mcycles
  tick 3: elapsed 400 Mcycles
  tick 4: elapsed 500 Mcycles
  async demo: done
  heap used: 128 / 1048576 bytes
  halting — Stage 1 exit-gate demo complete.
```

```
$ cargo xtask test --arch=x86_64
...
── kernel_test harness ──────────────────────────
  [ OK ] smoke_arch_backend
  [ OK ] smoke_spin_lock_cycle
  [ OK ] smoke_scheduler_drives_future
  [ OK ] smoke_monotonic_advances
  [ OK ] smoke_sleep_future_waits
  [ OK ] smoke_bitmap_first_set
  [ OK ] smoke_box_roundtrip
  [ OK ] smoke_typed_id_sanity
── summary: 8 pass, 0 fail, 0 skip ──
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

- **`memory/` Stage-1 subset**: buddy frame allocator, page-table
  manipulation (4 KiB / 2 MiB / 1 GiB), final kernel page tables,
  `console::remap_to_virtual` handoff, replace the bump heap with a
  proper kernel heap. *This is the Stage-1 critical-path item that is
  still open.*
- **`frame/` Wave-2 items**: GDT with TSS, IST stacks for NMI/#DF/#MC,
  trap-prologue PKRS save scaffolding. The IDT exists today; what's
  missing is the per-trap IST redirection and the separate stacks.
- **`boot/` full `validate_boot_info`**: today we only do magic-presence
  + min-RAM checks. The 6-check full validation from `boot/` §3 lands
  when its callers need the stricter guarantees.
- **`interrupts/`**: no external IRQ routing yet. APIC / GICv3 bring-up
  is Wave 2 after MMU.

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

| commit      | landed                                                     |
|-------------|-----------------------------------------------------------|
| Baseline    | 217-file NARF v0.2 design tree                            |
| Wave 0      | Cargo workspace + nightly + build-std + narf-lib primitives |
| Wave 1      | arch/ + console/ + boot/ + frame/ ⇒ bootable x86_64        |
| Wave 2a     | IDT + trap dispatch (ud2 self-test verified)              |
| Wave 3      | time/ + scheduler/ + async executor + timer-driven demo   |
| domains+verif | 16-domain enumeration + verification/ harness + 4 tests |
| more tests | 4 additional smoke tests covering scheduler/time/alloc    |

## Pickup hint for the next session

The biggest open chunk is `memory/` Wave 2. Suggested plan:

1. `PhysFrame` + frame-bitmap allocator backed by the boot-info memory map.
2. Page-table manipulation helpers (`map_page`, `unmap_page`) in
   `memory/src/paging.rs`; start with 4 KiB pages, add 2 MiB / 1 GiB as
   `Folio::order` consumers arrive.
3. Build the final kernel page tables: identity-map the low 4 GiB
   (devices, early boot) + higher-half-map the kernel text/data.
4. Execute the `console/` §3.1 MMU-enable handoff and print
   `mmu: handoff...`. This closes exit-gate #2.
5. Retire the bump heap; wire a real slab (SLAB/SLUB-lite) over the
   frame allocator.

`frame/` GDT/TSS is a good parallel task — it's self-contained and
prevents catastrophic faults from wedging the kernel, but has no
dependencies on the MMU work.
