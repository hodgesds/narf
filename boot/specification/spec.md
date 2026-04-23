# boot — Specification

> Status: **Outline v0.1** (Stage 1).

## 1. Purpose & scope

**Owns:** Entry point from the bootloader, parsing of memory map /
firmware tables / devicetree, hand-off to `frame::init_bsp`.

**Does NOT own:** CPU configuration beyond what's strictly needed to
reach the hand-off (that's `frame/`), paging after hand-off (`memory/`).

## 2. Assumptions

- Bootloader handed us control in a documented state (Limine protocol
  on x86_64, U-Boot FDT entry on aarch64).
- Kernel image is linked at its runtime virtual address.
- **All data supplied via `BootInfo` is treated as untrusted input.**
  "Documented state" does not mean "correct state." `boot/` validates
  every field before handing off to `frame/` — see `validate_boot_info`
  in §3.

## 3. Public interface

```rust
pub struct RawBootInfo;       // bootloader-supplied, untrusted

pub struct BootInfo {         // post-validation, trusted
    pub memory_map: &'static [MemRegion],
    pub acpi_rsdp: Option<PhysAddr>,
    pub devicetree: Option<&'static [u8]>,
    pub cmdline: &'static str,
    pub uart_phys: PhysAddr,  // for console::early_init
    pub uart_virt: VirtAddr,  // for console::remap_to_virtual (set by memory/ during MMU bringup)
}

pub fn validate_boot_info(raw: &RawBootInfo) -> Result<BootInfo, BootError>;
#[no_mangle] pub extern "C" fn _start() -> !; // per-arch entry
```

**`validate_boot_info` checks (binding):**

1. No overlapping memory-map regions.
2. At least one usable RAM region ≥ 1 MiB (a smaller RAM-only system
   cannot boot NARF).
3. RSDP pointer, if present, falls within a firmware-reserved region
   in the memory map.
4. DTB pointer, if present, has valid magic (`0xD00DFEED`) and a
   sane total size (≤ 2 MiB).
5. Memory map regions are page-aligned.
6. Reserved regions cover the kernel's own image and the bootloader's
   reserved areas — overlap with usable RAM is rejected.

A failed validation panics in `boot/` *before* any subsystem
consumes the data; this prevents a malicious or buggy bootloader
from turning into a kernel-side memory-corruption primitive.

## 4. Invariants & safety properties

- `BootInfo` is consumed exactly once; never dangles.
- Boot-only code is in its own linker section, reclaimed as free memory
  after `frame::init_bsp` returns. **The linker scripts in
  `build/arch-{x86_64,aarch64}.ld` define a `.boot` section and
  include a static assertion that `.boot` precedes `.text` and `.data`
  in the loaded image** — without this the reclamation guarantee is
  unverifiable.
- **Console is live before MMU enable, and survives it.** `boot/`
  calls `console::early_init(uart_phys, kind)` as its second
  operation (after memory-map parse), so any panic during the
  bring-up sequence is visible. When `memory/` takes the MMU on, it
  must call `console::remap_to_virtual(uart_virt)` inside the
  critical section per `console/` §3.1. `boot/` is responsible for
  passing both the physical UART base and the kernel-virtual UART
  base to `memory/` as part of the MMU-bringup input.

## 5. Architecture notes

### x86_64
- **Limine is the sole Stage 1 bootloader.** Multiboot2 is a Stage 4
  stretch goal and not supported in CI until then. This prevents the
  codebase from growing two divergent boot paths.
- Protocol requires higher-half kernel + feature-request markers.
- Memory map from Limine features; ACPI RSDP via Limine feature.

### aarch64
- **U-Boot FDT entry is the sole Stage 1 boot path.** EFI stub support
  is Stage 4. QEMU `virt` natively provides FDT; EFI adds a UEFI
  runtime dependency that Stage 1 CI does not need.
- Entry: physical address `0x4008_0000`, MMU off, X0 = DTB physical
  address (Linux/U-Boot ABI).
- Memory map + reserved regions from the FDT `/memory` and
  `/reserved-memory` nodes.

## 6. Dependencies

- **Consumes:** `build/` (linker scripts — the `.boot` section
  definition and `.boot before .text` assertion live in
  `arch-{x86_64,aarch64}.ld`; without this the reclamation guarantee
  is unverifiable), `arch/` (trait implementations), `crypto/` (Stage 4:
  SHA-256/BLAKE3 for measured-boot hash chain).
- **Provides to:** `frame/`, and through it everything.

## 7. Stage assignment

Stage 1.

## 8. Open questions

- Single Limine-only on x86_64, or dual-support with multiboot2 for CI flexibility?
- Measured boot / TPM integration — defer or plan slot in Stage 4?
- Early framebuffer handoff for `console/` on systems without serial.
