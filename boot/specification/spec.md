# boot — Specification

> Status: **v1.0** (Stage 1 design lock). v0.1 outlined entry
> + handoff; v1.0 locks the bootloader portfolio, the
> measured-boot integration that drivers framework signing
> rests on, and the framebuffer handoff.

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
#[repr(C)]
pub struct RawBootInfo {      // bootloader-supplied, untrusted
    pub magic: u64,
    pub payload: PhysAddr,
}

pub struct BootInfo {         // post-validation, trusted
    pub memory_map: &'static [MemRegion],
    pub acpi_rsdp: Option<PhysAddr>,
    pub devicetree: Option<&'static [u8]>,
    pub cmdline: &'static str,
    pub uart_phys: PhysAddr,  // for console::early_init
    pub uart_virt: VirtAddr,  // for console::remap_to_virtual (set by memory/ during MMU bringup)
}

pub unsafe fn parse_raw(raw: &RawBootInfo) -> Result<BootInfo, BootError>;
pub fn validate_memory_map(map: &[MemRegion]) -> Result<(), BootError>;
#[no_mangle] pub extern "C" fn _start() -> !; // per-arch entry
```

**Handoff validation checks (binding):**

1. Every retained memory-map region is non-empty, its end address does
   not overflow, and no two retained regions overlap.
2. The bootloader's advertised map must fit the architecture's bounded
   early-boot storage. Overflow is rejected, never silently truncated.
3. At least one usable RAM region ≥ 1 MiB (a smaller RAM-only system
   cannot boot NARF).
4. An RSDP pointer is accepted only from a protocol-defined field:
   PVH's `rsdp_paddr` or a bounded Multiboot2 ACPI tag. The ACPI
   subsystem validates the RSDP signature, length, and checksum before
   following any child table.
5. A DTB pointer, if present, has valid magic (`0xD00DFEED`) and a
   sane total size (≤ 2 MiB).
6. FDT `/memreserve/`, `/reserved-memory`, DTB storage, and initramfs
   storage are subtracted before usable RAM is exposed.
7. The kernel image is excluded independently using linker-provided
   physical bounds when `frame/` initializes the allocator. This is
   necessary for PVH/E820 maps, which legitimately describe the
   loaded kernel's containing RAM range as usable.

Raw PC firmware maps need not be page-aligned. Allocators round usable
range starts up and ends down before issuing frames.

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
- Direct Linux/U-Boot FDT entry and the `BOOTAA64.EFI` removable-media
  loader are supported. The loader obtains the standard EFI DTB
  configuration table, validates and loads the kernel ELF64 `PT_LOAD`
  segments at their physical addresses, exits Boot Services, and enters
  the same Linux-compatible ABI.
- Entry: physical address `0x4008_0000`, MMU off, X0 = DTB physical
  address (Linux/U-Boot ABI).
- Memory map + reserved regions from the FDT `/memory` and
  `/reserved-memory` nodes.
- The early scan accepts FDT v17+, obtains the command line and Linux
  initrd range from `/chosen`, and subtracts both `/memreserve/` and
  static `/reserved-memory/*/reg` ranges before exposing usable RAM.
  DTB and initrd storage are also excluded from the usable map.

## 6. Dependencies

- **Consumes:** `build/` (linker scripts — the `.boot` section
  definition and `.boot before .text` assertion live in
  `arch-{x86_64,aarch64}.ld`; without this the reclamation guarantee
  is unverifiable), `arch/` (trait implementations), `crypto/` (Stage 4:
  SHA-256/BLAKE3 for measured-boot hash chain).
- **Provides to:** `frame/`, and through it everything.

## 7. Stage assignment

Stage 1.

## 8. Resolved decisions

### 8.1 Bootloader portfolio (resolved)

**Decision (was open):** **Limine on x86_64; UEFI-stub on
aarch64; multiboot2 fallback for CI.** Three loaders, all
producing the same `RawBootInfo` shape that `frame/` consumes.

- **Limine** is the primary x86_64 bootloader: well-maintained,
  modern, supports the protocol features we care about
  (high-half kernel, KASLR, Smarter ACPI handoff).
- **multiboot2** stays as a CI fallback because QEMU's
  `-kernel` direct-load path is multiboot2; this lets us boot
  fresh kernels in xtask without re-imaging.
- **UEFI loader** on aarch64 is the SystemReady-compatible removable
  media path and is boot-gated with AAVMF; `-kernel` direct entry
  remains the fast functional-test path.

The three loaders converge on `RawBootInfo` before any
NARF-specific code runs; downstream subsystems see only the
unified structure.

### 8.2 Measured boot / TPM (resolved)

**Decision (was open):** **TPM measured boot is mandatory in
release builds, optional in dev/CI builds.**

Release builds:
- PCR 7 captures Secure Boot state (UEFI standard).
- PCR 14 captures the kernel image SHA-256.
- PCR 15+ are reserved for per-driver firmware measurement
  (see `security-model/spec` §10.3).

The kernel CA root key (signing chain in `security-model/`
§9) is sealed against PCRs 7 + 14. Bootloader compromise is
caught at unseal time; kernel modification is caught at
PCR 14 mismatch.

Dev/CI builds boot without TPM (no `narf.modules.allow_unsigned`
loosening). The CA root is read from an unsealed location;
modules sign with a CI-only CA. Production images explicitly
re-key.

### 8.3 Framebuffer handoff (resolved)

**Decision (was open):** **bootloader provides framebuffer
descriptor in `RawBootInfo`**; `console/` consumes it during
its `Stage::Early` init. Limine fills `framebuffer = Some(fb)`;
UEFI-stub fills from GOP; multiboot2 fills from the framebuffer
tag.

If no framebuffer is described (serial-only QEMU), `console/`
runs serial-only. The framebuffer console is opt-in based on
the descriptor's presence.

`graphics/` (the FB renderer) takes over the framebuffer at
Stage::Late once a real driver (bochs-display, virtio-gpu) is
probed. Until then, `console/` owns the linear FB at the
boot-mapped address.

## 9. RawBootInfo wire format

Locked at v1.0. Bootloaders MUST produce this exact layout;
subsequent kernel code reads it once and discards.

```rust
#[repr(C)]
pub struct RawBootInfo {
    pub magic:        u64,           // 0x4E_41_52_46_42_4F_4F_54 = "NARFBOOT"
    pub abi_version:  u32,           // currently 1
    pub _reserved:    u32,
    pub mem_map:      [MemRegion; MEM_MAP_MAX],   // 64 entries
    pub mem_map_len:  u32,
    pub kernel_phys:  u64,           // physical base of loaded kernel
    pub kernel_size:  u64,
    pub framebuffer:  Option<Framebuffer>,
    pub rsdp:         Option<PhysAddr>,           // x86_64
    pub dtb:          Option<PhysAddr>,           // aarch64
    pub initramfs:    Option<(PhysAddr, u64)>,    // (base, size)
    pub cmdline:      [u8; 256],
    pub cmdline_len:  u32,
}
```

Adding a field at the end with a `_reserved`-renaming follows
`BOOT_ABI_MINOR` bump rules. Any layout change is a
`BOOT_ABI_MAJOR` bump (flag-day).

## 10. Open questions

(none — all v0.1 questions resolved in §8)
