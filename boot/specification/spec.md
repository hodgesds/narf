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

- Bootloader handed us control in a documented state (Multiboot2 or Xen PVH
  on x86_64, Linux/U-Boot FDT entry on aarch64).
- Kernel image is linked at its runtime virtual address.
- **All data supplied via `BootInfo` is treated as untrusted input.**
  "Documented state" does not mean "correct state." `boot/` validates
  every field before handing off to `frame/` — see `validate_boot_info`
  in §3.

## 3. Public interface

The native x86_64 EFI application (`cargo xtask efi-image`) embeds its
kernel, initramfs and command line, then produces the existing Multiboot2
handoff. `narf-boot-protocol` (`boot/protocol/`) validates the ELF load plan
and constructs the information block without kernel or EFI dependencies.
The loader's mode bridge supplies EAX=`0x36d76289`, EBX=physical information
pointer, paging off and interrupts disabled. Existing kernel entry, KASLR,
and normalized `BootInfo` consumers are shared with other Multiboot2 loaders.

The loader retains the complete final EFI descriptor map in tag 17, in
addition to the coalesced type-6 map, and preserves the system table through
tag 12. EFI loader code/data, the kernel, initramfs, bridge, information block,
runtime and boot-services regions stay reserved. Boot-services reclamation
requires an explicit firmware-table lifetime audit. Native EFI currently
requires the kernel's fixed physical load range to be available; a collision
is fatal. Command-line
and initramfs bytes are embedded before any administrator signing. Firmware
load options do not override them. Build/install/run instructions and limits
are in `docs/NATIVE_UEFI.md`.

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

// Firmware-table pointers copied out of the (transient) handoff by
// parse_raw, for the later SMBIOS scan (`firmware/smbios/`).
pub struct SmbiosEntryCopy { pub bytes: [u8; 32], pub len: u8 } // zero-padded
pub struct FirmwareHandoff {
    pub efi_system_table: Option<u64>,          // multiboot2 tag 12 (EFI64 ST)
    pub smbios3_entry: Option<SmbiosEntryCopy>, // first tag 13 starting "_SM3_"
    pub smbios_entry: Option<SmbiosEntryCopy>,  // first tag 13 starting "_SM_"
}
pub fn firmware_handoff() -> FirmwareHandoff;   // EMPTY on PVH / aarch64 / before parse_raw

// EFI configuration-table lookup for the firmware TPM event logs
// (#1071). The table walk is generic over the GUID; the TCG2
// pair is surfaced together:
pub struct Tcg2LogTables {
    pub main_log: Option<u64>,     // LINUX_EFI_TPM_EVENT_LOG_GUID
    pub final_events: Option<u64>, // EFI_TCG2_FINAL_EVENTS_TABLE_GUID
}
pub fn find_efi_config_table(efi_system_table: u64, guid: &[u8; 16],
                             read: &dyn Fn(u64, &mut [u8]) -> bool) -> Option<u64>;
pub fn tcg2_log_tables(efi_system_table: u64,
                       read: &dyn Fn(u64, &mut [u8]) -> bool) -> Tcg2LogTables;
```

Multiboot2 tag 13's payload is `u8 major, u8 minor, u8 reserved[6]`
followed by the loader's copy of the entry-point structure (Limine:
`tag->size = 16 + entry->length`, one tag per entry point found); at
most 32 bytes are kept. A zero tag-12 pointer is treated as absent.

`KernelCmdline::console_loglevel()` evaluates `quiet` (4), `debug` (10), and
`loglevel=N` (clamped to 1..15) in command-line order and returns the final
explicit threshold, or `None` when no verbosity token was supplied.

**Cmdline store contract (per-arch `parse_raw`):** the bootloader-supplied
command line is copied into a static 2048-byte buffer (`CMDLINE_CAP`,
matching Linux's `COMMAND_LINE_SIZE`); the store keeps at most
`CMDLINE_CAP - 1` bytes. On aarch64 the source is the FDT
`/chosen/bootargs`, extracted by `narf-firmware-fdt` at the same 2048-byte
cap (`BOOTARGS_CAP`). Truncation is never silent: the aarch64 store
records it (`narf_boot::aarch64::cmdline_truncated()`) and prints a
warning naming the sizes to the boot UART at store time (#960 — a
256-byte cap previously dropped trailing tokens, including the test
harness's `test_subsystem_exclude=`, without a trace).

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
- Limine supplies Multiboot2 for existing UEFI media and explicit legacy packages;
  QEMU direct boot uses Xen PVH. Both enter the same 32-bit kernel stub.
- The Stage-5 native EFI loader also supplies Multiboot2, with a small
  64-bit-to-32-bit mode bridge. It embeds all boot payloads in one PE image.
- Memory map, RSDP copy, initramfs and framebuffer use the corresponding
  Multiboot2 tags. Native EFI passes BGRX GOP only; other layouts remain
  serial-only until the kernel framebuffer ABI describes channel masks.

### aarch64
- Direct Linux/U-Boot FDT entry and the `BOOTAA64.EFI` removable-media
  loader are supported. The loader obtains the standard EFI DTB
  configuration table and verifies a build-time-bound BLAKE2b-512 digest of
  the complete kernel before parsing its ELF header. A missing binding or
  mismatch is fatal. It then validates and loads the kernel ELF64 `PT_LOAD`
  segments at their physical addresses, exits Boot Services, and enters the
  same Linux-compatible ABI.
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

**Current portfolio:** Limine-backed x86_64 media/legacy packages, default
self-contained x86_64 native EFI packages, aarch64 EFI/FDT, and Xen PVH direct boot
for x86_64 CI. All normalize through the same `BootInfo` consumed by `frame/`.

- **Limine** remains the existing x86_64 media bootloader: well-maintained,
  modern, supports the protocol features we care about
  (high-half kernel, KASLR, Smarter ACPI handoff).
- **Native EFI** is built with `cargo xtask efi-image`; its standard
  Multiboot2 handoff reuses the existing kernel entry. It is not yet the
  default for existing media or distribution-package commands.
- **Xen PVH** is QEMU's x86_64 `-kernel` direct-load path; it lets xtask
  boot fresh kernels without re-imaging. Multiboot2 remains supported for
  Limine, GRUB and the native EFI application.
- **UEFI loader** on aarch64 is the SystemReady-compatible removable
  media path and is boot-gated with AAVMF; `-kernel` direct entry
  remains the fast functional-test path. Native packages may place the kernel
  beside the loader under `EFI/NARF`; removable media retains `boot/narf-frame`.
  Both layouts use a loader bound to that exact kernel before any optional
  Authenticode signing.

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

## 9. RawBootInfo entry wrapper

The implemented entry wrapper in `boot/src/info.rs` is two 64-bit fields.
Architecture assembly constructs it from registers and passes it to Rust;
it is not a serialized copy of the normalized `BootInfo` structure.

```rust
#[repr(C)]
pub struct RawBootInfo {
    pub magic: u64,
    pub payload: PhysAddr,
}
```

`magic` and `payload` identify the protocol-specific structure: Multiboot2
magic plus information pointer, PVH's start-info pointer (identified by its
payload magic), or the FDT handoff. Multiboot2 tags and FDT properties carry
the extensible payload. The earlier inline `NARFBOOT` structure documented
here was never the implemented entry ABI. This correction does not change
the kernel's register or struct layout.

## 10. Open questions

(none — all v0.1 questions resolved in §8)
