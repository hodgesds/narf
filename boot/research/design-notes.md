# boot — Design Notes
_2026-04-22_

## Load-bearing decisions

**BootInfo is the single trust boundary crossing from firmware to kernel.**
Everything NARF knows about hardware at startup comes through `BootInfo`. The
spec calls it "consumed exactly once; never dangles," but says nothing about
*validation*. The arm-systemready summary is explicit: firmware-supplied data
must be treated adversarially. On x86_64 Limine is a user-controlled bootloader;
on aarch64 U-Boot is frequently vendor-patched. `BootInfo` must be treated as
untrusted input, not a trusted oracle.

**Limine is the primary x86_64 bootloader; multiboot2 is listed as "supported."**
These two protocols have incompatible memory-map formats, ACPI-pointer delivery
mechanisms, and module conventions. Supporting both doubles the boot parsing
surface. The spec never resolves whether multiboot2 is a first-class target or
a CI escape hatch. That ambiguity will cause divergent boot-path code to persist
indefinitely.

**aarch64 boot is underspecified relative to x86_64.** x86_64 gets Limine
defaults, ACPI RSDP via Limine feature, and a known entry contract. aarch64 gets
"EFI stub or U-Boot raw entry" and "QEMU virt: devicetree path, entry at
`0x4008_0000`." EFI stub and U-Boot raw are radically different handoff
contracts. The spec picks neither and defines neither entry invariant in detail.
Stage 1 cannot actually boot on aarch64 hardware without pinning one.

**Boot-only code reclamation is stated but the linker section is unnamed.**
`§4` says boot-only code lives in "its own linker section, reclaimed as free
memory." But `build/` spec defines no named section for this (no `.boot` or
`.init` section in the linker script sketch). Without coordination between
`boot/` and `build/` linker scripts, reclamation is unimplementable.

## Divergences from precedent

**vs. Linux:** Linux's `__init` / `__initdata` sections are 30+ years old and
well-understood. NARF should adopt the same pattern verbatim for boot-only code
rather than inventing new convention. The rust-embedded idiom of a `#[link_section
= ".boot.text"]` attribute is the direct Rust analogue and is unambiguous.

**vs. Limine's own guarantee:** The Limine protocol guarantees the kernel is
loaded at its linked virtual address with 4-level paging enabled on x86_64.
NARF's spec says "Kernel image is linked at its runtime virtual address" as an
assumption, which is correct for Limine. But it then lists multiboot2 as an
alternative, and multiboot2 does *not* provide higher-half mapping out of the
box — the kernel must relocate itself. The spec does not acknowledge this gap.
Either drop multiboot2 or specify that the boot crate performs self-relocation.

**vs. Redox:** Redox separates the bootloader binary (written in assembly + a
thin Rust shim) from the kernel proper. NARF conflates "boot entry" and "BootInfo
parsing" in a single `boot/` crate. This is fine, but it means `boot/` must
not link against anything that requires a heap or global allocator, since those
are set up by `memory/` after `frame::init_bsp`. The spec does not state this
no-allocator precondition for the `boot/` crate.

**vs. Fuchsia:** Fuchsia's ZBI (Zircon Boot Image) is a kernel-defined boot
record format with a checksum and typed items. This is strictly better than
parsing Limine's tagged-pointer structures without validation. NARF should
consider defining a NARF-kernel-boot-record that is a validated, checksummed
snapshot of `BootInfo`, written by the boot entry and consumed by `frame/`. This
decouples the bootloader protocol from the kernel's internal representation.

## Proposed spec changes

- §2 Assumptions: Add **"All data supplied via `BootInfo` is treated as
  untrusted input; `boot/` validates memory-map region types, overlap, and
  alignment before handing off to `frame/`."** The current spec lists the
  assumption that the bootloader "handed us control in a documented state" without
  acknowledging that "documented" ≠ "correct."

- §3 Public interface: Add **`pub fn validate_boot_info(raw: &RawBootInfo) ->
  Result<BootInfo, BootError>`** as a distinct step from parsing. Validation
  checks: no overlapping regions, at least one usable RAM region ≥ 1 MiB, RSDP
  pointer if present falls within a firmware-reserved region, DTB pointer if
  present has valid magic (`0xD00DFEED`). Making validation explicit prevents
  callers from assuming a `BootInfo` is already trusted.

- §4 Invariants: Add **"Boot-only code and data must live in a `.boot` linker
  section defined in `build/` linker scripts; the linker script must include an
  assertion that `.boot` precedes `.text` and `.data`."** Without this, the
  reclamation guarantee is unverifiable.

- §5 Architecture notes (aarch64): **Pick U-Boot FDT entry as the Stage 1
  aarch64 boot path.** Drop "EFI stub or U-Boot raw entry" ambiguity. aarch64
  QEMU `virt` natively provides FDT; EFI stub adds UEFI dependency that is not
  needed for Stage 1 CI. Add: entry is at `0x4008_0000`, MMU off, X0 = DTB
  physical address, as per Linux/U-Boot ABI. Stage 4 can add EFI.

- §5 Architecture notes (x86_64): **Pin Limine as the sole Stage 1
  bootloader.** State explicitly: "Multiboot2 is a Stage 4 stretch goal and not
  supported in CI until then." This prevents the codebase from growing two
  divergent boot paths simultaneously.

- §6 Dependencies: Add **`build/` as an explicit dependency** with a note:
  "boot-section reclamation depends on the `.boot` linker section being defined
  in `build/arch-{x86_64,aarch64}.ld`." Currently `build/` is not listed as a
  `boot/` dependency, but the linker scripts are a build output, not a
  boot-crate input.

## Open invariants / cross-subsystem hazards

**boot ↔ frame:** `frame::init_bsp` is called with a `&BootInfo` reference.
`frame/` §4 says `BootInfo` is "consumed exactly once; never dangles." But
`frame/` §2 says "boot/ has placed the kernel at its linked address with the
MMU in a known state." If Limine provides higher-half mapping and `boot/`
calls `frame::init_bsp` while still on the bootloader stack (which may be
identity-mapped below the higher-half boundary), the `BootInfo` reference may
point into a region that `memory/` will reclaim. Coordinate: `BootInfo` must be
copied into a kernel-owned page before calling `frame::init_bsp`, or the
`memory/` allocator must mark the Limine-stack page as reserved until after
`init_bsp`.

**boot ↔ memory:** "Boot-only code is reclaimed as free memory after
`frame::init_bsp` returns." But `memory/` physical allocator initializes
*during* `frame::init_bsp`. The sequencing is: boot → frame::init_bsp →
memory::init_physical_allocator → (mark .boot as free). If `memory/` reads the
`BootInfo` memory map during its own init, and `.boot` is already poisoned or
freed, memory::init will crash. The spec says nothing about the reclamation
ordering relative to memory init.

**boot ↔ crypto:** `§6` lists `crypto/` as a Stage 4 dependency for measured
boot. But the arm-systemready summary strongly recommends DTB integrity
validation at boot time (checksums or signatures from bootloader). If NARF ever
supports measured boot, the hash of `BootInfo`/DTB must be taken *before*
`frame::init_bsp`, not during Stage 4 crypto init. The architecture slot needs
to be reserved now, not bolted on later.

**boot ↔ console:** There is no pre-console debug path. The UART is initialized
by `console::early_init`, which is called from `frame::init_bsp`. Any boot-time
panic before `early_init` is silent. The spec should acknowledge this window and
specify whether `boot/` can emit debug output (e.g., via QEMU `0xE9` port on
x86_64) before `console/` is ready.

## Additional opinionated commentary

The spec is thin relative to its importance. Boot is the point where every
security invariant either holds or doesn't, and the spec reads like it was
written last. Two push-back points:

1. **No UEFI runtime service policy.** The arm-systemready summary warns: "Resolve
   all hardware discovery during boot; don't defer to runtime." The NARF spec
   says nothing about whether UEFI runtime services (SetVariable, GetTime,
   UpdateCapsule) are called after `ExitBootServices`. On aarch64 SystemReady,
   these services run in EL1 and can corrupt arbitrary physical memory. NARF
   must either call `ExitBootServices` before `frame::init_bsp` and never touch
   runtime services again, or explicitly document which services are accessed
   and under what memory-protection regime. The current spec is silent.

2. **DTB is not validated.** The devicetree summary notes: "No integrity
   protection: DTB is not signed or checksummed." NARF's `boot/` accepts the DTB
   pointer from U-Boot/EFI and passes it as `devicetree: Option<&'static [u8]>`
   in `BootInfo`. A corrupt or attacker-controlled DTB can point
   `devicetree[...]` to arbitrary physical memory, which downstream consumers
   (`bus/`, `memory/`) will parse. At minimum, `boot/` must check the DTB magic
   bytes and total size before passing the slice. Ideally it should verify a
   firmware-provided signature.
