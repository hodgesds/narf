# boot — Research

## Primary sources

- **Limine Boot Protocol**.
  <https://github.com/limine-bootloader/limine/blob/trunk/PROTOCOL.md>
- **Multiboot2 specification**.
  <https://www.gnu.org/software/grub/manual/multiboot2/multiboot.html>
- **UEFI Specification (latest)**.
  <https://uefi.org/specifications>
- **Arm SystemReady** — standardised EFI-based boot for aarch64.
  <https://www.arm.com/architecture/system-architectures/systemready-certification-program>
- **Devicetree specification**.
  <https://www.devicetree.org/specifications/>

## Secondary sources

- **Phil Oppermann, "Booting"** chapters.
- **`bootloader` crate (rust-osdev)**.
- **Redox `boot/`**.
- **QEMU `virt` machine model docs** — memory map for aarch64 experiments.

## Distilled summaries

- (None at Stage 1; the primary docs are authoritative and short.)

## Fetched this round

- summaries/arm-systemready.md — Firmware-to-kernel handoff, ACPI vs. devicetree, and capability establishment at boot
- summaries/devicetree-spec.md — Static hardware description format with phandle-based references and binding contracts

## Open research questions

- ACPI vs. devicetree on aarch64 — pick one for Stage 1 QEMU tests.
- Kernel-command-line format — share it across arches.
