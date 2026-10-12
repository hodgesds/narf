# boot — Bootloader handoff + early init

Accepts control from a bootloader, parses the memory map / ACPI /
devicetree, hands a `BootInfo` to `frame/`.

x86_64 UEFI systems currently enter through Limine's
`EFI/BOOT/BOOTX64.EFI`, which converts the firmware handoff to
Multiboot2. aarch64 uses the Linux/U-Boot FDT entry ABI through direct boot or
NARF's `BOOTAA64.EFI` loader. CI exercises removable-media and native-package
paths through OVMF/AAVMF. Both package loaders authenticate their exact
configuration/kernel payload when signed: Limine's enrolled BLAKE2b policy on
x86_64 and a digest bound into the NARF loader on aarch64. See
[`docs/SECURE_BOOT.md`](../docs/SECURE_BOOT.md).

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: 1.
