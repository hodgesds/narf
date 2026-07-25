# boot — Bootloader handoff + early init

Accepts control from a bootloader, parses the memory map / ACPI /
devicetree, hands a `BootInfo` to `frame/`.

x86_64 UEFI systems currently enter through Limine's
`EFI/BOOT/BOOTX64.EFI`, which converts the firmware handoff to
Multiboot2. CI exercises that removable-media path through OVMF.
aarch64 still uses the Linux/U-Boot FDT entry ABI; its native EFI stub
is not implemented yet. Secure Boot-enforcing firmware is also not yet
supported because the loader and kernel-image signing flow is pending.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: 1.
