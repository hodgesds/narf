# boot — Bootloader handoff + early init

Accepts control from a bootloader, parses the memory map / ACPI /
devicetree, hands a `BootInfo` to `frame/`.

x86_64 native packages and `cargo xtask efi-image` embed kernel/initramfs/config
in NARF's own EFI application and emit a Multiboot2 handoff without Limine; see
[build, run, and install instructions](../docs/NATIVE_UEFI.md).
aarch64 uses the Linux/U-Boot FDT entry ABI through direct boot or
NARF's `BOOTAA64.EFI` loader. CI exercises removable-media and native-package
paths through OVMF/AAVMF. Both package loaders authenticate their exact
configuration/kernel payload when signed: the embedded PE section on x86_64
and a digest bound into the NARF loader on aarch64. Existing x86 media and
explicit legacy packages retain Limine's enrolled configuration/kernel policy. See
[`docs/SECURE_BOOT.md`](../docs/SECURE_BOOT.md).

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: 1.
