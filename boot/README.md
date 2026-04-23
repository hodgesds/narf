# boot — Bootloader handoff + early init

Accepts control from a bootloader, parses the memory map / ACPI /
devicetree, hands a `BootInfo` to `frame/`.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: 1.
