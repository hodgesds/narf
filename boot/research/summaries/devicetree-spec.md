# Devicetree Specification

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## Overview

The Devicetree Specification defines a language and binary format (Device Tree Binary, DTB) for describing hardware to bootloaders and kernels. Unlike ACPI tables (which are drivers and services), devicetree is a static, declarative description of hardware topology and properties. For NARF's boot subsystem, devicetree offers a lightweight, deterministic alternative to ACPI, especially on embedded and custom platforms.

## Key Mechanisms

**Devicetree Structure:**
- A devicetree is a hierarchical graph of nodes representing system components (CPUs, memory, devices, buses)
- Each node has a unit name and address (e.g., `cpu@0` for CPU 0)
- Properties are key-value pairs providing configuration (e.g., `clock-frequency = <...>`, `reg = <...>`)
- Standard properties include `compatible` (driver binding), `reg` (address/size), `interrupts` (IRQ binding)
- The root node contains system-level properties; child nodes represent devices and buses

**Binding Contracts:**
- Each device has a `compatible` property listing driver bindings in order of preference (e.g., `compatible = "samsung,exynos-gpio", "gpio-generic"`)
- Bootloaders and OS select drivers based on compatible strings; if the primary is unavailable, fallback options are tried
- Binding specifications (published separately) define which properties are required/optional for each device class
- This allows OS-independent hardware description; different OSes can consume the same devicetree

**Binary Format (DTB):**
- Devicetree source (.dts) is compiled into a compact binary format (.dtb)
- DTB format includes a header, device tree structure block, strings block, and reserved memory block
- The firmware or bootloader loads DTB into memory at a known address and passes a pointer to the kernel
- Kernels can also modify DTB at runtime before passing to drivers (e.g., removing disabled nodes)

**Standard Properties:**
- `reg` encodes address and size of device memory/ports; format depends on parent's `#address-cells` and `#size-cells`
- `interrupts` lists IRQ numbers; format depends on parent interrupt controller's binding
- `clocks`, `resets`, `power-domains` reference other nodes, enabling dependency tracking
- `status` (okay, disabled, fail, fail-sss) indicates whether a device is available

## Critical Invariants

1. **Staticness**: Devicetree is static at boot time; properties do not change after kernel initialization. This differs from ACPI, which includes runtime services.

2. **Pointer-free references**: Device references use phandles (opaque 32-bit IDs) rather than memory pointers, enabling relocation and GC-safe structures.

3. **Binding determinism**: Driver selection is deterministic; the OS always chooses the first matching `compatible` entry.

4. **Memory layout independence**: Devicetree descriptions do not encode absolute addresses; the `reg` property is interpreted by parent context (memory controller, bus bridge).

5. **Backward compatibility**: New properties are additive; removing or changing existing properties breaks compatibility. Bindings must define a clear versioning strategy.

## Performance Trade-Offs

**Parsing speed:**
- DTB parsing is much faster than ACPI parsing because DTB is a simple tokenized format
- Parsing time is O(nodes) with minimal branching; ACPI is O(tables * complexity)
- On embedded systems, this difference is negligible; on large servers with complex ACPI, devicetree saves significant boot time

**Completeness vs. simplicity:**
- ACPI is Turing-complete (includes AML bytecode), enabling complex hardware behavior description
- Devicetree is declarative; complex logic must be implemented in drivers
- This trades flexibility for simplicity; devicetree kernels often have smaller boot code but may require driver updates for new hardware features

**Memory overhead:**
- DTB is typically 10-50 KB; ACPI tables can be 1-10 MB
- Smaller DTB means less firmware memory usage and faster copying to kernel memory

**Flexibility:**
- ACPI allows runtime service calls, supporting hardware discovery and state changes
- Devicetree is immutable post-boot; all discovery must happen during initialization
- For NARF's deterministic model, immutability is preferable; for general-purpose kernels, ACPI's flexibility is valuable

## Pitfalls and Warnings

1. **Bootloader responsibility**: Devicetree must be provided by the bootloader or firmware. If the bootloader is missing, broken, or outdated, the kernel cannot boot. ACPI shifts this responsibility to hardware manufacturers, though not always successfully.

2. **Binding version mismatch**: If a kernel driver implements binding v2 but the firmware provides devicetree using binding v1, the driver may ignore critical properties. Versions must be negotiated explicitly.

3. **Out-of-tree bindings**: Linux accepts new devicetree bindings informally; without centralized validation, incompatible bindings can emerge, fragmenting the ecosystem.

4. **Phandle collisions**: If a DTB is constructed carelessly, phandles can collide (two devices with the same phandle). The DTB format has no built-in validation; parsers must assume DTB is trustworthy.

5. **Memory node semantics**: The `/memory` node describes physical RAM, but multiple memory nodes or hotplug-capable memory introduce ambiguity. Kernels vary in how they interpret these; NARF should have explicit semantics.

6. **Interrupt wiring complexity**: Complex interrupt controllers (with multiple levels, shared lines, or MSI) require careful binding design. Incorrect wiring in DTB leads to lost or miswired interrupts.

7. **No integrity protection**: DTB is not signed or checksummed. If the bootloader or firmware corrupts DTB in memory, the kernel has no way to detect it.

## Recommendations for NARF Boot Designers

**Adopt:**
- Devicetree as the primary hardware description format for deterministic, embedded-friendly boot
- Static, immutable hardware description to align with NARF's predictable isolation model
- Phandle-based device references (not memory addresses) for capability safety
- Binding specifications per device class; require explicit versioning in bindings
- DTB integrity validation at boot time (checksums or signatures from bootloader)

**Avoid:**
- Relying on bootloader to provide DTB; validate DTB format and content before use
- Mixing ACPI and devicetree in the same boot path (confusing, error-prone)
- Out-of-tree or ad-hoc bindings; maintain a canonical registry of supported bindings
- Modifying DTB at runtime (defeats predictability)
- Assuming phandles are globally unique; validate phandles at boot

**Specific to NARF:**
- Extend devicetree with capability-aware bindings: each device node includes a capability ID or domain assignment
- Use DTB to initialize the capability graph at boot; firmware can assert which domains own which devices
- Add MTE tag metadata to `reg` properties, specifying tag assignments for memory regions
- Validate all DTB data against a schema before consuming it; don't trust bootloader
- Store devicetree in read-only memory region after boot; prevent runtime modifications

<https://www.devicetree.org/specifications/>
