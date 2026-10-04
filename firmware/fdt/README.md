# firmware/fdt — Flattened Device Tree (FDT / DTB) Parser

`narf-firmware-fdt` parses the Flattened Device Tree — the DTB binary a
bootloader or hypervisor passes to the kernel to describe the hardware on
platforms that have no self-describing enumeration bus. On aarch64 this
is the primary hardware-discovery mechanism (the boot CPU enters with a
pointer to the blob); on x86_64-virt it can arrive through `fw_cfg`. The
crate implements the Devicetree Specification v0.4 / FDT structure
version 17.

The parser is pure-data and side-effect-free: it operates over a byte
slice covering the blob and never maps physical memory itself — callers
hand it the bytes. Everything in a DTB is stored big-endian per the
specification, so every multi-byte read goes through a big-endian helper.
Robustness against untrusted firmware is a first-class concern: the
header is validated (magic, version compatibility, total size), and
before any walker trusts an offset the crate checks that the struct,
strings, and memory-reserve blocks are properly aligned, in bounds, and
non-overlapping.

The blob has three regions the parser understands. The 40-byte header
carries the offsets and sizes of the other blocks and the boot CPU's
physical ID. The structure block is a token stream — begin-node,
end-node, property, nop, end — that encodes the device tree as a nested
hierarchy of nodes, each with a unit name and a set of properties; the
walker reconstructs this tree, resolving each property's name through an
offset into the separate strings block. The memory-reserve map lists
physical ranges the kernel must not allocate over. Beyond the raw walk,
the crate decodes the higher-level bindings the kernel needs — `reg`
address/size cells, `interrupts`, and the `/reserved-memory` ranges
(including their `no-map` and `reusable` flags) that carve out regions
for which the OS must not create a standard virtual mapping.

This crate is `no_std`. Its only dependencies are `narf-lib` and the
kernel test harness, reflecting that it is a self-contained byte-stream
decoder with no kernel-subsystem entanglements of its own.

- Spec: [`specification/spec.md`](./specification/spec.md)
