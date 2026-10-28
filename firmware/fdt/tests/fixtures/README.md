# FDT test fixtures

## `qemu-virt.dtb`

A real Flattened Device Tree blob emitted by QEMU for its `virt`
machine — the fixture the `smoke_fdt_real_qemu_virt_*` kernel smokes
in `firmware/fdt/src/tests.rs` are pinned against. The older smokes
in that file build synthetic blobs in code; this fixture exists so
the parser is also held against bytes a real firmware-class
generator produced (programme step 1 of #1048).

Provenance:

- Generator: QEMU 8.2.2 (`qemu-system-aarch64`), `-machine
  virt,gic-version=3,dumpdtb=...`
- Machine configuration: `-cpu cortex-a72 -smp 4 -m 1024`
- Content: 62 nodes — GICv3 + ITS, 4× Cortex-A72 with PSCI enable,
  PL011 UART, PL031 RTC, PL061 GPIO, 32 virtio-mmio slots, PCIe host,
  CFI flash (2× 64 MiB banks), `/chosen` with `stdout-path` only.

QEMU writes the blob into a 1 MiB buffer and sets `totalsize` to the
buffer size; every byte past the end of the strings block in that
buffer is zero. The checked-in copy is trimmed to the content end
(8023 bytes) with `totalsize` adjusted to match. The header fields,
memory-reserve map, structure block, and strings block are
byte-identical to QEMU's output.
