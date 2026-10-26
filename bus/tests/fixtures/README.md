# bus DT test fixture

## `qemu-virt.dtb`

Byte-identical copy of `firmware/fdt/tests/fixtures/qemu-virt.dtb`
— a real Flattened Device Tree blob emitted by QEMU 8.2.2
(`-machine virt,gic-version=3,dumpdtb=...`, `-cpu cortex-a72
-smp 4 -m 1024`, 8023 bytes after the documented trim; full
provenance in the firmware crate's copy of this README).

The copy lives here so the `bus` decoder census smoke
(`smoke_bus_dt_decode_fixture_census`) pins `dt::decode_devices`
against the same real-world bytes the parser is pinned against,
without a cross-crate path dependency between the two crates'
test trees. If the firmware fixture is ever regenerated, this
copy must be refreshed in the same commit and the census smoke's
expectations re-derived from the new blob.
