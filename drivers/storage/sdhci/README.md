# drivers/storage/sdhci — SDHCI SD/MMC host controller

`narf-drivers-storage-sdhci` is the clean-room SD host controller
driver, from the SD Host Controller Simplified Specification v3.00 and
the SD Physical Layer Simplified Specification (both free from
sdcard.org; section numbers in the source refer to them). It performs
the full controller bring-up over the BAR0 MMIO window — software
reset, power-on, init clock, and the CMD0/CMD8/ACMD41/CMD2/CMD3/CMD7
identification handshake — plus single-block PIO transfers (CMD17/
CMD24), with response and register decoding borrowed from
`narf-drivers-storage-core` (`sd_proto`).

The implementation lives in `src/sdhci.rs` (`Sdhci`, `SdCard`,
`SdhciTransport` with its `MmioTransport`, `SdhciError`, `probe()`),
with `SdhciBlockDevice` implementing `BlockDeviceSync` for the block
layer and `src/sdhci/fixture_tests.rs` holding the fixtures. The crate
is dual-build (built-in or loadable `.ko`, `src/module_probe.rs`).

- Spec: [`../specification/spec.md`](../specification/spec.md)
