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

## Power management (#839)

`src/sdhci/pm.rs` joins the `power` device_pm fan-out at probe:
suspend refuses new I/O, drains the controller and cuts the SD clock
+ card power; resume re-runs the bring-up hardware sequence and
re-identifies the card, revalidating CID + capacity + CCS before
serving I/O again (a mismatch keeps the controller suspended; a card
removed while suspended unpublishes `sdhci0`). After 5 s idle the
Stage::Late monitor task gates the card clock + power; the next block
I/O ungates synchronously. Fixture-validated end to end in `pm.rs`.

- Spec: [`../specification/spec.md`](../specification/spec.md)
