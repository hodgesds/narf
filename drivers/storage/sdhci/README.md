# drivers/storage/sdhci — SDHCI SD/MMC host controller

`narf-drivers-storage-sdhci` is the clean-room SD host controller
driver, from the SD Host Controller Simplified Specification v3.00 and
the SD Physical Layer Simplified Specification (both free from
sdcard.org; section numbers in the source refer to them). It performs
the full controller bring-up over the BAR0 MMIO window — software
reset, power-on, init clock, and the CMD0/CMD8/ACMD41/CMD2/CMD3/CMD7
identification handshake — then negotiates the data path (#837):
25 MHz clock raise from the Capabilities base clock, 4-bit bus
(ACMD51 SCR probe + ACMD6), and multi-block CMD18/CMD25 with
Auto-CMD12 over SDMA/ADMA2 (coherent bounce buffer, PIO fallback),
with response and register decoding borrowed from
`narf-drivers-storage-core` (`sd_proto`). UHS-I (#838, stacked on
#837) follows the bus-width step: ACMD41 S18R + CMD11 1.8 V
signalling switch, CMD6 mode switch (SDR12/SDR25/SDR50/SDR104/DDR50),
and CMD19 tuning with SDR25 fallback — a failed switch power-cycles
the card and re-identifies at 3.3 V without UHS.

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

Card detect (#836): an empty slot at probe installs the controller
with no card known instead of failing probe, and a Stage::Late poll
task (`spawn_card_poll_task`, 500 ms cadence — no IRQ handler is
registered, as in RTSX) reconciles the Present State card level with
the known card: identify-on-insert, teardown-on-remove (block devices
`sdhci0` + `sdhci0p<N>` withdrawn, CMD/DAT lines reset). The Card
Insertion / Removal interrupt status bits (SDHCI 3.00 §2.2.18) are
enabled and acknowledged, but the Present State level is
authoritative — a command's blanket NIS clear can wipe an edge before
the poller sees it. The controller itself is never uninstalled: only
the card state toggles, so the install-once address invariant holds.

- Spec: [`../specification/spec.md`](../specification/spec.md)
