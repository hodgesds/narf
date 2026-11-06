# drivers/storage/rtsx — Realtek PCIe SD/MMC card reader

`narf-drivers-storage-rtsx` drives the Realtek RTSX PCIe SD/microSD
card reader (Realtek vendor `0x10EC`). It maps BAR0 and talks to the
chip through two mechanisms: a host command buffer — a DMA-coherent
page of up to 256 4-byte `(type, addr, mask, data)` tuples dispatched
via HCBAR/HCBCTLR — and a 512-byte on-chip ping-pong buffer used for
R2 (CID/CSD) responses and single-block transfers (CMD17/CMD24). The
ADMA ring-buffer path for multi-block transfers is not programmed by
this driver.

The implementation lives in `src/rtsx/`: `mod.rs` (controller,
transport trait, card-slot polling, PCI probe), `regs.rs`, `cmd.rs`,
`card.rs`, `block_bridge.rs`, and `fixture_tests.rs`. All hardware
access goes through the `RtsxTransport` trait, with the production
implementation over the BAR0 mapping and command DMA page and fixtures
over a register-level model of the chip and card.
`src/rtsx/block_bridge.rs` wraps an enumerated card as a
`BlockDeviceSync` and registers it in the block-device registry as
`mmcblk0`. The crate is dual-build (built-in or loadable `.ko`).

- Spec: [`../specification/spec.md`](../specification/spec.md)
