# drivers/net — Research

## Primary sources

- **Intel 82574L / E1000 datasheet** — candidate first real-HW target.
  <https://www.intel.com/content/www/us/en/products/docs/network-io/ethernet/10-25-40-gigabit-adapters/82574-gbe-controller-datasheet.html>
- **Intel I225/I226 (IGC) datasheet** — modern candidate.
- **VirtIO 1.2 §5.1 — virtio-net** (shared with `drivers/virtio/`).

## Secondary sources

- **smoltcp** — `no_std` Rust TCP/IP stack; if we ever need an in-kernel
  stack this is the go-to. <https://github.com/smoltcp-rs/smoltcp>
- **DPDK PMDs** — polled-mode driver idioms.
- **Linux `drivers/net/ethernet/intel/*`**.

## Distilled summaries

- `summaries/intel-82574l-datasheet.md` — Intel 82574L NIC hardware architecture

## Fetched this round (2026-04-22)

- `summaries/intel-82574l-datasheet.md` — Intel 82574L real-hardware target

## Open research questions

- Poll-mode vs. interrupt-driven default for RX.
- Which NIC to prototype against in QEMU for CI parity.
