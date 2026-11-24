# drivers/net/mlx4 — Mellanox ConnectX-3 NIC

Clean-room driver for the Mellanox ConnectX-3 family (MT27500 `15b3:1003`
and ConnectX-3 Pro MT27520 `15b3:1007`) in Ethernet mode. ConnectX-3 is a
different device generation from ConnectX-4/5/6 (`../mlx5`): it speaks the
legacy **Hardware Command Register** (HCR) firmware interface and the
`mlx4` ICM context-memory model, sharing no wire formats with the
ConnectX-4+ host command queue — so it lives in its own crate.

Clean-room from the public ConnectX-3 Programmer's Reference Manual (PRM);
register layouts, command opcodes and context/descriptor formats are
hardware facts, never taken from GPL source.

## Layout

| module | contents |
|---|---|
| `mlx4.rs` | controller core: HCR command transport, bring-up sequence, datapath (TX/RX pumps), `HwNic`/`Interface`, probe/registration |
| `cmd.rs` | HCR register layout, opcodes, GO-word + status encode/decode |
| `fw.rs` | `QUERY_FW` / `QUERY_DEV_CAP` / `QUERY_ADAPTER` output decoders |
| `icm.rs` | ICM VPM mailbox, `INIT_HCA` mailbox, sequential ICM layout planner |
| `eq.rs` | Event-queue context, EQE decode, consumer doorbell |
| `cq.rs` | Completion-queue context, CQE decode (+ Ethernet RX checksum), arm/CI doorbells |
| `qp.rs` | QP context (Ethernet MLX transport) + RST→INIT→RTR→RTS modify mailbox |
| `mr.rs` | MTT entries, MPT context, lkey/rkey swizzle |
| `port.rs` | `SET_PORT` (GENERAL/MAC_TABLE), `QUERY_PORT` decode, link-speed map |
| `wqe.rs` | TX control+data WQE, RX scatter WQE, checksum-offload flags, doorbell words |
| `wire.rs` / `bit_field.rs` | big-endian scalar + MSB-first bit-field helpers |
| `tests.rs` | wire-format round-trips + TCP/UDP TX/RX checksum-offload smokes |

## Datapath

Single Ethernet queue (one EQ/CQ/QP). TX copies the frame into a staging
slot and posts a send WQE with IP + TCP/UDP checksum offload; RX posts
scatter WQEs into a staging pool and, on completion, mirrors a copy to the
frame ring and delivers the frame to the kernel stack via
`publish::deliver_rx`. The driver `publish_netdev`s an `eth%d` interface and
installs a synchronous CQ drain (`install_rx_drain`) for ARP/TCP-handshake
busy-waits, exactly like the sibling mlx5 and e1000 drivers. TX/RX checksum
offload is advertised (`NicCaps::TX_CSUM | RX_CSUM`).

## Dual-build

Built-in by default; `--no-default-features --features module` builds a
loadable `narf_drivers_net_mlx4.ko` that registers the ConnectX-3 id
through the `narf_register_pci_driver` KSYMTAB export (registration-only
until the datapath ABI is exported to modules, mirroring mlx5).

## Validation

QEMU emulates no ConnectX-3 device, so CI coverage is the `tests.rs`
wire-format suite under `drivers/net/mlx4` — every command, context and
descriptor is byte-checked, and the TCP/UDP TX checksum-offload request +
RX checksum decode are asserted directly. End-to-end bring-up and live
traffic (and the ICM-profile sizing, driver UAR index, and any
reset-sequence tuning) are validated on ConnectX-3 silicon at boot;
see [`../specification/mlx4.md`](../specification/mlx4.md).
