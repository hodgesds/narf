# drivers/net/mlx4 — Mellanox ConnectX-3 NIC

Clean-room driver for the Mellanox ConnectX-3 family (MT27500 `15b3:1003`
and ConnectX-3 Pro MT27520 `15b3:1007`) in Ethernet mode. ConnectX-3 is a
different device generation from ConnectX-4/5/6 (`../mlx5`): it speaks the
legacy **Hardware Command Register** (HCR) firmware interface and the
`mlx4` ICM context-memory model, sharing no wire formats with the
ConnectX-4+ host command queue — so it lives in its own crate.

Based on the public ConnectX-3 PRM and cross-checked against Linux mlx4
(`cmd.c`, `fw.c`, `profile.c`, `en_rx.c`, `en_resources.c`, `port.c`).
The repository and these adaptations are GPL-compatible.

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
slot and posts a send WQE for a software-checksummed frame; RX posts
scatter WQEs into a staging pool and, on completion, mirrors a copy to the
frame ring and delivers the frame to the kernel stack via
`publish::deliver_rx`. The driver `publish_netdev`s an `eth%d` interface and
installs a synchronous CQ drain (`install_rx_drain`) for ARP/TCP-handshake
busy-waits, exactly like the sibling mlx5 and e1000 drivers. RX checksum
validation is advertised; TX offload is disabled on this plain-frame path.

## Dual-build

Built-in by default; `--no-default-features --features module` builds the
shared HCR/ICM/packet engine as a module, with per-device DMA/BAR grants,
TX callback and RX/link poller. Both `15b3:1003` and `15b3:1007` register.
`register() -> i32` propagates registration failure. This is a single-port,
single-queue Ethernet bring-up implementation; it needs silicon validation.

Build with `cargo xtask build-module --package narf-drivers-net-mlx4
--no-default-features --features module --out target/mlx4-bringup.ko`
(on one command line); add `--arch=aarch64` for that target. Select
`narf-drivers-net/mlx4-module-only` in the loading kernel to suppress its
built-in PCI registration. Modules must be built/stamped for that kernel's
ABI and loaded under the normal module trust policy.

ConnectX-3 runs onboard flash firmware. `QUERY_FW` specifies host memory
mapped by `MAP_FA`; it does not consume a Linux firmware file. Mapping is
batched at 256 entries per mailbox, without a one-mailbox size limit.
Commands require both GO-clear and the expected toggle. Each command has
a 10-second deadline within a 60-second bring-up budget. Timeout disables
further commands. Resident DMA, including a timed-out mailbox, stays pinned
until reboot because a reset/drain proof is not implemented. Completed
mailboxes are freed. Warm rebind and unload/reload on hardware remain open.

## Validation

`cargo test -p narf-drivers-net-mlx4 --no-default-features --features module
--lib` tests the compiled module against a KABI/HCR/DMA model. It covers a
32 MiB + 4 KiB firmware area, separate CPU/bus addresses, TX/RX, empty-CQ
ownership, receive doorbells, missing completion, stale toggle and a failed
required SET_PORT command. QEMU `modules/e2e/wired` loads/unloads the real
`.ko` files and checks symbol resolution and invalid-token rejection. The
existing `drivers/net/mlx4` tests cover wire formats. QEMU has no ConnectX-3
model, so these checks do not prove hardware bring-up or live traffic;
see [`../specification/mlx4.md`](../specification/mlx4.md).
