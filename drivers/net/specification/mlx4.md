# mlx4 (ConnectX-3) driver specification

Clean-room Ethernet driver for the Mellanox ConnectX-3 family
(MT27500 `15b3:1003`, ConnectX-3 Pro MT27520 `15b3:1007`), built from the
public ConnectX-3 PRM. ConnectX-3 predates the ConnectX-4+ host command
queue that `mlx5` implements; it uses the legacy HCR command register and
the ICM context-memory model, so none of the mlx5 wire formats apply.

## Device model (how it differs from mlx5)

| aspect | ConnectX-3 (mlx4) | ConnectX-4+ (mlx5) |
|---|---|---|
| command interface | 28-byte HCR register window in BAR0 (`0x80680`), GO/token/status | 64-byte command entries in a host command queue |
| context memory | ICM — driver pages mapped to firmware virtual addresses (MAP_FA/MAP_ICM) | host-owned, referenced per object |
| doorbells | BAR2 UAR pages (send `+0x14`, CQ `+0x20`, EQ `+0x800+8·(eqn%4)`) | BAR0 UAR region |
| TX WQE | ctrl seg + data seg; csum bits in `srcrb_flags` | ctrl seg + data seg; csum via eth seg |

## Bring-up sequence (`run_bringup`)

1. `QUERY_FW` — firmware version, ICM firmware-area page count.
2. `MAP_FA` — map the firmware area's ICM pages (VPM mailbox).
3. `RUN_FW`.
4. `QUERY_DEV_CAP` — object counts, entry sizes, port count.
5. Plan ICM layout → `SET_ICM_SIZE` → `MAP_ICM_AUX` → `MAP_ICM` per table.
6. `INIT_HCA` — hand firmware the table bases + log sizes.
7. `QUERY_ADAPTER` — board id / interrupt pin (informational).
8. `INIT_PORT` (port 1).
9. `setup_datapath`: EQ → CQ → QP (RST→INIT→RTR→RTS), one physical MR over
   the datapath buffers, `SET_PORT` MTU + unicast MAC, post the RX ring.

## Datapath

One EQ, one CQ (shared TX+RX completions), one QP. TX: copy into a staging
slot, post a `Send` WQE with `MLX4_WQE_CTRL_IP_CSUM | TCP_UDP_CSUM`, ring
the BAR2 send doorbell. RX: scatter WQEs into a pool; on a completion, read
the CQE (byte count + IP/TCP/UDP checksum status), mirror a copy to the
frame ring, deliver to the stack, repost the slot. `NicCaps::TX_CSUM |
RX_CSUM` advertised; the RX checksum fast path marks `RxMeta::csum_l4` when
the CQE reports an IP-OK TCP/UDP frame whose folded checksum is `0xffff`.

## Test coverage (`src/mlx4/tests.rs`, group `drivers/net/mlx4`)

QEMU emulates no mlx4 device, so coverage is wire-format round-trips plus
the TCP/UDP acceptance that matters for the driver:

- HCR GO-word / status / pending encoding.
- `QUERY_FW` / `QUERY_DEV_CAP` / `QUERY_ADAPTER` decode.
- VPM mailbox + `INIT_HCA` field placement; ICM layout consistency.
- MTT entry + lkey swizzle round-trip; MPT context.
- EQ/CQ/QP context field placement; EQE/CQE decode + ownership phase.
- `SET_PORT` GENERAL + MAC-table build; `QUERY_PORT` + link-speed decode.
- **TX WQE requests IP + TCP/UDP checksum offload** and points its data
  segment at the staging buffer; a plain send leaves the bits clear.
- **RX CQE reports TCP and UDP L4 checksum verified** on the IP-OK /
  `0xffff` fast path; a partial checksum does not claim OK; a bad-FCS
  completion is flagged for drop.
- TX staging-slot recycle; PCI match table.

## Silicon validation (open)

The wire encodings are unit-validated, and the resource numbers are now
derived from `QUERY_DEV_CAP` rather than hardcoded: the driver's doorbell
UAR page is the first page past `reserved_uars`; the EQ/CQ/QP/MPT numbers
and the MTT base sit at the first index past each resource's reserved
range; and the ICM context tables are sized to cover `reserved + 1` so
those objects always fit. The following are still confirmed on a
ConnectX-3 card at boot (QEMU cannot exercise them):

- End-to-end bring-up (firmware handshake, ICM mapping, `INIT_HCA` accept).
- The cMPT sub-table placement within the ICM layout.
- Whether a pre-driver hardware reset is required on this board (left out
  deliberately — a blind, untested reset risks wedging bring-up; add it
  only once silicon shows it is needed).
- Live TCP/UDP throughput (the follow-on performance pass).
