# mlx4 (ConnectX-3) driver specification

Ethernet bring-up driver for the Mellanox ConnectX-3 family
(MT27500 `15b3:1003`, ConnectX-3 Pro MT27520 `15b3:1007`), built from the
public ConnectX-3 PRM and checked against Linux mlx4. ConnectX-3 predates the ConnectX-4+ host command
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
8. `setup_datapath`: EQ → CQ → QP (RST→INIT→RTR→RTS), one physical MR over
   the datapath buffers, `SET_PORT` MTU + unicast MAC + legacy A0 receive steering, post the RX ring.
9. `INIT_PORT` (port 1), then `QUERY_PORT` for actual carrier.

## Datapath

One EQ, one CQ (shared TX+RX completions), one QP. TX: copy into a staging
slot, post a `Send` WQE for a software-checksummed frame, ring
the BAR2 send doorbell. RX: scatter WQEs into a pool; on a completion, read
the CQE (byte count + IP/TCP/UDP checksum status), mirror a copy to the
frame ring, deliver to the stack, repost the slot. `NicCaps::RX_CSUM` advertised; the RX checksum fast path marks `RxMeta::csum_l4` when
the CQE reports an IP-OK TCP/UDP frame whose folded checksum is `0xffff`.

## Test coverage (`src/mlx4/tests.rs`, group `drivers/net/mlx4`)

The kernel wire-format tests cover:

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
those objects always fit. The following still require confirmation on a
ConnectX-3 card at boot (QEMU cannot exercise them):

- End-to-end bring-up (firmware handshake, ICM mapping, `INIT_HCA` accept).
- Firmware acceptance of the sparse, size-aligned ICM profile. cMPT bank
  addresses now use Linux's type index at bits 25:24; host tests check it.
- Whether a pre-driver hardware reset is required on this board (left out
  deliberately — a blind, untested reset risks wedging bring-up; add it
  only once silicon shows it is needed).
- Live TCP/UDP throughput (the follow-on performance pass).

## Module interface and bounded waits

The `builtin` and `module` features select adapters around the same engine.
Module `register() -> i32` installs both PCI IDs and propagates failure.
BAR access, CPU/device DMA mappings, TX, RX and carrier updates use the
C KABI. The kernel build feature `narf-drivers-net/mlx4-module-only` leaves
PCI binding to the module. Network delivery uses `narf_netif_rx`; link
polling uses `narf_netif_set_link` with owner/device/ifindex validation.

The HCR waits check GO and the posted toggle, with a 10-second command
budget capped by the 60-second overall bring-up deadline. Command timeout
is terminal. Required SET_PORT failures abort initialization. QUERY_PORT
runs at most once per second after bring-up; cached carrier reflects it.
Completed mailboxes are freed; hardware-resident DMA and timed-out mailboxes
are pinned on every exit, including built-in failure. This trades retained
memory for avoiding DMA into freed pages. Reset/drain/rebind is open.

Host module tests execute 8193 firmware pages through 33 MAP_FA commands,
exercise TX and RX with non-identity DMA addresses, and reject stuck GO,
stale toggle and required port-command failure. `modules/e2e/wired` checks
loading the compiled module image inside NARF. Neither substitutes for a
cold boot and bidirectional traffic on the physical card.
