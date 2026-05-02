# mlx5 — Specification

> Status: **v0.4** (Stage 4: chained mailboxes + QUERY_HCA_CAP + NOP self-test).
>
> Clean-room driver for Mellanox / NVIDIA ConnectX-4 / 5 / 6 / 7
> family Ethernet + InfiniBand HCAs. Reference material: the
> public *Mellanox Programmer's Reference Manual* (PRM) — the
> register layout, command-interface format, WQE/CQE shapes
> are all openly published. No GPL Linux source consulted.

## 1. Purpose & scope

**Owns:** Bring-up of ConnectX-class HCAs through the documented
init-segment register set + 64-byte command-mailbox interface,
followed by EQ/CQ/QP/WQ allocation via firmware commands.

**Does NOT own (Stage 1):** RDMA verbs, fast-path WQE
construction, RoCE / steering tables, SR-IOV management.

## 2. Why mlx5 is clean-room friendly

Unlike GPUs (per-family register-offset sprawl), an mlx5 HCA
exposes a tiny, *uniform* surface:

- **BAR0 init segment** — ~32 documented dwords (fw_rev,
  cmdif_rev, cmd_dbell, initializing-bit, health buffer). Same
  layout across every ConnectX-4..7 SKU.
- **64-byte command mailbox** at `cmdq_addr` — input/output
  blocks both 64 bytes, opcode + opmod fields, all opcodes
  enumerated in the PRM.
- **BAR2 doorbell** — 4-KiB UAR (User Access Region) pages,
  uniform across the family.
- **WQE / CQE descriptors** in host RAM — formats fully
  documented per packet type (Send / Recv / RoCE-v2 / etc.).

There is no equivalent to amdgpu's "DCN block base shifts per
SKU" — one offset table covers the whole family.

## 3. Stage 1 scope

This stage lands the *passive* pieces:

- PCI match table covering ConnectX-4 (`0x1011`),
  ConnectX-4 Lx (`0x1013`), ConnectX-4 Lx VF (`0x1015`),
  ConnectX-5 (`0x1017`), ConnectX-5 Ex (`0x1019`),
  ConnectX-6 (`0x101B`), and ConnectX-6 Dx (`0x101D`),
  vendor `0x15B3` (Mellanox / NVIDIA).
- `InitSegment` decoder over a 4 KiB BAR0 buffer, surfacing:
  - `fw_rev_major` / `fw_rev_minor` / `fw_rev_subminor`
  - `cmd_interface_rev`
  - `cmdq_log_size` / `cmdq_addr` (host phys for the cmd
    mailbox)
  - `initializing` bit (set by FW while it is starting up;
    driver waits for it to clear).
  - 64-byte `health_buffer` raw block (parsed deeper in a
    later stage).
- `Mlx5Hca` struct with a `bring_up()` placeholder that:
  - claims BAR0,
  - decodes the init segment,
  - polls the initializing bit with a documented timeout,
  - records the bound driver against `narf-drivers`.
- All register fields decoded as **big-endian**, per PRM §1.4
  (the HCA register space is BE; driver byte-swaps on read).

What this stage does NOT do:

- Issue any firmware command (Stage 2).
- Allocate EQ/CQ/QP (Stage 3+).
- Bring up a queue or send/receive a packet.

## 4. Init-segment layout (BAR0)

The PRM defines the init segment at offset 0 of BAR0. Stage-1
fields:

| BAR0 off | name                | width | notes                |
|----------|---------------------|-------|----------------------|
| 0x0000   | `fw_rev_major`      | u16   | BE                   |
| 0x0002   | `fw_rev_minor`      | u16   | BE                   |
| 0x0004   | `fw_rev_subminor`   | u16   | BE                   |
| 0x0006   | `cmd_interface_rev` | u16   | BE                   |
| 0x0010   | `cmdq_addr_high`    | u32   | BE                   |
| 0x0014   | `cmdq_addr_low_sz`  | u32   | low 4 bits = log2 sz |
| 0x0018   | `cmd_dbell_vector`  | u32   | BE; one bit per slot |
| 0x001C   | `health_buffer[64]` | bytes | raw, parsed later    |
| 0x0FFC   | `initializing`      | u32   | bit 31 = initializing |

The "initializing" register at offset `0x0FFC` is the documented
gate: the driver MUST poll it and only proceed once bit 31
clears. The PRM specifies a 2-second worst-case wait before the
driver should declare the HCA dead.

## 5. Public API (Stage 1)

```rust
pub struct InitSegment { /* decoded fields above */ }
pub fn decode_init_segment(raw: &[u8; 0x1000]) -> InitSegment;
pub fn is_initializing(raw: &[u8; 0x1000]) -> bool;

pub struct Mlx5Hca { /* mmio + decoded segment */ }
impl Mlx5Hca {
    pub unsafe fn bring_up(dev: &BusDevice, cap: &Cap<…, Write>)
        -> Result<Self, Mlx5Error>;
    pub fn fw_rev(&self) -> (u16, u16, u16);
    pub fn cmd_interface_rev(&self) -> u16;
}
```

## 6. Smokes

Per the user's "co-locate driver smokes with the driver" rule,
all mlx5 smokes live in `drivers/net/src/mlx5/tests.rs` rather
than the shared `drivers/net/src/tests.rs`. They:

- assert the PCI match table is registered for the seven
  ConnectX-4..6 IDs,
- decode a synthetic 4 KiB init-segment buffer round-trip,
- verify `is_initializing` correctly reads bit 31 of the
  `0x0FFC` dword.

Live-silicon `bring_up` tests will land alongside these once we
have a server target with a ConnectX HCA in CI.

## 7. Future stages

- **Stage 2** — issue NOP / QUERY_HCA_CAP commands through the
  64-byte mailbox, verify `cmd_dbell_vector` polling.
- **Stage 3** — allocate UAR + EQ + CQ; subscribe to async
  events.
- **Stage 4** — allocate QP/SQ/RQ + send a single Ethernet
  frame.
- **Stage 5** — RSS steering table + multi-queue.
- **Stage 6+** — RoCE-v2, RDMA verbs surface.

## 8. Changelog

- **v0.1** (Stage 1): PCI match + init-segment decoder +
  initializing-bit poll + smokes co-located in driver dir.
- **v0.4** (Stage 4): multi-block mailbox chain support
  (`mailbox.rs` — `block_count_for`, `write_input_chain`,
  `read_output_chain`), `Mlx5Hca::issue_command_with_mailboxes`
  full-stack live transport (allocates input + output chain
  pages, populates input chunks, threads next-pointers through
  output blocks so FW can scatter its reply, posts the
  mailbox-CQE, polls completion, reassembles the contiguous
  output Vec<u8>), `query_hca_cap(group, current)` returning the
  raw 4-KiB response (structured decode lives in Stage 5),
  `HcaCapGroup` enum (GeneralDevice / EthernetOffload / Atomic /
  Roce / IpoibOffloads), and a NOP self-test posted from probe
  whose result lives on `Mlx5Hca::nop_selftest()` — non-fatal
  so a slow host doesn't fail bring-up.
- **v0.3** (Stage 3): cmdq DMA backing allocated in `bring_up`
  + `cmdq_addr_high` / `cmdq_addr_low_sz` registers programmed
  to point firmware at it (4-KiB-aligned phys, log_size = 0,
  one slot for synchronous bring-up). Live transport surface:
  `Mlx5Hca::issue_command_inline(op, input_modifier, &inline)`
  writes the CQE into slot 0, calls `ring_cmd_doorbell(1)` (BAR0
  + 0x18, BE-encoded slot mask), polls the slot's `status_own`
  byte until bit 0 clears, and decodes the inline reply through
  Stage-2 `decode_response`. DMA-mailbox transport: 512-byte
  `MailboxBlock` layout (480-byte payload + chain pointer at
  0x1F0/0x1F4 + block metadata at 0x1FC..0x200) and
  `build_cqe_with_mailboxes` for opcodes whose input + output
  exceed the inline 8-byte windows. Stage 4 will chain multi-
  block mailbox payloads + post the first NOP from probe.
- **v0.2** (Stage 2): 64-byte Command Queue Entry layout
  (`cmd.rs`) — builder for inline-mode CQEs, BE opcode + input
  modifier encoding, byte-XOR signature, ownership-bit poll,
  inline-response decoder, mapped status-code catalog
  (`CmdStatus`), `simulate_completion` test-harness helper for
  driving the decoder against synthesised replies. Opcodes
  surfaced: `Nop` (0x101) and `QueryHcaCap` (0x100).
  Live cmdq DMA + doorbell programming is deferred to Stage 3
  so the format can be locked + smoke-tested in isolation.

## 9. Stage 2 — command-mailbox layout

The Command Queue Entry (CQE) is a 64-byte structure laid out
according to PRM §3.5. All multi-byte fields are big-endian.
Software:

1. Builds a CQE in a 64-byte slot of the cmdq (allocated in
   Stage 3); the CQE has `status_own` bit 0 set to 1 ("HW owns").
2. Rings the `cmd_dbell` register at BAR0+0x18 with a bitmask of
   slot indices to launch.
3. Polls the slot's `status_own` byte until bit 0 clears.
4. Decodes the `command_output_inline` (16 B) + status code at
   offset 0x20.

Inline-mode CQEs are sufficient for opcodes whose input + output
both fit in 8 bytes each (NOP, simple QUERY_*). Larger commands
use DMA-mailbox pointers at offsets 0x08 / 0x30 — Stage 3.

### Status codes

| Raw | Variant         | Meaning                            |
|-----|-----------------|------------------------------------|
| 00  | `Ok`            | Command completed successfully     |
| 01  | `InternalErr`   | Firmware internal error            |
| 02  | `BadOp`         | Opcode unknown to firmware         |
| 03  | `BadParam`      | Bad input modifier / inline arg    |
| 04  | `BadSysState`   | HCA in wrong state for opcode      |
| 05  | `BadResource`   | Resource handle invalid            |
| 06  | `ResourceBusy`  | Resource currently in use          |
| 08  | `ExceedLim`     | Resource limit reached             |
| 09  | `BadResState`   | Resource in wrong state            |
| 0A  | `BadIndex`      | Index out of range                 |
| 0F  | `NoResources`   | Out of HW resources                |
| 50  | `BadInputLen`   | input_length mismatch              |
| 51  | `BadOutputLen`  | output_length mismatch             |
| —   | `Unknown(b)`    | Unmapped — preserves the raw byte  |
