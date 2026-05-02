# mlx5 — Specification

> Status: **v0.15** (Stage 15: async events — EQE polling + EQ doorbell).
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
- **v0.15** (Stage 15): async events. `mlx5/eqe.rs` lays out
  the 64-byte EQE — event_type at byte 0x01, event_sub_type
  at 0x03, owner bit (bit 0 of byte 0x3F). Typed `EventType`
  catalog (CompletionEvent / PathMigrated / CommErrorReceived
  / SendQueueDrained / SrqLastWqeReached / PortStateChange /
  CommandInterfaceCompletion / PageRequest / SrqLimitReached /
  NicVportChange / Unknown(raw)) per PRM §16.4.5.
  `pop_event(eq_bytes, capacity, consumer)` mirrors
  `pop_completion`. `Mlx5Hca::poll_eq(eq_number)` reads from the
  EQ DMA backing at the cursor, advances on success.
  `arm_eq(uar_page, eq_number, consumer)` writes the EQ doorbell
  at UAR offset 0x40 to ack consumed events. `LiveEq` gains a
  `consumer` cursor. Three smokes: EQE decode round-trip,
  EventType catalog, pop_event ring walk.
- **v0.14** (Stage 14): flow-steering primitives — Transport
  Interface Receive (TIR), Transport Interface Send (TIS),
  Receive Queue Table (RQT). Nine new opcodes spanning the
  CREATE/DESTROY pairs plus `SetFlowTableRoot`.
  `mlx5/steering.rs` lays out:
  - 256-byte TIR context with disp_type byte (TIR_DISP_DIRECT
    /TIR_DISP_INDIRECT_RQT) at 0x04, inline_rqn (BE u32 at
    0x1C), transport_domain (BE u32 at 0x24);
  - 256-byte TIS context with priority byte at 0x00 +
    transport_domain at 0x24;
  - RQT context with max_size + actual_size at 0x10 / 0x14
    followed by an N-entry 4-byte BE rqn list at 0x20.
  `Mlx5Hca::create_tir`, `create_tis`, `create_rqt` post via
  Stage-7 input-mailbox transport and return the FW-assigned
  IDs. Validation: RqtError::TooLarge for > 128 RQs in an RQT.
  Four smokes: opcode pins, TIR layout (direct + indirect
  paths), TIS layout, RQT layout + validation.
- **v0.13** (Stage 13): memory-region registration. Two new
  opcodes `CreateMkey` (0x200) + `DestroyMkey` (0x202).
  `mlx5/mkey.rs` lays out the 64-byte mkey context — access
  flags (high nibble of byte 0x00, MKC_ACCESS_LOCAL_WRITE/
  LOCAL_READ/REMOTE_READ/REMOTE_WRITE), pd (BE u32 at 0x04 low
  24 bits), start_addr (BE u64 at 0x18), length (BE u64 at 0x20),
  log_page_size (BE u32 at 0x2C) — followed by an N-entry
  8-byte BE phys-addr list at offset 0x40.
  `Mlx5Hca::create_mkey(params, &pages)` posts CREATE_MKEY and
  returns the L_KEY (mkey_index << 8); WQE pointer-data segments
  carry this directly. `destroy_mkey(l_key)` releases. New error:
  `MkeyBuild`. Four smokes: full layout round-trip, validation
  (BadPd / NoPages), L_KEY packing math, opcode pins.
- **v0.12** (Stage 12): per-vport NIC context (MAC + MTU). Two
  new opcodes `QueryNicVportContext` (0x754) +
  `ModifyNicVportContext` (0x755). `mlx5/vport.rs` decodes the
  256-byte vport context — MTU as BE u32 at byte 0x24,
  permanent_mac (6 B at 0xF4) + current_mac (6 B at 0xFA).
  `Mlx5Hca::query_nic_vport_context()` + `set_mtu(mtu)` live
  wrappers. `refresh_nic_state()` caches MAC + MTU on the
  driver. `impl HwNic for Mlx5Hca` plugs the driver into the
  shared `narf-drivers-net` registry alongside e1000 / r8169 /
  qcnfa765. New error: `VportDecode`. Four smokes.
- **v0.11** (Stage 11): high-level `post_send` / `post_recv` /
  `poll_cq`. `mlx5/ring.rs` factors the SQ/RQ/CQ ring layout
  into pure-data helpers: `WQE_STRIDE` = 64 (16-byte ctrl + up
  to 3 16-byte data segments — `MAX_DATA_SEGS_PER_WQE` = 3),
  `CQE_STRIDE` = 64, `sq_offset_of` / `rq_offset_of` /
  `cq_offset_of` index calculators, `sq_size_bytes` /
  `rq_size_bytes` for QP-buffer region sizing (SQ first, RQ
  follows). `IoVec { va, l_key, len }` scatter/gather descriptor.
  `build_send_wqe(qp, idx, opcode, cqe_req, &iovecs)` produces
  a complete 64-byte send WQE with control segment + data
  segments; `build_recv_wqe(&iovecs)` produces the 64-byte recv
  WQE (segment-count u16 BE at offset 0 + data segments).
  `pop_completion(cq_bytes, capacity, consumer)` walks the CQ
  ring at the consumer cursor and returns the first SW-owned
  CQE + advanced consumer. `QpParams::uar_page` records the
  UAR bound to the QP for SQ doorbells.
  Live transport on `Mlx5Hca`: `post_send(qp_num, opcode,
  cqe_req, &iovecs)` builds the WQE, copies it into the SQ
  slot at `sq_tail`, advances the tail, and rings the SQ
  doorbell via the QP's `uar_page`. `post_recv(qp_num,
  &iovecs)` does the same against the RQ region. `poll_cq(
  cq_num)` reads the CQE at the CQ's consumer cursor, returns
  `None` if HW still owns it, otherwise decodes + advances the
  cursor. New errors: `RingBuild(RingError)`, `UnknownQp`,
  `UnknownCq`. `LiveQp` gains `sq_tail` / `rq_tail`; `LiveCq`
  gains `consumer`.
  Five new smokes: ring-offset arithmetic + wraparound, send-WQE
  layout for a 2-iovec list (ds = 1 + 2, qp_num + wqe_idx in
  control, both data segments round-trip), recv-WQE layout
  (segment-count BE at 0x00 + data seg at 0x10), validation
  rejection paths (NoSegments / TooManySegments for both
  send + recv), pop_completion walks a synthetic 8-CQE ring
  (slot 0 SW-owned → returned + cursor advances; slot 1
  HW-owned → None).
- **v0.10** (Stage 10): WQE / CQE wire format work + SQ
  doorbell. `mlx5/wqe.rs` lays out the 16-byte send-WQE control
  segment (`build_ctrl_segment(opcode, qp_num, wqe_idx, ds,
  cqe_req, signature)` — opcode at bits[7:0] of dword 0, wqe_idx
  at bits[23:8] of dword 0, qp_num at bits[31:8] of dword 1, ds
  count at bits[7:0] of dword 1, signature at bits[31:24] of
  dword 2) plus the 16-byte pointer-data segment (`build_data_seg_ptr(
  byte_count, l_key, va)` — four BE u32 dwords). `SendOpcode`
  enum surfaces NOP / SND_INV / RDMA_WRITE / SEND / SEND_IMM /
  RDMA_READ / ATOMIC_CS / ATOMIC_FA at their PRM-pinned values.
  `mlx5/cqe.rs` lays out the 64-byte CQE — `byte_count` (BE u32
  at 0x14), `status` (byte 0x37), `wqe_counter` (BE u16 at 0x38),
  `qp_op_own` (BE u32 at 0x3C: bits[31:8] qp_num, bits[7:4]
  opcode, bit[0] owner). `decode_cqe` returns a typed `CqeView`;
  `is_hw_owned` polls bit 0 of byte 0x3F. `CqeOpcode` enum
  (Requester / ResponderRdmaWrite / ResponderSend / Resize /
  NoOp / Error) + `CqeStatus` catalog (Success / LocalLengthError
  / LocalQpOpError / LocalProtectionError / WrFlushedError /
  MwBindError / BadResponseError / LocalAccessError /
  RemoteInvalidRequest / RemoteAccessError / RemoteOpError /
  Unknown(raw)). `simulate_completion` test-harness helper.
  `Mlx5Hca::ring_sq_doorbell(uar_page, qp_num, wqe_idx)` writes
  to UAR offset 0x800 — the documented SQ-doorbell offset within
  a UAR page; doorbell value packs qp_num in high 24 bits and
  the wqe_idx low byte. Live `post_send` / `post_recv` /
  `poll_cq` higher-level wrappers will land in Stage 11 once the
  SQ/RQ-region offsets within the QP buffer are finalised.
  Six new smokes: control-segment round-trip, data-segment
  round-trip, send-opcode discriminants pinned, CQE
  decode round-trip via simulate_completion, ownership-bit
  toggle isolated to bit 0 of byte 0x3F, CqeStatus catalog
  including unmapped → Unknown.
- **v0.9** (Stage 9): six new opcodes for the QP family —
  `CreateQp` (0x500), `DestroyQp` (0x501), `Rst2InitQp`
  (0x502), `Init2RtrQp` (0x503), `Rtr2RtsQp` (0x504), `ToRstQp`
  (0x50A). `mlx5/qp.rs` lays out the 512-byte QP context
  (qpc) + `build_create_qp_input(params, &pages)` — state
  (high nibble of byte 0x00) | qp_type (low nibble: Rc 0x0 / Uc
  0x1 / Ud 0x2 / Xrc 0x3 / Dct 0x6 / RawEthernet 0x9), bit-
  packed pd (24 bits at byte 0x10), cqn_snd (24 bits at 0x18),
  cqn_rcv (24 bits at 0x20), log_sq_size (5 bits at byte 0x29
  low) + log_rq_size (5 bits at 0x2B low), byte-aligned
  log_page_size (0x2C), followed by an 8-byte BE phys-addr
  list at offset 0x200. `decode_qp_state` / `decode_qp_type`
  / `decode_create_qp_input` round-trip. `Mlx5Hca::create_qp(
  params, page_count)` posts CREATE_QP via the input-mailbox
  transport, masks 24 bits of output_modifier as `qp_number`,
  and pushes a `LiveQp { qp_number, _pages, params, state }`
  onto the registry — initial state is `Rst`. `Mlx5Hca::
  modify_qp(qp_number, transition)` walks the documented state
  machine — each `QpTransition` (ToRst / RstToInit / InitToRtr
  / RtrToRts) maps to one of the dedicated opcodes; qp_number
  rides in input_modifier; the driver's mirrored state field is
  updated on success. `qp_state(qp_number)` introspection.
  `Mlx5Error::QpBuild` surfaces builder errors. Five new smokes:
  six QP opcodes pinned, CREATE_QP layout (length, state|type
  byte, log_page_size, BE phys list, full param round-trip),
  validation rejection paths (BadLogSqSize / BadLogRqSize / BadPd
  / BadCqn / NoPages), state-byte high-nibble round-trip across
  Rst/Init/Rtr/Rts/Sqer/Err while preserving qp_type low nibble,
  transition-to-opcode mapping (no collisions, all in 0x5xx
  range).
- **v0.8** (Stage 8): three new opcodes — `AllocUar` (0x802),
  `AllocPd` (0x800), `CreateCq` (0x400). `Mlx5Hca::alloc_uar()`
  + `alloc_pd()` issue inline-output commands and stash the
  FW-assigned 24-bit IDs on the driver's `uars` / `pds`
  registries (every alloc stays owned until a future free path
  is added). `mlx5/cq.rs` lays out the 256-byte CQ context
  (cqc) + `build_create_cq_input(params, &pages)` —
  bit-packed `log_cq_size` (5 bits at byte 0x07 low) +
  `uar_page` (24 bits across 0x08..0x0A), byte-aligned
  `log_page_size` (0x0C) + `c_eqn` (0x0F — the bound EQ for
  async events), followed by an N-entry 8-byte BE phys-addr
  list. `Mlx5Hca::create_cq(params, page_count)` allocates
  the CQE-buffer pages, posts CREATE_CQ via the Stage-7
  input-mailbox transport, masks 24 bits of `output_modifier`
  as `cq_number`, and pushes a `LiveCq` onto the registry.
  `Mlx5Error::CqBuild` surfaces validation errors.
  Introspection: `cq_count()` / `uar_count()` / `pd_count()`.
  Four new smokes: opcode discriminants pinned, CREATE_CQ
  layout (length, log_page_size + c_eqn placements, BE
  phys-addr list, full param round-trip), validation rejection
  paths, `c_eqn` binding lands at byte 0x0F.
- **v0.7** (Stage 7): `Mlx5Hca::issue_command_with_input_mailbox`
  — input rides through the chained-mailbox transport, output
  fits in the CQE's 8-byte inline window (eq_number / cq_number
  / pd ride in `output_modifier`). `Mlx5Hca::create_eq(params,
  page_count)` is the first live resource-creating command:
  allocates `page_count` 4-KiB DMA pages, builds the CREATE_EQ
  payload via Stage-6 `eq::build_create_eq_input`, posts via
  the input-mailbox transport, masks low 24 bits of
  output_modifier as `eq_number`, and stashes a `LiveEq` record
  (eq_number + DMA pages + params) on the driver so the backing
  isn't dropped while the EQ is live. `eq_count()` query.
  `uar_write32(uar_page, byte_offset, value)` — 4-byte BE
  doorbell into the UAR page at BAR0 + `UAR_BASE_DEFAULT (0x100000)
  + uar_page*4096 + byte_offset`. `Mlx5Error::EqBuild` surfaces
  Stage-6 EQ-builder validation errors. Three new smokes:
  input-mb + inline-output CQE layout (input_mb populated,
  output_mb zero, signature still XOR-balanced), eq_number
  mask of low 24 bits from output_modifier, UAR base + per-page
  byte-offset arithmetic.
- **v0.6** (Stage 6): `bit_field.rs` provides MSB-first absolute-bit
  read/write helpers (`read_bits_be` / `write_bits_be`) for the
  `mlx5_ifc` convention used everywhere in the PRM. Two new
  bit-packed cap accessors land on `HcaGeneralCaps` —
  `log_max_qp` (5 bits at byte 0x47 low) and `log_max_eq` (4 bits
  at byte 0x47 low nibble). `CmdOp::CreateEq = 0x301` opcode.
  `mlx5/eq.rs` lays out the 256-byte EQ context (eqc) +
  `build_create_eq_input(params, &pages)` producing the
  CREATE_EQ input mailbox payload (eqc + 8-byte BE phys-addr
  list); `decode_create_eq_input` round-trips the bit-packed +
  byte-aligned fields (log_eq_size, uar_page, intr_vector,
  log_page_size). Validation rejects oversize log_eq_size /
  uar_page + empty page lists. Live CREATE_EQ posting + UAR
  doorbell wiring are Stage 7.
- **v0.5** (Stage 5): typed cap decoders in `mlx5/caps.rs`.
  `HcaGeneralCaps` exposes vhca_id (BE u16 at 0x10),
  log_max_srq_sz (0x40), log_max_qp_sz (0x41), log_max_cq_sz
  (0x53), log_max_eq_sz (0x5B), log_max_mkey (0x60), log_max_pd
  (0x68); `EthernetOffloadCaps` exposes per-byte offload flags
  (tx_csum / rx_csum / lso / lro / rss / vlan_insert /
  vlan_strip) plus max_lso_size (BE u32 at 0x14). Both retain
  `raw()` for fields we haven't committed to and reject buffers
  shorter than the highest committed offset
  (`CapsDecodeError::Truncated`). `Mlx5Hca::query_general_caps`
  + `query_ethernet_offload_caps` wrap Stage-4
  `query_hca_cap` with the typed views. Bit-packed sub-fields
  (e.g. log_max_qp at the low 5 bits of 0x47) defer to a later
  stage that adds a `bit_field!` helper rather than inlining
  masks here.
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
