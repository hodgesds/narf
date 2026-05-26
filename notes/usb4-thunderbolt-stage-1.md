# USB4 / Thunderbolt — Stage-1 topology walker

Date: 2026-05-26.

## What landed in Stage-1

Three new modules, one `Stage::Late` initcall, nine smokes.

1. **`cm.rs`** — SW-CM control-packet protocol. `Header` (route
   22+32, unknown 10) + `Address` (offset 13, length 6, port 6,
   space 2, seq 2) match `tb_msgs.h` bit-for-bit. `CfgPkgType`
   covers READ / WRITE / ERROR / NOTIFY_ACK / EVENT / XDOMAIN /
   OVERRIDE / RESET / ICM 10–12. `CfgSpace`: HOPS / PORT / SWITCH /
   COUNTERS. `encode_cfg_read` + `encode_cfg_write` produce the
   on-wire dword stream Stage-2 hands to the NHI mailbox.
   `compose_downstream` / `route_depth` port Linux's
   `tb_downstream_route()` / `tb_route_length()`.

2. **`adapter.rs`** — `AdapterType` maps the 24-bit
   `tb_regs_port_header.type`: INACTIVE / PORT (lane) / NHI /
   DP-IN / DP-OUT / PCIe-DOWN / PCIe-UP / USB3-DOWN / USB3-UP.
   Predicates (`is_tunnel_endpoint`, `is_pcie_source/sink`,
   `is_dp_in/out`, `is_lane`) feed Stage-2 tunnel planning.

3. **`switch.rs`** — Switch + Topology + walker. `Switch` holds
   route, depth, vendor / device, upstream port, max port, adapters.
   `Topology` is BFS-ordered (host at index 0). `walk_topology<P:
   TopologyProbe>` does depth-bounded BFS: skips disconnected
   lanes, skips the parent-facing lane (no loops). `TopologyProbe`
   exposes `read_switch` / `read_port` / `port_has_peer` — Stage-1
   stubs these; Stage-2 wires them through NHI ring 0.

4. **`lib.rs`** — Stage::Late `thunderbolt-topology` initcall.
   Returns `NotPresent` when no NHI is bound. On real HW logs
   `thunderbolt: domain 0 (N controllers, NHI vV, H hops) —
   Stage-1 topology walker ready, awaiting Stage-2 mailbox`.

5. **`tests.rs`** — Nine smokes across `…/cm`, `…/adapter`,
   `…/switch`: header round-trip, address round-trip, cfg_read
   layout, cfg_write payload check, route compose+depth, adapter
   decode + masking, endpoint predicates, BFS over a synthetic
   3-switch tree, walker skips empty lanes, route-too-wide reject.

## What Stage-1 does NOT do (Stage-2+)

- No NHI ring-0 mailbox — walker's probe trait is a closure
  surface; Stage-2 plumbs DMA, IRQs, completion demux.
- No PCIe / DP / USB3 tunnel setup. Endpoint predicates exist so
  the Stage-2 planner can pair source/sink across the tree.
- No security levels, no ICM firmware path, no IOMMU / DMA-remap,
  no CL0s / CL1 / CL2.

## Source citation

Linux `drivers/thunderbolt/{nhi,tb,switch,ctl}.c`, `tb_msgs.h`,
`tb_regs.h`, `include/linux/thunderbolt.h` — direct adaptation
under post-2026-05-20 GPL-2.0-or-later relicense
(`feedback_no_gpl_links`). USB4 1.0 §"Routing", §"Topology",
§"Adapter Layer" is the public-spec backstop.

## Verification

- `cargo xtask test --arch=x86_64`: 2569 pass / 0 fail / 49 skip
  (baseline 2451; Stage-1 adds 9 smokes).
- `cargo xtask run --arch=x86_64 --display none`: Stage::Device
  `intel-thunderbolt` fires + Stage::Late `thunderbolt-topology`
  returns `not-present` on QEMU (no NHI emulation).
