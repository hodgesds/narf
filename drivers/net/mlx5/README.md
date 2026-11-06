# drivers/net/mlx5 — Mellanox ConnectX NIC

Clean-room driver for the Mellanox/NVIDIA ConnectX-4/5/6 family, from
the public Mellanox PRM. `mlx5.rs` holds PCI matching, the 4 KiB BAR0
init-segment decoder, and `bring_up`; the `mlx5/` modules implement
the staged build the spec tracks — `cmd.rs` and `mailbox.rs` (command
queue), `caps.rs` (HCA capabilities), `eq.rs`/`eqe.rs` (event queues),
`cq.rs`/`cqe.rs` (completion queues), `ring.rs` (SQ/RQ/CQ rings),
`qp.rs`/`wqe.rs` (queue pairs and work entries), `vport.rs`,
`mkey.rs`, `steering.rs` (flow steering: TIR/TIS/RQT), and
`bit_field.rs` (the PRM's MSB-first field layout). The crate
implements `HwNic`.

Dual-build: the built-in build compiles the real driver; the `.ko`
build registers through the `narf_register_pci_driver` KSYMTAB export
and is registration-only until the device datapath ABI lands.

- Spec: [`../specification/mlx5.md`](../specification/mlx5.md) ·
  [drivers/net specification](../specification/spec.md)
