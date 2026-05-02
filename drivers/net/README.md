# drivers/net — Network drivers

Network device drivers. Exports frames via the `HwNic` trait and the
`narf_net` packet helpers (Ethernet / ARP / IPv4 / ICMP).

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)

## In-tree NICs

| driver | scope | notes |
|---|---|---|
| `e1000` | Intel 8254x family | clean-room from public Intel datasheet; TX + RX descriptor rings, polled. |
| `e1000e` | Intel 8257x family | shares the `e1000` core, extension VID/DIDs. |
| `igc` | Intel I225 / I226 family — 2.5 GbE | clean-room from public Intel datasheets; CTRL.RST + RAL/RAH MAC + legacy TX/RX descriptor rings + tx/rx (Stage cut: MSI-X + advanced descriptors are follow-ups). |
| `rtl8139` | Realtek RTL8139 10/100 Mbps | clean-room from public Realtek programming guide; CONFIG1 unlock + CR.RST + IDR0..5 MAC + 64 KiB cyclic RX ring + 4 × 2 KiB TX buffers + tx/rx + link status. |
| `r8169` | Realtek RTL81xx 1 GbE family | clean-room TX/RX descriptor rings + MSI-X. |
| `rtl8125` | Realtek RTL8125 / 8125B 2.5 GbE | clean-room PCI match + reset + MAC decode + TX descriptor layout (stages 1-3). |
| `ixgbe` | Intel 82599 / X540 / X550 / X550EM 10 GbE | clean-room; reset + EEPROM MAC + advanced TX + RX + MSI-X + `HwNic` impl. |
| `mlx5` | Mellanox ConnectX-4 / 5 / 6 family | clean-room v1.0 from the public Mellanox PRM — full lifecycle (cmdq, EQ/CQ/QP, WQE/CQE wire format, flow steering TIR/TIS/RQT, mkey, vport, async events, teardown). [`specification/mlx5.md`](./specification/mlx5.md) tracks the 16-stage build. |
| `iwlwifi` | Intel Wi-Fi 6 / 6E (AX200 / AX201 / AX210 / AX211) | structural probe only — operational register map (CSR/PRPH offsets, firmware loader, TFD/RBD descriptors, host-command opcodes) is not in any public Intel doc. [`specification/iwlwifi.md`](./specification/iwlwifi.md) documents the wall. |
| `qcnfa765` | Qualcomm WCN6855 (NFA765) Wi-Fi 6E | scaffolding only. |

## Conventions

- Each driver lives in `src/<name>.rs` (or `src/<name>/` directory
  module) with co-located smokes at `src/<name>/tests.rs`.
- `kernel_test_in!("drivers/net/<name>", smoke_*)` for registration,
  `#![cfg(target_arch = "x86_64")]` gating where the smoke needs
  x86-only infra.
- PCI matching via `narf_bus::register_pci_driver`. DMA via
  `narf-io::alloc_coherent`. Locks via `narf-lib::sync::IrqSafeSpinLock`.
- All NIC drivers in this directory are clean-room — register layouts
  and command formats come from public datasheets / PRMs only, never
  from a GPL Linux source.
