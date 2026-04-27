# drivers — Driver Framework + Drivers

The driver framework (lifecycle, domain binding, capability bootstrap)
plus the in-tree driver specs.

- Framework spec: [`specification/spec.md`](./specification/spec.md)
- Framework research: [`research/README.md`](./research/README.md)
- Stage: **Stage 3 framework landed.** `Driver` trait (async lifecycle
  via `Pin<Box<dyn Future>>`), `DriverHandle` cap marker →
  `CapKind::Driver`, `DriverManifest` (typed `CapKind` slice, not
  string list), `DomainPolicy::{Shared, Dedicated}`, `DriverEnv`,
  `DriverRegistry` with cap-gated `register()` returning a fresh
  per-driver `Cap<DriverHandle, Write>`, `DriverPhase` state machine
  providing shared exclusivity for `start_named`/`quiesce_named`,
  `with_entry` observer accessor, `NoopDriver` reference impl,
  `bootstrap_authority()`. Deferred to Stage 4: `#[driver(...)]`
  proc-macro + TOML manifest parser, panic containment (needs `frame/`
  trap-prologue cooperation), manifest signing (`crypto/`), unregister
  path, IRQ binding + MMIO region mapping in `DriverEnv`, multi-driver
  hot-reload.
- Per-driver subfolders:
  - [`virtio/`](./virtio/) — Stage 3 skeleton landed; full Stage 4.
  - [`nvme/`](./nvme/)
  - [`net/`](./net/)
  - [`gpu/`](./gpu/)
  - [`storage/`](./storage/) — non-NVMe storage (AHCI today).

## Live driver portfolio (Stage 4)

Driver registration is via `bus::register_pci_driver(PciMatch {…})` —
each driver crate ships a `register_pci_driver()` entry point. The
kernel-test harness or boot-time driver loader calls those + then
`bus::probe_all_pci(authority)` walks the bus and dispatches each
device to the highest-specificity matching probe.

| crate                          | match (vendor : device ids)             | data path                                    |
|--------------------------------|-----------------------------------------|----------------------------------------------|
| `narf-drivers-nvme`            | 0x1B36 : 0x0010 (QEMU NVMe)             | admin queue + IDENTIFY CTRL/NS + I/O queue + Read/Write LBA + MSI-X-driven completions |
| `narf-drivers-virtio` (blk)    | 0x1AF4 : 0x1042 (virtio-blk modern)     | virtqueue 0 + polled & IRQ-driven Read/Write sector |
| `narf-drivers-virtio` (net)    | 0x1AF4 : 0x1041 (virtio-net modern)     | RX + TX virtqueues, polled                   |
| `narf-drivers-virtio` (rng)    | 0x1AF4 : 0x1044 (virtio-rng modern)     | structural probe (single virtqueue brought up) |
| `narf-drivers-virtio` (balloon)| 0x1AF4 : 0x1045 (virtio-balloon modern) | structural probe (inflate+deflate queues)    |
| `narf-drivers-net` (e1000)     | 0x8086 : 0x100C/0x100E/0x100F/0x10D3/0x153A | TX descriptor ring + RX descriptor ring + buffer pool, polled |
| `narf-drivers-storage` (AHCI)  | 0x8086 : 0x2922 (ICH9), 0x3A22 (ICH10)  | HBA reset + port enumeration + IDENTIFY DEVICE + READ/WRITE DMA EXT |

## Bus-level helpers each driver builds on

`bus::pci_cap` — generic capability-list walker (standard caps).
`bus::pci_cap_ext` — extended capability walker (offset 0x100+) +
  AER reader.
`bus::pci_express` — PCI Express cap reader + Function-Level Reset.
`bus::pci` — command-register helpers (BME, MEM_SPACE, INTX_DISABLE)
  + `requester_id(device)` for GIC ITS DeviceID.
`bus::msi` — legacy MSI cap (single-vector / multi-vector with
  message-address/data in cfg-space).
`bus::msix` — MSI-X cap walker, table programming
  (`program_vector` + `program_vector_block`), per-vector mask /
  unmask, global enable.
`bus::bar` — BAR sizing (write-all-1s / read-back) + `MmioRegion`
  with volatile `read32`/`write32`.
`bus::pcie` — shared ECAM walker (x86_64 q35 + aarch64 QEMU virt).
`bus::driver_match` — PciMatch registry + `probe_all_pci`.

`narf_interrupts::vector` — IDT vector allocator (single +
  contiguous-block).
`narf_interrupts::dispatch` — generic vector → fire-count + waker
  table.
`narf_interrupts::wait` — `wait_for_irq(vector).await` future.
`narf_interrupts::aarch64::its` — GIC ITS bring-up + MAPC/MAPD/MAPTI
  command issuance (so `MsixTable::program_vector` registers the
  EventID translation alongside writing the table entry).
