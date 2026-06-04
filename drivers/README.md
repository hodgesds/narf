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

| crate                            | match (vendor : device ids)             | data path                                    |
|----------------------------------|-----------------------------------------|----------------------------------------------|
| `narf-drivers-nvme`              | 0x1B36 : 0x0010 (QEMU) + 3 Samsung VID/DIDs + class-storage backstop | admin queue + IDENTIFY CTRL/NS + I/O queue + Read/Write LBA + MSI-X-driven completions |
| `narf-drivers-virtio` (blk)      | 0x1AF4 : 0x1042 | virtqueue 0 + polled & IRQ-driven Read/Write sector + MSI-X (q0) |
| `narf-drivers-virtio` (net)      | 0x1AF4 : 0x1041 | RX + TX virtqueues, polled `tx`/`rx`, async `rx_irq_async` on receiveq MSI-X |
| `narf-drivers-virtio` (rng)      | 0x1AF4 : 0x1044 | requestq + polled `read_bytes(out)` entropy fetch |
| `narf-drivers-virtio` (balloon)  | 0x1AF4 : 0x1045 | inflate + deflate queues + `inflate(pfns)` / `deflate(pfns)` polled |
| `narf-drivers-virtio` (console)  | 0x1AF4 : 0x1043 / 0x1003 | receiveq + transmitq + emerg_wr cfg + write_bytes / read_bytes + MSI-X (receiveq) |
| `narf-drivers-virtio` (scsi)     | 0x1AF4 : 0x1048 | controlq + eventq + cmdq[0] + submit_cmd + submit_tmf + REPORT LUNS + MSI-X (cmdq[0]) |
| `narf-drivers-virtio` (9p)       | 0x1AF4 : 0x1009 | requestq + 9P2000.L `tversion` / `tattach` / `twalk` / `tlopen` / `tread` / `tclunk` live ops + MSI-X |
| `narf-drivers-virtio` (fs)       | 0x1AF4 : 0x105A | hiprio + request[0] + FUSE submit + `fuse_init`/`fuse_lookup`/`fuse_read` + MSI-X (request[0]) |
| `narf-drivers-virtio` (vsock)    | 0x1AF4 : 0x1053 | rx + tx + event queues + send/recv/drain_events + MSI-X (rx) |
| `narf-drivers-virtio` (iommu)    | 0x1AF4 : 0x1057 | requestq + eventq + attach/detach/map/unmap + MSI-X (requestq) |
| `narf-drivers-virtio` (gpu)      | 0x1AF4 : 0x1050 / 0x1010 | controlq + cursorq + 2D pipeline (init_scanout / paint_solid / paint_test_pattern / flush) + MSI-X (controlQ) |
| `narf-drivers-virtio` (input)    | 0x1AF4 : 0x1052 | eventQ drain → `narf_input` global ring + MSI-X (eventQ) |
| `narf-drivers-virtio` (snd)      | 0x1AF4 : 0x1059 | controlq + tx + rx + eventq, set_params/prepare/start + `play_buffer` / `play_buffer_phys` PCM submit |
| `narf-drivers-net` (e1000)       | 0x8086 : 0x100C/0x100E/0x100F/0x10D3/0x153A | TX descriptor ring + RX descriptor ring + buffer pool, polled |
| `narf-drivers-net` (ixgbe)       | 0x8086 : 0x10FB / 0x1528 / 0x1563 / 0x15AB | reset + EEPROM MAC + advanced TX/RX + MSI-X + `HwNic` |
| `narf-drivers-net` (mlx5)        | Mellanox ConnectX-4/5/6 family | clean-room cmdq + EQ/CQ/QP + WQE/CQE + flow steering + mkey + vport + teardown |
| `narf-drivers-net` (r8169)       | 0x10EC : RTL8169 family | clean-room TX + RX descriptor ring + MSI-X |
| `narf-drivers-net` (rtl8125)     | 0x10EC : 0x8125 / 0x3000 | clean-room PCI match + reset + MAC decode + TX descriptor layout |
| `narf-drivers-net` (iwlwifi)     | 0x8086 : AX200/AX201/AX210/AX211 | structural probe only — operational register map blocked on public docs |
| `narf-drivers-storage` (AHCI)    | 0x8086 : 0x2922 (ICH9), 0x3A22 (ICH10)  | HBA reset + port enumeration + IDENTIFY DEVICE + READ/WRITE DMA EXT + READ/WRITE FPDMA QUEUED (NCQ) + port-multiplier topology snapshot |
| `narf-drivers-storage` (SDHCI)   | PCI class 08:05 (any vendor)            | software reset + 3.3V power + 400 kHz init clock + CMD0/CMD8/ACMD41/CMD2/CMD3/CMD7 SD identification + CMD17/CMD24 PIO read/write_block |
| `narf-drivers-net` (igc)         | 0x8086 : 0x15F2/0x15F3/0x0D9F (I225) + 0x125B/0x125C/0x125D (I226) | clean-room from public Intel datasheets — CTRL.RST reset + RAL/RAH MAC + legacy TX + RX rings + tx/rx |
| `narf-drivers-net` (rtl8139)     | 0x10EC : 0x8139                         | clean-room from public Realtek programming guide — CONFIG1 unlock + CR.RST + IDR0..5 MAC + 64 KiB RX ring + 4 × 2 KiB TX buffers + tx/rx + link status |
| `narf-drivers-net` (rtl8126)     | 0x10EC : 0x8126                         | clean-room PCIe match + reset + MAC decode + TX descriptor layout |
| `narf-drivers-net` (atheros)     | 0x1969 : 0x1063/0x1083/0x10A1/0x2060    | Atheros AR81xx (atl1c) Gigabit Ethernet — MAC/PHY reset + EEPROM reload + split RX ring (RFD/RRS) + TX ring |
| `narf-drivers-net` (tg3)         | 0x14E4 : BCM5700..BCM5782 family        | Broadcom Tigon3 Gigabit Ethernet — hardware reset + core clock config + MAC/PHY init + TX/RX rings |
| `narf-drivers-net` (forcedeth)   | 0x10DE : MCP55..MCP77 family            | Nvidia nForce MAC — PHY init + EEPROM MAC decode + TX/RX descriptor rings |
| `narf-drivers-net` (vmxnet3)     | 0x15AD : 0x07B0                         | VMware vmxnet3 paravirtual NIC — UPT init + shared-memory queue config + TX/RX rings |
| `narf-drivers-platform` (smbus)  | PCI class 0x0C, subclass 0x05 (any vendor) | Intel ICH SMBus — IO BAR4 + read/write byte data + read word data via host-controller PIO transactions per ICH9 datasheet |
| `narf-drivers-platform` (tpm)    | MMIO 0xFED40000 (locality 0)            | TPM 2.0 — CRB (PC Client PTP) + TIS (legacy) auto-detect + `submit(cmd)` + `tpm2_get_random` per TCG public spec |
| `narf-drivers-hwmon`             | Dell SMBIOS vendor (`dell_smm`) / CPUID + MSR (`coretemp`, `k10temp`) / Super-I/O port (`nct6775`) | Hardware monitoring: `coretemp` (Intel DTS) and `k10temp` (AMD Zen) temperature sensors, `dell_smm` Dell SMM fan/temp control, and `nct6775` Super-I/O sensors. |
| `narf-drivers-usb` (Hub class)   | xHCI hot-plug, USB class 0x09           | GET_DESCRIPTOR(Hub) + SET_FEATURE(PORT_POWER) + per-port reset + GET_STATUS for downstream device enumeration |
| `narf-drivers-usb` (xHCI)        | QEMU + AMD Phoenix VID/DIDs | HCRST + DCBAA + Command/Event Rings + scratchpad + USBCMD.RS=1 + port reset + Enable Slot + Address Device + GET_DESCRIPTOR + Configure Endpoint + bulk/interrupt IN/OUT |
| `narf-drivers-usb` (HID kbd)     | xHCI hot-plug | Set Protocol(Boot) → interrupt-IN polling → Usage 0x07 → KeyCode press/release diff → `narf_input` |
| `narf-drivers-usb` (Mass Storage)| xHCI hot-plug, USB class 08:06:50 | enumerate-and-attach → CBW/CSW Bulk-Only Transport → INQUIRY / READ CAPACITY(10) / READ(10) / WRITE(10) + multi-block read/write up to 8 LBAs/xfer |
| `narf-audio` (Intel HDA)         | 0x1022:0x15E3 (AMD Phoenix), 0x1002:0x1640 (Radeon) | BAR0 + GCTL.CRST + CORB/RIRB rings + STATESTS codec walk + Get Parameter verbs + output stream descriptor + BDL + cyclic period buffer + 48 kHz S16LE stereo + `start_output` / `load_period` / `load_sine_test_tone` for audible playback |
| `narf-firmware-fw-cfg`           | x86_64 PIO 0x510/0x511 | QEMU `fw_cfg` directory parse + `find` / `read` / `read_string` |

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
