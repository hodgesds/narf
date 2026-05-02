# drivers/virtio — VirtIO

NARF's VirtIO subsystem. Modern virtio-PCI transport (VirtIO 1.2) for
all device classes; legacy + virtio-mmio paths exist alongside.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)

## In-tree drivers

Every driver lives in its own `<class>_pci.rs` file (or `<class>_pci/`
directory module) with co-located smokes. All speak the modern
virtio-PCI transport: cap-list walk → reset → ACK / DRIVER →
VERSION_1 negotiation → queue program → DRIVER_OK. MSI-X is enabled
on each driver's primary completion queue via
`pci::enable_msix_queue` and stored as `Option<u8>` so consumers can
`narf_interrupts::wait_for_irq(v).await`. The polled-completion
fallback stays in place so sync callers + IRQ-less environments keep
working.

| driver         | virtio device id | scope |
|----------------|------------------|-------|
| `blk_pci`      | 2  (`0x1042`)    | header / data / status descriptor chain, sync + async (IRQ-driven) read/write, MSI-X. |
| `net_pci`      | 1  (`0x1041`)    | RX + TX virtqueues, polled `tx` / `rx`, async `rx_irq_async` on receiveq MSI-X. |
| `console_pci`  | 3  (`0x1043`)    | receiveq + transmitq + ConsoleConfig (cols/rows/emerg_wr) + ControlEvent decode + write_bytes / read_bytes + MSI-X. |
| `rng_pci`      | 4  (`0x1044`)    | requestq + `read_bytes(out)` polled entropy fetch. |
| `balloon_pci`  | 5  (`0x1045`)    | inflate + deflate queues, `inflate(pfns)` / `deflate(pfns)` polled, ≤ 1024 PFNs / call. |
| `scsi_pci`     | 8  (`0x1048`)    | controlq + eventq + cmdq[0] + submit_cmd + submit_tmf + REPORT LUNS helper + MSI-X. |
| `p9_pci`       | 9  (`0x1009`)    | requestq + 9P2000.L `tversion` / `tattach` / `twalk` / `tlopen` / `tread` / `tclunk` live ops + MSI-X. |
| `gpu_pci`      | 16 (`0x1050`)    | controlq + cursorq, 2D pipeline (`init_scanout` / `paint_solid` / `paint_test_pattern` / `flush`) + MSI-X. |
| `input_pci`    | 18 (`0x1052`)    | eventQ drain → `narf_input` global ring (KEY / REL events) + MSI-X. |
| `vsock_pci`    | 19 (`0x1053`)    | rx + tx + event queues, `VsockHdr` builders, `send` / `recv` / `drain_events` + MSI-X. |
| `iommu_pci`    | 23 (`0x1057`)    | requestq + eventq, attach / detach / map / unmap with §5.16.6 tail-status decode + MSI-X. |
| `fs_pci`       | 26 (`0x105A`)    | hiprio + request[0] queues, FUSE-on-virtio submit + `fuse_init` / `fuse_lookup` / `fuse_read` helpers + MSI-X. |
| `snd_pci`      | 25 (`0x1059`)    | controlq + eventq + tx + rx queues, `set_params` / `prepare` / `start` + `play_buffer` / `play_buffer_phys` PCM submit. |

## Shared infra

- [`pci.rs`](./src/pci.rs) — cap discovery (`discover` / `map_cap`),
  common-cfg register offsets, `enable_msix_queue` helper used by
  every live driver to bind one queue to one MSI-X vector.
- [`queue.rs`](./src/queue.rs) — split-virtqueue layout
  (`VirtqueueLayout`), descriptor / avail / used helpers, fence wrapper
  for consistent in/out memory ordering.

## MSI-X

Each driver with a live virtqueue path calls
`pci::enable_msix_queue(common, cap, device, q_idx)` from inside its
`probe` (best-effort — failure falls through to the polled path).
The returned IDT vector is stored in `Self::irq_vector`; consumers wait
on it via `narf_interrupts::wait_for_irq(vector).await`. The bound
queues per driver are listed in the table above.

## Smokes

Per-driver smokes live in `src/<class>_pci/tests.rs` (preferred) or
`src/<class>_pci_tests.rs`. Each registers under
`drivers/virtio/<class>_pci` via
`narf_kernel_test::kernel_test_in!`. Live smokes (those that need a
real device) skip cleanly when QEMU doesn't expose the device; pure-
data smokes run unconditionally.
