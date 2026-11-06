# drivers/net/vmxnet3 — VMware vmxnet3 paravirtual NIC

Paravirtual driver for guests on VMware ESX/Workstation. `vmxnet3.rs`
implements the documented bring-up sequence (Stages 0–2): map the two
4 KiB BARs — BAR0 for doorbells, BAR1 for the control plane — negotiate
the revision and UPT version, allocate the `Vmxnet3_DriverShared`
structure in DMA-coherent memory, and wire TX/RX rings (Stage 2 wires
ring 1 only). Stage 3 adds the datapath: single-descriptor TX with the
staged-gen publish protocol, completion-driven RX drain and refill,
polling TX/RX pumps (no MSI-X vector bound yet), carrier publication
via `GET_LINK` + ECR events, and a `HwNic` implementation registered
with the net stack. `vmxnet3/regs.rs` holds register offsets and
command codes; `vmxnet3/shared.rs` holds the shared structure and
descriptor types.

QEMU fixture: `XTASK_QEMU_VMXNET3=1 cargo xtask run` swaps the legacy
NIC model for QEMU's emulated vmxnet3 (0x07B0) on the same `n1`
backend, so the datapath + publication smoke runs under QEMU; the
smoke skips when no vmxnet3 device is present.

Dual-build: the built-in build compiles the real driver; the `.ko`
build registers through the `narf_register_pci_driver` KSYMTAB export
and is registration-only until the device datapath ABI lands.

- Spec: [drivers/net specification](../specification/spec.md)
