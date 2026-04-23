# drivers/virtio — Research

## Primary sources

- **Virtual I/O Device (VIRTIO) Version 1.2 (OASIS)** — canonical spec.
  <https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html>
- **VIRTIO 1.3 (draft / upcoming)** — worth tracking.

## Secondary sources

- **Linux `drivers/virtio/*`** — reference implementation.
- **Rust-VMM `virtio-queue` crate** — `no_std`-friendly Rust queue impl.
  <https://github.com/rust-vmm/vm-virtio>
- **Firecracker virtio device models** — small, readable Rust examples.
- **QEMU virtio-pci / virtio-mmio transports** — what we'll be talking to.

## Distilled summaries

- `summaries/virtio-1-2-spec.md` — VIRTIO 1.2 queue design for microkernels
- (Reuse `../../ipc/research/summaries/io-uring-sqcq.md` for queue
  mental model)

## Fetched this round (2026-04-22)

- `summaries/virtio-1-2-spec.md` — VIRTIO 1.2 specification

## Open research questions

- Packed-ring adoption state across hosts (QEMU/crosvm/cloud hypervisors).
- Access-for-non-PCI transports on aarch64 without devicetree.
