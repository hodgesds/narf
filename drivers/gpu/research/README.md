# drivers/gpu — Research

## Primary sources

- **VirtIO-GPU spec (§5.7 of VIRTIO 1.2)** — cleanest starting target.
- **Intel Graphics Programmer's Reference Manuals (PRMs)** — if we
  target iGFX. <https://01.org/linuxgraphics/documentation/hardware-specification-prms>

## Secondary sources

- **Mesa3D project** — userspace graphics stack that'd sit above a
  NARF driver.
- **Asahi Linux GPU reverse-engineering** — reference for aarch64
  Apple-Silicon GPUs (stretch goal).
- **Linux `drivers/gpu/drm/virtio/*`** — virtio-gpu kernel code.

## Distilled summaries

- (Defer.)

## Open research questions

- Which GPU class is realistic as NARF's first real graphics target.
- Presentation / KMS equivalent in a capability OS with no-root model.
