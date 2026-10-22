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

- [Navi22 Mesa ABI audit](navi22-mesa-abi.md) — every ioctl/query Mesa 26.2.4
  and libdrm 2.4.134 issue at init and first submission on GC 10.3.2, the
  Linux answer, NARF's answer and the owning milestone.
- [Navi48 display acceptance](navi48-display-acceptance.md) — board/route
  inventory, physical run matrix and required artifacts; no physical passes yet.
- [Navi48 protected-output requirements](navi48-protected-output.md) — separate
  firmware, protocol, authorization and validation gates; HDCP remains unsupported
  and unadvertised.

## Open research questions

- Which GPU class is realistic as NARF's first real graphics target.
- Presentation / KMS equivalent in a capability OS with no-root model.

## Reproducing Linux reference checks

The RX 9000 completion work uses upstream Linux `v7.3-rc4`, commit
`93f51579e7df248780214094418f205253383cc5`. All 27 existing Linux comparison
harnesses pass against a clean Git checkout at that revision. Source archive
comparisons do not establish this Git provenance.

```sh
cargo xtask gpu-reference --linux-tree /path/to/linux \
    --linux-revision 93f51579e7df248780214094418f205253383cc5
```

The runner verifies the revision and checkout cleanliness before and after each
harness. Keep generated files outside the Linux tree. These source comparisons
complement the separate Mesa/Addrlib/codec checks and native execution tests;
they do not establish physical board or application acceptance.
