# drivers/storage/core — Shared storage-driver helpers

`narf-drivers-storage-core` holds the leaf modules the storage drivers
and their smokes share, so no driver re-implements protocol decoding or
request gating. It is a library crate, not a driver: it binds no PCI
device itself, and per-driver crates depend on it (the
`narf-drivers-storage` facade re-exports it).

- `src/sd_proto.rs` — pure, MMIO-free decoders for SD responses and
  registers: R1/R1b status, R6, R7, CID, and CSD (v1.0 and v2.0 capacity
  formulas), from the SD Physical Layer Simplified Specification.
- `src/emmc.rs` — eMMC EXT_CSD register decoder from JEDEC JESD84-B51
  (card revision, bus width, partition and boot/RPMB sizes, user
  capacity, lifetime/health estimates).
- `src/ufs.rs` — UFSHCI 3.0 register layout plus UTP transfer-descriptor
  and UPIU codecs (JESD223D/JESD220D). This is the bytes-on-the-wire
  layer; live MMIO bring-up and DMA submission land on top of it.
- `src/req_gate.rs` — per-device request gate (`ReqGate`): mutual
  exclusion for a synchronous transfer spins on a per-device
  `AtomicBool` without masking interrupts, instead of holding the
  driver's global spinlock across the whole device round-trip.

- Spec: [`../specification/spec.md`](../specification/spec.md)
