# drivers/virtio — VirtIO (first driver)

The first real driver NARF ships. Targets VirtIO 1.2 split virtqueues
to start, then packed. Runs in a dedicated PKS/MTE domain; transport is
the Narf-Ring to the rest of the kernel.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: **Stage 3 skeleton landed.** virtio-mmio register constants
  (§4.2.2), `VirtioMmioDevice::probe` / `probe_raw` validating magic /
  version / device-id / vendor-id, `ProbeError` enum,
  `VirtioSkeletonDriver` implementing the `narf_drivers::Driver`
  trait. Volatile MMIO reads use the `compiler_fence(SeqCst)` pair
  per `arch/` §4. Deferred to Stage 4: feature negotiation
  (`DEVICE_FEATURES` / `DRIVER_FEATURES` / `FEATURES_OK`), STATUS-bit
  progression (`ACK → DRIVER → FEATURES_OK → DRIVER_OK`), virtqueue
  descriptor-ring construction, doorbell via `QUEUE_NOTIFY`, used-ring
  completion consumption, IRQ binding, device-specific subdrivers
  (virtio-blk, virtio-net, virtio-console, virtio-gpu).
