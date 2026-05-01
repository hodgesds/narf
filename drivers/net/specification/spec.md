# drivers/net — Specification

> Status: **v1.0** (Stage 4 design lock). v0.1 outlined the
> NIC driver shape; v1.0 locks the first real-hardware
> target, the RSS/multi-queue policy, and the zero-copy TX
> integration with `net/spec` §8.4 fast-path mechanism.

## 1. Purpose & scope

**Owns:** Receive/transmit paths for network adapters, per-device ring
management, offload negotiation (checksum, segmentation where supported).

**Does NOT own:** The IP/transport stack (outside this tree). NARF ships
a raw-frame Narf-Ring and nothing higher.

## 2. Assumptions

- `io/` supplies DMA buffers suitable for RX/TX rings.
- `interrupts/` delivers RX/TX IRQs into the driver's domain via UIPI
  where available. **If UIPI is unavailable, `interrupts/` delivers
  the same logical event via a kernel-mediated notification path
  with a documented worst-case latency budget set in `verification/`'s
  perf suite (initial target: ≤ 5 µs)**. The driver's async model
  is identical in both paths — it polls a Narf-Ring waker; only the
  wake-arrival latency differs. This makes UIPI an optimisation, not
  a correctness assumption.

## 3. Public interface

- Inbound, **batch-first**:
  - `submit_tx_batch(bufs: &[BufRef]) -> Future<BatchResult>`
  - `recv_rx_batch(max: usize) -> Future<Vec<Frame>>`
  Single-frame helpers (`submit_tx`, `recv_rx`) wrap the batch APIs
  with a length of 1; they exist for ergonomics, not as the canonical
  shape. Single-frame-as-the-canonical-API is a performance
  anti-pattern at any line rate ≥ 1 GbE — every modern NIC and stack
  does batching, and retrofitting it later forces a redesign.
- Outbound: per-queue frame Narf-Rings (RSS / multi-queue), plus a
  control plane (link up/down, stats).

## 4. Invariants & safety properties

- Received frames are placed into buffers the driver domain *owns*; no
  cross-domain view until the frame is moved via Narf-Ring ownership transfer.
- Descriptor rings validate every writable field before trusting.

## 5. Architecture notes

Bus transport differs per platform: PCIe on both primary archs; MMIO
only on embedded aarch64.

## 6. Dependencies

- **Consumes:** `drivers/` (framework), `io/`, `ipc/`, `interrupts/`,
  `capabilities/`, `bus/` (device discovery), `net/` (implements the
  frame-ring contract).
- **Provides to:** raw-frame Narf-Ring consumers (`net/` contract
  exposes them to the userspace stack).

## 7. Stage assignment

virtio-net in Stage 3 as a byproduct of `drivers/virtio/`; real-hardware
driver (candidate: Intel E1000 or IGC as the simplest starting point) in Stage 4.

## 8. Resolved decisions

### 8.1 First real-hardware target (resolved)

**Decision:** **E1000 (8086:100e) and IGC (8086:15f3 family)**
together. E1000 covers QEMU compat + ancient hardware test
beds; IGC is modern Intel client NICs (Tiger Lake+).

MLX5 / ConnectX-class is deferred to Stage 5+ when fast-path
networking has a concrete consumer demanding RDMA / GPUDirect
features. The fast-path infrastructure (`net/spec` §8.4) is
ready when MLX5 is ready.

### 8.2 RSS / multi-queue policy (resolved)

**Decision:** mirrors `drivers/virtio/spec` §8.3 —
**CPU-count based, capped by device support**.

E1000 (single-queue legacy) → 1 queue, single-vector MSI-X.
IGC (8 queues per direction typical) →
`min(cpu_count, 8)` queues with MSI-X per queue.

RSS hash schemes follow `net/spec` §8.3 `RssScheme` enum;
drivers translate to hardware-specific RSS tables.

### 8.3 Zero-copy TX (resolved)

**Decision:** **shared TX-ring slot layout with embedded
DMA buffer cap** so Narf-Rings + the driver's TX descriptor
ring share the same packet-buffer phys addresses.

```rust
#[repr(C)]
pub struct TxSlot {
    pub buf:    Cap<DmaBuffer, Read>,    // packet payload (in user-space pool)
    pub len:    u16,
    pub flags:  u16,                     // CSUM_OFFLOAD | TSO | ...
    pub _pad:   [u8; 4],
}
```

When a stack daemon submits a TX slot, the driver reads the
buf cap, resolves to the underlying DMA buffer (the
fast-path huge-page pool), points the NIC's TX descriptor
directly at the buffer's phys addr, and rings the doorbell.
No copy.

For the IRQ-driven path (default, non-fast-path), the slot
can carry an inline payload or a DMA-buffer cap; drivers
support both. For fast-path (`dispatch = Polled`), only the
DMA-buffer-cap form is supported (consumer is expected to
manage its own pool).

## 9. ABI versioning

Per-driver crates export the `BusDevice` match table; the
net-driver-trait surface (`NetIface`) is exported through
`net/`'s SDK at `@v0`.

`NET_DRIVER_ABI_MAJOR = 1`, `NET_DRIVER_ABI_MINOR = 0`.

## 10. Open questions

(none — all v0.1 questions resolved in §8)
