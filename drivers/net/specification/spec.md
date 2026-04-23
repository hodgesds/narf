# drivers/net — Specification

> Status: **Outline v0.1** (Stage 3 via virtio-net; Stage 4 real hardware).

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

## 8. Open questions

- First real-HW target: E1000 (simple, ubiquitous in QEMU) vs. IGC
  (modern Intel client NICs) vs. MLX5 (overkill but P2P-DMA friendly).
- RSS / multi-queue policy.
- Zero-copy TX from userspace — works naturally with Narf-Rings if we
  design the TX-ring slot carefully.
