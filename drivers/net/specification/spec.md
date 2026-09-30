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

### 3.1 i40e runtime profile

Each X710/XL710/XXV710/X722 PF negotiates 1–8 64-entry TX/RX pairs.
The count is the largest power of two bounded by online CPUs, the PF's queue
allocation, HMC capacity, firmware RX/TX/RSS capabilities, available MSI-X table
entries and host IRQ vectors. Entry 0 delivers admin/fatal causes; entry N+1
links PF-relative RX queue N to TX queue N. A single contiguous TC0 VSI map,
52-byte Toeplitz key and balanced 128/512-entry RSS table describe the same
queue set. X710 uses PF key/LUT registers; X722 uses per-VSI AQ key/LUT commands.
RSS selects non-tunnel IPv4/IPv6 TCP/UDP traffic; other traffic uses queue 0.
TX selects a stable queue from packet addresses/ports, preserving flow ordering
across submitting CPUs; fragments use addresses only.

Each pair has its own lock, completion worker, MSI-X route and TX watchdog.
Workers prefer separate online CPUs. On x86, MSI-X targets the corresponding
APIC when addressable; the current aarch64 ITS exposes only collection 0,
so IRQs target the BSP while workers can run on other CPUs. The existing
single SPSC frame-ring ABI remains usable: RX workers serialize only delivery
into the shared IPC producer, and the TX worker steers frames to hardware
queues. `I40eNic::queue_count()` reports the negotiated hardware count.

Hard IRQs mask/record; bounded executor drains rearm after inspecting completions.
Waits snapshot interrupt counters before checking queues. Timers recover lost
interrupts (10 ms queue, 100 ms admin); 250 ms without TX progress fails the PF.
Link changes trigger an asynchronous AQ refresh with a retained retry intent.

`I40eNic::transmit_with_meta(bytes, TxMeta)` returns on descriptor publication,
with an owned DMA copy retained until EOP completion. `transmit` submits plain
frames with the same asynchronous completion semantics. Ring-full returns
without publishing a partial packet; the IPC TX task retains its frame while
waiting for credits. `dropped_frames()` returns rejected TX and dropped RX
counts. A full RX IPC ring drops incoming frames while completion handling
continues. Hardware checksum results travel in `Frame::rx_meta`.

`Interface::offloads` and `HwNic::caps` advertise TCP/UDP checksums for
unfragmented IPv4 and IPv6 without extension headers, RX checksum reporting,
and TCP TSO up to 65,535 Ethernet bytes. MSS is at least 64; each segment's
IP packet must fit MTU 1500. IPv4/TCP options and up to two in-band VLAN tags
are accepted. Offload packets use exact IP lengths without Ethernet padding.
The driver builds pseudoheader seeds and TSO contexts; the caller need not
produce Linux `CHECKSUM_PARTIAL` headers. Malformed lengths, IP fragments,
tunnels, IPv6 extensions, SYN/RST/URG TSO, and VLAN insertion requests are
rejected. Probe configures the existing VSI to retain VLAN headers and refuses
a preassigned port VLAN. RX checksum credit requires a known, non-tunnelled
TCP/UDP PTYPE and valid parser/checksum status. Multi-buffer RX packets are
dropped through EOF; checksum failures are delivered for software verification.

TX head writeback is checked against the submitted interval before returning
credits or freeing DMA. AQ cancellation/timeout, watchdog expiry and fatal
hardware causes stop new submissions and report link down. A supervisor
withdraws hardware publication, waits for every bounded worker lease, masks and
synchronizes interrupts, then waits asynchronously for PF/global reset and NVM
readiness. Only confirmed reset permits discarding outstanding TX DMA and
clearing descriptor/completion state. The same initialization path rediscovers
VSI IDs/queue-set handles and restores AQ, HMC, queue contexts, VLAN policy,
RSS, filters, MSI-X and link reporting before publishing a new generation.
Queue count, MAC, registered interface and IPC endpoints remain stable; resource
shrinkage or a changed MAC fails the rebuild instead of silently changing them.

`I40eNic::recovery_status()` reports recovery activity, generation (successful
rebuild count), failed attempts and the last rebuild error. Failed attempts
retain all DMA and retry with 100 ms–30 s capped exponential backoff. The TX
worker retains an unsubmitted IPC frame through recovery; packets already
submitted whose completion was lost are discarded and counted in
`dropped_frames().0`, never replayed. Completion watchdogs reset at generation
changes. Firmware setup commands use bounded responsive polling; reset waits
release the executor between samples. No IRQ-disabling guard crosses an await.

All DMA allocations are owned before publication. Final teardown
masks/disables MSI-X, removes and synchronizes handlers, then waits for PF reset
before freeing DMA; failed final reset quarantines those allocations.
Coherent DMA barriers include outer-shareable ordering on aarch64. Extra VSIs,
DCB, jumbo frames, tunnels and VLAN insertion are outside this profile.

Memory-backed firmware tests exercise real AQ commands, multiqueue/RSS setup,
failed reset DMA retention, failed rebuild retry, stable publication/IPC and
post-recovery traffic without touching a physical NIC. Physical reset recovery
and packet distribution still require validation on a dedicated test adapter.

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

**iwlwifi and ath11k** are moved to `drivers/wireless` as of
Stage 3 bring-up.

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

## 8a. Realtek PHY / RX descriptor sub-module (`rtl_phy`)

References (public-only):
- **Realtek "RTL8125 Series 2.5 Gigabit Ethernet Controller —
  Registers Datasheet" Rev. 1.0** — Realtek. Public document.
  §2.10 PHYAR PHY Access Register layout (Flag bit 31; register
  address bits 26..21 with 5 valid bits for Clause 22; data bits
  15..0). §3.1.2 Receive Descriptor Format (16 bytes, OWN/EOR/FS/
  LS/MAR/PAM/BAR/RES/length packing).
- **Realtek "RTL8111B/RTL8168B Integrated Gigabit Ethernet
  Controller — Registers Datasheet" Rev. 1.0** (Jan 2006) — Realtek.
  Public. The "B" PHYAR + RX descriptor layouts that the RTL8125
  inherits unchanged.
- **IEEE 802.3 Clause 22** — public MII MDIO frame format. PHYAR
  is the MMIO-shaped wrapper around Clause 22 reads/writes.

Surfaced:
- `phyar_read_request` / `phyar_write_request` / `phyar_data` /
  `phyar_done` for the MMIO offset 0x60 register.
- `prepare_rx_desc` (host → chip) and `RxStatus::parse` (chip →
  host) for the 16-byte RX descriptor.
- MII Clause 22 register addresses (BMCR / BMSR / PHYSID1/2 /
  ADVERTISE / LPA / GBCR / GBSR) and the BMCR/BMSR bit constants
  for reset / autoneg / link-up / speed-100 / speed-1000 / full-
  duplex.

## 9. ABI versioning

Per-driver crates export the `BusDevice` match table; the
net-driver-trait surface (`NetIface`) is exported through
`net/`'s SDK at `@v0`.

`NET_DRIVER_ABI_MAJOR = 1`, `NET_DRIVER_ABI_MINOR = 0`.

## 10. Open questions

(none — all v0.1 questions resolved in §8)
