# PCIe Architecture Overview

## Key Mechanisms

PCIe fundamentally differs from legacy parallel buses through its "point-to-point topology, with separate serial links connecting every device to the root complex." This architecture directly benefits capability-based systems: each device has an isolated communication channel, enabling fine-grained access control without arbitration overhead that plagued shared-bus designs.

The lane-based scaling model—×1, ×4, ×8, ×16—maps naturally onto NARF's domain isolation. Unlike PCI's "shared parallel bus architecture, in which the PCI host and all devices share a common set of address, data, and control lines," PCIe lanes are independent unidirectional pairs. This permits asymmetric trust domains: you could enforce stricter MTE tagging on GPU command rings while relaxing it for trusted network adapters, since physical isolation prevents cross-lane data corruption.

PCIe's credit-based flow control layer offers semantic richness for capability revocation. Rather than revoking capability handles globally, you can manipulate credit allocations per-device, degrading throughput predictably instead of causing hard failures. The transaction layer's split-request-response model suits async executors perfectly—a domain waiting for DMA completion can yield rather than spin.

## Critical Invariants

**Lane negotiation** occurs during initialization and can degrade dynamically. NARF's bus subsystem must treat negotiated width as a runtime property, not a boot-time constant. If a ×16 GPU reports ×8 after power excursion, your IPC bandwidth assumptions collapse. Maintain invariant: *actual_lanes ≤ negotiated_lanes*, checked on every major transaction batch.

**Sequence numbering and CRC** in the data link layer provide detection, not correction. PCIe requires replay of corrupted packets. For zero-copy IPC, this means shared buffers must survive retransmission: don't assume the first write succeeded. Implement idempotent message handlers or explicit acknowledgment protocols above PCIe.

**Power excursion** (100 microseconds at 3× sustained draw, logarithmically decaying) breaks real-time assumptions. If your capability revocation handler assumes <1µs latency to starve a rogue device, power transients violating the 25W/75W/150W slot limits will trigger resets you didn't expect. Establish timeout-based deadlock detection, not hard latency bounds.

## Performance Trade-Offs

Encoding overhead varies: PCIe 1.x uses 8b/10b (20% waste), while 3.0+ uses 128b/130b (1.54% waste). For a NARF IPC allocator, this means your theoretical bandwidth advertised to userspace must discount encoding. Claiming 4 GB/s from a ×16 PCIe 1.0 slot is misleading; actual payload is 3.2 GB/s.

**Data striping** across lanes reduces per-packet latency but requires hardware deskewing within 20/8/6 nanoseconds for 2.5/5/8 GT/s respectively. Small messages (sub-128 bytes) suffer padding penalties and may not benefit from ×16 slots. Profile your typical IPC message size; if median is 64 bytes, a ×4 slot avoids striping complexity without throughput loss.

Full-duplex lanes enable simultaneous request-response, but credit-based flow control introduces round-trip latency. If a device exhausts its transmit credits and stalls, downstream capability checks (e.g., verifying a DMA mapping) block the entire capability chain. Design your async executor to parallelize independent capability validations across different endpoints.

## Common Pitfalls

**Hot-plugging misconception**: While PCIe supports removal, NARF's capability table and domain mappings assume static topology at initialization. Enumerate devices early, assign capabilities by slot+function, and treat hot-plug as an error-recovery path, not a normal mode. Unplugging a GPU mid-DMA will generate NAK floods; your bus subsystem must detect link degradation and quarantine the device's capabilities.

**Power connector failures**: The 12VHPWR connector had widespread melting issues due to partial seating. This isn't a pure PCIe problem, but affects your hardware assumptions. Never assume power delivery matches enumeration: a device might negotiate ×16 but brownout under load. Implement power-aware capability downgrading triggered by detection of voltage sag.

**Mixing generations carelessly**: PCIe 5.0 uses PAM-4 modulation + FEC instead of NRZ + 128b/130b. If your bus driver assumes 128b/130b framing for all devices, a PCIe 5.0 device will produce bit errors. Version negotiation must occur before you install capability handlers for a device.

## Recommendations for NARF

1. **Capability-per-lane granularity**: Rather than one capability covering a ×16 card, issue separate capabilities for logical bundles (e.g., four ×4 "slices"). Revocation of one slice doesn't require full device reset.

2. **Async flow-control feedback**: Integrate PCIe credit exhaustion into your async executor's wake-up mechanism. When a device runs out of credits, deschedule its corresponding async task rather than polling.

3. **Detect non-idempotent boundaries**: Mark capability domains that span multiple TLPs with an "atomicity requirement" flag. Your replay mechanism must handle partial TLP bursts crossing domain boundaries.

4. **Power-aware downgrading**: Monitor link health (via negotiated vs. actual lane width, error counters). If CRC failures spike, reduce the device's granted capability bandwidth before a hard fault occurs.

5. **Avoid fixed-size buffer assumptions**: PCIe requires minimum receiver credits for CONFIG TLPs, but actual available space varies. Make capability-grant decisions based on advertised credits, not theoretical maximums.

PCIe's strengths—isolation, negotiation, and full-duplex links—align naturally with NARF's principles. Its hazards—power transients, encoding variability, and dynamic degradation—require treating the bus as a runtime-adaptive component, not a static initialization artifact.

<https://en.wikipedia.org/wiki/PCI_Express>
