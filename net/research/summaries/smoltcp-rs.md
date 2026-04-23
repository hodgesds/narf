# Smoltcp: Standalone Bare-Metal TCP/IP Stack

## Overview

Smoltcp is a "standalone, event-driven TCP/IP stack designed for bare-metal, real-time systems" that aligns well with NARF's zero-allocation, capability-based architecture. Its heap-free design and minimal dependencies make it suitable for kernel-space or userspace networking integration.

## Mechanisms

**Core Architecture:** Smoltcp operates without heap allocation entirely, using compile-time-configured buffers. The stack supports IPv4/IPv6, TCP/UDP, ICMP, and 6LoWPAN across Ethernet and IEEE 802.15.4 media layers.

**Event-Driven Processing:** Rather than blocking operations, the design uses explicit polling with configurable timeouts, enabling integration with NARF's async executor. Applications drive socket state machines through `send()` and `recv()` operations on fixed buffer queues.

**Configuration Model:** Compile-time settings (IFACE_MAX_ADDR_COUNT, REASSEMBLY_BUFFER_SIZE, etc.) control resource limits, eliminating dynamic allocation and enabling predictable memory footprints—critical for capability domains with fixed resource budgets.

## Key Invariants

**No heap dependency:** All buffers pre-allocated; perfect for kernel isolation. Resource budgets are compile-time constants.

**Stateless packet processing:** Reassembly buffers have bounded segment counts (max 4-32 gaps), preventing unbounded resource consumption from fragmented packets.

**Checksum validation:** TCP/UDP checksums generated/validated automatically, reducing user-space verification burden.

**Rate-limited ARP:** One request per second prevents address resolution DoS attacks.

## Performance Trade-offs

**Throughput vs. Complexity:** Achieves ~3.7-7.9 Gbps in loopback benchmarks by avoiding macro tricks and compile-time computation overhead. Accepts simpler, slower code for robustness.

**Memory vs. Features:** Selective acknowledgements and SACK remain unimplemented; window scaling and out-of-order reassembly are available but consume fixed buffer space. TCP stream reassembly is limited to 4 segments, preventing pathological reordering scenarios.

**Latency Consideration:** Nagle's algorithm and delayed acknowledgements are implemented, introducing slight RTT overhead but improving throughput for small-message workloads.

## Adoption Strategy for NARF

**Strengths:** The zero-allocation guarantee maps directly to capability-based resource isolation. Compile-time configuration prevents resource negotiation bugs. Event-driven design pairs naturally with async executors.

**Integration Points:** Wrap socket objects as capabilities; buffer ownership transfers leverage NARF's zero-copy IPC. Per-socket timeouts become domain-specific scheduling concerns.

**Userspace vs. Kernel:** Smoltcp works equally well in kernel or userspace. For NARF, consider userspace integration to reduce kernel TCB. Only critical path operations (packet steering, timer management) require kernel integration.

## Pitfalls to Avoid

**Buffer exhaustion:** Misconfigured REASSEMBLY_BUFFER_COUNT or FRAGMENTATION_BUFFER_SIZE can silently drop packets; audit sizing against worst-case workloads.

**Fragmentation assumptions:** IPv4 reassembly and TCP stream reassembly both assume contiguous or near-contiguous packet arrival; high packet loss scenarios may exceed segment limits.

**ARP cache bottlenecks:** Fixed neighbor cache (default 4 entries) becomes limiting in large networks; multicast/broadcast storms can evict critical entries.

**IPv6 limitations:** Router solicitation is generated but never processed; manual prefix configuration required—unsuitable for dynamic environments.

## License
Smoltcp uses 0-clause BSD licensing, permitting kernel incorporation with minimal restrictions.

## Reference
- Smoltcp Repository
- https://github.com/smoltcp-rs/smoltcp
