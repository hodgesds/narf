# Fuchsia Netstack3: Capability-Oriented Network Stack

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## Overview

Fuchsia Netstack3 is a modern, capability-based network stack implementation in Rust designed to be the philosophical sibling to NARF's architecture. It demonstrates how capability-based security integrates with network protocol implementation, providing a reference for NARF's networking subsystem design.

## Mechanisms

**Capability-Based API:** Netstack3 exposes network operations through Fuchsia's capability model. Each domain holding a channel to the network service gains only the operations explicitly permitted by that channel. For example, a domain might hold a capability to send on a specific UDP socket but not receive or manage connections.

**Resource Isolation:** Rather than global socket tables, Netstack3 isolates per-domain socket state. Each capability token references a distinct network resource (socket, interface, route) with associated permissions. This maps directly to NARF's capability-driven architecture.

**Async Task Integration:** Netstack3 uses async/await throughout, integrating cleanly with Fuchsia's async executor. NARF can follow this pattern: network operations are async tasks that suspend awaiting packet arrival or acknowledgment.

**Stateless Processing Model:** Network packets flow through isolated processing domains (parsing, protocol validation, state machine transitions) rather than monolithic state machines. Each domain implements a specific invariant or constraint.

## Key Invariants

**Capability Confinement:** Network resources (sockets, connections, buffers) are never referenced directly; they are always mediated through capabilities. A domain cannot access another's sockets without an explicit capability grant.

**Async Completion:** Network operations complete asynchronously. A task cannot block waiting for network events; instead, it awaits completion through async channels. This prevents deadlock and enables efficient scheduler integration.

**Zero-Copy Semantics:** Buffer ownership is transferred via capabilities. When an incoming packet arrives, the capability system ensures only the intended domain can access that buffer.

## Performance Trade-offs

**Capability Overhead:** Each network operation incurs capability system overhead (indexing, validation). Netstack3 amortizes this by batching operations where possible.

**Async Context Switching:** Using async/await for network operations requires executor context switches. These are cheaper than syscalls but more expensive than synchronous function calls.

**Memory Layout:** Capability-based isolation may fragment memory (per-domain heaps, isolated buffers). This impacts cache locality but gains isolation benefits.

## Adoption Strategy for NARF

**Adopt capability-based networking:** Map Fuchsia's channel-based API to NARF's capability system. Each network operation grants/revokes capabilities as needed.

**Integrate with async executor:** Network tasks are first-class async tasks in NARF's executor. Packet arrival triggers async completion, resuming waiting domains.

**Per-Domain State:** Maintain separate network state (socket tables, connection tables, ARP caches) per domain. Shared resources (physical interfaces) are mediated through singleton capabilities.

**Userspace Network Stack:** Like Netstack3, implement the network stack in userspace (perhaps leveraging smoltcp) with minimal kernel involvement. The kernel handles only packet steering and timer management.

## Pitfalls to Avoid

**Capability leakage:** If capabilities are shared unintentionally (e.g., via shared memory or copy-paste in code), isolation is compromised. Use sealed capabilities to prevent introspection.

**Deadlock in async chain:** If task A awaits task B which awaits task A (cyclic async), the executor deadlocks. Netstack3 mitigates this through careful dependency analysis. NARF must ensure the async executor detects cycles.

**Buffer lifetime mismanagement:** If a capability to a buffer is revoked while the domain still holds a reference, the domain can access freed memory. Pair capability revocation with explicit domain notification.

**Protocol state inconsistency:** Stateless processing means state is distributed across multiple domains. If state transitions are not atomic, intermediate states can be observed, breaking invariants. Use sealed capabilities to group atomic state.

## Reference
- Fuchsia Netstack3 RFC (RFC 0168)
- https://fuchsia.dev/fuchsia-src/contribute/governance/rfcs/0168_netstack3
