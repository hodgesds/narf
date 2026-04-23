# Fuchsia zx_channel: Capability-Based IPC

## Overview
Fuchsia's `zx_channel` is a capability-based messaging primitive that enables secure, ordered IPC between processes. Channels combine message queuing with handle (capability) ownership transfer, making them a natural fit for NARF's capability-driven architecture.

## Mechanisms

**Bidirectional Message Queues:**
Each channel endpoint maintains separate ordered queues for inbound and outbound messages. `zx_channel_write()` enqueues a message at the remote endpoint; `zx_channel_read()` dequeues from the local queue.

**Handle Ownership Transfer:**
Channels can transmit capabilities (handles) between processes. When a message carrying handles is written, ownership of those handles is transferred atomically: "atomic write the data into the channel and move ownership of all handles." The sender's handles become invalid; the receiver's new handles reference the same objects.

**Non-Duplicability:**
Unlike other Fuchsia handles, channels cannot be duplicated via `zx_handle_duplicate()`. This single-ownership model prevents handle proliferation and simplifies security analysis.

**Transaction IDs (zx_channel_call):**
For synchronous RPC, `zx_channel_call()` assigns a transaction ID to the outgoing message. The kernel automatically matches responses with the same transaction ID, enabling bidirectional RPC without explicit correlation logic in user code.

## Key Invariants

**Sequential message ordering:** Messages are delivered in FIFO order per endpoint. Concurrent reads/writes do not reorder messages.

**Atomic handle transfer:** Either all handles in a message are transferred, or the entire message is rejected. No partial transfers.

**Peer discovery:** Channels provide no built-in peer authentication. If a channel endpoint is leaked or shared unintentionally, the holder can communicate without explicit consent. NARF must use separate access-control channels for initial contact.

**Fire-and-forget semantics:** Closing a channel endpoint discards unread messages in that queue but does not affect messages already transmitted to the peer.

## Performance Characteristics

**Latency:** Measured in microseconds; exact latency depends on syscall overhead. `zx_channel_read()` is a direct syscall; no intermediate context switching.

**Throughput:** Message rate is limited by syscall frequency. Batching multiple messages per syscall improves throughput at the cost of increased latency per message.

**Queue buffering:** Unbounded per-endpoint message queues enable producer-consumer decoupling but risk memory exhaustion if producers outpace consumers.

## Pitfalls

1. **Handle exhaustion:** Unread messages retain their handles. Rapid arrival without processing leaks resources. NARF should enforce per-channel message quotas.

2. **Deadlock in synchronous RPC:** `zx_channel_call()` blocks the caller. Cyclic RPC dependencies (A→B→C→A) deadlock. NARF's async executor must use async IPC to mitigate.

3. **Unbounded queue growth:** Without backpressure, message queues exhaust memory. Implement per-channel limits and return backpressure errors.

4. **Ordering assumptions beyond single queue:** Multiple concurrent channels offer no global message order. Applications relying on total-order causal relationships must serialize.

## Adoption Guidance for NARF

**Adopt:**
- **Handle transfer model:** Use channels to transmit capability references between domains. Map Fuchsia handles to NARF capability tokens.
- **FIFO ordering:** Leverage per-endpoint queues for message sequencing; no need for external message ordering.
- **Non-duplication:** Enforce non-duplication at the type system level (e.g., linear types in Rust) to prevent accidental sharing.

**Avoid:**
- **Synchronous zx_channel_call():** Use async IPC (await-based) instead of blocking calls to prevent deadlock.
- **Unlimited message queues:** Enforce per-channel depth limits; return backpressure errors when limits are exceeded.
- **Sharing channels across domains:** Each channel represents a single trust relationship. Multiple concurrent domains should each have dedicated channels.

**Design point:**
Map NARF's capability-based IPC to Fuchsia's channel model. Each capability grant creates a bidirectional channel between sender and receiver. Handle transfer in channels becomes capability delegation. Use transaction IDs for RPC correlation, but implement async-await semantics rather than blocking calls.

## Reference
- Fuchsia zx_channel documentation
- https://fuchsia.dev/fuchsia-src/reference/kernel_objects/channel
