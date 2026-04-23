# NVM Express (NVMe) Specification 2.0

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## Key Mechanisms

NVMe is a high-performance SSD interface using PCIe as transport. The architecture employs paired submission and completion queues to decouple command submission from result collection.

**Submission and Completion Queues**: Commands are placed in submission queues (SQs); the device processes them and posts results to completion queues (CQs). Each queue is a ring buffer in host memory; the driver owns SQ and reads CQ. Multiple SQs can target the same CQ, supporting arbitration and priority scheduling.

**Command Structure**: NVMe commands are 64-byte fixed-size entries encoding opcode, namespace ID, and command-specific parameters. For I/O, commands reference Logical Block Addresses (LBAs) and point to data via Physical Region Descriptors (PRPs—pointer lists stored in host memory or inline in the command).

**Queue Pair Model**: An SQ-CQ pair forms the control channel. Queue 0 (the admin queue) is mandatory and used for device configuration and health monitoring. Queues 1+ are I/O queues created dynamically.

**Interrupt Handling**: Each CQ has a doorbell register and interrupt association. When the device posts completions, it may raise an interrupt (if unmasked). The driver polls the CQ to harvest completions; it then rings a doorbell to acknowledge processed entries, potentially re-arming interrupts.

## Invariants for NARF Driver Design

**Queue Ownership and Coherency**: The driver owns SQ; the device owns CQ. Queues must be physically contiguous and cache-line-aligned for optimal DMA performance. NARF should model queue pairs as capabilities: a capability grants read-write access to an SQ and read-only access to the corresponding CQ.

**Command Submission Ordering**: Commands enqueued in an SQ may be executed out-of-order (unless the device reports OAUQ support). Drivers must not assume sequential execution. Use capability-based per-command tracking: commands are tagged; results carry the same tag, allowing out-of-order harvest.

**Completion Acknowledgment**: The driver must advance a CQ head pointer after processing completions. If the driver does not advance, the device cannot reclaim CQ entries, and subsequent completions fail. Capability-based CQ access should enforce: advancing the head pointer is a separate operation from reading completions, preventing race conditions.

**Namespace Isolation**: Each NVMe namespace is logically independent (like a separate drive). Drivers are granted access to specific namespaces via capabilities. Commands targeting unauthorized namespaces should fail at validation time.

## Performance Trade-Offs

**Queue Depth vs. Memory and Latency**: Deeper queues (larger ring buffers) reduce submission stalls but consume more memory and increase CQ scanning latency. NARF should tune queue sizes per device; typical values are 256–4096 entries. Measure end-to-end latency (command submission to completion) to determine the optimal depth for your workload.

**Interrupt vs. Polling**: NVMe devices can interrupt on CQ updates or remain silent. Polling wastes CPU; interrupts introduce latency jitter. NARF should support both:
- Interrupt-driven for latency-sensitive workloads
- Polling for throughput-intensive workloads

Implement interrupt suppression (coalescing) to batch completions and reduce interrupt frequency under high load.

**PRP Chaining vs. Inline Data**: Commands can embed data (up to 3968 bytes inline) or reference external buffers via PRPs. Inline is simpler but wastes command slots; PRP chaining allows arbitrary buffer sizes. For NARF, use PRPs for all buffers >64 bytes; inline only for small metadata operations.

**Admin vs. I/O Queue Bandwidth**: Admin commands share the admin queue; under heavy admin load (e.g., health monitoring, namespace enumeration), I/O performance may degrade. Separate admin and I/O workloads by assigning them to distinct threads or async tasks.

## Pitfalls to Avoid

**PRP Format Violations**: PRPs encode host physical addresses with flags in low bits. If the driver incorrectly constructs a PRP list (e.g., forgets to set the "valid" flag or miscalculates alignment), the device may read garbage memory. NARF's buffer capability system must validate PRP construction before submission.

**Queue Doorbell Ordering**: The driver must enqueue a command fully before ringing the submission queue doorbell. If the doorbell is rung before the command is written, the device may fetch a half-initialized entry. Use volatile writes and memory barriers:
```
volatile_write(&sq[head], command);  // Must complete before doorbell
MemoryBarrier();
volatile_write(&SQ_DOORBELL, head + 1);
```

**CQ Wrap Counter Mismanagement**: NVMe completion queues have a phase bit that flips each wrap-around. Drivers must track phase to detect wrap-around and avoid interpreting stale completions. NARF should encode phase-bit management in the completion capability.

**Lost Completions from Interrupt Storms**: If the device raises interrupts faster than the driver harvests completions, subsequent interrupts may be coalesced or lost. Re-check the CQ after re-enabling interrupts to catch missed completions.

**Namespace Metadata Staleness**: Namespace capacity and block size are queried once at initialization but may change (e.g., due to firmware updates). NARF should implement periodic namespace re-enumeration or provide a capability revocation mechanism if metadata becomes stale.

**Timeout and Abort Complexity**: Commands can timeout if not completed within a driver-defined window. Aborting timed-out commands requires submitting an Abort command to the admin queue, which adds complexity. NARF should define clear timeout policies and implement abort logic defensively.

## Design Recommendations for NARF

**Model queues as capabilities**: Each I/O queue pair is a capability. The driver's capability encodes SQ and CQ addresses, doorbell locations, and queue depth. The frame subsystem enforces that only capable drivers can ring doorbells or read CQs.

**Implement per-namespace capabilities**: Each namespace granted to a driver is a separate capability. Commands targeting unauthorized namespaces fail at submission validation.

**Use async executor for completion harvesting**: Instead of polling or blocking on interrupts, register NVMe completion as an async event. The executor parks the driver on a completion capability until the CQ has pending work.

**Defer admin commands**: Batch admin operations (e.g., health logging, SMART queries) on a slow path, separate from I/O. Use a dedicated admin queue capability with lower scheduling priority.

**Implement PRP list validation**: Before submitting a command with PRPs, validate:
1. All PRPs are within granted buffer capabilities
2. Alignment is correct (4K boundaries)
3. Chain terminators are set correctly

**Test with QEMU NVMe**: QEMU provides a simple NVMe device model. Start with simulation before moving to real hardware.

The NVMe spec is complex; NARF's capability model should simplify ownership and validation invariants, making NVMe drivers safer and more auditable than traditional kernel drivers.

Source: https://nvmexpress.org/specifications/
