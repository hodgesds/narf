# Intel 82574L Datasheet: NIC Hardware Architecture

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## Key Mechanisms

The Intel 82574L is a single-port Gigabit Ethernet controller (E1000 family) providing hardware support for:

**Descriptor-based DMA**: The NIC uses descriptor rings stored in host memory. The driver enqueues transmit or receive descriptors; the hardware reads/writes them directly via DMA. Three ring types exist: transmit, receive, and interrupt throttling (ITR).

**Transmit and Receive Rings**: Each ring is a circular buffer. For transmit, the driver provides data addresses and packet metadata; the NIC fetches descriptors, reads data, and reports completion. For receive, the driver pre-allocates buffers; the NIC fills them with incoming packets and posts completion status.

**Interrupt Suppression and Coalescing**: The NIC supports interrupt throttling (ITR) and interrupt masking per queue. The driver can disable interrupts entirely, rely on edge-triggered interrupt notification, or configure coalescing timers to batch completions.

**Hardware Checksumming and Offloads**: The NIC implements TCP/UDP checksum offload, IP fragmentation, and TSO (TCP Segment Offload), reducing per-packet CPU overhead. These features are configured per-packet via descriptor fields.

## Invariants for NARF Driver Design

**Descriptor Ownership Transitions**: The driver owns descriptors until it marks them ready (by advancing the Transmit Descriptor Tail register); the hardware then owns them until completion. Once completion status is set, the driver re-owns the descriptor. This clear ownership transition is critical for avoiding data races in a capability-based system. NARF should model descriptor ownership via capability transfer.

**DMA Memory Safety**: All descriptor rings and data buffers must be physically pinned (cannot be swapped). The driver must ensure that buffers referenced by the NIC remain valid until the NIC signals completion. Capability-based buffer registration ensures this: only memory covered by a buffer capability can be used in descriptors.

**Register Access Atomicity**: Tail pointer writes must be atomic relative to descriptor enqueuing. If the driver advances the tail pointer before fully initializing a descriptor, the NIC may read partial or garbage data. Use volatile writes and appropriate memory barriers.

## Performance Trade-Offs

**Interrupt Coalescing vs. Latency**: Coalescing reduces CPU overhead but increases latency. The 82574L supports tunable ITR thresholds (measured in 256-nanosecond units). NARF should profile both interrupt-per-packet and coalesced modes; network latency-sensitive workloads favor low thresholds (~100 µs), while throughput-sensitive ones favor high (~1 ms).

**TSO/Checksum Offload vs. Complexity**: Hardware offloads save CPU but require driver logic to:
1. Determine packet capabilities
2. Set descriptor flags
3. Handle offload failures (e.g., packets too large for TSO)

For NARF's initial drivers, consider disabling offloads first (software checksumming only) to reduce complexity, then add hardware acceleration once the baseline driver is proven.

**Receive Buffer Allocation Strategy**: The driver can either:
- Pre-allocate large pools (memory waste, predictable latency)
- Allocate on-demand (CPU overhead, risk of buffer exhaustion under load)

NARF should use pre-allocated pools tied to capabilities, with a policy daemon deciding pool sizing based on NIC memory and system load.

**Polling vs. Interrupts**: The NIC can operate in pure polling mode (driver continuously reads completion status) or interrupt mode. Polling reduces latency jitter but wastes CPU idle time. For NARF's async executor, configure the NIC for interrupts; the async scheduler handles the batching.

## Pitfalls to Avoid

**Descriptor Ring Wrap-Around Corruption**: The ring is circular; indices wrap at ring size. If the driver advances the tail pointer incorrectly (e.g., off by one), the NIC may overwrite unprocessed descriptors. NARF should encode ring size and wrap logic at the capability level—descriptors in a ring capability are only valid within [head, tail) modulo ring size.

**Lost Completions from Premature Interrupt Masking**: If the driver masks interrupts and then misses checking the completion ring (due to async scheduling delays), subsequent interrupts are lost. Capability-based completion tracking should encode: "if interrupt delivery is masked, driver is responsible for polling at least every X milliseconds."

**DMA to Invalid Memory**: If a driver descriptor references memory outside its granted capability region, the NIC behavior is undefined (typically a system hang or memory corruption). NARF's capability system must prevent this: only buffers explicitly granted via buffer capabilities can appear in descriptors.

**Interrupt Masking Race Conditions**: The NIC has per-queue and per-function interrupt mask bits. Disabling one and checking for completions races with new packets arriving. Always re-check the completion ring after re-enabling interrupts.

**Incorrect Checksum Offload Configuration**: If the driver sets TSO but doesn't set the `DCMD_TSE` flag correctly, or miscalculates maximum segment size, the NIC generates malformed packets. Validate checksum configuration in the driver initialization phase; consider a self-test (send/receive known packets) before marking the driver as ready.

## Design Recommendations for NARF

**Use descriptor ownership tracking**: Model each descriptor as a capability. The driver's "own" capability indicates it can enqueue; once the NIC processes the descriptor, ownership transfers to the "complete" capability, which the driver can query asynchronously.

**Implement polled receive under load**: While interrupts are efficient at low load, under high throughput, context-switching overhead dominates. NARF's async executor should support switching to polling mode when packet rate exceeds a threshold (e.g., >50k pps).

**Pre-allocate and register DMA buffers**: Use a memory pool API to allocate packet buffers. Register each pool's physical address range with the NIC once. Avoid allocating descriptors at packet-by-packet granularity; use a slab allocator.

**Implement per-queue capability isolation**: Each transmit/receive queue is a separate capability. If a guest driver is given Tx-queue capability, it cannot access Rx. Model this explicitly.

**Test interrupt suppression carefully**: The 82574L supports `INTR_DELAY` (interrupt delay in microseconds). Start with simple coalescing (disabled) and add tuning after basic correctness is verified.

The 82574L is a solid real-hardware target for NARF's first network driver. Its DMA model and capability invariants map naturally to capability-based security.

Source: https://www.intel.com/content/www/us/en/products/docs/network-io/ethernet/10-25-40-gigabit-adapters/82574-gbe-controller-datasheet.html
