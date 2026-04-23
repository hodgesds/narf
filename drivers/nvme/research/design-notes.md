# drivers/nvme — Design Notes

> Created: 2026-04-22

---

## Load-bearing decisions

**One Narf-Ring exporting the block-device interface.** The spec says the NVMe driver's outbound interface is a single Narf-Ring to the block layer. But NVMe's architecture is intrinsically multi-queue: the spec mandates up to 65,535 I/O queues, and high-performance NVMe drives achieve ~1M IOPS precisely because they fan-out submissions across multiple queues targeting different NAND banks. Funnelling everything through one Narf-Ring re-serialises what the hardware was designed to parallelise. The block layer (`block/`) sits above and may provide a multi-queue abstraction, but the NVMe driver's "one ring" interface must either be logically multi-channel or the block layer will have to re-add queuing logic that the driver should be providing.

**Admin queue is never used on the I/O fast path.** This is stated as an invariant in §4. But the NVMe spec allows using the admin queue for SMART/health log queries, firmware download, and namespace management — all of which may be triggered by the kernel at any time (health monitoring, hot-plug namespace attach). If any of these are initiated while the I/O fast path is active, they share the admin queue with each other but not with I/O queues — which is correct. The invariant is true, but the corollary is missing: *admin queue operations may still block each other.* The spec needs a sequencing policy for admin queue access (mutex? async queue with back-pressure?).

**PRP / SGL validation against DMA buffer bounds.** This is §4. The NVMe spec supports two data transfer mechanisms: PRPs (Physical Region Pages — a chained list of 4K-aligned physical addresses) and SGLs (Scatter-Gather Lists — more flexible). The NARF spec mentions "PRP / SGL lists validated against the DMA buffer's bounds" — but PRPs and SGLs have completely different validation logic. PRPs chain via the last entry of each page pointing to the next page; SGLs use typed descriptors with explicit length and subtype fields. Conflating them in one invariant statement implies one validation path handles both, which is incorrect. They need separate validation functions with separate correctness proofs.

**MSI-X, one vector per I/O queue.** §5 on x86_64 specifies this. NVMe drives on real hardware can have 64–2048 MSI-X vectors. The "one per I/O queue" model is correct in theory, but the GICv3 on aarch64 has a finite number of LPIs (configurable, typically 8192–65536). If NARF creates many I/O queues and each gets an MSI-X vector, the interrupt controller becomes a bottleneck. The spec needs a minimum viable interrupt allocation policy: even 8 I/O queues with MSI-X coalescing gets most of the performance benefit.

---

## Divergences from precedent

**Capability-gated submission.** Linux NVMe uses a `bio` queue — anyone with a block device file descriptor can submit I/O. NARF requires `Cap<Namespace, Submit>` per namespace. This is correct and stronger than Linux's DAC model. But the NVMe spec research summary flags out-of-order completion as a NVMe invariant: "Commands enqueued in an SQ may be executed out-of-order." In NARF, if two tasks both hold `Cap<Namespace, Submit>` and both submit to the same I/O queue, their completions are interleaved. The capability does not imply a private queue. A task that wants sequential completion guarantees needs a private queue, not just a cap. The spec does not address queue ownership — is a `Cap<Namespace, Submit>` always sharing a queue with others, or can it imply a private queue?

**SPDK-inspired async model, but in-kernel.** SPDK runs in user space with polled completion. NARF's NVMe driver runs in a kernel domain with the async executor. SPDK achieves ~10M IOPS on NVMe by dedicating a core to polling and never sleeping. NARF's model (async Future, parked on interrupt) is correct for a general-purpose OS but will not match SPDK latency numbers. The spec should not claim or imply SPDK-level performance; it should claim "lower latency than Linux's block layer on the fast path."

**No CMB/HMB.** §8 mentions Controller Memory Buffer (CMB) and Host Memory Buffer (HMB) as open questions. CMB lets the host map the NVMe controller's on-device DRAM as MMIO and submit SQ entries directly to it, eliminating DMA for the submission path. HMB lets the controller DMA into host memory for its own internal tables. Both are Stage 4 scope per §8. This is fine, but CMB specifically changes the queue architecture: if submission entries live in BAR-mapped memory rather than host DRAM, the IOMMU model changes (the NVMe controller is now mapping *into* its own BAR, not into host memory). The spec should note this as a deferred architectural decision that, if adopted, requires `io/` changes.

---

## Proposed spec changes

- §3 Public interface: Change "one Narf-Ring exporting the block-device interface" to "per-queue Narf-Ring handles, with a multiplexer ring exposed to `block/`." The driver owns N physical I/O queues and exposes them via N rings or a single tagged ring with queue affinity. `block/`'s multi-queue dispatcher (Stage 4) selects which queue to use per submission. — *aligns the driver's interface with NVMe's native parallelism.*

- §3 Public interface: Separate `Cap<Namespace, Submit>` into `Cap<Namespace, Submit>` (shared queue) and `Cap<IoQueue, Own>` (private queue). A task holding `Cap<IoQueue, Own>` has exclusive use of one I/O queue pair for sequential completion guarantees. This is how SPDK achieves determinism. — *essential for database/storage workloads that need ordering guarantees.*

- §4 Invariants: Split PRP and SGL validation: "PRP lists: each entry is a 4K-aligned physical address within a granted DMA buffer cap; chain terminator is validated before traversal. SGL segments: each descriptor's length and subtype are validated; bit-field layouts are parsed via generated code, not hand-written bit shifts." — *prevents validation bypass via type confusion between PRP and SGL formats.*

- §4 Invariants: Add admin queue serialisation: "Admin queue operations are serialised via an async mutex. A second admin command may not be submitted until the first completion is harvested. Health-log polling and namespace management are on the slow path and may not preempt each other." — *prevents admin queue starvation from concurrent health monitoring.*

- §5 Architecture notes (aarch64): Add interrupt coalescing policy: "A minimum of 4 MSI-X vectors are required (1 admin + 3 I/O). If more vectors are unavailable from `interrupts/`, I/O queues are multiplexed onto shared vectors with completion ring disambiguation. Maximum vectors are capped at min(cpu_count, 64) to avoid LPI exhaustion on GICv3." — *prevents GICv3 LPI exhaustion on many-queue configurations.*

- §8 Open questions: Resolve multi-queue policy as "one I/O queue per CPU up to device max, minimum 4." Per-domain queues are a secondary option if a domain needs private I/O ordering. This is the Linux `nvme_set_queue_count()` approach and is well-validated. — *removes a design decision that blocks Stage 4 implementation.*

---

## Open invariants / cross-subsystem hazards

**`drivers/nvme/` ↔ `block/` queue interface mismatch.** `block/`'s Stage 3 work lands a "single-queue deadline scheduler" (`block/ §...`). NVMe's advantage is multi-queue. Wrapping a multi-queue NVMe driver behind a single-queue block interface wastes the hardware. `block/`'s multi-queue dispatch lands in Stage 4. The Stage 3–4 boundary means the NVMe driver (also Stage 4) will be designed against a multi-queue `block/` interface from day one — which is correct. But if the NVMe driver's Stage 4 design is finalised before `block/`'s multi-queue interface is locked, the two will diverge. They must be co-designed.

**`drivers/nvme/` ↔ `io/` PRP construction safety.** PRP lists reference physical addresses. If a PRP entry references a physical page that is also mapped in another domain's VA space (not the NVMe driver's DMA buffer), the NVMe controller will DMA into that page without the IOMMU knowing. The IOMMU check in `io/` validates that the DMA buffer cap covers the target range — but the PRP list itself is constructed by the driver from a physical address table. If the driver makes a construction error (offset miscalculation), the IOMMU does not catch it because the page itself is within the cap range but the wrong page within the range is targeted. This is a logic-safety gap, not a memory-safety gap, and requires the PRP builder to be formally validated or at minimum fuzz-tested under `verification/`.

**`drivers/nvme/` ↔ `rcu/` namespace metadata staleness.** The NVMe spec research summary notes "Namespace capacity and block size are queried once at initialization but may change." The `rcu/` QSBR variant is the right tool for protecting the namespace metadata table: writers (namespace hot-plug event) wait for a grace period before publishing new metadata; readers (I/O submission path) hold read-side references. But `drivers/nvme/` does not list `rcu/` as a dependency. It should.

---

## Additional opinionated commentary

The CQ phase-bit wrap counter bug is one of the most common NVMe driver correctness failures in published CVEs and in-the-wild driver reports. The NVMe spec research summary calls it out: "Drivers must track phase to detect wrap-around and avoid interpreting stale completions." NARF's capability model for CQ access should encode the phase bit as part of the CQ capability state, not as a driver-managed variable. If the phase bit is inside the capability (owned by the framework, not the driver), a wrap-counter bug in the driver produces a capability violation error, not silent data corruption. This is one of the clearest cases where NARF's capability model can provide a correctness guarantee that Linux's raw-pointer model cannot.
