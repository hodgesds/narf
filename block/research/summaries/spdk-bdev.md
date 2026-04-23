# SPDK Block Device Architecture

## Key Mechanisms

SPDK's block device layer ("bdev") implements a pluggable abstraction sitting between applications and physical storage. The design separates concerns across multiple layers: driver modules (NVMe, AIO, virtio), virtual block devices (vbdevs) that stack atop base devices, and configuration via JSON-RPC. This modularity mirrors what a microkernel needs—clean boundaries between components.

For NARF's PKS/MTE domain isolation model, SPDK's module architecture offers instructive parallels. The framework uses "lockless queues for sending I/O to block devices," avoiding centralized locks that would serialize across isolated domains. However, SPDK's approach still assumes shared memory; NARF's zero-copy IPC would require adapting buffer ownership semantics.

## Invariants

SPDK maintains several critical invariants worth adopting:

1. **Device abstraction is mandatory.** All underlying storage—NVMe, ramdisk, AIO—presents a uniform interface. NARF should enforce similar contracts at capability boundaries to prevent subsystem assumptions about storage specifics.

2. **Metadata lives with storage.** The system supports "RAID metadata may be stored on member disks," enabling recovery without external configuration. This resilience principle suits microkernel designs where persistent state cannot rely on global registries.

3. **Stacking is composition, not inheritance.** Virtual bdevs (OCF caching, crypto, delay simulation) layer atop base devices through explicit client-server relationships, not polymorphic inheritance. This aligns with capability-based security: each vbdev declares its dependency on a base bdev.

## Performance Trade-offs

SPDK illustrates several design tensions:

**Concurrency vs. simplicity:** The system provides "multiple, lockless queues," improving throughput but complicating state management. Crypto vbdevs, for instance, "break up all I/O into crypto operations of a size equal to the block size," trading latency for parallelism. NARF's async executor must decide whether to absorb such costs into the kernel or expose them to applications.

**Flexibility vs. resource predictability:** OCF caching "has a per-device RAM requirement" that varies by workload. A microkernel cannot rely on dynamic memory pools; NARF should define static quotas and fail gracefully when exceeded, rather than SPDK's implicit consumption model.

**Staging buffers for correctness:** Crypto writes "use a temporary scratch buffer…to avoid encrypting the data in the original source buffer." This adds memory overhead but prevents data corruption. In NARF's zero-copy design, such invariants become critical—you cannot retroactively encrypt buffers if IPC already transferred them.

## Pitfalls to Avoid

**Configuration complexity:** SPDK's JSON-RPC model, while flexible, creates a management surface. The document lists dozens of RPC commands with subtle parameter interdependencies (e.g., cluster sharing for Ceph RBD versus dedicated clusters). NARF should minimize configuration knobs, favoring defaults and static analysis.

**Module proliferation without discipline:** SPDK includes modules for every conceivable device type (DAOS, xNVMe, Virtio variants). Without clear lifecycle guarantees, microkernel designers risk inheriting unmaintained code. Each module should justify its presence against the core abstraction.

**Implicit resource bounds:** Many vbdevs (RAID, Logical Volumes) don't document their memory footprint or queue depths upfront. A microkernel must make resource consumption explicit—perhaps through capability-based billing or static declarations at module load time.

**Synchronous control paths:** JSON-RPC commands like `bdev_nvme_attach_controller` appear synchronous but may trigger asynchronous device discovery. NARF should clarify whether block control operations complete atomically or return handles to incomplete initialization.

## Recommendations for NARF Block Designers

**Adopt:**
- vbdev pattern for domain boundaries; treat domains as module-equivalent components with explicit base-device dependencies
- Capability-based authorization instead of JSON-RPC for cross-domain block requests
- Lockless queue architecture mapped to async executor threads
- Device abstraction as hard contract; all storage types present uniform interface
- Metadata persistence on devices themselves for recovery without global registries

**Avoid:**
- Dynamic buffer allocation in hot paths; preallocate all intermediate storage
- Implicit resource consumption; make memory footprint and queue depth explicit
- Module auto-discovery or implicit device binding
- Configuration knobs without clear rationale; favor static defaults
- Assuming synchronous control operations; clarify whether initialization is atomic or asynchronous

**Specific to NARF:**
- Model vbdevs as capabilities: domain A holds a capability to a vbdev that stacks on base device B
- Enforce static buffer allocation; fail I/O requests that exceed pre-reserved capacity
- Integrate I/O latency into async executor scheduling; allow prioritization based on latency contracts
- Define canonical recovery paths for RAID/metadata without relying on global configuration
- Zero-copy buffer semantics: metadata immutability is a type invariant; enforce through ownership

<https://spdk.io/doc/bdev.html>
