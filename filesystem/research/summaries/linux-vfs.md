# VFS Architecture for NARF: A Rust Microkernel Perspective

## Key Mechanisms

The Linux VFS provides a unified abstraction layer translating filesystem operations into type-specific implementations. Three core structures form the foundation:

**Dentries (Directory Entries)** cache pathname-to-inode mappings in RAM, enabling fast lookups without disk access. The dentry cache implements an LRU eviction strategy, keeping frequently accessed paths readily available. For NARF, this suggests maintaining a similar hierarchical cache but leveraging Rust's ownership model to eliminate double-free vulnerabilities inherent in C reference counting.

**Inodes** represent filesystem objects (files, directories, special devices). The documentation notes that "inodes are filesystem objects such as regular files, directories, FIFOs and other beasts. They live either on the disc or in the memory." NARF designers should model inodes as capability-bearing structures, where each inode operation transitions through domain boundaries using your PKS/MTE isolation.

**File objects** are per-process kernel-side abstractions allocated during open(). They maintain pointers to dentries and operation vectors. This three-level indirection (file → dentry → inode) enables VFS flexibility but introduces latency.

## Critical Invariants

1. **Single dentry per directory entry**: The VFS maintains a hard rule that "a directory must only ever have one dentry." This prevents aliasing anomalies. NARF's capability security should enforce this at the type system level.

2. **Inode lifecycle synchronization**: Inodes transition from disk to memory on demand; changes must write back coherently. With async executors, ensure write-back completion before capability revocation.

3. **Dentry cache coherency**: Negative dentries (non-existent entries) must be invalidated on concurrent filesystem mutations. Your zero-copy IPC should propagate invalidations without copying entire cache structures.

4. **Lock-free readonly paths**: The documentation emphasizes that "all methods are called without any locks being held, unless otherwise noted." RCU-walk mode (indicated by `LOOKUP_RCU` flags) permits lock-free pathname traversal. Rust's thread-safety guarantees align naturally with this constraint.

## Performance Trade-offs

**Caching complexity vs. lookup speed**: The dentry cache trades memory for fast pathname resolution, but coherency overhead increases with filesystem concurrency. NARF should profile cache eviction strategies; Linux's LRU may prove suboptimal for microkernel workloads with fewer concurrent processes.

**Synchronous vs. asynchronous I/O**: The VFS supports both, but mixing them requires careful error handling. Writeback errors are reported at next fsync(), creating delayed error visibility. For NARF's async executor, consider eager error propagation through capability revocation rather than deferred fsync() reporting.

**Superblock locking granularity**: Super operations like `sync_fs()` and `freeze_fs()` hold the superblock lock, serializing concurrent operations. NARF's fine-grained domain isolation could enable per-inode locking, reducing contention—but requires careful deadlock prevention across IPC boundaries.

## Pitfalls to Avoid

1. **RCU-walk mode violations**: Methods called during pathname lookup must not block or dereference unstable pointers. NARF's Rust compiler catches some violations, but async/await can obscure blocking calls. Document which operations are safe in RCU-walk.

2. **Dentry alias explosions**: Network filesystems can create multiple dentries for the same inode via `d_splice_alias()`. The newer `d_unalias_trylock()` callback mitigates this, but NARF should implement it from the start. Your capability model can encode aliasing constraints at the type level.

3. **Writeback error loss**: The current infrastructure reports errors to all file descriptors open during failure, not just those that dirtied pages. NARF's fine-grained domain isolation could track per-capability write tracking, enabling precise error attribution.

4. **Extended attribute handler ordering**: xattr handlers are matched linearly; handlers with generic prefixes must follow specific ones. Misorderingsilently ignores attributes. Use Rust's type system to enforce handler registration ordering.

## Recommendations for NARF Filesystem Designers

**Adopt**: The three-level (file/dentry/inode) indirection provides clean abstraction boundaries ideal for capability-based security. Each transition can validate security properties. Implement the `address_space_operations` interface with async readahead; your executor can parallelize I/O naturally.

**Avoid**: Don't replicate Linux's global dentry hash table. NARF's per-domain isolation suggests per-capability dentry caches, reducing lock contention but requiring careful invalidation protocols. Avoid mixing synchronous locking with async I/O; choose one and enforce it at the type level.

**Extend**: Implement eager writeback-error reporting via capability revocation rather than deferred fsync() semantics. Use Rust's Result types to encode error states, replacing C's errno convention. Consider layering a "virtual capability filesystem" above your physical filesystem, exposing only capabilities the process holds.

The VFS's key insight—factoring filesystem diversity into type-specific operations—transfers cleanly to capability microkernels. NARF's isolation boundaries align naturally with inode/dentry transitions, enabling stronger security properties than Linux's discretionary model.

Source: https://docs.kernel.org/filesystems/vfs.html
