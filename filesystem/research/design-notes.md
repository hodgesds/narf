# filesystem — Design Notes

> Created: 2026-04-22

---

## Load-bearing decisions

**No global root; every task has a root cap.** This is the correct capability-FS model and matches Fuchsia's philosophy. But it creates a bootstrap problem: who holds the first root cap, and how is it derived? On a POSIX system, pid 1 holds `/` and delegates. In NARF, the initramfs must be mounted by something before the first task with a root cap exists. The spec says "there is no global root" as an invariant, but the kernel-internal initramfs mount in Stage 3 is by definition ambient — it cannot hold a `DirCap` because caps require `capabilities/` to be initialised. The spec should describe the pre-capability bootstrap FS path (initramfs loaded before cap init) as a defined exception, sealed off and irrevocably narrowed once cap init completes.

**UTF-8 paths only; no byte-pathname transparency.** This is a deliberate break with POSIX. Linux VFS operates on byte strings. Any filename that is not valid UTF-8 on NARF is either rejected or passed to a compat layer in `drivers/fs/`. The research summary on Linux VFS notes that aliasing anomalies in dentries often arise from encoding inconsistencies in networked filesystems. Enforcing UTF-8 at the kernel level eliminates this class of bug. The risk: POSIX relibc programs in `userspace/` that create filenames with arbitrary bytes (common in scripting) will break without the compat FS. The spec should state: "the relibc shim translates byte-to-UTF-8 at the boundary; kernel FS is never exposed to raw bytes."

**Sleepable RCU for dentry-equivalent cache and mount-tree walks.** §6 lists `rcu/` (Sleepable variant) as a dependency. This is correct — a mount-tree walk that crosses a virtiofs boundary will await I/O, which cannot hold a classic RCU read-side lock (which must not sleep). The sleepable RCU variant exists for this case. But the spec does not say *which* data structures use which RCU variant. The mount tree (slow mutations, many concurrent walks) should use `rcu/` QSBR. The dentry-equivalent cache (frequent mutations on a warm FS) should use hazard pointers. Conflating them to "sleepable RCU" is too coarse — the performance characteristics are different and the Stage 4 unified page cache will feel this.

**Filesystem driver crashing in its domain fails open operations with `FsError::FsDomainFault` but does not take down `filesystem/` core.** This is the correct isolation property. But the spec does not say what happens to the *page cache* backing that filesystem's files. If pages are owned by the filesystem domain (dirty, awaiting writeback) and the domain dies, those pages contain user data that will never be written. Either the page cache is in the filesystem domain (and dies with it) or it is in `filesystem/` core's domain (and survives but is now inconsistent — dirty pages for a dead FS). The spec must resolve page-cache domain ownership before Stage 4.

---

## Divergences from precedent

**No dentry cache by name.** The spec has a "page cache" but never mentions a dentry-equivalent cache explicitly. The Linux VFS summary is blunt: dentries are the performance-critical structure for pathname resolution; without them, every path lookup hits the filesystem driver. NARF's path resolution goes through `resolve_step` on the `Filesystem` trait, which *may* be cached in the driver's domain, but `filesystem/` core has no defined lookup cache. This means a warm path like `open("/usr/lib/libc.so")` hits the virtiofs driver (a domain crossing) for every component. This is the most likely Stage 3 performance cliff.

**No `/proc` / `/sys` / `/dev`.** NARF explicitly does not replicate these. Linux's `/proc` and `/sys` are pseudo-filesystems that expose kernel state. NARF's `observability/` peek API replaces them. This is clean from a capability standpoint — no ambient stat-ing of `/proc/self/status`. The risk: every tool ported to NARF that reads `/proc/cpuinfo`, `/sys/class/net/`, or `/dev/urandom` will break silently. The relibc shim must intercept all three and redirect to the appropriate cap-gated API. The spec should enumerate which POSIX pseudo-filesystem paths get relibc shim treatment and which are simply absent.

**Cross-FS rename returns an error.** §4 states "Cross-FS operations (e.g. rename across mounts) are not transparent — they return an error." POSIX requires `EXDEV` for cross-device rename. NARF returns an error that "forces the caller to copy + unlink explicitly." This is stricter than POSIX: POSIX says the kernel can refuse but must return `EXDEV`; shells and `mv(1)` implement copy-then-unlink. NARF returns an error and delegates. For relibc compat, `rename(2)` must check if src and dst are on the same mount and either emulate the copy-unlink or return `EXDEV`. This needs to be in the relibc shim specification, not assumed.

**virtiofs as an early persistent FS.** The virtiofs spec research summary notes the "atime mount option" divergence: "The atime behavior for virtiofs is the same as the underlying filesystem of the directory that has been exported on the host." This means NARF's filesystem semantics for a virtiofs-backed mount are host-determined, not guest-determined. A NARF program that stats an atime and finds it violates NARF's spec is in a legitimate configuration. The spec should document: "virtiofs mounts inherit host filesystem semantics for time fields; NARF makes no promises about atime accuracy on virtiofs mounts."

---

## Proposed spec changes

- §2 Assumptions: Add explicit bootstrap exception: "During Stage 3 kernel init, the initramfs is mounted by a privileged boot path that holds ambient FS access. This path is sealed (made inaccessible) before the first userspace task receives its root cap. No code path reachable after sealing may bypass the cap requirement." — *defines the known exception to the no-ambient-root rule.*

- §3.2 Path resolution: Add: "Resolved path components are cached in a kernel-internal lookup cache (LUC), keyed by `(DomainId, NodeId, name)`. Cache entries carry a TTL set by the filesystem driver at resolution time. The LUC is per-mount-namespace (one per `Cap<MountPoint>`)." The spec currently has a page cache but no lookup cache; without one, the Stage 3 VFS will be unusable at realistic workloads. — *fills the dentry-cache-shaped hole in the spec.*

- §3.6 Filesystem driver interface: Add `fn invalidate_cache(&self, node: NodeId)` to the `Filesystem` trait. A filesystem driver that modifies a node must be able to invalidate the kernel's LUC entry for it. Without this, the lookup cache contains stale entries after write operations. — *required for cache correctness on mutable filesystems.*

- §4 Invariants: Add page-cache domain ownership invariant: "Page-cache pages for a filesystem-domain-backed FS are allocated in `filesystem/` core's domain, not in the filesystem driver's domain. The driver receives DMA-buffer-equivalent handles to read/write cache pages across the domain boundary. If the driver domain dies, the cache pages survive and are marked `FsError::FsDomainFault` pending." — *resolves the dirty-pages-after-crash ambiguity.*

- §6 Dependencies: Replace "rcu/ (Sleepable) for dentry-equivalent cache" with: "rcu/ QSBR for mount-tree structure; rcu/ hazard-pointer for lookup cache entries; rcu/ Sleepable for path resolution steps that may await I/O." Three separate patterns, each at the correct granularity. — *prevents choosing a single RCU variant that is wrong for two of three use cases.*

- §8 Open questions: Add a decision: "Encryption layer placement: per-file encryption lives in `filesystem/` core (Stage 4+), exposed via `Cap<FileNode, EncryptedWrite>` with a `Cap<Key, Derive>` provided at open time. Full-device encryption lives in `block/`. The two are composable but independent." — *closes the question with a concrete placement decision.*

---

## Open invariants / cross-subsystem hazards

**`filesystem/` ↔ `rcu/` sleepable RCU budget.** The `rcu/` sleepable variant requires cap-gated scopes and timeout-bounded sync (per `rcu/` spec §...). A mount-tree walk that crosses a virtiofs mount may await network I/O inside a sleepable RCU critical section. If the virtiofs daemon is unresponsive, the sleepable RCU section is held indefinitely. The RCU spec says "timeout-bounded" — what is the timeout, and what happens to the path resolution Future when it fires? The filesystem spec must define: max path resolution timeout per component, and the error type when a FS driver times out during a sleepable RCU section.

**`filesystem/` ↔ `capabilities/` cap table growth.** Every open file is a `Cap<NodeRef, FileRights>`. A long-running process that opens and closes files without explicit revocation grows its cap table. The spec says dropping the last cap closes the file, but the cap table slot may not be reclaimed immediately (depends on `capabilities/`'s reclamation policy, which is tied to `rcu/`). On a busy server opening thousands of connections, cap table growth could exhaust `capabilities/`'s table capacity. The spec needs a cap watermark and a documented back-pressure path.

**`filesystem/` ↔ `crypto/` integrity layer timing.** §2 lists `crypto/` as a dependency for "content-addressed or verified filesystems, Stage 4+." The virtiofs spec research summary warns about "semantic impedance mismatch" between FUSE ordering and queue ordering. If NARF adds per-read hash verification over virtiofs (a natural integrity extension), every read operation now includes a hash computation before the buffer is handed to the caller. This computation must happen in `filesystem/` core (not the driver domain) to be trustworthy. The key for verification must come from a `Cap<Key, Verify>`. The flow: read → virtiofs driver → buffer in core domain → hash → compare against manifest → caller. This is a new cross-domain pattern not described anywhere in the current specs.

---

## Additional opinionated commentary

The "persistent FS first target" question in §8 deserves a direct answer: write a NARF-native FS. Porting ext4 brings 30 years of POSIX compatibility baggage, including inode birth timestamps, sparse files, extended attributes, and a journal format NARF does not need. littlefs is designed for flash, not block storage, and its wear-levelling assumptions are wrong for NVMe. A NARF-native FS can be designed for the actual invariants: capability-addressed inodes, no backward symlinks, immutable path resolution semantics, and explicit async I/O. It will be less featureful than ext4 but it will be correct-by-construction against NARF's model. The virtiofs path (host provides the FS, NARF is a client) is entirely separate and should remain the primary path for Stage 4 while the native FS is developed in parallel.

The "no `/proc` / `/sys` replacement" decision is correct, but the spec hand-waves what replaces `/dev/urandom`. That is `crypto/`'s `rng_fill()`. But `/dev/null`, `/dev/zero`, and `/dev/full` have no equivalent in NARF's model. These are trivially implemented as special `Cap<FileNode, Special>` nodes but they need to exist somewhere, even if not at a fixed path. The relibc shim must provide them, and their backing implementation must be documented.
