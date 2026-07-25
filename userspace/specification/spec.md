# userspace — Specification

> Status: **v1.0** (Stage 4 design lock). v0.1 covered the
> Process abstraction + bootstrap + stable user-ABI promise;
> v1.0 locks the syscall versioning wire format that the
> drivers framework SDK mirrors, the PT_INTERP bootstrap, the
> POSIX-shim scope, and fork/exec semantics.

## 1. Purpose & scope

**Owns:** Process (and thread) abstraction at kernel level, ELF loader,
vDSO-like async-ring bootstrap page, relibc glue, minimal POSIX shim
surface that relibc needs.

**Does NOT own:** A specific shell / init / service manager. Those are
applications above NARF.

## 2. Assumptions

- `capabilities/` mints per-task cap tables.
- `ipc/` provides the ring pairs that a new process inherits.
- `memory/` allocates user address space and (optionally) a user PKU key.
- `scheduler/` schedules user tasks identically to kernel tasks (both
  are Futures).

## 3. Public interface

```rust
pub struct Process { /* cap table root, VM root, threads */ }
pub fn spawn_process(elf: &Elf, caps: CapBundle) -> Cap<Process, Own>;
pub fn exec_into(proc: &Process, arg0: &str, argv: &[&str], env: &[&str]);
```

The Linux-compatibility syscall surface includes stored `prctl(2)` process
state required by service managers and brokers. Capability-shaped controls
such as `PR_SET_KEEPCAPS` round-trip according to the Linux ABI but do not mint
or retain NARF capabilities; authority remains capability-object based.
Likewise, `SO_PEERSEC`, `SO_PEERGROUPS`, and `SO_PEERPIDFD` report
`ENOPROTOOPT` while NARF has no Linux Security Module label provider,
socket-stamped supplementary group list, or retained peer pidfd; the
compatibility layer never fabricates security identity.
AF_UNIX stream clients may bind a local pathname or abstract address before
`connect(2)`; binding does not put the socket into listening state. Connected
stream receive operations honor `MSG_PEEK` without consuming queued bytes.
Epoll readiness callbacks run without holding the parent epoll instance lock,
including during edge-state write-back for nested epoll sets.
Poll and epoll pass the file-description offset to offset-sensitive readiness
providers; `/dev/kmsg` is readable only while unread snapshot bytes remain.
`open(2)`/`openat(2)` reject an empty pathname with `ENOENT` before cwd
normalization; an empty path never aliases the current directory.
`clock_gettime(2)` accepts realtime/monotonic coarse clocks and process/thread
CPU clocks. Coarse clocks currently use the precise source; CPU clocks use the
calling task's accumulated user and kernel accounting.
Anonymous pipes implement `FIONREAD` on both ends and report the shared
immediately-readable byte count. Writes and final endpoint closure publish a
readiness notification so parked `poll`/`epoll` waiters wake without unrelated
system activity.
Legacy `clone(2)` honors `CLONE_PIDFD` by installing a pidfd in the parent and
writing its descriptor through the overloaded `parent_tid` pointer argument.

Linux NUMA compatibility reports live topology rather than a structural
single-node stub: `getcpu(2)` returns the current logical CPU and its
SRAT proximity node, while `move_pages(2)` walks the caller's page tables,
reports physical placement, and can replace resident private backing on
another node. `migrate_pages(2)` moves the caller's resident private pages
between node masks. Fault-time `set_mempolicy(2)` and `mbind(2)` placement
is intersected with the task's cgroup-v2 `cpuset.mems.effective` mask;
`get_mempolicy(MPOL_F_MEMS_ALLOWED)` reports that effective constraint.
`get_mempolicy(2)` rejects unknown/conflicting flags, undersized nodemask
buffers, and addresses supplied without `MPOL_F_ADDR`; address+node
queries fault in valid lazy pages and report their actual SRAT node.
`MPOL_F_STATIC_NODES` preserves physical node identities across cpuset
changes; `MPOL_F_RELATIVE_NODES` maps user-mask ordinals into the current
`cpuset.mems.effective` set and folds oversized ordinals as Linux does.
Both use Linux UAPI bits 15 and 14. `MPOL_PREFERRED_MANY` chooses the
nearest member of its preferred set by SLIT distance and falls back only
after preferred nodes are exhausted.
`MPOL_WEIGHTED_INTERLEAVE` distributes new base-page and hardware-huge-page
allocations according to the global per-node weights, while still intersecting
the policy mask with `cpuset.mems`. Weights are configured through Linux's
`/sys/kernel/mm/mempolicy/weighted_interleave/nodeN` ABI.
Automatic mode consumes real local-node HMAT access-bandwidth coordinates,
reduces them to bounded integer ratios, and is controlled by the sibling
`auto` attribute. A manual node-weight write disables automatic mode.
Ordinary and weighted interleave sequence positions are task-owned, survive
CPU migration, and are reclaimed with the task; CPU-local allocator state
does not determine a process's placement cycle.
`MPOL_F_NUMA_BALANCING` is accepted only with `MPOL_BIND` or
`MPOL_PREFERRED_MANY`. A bounded periodic scan protects one eligible base page
per task every 256 running timer ticks. Its next access restores the mapping
and, when the accessing CPU's node is inside the effective policy/cpuset mask,
migrates the private page there. Shared, locked, lazy, and policy-ineligible
pages are not sampled; allocation failure restores the original mapping.
`mbind(MPOL_MF_MOVE)` immediately conforms resident private pages in the
range, `MPOL_MF_STRICT` reports remaining misplacement as `EIO`, and
`MPOL_MF_MOVE_ALL` requires authority NARF does not grant ambiently.
`set_mempolicy_home_node(2)` updates the distance anchor of existing
MPOL_BIND or MPOL_PREFERRED_MANY ranges and returns `ENOENT` when no
eligible policy overlaps.
`move_pages(2)` migrates registry-owned shared-memory base pages by replacing
every live address-space alias under one rollback-capable transaction and
committing the shared-object backing last. Device/DMA shared mappings remain
non-migratable without an owner-specific quiesce protocol.
Removing a shared-memory handle rejects new attachments immediately but keeps
each already-mapped backing page registered and movable until its final
address-space alias is unmapped. Alias release occurs only after leaf teardown
and cross-CPU TLB invalidation; the final release returns the frame to the
allocator.
Anonymous private `mmap(MAP_HUGETLB)` supports Linux's default/explicit
2 MiB and explicit 1 GiB encodings when boot-reserved backing is available.
Mappings use hardware PD/PDPT leaves on x86_64 and L2/L1 block descriptors
on aarch64; allocation honors the effective task/range mempolicy and
`cpuset.mems`; `move_pages`, `migrate_pages`, and `mbind(MPOL_MF_MOVE)`
migrate complete hardware leaves between per-node pools while preserving
contents; `mprotect` operates at the selected hugepage granularity, `munmap`
returns backing to its per-node pool, and `fork` eagerly copies private huge
mappings on their original nodes. File-backed hugetlbfs and shared huge
mappings fail explicitly because NARF has no hugetlbfs or shared-huge refcount
contract.
The procfs task snapshot includes both base-page and hardware huge-page
regions with effective policy and per-node residency for
`/proc/<pid>/numa_maps`.
Sysfs exposes Linux memory blocks under `/sys/devices/system/memory/memoryN`
and each block's `nodeN/memoryN` membership from allocator RAM ranges
classified by SRAT; CPU topology is never used to infer memory membership.
Runtime hotplug creates newly discovered `memoryN` objects after allocator
commit. Offline blocks retain their identity and node membership, while
`state` and `online` query live topology across offline/online cycles.
Only CPU- or memory-bearing `nodeN` directories are instantiated; unused
architectural slots remain advertised through `possible` without appearing as
phantom nodes to Linux perf's directory-based topology reader. Membership is a
Linux-compatible `nodeN/memoryM -> ../../memory/memoryM` symlink.

Bootstrap: every new process receives two ring pairs (submit + complete)
for the kernel ABI plus a read-only config page with capability
handles to its parent-granted services. Additional ring pairs for
inter-service communication are obtained by presenting `Cap<RingPair,
Alloc>` to the kernel's ring-pair allocator. The bootstrap config page
includes one `Cap<RingPair, Alloc>` as a pre-granted capability.

**Maximum ring pairs per process: 64 (default; system-wide tunable).**
Exhaustion fails subsequent allocations with `Err(RingPairBudget)`.

The stack-daemon launcher keeps `StackAttachReply::admin` in kernel memory and
may bind it to an `AF_NETLINK`/`NETLINK_ROUTE` fd owned by the current task.
The fd is resolved through that task's table and the typed `SocketFile`; no raw
`AdminHandle` or capability slot is accepted through the Linux syscall ABI.
A public native cap-bearing operation remains unavailable until submissions
are validated against a real per-task capability table.

## 4. Invariants & safety properties

- No ambient authority: a new process has only the caps explicitly granted.
- **PKU and PKS are entirely independent hardware mechanisms** that
  happen to share a numeric range (0..15). A user process holding
  PKU key 3 and a kernel driver in PKS domain 3 do **not** interact —
  the hardware enforces them on disjoint accesses (Ring 3 data vs.
  supervisor data). The earlier wording "user PKU matches kernel PKS
  domain IDs only where explicitly shared" was misleading. What is
  *actually* shared is memory: a region can be mapped with both a
  user-accessible PKU key and a kernel-accessible PKS key, granting
  both rings independent access. The keys themselves do not unify.
  The kernel-side shadow lives in `DomainId::USERSPACE_K` regardless
  of which user PKU key the user side uses.
- relibc never performs a syscall the kernel hasn't explicitly wired up.

### 4.1 Stable user-space ABI promise

**NARF commits to the Linux "do not break user-space" principle.**
Once a syscall number lands in `Syscall` and is called by a binary
in narf-libc, its v0 wire ABI — argument shape, return semantics,
side effects observable to the caller — is stable indefinitely.

**Mechanisms for evolving the surface without breaking pre-existing
binaries:**

1. **Mint a new syscall number** when the new operation is
   conceptually distinct (e.g. `read` vs `pread64`).
2. **Mint a new version of an existing syscall** when extending the
   semantics of the same conceptual operation (e.g. tightening
   error reporting, broadening permitted argument values, adding a
   typed flag bits field). Versioning happens via the upper 8 bits
   of the 32-bit syscall number — see below.

**Wire format.** A raw syscall number is `(version << 24) | num`:

| bits   | field        | notes                                       |
|--------|--------------|---------------------------------------------|
| 0..23  | syscall id   | canonical number (16M slots; ~234 used)     |
| 24..31 | ABI version  | 0 = canonical wire ABI; 1..255 = overrides  |

`narf_userspace::{syscall_pack, syscall_number, syscall_version,
SYS_VERSION_SHIFT}` are the helpers. Pre-versioning binaries encode
`version=0` implicitly (the upper bits are zero), so they keep
dispatching to the v0 handler forever. New binaries opt in to a v1
ABI at compile time by packing `1` into bits 24..31; the kernel's
dispatch (`SyscallTable::dispatch_ctx_versioned`) probes the v1
handler first and falls through to v0 when no override exists for
the requested version.

**What's allowed under this promise:**

- Adding new syscall numbers (with reserved-zero argument fields
  the new path checks for).
- Adding new versions of existing syscalls.
- Adding new flag bits to existing typed flag arguments **only when
  zero is the prior caller's "I don't know about this bit" value**
  and the kernel rejects unknown bits (so a pre-existing caller
  that happens to set the bit gets a typed error instead of silently
  surprising behavior).
- Tightening reserved-zero fields to typed errors (callers that
  previously sent zero are unaffected).
- Loosening previously-rejected argument values (callers that sent
  the rejected values were already broken; loosening them turns
  failures into successes).

**What's not allowed:**

- Changing the meaning of an existing argument or return value at
  the same `(syscall, version)`.
- Removing a syscall number once published (it stays as a permanent
  no-op or tombstone if obsolete).
- Reusing a previously-published syscall number for a different op.

The `Syscall` enum is therefore append-only across the kernel's
lifetime; tombstoning an obsolete syscall is fine, removing the
number is not.

## 5. Architecture notes

### x86_64
- User CS/SS + `sysret` for slow-path return; rings bypass it on fast path.
- Stack red-zone honoured.
### aarch64
- EL0 entry; `eret`; TPIDR_EL0 for TLS.

## 6. Dependencies

- **Consumes:** `capabilities/`, `ipc/`, `memory/`, `scheduler/`, `abi/`,
  `arch/`, `frame/`, `net/` (stack-daemon attach protocol for a
  userspace network stack), `filesystem/` (per-task root caps).
- **Provides to:** everything running outside the kernel.

## 7. Stage assignment

Stage 4.

## 8. Resolved decisions

### 8.1 POSIX shim scope (resolved)

**Decision (was open):** **native-first ABI with relibc as a
thin compat layer**, not full POSIX compatibility.

The native NARF userspace ABI is the ring-pair model in §3.
relibc lives on top, translating POSIX calls (`read`, `write`,
`open`, `mmap`, …) into NARF submissions. Programs that link
against relibc compile from POSIX source unchanged; programs
that link against `narf-userspace-runtime` (a thin
typed-async crate) skip the POSIX layer entirely.

**Rationale:** full POSIX compatibility (every syscall, every
flag, every edge case) is the long-tail cost that has dominated
every "POSIX-on-microkernel" project. By making NARF-native
the primary ABI and relibc the bridge, we keep the surface
area honest. Production NARF code should target the native
ABI; relibc is for porting existing code.

### 8.2 Dynamic linking (resolved)

**Decision (was open):** **dynamic linker ships in v1.0** —
the `narf-ld.so` interpreter referenced via `PT_INTERP` (see
§8.4). Static-only would force every userspace binary to
re-include relibc + the runtime, multiplying image size; for
hundreds-of-applications scaling the dynamic linker is not
optional.

The dynamic linker is the same Shiva-style relocation engine
the driver framework's loader uses (`drivers/spec` §14). One
implementation, two consumers.

### 8.3 fork/exec semantics (resolved)

**Decision (was open):** **spawn-only**. NARF does not
implement Linux-compatible `fork()`. The
posix_spawn-equivalent native primitive is
`spawn_process(elf, caps)` in §3.

**Rationale:** `fork()` requires copy-on-write of the parent
address space, which interacts badly with cap tables (does
the child get a copy of every cap? clones are an explicit
operation in NARF, not implicit copies), with PKS/MTE domain
state (each domain's PKRS/TCF would need cloning), and with
the bootstrap ring pairs (you'd have two processes sharing a
ring and immediately diverging). The semantic mess is not
worth Linux source-compatibility for the small set of
programs that genuinely need fork-without-exec.

relibc's `fork()` returns `Err(ENOSYS)`. POSIX programs that
call `posix_spawn` work; programs that `fork(); exec()` are
patched (typically by replacing with `posix_spawn`).
`vfork()` is similarly unsupported. This is a known porting
cost for legacy code; the alternative is unsoundness in the
cap+domain model.

### 8.4 PT_INTERP capability bootstrap (resolved)

**Decision (was open):** **NARF ships `narf-ld.so`**, the
custom program interpreter referenced by every userspace ELF's
`PT_INTERP`. The interpreter is the Shiva-inspired model:

1. Kernel loads ELF, sets up address space, jumps to interp's
   entry point (not the program's).
2. Interpreter runs in user mode with bootstrap caps (provided
   via the kernel-mapped config page from `abi/spec` §3.1).
3. Interpreter resolves relocations against shared libraries
   (loaded via further bootstrap caps), populates the GOT,
   installs the program's cap table, allocates submission +
   completion rings.
4. Interpreter jumps to the program's `_start`.

This **moves the ABI bootstrap currently in `abi/spec` §3.1
into user mode**. The kernel's only role is loading the
interpreter and minting one bootstrap cap; everything else is
user code that can be debugged, traced, and updated without
kernel changes.

The interpreter is the same code path the driver loader uses
(see `drivers/spec` §11), just running in user mode instead of
kernel mode. One relocation engine, two callers.

## 9. ABI versioning

Syscall versioning per §4.1 is the canonical ABI-version
pattern across the kernel — all subsequent specs (`drivers/`,
`capabilities/`, etc.) mirror it.

`USERSPACE_ABI_MAJOR = 1`, `USERSPACE_ABI_MINOR = 0`.

The Syscall enum is **append-only** indefinitely (§4.1). Removed
entries become tombstones (returns `Err(ENOSYS)`) but keep
their number reserved.

## 10. Open questions

(none — all v0.1 questions resolved in §8)
