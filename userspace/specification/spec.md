# userspace — Specification

> Status: **Outline v0.1** (Stage 4).

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

Bootstrap: every new process receives two ring pairs (submit + complete)
for the kernel ABI plus a read-only config page with capability
handles to its parent-granted services. Additional ring pairs for
inter-service communication are obtained by presenting `Cap<RingPair,
Alloc>` to the kernel's ring-pair allocator. The bootstrap config page
includes one `Cap<RingPair, Alloc>` as a pre-granted capability.

**Maximum ring pairs per process: 64 (default; system-wide tunable).**
Exhaustion fails subsequent allocations with `Err(RingPairBudget)`.

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

## 8. Open questions

- **POSIX shim scope:** true POSIX compatibility via full relibc, or
  native-first ABI with relibc as a thin compat layer?
- Dynamic linking: do we ship `ld-musl`-style dynamic linker, or static-only first?
- fork / exec semantics — do we do Linux-compatible fork at all, or
  spawn-only? (Preferred: spawn-only; fork is painful in a capability OS.)
- **Custom `PT_INTERP` as the capability-bootstrap site (Shiva-inspired).**
  NARF ships its own program interpreter; binaries point their
  `PT_INTERP` at it. The interpreter resolves relocations, sets up the
  submission/completion Narf-Rings, installs the cap table, and
  initialises TLS before handing control to `_start`. This is the
  natural home for the ABI bootstrap currently described in `abi/`.
