# KeyKOS and EROS Architecture — Capability System Design

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## Overview

KeyKOS (Hardy, 1985) and EROS (Shapiro, Smith, Farber, SOSP 1999) are foundational capability-based operating systems. KeyKOS was the first production capability OS, running on IBM System/370. EROS refined the KeyKOS model with persistence, real-time guarantees, and principled revocation. Together, they establish the core patterns that NARF's capabilities subsystem should follow.

## Key Mechanisms

**Capabilities as Unforgeable Tokens:**
In KeyKOS, a capability (or "key") is a token that grants authority to perform operations on kernel objects. Capabilities cannot be forged by userspace—they are issued and managed exclusively by the kernel. Each capability encodes:
- The object it refers to (by kernel-assigned ID)
- The rights granted (read, write, execute, etc.)
- Optional restrictions (type, domain confinement)

UserSpace holds capabilities in a capability table (similar to file descriptors in Unix). Unlike file descriptors, capabilities can be passed directly between processes, delegating authority without kernel intervention.

**Capability Spaces (CSpace):**
KeyKOS introduced the concept of a capability space (CSpace), a per-task table of capabilities. Each task has its own CSpace, indexed by slot number. Capabilities are accessed by slot ID (0–N), not memory address. This isolation prevents one task from enumerating or stealing another's capabilities.

EROS extended CSpace with a persistent variant (PCSpace) stored on disk, enabling recovery and migration. For NARF's design, CSpace isolation is critical—use PKS/MTE to enforce that CSpace pages are only readable/writable by the owning domain.

**Capability Derivation:**
Capabilities support attenuation—deriving a weaker capability from a stronger one without kernel help. For example, a read-write capability to a file can derive a read-only capability. Derivation uses a monotonicity rule: you cannot gain rights by derivation, only lose them.

EROS formalized this as a "resume capability," a return path that encodes both the thread state and the capability set it should see. This prevents privilege escalation through re-entry.

**Revocation Mechanism:**
KeyKOS's revocation walk traverses the capability derivation tree (the "Depends-On" tree or CDT) to find and revoke all derived capabilities. This is expensive—O(capabilities-in-system) in the worst case.

EROS improved this with epoch-based revocation: instead of walking the tree, each capability carries a generation tag. When a parent capability is revoked, the kernel increments an epoch counter. Derived capabilities with stale epochs are automatically invalid. This reduces revocation cost to O(1).

**Potency Levels:**
EROS introduced potency levels—a hierarchy of capability types where less powerful types cannot create more powerful ones. This prevents certain confused deputy attacks (where a weaker component is tricked into using a stronger capability).

## Critical Invariants

1. **Non-delegation without capability transfer:** A task cannot grant authority it doesn't hold. Capabilities are the sole mechanism for authority delegation.

2. **Revocation completeness:** Once a capability is revoked, no use of a derived capability should succeed. This requires the revocation mechanism to be comprehensive and synchronous.

3. **Type safety:** A capability's type (e.g., endpoint, memory object, device) is immutable and enforced by the kernel. You cannot re-interpret a memory capability as an endpoint.

4. **Attenuation monotonicity:** Capability derivation weakens, never strengthens. Rights can be removed, not added.

## Performance Trade-offs

**Capability lookup overhead:**
Each capability operation requires a CSpace lookup. KeyKOS used a flat table (O(1) lookup); EROS added a hierarchical variant for sparse spaces. For NARF with 16 domains, a flat CSpace per domain is reasonable (256–1024 entries per domain). Lookup cost is negligible compared to IPC overhead.

**Revocation cost:**
KeyKOS's CDT walk can be slow (proportional to system size). EROS's epoch approach is O(1) for revocation but requires generation counters in every derived capability. For NARF, adopt epoch-based revocation; the memory overhead of counters is acceptable.

**Derivation latency:**
Creating a derived capability can be done in userspace (with proper sealing) or by kernel syscall. Userspace derivation is faster but requires cryptographic sealing; kernel derivation is slower but simpler to verify. NARF could use a hybrid: kernel handles sealing, userspace handles attenuation checks.

## Pitfalls and Warnings

1. **Covert channels via revocation timing:** If revocation takes variable time (because the CDT walk is slow), attackers can observe system state via timing variation. EROS mitigates this with epoch-based revocation, which is constant-time.

2. **Confused deputy problem:** A deputy (mediator process) holding strong capabilities can be tricked into misusing them. NARF should implement potency levels to restrict which processes can issue certain capability types.

3. **Capability leakage via side channels:** If a process accidentally writes a capability to a shared buffer, an attacker with CSpace read access (via Spectre-class attacks) can steal it. NARF must combine capability isolation (PKS/MTE CSpace protection) with side-channel mitigations (speculative execution controls).

4. **Revocation race conditions:** If revocation is asynchronous, a task can use a capability after it's revoked. NARF must ensure revocation is synchronous—the revoker blocks until all derived capabilities are invalidated.

5. **CDT memory overhead:** If every capability relationship is tracked, the CDT grows quadratically. EROS solved this with epochs; NARF should do the same.

## Recommendations for NARF Capabilities Designers

**Adopt:**
- Unforgeable token model: capabilities are kernel-issued, not userspace-derivable
- Per-domain CSpace isolated by PKS/MTE domain tags
- Epoch-based revocation for O(1) revocation cost
- Capability attenuation with monotonicity guarantee
- Potency levels to prevent confused deputy attacks
- Type-safe capability encoding in Rust using phantom types or newtype wrappers

**Avoid:**
- Flat global capability table (use per-domain CSpaces)
- CDT-based revocation (expensive and timing-leak risk)
- Capability representation as raw pointers (use opaque tokens)
- Allowing userspace to create new capabilities (always go through kernel)
- Mixed revocation models (consistent epoch-based revocation across all domains)

**Specific to NARF:**
- Combine KeyKOS's CSpace model with EROS's epoch revocation
- Use PKS domain tags to isolate CSpace pages per domain
- Implement MTE tags on capability structures to detect corruption
- Store revocation epochs in a kernel-owned array indexed by capability ID
- Design IPC to pass capabilities by CSpace slot ID, not by value (zero-copy safety)
- In async executor, ensure revocation completion is visible before resuming suspended tasks

<https://www.cis.upenn.edu/~KeyKOS/>, <https://pdos.csail.mit.edu/6.828/2008/readings/keykos-osr.pdf>
