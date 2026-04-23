# "Capability Myths Demolished" (Miller, Yee, Shapiro, 2003)

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## Overview

"Capability Myths Demolished" is a landmark 2003 paper debunking misconceptions about capability-based security. It refutes claims that capabilities are less secure than ACLs, harder to use, or inherently tied to object-oriented programming. For NARF designers, this paper clarifies what capabilities actually are and dispels design anti-patterns.

## Key Mechanisms

**Principle of Least Authority (PoLA):**
The paper emphasizes that capabilities are fundamentally about the Principle of Least Authority: each process should hold only the authority (capabilities) it needs for its job. This is not merely a nice-to-have; it's a security property that prevents privilege escalation.

Capabilities enable PoLA naturally: you cannot access a resource you don't have a capability for. In contrast, ACL systems (UNIX permissions, Windows ACLs) can accidentally grant overly broad authority. NARF should use capabilities to enforce PoLA by construction.

**Object Capabilities vs. ACL Capabilities:**
The paper distinguishes "object capabilities" (first-class values representing unforgeable authority) from "security labels" (e.g., "User123 can read File456"). Many systems claim to support "capabilities" but actually implement ACLs. NARF should use true object capabilities—opaque tokens that the kernel validates, not delegatable attributes.

**Revocation and Confinement:**
A key misconception is that "capabilities can't revoke." The paper clarifies: revocation is possible with proper design. However, revoking a capability held by a malicious process cannot force it to stop using the capability (the process will continue accessing cached data). The right model is to revoke at the *resource* level (invalidate the target), not at the holder level.

NARF should implement revocation as resource-side termination: when a capability is revoked, the kernel invalidates all future attempts to use it, but doesn't "reach into" the holder's memory to delete stale references.

**Ambient Authority and Implicit Delegation:**
The paper criticizes "ambient authority"—authority granted implicitly by environment or position (e.g., a UID in UNIX). Capabilities eliminate this: authority is explicit, passed as arguments. This prevents accidental privilege escalation.

NARF's IPC should always pass capabilities explicitly in messages, never relying on the sender's identity or context to infer authority.

## Critical Invariants

1. **Capabilities are unforgeable:** A process cannot invent or guess a valid capability. The kernel alone issues them.

2. **Capabilities are first-class values:** They can be stored, passed, and delegated like any other data. This makes authority explicit in the code.

3. **No ambient authority:** Capability rights depend on the argument, not on who's asking. This prevents confused deputy attacks where a server misuses a client's authority.

4. **Transparent delegation:** If A passes a capability to B, and B passes it to C, C's rights are determined by the capability, not by any relationship between C and the original authority source.

## Performance Trade-offs

**Capability passing overhead:**
Each IPC must serialize and deserialize capabilities. This adds CPU and memory cost compared to implicit delegation (like UNIX UID-based access). However, the security gain—preventing confused deputy and privilege escalation—justifies the cost.

NARF's async executor can batch capability transfers with IPC messages to amortize this overhead.

**Revocation timeliness:**
Resource-side revocation is not instantaneous. A cached copy of a revoked resource can continue to exist in a process's memory. The revoker cannot force deletion. This is acceptable—revocation means "no new operations can start," not "erase all memory."

For NARF, this means revocation is O(1): you invalidate the capability in the kernel, and any subsequent use fails. No need for expensive tree walks or memory scans.

## Pitfalls and Warnings

1. **Revocation false expectations:** Developers often expect that revoking a capability immediately stops all uses. In reality, a process can continue using cached data. NARF's design must document this clearly.

2. **Capability "amplification":** If a process holds a weak capability but the kernel bug allows it to derive a stronger one, the security model is broken. NARF must ensure that capability derivation never strengthens authority.

3. **Covert channels via capability passing timing:** If capability passing takes variable time based on who holds it, attackers can infer information. NARF should use constant-time revocation checks.

4. **Delegation chains:** If A delegates to B who delegates to C who delegates to D, tracing authority becomes hard. NARF should keep delegation chains shallow (max 2-3 levels) and provide audit trails.

## Recommendations for NARF Capability Design

**Adopt:**
- Object capabilities as first-class values (opaque tokens, not security labels)
- Principle of Least Authority: every component holds only needed capabilities
- Explicit delegation: all authority is passed as arguments, never ambient
- Resource-side revocation: invalidate capabilities in the resource, not the holder
- Type-safe capability wrappers in Rust to prevent type confusion

**Avoid:**
- Ambient authority patterns (e.g., granting rights based on sender identity)
- Implicit delegation (e.g., allowing a server to infer rights from context)
- Expecting instantaneous revocation of cached data
- Long capability delegation chains (increases confusion risk)
- Mixing capability and ACL models (pick one consistently)

**Specific to NARF:**
- Make every capability transfer explicit in IPC messages
- Design so revocation is O(1) kernel-side operation (no tree walks)
- Document that revocation invalidates future operations, not cached data
- Implement revocation auditing: log who revoked what and when
- Use Rust's type system to enforce capability monotonicity at compile time (e.g., can't construct a Write capability from a Read capability)
- Design async executor to fail gracefully when a task tries to use a revoked capability

<http://srl.cs.jhu.edu/pubs/SRL2003-02.pdf>
