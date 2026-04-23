# security-model — Specification

> Status: **Outline v0.2**. Drafted in Stage 1, revised every stage.
> v0.2 owns the **`DomainId` namespace** — a single source of truth for
> every reserved domain referenced across the tree.

## 1. Purpose & scope

**Owns:** The end-to-end security story. Threat model, trust boundaries,
how capabilities and PKS/MTE domains compose, what each layer assumes of
the other.

**Does NOT own:** Concrete cap mechanics (in `capabilities/`), concrete
domain switching (in `memory/`), per-driver threats (in the driver spec).

## 2. Assumptions

- CPU, firmware, and the bootloader are trusted (see Threat model §A for
  the exact fence).
- Rust's type system is sound; `unsafe` blocks in the TCB are audited.
- Cryptographic primitives (when introduced) come from a vetted crate.

## 3. Public interface

Documents (not code). Cross-links to capability types in `capabilities/`
and domain IDs in `memory/`.

- Threat model (attacker capabilities, goals, out-of-scope attacks).
- Trust boundaries diagram.
- Composition rules: capability ⟂ domain — a Cap grants *what* may be
  done; a domain constrains *where in memory* the doing can reach.
- Incident response playbook (domain fault → recover / panic).

## 4. Invariants & safety properties

- The TCB is strictly {`frame/`, `memory/` domain manager, the
  capability table code in `capabilities/`, executor core in `scheduler/`}.
  Anything outside this set is untrusted relative to the framekernel guarantees.
- Every kernel-side data access is covered by *both* a capability check
  *and* a domain tag — defence in depth, not a single-point-of-failure.
- A compromised driver in domain N can affect domain N's data and its
  own capabilities; nothing else, modulo the **enumerated exceptions
  in §4.2 below**. "Modulo documented exceptions" without enumeration
  is equivalent to no claim at all.

### 4.2 Documented isolation exceptions (enumerated)

A compromised domain N can additionally:

1. **Read shared read-only kernel image pages.** The kernel `.text`
   and `.rodata` are mapped into every domain with `Read | Execute`
   so cross-domain calls work. This is exploitable for ROP-style
   gadget chains within the kernel image; CET (x86_64) and BTI/PAC
   (aarch64) raise the cost. Mitigation: regular kernel-image audit;
   `frame/` enforces `R+X` (no `W`) on these pages.
2. **Read the active clocksource.** `time::now_monotonic()` reads a
   shared cache line. Information leak is bounded to the value of a
   monotonic counter, which is not security-sensitive.
3. **Read per-CPU executor scheduling state.** Side-channel risk only
   (timing inference about other tasks); the actual data is one
   cache line containing the current task's domain id and
   poll-counter. Mitigation: `scheduler/` may pad timing on cross-
   domain wake if a future audit shows a meaningful leak.
4. **Read its own task's `DomainSavedState` snapshot.** Required for
   crash diagnostics; contents reveal only the task's own PKRS/TCF
   history.
5. **Trigger cap-revocation propagation by holding stale caps.** A
   compromised domain can hold capabilities forever and invoke them
   to learn whether they were revoked elsewhere — a 1-bit
   information leak per cap per invocation. Cost-benefit: acceptable.

Anything not listed above is a hole, not an exception, and must be
filed as a security bug.

### 4.1 `DomainId` assignment table (authoritative)

Both PKS (x86_64) and MTE (aarch64) provide 16 domains. NARF reserves
the namespace as follows. **Every spec that references a `DomainId::*`
constant points back to this table**; `memory/` exposes the IDs as
public constants, but the assignment policy is owned here.

| ID  | Symbol                  | Owner subsystem      | Rationale |
| --- | ----------------------- | -------------------- | --------- |
| 0   | `DomainId::FRAME`       | `frame/`             | Default-deny key; the TCB Frame's own data and trap-entry stacks. PTE PK field of zero (the legacy default) lands here, so any forgotten `assign_domain` call is contained. |
| 1   | `DomainId::CAPS`        | `capabilities/`      | Cap-table storage. Held only inside `Cap::invoke` and during cap mint/derive/revoke. Distinct from FRAME so a TCB code path cannot incidentally read or scribble cap rows. |
| 2   | `DomainId::MEMORY_MGR`  | `memory/`            | Buddy free-list metadata, page-table walk scratch, slab-cache headers. Splitting from FRAME limits PKS-fault attribution. |
| 3   | `DomainId::SCHED`       | `scheduler/`         | Per-CPU run queues, task headers, RCU per-CPU epoch slots. Distinct so a misbehaving wake path can't smear the Frame. |
| 4   | `DomainId::IPC`         | `ipc/`               | Narf-Ring control structures (head/tail/flag pages). Payload buffers belong to the *producer's* domain, not this one. |
| 5   | `DomainId::TRACER`      | `tracing/`           | Tracer task storage + per-domain trace ring metadata. Reserved by `memory/` at boot. |
| 6   | `DomainId::KEYS`        | `crypto/`            | Cryptographic key material. The only domain whose contents are forbidden from crossing a domain boundary even via Narf-Ring (operations are invoked into the domain; bytes do not leave). |
| 7   | `DomainId::OBSERVE`     | `observability/`     | PMU counter scratch, GDB stub buffers, crash-dump assembly area. |
| 8   | `DomainId::USERSPACE_K` | `userspace/`         | Per-task kernel-side state for user processes (cap table mirror, ABI ring control). User pages live in their own user-PKU keys; this is the kernel's view of them. |
| 9..14 | `DomainId::DRIVER(n)` | `drivers/` framework | Six driver slots, allocated on demand by the driver framework when a manifest is loaded. Slot reuse follows revoke + epoch bump in `capabilities/`. |
| 15  | `DomainId::SCRATCH`    | shared               | Scratch domain for cross-domain buffers established via `memory::assign_shared` (e.g. Narf-Ring payload regions tagged for both producer and consumer). Never holds long-lived state. |

**Driver slot exhaustion:** with six driver slots and the framekernel
calling for per-driver isolation, NARF will exhaust this fixed pool
quickly (virtio + nvme + net + gpu + bus = 5; add a second NIC = 6;
add anything else = overflow). The **multiplexing decision** flagged in
`memory/` §8 is therefore not optional — by Stage 3 we must support
context-scoped `DomainId` aliasing so a driver's *meaning* of slot 9
depends on which task the executor is polling. The mechanism couples
to PKRS save/restore in `scheduler/` §4 and to per-task domain-tag
remapping in `memory/` §3.

**Why not "one driver per slot"?** It would cap NARF at six concurrent
drivers — unacceptable for a serious OS. The hardware ceiling is real;
the workaround is software multiplexing, not architectural reservation.

**Why not give USERSPACE its own slot range?** User PKU keys are a
disjoint 16-key namespace (`MSR_IA32_PKRU` on x86_64; user-mode MTE
tags on aarch64). User domains do not consume PKS slots. Slot 8 here
is the *kernel-side* shadow only.

## 5. Architecture notes

### x86_64
- PKS provides 16 supervisor keys. We map one domain per key.
- SMEP/SMAP/CET are mandatory; fail boot if absent.

### aarch64
- MTE provides 16 tags; map one per domain. PAC hardens forward-edge
  control flow. BTI required on cores that support it.

## 6. Dependencies

- **Consumes:** `capabilities/`, `memory/`, `frame/`, `interrupts/`,
  `crypto/` (primitive assumptions, measured-boot story, `Cap<Key>` policy).
- **Provides to:** every subsystem spec for its "threats we defend against" section.

## 7. Stage assignment

- Stage 1: draft with trust boundaries + threat model skeleton.
- Stage 2: domain composition rules, because PKS/MTE now exists.
- Stage 3: capability composition rules, because caps now exist.
- Stage 4: userland story (sandboxing, syscall surface, relibc trust).

## 8. Open questions

- Do we defend against speculative side channels at the domain boundary,
  or only at address-space boundaries? (Cost is large.)
- Is the bootloader in or out of the TCB? (Depends on measured-boot story.)
- How are firmware updates for drivers re-measured after boot?
