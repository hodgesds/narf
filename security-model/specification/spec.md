# security-model — Specification

> Status: **v1.0** (Stage 3 design lock). Drafted in Stage 1,
> revised every stage. v1.0 owns the **`DomainId` namespace** (the
> single source of truth for every reserved domain referenced
> across the tree), the threat model, the TCB enumeration, the
> TPM-rooted trust chain that the drivers framework signing flow
> layers on, and the side-channel posture.

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

## 8. Threat model (formal)

### 8.1 Attacker capabilities

The defender (NARF) must withstand:

1. **Untrusted user processes** — arbitrary code at CPL=3 / EL0
   with whatever caps were granted by their parent. May run
   unmodified relibc, custom binaries, JITed code, or a
   debugger.
2. **Compromised drivers** — kernel-mode code in `DomainId::DRIVER(n)`
   that has been corrupted (memory-safety bug, malicious
   author, supply-chain). The driver still runs in its assigned
   domain with its assigned caps; the threat is what it can
   reach beyond.
3. **Malicious devices** — DMA-capable hardware that may issue
   reads/writes outside its programmed regions, fire spurious
   IRQs, or violate protocol.
4. **Compromised user-mode driver host** — a user-mode-domain
   driver (drivers/spec §12) whose host process is corrupted.
   Same threat model as a compromised driver but at CPL=3.

### 8.2 Attacker goals (defended against)

- Read or write data in another domain (PKS/MTE-protected).
- Forge a capability or reuse a revoked cap.
- DMA into a domain not authorised for the device's IOMMU
  context.
- Bypass the bus dispatcher to claim a device already bound
  to another driver.
- Cause denial-of-service via cap-table exhaustion, IRQ-vector
  hoarding, frame-allocator starvation, or scheduler-budget
  abuse.
- Execute supervisor code via NX bypass, ROP/JOP, or BTI/CET
  evasion.
- Extract cryptographic key material from `DomainId::KEYS`.

### 8.3 Attacker goals (out of scope)

- **Speculative side channels at the domain boundary** — see
  §10.1 below.
- **Physical attacks** (cold-boot RAM extraction, DMA from a
  Thunderbolt cable to a non-IOMMU port, electron-microscope
  silicon analysis).
- **Firmware compromise below the kernel** — UEFI / BIOS / IPMI
  / SMM are out of NARF's control. Mitigated where possible by
  measured boot (§9), but a fully compromised firmware can
  always defeat the OS.
- **Hardware design flaws** without published microcode/firmware
  fixes (Spectre-class attacks beyond what the CPU vendor's
  mitigations cover).

### 8.4 The fence

The fence between defended and out-of-scope sits at the
boundary where NARF stops controlling the system: NARF defends
against attacks expressible in software running on top of an
honest CPU + honest firmware; below that line is hardware /
firmware territory and we trust them.

## 9. Trust chain (root to driver)

The trust chain that `drivers/spec` §5.3 layers on:

```text
TPM PCR (measured boot)
    │  (sealed against; locks the next link)
    ▼
Bootloader signature  ← UEFI Secure Boot or coreboot+vboot
    │
    ▼
Kernel image signature  ← signed by kernel-build CA
    │
    ▼
Kernel CA root key  ← compiled into the kernel image
    │  (signs vendor keys with permissions allowlist)
    ▼
Vendor cert  ← issued by kernel CA, 1-year validity, allowlists CapKinds
    │
    ▼
Module signature  ← Ed25519 over (.narfmod header + ELF blob)
```

**TPM PCR sealing** is optional but recommended: when
available, the kernel CA root's public key is sealed against
PCR 7 (Secure Boot state) and PCR 14 (kernel image hash). A
compromised bootloader that loads a different kernel cannot
unseal the CA root key, breaking the chain at install time.

**Without TPM**: the chain still works — the CA root is
embedded in the kernel image, which is itself signed by the
boot chain. Compromising the kernel image to substitute a CA
requires defeating UEFI Secure Boot + the install signature,
both of which are below NARF's threat model fence.

**Vendor cert revocation** is published as a signed revocation
manifest, distributed via the same channel as kernel updates,
and re-checked by the driver loader on every module load.
Revocation of a vendor cert immediately blocks loading any
module signed by that vendor; running modules continue but
log a `VendorRevoked` event and become unloadable on next
unload request.

## 10. Resolved decisions

### 10.1 Speculative side channels at domain boundaries

**Decision (was open):** **NARF does NOT defend against
speculative side channels at the domain boundary**, only at
address-space boundaries (kernel↔user) and at
explicit-no-leak boundaries (`DomainId::KEYS`).

**Rationale:** the cost of full speculative-side-channel
mitigation across every domain transition (PKS→PKS,
PKS→user, user→PKS) would be:

- ~30-50 cycles of `LFENCE`/`MFENCE`/`DSB ISH` per domain
  switch.
- Disabling speculative load past a PKS-protected access
  (would require the equivalent of `STIBP` on every
  cross-domain access — not currently exposed for PKS).
- Effective serialisation of the cross-domain hot path,
  destroying the performance benefit of in-kernel domain
  isolation.

The threat is real but bounded: a Spectre-class side channel
across a PKS boundary leaks bits of memory the attacker
already has logical read intent for. With cap-typed access
control, the attacker is at most learning what they could
already *try* to read but were blocked from. This is
significantly weaker than the cross-process Spectre threat
that motivates kernel-page-table-isolation.

**Mitigations applied at narrower boundaries:**

- Kernel↔user: full Spectre v2 / Meltdown / L1TF / MDS
  mitigations per `arch/`'s vulnerability matrix; this is
  the same posture mainstream kernels take.
- `DomainId::KEYS` boundary: explicit serialisation
  (`LFENCE` + scrub) at every entry/exit. Key material is
  the only domain whose contents must not leak even
  speculatively. The cost is concentrated on key ops, which
  are not hot-path.

**Future work**: when CPU vendors expose per-domain SBP
controls (Sapphire Rapids+ may have something usable for PKS),
revisit. For now, the tradeoff is documented.

### 10.2 Bootloader TCB membership

**Decision (was open):** **the bootloader is OUT of the kernel
TCB but IN the system TCB.** The kernel cannot defend against
a corrupted bootloader; measured boot (§9 PCR sealing) bridges
the gap. A system that hasn't enabled measured boot is
implicitly trusting its bootloader; a system that has shifts
the trust to the TPM hardware.

The kernel TCB enumeration in §4 is `{frame, memory domain
manager, capabilities table code, scheduler executor core}`.
Adding the bootloader would expand the audit surface
significantly without changing what the kernel actually
defends against — the bootloader's behaviour is fixed by the
time the kernel starts.

### 10.3 Firmware re-measurement after boot

**Decision (was open):** **firmware updates for drivers — i.e.
firmware blobs the driver downloads to its device — are
measured into a per-driver TPM PCR if the platform supports
it, otherwise logged**. The signing chain (§9) covers static
driver code; runtime firmware updates are a separate
attestation surface owned by the driver.

Concretely:

```rust
// Provided by crypto/ via Cap<Tpm, Extend>
fn extend_pcr(pcr: u8, data: &[u8]) -> Result<(), TpmError>;
```

A driver loading firmware to its device extends a per-driver
PCR with the firmware hash before issuing the device-side
load. Remote attestation can later verify "this driver is
running firmware blob X" by the PCR value.

Without TPM: the firmware load is logged to `tracing/` with
the hash; offline analysis can verify the binary against a
known-good catalog.

Either way, the **kernel CA root does not sign device firmware
blobs**. The driver vendor signs them; the driver verifies the
signature before loading; NARF doesn't get in the way.

## 11. Open questions

(none — all v0.2 questions resolved in §10)
