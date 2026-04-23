# memory — Design Notes

> 2026-04-22. Author: Claude Sonnet 4.6 (design-phase analysis).

---

## Load-bearing decisions

**PKS is per-CPU, not per-task.** The spec says `frame/` calls `enter_domain` on our behalf, but what it actually calls is `WRMSR(IA32_PKRS, mask)`. That MSR is per-physical-CPU. So "domain" in NARF maps to a current CPU state, not a task-private namespace. Two tasks at the same domain level running on different CPUs are isolated from each other (each core has its own PKRS), but a task preempted mid-critical-section will leave its PKRS mask in the next task's lap unless the scheduler saves/restores it. This is an implicit constraint the spec does not make explicit: **PKRS must be part of the task saved-state**, not just set on domain entry.

**Key 0 is the deny-by-default "free" key, not unrestricted.** The spec says untagged mappings "deny-by-default in release." PKS key 0 is the default for zero-field PTEs — it is the most dangerous key to misconfigure. If `IA32_PKRS.AD[0]` is set to 1 (deny), every untagged page faults. The invariant "every kernel mapping has a domain" implicitly requires the buddy allocator to tag frames at allocation time, before they are mapped. That is a Stage 2 dependency the spec does not spell out: the allocator must be domain-aware before any mapping using a non-zero key can be safely established.

**MTE granule is 16 B, not 4 KiB.** The spec is phrased at page-level semantics, which matches PKS. On aarch64, MTE tags at 16-byte granules — an order-of-magnitude finer. This is a silent cross-arch inconsistency. The allocator slab on aarch64 must align domain assignments to 16-byte boundaries, not just page boundaries. This is not a blocker, but it means "assign_domain(region, id)" has different alignment requirements per arch, and the spec's current signature does not communicate this.

**16 domains is a hard ceiling, and the spec punts.** §8 asks whether we support multiplexing. This is not a deferred question — it is a decision that must be made before Stage 2 lands, because the domain assignment policy (in `security-model/`) and the slab allocator (here) need to agree on a stable mapping. If multiplexing is possible, every `DomainId` is only meaningful relative to a task context. If it is not, we are allocating a global, static, sparse resource.

**Buddy allocator free-list contention on SMP.** The spec mentions per-NUMA-node lists as a future work item, but the Stage 1 SMP bringup in `scheduler/` means multi-CPU is actually Stage 2, and the buddy allocator will be hit from multiple CPUs immediately. A single global `IrqSafeSpinLock` on the free lists will serialize all frame allocations across CPUs — this is the classic Linux boot-path regressor. Per-CPU magazines or per-NUMA-node lists need to be at minimum designed before Stage 2, even if the implementation is simple.

---

## Divergences from precedent

**Linux SLUB/SLAB vs. NARF's per-domain slab:** Linux's slab allocator is not domain-aware at the hardware level (PKS was bolted on top of existing infrastructure). NARF proposes to make each slab "assigned to a domain." This is cleaner but imposes a hard constraint: a slab object cannot be accessed by code running in a different domain unless the domain rights mask explicitly allows it. This is the right design, but it means cross-domain reads (e.g., the Frame reading a driver's slab metadata to enforce a revocation) require temporary domain right widening, a pattern Linux avoids by running the whole kernel in domain 0 except for explicit protected regions.

**seL4 capability-typed memory vs. NARF's domain-tagged physical frames:** seL4 tracks every physical frame through its capability system — you cannot allocate a frame without holding a cap. NARF's `alloc_frame()` returns an `Option<PhysFrame>` with no capability check. The `PhysFrame` is `!Copy` so ownership is tracked in Rust types, but there is no revocation path for a live `PhysFrame`. If a driver holds a `PhysFrame` and its domain is revoked, the frame is not automatically returned. seL4 solves this with its CNode/untyped model; NARF has not addressed this. The Rust drop guarantee prevents leaks but not hostile holding.

**Redox uses a simpler buddy + Rust ownership model** that does not attempt hardware domain separation. NARF is doing something novel: hardware-enforced intra-kernel isolation without distinct page tables. The precedent for this is sparse — Linux's PKS usage is defensive (protecting a few ranges), not structural. NARF is betting the architectural bet; the risk is that aarch64 MTE's domain-switch cost model is different enough from x86_64 PKS to produce a visible asymmetry in driver isolation overhead between architectures.

**MTE vs. PKS domain-switch semantics are fundamentally different.** On x86_64, a domain switch is an explicit `WRMSR` — a single instruction that changes which keys are accessible. On aarch64, the domain identity is embedded in the *tag value of each pointer* in use. There is no per-CPU "active domain" register. To enforce that code in domain N cannot read domain M's data, you must ensure no pointer with tag M is reachable from domain N. This is a pointer-provenance problem, not a rights-mask problem. The spec treats them as symmetric via the HAL, but the implementation complexity is not symmetric. NARF's MTE "domain switch" is really "ensure all pointers flowing across the domain boundary have the correct tag," which requires tagging discipline at every allocation and IPC transfer — much closer to CHERI than to PKS.

---

## Proposed spec changes

- **§4 Invariants — add PKRS save/restore to task context:** State explicitly: "The active domain's PKRS mask is saved to the task's context block on preemption and restored on resume, by the scheduler, before any memory access in the new task's domain occurs." Without this, domain isolation has a TOCTOU window at every preemption.

- **§3 Public interface — split `assign_domain` into arch-specific granule forms:** `assign_domain(region: VirtRange, domain: DomainId)` should document that on aarch64, `region.start` and `region.len` must be 16-byte aligned (MTE granule), not just page-aligned. Add `#[cfg]-`documented alignment requirements or a typed `MteGranuleRange` wrapper.

- **§8 Open questions — resolve multiplexing before Stage 2:** Demote "do we support multiplexing?" from an open question to a mandatory pre-Stage-2 decision, documented in `security-model/`. The allocator's domain-tagging strategy and the scheduler's PKRS save/restore depend on the answer.

- **§4 Invariants — add frame-tag-at-allocation invariant:** Add: "A `PhysFrame` returned by `alloc_frame()` is always tagged to `DomainId::FRAME` (domain 0) at the point of return. The caller must invoke `assign_domain` before mapping into a non-Frame domain." This makes the allocation-to-domain-assignment contract explicit and prevents the gap where a freshly-allocated frame has no tag.

- **§5 Architecture notes — document MTE domain-switch model:** Add a note that "domain switch" on aarch64 is not a single instruction but a pointer-provenance discipline: all pointers passed across a domain boundary must be re-tagged, and the `enter_domain` HAL function on aarch64 has no direct analogue to `WRMSR`. The performance contract is therefore arch-asymmetric.

- **§6 Dependencies — add scheduler as a consumer:** `scheduler/` must write `PKRS` on every domain transition; add it as a consumer in the dependency list to make the PKRS save/restore coupling explicit.

- **§8 Open questions — add per-CPU magazine allocator design question:** "Should we implement per-CPU slab magazines (tcmalloc-style) in Stage 2 to avoid global buddy lock contention on SMP? If not, what is the SMP scale target?"

---

## Open invariants / cross-subsystem hazards

**`scheduler/` §3.5 (direct context transfer / domain entry):** Direct context transfer is the scheduler's mechanism for donating time-slices across domain boundaries. If the donated task is in domain N and the recipient is in domain M, a `WRMSR` must occur *before* the first instruction of the recipient executes. The scheduler spec does not state where in the transfer sequence the PKRS update occurs. If it is after the first instruction fetch, a window exists. Needs joint invariant between `memory/` §4 and `scheduler/` §3.

**`frame/` §? (domain fault handler):** When a PKS violation occurs (`PFEC.PK` set), `frame/` handles the trap. But `memory/` owns the PKRS mask semantics and the domain-to-key mapping. The fault handler needs to call into `memory/` to attribute the fault to a domain and return the correct `DomainId` for telemetry. This attribution function is not in §3's public interface. Either `frame/` calls `memory::domain_of_pte(pfec, va)` or `memory/` exposes a panic-safe attribution API.

**`tracing/` §3.4 (tracer domain):** The tracer task lives in `DomainId::TRACER`, which is "reserved by `memory/`." But the spec does not enumerate which `DomainId` values are pre-reserved. If `security-model/` allocates domain IDs and `memory/` reserves a few, there needs to be a single authoritative table. Currently memory §4 says domain 0 is the Frame; tracing says there is a TRACER domain. Neither spec says what the TRACER domain ID is, or that this is memory's responsibility to reserve.

**`capabilities/` revocation vs. `PhysFrame` drop:** As noted above, there is no forced return of `PhysFrame` when a driver's domain capability is revoked. `capabilities/` revocation (`capabilities/` §3 in future) needs a notification path into `memory/` to initiate frame reclamation, or NARF needs to document that domain revocation is always followed by a quiesce-and-free protocol, not a hard revocation.

**`rcu/` §? per-domain defer_drop queues:** RCU deferred drops are per-domain. The `defer_drop` queue itself is a data structure in some domain's memory. If a domain is being revoked, outstanding deferred drops in that domain's queue must be flushed to a safe zone before the domain's memory is reclaimed. This is a shutdown ordering problem the spec does not address.

---

## Additional opinionated commentary

The spec is remarkably clean for an outline, but it makes the classic mistake of treating PKS and MTE as two implementations of the same abstraction. They are not. PKS is a capability to *access classes of pages*, held in a per-CPU register. MTE is a *pointer-provenance* mechanism that catches spatial/temporal memory misuse. Using MTE as "domain isolation" requires a programming discipline that PKS does not — on x86_64 the hardware enforces the boundary even if code accidentally gets a stale pointer; on aarch64 the hardware only enforces if the pointer tag is wrong, which requires the software to tag correctly in the first place.

This does not make MTE a bad fit, but it means the aarch64 domain model is weaker against a capability-confused deputy (code in domain N that receives a legitimately-tagged pointer to domain M's data and then acts on it). On x86_64, PKS prevents the access even with a legitimate-looking pointer. On aarch64, MTE allows it because the tag matches. The spec should either acknowledge this as an accepted risk or add a pointer-tagging discipline (every cross-domain pointer transfer strips the tag and re-applies the receiver's domain tag) that restores equivalent isolation.

The 16-domain ceiling is real and will hurt. Consider: Frame (0), TCB (1), IPC rings (2), scheduler queues (3), tracer (4), crypto (5), filesystem (6), network (7), NVMe driver (8), GPU driver (9), virtio (10), bus/PCIe (11), user processes (shared?) (12), capabilities table (13), DMA buffers (14), spare (15). That is 16 exactly, and it assumes every driver type shares a domain, which undermines the isolation premise. The multiplexing question in §8 is not optional — it is the key architectural question.
