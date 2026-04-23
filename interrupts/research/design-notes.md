# interrupts — Design Notes

> Author: AI design review. Created 2026-04-22.

---

## Load-bearing decisions

1. **UIPI as primary fast-path on x86_64, with no equivalent on aarch64.** The entire "driver trap bypass" story depends on Intel UIPI (SDM Vol. 3A §11). The aarch64 GICv3 ITS path still delivers through the EL1 vector table; the gap is documented in `summaries/intel-uipi.md` but not yet canonised as an arch-divergence in `spec.md §5`.

2. **UPID and UITT live in kernel-controlled PKS domain 0.** If a driver could write to its own UPID, it could mask incoming interrupts (a DoS against itself or trick routing). The Frame must own those structures. This is implicit in the spec but unstated as an invariant — a compromised domain that can't DMA-write its own UPID but can craft a `SENDUIPI` could potentially spam another domain if UITT entry validation is lax.

3. **One IRQ owner at all times.** The `IrqTarget::Kernel` fallback and `IrqTarget::Uipi` are mutually exclusive by spec §4. Transition between them (e.g., driver reload) is a TOCTOU window: the Frame can acknowledge an edge-triggered IRQ after the old UITT entry is torn down but before the new one is installed, swallowing an interrupt.

4. **EOI-on-spurious always.** This is the right call for edge-triggered sources (spurious at the LAPIC level means the interrupt was already claimed by another CPU), but level-triggered devices that have dropped their assertion before the handler runs will see a legitimate spurious on x2APIC. The current invariant is correct but needs the "level-triggered caveat" documented.

5. **`rcu/` QSBR guards the IRQ routing table.** This means IRQ registration/deregistration blocks until all CPUs pass a quiescent state. At Stage 2, with a cooperative async executor, this is fine. At Stage 3+ with preemption, QSBR quiescence may stall a CPU pinned in a long Future poll. `rcu/` sleepable variant (Stage 3) must be adopted by `interrupts/` before the preemptive scheduler lands.

---

## Divergences from precedent

**vs. Linux:** Linux keeps interrupt routing in the kernel's own ring-0 context exclusively; drivers get a `request_irq` callback that runs at interrupt priority. NARF routes interrupts *into* a domain via UIPI, removing the kernel from the fast delivery path. This is a significant departure: Linux's design means every IRQ handler is under watchdog supervision (NMI watchdog, RCU stall detector). NARF's UIPI path has no such supervision once delivery completes. A stalled UIPI handler in domain N won't trigger a kernel panic — it will silently starve its device. Monitoring strategy for stuck UIPI handlers is unspecified.

**vs. seL4:** seL4 delivers interrupts as async IPC notifications to capability endpoints. A driver polls the endpoint (or the notification triggers a context switch). NARF's UIPI is faster (hardware-delivered, no poll loop unless receiver is off-CPU), but seL4's model has a cleaner audit trail: every IRQ delivery is a capability invocation. NARF's UIPI delivery bypasses capability checks on the *delivery side* — the UITT configuration is the security gate, not a runtime cap check. This is justified on performance grounds but means revocation of an IRQ cap must tear down the UITT entry atomically and synchronously, which the spec §3 does not yet describe.

**vs. Fuchsia:** Fuchsia interrupt objects are capabilities; user-space drivers call `zx_interrupt_wait()` which is kernel-mediated. NARF's approach is architecturally bolder but relies on PKS/UITT correctness being auditable — any bug in UITT setup allows cross-domain interrupt injection.

**vs. real-time kernels (Xenomai/PREEMPT_RT):** RT kernels treat IRQ latency as a first-class metric with hard bounds. NARF's async executor introduces variable delivery latency because a UIPI arriving while the receiver's Future is not polled parks in the UPID until the executor reschedules the receiver. On aarch64 without UIPI there's the additional trap overhead. Neither bound is stated anywhere in the spec.

---

## Proposed spec changes

- §2 Assumptions: **Add assumption** that `CR4.UINTR` can be set, and that PKS is available on the boot CPU — if either is absent, `interrupts/` must fall back to kernel-mode-only dispatch. Currently the spec assumes UIPI silently and has no fallback path described.

- §3 Public interface: **Add `deregister_irq(n: IrqNum)` and a quiescence fence** — the current API has `register_irq` with no tear-down path. Without it, driver reload (Stage 3) has no safe IRQ reclamation story. The fence must synchronise with `rcu/` QSBR so in-flight UITT reads complete before the UITT entry is zeroed.

- §4 Invariants: **Add UITT ownership invariant**: "UPID and UITT memory belongs to DomainId 0 (Frame); no driver domain may map it read-write." This closes the mask-your-own-interrupt attack described above.

- §4 Invariants: **Add stuck-handler detection invariant**: "A UIPI handler that has been 'in-flight' (UPID.ON set, vector pending) for longer than `MAX_IRQ_LATENCY_NS` must trigger a domain-scoped watchdog via `frame/` rather than silently stalling." Stage 2 can implement this with a per-driver software timer.

- §5 aarch64: **Explicitly document the asymmetry** — GICv3 ITS delivers to EL1 vector table; no direct-to-domain delivery. Add an open question: "Does GICv4 direct-inject for non-virtualisation workloads (each PKS domain ≡ a vPE) give us UIPI-equivalent latency on aarch64? Investigate before Stage 3."

- §6 Dependencies: **Add `scheduler/` as a consumer** — UIPI delivery to an off-CPU receiver must enqueue a wake-up in the executor. This bidirectional relationship (interrupts wakes scheduler, scheduler programs UITT when rescheduling a domain) is the highest-frequency cross-subsystem interaction in the whole kernel and needs explicit documentation.

- §8 Open questions: **Add "UIPI multiplexing"** — spec §8 already notes "1:1 vs. multiplex," but the answer has security consequences. If multiple tasks share a receiver UPID, any one of them can mask the others' deliveries by monopolising the UIF flag. Resolve before Stage 2 exit.

---

## Open invariants / cross-subsystem hazards

**interrupts ↔ memory §2 (domain manager):** UITT and UPID allocation must be in PKS domain 0 (the Frame's domain). `memory/` has no current API to allocate into a *specific* domain on behalf of `interrupts/`. `memory::alloc_frame()` returns an untagged frame; `memory::assign_domain()` is a post-hoc operation. There's a window between allocation and domain tagging where another domain could touch the frame. Need atomic "alloc-and-tag" semantics.

**interrupts ↔ scheduler §3.5 (CPU hot-plug):** When a CPU is brought offline, all UIPI receivers whose `UPID` targets that CPU's LAPIC ID become non-deliverable. The spec says nothing about migrating UIPI receiver state on CPU offline. If a domain is pinned to a CPU being taken down, pending interrupts vanish. This needs explicit handling in `scheduler/` Stage 2 (SMP hot-plug up) and a protocol in `interrupts/`.

**interrupts ↔ rcu §4 (QSBR quiescence):** The IRQ routing table is RCU-protected. On the UIPI fast path the reader holds no lock and takes no quiescent point — this is correct for QSBR (the reader being in a kernel Future poll is not a quiescent state). But if a Future poll runs without yielding for a long time (driver hot loop), `rcu/` stall detection will fire. `interrupts/` must document its quiescent-state discipline.

**interrupts ↔ capabilities §3 (Stage 3 gate):** Spec §2 says capabilities will gate IRQ registration in Stage 3 via `Cap<Irq(n), Own>`. But at Stage 2, IRQ registration is ungated. This is a deliberate stage split, but the interface (`register_irq`) will change signature between stages. The spec should version this change so Stage 2 callers (drivers framework) don't need to be rewritten wholesale at Stage 3.

---

## Additional opinionated commentary

The biggest under-specification is the **aarch64 delivery model**. The spec hand-waves "FIQ or event-register polling" as the driver-notification path. FIQ-to-EL1 is still a trap; EL0 FIQ routing requires FIQ-enable in HCR_EL2 which only makes sense in a virtualisation scenario. For a bare-metal framekernel where everything runs at EL1, the fast path for aarch64 domain notification is most likely: GICv3 LPI → EL1 vector table → Frame dispatches to domain via a lightweight software bounce → domain poll. That's one more hop than UIPI on x86_64, and the spec should state this rather than implying parity. GICv4's direct-inject feature could close the gap but only in a virt context (vPE model), which is architecturally awkward for a bare-metal design.

The `SENDUIPI` for driver-to-driver signalling is compelling and under-developed. If two drivers in different domains can SENDUIPI each other, the UITT table for each must be managed by the Frame. Any bug in that management is a cross-domain interrupt injection primitive. This should be called out as a TCB surface in `security-model/`.
