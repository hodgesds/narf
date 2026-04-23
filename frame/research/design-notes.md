# frame — Design Notes
_2026-04-22_

## Load-bearing decisions

**CpuLocal is the root of all per-CPU trust.** Every subsystem that needs
CPU-local state (scheduler, domain manager, interrupt nesting count) reaches
through `frame::current()`. This makes `CpuLocal` a load-bearing chokepoint: if
it can be corrupted or spoofed, domain isolation collapses. The spec treats this
as a pinned-to-page invariant but gives no size budget, no generation stamp, and
no integrity tag. That omission is dangerous in the TCB.

**enter_domain is a raw `unsafe fn` with no audit trail.** The spec says it runs
with interrupts disabled and returns them in the same state. That is necessary
but not sufficient: there is no invariant that the *current domain* is tracked in
`CpuLocal`, no assert that `enter_domain` is not called from interrupt context
already inside a different domain, and no mechanism to detect domain re-entrancy.
On x86_64 a nested `WRMSR IA32_PKRS` silently overwrites the previous domain
rights; on aarch64 a nested pointer-tag transition is not even architecturally
defined as a stack.

**Trap dispatch fans out with no latency budget.** The spec says trap entry never
allocates and fans out to `dispatch_trap`. But the fan-out depth — to
`interrupts/`, to `memory/` for PKS faults, to `capabilities/` for permission
checks — is unbounded by the spec. A #PF with PFEC.PK in the hot path can chain
through several subsystems. There is no budget, no inline threshold, and no
assertion that the trap entry fast path stays below, e.g., 200 cycles.

**Panic path owns quiesce but not multi-CPU coordination.** The spec says panic
never returns and "quiesces the system." In a multi-CPU system this means the
panicking CPU must halt APs; otherwise a different CPU can continue faulting
into an inconsistent domain state. The spec defers AP bring-up to Stage 2 but
does not note that the panic path must be re-audited when SMP arrives.

## Divergences from precedent

**vs. seL4:** seL4 has no `enter_domain` primitive — it is a single-address-space
pure capability microkernel. NARF's domain entry is structurally closer to
ARM TrustZone/SMC world-switch than to seL4 IPC. This is justified by the
framekernel premise, but it means NARF inherits TrustZone-style risks: a domain
entry with the wrong PKRS value is a silent privilege escalation with no seL4
analogue. The spec does not acknowledge this risk.

**vs. Linux:** Linux uses `swapgs` + `KERNEL_GS_BASE` for per-CPU data —
identical to the NARF spec. NARF adds domain entry on top, which Linux does not
have. Linux's TSS IST (Interrupt Stack Table) reserves 7 stacks for NMI,
double-fault, etc. The NARF spec lists GDT/TSS but never specifies IST slot
count. Omitting NMI IST is a correctness bug: without a dedicated IST stack,
an NMI arriving while RSP points at a PKS-protected stack will fault on stack
access before the handler even runs.

**vs. Hubris:** Hubris uses a compile-time-known task table with zero runtime
allocation even for task creation. NARF's `CpuLocal` is dynamic but the spec
doesn't commit to a maximum size. Hubris's approach is too restrictive for NARF's
scope, but NARF should at least declare an upper bound for cache-pressure
analysis.

**vs. Redox:** Redox uses a single global interrupt handler table with per-IRQ
closures. NARF's design correctly separates `frame/` (trap entry) from
`interrupts/` (routing), which is cleaner. The divergence is justified.

## Proposed spec changes

- §3 Public interface: Add `pub fn current_domain() -> DomainId` to `CpuLocal` —
  domain re-entrancy detection and domain-aware assertion macros require knowing
  the *currently active* domain without calling into `memory/`. Without this,
  `dispatch_trap` cannot cheaply attribute a PKS fault to the right domain.

- §4 Invariants: Add **"CpuLocal must fit in two cache lines (128 bytes)"** as a
  hard invariant with a `const_assert!` in the linker script or a
  `static_assert_size!` at the top of `frame/`. Unbounded growth of `CpuLocal`
  creates cache pressure on every `frame::current()` call.

- §4 Invariants: Add **"enter_domain is not re-entrant; the caller must
  atomically save and restore the previous DomainId."** Specify that
  `enter_domain` reads `CpuLocal.active_domain`, asserts it differs from `id`,
  and stores the new value; on return the caller must call a symmetric
  `exit_domain`. This closes the silent PKRS-overwrite hazard.

- §5 Architecture notes (x86_64): Specify **TSS IST slot assignments**: IST1 =
  NMI, IST2 = double-fault, IST3 = machine-check, IST4..7 reserved. The current
  spec omits this entirely, which is an implementation-blocking omission for Stage 1.

- §5 Architecture notes (aarch64): Specify that **SP must be 16-byte aligned at
  EL1 vector table entry** and that MTE is turned off on entry to the trap vector
  (TCF=0, ATA=0) until `dispatch_trap` validates the domain, then re-enabled.
  The current spec says nothing about MTE state across exception entry — this is
  a Stage 2 correctness hazard.

- §7 Stage assignment: The spec says "Stage 2 (domain enter/exit hooks once
  `memory/` has domains)" but the interface already declares `enter_domain` at
  Stage 1. Clarify: **Stage 1 ships `enter_domain` as a no-op stub; Stage 2
  wires it to `memory/` domain manager.** As written, Stage 1 code calling
  `enter_domain` will silently do nothing, which is a correctness hazard if
  callers assume domain rights are active.

- §8 Open questions: Add **"What happens to in-flight async tasks when a domain
  faults?"** The current open questions focus on nested exceptions and
  `CpuLocal` size; they ignore the async executor interaction with domain faults,
  which is the most novel risk in NARF's design.

## Open invariants / cross-subsystem hazards

**frame ↔ scheduler:** The async executor lives in `scheduler/`, but domain
entry/exit must happen around task resumption. If the executor resumes a task in
domain D while PKRS/MTE is set to domain D′, the resumed task has the wrong
domain rights. The spec does not say who owns the domain-switch on task switch.
`frame/` §4 says `enter_domain` is `frame`-owned; `scheduler/` spec says nothing
about domain discipline. This gap must be resolved before Stage 2.

**frame ↔ memory:** The PKS fault path in `dispatch_trap` calls into `memory/`
to determine whether the fault is legitimate or a domain violation. But
`memory/` may itself be in a restricted domain (DOMAIN_MEM). A PKS fault inside
`memory/`'s domain-manager code will re-enter `dispatch_trap` — potentially
while `memory/` holds a spinlock. The spec does not say whether the PKS fault
handler enters or exits any domain before calling `memory/`. This is a potential
deadlock or domain-re-entry bug.

**frame ↔ capabilities:** `§4` says "any subsystem that touches [cap tables] must
hold `enter_domain(DOMAIN_CAPS)`." But `dispatch_trap` itself may need to
validate capabilities (e.g., for capability-fault handlers). If `dispatch_trap`
runs before any domain is set up (Stage 1), it cannot call into `capabilities/`.
The stage boundary is under-specified.

**frame ↔ console:** The panic path "hands over to `console/`." `console/` §4
says `panic_sink` is signal-safe and holds no locks. But if the panic fires from
inside a PKS-protected domain, the UART MMIO may be in domain DOMAIN_CONSOLE and
inaccessible. The panic path must explicitly call `enter_domain(0)` (or
DOMAIN_KERNEL) before writing to the UART — the spec says nothing about this.

## Additional opinionated commentary

The spec is appropriately minimal for a TCB component, but it hand-waves on
two critical details that will block implementation:

1. **No domain-stack discipline.** NARF's domain model is intra-address-space but
   the trap entry is effectively a mini-world-switch. Every serious intra-space
   isolation mechanism (Mondriaan Memory Protection, lwC, CHERI compartments)
   ended up needing a per-domain stack or at minimum a per-domain RSP save slot
   in the thread state. The NARF spec implies a single kernel stack per CPU
   (via TSS). If a trap fires while executing in domain D on a stack tagged for
   domain D, the trap handler must switch to a domain-0 stack before accessing
   any kernel globals. This is not specified anywhere.

2. **No explicit PKRS save/restore in the interrupt entry path.** On x86_64, PKRS
   is an MSR, not saved by hardware on interrupt entry. Every IRQ handler
   implicitly runs with the PKRS of whoever was interrupted. If domain D is
   interrupted while holding domain-D rights and the IRQ handler touches domain-0
   data, it will fault. Linux does not have this problem because it has no PKRS.
   seL4 does not have it because it has no PKRS. NARF is novel here and the spec
   must mandate: *PKRS is saved to CpuLocal and reset to domain-0 rights on
   every interrupt/exception entry, restored on iret/eret.* The assembly stub
   needs to include `WRMSR IA32_PKRS` before any C code runs.
