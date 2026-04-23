# frame — Specification

> Status: **Outline v0.2** (Stage 1 → 2). v0.2 tightens `enter_domain`
> re-entrancy and specifies PKRS save/restore on trap entry.

## 1. Purpose & scope

**Owns:** Boot CPU bring-up, per-CPU state, privilege/domain configuration
(registering the set of PKS/MTE domains), IDT/GDT (x86_64) or exception
vector table (aarch64), trap/exception dispatch entry, panic path.

**Does NOT own:** Scheduling decisions (`scheduler/`), memory policy
(`memory/`), IRQ routing decisions (`interrupts/`). The Frame just gives
those subsystems the hooks they need.

## 2. Assumptions

- `boot/` has placed the kernel at its linked address with the MMU in a
  known state (see `arch/`).
- `arch/` provides CPU/MMU primitives.

## 3. Public interface

```rust
pub struct CpuLocal {
    id: CpuId,
    frame_state: FrameState,
    /// The domain currently active on this CPU. Updated *only* by
    /// `enter_domain` / `exit_domain` and by trap entry. Reading it
    /// from any other site is a bug.
    pub current_domain: DomainId,
    /// Snapshot of the PKRS/TCF state as of the most recent
    /// `enter_domain`. Exit restores from this.
    pub saved_domain_state: DomainSavedState,
    /* ... */
}
pub fn init_bsp(boot_info: &BootInfo) -> !;
pub fn init_ap(cpu: CpuId);
pub fn current() -> &'static CpuLocal;

/// Enter `id`. Saves the prior `DomainSavedState` into `CpuLocal` and
/// writes the new PKRS / TCF. Must be paired with `exit_domain`.
/// Requires interrupts disabled and the caller's current domain to be
/// recorded; nested entry into the same domain is a debug assert.
pub unsafe fn enter_domain(id: DomainId);

/// Exit the most recently entered domain, restoring the prior state.
/// Panics in debug if called without a matching `enter_domain`.
pub unsafe fn exit_domain();

pub fn panic(msg: &PanicInfo) -> !;
```

Trap entry is written in arch-asm, fans out to a `dispatch_trap(frame)`
Rust function that forwards to `interrupts/` or handles synchronous faults.

## 4. Invariants & safety properties

- There is exactly one `CpuLocal` per CPU, pinned to its per-CPU page.
- A trap handler never allocates.
- `enter_domain` only runs with interrupts disabled and returns with them
  in the same state.
- **`enter_domain` is not re-entrant into the same domain.** Nested entry
  silently overwrites the PKRS/TCF snapshot in `CpuLocal` and collapses
  the exit pairing. Debug builds assert `current_domain != id`; release
  builds log a `tracing/` critical event and proceed (we do not panic in
  the trap path).
- **Trap entry saves PKRS / TCF to the trap frame *before* running any
  Rust code.** The arch-asm prologue does:

  1. `swapgs` (x86_64) / set `TPIDR_EL1` (aarch64 if needed).
  2. Save GP regs + PKRS (`rdmsr IA32_PKRS`) / TCF (aarch64 `MRS`) into
     the trap frame.
  3. Switch PKRS/TCF to the Frame's own domain (domain 0).
  4. Call `dispatch_trap(frame)`.
  5. On return: restore PKRS/TCF from the trap frame, restore GP regs,
     `iretq` / `eret`.

  Without step 2–3 the Frame would execute trap handling under the
  faulting domain's rights — a privilege-escalation pathway.
- **NMI / double-fault / machine-check paths have their own IST-backed
  trap frames** and perform the same save/restore independently. They
  must not assume GS / TPIDR_EL1 is valid.
- Panic path never returns; it quiesces the system and hands over to
  `console/`. On SMP (Stage 2+) it broadcasts an `IPI-NMI` to halt APs
  before calling `console::panic_sink`.

## 5. Architecture notes

### x86_64
- GDT: kernel code, kernel data, user code, user data, TSS per CPU.
- IDT: 256 entries, trap gates for exceptions, interrupt gates for IRQs.
- Uses `swapgs` + per-CPU `KERNEL_GS_BASE` for `CpuLocal` pointer.
- **TSS IST slot assignments** (fixed, not negotiable):
  - IST1 — NMI.
  - IST2 — `#DF` (double fault).
  - IST3 — `#MC` (machine check).
  - IST4 — `#VC` (VMM communication, SEV-ES targets).
  - IST5..7 — reserved.
  Each IST slot has its own 16 KiB stack per CPU, allocated by
  `memory/` at AP bring-up time.
- Trap frame carries saved `IA32_PKRS` in a dedicated 64-bit field
  between the general-purpose regs and the error-code field.

### aarch64
- EL1 vector table aligned to 2 KiB; four groups of four vectors.
- `TPIDR_EL1` holds the `CpuLocal` pointer.
- SP_EL0 for user, SP_EL1 for kernel; SPSel=1 on entry.
- **Stack alignment:** SP must be 16-byte aligned at EL1 vector entry;
  the vector prologue enforces this before any push.
- **MTE is suspended on vector entry.** The prologue clears
  `SCTLR_EL1.TCF` (TCF=0, ATA=0) before any trap code runs; the saved
  TCF from the `DomainSavedState` is restored on `eret`. This prevents
  the trap handler itself from faulting on tag mismatches while
  running in Frame context.

## 6. Dependencies

- **Consumes:** `arch/`, `boot/`.
- **Provides to:** `scheduler/`, `memory/`, `interrupts/`, `console/` (panic), everything.

## 7. Stage assignment

Stage 1 (boot, trap dispatch, panic). Stage 2 (domain enter/exit hooks
once `memory/` has domains).

## 8. Open questions

- Do we trust nested exceptions, or force serialisation?
- Per-CPU `CpuLocal` size budget — we want it in one cache line if possible.
- Does the Frame own time-of-day, or defer to a `time/` subsystem later?
