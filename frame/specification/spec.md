# frame — Specification

> Status: **v1.0** (Stage 2 design lock). v0.2 tightened
> `enter_domain` re-entrancy + trap PKRS save; v1.0 locks the
> nested-exception policy, the per-CPU layout target, and the
> time-of-day ownership boundary.

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

Trap entry is written in arch assembly and materialises the architecture-owned
`narf_arch::{x86_64,aarch64}::trap_frame::TrapFrame`. `frame` re-exports the
selected type and fans out to a Rust dispatcher. The scheduler consumes that
shared type directly; it does not define or cast a mirror layout.

## 4. Invariants & safety properties

- There is exactly one `CpuLocal` per CPU, pinned to its per-CPU page.
- A trap handler never allocates.
- **x86_64 trap entry clears the live direction flag before executing any
  compiler-generated code.** CPL3 may be interrupted between `std` and `cld`;
  the CPU-pushed RFLAGS retains that user state for `iretq`, while the kernel
  must run with DF=0 so Rust/System-V string operations move forward.
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
  3. Enter neutral Frame execution state: PKRS all-allow, the Frame PCID root,
     or MTE tag checks suspended while retaining `SCTLR_EL1.ATA`.
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
- The trap-frame prefix carries a saved state plus a discriminator: inactive,
  `IA32_PKRS`, or CR3/PCID. Fast `SYSCALL` entry uses the same ordering before
  Rust and restores the snapshot on both SYSRET and IRET exits.

### aarch64
- EL1 vector table aligned to 2 KiB; four groups of four vectors.
- `TPIDR_EL1` holds the `CpuLocal` pointer.
- SP_EL0 for user, SP_EL1 for kernel; SPSel=1 on entry.
- **Stack alignment:** SP must be 16-byte aligned at EL1 vector entry;
  the vector prologue enforces this before any push.
- **MTE is suspended on vector entry.** The prologue clears
  `SCTLR_EL1.TCF/TCF0` while retaining `ATA`, then saves both SCTLR and GCR;
  the exact state is restored on `eret`. This prevents
  the trap handler itself from faulting on tag mismatches while
  running in Frame context.

## 6. Dependencies

- **Consumes:** `arch/`, `boot/`.
- **Provides to:** `scheduler/`, `memory/`, `interrupts/`, `console/` (panic), everything.

## 7. Stage assignment

Stage 1 (boot, trap dispatch, panic). Stage 2 (domain enter/exit hooks
once `memory/` has domains).

## 8. Resolved decisions

### 8.1 Nested-exception policy (resolved)

**Decision (was open):** **serialise** nested exceptions
explicitly via IST stacks (x86_64) and SP banking (aarch64).

The kernel has IST entries for NMI, #DF, #MC, #VC (per §5);
each gets its own 16 KiB stack. A nested exception arriving
mid-handler does not push onto the interrupted handler's
stack — it switches to the IST-assigned stack, preventing
stack overflow if the handler itself faults.

For non-IST exceptions (page fault, GP fault), the prologue
runs with `IF=0` (interrupt gate) so external IRQs cannot
nest. Synchronous faults nesting on synchronous faults
(double fault) are caught by #DF on its own IST.

aarch64 mirrors via SPSel=1 + separate vector groups for
"current EL with SP_EL1" vs "from lower EL" — same effect:
the handler context is segregated.

### 8.2 Per-CPU layout budget (resolved)

**Decision (was open):** **one cache line** for the hot fields,
not the entire `CpuLocal`. The hot-path fields:

```rust
#[repr(C, align(64))]
pub struct CpuLocalHot {
    pub current_task:    AtomicU64,    // task id
    pub current_domain:  DomainId,     // u8
    pub flags:           u8,
    pub padding:         [u8; 6],
    pub kernel_stack:    *mut u8,
    pub trap_frame_ptr:  *mut TrapFrame,
    pub saved_user_gs:   u64,          // x86_64 only; aarch64 = 0
    pub _reserved:       [u64; 3],
}
```

Cold fields (per-CPU run queue head, debug counters, GDT
pointer, IDT pointer) live elsewhere in the per-CPU page —
referenced through the hot struct's pointers when needed.

The 64-byte hot line is what `swapgs` / `TPIDR_EL1` points to
on x86_64 / aarch64 respectively. Fits in a single cache fetch
on every trap.

### 8.3 Time-of-day ownership (resolved)

**Decision (was open):** **`time/` owns time-of-day; `frame/`
owns the per-CPU TSC/timer counter cache only.**

`frame/` reads the raw counter (`RDTSC` / `CNTPCT_EL0`) for
the trap-entry timestamp embedded in the trap frame; it does
not convert to wall-clock. `time/` owns the wall-clock
calibration, leap-smear, NTP sync, and all conversion
arithmetic.

This is the existing v0.2 boundary; v1.0 just locks it.

### 8.4 Trap frame layout

The trap frame is part of the kernel-side ABI between `frame/` assembly,
`arch/`'s shared Rust representation, and the executor's preemption hook.
Architecture modules own the exact `#[repr(C)]` layouts and compile-time offset
assertions. `frame` and `scheduler` may not redeclare or cast mirror structs.
The schematic common portion is:

```rust
#[repr(C)]
pub struct TrapFrame {
    // saved domain state is the first field, so entry can neutralise rights
    // before exposing any Rust reference to the remainder
    pub domain:    ArchDomainTrapState,
    // GPRs (arch-specific layout — 15 on x86_64, 31 on aarch64)
    pub gpr:       [u64; ARCH_GPR_COUNT],
    // architectural fields
    pub vector:    u64,            // IDT vector / exception class
    pub err_code:  u64,            // page-fault error / FAR_EL1 /...
    pub rip:       u64,            // saved RIP / ELR_EL1
    pub cs_or_spsr:u64,            // saved CS / SPSR_EL1
    pub rflags_:   u64,            // saved RFLAGS / 0 (aarch64)
    pub rsp:       u64,            // saved RSP / SP_EL0
    pub ss_or_zero:u64,            // saved SS / 0
}
```

Drivers do not see this struct (it's in `DOMAIN_FRAME`,
TCB-only). Tracing / observability / panic-dump code that
needs to inspect a trap frame holds `Cap<Diagnostics, Read>`.

## 9. Open questions

(none — all v0.2 questions resolved in §8)
