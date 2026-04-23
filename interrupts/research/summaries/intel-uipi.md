# Intel UIPI — User Interrupts

**Primary source:** Intel Instruction Set Extensions (ISE) Programming
Reference, "User Interrupts" chapter; Intel SDM Vol. 3A §11 (User
Interrupts); LWN "User-space interrupts" (2021).

> Distilled for NARF design. Reading notes.

## What it is

UIPI lets hardware deliver an interrupt directly to a user-mode (or
non-TCB kernel) handler without transitioning to Ring 0. The target
sees a "user-interrupt event" and its handler runs in its own ring, with
its own stack, with interrupts disabled for the duration.

For NARF, UIPI is how a driver living in PKS domain N receives an IRQ
without a trip through the Frame — the hardware gets it straight to the
driver task, so the fast path is: device → LAPIC → driver domain.

## Key concepts

- **User interrupt handler**: an entry in the per-receiver **UIDT**
  (User Interrupt Descriptor Table), analogous to the IDT but used when
  the interrupt targets user mode.
- **UITT** (User Interrupt Target Table): a per-sender table enumerating
  which user interrupt vectors the sender may deliver to which receiver.
- **UPID** (User Posted Interrupt Descriptor): a 64-byte structure in
  memory tracking pending user interrupts for a given receiver.
- **Receiver state** MSRs:
  - `IA32_UINTR_HANDLER` — address of the receiver's handler.
  - `IA32_UINTR_STACKADJUST` — stack offset used on delivery.
  - `IA32_UINTR_MISC` — UINV (user interrupt notification vector), UITTSZ.
  - `IA32_UINTR_PD` — pointer to UPID.
  - `IA32_UINTR_TT` — pointer to UITT.
  - `IA32_UINTR_RR` — pending-interrupt request register (set by hardware).
- **Instructions:**
  - `SENDUIPI <index>` — sender instruction; looks up UITT entry by index,
    delivers to receiver specified there.
  - `UIRET` — return from a user-interrupt handler.
  - `STUI` / `CLUI` — enable / disable user interrupts (UIF flag).
  - `TESTUI` — query UIF.

## Delivery mechanics

1. Sender (another user task, or a device whose LAPIC is configured to
   post user interrupts) issues `SENDUIPI idx` (or the LAPIC posts).
2. Hardware looks up `UITT[idx]` → gets a UPID pointer + vector.
3. Hardware sets the corresponding bit in `UPID.PIR` (posted interrupt
   requests) and, if `UPID.ON` was clear, sends an **IPI** with the
   UINV vector to notify.
4. Target CPU, running the receiver, sees the UINV notification; if
   `UIF == 1` and the receiver is ready, it transitions to the handler
   in `IA32_UINTR_HANDLER` using `IA32_UINTR_STACKADJUST`.
5. Handler runs; `UIRET` returns.

If the receiver isn't currently scheduled on a CPU, the notification
sits in UPID until the scheduler dispatches the task, at which point
it is delivered.

## Enabling

- CPUID leaf 7 sub-leaf 0, EDX[5] ("UINTR").
- `CR4.UINTR` enables the feature.
- The kernel configures UDIT/UITT/UPID storage and writes the receiver
  MSRs when scheduling the receiver task.

## Why it matters for NARF

- UIPI makes "IRQ to driver domain without kernel trap" a real hardware
  feature rather than an optimisation wish.
- The Frame still configures the LAPIC (so it is part of the TCB), but
  the *delivery* to a driver domain bypasses the Frame's trap path.
- A driver task is the UIPI receiver. Its UPID and UITT live in the
  kernel-controlled PKS domain (so a compromised driver cannot rewrite
  them to intercept another domain's IRQs).
- SENDUIPI from one driver to another gives us low-overhead in-kernel
  signalling — a natural complement to Narf-Ring doorbells.

## aarch64 equivalent (gap notice)

There is no 1:1 equivalent of UIPI on aarch64. GICv3 with ITS + LPIs
delivers MSIs efficiently, but delivery to an EL1-resident driver task
still goes through the EL1 vector table. At EL0, FIQ routing can be
used. For NARF this means the aarch64 fast path has one more hop than
x86_64 UIPI; document this cost in `interrupts/` Stage 2 spec.

## Open questions this raises for the NARF spec

- How many UIDT/UITT entries per driver (sizing UITT arrays)?
- Can UPID memory live in the driver's own PKS domain, or must it be in
  a kernel-only domain? (Security review: a driver writing to its own
  UPID could mask interrupts it was supposed to receive.)
- What happens to pending UIPI if a driver is quiesced / reloaded.
- NMI semantics near UIPI delivery.
