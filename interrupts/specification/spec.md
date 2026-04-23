# interrupts — Specification

> Status: **Outline v0.1** (Stage 2).

## 1. Purpose & scope

**Owns:** IRQ routing table, UIPI enable / delivery setup, GICv3 ITS
programming, kernel fallback trap path when UIPI isn't available or for
drivers not opted in to it.

**Does NOT own:** Trap entry (`frame/` provides it), driver-specific
handling (drivers do that after the dispatch).

## 2. Assumptions

- `frame/` provides the vector table; we install handlers into it.
- `memory/` has allocated per-CPU APIC / GIC MMIO regions.
- `capabilities/` will gate IRQ registration (`Cap<Irq(n), Own>`) in Stage 3.

## 3. Public interface

```rust
pub fn register_irq(n: IrqNum, target: IrqTarget, domain: DomainId);
pub enum IrqTarget {
    Kernel(fn(&TrapFrame)),     // fallback: kernel-mode handler
    Uipi { uitt_entry: u32 },   // UIPI direct delivery to user/driver
}
pub fn end_of_interrupt(n: IrqNum);
pub fn trigger_sw(n: IrqNum, target_cpu: CpuId);
```

## 4. Invariants & safety properties

- Every IRQ has exactly one `target` at any time.
- UIPI targets carry a domain id; kernel programs UITT so hardware
  delivers only inside that domain.
- EOI is always issued, even on spurious; missed EOI panics with a
  domain-scoped containment.
- **PKRS / TCF are saved to the trap frame by `frame/`'s vector
  prologue before `dispatch_trap` runs.** `interrupts/` code executes
  under the Frame's domain (0), not the interrupted task's domain.
  This means an IRQ handler must not assume it can access the
  interrupted task's domain-private memory; it must either marshal
  through the task (wake a waker) or enter the task's domain
  explicitly.
- **UIPI delivery bypasses `frame/` trap entry.** The UIPI receiver
  runs directly in its configured domain — the hardware delivery path
  writes `IA32_PKRS` atomically as part of the UIPI transition. UITT
  entries are populated by `interrupts/` with the receiver's domain
  id encoded alongside the target address.
- **NMI does not participate in UIPI.** NMIs always take the IST
  path in `frame/` and run under the Frame's domain regardless of
  which task was interrupted. Drivers that rely on low-latency
  interrupt delivery use UIPI; NMI is reserved for the kernel's own
  rare-event needs (panic IPI, watchdog, profiling overflow).

## 5. Architecture notes

### x86_64
- Controllers: x2APIC for local, I/O APIC legacy path for devices that
  predate MSI/MSI-X. Prefer MSI-X where the device supports it.
- UIPI: `WRMSR IA32_UINTR_*` MSRs; UITT entries per driver; `SENDUIPI`
  instruction for driver-to-driver signalling.

### aarch64
- Controllers: GICv3 with ITS for MSI-like delivery. LPIs for per-device.
- User-mode delivery: no direct UIPI equivalent; closest is FIQ or
  explicit event-register polling by the driver task.

## 6. Dependencies

- **Consumes:** `arch/`, `frame/`, `memory/`, `rcu/` (QSBR for IRQ
  routing table + UITT reads on the hot delivery path).
- **Provides to:** every driver in `drivers/`, `scheduler/` (preemption IRQ).

## 7. Stage assignment

Stage 2.

## 8. Open questions

- If UIPI is unavailable, what's the perf ceiling of the kernel trap
  fallback for hot IRQs?
- GIC ITS LPI remapping cost — is there an aarch64 analogue worth
  highlighting in the spec?
- Do we multiplex UIPI receivers per domain, or 1:1?
