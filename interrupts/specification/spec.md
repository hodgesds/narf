# interrupts — Specification

> Status: **v1.0** (Stage 3 design lock). v0.1 covered routing
> + UIPI; v1.0 locks the `wait_for_irq` async surface, the
> `Cap<IrqVector, _>` mint flow, the missed-wake protocol the
> drivers framework relies on, and the per-vector quota.

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

pub struct InterruptedUserState {
    pub user: bool,
    pub abi: u64,
    pub ip: u64,
    pub sp: u64,
    pub regs: [u64; 34],
}
pub fn on_irq_with_user_state(
    vector: u8,
    interrupted_ip: u64,
    state: Option<&InterruptedUserState>,
);
pub fn interrupted_user_state() -> Option<InterruptedUserState>;

pub fn install_tlb_shootdown_bridge();

#[cfg(target_arch = "x86_64")]
pub unsafe fn ipi::shoot_range_mask(
    va: u64,
    pages: u64,
    tag: u16,
    target_cpus: u64,
);
#[cfg(target_arch = "x86_64")]
pub unsafe fn ipi::shoot_tag_only_mask(tag: u16, target_cpus: u64);
#[cfg(target_arch = "x86_64")]
pub unsafe fn ipi::shoot_full_mask(target_cpus: u64);

#[cfg(target_arch = "aarch64")]
pub fn gic::configure_pmu_ppi(intid: u32) -> Result<(), ()>;
```

The x86 shootdown mask is a logical-CPU bitmap. Implementations intersect it
with the online set and remove the sender, publish pending state only for the
remaining CPUs, send fixed-destination x2APIC IPIs only to those CPUs, and wait
only for their ACK counters. The unmasked `shoot_range`, `shoot_tag_only`, and
`shoot_full` helpers remain all-online-peer compatibility wrappers.

The PMU route accepts only private INTIDs 16–31, enables the current CPU's
redistributor immediately, and is inherited by subsequent per-CPU GIC
initialisation. Its input must come from firmware discovery.

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

## 8. Async-IRQ surface (`wait_for_irq`)

Drivers and other in-kernel async code consume IRQs through:

```rust
pub fn fire_count(vector: u8) -> u64;
pub fn wait_for_irq(vector: u8) -> WaitForIrq;

pub struct WaitForIrq { /* baseline: u64, vector: u8 */ }
impl Future for WaitForIrq { type Output = u64; /* post-IRQ count */ }
```

`wait_for_irq` snapshots the per-vector `fire_count` at
construction (the *baseline*). `poll()` returns Ready when the
counter has advanced past baseline. The IRQ-handler-side path
(`on_irq`) increments the counter atomically and wakes the
installed waker (if any).

### 8.1 Missed-wake protocol

`Future::poll`'s implementation is the canonical Linux-pattern
double-check:

```text
1. read fire_count → if > baseline, return Ready.
2. install waker (replaces any prior waker for this vector).
3. read fire_count again → if > baseline, return Ready;
                            else, return Pending.
```

This is sufficient for callers that wake through the scheduler
(real Waker integrated with task awakening). Callers using a
**noop waker** in a tight halt-then-poll loop (the in-kernel
test pattern, e.g. `verification/`'s blk_pci async smokes) must
additionally use the `arch::idle_halt_then_disable` primitive
to close the check-halt window — see `arch/spec` and the
canonical `cli; while !done { idle_halt_then_disable() } sti`
pattern.

### 8.2 IRQ delivery + dispatch

The in-kernel trap entry (`frame/`) calls
`narf_interrupts::on_irq_with_user_state(vector, state)` followed by `eoi()`.
The state contains the architecture's Linux perf register image when the IRQ
interrupted userspace. Synthetic/test callers may use `on_irq(vector)`, which
supplies no user state. A synchronous handler can read the contextual value
through `interrupted_user_state()` (or its IP through `interrupted_ip()`) only
during its handler walk. Dispatch otherwise preserves the `on_irq` contract:

```rust
pub fn on_irq(vector: u8) {
    narf_lib::context::enter_irq();                // 1. depth++
    let s = &SLOTS[vector as usize];
    s.fired.fetch_add(1, Release);                 // 2. count++
    if let Some(h) = HANDLERS[vector].load() { h(); }  // 3. sync handler
    if let Some(w) = s.waker.lock().take() { w.wake(); } // 4. async wake
    narf_lib::context::exit_irq();                 // 5. depth--
}
```

The order — increment first, sync handler second, waker third
— is the contract every consumer relies on. A waker observing
the wake call is guaranteed that any subsequent `fire_count`
read sees the increment (release-acquire ordering).

The `enter_irq` / `exit_irq` brackets give every handler-side
caller (drivers, allocators, locks) a true `in_irq()` answer
via `narf_lib::context::in_irq()`. `narf-memory`'s
`AllocContext::Sleepable` debug-asserts on this in slab::alloc
so a driver that accidentally calls `Box::new` from its ISR
panics in dev builds. Verified end-to-end by
`smoke_dispatch_in_irq_observed_inside_handler` (interrupts).

## 9. Capability surface

```rust
pub struct IrqVector;     // CapKind::BusDevice (badged with vector number)
pub struct MsiXTable;     // Cap minted on enable_msix
```

Drivers do not allocate vectors directly; the `bus/` layer
mints `Cap<IrqVector, _>` as part of the `enable_msix_for_probed`
flow, which:

1. Allocates an IDT vector via `interrupts::vector::alloc()`.
2. Programs the device's MSI-X table[N] to fire on that vector
   targeting **the current CPU's APIC ID** (not hardcoded 0 —
   see `drivers/spec` §3 for the wider-SMP correctness story).
3. Mints `Cap<IrqVector, Read>` for the driver instance, bound
   to the loaded module's lifetime.

Vector revocation on unload (the `drivers/spec` §7.3 REVOKED
step) clears the MSI-X table entry, releases the IDT vector,
and bumps the cap's epoch — any subsequent `wait_for_irq()`
on a revoked cap returns `Err(Revoked)` rather than blocking
forever.

## 10. ABI versioning

The `wait_for_irq` future and `fire_count` accessor are SDK
exports tagged at `@v0` in `narf-driver-sdk`. The wire-format
contract is:

- `fire_count` returns a monotonically-non-decreasing `u64`.
  Wraparound is permitted but undefined-behaviour-equivalent
  (it would take ~600 years at 1 GHz IRQ rate to wrap).
- `WaitForIrq` poll semantics in §8.1 are part of the ABI; the
  three-step double-check is observable via the `set_waker`
  call pattern.
- `IrqVector` cap badge encodes the vector number; reading a
  cap's badge is part of the SDK at `@v0`.

A future v1 of `wait_for_irq` (e.g. multi-vector wait, deadline
support) would ship as `@v1` exports alongside `@v0`. The v0
behaviour is locked indefinitely.

## 11. Per-vector quota

To prevent a misbehaving driver from monopolising the IDT:

- The IDT has 256 vectors total; 32 reserved for CPU exceptions,
  12 reserved for kernel-internal IPIs (timer, TLB shootdown,
  panic IPI, RESCHED, profiling overflow, debugger), leaving
  212 allocatable vectors.
- The `bus/` layer charges each `Cap<IrqVector, _>` mint
  against the requesting driver's `Cap<Quota, Spend>` (drivers
  spec §17.2). Quota exhaustion → `Err(QuotaExceeded)`.
- Vectors are not freed on driver unload immediately — they
  enter a reuse pool with a one-RCU-epoch quarantine to ensure
  no in-flight on_irq references the stale vector. After
  quarantine, the vector is available for re-allocation.

## 12. Resolved decisions

### 12.1 Trap-fallback latency ceiling (resolved)

**Decision (was open):** the kernel-trap fallback path is the
**default**, not a fallback. UIPI is an opt-in optimisation for
user-mode drivers (`drivers/spec` §12). In-kernel drivers always
go through the trap path; the optimisation is to keep the trap
handler short.

Measured cost on contemporary x86_64 (Cascade Lake, KVM): ~250
cycles entry, ~120 cycles `on_irq` body, ~80 cycles EOI, ~200
cycles iretq. Total ~650 cycles ≈ 200 ns at 3 GHz. This is the
performance floor for in-kernel IRQ-driven drivers and is
acceptable for hundreds-of-thousands-IRQs/sec workloads.

### 12.2 GIC ITS LPI cost (resolved)

**Decision (was open):** aarch64 GIC ITS LPI delivery is on
the equivalent path; programming costs are absorbed at MSI-X
enable time. Per-LPI delivery is comparable to x86_64 MSI-X
trap on contemporary cores. No spec-level treatment needed
beyond noting that the trap-path floor applies symmetrically.

### 12.3 UIPI receiver multiplexing (resolved)

**Decision (was open):** **1:1 — one UITT entry per driver
instance**, not multiplexed across the domain. UITT depth is
ample (256+ entries on Sapphire Rapids+) and per-driver
isolation is the load-bearing security property.

A user-mode-domain driver that hosts multiple device instances
(e.g. one virtio-net driver crate handling 4 NICs) gets one
UITT entry per **instance**, not one per crate. The loader
mints them at BIND time (drivers/spec §7.2 step 6) along with
the rest of the cap bundle.

## 13. Open questions

(none — all v0.1 questions resolved in §12)
