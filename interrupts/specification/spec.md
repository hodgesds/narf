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

#[cfg(target_arch = "x86_64")]
pub fn uses_hpet_fallback() -> bool; // x86_64::timer_pump diagnostic

pub fn install_tlb_shootdown_bridge();

#[cfg(target_arch = "x86_64")]
pub fn install_resched_ipi(); // notification-only; no queue work in hard IRQ

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
#[cfg(target_arch = "aarch64")]
pub fn gic::gicd_typer() -> u32;

// GIC discovery + backend selection (aarch64; GICv2 and GICv3).
pub mod gic_dt {                       // arch-neutral, allocation-free
    pub enum GicVersion { V2, V3 }
    pub struct MmioWindow { pub base: u64, pub len: u64 }
    pub struct GicDescription {
        pub version: GicVersion,
        pub dist: MmioWindow,          // reg[0]: GICD
        pub cpu: MmioWindow,           // reg[1]: GICC (v2) / GICR region (v3)
        pub redist_stride: Option<u64>, // v3 `redistributor-stride`
    }
    pub enum GicDetectError { BadBlob, NotFound, MissingReg(GicVersion) }
    pub fn detect(blob: &[u8]) -> Result<GicDescription, GicDetectError>;
    pub fn version_for_compatible(value: &[u8]) -> Option<GicVersion>;
}
#[cfg(target_arch = "aarch64")]
pub unsafe fn gic::probe(dtb_phys: Option<u64>, gicv3_sysreg: bool)
    -> Result<(GicDescription, gic::ProbeSource), gic::ProbeError>;
pub enum gic::ProbeSource { Devicetree, QemuVirtDefault }
pub enum gic::ProbeError { Devicetree(GicDetectError), NoSysregInterface, NotFound }
#[cfg(target_arch = "aarch64")]
pub fn gic::version() -> Option<GicVersion>;  // None before probe
#[cfg(target_arch = "aarch64")]
pub fn gic::is_v2() -> bool;                  // boot constant after probe
#[cfg(target_arch = "aarch64")]
pub unsafe fn gic::{init_bsp, init_ap(cpu_index: u32)}; // after probe
#[cfg(target_arch = "aarch64")]
pub fn gic::remap_mmio(cpu_index: u32);

// Trap-path CPU-interface primitives (called by frame/'s IRQ vector).
#[cfg(target_arch = "aarch64")]
pub unsafe fn ack_irq() -> u64;        // ICC_IAR1_EL1 (v3) | GICC_IAR (v2)
#[cfg(target_arch = "aarch64")]
pub fn iar_intid(iar: u64) -> u32;     // bits [23:0] (v3) | [9:0] (v2)
#[cfg(target_arch = "aarch64")]
pub unsafe fn eoi_for(iar: u64);       // ICC_EOIR1_EL1 (v3) | GICC_EOIR (v2)
#[cfg(target_arch = "aarch64")]
pub const SPURIOUS_INTID: u32 = 1023;

// GICv3 ITS (aarch64). Pure model + firmware parsers are arch-neutral.
#[cfg(target_arch = "aarch64")]
pub unsafe fn its::discover_firmware(dtb: Option<PhysAddr>) -> its_fw::Source;
#[cfg(target_arch = "aarch64")]
pub unsafe fn its::init_bsp() -> Result<(), its::ItsError>;
#[cfg(target_arch = "aarch64")]
pub fn its::doorbell_pa() -> u64;          // GITS_TRANSLATER of the discovered ITS
#[cfg(target_arch = "aarch64")]
pub fn its::pci_device_id(segment: u16, rid: u16) -> Option<u32>;
#[cfg(target_arch = "aarch64")]
pub const fn its::lpi_for_vector(v: u8) -> u32; // LPI_BASE + v
#[cfg(target_arch = "aarch64")]
pub unsafe fn its::create_device(device_id: u32, nvecs: u32) -> Result<its::DeviceInfo, its::ItsError>;
#[cfg(target_arch = "aarch64")]
pub unsafe fn its::map_event(device_id: u32, event: u32, lpi: u32, collection: u16) -> Result<(), its::ItsError>;
#[cfg(target_arch = "aarch64")]
pub unsafe fn its::unmap_event(device_id: u32, event: u32) -> Result<(), its::ItsError>;
#[cfg(target_arch = "aarch64")]
pub unsafe fn its::free_device(device_id: u32) -> Result<(), its::ItsError>;
#[cfg(target_arch = "aarch64")]
pub fn its::status() -> Option<its::Status>;
pub mod its_core; // GITS_BASER / CBASER / PROPBASER / PENDBASER negotiation,
                  // ITT sizing, command encodings, queue wrap + stall
pub mod its_fw;   // FDT / MADT / IORT parsing, RID → DeviceID

// GIC SPIs (aarch64, GICv2 + GICv3): devicetree platform devices
// (Qualcomm SoCs).
#[cfg(target_arch = "aarch64")]
pub fn gic::configure_spi(intid: u32, trigger: gic::SpiTrigger) -> Result<(), gic::SpiError>;
#[cfg(target_arch = "aarch64")]
pub fn gic::{mask_spi, unmask_spi, pend_spi}(intid: u32) -> Result<(), gic::SpiError>;
#[cfg(target_arch = "aarch64")]
pub fn gic::spi_limit() -> u32;              // 32 * (ITLinesNumber + 1), <= 1020
#[cfg(target_arch = "aarch64")]
pub const fn gic::spi_vector(intid: u32) -> u8; // intid & 0xFF (the trap's dispatch slot)
pub enum gic::SpiTrigger { Level, Edge }
pub enum gic::SpiError { OutOfRange(u32) }

pub fn vector::reserve(vector: u8) -> Result<(), VectorError>; // claim one fixed slot
pub fn vector::alloc() -> Result<u8, VectorError>;
pub fn vector::alloc_block(n: u8) -> Result<u8, VectorError>;
pub fn vector::alloc_block_aligned(n: u8, align: u8) -> Result<u8, VectorError>;
pub fn vector::free(vector: u8) -> Result<(), VectorError>;
```

SPI contract (aarch64). `configure_spi` disables the INTID, clears its
pending state, sets priority 0xA0, programs `GICD_ICFGR` (edge/level),
routes it to the calling CPU and enables it; INTIDs outside
`32..spi_limit()` are refused (`spi_limit` is `GICD_TYPER.ITLinesNumber`
on both versions). GICv3 routes with `GICD_IROUTER` = the caller's
affinity (IRM = 0) and puts the INTID in Group 1 NS; GICv2 writes the
caller's CPU-interface bit into `GICD_ITARGETSR` and leaves the group as
firmware configured it (Linux `irq-gic.c` behaviour). The API is identical
on both backends. The trap dispatches SPIs on
`intid & 0xFF`, so a driver binding a fixed SPI first claims that slot
with `vector::reserve` (refused with `Exhausted` when an MSI/LPI or
another SPI owns it, `OutOfRange` above `ALLOC_MAX`). `pend_spi`
(`GICD_ISPENDR`) is a self-test aid.

GIC discovery (aarch64). `gic::probe` runs once on the BSP, IRQs masked,
before `init_bsp`. It reads the devicetree through `gic_dt::detect`:
`arm,gic-400`, `arm,cortex-a15-gic` and `qcom,msm-qgic2` select GICv2,
`arm,gic-v3` selects GICv3, and `reg[0]` / `reg[1]` give the distributor
and the CPU interface (v2) or redistributor region (v3). A described GIC
with a missing or short `reg` is refused (`ProbeError::Devicetree`); a
DT-described v3 without `ID_AA64PFR0_EL1.GIC` is refused
(`NoSysregInterface`). Only when the devicetree has no GIC node does probe
fall back to the QEMU `virt` GICv3 bases, and only with the v3 sysreg
interface present — the pre-discovery behaviour. Parent `ranges` are
assumed identity (QEMU `virt`, Qualcomm `soc@0`). GICv2 SGIs use
`GICD_SGIR` with the CPU-interface bits each CPU reads from its banked
`GICD_ITARGETSR0..7`; the ITS refuses to initialise under GICv2
(`ItsError::NotGicV3`), so PCI MSI-X falls back as for any ITS-less
system.

`alloc_block_aligned` returns a contiguous run whose base is a multiple of
`align` (a power of two). Multi-message MSI requires it: the function writes
the vector index into the low `log2(n)` bits of Message Data, so the base's
low bits must be zero.

The x86 shootdown mask is a logical-CPU bitmap. Implementations intersect it
with the online set and remove the sender, publish pending state only for the
remaining CPUs, send fixed-destination x2APIC IPIs only to those CPUs, and wait
only for the corresponding per-request completion bits. Concurrent senders own
disjoint source lanes; a target-side pending-source bitmap coalesces only the
IPI while preserving every request, and each source serializes reuse of its
lane until all requested targets complete. The cumulative ACK, ever-received,
and INVPCID-path counters live in one cache-line-isolated record per CPU. The
receiver updates only its local record, and readers aggregate across CPUs only
when a total is requested. The unmasked `shoot_range`, `shoot_tag_only`, and
`shoot_full` helpers remain all-online-peer compatibility wrappers.

On aarch64, tagged memory requests use Inner Shareable TLBI operations and do
not enter the SGI bridge. The bridge remains responsible for untagged local
`VMALLE1` requests, which require peer execution to become system-wide.

ITS contract (aarch64). `narf_bus::init` calls `discover_firmware` before the
boot path runs `init_bsp`; ACPI (MADT GIC ITS / GICR / GICC + IORT) wins when
an RSDP is cached, then the devicetree (`arm,gic-v3`, `arm,gic-v3-its`,
`msi-map`), else the QEMU `virt` layout is assumed and logged. `init_bsp`
provisions flat device / collection tables from each `GITS_BASER<n>`'s Type
and Entry_Size with a read-back page size and shareability (tables, command
queue and property table are cleaned to PoC when the GIC reports
non-shareable), sizes the property table for the configured IDbits, gives the
BSP redistributor (found by `GICR_TYPER` affinity) a 64 KiB-aligned pending
table, and maps collection 0 to it. `map_event` creates a device's ITT on
first use (`DEFAULT_DEVICE_EVENTS` entries; `create_device` picks the size),
sets the LPI's enable bit, and issues MAPD / MAPTI / INV / SYNC; a second map
for the same DeviceID reuses its ITT. Every LPI targets collection 0. Command
submission is bounded (~1 s per wait) and reports `GITS_CREADR.Stalled` as
`ItsError::CmdStalled`. MSI-X (`narf_bus::msix`) and the Navi48 MSI route
translate the PCI RID through `pci_device_id` before mapping.

The PMU route accepts only private INTIDs 16–31, enables the current CPU's
redistributor immediately, and is inherited by subsequent per-CPU GIC
initialisation. Its input must come from firmware discovery.

**Oneshot level INTx** (`oneshot::Line`, x86_64). For a device whose
interrupt source only its owning task can clear (Linux
`request_threaded_irq(.., NULL, thread_fn, IRQF_ONESHOT)` through
`handle_fasteoi_irq`). `unsafe Line::bind_exclusive(gsi, name, notify)`
refuses a live (unmasked) route with `Error::Shared`, allocates a vector,
installs the hard half, and routes the GSI level/active-low to the current
CPU **masked**. The hard half never touches the device: it masks the GSI
(`acpi::ioapic::set_gsi_masked`), counts the delivery and calls `notify`
(wake only). The trap's EOI then retires Remote IRR with the line masked.
The owner services the device, clears the source and calls `unmask()`; a
still-asserted line is delivered again. Mask transitions are serialized
under an IRQ-safe lock, so an unmask cannot race a fresh delivery. `Drop`
masks the route, removes and synchronizes the handler and frees the vector.
Only exclusive GSIs are supported (masking a line shared with synchronous
handlers would stall them). Other architectures return `Error::Unsupported`.

## 4. Invariants & safety properties

- Every IRQ has exactly one `target` at any time.
- UIPI targets carry a domain id; kernel programs UITT so hardware
  delivers only inside that domain.
- EOI is always issued, even on spurious; missed EOI panics with a
  domain-scoped containment.
- **The aarch64 GIC backend is a boot constant.** `gic::probe` selects
  GICv2 or GICv3 exactly once, on the BSP, before any CPU unmasks IRQs;
  `ack_irq` / `iar_intid` / `eoi_for` branch on that one static and
  nothing changes it afterwards. `eoi_for` is handed the unmodified
  `ack_irq` value (GICv2 SGIs carry the source CPU in IAR bits [12:10],
  which `GICC_EOIR` must echo); the spurious INTID 1023 is never EOI'd.
  Every GIC MMIO / system-register access uses the `narf_arch`
  accessors, which carry `compiler_fence(SeqCst)` on both sides. The
  GICv2 `GICC` window is an `ioremap` Device-nGnRE mapping in TTBR1:
  present in every address space and untagged, so the trap path reaches
  it from `DomainId::FRAME` whichever task was interrupted.
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
- Timer-wheel deadlines use the successfully probed reliable LAPIC
  TSC-deadline clockevent exclusively. The HPET comparator/IOAPIC path remains
  armed as a fallback only when that reliable primary is unavailable; the two
  sources do not intentionally deliver the same deadline.
- The timer wheel is global, but exactly one logical CPU owns its LAPIC
  TSC-deadline clockevent at a time. Publishing a new earliest deadline
  transfers ownership to the publishing CPU. A previous owner's already-armed
  one-shot may fire once, but it must not mirror or re-arm the global minimum;
  this keeps wheel delivery O(1) rather than O(online CPUs). On expiry, the
  owner removes due slots into a fixed per-CPU deferred-wake queue before
  re-arming; it must not repeatedly floor and re-arm an already-due minimum.
- UIPI: `WRMSR IA32_UINTR_*` MSRs; UITT entries per driver; `SENDUIPI`
  instruction for driver-to-driver signalling.

### aarch64
- Controllers: GICv3 with ITS for MSI-like delivery (LPIs per device),
  or GICv2 (QEMU `virt,gic-version=2`; Qualcomm IPQ8074 / IPQ6018 /
  IPQ5018 `qcom,msm-qgic2`) with SPIs/PPIs/SGIs only. The GICv2 backend
  follows Linux `irq-gic.c` (`gic_dist_init`, `gic_cpu_init`,
  `gic_cpu_if_up`, `gic_ipi_send_mask`, `gic_handle_irq`): SPIs routed
  to the boot CPU, level, priority 0xA0, disabled at distributor init;
  `GICC_PMR` = 0xFF, `GICC_BPR` = 0, `GICC_CTLR` enable with firmware's
  bypass-disable bits kept; EOImode 0. GICv2m MSI frames are not
  implemented. `cargo xtask test --arch=aarch64` boots v2 with
  `NARF_GIC_VERSION=2`.
- ITS bring-up follows Linux `irq-gic-v3-its.c` (`its_alloc_tables`,
  `its_setup_baser`, `its_cpu_init_lpis`, `its_create_device`); DeviceIDs
  follow `iort_node_map_id` / `of_map_id`. Indirect (two-level) tables,
  multiple ITSes, per-CPU collections and vLPIs are not implemented; the
  per-CPU redistributor frame is found as `reg[1] + cpu * stride` from the
  devicetree (not yet by `GICR_TYPER` affinity), and the ITS keeps its own
  firmware discovery. Validated on QEMU and against register models only.
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

The reschedule IPI is notification-only: receipt interrupts or un-halts the
target, but its handler does not mutate scheduler queues or invoke policy
callbacks. The scheduler drains any staged cross-CPU wake inbox at its next
executor round boundary, where ready-queue growth may allocate safely.

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

- **GIC discovery residue (aarch64).** Resolved for the common case:
  the GIC version and windows come from the devicetree and GICv2 is a
  full backend (§3, §5). Still open: `ranges` translation for a GIC
  behind a non-identity bus, ACPI MADT GICD/GICC-driven selection,
  redistributor lookup by `GICR_TYPER` affinity on multi-cluster v3
  silicon, and GICv2m MSI frames for PCIe on IPQ parts.

- **aarch64 PCI INTx.** No PCI INTx-to-SPI (`interrupt-map`) routing
  exists, so `oneshot::Line` is x86_64-only; aarch64 INTx clients poll.
- **Shared oneshot lines.** A per-GSI registry with a mask refcount would
  let oneshot owners share a level line with each other (Linux requires
  matching `IRQF_ONESHOT` across sharers).

(all v0.1 questions resolved in §12)
