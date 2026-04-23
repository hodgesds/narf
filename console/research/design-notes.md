# console — Design Notes
_2026-04-22_

## Load-bearing decisions

**A single global spinlock protects all output.** The spec says "coarse lock is
fine for Stage 1" and "log records are never split across CPUs mid-line." Both
are correct for Stage 1. The hazard is lock-order inversion: `console/` is the
dependency of last resort — if any lock held by any other subsystem is taken when
`klog!` is called, and `console/` tries to take the spinlock, any code path that
calls `console/` while holding that other lock will deadlock. This is the same
class of bug as Linux's early_printk vs. spinlock ordering bugs. For Stage 1
(single CPU, cooperative scheduler) it doesn't matter. For Stage 2+ (SMP,
preemption) the global console lock must become an `IrqSafeSpinLock` at minimum,
and the panic path must avoid it entirely (write directly to the UART with
interrupts disabled and no lock).

**`panic_sink` is signal-safe: no allocation, no locks held across call sites.**
The spec's wording is ambiguous: "no locks held across call sites" could mean
"the caller must not hold locks when calling `panic_sink`" or "panic_sink
internally does not hold any locks." The latter is impossible if `panic_sink`
must write to a shared UART. The real requirement is: `panic_sink` writes
directly to the UART hardware register, bypassing the console spinlock,
accepting that output may be interleaved if multiple CPUs panic simultaneously.
This is the correct approach — halting on a lock held by a panicking CPU is worse
than interleaved output.

**Ring-buffer log with fixed size.** The spec says "a flood cannot exhaust
memory." Good. But the ring-buffer size and overflow policy (drop-oldest vs.
drop-newest vs. block-writer) are unspecified. For a kernel log, drop-oldest is
wrong (you lose the first symptom of a problem). Drop-newest is wrong (you
lose the latest state). The standard kernel approach is drop-newest with an
overflow counter — new messages are silently dropped but the count is reported.
Block-writer is wrong (caller blocks = deadlock risk). The spec should commit to
drop-newest with overflow counter.

**Structured log format is unresolved.** §8 asks: "plain text + key=value, or
JSON Lines, or binary token stream." This decision has downstream consequences:
the `tracing/` subsystem in Stage 2 will wire to `console/` for its panic
snapshot path; if `console/` uses plain text, `tracing/` cannot emit structured
records through it. The decision matters before Stage 2 begins.

## Divergences from precedent

**vs. Linux earlycon/early_printk:** Linux's early serial is a two-phase design:
`earlycon` (raw MMIO, no locks, before MMU-remap) and `early_printk` (after
partial init, still before the full TTY framework). NARF's spec has a single
`early_init` with no phase distinction. This is fine for NARF's simpler boot
sequence, but NARF should note that `console/` is in a different state before
vs. after `frame::init_bsp` completes (specifically: before `init_bsp`, there
is no `CpuLocal` and no spinlock; `write_str` must use only hardware registers
and no kernel data structures).

**vs. Hubris's logging:** Hubris uses a `sys_log` IPC message to the kernel's
supervisor task; there is no in-kernel print. This is appropriate for Hubris's
single-binary microcontroller target but too strict for NARF's development-phase
needs. NARF's in-kernel `klog!` is correctly present for Stage 1.

**vs. Tock OS PL011:** Tock's PL011 driver uses a `Driver` trait with capability
checks for write access. NARF's Stage 1 console bypasses capabilities, which is
correct (capabilities don't exist until Stage 3). But Stage 3 should add a
`Cap<Console, Write>` gate on `write_str` so userspace-domain drivers cannot
write to the console without a cap. The spec doesn't mention this transition.

**QEMU `0xE9` port:** The spec lists this as "a secondary debug sink" for x86_64.
This is correct for QEMU and should be the *primary* output sink for QEMU runs
where no serial is configured, since it requires no UART initialization. In
QEMU, writing a byte to port `0xE9` goes directly to the host's stdout with zero
latency, before any UART init. This is invaluable for debugging failures before
`early_init` completes, i.e., the "panic before the panic sink is ready" window.
The spec mentions it but doesn't say to use it as the pre-init fallback.

## Proposed spec changes

- §3 Public interface: Add **`pub fn write_str_direct(s: &str)`** — a variant
  that bypasses the spinlock and writes directly to hardware registers. Used by
  `panic_sink` and by any code path that may be called with the console lock
  already held. The current `write_str` + `panic_sink` conflation will cause
  deadlocks in the SMP/interrupt case.

- §4 Invariants: Replace "locking is coarse (a single global spinlock is fine
  for Stage 1)" with **"Stage 1: global `SpinLock`. Stage 2: `IrqSafeSpinLock`.
  `panic_sink` always bypasses the lock and writes directly to UART registers
  with interrupts disabled."** Stage-gating this in the spec prevents the Stage 2
  migration from being forgotten.

- §4 Invariants: Add **"Log ring buffer uses drop-newest policy with an atomic
  overflow counter. The overflow counter is emitted as a structured field at the
  start of every log line after an overflow event."** This specifies the overflow
  behavior that the current spec omits.

- §5 Architecture notes (x86_64): Elevate QEMU port `0xE9` to **"primary
  pre-init sink"**: "Before `early_init` is called, any output attempt uses port
  `0xE9` if running under QEMU (detected by reading back port `0xE9` — returns
  `0xE9` on QEMU, other values on real hardware). This provides debug output
  during the window between kernel entry and `console::early_init`."

- §8 Open questions — structured log format: **Resolve to `text + key=value`
  (logfmt style)**. Binary token streams require a decoder and are unreadable
  during early debug; JSON Lines are too verbose for kernel log rates; logfmt
  (`key=value key2=value2 message="..."`) is human-readable, machine-parseable,
  and has minimal encoding overhead. Document the schema: every record has
  `ts=<nanoseconds> lvl=<ERROR|WARN|INFO|DEBUG> subsys=<name> msg="..."` plus
  optional structured fields.

- §8 Open questions: Add **"Stage 3 transition: `write_str` gains a
  `Cap<Console, Write>` check for calls from non-kernel domains. The check is
  a no-op in Stage 1–2."** Without this note, the Stage 3 capabilities work
  will not include console gating and the console will remain an uncapped
  write path forever.

## Open invariants / cross-subsystem hazards

**console ↔ frame:** The panic path in `frame/` "hands over to `console/`."
`frame/` spec §4 says "panic path never returns; it quiesces the system and
hands over to `console/`." But `console/` §4 says `panic_sink` is the external
entry point. If the panic occurs inside `console/` itself (e.g., while holding
the console spinlock, the ring-buffer write panics), calling `panic_sink` will
try to acquire the spinlock again, deadlocking. The `panic_sink` must be
carefully implemented to never re-enter `console/`'s state — it must write to
hardware directly without using `console/`'s internal ring buffer or lock.

**console ↔ tracing:** The `tracing/` subsystem (Stage 2+) has a "panic-snapshot
path" that writes the flight recorder ring to persistent storage. If both
`tracing/` and `console/` write to the UART during panic, output will interleave.
Who goes first? Specify: `frame/` panic calls `tracing::panic_snapshot()` first
(captures flight recorder), then calls `console::panic_sink()` for human-readable
output. The console output comes last because it is the most human-readable
and should appear at the end of the output stream.

**console ↔ build:** `console/` §5 says the PL011 MMIO address for QEMU virt is
`0x0900_0000`. This address must be in the kernel's virtual address space from
the moment `console::early_init` is called. On aarch64 QEMU virt, the MMU is
off at boot entry, so physical = virtual and `0x0900_0000` is accessible.
After `memory/` enables the MMU and maps the kernel to high addresses, the
PL011 physical address must be mapped to a virtual address and `console/` must
be updated to use the virtual address. The spec has no "post-MMU remapping"
step for the UART base address. This is an implementation-blocking omission.

**console ↔ memory:** The fixed-size ring buffer is a global static in `console/`.
If it is allocated before `memory/` initializes, it is a BSS-section array —
correct. If it is dynamically allocated (e.g., to allow the size to be set from
the cmdline), it requires the heap to be available before `console::early_init`.
The spec should commit: "The ring buffer is a fixed-size BSS-section array;
its size is a compile-time constant (`CONSOLE_RING_SIZE`) defaulting to 64 KiB."

## Additional opinionated commentary

The console spec is the simplest in the project and is mostly correct. The two
sharpest critiques:

1. **The "signal-safe, no locks across call sites" requirement for `panic_sink`
   is not achievable with the current interface.** If `panic_sink` is called
   while `write_str`'s spinlock is held (e.g., a `klog!` mid-write causes a
   fault that triggers a panic), `panic_sink` cannot acquire the same spinlock.
   The fix is trivial — `panic_sink` writes directly to UART hardware — but the
   spec does not say this. It needs to say it explicitly to prevent implementors
   from using `write_str` inside `panic_sink`.

2. **The post-MMU UART remapping gap will cause a silent hang on aarch64 QEMU.**
   When `memory/` enables the MMU and the physical-to-virtual identity map is
   removed, `console/` will keep writing to physical address `0x0900_0000` but
   the virtual address `0x0900_0000` will no longer exist. The UART access will
   fault. This is a well-known early-boot bug in every kernel that has serial
   output — Linux handles it in `paging_init` with an `ioremap` call. NARF must
   have an equivalent `console::remap_to_virtual(new_va: VirtAddr)` function
   called during `memory::init`.
