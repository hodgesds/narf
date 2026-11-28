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

With `boot-init` and `init=/sbin/openrc-init`, the framekernel directly starts the
selected root's `/sbin/openrc-init` as PID 1 with the system executable
search path. It installs the distro root before scheduling the task. OpenRC
selects the runlevels and services from that root. A loader error is reported
on the boot console and ends the launch attempt.

With `narf.rootlog`, the init thread checkpoints the writable Btrfs root
log before each remaining initcall and before publishing the installed PID 1.
The filesystem owns the log file and its sync operations.

Kernel-stack overflow handling (see §4):

```rust
// frame/src/kstack_overflow.rs — shared by both arches; panics unless a
// kernel test armed this overflow, then returns the (pc, sp) to resume at.
pub fn report(how: &str, hit: GuardHit, fault: u64, pc: u64, sp: u64, fp: u64)
    -> Option<(u64, u64)>;
// x86_64
pub fn gdt::df_ist_top() -> u64;              // this CPU's #DF IST stack top
// aarch64
pub fn aarch64::trap::init_overflow_stack();  // per CPU, sets TPIDR_EL1
extern "C" fn rust_aarch64_bad_stack(frame: &mut TrapFrame, old_sp: u64);
```

Production x86 boot enables tickless idle on capable local clockevents.
`nohz=off` retains periodic ticks; the former `nohz_idle` flag remains accepted
as an alias for the default. The power initcall installs the predictive idle
governor and discovers firmware states before normal executor idle.

Production boot forwards `steal_policy=full|numa|llc|pick2` to the scheduler's staged
steal-policy selector before queue initialization. Absent or unknown values
retain the existing NUMA-aware default; runtime policy installation remains
capability-gated by the scheduler.

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

When the build enables `external-composition`, frame includes the registrar at
the build-supplied `NARF_COMPOSITION_RS` path and calls its
`register_initcalls()` after the module KABI registrar and before initcall
execution. This is one generic hook: composition-specific source and Cargo
dependencies are generated below `target/`, not added to frame. A composed
built-in entry receives its static `DomainId` only when its manifest declares
one; runtime modules never use this path.

Trap entry is written in arch assembly and materialises the architecture-owned
`narf_arch::{x86_64,aarch64}::trap_frame::TrapFrame`. `frame` re-exports the
selected type and fans out to a Rust dispatcher. On aarch64 the former padding
slot at offset 24 holds `SP_EL0`: vector entry saves it and vector return
restores it, so a task that parks inside a syscall cannot inherit another
task's user stack. Signal and fork snapshots use that saved value. The
816-byte frame appends a 528-byte FP/SIMD image at offset 288. Assembly captures
it before Rust executes and restores it after Rust completes; kernel Rust is
allowed to use SIMD, so signal code edits this image instead of restoring
hardware FP registers underneath compiler-held values. The scheduler consumes that
shared type directly; it does not define or cast a mirror layout.

On aarch64 the BSP selects the interrupt controller during early bring-up,
before any IRQ is unmasked: it locates the boot devicetree
(`narf_boot::aarch64::locate_dtb`), calls `narf_interrupts::aarch64::gic::probe`
(GICv2 or GICv3 from the DT `compatible` / `reg`; QEMU `virt` GICv3 bases only
when the tree has no GIC node and `ID_AA64PFR0_EL1.GIC` is set) and then
`gic::init_bsp`. A probe failure leaves IRQs masked. The IRQ vector's Rust
dispatcher (`rust_aarch64_irq`) acknowledges and EOIs through
`narf_interrupts::aarch64::{ack_irq, iar_intid, eoi_for}` and never touches
`ICC_*` system registers or `GICC` MMIO itself.

On aarch64, restorer-based Linux signal handlers receive an `rt_sigframe`
with Linux arm64 ucontext/GPR offsets and an FPSIMD context record. Delivery
uses guarded user copies before publishing the handler's PC/SP/LR. `rt_sigreturn`
snapshots the user frame once and validates user addresses, alignment, context
records and EL0-only PSTATE before restoring GPR/FP state. It never restores
kernel domain-control state from user memory. The existing NARF non-restorer
signal entry remains separate. A syscall already rewound for a blocking park
uses restart-pending signal delivery; completed syscalls are not restarted.
Both architectures' frame writers obtain the pre-handler signal mask from
`narf_userspace::signal_mask_for_delivery` and publish it in `uc_sigmask`.
The userspace sigreturn layer imports the user-edited mask with guarded access
before requesting register restoration; domain-control state is never imported
from that mask or any user signal frame.

The bare `zram` kernel-command-line flag explicitly installs memory's built-in
compressed-RAM swap backend during userspace bootstrap. Without it, NARF boots
with no swap area, matching Linux until a future `swapon(2)` path configures
one.

Cache-attribute setup is per CPU and part of bring-up. On x86_64 the BSP
calls `narf_arch::x86_64::pat::bp_init()` after the IDT is live and before any
AP starts, each AP calls `pat::cpu_init()` right after its IDT load in
`_ap_start_rust` (an AP that cannot take the BSP's layout halts offline, where
Linux would panic), and the S3 wake continuation reprograms the BSP before
device resume. PAT writes require matching readback; an establishment or S3
restore failure stops before device access, while an absent PAT uses the
conservative disabled table. On aarch64 `boot.S` (BSP) and `smp_entry.S` (each AP) write
`MAIR_EL1 = 0x44F004FF`, `narf_arch::aarch64::mair::MAIR_EL1_VALUE`; indices
0..=2 are unchanged and 3/4 add Normal-NC and Device-nGnRnE.
Before allocator donation, BSP initialization separately registers usable,
kernel-image and ACPI reclaimable/NVS RAM for cache-alias checks. Generic
Reserved ranges remain ambiguous and are not treated as RAM. Early and late
framebuffer mappings share the kernel/user WC type (ARM Normal-NC).

Early BSP setup applies Linux-style `quiet`, `debug`, and `loglevel=N` tokens
to the console threshold before emitting the normal boot banner. This affects
only physical console emission: the bounded klog remains complete, and panic
plus fatal-trap sinks remain unconditional.

The BSP calls `scheduler::init()` once before AP bring-up, then explicitly
creates CPU-budget grants and delegates `UserSchedulingAuthority` to the Linux
compatibility service before any user task can run. Scheduling syscalls never
bootstrap capabilities. Both architectures' IRQ tails finish EOI and interrupt
accounting before an RT event can request an own-stack user switch; kernel-mode
user continuations carry a sticky request to completed syscall exit.

Ordinary own-stack user returns (syscall, interrupt, and recoverable exception) call
`narf_scheduler::stackful::finish_user_return` after releasing handler locks and
hard-IRQ guards. It may enable interrupts on the task stack to activate queued
wakes and perform policy-approved rescheduling, then returns with interrupts
masked. Register/domain restoration keeps that mask until the atomic user
return instruction. A notification received late in kernel mode therefore
cannot be consumed by an IPI after the final wake check but before user entry.

Boot installs the procfs network snapshot adapters. Each adapter queries the
network stack using the namespace ID supplied by the open procfs file,
including for IPv6 addresses and routes.

### 3.1 x86_64 IA-32 emulation (Linux `CONFIG_IA32_EMULATION`)

Every CPU's GDT has Linux's 64-bit layout (`arch/x86/include/asm/segment.h`)
for each user-visible selector; the constants live in
`narf_arch::x86_64::segments`:

| index | selector | descriptor |
|-------|----------|------------|
| 1 | 0x08 | kernel code (NARF's; Linux uses 0x10) |
| 2 | 0x10 | kernel data |
| 4 | 0x23 | `__USER32_CS`: flat 32-bit user code, DPL 3 |
| 5 | 0x2b | `__USER_DS`: flat user data, DPL 3 |
| 6 | 0x33 | `__USER_CS`: long-mode user code, DPL 3 |
| 8–9 | 0x40 | TSS, loaded by `LTR` |
| 12–14 | 0x63, 0x6b, 0x73 | TLS slots, the running task's |

Slots 0, 3, 7, 10–11 (LDT, never installed) and 15 are empty. `gdt::init`
(BSP) and `gdt::init_ap` (each AP) build the table and publish it with
`segments::register_cpu_gdt(cpu, gdt)`; `segments::cpu_gdt(cpu)` returns it.

`IA32_STAR[63:48]` is `__USER32_CS`: `sysretq` returns to 0x33/0x2b and
`sysretl` to 0x23/0x2b. `IA32_CSTAR`, where AMD CPUs enter on a `syscall`
from compatibility mode, is `syscall32_ignore_x86_64`: Linux's
`ignore_sysret`, which returns -ENOSYS in eax with `sysretl` without touching
the stack or GS. (Intel raises #UD for that `syscall`.)

```rust
// narf_arch::x86_64::segments
pub const GDT_ENTRIES: usize = 16;
pub const GDT_ENTRY_TLS_MIN: usize = 12; // ..=GDT_ENTRY_TLS_MAX (14)
pub const USER32_CS: u16 = 0x23; pub const USER_DS: u16 = 0x2b;
pub const USER_CS: u16 = 0x33;   pub const TSS_SELECTOR: u16 = 0x40;
pub unsafe fn register_cpu_gdt(cpu: usize, gdt: *mut u64);
pub fn cpu_gdt(cpu: usize) -> *mut u64;
```

**The i386 system-call hook.** `int 0x80` from user mode is the i386 ABI
for every task (Linux `do_int80_emulation`). The gate builds a
`TrapContext` over the trap frame whose `args()` are ebx, ecx, edx, esi,
edi, ebp zero-extended, whose `set_return` writes rax with
`compat32::user_rax` and nothing else, and whose `in_ia32_syscall()` is
true, and calls `compat32::dispatch` with eax. `compat32` (userspace)
runs seccomp for `AUDIT_ARCH_I386`, the TLS calls, then
`compat32::table::dispatch` (the i386 table, owned by the IA-32 userspace
work), and delivers signals with restart semantics. If the call parked to
be re-executed (RIP rewound onto `int 0x80`), the gate restores eax to the
number (Linux `orig_ax`). A kernel-mode `int 0x80` panics, as Linux's
`do_int80_emulation` does. 64-bit code enters through `syscall` only; the
in-tree runtime (`narf-user-runtime`) and fixtures use it.
`compat32::user_rax` is the value sign-extended; a non-Ok NARF status
reads as its errno when the value carries one, else -EINVAL. A task parked
in an `int 0x80` call reports eax and ebx..ebp as its number and arguments
(`/proc/<pid>/syscall`). Seccomp sees these calls with `AUDIT_ARCH_I386`
and the i386 number (`seccomp_data`, `si_arch`, user notifications); they
never take the native constant-action cache, and strict mode admits the
i386 set (read 3, write 4, exit 1, sigreturn 119).

```rust
// narf_userspace::compat32
pub fn dispatch(nr: u32, ctx: &mut dyn TrapContext);
pub fn user_rax(ret: SyscallReturn) -> u64;
pub mod table {
    pub fn dispatch(nr: u32, ctx: &mut dyn TrapContext) -> Option<Syscall>;
    pub fn forward(ctx: &mut dyn TrapContext, variant: Syscall) -> Option<Syscall>;
}
pub mod tls {
    pub fn sys_set_thread_area(ctx: &mut dyn TrapContext); // i386 243
    pub fn sys_get_thread_area(ctx: &mut dyn TrapContext); // i386 244
    pub fn current_segments() -> UserSegments;             // fork/clone copy
    pub fn set_child_tls(segs: &mut UserSegments, gs_base: &mut u64,
                         fs_base: &mut Option<u64>, info: &UserDesc) -> i64;
    pub fn clone_settls(segs: &mut UserSegments, gs_base: &mut u64,
                        fs_base: &mut Option<u64>, u_info: u64) -> i64;
}
// narf_userspace::syscall
pub fn dispatch_native(variant: Syscall, ctx: &mut dyn TrapContext);
trait TrapContext {
    fn in_ia32_syscall(&self) -> bool { false } // TS_COMPAT
    fn in_compat_mode(&self) -> bool { false }  // trapping CS == __USER32_CS
}
```

**Entering a 32-bit task.** `UserProcess::ia32` asks the first entry (and a
fork/clone child's first resume) for CS = `__USER32_CS`; a fresh image gets
DS = ES = SS = `__USER_DS`, FS = GS = 0 with zero bases (Linux
`start_thread_ia32`). `UserProcess::segs: UserSegments` is the task's
initial TLS descriptors and DS/ES/FS/GS selectors (empty for an image, the
parent's for fork/clone), applied before the FS/GS bases.

**Per-task segment state.** The scheduler keeps each task's TLS
descriptors and selectors (Linux `thread.tls_array`, `ds`, `es`,
`fsindex`, `gsindex`). Switch-out saves the live selectors; switch-in loads
the task's descriptors into the running CPU's slots 12..=14, then its
selectors (GS through `load_gs_index`'s `swapgs` bracket with interrupts
masked; a selector whose descriptor is no longer loadable becomes null),
then the FS/GS bases. A register is reloaded only when it or its
replacement is non-null, so 64-bit-only switches reload nothing. A nested
poll restores the outer task's whole segment state after the inner task
yields. The first own-stack poll applies `UserProcess::segs`; execve
empties the slots and nulls the selectors.

`set_thread_area` (i386 243) and `get_thread_area` (244) follow
`arch/x86/kernel/tls.c`: `tls_desc_okay` (no 16-bit, code or non-present
segments; `LDT_empty`/`LDT_zero` clear a slot), entry -1 allocates the
first empty slot and writes its index back (-ESRCH when none), indexes
outside 12..=14 are -EINVAL, `fill_ldt` never sets L, and a data segment
register naming the rewritten slot is reloaded. `clone_settls` /
`set_child_tls` apply a `CLONE_SETTLS` descriptor to a child's
`UserSegments` (no allocation) and set the child's FS or GS base when its
selector names the slot.

```rust
// narf_scheduler::stackful (x86_64)
pub fn set_current_user_tls_desc(slot: usize, desc: u64);
pub fn current_user_tls() -> [u64; 3];
pub fn current_user_segments() -> ([u64; 3], UserSelectors);
pub fn set_current_user_segments(tls: [u64; 3], sel: UserSelectors);
// narf_arch::x86_64::segments
pub struct UserDesc { entry_number, base_addr, limit, flags }
pub fn tls_desc_okay(&UserDesc) -> bool;   pub fn fill_ldt(&UserDesc) -> u64;
pub fn fill_user_desc(idx: u32, desc: u64) -> UserDesc;
pub fn ldt_empty(&UserDesc) -> bool;       pub fn ldt_zero(&UserDesc) -> bool;
pub fn get_free_idx(&[u64; 3]) -> Option<u32>;
pub struct UserSelectors { ds, es, fs, gs }
pub fn read_user_selectors() -> UserSelectors;  pub fn cpu_tls() -> [u64; 3];
pub fn selector_loadable(sel: u16, tls: &[u64; 3]) -> bool;
pub unsafe fn load_tls(&[u64; 3]);         pub unsafe fn load_gs_index(u16);
pub unsafe fn load_user_selectors(UserSelectors, &[u64; 3]);
pub unsafe fn reload_selector_users(modified: u16, &[u64; 3]);
```

## 4. Invariants & safety properties

- There is exactly one `CpuLocal` per CPU, pinned to its per-CPU page.
- Hard-IRQ handling never allocates. The completed own-stack user-return loop
  may grow a ready queue after IRQ accounting ends and interrupts are enabled.
- IST exceptions (NMI, double fault, machine check, and SEV-ES #VC) never enter
  the scheduling return loop; their exception stacks cannot be suspended.
- Anonymous user demand faults that hit the protected memory reserve may yield
  only after memory has retired the page claim, released address-space and
  allocator locks, and frame has cleared the active per-CPU mempolicy slot.
  Each waiting fault links an entry from its own kernel stack into its NUMA
  node's wait queue (Linux `reclaim_throttle` on `pgdat->reclaim_wait`), so the
  registry has no capacity; registration and notification allocate nothing,
  completions wake in bounded batches outside the queue lock, the entry is
  recorded as the task's `stackful::StackWait` so a task dropped mid-park is
  unlinked before its stack is retired, and waits use the task-owned scheduler
  waker so CPU migration/hotplug do not invalidate a wait. Exact reclaim-cycle
  completion wakes matching waiters through a generation-ordered handshake. A
  task retries only after such completion, for at most Linux's sixteen-cycle
  reclaim bound; no stackful task fails without another park, and no path
  busy-yields.
- A kernel/current-EL fault inside guarded uaccess never enters that reclaim
  wait. The trap may make one non-parking demand-allocation attempt; reserve
  pressure falls through to the architecture probe fixup and becomes `EFAULT`.
  This keeps the per-CPU probe slot, x86 SMAP AC window, and IRQ mask within one
  uninterrupted task/CPU interval.
- x86 signal-frame writes use that guarded-uaccess path directly. A present
  stack page needs no address-space preflight; demand paging, stack growth, and
  COW are attempted by the synchronous fault handler, while an invalid or
  concurrently unmapped target reaches the probe fixup and terminates only the
  receiving task.
- **x86_64 IA-32 segments (§3.1).** Every CPU's `IA32_CSTAR` names the
  -ENOSYS `sysretl` stub before user code can run there, so a compat-mode
  `syscall` never jumps to an unprogrammed CSTAR at CPL 0. The kernel loads
  a user DS/ES/FS/GS selector only after `selector_loadable` accepts it
  against the slots this CPU now holds (otherwise null), so no switch, exec
  or `set_thread_area` path takes a #GP/#NP at CPL 0. GS is loaded only
  inside `swapgs` … `swapgs` with interrupts masked, and the user GS base is
  rewritten from the task's saved value afterwards. TLS descriptors are
  built only by `fill_ldt` from requests `tls_desc_okay` accepts: DPL 3,
  32-bit, data, present, never L — no 16-bit stack segment (no espfix
  leak), no call-gate or system descriptor.
- `int 0x80` serves user tasks only; a kernel-mode `int 0x80` panics. Its
  return replaces a user SS that no longer names a present DPL-3 writable
  data segment (a TLS slot emptied or narrowed under it) with `__USER_DS`,
  so the `iretq` cannot fault at CPL 0 (Linux delivers SIGSEGV through
  `fixup_bad_iret`; NARF has no bad-IRET fixup).
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
- **User x86 `#NM` is the deferred FP/SIMD restore boundary.** After the common
  prologue has entered Frame state, vector 7 from CPL3 asks the scheduler to
  restore only the currently published own-stack task image and returns to
  retry the faulting instruction. Vector 7 from CPL0, or without a matching
  published task/image, remains on the fatal exception path.
- **PKRU is eager per-task x86 state.** If CPUID.PKU is advertised, BSP and
  every AP set CR4.PKE before userspace runs. The scheduler saves PKRU on every
  user-task switch and restores it before return to CPL3; this is separate from
  lazy FP/SIMD handling because `WRPKRU` does not require an FP trap. PKRU is
  user-mode state and never replaces the trap entry PKRS save/restore used for
  supervisor domain enforcement.
- **x86 signal-frame FP capture and restore materialize scheduler-owned lazy
  state before FXSAVE/FXRSTOR.** Frame asks the scheduler to restore a deferred
  current-task image, clear CR0.TS, and mark the register file live before
  reading or replacing it. Frame must not independently clear TS for an
  own-stack task because that would make the scheduler skip the next save and
  could expose another task's register image.
- **aarch64 IRQ acknowledge runs only after the prologue above.** The GIC
  acknowledge (`ICC_IAR1_EL1` on GICv3, `GICC_IAR` MMIO on GICv2) is the
  first device access of `rust_aarch64_irq`, i.e. after step 3; its backend
  is fixed before the first IRQ unmask, so the per-trap cost is one load and
  branch on a boot-time static. The GICv2 `GICC` window is a TTBR1
  Device-nGnRE mapping (untagged, shared by every address space), so it is
  reachable from Frame state whichever task was interrupted.
- **NMI / double-fault / machine-check paths have their own IST-backed
  trap frames** and perform the same save/restore independently. They
  must not assume GS / TPIDR_EL1 is valid.
- **A kernel-stack overflow is reported, never silent, and never handled on
  the overflowed stack** (Linux `handle_stack_overflow` / arm64
  `handle_bad_stack`). x86_64: a #DF whose CR2 (or saved RSP) is guard VA
  (`kstack::guard_hit`) is reported from the #DF IST stack before anything
  reads the faulting stack; a CPL0 #PF on guard VA switches to the #DF IST
  stack (`call_on_stack`) and reports there. aarch64: every current-EL/SP_EL1
  vector first runs `KSTACK_CHECK` — for an SP in `KSTACK_L0_SLOT`, bit
  `KSTACK_SHIFT` of `SP - 816` set means the frame push would land below the
  stack's base — and branches, storing nothing, to `__narf_kstack_overflow`,
  which moves to this CPU's overflow stack (`TPIDR_EL1`, a guarded 16 KiB
  `KernelStack` set by `init_overflow_stack` before the CPU runs anything on a
  guarded stack) and calls `rust_aarch64_bad_stack`; an EL1 data abort on
  guard VA with SP still inside the stack is reported from the sync dispatch.
  `TPIDRRO_EL0` is entry scratch for that check and is zero whenever EL0 runs.
  The report (`kstack_overflow::report`) prints CPU, task, stack bounds, guard
  address, pc/sp/fp and a backtrace read from the overflowed stack, takes no
  lock and allocates nothing, then panics — except for an overflow a
  kernel-test build armed for that exact stack, which is retired instead.
- Panic path never returns; it quiesces the system and hands over to
  `console/`. On SMP (Stage 2+) it broadcasts an `IPI-NMI` to halt APs
  before calling `console::panic_sink`.

## 5. Architecture notes

### x86_64
- GDT per CPU in Linux's 64-bit layout (§3.1): kernel code and data, 32-bit
  user code, user data, 64-bit user code, the TSS and three TLS slots.
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
- CPU-time boundary (`scheduler/` §3.4.1): after the domain prefix and before
  the dispatcher, a trap whose frame CS is a user selector, and every SYSCALL
  entry while IF is still clear, call `narf_cputime_user_exit`; after the
  dispatcher returns and with IF clear (`cli`), a return through a user CS
  and every SYSRET call `narf_cputime_user_enter`, before the domain restore.
  Both are a TSC read and per-CPU stores; no lock, I/O or allocation.

### aarch64
- EL1 vector table aligned to 2 KiB; four groups of four vectors.
- `TPIDR_EL1` holds this CPU's kernel-stack overflow-stack top (written by
  `init_overflow_stack`; read by `vec.S` before it may store). The CPU id
  comes from MPIDR (`narf_arch::aarch64::cpu::current_cpu`), not from a
  `CpuLocal` pointer in `TPIDR_EL1`.
- SP_EL0 for user, SP_EL1 for kernel; SPSel=1 on entry.
- CPU-time boundary (`scheduler/` §3.4.1): `__narf_vec_sync_el0` calls
  `narf_cputime_user_exit` before its dispatcher and
  `narf_cputime_sync_el0_return` (masks IRQs; acts only for an EL0 SPSR)
  after it; `rust_aarch64_irq` does the same around an IRQ taken from EL0,
  the exit after `finish_user_return`.
- Each AP receives one contiguous 64 KiB kernel stack before `CPU_ON`. The AP
  entry trampoline uses its physical top with the MMU off, then rebases the
  empty stack to the high direct map before entering Rust. Before entering its
  scheduler loop the AP moves to a guarded 64 KiB `KernelStack`
  (`run_executor_on_guarded_stack`, both arches); the boot block is abandoned.
  AP executor and IRQ work must never run on a single-page boot stack.
- **Stack alignment:** SP must be 16-byte aligned at EL1 vector entry;
  the vector prologue enforces this before any push.
- **MTE is suspended on vector entry.** The prologue clears
  `SCTLR_EL1.TCF/TCF0` while retaining `ATA`, then saves both SCTLR and GCR;
  the exact state is restored on `eret`. This prevents
  the trap handler itself from faulting on tag mismatches while
  running in Frame context.
- **Interrupt controller:** GICv3 (system-register CPU interface) or GICv2
  (memory-mapped CPU interface; Qualcomm IPQ8074/IPQ6018/IPQ5018), chosen by
  `gic::probe` from the devicetree in BSP bring-up. Per-AP `gic::init_ap`
  runs in `_ap_start_rust` before the AP unmasks IRQs; the BSP maps each AP's
  GICv3 redistributor (`gic::remap_mmio`) before `CPU_ON`.

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
