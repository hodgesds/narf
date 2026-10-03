//! Control-register access.
//!
//! Every entry point takes the compiler_fence(SeqCst) pair per
//! `arch/` §4: CR4 in particular gates PKS / UIPI / OSFXSR, and fat
//! LTO reordering across the write is specifically a correctness
//! hazard the spec names.

use core::arch::asm;
use core::sync::atomic::{compiler_fence, AtomicBool, AtomicU64, Ordering};

use narf_lib::percpu::MAX_CPUS;

/// Cached copy of CR4, maintained by [`write_cr4`]. The trap/syscall entry
/// prologue reads this from MEMORY instead of executing `mov rax, cr4` to test
/// CR4.PKS (bit 24) / CR4.PCIDE (bit 17) and decide whether to enter a FRAME
/// isolation domain. Under KVM/SVM a `mov from CR4` VMEXITs, so reading the
/// register on every syscall + trap cost ~248k VMEXITs/sec under a redis load
/// (the dominant exit reason, ~half of all exit time). Those two bits are set
/// once at boot and never change (the domain switch writes CR3, never CR4), so
/// the cached value is always correct for the branch. `#[no_mangle]` because
/// the entry assembly references it by symbol via RIP (a linker-private
/// architecture ABI, like `NARF_X86_FRAME_PML4`).
#[unsafe(no_mangle)]
pub static NARF_X86_CACHED_CR4: AtomicU64 = AtomicU64::new(0);

/// CPU-local CR4 snapshots for Rust hot paths. CR4 is architecturally
/// per-CPU, so the linker-visible scalar above is suitable only for entry
/// assembly on systems whose boot policy keeps the relevant bits identical.
/// Rust code that needs the exact executing CPU's value must use
/// [`cached_cr4`] instead.
static PER_CPU_CACHED_CR4: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// Monotonic kernel-wide request to fault ring-3 `RDTSC` and `RDTSCP` on every
/// CPU. CR4.TSD cannot fault one without the other.
///
/// CR4.TSD is per-CPU, so publication alone is insufficient. A user task
/// reaches ring 3 on a CPU only after one of these activation points has run
/// [`activate_requested_user_instruction_interception`] on that CPU:
/// - the installation rendezvous, on every CPU online at installation;
/// - the userspace `UserTaskFuture` poll, before the first user entry and the
///   legacy longjmp re-entry;
/// - the scheduler's own-stack switch-in (`poll_to_yield`);
/// - the scheduler's direct task-to-task handoff (`prepare_direct_arch_state`).
///
/// A return to ring 3 from a trap or syscall stays on the CPU where the task
/// entered the kernel, which one of the points above has already armed.
///
/// CR4.TSD is sticky once set. Production never clears this request or the
/// bit. While the request is published, [`write_cr4`] ORs CR4.TSD into every
/// value it writes, with interrupts masked from that check through the write,
/// so a caller's read-modify-write that raced an arming rendezvous IPI cannot
/// undo it. The private CET/LAM writers read-modify-write the live register
/// during feature enablement, the boot and AP trampolines run once per CPU
/// before it can run a user task, and S3 resume restores the CR4 value
/// captured immediately before suspend. Only the `kernel-test` and
/// `verification-test-reset` hooks below clear it. The interceptor that
/// raised the request is likewise installed once for the kernel lifetime.
static USER_RDTSC_INTERCEPTION_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Last CR4 value written through [`write_cr4`] on the executing CPU.
///
/// All post-bootstrap CR4 mutations are required to use `write_cr4`, so this
/// avoids a serialising/intercepted `MOV from CR4` without weakening a
/// CPU-local feature gate. During early boot the zero initial value is the
/// conservative answer: no optional CR4-backed operation may execute.
#[inline]
pub fn cached_cr4() -> u64 {
    let cpu = crate::current_cpu_id().raw() as usize;
    cached_cr4_for_cpu(cpu)
}

/// Read the cached CR4 snapshot for an already-resolved CPU.
///
/// Kept crate-private so architecture helpers can share a caller's pinned CPU
/// identity without executing another RDTSCP. Cross-crate callers use the
/// unsafe operation-specific APIs that state the current-CPU requirement.
#[inline]
pub(crate) fn cached_cr4_for_cpu(cpu: usize) -> u64 {
    debug_assert!(cpu < MAX_CPUS, "CPU id out of CR4 cache range");
    PER_CPU_CACHED_CR4[if cpu < MAX_CPUS { cpu } else { 0 }].load(Ordering::Acquire)
}

/// CR4 bit: PKS (bit 24). Enables supervisor protection keys
/// (IA32_PKRS-based domain rights).
pub const CR4_PKS: u64 = 1 << 24;
/// CR4 bit: PKE (bit 22). Enables user-mode protection keys.
pub const CR4_PKE: u64 = 1 << 22;
/// CR4 bit: PCIDE (bit 17). Enables Process-Context Identifiers; once set,
/// CR3 carries a 12-bit PCID in bits 0..=11 and bit 63 of a CR3 write
/// can preserve the previous PCID's TLB entries instead of flushing.
pub const CR4_PCIDE: u64 = 1 << 17;
/// CR4 bit: FSGSBASE (bit 16). Enables the RDFSBASE/RDGSBASE and
/// WRFSBASE/WRGSBASE instructions at every privilege level.
pub const CR4_FSGSBASE: u64 = 1 << 16;
/// CR4 bit: OSXSAVE (bit 18). Enables XSAVE and processor extended states.
pub const CR4_OSXSAVE: u64 = 1 << 18;
/// CR4 bit: TSD (bit 2). When set, `RDTSC` at CPL > 0 raises #GP while
/// remaining available to kernel emulation at CPL0.
pub const CR4_TSD: u64 = 1 << 2;

/// Request kernel interception of ring-3 `RDTSC` and `RDTSCP` for the kernel
/// lifetime.
///
/// This both publishes the cross-CPU request and applies it to the executing
/// CPU. The userspace installer then applies it on every other online CPU
/// through the SMP rendezvous; CPUs brought online later apply it at the
/// activation points listed on `USER_RDTSC_INTERCEPTION_REQUESTED`.
pub fn request_user_rdtsc_interception() {
    USER_RDTSC_INTERCEPTION_REQUESTED.store(true, Ordering::Release);
    activate_requested_user_instruction_interception();
}

/// Apply all requested user-instruction traps to the executing CPU.
///
/// Called at each activation point listed on
/// `USER_RDTSC_INTERCEPTION_REQUESTED`: the installation rendezvous, the
/// `UserTaskFuture` poll, the own-stack switch-in and the direct handoff. The
/// cached fast path makes repeated calls a single CPU-local atomic load after
/// CR4.TSD is installed.
pub fn activate_requested_user_instruction_interception() {
    if !USER_RDTSC_INTERCEPTION_REQUESTED.load(Ordering::Acquire) || cached_cr4() & CR4_TSD != 0 {
        return;
    }

    // SAFETY: CR4.TSD is architectural on x86_64. The read-modify-write
    // preserves every other CR4 feature bit and updates NARF's per-CPU cache.
    unsafe {
        let current = read_cr4();
        if current & CR4_TSD == 0 {
            write_cr4(current | CR4_TSD);
        }
    }
}

/// Clear the global request and current CPU's CR4.TSD for isolated verification
/// tests. Production has no reset operation.
#[cfg(any(feature = "kernel-test", feature = "verification-test-reset"))]
#[doc(hidden)]
pub fn __verification_clear_user_rdtsc_interception() {
    USER_RDTSC_INTERCEPTION_REQUESTED.store(false, Ordering::Release);
    // SAFETY: verification teardown runs at CPL0 and preserves every CR4 bit
    // except TSD, which this module exclusively requested for the test.
    unsafe {
        let current = read_cr4();
        if current & CR4_TSD != 0 {
            write_cr4(current & !CR4_TSD);
        }
    }
}

/// Clear only the executing CPU's CR4.TSD bit while retaining the global
/// request. This lets the kernel scheduler test model first use on a migrated
/// CPU and prove that its switch-in path reapplies the request. It bypasses
/// [`write_cr4`], which would keep the requested bit set.
#[cfg(any(feature = "kernel-test", feature = "verification-test-reset"))]
#[doc(hidden)]
pub fn __test_clear_current_cpu_user_rdtsc_interception() {
    // SAFETY: the kernel test runs at CPL0 and preserves every other CR4 bit.
    unsafe {
        let current = read_cr4();
        if current & CR4_TSD != 0 {
            write_cr4_and_cache(current & !CR4_TSD);
        }
    }
}

/// CR0 bit: task switched. While set, an x87/MMX/SSE/AVX instruction raises
/// `#NM`; kernels use that fault to defer restoring a task's FP/SIMD image
/// until the task actually consumes the register file.
pub const CR0_TS: u64 = 1 << 3;

/// Read CR0.
///
/// # Safety
/// `MOV from CR0` is legal at CPL=0.
#[inline]
pub unsafe fn read_cr0() -> u64 {
    let value: u64;
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller guarantees CPL=0.
    unsafe {
        asm!("mov {value}, cr0", value = out(reg) value, options(nomem, nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
    value
}

/// Set CR0.TS so the next FP/SIMD instruction raises `#NM`.
///
/// # Safety
/// Must run at CPL=0. The caller must provide a `#NM` handler before returning
/// to code that may execute FP/SIMD instructions.
#[inline]
pub unsafe fn set_task_switched() {
    // SAFETY: forwarded CPL=0 contract.
    let value = unsafe { read_cr0() };
    if value & CR0_TS != 0 {
        return;
    }
    compiler_fence(Ordering::SeqCst);
    // SAFETY: setting the architecturally-defined TS bit preserves every
    // other CR0 bit read immediately above.
    unsafe {
        asm!("mov cr0, {value}", value = in(reg) (value | CR0_TS), options(nomem, nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Clear CR0.TS before restoring or using the current FP/SIMD register file.
///
/// # Safety
/// `CLTS` is privileged and therefore requires CPL=0.
#[inline]
pub unsafe fn clear_task_switched() {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller guarantees CPL=0.
    unsafe {
        asm!("clts", options(nomem, nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Read CR4.
///
/// # Safety
/// `MOV from CR4` is legal at CPL=0.
#[inline]
pub unsafe fn read_cr4() -> u64 {
    let v: u64;
    compiler_fence(Ordering::SeqCst);
    // SAFETY: MOV from CR4 at CPL=0 is always legal.
    unsafe {
        asm!("mov {out}, cr4", out = out(reg) v, options(nomem, nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
    v
}

/// Write CR4.
///
/// # Safety
/// - Only bits documented as writable may be set.
/// - Enabling new features may require other setup first (e.g. CR4.PKS
///   requires CPUID.(07h:0).ECX:31=1, else `#GP`).
///
/// While the kernel-wide user RDTSC interception request is published, the
/// written value always includes CR4.TSD. Interrupts are masked from that
/// check until the cached copy is updated, so an arming rendezvous IPI either
/// completes before the check or runs after this write and sees the new value.
#[inline]
pub unsafe fn write_cr4(value: u64) {
    let rflags = crate::x86_64::asm::read_rflags();
    // SAFETY: CLI is legal at CPL0; the saved IF is restored below.
    unsafe {
        asm!("cli", options(nomem, nostack));
    }
    let value = if USER_RDTSC_INTERCEPTION_REQUESTED.load(Ordering::Acquire) {
        value | CR4_TSD
    } else {
        value
    };
    // SAFETY: forwarded from the caller.
    unsafe {
        write_cr4_and_cache(value);
    }
    if rflags & (1 << 9) != 0 {
        // SAFETY: interrupts were enabled on entry.
        unsafe {
            asm!("sti", options(nomem, nostack));
        }
    }
}

/// Write CR4 exactly as given and update the cached copies.
///
/// # Safety
/// As for [`write_cr4`].
#[inline]
unsafe fn write_cr4_and_cache(value: u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller verified feature availability.
    unsafe {
        asm!("mov cr4, {v}", v = in(reg) value,
             options(nomem, nostack, preserves_flags));
    }
    // Keep the entry-prologue's cached copy in step with the register so the
    // trap/syscall path can test CR4.PKS/PCIDE from memory (no VMEXIT). Stored
    // AFTER the write so a concurrent entry reads either the old or new value,
    // never a torn one; feature bits change only during boot/AP bringup.
    let cpu = crate::current_cpu_id().raw() as usize;
    debug_assert!(cpu < MAX_CPUS, "CPU id out of CR4 cache range");
    PER_CPU_CACHED_CR4[if cpu < MAX_CPUS { cpu } else { 0 }].store(value, Ordering::Release);
    NARF_X86_CACHED_CR4.store(value, Ordering::Release);
    compiler_fence(Ordering::SeqCst);
}

/// Read CR3 (page-table base + PCID, when CR4.PCIDE=1).
///
/// # Safety
/// `MOV from CR3` is legal at CPL=0.
#[inline]
pub unsafe fn read_cr3() -> u64 {
    let v: u64;
    compiler_fence(Ordering::SeqCst);
    // SAFETY: MOV from CR3 at CPL=0 is always legal.
    unsafe {
        asm!("mov {out}, cr3", out = out(reg) v, options(nomem, nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
    v
}

/// Write CR3. When CR4.PCIDE=1, the low 12 bits encode a PCID and bit
/// 63 ("noflush") preserves the previous PCID's TLB entries.
///
/// # Safety
/// - The page-table base bits (PA bits, 12..=51) must point at a valid
///   4 KiB-aligned PML4 mapped writable in the current address space.
/// - When CR4.PCIDE=0, bits 0..=11 must encode legacy PWT/PCD and 0;
///   when CR4.PCIDE=1 they encode the PCID.
#[inline]
pub unsafe fn write_cr3(value: u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller upholds the contract above.
    unsafe {
        asm!("mov cr3, {v}", v = in(reg) value,
             options(nomem, nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}
