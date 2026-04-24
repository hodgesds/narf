//! narf-verification — kernel-test harness.
//!
//! Spec: `verification/specification/spec.md` §6 + §7. Stage-1 subset:
//! a `#[kernel_test]` collector (via the `linkme` pattern — statics in
//! a dedicated ELF section linked together into one array at build
//! time), a runtime `run_all` that iterates and prints pass/fail, and
//! `exit_with_result` that maps to the xtask's pass/fail exit codes.
//!
//! This is intentionally allocation-free so tests can run before the
//! bump heap is initialised, and single-threaded because Stage 1 is
//! single-CPU. Wave 2 will promote this to a per-CPU harness with
//! parallel execution once APs are online.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]
#![feature(generic_const_exprs)]
#![allow(incomplete_features)]

extern crate alloc;

use core::fmt::Write;

use narf_console::Writer;

/// A single test case.
///
/// Tests are `fn() -> TestResult` with no arguments — keep them pure so
/// they can be reordered / parallelised later. Test authors use the
/// `kernel_test!` macro to register a name/function pair into the
/// collector section.
#[derive(Copy, Clone)]
pub struct KernelTest {
    pub name: &'static str,
    pub run:  fn() -> TestResult,
}

impl core::fmt::Debug for KernelTest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KernelTest").field("name", &self.name).finish_non_exhaustive()
    }
}

/// Pass / fail / skip, with a static reason string.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TestResult {
    Pass,
    Fail(&'static str),
    Skip(&'static str),
}

/// Exit code returned by the harness. `exit_with_result` maps:
///
/// | summary        | exit_kernel code |
/// |----------------|------------------|
/// | all Pass/Skip  | 0                |
/// | any Fail       | 1                |
///
/// xtask maps those via `isa-debug-exit` to process exit codes 1 / 3.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Summary { AllOk, SomeFailed }

// ── test registration via an ELF section ──────────────────────────
//
// The pattern: put `KernelTest` entries in a dedicated linker section
// named `narf.tests`. The linker emits start/end symbols we read at
// runtime to form the slice. Callers define tests with `kernel_test!`.

extern "Rust" {
    static __narf_tests_start: KernelTest;
    static __narf_tests_end:   KernelTest;
}

/// Return a slice over every `#[kernel_test]`-registered test.
pub fn tests() -> &'static [KernelTest] {
    // SAFETY: the linker synthesises the start/end symbols at the
    // boundaries of the `narf.tests` section. The section contains
    // zero or more `KernelTest` structs and nothing else (the
    // `kernel_test!` macro is the only writer).
    let start = unsafe { &__narf_tests_start as *const KernelTest };
    let end   = unsafe { &__narf_tests_end   as *const KernelTest };
    let len   = (end as usize - start as usize) / core::mem::size_of::<KernelTest>();
    // SAFETY: `start` and `len` derived from the linker symbols,
    // which bound a contiguous region of KernelTest entries.
    unsafe { core::slice::from_raw_parts(start, len) }
}

/// Register a `#[kernel_test]`-like function. Expands to a static in
/// the `narf.tests` section.
///
/// Example:
///
/// ```ignore
/// use narf_verification::{kernel_test, TestResult};
/// fn math_is_still_math() -> TestResult {
///     if 1 + 1 == 2 { TestResult::Pass } else { TestResult::Fail("arithmetic broke") }
/// }
/// kernel_test!(math_is_still_math);
/// ```
#[macro_export]
macro_rules! kernel_test {
    ($name:ident) => {
        // Nested in a `const _:()` so multiple invocations in the same
        // module don't collide on the static's name. The static still
        // lands in the `narf.tests` section because `#[link_section]`
        // only cares about the final binary layout, not Rust scoping.
        const _: () = {
            #[used]
            #[link_section = "narf.tests"]
            static ENTRY: $crate::KernelTest = $crate::KernelTest {
                name: stringify!($name),
                run:  $name,
            };
        };
    };
}

/// Run every registered test, print results to the console, return a
/// summary. Intended to be called from the kernel's `_start_rust`
/// during CI builds (feature-gated by consumers).
pub fn run_all() -> Summary {
    let _ = writeln!(Writer, "");
    let _ = writeln!(Writer, "── kernel_test harness ──────────────────────────");
    let ts = tests();
    if ts.is_empty() {
        let _ = writeln!(Writer, "  (no tests registered)");
        return Summary::AllOk;
    }
    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut skip = 0usize;
    for t in ts {
        match (t.run)() {
            TestResult::Pass => {
                let _ = writeln!(Writer, "  [ OK ] {}", t.name);
                pass += 1;
            }
            TestResult::Fail(why) => {
                let _ = writeln!(Writer, "  [FAIL] {}: {}", t.name, why);
                fail += 1;
            }
            TestResult::Skip(why) => {
                let _ = writeln!(Writer, "  [skip] {}: {}", t.name, why);
                skip += 1;
            }
        }
    }
    let _ = writeln!(Writer, "── summary: {} pass, {} fail, {} skip ──",
        pass, fail, skip);

    if fail == 0 { Summary::AllOk } else { Summary::SomeFailed }
}

/// Run every test and immediately exit the kernel with the mapped code.
pub fn run_all_and_exit() -> ! {
    let code = match run_all() {
        Summary::AllOk      => 0,
        Summary::SomeFailed => 1,
    };
    // SAFETY: exit_kernel is the only post-test action we're authorised
    // to take; it does not return.
    unsafe { narf_arch::exit_kernel(code) }
}

// ── built-in smoke tests that always register ──────────────────
//
// These live in the library so any binary linking `narf-verification`
// gets at least this much coverage.

fn smoke_typed_id_sanity() -> TestResult {
    use narf_lib::id::{CpuId, DomainId, TaskId};
    if CpuId::new(7).raw() != 7 { return TestResult::Fail("CpuId::raw mismatch"); }
    if DomainId::FRAME.raw() != 0 { return TestResult::Fail("FRAME != 0"); }
    if DomainId::SCRATCH.raw() != 15 { return TestResult::Fail("SCRATCH != 15"); }
    if TaskId::new(0xDEAD).raw() != 0xDEAD { return TestResult::Fail("TaskId::raw mismatch"); }
    TestResult::Pass
}
kernel_test!(smoke_typed_id_sanity);

fn smoke_spin_lock_cycle() -> TestResult {
    use narf_lib::sync::{SpinLock, IrqsEnabled};
    let l = SpinLock::new(0u32);
    {
        let mut g = l.lock(IrqsEnabled);
        *g = 42;
    }
    if *l.lock(IrqsEnabled) == 42 { TestResult::Pass }
    else { TestResult::Fail("SpinLock round-trip lost its value") }
}
kernel_test!(smoke_spin_lock_cycle);

fn smoke_bitmap_first_set() -> TestResult {
    use narf_lib::bitmap::Bitmap;
    let mut b: Bitmap<128> = Bitmap::new();
    b.set(5);
    b.set(70);
    match (b.first_set(), b.count_ones()) {
        (Some(5), 2) => TestResult::Pass,
        _            => TestResult::Fail("Bitmap first_set/count_ones wrong"),
    }
}
kernel_test!(smoke_bitmap_first_set);

fn smoke_arch_backend() -> TestResult {
    use narf_arch::{BACKEND, DomainBackend};
    let expected = if cfg!(target_arch = "x86_64") { DomainBackend::Pks }
                   else if cfg!(target_arch = "aarch64") { DomainBackend::Mte }
                   else { return TestResult::Skip("unknown arch"); };
    if BACKEND == expected { TestResult::Pass }
    else { TestResult::Fail("BACKEND constant mismatch") }
}
kernel_test!(smoke_arch_backend);

fn smoke_monotonic_advances() -> TestResult {
    let a = narf_time::now_cycles();
    for _ in 0..100_000 { core::hint::spin_loop(); }
    let b = narf_time::now_cycles();
    if b > a { TestResult::Pass } else { TestResult::Fail("monotonic counter didn't advance") }
}
kernel_test!(smoke_monotonic_advances);

fn smoke_box_roundtrip() -> TestResult {
    use alloc::boxed::Box;
    let b: Box<[u32; 4]> = Box::new([1, 2, 3, 4]);
    let sum: u32 = b.iter().sum();
    if sum == 10 { TestResult::Pass } else { TestResult::Fail("Box<[u32;4]> sum wrong") }
}
kernel_test!(smoke_box_roundtrip);

fn smoke_scheduler_drives_future() -> TestResult {
    use core::sync::atomic::{AtomicUsize, Ordering};
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    narf_scheduler::init();
    for _ in 0..3 {
        narf_scheduler::spawn(async {
            COUNT.fetch_add(1, Ordering::Relaxed);
            narf_scheduler::yield_now().await;
            COUNT.fetch_add(10, Ordering::Relaxed);
        });
    }
    narf_scheduler::run_until_empty();
    // Three tasks × (1 + 10) = 33.
    if COUNT.load(Ordering::Relaxed) == 33 { TestResult::Pass }
    else { TestResult::Fail("scheduler didn't drive 3 tasks to completion") }
}
kernel_test!(smoke_scheduler_drives_future);

#[cfg(target_arch = "x86_64")]
fn smoke_timer_irq_fires() -> TestResult {
    // Hardware-IRQ end-to-end: program the LAPIC timer + STI, busy-wait
    // a while, confirm the tick counter advances. Requires PIC masking
    // (done by apic::init_bsp) — otherwise legacy PIC IRQs land on our
    // CPU-exception slots and cause #DF.
    use narf_arch::x86_64::Features;
    // SAFETY: CPUID always legal.
    let feats = unsafe { Features::probe() };
    if !feats.x2apic {
        return TestResult::Skip("x2APIC not exposed");
    }
    let before = narf_interrupts::x86_64::apic::timer_ticks();
    // SAFETY: APIC init has run at boot; this programs the timer + STI.
    unsafe {
        narf_interrupts::x86_64::apic::start_timer(
            narf_interrupts::VECTOR_TIMER, 500_000);
        narf_arch::enable_interrupts();
    }
    // Busy-wait ~50M cycles.
    let start = narf_time::Instant::now();
    while narf_time::Instant::now().cycles_since(start) < 50_000_000 {
        core::hint::spin_loop();
    }
    // SAFETY: disable IRQs + stop timer before checking.
    unsafe {
        narf_arch::disable_interrupts();
        narf_interrupts::x86_64::apic::stop_timer();
    }
    let after = narf_interrupts::x86_64::apic::timer_ticks();
    if after > before { TestResult::Pass }
    else { TestResult::Fail("LAPIC timer IRQ never fired") }
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_timer_irq_fires);

#[cfg(target_arch = "x86_64")]
fn smoke_probe_catches_page_fault() -> TestResult {
    // Arm the recoverable-fault probe, write to an unmapped virtual
    // address (above our 4 GiB identity map), and verify the handler
    // caught the #PF (vector 14) instead of panic-exiting.
    use core::arch::asm;
    use narf_arch::x86_64::probe;

    // Address above our 4-GiB identity map. The MMU handoff installed a
    // PML4 with PDPT[0..=3] = 1-GiB huge pages covering phys 0..=4 GiB.
    // Anything at 4 GiB and above has no PML4 entry and will #PF.
    let unmapped: u64 = 0x0000_0001_0000_0000;

    let recovery: u64;
    // Step 1: compute the recovery RIP and arm the probe. The
    // recovery label must match the one in the probing asm block
    // below. rustc rejects numeric asm labels (LLVM issue #99547);
    // use an alphabetic local.
    // SAFETY: LEA of a local label is always safe.
    unsafe {
        asm!(
            "lea {rec}, [99f + rip]",
            rec = out(reg) recovery,
            options(nostack, preserves_flags),
        );
    }
    // The `99:` target below is reachable via the LEA above because
    // rustc emits each asm block into the same translation unit and
    // local labels resolve at link time. We compute the recovery RIP
    // in the first block and use the label in the second.
    probe::arm(recovery);

    // Step 2: the probe. Writing to `unmapped` raises #PF; the trap
    // handler sees the armed probe, records vector, rewrites RIP to
    // the `99:` label, and iretqs there.
    // SAFETY: if PKS / paging are broken and this write *succeeds*,
    // it just stores a byte at a virtual address that doesn't exist
    // in our PML4; the test reports failure rather than crashing.
    unsafe {
        asm!(
            "mov byte ptr [{ptr}], 0",
            "99:",
            ptr = in(reg) unmapped,
            options(nostack),
        );
    }

    // Step 3: disarm and inspect.
    let caught = probe::disarm();
    match caught.vector {
        Some(14) => TestResult::Pass,
        Some(_)  => TestResult::Fail("wrong vector caught (not #PF)"),
        None     => TestResult::Fail("probe didn't catch the expected #PF"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_probe_catches_page_fault);

#[cfg(target_arch = "x86_64")]
fn smoke_nx_enforces_no_exec() -> TestResult {
    // Map a page NO_EXEC, attempt to execute from it, verify the
    // resulting #PF has the instruction-fetch bit (bit 4) set in the
    // error code. x86_64 #PF error-code bit 4 is defined as "this
    // fault was caused by an instruction fetch" (SDM Vol 3 §4.7).
    use core::arch::asm;
    use narf_arch::x86_64::{probe, Features};
    use narf_memory::{alloc_frame, FrameAllocError, free_frame, VirtAddr};
    use narf_memory::paging::{map_4kb, unmap_4kb, read_cr3, PtFlags};

    // SAFETY: CPUID always legal.
    let feats = unsafe { Features::probe() };
    if !feats.nx {
        return TestResult::Skip("NX not exposed");
    }

    let pml4 = unsafe { read_cr3() };
    let frame = match alloc_frame() {
        Ok(f) => f,
        Err(FrameAllocError::Uninitialised) =>
            return TestResult::Skip("frame allocator not initialised"),
        Err(_) => return TestResult::Fail("alloc_frame failed"),
    };
    // Same high-but-unmapped virt range as the PKS test (8 GiB+).
    let virt = VirtAddr::new(0x3_0000_1000);
    let phys = frame.start_address();
    let flags = PtFlags::WRITABLE | PtFlags::NO_EXEC;

    // SAFETY: live PML4 modification on the BSP with the test's
    // chosen virt not overlapping anything else.
    if unsafe { map_4kb(pml4, virt, phys, flags) }.is_err() {
        free_frame(frame);
        return TestResult::Fail("map_4kb NO_EXEC failed");
    }

    // Arm the probe, jump to the NO_EXEC page, catch the #PF.
    let recovery: u64;
    // SAFETY: LEA of a local label.
    unsafe {
        asm!(
            "lea {r}, [77f + rip]",
            r = out(reg) recovery,
            options(nostack, preserves_flags),
        );
    }
    probe::arm(recovery);

    // SAFETY: `jmp {ptr}` transfers to the tagged-NX page. The CPU
    // raises #PF on instruction fetch; our probe redirects to `77:`.
    unsafe {
        asm!(
            "jmp {p}",
            "77:",
            p = in(reg) virt.raw(),
            options(nostack),
        );
    }

    let caught = probe::disarm();
    let _ = unsafe { unmap_4kb(pml4, virt) };
    free_frame(frame);

    match caught.vector {
        None     => return TestResult::Fail("NX didn't fault on NO_EXEC jump"),
        Some(14) => {}
        Some(_)  => return TestResult::Fail("wrong vector caught (not #PF)"),
    }
    // Bit 4 of the #PF error code = instruction-fetch fault.
    if caught.error_code & (1 << 4) == 0 {
        return TestResult::Fail("fault caught but IF bit (4) not set — not NX");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_nx_enforces_no_exec);

#[cfg(target_arch = "aarch64")]
fn smoke_aarch64_features() -> TestResult {
    // SAFETY: MRS of ID_AA64* and CNTFRQ_EL0 is always legal at EL1.
    let feats = unsafe { narf_arch::aarch64::Features::probe() };
    let hz = unsafe { narf_arch::aarch64::cpuid::generic_timer_hz() };

    // generic_timer = true on ARMv8+; if our probe reports false we've
    // regressed the structural invariant.
    if !feats.generic_timer {
        return TestResult::Fail("generic_timer reported false");
    }
    // CNTFRQ must be non-zero — otherwise Instant::now would always
    // return 0 and the scheduler's sleep path would never advance.
    if hz == 0 {
        return TestResult::Fail("CNTFRQ_EL0 is zero");
    }
    // MTE level 0..=3 is the only valid range.
    if feats.mte > 3 {
        return TestResult::Fail("MTE level > 3 — bogus");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test!(smoke_aarch64_features);

fn smoke_domain_primitive_trait() -> TestResult {
    // Trait-level dispatch through `arch::Domain::*`. On x86_64 maps
    // to PKS; on aarch64 maps to MTE. Both are live; the aarch64 path
    // exercises `enter_domain` (SCTLR_EL1.TCF bit flip) + restore.
    use narf_arch::{DomainPrimitive, DomainBackend};

    // BACKEND must match the arch.
    let expected = if cfg!(target_arch = "x86_64") { DomainBackend::Pks }
                   else if cfg!(target_arch = "aarch64") { DomainBackend::Mte }
                   else { return TestResult::Skip("unknown arch") };
    if <narf_arch::Domain as DomainPrimitive>::BACKEND != expected {
        return TestResult::Fail("DomainPrimitive::BACKEND wrong");
    }

    #[cfg(target_arch = "aarch64")]
    {
        // aarch64 MTE: save + enter_domain (sync TCF) + exit_domain
        // + save-vs-saved equality. MTE get_rights/set_rights are
        // no-ops on aarch64 (rights are per-tag, not per-domain-
        // register), so we exercise the save/restore path instead.
        // SAFETY: legal MRS/MSR sequence at EL1.
        unsafe {
            let saved0 = <narf_arch::Domain as DomainPrimitive>::save();
            let inner  = <narf_arch::Domain as DomainPrimitive>::enter_domain(0, 9);
            <narf_arch::Domain as DomainPrimitive>::exit_domain(inner);
            let saved1 = <narf_arch::Domain as DomainPrimitive>::save();
            if saved0 != saved1 {
                return TestResult::Fail("MTE save round-trip not preserved");
            }
        }
    }

    // Live dispatch x86_64 path (unchanged).
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: CPUID always legal.
        let feats = unsafe { narf_arch::x86_64::Features::probe() };
        if !feats.pks {
            return TestResult::Skip("PKS not exposed on this host");
        }
        // SAFETY: CR4.PKS is enabled by frame/ at boot.
        unsafe {
            let saved = <narf_arch::Domain as DomainPrimitive>::save();
            <narf_arch::Domain as DomainPrimitive>::set_rights(
                5,
                <narf_arch::Domain as DomainPrimitive>::READ_ONLY,
            );
            let r = <narf_arch::Domain as DomainPrimitive>::get_rights(5);
            <narf_arch::Domain as DomainPrimitive>::restore(saved);

            if r != <narf_arch::Domain as DomainPrimitive>::READ_ONLY {
                return TestResult::Fail("trait-level get_rights didn't match set_rights");
            }
        }
    }
    TestResult::Pass
}
kernel_test!(smoke_domain_primitive_trait);

#[cfg(target_arch = "x86_64")]
fn smoke_domain_switch() -> TestResult {
    // End-to-end domain transition:
    //  1. Map a page with PK = DRIVER_0 (9).
    //  2. enter_domain(FRAME=0, DRIVER_0=9): PKRS allows 0 + 9, denies
    //     the other 14. Write to the page — succeeds.
    //  3. enter_domain(FRAME=0, DRIVER_1=10): now domain 9 is denied.
    //     Write to the page — faults with PK bit set.
    //  4. exit_domain restores original PKRS.
    //
    // This proves `enter_domain` + per-page PK tag actually scopes
    // access the way driver-framework Stage-3 code will rely on.
    use core::arch::asm;
    use narf_arch::x86_64::{probe, pks::{self, SavedPkrs}, Features};
    use narf_lib::id::DomainId;
    use narf_memory::{alloc_frame, FrameAllocError, free_frame, VirtAddr};
    use narf_memory::paging::{map_4kb, unmap_4kb, read_cr3, PtFlags};

    // SAFETY: CPUID always legal.
    let feats = unsafe { Features::probe() };
    if !feats.pks { return TestResult::Skip("PKS not exposed"); }

    let pml4 = unsafe { read_cr3() };
    let frame = match alloc_frame() {
        Ok(f) => f,
        Err(FrameAllocError::Uninitialised) =>
            return TestResult::Skip("frame allocator not initialised"),
        Err(_) => return TestResult::Fail("alloc_frame failed"),
    };
    let virt = VirtAddr::new(0x4_0000_1000);
    let phys = frame.start_address();
    let driver_pk = DomainId::DRIVER_0.raw(); // 9

    // SAFETY: live PML4; this virt is in an unused PDPT slot.
    if unsafe {
        map_4kb(pml4, virt, phys,
                PtFlags::WRITABLE | PtFlags::pk(driver_pk))
    }.is_err() {
        free_frame(frame);
        return TestResult::Fail("map_4kb with PK=DRIVER_0 failed");
    }

    // SAFETY: initial PKRS save so we can restore at the end.
    let outermost_saved: SavedPkrs = unsafe { pks::save() };

    // ---- Step 2: inside DRIVER_0 domain, write should succeed.
    // SAFETY: enter_domain is live with CR4.PKS=1.
    let scope1 = unsafe { pks::enter_domain(DomainId::FRAME.raw(), driver_pk) };
    // SAFETY: write to a page PKRS currently allows.
    unsafe {
        asm!("mov byte ptr [{p}], 1", p = in(reg) virt.raw(),
             options(nostack));
    }
    // SAFETY: restore after the write.
    unsafe { pks::exit_domain(scope1); }

    // ---- Step 3: now enter DRIVER_1 — domain 9 denied. Write #PFs.
    let scope2 = unsafe { pks::enter_domain(DomainId::FRAME.raw(),
                                             DomainId::DRIVER_1.raw()) };
    let recovery: u64;
    // SAFETY: LEA of local label.
    unsafe {
        asm!(
            "lea {r}, [66f + rip]",
            r = out(reg) recovery,
            options(nostack, preserves_flags),
        );
    }
    probe::arm(recovery);
    // SAFETY: expected-to-fault write.
    unsafe {
        asm!(
            "mov byte ptr [{p}], 2",
            "66:",
            p = in(reg) virt.raw(),
            options(nostack),
        );
    }
    let caught = probe::disarm();
    // SAFETY: restore PKRS for rest of the test.
    unsafe { pks::exit_domain(scope2); }

    // Restore outermost PKRS before exiting.
    // SAFETY: restore of the previously-saved state.
    unsafe { pks::restore(outermost_saved); }
    let _ = unsafe { unmap_4kb(pml4, virt) };
    free_frame(frame);

    match caught.vector {
        None => return TestResult::Fail("Step 3 write succeeded — domain enforcement failed"),
        Some(14) => {}
        Some(_)  => return TestResult::Fail("wrong vector (not #PF)"),
    }
    if caught.error_code & (1 << 5) == 0 {
        return TestResult::Fail("#PF caught but PK bit (5) not set — not domain fault");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_domain_switch);

#[cfg(target_arch = "x86_64")]
fn smoke_pks_enforces_deny_all() -> TestResult {
    // End-to-end PKS enforcement demo:
    //  1. Allocate a fresh 4 KiB frame.
    //  2. Map it at virt 0x2_0000_1000 (8 GiB + 4 KiB) with PK=9, in
    //     the *live* PML4 (the one CR3 currently points at).
    //  3. Set IA32_PKRS domain 9 to DENY_ALL.
    //  4. Arm the probe and attempt a write at the tagged virt.
    //  5. Verify the handler caught #PF (vector 14) with the PK bit
    //     (error-code bit 5) set.
    //  6. Restore PKRS, unmap the page, free the frame.
    use core::arch::asm;
    use narf_arch::x86_64::{probe, pks::{self, DomainRights}, Features};
    use narf_memory::{alloc_frame, FrameAllocError, free_frame, VirtAddr};
    use narf_memory::paging::{map_4kb, unmap_4kb, read_cr3, PtFlags};

    // SAFETY: CPUID always legal.
    let feats = unsafe { Features::probe() };
    if !feats.pks {
        return TestResult::Skip("PKS not exposed");
    }

    // SAFETY: allocator is up, read_cr3 is always safe.
    let pml4 = unsafe { read_cr3() };
    let frame = match alloc_frame() {
        Ok(f) => f,
        Err(FrameAllocError::Uninitialised) =>
            return TestResult::Skip("frame allocator not initialised"),
        Err(_) => return TestResult::Fail("alloc_frame failed"),
    };
    let virt = VirtAddr::new(0x2_0000_1000);
    let phys = frame.start_address();
    let flags = PtFlags::WRITABLE | PtFlags::pk(9);

    // SAFETY: live PML4 modification. We're the only CPU, interrupts
    // aren't in a weird state (kernel tests run synchronously on the
    // BSP), and virt is in unmapped territory (PDPT[8] is empty).
    if unsafe { map_4kb(pml4, virt, phys, flags) }.is_err() {
        free_frame(frame);
        return TestResult::Fail("map_4kb of test page failed");
    }

    // SAFETY: CR4.PKS is 1 (frame/ set it during boot based on CPUID).
    let saved_pkrs = unsafe { pks::save() };
    unsafe { pks::set_rights(9, DomainRights::DENY_ALL); }

    // Probe: a store to `virt` should #PF with PK bit in error code.
    let recovery: u64;
    // SAFETY: LEA of a local label.
    unsafe {
        asm!(
            "lea {r}, [88f + rip]",
            r = out(reg) recovery,
            options(nostack, preserves_flags),
        );
    }
    probe::arm(recovery);

    // SAFETY: store that's expected to fault. The probe catches it.
    unsafe {
        asm!(
            "mov byte ptr [{p}], 1",
            "88:",
            p = in(reg) virt.raw(),
            options(nostack),
        );
    }

    let caught = probe::disarm();

    // Restore PKRS before anything else so subsequent tests aren't
    // affected.
    // SAFETY: see pks::save.
    unsafe { pks::restore(saved_pkrs); }

    // Unmap the test page and release the frame.
    let _ = unsafe { unmap_4kb(pml4, virt) };
    free_frame(frame);

    match caught.vector {
        None => return TestResult::Fail("PKS didn't fault on DENY_ALL-tagged write"),
        Some(14) => {}
        Some(_) => return TestResult::Fail("wrong vector caught (not #PF)"),
    }
    // x86_64 #PF error-code bit 5 = protection-key violation.
    if caught.error_code & (1 << 5) == 0 {
        return TestResult::Fail("fault caught, but PK bit (5) not set — regular #PF, not PKS");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_pks_enforces_deny_all);

#[cfg(target_arch = "x86_64")]
fn smoke_pks_set_get_rights() -> TestResult {
    // SAFETY: CPUID always legal.
    let feats = unsafe { narf_arch::x86_64::Features::probe() };
    if !feats.pks {
        return TestResult::Skip("PKS not exposed by this CPU");
    }
    use narf_arch::x86_64::pks::{save, restore, get_rights, set_rights, DomainRights};
    // SAFETY: feats.pks==true.
    let saved = unsafe { save() };
    // Set domain 3 to read-only, domain 7 to deny-all; leave others.
    unsafe {
        set_rights(3, DomainRights::READ_ONLY);
        set_rights(7, DomainRights::DENY_ALL);
    }
    let r3 = unsafe { get_rights(3) };
    let r7 = unsafe { get_rights(7) };
    // Restore *before* returning so subsequent tests / code aren't
    // affected by our mutation.
    unsafe { restore(saved); }
    if r3 != DomainRights::READ_ONLY {
        return TestResult::Fail("set_rights(3, READ_ONLY) didn't round-trip");
    }
    if r7 != DomainRights::DENY_ALL {
        return TestResult::Fail("set_rights(7, DENY_ALL) didn't round-trip");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_pks_set_get_rights);

#[cfg(target_arch = "x86_64")]
fn smoke_pte_pk_field() -> TestResult {
    use narf_memory::paging::PtFlags;
    // Build a flag value with PK=7; check the round-trip + isolation
    // from other flag bits.
    let f = PtFlags::WRITABLE | PtFlags::pk(7);
    if f.pk_of() != 7 {
        return TestResult::Fail("pk_of didn't recover the PK field");
    }
    if !f.contains(PtFlags::WRITABLE) {
        return TestResult::Fail("pk bits stomped on unrelated flag bit");
    }
    // PK=0 is the default / "unrestricted" case.
    let g = PtFlags::PRESENT | PtFlags::pk(0);
    if g.pk_of() != 0 {
        return TestResult::Fail("pk(0) encoding wrong");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_pte_pk_field);

#[cfg(target_arch = "x86_64")]
fn smoke_pkrs_roundtrip() -> TestResult {
    // PKS availability is a hardware property; only run the roundtrip
    // if CR4.PKS was enabled during boot. Otherwise IA32_PKRS would
    // #GP and we'd re-enter the trap handler.
    // SAFETY: CPUID is always legal.
    let feats = unsafe { narf_arch::x86_64::Features::probe() };
    if !feats.pks {
        return TestResult::Skip("PKS not exposed by this CPU");
    }
    use narf_arch::x86_64::msr::{rdmsr, wrmsr, IA32_PKRS};
    // SAFETY: feats.pks==true means CR4.PKS is set (frame/ enabled it
    // at boot), so PKRS is accessible.
    let saved = unsafe { rdmsr(IA32_PKRS) };
    // Write 0xFFFF_FFFF — "all domains disallowed" — then read back.
    // Every 2-bit field set to 11 (AD|WD). u64 is fine even though
    // only the low 32 bits are defined; upper bits are reserved-zero.
    let test_value = 0xFFFF_FFFF_u64;
    unsafe { wrmsr(IA32_PKRS, test_value); }
    let got = unsafe { rdmsr(IA32_PKRS) };
    // Restore to avoid surprising subsequent code.
    unsafe { wrmsr(IA32_PKRS, saved); }
    if got == test_value {
        TestResult::Pass
    } else {
        TestResult::Fail("PKRS roundtrip mismatch")
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_pkrs_roundtrip);

#[cfg(target_arch = "x86_64")]
fn smoke_map_preserves_pk_field() -> TestResult {
    // Verify map_4kb preserves the PK field at the PTE level: tag a
    // virtual page with PK=5, then read back the PTE flags and check
    // that pk_of returns 5.
    use narf_memory::paging::{flags_at, map_4kb, unmap_4kb, PageTable, PtFlags};
    use narf_memory::{alloc_frame, FrameAllocError, PhysAddr, VirtAddr};

    let pml4 = match alloc_frame() {
        Ok(f) => f.start_address(),
        Err(FrameAllocError::Uninitialised) =>
            return TestResult::Skip("frame allocator not initialised"),
        Err(_) => return TestResult::Fail("alloc_frame failed"),
    };
    PageTable::zero_at(pml4.as_mut_ptr::<PageTable>());

    let virt = VirtAddr::new(0x9abc_0000);
    let phys = PhysAddr::new(0x8765_0000);
    let requested = PtFlags::WRITABLE | PtFlags::pk(5);
    // SAFETY: isolated PML4, identity-reachable via the low-4-GiB map.
    if unsafe { map_4kb(pml4, virt, phys, requested) }.is_err() {
        return TestResult::Fail("map_4kb with PK=5 failed");
    }
    let got = match unsafe { flags_at(pml4, virt) } {
        Some(f) => f,
        None    => return TestResult::Fail("flags_at returned None"),
    };
    if got.pk_of() != 5 {
        return TestResult::Fail("PK field lost through map_4kb");
    }
    if !got.contains(PtFlags::WRITABLE) {
        return TestResult::Fail("WRITABLE lost");
    }
    if !got.contains(PtFlags::PRESENT) {
        return TestResult::Fail("PRESENT missing");
    }
    let _ = unsafe { unmap_4kb(pml4, virt) };
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_map_preserves_pk_field);

#[cfg(target_arch = "x86_64")]
fn smoke_paging_map_translate_unmap() -> TestResult {
    use narf_memory::paging::{map_4kb, unmap_4kb, translate, PageTable, PtFlags};
    use narf_memory::{alloc_frame, FrameAllocError, PhysAddr, VirtAddr};

    // Fresh PML4 just for this test — doesn't touch the live address space.
    let pml4 = match alloc_frame() {
        Ok(f) => f.start_address(),
        Err(FrameAllocError::Uninitialised) =>
            return TestResult::Skip("frame allocator not initialised"),
        Err(_) => return TestResult::Fail("alloc_frame failed"),
    };
    PageTable::zero_at(pml4.as_mut_ptr::<PageTable>());

    // Map virtual 0x5678_0000 → physical 0x1234_0000 with RW.
    let virt = VirtAddr::new(0x5678_0000);
    let phys = PhysAddr::new(0x1234_0000);
    // SAFETY: PML4 owned by this test, no other CPU touches it, low-4-GiB
    // identity map guarantees table-level reachability.
    if let Err(e) = unsafe { map_4kb(pml4, virt, phys, PtFlags::WRITABLE) } {
        let _ = e;
        return TestResult::Fail("map_4kb failed");
    }

    // Translate back.
    let got = unsafe { translate(pml4, virt) };
    if got != Some(phys) {
        return TestResult::Fail("translate returned wrong physical address");
    }

    // Unmap.
    let removed = match unsafe { unmap_4kb(pml4, virt) } {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("unmap_4kb failed"),
    };
    if removed != phys {
        return TestResult::Fail("unmap returned wrong phys");
    }

    // Translate must now return None.
    if unsafe { translate(pml4, virt) }.is_some() {
        return TestResult::Fail("translate still resolves after unmap");
    }

    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_paging_map_translate_unmap);

fn smoke_frame_alloc_roundtrip() -> TestResult {
    // Allocator has to be initialised by the bin crate's _start_rust,
    // so we just assert alloc-then-free works and returns a valid frame.
    let f = match narf_memory::alloc_frame() {
        Ok(f) => f,
        Err(narf_memory::FrameAllocError::Uninitialised) => {
            return TestResult::Skip("frame allocator not initialised in this flavour");
        }
        Err(_) => return TestResult::Fail("alloc_frame unexpectedly failed"),
    };
    if f.start_address().raw() & (narf_memory::PAGE_SIZE - 1) != 0 {
        return TestResult::Fail("frame not page-aligned");
    }
    narf_memory::free_frame(f);
    TestResult::Pass
}
kernel_test!(smoke_frame_alloc_roundtrip);

fn smoke_sleep_future_waits() -> TestResult {
    use core::sync::atomic::{AtomicBool, Ordering};
    static DONE: AtomicBool = AtomicBool::new(false);
    narf_scheduler::init();
    let start = narf_time::Instant::now();
    narf_scheduler::spawn(async {
        narf_time::sleep_cycles(10_000_000).await;
        DONE.store(true, Ordering::Relaxed);
    });
    narf_scheduler::run_until_empty();
    let elapsed = narf_time::Instant::now().cycles_since(start);
    if !DONE.load(Ordering::Relaxed) {
        return TestResult::Fail("sleep future never completed");
    }
    if elapsed < 10_000_000 {
        return TestResult::Fail("completed before deadline — sleep isn't blocking");
    }
    TestResult::Pass
}
kernel_test!(smoke_sleep_future_waits);
