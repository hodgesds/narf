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
    if caught == 0 {
        return TestResult::Fail("probe didn't catch the expected #PF");
    }
    if caught - 1 != 14 {
        return TestResult::Fail("wrong vector caught (not #PF)");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_probe_catches_page_fault);

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
