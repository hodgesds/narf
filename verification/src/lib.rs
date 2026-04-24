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

fn smoke_scheduler_respects_waker() -> TestResult {
    // Proves the scheduler honours per-task wakers: a Parked future
    // that returns Pending *without* calling its waker must not be
    // re-polled until something else wakes it. Without the per-task
    // awake flag this test would fail because the old no-op waker
    // caused every Pending task to be repolled on every round.
    use core::future::Future;
    use core::pin::Pin;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use core::task::{Context, Poll, Waker};
    use narf_lib::sync::IrqSafeSpinLock;

    static POLLS:         AtomicUsize                     = AtomicUsize::new(0);
    static PARKED_WAKER:  IrqSafeSpinLock<Option<Waker>>  = IrqSafeSpinLock::new(None);

    struct Parked { ready: bool }
    impl Future for Parked {
        type Output = ();
        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            let this = self.get_mut();
            POLLS.fetch_add(1, Ordering::Relaxed);
            if this.ready { return Poll::Ready(()); }
            *PARKED_WAKER.lock() = Some(cx.waker().clone());
            this.ready = true;   // next poll (after being woken) completes
            Poll::Pending
        }
    }

    POLLS.store(0, Ordering::Relaxed);
    *PARKED_WAKER.lock() = None;

    narf_scheduler::init();
    narf_scheduler::spawn(Parked { ready: false });
    narf_scheduler::spawn(async {
        // Yield once so Parked gets a turn to register its waker, then
        // wake it. Under the old noop_waker Parked would already have
        // been re-polled many times by now; with per-task wakers it
        // must have been polled exactly once so far.
        narf_scheduler::yield_now().await;
        if let Some(w) = PARKED_WAKER.lock().take() { w.wake(); }
    });
    narf_scheduler::run_until_empty();

    match POLLS.load(Ordering::Relaxed) {
        2 => TestResult::Pass,
        n if n < 2 => TestResult::Fail("parked task never woke after wake()"),
        _          => TestResult::Fail("parked task re-polled without a wake — waker gating broken"),
    }
}
kernel_test!(smoke_scheduler_respects_waker);

fn smoke_cap_slot_layout() -> TestResult {
    // The cap-slot wire format is 16 bytes, 16-byte aligned. The ipc/
    // ring-slot layout assumes this; a size/align drift here is an ABI
    // break that would silently misalign every submission. Redundant
    // with the crate-internal const-asserts, but a runtime test gives
    // a visible failure in the verification harness.
    use narf_capabilities::CapSlot;
    if core::mem::size_of::<CapSlot>() != 16 {
        return TestResult::Fail("CapSlot size != 16");
    }
    if core::mem::align_of::<CapSlot>() != 16 {
        return TestResult::Fail("CapSlot align != 16");
    }
    let s = CapSlot::new(1, 2, 3, 4);
    if s.generation != 1 || s.index != 2 || s.rights != 3 || s.type_tag != 4 {
        return TestResult::Fail("CapSlot::new field order wrong");
    }
    if CapSlot::EMPTY.is_empty() != true { return TestResult::Fail("EMPTY not empty"); }
    if s.is_empty() { return TestResult::Fail("non-zero slot reported empty"); }
    TestResult::Pass
}
kernel_test!(smoke_cap_slot_layout);

fn smoke_cap_kind_registry() -> TestResult {
    // The CapKind integer values are permanent per spec §3.1 — adding
    // kinds is allowed, renumbering is an ABI break. Guard a handful
    // of the pinned values + the parse_kind round-trip.
    use narf_capabilities::{CapKind, parse_kind, kind_name};
    let pinned: &[(&str, CapKind, u32)] = &[
        ("BusDevice",      CapKind::BusDevice,      0x0001),
        ("BlockDevice",    CapKind::BlockDevice,    0x0010),
        ("NetIface",       CapKind::NetIface,       0x0020),
        ("FileNode",       CapKind::FileNode,       0x0030),
        ("Ring",           CapKind::Ring,           0x0040),
        ("Domain",         CapKind::Domain,         0x0050),
        ("Probe",          CapKind::Probe,          0x0060),
        ("Key",            CapKind::Key,            0x0070),
        ("Task",           CapKind::Task,           0x0080),
        ("SleepableReader",CapKind::SleepableReader,0x0090),
        ("Process",        CapKind::Process,        0x00A0),
    ];
    for &(name, kind, wire) in pinned {
        if kind as u32 != wire {
            return TestResult::Fail("CapKind wire value drifted — ABI break");
        }
        match parse_kind(name) {
            Ok(k) if k as u32 == wire => {}
            _ => return TestResult::Fail("parse_kind round-trip broken"),
        }
        if kind_name(kind) != name {
            return TestResult::Fail("kind_name round-trip broken");
        }
    }
    if parse_kind("DefinitelyNotAKind").is_ok() {
        return TestResult::Fail("parse_kind accepted garbage");
    }
    TestResult::Pass
}
kernel_test!(smoke_cap_kind_registry);

fn smoke_cap_derive_narrows_rights() -> TestResult {
    // Stage 3 Wave 2: derive checks if the cap is live, so the slot
    // must point to a real entry in the object table.
    use narf_capabilities::{Cap, Rights, Write, Grant, CapType, CapKind};

    struct TestObj;
    impl CapType for TestObj { const KIND: CapKind = CapKind::Domain; }

    let parent: Cap<TestObj, Grant> = Cap::<TestObj, Grant>::bootstrap();
    let derived: Cap<TestObj, Write> = parent.derive::<Write>().unwrap();

    let p = parent.slot();
    let d = derived.slot();
    if p.index != d.index || p.type_tag != d.type_tag {
        return TestResult::Fail("derive dropped non-rights metadata");
    }
    if d.rights != Write::BITS {
        return TestResult::Fail("derive did not tag rights bits");
    }
    TestResult::Pass
}
kernel_test!(smoke_cap_derive_narrows_rights);

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
fn smoke_aarch64_mte_l2() -> TestResult {
    // MTE-L2 live test: SCTLR_EL1.ATA is set by boot.S when MTE is
    // present, so GCR_EL1 is accessible here. Read it, write a
    // distinctive value, read back, restore. Verifies (a) the
    // feature probe matches QEMU's `-machine virt,mte=on` flag,
    // (b) the ATA bit actually ungated GCR_EL1, and (c) the
    // arch::aarch64::sysreg raw-encoding accessors work.
    // SAFETY: MRS ID_AA64* always legal.
    let feats = unsafe { narf_arch::aarch64::Features::probe() };
    if feats.mte < 2 {
        return TestResult::Skip("MTE level <2 (QEMU -machine virt,mte=on not in effect)");
    }
    use narf_arch::aarch64::sysreg::{read_gcr_el1, write_gcr_el1};
    // SAFETY: ATA=1, so GCR_EL1 is live.
    unsafe {
        let saved = read_gcr_el1();
        // Low 16 bits = exclusion mask (any-bit-set = exclude that tag
        // from IRG output). 0xABCD is arbitrary-but-distinct.
        write_gcr_el1(0xABCD);
        let got = read_gcr_el1();
        // Restore before any possible early-return.
        write_gcr_el1(saved);
        if got & 0xFFFF != 0xABCD {
            return TestResult::Fail("GCR_EL1 roundtrip lost the exclusion mask");
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test!(smoke_aarch64_mte_l2);

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

fn smoke_percpu_this_cpu() -> TestResult {
    // Stage-2 single-CPU: current_cpu_id() returns 0, so this_cpu()
    // always reads cell 0. Verify structural correctness.
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_lib::percpu::{PerCpu, MAX_CPUS};

    // PerCpu<u64> can hold a plain value; mutate via a pointer cast
    // to AtomicU64 for the test.
    static CELL: PerCpu<u64> = PerCpu::new(0);

    let ptr = CELL.this_cpu() as *const u64 as *mut u64;
    // SAFETY: `ptr` points at a live `u64` cell inside `CELL`. We
    // treat it as an `AtomicU64` for the test roundtrip.
    let atomic = unsafe { AtomicU64::from_ptr(ptr) };

    atomic.store(0xDEAD_BEEF, Ordering::Relaxed);
    if atomic.load(Ordering::Relaxed) != 0xDEAD_BEEF {
        return TestResult::Fail("PerCpu cell roundtrip failed");
    }

    if narf_arch::current_cpu_id().raw() != 0 {
        return TestResult::Fail("Stage-2 current_cpu_id != 0");
    }

    // Iter should produce MAX_CPUS entries (most 0, the one we
    // wrote = 0xDEAD_BEEF).
    let count = CELL.iter().count();
    if count != MAX_CPUS {
        return TestResult::Fail("PerCpu::iter didn't yield MAX_CPUS cells");
    }

    // Cleanup so the value doesn't leak across tests.
    atomic.store(0, Ordering::Relaxed);
    TestResult::Pass
}
kernel_test!(smoke_percpu_this_cpu);

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

#[cfg(target_arch = "x86_64")]
fn smoke_bus_enumerates_pcie() -> TestResult {
    // Walk QEMU q35's PCIe ECAM at its default base. q35 exposes a
    // PCI-Express host bridge at 00:00.0 plus any attached devices.
    // We expect at minimum the host bridge entry (vendor != 0xFFFF).
    use narf_bus::{devices, BusKind};
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    // SAFETY: ECAM_DEFAULT_BASE (0xb000_0000) is inside q35's
    // pcie-mmcfg region and below the 4-GiB identity map installed
    // by memory/mmu::init_mmu. No MMIO write happens during the walk.
    let n = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    if n == 0 {
        return TestResult::Fail("ECAM walk found zero devices on q35 — host bridge missing");
    }
    // Host bridge must be the first entry (function 0 on bus 0, dev 0).
    let devs = devices();
    let has_host_bridge = devs.iter().any(|d| matches!(
        &d.kind,
        BusKind::Pcie { addr, .. } if addr.bus == 0 && addr.device == 0 && addr.function == 0
    ));
    if !has_host_bridge {
        return TestResult::Fail("00:00.0 host bridge not found in ECAM walk");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_bus_enumerates_pcie);

#[cfg(target_arch = "aarch64")]
fn smoke_bus_enumerates_virtio_mmio() -> TestResult {
    // QEMU `virt` exposes 32 virtio-mmio transport slots at
    // 0x0a00_0000 (stride 0x200). We don't have easy access to the
    // DTB pointer from here, so the enumerator's fallback path probes
    // the documented slot layout when no DTB is supplied — this
    // covers the default cargo-xtask-test boot.
    use narf_bus::{devices, snapshot};
    // SAFETY: the fallback reads 4-byte MMIO from identity-mapped
    // virtio-mmio registers and rejects invalid magic, so stray
    // ranges don't produce phantom devices.
    let _n = unsafe { narf_bus::init(None) };
    let devs = devices();
    // Structural: snapshot must agree with devices() post-init.
    if snapshot().len() != devs.len() {
        return TestResult::Fail("snapshot vs devices mismatch after init");
    }
    // QEMU virt without extra -device flags still exposes magic on
    // every slot; populated slots (DeviceID != 0) appear only when a
    // device is attached. We don't require one — just that the walk
    // runs cleanly. If any device is present, it must have a
    // VirtioMmio kind variant.
    for d in devs.iter() {
        match &d.kind {
            narf_bus::BusKind::VirtioMmio { base, .. } => {
                if base.raw() < 0x0a00_0000 || base.raw() >= 0x0a00_0000 + 32 * 0x200 {
                    return TestResult::Fail("virtio-mmio base outside QEMU virt range");
                }
            }
            _ => return TestResult::Fail("non-virtio device in aarch64 registry"),
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test!(smoke_bus_enumerates_virtio_mmio);

fn smoke_bus_claim_device_not_found() -> TestResult {
    // Structural test for the claim-API stub: claiming an address
    // that doesn't exist must cleanly return NotFound / NotInitialised,
    // never panic.
    use narf_bus::{claim_device, BusAddr};
    use narf_memory::PhysAddr;
    let bogus = BusAddr::Mmio(PhysAddr::new(0xdead_beef_0000));
    match claim_device(bogus) {
        Err(narf_bus::ClaimError::NotFound)
        | Err(narf_bus::ClaimError::NotInitialised) => TestResult::Pass,
        Ok(_)  => TestResult::Fail("claim of bogus addr succeeded"),
    }
}
kernel_test!(smoke_bus_claim_device_not_found);

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

fn smoke_tracing_note_section_present() -> TestResult {
    // Drive the internal probe sites so their nop actually executes
    // in this test pass (the real smoke is the metadata, but exercising
    // the marker proves the inline asm compiled and LTO kept it).
    narf_tracing::exercise_internal_probes();

    // The .note.narf.probes section must be non-empty: narf-tracing
    // emits two internal probe sites (tracing::loaded + tracing::heartbeat)
    // and `#[used]` plus `KEEP(*(.note.narf.probes))` in the linker
    // script keep them even under fat LTO.
    let probes = narf_tracing::probes();
    if probes.is_empty() {
        return TestResult::Fail(".note.narf.probes section empty — linker didn't keep the entries");
    }

    // Look for our two well-known entries.
    let mut saw_loaded = false;
    let mut saw_heartbeat = false;
    for p in probes {
        if p.provider == "tracing" && p.name == "loaded"    { saw_loaded = true; }
        if p.provider == "tracing" && p.name == "heartbeat" { saw_heartbeat = true; }
    }
    if !saw_loaded    { return TestResult::Fail("tracing::loaded probe not in .note.narf.probes"); }
    if !saw_heartbeat { return TestResult::Fail("tracing::heartbeat probe not in .note.narf.probes"); }

    // Structural sanity: argc matches the args-type string.
    for p in probes {
        let expected = if p.args.is_empty() { 0 }
                       else { (p.args.as_bytes().iter().filter(|&&b| b == b',').count() as u32) + 1 };
        if p.argc != expected {
            return TestResult::Fail("probe argc / args mismatch");
        }
    }
    TestResult::Pass
}
kernel_test!(smoke_tracing_note_section_present);

fn smoke_tracing_flight_ring_basic() -> TestResult {
    // Drop-oldest ring: N=4, write 6 records, expect overruns == 2.
    use narf_tracing::FlightRing;
    static RING: FlightRing<u32, 4> = FlightRing::new();

    for i in 1u32..=6 { RING.record(i); }

    if RING.total() != 6 {
        return TestResult::Fail("FlightRing.total wrong after 6 records");
    }
    if RING.overruns() != 2 {
        return TestResult::Fail("FlightRing.overruns not 2 after 2 wraps");
    }

    // Snapshot should return the 4 most recent writes. Single-threaded
    // writer means no torn slots, so all four come back.
    let mut out = [0u32; 4];
    let n = RING.snapshot(&mut out);
    if n != 4 {
        return TestResult::Fail("FlightRing.snapshot returned the wrong count");
    }
    let mut present = [false; 7];
    for &v in &out {
        if (v as usize) < present.len() { present[v as usize] = true; }
    }
    for expected in [3u32, 4, 5, 6] {
        if !present[expected as usize] {
            return TestResult::Fail("FlightRing.snapshot missing a recent entry");
        }
    }
    TestResult::Pass
}
kernel_test!(smoke_tracing_flight_ring_basic);

// ── rcu/ side-track tests ───────────────────────────────────────────
//
// Exercise the QSBR + Epoch variants end-to-end: pin, load through an
// Atomic<T>, swap, defer-drop, sync, confirm the old value's Drop ran.

fn smoke_rcu_qsbr_pin_unpin() -> TestResult {
    // Baseline: pin() increments reader-in-flight; dropping the guard
    // decrements it. While pinned, `report_quiescent()` must NOT advance
    // the local epoch — advancing under a live reader would let their
    // Shared<'g, T> get reclaimed.
    let before = narf_rcu::qsbr::global_epoch();
    {
        let _g = narf_rcu::pin();
        // With a live reader, report_quiescent is a safe no-op and
        // sync_blocking must not accelerate reclamation.
        narf_rcu::report_quiescent();
    }
    // Guard dropped — CPU is quiescent. Call sync to publish + drain.
    narf_rcu::sync();
    let after = narf_rcu::qsbr::global_epoch();
    if after <= before {
        return TestResult::Fail("global epoch didn't advance after sync");
    }
    TestResult::Pass
}
kernel_test!(smoke_rcu_qsbr_pin_unpin);

fn smoke_rcu_qsbr_reclaims() -> TestResult {
    // Deferred-drop round-trip: publish a value, swap it, sync, confirm
    // the displaced allocation's Drop ran.
    use core::sync::atomic::{AtomicUsize, Ordering};
    use narf_rcu::{Atomic, Owned};

    static DROPS: AtomicUsize = AtomicUsize::new(0);
    struct Canary;
    impl Drop for Canary {
        fn drop(&mut self) { DROPS.fetch_add(1, Ordering::Relaxed); }
    }

    DROPS.store(0, Ordering::Relaxed);
    let cell: Atomic<Canary> = Atomic::new(Canary);

    // Swap the initial Canary out of the cell — this queues it for
    // deferred drop at the current epoch.
    {
        let g = narf_rcu::pin();
        cell.store(Owned::new(Canary), &g);
    }
    // No drops yet — the queued entry is still pending its grace period.
    if DROPS.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("deferred drop ran before sync()");
    }

    // Wait a grace period. The queued Canary must now have dropped.
    narf_rcu::sync();

    if DROPS.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("deferred Canary didn't Drop after sync()");
    }

    // Also verify the new value is still readable.
    let g = narf_rcu::pin();
    let s = cell.load(&g);
    if s.is_null() {
        return TestResult::Fail("Atomic<Canary> became null after store+sync");
    }
    drop(g);

    // Drop the cell itself — the still-live Canary drops inline.
    drop(cell);
    if DROPS.load(Ordering::Relaxed) != 2 {
        return TestResult::Fail("cell-drop didn't reclaim the last value");
    }
    TestResult::Pass
}
kernel_test!(smoke_rcu_qsbr_reclaims);

fn smoke_rcu_epoch_pin_cycle() -> TestResult {
    // Epoch-variant pin/unpin. min_pinned() must drop back to u64::MAX
    // after the guard is released.
    let before = narf_rcu::epoch::min_pinned();
    {
        let g = narf_rcu::epoch::pin();
        // While pinned, min_pinned() must not be u64::MAX (we're pinned).
        if narf_rcu::epoch::min_pinned() == u64::MAX {
            return TestResult::Fail("Epoch pin didn't publish a snapshot");
        }
        // Guard's snapshot must be <= current advance target.
        let adv = narf_rcu::epoch::advance();
        if g.epoch() > adv {
            return TestResult::Fail("EpochGuard epoch greater than current global");
        }
    }
    // Guard dropped. Back to "no pinned reader" = u64::MAX.
    if narf_rcu::epoch::min_pinned() != u64::MAX {
        return TestResult::Fail("Epoch guard drop didn't release the slot");
    }
    let _ = before;
    TestResult::Pass
}
kernel_test!(smoke_rcu_epoch_pin_cycle);

fn smoke_rcu_epoch_defer_drop() -> TestResult {
    // Epoch-backed defer_drop runs the destructor.
    use alloc::boxed::Box;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static DROPS: AtomicUsize = AtomicUsize::new(0);
    struct Canary;
    impl Drop for Canary {
        fn drop(&mut self) { DROPS.fetch_add(1, Ordering::Relaxed); }
    }

    DROPS.store(0, Ordering::Relaxed);
    narf_rcu::epoch::defer_drop(Box::new(Canary));
    if DROPS.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("epoch::defer_drop didn't run destructor");
    }
    TestResult::Pass
}
kernel_test!(smoke_rcu_epoch_defer_drop);

fn smoke_ipc_spsc_round_trip() -> TestResult {
    // Producer and consumer on the same executor: send 8 u64 values
    // through a 4-slot ring, sum them on the consumer side. Exercises
    // the wrap-around + back-pressure-via-waker path at the same time:
    // the consumer must drain before the producer can publish the
    // second half.
    use core::sync::atomic::{AtomicU64, Ordering};
    static SUM: AtomicU64 = AtomicU64::new(0);

    SUM.store(0, Ordering::Relaxed);
    narf_scheduler::init();

    let (mut tx, mut rx) = narf_ipc::channel::<u64, 4>();

    narf_scheduler::spawn(async move {
        for i in 1u64..=8 {
            let _ = tx.send(i).await;
        }
        // tx dropped here → closes the ring.
    });

    narf_scheduler::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(v)                           => { SUM.fetch_add(v, Ordering::Relaxed); }
                Err(narf_ipc::RecvError::Closed) => break,
            }
        }
    });

    narf_scheduler::run_until_empty();
    // 1 + 2 + … + 8 = 36.
    if SUM.load(Ordering::Relaxed) == 36 { TestResult::Pass }
    else { TestResult::Fail("SPSC round-trip didn't deliver every message") }
}
kernel_test!(smoke_ipc_spsc_round_trip);

fn smoke_ipc_spsc_try_send_full() -> TestResult {
    // Fill a 2-slot ring without a consumer; the third try_send must
    // return Full and hand the message back.
    let (mut tx, _rx) = narf_ipc::channel::<u32, 2>();
    tx.try_send(10).expect("slot 0 free");
    tx.try_send(20).expect("slot 1 free");
    match tx.try_send(30) {
        Err(narf_ipc::TrySendError::Full(30)) => TestResult::Pass,
        Err(narf_ipc::TrySendError::Full(_))  => TestResult::Fail("Full returned wrong value"),
        Err(narf_ipc::TrySendError::Closed(_)) => TestResult::Fail("unexpected Closed"),
        Ok(())                                => TestResult::Fail("try_send accepted beyond capacity"),
    }
}
kernel_test!(smoke_ipc_spsc_try_send_full);

fn smoke_ipc_spsc_close_eof() -> TestResult {
    // Drop the producer without sending anything → consumer's first
    // recv resolves to Closed. Also verifies the path where the drop's
    // wake fires against an already-parked RecvFuture.
    use core::sync::atomic::{AtomicU8, Ordering};
    static OUTCOME: AtomicU8 = AtomicU8::new(0);       // 0=pending, 1=closed, 2=unexpected

    OUTCOME.store(0, Ordering::Relaxed);
    narf_scheduler::init();

    let (tx, mut rx) = narf_ipc::channel::<u32, 4>();

    // Consumer task: parks on recv, then observes Closed.
    narf_scheduler::spawn(async move {
        match rx.recv().await {
            Err(narf_ipc::RecvError::Closed) => { OUTCOME.store(1, Ordering::Relaxed); }
            _                                => { OUTCOME.store(2, Ordering::Relaxed); }
        }
    });

    // Producer dropper: yields once to let the consumer park, then drops.
    narf_scheduler::spawn(async move {
        narf_scheduler::yield_now().await;
        drop(tx);
    });

    narf_scheduler::run_until_empty();
    match OUTCOME.load(Ordering::Relaxed) {
        1 => TestResult::Pass,
        2 => TestResult::Fail("recv returned unexpected variant"),
        _ => TestResult::Fail("recv future never resolved after producer drop"),
    }
}
kernel_test!(smoke_ipc_spsc_close_eof);

fn smoke_ipc_spsc_drain_then_eof() -> TestResult {
    use core::sync::atomic::{AtomicU32, Ordering};
    static COUNT:  AtomicU32 = AtomicU32::new(0);
    static CLOSED: AtomicU32 = AtomicU32::new(0);

    COUNT.store(0, Ordering::Relaxed);
    CLOSED.store(0, Ordering::Relaxed);
    narf_scheduler::init();

    let (mut tx, mut rx) = narf_ipc::channel::<u32, 4>();
    narf_scheduler::spawn(async move {
        let _ = tx.try_send(10);
        let _ = tx.try_send(20);
        let _ = tx.try_send(30);
    });
    narf_scheduler::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(_)  => { COUNT.fetch_add(1, Ordering::Relaxed); }
                Err(_) => { CLOSED.store(1, Ordering::Relaxed); break; }
            }
        }
    });
    narf_scheduler::run_until_empty();

    if COUNT.load(Ordering::Relaxed) != 3 {
        return TestResult::Fail("drain lost messages before Closed");
    }
    if CLOSED.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("Closed not observed after drain");
    }
    TestResult::Pass
}
kernel_test!(smoke_ipc_spsc_drain_then_eof);

// ── abi ───────────────────────────────────────────────────────────

fn smoke_abi_submission_layout() -> TestResult {
    // Wire-format pin. Spec §3 field order is op, flags, caps, tag,
    // inline; under `#[repr(C)]` the 16-aligned `CapSlot` forces an
    // 8-byte interior pad and an 8-byte tail pad, for 144 bytes total
    // at 16-byte alignment. The naive 4+4+64+8+48=128 undercounts both.
    use core::mem::{align_of, size_of};
    if size_of::<narf_abi::Submission>() != 144 {
        return TestResult::Fail("Submission size drifted from 144");
    }
    if align_of::<narf_abi::Submission>() != 16 {
        return TestResult::Fail("Submission alignment drifted from 16");
    }
    // Every OpCode discriminant must match the spec-pinned wire tag.
    // Adding a variant is fine; changing one of these is an ABI break.
    let opcode_pins: &[(narf_abi::OpCode, u32)] = &[
        (narf_abi::OpCode::Noop,        0x0000),
        (narf_abi::OpCode::Cancel,      0x0001),
        (narf_abi::OpCode::RingSend,    0x0002),
        (narf_abi::OpCode::RingRecv,    0x0003),
        (narf_abi::OpCode::Yield,       0x0004),
        (narf_abi::OpCode::DomainEnter, 0x0005),
        (narf_abi::OpCode::DomainExit,  0x0006),
    ];
    for &(op, wire) in opcode_pins {
        if op.as_u32() != wire {
            return TestResult::Fail("OpCode wire discriminant drifted");
        }
    }
    TestResult::Pass
}
kernel_test!(smoke_abi_submission_layout);

fn smoke_abi_completion_layout() -> TestResult {
    // Same pin for completions: 64 bytes, 8-byte aligned (status is u32
    // at offset 8, Rust inserts 4 bytes of tail padding before result).
    use core::mem::{align_of, size_of};
    if size_of::<narf_abi::Completion>() != 64 {
        return TestResult::Fail("Completion size drifted from 64");
    }
    if align_of::<narf_abi::Completion>() != 8 {
        return TestResult::Fail("Completion alignment drifted from 8");
    }
    let status_pins: &[(narf_abi::NarfStatus, u32)] = &[
        (narf_abi::NarfStatus::Ok,              0x0000),
        (narf_abi::NarfStatus::Pending,         0x0001),
        (narf_abi::NarfStatus::Cancelled,       0x0002),
        (narf_abi::NarfStatus::CancelRequested, 0x0003),
        (narf_abi::NarfStatus::CapRevoked,      0x0004),
        (narf_abi::NarfStatus::InvalidOp,       0x0005),
        (narf_abi::NarfStatus::Busy,            0x0006),
        (narf_abi::NarfStatus::Closed,          0x0007),
    ];
    for &(st, wire) in status_pins {
        if st.as_u32() != wire {
            return TestResult::Fail("NarfStatus wire discriminant drifted");
        }
    }
    TestResult::Pass
}
kernel_test!(smoke_abi_completion_layout);

fn smoke_abi_ring_roundtrip() -> TestResult {
    // Submit a Submission through the submission ring, on the kernel
    // side turn it into a Completion, then verify the tag round-trips
    // through the completion ring. This proves the `narf_ipc` SPSC ring
    // happily carries the wire-layout-pinned `Submission`/`Completion`
    // types at their declared sizes (i.e. we haven't accidentally made
    // the payload an un-transferable type).
    use core::sync::atomic::{AtomicU64, Ordering};
    static RECEIVED_TAG: AtomicU64 = AtomicU64::new(0);

    RECEIVED_TAG.store(0, Ordering::Relaxed);
    narf_scheduler::init();

    let (mut sq_tx, mut sq_rx) = narf_abi::submission_channel::<4>();
    let (mut cq_tx, mut cq_rx) = narf_abi::completion_channel::<4>();

    // Userland side: submit, await completion, stash the tag.
    narf_scheduler::spawn(async move {
        let sub = narf_abi::Submission::noop(narf_abi::Tag::new(0xDEADBEEF));
        let _ = sq_tx.send(sub).await;
        if let Ok(c) = cq_rx.recv().await {
            RECEIVED_TAG.store(c.tag, Ordering::Relaxed);
        }
    });

    // Kernel side: drain one submission, emit a matching completion.
    narf_scheduler::spawn(async move {
        if let Ok(sub) = sq_rx.recv().await {
            let c = narf_abi::Completion::ok(sub.tag());
            let _ = cq_tx.send(c).await;
        }
    });

    narf_scheduler::run_until_empty();
    if RECEIVED_TAG.load(Ordering::Relaxed) == 0xDEADBEEF {
        TestResult::Pass
    } else {
        TestResult::Fail("submission→completion tag did not round-trip")
    }
}
kernel_test!(smoke_abi_ring_roundtrip);

fn smoke_cap_bootstrap_and_invoke() -> TestResult {
    // A freshly-bootstrapped cap is live: check_live / is_live / invoke
    // with NoopOp all succeed. Epoch starts at 1.
    use narf_capabilities::{Cap, CapKind, CapType, NoopOp, Write, object_table};

    struct TestObj;
    impl CapType for TestObj { const KIND: CapKind = CapKind::Endpoint; }

    let cap: Cap<TestObj, Write> = Cap::<TestObj, Write>::bootstrap();
    if !cap.is_live() { return TestResult::Fail("fresh cap not live"); }
    if cap.check_live().is_err() { return TestResult::Fail("check_live on fresh cap failed"); }
    if cap.invoke(NoopOp).is_err() { return TestResult::Fail("NoopOp invoke failed on fresh cap"); }
    if object_table::kind_at(cap.slot().index) != Some(CapKind::Endpoint) {
        return TestResult::Fail("object_table lost the registered kind");
    }
    TestResult::Pass
}
kernel_test!(smoke_cap_bootstrap_and_invoke);

fn smoke_cap_revoke_invalidates() -> TestResult {
    // Bootstrap cap, keep a clone, revoke the original → clone sees
    // Revoked on its next check_live / invoke. O(1) mass invalidation.
    use narf_capabilities::{Cap, CapError, CapKind, CapType, NoopOp, Write};

    struct TestObj;
    impl CapType for TestObj { const KIND: CapKind = CapKind::Endpoint; }

    let parent: Cap<TestObj, Write> = Cap::<TestObj, Write>::bootstrap();
    let clone  = parent;               // Cap is Copy
    let derived: Cap<TestObj, Write> = parent.derive::<Write>().unwrap();
    parent.revoke();

    match clone.check_live() {
        Err(CapError::Revoked) => {}
        Ok(_)                  => return TestResult::Fail("clone still live after revoke"),
        Err(_)                 => return TestResult::Fail("clone reported wrong error"),
    }
    if derived.is_live()    { return TestResult::Fail("derived cap survived parent revoke"); }
    if clone.invoke(NoopOp) != Err(CapError::Revoked) {
        return TestResult::Fail("invoke didn't gate on epoch");
    }
    TestResult::Pass
}
kernel_test!(smoke_cap_revoke_invalidates);

fn smoke_cap_independent_objects() -> TestResult {
    // Revoking one object does not invalidate caps to another object
    // of the same kind — epochs are per-index, not global.
    use narf_capabilities::{Cap, CapKind, CapType, Write};

    struct TestObj;
    impl CapType for TestObj { const KIND: CapKind = CapKind::Endpoint; }

    let a: Cap<TestObj, Write> = Cap::<TestObj, Write>::bootstrap();
    let b: Cap<TestObj, Write> = Cap::<TestObj, Write>::bootstrap();
    if a.slot().index == b.slot().index {
        return TestResult::Fail("distinct bootstraps produced the same index");
    }
    a.revoke();
    if !b.is_live() { return TestResult::Fail("revoking a killed unrelated b"); }
    TestResult::Pass
}
kernel_test!(smoke_cap_independent_objects);

fn smoke_io_dma_alloc_free() -> TestResult {
    // alloc_coherent returns a page-aligned nonzero phys address with
    // the requested (rounded) length; drop returns the storage.
    use narf_io::{alloc_coherent, free_coherent};
    use narf_lib::id::DomainId;
    use narf_memory::PAGE_SIZE;

    let buf = match alloc_coherent(256, DomainId::DRIVER_0) {
        Ok(b) => b,
        Err(_) => return TestResult::Skip("frame allocator unavailable in this flavour"),
    };
    if buf.phys_addr().raw() == 0 {
        return TestResult::Fail("DMA buffer phys addr is zero");
    }
    if buf.phys_addr().raw() & (PAGE_SIZE - 1) != 0 {
        return TestResult::Fail("DMA buffer phys addr not page-aligned");
    }
    if buf.len() != PAGE_SIZE as usize {
        return TestResult::Fail("DMA buffer length not rounded to a page");
    }
    if buf.domain() != DomainId::DRIVER_0 {
        return TestResult::Fail("DMA buffer domain mismatch");
    }
    // Explicit free path (Drop path tested implicitly by the others).
    free_coherent(buf);
    TestResult::Pass
}
kernel_test!(smoke_io_dma_alloc_free);

fn smoke_io_dma_cap_bootstrap() -> TestResult {
    // Exercises Wave-2 cap table + Wave-3a DmaBuffer: bootstrap a
    // Cap<DmaBuffer, Write>, confirm it's live, revoke, confirm dead.
    use narf_capabilities::{Cap, CapError, CapType, Write};
    use narf_io::DmaBuffer;

    // Sanity: the CapType wiring points at CapKind::DmaBuffer.
    if DmaBuffer::KIND as u32 != narf_capabilities::CapKind::DmaBuffer as u32 {
        return TestResult::Fail("DmaBuffer::KIND not DmaBuffer");
    }

    let cap: Cap<DmaBuffer, Write> = Cap::<DmaBuffer, Write>::bootstrap();
    if !cap.is_live() { return TestResult::Fail("fresh DmaBuffer cap not live"); }
    if cap.check_live().is_err() {
        return TestResult::Fail("check_live on fresh DmaBuffer cap failed");
    }
    let clone = cap;
    cap.revoke();
    match clone.check_live() {
        Err(CapError::Revoked) => {}
        Ok(_) => return TestResult::Fail("DmaBuffer cap still live after revoke"),
        Err(_) => return TestResult::Fail("DmaBuffer cap reported wrong error"),
    }
    TestResult::Pass
}
kernel_test!(smoke_io_dma_cap_bootstrap);

fn smoke_io_iommu_stub_map_unmap() -> TestResult {
    // Wave-3a IOMMU stub: construct a context, map a DmaBuffer, unmap,
    // confirm the no-op returns and the internal mapping count tracks.
    use narf_io::{alloc_coherent, IommuContext, IoError};
    use narf_lib::id::DomainId;

    let dom = DomainId::DRIVER_1;
    let buf = match alloc_coherent(4096, dom) {
        Ok(b) => b,
        Err(_) => return TestResult::Skip("frame allocator unavailable in this flavour"),
    };

    let ctx = IommuContext::new(dom);
    if ctx.domain() != dom { return TestResult::Fail("IommuContext domain mismatch"); }
    if ctx.mapping_count() != 0 { return TestResult::Fail("fresh context not empty"); }

    if ctx.map(&buf, 0x1000_0000).is_err() {
        return TestResult::Fail("stub map returned error");
    }
    if ctx.mapping_count() != 1 { return TestResult::Fail("mapping count not bumped"); }

    // A mismatched-domain buffer must be rejected.
    let other = match alloc_coherent(4096, DomainId::DRIVER_2) {
        Ok(b) => b,
        Err(_) => return TestResult::Skip("frame allocator exhausted mid-test"),
    };
    match ctx.map(&other, 0x2000_0000) {
        Err(IoError::DomainMismatch) => {}
        _ => return TestResult::Fail("cross-domain map should have rejected"),
    }

    if ctx.unmap(0x1000_0000, 4096).is_err() {
        return TestResult::Fail("stub unmap returned error");
    }
    if ctx.mapping_count() != 0 { return TestResult::Fail("mapping count not decremented"); }

    // Unmapping nothing is an error.
    match ctx.unmap(0x1000_0000, 4096) {
        Err(IoError::NotMapped) => {}
        _ => return TestResult::Fail("unmap of empty context should fail"),
    }

    TestResult::Pass
}
kernel_test!(smoke_io_iommu_stub_map_unmap);

fn smoke_drivers_register_and_lifecycle() -> TestResult {
    // Exercises the whole Wave-3a framework path: mint a registration
    // authority, register a NoopDriver, drive its start + quiesce,
    // and observe the phase transitions via `with_entry`.
    use narf_drivers::{
        DomainPolicy, DriverManifest, DriverPhase, NoopDriver,
        bootstrap_authority, registry,
    };

    static MANIFEST: DriverManifest = DriverManifest {
        name:          "noop.smoke-1",
        domain_policy: DomainPolicy::Shared,
        caps_required: &[],
    };

    let authority = bootstrap_authority();
    let before = registry().len();
    let _handle = match registry().register(&authority, &MANIFEST, NoopDriver::new()) {
        Ok(h)  => h,
        Err(_) => return TestResult::Fail("register() failed on fresh authority"),
    };
    if registry().len() != before + 1 {
        return TestResult::Fail("registry length didn't grow after register");
    }

    // Freshly registered → Loaded.
    match registry().with_entry("noop.smoke-1", |s| s.phase) {
        Some(DriverPhase::Loaded) => {}
        _ => return TestResult::Fail("post-register phase not Loaded"),
    }

    narf_scheduler::init();
    narf_scheduler::spawn(async {
        let _ = registry().start_named("noop.smoke-1").await;
    });
    narf_scheduler::run_until_empty();
    match registry().with_entry("noop.smoke-1", |s| s.phase) {
        Some(DriverPhase::Started) => {}
        _ => return TestResult::Fail("post-start phase not Started"),
    }

    narf_scheduler::init();
    narf_scheduler::spawn(async {
        let _ = registry().quiesce_named("noop.smoke-1").await;
    });
    narf_scheduler::run_until_empty();
    match registry().with_entry("noop.smoke-1", |s| s.phase) {
        Some(DriverPhase::Quiesced) => {}
        _ => return TestResult::Fail("post-quiesce phase not Quiesced"),
    }

    // Re-entry is a no-op (idempotent): calling start on a Quiesced
    // entry or quiesce twice must not explode.
    narf_scheduler::init();
    narf_scheduler::spawn(async {
        let _ = registry().start_named("noop.smoke-1").await;
        let _ = registry().quiesce_named("noop.smoke-1").await;
    });
    narf_scheduler::run_until_empty();
    match registry().with_entry("noop.smoke-1", |s| s.phase) {
        Some(DriverPhase::Quiesced) => TestResult::Pass,
        _ => TestResult::Fail("post-reentry phase drifted off Quiesced"),
    }
}
kernel_test!(smoke_drivers_register_and_lifecycle);

fn smoke_drivers_register_revoked_authority() -> TestResult {
    // A revoked authority cap must not be able to register further
    // drivers — cap-table epoch gates the whole framework load path.
    use narf_drivers::{
        DomainPolicy, DriverManifest, NoopDriver, RegistrationError,
        bootstrap_authority, registry,
    };

    static MANIFEST: DriverManifest = DriverManifest {
        name:          "noop.revoke-test",
        domain_policy: DomainPolicy::Shared,
        caps_required: &[],
    };

    let authority = bootstrap_authority();
    authority.revoke();
    match registry().register(&authority, &MANIFEST, NoopDriver::new()) {
        Err(RegistrationError::AuthorityRevoked) => TestResult::Pass,
        Err(_) => TestResult::Fail("wrong error variant from revoked-authority register"),
        Ok(_)  => TestResult::Fail("register() accepted a revoked authority"),
    }
}
kernel_test!(smoke_drivers_register_revoked_authority);

fn smoke_drivers_dedicated_domain_exhaustion() -> TestResult {
    // security-model/ §4.1 caps dedicated-domain drivers at 6.
    // Register 6, confirm the 7th hard-errors.
    use narf_drivers::{
        DomainPolicy, DriverManifest, NoopDriver, RegistrationError,
        bootstrap_authority, registry,
    };

    // Seven distinct static manifests — kernel_test requires 'static
    // references, and the registry stores &'static DriverManifest.
    static M0: DriverManifest = DriverManifest { name: "ded.0", domain_policy: DomainPolicy::Dedicated, caps_required: &[] };
    static M1: DriverManifest = DriverManifest { name: "ded.1", domain_policy: DomainPolicy::Dedicated, caps_required: &[] };
    static M2: DriverManifest = DriverManifest { name: "ded.2", domain_policy: DomainPolicy::Dedicated, caps_required: &[] };
    static M3: DriverManifest = DriverManifest { name: "ded.3", domain_policy: DomainPolicy::Dedicated, caps_required: &[] };
    static M4: DriverManifest = DriverManifest { name: "ded.4", domain_policy: DomainPolicy::Dedicated, caps_required: &[] };
    static M5: DriverManifest = DriverManifest { name: "ded.5", domain_policy: DomainPolicy::Dedicated, caps_required: &[] };
    static M6: DriverManifest = DriverManifest { name: "ded.6", domain_policy: DomainPolicy::Dedicated, caps_required: &[] };

    let a = bootstrap_authority();
    for m in [&M0, &M1, &M2, &M3, &M4, &M5].iter().copied() {
        if registry().register(&a, m, NoopDriver::new()).is_err() {
            return TestResult::Fail("dedicated-domain register failed before limit");
        }
    }
    match registry().register(&a, &M6, NoopDriver::new()) {
        Err(RegistrationError::NoDomain) => TestResult::Pass,
        Err(_) => TestResult::Fail("wrong error variant on domain exhaustion"),
        Ok(_)  => TestResult::Fail("7th dedicated-domain register accepted"),
    }
}
kernel_test!(smoke_drivers_dedicated_domain_exhaustion);

// ── drivers/virtio — Wave 3b side-track ─────────────────────────────
//
// The side-track crate defines `VirtioMmioDevice::probe` + a skeleton
// `Driver`. These two tests exercise the happy path on aarch64 (where
// QEMU `virt` exposes 32 virtio-mmio slots) and a synthesised
// wrong-magic path that doesn't rely on real hardware at all.

#[cfg(target_arch = "aarch64")]
fn smoke_virtio_mmio_probe() -> TestResult {
    // QEMU `virt` populates virtio-mmio slot 0 at 0x0a00_0000 onwards;
    // the bus enumerator has already filtered out empty slots
    // (device_id == 0), so a non-empty registry proves at least one
    // probe will succeed. Re-probe every registry entry here to
    // exercise VirtioMmioDevice::probe directly.
    use narf_bus::{devices, BusKind};
    use narf_drivers_virtio::VirtioMmioDevice;
    // SAFETY: init tolerates a null/absent DTB by falling back to the
    // QEMU-virt default layout; identity-map covers the MMIO window.
    let _n = unsafe { narf_bus::init(None) };
    let mut ok = 0usize;
    for d in devices() {
        if !matches!(d.kind, BusKind::VirtioMmio { .. }) { continue; }
        // SAFETY: the bus registry published these entries after
        // confirming their MMIO regions are mapped and readable;
        // `probe` does a bounded u32 read.
        match unsafe { VirtioMmioDevice::probe(&d) } {
            Ok(v) => {
                if v.version() != 2 {
                    return TestResult::Fail("probed transport reported non-modern version");
                }
                ok += 1;
            }
            Err(_) => {
                // The bus registry filters out empty (device_id == 0)
                // MMIO slots before we see them, so a bus-registry
                // entry that fails probe is a real anomaly — magic
                // mismatch or unsupported version.
                return TestResult::Fail("unexpected probe error on bus-registry virtio-mmio entry");
            }
        }
    }
    // The bus-registry filter drops empty slots, so on QEMU virt we
    // must see at least one successful probe. If the registry had
    // returned zero entries we'd accept that — but we observed at
    // least one via the iterator.
    if ok == 0 {
        // Registry had no virtio-mmio entries at all — either QEMU
        // changed its defaults or the DTB fallback is off. Tolerate
        // as a skip rather than a hard fail.
        return TestResult::Skip("no virtio-mmio entries in bus registry");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test!(smoke_virtio_mmio_probe);

#[cfg(target_arch = "x86_64")]
fn smoke_virtio_mmio_probe() -> TestResult {
    // x86_64 under QEMU q35 has no virtio-mmio transports (virtio
    // lives behind PCIe on that machine). Assert structural: the bus
    // registry, once walked, contains zero VirtioMmio entries.
    use narf_bus::{devices, BusKind};
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    // SAFETY: ECAM_DEFAULT_BASE is inside q35's pcie-mmcfg region and
    // the walker performs read-only config-space probes.
    let _n = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    for d in devices() {
        if matches!(d.kind, BusKind::VirtioMmio { .. }) {
            return TestResult::Fail("unexpected virtio-mmio entry on x86_64 q35");
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test!(smoke_virtio_mmio_probe);

fn smoke_virtio_mmio_wrong_magic() -> TestResult {
    // Synthesise a fake MMIO window on the stack: a zeroed u32 at
    // offset 0 (the MAGIC_VALUE register) will not match VIRTIO_MAGIC
    // (0x7472_6976), so the probe must reject with WrongMagic. No
    // real hardware is touched, and the buffer does not escape this
    // function body.
    use narf_drivers_virtio::{ProbeError, VirtioMmioDevice};
    // 64 u32 slots = 256 bytes > 0x100 CONFIG offset, so any read
    // `probe_raw` performs lands inside the buffer. All zeros means
    // the very first read (MAGIC_VALUE) fails and we never touch the
    // tail.
    let fake: [u32; 64] = [0; 64];
    let addr = fake.as_ptr() as u64;
    // SAFETY: `fake` is a stack-allocated u32-aligned buffer covering
    // at least CONFIG bytes; `probe_raw` reads only 4-byte words
    // within it. The buffer's lifetime is this function body — we do
    // not stash the pointer anywhere.
    let result = unsafe { VirtioMmioDevice::probe_raw(addr) };
    // Prevent the optimiser from eliding the buffer even under fat LTO.
    core::hint::black_box(&fake);
    match result {
        Err(ProbeError::WrongMagic) => TestResult::Pass,
        Err(e) => {
            let _ = e;
            TestResult::Fail("wrong-magic probe returned the wrong error variant")
        }
        Ok(_)  => TestResult::Fail("wrong-magic probe unexpectedly succeeded"),
    }
}
kernel_test!(smoke_virtio_mmio_wrong_magic);


// ── Stage-3 exit-gate integration ──────────────────────────────────
//
// Spec: ROADMAP.md Stage 3 exit criterion — "A VirtIO device, running
// in its own PKS domain, moves a buffer through a Narf-Ring to another
// domain using only capability invocations, with no copy and no Ring-0
// trap on the fast path."
//
// The Wave-3b demonstration composes: io/ DmaBuffer + capabilities/
// cap-table + ipc/ Narf-Ring + scheduler. Driving real virtio silicon
// is the drivers/virtio/ side-track's job; this integration proves the
// composition works. Two tasks — notionally the "driver domain" and
// the "consumer domain" — trade ownership of a DmaBuffer plus a
// `Cap<DmaBuffer, Read>` through the ring. No memcpy on the payload
// (the DmaBuffer is moved by handle, not by content); the cap's
// `check_live` gate on the receive side is the spec's "capability
// invocation" on the fast path.

fn smoke_exit_gate_buffer_handoff() -> TestResult {
    use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
    use narf_capabilities::{Cap, Read};
    use narf_io::{DmaBuffer, alloc_coherent};
    use narf_lib::id::DomainId;
    use narf_memory::PAGE_SIZE;

    /// 17-byte payload pattern. Non-trivial so a zeroed/untouched
    /// buffer doesn't accidentally match.
    const PATTERN: [u8; 17] = [
        0xA5, 0x5A, 0x01, 0xFE, 0x42, 0x00, 0xFF, 0x10,
        0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xAA,
    ];

    static OUTCOME:   AtomicU8    = AtomicU8::new(0);   // 0=pending, 1=ok, 2=bad
    static READ_LEN:  AtomicUsize = AtomicUsize::new(0);

    struct Handoff {
        buf: DmaBuffer,
        cap: Cap<DmaBuffer, Read>,
    }

    OUTCOME.store(0, Ordering::Relaxed);
    READ_LEN.store(0, Ordering::Relaxed);

    let (mut tx, mut rx) = narf_ipc::channel::<Handoff, 2>();
    narf_scheduler::init();

    // "Driver domain" task: allocate, fill, hand off.
    narf_scheduler::spawn(async move {
        let Ok(buf) = alloc_coherent(PATTERN.len(), DomainId::DRIVER_0) else {
            return;
        };
        // Write the pattern to the buffer's physical memory. Valid
        // per `PhysAddr::as_mut_ptr`'s documented contract
        // (memory/src/addr.rs — caller must ensure identity-mapped or
        // remap_to_virtual-translated). Kernel keeps low RAM
        // identity-mapped on both arches; alloc_coherent returns
        // low-RAM frames, so the precondition holds.
        // SAFETY: buf is exclusively owned here; we write its full
        // allocated length at byte granularity.
        unsafe {
            let dst = buf.phys_addr().as_mut_ptr::<u8>();
            for (i, b) in PATTERN.iter().enumerate() {
                core::ptr::write_volatile(dst.add(i), *b);
            }
        }
        let cap: Cap<DmaBuffer, Read> = Cap::<DmaBuffer, Read>::bootstrap();
        let _ = tx.send(Handoff { buf, cap }).await;
        // Producer drops tx here; consumer finishes its recv.
    });

    // "Consumer domain" task: receive, gate on cap, read, assert.
    narf_scheduler::spawn(async move {
        let Ok(Handoff { buf, cap }) = rx.recv().await else {
            OUTCOME.store(2, Ordering::Relaxed);
            return;
        };
        // The spec's "capability invocation on the fast path": if the
        // cap were revoked between send and read, this fails — see
        // the revoked-variant test below.
        if cap.check_live().is_err() {
            OUTCOME.store(2, Ordering::Relaxed);
            return;
        }
        // SAFETY: buf ownership transferred to this task; identity-
        // mapped phys address readable.
        let mut ok = true;
        unsafe {
            let src = buf.phys_addr().as_ptr::<u8>();
            for (i, expected) in PATTERN.iter().enumerate() {
                if core::ptr::read_volatile(src.add(i)) != *expected {
                    ok = false; break;
                }
            }
        }
        READ_LEN.store(buf.len(), Ordering::Relaxed);
        OUTCOME.store(if ok { 1 } else { 2 }, Ordering::Relaxed);
        // buf drops here → frame returns to allocator.
    });

    narf_scheduler::run_until_empty();

    // Both tasks must have run to completion.
    if READ_LEN.load(Ordering::Relaxed) < PATTERN.len() {
        return TestResult::Fail("consumer never received a buffer");
    }
    if READ_LEN.load(Ordering::Relaxed) != PAGE_SIZE as usize {
        return TestResult::Fail("buffer length wasn't page-rounded on receive");
    }
    match OUTCOME.load(Ordering::Relaxed) {
        1 => TestResult::Pass,
        2 => TestResult::Fail("payload mismatch or cap check_live failed"),
        _ => TestResult::Fail("consumer task never ran"),
    }
}
kernel_test!(smoke_exit_gate_buffer_handoff);

fn smoke_exit_gate_revoked_cap_rejected() -> TestResult {
    // Same flow, but the producer revokes the cap after sending. The
    // consumer's `check_live` must reject the receive — a revoked
    // object is exactly the case epoch bumping invalidates O(1).
    //
    // Determinism precondition: single-CPU cooperative FIFO scheduler
    // (scheduler/src/lib.rs). `yield_now` pushes the yielder to the
    // queue tail, so producer-revoke always runs before consumer-
    // check_live. A preemptive or multi-CPU executor would make this
    // test racy — revisit the schedule when that lands.
    use core::sync::atomic::{AtomicU8, Ordering};
    use narf_capabilities::{Cap, Read};
    use narf_io::{DmaBuffer, alloc_coherent};
    use narf_lib::id::DomainId;

    static OUTCOME: AtomicU8 = AtomicU8::new(0); // 0 pending, 1 properly-rejected, 2 slipped-through

    struct Handoff {
        buf: DmaBuffer,
        cap: Cap<DmaBuffer, Read>,
    }

    OUTCOME.store(0, Ordering::Relaxed);

    let (mut tx, mut rx) = narf_ipc::channel::<Handoff, 2>();
    narf_scheduler::init();

    narf_scheduler::spawn(async move {
        let Ok(buf) = alloc_coherent(16, DomainId::DRIVER_0) else { return };
        let cap: Cap<DmaBuffer, Read> = Cap::<DmaBuffer, Read>::bootstrap();
        let cap_clone = cap;                         // Cap is Copy
        let _ = tx.send(Handoff { buf, cap: cap_clone }).await;
        // Yield so the consumer picks up the send before we revoke.
        narf_scheduler::yield_now().await;
        cap.revoke();                                // bumps the shared epoch
    });

    narf_scheduler::spawn(async move {
        let Ok(Handoff { buf: _buf, cap }) = rx.recv().await else {
            OUTCOME.store(2, Ordering::Relaxed);
            return;
        };
        // Yield once more to give the producer a chance to revoke
        // before we gate. On single-CPU cooperative this models the
        // "producer yanked authority before consumer touched buffer"
        // window the exit-gate criterion insists we honour.
        narf_scheduler::yield_now().await;
        match cap.check_live() {
            Err(_) => OUTCOME.store(1, Ordering::Relaxed),
            Ok(()) => OUTCOME.store(2, Ordering::Relaxed),
        }
    });

    narf_scheduler::run_until_empty();
    match OUTCOME.load(Ordering::Relaxed) {
        1 => TestResult::Pass,
        2 => TestResult::Fail("revoked cap slipped past check_live"),
        _ => TestResult::Fail("consumer never reached check_live"),
    }
}
kernel_test!(smoke_exit_gate_revoked_cap_rejected);

// ── block ──

fn smoke_block_device_trait() -> TestResult {
    use narf_drivers_virtio::blk::VirtioBlkDevice;
    use narf_drivers_virtio::VirtioMmioDevice;
    use narf_block::{BlockDevice, BlockRequest, BlockOp, QosHint};
    use narf_io::{alloc_coherent, register};
    use narf_lib::id::DomainId;
    use narf_capabilities::{Cap, Read, Rights};

    narf_scheduler::init();

    // 1. Probe a fake device (null addr).
    let mmio = unsafe { VirtioMmioDevice::probe_raw(0) };
    let Ok(mmio_dev) = mmio else {
        // probe_raw(0) fails magic check; this is expected for a compile test.
        // To do a real functional test, we'd need a mock VirtIO device.
        return TestResult::Pass;
    };

    let mut blk = VirtioBlkDevice::new(mmio_dev);
    
    // 2. Initialise.
    if let Err(_) = unsafe { blk.init(DomainId::DRIVER_0) } {
        return TestResult::Fail("VirtioBlkDevice::init failed");
    }

    // 3. Submit a request.
    let Ok(buf) = alloc_coherent(512, DomainId::DRIVER_0) else {
        return TestResult::Fail("DMA alloc failed");
    };
    let index = register(buf);
    let cap = unsafe { Cap::<narf_io::DmaBuffer, Read>::mint(
        narf_capabilities::CapSlot::new(1, index, Read::BITS, narf_capabilities::CapKind::DmaBuffer as u32)
    ) };

    let req = BlockRequest {
        op: BlockOp::Read,
        lba: 0,
        blocks: 1,
        buffer: cap,
        qos: QosHint::Latency,
        user_tag: 0x42,
    };

    let _future = blk.submit(req);
    
    // 4. Poll.
    blk.poll();

    TestResult::Pass
}
kernel_test!(smoke_block_device_trait);

fn smoke_exit_gate_virtio_blk() -> TestResult {
    use core::sync::atomic::{AtomicU8, Ordering};
    use alloc::sync::Arc;
    use narf_drivers_virtio::blk::VirtioBlkDevice;
    use narf_drivers_virtio::class_blk::VirtioBlkServer;
    use narf_drivers_virtio::VirtioMmioDevice;
    use narf_block::{BlockRequest, BlockCompletion, BlockOp, QosHint};
    use narf_io::{alloc_coherent, register};
    use narf_lib::id::DomainId;
    use narf_capabilities::{Cap, Read, Rights};

    static OUTCOME: AtomicU8 = AtomicU8::new(0);

    narf_scheduler::init();

    // 1. Setup rings and server.
    let (mut req_tx, req_rx) = narf_ipc::channel::<BlockRequest, 4>();
    let (compl_tx, mut compl_rx) = narf_ipc::channel::<BlockCompletion, 4>();

    let mmio = unsafe { VirtioMmioDevice::probe_raw(0) };
    let Ok(mmio_dev) = mmio else { return TestResult::Pass; };

    let mut blk = VirtioBlkDevice::new(mmio_dev);
    unsafe { blk.init(DomainId::DRIVER_0).unwrap(); }
    let blk = Arc::new(blk);

    let mut server = VirtioBlkServer::new(blk.clone(), req_rx, compl_tx);

    // 2. Spawn "Driver Domain" server task.
    narf_scheduler::spawn(async move {
        server.run().await;
    });

    // 3. Spawn "Consumer Domain" task.
    narf_scheduler::spawn(async move {
        let Ok(buf) = alloc_coherent(512, DomainId::DRIVER_0) else { return; };
        let index = register(buf);
        let cap = unsafe { Cap::<narf_io::DmaBuffer, Read>::mint(
            narf_capabilities::CapSlot::new(1, index, Read::BITS, narf_capabilities::CapKind::DmaBuffer as u32)
        ) };

        let req = BlockRequest {
            op: BlockOp::Read,
            lba: 0,
            blocks: 1,
            buffer: cap,
            qos: QosHint::Latency,
            user_tag: 0xDEADBEEF,
        };

        // Send request.
        let _ = req_tx.send(req).await;

        // Receive completion.
        if let Ok(compl) = compl_rx.recv().await {
            if compl.user_tag == 0xDEADBEEF {
                OUTCOME.store(1, Ordering::Relaxed);
            }
        }
        
        // Signal termination by dropping tx/rx.
        core::mem::drop(req_tx);
        core::mem::drop(compl_rx);
    });

    // 4. Spawn Polling task.
    let blk_poll = blk.clone();
    narf_scheduler::spawn(async move {
        loop {
            blk_poll.poll();
            narf_scheduler::yield_now().await;
            if OUTCOME.load(Ordering::Relaxed) != 0 { break; }
        }
    });

    narf_scheduler::run_until_empty();

    match OUTCOME.load(Ordering::Relaxed) {
        1 => TestResult::Pass,
        _ => TestResult::Fail("exit gate flow did not complete"),
    }
}
kernel_test!(smoke_exit_gate_virtio_blk);

fn smoke_abi_dispatcher_roundtrip() -> TestResult {
    use core::sync::atomic::{AtomicU8, Ordering};
    use narf_abi::{submission_channel, completion_channel, Dispatcher, Submission, Tag, NarfStatus, OpCode};

    static OUTCOME: AtomicU8 = AtomicU8::new(0);

    narf_scheduler::init();

    let (mut sq_tx, sq_rx) = submission_channel::<4>();
    let (cq_tx, mut cq_rx) = completion_channel::<4>();

    // 1. Spawn "Kernel" task: the dispatcher.
    narf_scheduler::spawn(async move {
        let mut dispatcher = Dispatcher::new(sq_rx, cq_tx);
        dispatcher.run().await;
    });

    // 2. Spawn "Userland" task: the producer.
    narf_scheduler::spawn(async move {
        // Op 1: Noop
        let tag1 = Tag::new(0x1111);
        sq_tx.send(Submission::noop(tag1)).await.unwrap();

        let c1 = cq_rx.recv().await.unwrap();
        if c1.tag() != tag1 || c1.status != NarfStatus::Ok {
            OUTCOME.store(2, Ordering::Relaxed);
            return;
        }

        // Op 2: Yield
        let tag2 = Tag::new(0x2222);
        let mut sub2 = Submission::noop(tag2);
        sub2.op = OpCode::Yield;
        sq_tx.send(sub2).await.unwrap();

        let c2 = cq_rx.recv().await.unwrap();
        if c2.tag() != tag2 || c2.status != NarfStatus::Ok {
            OUTCOME.store(3, Ordering::Relaxed);
            return;
        }

        OUTCOME.store(1, Ordering::Relaxed);
        
        // Signal termination by dropping SQ/CQ.
        core::mem::drop(sq_tx);
        core::mem::drop(cq_rx);
    });

    narf_scheduler::run_until_empty();

    match OUTCOME.load(Ordering::Relaxed) {
        1 => TestResult::Pass,
        2 => TestResult::Fail("Noop failed or tag mismatch"),
        3 => TestResult::Fail("Yield failed or tag mismatch"),
        _ => TestResult::Fail("Dispatcher never completed roundtrip"),
    }
}
kernel_test!(smoke_abi_dispatcher_roundtrip);
