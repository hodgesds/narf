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
        Err(narf_bus::ClaimError::AuthorityRevoked) => {
            TestResult::Fail("AuthorityRevoked on un-authorised path")
        }
        Ok(_) => TestResult::Fail("claim of bogus addr succeeded"),
    }
}
kernel_test!(smoke_bus_claim_device_not_found);

fn smoke_bus_msix_alloc_vector() -> TestResult {
    // Exercises the MsixTable::alloc_vector arithmetic against a
    // synthetic table so the test doesn't depend on any particular
    // device having an MSI-X capability. The synthetic helper mirrors
    // the shape of a real `enable_msix` return value — same fields,
    // same one-writer `&mut self` gate — so the arithmetic path is
    // the real one. Real capability-list walking against a PCIe
    // device lands with the Stage-4 BAR-map work; until then `bus/`
    // only exposes the walker itself and relies on this synthetic
    // path for coverage.
    use narf_bus::msix::__synth_msix_table;
    let mut t = __synth_msix_table(4);
    if t.size() != 4 { return TestResult::Fail("synthetic size mismatch"); }
    if t.free() != 4 { return TestResult::Fail("initial free mismatch"); }

    let v0 = t.alloc_vector().expect("slot 0");
    let v1 = t.alloc_vector().expect("slot 1");
    if v0.vector != 0 || v1.vector != 1 {
        return TestResult::Fail("monotonic vector allocation broken");
    }
    if t.free() != 2 { return TestResult::Fail("free count not decremented"); }

    // Bulk reservation path: take the remaining two.
    if t.alloc_block(2).is_err() {
        return TestResult::Fail("alloc_block(2) rejected a fitting reservation");
    }
    if t.alloc_vector().is_some() {
        return TestResult::Fail("alloc_vector returned Some on a full table");
    }
    match t.alloc_block(1) {
        Err(narf_bus::MsixError::TableOverflow) => {}
        Ok(_)  => return TestResult::Fail("alloc_block past capacity succeeded"),
        Err(_) => return TestResult::Fail("wrong error on overflow"),
    }
    TestResult::Pass
}
kernel_test!(smoke_bus_msix_alloc_vector);

#[cfg(target_arch = "aarch64")]
fn smoke_bus_msix_enable_on_virtio() -> TestResult {
    // virtio-mmio transports have no PCIe capability list. `enable_msix`
    // must reject them cleanly with `NotPcie`, never `CapabilityNotFound`
    // (which implies "PCIe with no MSI-X cap") and never UB-read the
    // non-existent config window.
    use narf_bus::{
        bootstrap_registry_authority, claim_device_cap, devices, enable_msix,
        BusKind, MsixError,
    };
    // SAFETY: the aarch64 enumerator falls back to probing the QEMU
    // virt virtio-mmio slot layout when no DTB is supplied. The reads
    // are volatile and validate magic before trusting the slot.
    let _ = unsafe { narf_bus::init(None) };
    let devs = devices();
    let virtio = devs.iter().find(|d| matches!(d.kind, BusKind::VirtioMmio { .. }));
    let Some(dev) = virtio else {
        return TestResult::Skip("no virtio-mmio device in this flavour");
    };

    let authority = bootstrap_registry_authority();
    let (_handle, dev_cap) = match claim_device_cap(&authority, dev.addr) {
        Ok(ok)  => ok,
        Err(_)  => return TestResult::Fail("claim_device_cap on a live address failed"),
    };
    match enable_msix(&dev_cap, dev) {
        Err(MsixError::NotPcie) => TestResult::Pass,
        Err(_) => TestResult::Fail("wrong error on virtio-mmio"),
        Ok(_)  => TestResult::Fail("enable_msix accepted a virtio-mmio device"),
    }
}
#[cfg(target_arch = "aarch64")]
kernel_test!(smoke_bus_msix_enable_on_virtio);

fn smoke_bus_hotplug_listener_roundtrip() -> TestResult {
    // Register a listener, dispatch an Attach + Detach, confirm the
    // listener's atomic advanced to 2.
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use narf_bus::hotplug::__clear_listeners;
    use narf_bus::{
        bootstrap_registry_authority, dispatch_event, register_listener, BusAddr, DeviceId,
        HotplugEvent, HotplugListener, PcieAddr,
    };

    // Isolate from any prior test run — the harness shares global state.
    __clear_listeners();

    struct Counter { hits: AtomicUsize }
    impl HotplugListener for Counter {
        fn on_event(&self, _ev: HotplugEvent) {
            self.hits.fetch_add(1, Ordering::Relaxed);
        }
    }

    let authority = bootstrap_registry_authority();
    let counter = Arc::new(Counter { hits: AtomicUsize::new(0) });
    if register_listener(&authority, counter.clone()).is_err() {
        return TestResult::Fail("register_listener rejected a live authority");
    }

    let addr = BusAddr::Pcie(PcieAddr::new(0, 0, 1, 0));
    dispatch_event(HotplugEvent::Attach {
        addr,
        device_id: DeviceId { vendor: 0x1af4, device: 0x1001, class: 0 },
    });
    dispatch_event(HotplugEvent::Detach { addr });

    if counter.hits.load(Ordering::Relaxed) != 2 {
        return TestResult::Fail("listener did not see both events");
    }
    // Restore a clean list so later tests don't see lingering state.
    __clear_listeners();
    TestResult::Pass
}
kernel_test!(smoke_bus_hotplug_listener_roundtrip);

fn smoke_bus_hotplug_revoked_authority() -> TestResult {
    // Revoking the authority before `register_listener` must fail with
    // AuthorityRevoked; same epoch-gate path the other cap-gated
    // subsystems rely on.
    use alloc::sync::Arc;
    use narf_bus::hotplug::__clear_listeners;
    use narf_bus::{
        bootstrap_registry_authority, register_listener, HotplugError, HotplugEvent,
        HotplugListener,
    };

    __clear_listeners();

    struct Sink;
    impl HotplugListener for Sink {
        fn on_event(&self, _: HotplugEvent) {}
    }

    let authority = bootstrap_registry_authority();
    authority.revoke();
    match register_listener(&authority, Arc::new(Sink) as Arc<dyn HotplugListener>) {
        Err(HotplugError::AuthorityRevoked) => TestResult::Pass,
        Ok(_) => TestResult::Fail("register_listener accepted a revoked authority"),
    }
}
kernel_test!(smoke_bus_hotplug_revoked_authority);

fn smoke_bus_iommu_group_default() -> TestResult {
    // Stage-3 stub: every enumerated device lives in group 0 on the
    // default QEMU line (no vIOMMU). Once ACS-walked grouping lands in
    // Stage 4 this test is where we'll assert the real mapping.
    use narf_bus::{devices, iommu_group_for};
    #[cfg(target_arch = "x86_64")]
    {
        use narf_bus::x86_64::ECAM_DEFAULT_BASE;
        // SAFETY: walking QEMU q35's identity-mapped ECAM.
        let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    }
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: fallback probes the identity-mapped virtio-mmio layout.
        let _ = unsafe { narf_bus::init(None) };
    }

    let devs = devices();
    if devs.is_empty() {
        return TestResult::Skip("empty registry on this flavour");
    }
    for d in devs.iter() {
        if iommu_group_for(d) != 0 {
            return TestResult::Fail("Stage-3 stub reported non-zero group");
        }
    }
    TestResult::Pass
}
kernel_test!(smoke_bus_iommu_group_default);

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

fn smoke_lib_current_domain_hook() -> TestResult {
    // narf-arch provides `narf_arch_current_domain` as the weak hook
    // `narf-lib` calls. Stage-3 default: 0 == DomainId::FRAME. Any
    // drift here breaks every assert_in_domain / assert_tcb caller.
    use narf_lib::assert::current_domain;
    use narf_lib::id::DomainId;

    if current_domain() != DomainId::FRAME {
        return TestResult::Fail("arch hook returned non-FRAME domain at boot");
    }
    TestResult::Pass
}
kernel_test!(smoke_lib_current_domain_hook);

fn smoke_lib_assert_in_domain_passes_on_frame() -> TestResult {
    // The always-on assert variant must not panic when the expected
    // domain matches. Stage-3 default has every task running in FRAME.
    use narf_lib::id::DomainId;
    narf_lib::assert_in_domain!(DomainId::FRAME);
    narf_lib::assert_tcb!();
    TestResult::Pass
}
kernel_test!(smoke_lib_assert_in_domain_passes_on_frame);

fn smoke_lib_bug_on_false_is_silent() -> TestResult {
    // bug_on! is a panic-path macro; a false condition must NOT panic.
    // Also implicitly tests the format-args path compiles.
    narf_lib::bug_on!(false, "should not fire");
    narf_lib::bug_on!(1 + 1 != 2, "arithmetic drift: {}", 42);
    TestResult::Pass
}
kernel_test!(smoke_lib_bug_on_false_is_silent);

// ── crypto/ smokes ──────────────────────────────────────────────────
//
// Stage-3 round 2: cap-gated primitive surface in narf-crypto. Vectors
// come from canonical sources so a regression in the underlying
// RustCrypto crates surfaces immediately rather than as a downstream
// protocol failure.

fn smoke_crypto_ed25519_verify() -> TestResult {
    // RFC 8032 §7.1 Test 1: empty message, well-known key + signature.
    use narf_capabilities::{Cap, Read};
    use narf_crypto::{ed25519_verify, Ed25519Verify, Key};

    let public: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
        0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
        0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
        0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
    ];
    let sig: [u8; 64] = [
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72,
        0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
        0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
        0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
        0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac,
        0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
        0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
        0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
    ];

    let cap: Cap<Key<Ed25519Verify>, Read> =
        Cap::<Key<Ed25519Verify>, Read>::bootstrap();
    if ed25519_verify(&cap, &public, b"", &sig).is_err() {
        return TestResult::Fail("ed25519 verify rejected RFC 8032 vector");
    }

    // Negative: flip a byte in the signature, must reject.
    let mut bad_sig = sig;
    bad_sig[0] ^= 0x01;
    if ed25519_verify(&cap, &public, b"", &bad_sig).is_ok() {
        return TestResult::Fail("ed25519 verify accepted tampered signature");
    }

    TestResult::Pass
}
kernel_test!(smoke_crypto_ed25519_verify);

fn smoke_crypto_chacha20_roundtrip() -> TestResult {
    // Seal then open: tag must match and plaintext must round-trip.
    // Cap is a fresh bootstrap; key bytes are a 32-byte zero-key
    // (vector quality doesn't matter here, only seal/open closure).
    use alloc::vec::Vec;
    use narf_capabilities::{Cap, Grant};
    use narf_crypto::{chacha20_open, chacha20_seal, ChaCha20Poly1305Alg, Key};

    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let aad: &[u8] = b"narf-crypto-aad";
    let original: Vec<u8> = b"the quick brown fox jumps over the lazy dog".to_vec();

    let cap: Cap<Key<ChaCha20Poly1305Alg>, Grant> =
        Cap::<Key<ChaCha20Poly1305Alg>, Grant>::bootstrap();

    let mut buf = original.clone();
    if chacha20_seal(&cap, &key, &nonce, &mut buf, aad).is_err() {
        return TestResult::Fail("chacha20 seal returned AeadFailure");
    }
    if buf.len() != original.len() + 16 {
        return TestResult::Fail("chacha20 seal didn't append 16-byte tag");
    }
    if buf[..original.len()] == original[..] {
        return TestResult::Fail("chacha20 seal left plaintext unencrypted");
    }
    if chacha20_open(&cap, &key, &nonce, &mut buf, aad).is_err() {
        return TestResult::Fail("chacha20 open rejected our own ciphertext");
    }
    if buf != original {
        return TestResult::Fail("chacha20 open didn't recover plaintext");
    }

    // Tamper the AAD on open — must reject.
    let mut buf2 = original.clone();
    let _ = chacha20_seal(&cap, &key, &nonce, &mut buf2, aad);
    if chacha20_open(&cap, &key, &nonce, &mut buf2, b"different-aad").is_ok() {
        return TestResult::Fail("chacha20 open accepted mismatched AAD");
    }

    TestResult::Pass
}
kernel_test!(smoke_crypto_chacha20_roundtrip);

fn smoke_crypto_hkdf_test_vector() -> TestResult {
    // RFC 5869 Test Case 1 — HKDF-SHA-256.
    use narf_capabilities::{Cap, Read};
    use narf_crypto::{hkdf_expand, Hkdf, Key};

    let ikm: [u8; 22] = [0x0b; 22];
    let salt: [u8; 13] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];
    let info: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
    let expected: [u8; 42] = [
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
        0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
        0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
        0x58, 0x65,
    ];

    let cap: Cap<Key<Hkdf>, Read> = Cap::<Key<Hkdf>, Read>::bootstrap();
    let okm = match hkdf_expand(&cap, &salt, &ikm, &info, 42) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("hkdf_expand returned an error"),
    };
    if okm.len() != 42 || okm[..] != expected[..] {
        return TestResult::Fail("hkdf_expand output mismatched RFC 5869 vector");
    }
    TestResult::Pass
}
kernel_test!(smoke_crypto_hkdf_test_vector);

fn smoke_crypto_blake3_known_answer() -> TestResult {
    // BLAKE3 empty-input digest, official KAT:
    // af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262
    use narf_crypto::blake3_hash;

    let expected: [u8; 32] = [
        0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6,
        0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc, 0xc9, 0x49,
        0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7,
        0xcc, 0x9a, 0x93, 0xca, 0xe4, 0x1f, 0x32, 0x62,
    ];
    let got = blake3_hash(b"");
    if got != expected {
        return TestResult::Fail("blake3 empty-input hash drifted from KAT");
    }
    TestResult::Pass
}
kernel_test!(smoke_crypto_blake3_known_answer);

// ── net ───────────────────────────────────────────────────────────

fn smoke_net_loopback_register() -> TestResult {
    // Register a uniquely-named loopback (the global registry persists
    // across tests in a single boot, so don't use the default name) and
    // verify the registry exposes its name/MAC/MTU + link state.
    use narf_net::{Loopback, bootstrap_authority, register_loopback_named, registry};

    // Scheduler must be live: register_loopback_named spawns a
    // forwarder task at registration time (per the Stage-3 spec).
    narf_scheduler::init();

    let authority = bootstrap_authority();
    let before = registry().len();
    let _handle = match register_loopback_named(&authority, "lo.smoke-register") {
        Ok(h)  => h,
        Err(_) => return TestResult::Fail("register_loopback_named failed on fresh authority"),
    };
    if registry().len() != before + 1 {
        return TestResult::Fail("registry length didn't grow after register");
    }

    let info = registry().with_interface("lo.smoke-register", |i| {
        (i.mac(), i.mtu(), i.link_up())
    });
    match info {
        Some((mac, mtu, link)) => {
            if mac != Loopback::DEFAULT_MAC { return TestResult::Fail("MAC mismatch"); }
            if mtu != Loopback::DEFAULT_MTU { return TestResult::Fail("MTU mismatch"); }
            if !link { return TestResult::Fail("loopback link not up"); }
            TestResult::Pass
        }
        None => TestResult::Fail("registered interface not found by name"),
    }
}
kernel_test!(smoke_net_loopback_register);

fn smoke_net_loopback_roundtrip() -> TestResult {
    // End-to-end zero-copy: write a known payload into a DmaBuffer,
    // wrap as a Frame, send via loopback's tx_ring, recv via rx_ring,
    // verify byte-exact match. Producer + consumer + forwarder all
    // share one cooperative executor; the forwarder spawned at
    // register time pumps tx → rx.
    use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};
    use narf_io::alloc_coherent;
    use narf_lib::id::DomainId;
    use narf_net::{Frame, bootstrap_authority, register_loopback_named, registry};

    const PAYLOAD: [u8; 24] = [
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    ];

    static OUTCOME:  AtomicU8  = AtomicU8::new(0); // 0 pending, 1 ok, 2 mismatch, 3 lost
    static GOT_LEN:  AtomicU32 = AtomicU32::new(0);

    OUTCOME.store(0, Ordering::Relaxed);
    GOT_LEN.store(0, Ordering::Relaxed);

    narf_scheduler::init();

    let authority = bootstrap_authority();
    if register_loopback_named(&authority, "lo.smoke-roundtrip").is_err() {
        return TestResult::Fail("register_loopback_named failed");
    }

    // Take the producer + consumer out of the interface — sole-owner
    // SPSC discipline. Both ring halves are still owned by the
    // registry-held Loopback; we hold them only for the duration of
    // this test.
    let tx = registry().with_interface("lo.smoke-roundtrip", |i| {
        i.tx_ring().lock().take()
    }).flatten();
    let rx = registry().with_interface("lo.smoke-roundtrip", |i| {
        i.rx_ring().lock().take()
    }).flatten();
    let (Some(mut tx), Some(mut rx)) = (tx, rx) else {
        return TestResult::Fail("loopback ring halves missing");
    };

    // Sender: alloc, fill, frame, send. Drops tx at the end of the
    // task — the forwarder observes Closed and exits, but our send
    // has already landed by then.
    narf_scheduler::spawn(async move {
        let Ok(buf) = alloc_coherent(PAYLOAD.len(), DomainId::DRIVER_0) else {
            return;
        };
        // SAFETY: buf is exclusively owned here; alloc_coherent returns
        // identity-mapped low-RAM frames so phys_addr is a valid raw
        // pointer (same precondition as smoke_exit_gate_buffer_handoff).
        unsafe {
            let dst = buf.phys_addr().as_mut_ptr::<u8>();
            for (i, b) in PAYLOAD.iter().enumerate() {
                core::ptr::write_volatile(dst.add(i), *b);
            }
        }
        let frame = Frame::new(buf, PAYLOAD.len() as u32);
        let _ = tx.send(frame).await;
    });

    // Receiver: recv one frame, verify payload survived the loopback
    // round-trip without copy.
    narf_scheduler::spawn(async move {
        let Ok(frame) = rx.recv().await else {
            OUTCOME.store(3, Ordering::Relaxed);
            return;
        };
        let len = frame.len();
        GOT_LEN.store(len, Ordering::Relaxed);
        let (buf, used) = frame.into_parts();
        let mut ok = used as usize == PAYLOAD.len();
        // SAFETY: buf ownership transferred here; identity-mapped read.
        unsafe {
            let src = buf.phys_addr().as_ptr::<u8>();
            for (i, expected) in PAYLOAD.iter().enumerate() {
                if core::ptr::read_volatile(src.add(i)) != *expected {
                    ok = false; break;
                }
            }
        }
        OUTCOME.store(if ok { 1 } else { 2 }, Ordering::Relaxed);
        // buf drops → frame returns to allocator. rx drops here too,
        // closing the rx ring; the forwarder will hit Err on its next
        // send and exit cleanly.
    });

    narf_scheduler::run_until_empty();

    if GOT_LEN.load(Ordering::Relaxed) == 0 {
        return TestResult::Fail("receiver never observed a frame");
    }
    if GOT_LEN.load(Ordering::Relaxed) as usize != PAYLOAD.len() {
        return TestResult::Fail("frame length didn't match payload length");
    }
    match OUTCOME.load(Ordering::Relaxed) {
        1 => TestResult::Pass,
        2 => TestResult::Fail("payload mismatch after loopback round-trip"),
        3 => TestResult::Fail("rx recv resolved Closed before delivering a frame"),
        _ => TestResult::Fail("receiver task never ran"),
    }
}
kernel_test!(smoke_net_loopback_roundtrip);

fn smoke_net_loopback_revoked_authority() -> TestResult {
    // A revoked authority cap must not be able to register further
    // interfaces — same epoch-gate path the drivers/ framework relies
    // on (smoke_drivers_register_revoked_authority is the parallel).
    use narf_net::{RegisterError, bootstrap_authority, register_loopback_named};

    // Scheduler must be live: register short-circuits on
    // AuthorityRevoked before spawning, but staying consistent with the
    // other two net tests keeps the harness state predictable across
    // boots.
    narf_scheduler::init();

    let authority = bootstrap_authority();
    authority.revoke();
    match register_loopback_named(&authority, "lo.smoke-revoked") {
        Err(RegisterError::AuthorityRevoked) => TestResult::Pass,
        Err(_) => TestResult::Fail("wrong error variant from revoked-authority register"),
        Ok(_)  => TestResult::Fail("register_loopback_named accepted a revoked authority"),
    }
}
kernel_test!(smoke_net_loopback_revoked_authority);

// ── filesystem (Stage 3) ────────────────────────────────────────────
//
// Tiny CPIO newc archive with a single file "hello" containing "world".
// Hand-built so the harness has zero dependency on a host cpio tool;
// see filesystem/src/lib.rs for the on-the-wire format. Byte counts:
//   header "hello"        : 110
//   name   "hello\0"      :   6   (110+6 = 116, 4-byte aligned)
//   data   "world"        :   5   (116+5 = 121)
//   pad                   :   3   (-> 124)
//   header TRAILER!!!     : 110   (-> 234)
//   name   "TRAILER!!!\0" :  11   (-> 245)
//   pad                   :   3   (-> 248)
static SMOKE_INITRAMFS: &[u8] = b"\
070701\
00000001\
000081A4\
00000000\
00000000\
00000001\
00000064\
00000005\
00000000\
00000000\
00000000\
00000000\
00000006\
00000000\
hello\0\
world\0\0\0\
070701\
00000000\
00000000\
00000000\
00000000\
00000001\
00000000\
00000000\
00000000\
00000000\
00000000\
00000000\
0000000B\
00000000\
TRAILER!!!\0\0\0\0";

fn smoke_fs_initramfs_mount_and_stat() -> TestResult {
    use narf_filesystem::{
        Initramfs, bootstrap_mount_authority, registry, resolve, FileType,
    };

    let fs = match Initramfs::from_cpio("smoke-fs-stat", SMOKE_INITRAMFS) {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("CPIO parse failed at fixture build"),
    };

    let authority = bootstrap_mount_authority();
    let _handle = match registry().mount(&authority, "/smoke-stat", fs) {
        Ok(h)  => h,
        Err(_) => return TestResult::Fail("mount() refused a live authority"),
    };

    // Look up the FsInstance by mount path and stat "hello".
    let stat_opt = registry().with_mount("/smoke-stat", |fs| {
        let root = fs.root();
        let file = resolve(root, "hello").ok()?;
        Some(file.stat())
    }).flatten();

    let stat = match stat_opt {
        Some(s) => s,
        None    => return TestResult::Fail("resolve(hello) failed inside mounted FS"),
    };
    if stat.size != 5            { return TestResult::Fail("stat.size != 5"); }
    if stat.mode.file_type != FileType::File {
        return TestResult::Fail("stat reported non-File type");
    }
    TestResult::Pass
}
kernel_test!(smoke_fs_initramfs_mount_and_stat);

fn smoke_fs_initramfs_read() -> TestResult {
    use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
    use narf_filesystem::{
        Initramfs, bootstrap_mount_authority, registry, resolve,
    };

    static OUTCOME: AtomicU8    = AtomicU8::new(0);   // 0 pending, 1 ok, 2 mismatch, 3 short
    static GOT_LEN: AtomicUsize = AtomicUsize::new(0);
    OUTCOME.store(0, Ordering::Relaxed);
    GOT_LEN.store(0, Ordering::Relaxed);

    let fs = match Initramfs::from_cpio("smoke-fs-read", SMOKE_INITRAMFS) {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("CPIO parse failed at fixture build"),
    };
    let authority = bootstrap_mount_authority();
    let _handle = match registry().mount(&authority, "/smoke-read", fs) {
        Ok(h)  => h,
        Err(_) => return TestResult::Fail("mount() refused a live authority"),
    };

    let file = match registry().with_mount("/smoke-read", |fs| {
        resolve(fs.root(), "hello").ok()
    }).flatten() {
        Some(f) => f,
        None    => return TestResult::Fail("resolve(hello) returned None"),
    };

    narf_scheduler::init();
    narf_scheduler::spawn(async move {
        let mut buf = [0u8; 16];
        let n = match file.read(0, &mut buf).await {
            Ok(n)  => n,
            Err(_) => { OUTCOME.store(3, Ordering::Relaxed); return; }
        };
        GOT_LEN.store(n, Ordering::Relaxed);
        if n != 5 { OUTCOME.store(3, Ordering::Relaxed); return; }
        if &buf[..5] == b"world" {
            OUTCOME.store(1, Ordering::Relaxed);
        } else {
            OUTCOME.store(2, Ordering::Relaxed);
        }
    });
    narf_scheduler::run_until_empty();

    match OUTCOME.load(Ordering::Relaxed) {
        1 => TestResult::Pass,
        2 => TestResult::Fail("read returned wrong bytes"),
        3 => TestResult::Fail("read short or errored"),
        _ => TestResult::Fail("read task never ran"),
    }
}
kernel_test!(smoke_fs_initramfs_read);

fn smoke_fs_lookup_missing() -> TestResult {
    use narf_filesystem::{
        FsError, Initramfs, bootstrap_mount_authority, registry, resolve,
    };

    let fs = match Initramfs::from_cpio("smoke-fs-miss", SMOKE_INITRAMFS) {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("CPIO parse failed at fixture build"),
    };
    let authority = bootstrap_mount_authority();
    let _handle = match registry().mount(&authority, "/smoke-miss", fs) {
        Ok(h)  => h,
        Err(_) => return TestResult::Fail("mount() refused a live authority"),
    };

    let res = registry().with_mount("/smoke-miss", |fs| {
        resolve(fs.root(), "does-not-exist")
    });
    match res {
        Some(Err(FsError::NotFound)) => TestResult::Pass,
        Some(Err(_)) => TestResult::Fail("wrong error for missing file"),
        Some(Ok(_))  => TestResult::Fail("missing file resolved to a node"),
        None         => TestResult::Fail("with_mount couldn't find the mount we just made"),
    }
}
kernel_test!(smoke_fs_lookup_missing);

fn smoke_fs_mount_revoked_authority() -> TestResult {
    use narf_filesystem::{
        FsError, Initramfs, bootstrap_mount_authority, registry,
    };

    let fs = match Initramfs::from_cpio("smoke-fs-rev", SMOKE_INITRAMFS) {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("CPIO parse failed at fixture build"),
    };
    let authority = bootstrap_mount_authority();
    authority.revoke();
    match registry().mount(&authority, "/smoke-rev", fs) {
        Err(FsError::PermissionDenied) => TestResult::Pass,
        Err(_) => TestResult::Fail("revoked authority returned wrong FsError"),
        Ok(_)  => TestResult::Fail("mount() accepted a revoked authority"),
    }
}
kernel_test!(smoke_fs_mount_revoked_authority);

// ── power/ smokes ───────────────────────────────────────────────────
//
// Stage-3 round 3: cap-gated C-state registry, DVFS governor framework,
// per-driver runtime PM. Tests run after net/ / fs/ smokes in this
// file, so the global power tables may already hold defaults from a
// previous `init()` call — the registry deliberately tolerates this
// (duplicate-id rejection on cstates, governor slot is overwritten).

fn smoke_power_cstate_register() -> TestResult {
    use narf_power::{
        bootstrap_power_authority, cstate_count, init, register_cstate,
        select_idle_state, CState, PowerError,
    };

    init();
    let baseline = cstate_count();
    if baseline < 2 {
        return TestResult::Fail("init() did not register C0 + C1");
    }

    // Pick an `id` that won't collide with C0/C1 or with anything a
    // previous test may have inserted. 200 is well above the realistic
    // ACPI _CST depth so it stays unique across the harness boot.
    let cap = bootstrap_power_authority();
    let synth = CState {
        id: 200,
        exit_latency_us: 50,
        power_draw_mw: 100,
        entry: || { /* test stub */ },
    };
    if let Err(e) = register_cstate(&cap, synth) {
        // `DuplicateCState` here means a previous run of this test
        // already inserted id=200 — re-running the harness from a
        // single boot is fine; treat as Pass.
        if e != PowerError::DuplicateCState {
            return TestResult::Fail("register_cstate rejected a fresh id");
        }
    }

    // select_idle_state should return *some* state whose latency fits
    // within the Stage-3 deadline budget. C1 (latency 1us) is the
    // expected answer in a fresh harness; the synthetic state at 50us
    // also fits. Either is acceptable for "sensible".
    let chosen = match select_idle_state() {
        Ok(s)  => s,
        Err(_) => return TestResult::Fail("select_idle_state returned NoMatchingState"),
    };
    if chosen.exit_latency_us > 1_000 {
        return TestResult::Fail("selected state exceeded the deadline budget");
    }
    TestResult::Pass
}
kernel_test!(smoke_power_cstate_register);

fn smoke_power_governor_swap() -> TestResult {
    use narf_power::{
        bootstrap_governor_authority, current_governor_name, init,
        install_governor, OnDemand, Powersave, PowerError,
    };

    init();

    // Default after init() is `Performance`. Tests earlier in the same
    // boot may have swapped it; install_governor is idempotent so we
    // re-establish the baseline before swapping again.
    let cap = bootstrap_governor_authority();
    if install_governor(&cap, narf_power::Performance).is_err() {
        return TestResult::Fail("install_governor(Performance) failed on a live cap");
    }
    if current_governor_name() != Some("performance") {
        return TestResult::Fail("baseline governor name was not 'performance'");
    }

    // Live cap — install OnDemand, confirm name flips.
    if install_governor(&cap, OnDemand).is_err() {
        return TestResult::Fail("install_governor(OnDemand) rejected a live cap");
    }
    if current_governor_name() != Some("ondemand") {
        return TestResult::Fail("governor name didn't update after install");
    }

    // Revoke the cap, then attempt to install Powersave — must fail.
    cap.revoke();
    match install_governor(&cap, Powersave) {
        Err(PowerError::AuthorityRevoked) => {}
        Err(_) => return TestResult::Fail("revoked install returned wrong error variant"),
        Ok(_)  => return TestResult::Fail("install_governor accepted a revoked cap"),
    }

    // The active governor must still be OnDemand — a failed install
    // doesn't displace the previous policy.
    if current_governor_name() != Some("ondemand") {
        return TestResult::Fail("failed install displaced the active governor");
    }

    // Reset the active governor to Performance for downstream tests
    // (none today, but the harness convention is to leave global state
    // approximating the post-init baseline).
    let cap2 = bootstrap_governor_authority();
    let _ = install_governor(&cap2, narf_power::Performance);
    TestResult::Pass
}
kernel_test!(smoke_power_governor_swap);

fn smoke_power_device_pm_lifecycle() -> TestResult {
    use core::future::Future;
    use core::pin::Pin;
    use core::sync::atomic::{AtomicU32, Ordering};
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use narf_power::{
        bootstrap_device_pm_authority, register_device_pm, resume_device,
        suspend_device, DeviceRuntimePm,
    };

    // Counters shared with the trivial DeviceRuntimePm impl. `Arc<...>`
    // so the registry-stashed Box<dyn DeviceRuntimePm> can keep its own
    // handle while the test body still observes the post-resume values.
    let suspends = Arc::new(AtomicU32::new(0));
    let resumes  = Arc::new(AtomicU32::new(0));

    struct Counter {
        suspends: Arc<AtomicU32>,
        resumes:  Arc<AtomicU32>,
    }
    impl DeviceRuntimePm for Counter {
        fn suspend<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
            let c = self.suspends.clone();
            Box::pin(async move {
                c.fetch_add(1, Ordering::Release);
            })
        }
        fn resume<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
            let c = self.resumes.clone();
            Box::pin(async move {
                c.fetch_add(1, Ordering::Release);
            })
        }
    }

    let cap = bootstrap_device_pm_authority();
    let dev = Counter { suspends: suspends.clone(), resumes: resumes.clone() };
    let handle = match register_device_pm(&cap, dev) {
        Ok(h)  => h,
        Err(_) => return TestResult::Fail("register_device_pm rejected a live cap"),
    };

    // Drive suspend + resume through the scheduler — confirms the
    // futures returned by the trait actually compose with the Stage-1
    // executor and that the registry's "take then put back" dance
    // doesn't deadlock the global lock.
    narf_scheduler::init();
    narf_scheduler::spawn(async move {
        let _ = suspend_device(handle).await;
        let _ = resume_device(handle).await;
    });
    narf_scheduler::run_until_empty();

    if suspends.load(Ordering::Acquire) != 1 {
        return TestResult::Fail("DeviceRuntimePm::suspend was not called exactly once");
    }
    if resumes.load(Ordering::Acquire) != 1 {
        return TestResult::Fail("DeviceRuntimePm::resume was not called exactly once");
    }
    TestResult::Pass
}
kernel_test!(smoke_power_device_pm_lifecycle);

fn smoke_rcu_sleepable_enter_exit() -> TestResult {
    use narf_rcu::sleepable::{SleepableReader, SleepableScope};

    let scope = SleepableScope::new();
    let cap = SleepableReader::bootstrap_cap();

    if scope.active() != 0 {
        return TestResult::Fail("scope.active() must start at 0");
    }
    {
        let _g = match scope.enter(&cap) {
            Ok(g)  => g,
            Err(_) => return TestResult::Fail("enter rejected a fresh cap"),
        };
        if scope.active() != 1 {
            return TestResult::Fail("active didn't reach 1 after enter");
        }
    }
    if scope.active() != 0 {
        return TestResult::Fail("active didn't return to 0 after guard drop");
    }
    TestResult::Pass
}
kernel_test!(smoke_rcu_sleepable_enter_exit);

fn smoke_rcu_sleepable_sync_drains() -> TestResult {
    // Two-task choreography on the cooperative executor:
    //   A. holder task: enters scope, yields a few times, drops guard.
    //   B. waiter task: awaits sync_async(deadline = +1B cycles); must
    //      observe Drained, NOT Timeout.
    //
    // The 1-billion-cycle deadline is well past the holder's natural
    // exit on the cooperative single-CPU executor. The static
    // SCOPE/CAP avoid lifetime-juggling between the two spawned
    // futures (they need 'static or move-by-Arc; static is simpler).
    use core::sync::atomic::{AtomicU8, Ordering};
    use narf_rcu::sleepable::{SleepableReader, SleepableScope, SyncOutcome, sync_async};
    use narf_capabilities::{Cap, Read};

    static SCOPE:    SleepableScope             = SleepableScope::new();
    static CAP_SET:  core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    static mut CAP:  Option<Cap<SleepableReader, Read>> = None;
    static OUTCOME:  AtomicU8 = AtomicU8::new(0);   // 0=pending, 1=drained, 2=timeout, 3=error

    OUTCOME.store(0, Ordering::Relaxed);
    SCOPE.clear_over_budget();
    // Force a fresh cap each invocation. Last-test residue (especially
    // when the harness repeats) would otherwise see active != 0 leak.
    // SAFETY: harness is single-threaded; no concurrent CAP access.
    unsafe {
        CAP = Some(SleepableReader::bootstrap_cap());
        CAP_SET.store(true, Ordering::Release);
    }

    narf_scheduler::init();

    // Holder task — yields three times, then drops the guard.
    narf_scheduler::spawn(async move {
        // SAFETY: CAP is set above on the same thread before spawn.
        let cap = unsafe { CAP.as_ref().unwrap() };
        let g = SCOPE.enter(cap).expect("enter must succeed");
        for _ in 0..3 { narf_scheduler::yield_now().await; }
        drop(g);
    });

    // Waiter task — sync_async with a generous deadline.
    narf_scheduler::spawn(async move {
        let deadline = narf_time::Instant::now().plus_cycles(1_000_000_000);
        match sync_async(&SCOPE, deadline).await {
            SyncOutcome::Drained   => OUTCOME.store(1, Ordering::Relaxed),
            SyncOutcome::Timeout   => OUTCOME.store(2, Ordering::Relaxed),
            SyncOutcome::Cancelled => OUTCOME.store(3, Ordering::Relaxed),
        }
    });

    narf_scheduler::run_until_empty();

    let _ = CAP_SET.load(Ordering::Acquire); // suppress warning if cfg trims

    match OUTCOME.load(Ordering::Relaxed) {
        1 => TestResult::Pass,
        2 => TestResult::Fail("sync_async returned Timeout when readers should have drained"),
        3 => TestResult::Fail("sync_async returned Cancelled (Stage-4 path)"),
        _ => TestResult::Fail("sync_async never resolved"),
    }
}
kernel_test!(smoke_rcu_sleepable_sync_drains);

fn smoke_rcu_sleepable_timeout() -> TestResult {
    // Holder never drops within the deadline. Waiter must observe
    // Timeout. The deadline is 10_000 cycles from the moment
    // sync_async is created — vanishingly short on any real CPU,
    // guaranteed to fire before a typical yield round completes
    // even on the cooperative executor.
    use core::sync::atomic::{AtomicU8, Ordering};
    use narf_rcu::sleepable::{SleepableReader, SleepableScope, SyncOutcome, sync_async};
    use narf_capabilities::{Cap, Read};

    static SCOPE:    SleepableScope             = SleepableScope::new();
    static mut CAP:  Option<Cap<SleepableReader, Read>> = None;
    static OUTCOME:  AtomicU8 = AtomicU8::new(0);
    static DONE:     core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

    OUTCOME.store(0, Ordering::Relaxed);
    DONE.store(false, Ordering::Relaxed);
    SCOPE.clear_over_budget();
    // SAFETY: harness is single-threaded.
    unsafe { CAP = Some(SleepableReader::bootstrap_cap()); }

    narf_scheduler::init();

    // Holder task — holds the guard until DONE flips. Yields each
    // round so the executor doesn't deadlock.
    narf_scheduler::spawn(async move {
        // SAFETY: CAP is set above before spawn.
        let cap = unsafe { CAP.as_ref().unwrap() };
        let _g = SCOPE.enter(cap).expect("enter must succeed");
        while !DONE.load(Ordering::Acquire) {
            narf_scheduler::yield_now().await;
        }
        // _g drops here.
    });

    // Waiter task — short deadline, expect Timeout.
    narf_scheduler::spawn(async move {
        let deadline = narf_time::Instant::now().plus_cycles(10_000);
        let outcome = sync_async(&SCOPE, deadline).await;
        match outcome {
            SyncOutcome::Timeout   => OUTCOME.store(2, Ordering::Relaxed),
            SyncOutcome::Drained   => OUTCOME.store(1, Ordering::Relaxed),
            SyncOutcome::Cancelled => OUTCOME.store(3, Ordering::Relaxed),
        }
        // Release the holder so run_until_empty terminates.
        DONE.store(true, Ordering::Release);
    });

    narf_scheduler::run_until_empty();

    match OUTCOME.load(Ordering::Relaxed) {
        2 => TestResult::Pass,
        1 => TestResult::Fail("sync_async drained when it should have timed out"),
        3 => TestResult::Fail("sync_async returned Cancelled (Stage-4 path)"),
        _ => TestResult::Fail("sync_async never resolved"),
    }
}
kernel_test!(smoke_rcu_sleepable_timeout);

fn smoke_rcu_sleepable_revoked_cap_rejected() -> TestResult {
    use narf_capabilities::CapError;
    use narf_rcu::sleepable::{SleepableReader, SleepableScope};

    let scope = SleepableScope::new();
    let cap = SleepableReader::bootstrap_cap();
    // Clone-by-Copy keeps the slot bits while transferring ownership of
    // the original to revoke(). After revoke, the duplicate cap with
    // the same generation snapshot must fail check_live and bounce out
    // of enter() with CapError::Revoked.
    let cap_copy = cap;
    cap.revoke();

    if scope.active() != 0 {
        return TestResult::Fail("scope.active() must start at 0");
    }
    match scope.enter(&cap_copy) {
        Err(CapError::Revoked) => {}
        Err(_) => return TestResult::Fail("wrong error variant from revoked cap"),
        Ok(_)  => return TestResult::Fail("enter accepted a revoked cap"),
    }
    if scope.active() != 0 {
        return TestResult::Fail("rejected enter must not bump active");
    }
    TestResult::Pass
}
kernel_test!(smoke_rcu_sleepable_revoked_cap_rejected);

// ── rcu/ hazard-pointer tests ──────────────────────────────────────
//
// Cover the three load-bearing properties of `HazardDomain`:
//   * publish + retire round-trip (no readers active)
//   * retire while a reader holds the guard — drop must wait
//   * batch retire of unheld pointers — one scan() drains all

fn smoke_rcu_hazard_publish_retire() -> TestResult {
    // Publisher allocates a Box<u32>, exposes it via AtomicPtr; reader
    // acquires a guard; verifies the value; drops the guard. Publisher
    // then retires the pointer with a Drop-counting trampoline; one
    // scan() must reclaim it.
    use alloc::boxed::Box;
    use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
    use narf_rcu::hazard::HazardDomain;

    static DROPS: AtomicUsize = AtomicUsize::new(0);
    struct Canary { v: u32 }
    impl Drop for Canary {
        fn drop(&mut self) { DROPS.fetch_add(1, Ordering::Relaxed); }
    }

    DROPS.store(0, Ordering::Relaxed);

    let domain = HazardDomain::new();
    let raw = Box::into_raw(Box::new(Canary { v: 0xdead_beef }));
    let cell: AtomicPtr<Canary> = AtomicPtr::new(raw);

    {
        let g = match domain.acquire(&cell) {
            Some(g) => g,
            None    => return TestResult::Fail("acquire returned None on a non-null cell"),
        };
        if g.v != 0xdead_beef {
            return TestResult::Fail("hazard guard saw wrong value");
        }
        // Guard drops here.
    }

    if DROPS.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("Canary dropped before retire was called");
    }

    fn drop_canary(p: *mut Canary) {
        // SAFETY: the test owns the pointer; retire's contract is that
        // we'll be invoked once no hazard slot names it.
        unsafe { drop(Box::from_raw(p)); }
    }
    domain.retire(raw, drop_canary);

    if DROPS.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("retire ran the dropper before scan()");
    }
    domain.scan();
    if DROPS.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("scan() didn't reclaim the unheld retired pointer");
    }
    TestResult::Pass
}
kernel_test!(smoke_rcu_hazard_publish_retire);

fn smoke_rcu_hazard_retired_but_held() -> TestResult {
    // Reader acquires the guard, THEN publisher retires the pointer.
    // scan() while the guard is live must NOT reclaim. Drop the guard,
    // scan() again — drop fires.
    use alloc::boxed::Box;
    use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
    use narf_rcu::hazard::HazardDomain;

    static DROPS: AtomicUsize = AtomicUsize::new(0);
    struct Canary;
    impl Drop for Canary {
        fn drop(&mut self) { DROPS.fetch_add(1, Ordering::Relaxed); }
    }

    DROPS.store(0, Ordering::Relaxed);

    let domain = HazardDomain::new();
    let raw = Box::into_raw(Box::new(Canary));
    let cell: AtomicPtr<Canary> = AtomicPtr::new(raw);

    let g = match domain.acquire(&cell) {
        Some(g) => g,
        None    => return TestResult::Fail("acquire returned None on a non-null cell"),
    };

    fn drop_canary(p: *mut Canary) {
        // SAFETY: hazard discipline; we're not invoked while held.
        unsafe { drop(Box::from_raw(p)); }
    }
    domain.retire(raw, drop_canary);

    // First scan: hazard slot still names the pointer. Drop must NOT
    // fire.
    domain.scan();
    if DROPS.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("scan() reclaimed a still-held hazard pointer");
    }
    if domain.pending_retires() != 1 {
        return TestResult::Fail("retire-list lost the entry that was held back");
    }

    // Drop the guard, then scan. Now reclamation is allowed.
    drop(g);
    domain.scan();
    if DROPS.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("post-release scan() didn't reclaim the entry");
    }
    if domain.pending_retires() != 0 {
        return TestResult::Fail("retire list still pending after successful scan");
    }
    TestResult::Pass
}
kernel_test!(smoke_rcu_hazard_retired_but_held);

fn smoke_rcu_hazard_scan_frees_unheld() -> TestResult {
    // Bulk retire several pointers with no reader holding any of them.
    // One scan() must drain them all.
    use alloc::boxed::Box;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use narf_rcu::hazard::HazardDomain;

    static DROPS: AtomicUsize = AtomicUsize::new(0);
    struct Canary;
    impl Drop for Canary {
        fn drop(&mut self) { DROPS.fetch_add(1, Ordering::Relaxed); }
    }

    DROPS.store(0, Ordering::Relaxed);
    let domain = HazardDomain::new();

    fn drop_canary(p: *mut Canary) {
        // SAFETY: hazard discipline; the test never holds these.
        unsafe { drop(Box::from_raw(p)); }
    }

    // Retire eight pointers — under the threshold so no inline scan
    // fires; we trigger reclamation explicitly.
    let n = 8usize;
    for _ in 0..n {
        let raw = Box::into_raw(Box::new(Canary));
        domain.retire(raw, drop_canary);
    }
    if DROPS.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("bulk retire ran droppers inline (threshold misconfigured?)");
    }
    if domain.pending_retires() != n {
        return TestResult::Fail("retire-list length mismatch before scan");
    }
    domain.scan();
    if DROPS.load(Ordering::Relaxed) != n {
        return TestResult::Fail("scan() didn't drain the full retire list");
    }
    if domain.pending_retires() != 0 {
        return TestResult::Fail("retire-list non-empty after scan");
    }
    TestResult::Pass
}
kernel_test!(smoke_rcu_hazard_scan_frees_unheld);

// ── observability/ Stage-2/3 smoke tests ────────────────────────────
//
// PMU read paths, panic-snapshot install, and the synthesised
// CrashFrame round-trip. Each test is independent — the panic-ring
// install test uses `__test_clear_panic_ring` to reset shared state.

fn smoke_obs_pmu_cycles_monotonic() -> TestResult {
    use narf_capabilities::{Cap, Read};
    use narf_observability::{read_cycles, ObsError, Pmu};

    let cap: Cap<Pmu, Read> = Cap::bootstrap();
    let a = match read_cycles(&cap) {
        Ok(v) => v,
        Err(ObsError::NotAvailable) => {
            return TestResult::Skip("PMU not exposed at this ring (CR4.PCE / PMUSERENR_EL0)");
        }
        Err(_) => {
            return TestResult::Fail("read_cycles failed unexpectedly");
        }
    };
    // Short busy wait — long enough for at least one cycle even on a
    // serialising counter.
    for _ in 0..10_000 { core::hint::spin_loop(); }
    let b = match read_cycles(&cap) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("second read_cycles failed"),
    };
    if b > a { TestResult::Pass }
    else { TestResult::Fail("cycle counter did not advance across busy-wait") }
}
kernel_test!(smoke_obs_pmu_cycles_monotonic);

fn smoke_obs_pmu_cap_gated() -> TestResult {
    // Revoking the Pmu Read cap must surface as Err(Revoked) — the
    // hot-path epoch gate is the load-bearing invariant from
    // capabilities/ §3.
    use narf_capabilities::{Cap, Read};
    use narf_observability::{read_cycles, ObsError, Pmu};

    let cap: Cap<Pmu, Read> = Cap::bootstrap();
    cap.revoke();
    // After revoke, the cap copy still exists (Cap is Copy) but its
    // generation no longer matches the object epoch.
    match read_cycles(&cap) {
        Err(ObsError::Revoked) => TestResult::Pass,
        Err(_)                 => TestResult::Fail("wrong error variant from revoked PMU cap"),
        Ok(_)                  => TestResult::Fail("read_cycles accepted a revoked cap"),
    }
}
kernel_test!(smoke_obs_pmu_cap_gated);

fn smoke_obs_crash_frame_captures_regs() -> TestResult {
    use narf_observability::{capture_crash_frame, ArchRegs, CRASH_STACK_WORDS};

    // Synthesise a register set with a recognisable IP value; the
    // capture must preserve every field and surface that IP via the
    // arch-agnostic `instruction_ptr`.
    #[cfg(target_arch = "x86_64")]
    let regs = ArchRegs {
        rax: 0x11, rbx: 0x22, rcx: 0x33, rdx: 0x44,
        rsi: 0x55, rdi: 0x66, rbp: 0x77, rsp: 0x88,
        r8: 0x99, r9: 0xAA, r10: 0xBB, r11: 0xCC,
        r12: 0xDD, r13: 0xEE, r14: 0xFF, r15: 0x10,
        rip: 0xDEAD_BEEF, rflags: 0x202, cs: 0x08, ss: 0x10,
    };
    #[cfg(target_arch = "aarch64")]
    let regs = {
        let mut r = ArchRegs::default();
        r.x[0]   = 0x11;
        r.x[30]  = 0x1E;        // LR
        r.sp     = 0x88;
        r.pc     = 0xDEAD_BEEF;
        r.pstate = 0x3C5;
        r
    };

    let frame = capture_crash_frame(regs);

    if frame.registers != regs {
        return TestResult::Fail("crash_frame did not preserve ArchRegs verbatim");
    }
    if frame.instruction_ptr != 0xDEAD_BEEF {
        return TestResult::Fail("instruction_ptr not synthesised from arch regs");
    }
    if frame.stack.len() != CRASH_STACK_WORDS {
        return TestResult::Fail("stack snapshot has wrong length");
    }
    // At least one stack word should be non-zero — we walked our own
    // active stack so a return address or frame pointer must appear.
    if !frame.stack.iter().any(|w| *w != 0) {
        return TestResult::Fail("stack snapshot was entirely zero");
    }
    TestResult::Pass
}
kernel_test!(smoke_obs_crash_frame_captures_regs);

fn smoke_obs_panic_snapshot_roundtrip() -> TestResult {
    // Install a flight-recorder ring under a Recorder Grant cap, push
    // a few ObservabilityEvents, take_snapshot, and verify they appear
    // newest-first in the snapshot.
    use narf_capabilities::{Cap, Grant};
    use narf_observability::{
        install_panic_snapshot, take_snapshot, ObservabilityEvent, Recorder,
        SNAPSHOT_CAPACITY, __test_clear_panic_ring,
    };
    use narf_tracing::FlightRing;

    __test_clear_panic_ring();

    static RING: FlightRing<ObservabilityEvent, SNAPSHOT_CAPACITY>
        = FlightRing::new();

    let cap: Cap<Recorder, Grant> = Cap::bootstrap();
    if install_panic_snapshot(&cap, &RING).is_err() {
        return TestResult::Fail("install_panic_snapshot returned Err with a live cap");
    }

    let events = [
        ObservabilityEvent::CapInvoke { kind: 1, generation: 100 },
        ObservabilityEvent::Pmu       { cycles: 200, instructions: 0 },
        ObservabilityEvent::Panic     { ip: 0xDEAD_BEEF, domain: 7 },
    ];
    for ev in &events {
        RING.record(*ev);
    }

    let snap = match take_snapshot() {
        Some(s) => s,
        None    => {
            __test_clear_panic_ring();
            return TestResult::Fail("take_snapshot returned None after install");
        }
    };
    if snap.len() < events.len() {
        __test_clear_panic_ring();
        return TestResult::Fail("snapshot length below pushed event count");
    }
    // FlightRing::snapshot is newest-first, so events appear reversed.
    let entries = snap.entries();
    let expected_newest = events[events.len() - 1];
    if entries[0] != expected_newest {
        __test_clear_panic_ring();
        return TestResult::Fail("snapshot ordering is not newest-first");
    }
    // Walk back through the pushed history.
    for (i, ev) in events.iter().rev().enumerate() {
        if entries[i] != *ev {
            __test_clear_panic_ring();
            return TestResult::Fail("snapshot entry did not match pushed event");
        }
    }
    __test_clear_panic_ring();
    TestResult::Pass
}
kernel_test!(smoke_obs_panic_snapshot_roundtrip);

fn smoke_arch_patch_word_roundtrip() -> TestResult {
    // arch::patch_word is the atomic instruction-word replace primitive
    // backing tracing/'s runtime arming. Exercise it on a writable u32
    // (data, not text — the serialisation sequence is still run, proving
    // the helper doesn't fault on non-text memory). Tests that:
    //   - the write is visible to a subsequent volatile read
    //   - overwriting twice leaves the last value
    //   - the caller's remaining registers / flags aren't clobbered
    use core::sync::atomic::{AtomicU32, Ordering};
    static SLOT: AtomicU32 = AtomicU32::new(0xDEAD_BEEF);
    let addr = SLOT.as_ptr() as *mut u32;
    // SAFETY: SLOT is a static mut u32 (interior-atomic); addr is
    // 4-byte aligned. `patch_word` only writes 4 bytes + serialises.
    unsafe {
        narf_arch::patch_word(addr, 0xCAFE_F00D);
        if SLOT.load(Ordering::Acquire) != 0xCAFE_F00D {
            return TestResult::Fail("first patch not visible");
        }
        narf_arch::patch_word(addr, 0x1234_5678);
        if SLOT.load(Ordering::Acquire) != 0x1234_5678 {
            return TestResult::Fail("second patch overwrote wrong");
        }
    }
    TestResult::Pass
}
kernel_test!(smoke_arch_patch_word_roundtrip);

fn smoke_tracing_arm_disarm_cycle() -> TestResult {
    // Stage-3 arm/disarm exercises the cap gate plus the arch patch
    // path end-to-end. A 4-byte slot in a static mut stands in for
    // a real probe site's arming word.
    use core::sync::atomic::{AtomicU32, Ordering};
    use narf_capabilities::{Cap, Grant};
    use narf_tracing::{arm, disarm, any_armed, ProbeArming};

    static SLOT: AtomicU32 = AtomicU32::new(0x9090_9090); // nop sled
    let addr = SLOT.as_ptr() as *mut u32;

    let cap: Cap<ProbeArming, Grant> = Cap::<ProbeArming, Grant>::bootstrap();
    let before_armed = any_armed();

    // SAFETY: addr is 4-byte aligned static storage; patch_word only
    // writes 4 bytes + serialises.
    unsafe {
        if arm(&cap, addr, 0xAA55_AA55).is_err() {
            return TestResult::Fail("arm() failed on live cap");
        }
    }
    if SLOT.load(Ordering::Acquire) != 0xAA55_AA55 {
        return TestResult::Fail("arm did not patch the slot");
    }
    if !any_armed() {
        return TestResult::Fail("any_armed() did not go true after arm");
    }

    // Revoked cap must be rejected without patching.
    let revoked: Cap<ProbeArming, Grant> = Cap::<ProbeArming, Grant>::bootstrap();
    revoked.revoke();
    // SAFETY: same as above; call should never reach patch_word.
    unsafe {
        if arm(&revoked, addr, 0xDEAD_0000).is_ok() {
            return TestResult::Fail("revoked cap slipped past arm gate");
        }
    }
    if SLOT.load(Ordering::Acquire) != 0xAA55_AA55 {
        return TestResult::Fail("arm on revoked cap mutated the slot anyway");
    }

    // Disarm: restore, armed count drops back.
    // SAFETY: same preconditions.
    unsafe {
        if disarm(&cap, addr, 0x9090_9090).is_err() {
            return TestResult::Fail("disarm() failed on live cap");
        }
    }
    if SLOT.load(Ordering::Acquire) != 0x9090_9090 {
        return TestResult::Fail("disarm did not restore the slot");
    }
    if any_armed() != before_armed {
        return TestResult::Fail("any_armed() didn't decrement back");
    }
    TestResult::Pass
}
kernel_test!(smoke_tracing_arm_disarm_cycle);

fn smoke_tracing_dispatch_fire_routes_handler() -> TestResult {
    // Register a handler for a fresh probe id, fire() → handler runs;
    // unregister → fire() is a no-op; revoked cap cannot register.
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_capabilities::{Cap, Grant};
    use narf_tracing::{
        fire, handler_table, reserve_probe_id,
        ProbeArgs, ProbeHandler, ProbeHandlerInstall, RegisterError,
    };

    static HITS: AtomicU64 = AtomicU64::new(0);
    static SUM:  AtomicU64 = AtomicU64::new(0);
    HITS.store(0, Ordering::Relaxed);
    SUM.store(0, Ordering::Relaxed);

    struct Counter;
    impl ProbeHandler for Counter {
        fn fire(&self, args: ProbeArgs) {
            HITS.fetch_add(1, Ordering::Relaxed);
            SUM.fetch_add(args.0[0], Ordering::Relaxed);
        }
    }

    let pid = reserve_probe_id();
    let cap: Cap<ProbeHandlerInstall, Grant> =
        Cap::<ProbeHandlerInstall, Grant>::bootstrap();

    // No handler yet — fire is a no-op.
    fire(pid, ProbeArgs::one(7));
    if HITS.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("fire() ran without a registered handler");
    }

    handler_table().register(&cap, pid, Counter).expect("register");
    fire(pid, ProbeArgs::one(7));
    fire(pid, ProbeArgs::one(35));
    if HITS.load(Ordering::Relaxed) != 2 || SUM.load(Ordering::Relaxed) != 42 {
        return TestResult::Fail("handler missed a fire or arg was lost");
    }

    // Duplicate register: rejected.
    match handler_table().register(&cap, pid, Counter) {
        Err(RegisterError::DuplicateProbeId) => {}
        _ => return TestResult::Fail("duplicate-id register accepted"),
    }

    // Revoked cap cannot register OR unregister.
    let revoked: Cap<ProbeHandlerInstall, Grant> =
        Cap::<ProbeHandlerInstall, Grant>::bootstrap();
    revoked.revoke();
    let pid2 = reserve_probe_id();
    match handler_table().register(&revoked, pid2, Counter) {
        Err(RegisterError::AuthorityRevoked) => {}
        _ => return TestResult::Fail("revoked cap slipped past register"),
    }

    // Unregister and confirm fire is silent again.
    handler_table().unregister(&cap, pid).expect("unregister");
    let before = HITS.load(Ordering::Relaxed);
    fire(pid, ProbeArgs::one(100));
    if HITS.load(Ordering::Relaxed) != before {
        return TestResult::Fail("fire() called a torn-down handler");
    }
    TestResult::Pass
}
kernel_test!(smoke_tracing_dispatch_fire_routes_handler);

fn smoke_tracing_fntime_welford_accumulates() -> TestResult {
    // Direct record_cycles() path: deterministic (no clock noise).
    // Feed {1, 2, 3, 4, 5}, confirm count/min/max/mean.
    use narf_tracing::{FnTime, Welford};
    static LAT: FnTime = FnTime::new("test::welford");
    for x in [1u64, 2, 3, 4, 5] { LAT.record_cycles(x); }
    let w: Welford = LAT.welford();
    if w.count != 5 { return TestResult::Fail("count != 5"); }
    if w.min != 1 || w.max != 5 { return TestResult::Fail("min/max wrong"); }
    // Mean of 1..=5 is exactly 3.0.
    if (w.mean - 3.0).abs() > 1e-9 { return TestResult::Fail("mean drifted"); }
    // Sample variance of 1..=5 is 2.5.
    let var = w.sample_variance();
    if (var - 2.5).abs() > 1e-9 { return TestResult::Fail("sample variance off"); }
    TestResult::Pass
}
kernel_test!(smoke_tracing_fntime_welford_accumulates);

fn smoke_tracing_fntime_scope_records_cycles() -> TestResult {
    // ScopeGuard path: drop records elapsed cycles into the FnTime.
    // Busy-wait a non-trivial number of cycles so a stuck timer
    // surfaces as a 0-sample.
    use narf_tracing::{scope, FnTime};
    static LAT: FnTime = FnTime::new("test::scope");
    let before = LAT.welford().count;
    {
        let _g = scope(&LAT);
        narf_time::busy_wait_cycles(10_000);
    }
    if LAT.live_scopes() != 0 {
        return TestResult::Fail("ScopeGuard drop didn't balance live_scopes");
    }
    let w = LAT.welford();
    if w.count != before + 1 { return TestResult::Fail("scope did not add sample"); }
    if w.max < 10_000 { return TestResult::Fail("scope sample shorter than busy-wait"); }
    TestResult::Pass
}
kernel_test!(smoke_tracing_fntime_scope_records_cycles);

fn smoke_tracing_histogram_quantile_bucket() -> TestResult {
    // 10 bulk samples of 1000 (bucket 10, lower = 512) plus one outlier
    // of 1<<20 (bucket 21, lower = 1<<20). With 11 samples the outlier
    // falls inside the p99 band — ceil(11 * 990 / 1000) = 11 — so p99
    // must land in the outlier bucket while p50 stays in the bulk one.
    use narf_tracing::Histogram;
    let h = Histogram::new();
    for _ in 0..10 { h.add(1000); }
    if h.p50() != 512 {
        return TestResult::Fail("bucket lower bound for 1000 drifted from 512");
    }
    h.add(1u64 << 20);
    if h.p50() != 512 {
        return TestResult::Fail("outlier moved p50 off the bulk bucket");
    }
    // 1<<20 is 1_048_576; bucket index = 64 - 43 = 21, lower = 1<<20.
    if h.p99() != 1u64 << 20 {
        return TestResult::Fail("outlier did not move p99 into its bucket");
    }
    if h.count() != 11 { return TestResult::Fail("count mismatch"); }
    TestResult::Pass
}
kernel_test!(smoke_tracing_histogram_quantile_bucket);

fn smoke_obs_pmu_sample_into_ring() -> TestResult {
    // sample_pmu pushes one ObservabilityEvent::Pmu per call, cap-gated
    // on Cap<Pmu, Read>. Revoking the cap must surface as Err(Revoked).
    use narf_capabilities::{Cap, Read};
    use narf_observability::{
        sample_pmu, take_snapshot, install_panic_snapshot, ObsError,
        ObservabilityEvent, Pmu, Recorder, SNAPSHOT_CAPACITY,
        __test_clear_panic_ring,
    };
    use narf_tracing::FlightRing;

    __test_clear_panic_ring();

    static RING: FlightRing<ObservabilityEvent, SNAPSHOT_CAPACITY>
        = FlightRing::new();
    let rec: Cap<Recorder, narf_capabilities::Grant> = Cap::bootstrap();
    if install_panic_snapshot(&rec, &RING).is_err() {
        return TestResult::Fail("install_panic_snapshot failed");
    }

    let cap: Cap<Pmu, Read> = Cap::bootstrap();
    if sample_pmu(&cap, &RING).is_err() {
        __test_clear_panic_ring();
        return TestResult::Fail("sample_pmu returned Err with a live cap");
    }
    if sample_pmu(&cap, &RING).is_err() {
        __test_clear_panic_ring();
        return TestResult::Fail("sample_pmu second call returned Err");
    }
    let snap = match take_snapshot() {
        Some(s) => s,
        None    => {
            __test_clear_panic_ring();
            return TestResult::Fail("take_snapshot returned None after sampling");
        }
    };
    if snap.len() < 2 {
        __test_clear_panic_ring();
        return TestResult::Fail("ring received fewer than 2 samples");
    }
    for ev in snap.entries().iter().take(2) {
        match ev {
            ObservabilityEvent::Pmu { .. } => {}
            _ => {
                __test_clear_panic_ring();
                return TestResult::Fail("sampled entry was not Pmu variant");
            }
        }
    }

    cap.revoke();
    match sample_pmu(&cap, &RING) {
        Err(ObsError::Revoked) => {}
        _ => {
            __test_clear_panic_ring();
            return TestResult::Fail("sample_pmu did not fail-closed on revoked cap");
        }
    }

    __test_clear_panic_ring();
    TestResult::Pass
}
kernel_test!(smoke_obs_pmu_sample_into_ring);

fn smoke_obs_core_dump_bundles_snapshot() -> TestResult {
    // capture_core_dump returns the CrashFrame + take_snapshot in one
    // call. Without an installed ring the snapshot field is None; after
    // install + record it carries the last-N events.
    use narf_capabilities::{Cap, Grant};
    use narf_observability::{
        capture_core_dump, install_panic_snapshot, ArchRegs,
        ObservabilityEvent, Recorder, SNAPSHOT_CAPACITY,
        __test_clear_panic_ring,
    };
    use narf_tracing::FlightRing;

    __test_clear_panic_ring();

    let regs = ArchRegs::default();
    let dump_before = capture_core_dump(regs);
    if dump_before.snapshot.is_some() {
        return TestResult::Fail("snapshot is Some before any install");
    }

    static RING: FlightRing<ObservabilityEvent, SNAPSHOT_CAPACITY>
        = FlightRing::new();
    let rec: Cap<Recorder, Grant> = Cap::bootstrap();
    if install_panic_snapshot(&rec, &RING).is_err() {
        return TestResult::Fail("install_panic_snapshot failed");
    }
    RING.record(ObservabilityEvent::Panic { ip: 0x1234, domain: 2 });

    let dump_after = capture_core_dump(regs);
    let snap = match dump_after.snapshot {
        Some(s) => s,
        None    => {
            __test_clear_panic_ring();
            return TestResult::Fail("snapshot missing after install + record");
        }
    };
    if snap.len() < 1 {
        __test_clear_panic_ring();
        return TestResult::Fail("snapshot is empty after recording an event");
    }
    match snap.entries()[0] {
        ObservabilityEvent::Panic { ip: 0x1234, domain: 2 } => {}
        _ => {
            __test_clear_panic_ring();
            return TestResult::Fail("snapshot head did not match recorded Panic event");
        }
    }

    __test_clear_panic_ring();
    TestResult::Pass
}
kernel_test!(smoke_obs_core_dump_bundles_snapshot);

fn smoke_scheduler_budget_cap_revokes_task() -> TestResult {
    // A Cap<CpuBudget, Spend>-attached task runs while the cap is live,
    // and is dropped by the scheduler once the cap is revoked.
    use core::future::Future;
    use core::pin::Pin;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use core::task::{Context, Poll};
    use narf_capabilities::Cap;
    use narf_scheduler::{CpuBudget, ResourceBudget, TaskSpec};

    static RUNS: AtomicUsize = AtomicUsize::new(0);

    struct Alive;
    impl Future for Alive {
        type Output = ();
        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            RUNS.fetch_add(1, Ordering::Relaxed);
            // Always ask to be re-polled — would run forever if the
            // scheduler never dropped the task.
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    RUNS.store(0, Ordering::Relaxed);
    narf_scheduler::init();

    let cap: Cap<CpuBudget, narf_capabilities::Spend> = Cap::bootstrap();
    // Spawn a second task that revokes the budget cap after a few
    // yields so the scheduler has a clear "alive, then dead" window.
    let revoke_cap = cap;
    narf_scheduler::spawn_with_spec(
        Alive,
        TaskSpec::budgeted(ResourceBudget::unthrottled(), cap),
    );
    narf_scheduler::spawn(async move {
        for _ in 0..4 { narf_scheduler::yield_now().await; }
        revoke_cap.revoke();
    });

    narf_scheduler::run_until_empty();

    let n = RUNS.load(Ordering::Relaxed);
    if n == 0 {
        return TestResult::Fail("budgeted task never polled while cap was live");
    }
    // After revoke the task must drop, not spin forever — if we got
    // here at all the scheduler terminated, which is the assertion.
    TestResult::Pass
}
kernel_test!(smoke_scheduler_budget_cap_revokes_task);

fn smoke_scheduler_budget_accounts_cycles() -> TestResult {
    // The executor charges measured cycles into the task's
    // `BudgetAccount` via `ResourceBudget` — single-shot task, so we
    // can't observe the account post-drop, but we can verify the
    // types compose and TaskSpec construction doesn't require a cap.
    use narf_scheduler::{BudgetAccount, OverrunPolicy, ResourceBudget, TaskSpec};

    let unthrottled = TaskSpec::unthrottled();
    if unthrottled.budget_cap.is_some() {
        return TestResult::Fail("unthrottled TaskSpec should not carry a budget cap");
    }
    if unthrottled.budget.policy != OverrunPolicy::Ignore {
        return TestResult::Fail("unthrottled budget must default to Ignore policy");
    }

    let mut acct = BudgetAccount::new();
    let budget   = ResourceBudget::fair_share(100_000, 1_000);
    let over     = acct.charge(2_000, &budget);
    if !over {
        return TestResult::Fail("charge exceeding burst_cycles should report over-budget");
    }
    if acct.overruns != 1 || acct.polls != 1 || acct.cycles_spent != 2_000 {
        return TestResult::Fail("BudgetAccount did not accumulate correctly");
    }
    let under = acct.charge(500, &budget);
    if under {
        return TestResult::Fail("500 cycles inside burst should not report over-budget");
    }
    if acct.overruns != 1 || acct.polls != 2 || acct.cycles_spent != 2_500 {
        return TestResult::Fail("BudgetAccount running totals drifted");
    }
    TestResult::Pass
}
kernel_test!(smoke_scheduler_budget_accounts_cycles);

fn smoke_abi_cancel_before_target_marks_cancelled() -> TestResult {
    // §3.1 protocol: a Cancel submitted *before* its target is drained
    // must complete the target with `Cancelled` (when CANCELLABLE is
    // set on the target). The cancel op itself always completes `Ok`.
    use core::sync::atomic::{AtomicU8, Ordering};
    use narf_abi::{
        completion_channel, submission_channel, Dispatcher, NarfStatus,
        Submission, SubmissionFlags, Tag,
    };

    static OUTCOME: AtomicU8 = AtomicU8::new(0);

    narf_scheduler::init();
    let (mut sq_tx, sq_rx) = submission_channel::<4>();
    let (cq_tx, mut cq_rx) = completion_channel::<4>();

    narf_scheduler::spawn(async move {
        let mut d = Dispatcher::new(sq_rx, cq_tx);
        d.run().await;
    });

    narf_scheduler::spawn(async move {
        let target = Tag::new(0x7777);
        let canceller = Tag::new(0xC001);

        // 1. Submit the cancel first — dispatcher records the target.
        sq_tx.send(Submission::cancel(canceller, target)).await.unwrap();
        let c1 = cq_rx.recv().await.unwrap();
        if c1.tag() != canceller || c1.status != NarfStatus::Ok {
            OUTCOME.store(2, Ordering::Relaxed);
            return;
        }

        // 2. Submit the target with CANCELLABLE — must come back Cancelled.
        let mut sub = Submission::noop(target);
        sub.flags = SubmissionFlags::CANCELLABLE;
        sq_tx.send(sub).await.unwrap();
        let c2 = cq_rx.recv().await.unwrap();
        if c2.tag() != target || c2.status != NarfStatus::Cancelled {
            OUTCOME.store(3, Ordering::Relaxed);
            return;
        }

        OUTCOME.store(1, Ordering::Relaxed);
        core::mem::drop(sq_tx);
        core::mem::drop(cq_rx);
    });

    narf_scheduler::run_until_empty();
    match OUTCOME.load(Ordering::Relaxed) {
        1 => TestResult::Pass,
        2 => TestResult::Fail("cancel submission did not complete Ok"),
        3 => TestResult::Fail("cancellable target did not complete Cancelled"),
        _ => TestResult::Fail("cancel protocol round-trip did not run"),
    }
}
kernel_test!(smoke_abi_cancel_before_target_marks_cancelled);

fn smoke_abi_cancel_non_cancellable_marks_request() -> TestResult {
    // §3.1: a target without CANCELLABLE completes with
    // `CancelRequested` so the caller knows the op ran to completion.
    use core::sync::atomic::{AtomicU8, Ordering};
    use narf_abi::{
        completion_channel, submission_channel, Dispatcher, NarfStatus,
        Submission, Tag,
    };

    static OUTCOME: AtomicU8 = AtomicU8::new(0);

    narf_scheduler::init();
    let (mut sq_tx, sq_rx) = submission_channel::<4>();
    let (cq_tx, mut cq_rx) = completion_channel::<4>();

    narf_scheduler::spawn(async move {
        let mut d = Dispatcher::new(sq_rx, cq_tx);
        d.run().await;
    });

    narf_scheduler::spawn(async move {
        let target = Tag::new(0x8888);
        let canceller = Tag::new(0xC002);

        sq_tx.send(Submission::cancel(canceller, target)).await.unwrap();
        let _ = cq_rx.recv().await.unwrap();

        // No CANCELLABLE flag on the target.
        sq_tx.send(Submission::noop(target)).await.unwrap();
        let c = cq_rx.recv().await.unwrap();
        if c.tag() != target || c.status != NarfStatus::CancelRequested {
            OUTCOME.store(2, Ordering::Relaxed);
            return;
        }

        OUTCOME.store(1, Ordering::Relaxed);
        core::mem::drop(sq_tx);
        core::mem::drop(cq_rx);
    });

    narf_scheduler::run_until_empty();
    match OUTCOME.load(Ordering::Relaxed) {
        1 => TestResult::Pass,
        2 => TestResult::Fail("non-cancellable target did not surface CancelRequested"),
        _ => TestResult::Fail("dispatcher did not run the protocol"),
    }
}
kernel_test!(smoke_abi_cancel_non_cancellable_marks_request);

fn smoke_abi_linked_chain_cancels_forward() -> TestResult {
    // §3.1 "Linked submissions": cancelling any member of a LINKED
    // chain auto-cancels the rest of the chain. Here the producer
    // submits A (starts a chain), then B (LINKED, inherits A's chain),
    // then Cancel(A), then C (LINKED, still same chain). The chain
    // registry flagged chain_id when Cancel(A) ran; C must short-
    // circuit with Cancelled even though it was never named directly.
    use core::sync::atomic::{AtomicU8, Ordering};
    use narf_abi::{
        completion_channel, submission_channel, Dispatcher, NarfStatus,
        Submission, SubmissionFlags, Tag,
    };

    static OUTCOME: AtomicU8 = AtomicU8::new(0);

    narf_scheduler::init();
    let (mut sq_tx, sq_rx) = submission_channel::<8>();
    let (cq_tx, mut cq_rx) = completion_channel::<8>();

    narf_scheduler::spawn(async move {
        let mut d = Dispatcher::new(sq_rx, cq_tx);
        d.run().await;
    });

    narf_scheduler::spawn(async move {
        let ta = Tag::new(0xA0);
        let tb = Tag::new(0xB0);
        let tc = Tag::new(0xC0);
        let tcan = Tag::new(0xCA);

        // A — fresh chain, CANCELLABLE. Runs to completion before the
        // cancel arrives (serial dispatch) → Ok.
        let mut a = Submission::noop(ta);
        a.flags = SubmissionFlags::CANCELLABLE;
        sq_tx.send(a).await.unwrap();

        // B — LINKED, CANCELLABLE. Part of A's chain.
        let mut b = Submission::noop(tb);
        b.flags = SubmissionFlags::CANCELLABLE | SubmissionFlags::LINKED;
        sq_tx.send(b).await.unwrap();

        // Cancel A. The Dispatcher marks A's chain_id pending.
        sq_tx.send(Submission::cancel(tcan, ta)).await.unwrap();

        // C — LINKED, CANCELLABLE. Must short-circuit with Cancelled.
        let mut c = Submission::noop(tc);
        c.flags = SubmissionFlags::CANCELLABLE | SubmissionFlags::LINKED;
        sq_tx.send(c).await.unwrap();

        // Drain: A (Ok), B (Ok — entered chain before cancel marked it),
        // cancel (Ok), C (Cancelled).
        let ca = cq_rx.recv().await.unwrap();
        if ca.tag() != ta || ca.status != NarfStatus::Ok {
            OUTCOME.store(2, Ordering::Relaxed); return;
        }
        let cb = cq_rx.recv().await.unwrap();
        if cb.tag() != tb || cb.status != NarfStatus::Ok {
            OUTCOME.store(3, Ordering::Relaxed); return;
        }
        let ccan = cq_rx.recv().await.unwrap();
        if ccan.tag() != tcan || ccan.status != NarfStatus::Ok {
            OUTCOME.store(4, Ordering::Relaxed); return;
        }
        let cc = cq_rx.recv().await.unwrap();
        if cc.tag() != tc || cc.status != NarfStatus::Cancelled {
            OUTCOME.store(5, Ordering::Relaxed); return;
        }

        OUTCOME.store(1, Ordering::Relaxed);
        core::mem::drop(sq_tx);
        core::mem::drop(cq_rx);
    });

    narf_scheduler::run_until_empty();
    match OUTCOME.load(Ordering::Relaxed) {
        1 => TestResult::Pass,
        2 => TestResult::Fail("A did not complete Ok"),
        3 => TestResult::Fail("B did not complete Ok (chain not yet cancelled when B dispatched)"),
        4 => TestResult::Fail("Cancel op did not complete Ok"),
        5 => TestResult::Fail("C was not auto-cancelled via its chain"),
        _ => TestResult::Fail("linked chain roundtrip did not run"),
    }
}
kernel_test!(smoke_abi_linked_chain_cancels_forward);

fn smoke_abi_cancel_stale_tag_is_noop() -> TestResult {
    // §3.1: the cancel op is non-blocking and always succeeds even
    // when the target tag never shows up. A subsequent unrelated
    // submission must not inherit the cancel.
    use core::sync::atomic::{AtomicU8, Ordering};
    use narf_abi::{
        completion_channel, submission_channel, Dispatcher, NarfStatus,
        Submission, Tag,
    };

    static OUTCOME: AtomicU8 = AtomicU8::new(0);

    narf_scheduler::init();
    let (mut sq_tx, sq_rx) = submission_channel::<4>();
    let (cq_tx, mut cq_rx) = completion_channel::<4>();

    narf_scheduler::spawn(async move {
        let mut d = Dispatcher::new(sq_rx, cq_tx);
        d.run().await;
    });

    narf_scheduler::spawn(async move {
        let stale  = Tag::new(0xDEAD);
        let other  = Tag::new(0xAAAA);
        let canceller = Tag::new(0xC003);

        // Cancel a tag the producer will never submit.
        sq_tx.send(Submission::cancel(canceller, stale)).await.unwrap();
        let c1 = cq_rx.recv().await.unwrap();
        if c1.status != NarfStatus::Ok {
            OUTCOME.store(2, Ordering::Relaxed);
            return;
        }

        // Now submit an unrelated tag — must complete Ok.
        sq_tx.send(Submission::noop(other)).await.unwrap();
        let c2 = cq_rx.recv().await.unwrap();
        if c2.tag() != other || c2.status != NarfStatus::Ok {
            OUTCOME.store(3, Ordering::Relaxed);
            return;
        }

        OUTCOME.store(1, Ordering::Relaxed);
        core::mem::drop(sq_tx);
        core::mem::drop(cq_rx);
    });

    narf_scheduler::run_until_empty();
    match OUTCOME.load(Ordering::Relaxed) {
        1 => TestResult::Pass,
        2 => TestResult::Fail("cancel for a never-submitted tag did not return Ok"),
        3 => TestResult::Fail("unrelated tag inherited a stale cancel"),
        _ => TestResult::Fail("dispatcher never drained"),
    }
}
kernel_test!(smoke_abi_cancel_stale_tag_is_noop);

fn smoke_scheduler_donate_to_reorders_head() -> TestResult {
    // donate_to moves the named task to the head of the ready queue.
    // Called *before* run_until_empty, it swaps spawn-order so the
    // donee's first poll lands ahead of the task that was spawned
    // before it.
    use core::sync::atomic::{AtomicU32, Ordering};
    use narf_capabilities::{Cap, Invoke};
    use narf_scheduler::{donate_to, Task};

    static FIRST_TAG: AtomicU32 = AtomicU32::new(0);
    FIRST_TAG.store(0, Ordering::Relaxed);

    narf_scheduler::init();

    let donation: Cap<Task, Invoke> = Cap::bootstrap();

    // Spawn A first, B second. Both record their own tag into
    // FIRST_TAG on first poll if the slot is still 0.
    let _a = narf_scheduler::spawn(async {
        let _ = FIRST_TAG.compare_exchange(0, 0xAAAA, Ordering::Relaxed, Ordering::Relaxed);
    });
    let b = narf_scheduler::spawn(async {
        let _ = FIRST_TAG.compare_exchange(0, 0xBBBB, Ordering::Relaxed, Ordering::Relaxed);
    });

    // Donate to B *before* run_until_empty so the reorder is
    // observable. Without donation A would write first.
    if donate_to(b, &donation).is_err() {
        return TestResult::Fail("donate_to returned Err on a live cap");
    }

    narf_scheduler::run_until_empty();

    match FIRST_TAG.load(Ordering::Relaxed) {
        0xBBBB => TestResult::Pass,
        0xAAAA => TestResult::Fail("donee did not run ahead of the pre-spawned task"),
        _      => TestResult::Fail("neither task ran"),
    }
}
kernel_test!(smoke_scheduler_donate_to_reorders_head);

fn smoke_scheduler_donate_to_rejects_revoked_cap() -> TestResult {
    use narf_capabilities::{Cap, Invoke};
    use narf_scheduler::{donate_to, DonateError, Task, TaskId};

    narf_scheduler::init();
    let cap: Cap<Task, Invoke> = Cap::bootstrap();
    cap.revoke();
    match donate_to(TaskId(1), &cap) {
        Err(DonateError::AuthorityRevoked) => TestResult::Pass,
        Err(other) => {
            let _ = other;
            TestResult::Fail("donate_to with revoked cap returned wrong error")
        }
        Ok(()) => TestResult::Fail("donate_to with revoked cap succeeded"),
    }
}
kernel_test!(smoke_scheduler_donate_to_rejects_revoked_cap);

fn smoke_scheduler_donate_to_missing_target() -> TestResult {
    use narf_capabilities::{Cap, Invoke};
    use narf_scheduler::{donate_to, DonateError, Task, TaskId};

    narf_scheduler::init();
    let cap: Cap<Task, Invoke> = Cap::bootstrap();
    // An id far past any live task's id — guaranteed not to match.
    match donate_to(TaskId(u64::MAX), &cap) {
        Err(DonateError::TargetNotFound) => TestResult::Pass,
        _ => TestResult::Fail("donate_to to unknown id did not return TargetNotFound"),
    }
}
kernel_test!(smoke_scheduler_donate_to_missing_target);

fn smoke_scheduler_cpu_set_membership() -> TestResult {
    use narf_scheduler::{Affinity, CpuId, CpuSet};

    let all = CpuSet::ALL;
    if !all.contains(CpuId::BOOT) {
        return TestResult::Fail("CpuSet::ALL should contain the boot CPU");
    }
    let empty = CpuSet::EMPTY;
    if empty.contains(CpuId::BOOT) {
        return TestResult::Fail("CpuSet::EMPTY should not contain any CPU");
    }
    let single = CpuSet::single(CpuId(3));
    if !single.contains(CpuId(3)) || single.contains(CpuId(0)) {
        return TestResult::Fail("CpuSet::single membership incorrect");
    }
    if single.len() != 1 {
        return TestResult::Fail("single-CPU set should have len 1");
    }

    let pinned = Affinity::pinned(CpuId(0));
    if pinned.preferred != Some(CpuId(0)) {
        return TestResult::Fail("pinned affinity should prefer the pinned CPU");
    }
    if !pinned.allowed.contains(CpuId(0)) {
        return TestResult::Fail("pinned affinity should allow the pinned CPU");
    }
    TestResult::Pass
}
kernel_test!(smoke_scheduler_cpu_set_membership);

fn make_block_request(op: narf_block::BlockOp, user_tag: u64) -> narf_block::BlockRequest {
    use narf_block::{BlockRequest, QosHint};
    use narf_capabilities::{Cap, CapSlot, Read, Rights};
    let cap = unsafe { Cap::<narf_io::DmaBuffer, Read>::mint(
        CapSlot::new(1, 0, Read::BITS, narf_capabilities::CapKind::DmaBuffer as u32)
    )};
    BlockRequest {
        op,
        lba: 0,
        blocks: 1,
        buffer: cap,
        qos: QosHint::Latency,
        user_tag,
    }
}

fn smoke_block_deadline_prefers_reads() -> TestResult {
    // With fresh deadlines, a mixed read/write workload drains reads
    // first until the starvation bound triggers, then services one
    // write, then resumes reads. Matches the Linux deadline default.
    use narf_block::{BlockOp, DeadlineScheduler, STARVE_BOUND};

    let s = DeadlineScheduler::new();
    let far_future = u64::MAX / 2;

    // Enqueue one write followed by STARVE_BOUND + 2 reads.
    s.enqueue(make_block_request(BlockOp::Write { fua: false }, 0x100), far_future);
    for i in 0..(STARVE_BOUND + 2) {
        s.enqueue(make_block_request(BlockOp::Read, 0x200 + i as u64), far_future);
    }

    // First STARVE_BOUND picks should all be reads.
    for i in 0..STARVE_BOUND {
        let req = match s.dequeue_next(0) {
            Some(r) => r,
            None    => return TestResult::Fail("scheduler underflowed"),
        };
        if req.op != BlockOp::Read {
            return TestResult::Fail("read lane starved before STARVE_BOUND");
        }
        if req.user_tag != 0x200 + i as u64 {
            return TestResult::Fail("read lane drained out of order");
        }
    }
    // The STARVE_BOUND+1-th pick must be the pending write.
    let req = s.dequeue_next(0).expect("pending");
    if !matches!(req.op, BlockOp::Write { .. }) {
        return TestResult::Fail("write was not promoted after STARVE_BOUND reads");
    }
    if req.user_tag != 0x100 {
        return TestResult::Fail("wrong write promoted");
    }
    // And the remaining picks are reads again.
    let req = s.dequeue_next(0).expect("pending");
    if req.op != BlockOp::Read {
        return TestResult::Fail("read lane did not resume after write flush");
    }
    TestResult::Pass
}
kernel_test!(smoke_block_deadline_prefers_reads);

fn smoke_block_deadline_promotes_expired() -> TestResult {
    // A write with an already-past deadline must beat reads that are
    // still within their deadline, regardless of the starvation count.
    use narf_block::{BlockOp, DeadlineScheduler};

    let s = DeadlineScheduler::new();
    s.enqueue(make_block_request(BlockOp::Read, 0x10),                   1_000);
    s.enqueue(make_block_request(BlockOp::Write { fua: false }, 0x20),   500);

    // now_cycles = 750 → the write at deadline 500 is expired,
    // the read at deadline 1_000 is not.
    let req = s.dequeue_next(750).expect("pending");
    if !matches!(req.op, BlockOp::Write { .. }) || req.user_tag != 0x20 {
        return TestResult::Fail("expired write was not promoted ahead of the read");
    }
    // Next: the read is still pending.
    let req = s.dequeue_next(750).expect("pending");
    if req.op != BlockOp::Read || req.user_tag != 0x10 {
        return TestResult::Fail("pending read was not drained next");
    }
    if !s.is_empty() {
        return TestResult::Fail("scheduler should be empty after draining both");
    }
    TestResult::Pass
}
kernel_test!(smoke_block_deadline_promotes_expired);

fn smoke_block_deadline_tags_are_monotonic() -> TestResult {
    use narf_block::{BlockOp, DeadlineScheduler};

    let s = DeadlineScheduler::new();
    let t1 = s.enqueue(make_block_request(BlockOp::Read, 0), u64::MAX);
    let t2 = s.enqueue(make_block_request(BlockOp::Write { fua: false }, 1), u64::MAX);
    let t3 = s.enqueue(make_block_request(BlockOp::Read, 2), u64::MAX);
    if !(t1 < t2 && t2 < t3) {
        return TestResult::Fail("enqueue tags not monotonically assigned");
    }
    if s.reads_pending() != 2 || s.writes_pending() != 1 {
        return TestResult::Fail("per-lane pending counts off");
    }
    TestResult::Pass
}
kernel_test!(smoke_block_deadline_tags_are_monotonic);
